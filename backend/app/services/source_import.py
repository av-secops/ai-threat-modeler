"""Allowlisted HTTPS document import with DNS validation and pinned connections."""

import ipaddress
import os
import socket
from urllib.parse import urlsplit, urljoin, unquote

import urllib3

from .document_ingestion import _extract_text_from_bytes


def allowed_hosts():
    return {host.strip().lower() for host in os.getenv('AEGIS_DOCUMENT_IMPORT_HOSTS', '').split(',') if host.strip()}


def import_url(url):
    for _ in range(4):
        parts = urlsplit(url)
        if parts.scheme != 'https' or parts.hostname not in allowed_hosts() or parts.username or parts.password or parts.port not in {None, 443}:
            raise ValueError('Import requires HTTPS on an administrator-approved documentation host.')
        addresses = {entry[4][0] for entry in socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            raise ValueError('Private, local and metadata addresses cannot be imported.')
        address = sorted(addresses)[0]
        path = parts.path or '/'
        if parts.query:
            path += '?' + parts.query
        # Pin the validated address while retaining TLS hostname verification.
        with urllib3.HTTPSConnectionPool(address, port=443, server_hostname=parts.hostname, assert_hostname=parts.hostname,
                cert_reqs='CERT_REQUIRED', timeout=urllib3.Timeout(connect=5, read=10)) as pool:
            response = pool.request('GET', path, headers={'Host': parts.hostname, 'Accept-Encoding': 'identity'},
                redirect=False, retries=False, preload_content=False)
            try:
                if response.status in {301, 302, 303, 307, 308}:
                    url = urljoin(url, response.headers.get('Location', ''))
                    continue
                if response.status != 200:
                    raise ValueError('Documentation host did not return a readable document.')
                if response.headers.get('Content-Encoding', 'identity') not in {'', 'identity'}:
                    raise ValueError('Compressed HTTP responses are not supported for URL import.')
                mime = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                if mime and mime not in {'application/pdf', 'application/json', 'application/xml', 'application/yaml',
                        'application/x-yaml', 'application/octet-stream', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'text/plain', 'text/markdown', 'text/csv', 'text/xml', 'text/yaml', 'text/x-yaml'}:
                    raise ValueError('Import requires a document response, not an HTML page or executable.')
                raw = response.read(8_000_001, decode_content=False)
                if len(raw) > 8_000_000:
                    raise ValueError('Document exceeds the 8 MB limit.')
            finally:
                response.close()
        filename = unquote(parts.path.rsplit('/', 1)[-1])[:200]
        if not filename or any(c in filename for c in '\r\n\\'):
            raise ValueError('URL must name a supported document file.')
        text, extension, metadata = _extract_text_from_bytes(filename, raw)
        import hashlib
        import uuid
        return {'id': uuid.uuid4().hex, 'name': filename, 'kind': extension.lstrip('.'), 'text': text,
            'included': True, 'environment': 'unspecified', 'version': '',
            'metadata': {**metadata, 'import_url': url, 'content_hash': hashlib.sha256(raw).hexdigest(), 'role': 'source_design'}}
    raise ValueError('Too many documentation redirects.')
