"""Bounded external assessment imports; imported results are not native scans."""

import hashlib
import json
import re
from datetime import date

from .document_ingestion import _extract_text_from_bytes


def redact(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if re.search(r'secret|password|token|api.?key|private.?key', k, re.I) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]', value)
        value = re.sub(r'(?i)(bearer\s+|(?:password|token|secret|api[_ -]?key)\s*[:=]\s*)[^\s,;]+', r'\1[REDACTED]', value)
    return value


def objects(value, field, limit):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f'{field} must be an array of objects.')
    if len(value) > limit:
        raise ValueError(f'{field} exceeds the {limit} item limit; split the report.')
    return value


def mapping(value, field):
    if not isinstance(value, dict):
        raise ValueError(f'{field} must be an object.')
    return value


def parse_report(raw, filename, metadata):
    if len(raw) > 8_000_000:
        raise ValueError('Report exceeds the 8 MB limit.')
    date.fromisoformat(metadata['report_date'])
    if metadata['category'] == 'secret_detection':
        # Arbitrary scanner messages can embed an unrecognizable credential.
        # Never retain their free text, snippets or match payloads.
        data = json.loads(raw)
        records = data if isinstance(data, list) else mapping(data, 'Secret report').get('results', data.get('findings', []))
        records = objects(records, 'Secret findings', 2000)
        findings = [{'id': f'secret-{i + 1}', 'title': 'Potential secret (value omitted)', 'severity': 'Unspecified',
            'location': str(item.get('File', item.get('file', item.get('path', 'Unspecified'))))[:500],
            'line': item.get('StartLine', item.get('line')) if isinstance(item.get('StartLine', item.get('line')), int) else None, 'source_status': 'imported_unverified'}
            for i, item in enumerate(records[:2000]) if isinstance(item, dict)]
        details = {'format': 'masked_secret_findings', 'findings': findings, 'text': '', 'warning': 'All secret values and free-text scanner messages were omitted.'}
    elif filename.lower().endswith(('.json', '.sarif', '.sarif.json')):
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('Expected a structured report object.')
        findings = []
        if data.get('version') == '2.1.0' and isinstance(data.get('runs'), list):
            for run in objects(data['runs'], 'SARIF runs', 30):
                for item in objects(run.get('results', []), 'SARIF results', 2000):
                    locations = objects(item.get('locations', []), 'SARIF locations', 100)
                    location = mapping(next(iter(locations), {}).get('physicalLocation', {}), 'physicalLocation')
                    message = mapping(item.get('message', {}), 'message')
                    artifact = mapping(location.get('artifactLocation', {}), 'artifactLocation')
                    region = mapping(location.get('region', {}), 'region')
                    if item.get('level') is not None and not isinstance(item['level'], str):
                        raise ValueError('SARIF level must be text.')
                    findings.append({'id': item.get('ruleId', f'finding-{len(findings) + 1}'),
                        'title': str(message.get('text', 'Imported finding'))[:1000],
                        'severity': {'error': 'High', 'warning': 'Medium', 'note': 'Low'}.get(item.get('level'), 'Unspecified'),
                        'original_severity': item.get('level', 'unspecified'),
                        'location': str(artifact.get('uri', ''))[:500],
                        'line': region.get('startLine'), 'source_status': 'imported_unverified'})
                    if len(findings) > 2000:
                        raise ValueError('Report exceeds 2000 findings; split the report.')
            details = {'format': 'SARIF 2.1.0 subset', 'findings': findings, 'warning': 'SARIF level is a priority mapping, not an independently verified severity.'}
        elif data.get('bomFormat') == 'CycloneDX' or data.get('spdxVersion'):
            inventory = objects(data.get('components', data.get('packages', [])), 'SBOM inventory', 10000)
            details = {'format': 'SBOM inventory', 'inventory': [{'name': str(c.get('name', 'Unspecified'))[:500], 'version': str(c.get('version', c.get('versionInfo', 'Unspecified')))[:200],
                'licenses': c.get('licenses', c.get('licenseConcluded', 'Unspecified'))} for c in inventory], 'findings': [],
                'warning': 'Inventory only. This import does not establish vulnerability or license compliance coverage.'}
        else:
            records = objects(data.get('findings', []), 'Findings', 2000)
            findings = [{'id': str(c.get('id', i)), 'title': str(c.get('title', 'Imported finding'))[:1000],
                'severity': str(c.get('severity', 'Unspecified'))[:50], 'description': str(c.get('description', ''))[:6000],
                'location': str(c.get('location', ''))[:500], 'source_status': 'imported_unverified'} for i, c in enumerate(records[:2000]) if isinstance(c, dict)]
            details = {'format': 'generic findings JSON', 'findings': findings,
                'warning': 'Unrecognized scanner fields are not treated as assessed coverage.'}
    else:
        text, extension, info = _extract_text_from_bytes(filename, raw)
        details = {'format': extension, 'text': text[:100000], 'findings': [],
            'warning': 'Document attachment: findings require product-team review. ' + str(info.get('warning', ''))}
    artifact_hash = hashlib.sha256(raw).hexdigest()
    for index, finding in enumerate(details['findings']):
        finding['import_id'] = f'{artifact_hash[:16]}:{index + 1}'
    return {**redact(metadata), **redact(details), 'filename': filename, 'artifact_hash': artifact_hash,
        'affected_component_ids': [], 'affected_flow_ids': [], 'link_status': 'unlinked_pending_review'}
