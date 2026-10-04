"""Bounded diagram import. OCR labels never masquerade as verified connectors."""

import base64
import hashlib
import html
import io
import json
import math
import os
import re
import time
import urllib.parse
import zlib

from defusedxml import ElementTree
from PIL import Image

from ..models import Component, DataFlow, SystemArchitecture, TrustBoundary

DIAGRAM_EXTENSIONS = {'.drawio', '.xml', '.mmd', '.mermaid', '.png', '.jpg', '.jpeg'}


def _clean(value):
    return re.sub(r'<[^>]*>', '', html.unescape(str(value))).strip()[:500]


def _kind(label, style=''):
    name = label.lower()
    if 'dynamodb' in name:
        return 'Database'
    if 'elasticache' in name or 'redis' in name:
        return 'Cache'
    if 'load balancer' in name:
        return 'Load Balancer'
    if 'lambda' in name:
        return 'Serverless Function'
    if 'ecr' in name or 'container registry' in name:
        return 'Container Registry'
    if 'ecs' in name or 'fargate' in name:
        return 'Container Platform'
    if 'parameter store' in name:
        return 'Secrets Manager'
    if 'cloudwatch' in name:
        return 'Monitoring'
    if name in {'devices', 'sdk'}:
        return 'External Entity'
    if any(s in name for s in ('postgres', 'mysql', 'mongodb', 'redis', 'database', 'rds')) or 'cylinder' in style:
        return 'Database'
    if any(s in name for s in ('s3', 'blob', 'storage')):
        return 'Object Storage'
    if any(s in name for s in ('user', 'customer', 'partner')):
        return 'External Entity'
    if any(s in name for s in ('keycloak', 'auth0', 'identity provider', 'azure ad')):
        return 'Identity Provider'
    if any(s in name for s in ('react', 'frontend', 'browser', 'mobile')):
        return 'WebClient'
    if 'gateway' in name:
        return 'API Gateway'
    return 'API' if 'api' in name else 'Service'


def _evidence(filename, locator, statement, inferred=False):
    return {'document': filename, 'locator': locator, 'statement': statement,
        'source_type': 'diagram_import', 'evidence_basis': 'inferred' if inferred else 'source_design',
        'verification_status': 'requires_architect_review' if inferred else 'not_runtime_verified'}


def _drawio(raw, filename):
    root = ElementTree.fromstring(raw)
    if root.tag not in {'mxfile', 'mxGraphModel'}:
        raise ValueError('Expected a draw.io mxfile or mxGraphModel document.')
    pages = root.findall('diagram') if root.tag == 'mxfile' else [root]
    model = SystemArchitecture(components=[], flows=[], metadata={'diagram_relationships': [], 'diagram_issues': [],
        'diagram_extraction': {'version': 1, 'method': 'structured', 'local_processing': True}})
    warnings = []
    for page_index, page in enumerate(pages[:20]):
        graph = page.find('mxGraphModel') if page.tag == 'diagram' else page
        if graph is None and page.text:
            packed = base64.b64decode(page.text.strip(), validate=True)
            decoder = zlib.decompressobj(-15)
            unpacked = decoder.decompress(packed, 2_000_001)
            if len(unpacked) > 2_000_000 or not decoder.eof:
                raise ValueError('Compressed diagram exceeds the import size limit.')
            graph = ElementTree.fromstring(urllib.parse.unquote(unpacked.decode('utf-8')))
        if graph is None:
            warnings.append(f'Page {page_index + 1} could not be read.')
            continue
        for wrapper in graph.iter():
            child = wrapper.find('mxCell') if wrapper.tag in {'object', 'UserObject'} else None
            if child is not None:
                child.set('id', wrapper.get('id', child.get('id', '')))
                if not child.get('value'):
                    child.set('value', wrapper.get('label', wrapper.get('name', '')))
        cells = graph.findall('.//mxCell')
        if len(cells) > 5000:
            raise ValueError('Diagram exceeds the 5000-cell limit.')
        scope = hashlib.sha256(f'{filename}:{page_index}'.encode()).hexdigest()[:10]
        by_id = {c.get('id'): c for c in cells}
        if len(by_id) != len(cells) or None in by_id:
            raise ValueError('Diagram cells require unique IDs.')
        geometry = {}
        def position(cell, seen=None):
            seen = set() if seen is None else seen
            if cell.get('id') in seen:
                raise ValueError('Diagram containment is cyclic.')
            seen.add(cell.get('id'))
            g = cell.find('mxGeometry')
            if g is None or g.get('relative') == '1':
                return None
            values = [float(g.get(k, '0')) for k in ('x', 'y', 'width', 'height')]
            if not all(math.isfinite(v) and abs(v) < 1000000 for v in values):
                raise ValueError('Diagram coordinates exceed the supported range.')
            parent = by_id.get(cell.get('parent'))
            if parent is not None and parent.get('vertex') == '1':
                p = position(parent, seen)
                if p:
                    values[0] += p[0]
                    values[1] += p[1]
            return values if values[2] > 0 and values[3] > 0 else None
        for cell in cells:
            if cell.get('vertex') == '1':
                geometry[cell.get('id')] = position(cell)
        extents = [g for g in geometry.values() if g]
        if extents:
            x0, y0 = min(g[0] for g in extents), min(g[1] for g in extents)
            width, height = max(g[0]+g[2] for g in extents)-x0, max(g[1]+g[3] for g in extents)-y0
        def source_evidence(cell, statement):
            item = {**_evidence(filename, f'Page {page_index + 1}, cell {cell.get("id")}', statement),
                'page': page_index + 1, 'source_key': f'{page_index}:{cell.get("id")}', 'extraction_method': 'structured'}
            g = geometry.get(cell.get('id'))
            if g:
                item.update({'diagram_geometry': g, 'bbox': [(g[0]-x0)/width, (g[1]-y0)/height, g[2]/width, g[3]/height],
                    'region_alignment': 'approximate_drawing_extent'})
            elif cell.get('edge') == '1':
                ends = [geometry.get(cell.get(k)) for k in ('source', 'target')]
                if all(ends):
                    points = [[(g[0]+g[2]/2-x0)/width, (g[1]+g[3]/2-y0)/height] for g in ends]
                    left, top = min(p[0] for p in points), min(p[1] for p in points)
                    right, bottom = max(p[0] for p in points), max(p[1] for p in points)
                    item.update({'bbox': [max(0, left-.01), max(0, top-.01), min(1, right+.01)-max(0, left-.01), min(1, bottom+.01)-max(0, top-.01)],
                        'region_alignment': 'approximate_endpoint_extent'})
            return item
        ids = {c.get('id'): f'diagram:{scope}:{c.get("id")}' for c in cells if c.get('vertex') == '1'}
        boundary_ids = set()
        group_ids = set()
        for cell in cells:
            if cell.get('vertex') != '1':
                continue
            name, style = _clean(cell.get('value', '')), cell.get('style', '')
            if not name:
                warnings.append(f'Unlabeled shape {cell.get("id")} requires review.')
                continue
            identifier = ids[cell.get('id')]
            evidence = [source_evidence(cell, name)]
            if 'trust boundary' in name.lower():
                boundary_ids.add(cell.get('id'))
                model.trust_boundaries.append(TrustBoundary(id=identifier, name=name, boundary_type='explicit', evidence=evidence))
            elif 'swimlane' in style or 'group' in style:
                group_ids.add(cell.get('id'))
                model.metadata.setdefault('diagram_groups', []).append({'id': identifier, 'name': name, 'evidence': evidence})
                warnings.append(f'Group "{name}" is not automatically a trust boundary.')
            else:
                model.components.append(Component(id=identifier, name=name, type=_kind(name, style), trust_level='unknown', evidence=evidence,
                    properties={'evidence_status': 'explicit', 'diagram_source': filename, 'diagram_key': f'{page_index}:{cell.get("id")}',
                        'diagram_bbox': evidence[0].get('bbox')}))
        included = {c.id for c in model.components}
        for cell in cells:
            if cell.get('edge') == '1':
                source, target = ids.get(cell.get('source')), ids.get(cell.get('target'))
                if source not in included or target not in included:
                    warnings.append(f'Connector {cell.get("id")} has an unresolved endpoint.')
                    continue
                label, style = _clean(cell.get('value', '')), cell.get('style', '')
                styles = dict(part.split('=', 1) for part in style.split(';') if '=' in part)
                reverse = styles.get('startArrow', 'none') not in {'none', ''}
                forward = styles.get('endArrow', 'classic') not in {'none', ''}
                relation = 'hosts' if re.search(r'\b(hosts?|hosted on|deployed (?:on|in)|runs on)\b', label, re.I) else 'depends_on' if re.search(r'\bdepends on\b', label, re.I) else None
                if relation or (not forward and not reverse):
                    model.metadata['diagram_relationships'].append({'id': f'relation:{scope}:{cell.get("id")}',
                        'source_id': source, 'target_id': target, 'kind': relation or 'unknown', 'description': label,
                        'evidence': [source_evidence(cell, label or 'Undirected connection')]})
                if not forward and not reverse:
                    warnings.append(f'Connector {cell.get("id")} has no arrowhead; direction needs review.')
                    continue
                if relation:
                    continue
                pairs = ([(source, target)] if forward else []) + ([(target, source)] if reverse else [])
                for n, (left, right) in enumerate(pairs):
                    protocol = re.search(r'\b(HTTPS|HTTP|TLS|mTLS|WSS|WS|TCP|gRPCS)\b', label, re.I)
                    model.flows.append(DataFlow(id=f'flow:{scope}:{cell.get("id")}:{n}', source_id=left, target_id=right,
                        protocol=protocol.group(1) if protocol else 'unknown', description=label,
                        properties={'diagram_key': f'{page_index}:{cell.get("id")}:{n}'},
                        evidence=[source_evidence(cell, label or f'{left} -> {right}')]))
        for cell in cells:
            if ids.get(cell.get('id')) not in included:
                continue
            parent, visited = cell.get('parent'), set()
            while parent in by_id and parent not in visited:
                visited.add(parent)
                if parent in group_ids:
                    model.metadata['diagram_relationships'].append({'id': f'containment:{scope}:{parent}:{cell.get("id")}',
                        'source_id': ids[parent], 'target_id': ids[cell.get('id')], 'kind': 'contains',
                        'description': 'Drawing containment; not a runtime data flow or a security control.', 'evidence': [source_evidence(cell, 'Group membership')]})
                parent = by_id[parent].get('parent')
        for boundary in model.trust_boundaries:
            raw_id = next((key for key in boundary_ids if ids[key] == boundary.id), None)
            if raw_id:
                def descendant(cell):
                    parent, seen = cell.get('parent'), set()
                    while parent in by_id and parent not in seen:
                        if parent == raw_id:
                            return True
                        seen.add(parent)
                        parent = by_id[parent].get('parent')
                    return False
                boundary.components = [ids[c.get('id')] for c in cells if descendant(c) and ids.get(c.get('id')) in included]
                parent = next((c.get('parent') for c in cells if c.get('id') == raw_id), None)
                seen = set()
                while parent in by_id and parent not in boundary_ids and parent not in seen:
                    seen.add(parent)
                    parent = by_id[parent].get('parent')
                boundary.parent_id = ids.get(parent) if parent in boundary_ids else None
    if len(pages) > 20:
        warnings.append('Only the first 20 diagram pages were imported.')
    return model, warnings


def _mermaid(raw, filename):
    text = raw.decode('utf-8-sig')
    model = SystemArchitecture(components=[], flows=[])
    nodes, warnings, groups, stack = {}, [], {}, []
    scope = hashlib.sha256(filename.encode()).hexdigest()[:10]
    def node(token, line):
        match = re.fullmatch(r'([\w-]+)\s*(?:\[\(?(.*?)\)?\]|\(\(?(.*?)\)?\))?', token.strip())
        if not match:
            raise ValueError('Unsupported Mermaid node syntax')
        key = match[1]
        label = _clean((match[2] or match[3] or key).strip('"'))
        if key not in nodes or label != key:
            nodes[key] = Component(id=f'diagram:{scope}:{key}', name=label, type=_kind(label), trust_level='unknown',
                evidence=[_evidence(filename, f'Line {line}', label)], properties={'evidence_status': 'explicit'})
        if stack:
            groups[stack[-1]]['members'].add(nodes[key].id)
        return nodes[key].id
    for index, line in enumerate(text.splitlines(), 1):
        line = line.strip().rstrip(';')
        if not line or line.startswith(('%%', 'flowchart ', 'graph ', '```')):
            continue
        try:
            if line.startswith('subgraph '):
                name = _clean(line[9:].strip('[]"'))
                stack.append(name)
                groups[name] = {'members': set(), 'parent': stack[-2] if len(stack) > 1 else None}
                continue
            if line == 'end':
                if stack:
                    stack.pop()
                continue
            edge = re.fullmatch(r'(.+?)\s*(<-->|-->|-\.->|==>)\s*(?:\|([^|]*)\|)?\s*(.+)', line)
            if edge:
                source, target = node(edge[1], index), node(edge[4], index)
                for suffix, left, right in [('f', source, target)] + ([('r', target, source)] if edge[2] == '<-->' else []):
                    model.flows.append(DataFlow(id=f'flow:{scope}:{index}:{suffix}', source_id=left, target_id=right, protocol='unknown',
                        description=_clean(edge[3] or ''), assumed=edge[2] == '-.->', evidence=[_evidence(filename, f'Line {index}', line)]))
            elif line.startswith(('style ', 'classDef ', 'class ', 'direction ', 'linkStyle ')):
                continue
            else:
                node(line, index)
        except ValueError:
            warnings.append(f'Unsupported Mermaid construct on line {index}; review the source.')
    model.components = list(nodes.values())
    for name, group in groups.items():
        if 'trust boundary' in name.lower():
            model.trust_boundaries.append(TrustBoundary(id='boundary:' + fingerprint_short([filename, name]), name=name,
                boundary_type='explicit', components=sorted(group['members'])))
        else:
            warnings.append(f'Group "{name}" is not automatically a trust boundary.')
    return model, warnings


def fingerprint_short(value):
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()[:20]


def _image(raw, filename, budget=120):
    with Image.open(io.BytesIO(raw)) as image:
        if image.width * image.height > 24_000_000:
            raise ValueError('Diagram exceeds the 24-megapixel limit.')
        image.load()
        embedded = image.info.get('mxfile')
        if embedded:
            if not isinstance(embedded, str) or len(embedded) > 2_000_000:
                raise ValueError('Embedded diagram exceeds the import size limit.')
            embedded = urllib.parse.unquote(embedded)
            if not embedded.lstrip().startswith('<'):
                raise ValueError('Unsupported embedded diagram encoding; upload the .drawio source.')
            model, warnings = _drawio(embedded.encode('utf-8'), filename)
            model.metadata['diagram_extraction']['method'] = 'embedded_drawio'
            warnings.append('Embedded draw.io data was used. Image-region alignment is approximate; verify the drawing against its embedded source.')
            return model, warnings
        from .diagram_vision import extract_raster
        return extract_raster(image, filename, budget)


def extract_pdf_diagram(filename, raw):
    import pymupdf
    if len(raw) > 8_000_000:
        raise ValueError('Diagram PDF exceeds the 8 MB limit.')
    from .diagram_vision import preview_image
    model = SystemArchitecture(components=[], flows=[], metadata={'diagram_relationships': [], 'diagram_issues': [], 'diagram_pages': []})
    warnings, previews = [], []
    started = time.monotonic()
    with pymupdf.open(stream=raw, filetype='pdf') as document:
        if document.needs_pass:
            raise ValueError('Encrypted diagram PDFs must be unlocked before upload.')
        for index in range(min(len(document), 8)):
            remaining = 240 - (time.monotonic() - started)
            if remaining < 5:
                warnings.append(f'Diagram PDF processing budget reached. Pages {index + 1} onward were not processed.')
                break
            page = document[index]
            if page.rect.width * page.rect.height > 12_000_000:
                raise ValueError('Diagram page dimensions exceed the rendering limit.')
            pixels = page.get_pixmap(matrix=pymupdf.Matrix(1.25, 1.25), alpha=False)
            image = pixels.tobytes('png')
            imported, notes = _image(image, f'{filename} page {index + 1}', budget=min(120, remaining))
            for element in [*imported.components, *imported.flows, *imported.trust_boundaries]:
                for record in element.evidence:
                    record.update({'document': filename, 'page': index + 1})
            for relation in (imported.metadata or {}).get('diagram_relationships', []):
                for record in relation.get('evidence', []):
                    record.update({'document': filename, 'page': index + 1})
            for name in ('diagram_relationships', 'diagram_issues', 'diagram_groups'):
                model.metadata.setdefault(name, []).extend((imported.metadata or {}).get(name, []))
            model.metadata['diagram_pages'].append({'page': index + 1, **(imported.metadata or {}).get('diagram_extraction', {})})
            model.components.extend(imported.components)
            model.flows.extend(imported.flows)
            model.trust_boundaries.extend(imported.trust_boundaries)
            warnings.extend(f'Page {index + 1}: {note}' for note in notes)
            with Image.open(io.BytesIO(image)) as preview:
                previews.append({'page': index + 1, 'image': preview_image(preview)})
            if len(model.components) > 1000 or len(model.flows) > 3000:
                raise ValueError('Diagram PDF exceeds the model size limit.')
        if len(document) > 8:
            warnings.append('Only the first 8 diagram pages were processed; split the document to review additional pages.')
    return '\n'.join(c.name for c in model.components) or 'Unreadable architecture diagram; manual review required.', '.pdf', {
        'diagram_model': model.model_dump(), 'diagram_review_required': True, 'extraction_quality': 'diagram_requires_review',
        'artifact_hash': hashlib.sha256(raw).hexdigest(), 'warning': ' '.join(warnings), 'diagram_pages': previews}


def extract_diagram(filename, raw):
    from defusedxml.common import DefusedXmlException
    from xml.etree.ElementTree import ParseError
    extension = os.path.splitext(filename)[1].lower()
    if len(raw) > 8_000_000:
        raise ValueError('Diagram exceeds the 8 MB limit.')
    try:
        model, warnings = (_drawio(raw, filename) if extension in {'.drawio', '.xml'} else
            _mermaid(raw, filename) if extension in {'.mmd', '.mermaid'} else _image(raw, filename))
    except (ValueError, OSError, DefusedXmlException, ParseError) as exc:
        raise ValueError(f'Could not import {filename}: {exc}') from exc
    if len(model.components) > 1000 or len(model.flows) > 3000:
        raise ValueError('Diagram exceeds the model size limit.')
    text = raw.decode('utf-8-sig') if extension in {'.drawio', '.xml', '.mmd', '.mermaid'} else '\n'.join(c.name for c in model.components) or 'Architecture image could not be read; manual review required.'
    preview = ''
    if extension in {'.png', '.jpg', '.jpeg'}:
        from .diagram_vision import preview_image
        with Image.open(io.BytesIO(raw)) as source:
            preview = preview_image(source)
    return text, extension, {'diagram_model': model.model_dump(), 'content_hash': hashlib.sha256(raw).hexdigest(),
        'artifact_hash': hashlib.sha256(raw).hexdigest(),
        'extraction_quality': 'diagram_requires_review' if warnings else 'structured_complete',
        'warning': ' '.join(warnings), 'diagram_review_required': True, 'original_diagram': text if extension in {'.mmd', '.mermaid'} else '',
        'source_preview': preview}
