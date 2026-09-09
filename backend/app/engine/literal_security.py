"""Literal security settings: bounded values, scoped sources and no inferred defaults."""

import re
from .flow_extraction import alias_index, find_mentions

FIELDS = {
    'authorization_model': ('none', 'rbac', 'abac', 'object_level'),
    'error_handling': ('verbose', 'generic'), 'tls_version': ('1.0', '1.1', '1.2', '1.3'),
    'jwt_algo': ('none', 'hs256', 'rs256', 'es256'), 'same_site_cookie': ('none', 'lax', 'strict'),
    **{key: (True, False) for key in ('cors_misconfigured', 'security_headers', 'ddos_protection',
        'debug_mode', 'default_credentials', 'device_authentication', 'vendor_assessment',
        'pod_security_policy', 'pod_security_enforced', 'certificate_pinning', 'admin_portal', 'hardcoded_secrets', 'runs_as_root',
        'cookie_authentication', 'csrf_protection')},
}


def apply_literal_settings(architecture):
    from .source_correlation import _source_parts, _scope, _applicable, _PLANNED, _UNKNOWN
    from .control_statements import non_assertion
    components = {c.id: c for c in architecture.components}
    aliases = alias_index(components)
    parts, documents = _source_parts(architecture)
    lines = [(line, citation, documents.get(document, {})) for document, rows in parts.items() for line, citation in rows]
    for line, citation, document in lines:
        ids = {m[2] for m in find_mentions(line, aliases)}
        if len(ids) != 1 or _PLANNED.search(line) or _UNKNOWN.search(line) or non_assertion(line):
            continue
        component = components[next(iter(ids))]
        scope = _scope(line, document)
        if not _applicable(scope, component) or scope['endpoints'] or scope['workflow_restricted']:
            continue
        number = citation.get('line')
        for field, choices in FIELDS.items():
            match = re.search(r'\b' + field + r'\s*[:=]\s*["\']?([a-z0-9_.]+)', line, re.I)
            if not match:
                continue
            raw = match.group(1).lower()
            value = {'true': True, 'false': False}.get(raw, raw)
            if value not in choices:
                continue
            old = component.properties.get('literal_security_evidence', {}).get(field)
            if old and old['value'] != value:
                component.properties.pop(field, None)
                component.properties.setdefault('control_assertions', {})[field] = 'conflicting'
                continue
            if component.properties.get('control_assertions', {}).get(field) == 'conflicting':
                continue
            component.properties[field] = value
            component.properties.setdefault('literal_security_evidence', {})[field] = {'value': value, 'line': number, 'statement': line}
            evidence = {**citation, 'source_type': 'configuration', 'source_ref': component.id, 'line': number, 'statement': line, 'confidence': 'High', 'scope': scope}
            if evidence not in component.evidence:
                component.evidence.append(evidence)
            component.confidence = 'High'
