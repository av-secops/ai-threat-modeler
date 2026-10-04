"""Deterministic comparison of report snapshots, with identity and evidence separated."""

from collections import Counter, defaultdict, deque
from copy import deepcopy
import hashlib
import json
import re

import networkx as nx

COMPARISON_VERSION = '3'
SEVERITY = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
METADATA_FIELDS = {'metadata', 'evidence', 'evidence_details', 'source_document', 'source_documents',
    'source_line', 'source_lines', 'line', 'locator', 'cite', 'source_attribution', 'provenance',
    'source_id', 'source_ids', 'source_text', 'statement', 'origin', 'confidence', 'confidence_score',
    'stated_weaknesses', 'review_id', 'extraction_confidence', 'control_evidence', 'control_claims'}
IDENTITY_FIELDS = ('logical_id', 'resource_address', 'resource_id', 'arn', 'qualified_name')
SCOPE_FIELDS = ('provider', 'account_id', 'cloud_account', 'subscription_id', 'project_id', 'region', 'cloud_region', 'tenant_id', 'namespace', 'environment')
POSITIVE_CONTROLS = frozenset({'authentication', 'authentication_enabled', 'authorization', 'authorization_enabled',
    'object_level_auth', 'function_level_auth', 'encryption_at_rest', 'transport_encryption', 'mfa_enabled',
    'input_validation', 'parameterized_queries', 'output_encoding', 'rate_limiting', 'rate_limit_enabled',
    'audit_logging', 'logging_enabled', 'session_revocation', 'tenant_isolation', 'network_isolation',
    'webhook_signature_validation', 'signature_validation', 'imds_v2_required'})


def fingerprint(value):
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(fingerprint(value).encode()).hexdigest()


def normalized(value):
    return re.sub(r'[^a-z0-9]', '', str(value or '').casefold())


def canonical(value):
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted((canonical(v) for v in value), key=fingerprint)
    return value


def semantic_properties(value):
    return {k: canonical(v) for k, v in (value or {}).items()
            if k not in METADATA_FIELDS and not k.startswith(('source_', 'evidence_', 'inferred_', 'review_'))
            and k not in IDENTITY_FIELDS and v is not None}


def fields(before, after, prefix=''):
    changes = []
    for key in sorted(set(before) | set(after)):
        left, right = before.get(key), after.get(key)
        path = f'{prefix}.{key}' if prefix else key
        if isinstance(left, dict) and isinstance(right, dict):
            changes.extend(fields(left, right, path))
        elif canonical(left) != canonical(right):
            changes.append({'field': path, 'before': left, 'after': right})
    return changes


def report_provenance(report):
    status = report.get('engine_status') or {}
    kb = status.get('knowledge_base') or {}
    release = kb.get('release') or {}
    versions = {str((t.get('explanation') or {}).get('provenance', {}).get('engine_version'))
                for t in report.get('threats', []) if (t.get('explanation') or {}).get('provenance', {}).get('engine_version')}
    if status.get('engine_version'):
        versions.add(str(status['engine_version']))
    models = (status.get('local_models') or {}).get('models', [])
    if not models:
        models = [m for t in report.get('threats', [])
                  for m in (t.get('explanation') or {}).get('provenance', {}).get('models', [])]
    model_set = {fingerprint({k: m.get(k) for k in ('role', 'model', 'revision', 'fallback')}) for m in models}
    return {'engine_versions': sorted(versions),
            'knowledge_base': {**{k: kb.get(k) for k in ('schema_version', 'threats', 'typed_rules', 'deterministic_rules')},
                'content_digest': release.get('content_digest') or kb.get('content_digest')},
            'models': [json.loads(m) for m in sorted(model_set)],
            'settings': report.get('comparison_settings') or {
                'analysis_mode': status.get('analysis_mode'), 'domain': (report.get('domain_context') or {}).get('profile')}}


def engine_identity(report):
    return fingerprint(report_provenance(report))


def identity_tokens(row):
    values = {**(row.get('metadata') or {}), **(row.get('properties') or {}), **row}
    return {f'{key}:{values[key]}' for key in IDENTITY_FIELDS if values.get(key)}


def component_scope(row):
    values = {**(row.get('metadata') or {}), **(row.get('properties') or {}), **row}
    return {key: str(values[key]).casefold() for key in SCOPE_FIELDS if values.get(key) is not None}


def compatible_identity(before, after, *, strict_scope=False):
    left, right = component_scope(before), component_scope(after)
    if any(left[key] != right[key] for key in left.keys() & right.keys()):
        return False
    if strict_scope and left != right:
        return False
    return normalized(before.get('type')) == normalized(after.get('type'))


def match_components(left, right, overrides=None):
    a, b = {r['id']: r for r in left}, {r['id']: r for r in right}
    if len(a) != len(left) or len(b) != len(right):
        raise ValueError('Component IDs must be unique within each compared report.')
    matches, methods = {}, {}
    for old, new in (overrides or {}).items():
        if old not in a or new not in b or new in matches.values():
            raise ValueError('Component mappings must reference existing elements and be one-to-one.')
        matches[old], methods[old] = new, 'reviewer'
    for old in sorted(a):
        if old in b and old not in matches and old not in matches.values() and compatible_identity(a[old], b[old]):
            matches[old], methods[old] = old, 'id'
    used = set(matches.values())
    resource_index, name_index, type_index = defaultdict(set), defaultdict(set), defaultdict(list)
    for identifier, row in b.items():
        for token in identity_tokens(row):
            resource_index[token].add(identifier)
        kind = normalized(row.get('type'))
        name_index[normalized(row.get('name')), kind].add(identifier)
        type_index[kind].append(identifier)
    for identifiers in type_index.values():
        identifiers.sort()
    for method in ('resource_identity', 'name_and_type'):
        choices = {}
        for old, row in a.items():
            if old in matches:
                continue
            candidates = []
            potential = set().union(*(resource_index[token] for token in identity_tokens(row))) if method == 'resource_identity' else (
                name_index[normalized(row.get('name')), normalized(row.get('type'))] if normalized(row.get('name')) else set())
            for new in sorted(potential - used):
                target = b[new]
                if not compatible_identity(row, target, strict_scope=True):
                    continue
                candidates.append(new)
            if len(candidates) == 1:
                choices[old] = candidates[0]
        counts = Counter(choices.values())
        for old, new in choices.items():
            if counts[new] == 1:
                matches[old], methods[old] = new, method
                used.add(new)
    suggestions = []
    for old in sorted(a.keys() - matches.keys()):
        candidates = []
        words = set(re.findall(r'[a-z0-9]+', a[old].get('name', '').lower()))
        for new in type_index[normalized(a[old].get('type'))]:
            if new in used or not compatible_identity(a[old], b[new], strict_scope=True):
                continue
            other = set(re.findall(r'[a-z0-9]+', b[new].get('name', '').lower()))
            score = len(words & other) / max(len(words | other), 1)
            candidates.append({'id': new, 'name': b[new].get('name', new), 'similarity': round(score, 2)})
        suggestions.append({'before_id': old, 'before_name': a[old].get('name', old),
                            'candidates': sorted(candidates, key=lambda c: (-c['similarity'], c['id']))[:5]})
    return matches, methods, suggestions


def pair_rows(left, right, key, projection):
    """Consume exact occurrences first; do not arbitrarily pair parallel changed rows."""
    a, b = defaultdict(list), defaultdict(list)
    for row in left:
        a[key(row, 'before')].append(row)
    for row in right:
        b[key(row, 'after')].append(row)
    paired, removed, added = [], [], []
    for group in sorted(set(a) | set(b), key=str):
        old, new = sorted(a[group], key=fingerprint), sorted(b[group], key=fingerprint)
        exact_rows = defaultdict(deque)
        for index, row in enumerate(new):
            exact_rows[fingerprint(projection(row, 'after'))].append(index)
        consumed = set()
        unmatched = []
        for row in old:
            exact = exact_rows[fingerprint(projection(row, 'before'))]
            if not exact:
                unmatched.append(row)
            else:
                index = exact.popleft()
                consumed.add(index)
                paired.append((row, new[index]))
        new = [row for index, row in enumerate(new) if index not in consumed]
        if len(unmatched) == len(new) == 1:
            paired.append((unmatched.pop(), new.pop()))
        removed.extend(unmatched)
        added.extend(new)
    return paired, removed, added


def evidence(row):
    return canonical({k: row.get(k) for k in ('evidence', 'evidence_details') if row.get(k)} | {
        'source': {k: v for k, v in row.items() if k in METADATA_FIELDS and k not in {'provenance', 'evidence', 'evidence_details'}},
        'properties': {k: v for k, v in (row.get('properties') or {}).items() if k in METADATA_FIELDS or k.startswith(('source_', 'evidence_'))}})


def review_for(row, annotations):
    identifier = row.get('id')
    return {field: (annotations.get(field) or {}).get(identifier) for field in ('owners', 'notes', 'reviewStates', 'dueDates', 'verification', 'acceptanceExpiry')}


def finding_projection(row):
    explanation = row.get('explanation') or {}
    return canonical({key: row.get(key) for key in ('severity', 'tier', 'risk_score', 'root_cause', 'specific_control',
        'affected_stride_categories', 'stride_category', 'category', 'cwe', 'owasp_top_10', 'mitre_attack', 'mitre_atlas',
        'preconditions', 'exposure', 'likelihood', 'impact')} | {
            'control_state': explanation.get('control_state'), 'matched_controls': explanation.get('matched_controls')})


def direction(changes, kind, before=None, after=None):
    if kind == 'finding':
        old, new = (SEVERITY.get(r.get('severity'), 0) for r in (before, after))
        if old != new:
            return 'worsened' if new > old else 'improved'
        if before.get('tier') != after.get('tier'):
            return 'worsened' if after.get('tier') == 'Confirmed' else 'changed'
        if (before.get('risk_score') or 0) != (after.get('risk_score') or 0):
            return 'worsened' if (after.get('risk_score') or 0) > (before.get('risk_score') or 0) else 'improved'
    signals = []
    for change in changes:
        key, old, new = change['field'].split('.')[-1], change['before'], change['after']
        if key == 'protocol':
            secure, insecure = {'https', 'tls', 'mtls', 'wss', 'grpcs'}, {'http', 'ws'}
            if old in insecure and new in secure:
                signals.append('improved')
            elif old in secure and new in insecure:
                signals.append('worsened')
        elif key in {'trust_level', 'exposure'}:
            if old in ('public', 'internet') and new in ('private', 'internal', 'restricted'):
                signals.append('improved')
            elif new in ('public', 'internet') and old in ('private', 'internal', 'restricted'):
                signals.append('worsened')
        elif type(old) is bool and type(new) is bool:
            negative = key in {'public', 'public_access', 'publicly_accessible', 'privileged', 'debug_mode', 'wildcard_permissions'}
            positive = key in POSITIVE_CONTROLS
            if negative or positive:
                signals.append('worsened' if new == negative else 'improved')
    return signals[0] if signals and len(set(signals)) == 1 else 'changed'


def compare_reports(before, after, *, component_mappings=None, before_annotations=None, after_annotations=None, sources_changed=False):
    before, after = deepcopy(before), deepcopy(after)
    before_annotations, after_annotations = before_annotations or {}, after_annotations or {}
    old, new = before.get('architecture') or {}, after.get('architecture') or {}
    matches, methods, suggestions = match_components(old.get('components', []), new.get('components', []), component_mappings)
    reverse = {v: k for k, v in matches.items()}
    remap = lambda cid, side: reverse.get(cid, f'new:{cid}') if side == 'after' else cid
    provenance = {'before': report_provenance(before), 'after': report_provenance(after)}
    engine_changed = provenance['before'] != provenance['after']
    warnings = []
    if not all(p['engine_versions'] and p['knowledge_base'].get('content_digest') for p in provenance.values()):
        warnings.append('Engine or knowledge provenance is incomplete in at least one report.')
    if engine_changed:
        warnings.append('Analysis provenance differs. Changes may reflect detection or settings as well as the design.')
    changes, buckets = [], {}

    def component_projection(row, _side):
        return {'name': row.get('name'), 'type': normalized(row.get('type')), 'trust_level': row.get('trust_level'),
                'data_classification': canonical(row.get('data_classification')),
                'properties': semantic_properties(row.get('properties'))}

    def flow_projection(row, side):
        return {'source_id': remap(row.get('source_id'), side), 'target_id': remap(row.get('target_id'), side),
                'protocol': str(row.get('protocol') or 'unknown').lower(), 'data_type': canonical(row.get('data_type')),
                'description': row.get('description'),
                'properties': semantic_properties(row.get('properties')), 'assumed': bool(row.get('assumed') or (row.get('properties') or {}).get('assumed'))}

    def flow_key(row, side):
        values = row.get('properties') or {}
        return fingerprint([remap(row.get('source_id'), side), remap(row.get('target_id'), side), values.get('workflow'),
                            values.get('operation') or row.get('operation'), values.get('logical_id')])

    flow_identities = {}
    for side, model in [('before', old), ('after', new)]:
        for row in model.get('flows', []):
            identifier = row.get('id') or row.get('review_id') or (row.get('properties') or {}).get('review_id')
            if identifier:
                flow_identities[side, identifier] = flow_key(row, side)

    def risk_key(row, side):
        explanation = row.get('explanation') or {}
        rule = row.get('rule_id') or explanation.get('rule_id') or ((explanation.get('provenance') or {}).get('knowledge_rule') or {}).get('id')
        cause = rule or row.get('specific_control') or row.get('root_cause') or row.get('id') or normalized(row.get('title'))
        routes = [flow_identities.get((side, f), f) for f in row.get('affected_data_flows') or []]
        return fingerprint([cause, sorted(remap(c, side) for c in row.get('affected_components') or []), sorted(routes)])

    def boundary_projection(row, side):
        return {'name': row.get('name'), 'components': sorted(remap(c, side) for c in row.get('components', [])),
                'parent_id': row.get('parent_id'), 'boundary_type': row.get('boundary_type'),
                'trust_level': row.get('trust_level'), 'properties': semantic_properties(row.get('properties'))}

    def record(kind, left, right, ordinal=0):
        projection = {'component': component_projection, 'flow': flow_projection, 'finding': lambda r, s: finding_projection(r),
                      'boundary': boundary_projection}[kind]
        semantic = fields(projection(left, 'before'), projection(right, 'after')) if left and right else []
        evidence_changed = bool(left and right and evidence(left) != evidence(right))
        reviews = {'before': review_for(left or {}, before_annotations), 'after': review_for(right or {}, after_annotations)} if kind == 'finding' else None
        review_changed = bool(left and right and reviews and reviews['before'] != reviews['after'])
        if left is None:
            state, reason = 'new', 'Present in the target model and absent from the matched baseline scope.'
        elif right is None:
            state = 'no_longer_reported' if kind == 'finding' else 'removed'
            out_of_scope = kind == 'finding' and any(cid not in matches for cid in left.get('affected_components', []))
            reason = ('Affected component is no longer matched in target scope.' if out_of_scope else
                      'The target report no longer produces this finding.' if kind == 'finding' else 'Absent from the target model.')
            if kind == 'finding':
                reason += ' Review scope, control evidence and analysis changes; remediation is not verified.'
        elif semantic:
            state = direction(semantic, kind, left, right)
            reason = 'Changed: ' + ', '.join(c['field'].replace('properties.', '') for c in semantic) + '.'
        elif review_changed:
            state, reason = 'review_changed', 'Reviewer decisions, ownership, verification or notes changed.'
        elif evidence_changed:
            state, reason = 'evidence_changed', 'Source evidence changed; security properties are unchanged.'
        else:
            state, reason = 'unchanged', 'Matched security properties are unchanged.'
        row = right or left
        identifier = digest([kind, left.get('id') if left else None, right.get('id') if right else None,
                             flow_key(row, 'after' if right else 'before') if kind == 'flow' else row.get('name') or row.get('title'), ordinal])[:20]
        title = row.get('title') or row.get('name') or (f"{row.get('source_id')} -> {row.get('target_id')}" if kind == 'flow' else row.get('id', kind))
        change = {'id': identifier, 'kind': kind, 'title': title, 'status': state, 'reason': reason,
                  'severity': row.get('severity'), 'stride': (row.get('affected_stride_categories') or [row.get('stride_category') or row.get('category')]) if kind == 'finding' else [],
                  'before': left, 'after': right, 'fields': semantic, 'evidence_changed': evidence_changed,
                  'review_changed': review_changed, 'review': reviews, 'provenance_changed': engine_changed,
                  'before_evidence': evidence(left or {}), 'after_evidence': evidence(right or {})}
        changes.append(change)
        return change

    for kind, plural, key, projection in [
        ('component', 'components', lambda r, s: remap(r['id'], s), component_projection),
        ('flow', 'flows', flow_key, flow_projection),
        ('boundary', 'boundaries', lambda r, s: fingerprint(sorted(remap(c, s) for c in r.get('components', []))) if r.get('components') else r.get('name'), boundary_projection),
        ('finding', 'findings', risk_key, lambda r, s: finding_projection(r)),
    ]:
        source = 'trust_boundaries' if kind == 'boundary' else 'threats' if kind == 'finding' else plural
        a, b = (before, after) if kind == 'finding' else (old, new)
        paired, removed, added = pair_rows(a.get(source, []), b.get(source, []), key, projection)
        bucket = {'added': added, 'changed': [], 'unchanged': [], 'no_longer_reported' if kind == 'finding' else 'removed': removed}
        for i, (left, right) in enumerate(paired):
            change = record(kind, left, right, i)
            if change['status'] == 'unchanged':
                bucket['unchanged'].append(right)
            else:
                bucket['changed'].append({'before': left, 'after': right, 'fields': change['fields'], 'status': change['status']})
        for i, row in enumerate(removed):
            record(kind, row, None, i)
        for i, row in enumerate(added):
            record(kind, None, row, i)
        buckets[plural] = bucket
    changes.sort(key=lambda r: (-SEVERITY.get(r['severity'], 0), r['kind'], r['title'], r['id']))
    findings = [c for c in changes if c['kind'] == 'finding']
    material = [c for c in findings if c['status'] not in ('unchanged', 'review_changed', 'evidence_changed')]
    changed_findings = [c for c in findings if c['before'] and c['after'] and c['status'] != 'unchanged']
    resolved = [{**c['before'], 'reason': c['reason']} for c in findings if c['status'] == 'no_longer_reported']
    revalidate = [c['after']['id'] for c in findings if c['after'] and (sources_changed or engine_changed or c['status'] != 'unchanged')]
    summary = {'findings': dict(Counter(c['status'] for c in findings)),
               'new_critical_high': sum(c['status'] == 'new' and SEVERITY.get(c['severity'], 0) >= 3 for c in findings),
               'worsened_critical_high': sum(c['status'] == 'worsened' and SEVERITY.get(c['severity'], 0) >= 3 for c in findings),
               'security_changes': sum(c['status'] in ('new', 'removed', 'changed', 'worsened', 'improved', 'no_longer_reported') for c in changes)}
    return {**buckets, 'schema_version': COMPARISON_VERSION, 'changes': changes, 'summary': summary,
        'matches': [{'before_id': a, 'after_id': b, 'method': methods[a]} for a, b in sorted(matches.items())],
        'mapping_suggestions': suggestions, 'provenance': provenance, 'engine_changed': engine_changed,
        'warnings': warnings, 'impact': impact_changes(old, new, remap),
        'architectures': {'before': old, 'after': new},
        'revision_summary': {'changed': bool(material or sources_changed or engine_changed or any(c['status'] != 'unchanged' for c in changes if c['kind'] != 'finding')),
            'new_threats': buckets['findings']['added'], 'resolved_threats': resolved, 'no_longer_reported': resolved,
            'severity_changes': [{'id': c['after']['id'], 'title': c['title'], 'from_severity': c['before'].get('severity'),
                'to_severity': c['after'].get('severity'), 'from_tier': c['before'].get('tier'), 'to_tier': c['after'].get('tier')} for c in changed_findings
                if c['before'].get('severity') != c['after'].get('severity') or c['before'].get('tier') != c['after'].get('tier')],
            'revalidation_required': revalidate, 'finding_matches': [{'before': c['before'].get('id'), 'after': c['after'].get('id')} for c in findings if c['before'] and c['after']],
            'added_components': [c.get('name', c['id']) for c in buckets['components']['added']],
            'removed_components': [c.get('name', c['id']) for c in buckets['components']['removed']],
            'score_delta': after['score'] - before['score'] if isinstance(after.get('score'), (int, float)) and isinstance(before.get('score'), (int, float)) else None,
            'score_delta_explanation': warnings + (['Source material changed; prior review decisions need revalidation.'] if sources_changed else [])},
        'notice': 'No longer reported is not verified remediation. Review source evidence, scope and analysis provenance.'}


def impact_changes(before, after, remap):
    def paths(model, side):
        nodes = {c['id']: c for c in model.get('components', [])}
        graph = nx.DiGraph()
        graph.add_nodes_from(nodes)
        for flow in model.get('flows', []):
            if flow.get('assumed') or (flow.get('properties') or {}).get('assumed'):
                continue
            if flow.get('source_id') in nodes and flow.get('target_id') in nodes:
                graph.add_edge(flow['source_id'], flow['target_id'])
        output = {}
        for cid, node in nodes.items():
            if node.get('trust_level') != 'public':
                continue
            output[f'public:{remap(cid, side)}'] = {'type': 'public_entry', 'components': [cid], 'description': f"Public entry: {node.get('name', cid)}"}
            routes = nx.single_source_shortest_path(graph, cid, cutoff=12)
            for target, route in routes.items():
                if target == cid or not any(k in normalized(nodes[target].get('type')) for k in ('database', 'storage', 'secrets')):
                    continue
                key = fingerprint([remap(cid, side), remap(target, side)])
                output[key] = {'type': 'data_reachability', 'components': route, 'description': ' -> '.join(nodes[i].get('name', i) for i in route)}
        return output
    old, new = paths(before, 'before'), paths(after, 'after')
    return {'added': [new[k] for k in sorted(new.keys() - old.keys())],
            'removed': [old[k] for k in sorted(old.keys() - new.keys())],
            'notice': 'Reachability follows stated modeled flows, up to 12 hops. It does not prove exploitability or effective cloud permissions.'}
