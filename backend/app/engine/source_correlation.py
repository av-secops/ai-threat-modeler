"""Source-scoped claims shared by architecture review and threat analysis.

Retrieval may suggest rules, but it cannot establish a deployed control. Only
compatible, cited claims can set a component property; uncertainty stays explicit.
"""

from collections import defaultdict
from bisect import bisect_right
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import re

from . import control_statements, source_index
from .flow_extraction import alias_index, find_mentions
from .control_contracts import presence, scope_matches

VERSION = 'source-correlation-3'
_PLANNED = re.compile(r'\b(?:planned|proposed|recommended|roadmap|todo|should|must|will|intend(?:s|ed)?|plan(?:s)? to)\b', re.I)
_UNKNOWN = re.compile(r'\b(?:unknown|unspecified|not documented|not specified|to be confirmed)\b', re.I)
_ENDPOINT = re.compile(r'(?<![\w:/])(/[A-Za-z0-9_{}*-]+(?:/[A-Za-z0-9_{}*-]+)*)')
_ENVIRONMENT = re.compile(r'\b(?:in|for|on)\s+(?:the\s+)?(production|prod|staging|stage|development|dev|test)(?:\s+environment)?\b', re.I)
_WORKFLOW_SCOPE = re.compile(r'\b(?:deprecated|legacy|selected|workload-specific|tenant-specific|only)\b.*\b(?:route|endpoint|webhook|workload|export|request|quota)s?\b', re.I)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def normalize_environment(value):
    folded = str(value or '').strip().lower()
    return {'prod': 'production', 'stage': 'staging', 'dev': 'development', 'unspecified': '', 'unknown': ''}.get(folded, folded)


def source_metadata(document):
    """Document revisions and deployment releases are separate concepts."""
    return {**document, 'document_version': document.get('document_version') or '',
            'deployment_version': document.get('deployment_version') or '',
            'environment': document.get('environment') or 'unspecified'}


@lru_cache(maxsize=128)
def _claims(body):
    # Cache extraction, never architecture-specific resolutions or mutable models.
    unique = {}
    for claim in control_statements.statements(body):
        if claim.control == 'rate_limiting' and re.search(r'\bconcurrency quotas?\b', claim.clause, re.I) and not re.search(r'\brate limit|throttl', claim.clause, re.I):
            continue
        state = 'present' if claim.affirmed else 'absent'
        if _PLANNED.search(claim.clause):
            state = 'planned'
        elif _UNKNOWN.search(claim.clause):
            state = 'unknown'
        for control in [claim.control, *(control_statements.IMPLIED_BY.get(claim.control, ()) if state == 'present' else ())]:
            key = (control, state, claim.clause)
            unique[key] = key
    return tuple(unique)


def _source_parts(architecture):
    metadata = architecture.metadata or {}
    text = metadata.get('source_text') or metadata.get('architecture_text') or ''
    index = source_index.build(text)
    documents = {d.get('filename'): source_metadata(d) for d in metadata.get('source_documents') or []}
    parts = defaultdict(list)
    for number, line in enumerate(text.splitlines(), 1):
        citation = index.cite(number)
        if citation and citation.line and citation.role != 'reference_report':
            parts[citation.document].append((line, citation.as_dict()))
    return parts, documents


def _citation_index(lines):
    body, offsets, citations, length = [], [], [], 0
    for line, citation in lines:
        normalized = ' '.join(line.lower().split())
        if not normalized:
            continue
        offsets.append(length)
        citations.append(citation)
        body.append(normalized)
        length += len(normalized) + 1
    return ' '.join(body), offsets, citations


def _locate(clause, lines, indexed=None):
    needle = ' '.join(clause.lower().split())
    if not needle:
        return {}
    body, offsets, citations = indexed if indexed is not None else _citation_index(lines)
    position = body.find(needle)
    return citations[bisect_right(offsets, position) - 1] if position >= 0 and citations else {}


def _scope(statement, document):
    environment = _ENVIRONMENT.search(statement)
    return {'environment': normalize_environment(environment.group(1) if environment else document.get('environment')),
            'deployment_version': str(document.get('deployment_version') or ''),
            'tenant_id': str(document.get('tenant_id') or ''),
            'cloud_account': str(document.get('cloud_account') or ''),
            **{key: deepcopy(document[key]) for key in ('region', 'cloud_region', 'cloud_provider', 'technology',
                'resource_type', 'trust_boundary', 'boundary_ids') if document.get(key)},
            'endpoints': sorted(set(_ENDPOINT.findall(statement))),
            'workflow_restricted': bool(_WORKFLOW_SCOPE.search(statement))}


def _applicable(scope, component):
    return scope_matches(scope, component.properties or {}, component_type=component.type)


def _subject(statement, control, lines, aliases):
    mentions = find_mentions(re.sub(r'[-_]+', ' ', statement), aliases)
    if mentions:
        # Prefer the explicit subject immediately before the control's predicate.
        terms = control_statements.CONTROL_TERMS.get(control, ())
        starts = [m.start() for term in terms for m in control_statements._term_pattern(term).finditer(statement)]
        before = [m for m in mentions if not starts or m[0] < min(starts)]
        chosen = before[-1] if before else mentions[0]
        return chosen[2], 'named_subject'
    # Only a dedicated heading establishes inherited context. Arbitrary preceding
    # component mentions are not sufficient to resolve an omitted subject.
    for index, (line, _) in enumerate(lines):
        if statement.strip() in line:
            for previous, _ in reversed(lines[max(0, index - 4):index]):
                if re.match(r'^\s*#{1,6}\s+|^\s*[^|:.]{2,100}:\s*$', previous):
                    found = find_mentions(re.sub(r'[-_]+', ' ', previous), aliases)
                    ids = {m[2] for m in found}
                    return (next(iter(ids)), 'section_subject') if len(ids) == 1 else (None, 'ambiguous_subject')
    return None, 'unresolved_subject'


def _resolved_state(records):
    states = {r['state'] for r in records if r.get('applicable', True)}
    if {'present', 'absent'} <= states:
        return 'conflicting'
    if 'absent' in states:
        return 'absent'
    if 'present' in states:
        return 'present'
    if 'planned' in states:
        return 'planned'
    return 'unknown'


def reconcile_claims(architecture):
    """Rebuild a reproducible evidence ledger without treating its output as input."""
    parts, documents = _source_parts(architecture)
    components = {c.id: c for c in architecture.components}
    aliases = alias_index(components)
    # Explicit reviewer aliases supplement the parser's existing alias vocabulary.
    owners = defaultdict(set)
    for component in components.values():
        for name in [component.id, component.name, *(component.properties.get('aliases') or [])]:
            owners[re.sub(r'[-_]+', ' ', str(name)).lower()].add(component.id)
    aliases = [(name, identifier) for name, identifier in aliases if name not in owners or len(owners[name]) == 1]
    aliases.extend((name, next(iter(ids))) for name, ids in owners.items() if len(ids) == 1)
    aliases.sort(key=lambda row: -len(row[0]))
    facts, unresolved = [], []
    component_sources = defaultdict(list)
    for filename, lines in parts.items():
        document = documents.get(filename, {})
        if document.get('role') == 'reference_report' or document.get('diagram_model'):
            continue
        for line, citation in lines:
            for _, _, identifier in find_mentions(re.sub(r'[-_]+', ' ', line), aliases):
                evidence = {**citation, 'source_id': document.get('source_id') or citation['source_id'],
                    'source_type': 'architecture_input', 'statement': line.strip(), 'confidence': 'High',
                    'document_version': document.get('document_version') or '',
                    'verification_status': 'not_runtime_verified', 'scope': _scope(line, document)}
                if _applicable(evidence['scope'], components[identifier]) and evidence not in component_sources[identifier]:
                    component_sources[identifier].append(evidence)
        body = '\n'.join(line for line, _ in lines)
        citations = _citation_index(lines)
        extracted = _claims(body) if len(body) <= 32000 else _claims.__wrapped__(body)
        for control, state, statement in extracted:
            citation = _locate(statement, lines, citations)
            scope = _scope(statement, document)
            fact = {**citation, 'source_id': document.get('source_id') or citation.get('source_id') or fingerprint(filename)[:20],
                    'document': filename, 'document_version': document.get('document_version') or '',
                    'source_type': 'architecture_input', 'evidence_scope': 'control',
                    'kind': 'control', 'control': control, 'state': state, 'statement': statement,
                    'scope': scope, 'verification_status': 'not_runtime_verified', 'basis': 'source_statement'}
            fact['id'] = 'claim:' + fingerprint(fact)[:24]
            fact['element_id'], fact['resolution'] = _subject(statement, control, lines, aliases)
            if not fact['element_id']:
                unresolved.append(fact)
            else:
                fact['applicable'] = _applicable(scope, components[fact['element_id']])
                fact['scope_status'] = 'endpoint_only' if scope['endpoints'] or scope['workflow_restricted'] else 'matching' if fact['applicable'] else 'scope_unconfirmed'
            facts.append(fact)

    by_component = defaultdict(list)
    for fact in facts:
        if fact['element_id']:
            by_component[fact['element_id']].append(fact)
    conflicts = []
    managed = {f['control'] for f in facts}
    for identifier, component in components.items():
        props = component.properties
        if component_sources[identifier]:
            existing = [e for e in component.evidence or [] if e.get('source_type') != 'inference']
            for evidence in component_sources[identifier]:
                if evidence not in existing:
                    existing.append(evidence)
            component.evidence = existing
            props['evidence_status'] = 'explicit'
            component.confidence = 'High'
        direct_config = bool(props.get('iac_source') or props.get('resource_type') or props.get('source_file'))
        if direct_config:
            props.setdefault('configuration_control_values', {key: value for key, value in props.items()
                if key in control_statements.CONTROL_TERMS and isinstance(value, bool)})
        component_claims = by_component[identifier]
        # Reconciliation must not propagate a planned/scoped claim credited by
        # the older prose parser to unrelated components.
        grouped = defaultdict(list)
        for fact in component_claims:
            grouped[fact['control']].append(fact)
        previous = props.get('control_evidence') or {}
        for control in managed:
            records = grouped[control]
            owner_records = [r for r in previous.get(control, []) if r.get('source_ref') == 'reviewer_clarification'
                and r.get('applicable') is not False and _applicable(r.get('scope') or {}, component)]
            configured = props.get('configuration_control_values', {}).get(control)
            if direct_config and isinstance(configured, bool):
                records = [*records, {'state': 'present' if configured else 'absent',
                    'statement': f'{control} = {configured} in the submitted resource configuration.',
                    'basis': 'submitted_configuration', 'scope': {}, 'applicable': True,
                    'element_id': identifier, 'control': control, 'document': props.get('source_file') or props.get('source_document'),
                    'verification_status': 'not_runtime_verified'}]
            broad = [r for r in records if r.get('applicable', True) and not r.get('scope', {}).get('endpoints') and not r.get('scope', {}).get('workflow_restricted')]
            broad.extend(owner_records)
            state = _resolved_state(broad)
            scoped = [r for r in records if r.get('applicable') and (r.get('scope', {}).get('endpoints') or r.get('scope', {}).get('workflow_restricted'))]
            if state == 'unknown' and scoped:
                state = 'partial'
            # A general claim cannot erase an explicitly documented exception.
            # Contradictions on one endpoint do not establish global absence.
            scoped_groups = defaultdict(list)
            for record in scoped:
                scoped_groups[fingerprint(record.get('scope', {}))].append(record)
            scoped_conflicts = [group for group in scoped_groups.values() if _resolved_state(group) == 'conflicting']
            if scoped_conflicts or (state in {'present', 'absent'} and any(
                    r['state'] in {'present', 'absent'} and r['state'] != state for r in scoped)):
                state = 'partial'
            for group in scoped_conflicts:
                conflicts.append({'element_id': identifier, 'control': control, 'state': 'conflicting',
                    'scope': deepcopy(group[0]['scope']), 'claim_ids': [r['id'] for r in group if 'id' in r]})
            if not broad and not records and not props.get('control_evidence', {}).get(control):
                # Do not erase independent structured control fields.
                if props.get('authoritative') and control not in props.get('correlated_controls', {}):
                    continue
            if state in {'present', 'absent'}:
                props[control] = state == 'present'
            else:
                props.pop(control, None)
            props['explicit_negations'] = [key for key in props.get('explicit_negations', []) if key != control]
            if state == 'absent':
                props['explicit_negations'].append(control)
            props.setdefault('control_assertions', {})[control] = state
            props.setdefault('control_evidence', {})[control] = deepcopy(broad)
            props.setdefault('correlated_controls', {})[control] = {'state': state,
                'claim_ids': [r['id'] for r in records if 'id' in r], 'scoped_claims': deepcopy(scoped)}
            if state == 'conflicting':
                conflicts.append({'element_id': identifier, 'control': control, 'state': state,
                    'claim_ids': [r['id'] for r in broad if 'id' in r]})
        props['correlation_evidence'] = deepcopy(component_claims)
        # A stale parser weakness is not proof when the reconciled claim is
        # planned, contradictory, or limited to a different deployment.
        props['stated_weaknesses'] = [w for w in props.get('stated_weaknesses', [])
            if not any(f['statement'].strip() == w.get('statement', '').strip() and
                (not f.get('applicable') or f['state'] not in {'absent'} or
                 props.get('correlated_controls', {}).get(f['control'], {}).get('state') == 'conflicting')
                for f in component_claims)]

    # Diagram nodes and arrows use the same model; retain explicit/inferred basis.
    for component in components.values():
        for evidence in component.evidence or []:
            facts.append({'id': 'component:' + fingerprint([component.id, evidence])[:24],
                'element_id': component.id, 'kind': 'component', **deepcopy(evidence),
                'basis': 'owner_correction' if component.properties.get('reviewer_declared') else 'source_statement' if component.properties.get('evidence_status') == 'explicit' else 'inferred'})
    flow_gaps = []
    for flow in architecture.flows:
        assumed = flow.assumed or presence(flow.properties.get('assumed')) is True
        identifier = flow.id or flow.properties.get('review_id') or f'flow:{flow.source_id}->{flow.target_id}'
        for evidence in flow.evidence or []:
            facts.append({'id': 'flow:' + fingerprint([identifier, evidence])[:24],
                'element_id': identifier, 'kind': 'flow', **deepcopy(evidence),
                'source_component': flow.source_id, 'target_component': flow.target_id,
                'protocol': flow.protocol, 'data_type': flow.data_type,
                'basis': 'inferred' if assumed else 'owner_correction' if flow.properties.get('reviewer_declared') else 'source_statement'})
        if assumed or not flow.evidence or flow.protocol.lower() == 'unknown':
            flow_gaps.append({'element_id': identifier, 'assumed': assumed,
                'missing': [key for key, missing in [('source_evidence', not flow.evidence), ('protocol', flow.protocol.lower() == 'unknown'), ('confirmed_path', assumed)] if missing]})
    result = {'version': VERSION, 'facts': facts, 'unresolved_claims': unresolved,
              'conflicts': conflicts, 'flow_gaps': flow_gaps,
              'ambiguous_aliases': [{'alias': name, 'component_ids': sorted(ids)} for name, ids in owners.items() if len(ids) > 1],
              'verification_status': 'not_runtime_verified'}
    architecture.metadata = {**(architecture.metadata or {}), 'source_correlation': result}
    return result


def control_dependency_digest(architecture, element_id, control):
    """Invalidate an answer when its target or relevant evidence changes, not a label."""
    target = next((c for c in architecture.components if c.id == element_id), None)
    if target:
        identity = [target.id, target.type, target.trust_level,
                    {key: target.properties.get(key) for key in ('environment', 'cloud_account', 'tenant_id', 'deployment_version',
                        'technology', 'technologies', 'cloud_provider', 'region', 'cloud_region', 'trust_boundary', 'canonical_boundaries')},
                    sorted((f.source_id, f.target_id, f.protocol, f.data_type, f.assumed or presence(f.properties.get('assumed')) is True)
                        for f in architecture.flows if element_id in {f.source_id, f.target_id})]
        facts = [f for f in target.properties.get('correlation_evidence', []) if f.get('control') == control]
        return fingerprint([identity, facts, target.properties.get(control)])
    flow = next((f for f in architecture.flows if f.properties.get('review_id') == element_id), None)
    return fingerprint(flow.model_dump() if flow else ['missing', element_id])
