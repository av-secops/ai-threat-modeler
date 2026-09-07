"""Source-scoped claims shared by architecture review and threat analysis.

Retrieval may suggest rules, but it cannot establish a deployed control. Only
compatible, cited claims can set a component property; uncertainty stays explicit.
"""

from collections import defaultdict
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import re

from . import control_statements, source_index
from .flow_extraction import alias_index, find_mentions

VERSION = 'source-correlation-1'
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


def _locate(clause, lines):
    needle = ' '.join(clause.lower().split())
    for offset, (line, citation) in enumerate(lines):
        if needle in ' '.join(' '.join(item[0] for item in lines[offset:offset + 12]).lower().split()):
            # Prefer the actual starting line over an earlier nearby paragraph.
            if needle[:min(24, len(needle))] in ' '.join(line.lower().split()):
                return citation
    return next((cite for line, cite in lines if needle in ' '.join(line.lower().split())), {})


def _scope(statement, document):
    environment = _ENVIRONMENT.search(statement)
    return {'environment': normalize_environment(environment.group(1) if environment else document.get('environment')),
            'deployment_version': str(document.get('deployment_version') or ''),
            'tenant_id': str(document.get('tenant_id') or ''),
            'cloud_account': str(document.get('cloud_account') or ''),
            'endpoints': sorted(set(_ENDPOINT.findall(statement))),
            'workflow_restricted': bool(_WORKFLOW_SCOPE.search(statement))}


def _applicable(scope, component):
    props = component.properties or {}
    for key in ('environment', 'deployment_version', 'tenant_id', 'cloud_account'):
        actual = normalize_environment(props.get(key)) if key == 'environment' else str(props.get(key) or '')
        if scope.get(key) and scope[key] != actual:
            return False
    return True


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
        if document.get('role') == 'reference_report':
            continue
        for line, citation in lines:
            for _, _, identifier in find_mentions(re.sub(r'[-_]+', ' ', line), aliases):
                evidence = {**citation, 'source_id': document.get('source_id') or citation['source_id'],
                    'source_type': 'architecture_input', 'statement': line.strip(), 'confidence': 'High',
                    'document_version': document.get('document_version') or '',
                    'verification_status': 'not_runtime_verified', 'scope': _scope(line, document)}
                if evidence not in component_sources[identifier]:
                    component_sources[identifier].append(evidence)
        body = '\n'.join(line for line, _ in lines)
        extracted = _claims(body) if len(body) <= 32000 else _claims.__wrapped__(body)
        for control, state, statement in extracted:
            normalized = re.sub(r'[-_]+', ' ', statement)
            mentions = find_mentions(normalized, aliases)
            citation = _locate(statement, lines)
            scope = _scope(statement, document)
            fact = {**citation, 'source_id': document.get('source_id') or citation.get('source_id') or fingerprint(filename)[:20],
                    'document': filename, 'document_version': document.get('document_version') or '',
                    'kind': 'control', 'control': control, 'state': state, 'statement': statement,
                    'scope': scope, 'verification_status': 'not_runtime_verified', 'basis': 'source_statement'}
            fact['id'] = 'claim:' + fingerprint(fact)[:24]
            fact['element_id'] = mentions[0][2] if mentions else None
            fact['resolution'] = 'named_subject' if mentions else 'unresolved_subject'
            if not mentions:
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
        managed = {f['control'] for f in facts if f['element_id'] or len(parts) > 1}
        grouped = defaultdict(list)
        for fact in component_claims:
            grouped[fact['control']].append(fact)
        previous = props.get('control_evidence') or {}
        for control in managed:
            records = grouped[control]
            owner_records = [r for r in previous.get(control, []) if r.get('source_ref') == 'reviewer_clarification']
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
        identifier = flow.properties.get('review_id') or f'flow:{flow.source_id}->{flow.target_id}'
        for evidence in flow.evidence or []:
            facts.append({'id': 'flow:' + fingerprint([identifier, evidence])[:24],
                'element_id': identifier, 'kind': 'flow', **deepcopy(evidence),
                'source_component': flow.source_id, 'target_component': flow.target_id,
                'protocol': flow.protocol, 'data_type': flow.data_type,
                'basis': 'inferred' if flow.assumed else 'owner_correction' if flow.properties.get('reviewer_declared') else 'source_statement'})
        if flow.assumed or not flow.evidence or flow.protocol.lower() == 'unknown':
            flow_gaps.append({'element_id': identifier, 'assumed': flow.assumed,
                'missing': [key for key, missing in [('source_evidence', not flow.evidence), ('protocol', flow.protocol.lower() == 'unknown'), ('confirmed_path', flow.assumed)] if missing]})
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
                    {key: target.properties.get(key) for key in ('environment', 'cloud_account', 'tenant_id', 'deployment_version')},
                    sorted((f.source_id, f.target_id, f.protocol, f.data_type) for f in architecture.flows if element_id in {f.source_id, f.target_id})]
        facts = [f for f in target.properties.get('correlation_evidence', []) if f.get('control') == control]
        return fingerprint([identity, facts, target.properties.get(control)])
    flow = next((f for f in architecture.flows if f.properties.get('review_id') == element_id), None)
    return fingerprint(flow.model_dump() if flow else ['missing', element_id])
