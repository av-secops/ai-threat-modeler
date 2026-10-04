"""Validate control/evidence compatibility without treating citations as runtime proof."""

from .control_statements import non_assertion
from .issue_inventory import dispositions
from .control_contracts import CONTROL_ALIASES, control_effectiveness
from .source_correlation import _applicable
from .reasoning_contracts import coverage_assurance, finalize_path_assurance, remediation_contract


def _statement_key(statement):
    return ' '.join(str(statement or '').lower().split()).strip(' .;')


def _declaration_index(architecture):
    """Index source weaknesses separately from boolean control observations.

    A source can explicitly describe SQL concatenation or credential disclosure
    without supplying a boolean for each related mitigation. Preserve that fact,
    but do not manufacture absent controls from it.
    """
    from . import source_index
    from .known_issue_taxonomy import CONTROL_PROPERTIES
    from .source_correlation import _scope

    metadata = architecture.metadata or {}
    index = source_index.build(metadata.get('source_text') or metadata.get('architecture_text') or '')
    documents = {document.get('filename'): document for document in metadata.get('source_documents') or []
        if isinstance(document, dict)}
    declarations = {}

    def add(statement, component_id, control, rule_id, record):
        if not statement or not component_id or not control:
            return
        citation = index.find(statement)
        scope = _scope(statement, documents.get(citation.document, {}) if citation else {})
        if 'scope' in record:
            if not isinstance(record['scope'], dict):
                return
            scope.update(record['scope'])
        controls = {CONTROL_ALIASES.get(name, name) for name in CONTROL_PROPERTIES.get(control, (control,))}
        declarations.setdefault(_statement_key(statement), []).append({
            'component_id': component_id, 'controls': controls, 'rule_id': rule_id, 'scope': scope,
            'statement': statement, 'applicable': record.get('applicable') is not False,
            'state': record.get('state'), 'basis': 'explicit_source_weakness'})

    for component in architecture.components:
        for record in component.properties.get('stated_weaknesses') or []:
            if isinstance(record, dict):
                add(record.get('statement'), component.id, record.get('control'), record.get('rule_id'), record)
    for record in metadata.get('known_issues') or []:
        if not isinstance(record, dict):
            continue
        for component_id in record.get('component_hints') or []:
            add(record.get('description'), component_id, record.get('control'), record.get('suggested_threat_id'), record)
    return declarations


def _declared_support(threat, component, control, declarations):
    properties = component.properties
    correlated = properties.get('correlated_controls', {}).get(control, {}).get('state')
    asserted = properties.get('control_assertions', {}).get(control)
    if correlated in {'planned', 'partial', 'conflicting'} or asserted in {'planned', 'partial', 'conflicting'}:
        return None
    for evidence in threat.evidence_details:
        if evidence.get('source_type') != 'architecture_input' or evidence.get('applicable') is False:
            continue
        statement = evidence.get('statement')
        if not statement or non_assertion(statement) or not _applicable(evidence.get('scope', {}), component):
            continue
        for declaration in declarations.get(_statement_key(statement), []):
            if (declaration['component_id'] != component.id or control not in declaration['controls']
                    or not declaration['applicable'] or not _applicable(declaration['scope'], component)
                    or declaration['state'] in {'planned', 'partial', 'conflicting', 'unknown'}):
                continue
            if evidence.get('stated_weakness_rule') and evidence['stated_weakness_rule'] != declaration['rule_id']:
                continue
            return {key: declaration[key] for key in ('component_id', 'rule_id', 'scope', 'statement', 'basis')}
    return None


def _expected_state(threat, control, control_values):
    if control in control_values:
        return 'present' if control_values[control] is True else 'absent'
    # This taxonomy rule describes an unsafe present property, not a missing
    # defense. Related private-subnet remediation remains an absence check.
    if control == 'public_access' and threat.id.startswith('GENERIC-PUBLIC-EXPOSURE-001'):
        return 'present'
    return 'absent'


def validate_evidence(threats, architecture):
    components = {c.id: c for c in architecture.components}
    declarations = _declaration_index(architecture)
    for threat in threats:
        explanation = dict(threat.explanation or {})
        controls = list(dict.fromkeys(CONTROL_ALIASES.get(control, control)
            for control in explanation.get('matched_controls') or []))
        control_values = {CONTROL_ALIASES.get(control, control): value
            for control, value in (explanation.get('matched_control_values') or {}).items()}
        reasons, trace, source_support = [], [], []
        identifiers = set(threat.affected_components or []) | {value for value in
            (threat.component, threat.component_id, threat.affected_component) if value}
        for identifier in sorted(identifiers):
            component = components.get(identifier)
            if not component:
                continue
            if component.properties.get('diagram_review_required'):
                reasons.append(f'{component.name} is an unreviewed image candidate; its identity is not established.')
            if component.id.startswith(('diagram:ocr:', 'diagram:visual:')) and controls:
                for control in controls:
                    expected = _expected_state(threat, control, control_values)
                    records = [*component.properties.get('control_evidence', {}).get(control, []),
                        *[e for e in component.properties.get('correlation_evidence', []) if e.get('applicable')]]
                    scoped = [e for e in [*records, *threat.evidence_details] if e.get('control') == control
                        and e.get('evidence_scope') != 'topology' and e.get('state') == expected
                        and e.get('applicable') is not False and _applicable(e.get('scope') or {}, component)]
                    independent = [e for e in threat.evidence_details if e.get('source_type') in {'code', 'iac', 'static_analysis'}
                        and e.get('applicable') is not False and _applicable(e.get('scope') or {}, component)]
                    if not scoped and not independent:
                        reasons.append(f'{component.name}/{control}: no control-specific {expected} evidence; a diagram label is not a control assertion.')
            for control in controls:
                effectiveness = control_effectiveness(component, control, scope=explanation.get('control_scope'))
                state = effectiveness['state']
                trace.append({'component': identifier, **effectiveness})
                expected = _expected_state(threat, control, control_values)
                if state != expected:
                    support = _declared_support(threat, component, control, declarations) if (
                        state == 'unknown' and effectiveness['applicable']) else None
                    if support:
                        source_support.append({**support, 'control': control})
                    else:
                        reasons.append(f'{identifier}/{control} is {state}; the required {expected} state is not established for this scope.')
        statements = [str(e.get('statement') or '') for e in threat.evidence_details if e.get('statement')]
        if statements and all(non_assertion(statement) for statement in statements):
            reasons.append('Cited text compares controls but does not assert a deployment weakness.')
        if reasons and threat.tier == 'Confirmed':
            threat.tier = 'Potential'
            threat.finding_type = 'validation_question'
            threat.confidence = 'Low'
            threat.confidence_score = min(threat.confidence_score or .5, .5)
            explanation['control_state'] = 'unknown'
            explanation['evidence_basis'] = 'requires_review'
            if not threat.title.startswith('Validate evidence: '):
                threat.title = 'Validate evidence: ' + threat.title
            threat.description = 'The submitted evidence does not establish this weakness. ' + ' '.join(sorted(set(reasons)))
        explanation['evidence_validation'] = {'status': 'requires_review' if reasons else 'compatible',
            'reasons': sorted(set(reasons)), 'controls': trace, 'source_weakness_support': source_support, 'runtime_verified': False}
        explanation['remediation_validation'] = remediation_contract(threat, components)
        threat.explanation = explanation
    return threats


def attach_assurance(result):
    result.engine_status = result.engine_status or {}
    finalize_path_assurance(result)
    result.engine_status['policy_evaluations'] = _policy_evaluations(result.architecture)
    inventory = dispositions(result.architecture, result.threats)
    result.engine_status['issue_inventory'] = inventory
    result.engine_status['evidence_validation'] = {
        'requires_review': sum((t.explanation or {}).get('evidence_validation', {}).get('status') == 'requires_review' for t in result.threats),
        'runtime_verified': False,
    }
    result.engine_status['reasoning_assurance'] = coverage_assurance(result)
    components = {c.id: c for c in result.architecture.components}
    for threat in result.threats:
        threat.explanation = {**(threat.explanation or {}),
            'remediation_validation': remediation_contract(threat, components)}
    if inventory['unaccounted']:
        gate = result.engine_status.setdefault('quality_gate', {})
        gate['unaccounted_source_issues'] = inventory['unaccounted']
        gate['source_issue_review_required'] = True
        warning = {'check': 'unaccounted_source_issues', 'count': inventory['unaccounted'],
            'detail': 'Declared source issues remain without a scoped finding. Inspect the source issue inventory.'}
        gate['completeness_warnings'] = [w for w in gate.get('completeness_warnings', []) if w.get('check') != warning['check']] + [warning]
        if gate.get('status') != 'blocked':
            gate['status'] = gate['publication_status'] = 'review'
    from .analysis_contracts import attach_output_contract
    return attach_output_contract(result)


def _policy_evaluations(architecture):
    from .policy_semantics import evaluate_access

    evaluations = []
    for component in architecture.components:
        if 'access_queries' not in component.properties:
            continue
        queries = component.properties['access_queries']
        if not isinstance(queries, list):
            evaluations.append({'component': component.id, 'request': {}, 'decision': 'unknown',
                'matched_statements': [], 'limits': ['access_queries must be a list of policy requests'],
                'runtime_verified': False})
            continue
        for query in queries[:50]:
            request = {key: query.get(key) for key in ('principal', 'action', 'resource')} if isinstance(query, dict) else {}
            evaluations.append({'component': component.id, 'request': request, **evaluate_access(query)})
        if len(queries) > 50:
            evaluations.append({'component': component.id, 'request': {}, 'decision': 'unknown',
                'matched_statements': [], 'limits': ['Additional requests exceed the per-component evaluation limit'],
                'unevaluated_requests': len(queries) - 50, 'runtime_verified': False})
    return evaluations
