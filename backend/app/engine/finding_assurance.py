"""Validate control/evidence compatibility without treating citations as runtime proof."""

from .control_statements import non_assertion
from .issue_inventory import dispositions


def validate_evidence(threats, architecture):
    components = {c.id: c for c in architecture.components}
    for threat in threats:
        explanation = dict(threat.explanation or {})
        controls = explanation.get('matched_controls') or []
        reasons, trace = [], []
        for identifier in threat.affected_components:
            component = components.get(identifier)
            if not component:
                continue
            for control in controls:
                state = component.properties.get('correlated_controls', {}).get(control, {}).get('state', 'unknown')
                trace.append({'component': identifier, 'control': control, 'state': state})
                if state in {'present', 'planned', 'conflicting'}:
                    statements = {e.get('statement') for e in threat.evidence_details}
                    scoped_absence = any(r.get('control') == control and r.get('state') == 'absent' and r.get('applicable') and r.get('statement') in statements
                        for r in component.properties.get('correlation_evidence', []))
                    if not scoped_absence:
                        reasons.append(f'{identifier}/{control} is {state}; absence is not established for this scope.')
        statements = [str(e.get('statement') or '') for e in threat.evidence_details if e.get('statement')]
        if statements and all(non_assertion(statement) for statement in statements):
            reasons.append('Cited text compares controls but does not assert a deployment weakness.')
        if reasons and threat.tier == 'Confirmed':
            threat.tier = 'Potential'
            threat.finding_type = 'validation_question'
            threat.confidence = 'Low'
        explanation['evidence_validation'] = {'status': 'requires_review' if reasons else 'compatible',
            'reasons': sorted(set(reasons)), 'controls': trace, 'runtime_verified': False}
        threat.explanation = explanation
    return threats


def attach_assurance(result):
    from .policy_semantics import evaluate_access
    result.engine_status['policy_evaluations'] = [
        {'component': c.id, 'request': {k: q.get(k) for k in ('principal', 'action', 'resource')}, **evaluate_access(q)}
        for c in result.architecture.components for q in c.properties.get('access_queries', [])[:50] if isinstance(q, dict)]
    inventory = dispositions(result.architecture, result.threats)
    result.engine_status['issue_inventory'] = inventory
    result.engine_status['evidence_validation'] = {
        'requires_review': sum((t.explanation or {}).get('evidence_validation', {}).get('status') == 'requires_review' for t in result.threats),
        'runtime_verified': False,
    }
    if inventory['unaccounted']:
        gate = result.engine_status.setdefault('quality_gate', {})
        gate['unaccounted_source_issues'] = inventory['unaccounted']
        gate['source_issue_review_required'] = True
        warning = {'check': 'unaccounted_source_issues', 'count': inventory['unaccounted'],
            'detail': 'Declared source issues remain without a scoped finding. Inspect the source issue inventory.'}
        gate['completeness_warnings'] = [w for w in gate.get('completeness_warnings', []) if w.get('check') != warning['check']] + [warning]
        if gate.get('status') != 'blocked':
            gate['status'] = gate['publication_status'] = 'review'
    return result
