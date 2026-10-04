"""Final-output accounting shared by original and refreshed reports."""

from collections import Counter
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def attach_output_contract(result):
    status = result.engine_status
    from .diagram_quality import diagram_quality
    quality = diagram_quality(result.architecture)
    status['diagram_quality'] = quality
    if not quality['score_available']:
        result.score = None
        result.summary = ('Architecture extraction requires review. Findings are provisional; '
            'an absence of findings is not an assessment of security. Review the original image, '
            'component identities and connector directions before publishing a final report.')
        result.risk_methodology = {**(result.risk_methodology or {}), 'score_status': 'unavailable_incomplete_architecture'}
        gate = status.setdefault('quality_gate', {})
        gate.update(status='blocked', publication_status='blocked', extraction_status='incomplete')
        gate['integrity_violations'] = [r for r in gate.get('integrity_violations', []) if r.get('check') != 'diagram_extraction'] + [
            {'check': 'diagram_extraction', 'count': len(quality['reasons']), 'detail': 'Architecture extraction incomplete. ' + ' '.join(quality['reasons'])}]
    threats = result.threats
    ids = {t.id for t in threats}
    components = {c.id for c in result.architecture.components}
    names = {c.id: c.name for c in result.architecture.components}
    flows = {flow.id: flow for flow in result.architecture.flows if flow.id}
    issues = []
    for identifier, count in Counter(t.id for t in threats).items():
        if count > 1:
            issues.append({'type': 'duplicate_finding_id', 'id': identifier})
    for threat in threats:
        threat.explanation = {**(threat.explanation or {}), 'impacted_components':
            [names.get(identifier, identifier) for identifier in threat.affected_components]}
        references = set(threat.affected_components) | {threat.component, threat.component_id, threat.affected_component}
        for identifier in references - components - {None, ''}:
            issues.append({'type': 'unknown_finding_component', 'finding_id': threat.id, 'id': identifier})
        for reference in threat.affected_flow_refs:
            flow = flows.get(reference.get('id'))
            if flow is None or (reference.get('number') and reference['number'] != flow.flow_number):
                issues.append({'type': 'invalid_finding_flow_reference', 'finding_id': threat.id, 'id': reference.get('id')})
    for cell in (result.stride_coverage or {}).get('cells', []):
        for identifier in set(cell.get('finding_ids', [])) - ids:
            issues.append({'type': 'dangling_coverage_finding', 'id': identifier})
    for row in status.get('issue_inventory', {}).get('issues', []):
        for identifier in set(row.get('finding_ids', [])) - ids:
            issues.append({'type': 'dangling_issue_finding', 'id': identifier})

    survivors = {identifier: t.id for t in threats for identifier in
        [t.id, *((t.explanation or {}).get('merged_finding_ids') or [])]}
    knowledge = status.get('knowledge_base', {})
    for decision in knowledge.get('candidate_decisions', []):
        original = decision.get('finding_ids', [])
        decision['final_finding_ids'] = sorted({survivors[i] for i in original if i in survivors})
        if original:
            decision['final_disposition'] = 'retained_or_merged' if decision['final_finding_ids'] else 'not_in_final_report'
    knowledge['status'] = 'degraded' if knowledge.get('validation_issues') or knowledge.get('unsupported_predicate_rules') else knowledge.get('status', 'active')
    status['output_contract'] = {'version': 'analysis-quality-1', 'valid': not issues,
        'issues': issues, 'finding_count': len(threats),
        'confirmed_by_severity': dict(Counter(t.severity for t in threats if t.tier == 'Confirmed')),
        'potential_by_severity': dict(Counter(t.severity for t in threats if t.tier != 'Confirmed')),
        'runtime_verified': False}
    status['analysis_manifest'] = {'contract_version': 'analysis-quality-1',
        'architecture_digest': digest(result.architecture.model_dump()),
        'knowledge_digest': knowledge.get('content_digest'),
        'local_models': status.get('local_models', {}),
        'semantic_output_digest': digest(sorted((t.model_dump() for t in threats), key=lambda t: t['id'])),
        'independent_acceptance': 'not_established_by_this_run'}
    if issues:
        gate = status.setdefault('quality_gate', {})
        gate.update(status='blocked', publication_status='blocked', model_integrity='violated')
        gate['output_integrity_issues'] = issues
        gate['integrity_violations'] = [row for row in gate.get('integrity_violations', []) if row.get('check') != 'output_integrity'] + [
            {'check': 'output_integrity', 'count': len(issues), 'detail': 'Final finding references or identifiers are inconsistent. Review output integrity diagnostics.'}]
    metadata = result.architecture.metadata or {}
    if metadata.get('iac_coverage'):
        status['iac_coverage'] = metadata['iac_coverage']
    if metadata.get('iac_parse_failures'):
        failures = metadata['iac_parse_failures']
        status['iac_input_failures'] = failures
        gate = status.setdefault('quality_gate', {})
        gate['completeness_warnings'] = [row for row in gate.get('completeness_warnings', []) if row.get('check') != 'unparsed_iac'] + [
            {'check': 'unparsed_iac', 'count': len(failures), 'detail': 'An uploaded infrastructure artifact could not be evaluated. This is a partial report; inspect IaC input failures.'}]
        if gate.get('status') != 'blocked':
            gate.update(status='review', publication_status='review')
    return result
