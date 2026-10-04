"""Reasoning regressions; these fixtures are not an independent accuracy benchmark."""

from copy import deepcopy

import pytest

from app.models import AnalysisResult, Component, DataFlow, SystemArchitecture, Threat
from app.engine.attack_path_engine import generate_attack_paths, _permission_state
from app.engine.control_contracts import control_effectiveness, control_value, scope_matches
from app.engine.finding_assurance import attach_assurance, validate_evidence
from app.engine.policy_semantics import evaluate_access
from app.engine.reasoning_contracts import coverage_assurance, finalize_path_assurance, remediation_contract
from app.engine.source_correlation import _citation_index, _locate, reconcile_claims, control_dependency_digest


def component(identifier='orders', **properties):
    return Component(id=identifier, name=f'{identifier.title()} API', type='API', properties=properties)


def finding(**changes):
    return Threat(**{'id': 'risk-1', 'title': 'Missing query binding', 'category': 'Tampering',
        'severity': 'High', 'description': 'Query binding is absent.', 'mitigation': 'Bind query parameters.',
        'tier': 'Confirmed', 'component': 'orders', 'affected_components': ['orders'],
        'explanation': {'matched_controls': ['parameterized_queries']}, **changes})


def report(model, risks=None, **changes):
    return AnalysisResult(project_name='Reasoning fixture', summary='Analysis complete and 1 modeled attack paths.',
        threats=risks or [], architecture=model, score=50, engine_status={}, **changes)


@pytest.mark.parametrize('dimension,actual,expected', [
    ('environment', 'production', 'staging'), ('deployment_version', '26.2', '26.1'),
    ('tenant_id', 'tenant-a', 'tenant-b'), ('cloud_account', 'account-a', 'account-b'),
    ('region', 'eu-west-1', 'us-east-1'), ('technology', 'Node.js', 'Go'),
    ('resource_type', 'aws_s3_bucket', 'aws_db_instance'),
    ('trust_boundary', 'private-subnet', 'public-subnet'),
    ('boundary_ids', ['account-a', 'private-subnet'], ['account-b', 'private-subnet']),
])
def test_control_scope_mismatch_cannot_credit_a_control(dimension, actual, expected):
    target = component(**{dimension: actual, 'parameterized_queries': True,
        'control_evidence': {'parameterized_queries': [{'state': 'present', 'scope': {dimension: expected}}]}})
    assert control_value(target.properties, 'parameterized_queries') == 'unknown'
    assert control_effectiveness(target, 'parameterized_queries')['state'] == 'unknown'
    assert not scope_matches({dimension: expected}, {})


def test_environment_alias_and_boundary_conjunction():
    assert scope_matches({'environment': 'prod', 'boundary_ids': ['vpc', 'private']},
        {'environment': 'production', 'canonical_boundaries': ['vpc', 'private', 'aws']})
    assert not scope_matches({'boundary_ids': ['vpc', 'other']}, {'canonical_boundaries': ['vpc', 'private']})
    assert not scope_matches({'tenant_id': 'Acme'}, {'tenant_id': 'acme'})


def test_present_component_control_cannot_override_requested_scope_mismatch():
    target = component(environment='production', rate_limiting=True,
        control_evidence={'rate_limiting': [{'state': 'present', 'scope': {'environment': 'production'}}]})
    assessed = control_effectiveness(target, 'rate_limiting', scope={'environment': 'staging'})
    assert assessed['state'] == 'unknown'
    assert not assessed['effective_for_claim']


def test_citing_only_one_side_of_a_conflict_does_not_confirm_absence():
    absent = {'control': 'parameterized_queries', 'state': 'absent', 'applicable': True,
        'statement': 'Orders API has no parameterized queries.'}
    target = component(correlated_controls={'parameterized_queries': {'state': 'conflicting'}},
        control_evidence={'parameterized_queries': [absent]}, correlation_evidence=[absent])
    risk = finding(evidence_details=[absent])
    validate_evidence([risk], SystemArchitecture(components=[target], flows=[]))
    assert risk.tier == 'Potential'


@pytest.mark.parametrize('required', ['parameterized_queries', 'object_level_auth', 'mfa_enabled'])
def test_waf_cannot_substitute_for_application_controls(required):
    result = control_effectiveness(component(waf_enabled=True), 'waf_enabled', required_control=required)
    assert result['state'] == 'present'
    assert not result['effective_for_claim'] and not result['runtime_verified']


@pytest.mark.parametrize('state', ['planned', 'partial', 'unknown', 'conflicting'])
def test_uncertain_control_state_never_confirms_a_missing_control(state):
    target = component(parameterized_queries=False,
        correlated_controls={'parameterized_queries': {'state': state}})
    risk = finding()
    validate_evidence([risk], SystemArchitecture(components=[target], flows=[]))
    assert risk.tier == 'Potential'
    assert risk.explanation['evidence_validation']['status'] == 'requires_review'


def test_prompt_silence_is_unknown_not_confirmed_absence():
    risk = finding()
    validate_evidence([risk], SystemArchitecture(components=[component(waf_enabled=True)], flows=[]))
    assert risk.tier == 'Potential'
    assert risk.explanation['control_state'] == 'unknown'


@pytest.mark.parametrize('value', ['planned', 'unknown', '${var.control}', 'partially implemented'])
def test_uncertain_control_value_cannot_be_overridden_by_stale_negation(value):
    assert control_value({'rate_limiting': value, 'explicit_negations': ['rate_limiting']}, 'rate_limiting') == 'unknown'


def test_explicit_control_absence_survives_assurance():
    risk = finding()
    validate_evidence([risk], SystemArchitecture(components=[component(parameterized_queries=False)], flows=[]))
    assert risk.tier == 'Confirmed'
    assert risk.explanation['evidence_validation']['status'] == 'compatible'


def declared_authorization_model():
    statement = 'Orders API has no access control for consumer groups.'
    record = {'rule_id': 'GENERIC-MISSING-AUTHORIZATION-001', 'control': 'authorization_enforcement',
        'statement': statement}
    target = component(environment='production', stated_weaknesses=[record])
    risk = finding(explanation={'matched_controls': ['rbac_enabled']}, evidence_details=[{
        'source_type': 'architecture_input', 'source_ref': 'orders', 'statement': statement,
        'stated_weakness_rule': record['rule_id']}])
    return SystemArchitecture(components=[target], flows=[], metadata={'source_text': statement}), risk


@pytest.mark.parametrize('source_kind', ['stated_weakness', 'known_issue'])
def test_scoped_source_weakness_matches_control_vocabulary_without_inventing_absence(source_kind):
    model, risk = declared_authorization_model()
    if source_kind == 'known_issue':
        declaration = model.components[0].properties.pop('stated_weaknesses')[0]
        model.metadata['known_issues'] = [{'description': declaration['statement'],
            'control': declaration['control'], 'suggested_threat_id': declaration['rule_id'],
            'component_hints': ['orders']}]
    validate_evidence([risk], model)
    assert risk.tier == 'Confirmed'
    assurance = risk.explanation['evidence_validation']
    assert assurance['status'] == 'compatible'
    assert assurance['source_weakness_support'][0]['control'] == 'rbac_enabled'
    assert assurance['controls'][0]['state'] == 'unknown'
    assert control_value(model.components[0].properties, 'rbac_enabled') == 'unknown'
    assert assurance['runtime_verified'] is False


@pytest.mark.parametrize('mismatch', ['component', 'control', 'statement', 'rule', 'evidence_scope',
    'declaration_scope', 'finding_scope', 'unmapped', 'reference_report', 'planned', 'partial', 'conflicting', 'present'])
def test_declared_weakness_does_not_bypass_evidence_scope_or_control_conflicts(mismatch):
    model, risk = declared_authorization_model()
    target = model.components[0]
    record = target.properties['stated_weaknesses'][0]
    if mismatch == 'component':
        model.components.append(component('other', stated_weaknesses=[target.properties.pop('stated_weaknesses')[0]]))
    elif mismatch == 'control':
        risk.explanation['matched_controls'] = ['mfa_enabled']
    elif mismatch == 'statement':
        risk.evidence_details[0]['statement'] = 'An unrelated statement.'
    elif mismatch == 'rule':
        risk.evidence_details[0]['stated_weakness_rule'] = 'SOME-OTHER-RULE'
    elif mismatch == 'evidence_scope':
        risk.evidence_details[0]['scope'] = {'environment': 'staging'}
    elif mismatch == 'declaration_scope':
        record['scope'] = {'environment': 'staging'}
    elif mismatch == 'finding_scope':
        risk.explanation['control_scope'] = {'environment': 'staging'}
    elif mismatch == 'unmapped':
        target.properties['stated_weaknesses'] = []
    elif mismatch == 'reference_report':
        risk.evidence_details[0]['source_type'] = 'reference_report'
    elif mismatch == 'present':
        target.properties['rbac_enabled'] = True
    else:
        target.properties['correlated_controls'] = {'rbac_enabled': {'state': mismatch}}
    validate_evidence([risk], model)
    assert risk.tier == 'Potential'
    assert risk.explanation['evidence_validation']['status'] == 'requires_review'
    assert not risk.explanation['evidence_validation']['source_weakness_support']


def test_control_value_alias_keeps_the_expected_detection_polarity():
    risk = finding(explanation={'matched_controls': ['authorization_checks'],
        'matched_control_values': {'authorization_checks': True}})
    validate_evidence([risk], SystemArchitecture(components=[component(object_level_auth=True)], flows=[]))
    assert risk.tier == 'Confirmed'
    assert risk.explanation['evidence_validation']['status'] == 'compatible'


@pytest.mark.parametrize('public,expected_tier', [(True, 'Confirmed'), (False, 'Potential'), (None, 'Potential')])
def test_public_exposure_requires_present_exposure_not_an_absent_defense(public, expected_tier):
    risk = finding(id='GENERIC-PUBLIC-EXPOSURE-001-orders', explanation={'matched_controls': ['public_access']})
    validate_evidence([risk], SystemArchitecture(components=[component(public_access=public)], flows=[]))
    assert risk.tier == expected_tier


def test_endpoint_exception_does_not_silently_protect_every_route():
    target = component(rate_limiting=True, correlated_controls={'rate_limiting': {'state': 'partial',
        'scoped_claims': [{'state': 'absent', 'applicable': True, 'scope': {'endpoints': ['/export']}}]}},
        control_evidence={'rate_limiting': [{'state': 'present', 'scope': {}}]})
    assert control_effectiveness(target, 'rate_limiting')['state'] == 'unknown'
    assert control_effectiveness(target, 'rate_limiting', scope={'endpoint': '/export'})['state'] == 'absent'


def test_document_claims_respect_technology_and_boundary_metadata():
    text = 'Document: controls.md\nType: md\nRole: source_design\nContent:\nOrders API enforces rate limiting.'
    model = SystemArchitecture(components=[component(technology='Node.js', canonical_boundaries=['private'])], flows=[],
        metadata={'source_text': text, 'source_documents': [{'filename': 'controls.md',
            'technology': 'Go', 'boundary_ids': ['public']} ]})
    correlate = reconcile_claims(model)
    assert correlate['facts'][0]['applicable'] is False
    assert not model.components[0].properties.get('evidence_status')
    assert control_value(model.components[0].properties, 'rate_limiting') == 'unknown'
    model.metadata['source_documents'][0].update(technology='Node.js', boundary_ids=['private'])
    reconcile_claims(model)
    assert control_value(model.components[0].properties, 'rate_limiting') == 'present'
    before = model.model_dump()
    reconcile_claims(model)
    assert model.model_dump() == before


def test_reviewer_answer_cannot_escape_deployment_scope():
    model = SystemArchitecture(components=[component(environment='production', control_evidence={
        'rate_limiting': [{'state': 'present', 'source_ref': 'reviewer_clarification', 'scope': {'environment': 'staging'}}]})],
        flows=[], metadata={'source_text': 'Orders API rate limiting is not documented.'})
    reconcile_claims(model)
    assert control_value(model.components[0].properties, 'rate_limiting') == 'unknown'


def test_unresolved_subject_clears_legacy_prose_inference_not_structured_control():
    model = SystemArchitecture(components=[component(rate_limiting=False),
        component('billing', authoritative=True, rate_limiting=True)], flows=[],
        metadata={'source_text': 'The API has no rate limiting.'})
    ledger = reconcile_claims(model)
    assert ledger['unresolved_claims']
    assert control_value(model.components[0].properties, 'rate_limiting') == 'unknown'
    assert control_value(model.components[1].properties, 'rate_limiting') == 'present'


def test_citation_lookup_spans_lines_without_returning_preceding_paragraph():
    lines = [('Summary', {'line': 1}), ('', {'line': 2}), ('Orders API enforces', {'line': 3}),
        (' rate limiting.', {'line': 4})]
    indexed = _citation_index(lines)
    assert _locate('Orders API enforces rate limiting.', lines, indexed) == {'line': 3}
    assert _locate('Not in the document', lines, indexed) == {}


def test_citation_index_built_once_per_document_not_per_control_or_component(monkeypatch):
    from app.engine import source_correlation
    original, calls = source_correlation._citation_index, []

    def counted(lines):
        calls.append(len(lines))
        return original(lines)

    monkeypatch.setattr(source_correlation, '_citation_index', counted)
    model = SystemArchitecture(components=[component(str(index)) for index in range(50)], flows=[],
        metadata={'source_text': '\n'.join(f'{index} API enforces rate limiting.' for index in range(50))})
    assert len(reconcile_claims(model)['facts']) >= 50
    assert len(calls) == 1


def test_boundary_or_flow_assumption_changes_invalidate_control_answer_digest():
    model = SystemArchitecture(components=[component(canonical_boundaries=['private']), component('db')],
        flows=[DataFlow(source_id='orders', target_id='db', protocol='TLS')])
    initial = control_dependency_digest(model, 'orders', 'rate_limiting')
    model.components[0].properties['canonical_boundaries'] = ['public']
    changed = control_dependency_digest(model, 'orders', 'rate_limiting')
    assert changed != initial
    model.flows[0].properties['assumed'] = True
    assert control_dependency_digest(model, 'orders', 'rate_limiting') != changed


def policy(action='s3:GetObject', effect='Allow', **changes):
    return {'Statement': [{'Effect': effect, 'Action': action, 'Resource': '*', **changes}]}


def access_query(**changes):
    return {'principal': 'arn:aws:iam::111111111111:user/reviewer', 'action': 's3:GetObject',
        'resource': 'arn:aws:s3:::bucket/object', 'policy_inventory_complete': True,
        'policy_sets': {'identity': [policy()]}, **changes}


def test_scp_allow_union_per_level_and_intersection_between_levels():
    query = access_query(policy_levels={'scp': [
        {'id': 'root', 'policies': [policy('ec2:*'), policy('s3:*')]},
        {'id': 'ou-production', 'policies': [policy('*')]},
        {'id': 'account', 'policies': [policy('*')]}]})
    assert evaluate_access(query)['decision'] == 'allowed_in_supplied_policies'
    query['policy_levels']['scp'][1]['policies'] = [policy('ec2:*')]
    assert evaluate_access(query)['decision'] == 'implicit_deny'
    query['policy_levels']['scp'][1]['policies'] = [policy('*'), policy('s3:*', 'Deny')]
    assert evaluate_access(query)['decision'] == 'explicit_deny'


def test_flat_multiple_scp_documents_do_not_invent_attachment_hierarchy():
    query = access_query()
    query['policy_sets']['scp'] = [policy('ec2:*'), policy('s3:*')]
    assert evaluate_access(query)['decision'] == 'unknown'


@pytest.mark.parametrize('changes', [
    {'policy_inventory_complete': 'false'}, {'principal': ''}, {'action': '*'},
    {'resource': '${var.resource}'}, {'principal': ['user']},
    {'principal': 'arn:aws:sts::111111111111:assumed-role/orders/session'},
    {'action': 'kms:Decrypt'}, {'action': 'sts:AssumeRole'},
])
def test_unresolved_policy_request_never_reports_an_allow(changes):
    assert evaluate_access(access_query(**changes))['decision'] == 'unknown'


def test_unsupported_policy_group_cannot_establish_explicit_deny():
    query = access_query()
    query['policy_sets']['invented'] = [policy('*', 'Deny')]
    assert evaluate_access(query)['decision'] == 'unknown'


@pytest.mark.parametrize('statement', [
    {'Effect': [], 'Action': '*', 'Resource': '*'},
    {'Effect': 'Allow', 'Action': 3, 'Resource': '*'},
    {'Effect': 'Allow', 'Action': '*', 'Resource': '*', 'Condition': {'Bool': {'aws:SecureTransport': 'maybe'}}},
])
def test_malformed_policy_statements_abstain_without_crashing(statement):
    query = access_query(context={'aws:SecureTransport': True}, policy_sets={'identity': [{'Statement': [statement]}]})
    assert evaluate_access(query)['decision'] == 'unknown'


@pytest.mark.parametrize('changes', [{'policy_sets': []}, {'policy_sets': None}, {'context': []}, {'policy_levels': []}])
def test_invalid_empty_policy_containers_are_not_a_complete_empty_inventory(changes):
    assert evaluate_access(access_query(**changes))['decision'] == 'unknown'


def test_resource_policies_need_a_principal_and_no_shell_bracket_wildcards():
    query = access_query(policy_sets={'resource': [policy()]})
    assert evaluate_access(query)['decision'] == 'unknown'
    query = access_query(resource='arn:aws:s3:::bucket/a')
    query['policy_sets']['identity'][0]['Statement'][0]['Resource'] = 'arn:aws:s3:::bucket/[ab]'
    assert evaluate_access(query)['decision'] == 'implicit_deny'


def test_cross_account_is_inferred_from_resource_arn_not_a_false_flag():
    query = access_query(resource='arn:aws:sqs:eu-west-1:222222222222:queue', action='sqs:SendMessage', cross_account=False)
    query['policy_sets']['identity'] = [policy('sqs:SendMessage')]
    assert evaluate_access(query)['decision'] == 'implicit_deny'


def test_multi_value_condition_is_unknown_without_set_operator_support():
    query = access_query(context={'aws:TagKeys': ['tenant', 'owner']})
    query['policy_sets']['identity'] = [policy(Condition={'StringEquals': {'aws:TagKeys': 'tenant'}})]
    assert evaluate_access(query)['decision'] == 'unknown'


def route_model(assumed=False):
    web, orders, db = component('web'), component(iam_role='orders-role'), component('db')
    web.trust_level = 'public'
    return SystemArchitecture(components=[web, orders, db], flows=[
        DataFlow(id='F1', flow_number='1', source_id='web', target_id='orders', protocol='HTTPS'),
        DataFlow(id='F2', flow_number='2', source_id='orders', target_id='db', protocol='TLS', assumed=assumed)])


def test_final_report_separates_inferred_hypotheses_from_explicit_paths():
    model = route_model(assumed=True)
    risk = finding(component='db', affected_components=['db'])
    paths = generate_attack_paths(model, [risk])
    assert paths[0]['reasoning_status'] == 'inferred_hypothesis'
    risk.attack_path = deepcopy(paths[0])
    result = report(model, [risk], attack_chains={'paths': paths, 'count': 1})
    attach_assurance(result)
    assert result.attack_chains['count'] == 0
    assert result.attack_chains['hypothesis_count'] == 1
    assert result.threats[0].attack_path is None
    assert '0 modeled attack paths' in result.summary
    snapshot = result.attack_chains
    finalize_path_assurance(result)
    assert result.attack_chains == snapshot


def test_legacy_property_assumed_flag_is_not_promoted_to_explicit_flow():
    model = route_model()
    model.flows[0].properties['assumed'] = True
    assert not generate_attack_paths(model, [finding(component='db')])[0]['evidence_supported']


def test_identity_labels_and_allowed_hops_do_not_prove_execution_context():
    model = route_model()
    paths = generate_attack_paths(model, [finding(component='db')])
    checks = paths[0]['precondition_checks']
    assert any(check['kind'] == 'execution_context' and check['state'] == 'unknown' for check in checks)
    assert paths[0]['precondition_status'] == 'unresolved'
    assert paths[0]['hops'][0]['flow_number'] == '1'
    assert paths[0]['exploit_status'] == 'not_verified'


def test_contradicted_exploit_precondition_prevents_a_modeled_path():
    model = route_model()
    risk = finding(preconditions=['Attacker has a privileged session.'], explanation={'precondition_evidence': [{
        'statement': 'Attacker has a privileged session.', 'state': 'unmet', 'component_id': 'orders',
        'source_ref': 'review-1', 'scope': {}}]})
    assert generate_attack_paths(model, [risk]) == []
    assert risk.explanation['attack_path_reason'] == 'contradicted_precondition'


def test_conflicting_exploit_precondition_does_not_establish_or_disprove_exploit():
    model = route_model()
    records = [{'statement': 'Attacker has a privileged session.', 'state': state, 'component_id': 'orders',
        'source_ref': state, 'scope': {}} for state in ('met', 'unmet')]
    risk = finding(preconditions=['Attacker has a privileged session.'], explanation={'precondition_evidence': records})
    path, = generate_attack_paths(model, [risk])
    assert next(check for check in path['precondition_checks'] if check['kind'] == 'exploit')['state'] == 'unknown'


def test_permission_evidence_requires_source_scope_and_real_identity():
    model = route_model()
    source, target = model.components[1:]
    source.properties['environment'] = 'production'
    flow = model.flows[1]
    flow.properties = {'required_permissions': ['db:read'], 'authorization_evidence': {
        'source_ref': 'policy', 'identity': 'orders-role', 'resource': 'db', 'actions': ['db:read'],
        'decision': 'allow', 'source_scope': {'environment': 'staging'}}}
    assert _permission_state(flow, source, target) == 'unknown'
    flow.properties['authorization_evidence']['source_scope']['environment'] = 'production'
    assert _permission_state(flow, source, target) == 'allowed'
    source.properties.pop('iam_role')
    flow.properties['authorization_evidence']['identity'] = 'unspecified_workload_identity'
    assert _permission_state(flow, source, target) == 'unknown'


def test_permission_evaluation_reused_within_run_but_not_across_runs(monkeypatch):
    from app.engine import attack_path_engine
    original, calls = attack_path_engine._permission_state, []

    def counted(flow, source, target):
        calls.append(flow.id)
        return original(flow, source, target)

    monkeypatch.setattr(attack_path_engine, '_permission_state', counted)
    model = route_model()
    risks = [finding(id=f'risk-{index}', component='db') for index in range(40)]
    assert len(generate_attack_paths(model, risks)) == 40
    assert calls == ['F1', 'F2']
    generate_attack_paths(model, risks)
    assert calls == ['F1', 'F2', 'F1', 'F2']


def test_endpoint_permission_evidence_cannot_authorize_another_operation():
    source, target = component(iam_role='orders-role'), component('db')
    flow = DataFlow(source_id='orders', target_id='db', protocol='TLS', properties={
        'endpoint': '/orders', 'required_permissions': ['db:read'], 'authorization_evidence': {
            'source_ref': 'review', 'identity': 'orders-role', 'resource': 'db', 'actions': ['db:read'],
            'decision': 'allow', 'scope': {'endpoints': ['/admin']}}})
    assert _permission_state(flow, source, target) == 'unknown'
    flow.properties['authorization_evidence']['scope']['endpoints'] = ['/orders']
    assert _permission_state(flow, source, target) == 'allowed'


def test_remediation_has_stable_ids_scoped_acceptance_and_no_fabricated_results():
    target = component(environment='production', tenant_id='tenant-a')
    risk = finding(affected_flow_refs=[{'id': 'F1', 'number': '1'}])
    contract = remediation_contract(risk, {'orders': target})
    criterion, = contract['criteria']
    assert criterion['status'] == 'not_performed'
    assert criterion['test_definition_status'] == 'defined'
    assert criterion['scope'][0]['tenant_id'] == 'tenant-a'
    assert criterion['flow_refs'] == risk.affected_flow_refs
    assert criterion['acceptance_condition'] and criterion['required_evidence']
    assert not criterion['runtime_verified']
    assert contract == remediation_contract(risk, {'orders': target})
    criterion['flow_refs'].clear()
    assert risk.affected_flow_refs


def test_unknown_control_requires_owner_defined_acceptance_not_generic_verified_claim():
    contract = remediation_contract(finding(explanation={'matched_controls': ['custom_control']}), {'orders': component()})
    assert contract['criteria'][0]['test_definition_status'] == 'owner_definition_required'


def test_empty_coverage_does_not_mean_100_percent_evidence_resolution():
    result = report(SystemArchitecture(components=[], flows=[]))
    assert coverage_assurance(result)['evidence_resolution_percent'] is None


def test_known_finding_does_not_hide_other_unresolved_controls_in_same_cell():
    result = report(route_model(), stride_coverage={'cells': [
        {'status': 'finding', 'control_assessment': {'controls': {'mfa_enabled': 'absent', 'session_timeout': 'unknown'}}},
        {'status': 'control_present', 'control_assessment': {'controls': {'parameterized_queries': 'present'}}},
        {'status': 'not_applicable'}]})
    assurance = coverage_assurance(result)
    assert assurance['applicable_cells'] == 2
    assert assurance['unresolved_cells'] == 1
    assert assurance['evidence_resolution_percent'] == 50
    assert assurance['independent_accuracy_established'] is False


@pytest.mark.parametrize('queries', [None, {}, 'not a list', [None, 'not a request']])
def test_malformed_policy_queries_remain_visible_without_breaking_report_finalization(queries):
    result = report(SystemArchitecture(components=[component(access_queries=queries)], flows=[]))
    attach_assurance(result)
    evaluations = result.engine_status['policy_evaluations']
    assert evaluations and all(item['decision'] == 'unknown' for item in evaluations)
    assert all(item['limits'] and not item['runtime_verified'] for item in evaluations)


def test_truncated_policy_evaluation_is_disclosed_instead_of_silently_omitted():
    result = report(SystemArchitecture(components=[component(access_queries=[access_query() for _ in range(52)])], flows=[]))
    attach_assurance(result)
    evaluations = result.engine_status['policy_evaluations']
    assert len(evaluations) == 51
    assert evaluations[-1]['decision'] == 'unknown'
    assert evaluations[-1]['unevaluated_requests'] == 2


def test_finalizer_does_not_trust_an_evidence_flag_over_an_inferred_hop():
    model = route_model(assumed=True)
    risk = finding(component='db')
    paths = generate_attack_paths(model, [risk])
    paths[0].update(evidence_supported=True, path_status='explicit', inferred_hops=0)
    result = report(model, [risk], attack_chains={'paths': paths})
    finalize_path_assurance(result)
    assert result.attack_chains['count'] == 0
    assert result.attack_chains['hypothesis_count'] == 1


def test_finalizer_removes_a_superseded_hypothesis_and_refreshes_the_attached_path():
    model = route_model(assumed=True)
    risk = finding(component='db')
    old_path, = generate_attack_paths(model, [risk])
    risk.attack_path = deepcopy(old_path)
    risk.explanation['attack_path_reason'] = 'inferred_route_requires_review'
    model.flows[-1].assumed = False
    new_path, = generate_attack_paths(model, [risk])
    result = report(model, [risk], attack_chains={'paths': [new_path], 'hypotheses': [old_path]})
    finalize_path_assurance(result)
    assert result.attack_chains['hypothesis_count'] == 0
    assert result.attack_chains['count'] == 1
    assert result.threats[0].attack_path['path_status'] == 'explicit'
    assert 'attack_path_reason' not in result.threats[0].explanation


def test_remediation_alias_uses_the_canonical_control_acceptance_check():
    risk = finding(explanation={'matched_controls': ['authorization_checks', 'object_level_auth']})
    criterion, = remediation_contract(risk, {'orders': component()})['criteria']
    assert criterion['control'] == 'object_level_auth'
    assert criterion['test_definition_status'] == 'defined'


def test_analyzer_refresh_and_json_round_trip_retain_reasoning_metadata():
    from app.engine.analyzer import ThreatAnalyzer

    analyzer = ThreatAnalyzer()
    result = analyzer.analyze_from_text(
        'React calls Orders API over HTTPS. Orders API is a Node.js REST API. '
        'Orders API writes customer records to PostgreSQL over TLS.\n'
        'KNOWN ISSUES:\n- Orders API has no parameterized queries.',
        project_name='Reasoning integration', use_local_slm=False)
    risk = next(risk for risk in result.threats if 'parameterized_queries' in risk.explanation.get('matched_controls', []))
    assert risk.explanation['evidence_validation']['runtime_verified'] is False
    criteria = risk.explanation['remediation_validation']['criteria']
    assert criteria and all(criterion['flow_refs'] == risk.affected_flow_refs for criterion in criteria)
    assert result.engine_status['reasoning_assurance']['version'] == 'reasoning-controls-2'
    assert result.attack_chains['count'] == len(result.attack_chains['paths'])
    serialized = AnalysisResult.model_validate_json(result.model_dump_json())
    refreshed = analyzer.refresh_result_artifacts(serialized, use_local_slm=False)
    corresponding = next(item for item in refreshed.threats if item.id == risk.id)
    assert [criterion['id'] for criterion in corresponding.explanation['remediation_validation']['criteria']] == [criterion['id'] for criterion in criteria]
    assert all(criterion['flow_refs'] == corresponding.affected_flow_refs
        for criterion in corresponding.explanation['remediation_validation']['criteria'])
    assert refreshed.engine_status['reasoning_assurance']['runtime_verified'] is False
    assert all(path['path_status'] == 'explicit' for path in refreshed.attack_chains['paths'])
    assert refreshed.report_markdown and refreshed.engine_status['output_contract']['valid']


@pytest.mark.parametrize('state', ['unknown', 'planned', 'partial', 'conflicting'])
def test_internal_llm_tampering_candidate_preserves_uncertain_controls(state):
    from app.engine.stride_coverage_engine import StrideCoverageEngine, UNKNOWN_CANDIDATE_BUDGET

    controls = ('prompt_sanitization', 'untrusted_context_separation', 'output_validation')
    target = Component(id='llm', name='LLM', type='ML Service', trust_level='internal', confidence='High',
        properties={'technology': 'llm', 'correlated_controls': {control: {'state': state} for control in controls}})
    model = SystemArchitecture(components=[target], flows=[])
    before = model.model_dump()
    risks, coverage = StrideCoverageEngine().assess(model, [])
    risk, = [risk for risk in risks if risk.category == 'Tampering']
    assert 'prompt injection' in risk.title.lower()
    assert risk.tier == 'Potential' and risk.finding_type == 'validation_question'
    assert risk.explanation['scope_resolution'] == 'component_profile'
    assert set(risk.explanation['matched_controls']) == set(controls)
    cell = next(cell for cell in coverage['cells'] if cell['category'] == 'Tampering')
    assert set(cell['unresolved_controls']) == set(controls)
    assert len(risks) <= UNKNOWN_CANDIDATE_BUDGET
    assert model.model_dump() == before


def test_documented_llm_controls_do_not_create_an_absence_finding():
    from app.engine.stride_coverage_engine import StrideCoverageEngine

    target = Component(id='llm', name='LLM', type='ML Service', properties={
        'prompt_sanitization': True, 'untrusted_context_separation': True, 'output_validation': True})
    risks, coverage = StrideCoverageEngine().assess(SystemArchitecture(components=[target], flows=[]), [])
    assert not any(risk.category == 'Tampering' for risk in risks)
    assert next(cell for cell in coverage['cells'] if cell['category'] == 'Tampering')['status'] == 'control_present'


@pytest.mark.parametrize('kind,name,technology', [
    ('ML Service', 'Fraud classifier', 'xgboost'), ('Service', 'Orders API', 'nodejs'),
    ('Database', 'OpenAI conversation archive', 'postgresql'),
])
def test_ai_scope_alone_does_not_invent_a_language_model(kind, name, technology):
    from app.engine.stride_coverage_engine import StrideCoverageEngine

    target = Component(id='target', name=name, type=kind,
        properties={'technology': technology, 'ai_scope': True, 'ml_pipeline': True})
    risks, _ = StrideCoverageEngine().assess(SystemArchitecture(components=[target], flows=[]), [])
    assert not any('prompt injection' in risk.title.lower() for risk in risks)


def test_subjectless_ai_weakness_stays_unresolved_while_llm_risk_is_visible(analyze):
    text = ('User submits prompts via a React frontend to a FastAPI backend. '
        'Backend forwards prompts to an LLM running on a GPU instance. '
        'LLM outputs are sent back. No output validation or prompt sanitization.')
    result = analyze(text, 'AI uncertainty regression')
    risks = [risk for risk in result.threats if 'prompt injection' in risk.title.lower()]
    assert risks and all(risk.tier == 'Potential' for risk in risks)
    assert all(risk.affected_components == ['llm'] for risk in risks)
    ledger = result.architecture.metadata['source_correlation']
    unresolved = [claim for claim in ledger['unresolved_claims'] if claim['control'] == 'prompt_sanitization']
    assert unresolved and all(claim['element_id'] is None for claim in unresolved)
    assert all(control_value(target.properties, 'prompt_sanitization') == 'unknown'
        for target in result.architecture.components)
    assert not any(risk.attack_path for risk in risks)
