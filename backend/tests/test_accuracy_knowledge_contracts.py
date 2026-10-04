"""Accuracy guardrails and engineering fixtures, not a reviewed production benchmark."""

from copy import deepcopy
import pytest

from app.engine.confidence_calibration import ConfidenceCalibrator
from app.engine.control_contracts import presence
from app.engine.control_statements import read
from app.engine.knowledge_threat_engine import KnowledgeThreatEngine, _compile_logic
from app.knowledge_base.evaluation import CASES, contract_model
from app.knowledge_base.governance import quarantine_reason, review_digest
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Component, SystemArchitecture, Threat

KB = ThreatKnowledgeBase()
RULES = [r for r in KB.threats if r.get('test_contract')]


def test_named_webhook_receiver_does_not_blame_provider_or_duplicate():
    from app.engine.analyzer import ThreatAnalyzer

    result = ThreatAnalyzer().analyze_from_text(
        'React calls a Payments API. Stripe webhooks enter through the Payments API.\n'
        'KNOWN ISSUES:\n- The Payments API does not verify webhook signatures.',
        use_local_slm=False,
    )
    findings = [f for f in result.threats if f.tier == 'Confirmed'
        and 'CWE-345' in f.cwe and 'webhook' in f.title.lower()]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_components == ['payments_api']
    assert 'webhook_signature_validation' in finding.explanation['matched_controls']
    assert len(finding.explanation['merged_finding_ids']) >= 2


@pytest.fixture(scope='module')
def engine():
    return KnowledgeThreatEngine(KB)


@pytest.mark.parametrize('rule', RULES, ids=lambda r: r['id'])
@pytest.mark.parametrize('case', CASES)
def test_context_rule_contract(rule, case, engine):
    model = contract_model(rule, case)
    findings, _ = engine.analyze(model)
    found = [f for f in findings if f.id == f"KB-{rule['id']}-target"]
    assert bool(found) is (case == 'positive')
    if found:
        calibrated, _ = ConfidenceCalibrator().calibrate(found, model)
        assert calibrated[0].tier == 'Confirmed'
        assert calibrated[0].explanation['verification_status'] == 'not_runtime_verified'


@pytest.mark.parametrize('rule', RULES, ids=lambda r: r['id'])
def test_new_control_vocabulary_and_provenance(rule):
    control = rule['test_contract']['control']
    assert control in read('THE COMPONENT HAS NO ' + control.replace('_', ' ').upper()).denied
    assert control in read('The component enforces ' + control.replace('_', ' ') + '.').affirmed
    assert rule['references'] and rule['verification'] and rule['counterexamples'] and rule['source_version']
    assert rule['last_reviewed'] is None  # Do not invent independent review dates.
    assert rule['taxonomy_mapping_quality']['owasp_top_10'] == 'unmapped'
    assert not rule['owasp_top_10']  # STRIDE disclosure is not an OWASP cryptography mapping.


@pytest.mark.parametrize('value', ['planned', 'partially implemented', 'maybe enabled', '${var.mfa}', 'arbitrary service name'])
def test_unresolved_values_do_not_become_protection_or_a_defect(value):
    assert presence(value) is None
    for expected in (True, False):
        predicate = _compile_logic({'conditions': [{'field': 'mfa_enabled', 'op': '!=', 'value': expected}]})
        assert predicate({'mfa_enabled': value}, set())[0] is None


@pytest.mark.parametrize('source', ['rule_evaluation', 'coverage_assessment', 'llm_challenger', 'inference'])
def test_a_detector_cannot_confirm_its_own_conclusion(source):
    model = SystemArchitecture(components=[Component(id='api', name='API', type='API')], flows=[])
    finding = Threat(id='test', title='Missing MFA', category='Spoofing', severity='High',
        description='MFA absent', mitigation='Require MFA', affected_components=['api'],
        evidence_details=[{'source_type': source, 'statement': 'MFA is absent.'}],
        explanation={'matched_controls': ['mfa_enabled']})
    result, _ = ConfidenceCalibrator().calibrate([finding], model)
    assert result[0].tier == 'Potential'
    assert result[0].confidence_score < .8


def test_topology_approval_and_wrong_scope_cannot_confirm_controls(engine):
    rule = RULES[0]
    model = contract_model(rule, 'positive')
    for patch in ({'evidence_scope': 'topology'}, {'applicable': False}, {'state': 'planned'}):
        copy = model.model_copy(deep=True)
        copy.components[0].evidence[0].update(patch)
        findings, _ = engine.analyze(copy)
        calibrated, _ = ConfidenceCalibrator().calibrate(findings, copy)
        assert all(t.tier == 'Potential' for t in calibrated)


def test_external_approval_is_bound_to_rule_contents():
    rule = deepcopy(RULES[0]['raw'])
    rule['origin'] = 'external'
    assert quarantine_reason(rule)
    rule['approval'] = {'reviewer': 'test-reviewer', 'reviewed_at': '2026-10-03', 'content_digest': review_digest(rule)}
    assert quarantine_reason(rule) is None
    rule['severity'] = 'Critical'
    assert quarantine_reason(rule)


def test_quarantine_is_removed_from_predicates_and_retrieval():
    rule = deepcopy(RULES[0]['raw'])
    rule.update(id='QUARANTINED-TEST', lifecycle='quarantined')
    assert KB._normalize_and_merge([rule]) == []
    assert KB.quarantined_rules[-1]['rule_id'] == rule['id']


def test_new_json_file_cannot_self_activate(tmp_path):
    import json
    kb = ThreatKnowledgeBase()
    rule = deepcopy(RULES[0]['raw'])
    rule.pop('origin', None)
    rule['lifecycle'] = 'active'
    (tmp_path / 'unapproved.json').write_text(json.dumps([rule]), encoding='utf-8')
    kb.kb_dir = tmp_path
    kb.load_all()
    assert kb.get_all_threats() == []
    assert len(kb.quarantined_rules) == 1


def test_governance_counts_are_not_compliance_or_recall_claims():
    assert not KB.validation_issues
    assert KB.governance_audit['counts']['contract_testable'] == len(RULES)
    assert KB.governance_audit['independent_accuracy_established'] is False


def test_reviewing_one_image_does_not_approve_another():
    from app.engine.diagram_quality import diagram_quality
    model = SystemArchitecture(components=[], flows=[], metadata={
        'diagram_extractions': [{'source_id': s, 'method': 'ocr_only', 'version': 2} for s in ('one', 'two')],
        'diagram_review_tasks': [{'kind': 'topology', 'source_id': 'one', 'status': 'reviewed'}]})
    assert not diagram_quality(model)['score_available']
    model.metadata['diagram_review_tasks'].append({'kind': 'topology', 'source_id': 'two', 'status': 'reviewed'})
    assert diagram_quality(model)['score_available']


def test_non_latin_labels_are_not_deleted_as_logo_noise():
    from app.services.diagram_geometry import group_labels
    labels, annotations = group_labels([{'text': '\u8ba2\u5355\u670d\u52a1', 'bbox': [.1, .1, .2, .1]}])
    assert len(labels) == 1 and not annotations


def test_adjacent_colored_subnets_do_not_share_one_box():
    pytest.importorskip('cv2')
    from PIL import Image, ImageDraw
    from app.services.diagram_geometry import local_candidates
    image = Image.new('RGB', (1000, 500), 'white')
    draw = ImageDraw.Draw(image)
    draw.rectangle((100, 100, 500, 400), outline=(110, 155, 0), width=2)
    draw.rectangle((500, 100, 800, 400), outline=(0, 175, 175), width=2)
    rows = [{'text': 'Public subnet', 'bbox': [.13, .23, .13, .04]},
        {'text': 'Private subnet', 'bbox': [.53, .23, .14, .04]}]
    _, groups, _ = local_candidates(image, rows)
    assert len(groups) == 2
    assert groups[0]['bbox'][0] < .2 and .48 < groups[1]['bbox'][0] < .52
    assert groups[0]['bbox'][2] < .45


def test_specialist_workflow_requires_matching_absence_evidence():
    from app.engine.workflow_checks import analyze_workflows
    c = Component(id='provision', name='Provisioning service', type='Service', properties={'environment': 'production'})
    evidence = {'control': 'subscriber_authorization', 'state': 'absent', 'source_type': 'architecture_input',
        'statement': 'Subscriber authorization is absent.', 'scope': {'environment': 'staging'}}
    model = SystemArchitecture(components=[c], flows=[], metadata={'workflows': [{'id': 'activate',
        'components': ['provision'], 'invariants': {'subscriber_authorization': False}, 'evidence': [evidence]}]})
    assert analyze_workflows(model)[0] == []
    evidence['scope']['environment'] = 'production'
    model.metadata['workflows'][0]['evidence'] = [evidence]
    assert len(analyze_workflows(model)[0]) == 1
    evidence['state'] = 'present'
    assert analyze_workflows(model)[0] == []


def test_permission_evidence_for_other_environment_is_unknown():
    from app.engine.attack_path_engine import _permission_state
    from app.models import DataFlow
    source = Component(id='api', name='API', type='API', properties={'iam_role': 'orders-role'})
    target = Component(id='bucket', name='Orders bucket', type='Object Storage', properties={'environment': 'production'})
    flow = DataFlow(source_id='api', target_id='bucket', protocol='HTTPS', properties={
        'required_permissions': ['s3:GetObject'], 'authorization_evidence': {'source_ref': 'policy.tf',
            'identity': 'orders-role', 'resource': 'bucket', 'actions': ['s3:GetObject'], 'decision': 'allow',
            'scope': {'environment': 'staging'}}})
    assert _permission_state(flow, source, target) == 'unknown'
    flow.properties['authorization_evidence']['scope']['environment'] = 'production'
    assert _permission_state(flow, source, target) == 'allowed'


@pytest.mark.parametrize('state', ['protected', 'unknown', 'conflicting', 'planned', 'partial'])
def test_counterfactual_change_invalidates_cached_rule_match(engine, state):
    rule = RULES[0]
    def matched(case):
        return any(f.id == f"KB-{rule['id']}-target" for f in engine.analyze(contract_model(rule, case))[0])
    assert matched('positive')
    assert not matched(state)
    assert matched('positive')
