"""Regression gates for the analysis-quality workplan, not independent accuracy labels."""

from copy import deepcopy

import pytest

from app.engine.canonical_model import canonicalize_architecture
from app.engine.control_contracts import control_value
from app.engine.knowledge_threat_engine import _compile_logic, _negated_by_control
from app.models import Component, SystemArchitecture, Threat


@pytest.mark.parametrize('operator,values,expected', [
    ('AND', [True, None], None), ('AND', [False, None], False),
    ('AND', [True, True], True), ('OR', [False, None], None),
    ('OR', [True, None], True), ('OR', [False, False], False),
])
def test_predicates_distinguish_unknown_from_false(operator, values, expected):
    predicate = _compile_logic({'operator': operator, 'conditions': [
        {'field': 'a', 'op': '==', 'value': True}, {'field': 'b', 'op': '==', 'value': True}]})
    outcome, fields = predicate(dict(zip(('a', 'b'), values)), set())
    assert outcome is expected
    assert fields


@pytest.mark.parametrize('state', ['partial', 'planned', 'conflicting', 'unknown'])
def test_unresolved_control_cannot_suppress_a_candidate(state):
    props = {'mfa_enabled': True, 'correlated_controls': {'mfa_enabled': {'state': state}}}
    assert not _negated_by_control(props, {'negating_controls': ['mfa_enabled']})


def test_endpoint_exception_is_not_erased_by_broad_protection():
    architecture = SystemArchitecture(components=[Component(id='orders', name='Orders API', type='API')],
        flows=[], metadata={'source_text': 'Orders API enforces rate limiting.\nOrders API has no rate limiting on /export.'})
    result, _ = canonicalize_architecture(architecture)
    props = result.components[0].properties
    assert props['correlated_controls']['rate_limiting']['state'] == 'partial'
    assert control_value(props, 'rate_limiting') == 'unknown'
    assert len(props['correlated_controls']['rate_limiting']['scoped_claims']) == 1
    again, _ = canonicalize_architecture(result.model_copy(deep=True))
    assert result.model_dump() == again.model_dump()


def finding(identifier, source, **kwargs):
    return Threat(id=identifier, title='Missing MFA', category='Spoofing', description='MFA is absent.',
        mitigation='Enable MFA.', severity='High', tier='Confirmed', component='admin',
        affected_components=['admin'], cwe=['CWE-308'], root_cause='Missing MFA',
        evidence_details=[{'source_id': source, 'document': source, 'statement': 'Admin portal has no MFA.'}],
        explanation={'matched_controls': ['mfa_enabled'], 'rule_provenance': {'id': identifier}}, **kwargs)


def test_dedup_retains_distinct_source_citations_and_provenance():
    from app.engine.deduplication_engine import deduplicate_threats
    left, right = finding('a', 'prompt'), finding('b', 'design.pdf')
    before = deepcopy([left.model_dump(), right.model_dump()])
    result = deduplicate_threats([left, right])
    assert len(result) == 1
    assert {e['source_id'] for e in result[0].evidence_details} == {'prompt', 'design.pdf'}
    assert set(result[0].explanation['merged_finding_ids']) == {'a', 'b'}
    assert {p['id'] for p in result[0].explanation['rule_provenances']} == {'a', 'b'}
    assert [left.model_dump(), right.model_dump()] == before
    assert [t.model_dump() for t in deduplicate_threats(result)] == [t.model_dump() for t in result]


def test_dedup_preserves_environment_and_endpoint_scope():
    from app.engine.deduplication_engine import deduplicate_threats
    left, right = finding('a', 'prompt'), finding('b', 'design.pdf')
    left.evidence_details[0]['scope'] = {'environment': 'production', 'endpoints': ['/admin']}
    right.evidence_details[0]['scope'] = {'environment': 'staging', 'endpoints': ['/login']}
    assert len(deduplicate_threats([left, right])) == 2


def test_collapse_does_not_merge_overlapping_but_different_controls():
    from app.engine.analyzer import ThreatAnalyzer
    left, right = finding('KB-a', 'prompt'), finding('KB-b', 'design.pdf')
    right.title = 'Token validation weakness'
    right.explanation['matched_controls'] = ['mfa_enabled', 'token_validation']
    assert len(ThreatAnalyzer._collapse_findings_on_the_same_control([left, right])) == 2


def test_prose_weakness_joins_final_issue_accounting():
    from app.engine.parser import ArchitectureParser
    from app.engine.issue_inventory import dispositions
    architecture = ArchitectureParser().parse('The admin portal has no multi-factor authentication.')
    ledger = dispositions(architecture, [])
    assert ledger['declared'] >= 1
    assert all(row['disposition'] == 'needs_clarification' for row in ledger['issues'])


def test_review_conflict_is_retained_when_equivalent_findings_merge():
    from app.engine.deduplication_engine import deduplicate_threats
    left, right = finding('a', 'prompt'), finding('b', 'design.pdf')
    left.review_status, right.review_status = 'accepted', 'rejected'
    result = deduplicate_threats([left, right])[0]
    assert result.review_status == 'pending_review'
    assert {d['review_status'] for d in result.explanation['merged_review_decisions']} == {'accepted', 'rejected'}


def test_control_verbs_do_not_create_components():
    from app.engine.component_roles import find_named_roles
    assert find_named_roles('KMS encrypts database. Rate limits protect API gateway.') == []
    assert find_named_roles('The payment processor stores invoices.')[0]['id'] == 'payment_processor'


def test_same_control_with_shared_secondary_cwe_merges(analyzer):
    result = analyzer.analyze_from_text('React calls Orders API over HTTPS. Orders API has no rate limiting.', use_local_slm=False)
    threats = [t for t in result.threats if t.tier == 'Confirmed' and 'rate_limiting' in t.explanation.get('matched_controls', [])]
    assert len(threats) == 1
    assert {'CWE-400', 'CWE-770'} <= set(threats[0].cwe)


def test_issue_accounting_uses_resolved_callback_receiver(analyzer):
    result = analyzer.analyze_from_text('Stripe sends webhooks to the Node.js API over HTTPS.\nKnown issues:\n- Stripe webhook signatures are not verified.', use_local_slm=False)
    inventory = result.engine_status['issue_inventory']
    assert inventory['declared'] > 0 and inventory['unaccounted'] == 0
    assert inventory['issues'][0]['component'] == 'node_js'


def test_reference_to_storage_is_not_runtime_data_flow():
    from app.engine.iac_parser import IaCParser
    architecture = IaCParser().parse('resource "aws_s3_bucket" "images" { bucket = "images" }\n'
        'resource "aws_lambda_function" "app" { environment { variables = { BUCKET = aws_s3_bucket.images.id } } }', 'terraform')
    assert architecture.flows and all(flow.assumed for flow in architecture.flows)
    assert architecture.metadata['iac_coverage']['status'] == 'partial'
    assert architecture.metadata['iac_coverage']['runtime_verified'] is False


def test_variants_cannot_count_as_independent_architectures():
    from app.engine.evaluation_governance import holdout_gate
    records = [{'query': f'Architecture variant {i}', 'architecture_family': 'same-product',
        'review_status': 'approved', 'reviewed_by': 'reviewer'} for i in range(100)]
    assert not holdout_gate(records)['eligible']


def test_feedback_cannot_forge_training_approval(tmp_path):
    from app.engine.retrieval_quality import RetrievalFeedbackStore
    store = RetrievalFeedbackStore(tmp_path / 'feedback.jsonl')
    assert store.summary()['observed_false_positive_rate'] is None
    event = store.record({'decision': 'accepted', 'event': 'approval', 'approved_for_training': True,
        'feedback_id': 'forged', 'schema_version': 'untrusted'})
    assert event['event'] == 'decision' and event['approved_for_training'] is False
    assert event['feedback_id'] != 'forged'
    assert store.approved_training_records() == []
    with pytest.raises(ValueError):
        store.approve(event['feedback_id'], '')


def test_flow_numbers_survive_unrelated_insertions_and_invalid_parents_block():
    from app.models import DataFlow, TrustBoundary
    architecture = SystemArchitecture(components=[Component(id=id, name=id, type='API') for id in ('a', 'b', 'c')],
        flows=[DataFlow(source_id='a', target_id='b', protocol='TLS')])
    model, _ = canonicalize_architecture(architecture)
    flow_id, flow_number = model.flows[0].id, model.flows[0].flow_number
    model.flows.insert(0, DataFlow(source_id='c', target_id='a', protocol='HTTPS'))
    model, _ = canonicalize_architecture(model)
    assert model.flows[1].id == flow_id and model.flows[1].flow_number == flow_number
    assert len({f.flow_number for f in model.flows}) == 2
    model.trust_boundaries = [TrustBoundary(id='x', name='x', boundary_type='network', parent_id='missing', components=['a'])]
    _, validation = canonicalize_architecture(model)
    assert not validation['valid']


@pytest.mark.parametrize('content,root', [
    ('FROM alpine\nUSER root\n', True),
    ('FROM alpine\nUSER 0:1000\n', True),
    ('FROM alpine\nUSER 1000\n', False),
    ('FROM alpine\nUSER root\nUSER 1000\n', False),
    ('FROM alpine AS builder\nUSER root\nFROM scratch\nCOPY --from=builder /app /app\n', False),
    ('FROM alpine AS base\nUSER 0\nFROM base\n', True),
    ('FROM alpine AS base\nUSER 0\nONBUILD USER 1000\nFROM base\n', False),
    ('FROM alpine\nUSER ${APP_USER}\n', False),
    ('FROM alpine\nEXPOSE 6379\n', False),
])
def test_dockerfile_final_stage_and_unknown_defaults(content, root):
    from app.engine.iac_parser import IaCParser
    architecture = IaCParser().parse(content, filename='Dockerfile')
    findings = architecture.metadata['iac_findings']
    assert bool(findings) is root
    assert len(architecture.components) == 1 and not architecture.flows
    assert architecture.components[0].properties['publicly_accessible'] is None
    assert architecture.metadata['iac_coverage']['status'] == 'partial'
    if findings:
        assert findings[0]['resource_id'] == architecture.components[0].id
        assert findings[0]['line'] >= 2
        assert findings[0]['severity'] == 'Medium'


def test_dockerfile_upload_is_parsed_as_iac():
    from app.services.document_ingestion import _extract_text_from_bytes
    from app.engine.parser import ArchitectureParser
    source = 'FROM alpine\nUSER root\n'
    text, kind, _ = _extract_text_from_bytes('Dockerfile', source.encode())
    assert kind == '.dockerfile'
    architecture = ArchitectureParser().parse(f'Document: Dockerfile\nType: dockerfile\nRole: source_design\nContent:\n{text}')
    assert architecture.metadata['iac_findings'][0]['rule_id'] == 'IAC-DOCKERFILE-ROOT-USER'
    assert architecture.metadata['iac_coverage']['artifacts'][0]['format'] == 'dockerfile'


def test_dockerfile_heredoc_cannot_create_a_false_root_finding():
    from app.engine.iac_parser import IaCParser
    with pytest.raises(ValueError, match='heredoc'):
        IaCParser().parse('FROM alpine\nUSER 1000\nRUN <<EOF\nUSER root\nEOF\n', filename='Dockerfile')


def test_failed_embedded_iac_is_visible_in_final_report(analyzer):
    result = analyzer.analyze_from_text('User Context:\nReact calls Orders API over HTTPS.\n\n'
        'Document: Dockerfile\nType: dockerfile\nRole: source_design\nContent:\n'
        'FROM alpine\nUSER 1000\nRUN <<EOF\nUSER root\nEOF\n', use_local_slm=False)
    assert result.engine_status['iac_input_failures'][0]['document'] == 'Dockerfile'
    assert any(w['check'] == 'unparsed_iac' for w in result.engine_status['quality_gate']['completeness_warnings'])
    assert all(t.tier != 'Confirmed' for t in result.threats)


def test_release_does_not_hide_models_after_200(tmp_path):
    import json
    from app.services.product_store import ProductStore
    store = ProductStore(tmp_path / 'catalog.db')
    product = store.create('products', 'Large product', 'test')
    release = store.create('releases', '26.09', 'test', product['id'])
    with store.connect() as db:
        db.executemany('INSERT INTO workspaces(id,release_id,environment,version,payload,updated) VALUES(?,?,?,?,?,?)',
            [(str(i), release['id'], 'production', 1, json.dumps({'projectName': f'Model {i}', 'revisions': []}), i) for i in range(225)])
    assert len(store.release(release['id'])['workspaces']) == 225


def test_control_conflict_requires_review_without_falsely_breaking_topology(analyzer):
    result = analyzer.analyze_from_text('Orders API stores orders in PostgreSQL.\nKnown issues:\n- Orders API has no rate limiting.\nControls:\nOrders API enforces rate limiting.', use_local_slm=False)
    assert result.architecture_validation['valid'] is True
    gate = result.engine_status['quality_gate']
    assert gate['publication_status'] == 'review'
    assert any(row['check'] == 'conflicting_control_evidence' for row in gate['completeness_warnings'])
    assert not any(t.tier == 'Confirmed' and 'rate_limiting' in t.explanation.get('matched_controls', []) for t in result.threats)


def test_parallel_flow_coverage_does_not_share_control_state_or_identity():
    from app.models import DataFlow
    from app.engine.stride_coverage_engine import StrideCoverageEngine
    from app.services.model_review import _questions
    architecture = SystemArchitecture(components=[Component(id=id, name=id, type='API') for id in ('a', 'b')],
        flows=[DataFlow(id='secure', source_id='a', target_id='b', protocol='HTTPS', confidence='High'),
            DataFlow(id='insecure', source_id='a', target_id='b', protocol='HTTP', confidence='High')])
    model, _ = canonicalize_architecture(architecture)
    findings, coverage = StrideCoverageEngine().assess(model, [])
    cells = {c['element_id']: c for c in coverage['cells'] if c['element_kind'] == 'flow' and c['category'] == 'Information Disclosure'}
    assert cells['flow:secure']['status'] == 'control_present'
    assert cells['flow:insecure']['status'] == 'finding'
    assert len({t.id for t in findings}) == len(findings)
    assert all(t.data_flow != 'secure' for t in findings if t.category == 'Information Disclosure')
    assert {q['element_id'] for q in _questions(model, coverage)} >= {'secure', 'insecure'}
