"""Synthetic tests of governance mechanics, not independent accuracy measurements."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import sqlite3
import json
from pathlib import Path

import pytest

from app.knowledge_base.evaluation import evaluate_contracts
from app.knowledge_base.curation import LEGACY_CURATION, apply_legacy_curation
from app.knowledge_base.governance import audit_contracts, review_digest
from app.knowledge_base.holdout import (
    STRIDE, judgment_digest, record_review, scenario_digest, score_holdout, validate_holdout,
)
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.knowledge_base.releases import KnowledgeReleaseStore, ReleaseConflict, ReleaseGateError


FUTURE = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


@pytest.fixture(scope='module')
def rule():
    result = deepcopy(ThreatKnowledgeBase().get_by_id('CTX-AWS-LAMBDA-INVOKE'))
    # These names explicitly identify synthetic attestations used only in tests.
    approval = {'reviewer': 'pytest-rule-reviewer', 'reviewed_at': '2026-01-01',
        'content_digest': review_digest(result['raw'])}
    result['approval'] = approval
    result['raw']['approval'] = approval
    return result


def kb_for(rule):
    return ThreatKnowledgeBase.from_canonical_rules([deepcopy(rule)])


def approve(store, digest, *, waivers=None):
    baseline = store.active()['digest']
    assessment = store.assess(digest, baseline_digest=baseline)
    return store.approve(digest, reviewer='pytest-reviewer', reason='Synthetic test review',
        expected_assessment_digest=assessment['assessment_digest'], valid_until=FUTURE,
        waivers=waivers, baseline_digest=baseline)['approval_id']


def activate(store, digest, *, waivers=None, rollback=False):
    approval_id = approve(store, digest, waivers=waivers)
    return getattr(store, 'rollback' if rollback else 'publish')(digest, approval_id=approval_id,
        actor='pytest-publisher', reason='Synthetic test activation', expected_revision=store.active()['revision'])


def test_artifact_is_content_addressed_and_immutable(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    first = store.stage(kb_for(rule), actor='pytest-author')
    second = store.stage(kb_for(rule), actor='another-author')
    assert first == second
    assert store.active()['digest'] is None
    with sqlite3.connect(store.path) as db:
        with pytest.raises(sqlite3.IntegrityError, match='immutable'):
            db.execute('UPDATE kb_artifacts SET payload = ?', ('{}',))
        with pytest.raises(sqlite3.IntegrityError, match='immutable'):
            db.execute('DELETE FROM kb_artifacts')
    first['payload']['rules'][0]['title'] = 'Changed in caller memory'
    assert store.artifact(first['digest'])['payload']['rules'][0]['title'] == rule['title']


def test_integrity_verification_detects_out_of_band_corruption(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    candidate = store.stage(kb_for(rule), actor='pytest-author')
    with sqlite3.connect(store.path) as db:
        db.execute('DROP TRIGGER kb_artifacts_no_update')
        db.execute('UPDATE kb_artifacts SET payload = ?', ('{}',))
    with pytest.raises(ValueError, match='integrity'):
        store.artifact(candidate['digest'])


def test_author_cannot_self_approve_and_stale_assessment_fails(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(rule), actor='pytest-author')['digest']
    assessment = store.assess(digest)
    assert not assessment['blockers']
    with pytest.raises(ValueError, match='own release'):
        store.approve(digest, reviewer='pytest-author', reason='test',
            expected_assessment_digest=assessment['assessment_digest'], valid_until=FUTURE)
    with pytest.raises(ReleaseConflict):
        store.approve(digest, reviewer='pytest-reviewer', reason='test',
            expected_assessment_digest='0' * 64, valid_until=FUTURE)


def test_publish_and_rollback_preserve_history_and_require_fresh_baseline_review(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    first = store.stage(kb_for(rule), actor='pytest-author')['digest']
    first_approval = approve(store, first)
    assert store.publish(first, approval_id=first_approval, actor='pytest-publisher', reason='test', expected_revision=0)['revision'] == 1
    changed = deepcopy(rule)
    changed['title'] += ' (reworded)'
    second = store.stage(kb_for(changed), actor='pytest-author')['digest']
    assert second != first
    assert activate(store, second)['revision'] == 2
    with pytest.raises(ReleaseConflict, match='baseline'):
        store.rollback(first, approval_id=first_approval, actor='pytest-publisher', reason='test', expected_revision=2)
    assert activate(store, first, rollback=True)['revision'] == 3
    assert [event['action'] for event in store.history()] == ['rollback', 'publish', 'publish']
    assert store.load_active().release_provenance['content_digest'] == first
    assert store.load_active().get_all_threats() == [rule]


def test_pointer_compare_and_swap_and_revoked_review(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(rule), actor='pytest-author')['digest']
    approval_id = approve(store, digest)
    with pytest.raises(ReleaseConflict):
        store.publish(digest, approval_id=approval_id, actor='pytest-publisher', reason='test', expected_revision=9)
    store.revoke_approval(approval_id, actor='pytest-admin', reason='test revocation')
    with pytest.raises(ReleaseGateError, match='revoked'):
        store.publish(digest, approval_id=approval_id, actor='pytest-publisher', reason='test', expected_revision=0)
    assert store.active()['revision'] == 0


def test_configured_runtime_requires_published_approved_release(tmp_path, rule, monkeypatch):
    from app.knowledge_base import loader

    database = tmp_path / 'kb.sqlite'
    monkeypatch.setenv('AEGIS_KB_RELEASE_DB', str(database))
    monkeypatch.setattr(loader, '_kb_instance', None)
    with pytest.raises(RuntimeError, match='refusing bundled fallback'):
        loader.get_knowledge_base()
    store = KnowledgeReleaseStore(database)
    with pytest.raises(KeyError, match='No knowledge release'):
        loader.get_knowledge_base()
    digest = store.stage(kb_for(rule), actor='pytest-author')['digest']
    result = activate(store, digest)
    assert result['restart_required'] and not result['runtime_applied']
    loaded = loader.get_knowledge_base()
    assert loaded.release_provenance['mode'] == 'published_release'
    assert loaded.get_statistics()['release_provenance']['content_digest'] == digest
    assert loader.reload_knowledge_base().release_provenance['content_digest'] == digest
    store.revoke_approval(loaded.release_provenance['approval_id'], actor='pytest-admin', reason='test')
    with pytest.raises(ReleaseGateError, match='revoked'):
        loader.reload_knowledge_base()
    assert loader._kb_instance is None
    with pytest.raises(ReleaseGateError, match='revoked'):
        loader.get_knowledge_base()


def test_expired_published_approval_blocks_next_load_and_can_be_renewed(tmp_path, rule, monkeypatch):
    from app.knowledge_base import releases

    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(rule), actor='pytest-author')['digest']
    activate(store, digest)
    with monkeypatch.context() as patch:
        patch.setattr(releases, '_date', lambda _: datetime.now(timezone.utc) - timedelta(days=1))
        with pytest.raises(ReleaseGateError, match='expired'):
            store.load_active()
    assert activate(store, digest)['revision'] == 2
    assert store.load_active().release_provenance['activation_revision'] == 2


def test_missing_fixtures_are_untested_not_passed_and_need_explicit_waiver(tmp_path, rule):
    legacy = deepcopy(rule)
    legacy['test_contract'] = {}
    legacy['verification'] = ''
    kb = kb_for(legacy)
    results = evaluate_contracts(kb)
    assert results['cases'] == 0
    assert results['coverage']['untested_rule_ids'] == [rule['id']]
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb, actor='pytest-author')['digest']
    with pytest.raises(ReleaseGateError):
        approve(store, digest)
    assessment = store.assess(digest)
    waivers = [{**{key: gap[key] for key in ('rule_id', 'code')}, 'reason': 'Legacy curation is tracked',
        'tracking_reference': 'TEST-KB-1', 'expires_at': FUTURE} for gap in assessment['blockers']]
    published = activate(store, digest, waivers=waivers)
    assert len(published['waived_gaps']) == 2
    assert published['independent_accuracy_established'] is False
    assert store.load_active().governance_audit['issues']


def test_expired_exception_is_rejected(tmp_path, rule):
    legacy = deepcopy(rule)
    legacy['verification'] = ''
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(legacy), actor='pytest-author')['digest']
    with pytest.raises(ValueError, match='expired'):
        approve(store, digest, waivers=[{'rule_id': rule['id'], 'code': 'missing_verification',
            'reason': 'test', 'tracking_reference': 'TEST-1', 'expires_at': PAST}])


def test_regression_failures_and_invalid_fixtures_cannot_be_waived(tmp_path, rule):
    broken = deepcopy(rule)
    broken['test_contract']['control'] = 'a_property_the_rule_does_not_read'
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(broken), actor='pytest-author')['digest']
    assessment = store.assess(digest)
    assert assessment['contracts']['failures']
    with pytest.raises(ValueError, match='waivable'):
        approve(store, digest, waivers=[{'rule_id': None, 'code': 'regression_failed',
            'reason': 'test', 'tracking_reference': 'TEST-1', 'expires_at': FUTURE}])
    broken['test_contract']['cases'] = ['positive']
    report = evaluate_contracts(kb_for(broken))
    assert report['failures'][0]['case'] == 'fixture_schema'


def test_engine_change_invalidates_approval(tmp_path, rule, monkeypatch):
    from app.knowledge_base import releases

    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    digest = store.stage(kb_for(rule), actor='pytest-author')['digest']
    approval_id = approve(store, digest)
    original = releases.evaluate_contracts
    def changed_engine(kb):
        report = original(kb)
        report['results'][0]['passed'] = False
        report['failures'] = [report['results'][0]]
        return report
    monkeypatch.setattr(releases, 'evaluate_contracts', changed_engine)
    with pytest.raises(ReleaseConflict):
        store.publish(digest, approval_id=approval_id, actor='pytest-publisher', reason='test', expected_revision=0)


def test_empty_quarantined_or_loader_invalid_source_cannot_publish(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    empty = ThreatKnowledgeBase.from_canonical_rules([])
    digest = store.stage(empty, actor='pytest-author')['digest']
    assert 'empty_catalog' in {item['code'] for item in store.assess(digest)['blockers']}
    kb = kb_for(rule)
    kb.quarantined_rules = [{'rule_id': 'external', 'reason': 'not reviewed'}]
    kb.validation_issues = [{'module': 'invalid.json', 'issue': 'bad schema'}]
    digest = store.stage(kb, actor='pytest-author')['digest']
    assert {'quarantined_rules_in_source', 'loader_validation_issues'} <= {item['code'] for item in store.assess(digest)['blockers']}


def test_typed_invalid_rule_is_visible_not_an_unhandled_loader_crash(rule):
    kb = ThreatKnowledgeBase.from_canonical_rules([])
    invalid = deepcopy(rule['raw'])
    invalid['detection']['evidence_requirement'] = 'made_up_state'
    assert kb._normalize_and_merge([invalid]) == []
    assert 'typed contract' in kb.validation_issues[0]['issue']
    invalid_snapshot = deepcopy(rule)
    invalid_snapshot['id'] = ''
    with pytest.raises(ValueError, match='Invalid release rule'):
        ThreatKnowledgeBase.from_canonical_rules([invalid_snapshot])


def test_audit_classifies_legacy_work_without_modifying_rules(rule):
    legacy = deepcopy(rule)
    legacy['taxonomy_mapping_quality']['cwe'] = 'stride_category_fallback'
    legacy['approval'] = {}
    legacy['references'] = []
    copy = deepcopy(legacy)
    audit = audit_contracts([legacy])
    assert legacy == copy
    assert {'source_review', 'taxonomy_review', 'human_review'} <= set(audit['workstreams'])
    assert not audit['independent_accuracy_established']


def test_reassessment_is_conservative_about_new_rules_and_unknown_coverage(tmp_path, rule):
    store = KnowledgeReleaseStore(tmp_path / 'kb.sqlite')
    first = store.stage(kb_for(rule), actor='pytest-author')['digest']
    changed = deepcopy(rule)
    changed['severity'] = 'Critical'
    second = store.stage(kb_for(changed), actor='pytest-author')['digest']
    reports = [{'id': 'affected', 'knowledge_provenance': {'content_digest': first, 'evaluated_rule_ids': [rule['id']]}},
        {'id': 'unaffected', 'knowledge_provenance': {'content_digest': first, 'evaluated_rule_ids': []}},
        {'id': 'old-report'}]
    decisions = store.reassessment_plan(first, second, reports)['reports']
    assert [row['reassessment_required'] for row in decisions] == [True, False, True]
    assert decisions[2]['reason'] == 'unknown_previous_coverage'


@pytest.mark.parametrize('identifier', sorted(LEGACY_CURATION))
def test_legacy_curation_adds_actual_source_specific_content_without_fake_approval(identifier):
    kb = ThreatKnowledgeBase()
    rule = kb.get_by_id(identifier)
    assert rule['curation']['base_digest'] == LEGACY_CURATION[identifier]['base_digest']
    assert rule['source_version'] and rule['source_checked_at'] == '2026-10-04'
    assert rule['verification'] == LEGACY_CURATION[identifier]['verification']
    assert rule['counterexamples'] == LEGACY_CURATION[identifier]['counterexamples']
    assert not rule['approval'] and rule['last_reviewed'] is None
    assert not rule['curation']['independent_approval']
    assert set(LEGACY_CURATION[identifier]['references']) <= set(rule['references'])
    original = json.loads((Path(kb.kb_dir) / rule['source_module']).read_text(encoding='utf-8'))
    original = next(row for row in original if (row.get('id') or row.get('threat_id')) == identifier)
    assert not original.get('counterexamples') and not original.get('source_version')
    assert rule['raw'].get('framework_mappings', []) == original.get('framework_mappings', [])
    changed = deepcopy(original)
    changed['description'] = 'A changed threat requires new curation.'
    untouched, issue = apply_legacy_curation(changed)
    assert untouched == changed and issue and not untouched.get('curation')


def test_bounded_legacy_improvement_counts_and_added_regression_coverage():
    kb = ThreatKnowledgeBase()
    assert kb.governance_audit['counts']['legacy_rules_source_curated'] == 12
    curated = [rule for rule in kb.threats if rule.get('curation')]
    deterministic = [rule for rule in curated if rule.get('test_contract')]
    assert len(deterministic) == 8
    report = evaluate_contracts(ThreatKnowledgeBase.from_canonical_rules(deterministic))
    assert report['cases'] == report['passed'] == 56
    assert not report['failures'] and not report['independent_accuracy']
    assert all(rule['rule_kind'] == 'candidate' for rule in curated if not rule.get('test_contract'))


@pytest.fixture
def scenario():
    return {'id': 'test-api', 'query': 'The Payments API accepts webhooks without verifying signatures.',
        'architecture_family': 'payments-webhook-a', 'domains': ['payments'], 'source': 'human_authored',
        'author': 'pytest-author', 'source_reference': 'Synthetic unit-test fixture, not an independent corpus',
        'expected_findings': [{'id': 'signature', 'title': 'Webhook spoofing', 'components': ['Payments API'],
            'stride': 'Spoofing', 'severity': 'High', 'rationale': 'Caller authenticity is not verified.',
            'evidence': [{'source_ref': 'input', 'quote': 'without verifying signatures'}]}],
        'assessed_stride': list(STRIDE), 'label_completeness': 'complete_for_stated_scope'}


TRAINING = [{'query': 'A different application with an identity provider.', 'architecture_family': 'identity-training'}]
POLICY = {'minimum_scenarios': 1, 'required_domains': ['payments'], 'training': TRAINING}


def reviewed(scenario):
    return record_review(scenario, reviewer='pytest-label-reviewer', reason='Synthetic test label check')


def test_holdout_requires_content_bound_review_and_actual_training_inventory(scenario):
    assert not validate_holdout([scenario], **POLICY)['eligible']
    record = reviewed(scenario)
    report = validate_holdout([record], **POLICY)
    assert report['eligible'] and not report['independent_accuracy_established']
    assert not validate_holdout([record], minimum_scenarios=1, required_domains=['payments'])['eligible']
    record['query'] += ' New architecture fact.'
    assert scenario_digest(record) != record['review']['content_digest']
    assert not validate_holdout([record], **POLICY)['eligible']


def test_holdout_rejects_self_review_fabricated_quotes_partial_labels_and_generated_sources(scenario):
    with pytest.raises(ValueError, match='author'):
        record_review(scenario, reviewer=scenario['author'], reason='test')
    invalid = deepcopy(scenario)
    invalid['expected_findings'][0]['evidence'][0]['quote'] = 'not in any supplied source'
    assert not validate_holdout([invalid], **POLICY)['eligible']
    invalid = reviewed(scenario)
    invalid['label_completeness'] = 'partial'
    assert not validate_holdout([reviewed(invalid)], **POLICY)['eligible']
    invalid = deepcopy(scenario)
    invalid['source'] = 'rule_generated'
    assert not validate_holdout([invalid], **POLICY)['eligible']


def test_holdout_detects_duplicate_families_and_training_leakage(scenario):
    record = reviewed(scenario)
    duplicate = deepcopy(scenario)
    duplicate['id'] = 'another-id'
    duplicate['query'] += ' Additional context.'
    report = validate_holdout([record, reviewed(duplicate)], **POLICY)
    assert 'duplicate_architecture_family' in {row['code'] for row in report['issues']}
    leaked = validate_holdout([record], minimum_scenarios=1, required_domains=['payments'],
        training=[{'query': 'Changed wording', 'architecture_family': 'PAYMENTS WEBHOOK A'}])
    assert 'training_leakage' in {row['code'] for row in leaked['issues']}


def test_holdout_reports_uncovered_domains_and_stride_instead_of_inventing_coverage(scenario):
    record = reviewed(scenario)
    result = validate_holdout([record], training=TRAINING)
    assert not result['eligible']
    assert 'missing_domain_coverage' in {item['code'] for item in result['issues']}
    assert 'insufficient_scenarios' in {item['code'] for item in result['issues']}


def test_scoring_requires_complete_prediction_sets_and_reviewed_one_to_one_matches(scenario):
    record = reviewed(scenario)
    predictions = {'test-api': [{'id': 'risk-1', 'title': 'Webhook risk'}, {'id': 'noise', 'title': 'Unrelated risk'}]}
    matches = [{'expected_id': 'signature', 'prediction_id': 'risk-1'}]
    review = {'decision': 'approved', 'reviewer': 'pytest-adjudicator', 'reason': 'Synthetic matching check',
        'reviewed_at': datetime.now(timezone.utc).isoformat(),
        'content_digest': judgment_digest(record, predictions['test-api'], matches)}
    judgments = {'test-api': {'matches': matches, 'review': review}}
    result = score_holdout([record], predictions, judgments, **POLICY)
    assert result['metrics']['precision'] == .5
    assert result['metrics']['recall'] == 1
    assert not result['independent_accuracy_established']
    changed = deepcopy(predictions)
    changed['test-api'][0]['title'] = 'Different actual finding'
    with pytest.raises(ValueError, match='content-bound'):
        score_holdout([record], changed, judgments, **POLICY)
    with pytest.raises(ValueError, match='exactly'):
        score_holdout([record], {}, judgments, **POLICY)
