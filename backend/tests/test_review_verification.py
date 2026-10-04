"""New closure requests require structured evidence; saved legacy reviews remain readable."""

from datetime import datetime, timezone
import json
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.services.assessment_api import ReviewInput, router
from app.services.assessment_store import AssessmentStore
from app.services.product_store import ProductStore, StoreConflict
from app.services.security_workflows import Verification


ADMIN = {'name': 'security-reviewer', 'role': 'admin'}


@pytest.fixture
def store(tmp_path):
    product_store = ProductStore(tmp_path / 'review-verification.sqlite3')
    result = AssessmentStore(product_store)
    result.pin_template('workspace-review', 'security-reviewer')
    with product_store.connect() as db:
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', (
            'report-review', 'workspace-review', json.dumps({'threats': [{'id': 'risk-review'}]}), 'security-reviewer', time.time()))
    return result


def check(**changes):
    return {'method': 'test', 'reference': 'ci/security-negative-tests/123', 'result': 'passed',
            'checked_at': datetime.fromtimestamp(time.time() - 60, timezone.utc).isoformat(), **changes}


def closure(**changes):
    return {'status': 'verified_fixed', 'remarks': 'Negative tests reviewed for this deployment.', 'owner': 'product-team',
            'acceptance_criteria': ['Cross-account invoice access is rejected.'], 'verification': [check()], **changes}


def save(store, value):
    return store.review('report-review', 'risk-review', value, ADMIN)


@pytest.mark.parametrize('value', [
    {'status': 'verified_fixed', 'remarks': 'Looks fixed.', 'verification_evidence': 'Free-text claim.'},
    closure(acceptance_criteria=[]),
    closure(verification=[]),
    closure(verification=[check(result='failed')]),
    closure(verification=[check(result='inconclusive')]),
    closure(verification=[check(), check(result='failed')]),
    closure(verification=[check(), check(result='inconclusive')]),
], ids=['legacy-text-only', 'missing-criteria', 'missing-checks', 'failed', 'inconclusive', 'mixed-failed', 'mixed-inconclusive'])
def test_new_closure_rejects_incomplete_or_nonpassing_verification(store, value):
    with pytest.raises(ValueError, match='passing structured verification'):
        save(store, value)
    assert store.reviews('report-review')['events'] == []
    assert not any(row['action'] == 'review_finding' for row in store.store.audit_log())


@pytest.mark.parametrize('method', ['test', 'configuration_review', 'code_review', 'independent_report'])
def test_valid_structured_closure_is_persisted_with_compatibility_summary(store, method):
    value = closure(verification=[check(method=method)])
    response = save(store, value)
    saved = response['latest']['risk-review']
    assert saved['status'] == 'verified_fixed'
    assert saved['verification'][0]['method'] == method
    assert saved['verification'][0]['reference'] == value['verification'][0]['reference']
    assert saved['acceptance_criteria'] == value['acceptance_criteria']
    assert saved['verification_status'] == 'reviewer_attested_not_automatically_tested'
    assert 'ci/security-negative-tests/123' in saved['verification_evidence']
    assert saved['security_workflow'] is True
    assert saved['author'] == ADMIN['name']
    assert isinstance(saved['version'], int)


def test_api_and_store_accept_shared_verification_models(store):
    payload = ReviewInput.model_validate(closure())
    assert isinstance(payload.verification[0], Verification)
    result = save(store, payload.model_dump())
    assert result['latest']['risk-review']['verification'][0]['result'] == 'passed'


@pytest.mark.parametrize('changes', [
    {'verification': [check(reference='  ')]},
    {'verification': [check(method='manual_guess')]},
    {'verification': [check(result='Pass')]},
    {'verification': [check(checked_at='not-a-date')]},
    {'verification': [check(extra_secret='rejected')]},
    {'acceptance_criteria': ['  ']},
    {'acceptance_criteria': ['x' * 3001]},
    {'acceptance_criteria': ['A concrete criterion'] * 21},
    {'verification': [check()] * 21},
    {'verification': None},
    {'acceptance_criteria': None},
], ids=['blank-reference', 'method', 'result', 'bad-date', 'extra-field', 'blank-criterion',
        'long-criterion', 'too-many-criteria', 'too-many-checks', 'null-checks', 'null-criteria'])
def test_shared_schema_bounds_apply_to_api_and_direct_store_calls(store, changes):
    value = closure(**changes)
    with pytest.raises(ValidationError):
        ReviewInput.model_validate(value)
    with pytest.raises(ValueError):
        save(store, value)
    assert store.reviews('report-review')['events'] == []


@pytest.mark.parametrize('when', ['2026-10-04T10:00:00', '2026-10-04',
    datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()])
def test_verification_must_be_timezone_aware_and_not_future_dated(store, when):
    with pytest.raises(ValueError, match='Verification'):
        save(store, closure(verification=[check(checked_at=when)]))


def test_failed_evidence_can_be_recorded_without_closing_risk(store):
    result = save(store, closure(status='in_review', verification=[check(result='failed')]))
    saved = result['latest']['risk-review']
    assert saved['status'] == 'in_review' and saved['verification'][0]['result'] == 'failed'


@pytest.mark.parametrize('owner', ['', '  ', None])
def test_verified_fixed_requires_an_accountable_owner(store, owner):
    with pytest.raises(ValueError, match='accountable owner'):
        save(store, closure(owner=owner))
    assert store.reviews('report-review')['events'] == []


def test_stale_structured_closure_does_not_overwrite_a_review(store):
    first = save(store, closure(status='in_review', verification=[]))
    with pytest.raises(StoreConflict):
        save(store, closure(expected_version=0))
    result = save(store, closure(expected_version=first['latest']['risk-review']['version']))
    assert len(result['events']) == 2


def test_old_saved_verified_fixed_records_remain_readable_but_cannot_be_resubmitted_as_new_closure(store):
    legacy = {'status': 'verified_fixed', 'remarks': 'Historical manual review.', 'verification_evidence': 'Old test report.'}
    with store.store.connect() as db:
        cursor = db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
                            ('report-review', 'risk-review', json.dumps(legacy), 'previous-reviewer', 1))
        version = cursor.lastrowid
    response = store.reviews('report-review')
    assert response['latest']['risk-review']['status'] == 'verified_fixed'
    assert response['events'][0]['verification_evidence'] == 'Old test report.'
    assert 'verification' not in response['events'][0]
    with pytest.raises(ValueError, match='structured verification'):
        save(store, {**legacy, 'expected_version': version})
    assert len(store.reviews('report-review')['events']) == 1


def test_security_workflow_marker_and_acceptance_expiry_are_preserved(store):
    expires = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
    response = save(store, {'status': 'accepted', 'owner': 'product-team', 'remarks': 'Time-bound risk decision.',
                            'acceptance_expires_at': expires})
    saved = response['latest']['risk-review']
    assert saved['status'] == 'accepted' and saved['acceptance_expires_at'] == expires
    assert saved['security_workflow'] is True
    with pytest.raises(ValueError, match='expiry'):
        save(store, {'status': 'accepted', 'owner': 'product-team', 'remarks': 'No expiry.', 'expected_version': saved['version']})


@pytest.fixture
def api(store, monkeypatch):
    monkeypatch.setenv('AEGIS_OIDC_ENABLED', 'false')
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'review-token': {
        'name': ADMIN['name'], 'role': 'admin', 'products': {'*': 'admin'}}}))
    product = store.store.create('products', 'Review product', ADMIN['name'])
    release = store.store.create('releases', '26.10', ADMIN['name'], product['id'])
    store.store.save_workspace(release['id'], {'id': 'workspace-review', 'revisions': []}, None, 'production', 0, ADMIN['name'])
    app = FastAPI()
    app.state.product_store = store.store
    app.state.assessment_store = store
    app.include_router(router)
    with TestClient(app, headers={'Authorization': 'Bearer review-token'}) as result:
        yield result


def test_actual_review_endpoint_rejects_legacy_text_and_accepts_structured_evidence(api):
    path = '/enterprise/assessment-reports/report-review/reviews/risk-review'
    bad = api.post(path, json={'status': 'verified_fixed', 'owner': 'product-team', 'remarks': 'Free-text claim.',
                               'verification_evidence': 'Tested manually.'})
    assert bad.status_code == 400 and 'structured verification' in bad.json()['detail']
    good = api.post(path, json=closure())
    assert good.status_code == 200
    assert good.json()['latest']['risk-review']['verification'][0]['result'] == 'passed'
    assert api.get('/enterprise/assessment-reports/report-review/reviews').status_code == 200


def test_actual_review_endpoint_rejects_failed_and_invalid_evidence(api):
    path = '/enterprise/assessment-reports/report-review/reviews/risk-review'
    assert api.post(path, json=closure(verification=[check(result='failed')])).status_code == 400
    assert api.post(path, json=closure(verification=[check(method='guess')])).status_code == 422
    assert api.post(path, json=closure(verification=[check(reference='')])).status_code == 422


def test_import_graph_has_no_assessment_workflow_cycle():
    import importlib
    assert importlib.import_module('app.services.security_workflows').Verification is Verification
    assert importlib.import_module('app.services.assessment_store').AssessmentStore is AssessmentStore
    assert importlib.import_module('app.services.security_workflow_api').router is not None
    assert importlib.import_module('app.services.assessment_api').ReviewInput is ReviewInput
