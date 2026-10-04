"""Installation KB API contracts using isolated stores and synthetic approvals."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.knowledge_base.governance import review_digest
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.knowledge_base.releases import KnowledgeReleaseStore
from app.services import knowledge_admin_api as api
from app.services.assessment_store import AssessmentStore
from app.services.product_store import ProductStore
from app.services.workspace_access import ENV_KEYS


PREFIX = '/enterprise/knowledge'
FUTURE = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()


def headers(name='alice'):
    return {'Authorization': f'Bearer {name}-token'}


@pytest.fixture
def auth(monkeypatch):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('ENVIRONMENT', 'production')
    values = {f'{name}-token': {'name': name, 'role': role, 'products': products}
        for name, role, products in (
            ('alice', 'admin', {'*': 'admin'}), ('bob', 'admin', {'*': 'admin'}),
            ('product-admin', 'admin', {'one-product': 'admin'}),
            ('viewer', 'viewer', {'*': 'viewer'}), ('editor', 'editor', {'*': 'editor'}))}
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps(values))


@pytest.fixture(scope='module')
def canonical_rule():
    rule = deepcopy(ThreatKnowledgeBase().get_by_id('CTX-AWS-LAMBDA-INVOKE'))
    rule['approval'] = {'reviewer': 'pytest-rule-reviewer', 'reviewed_at': '2026-01-01',
        'content_digest': review_digest(rule['raw'])}
    rule['raw']['approval'] = rule['approval']
    return rule


@pytest.fixture
def setup(tmp_path, monkeypatch, auth, canonical_rule):
    store = KnowledgeReleaseStore(tmp_path / 'knowledge.sqlite')
    monkeypatch.setenv('AEGIS_KB_RELEASE_DB', str(store.path))
    kb = ThreatKnowledgeBase.from_canonical_rules([canonical_rule])
    monkeypatch.setattr(api, 'ThreatKnowledgeBase', lambda: ThreatKnowledgeBase.from_canonical_rules(kb.threats))
    app = FastAPI()
    app.state.assessment_store = AssessmentStore(ProductStore(tmp_path / 'workspaces.sqlite'))
    app.state.threat_analyzer = SimpleNamespace(knowledge_base=SimpleNamespace(release_provenance={'mode': 'bundled'}))
    app.include_router(api.router)
    app.dependency_overrides[api.release_store] = lambda: store
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, app=app, store=store, kb=kb)


def stage(setup):
    response = setup.client.post(PREFIX + '/stage', headers=headers())
    assert response.status_code == 200, response.text
    assert response.json()['created_by'] == 'alice'
    return response.json()['content_digest']


def approve(setup, digest, **extra):
    assessment = setup.client.get(f'{PREFIX}/releases/{digest}/assessment', headers=headers()).json()
    body = {'reason': 'Synthetic test release review', 'valid_until': FUTURE,
        'expected_assessment_digest': assessment['assessment_digest'], **extra}
    return setup.client.post(f'{PREFIX}/releases/{digest}/approve', json=body, headers=headers('bob'))


def activate(setup, digest, action='publish'):
    response = approve(setup, digest)
    assert response.status_code == 200, response.text
    return setup.client.post(f'{PREFIX}/releases/{digest}/{action}', headers=headers(), json={
        'reason': 'Synthetic test activation', 'approval_id': response.json()['approval_id'],
        'expected_revision': setup.store.active()['revision']})


@pytest.mark.parametrize('name', ['viewer', 'editor', 'product-admin'])
def test_every_operation_requires_installation_admin(setup, name):
    paths = [('/status', 'get', None), ('/stage', 'post', None),
        (f'/releases/{"0" * 64}/assessment', 'get', None),
        (f'/releases/{"0" * 64}/approve', 'post', {}),
        ('/approvals/1/revoke', 'post', {'reason': 'test'}),
        (f'/releases/{"0" * 64}/reassessment', 'post', {}),
        (f'/releases/{"0" * 64}/publish', 'post', {})]
    for path, method, body in paths:
        response = setup.client.request(method, PREFIX + path, json=body, headers=headers(name))
        assert response.status_code == 403, (path, response.text)
    assert setup.store.active()['revision'] == 0


def test_unauthorized_request_does_not_create_release_database(tmp_path, monkeypatch, auth):
    database = tmp_path / 'not-created.sqlite'
    monkeypatch.setenv('AEGIS_KB_RELEASE_DB', str(database))
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        assert client.get(PREFIX + '/status').status_code == 401
        assert client.get(PREFIX + '/status', headers=headers('product-admin')).status_code == 403
    assert not database.exists()


def test_invalid_release_database_dependency_returns_safe_503(tmp_path, monkeypatch, auth):
    database = tmp_path / 'invalid.sqlite'
    database.write_text('not a SQLite database', encoding='utf-8')
    monkeypatch.setenv('AEGIS_KB_RELEASE_DB', str(database))
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        response = client.get(PREFIX + '/status', headers=headers())
    assert response.status_code == 503
    assert str(database) not in response.text


def test_full_release_lifecycle_uses_server_identity_and_baseline_without_hot_reload(setup):
    first = stage(setup)
    assert approve(setup, first, reviewer='caller-invented').status_code == 422
    response = activate(setup, first)
    assert response.status_code == 200, response.text
    assert response.json()['restart_required'] and not response.json()['runtime_applied']
    assert setup.app.state.threat_analyzer.knowledge_base.release_provenance == {'mode': 'bundled'}
    setup.app.state.threat_analyzer.knowledge_base = setup.store.load_active()
    assert not setup.client.get(PREFIX + '/status', headers=headers()).json()['restart_required']

    setup.kb.threats[0]['severity'] = 'Critical'
    second = stage(setup)
    assert approve(setup, second, baseline_digest=None).status_code == 409
    assert activate(setup, second).status_code == 200  # Omitted baseline binds to the active catalog.
    status = setup.client.get(PREFIX + '/status?history_limit=1', headers=headers()).json()
    assert status['requested']['digest'] == second
    assert status['effective']['content_digest'] == first
    assert status['restart_required'] and len(status['history']) == 1
    assert activate(setup, first, action='rollback').status_code == 200
    assert setup.store.active()['digest'] == first
    # Same content, newer approval/activation still requires restarting workers.
    assert setup.client.get(PREFIX + '/status', headers=headers()).json()['restart_required']


def test_release_error_status_contract(setup):
    client = setup.client
    assert client.get(f'{PREFIX}/releases/not-a-digest/assessment', headers=headers()).status_code == 400
    assert client.get(f'{PREFIX}/releases/{"0" * 64}/assessment', headers=headers()).status_code == 404
    assert client.post(PREFIX + '/approvals/999/revoke', json={'reason': 'test'}, headers=headers()).status_code == 404
    assert client.post(PREFIX + '/approvals/0/revoke', json={'reason': 'test'}, headers=headers()).status_code == 422
    assert client.post(PREFIX + '/approvals/999999999999999999999999/revoke', json={'reason': 'test'}, headers=headers()).status_code == 422
    first = stage(setup)
    assert approve(setup, first, expected_assessment_digest='0' * 64).status_code == 409
    assert approve(setup, first, valid_until='not-a-date').status_code == 400
    assert approve(setup, first, waivers=[{'rule_id': ['invalid'], 'code': ['unhashable']}]).status_code == 422
    approved = approve(setup, first).json()['approval_id']
    body = {'reason': 'test activation', 'approval_id': approved, 'expected_revision': 17}
    assert client.post(f'{PREFIX}/releases/{first}/publish', json=body, headers=headers()).status_code == 409
    assert client.post(f'{PREFIX}/approvals/{approved}/revoke', json={'reason': 'test'}, headers=headers()).status_code == 200
    assert client.post(f'{PREFIX}/approvals/{approved}/revoke', json={'reason': 'test'}, headers=headers()).status_code == 409
    body['expected_revision'] = 0
    blocked = client.post(f'{PREFIX}/releases/{first}/publish', json=body, headers=headers())
    assert blocked.status_code == 422 and blocked.json()['detail']['blockers'][0]['code'] == 'approval_missing_or_revoked'
    setup.kb.threats[0]['verification'] = ''
    candidate = stage(setup)
    blocked = approve(setup, candidate)
    assert blocked.status_code == 422
    assert 'missing_verification' in {item['code'] for item in blocked.json()['detail']['blockers']}


def test_storage_errors_are_service_unavailable_not_tracebacks(setup, monkeypatch):
    def unavailable():
        raise sqlite3.OperationalError('sensitive local path details')
    monkeypatch.setattr(setup.store, 'active', unavailable)
    response = setup.client.get(PREFIX + '/status', headers=headers())
    assert response.status_code == 503
    assert 'sensitive' not in response.text


def save_report(setup, identifier, digest, evaluated=None, **extra):
    assessments = setup.app.state.assessment_store
    assessments.pin_template('assessment-test', 'pytest-author')
    body = {'id': 'caller-style-id-not-authoritative', 'threats': [], 'engine_status': {
        'knowledge_base': {'release': {'content_digest': digest}, 'evaluated_rule_ids': evaluated}}, **extra}
    with assessments.store.connect() as connection:
        connection.execute('INSERT INTO assessment_results VALUES (?,?,?,?,?)',
            (identifier, 'assessment-test', json.dumps(body), 'pytest-analysis-worker', 1))


def test_reassessment_uses_only_authoritative_reports_and_bounds_pages(setup):
    before = stage(setup)
    assert activate(setup, before).status_code == 200
    setup.kb.threats[0]['severity'] = 'Critical'
    after = stage(setup)
    rule_id = setup.kb.threats[0]['id']
    save_report(setup, 'report-a', before, [rule_id])
    save_report(setup, 'report-b', before, [])
    save_report(setup, 'report-c', before, None,
        knowledge_provenance={'content_digest': before, 'evaluated_rule_ids': []})
    path = f'{PREFIX}/releases/{after}/reassessment'
    assert setup.client.post(path, headers=headers(), json={'reports': [{'id': 'invented'}]}).status_code == 422
    first = setup.client.post(path, headers=headers(), json={'limit': 1})
    assert first.status_code == 200, first.text
    first = first.json()
    assert first['source'] == 'authoritative_assessment_results'
    assert first['page_count'] == 1 and first['has_more'] and first['next_after_report_id'] == 'report-a'
    assert first['reports'][0]['report_id'] == 'report-a'
    assert first['reports'][0]['reassessment_required']
    assert first['reports'][0]['assessment_id'] == 'assessment-test'
    assert first['reports'][0]['affected_rule_ids'] == [rule_id]
    assert first['automatic_rerun'] is False
    second = setup.client.post(path, headers=headers(), json={'limit': 1, 'after_report_id': 'report-a'}).json()
    assert second['reports'][0]['report_id'] == 'report-b'
    assert not second['reports'][0]['reassessment_required']
    last = setup.client.post(path, headers=headers(), json={'limit': 1, 'after_report_id': 'report-b'}).json()
    assert last['reports'][0]['report_id'] == 'report-c' and not last['has_more']
    assert last['reports'][0]['reason'] == 'unknown_previous_coverage'
    assert last['reports'][0]['reassessment_required']
    assert setup.app.state.assessment_store.result('report-a')['threats'] == []


@pytest.mark.parametrize('payload', [
    {'limit': 101}, {'limit': 0}, {'report_ids': ['a'] * 101},
    {'report_ids': ['a', 'a']}, {'report_ids': ['a'], 'after_report_id': 'a'},
    {'report_ids': ['a', 'b'], 'limit': 1}, {'baseline_digest': 'invalid'},
])
def test_reassessment_rejects_unbounded_or_ambiguous_selections(setup, payload):
    assert setup.client.post(f'{PREFIX}/releases/{"0" * 64}/reassessment',
        json=payload, headers=headers()).status_code == 422


def test_reassessment_missing_records_and_catalogs_are_not_silent_success(setup):
    digest = stage(setup)
    path = f'{PREFIX}/releases/{digest}/reassessment'
    response = setup.client.post(path, json={'report_ids': ['missing']}, headers=headers())
    assert response.status_code == 404
    response = setup.client.post(f'{PREFIX}/releases/{"0" * 64}/reassessment', json={}, headers=headers())
    assert response.status_code == 404
    response = setup.client.post(path, json={}, headers=headers())
    assert response.status_code == 200 and response.json()['page_count'] == 0


def test_reassessment_handles_legacy_provenance_but_does_not_flag_current_reports(setup):
    digest = stage(setup)
    save_report(setup, 'current-report', digest)
    assessments = setup.app.state.assessment_store
    with assessments.store.connect() as connection:
        connection.execute('INSERT INTO assessment_results VALUES (?,?,?,?,?)',
            ('legacy-malformed', 'assessment-test', 'not valid JSON', 'pytest-worker', 2))
    response = setup.client.post(f'{PREFIX}/releases/{digest}/reassessment',
        json={'report_ids': ['current-report', 'legacy-malformed']}, headers=headers())
    assert response.status_code == 200, response.text
    rows = {item['report_id']: item for item in response.json()['reports']}
    assert not rows['current-report']['reassessment_required']
    assert rows['current-report']['reason'] == 'already_on_target_release'
    assert rows['legacy-malformed']['reassessment_required']
    assert rows['legacy-malformed']['reason'] == 'unknown_previous_coverage'
