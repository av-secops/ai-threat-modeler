"""Hermetic workflow tests: no Jira/cloud calls, no production database writes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.services.product_store import ProductStore, StoreConflict
from app.services.security_workflows import (SecurityWorkflows, JiraConnections, JiraConnection, JiraAdapter,
    JiraFailure, PatternInput, RiskReview, TicketLink, MAX_ATTEMPTS, LEASE_SECONDS,
    workflow_review_overlays, effective_workflow_review)
from app.services.security_workflow_api import router, start_security_workflows, principal


ADMIN = {'name': 'security-architect', 'role': 'admin'}
EDITOR = {'name': 'product-engineer', 'role': 'editor'}
VIEWER = {'name': 'read-only', 'role': 'viewer'}


def date(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


@pytest.fixture
def setup(tmp_path):
    store = ProductStore(tmp_path / 'workflow.sqlite3')
    clock = [1_800_000_000.0]
    service = SecurityWorkflows(store, clock=lambda: clock[0])
    product = store.create('products', 'Workflow product', 'test')['id']
    release = store.create('releases', '26.10', 'test', product)['id']
    application = store.create('applications', 'Portal', 'test', product)['id']
    workspace = 'workspace-1'
    report = {'threats': [{'id': 'f1', 'title': 'Missing scoped authorization', 'severity': 'High'},
                          {'id': 'f2', 'title': 'Missing audit records', 'severity': 'Medium'}],
              'architecture': {'components': [{'id': 'api', 'type': 'API', 'properties': {'mfa_enabled': False}},
                                                {'id': 'db', 'type': 'Database', 'properties': {}}]},
              'engine_status': {'assessment': {'id': workspace, 'report_id': 'report-1'}}}
    # Minimal authoritative assessment storage; production creates this through AssessmentStore.
    with store.connect() as db:
        db.execute('CREATE TABLE assessment_results(id TEXT PRIMARY KEY,assessment_id TEXT,body TEXT,actor TEXT,created REAL)')
        db.execute('''CREATE TABLE finding_review_events(id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,finding_id TEXT,body TEXT,actor TEXT,created REAL)''')
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', ('report-1', workspace, json.dumps(report), 'test', clock[0]))
    store.save_workspace(release, {'id': workspace, 'revisions': [{'number': 1, 'data': report}]}, application, 'production', 0, 'test')
    connections = JiraConnections({'corporate': {'base_url': 'https://example.atlassian.net', 'project_key': 'SEC',
        'product_ids': [product], 'username_env': 'TEST_JIRA_USER', 'token_env': 'TEST_JIRA_TOKEN'}})
    return SimpleNamespace(store=store, service=service, product=product, release=release, application=application,
                           workspace=workspace, report=report, clock=clock, connections=connections)


def scope(s):
    return s.product, s.workspace, 1


def pattern(s, **values):
    return {'name': 'Corporate API authentication', 'owner': 'identity-team', 'description': 'Managed API identity controls',
        'environment': 'production', 'application_id': s.application, 'component_types': ['API'],
        'controls': [{'control': 'mfa_enabled', 'state': 'present', 'statement': 'MFA is enforced by the identity provider.',
                      'source_references': ['policy/identity-v3']}], 'expires_at': date(s.clock[0] + 86400), **values}


def publish(s, **values):
    result = s.service.create_pattern_version(s.product, pattern(s, **values), EDITOR)
    return s.service.transition_pattern(s.product, result['pattern_id'], 1,
        {'status': 'published', 'expected_revision': 1, 'reason': 'Reviewed scoped control documentation'}, ADMIN)


def inheritance(row, **values):
    return {'pattern_id': row['pattern_id'], 'pattern_version': row['version'], 'component_ids': ['api'],
            'reason': 'This API uses the corporate identity provider.', **values}


def review(s, **values):
    return s.service.review_risk(*scope(s), 'f1', {'owner': 'payments-team', 'remarks': 'Assign for architecture review.',
                                                 'status': 'in_review', **values}, ADMIN)


def link(s):
    review(s)
    return s.service.link_ticket(*scope(s), 'f1', {'connection': 'corporate', 'issue_key': 'SEC-123'}, EDITOR, s.connections)


class FakeJira:
    def __init__(self, status='Done', fail=None):
        self.status, self.fail, self.reads, self.writes = status, fail, [], []

    def read_issue(self, key):
        self.reads.append(key)
        if self.fail:
            raise self.fail
        return {'key': key, 'project_key': 'SEC', 'status': self.status, 'updated': '2026-10-04T10:00:00Z'}

    def update_property(self, key, body):
        self.writes.append((key, body))


def dispatch(s, fake=None, limit=5):
    fake = fake or FakeJira()
    return s.service.dispatch(s.product, ADMIN, s.connections, limit=limit, adapter_factory=lambda config: fake)


def test_patterns_immutable_versions_and_audit(setup):
    s = setup
    row = publish(s)
    assert row['revision'] == 2
    next_version = s.service.create_pattern_version(s.product, pattern(s, expected_version=1, owner='platform-team'), EDITOR, row['pattern_id'])
    assert next_version['version'] == 2 and next_version['status'] == 'draft'
    listed = s.service.patterns(s.product)['items']
    assert len(listed) == 2 and listed[1]['body']['owner'] == 'identity-team'
    with pytest.raises(StoreConflict):
        s.service.create_pattern_version(s.product, pattern(s, expected_version=1), EDITOR, row['pattern_id'])
    with pytest.raises(StoreConflict):
        s.service.transition_pattern(s.product, row['pattern_id'], 1,
            {'status': 'retired', 'expected_revision': 1, 'reason': 'Stale review'}, ADMIN)
    assert len(s.service.events(s.product, row['pattern_id'])['items']) == 3
    assert any(e['action'] == 'security_workflows.pattern_published' for e in s.store.audit_log())


def test_inheritance_is_scoped_evidence_not_suppression(setup):
    s = setup
    row = publish(s)
    result = s.service.inherit_pattern(*scope(s), inheritance(row), EDITOR)
    claim = result['claims'][0]
    assert claim['state'] == 'conflicting' and claim['declared_state'] == 'present'
    assert claim['verification_status'] == 'requires_validation' and claim['suppresses_finding'] is False
    assert result['environment'] == 'production' and result['report_revision'] == 1
    assert s.service.inherit_pattern(*scope(s), inheritance(row), EDITOR)['id'] == result['id']
    assert len(s.service.inherited_evidence(*scope(s))['items']) == 1
    assert s.store.workspace(s.workspace)['workspace']['revisions'][0]['data'] == s.report
    s.clock[0] += 86401
    assert s.service.inherited_evidence(*scope(s))['items'][0]['stale']
    with pytest.raises(StoreConflict, match='unexpired'):
        s.service.inherit_pattern(*scope(s), inheritance(row), EDITOR)


@pytest.mark.parametrize('changes', [{'environment': 'staging'}, {'application_id': None}])
def test_no_cross_environment_or_application_inheritance(setup, changes):
    row = publish(setup, **changes)
    with pytest.raises(ValueError, match='scope'):
        setup.service.inherit_pattern(*scope(setup), inheritance(row), EDITOR)


def test_no_wrong_component_or_product_inheritance(setup):
    s = setup
    row = publish(s)
    for component in ['db', 'does-not-exist']:
        with pytest.raises(ValueError, match='component'):
            s.service.inherit_pattern(*scope(s), inheritance(row, component_ids=[component]), EDITOR)
    other = s.store.create('products', 'Other product', 'test')['id']
    with pytest.raises(LookupError):
        s.service.inherit_pattern(other, s.workspace, 1, inheritance(row), EDITOR)
    other_app = s.store.create('applications', 'Other portal', 'test', other)['id']
    with pytest.raises(ValueError, match='another product'):
        s.service.create_pattern_version(s.product, pattern(s, application_id=other_app), EDITOR)


def test_retirement_stales_bindings_and_drafts_cannot_inherit(setup):
    s = setup
    row = s.service.create_pattern_version(s.product, pattern(s), EDITOR)
    with pytest.raises(StoreConflict):
        s.service.inherit_pattern(*scope(s), inheritance(row), EDITOR)
    s.service.transition_pattern(s.product, row['pattern_id'], 1,
        {'status': 'published', 'expected_revision': 1, 'reason': 'Ready for use'}, ADMIN)
    s.service.inherit_pattern(*scope(s), inheritance(row), EDITOR)
    s.service.transition_pattern(s.product, row['pattern_id'], 1,
        {'status': 'retired', 'expected_revision': 2, 'reason': 'Provider configuration changed'}, ADMIN)
    assert s.service.inherited_evidence(*scope(s))['items'][0]['stale']


@pytest.mark.parametrize('expires', [0, -1, 367 * 86400])
def test_pattern_expiry_bounded(setup, expires):
    with pytest.raises(ValueError):
        setup.service.create_pattern_version(setup.product, pattern(setup, expires_at=date(setup.clock[0] + expires)), EDITOR)


def test_pending_risks_listing_uses_authoritative_report(setup):
    s = setup
    result = s.service.risk_register(*scope(s), limit=1)
    assert result['total'] == 2 and result['next_offset'] == 1
    assert result['items'][0]['review']['version'] == 0
    assert result['items'][0]['review']['effective_status'] == 'pending_review'
    # A caller-controlled snapshot cannot invent a finding absent from the server report.
    with s.store.connect() as db:
        db.execute("UPDATE workspaces SET payload=json_set(payload,'$.revisions[0].data.threats[0].id','forged') WHERE id=?", (s.workspace,))
    assert s.service.risk_register(*scope(s))['items'][0]['finding']['id'] == 'f1'
    with pytest.raises(LookupError):
        s.service.review_risk(*scope(s), 'forged', {'remarks': 'Invented risk'}, ADMIN)


def test_risk_cannot_reference_another_workspace_report(setup):
    s = setup
    s.store.save_workspace(s.release, {'id': 'forged', 'revisions': [{'number': 1, 'data': s.report}]},
                           s.application, 'production', 0, 'test')
    with pytest.raises(ValueError, match='belonging'):
        s.service.review_risk(s.product, 'forged', 1, 'f1', {'remarks': 'Cross-workspace test'}, ADMIN)
    with pytest.raises(LookupError):
        s.service.review_risk(s.product, s.workspace, 99, 'f1', {'remarks': 'Missing revision'}, ADMIN)


def test_risk_optimistic_lock_comments_and_history(setup):
    s = setup
    first = review(s)
    with pytest.raises(StoreConflict):
        review(s, remarks='Stale review')
    comment = s.service.comment_risk(*scope(s), 'f1', {'expected_version': 1, 'comment': 'Product owner will review on Monday.'}, EDITOR)
    assert comment['version'] == 2 and comment['body']['owner'] == first['body']['owner']
    assert len(s.service.events(s.product, first['id'])['items']) == 2
    assert s.service.risk_register(*scope(s))['items'][0]['review']['version'] == 2


def test_concurrent_risk_reviews_have_one_winner(setup):
    s = setup
    review(s)

    def attempt(index):
        try:
            review(s, expected_version=1, remarks='Concurrent review ' + str(index))
            return True
        except StoreConflict:
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt, range(4))) == 1


def test_expiring_acceptance_immediate_and_auditable(setup):
    s = setup
    accepted = review(s, status='accepted', acceptance_expires_at=date(s.clock[0] + 30), target_date=date(s.clock[0] + 20))
    assert not accepted['closed']
    s.clock[0] += 31
    before_sweep = s.service.risks(*scope(s))['items'][0]
    assert before_sweep['acceptance_expired'] and before_sweep['effective_status'] == 'pending_review' and before_sweep['overdue']
    expired = s.service.expire_acceptances(s.product, ADMIN)
    assert expired[0]['version'] == 2 and expired[0]['body']['status'] == 'pending_review'
    assert expired[0]['body']['owner'] == 'payments-team'
    assert s.service.expire_acceptances(s.product, ADMIN) == []
    assert s.service.events(s.product, accepted['id'])['items'][0]['action'] == 'risk_acceptance_expired'


def test_verified_fixed_requires_actual_attestation_and_reopening(setup):
    s = setup
    for values in [{}, {'acceptance_criteria': ['Authorization tests pass']},
                   {'acceptance_criteria': ['Authorization tests pass'], 'verification': [
                       {'method': 'test', 'reference': 'ci/run-123', 'result': 'failed', 'checked_at': date(s.clock[0])}]}]:
        with pytest.raises(ValueError, match='passing verification'):
            review(s, status='verified_fixed', **values)
    evidence = {'acceptance_criteria': ['Object-level negative tests pass'], 'verification': [
        {'method': 'test', 'reference': 'ci/run-123', 'result': 'passed', 'checked_at': date(s.clock[0])}]}
    fixed = review(s, status='verified_fixed', **evidence)
    assert fixed['closed'] and fixed['body']['verification_status'] == 'reviewer_attested_not_automatically_tested'
    with pytest.raises(StoreConflict, match='Reopen'):
        review(s, status='verified_fixed', expected_version=1, **evidence)
    assert not review(s, status='in_review', expected_version=1)['closed']


@pytest.mark.parametrize('status', ['accepted', 'verified_fixed', 'false_positive'])
def test_final_decisions_require_admin(setup, status):
    with pytest.raises(PermissionError):
        setup.service.review_risk(*scope(setup), 'f1', {'status': status, 'owner': 'team', 'remarks': 'Team decision'}, EDITOR)


def test_owner_deadline_and_verification_constraints(setup):
    s = setup
    for values in [{'owner': ''}, {'status': 'accepted'},
                   {'acceptance_expires_at': date(s.clock[0] + 50)},
                   {'status': 'accepted', 'acceptance_expires_at': date(s.clock[0] + 367 * 86400)},
                   {'target_date': '2026-10-04T12:00:00'},
                   {'verification': [{'method': 'test', 'reference': 'future-test', 'result': 'passed', 'checked_at': date(s.clock[0] + 1000)}]}]:
        with pytest.raises(ValueError):
            review(s, **values)


def test_archived_product_rejects_mutations(setup):
    s = setup
    s.store.update_product(s.product, 'Workflow product', True, 'test')
    with pytest.raises(StoreConflict):
        review(s)
    with pytest.raises(StoreConflict):
        s.service.create_pattern_version(s.product, pattern(s), EDITOR)


def test_ticket_link_idempotence_queue_and_no_auto_closure(setup):
    s = setup
    ticket = link(s)
    same = s.service.link_ticket(*scope(s), 'f1', {'connection': 'corporate', 'issue_key': 'SEC-123'}, EDITOR, s.connections)
    assert same['id'] == ticket['id']
    assert len(s.service.outbox(s.product)['items']) == 1
    assert not ticket['body']['verified_link']
    assert dispatch(s)[0]['state'] == 'succeeded'
    linked = s.service.ticket_links(*scope(s), 'f1')[0]
    assert linked['body']['remote_status'] == 'Done' and linked['body']['verified_link']
    assert s.service.risks(*scope(s))['items'][0]['effective_status'] == 'in_review'


def test_ticket_push_only_owned_property_and_duplicate_requests(setup):
    s = setup
    ticket = link(s)
    payload = {'operation': 'push', 'idempotency_key': 'push-0001'}
    with pytest.raises(StoreConflict, match='verify'):
        s.service.enqueue_ticket(s.product, ticket['id'], payload, EDITOR, s.connections)
    dispatch(s)
    queued = s.service.enqueue_ticket(s.product, ticket['id'], payload, EDITOR, s.connections)
    assert s.service.enqueue_ticket(s.product, ticket['id'], payload, EDITOR, s.connections)['id'] == queued['id']
    fake = FakeJira()
    dispatch(s, fake)
    assert len(fake.writes) == 1 and fake.writes[0][1]['review_status'] == 'in_review'
    assert 'architecture' not in fake.writes[0][1] and 'verification' not in fake.writes[0][1]
    assert dispatch(s, fake) == []
    with pytest.raises(StoreConflict):
        s.service.enqueue_ticket(s.product, ticket['id'], {'operation': 'pull', 'idempotency_key': 'push-0001'}, EDITOR, s.connections)


def test_stale_push_superseded_and_acceptance_expiry_not_exported_stale(setup):
    s = setup
    ticket = link(s)
    dispatch(s)
    s.service.enqueue_ticket(s.product, ticket['id'], {'operation': 'push', 'idempotency_key': 'push-0002'}, EDITOR, s.connections)
    review(s, expected_version=1, status='accepted', acceptance_expires_at=date(s.clock[0] + 10))
    assert dispatch(s)[0]['state'] == 'superseded'
    s.service.enqueue_ticket(s.product, ticket['id'], {'operation': 'push', 'idempotency_key': 'push-0003'}, EDITOR, s.connections)
    s.clock[0] += 11
    fake = FakeJira()
    assert dispatch(s, fake)[0]['state'] == 'superseded'
    assert fake.writes == []


def test_retry_backoff_redacted_errors_and_max_attempts(setup):
    s = setup
    link(s)
    fake = FakeJira(fail=RuntimeError('secret-token-response'))
    for index in range(MAX_ATTEMPTS):
        result = dispatch(s, fake)[0]
        assert result['attempts'] == index + 1
        assert 'secret-token' not in result['error']
        assert result['state'] == ('failed' if index + 1 == MAX_ATTEMPTS else 'retry_wait')
        assert dispatch(s, fake) == []
        s.clock[0] = result['due']


def test_nonretryable_remote_failure_and_retry_after(setup):
    s = setup
    link(s)
    result = dispatch(s, FakeJira(fail=JiraFailure('Rate limited.', retryable=True, retry_after=500)))[0]
    assert result['due'] == s.clock[0] + 500
    s.clock[0] += 500
    assert dispatch(s, FakeJira(fail=JiraFailure('Forbidden.', retryable=False)))[0]['state'] == 'failed'


def test_crashed_worker_lease_is_recoverable(setup):
    s = setup
    link(s)
    claimed = s.service._claim(s.product, ADMIN['name'])
    assert claimed['attempts'] == 1 and dispatch(s) == []
    s.clock[0] += LEASE_SECONDS + 1
    assert dispatch(s)[0]['attempts'] == 2


def test_connector_scope_change_blocks_existing_ticket(setup):
    s = setup
    ticket = link(s)
    changed = JiraConnections({'corporate': {'base_url': 'https://another.atlassian.net', 'project_key': 'SEC',
        'product_ids': [s.product], 'username_env': 'TEST_JIRA_USER', 'token_env': 'TEST_JIRA_TOKEN'}})
    fake = FakeJira()
    result = s.service.dispatch(s.product, ADMIN, changed, adapter_factory=lambda config: fake)[0]
    assert result['state'] == 'failed' and fake.reads == []
    with pytest.raises(StoreConflict):
        s.service.enqueue_ticket(s.product, ticket['id'], {'operation': 'pull', 'idempotency_key': 'scope-001'}, EDITOR, changed)


def test_ticket_identity_and_cross_product_protection(setup):
    s = setup
    link(s)
    wrong = FakeJira()
    wrong.read_issue = lambda key: {'key': 'OTHER-123', 'project_key': 'OTHER', 'status': 'Done'}
    assert dispatch(s, wrong)[0]['state'] == 'failed'
    assert not s.service.ticket_links(*scope(s), 'f1')[0]['body']['verified_link']
    other = s.store.create('products', 'Other', 'test')['id']
    with pytest.raises(ValueError):
        s.connections.get('corporate', other)
    with pytest.raises(ValueError):
        s.service.link_ticket(*scope(s), 'f1', {'connection': 'corporate', 'issue_key': 'BAD-123'}, EDITOR, s.connections)


@pytest.mark.parametrize('url', ['http://example.com', 'https://user:pass@example.com', 'https://example.com/api',
                                'https://example.com?token=abc', 'https://example.com:8080', 'https://example.com/#abc'])
def test_jira_origin_validation(setup, url):
    config = setup.connections.get('corporate', setup.product).model_dump()
    config['base_url'] = url
    with pytest.raises(ValidationError):
        JiraConnection.model_validate(config)


@pytest.mark.parametrize('address', ['127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', '100.64.0.1'])
def test_jira_dns_blocks_private_and_metadata_before_connecting(setup, monkeypatch, address):
    monkeypatch.setenv('TEST_JIRA_USER', 'test@example.com')
    monkeypatch.setenv('TEST_JIRA_TOKEN', 'not-a-real-token')
    monkeypatch.setattr('app.services.security_workflows.socket.getaddrinfo', lambda *args, **kwargs: [(0, 0, 0, '', (address, 443))])
    pool = Mock(side_effect=AssertionError('Network must not be contacted'))
    monkeypatch.setattr('app.services.security_workflows.urllib3.HTTPSConnectionPool', pool)
    adapter = JiraAdapter(setup.connections.get('corporate', setup.product))
    with pytest.raises(JiraFailure, match='public addresses'):
        adapter.read_issue('SEC-123')
    pool.assert_not_called()


def test_jira_http_contract_tls_pinning_and_owned_property(setup, monkeypatch):
    monkeypatch.setenv('TEST_JIRA_USER', 'test@example.com')
    monkeypatch.setenv('TEST_JIRA_TOKEN', 'not-a-real-token')
    monkeypatch.setattr('app.services.security_workflows.socket.getaddrinfo', lambda *args, **kwargs: [(0, 0, 0, '', ('93.184.216.34', 443))])
    response = Mock(status=200, headers={})
    response.read.return_value = json.dumps({'key': 'SEC-123', 'fields': {'project': {'key': 'SEC'}, 'status': {'name': 'Done'}}}).encode()
    pool = Mock()
    pool.request.return_value = response
    context = Mock()
    context.__enter__ = Mock(return_value=pool)
    context.__exit__ = Mock(return_value=False)
    factory = Mock(return_value=context)
    monkeypatch.setattr('app.services.security_workflows.urllib3.HTTPSConnectionPool', factory)
    adapter = JiraAdapter(setup.connections.get('corporate', setup.product))
    assert adapter.read_issue('SEC-123')['status'] == 'Done'
    assert factory.call_args.args[0] == '93.184.216.34'
    assert factory.call_args.kwargs['assert_hostname'] == 'example.atlassian.net'
    assert pool.request.call_args.kwargs['redirect'] is False
    response.read.return_value = b''
    response.status = 204
    adapter.update_property('SEC-123', {'risk_id': 'risk-1'})
    assert pool.request.call_args.args == ('PUT', '/rest/api/3/issue/SEC-123/properties/com.aegis.threat-model')
    assert pool.request.call_args.kwargs['retries'] is False
    assert response.close.call_count == 2


@pytest.mark.parametrize('status,encoding,body', [(302, '', b''), (200, 'gzip', b'compressed'),
                                                (200, '', b'x' * 256001), (200, '', b'not-json')],
                         ids=['redirect', 'compression', 'oversized', 'invalid-json'])
def test_jira_responses_are_bounded_and_redirects_rejected(setup, monkeypatch, status, encoding, body):
    monkeypatch.setenv('TEST_JIRA_USER', 'test@example.com')
    monkeypatch.setenv('TEST_JIRA_TOKEN', 'not-a-real-token')
    monkeypatch.setattr('app.services.security_workflows.socket.getaddrinfo', lambda *args, **kwargs: [(0, 0, 0, '', ('93.184.216.34', 443))])
    response = Mock(status=status, headers={'Content-Encoding': encoding})
    response.read.return_value = body
    context = Mock()
    context.__enter__ = Mock(return_value=Mock(request=Mock(return_value=response)))
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr('app.services.security_workflows.urllib3.HTTPSConnectionPool', Mock(return_value=context))
    with pytest.raises(JiraFailure):
        JiraAdapter(setup.connections.get('corporate', setup.product)).read_issue('SEC-123')
    response.close.assert_called_once()


def test_input_limits_and_unknown_fields(setup):
    with pytest.raises(ValidationError):
        RiskReview.model_validate({'remarks': 'Good reason', 'owner': 'x' * 201})
    with pytest.raises(ValidationError):
        PatternInput.model_validate(pattern(setup, controls=[]))
    with pytest.raises(ValidationError):
        TicketLink.model_validate({'connection': 'corporate', 'issue_key': 'SEC-123/../../admin'})
    with pytest.raises(ValidationError):
        TicketLink.model_validate({'connection': 'corporate', 'issue_key': 'SEC-123', 'base_url': 'https://evil.example'})
    large_control = {'control': 'mfa_enabled', 'state': 'present', 'statement': 'x' * 3000,
                     'source_references': ['x' * 3000] * 20}
    another_control = {**large_control, 'control': 'logging_enabled'}
    with pytest.raises(ValueError, match='64 KB'):
        setup.service.create_pattern_version(setup.product, pattern(setup, controls=[large_control, another_control]), EDITOR)


def client(s, identity=ADMIN, policy=None):
    app = FastAPI()
    app.state.product_store = s.store
    start_security_workflows(app, access=policy)
    app.state.security_workflows.clock = lambda: s.clock[0]
    app.include_router(router)
    app.dependency_overrides[principal] = lambda: identity
    return TestClient(app)


def base(s):
    return '/enterprise/products/' + s.product + '/security-workflows'


def test_api_requires_explicit_access_policy_for_authenticated_users(setup):
    assert client(setup).get(base(setup) + '/patterns').status_code == 503
    assert client(setup, policy=lambda **kwargs: False).get(base(setup) + '/patterns').status_code == 403
    assert client(setup, policy=lambda **kwargs: None).get(base(setup) + '/patterns').status_code == 403


def test_api_list_review_comment_and_pattern_contract(setup):
    s = setup
    policy = Mock(return_value=True)
    api = client(s, policy=policy)
    path = base(s) + '/workspaces/' + s.workspace + '/revisions/1/risks'
    assert api.get(path).json()['total'] == 2
    response = api.put(path + '/f1', json={'status': 'in_review', 'owner': 'app-team', 'remarks': 'Please review this risk.'})
    assert response.status_code == 200 and response.json()['version'] == 1
    assert policy.call_args.kwargs['workspace_id'] == s.workspace and policy.call_args.kwargs['write']
    assert api.put(path + '/f1', json={'remarks': 'Stale update'}).status_code == 409
    assert api.put(path + '/invented', json={'remarks': 'Missing finding'}).status_code == 404
    assert api.post(path + '/f1/comments', json={'expected_version': 1, 'comment': 'Owner is investigating.'}).json()['version'] == 2
    assert len(api.get(path + '/f1/events').json()['items']) == 2
    created = api.post(base(s) + '/patterns', json=pattern(s))
    assert created.status_code == 200
    assert len(api.get(base(s) + '/patterns').json()['items']) == 1
    assert api.get(path + '?limit=101').status_code == 422
    assert api.get(base(s) + '/outbox').json()['items'] == []


def test_api_viewer_read_only_and_dispatch_disabled(setup, monkeypatch):
    s = setup
    api = client(s, VIEWER, lambda **kwargs: True)
    assert api.get(base(s) + '/patterns').status_code == 200
    assert api.post(base(s) + '/patterns', json=pattern(s)).status_code == 403
    monkeypatch.delenv('AEGIS_JIRA_SYNC_ENABLED', raising=False)
    admin = client(s, policy=lambda **kwargs: True)
    assert admin.post(base(s) + '/outbox/dispatch', json={}).status_code == 409


def test_api_product_and_workspace_policies_are_both_enforced_for_sync(setup):
    s = setup
    ticket = link(s)
    seen = []

    def guard(**kwargs):
        seen.append(kwargs['workspace_id'])
        return kwargs['workspace_id'] is None
    api = client(s, policy=guard)
    result = api.post(base(s) + '/tickets/' + ticket['id'] + '/sync', json={'operation': 'pull', 'idempotency_key': 'denied-001'})
    assert result.status_code == 403 and seen == [None, s.workspace]


def test_canonical_register_receives_reviews_and_expiration_overlay(setup):
    s = setup
    decision = review(s, status='accepted', acceptance_expires_at=date(s.clock[0] + 10), target_date=date(s.clock[0] + 5))
    with s.store.read_snapshot() as db:
        canonical = db.execute('SELECT * FROM finding_review_events ORDER BY id DESC LIMIT 1').fetchone()
        assert decision['canonical_version'] == canonical['id']
        assert json.loads(canonical['body'])['owner'] == 'payments-team'
        before = workflow_review_overlays(db, s.product, now=s.clock[0])
    s.clock[0] += 11
    with s.store.read_snapshot() as db:
        after = workflow_review_overlays(db, s.product, now=s.clock[0])
        assert workflow_review_overlays(db, 'nonexistent-product', now=s.clock[0]) == {}
    projected = json.loads(after[('report-1', 'f1')]['body'])
    assert projected['status'] == 'pending_review' and projected['overdue'] and projected['acceptance_expired']
    assert before[('report-1', 'f1')]['id'] != after[('report-1', 'f1')]['id']
    assert json.loads(canonical['body'])['status'] == 'accepted'
    s.service.expire_acceptances(s.product, ADMIN)
    with s.store.read_snapshot() as db:
        latest = db.execute('SELECT body FROM finding_review_events ORDER BY id DESC LIMIT 1').fetchone()
    assert json.loads(latest['body'])['status'] == 'pending_review'


def test_dashboard_reads_workflow_projection_as_open_after_expiry(setup):
    from app.services.product_dashboard import _load, _build, DashboardFilters
    s = setup
    review(s, status='accepted', acceptance_expires_at=date(s.clock[0] + 10))
    with s.store.read_snapshot() as db:
        data = _load(db, s.product)
        data[-1].update(workflow_review_overlays(db, s.product, now=s.clock[0]))
        before, _ = _build(data, s.product, DashboardFilters())
    s.clock[0] += 11
    with s.store.read_snapshot() as db:
        data = _load(db, s.product)
        data[-1].update(workflow_review_overlays(db, s.product, now=s.clock[0]))
        after, rows = _build(data, s.product, DashboardFilters())
    assert before['metrics']['accepted_risks'] == 1
    assert after['metrics']['accepted_risks'] == 0 and after['metrics']['open_risks'] == 2
    assert before['snapshot'] != after['snapshot']
    assert next(row for row in rows if row['finding_id'] == 'f1')['owner'] == 'payments-team'


def test_concurrent_legacy_decision_cannot_be_overwritten_or_expired(setup):
    s = setup
    review(s, status='accepted', acceptance_expires_at=date(s.clock[0] + 10))
    with s.store.connect() as db:
        event = db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
            ('report-1', 'f1', json.dumps({'status': 'in_review', 'owner': 'new-owner', 'remarks': 'Fresh review'}), 'legacy-reviewer', s.clock[0]))
        canonical_version = event.lastrowid
    with pytest.raises(StoreConflict, match='another risk register'):
        review(s, expected_version=1)
    refreshed = s.service.risk_register(*scope(s))['items'][0]['review']
    assert refreshed['superseded_by_risk_register'] and refreshed['body']['owner'] == 'new-owner'
    assert refreshed['canonical_version'] == canonical_version
    s.clock[0] += 11
    assert s.service.expire_acceptances(s.product, ADMIN) == []
    with s.store.read_snapshot() as db:
        assert workflow_review_overlays(db, s.product, now=s.clock[0]) == {}
    assert review(s, expected_version=1, expected_canonical_version=canonical_version)['version'] == 2


def test_global_admin_product_editor_cannot_accept_or_close(setup):
    from app.services.workspace_access import VerifiedIdentity
    s = setup
    identity = VerifiedIdentity(name='scoped-admin', role='admin', subject='sub', issuer='operator',
        auth_method='token', products=((s.product, 'editor'),), display_name='Scoped admin')
    payload = {'owner': 'team', 'remarks': 'Forbidden decision', 'status': 'accepted',
               'acceptance_expires_at': date(s.clock[0] + 100)}
    with pytest.raises(HTTPException) as caught:
        s.service.review_risk(*scope(s), 'f1', payload, identity)
    assert caught.value.status_code == 403
    api = client(s, identity)
    path = base(s) + '/workspaces/' + s.workspace + '/revisions/1/risks/f1'
    assert api.put(path, json=payload).status_code == 403
    payload['status'] = 'in_review'
    payload.pop('acceptance_expires_at')
    assert api.put(path, json=payload).status_code == 200
