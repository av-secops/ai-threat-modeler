import csv
import io
import json
import sqlite3
import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.product_store import ProductStore, StoreConflict
from app.services.assessment_store import AssessmentStore
from app.services.enterprise_api import router
from app.services.product_dashboard import DashboardFilters, dashboard, portfolio, observe, history, finding_detail


@pytest.fixture
def setup(tmp_path):
    store = ProductStore(tmp_path / 'dashboard.sqlite3')
    AssessmentStore(store)
    p = store.create('products', 'Product', 'test')
    r = store.create('releases', '26.09', 'test', p['id'])
    a = store.release_application(r['id'], 'Portal', 'test')
    return store, p, r, a


def finding(id='f1', severity='High', **values):
    return {'id': id, 'title': 'Risk ' + id, 'severity': severity, 'tier': 'Confirmed',
            'category': 'Tampering', **values}


def model(setup, threats, id=None, quality='ready', app=True):
    store, _, release, application = setup
    id = id or str(uuid4())
    try:
        old = store.workspace(id)
        workspace, version = old['workspace'], old['version']
    except LookupError:
        workspace, version = {'id': id, 'projectName': 'Review', 'revisions': [], 'draft': {'payload': {'assessment_id': id}}}, 0
    report_id = str(uuid4())
    body = {'threats': threats, 'score': 65, 'summary': 'Synthetic report for dashboard verification.',
            'architecture': {'components': [], 'data_flows': [], 'trust_boundaries': []},
            'diagram': 'flowchart LR\n  User[User] --> API[API]',
            'engine_status': {'assessment': {'id': id, 'report_id': report_id},
                                               'quality_gate': {'publication_status': quality}}}
    with store.connect() as db:
        db.execute('INSERT OR IGNORE INTO assessment_sessions VALUES(?,1,?,?)', (id, 'test', time.time()))
        db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)', (report_id, id, json.dumps(body), 'test', time.time()))
    workspace['revisions'].append({'number': len(workspace['revisions'])+1, 'data': body})
    store.save_workspace(release['id'], workspace, application['id'] if app else None, 'production', version, 'test')
    return id, report_id


def review(store, report, finding_id, status, **kwargs):
    with store.connect() as db:
        db.execute('INSERT INTO finding_review_events(report_id,finding_id,body,actor,created) VALUES(?,?,?,?,?)',
                   (report, finding_id, json.dumps({'status': status, **kwargs}), 'reviewer', time.time()))


def test_expired_acceptance_reopens_every_read_surface_without_rewriting_history(setup, monkeypatch):
    store, product, _, _ = setup
    workspace, report = model(setup, [finding()])
    now = time.time()
    expiry = datetime.fromtimestamp(now + 3600, timezone.utc).isoformat()
    review(store, report, 'f1', 'accepted', owner='Security owner', security_workflow=True,
           acceptance_expires_at=expiry)
    before = dashboard(store, product['id'], DashboardFilters())
    assert before['metrics']['accepted_risks'] == 1
    monkeypatch.setattr(time, 'time', lambda: now + 7200)
    after = dashboard(store, product['id'], DashboardFilters())
    assert after['metrics']['accepted_risks'] == 0
    assert after['metrics']['open_risks'] == 1
    assert before['snapshot'] != after['snapshot']
    row = after['findings']['rows'][0]
    assert row['acceptance_expired'] and isinstance(row['review_version'], int)
    register = AssessmentStore(store).reviews(report)
    detail = finding_detail(store, product['id'], workspace, report, 'f1')['reviews']
    for result in (register, detail):
        assert result['latest']['f1']['status'] == 'pending_review'
        assert result['events'][-1]['status'] == 'accepted'
        assert result['events'][-1]['version'] == row['review_version']
    with pytest.raises(StoreConflict):
        dashboard(store, product['id'], DashboardFilters(), before['snapshot'], export=True)


def test_new_standard_acceptance_requires_owner_and_bounded_expiry(setup):
    store, _, _, _ = setup
    _, report = model(setup, [finding()])
    assessment = AssessmentStore(store)
    identity = {'role': 'admin', 'name': 'security-owner'}
    value = {'status': 'accepted', 'remarks': 'Business review approved.', 'owner': 'Product architect'}
    for expiry in ('', 'invalid', '2020-01-01T00:00:00+00:00', '2999-01-01T00:00:00+00:00', '2999-01-01'):
        with pytest.raises(ValueError, match='expiry'):
            assessment.review(report, 'f1', {**value, 'acceptance_expires_at': expiry}, identity)
    expiry = datetime.fromtimestamp(time.time() + 86400, timezone.utc).isoformat()
    with pytest.raises(ValueError, match='owner'):
        assessment.review(report, 'f1', {**value, 'owner': '', 'acceptance_expires_at': expiry}, identity)
    accepted = assessment.review(report, 'f1', {**value, 'acceptance_expires_at': expiry}, identity)
    assert accepted['latest']['f1']['status'] == 'accepted'
    assert accepted['latest']['f1']['security_workflow'] is True


def test_legacy_acceptance_is_readable_until_explicit_rereview(setup):
    store, product, _, _ = setup
    _, report = model(setup, [finding()])
    review(store, report, 'f1', 'accepted', remarks='Legacy review')
    assert AssessmentStore(store).reviews(report)['latest']['f1']['status'] == 'accepted'
    assert dashboard(store, product['id'], DashboardFilters())['metrics']['accepted_risks'] == 1


def test_latest_report_only_and_authoritative_findings(setup):
    store, p, _, _ = setup
    id, _ = model(setup, [finding('old')])
    model(setup, [finding('new', 'Critical')], id, quality='blocked')
    # Client data does not override the server's immutable report body.
    with store.connect() as db:
        db.execute("UPDATE workspaces SET payload=json_set(payload,'$.revisions[1].data.threats',json('[]')) WHERE id=?", (id,))
    result = dashboard(store, p['id'], DashboardFilters())
    assert result['metrics']['open_risks'] == 1
    assert result['findings']['rows'][0]['finding_id'] == 'new'
    assert result['coverage']['quality'] == {'blocked': 1}
    assert result['coverage']['models_completed'] == 1


def test_review_lifecycle_and_percentage_denominators(setup):
    store, p, _, _ = setup
    _, report = model(setup, [finding(str(i), s) for i, s in enumerate(
        ['Critical', 'High', 'Medium', 'Low', 'Unknown', 'Critical', 'High', 'High', 'High'])]
        + [finding('question', finding_type='validation_question')])
    review(store, report, '1', 'mitigation_proposed')
    review(store, report, '2', 'accepted')
    review(store, report, '3', 'verified_fixed', verification_evidence='Deployment checked')
    review(store, report, '5', 'false_positive')
    review(store, report, '6', 'mitigated')
    review(store, report, '7', 'verified_fixed')  # Historical corrupt/unproven closure.
    review(store, report, '8', 'in_review')
    result = dashboard(store, p['id'], DashboardFilters())
    assert result['metrics']['open_risks'] == 4
    assert result['metrics']['verified_fixed'] == result['metrics']['accepted_risks'] == 1
    assert result['metrics']['validation_questions'] == 1
    assert result['severity'][0]['percent'] == 25
    assert sum(s['count'] for s in result['statuses']) == 10
    assert next(s for s in result['statuses'] if s['name'] == 'unknown')['count'] == 2
    result = dashboard(store, p['id'], DashboardFilters(severity='Critical', status='open', kind='risk'))
    assert result['findings']['total'] == 1


def test_ids_scoped_overlap_and_partial_coverage(setup):
    store, p, r, a = setup
    model(setup, [finding()], app=False)
    model(setup, [finding()])
    store.release_application(r['id'], 'Unassessed app', 'test')
    result = dashboard(store, p['id'], DashboardFilters())
    assert len({f['occurrence_id'] for f in result['findings']['rows']}) == 2
    assert result['coverage']['overlapping_releases'] == 1
    assert result['coverage']['applications_registered'] == 2
    assert result['coverage']['applications_assessed'] == 1
    assert dashboard(store, p['id'], DashboardFilters(scope='release'))['coverage']['applications_assessed'] == 0
    assert dashboard(store, p['id'], DashboardFilters(application_id=a['id']))['findings']['total'] == 1


def test_legacy_forged_report_clone_and_empty_states(setup):
    store, p, r, _ = setup
    _, report = model(setup, [])
    for id, data in [('legacy', {'threats': [finding()]}), ('forged', {'engine_status': {'assessment': {'report_id': report}}})]:
        store.save_workspace(r['id'], {'id': id, 'revisions': [{'number': 1, 'data': data}]}, None, 'test', 0, 'test')
    store.clone_release(r['id'], '26.10', 'test')
    result = dashboard(store, p['id'], DashboardFilters())
    assert result['coverage']['models_completed'] == 1
    assert result['coverage']['legacy_unverified'] == 2
    assert result['coverage']['drafts'] == 3
    assert result['metrics']['open_risks'] == 0
    assert all(s['percent'] is None for s in result['severity'])
    other = store.create('products', 'Empty', 'test')
    assert dashboard(store, other['id'], DashboardFilters())['coverage']['applications_registered'] == 0


def test_snapshot_pagination_csv_and_invalidation(setup):
    store, p, _, _ = setup
    _, report = model(setup, [finding(str(i), title='=HYPERLINK("bad")') for i in range(35)])
    filters = DashboardFilters()
    first = dashboard(store, p['id'], filters, page_size=20)
    second = dashboard(store, p['id'], filters, first['snapshot'], page=2, page_size=20)
    assert len(first['findings']['rows']) == 20 and len(second['findings']['rows']) == 15
    exported = list(csv.DictReader(io.StringIO(dashboard(store, p['id'], filters, first['snapshot'], export=True))))
    assert len(exported) == 35 and exported[0]['title'].startswith("'=HYPERLINK")
    review(store, report, '0', 'in_review')
    with pytest.raises(StoreConflict):
        dashboard(store, p['id'], filters, first['snapshot'])
    with pytest.raises(StoreConflict):
        dashboard(store, p['id'], filters, first['snapshot'], export=True)


def test_observations_are_explicit_idempotent_and_do_not_imply_fixes(setup):
    store, p, _, _ = setup
    _, report = model(setup, [finding()])
    assert history(store, p['id'])['observations'] == []
    assert len(observe(store, p['id'], 'test')['observations']) == 1
    assert len(observe(store, p['id'], 'test')['observations']) == 1
    review(store, report, 'f1', 'accepted')
    observed = observe(store, p['id'], 'test')['observations']
    assert len(observed) == 2
    assert observed[0]['body']['metrics']['accepted_risks'] == 1
    assert observed[0]['body']['metrics']['verified_fixed'] == 0


def test_portfolio_and_archive_scope(setup):
    store, p, r, _ = setup
    model(setup, [finding()])
    other = store.create('products', 'Empty', 'test')
    assert portfolio(store)['products_total'] == 2
    assert portfolio(store)['products_assessed'] == 1
    store.update_product(other['id'], other['name'], True, 'test')
    assert portfolio(store)['products_total'] == 1
    assert portfolio(store, True)['products_total'] == 2
    with store.connect() as db:
        db.execute('UPDATE releases SET archived=1 WHERE id=?', (r['id'],))
    assert dashboard(store, p['id'], DashboardFilters())['metrics']['open_risks'] == 0
    assert dashboard(store, p['id'], DashboardFilters(archived=True))['metrics']['open_risks'] == 1


def test_read_snapshot_does_not_lock_writer(setup):
    store, *_ = setup
    with store.read_snapshot() as read:
        read.execute('SELECT * FROM products').fetchall()
        with sqlite3.connect(store.path, timeout=.1) as write:
            write.execute('BEGIN IMMEDIATE')
            write.execute("UPDATE products SET name='Concurrent update'")
        assert read.execute('SELECT name FROM products').fetchone()[0] == 'Product'


def test_api_permissions_parameters_and_cross_product_filters(setup, monkeypatch):
    store, p, _, _ = setup
    model(setup, [finding()])
    other = store.create('products', 'Other', 'test')
    release = store.create('releases', 'Other release', 'test', other['id'])
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'view': {'name': 'Viewer', 'role': 'viewer'}, 'edit': {'name': 'Editor', 'role': 'editor'}}))
    app = FastAPI()
    app.state.product_store = store
    app.include_router(router)
    with TestClient(app) as client:
        path = f"/enterprise/products/{p['id']}/security-dashboard"
        headers = {'Authorization': 'Bearer view'}
        assert client.get(path).status_code == 401
        assert client.get(path, headers=headers).status_code == 200
        assert client.get(path, params={'page_size': 101}, headers=headers).status_code == 422
        assert client.get(path, params={'sort': 'DROP TABLE'}, headers=headers).status_code == 422
        assert client.get(path, params={'release_id': release['id']}, headers=headers).status_code == 400
        assert client.post(path+'/history', headers=headers).status_code == 403
        assert client.post(path+'/history', headers={'Authorization': 'Bearer edit'}).status_code == 200
        snapshot = client.get(path, headers=headers).json()['snapshot']
        result = client.get(path+'/export', params={'snapshot': snapshot}, headers=headers)
        assert result.status_code == 200 and 'text/csv' in result.headers['content-type']
        assert client.get('/enterprise/security-dashboard', headers=headers).json()['products_total'] == 2


def test_more_than_200_models_are_not_truncated(setup):
    store, p, _, _ = setup
    for _ in range(205):
        model(setup, [finding()])
    result = dashboard(store, p['id'], DashboardFilters())
    assert result['coverage']['models_completed'] == result['metrics']['open_risks'] == 205
    assert len(result['findings']['rows']) == 25


def test_details_use_exact_report_and_enforce_product_association(setup):
    store, p, _, _ = setup
    id, old = model(setup, [finding('old', description='Original evidence')])
    model(setup, [finding('new')], id)
    detail = finding_detail(store, p['id'], id, old, 'old')
    assert detail['threat']['description'] == 'Original evidence'
    other = store.create('products', 'Other', 'test')
    with pytest.raises(LookupError):
        finding_detail(store, other['id'], id, old, 'old')
    with pytest.raises(LookupError):
        finding_detail(store, p['id'], id, old, 'new')


def test_scale_100_releases_50000_findings(setup, capsys):
    store, p, _, a = setup
    threats = [finding(str(i), ['Critical', 'High', 'Medium', 'Low'][i % 4]) for i in range(500)]
    for i in range(100):
        r = store.create('releases', f'scale-{i}', 'test', p['id'])
        model((store, p, r, a), threats)
    samples = []
    for _ in range(3):
        started = time.perf_counter()
        result = dashboard(store, p['id'], DashboardFilters())
        samples.append(time.perf_counter() - started)
    assert result['metrics']['open_risks'] == 50000
    assert result['coverage']['releases_assessed'] == 100
    assert len(result['findings']['rows']) == 25
    assert len(json.dumps(result)) < 200_000
    with capsys.disabled():
        print(f'\nDashboard benchmark: 50,000 findings; seconds={samples}; response_bytes={len(json.dumps(result))}')
