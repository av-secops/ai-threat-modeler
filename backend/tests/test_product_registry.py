from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import sqlite3
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.services.product_store import ProductStore, StoreConflict
from app.services.enterprise_api import router
from app.services.durable_jobs import JobRunner


@pytest.fixture
def store(tmp_path):
    return ProductStore(tmp_path / 'registry.sqlite3')


def test_names_unique_archived_reserved_and_simultaneous_create(store):
    def create(name):
        try:
            return store.create('products', name, 'tester')
        except StoreConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, ['OPTIMA', '  optima  ']))
    assert sum(r is not None for r in results) == 1
    product = next(r for r in results if r)
    store.update_product(product['id'], 'Optima', True, 'tester')
    with pytest.raises(StoreConflict):
        store.create('products', 'OPTIMA', 'tester')


def test_scope_optimistic_lock_immutable_reports_and_clone(store):
    product = store.create('products', 'Catalog', 'tester')
    release = store.create('releases', '26.09', 'tester', product['id'])
    workspace = {'id': 'workspace-one', 'projectName': 'Catalog', 'revisions': [{'number': 1, 'data': {'threats': []}}],
        'draft': {'payload': {'answers': [{'state': 'present'}]}, 'preparedSignature': 'old', 'preview': {}}}
    store.save_workspace(release['id'], workspace, None, 'production', 0, 'tester')
    with pytest.raises(StoreConflict):
        store.save_workspace(release['id'], workspace, None, 'production', 0, 'tester')
    edited = deepcopy(workspace)
    edited['revisions'] = []
    with pytest.raises(StoreConflict):
        store.save_workspace(release['id'], edited, None, 'production', 1, 'tester')
    clone = store.clone_release(release['id'], '26.10', 'tester')
    cloned_id = store.release(clone['id'])['workspaces'][0]['id']
    copied = store.workspace(cloned_id)['workspace']
    assert copied['revisions'] == [] and copied['draft']['payload']['answers'] == []
    assert copied['draft']['payload']['deployment_version'] == '26.10'
    assert copied['draft']['preview'] is None
    assert store.workspace(workspace['id'])['workspace']['revisions'] == workspace['revisions']
    assert any(row['action'] == 'clone_release' for row in store.audit_log())


def test_roles_are_enforced_server_side(store, monkeypatch):
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'editor-token': {'name': 'Alice', 'role': 'editor'}, 'viewer-token': {'name': 'Bob', 'role': 'viewer'}}))
    app = FastAPI()
    app.state.product_store = store
    app.include_router(router)
    with TestClient(app) as client:
        assert client.get('/enterprise/products').status_code == 401
        assert client.post('/enterprise/products', json={'name': 'Test'}, headers={'Authorization': 'Bearer viewer-token'}).status_code == 403
        assert client.post('/enterprise/products', json={'name': 'Test'}, headers={'Authorization': 'Bearer editor-token'}).status_code == 200
        assert client.get('/enterprise/audit', headers={'Authorization': 'Bearer editor-token'}).status_code == 403
        assert client.get('/enterprise/products', headers={'Authorization': 'Bearer viewer-token'}).json()[0]['name'] == 'Test'


def test_durable_job_result_survives_reload_and_is_owner_scoped(store):
    runner = JobRunner(store, lambda data: {'value': data['value']})
    try:
        job = runner.submit({'value': 42}, 'Alice')
        deadline = time.time() + 10
        while time.time() < deadline and runner.get(job['id'], 'Alice')['state'] != 'completed':
            time.sleep(.1)
        assert runner.get(job['id'], 'Alice')['result'] == {'value': 42}
        with pytest.raises(LookupError):
            runner.get(job['id'], 'Bob')
        reloaded = ProductStore(store.path)
        with reloaded.connect() as db:
            assert reloaded.require(db, 'jobs', job['id'])['state'] == 'completed'
    finally:
        runner.stop()
        runner.thread.join(timeout=3)


def test_release_summary_tracks_scope_dates_and_report_completion(store):
    product = store.create('products', 'Release scope test', 'tester')
    release = store.create('releases', '26.09', 'tester', product['id'])
    created_at = release['created_at']
    row = store.product(product['id'])['releases'][0]
    assert row['model_count'] == row['reported_models'] == row['draft_models'] == 0
    app = store.release_application(release['id'], 'Billing', 'tester')
    # Naming an application alone does not claim a model or report exists.
    assert store.product(product['id'])['releases'][0]['model_count'] == 0
    full = {'id': 'full-release', 'projectName': 'Release', 'revisions': [], 'draft': {}}
    standalone = {'id': 'billing-only', 'projectName': 'Billing review', 'revisions': [], 'draft': {}}
    store.save_workspace(release['id'], full, None, 'production', 0, 'tester')
    store.save_workspace(release['id'], standalone, app['id'], 'production', 0, 'tester')
    full['revisions'] = [{'number': 1, 'createdAt': '2026-09-09T12:00:00Z', 'data': {'threats': []}},
                         {'number': 2, 'createdAt': '2026-09-10T12:00:00Z', 'data': {'threats': []}}]
    store.save_workspace(release['id'], full, None, 'production', 1, 'tester')
    row = store.product(product['id'])['releases'][0]
    assert row['created_at'] == created_at
    assert (row['model_count'], row['reported_models'], row['draft_models']) == (2, 1, 1)
    assert (row['release_models'], row['application_models']) == (1, 1)
    assert row['last_modeled_at'] == '2026-09-10T12:00:00Z'
    detail = {w['id']: w for w in store.release(release['id'])['workspaces']}
    assert detail['billing-only']['application_name'] == 'Billing'
    assert detail['billing-only']['model_scope'] == 'application'
    assert detail['full-release']['model_scope'] == 'release'
    clone = store.clone_release(release['id'], '26.10', 'tester')
    cloned = next(r for r in store.product(product['id'])['releases'] if r['id'] == clone['id'])
    assert cloned['reported_models'] == 0 and cloned['draft_models'] == 2
    assert cloned['last_modeled_at'] is None
    assert cloned['created_at'] >= created_at


def test_ad_hoc_application_identity_is_atomic_scoped_and_backwards_compatible(store):
    product = store.create('products', 'Product', 'tester')
    release = store.create('releases', '26.09', 'tester', product['id'])
    original = store.create('applications', 'Billing', 'tester', product['id'])
    assert store.release_application(release['id'], '  BILLING  ', 'tester')['id'] == original['id']
    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(lambda name: store.release_application(release['id'], name, 'tester')['id'], ['Portal', ' portal ']))
    assert ids[0] == ids[1]
    other = store.create('products', 'Other product', 'tester')
    other_release = store.create('releases', '26.09', 'tester', other['id'])
    assert store.release_application(other_release['id'], 'Billing', 'tester')['id'] != original['id']
    store.update_product(product['id'], product['name'], True, 'tester')
    with pytest.raises(StoreConflict):
        store.release_application(release['id'], 'Another app', 'tester')


def test_second_application_in_same_release_preserves_existing_reports_and_draft(store):
    product = store.create('products', 'Multi-application product', 'tester')
    release = store.create('releases', '26.09', 'tester', product['id'])
    portal = store.release_application(release['id'], 'Portal', 'tester')
    first = {'id': 'portal-model', 'projectName': 'Portal model', 'draft': {'payload': {'sources': []}},
             'revisions': [{'number': 1, 'createdAt': '2026-09-09T12:00:00Z',
                            'data': {'threats': [{'id': 'first-risk'}]}}]}
    store.save_workspace(release['id'], first, portal['id'], 'production', 0, 'tester')
    original = store.workspace(first['id'])

    billing = store.release_application(release['id'], 'Billing', 'tester')
    second = {'id': 'billing-model', 'projectName': 'Billing model', 'revisions': [],
              'draft': {'payload': {'sources': [{'text': 'Billing architecture'}]}}}
    store.save_workspace(release['id'], second, billing['id'], 'production', 0, 'tester')
    reloaded = ProductStore(store.path)
    assert reloaded.workspace(second['id'])['workspace']['draft'] == second['draft']
    assert reloaded.workspace(first['id']) == original
    second['revisions'] = [{'number': 1, 'createdAt': '2026-09-09T13:00:00Z', 'data': {'threats': []}}]
    reloaded.save_workspace(release['id'], second, billing['id'], 'production', 1, 'tester')
    assert reloaded.workspace(first['id']) == original
    summary = reloaded.product(product['id'])['releases'][0]
    assert (summary['model_count'], summary['reported_models'], summary['application_models']) == (2, 2, 2)
    rows = reloaded.release(release['id'])['workspaces']
    assert {row['application_id'] for row in rows} == {portal['id'], billing['id']}
    assert {row['revisions'] for row in rows} == {1}


def test_existing_release_dates_migrate_from_audit_without_rewriting_history(tmp_path):
    path = tmp_path / 'legacy.sqlite3'
    with sqlite3.connect(path) as db:
        db.executescript('''
            CREATE TABLE releases(id TEXT PRIMARY KEY,product_id TEXT,name TEXT,name_key TEXT,archived INTEGER DEFAULT 0);
            CREATE TABLE audit(id INTEGER PRIMARY KEY,at REAL,actor TEXT,action TEXT,target TEXT);
            INSERT INTO releases VALUES('known','product','26.08','26.08',0),('unknown','product','26.07','26.07',0);
            INSERT INTO audit VALUES(1,1234567890,'tester','create_releases','known');
        ''')
    for _ in range(2):
        migrated = ProductStore(path)
        assert migrated.release('known')['created_at'] == 1234567890
        assert migrated.release('unknown')['created_at'] is None
        assert len(migrated.audit_log()) == 1


def test_release_application_api_enforces_editor_role(store, monkeypatch):
    product = store.create('products', 'API permissions', 'tester')
    release = store.create('releases', '26.09', 'tester', product['id'])
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'edit': {'name': 'Editor', 'role': 'editor'}, 'view': {'name': 'Viewer', 'role': 'viewer'}}))
    app = FastAPI()
    app.state.product_store = store
    app.include_router(router)
    with TestClient(app) as client:
        path = f"/enterprise/releases/{release['id']}/applications"
        assert client.post(path, json={'name': 'Portal'}, headers={'Authorization': 'Bearer view'}).status_code == 403
        first = client.post(path, json={'name': 'Portal'}, headers={'Authorization': 'Bearer edit'})
        again = client.post(path, json={'name': ' portal '}, headers={'Authorization': 'Bearer edit'})
        assert first.status_code == again.status_code == 200
        assert first.json()['id'] == again.json()['id']
