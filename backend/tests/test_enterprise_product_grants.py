import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.enterprise_api import router
from app.services.product_store import ProductStore


@pytest.fixture
def scoped_api(tmp_path, monkeypatch):
    store = ProductStore(tmp_path / 'grants.sqlite3')
    first = store.create('products', 'Authorized', 'tester')
    second = store.create('products', 'Private', 'tester')
    releases = []
    for i, product in enumerate((first, second)):
        release = store.create('releases', '1', 'tester', product['id'])
        store.save_workspace(release['id'], {'id': f'w{i}', 'revisions': [{'number': 1,
            'data': {'architecture': {'components': [], 'flows': []}, 'threats': []}}]}, None, 'production', 0, 'tester')
        releases.append(release)
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'scoped': {'name': 'Alice', 'role': 'admin', 'products': {first['id']: 'editor'}},
        'view': {'name': 'Bob', 'role': 'editor', 'products': {first['id']: 'viewer'}},
    }))
    monkeypatch.delenv('AEGIS_OIDC_ENABLED', raising=False)
    app = FastAPI()
    app.state.product_store = store
    app.include_router(router)
    with TestClient(app, headers={'Authorization': 'Bearer scoped'}) as client:
        yield client, first, second, releases


def test_every_product_surface_enforces_scopes(scoped_api):
    client, first, second, releases = scoped_api
    assert [p['id'] for p in client.get('/enterprise/products').json()] == [first['id']]
    portfolio = client.get('/enterprise/security-dashboard').json()
    assert portfolio['products_total'] == 1
    assert portfolio['products'][0]['product']['id'] == first['id']
    for path in (f"/products/{second['id']}", f"/releases/{releases[1]['id']}", '/workspaces/w1',
                 f"/products/{second['id']}/security-dashboard", f"/products/{second['id']}/comparisons",
                 f"/products/{second['id']}/comparison-catalog", f"/products/{second['id']}/security-dashboard/history"):
        assert client.get('/enterprise' + path).status_code == 404, path
    assert client.get('/enterprise/audit').status_code == 403
    assert client.post('/enterprise/products', json={'name': 'Another'}).status_code == 403
    assert client.post('/enterprise/compare', json={'before_workspace': 'w0', 'after_workspace': 'w1',
        'before_revision': 1, 'after_revision': 1}).status_code == 404


def test_product_grant_limits_global_role_on_writes(scoped_api):
    client, first, second, releases = scoped_api
    assert client.get(f"/enterprise/products/{first['id']}").json()['permissions'] == {'edit': True, 'admin': False}
    assert client.patch(f"/enterprise/products/{first['id']}", json={'name': 'Changed'}).status_code == 404
    assert client.post(f"/enterprise/products/{first['id']}/releases", json={'name': '2'}).status_code == 200
    assert client.post(f"/enterprise/releases/{releases[1]['id']}/clone", json={'name': '2'}).status_code == 404
    assert client.put(f"/enterprise/releases/{releases[0]['id']}/workspaces", json={
        'workspace': {'id': 'w1', 'revisions': []}, 'expected_version': 1}).status_code == 404
    assert client.post(f"/enterprise/products/{first['id']}/releases", json={'name': '3'},
        headers={'Authorization': 'Bearer view'}).status_code == 404
