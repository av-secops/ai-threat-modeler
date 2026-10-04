import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import model_tools_api as api

PREFIX = '/enterprise/model-tools'


def model():
    return {'model_id': 'api', 'architecture': {
        'components': [{'id': 'api', 'name': 'Orders', 'type': 'Service'}], 'flows': []}}


def snapshot():
    return {'schema_version': 'aegis-cloud-snapshot/1', 'provider': 'aws', 'account_id': '123456789012',
        'region': 'us-east-1', 'observed_at': '2026-10-04T12:00:00Z', 'coverage': {'ec2': {'status': 'complete'}},
        'resources': [{'id': 'arn:aws:ec2:us-east-1:123456789012:instance/i-abc', 'service': 'ec2',
                       'type': 'aws_ec2_instance', 'properties': {'metadata_HttpTokens': 'required'}}]}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'edit': {'name': 'Editor', 'role': 'editor', 'products': {}},
        'view': {'name': 'Viewer', 'role': 'viewer', 'products': {}},
    }))
    monkeypatch.delenv('AEGIS_OIDC_ENABLED', raising=False)
    app = FastAPI()
    app.include_router(api.router)
    # No database or cloud clients: these endpoints only transform supplied data.
    with TestClient(app, headers={'Authorization': 'Bearer edit'}) as value:
        yield value


@pytest.mark.parametrize('path,payload', [
    ('/validate', {'document': model()}),
    ('/import', {'document': model(), 'format': 'aegis'}),
    ('/export', {'document': model(), 'format': 'otm'}),
    ('/cloud-snapshot/model', {'document': snapshot()}),
    ('/cloud-snapshot/compare', {'baseline': snapshot(), 'observed': snapshot()}),
])
def test_all_endpoints_require_editor_and_expose_no_stored_data(client, path, payload):
    assert client.post(PREFIX + path, json=payload, headers={'Authorization': ''}).status_code == 401
    assert client.post(PREFIX + path, json=payload, headers={'Authorization': 'Bearer view'}).status_code == 403
    response = client.post(PREFIX + path, json=payload)
    assert response.status_code == 200, response.text
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('format_name', ['otm', 'threat-dragon'])
def test_external_export_import_returns_visible_warnings_and_provenance(client, format_name):
    exported = client.post(PREFIX + '/export', json={'format': format_name, 'document': model()}).json()
    assert exported['warnings'] and exported['schema']
    imported = client.post(PREFIX + '/import', json={'format': format_name, 'document': exported['document']})
    assert imported.status_code == 200, imported.text
    assert imported.json()['provenance']['verification'] == 'imported_unverified'
    assert imported.json()['warnings']


def test_invalid_graph_and_cross_account_snapshot_return_400(client):
    value = model()
    value['architecture']['flows'] = [{'id': 'f', 'source_id': 'api', 'target_id': 'missing', 'protocol': 'HTTPS'}]
    assert client.post(PREFIX + '/validate', json={'document': value}).status_code == 400
    observed = snapshot()
    observed['account_id'] = '999999999999'
    assert client.post(PREFIX + '/cloud-snapshot/compare', json={'baseline': snapshot(), 'observed': observed}).status_code == 400


def test_partial_inventory_stays_partial_and_does_not_claim_fixed(client):
    observed = snapshot()
    observed['resources'] = []
    observed['coverage']['ec2'] = {'status': 'partial', 'reason': 'AccessDenied'}
    response = client.post(PREFIX + '/cloud-snapshot/compare', json={'baseline': snapshot(), 'observed': observed})
    assert response.status_code == 200
    assert response.json()['coverage']['ec2']['status'] == 'partial'
    assert response.json()['changes'][0]['status'] == 'not_observed'


def test_missing_interchange_dependency_is_503_without_internal_details(client, monkeypatch):
    def missing(*args, **kwargs):
        raise RuntimeError('local path or installation detail should not leak')
    monkeypatch.setattr(api, 'export_model', missing)
    response = client.post(PREFIX + '/export', json={'format': 'otm', 'document': model()})
    assert response.status_code == 503
    assert 'local path' not in response.text


@pytest.mark.parametrize('body', ['{"document": {}, "document": {}}', '{"document": {"x": NaN}}', '{bad'])
def test_bad_json_is_rejected_without_silent_key_override(client, body):
    response = client.post(PREFIX + '/validate', content=body, headers={'Content-Type': 'application/json'})
    assert response.status_code == 400


def test_oversized_requests_are_bounded_with_and_without_content_length(client, monkeypatch):
    monkeypatch.setattr(api, 'MAX_REQUEST_BYTES', 64)
    response = client.post(PREFIX + '/validate', content='x' * 65, headers={'Content-Type': 'application/json'})
    assert response.status_code == 413
    response = client.post(PREFIX + '/validate', content=iter([b'x' * 40, b'x' * 40]), headers={'Content-Type': 'application/json'})
    assert response.status_code == 413


def test_unsupported_format_extra_fields_and_compression_are_rejected(client):
    assert client.post(PREFIX + '/import', json={'format': 'xml', 'document': {}}).status_code == 422
    assert client.post(PREFIX + '/validate', json={'document': model(), 'product_id': 'hidden'}).status_code == 422
    assert client.post(PREFIX + '/validate', json={'document': model()}, headers={'Content-Encoding': 'gzip'}).status_code == 415


def test_router_has_no_cloud_discovery_or_mutation_endpoint(client):
    assert client.post(PREFIX + '/discover-aws', json={}).status_code == 404


def test_parent_application_mounts_model_tools_without_starting_storage(client):
    from app.main import app
    # Do not enter lifespan: stateless routes must work without opening the user's
    # database, starting jobs, or constructing model/cloud clients.
    mounted = TestClient(app, headers={'Authorization': 'Bearer edit'})
    try:
        response = mounted.post(PREFIX + '/validate', json={'document': model()})
        assert response.status_code == 200, response.text
        assert response.json()['model_id'] == 'api'
        assert response.headers['Cache-Control'] == 'no-store'
    finally:
        mounted.close()
