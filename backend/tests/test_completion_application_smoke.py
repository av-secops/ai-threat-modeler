"""Router/lifespan integration with isolated storage and no model/network setup."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import main


def test_new_routers_and_stores_are_available_in_application_lifespan(tmp_path, monkeypatch):
    monkeypatch.setenv('AEGIS_WORKSPACE_DB', str(tmp_path / 'workspace.sqlite3'))
    monkeypatch.setenv('AEGIS_ALLOW_LOCAL_WORKSPACE', 'true')
    monkeypatch.setenv('AEGIS_OIDC_ENABLED', 'false')
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', '{}')
    monkeypatch.setenv('ENVIRONMENT', 'development')
    monkeypatch.delenv('AEGIS_KB_RELEASE_DB', raising=False)
    monkeypatch.setattr(main, 'ThreatAnalyzer', lambda: SimpleNamespace(
        knowledge_base=SimpleNamespace(release_provenance={'mode': 'bundled'})))
    from app.services.knowledge_admin_api import release_store
    from app.knowledge_base.releases import KnowledgeReleaseStore
    main.app.dependency_overrides[release_store] = lambda: KnowledgeReleaseStore(tmp_path / 'kb.sqlite3')
    try:
        with TestClient(main.app) as client:
            assert client.get('/health').status_code == 200
            product = client.post('/enterprise/products', json={'name': 'Isolated integration check'})
            assert product.status_code == 200, product.text
            product_id = product.json()['id']
            patterns = client.get(f'/enterprise/products/{product_id}/security-workflows/patterns')
            assert patterns.status_code == 200, patterns.text
            assert patterns.json()['items'] == []
            knowledge = client.get('/enterprise/knowledge/status')
            assert knowledge.status_code == 200, knowledge.text
            assert knowledge.json()['effective']['mode'] == 'bundled'
            assert knowledge.json()['independent_accuracy_established'] is False
            model = client.post('/enterprise/model-tools/validate', json={'document': {
                'model_id': 'smoke', 'architecture': {'components': [{'id': 'api', 'name': 'API', 'type': 'API'}],
                    'flows': [], 'trust_boundaries': []}, 'threats': []}})
            assert model.status_code == 200, model.text
            assert model.headers['cache-control'] == 'no-store'
            assert main.app.state.security_workflows.store is main.app.state.product_store
        assert main.app.state.job_runner.stop_event.is_set()
    finally:
        main.app.dependency_overrides.pop(release_store, None)
