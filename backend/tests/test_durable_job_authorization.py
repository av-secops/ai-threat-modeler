"""Queued authorization is current policy, not a worker's installation role."""

import hashlib
import json
from types import SimpleNamespace

from fastapi import FastAPI
import pytest

from app.models import AnalysisResult, Component, SystemArchitecture
from app.services.durable_jobs import JobRunner
from app.services.enterprise_api import start_enterprise
from app.services.product_store import ProductStore
from app.services.workspace_access import ENV_KEYS


def stopped_runner(store, analyze, **options):
    runner = JobRunner(store, analyze, **options)
    runner.stop()
    runner.thread.join(timeout=3)
    assert not runner.thread.is_alive()
    return runner


def claim(runner, payload=None, actor='architect'):
    job = runner.submit(payload or {'project_name': 'Test'}, actor)
    with runner.store.connect() as db:
        db.execute("UPDATE jobs SET state='running',owner=? WHERE id=?", (runner.owner, job['id']))
        return dict(db.execute('SELECT * FROM jobs WHERE id=?', (job['id'],)).fetchone())


def test_optional_authorization_preserves_legacy_single_argument_analyzer(tmp_path):
    runner = stopped_runner(ProductStore(tmp_path / 'jobs.sqlite3'), lambda value: {'value': value['value']})
    row = claim(runner, {'value': 7})
    runner.execute(row)
    result = runner.get(row['id'], 'architect')
    assert result['state'] == 'completed' and result['result'] == {'value': 7}


def test_authorization_runs_before_analysis_and_again_before_publication(tmp_path):
    events = []

    def authorize(actor, payload):
        events.append(('authorize', actor))
        return {'name': actor, 'generation': len(events)}

    def analyze(payload, *, identity):
        events.append(('analyze', identity['generation']))
        return {'result': True}

    def publish(result, *, identity, db):
        assert db.execute('SELECT 1').fetchone()[0] == 1
        events.append(('publish', identity['generation']))
        return result

    runner = stopped_runner(ProductStore(tmp_path / 'jobs.sqlite3'), analyze,
                            authorize=authorize, publish=publish)
    row = claim(runner)
    runner.execute(row)
    assert events == [('authorize', 'architect'), ('authorize', 'architect'), ('analyze', 2),
                      ('authorize', 'architect'), ('publish', 4)]
    assert runner.get(row['id'], 'architect')['state'] == 'completed'


def test_failed_publication_rolls_back_report_and_job_result_together(tmp_path):
    store = ProductStore(tmp_path / 'jobs.sqlite3')
    with store.connect() as db:
        db.execute('CREATE TABLE test_publications(value TEXT)')

    def publish(result, *, identity, db):
        db.execute('INSERT INTO test_publications VALUES(?)', ('unpublished',))
        return object()  # Serialization must fail and roll back the report insert.

    runner = stopped_runner(store, lambda _: {}, publish=publish)
    row = claim(runner)
    runner.execute(row)
    assert runner.get(row['id'], 'architect')['state'] == 'failed'
    assert runner.get(row['id'], 'architect')['result'] is None
    with store.read_snapshot() as db:
        assert db.execute('SELECT count(*) FROM test_publications').fetchone()[0] == 0


def test_worker_losing_ownership_cannot_publish(tmp_path):
    store, published = ProductStore(tmp_path / 'jobs.sqlite3'), []

    def analyze(payload):
        with store.connect() as db:
            db.execute("UPDATE jobs SET owner='replacement-worker' WHERE state='running'")
        return {}

    runner = stopped_runner(store, analyze, publish=lambda *a, **kw: published.append(True))
    row = claim(runner)
    runner.execute(row)
    assert not published
    assert runner.get(row['id'], 'architect')['state'] == 'running'


@pytest.fixture(params=['token', 'oidc'])
def enterprise_job(request, tmp_path, monkeypatch):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('ENVIRONMENT', 'production')
    monkeypatch.setenv('AEGIS_WORKSPACE_DB', str(tmp_path / 'enterprise.sqlite3'))
    app = FastAPI()
    start_enterprise(app)
    runner = app.state.job_runner
    runner.stop()
    runner.thread.join(timeout=3)
    assert not runner.thread.is_alive()
    store = app.state.product_store
    product = store.create('products', 'Allowed product', 'fixture')['id']
    foreign = store.create('products', 'Other product', 'fixture')['id']
    release = store.create('releases', '1.0', 'fixture', product)['id']
    store.save_workspace(release, {'id': 'assessment', 'revisions': []}, None, 'production', 0, 'fixture')
    app.state.assessment_store.pin_template('assessment', 'fixture')
    issuer = 'https://identity.example/realms/security'
    actor = (f"oidc:{hashlib.sha256(issuer.encode()).hexdigest()[:16]}:subject-1"
             if request.param == 'oidc' else 'architect')

    def configure(*, role='editor', products=None, removed=False):
        record = {'name': 'Architect display' if request.param == 'oidc' else actor,
                  'role': role, 'products': {product: role} if products is None else products}
        if request.param == 'oidc':
            monkeypatch.setenv('AEGIS_OIDC_ENABLED', 'true')
            monkeypatch.setenv('AEGIS_OIDC_ISSUER', issuer)
            monkeypatch.setenv('AEGIS_OIDC_AUDIENCE', 'aegis-api')
            monkeypatch.setenv('AEGIS_OIDC_JWKS_URL', issuer + '/keys')
            monkeypatch.setenv('AEGIS_OIDC_PRINCIPALS', json.dumps({} if removed else {'subject-1': record}))
        else:
            monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({} if removed else {'not-stored-in-job': record}))

    configure()
    prepared_by, analyses = [], []

    def prepare(payload, identity, **kwargs):
        assert kwargs == {'require_ready': True, 'record': False}
        prepared_by.append(identity)
        architecture = SystemArchitecture(components=[Component(id='api', name='API', type='API')], flows=[],
            metadata={'assessment': {'id': 'assessment', 'complete': True}})
        return {'architecture': architecture.model_dump(), 'readiness': {'ready': True}}

    def analyze(architecture, project_name, **kwargs):
        analyses.append(project_name)
        return AnalysisResult(project_name=project_name, summary='Synthetic job result', threats=[],
                              architecture=architecture, score=None, engine_status={})

    monkeypatch.setattr(app.state.assessment_store, 'prepare', prepare)
    app.state.threat_analyzer = SimpleNamespace(analyze=analyze)
    return SimpleNamespace(app=app, runner=runner, store=store, product=product, foreign=foreign,
                           actor=actor, configure=configure, prepared_by=prepared_by, analyses=analyses,
                           payload={'project_name': 'Test assessment', 'assessment_id': 'assessment',
                                    'application_types': ['web']})


def reports(store):
    with store.read_snapshot() as db:
        return [dict(row) for row in db.execute('SELECT * FROM assessment_results')]


def test_actor_removed_while_queued_cannot_analyze_or_publish(enterprise_job):
    setup = enterprise_job
    row = claim(setup.runner, setup.payload, setup.actor)
    setup.configure(removed=True)
    setup.runner.execute(row)
    result = setup.runner.get(row['id'], setup.actor)
    assert result['state'] == 'failed' and result['result'] is None
    assert 'authorized' in result['error']
    assert not setup.analyses and not setup.prepared_by and not reports(setup.store)
    assert 'not-stored-in-job' not in row['payload']


def test_product_grant_revoked_while_queued_is_rechecked(enterprise_job):
    setup = enterprise_job
    row = claim(setup.runner, setup.payload, setup.actor)
    setup.configure(products={setup.foreign: 'editor'})
    setup.runner.execute(row)
    assert setup.runner.get(row['id'], setup.actor)['state'] == 'failed'
    assert not setup.analyses and not reports(setup.store)


def test_revocation_during_analysis_prevents_report_and_job_publication(enterprise_job):
    setup = enterprise_job
    original = setup.app.state.threat_analyzer.analyze

    def revoke(architecture, project_name, **kwargs):
        result = original(architecture, project_name, **kwargs)
        setup.configure(role='viewer')
        return result

    setup.app.state.threat_analyzer.analyze = revoke
    row = claim(setup.runner, setup.payload, setup.actor)
    setup.runner.execute(row)
    result = setup.runner.get(row['id'], setup.actor)
    assert setup.analyses == ['Test assessment']
    assert result['state'] == 'failed' and result['result'] is None
    assert not reports(setup.store)


def test_job_uses_current_product_role_and_publishes_as_submitting_actor(enterprise_job):
    setup = enterprise_job
    setup.configure(role='admin', products={setup.product: 'editor'})
    row = claim(setup.runner, setup.payload, setup.actor)
    setup.runner.execute(row)
    result = setup.runner.get(row['id'], setup.actor)
    assert result['state'] == 'completed', result['error']
    assert setup.prepared_by[0].name == setup.actor
    assert setup.prepared_by[0].role == 'editor'
    saved = reports(setup.store)
    assert len(saved) == 1 and saved[0]['actor'] == setup.actor
    assert result['result']['engine_status']['assessment']['report_id'] == saved[0]['id']
    assert 'analysis-worker' not in saved[0]['actor']
    assert 'not-stored-in-job' not in json.dumps(result)


def test_unknown_unbound_assessment_cannot_be_claimed_by_scoped_job(enterprise_job):
    setup = enterprise_job
    with pytest.raises(ValueError, match='not authorized'):
        claim(setup.runner, {**setup.payload, 'assessment_id': 'unbound'}, setup.actor)
    assert not setup.prepared_by and not reports(setup.store)


def test_malformed_current_access_configuration_fails_closed(enterprise_job, monkeypatch):
    setup = enterprise_job
    row = claim(setup.runner, setup.payload, setup.actor)
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', 'malformed-json')
    setup.runner.execute(row)
    result = setup.runner.get(row['id'], setup.actor)
    assert result['state'] == 'failed' and result['result'] is None
    assert 'malformed-json' not in result['error']
    assert not reports(setup.store)


def test_engine_cannot_publish_result_under_a_different_assessment(enterprise_job):
    setup = enterprise_job
    original = setup.app.state.threat_analyzer.analyze

    def wrong_scope(architecture, project_name, **kwargs):
        result = original(architecture, project_name, **kwargs)
        result.architecture.metadata['assessment']['id'] = 'different-assessment'
        return result

    setup.app.state.threat_analyzer.analyze = wrong_scope
    row = claim(setup.runner, setup.payload, setup.actor)
    setup.runner.execute(row)
    assert setup.runner.get(row['id'], setup.actor)['state'] == 'failed'
    assert not reports(setup.store)


def test_publication_rechecks_original_persisted_payload_not_mutated_input(tmp_path):
    checked = []

    def authorize(actor, payload):
        checked.append(payload['assessment_id'])
        return actor

    def analyze(payload, *, identity):
        payload['assessment_id'] = 'unrelated'
        return {}

    runner = stopped_runner(ProductStore(tmp_path / 'jobs.sqlite3'), analyze, authorize=authorize)
    row = claim(runner, {'assessment_id': 'original'})
    runner.execute(row)
    assert checked == ['original', 'original', 'original']


def test_static_identity_cannot_downgrade_into_local_admin_after_revocation(tmp_path, monkeypatch):
    from app.services.workspace_access import WorkspaceAccess
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('AEGIS_WORKSPACE_DB', str(tmp_path / 'enterprise.sqlite3'))
    monkeypatch.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'secret': {'name': 'local-user', 'role': 'admin'}}))
    app = FastAPI()
    start_enterprise(app)
    runner = app.state.job_runner
    runner.stop()
    runner.thread.join(timeout=3)
    row = claim(runner, {'project_name': 'Draft', 'assessment_id': 'legacy-draft'}, 'local-user')
    assert json.loads(row['payload'])['_aegis_job_identity']['auth_method'] == 'token'
    monkeypatch.delenv('AEGIS_WORKSPACE_TOKENS')
    assert WorkspaceAccess.from_env()._local is not None
    runner.execute(row)
    result = runner.get(row['id'], 'local-user')
    assert result['state'] == 'failed' and 'authorized' in result['error']


def test_preupgrade_guarded_job_without_identity_binding_fails_closed(enterprise_job):
    setup = enterprise_job
    row = claim(setup.runner, setup.payload, setup.actor)
    payload = json.loads(row['payload'])
    payload.pop('_aegis_job_identity')
    row['payload'] = json.dumps(payload)
    with setup.store.connect() as db:
        db.execute('UPDATE jobs SET payload=? WHERE id=?', (row['payload'], row['id']))
    setup.runner.execute(row)
    assert setup.runner.get(row['id'], setup.actor)['state'] == 'failed'
    assert not setup.analyses and not reports(setup.store)
