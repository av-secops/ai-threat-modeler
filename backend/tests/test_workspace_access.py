"""Authentication and product isolation contracts; no identity-provider network calls."""

from dataclasses import FrozenInstanceError
import json
import time
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import jwt
import httpx
import pytest
from pydantic import ValidationError
from starlette.requests import Request
from starlette.websockets import WebSocketDisconnect

from app.services import workspace_access as access
from app.services.assessment_store import AssessmentStore
from app.services.product_store import ProductStore


def request(token=None, *, headers=None, client='127.0.0.1'):
    values = [(b'authorization', f'Bearer {token}'.encode())] if token is not None else []
    values += [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request({'type': 'http', 'headers': values, 'client': (client, 1000),
                    'method': 'GET', 'path': '/', 'query_string': b'', 'scheme': 'http',
                    'server': ('localhost', 8000)})


def grant(products=None, role='editor', name='architect'):
    return {'name': name, 'role': role, 'products': {'alpha': role} if products is None else products}


def identity(products=None, role='editor', name='architect'):
    return access.WorkspaceAccess(tokens={'secret': grant(products, role, name)}).authenticate(request('secret'))


@pytest.fixture(scope='module')
def signing_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update({'kid': 'current', 'alg': 'RS256', 'use': 'sig'})
    return private, public


def token(private, changes=None, **headers):
    now = int(time.time())
    claims = {'iss': 'https://identity.example/realms/workspace', 'sub': 'user-42',
              'aud': 'aegis-api', 'iat': now - 10, 'exp': now + 300}
    for key, value in (changes or {}).items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return jwt.encode(claims, private, algorithm='RS256', headers={'kid': 'current', **headers})


def oidc(signing_key, **kwargs):
    return access.WorkspaceAccess(
        oidc=access.OIDCConfig('https://identity.example/realms/workspace', 'aegis-api',
                              'https://identity.example/realms/workspace/keys'),
        oidc_principals={'user-42': grant()},
        jwks_fetcher=lambda _: {'keys': [signing_key[1]]}, **kwargs)


def denied(call, status):
    with pytest.raises(HTTPException) as result:
        call()
    assert result.value.status_code == status


def test_verified_oidc_identity_is_immutable_and_claims_do_not_grant_roles(signing_key):
    signed = token(signing_key[0], {'role': 'admin', 'products': {'*': 'admin'},
                                  'name': 'another-administrator'})
    user = oidc(signing_key).authenticate(request(signed, headers={'x-user-role': 'admin'}))
    assert user.role == 'editor'
    assert user.products == (('alpha', 'editor'),)
    assert user.name.startswith('oidc:') and user.name.endswith(':user-42')
    assert user.display_name == 'architect'
    with pytest.raises(FrozenInstanceError):
        user.role = 'admin'
    with pytest.raises(TypeError):
        user.products[0] = ('*', 'admin')
    denied(lambda: access.require_product(user, 'beta'), 403)
    denied(lambda: access.require_product({'role': 'admin', 'products': {'*': 'admin'}}, 'alpha'), 403)


@pytest.mark.parametrize('changes', [
    {'exp': int(time.time()) - 100}, {'iss': 'https://attacker.example'}, {'aud': 'other-api'},
    {'exp': None}, {'iat': None}, {'sub': None}, {'nbf': int(time.time()) + 300},
    {'iat': int(time.time()) + 300}, {'exp': int(time.time()) + 10000},
    {'exp': str(int(time.time()) + 300)}, {'token_use': 'id'},
])
def test_oidc_rejects_invalid_registered_claims(signing_key, changes):
    denied(lambda: oidc(signing_key).authenticate(request(token(signing_key[0], changes))), 401)


def test_oidc_rejects_forged_signature_and_algorithm_confusion(signing_key):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    denied(lambda: oidc(signing_key).authenticate(request(token(attacker))), 401)
    unsigned = jwt.encode({'sub': 'user-42'}, '', algorithm='none', headers={'kid': 'current'})
    denied(lambda: oidc(signing_key).authenticate(request(unsigned)), 401)
    symmetric = jwt.encode({'sub': 'user-42'}, 'attacker-key-that-is-long-enough-for-test', algorithm='HS256', headers={'kid': 'current'})
    denied(lambda: oidc(signing_key).authenticate(request(symmetric)), 401)
    denied(lambda: oidc(signing_key).authenticate(request(token(signing_key[0], jku='https://attacker.example/keys'))), 401)
    denied(lambda: oidc(signing_key).authenticate(request(token(signing_key[0], crit=['unsupported']))), 401)


def test_oidc_unmapped_identity_does_not_gain_access(signing_key):
    denied(lambda: oidc(signing_key).authenticate(request(token(signing_key[0], {'sub': 'not-granted'}))), 403)


def test_oidc_does_not_downgrade_to_local_or_static_tokens(signing_key):
    configured = oidc(signing_key, tokens={'secret': grant()}, local_identity=grant())
    denied(lambda: configured.authenticate(request()), 401)
    denied(lambda: configured.authenticate(request('secret')), 401)
    allowed = oidc(signing_key, tokens={'secret': grant()}, allow_tokens_with_oidc=True)
    assert allowed.authenticate(request('secret')).auth_method == 'token'


def test_jwks_cache_bounds_rotation_and_failed_refresh(signing_key):
    now, calls = [1000], []
    document = [{'keys': [signing_key[1]]}]

    def fetch(url):
        calls.append(url)
        if isinstance(document[0], Exception):
            raise document[0]
        return document[0]

    config = access.OIDCConfig('https://identity.example', 'aegis-api', 'https://identity.example/keys')
    cache = access.JWKSCache(config, fetcher=fetch, clock=lambda: now[0])
    cache.get('current', 'RS256')
    for index in range(100):
        cache.get('current', 'RS256')
        denied(lambda: cache.get(f'unknown-{index}', 'RS256'), 401)
    assert len(calls) == 1
    now[0] += 31
    document[0] = {'keys': [{**signing_key[1], 'kid': 'rotated'}]}
    cache.get('rotated', 'RS256')
    assert len(calls) == 2
    denied(lambda: cache.get('current', 'RS256'), 401)
    now[0] += 301
    document[0] = RuntimeError('provider unavailable')
    denied(lambda: cache.get('rotated', 'RS256'), 503)
    denied(lambda: cache.get('rotated', 'RS256'), 503)
    assert len(calls) == 3


@pytest.mark.parametrize('mutation', ['too_many', 'duplicate', 'private', 'no_keys'])
def test_jwks_invalid_documents_fail_closed(signing_key, mutation):
    key = signing_key[1]
    documents = {'too_many': {'keys': [key] * 65}, 'duplicate': {'keys': [key, key]},
                 'private': {'keys': [{**key, 'd': 'private'}]}, 'no_keys': {'keys': []}}
    cache = access.JWKSCache(access.OIDCConfig('https://id.example', 'api', 'https://id.example/keys'),
                             fetcher=lambda _: documents[mutation])
    denied(lambda: cache.get('current', 'RS256'), 503)


@pytest.mark.parametrize('mode', ['redirect', 'oversized'])
def test_jwks_network_fetch_rejects_redirects_and_oversized_bodies(monkeypatch, mode):
    real_client, seen = httpx.Client, []

    def response(incoming):
        seen.append(str(incoming.url))
        if mode == 'redirect':
            return httpx.Response(302, headers={'location': 'https://attacker.example'})
        return httpx.Response(200, content=b' ' * 256_001)

    def client(**options):
        assert options['follow_redirects'] is False
        assert options['trust_env'] is False
        return real_client(transport=httpx.MockTransport(response), **options)

    monkeypatch.setattr(httpx, 'Client', client)
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        access._fetch_jwks('https://identity.example/keys')
    assert seen == ['https://identity.example/keys']


def test_configuration_is_strict_and_local_legacy_use_is_preserved():
    denied(lambda: access.OIDCConfig('http://id.example', 'api', 'https://id.example/keys'), 503)
    denied(lambda: access.OIDCConfig('https://id.example', 'api', 'https://id.example/keys', ('HS256',)), 503)
    denied(lambda: access.WorkspaceAccess.from_env({'AEGIS_OIDC_ENABLED': 'yes'}), 503)
    denied(lambda: access.WorkspaceAccess.from_env({'AEGIS_WORKSPACE_TOKENS': 'not-json'}), 503)
    local = access.WorkspaceAccess.from_env({})
    assert local.authenticate(request()).role == 'admin'
    assert not local.authenticate(request()).scopes_configured
    denied(lambda: local.authenticate(request(client='192.0.2.5', headers={'x-forwarded-for': '127.0.0.1'})), 403)
    denied(lambda: local.authenticate(request(headers={'origin': 'https://attacker.example'})), 403)
    denied(lambda: local.authenticate(request('bad-secret')), 401)
    denied(lambda: access.WorkspaceAccess.from_env({'ENVIRONMENT': 'production'}).authenticate(request()), 401)
    denied(lambda: access.WorkspaceAccess.from_env({'AEGIS_ALLOW_LOCAL_WORKSPACE': 'false'}).authenticate(request()), 401)
    legacy = access.WorkspaceAccess(tokens={'secret': {'name': 'old-user', 'role': 'editor'}})
    user = legacy.authenticate(request('secret'))
    assert not user.scopes_configured and access.can_access_product(user, 'any-existing-product')


def test_scoped_token_requires_matching_product_even_for_admin():
    user = identity({'alpha': 'admin'}, 'admin')
    assert access.require_product(user, 'alpha', 'admin') == 'alpha'
    denied(lambda: access.require_product(user, 'beta'), 403)
    denied(lambda: access.require_platform_admin(user), 403)
    assert access.filter_products(user, [{'id': 'alpha'}, {'id': 'beta'}]) == [{'id': 'alpha'}]
    none = identity({}, 'admin')
    assert not access.can_access_product(none, 'alpha')
    wildcard = identity({'*': 'admin', 'alpha': 'viewer'}, 'admin')
    denied(lambda: access.require_product(wildcard, 'alpha', 'editor'), 403)
    assert access.can_access_product(wildcard, 'beta', 'admin')
    assert not access.can_access_product(identity({'alpha': 'admin'}, 'viewer'), 'alpha', 'editor')
    assert access.identity_for_product(wildcard, 'alpha').role == 'viewer'
    assert wildcard.role == 'admin'


@pytest.fixture
def stored(tmp_path):
    store = ProductStore(tmp_path / 'workspace.sqlite3')
    assessments = AssessmentStore(store)
    products, releases = {}, {}
    for name in ('alpha', 'beta'):
        products[name] = store.create('products', name, 'fixture')['id']
        releases[name] = store.create('releases', '1.0', 'fixture', products[name])['id']
        store.save_workspace(releases[name], {'id': name + '-ws', 'revisions': []}, None, 'production', 0, 'fixture')
        assessments.pin_template(name + '-ws', 'fixture')
        with store.connect() as db:
            db.execute('INSERT INTO assessment_results VALUES(?,?,?,?,?)',
                       (name + '-report', name + '-ws', '{"threats":[{"id":"finding"}]}', 'fixture', time.time()))
            db.execute('INSERT INTO security_reports VALUES(?,?,?,?,?)',
                       (name + '-external', name + '-ws', '{}', 'fixture', time.time()))
    return store, assessments, products, releases


def test_resolvers_use_database_ownership_not_supplied_names(stored):
    store, _, products, releases = stored
    user = identity({products['alpha']: 'editor'})
    assert access.require_resource(store, user, 'release', releases['alpha']) == products['alpha']
    assert access.require_resource(store, user, 'workspace', 'alpha-ws') == products['alpha']
    denied(lambda: access.require_resource(store, user, 'workspace', 'beta-ws'), 404)
    denied(lambda: access.require_resource(store, user, 'release', releases['beta']), 404)
    denied(lambda: access.require_resource(store, user, 'workspace', 'missing'), 404)
    comparison = store.save_comparison(products['beta'], 'Foreign report', {}, {}, 'fixture')
    denied(lambda: access.require_resource(store, user, 'comparison', comparison['id']), 404)
    denied(lambda: access.require_comparison_inputs(store, user, ['alpha-ws', 'beta-ws']), 404)
    wildcard = identity({'*': 'editor'})
    denied(lambda: access.require_comparison_inputs(store, wildcard, ['alpha-ws', 'beta-ws']), 400)
    assert access.require_comparison_inputs(store, user, ['alpha-ws', 'alpha-ws']) == products['alpha']
    foreign_app = store.create('applications', 'Foreign app', 'fixture', products['beta'])['id']
    denied(lambda: access.require_workspace_save(store, user, releases['alpha'], application_id=foreign_app), 404)
    denied(lambda: access.require_workspace_save(store, user, releases['alpha'], workspace_id='beta-ws'), 404)


def test_scoped_assessments_must_be_bound_and_reports_resolve_trusted_scope(stored):
    store, assessments, products, _ = stored
    user = identity({products['alpha']: 'editor'})
    assert access.require_assessment(store, user, 'alpha-ws') == products['alpha']
    denied(lambda: access.require_assessment(store, user, 'beta-ws'), 404)
    denied(lambda: access.require_assessment(store, user, 'arbitrary-new-id'), 404)
    denied(lambda: access.require_model_review(store, user, SimpleNamespace(assessment_id='')), 400)
    assert access.require_assessment_report(store, user, 'alpha-report') == 'alpha-ws'
    denied(lambda: access.require_assessment_report(store, user, 'beta-report'), 404)
    denied(lambda: access.require_assessment_report(store, user, 'beta-external', external=True), 404)
    denied(lambda: access.require_assessment_report(store, user, 'alpha-report', assessment_id='beta-ws'), 404)
    assessments.pin_template('unassigned', user.name)
    denied(lambda: access.require_assessment(store, user, 'unassigned'), 404)
    assert access.require_assessment(store, user, 'unassigned', allow_unassigned_owner=True) is None
    other = identity({products['alpha']: 'editor'}, name='other')
    denied(lambda: access.require_assessment(store, other, 'unassigned', allow_unassigned_owner=True), 404)


def test_assessment_api_rejects_cross_product_reads_writes_exports(stored):
    from app.services import assessment_api
    store, assessments, products, _ = stored
    user = identity({products['alpha']: 'editor'})
    app = FastAPI()
    app.include_router(assessment_api.router)
    app.dependency_overrides[assessment_api.principal] = lambda: user
    app.dependency_overrides[assessment_api.editor] = lambda: user
    app.dependency_overrides[assessment_api.assessment_store] = lambda: assessments
    client = TestClient(app)
    for url in ('/enterprise/assessment-reports/beta-report/reviews',
                '/enterprise/assessment-reports/beta-report/register/json',
                '/enterprise/assessments/beta-ws/security-reports'):
        assert client.get(url).status_code == 404
    assert client.post('/enterprise/assessment-reports/beta-report/reviews/finding',
                       json={'remarks': 'Review remarks'}).status_code == 404
    assert client.post('/enterprise/assessments/beta-ws/security-reports',
                       data={'metadata': '{}'}, files={'file': ('report.json', b'{}')}).status_code == 404
    assert client.get('/enterprise/assessments/alpha-ws/security-reports').status_code == 200


def test_review_expiry_contract_and_product_admin_acceptance(stored, monkeypatch):
    from app.services.assessment_api import ReviewInput, review
    store, assessments, products, _ = stored
    assert ReviewInput(remarks='Review note').acceptance_expires_at == ''
    with pytest.raises(ValidationError):
        ReviewInput(remarks='Review note', acceptance_expires_at='x' * 51)
    expiry = '2027-01-01T00:00:00Z'
    payload = ReviewInput(status='accepted', remarks='Temporary risk acceptance',
                          owner='Product owner', acceptance_expires_at=expiry)
    user = identity({products['alpha']: 'editor'}, role='admin')
    denied(lambda: review('alpha-report', 'finding', payload, assessments, user), 403)
    monkeypatch.setattr(assessments, 'review', lambda report_id, finding_id, value, identity: value)
    admin = identity({products['alpha']: 'admin'}, role='admin')
    assert review('alpha-report', 'finding', payload, assessments, admin)['acceptance_expires_at'] == expiry
    # Final decisions use the same product-admin policy as the workflow route.
    false_positive = payload.model_copy(update={'status': 'false_positive'})
    denied(lambda: review('alpha-report', 'finding', false_positive, assessments, user), 403)
    mitigation = payload.model_copy(update={'status': 'mitigation_proposed'})
    assert review('alpha-report', 'finding', mitigation, assessments, user)['status'] == 'mitigation_proposed'


@pytest.mark.parametrize('status', ['accepted', 'verified_fixed', 'false_positive'])
def test_standard_review_terminal_status_requires_product_admin_in_api_and_store(stored, status):
    from app.services.assessment_api import ReviewInput, review
    _, assessments, products, _ = stored
    payload = ReviewInput(status=status, remarks='Proposed final decision', owner='Product owner')
    editor = identity({products['alpha']: 'editor'}, role='editor')
    global_admin = identity({products['alpha']: 'editor'}, role='admin')
    for user in (editor, global_admin):
        denied(lambda: review('alpha-report', 'finding', payload, assessments, user), 403)
    with pytest.raises(ValueError, match='Product administrator'):
        assessments.review('alpha-report', 'finding', payload.model_dump(), editor)
    denied(lambda: assessments.review('alpha-report', 'finding', payload.model_dump(), global_admin), 404)
    assert not assessments.reviews('alpha-report')['events']
    result = assessments.review('alpha-report', 'finding',
        {'status': 'mitigation_proposed', 'remarks': 'Implement scoped tenant checks.', 'expected_version': 0}, editor)
    assert result['latest']['finding']['status'] == 'mitigation_proposed'


@pytest.fixture
def isolated_env(monkeypatch):
    for key in access.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    access._configured_access.cache_clear()
    yield monkeypatch
    access._configured_access.cache_clear()


def test_principal_cache_refreshes_when_operator_revokes_grants(isolated_env):
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant()}))
    assert access.can_access_product(access.authenticate_request(request('secret')), 'alpha')
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant({})}))
    assert not access.can_access_product(access.authenticate_request(request('secret')), 'alpha')
    denied(lambda: access.authenticate_request(request(headers={'x-user': 'architect', 'x-role': 'admin'})), 401)


def test_main_routes_enforce_configured_identity_before_analysis(isolated_env):
    from app import main
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'viewer': grant(role='viewer')}))
    client = TestClient(main.app)
    body = {'project_name': 'Same project', 'description': 'React frontend calls Node API.'}
    assert client.post('/analyze', json=body).status_code == 401
    assert client.post('/analyze', json=body, headers={'Authorization': 'Bearer viewer'}).status_code == 403
    assert client.post('/analyze-code', json={'project_name': 'Code', 'code_content': 'const x = 12345;'}).status_code == 401
    assert client.post('/admin/retrain-local-models').status_code == 401
    assert client.get('/admin/retrieval-metrics', headers={'Authorization': 'Bearer viewer'}).status_code == 403
    assert client.post('/feedback/findings', json={'project_name': 'Demo', 'finding_id': 'f1', 'decision': 'accepted'}).status_code == 401
    assert client.get('/health').json() == {'status': 'ok', 'version': '2.3.2'}
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect('/ws/analyze') as socket:
            socket.send_json({})
            socket.receive_json()
    assert error.value.code == 4401


def test_browser_websocket_first_message_token_contract(isolated_env):
    from app import main
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'editor': grant(), 'viewer': grant(role='viewer')}))
    client = TestClient(main.app)
    with client.websocket_connect('/ws/analyze') as socket:
        socket.send_json({'access_token': 'editor', 'description': 'short'})
        result = socket.receive_json()
        assert result['type'] == 'error' and 'Description' in result['message']
        assert 'editor' not in json.dumps(result)
    for bearer, code in [('bad', 4401), ('viewer', 4403)]:
        with pytest.raises(WebSocketDisconnect) as error:
            with client.websocket_connect('/ws/analyze') as socket:
                socket.send_json({'access_token': bearer, 'description': 'A Node.js application'})
                socket.receive_json()
        assert error.value.code == code
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect('/ws/analyze?access_token=editor'):
            pass
    assert error.value.code == 4401


def test_websocket_token_is_consumed_and_oversized_message_rejected(isolated_env):
    from app import main
    from starlette.websockets import WebSocket
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant()}))
    scope = {**request().scope, 'type': 'websocket'}
    socket = WebSocket(scope, None, None)
    payload = {'access_token': 'secret', 'description': 'Node.js application'}
    assert access.authenticate_websocket_payload(socket, payload).name == 'architect'
    assert 'access_token' not in payload and not socket.headers.get('authorization')
    with pytest.raises(WebSocketDisconnect) as error:
        with TestClient(main.app).websocket_connect('/ws/analyze') as socket:
            socket.send_text('x' * 32_769)
            socket.receive_json()
    assert error.value.code == 1009


def test_websocket_waits_at_most_five_seconds_for_first_message(isolated_env):
    from app import main
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant()}))
    with pytest.raises(WebSocketDisconnect) as error:
        with TestClient(main.app).websocket_connect('/ws/analyze') as socket:
            socket.receive_json()
    assert error.value.code == 4408


@pytest.mark.parametrize(('url', 'body'), [
    ('/analyze-iac', {'project_name': 'IaC', 'iac_content': 'services: {}'}),
    ('/analyze-with-llm', {'project_name': 'LLM', 'description': 'Node.js web application',
                           'llm_provider': 'openai', 'api_key': 'test-key-not-real'}),
    ('/llm/models', {'provider': 'openai', 'api_key': 'test-key-not-real'}),
    ('/validate-api-key', {'provider': 'openai', 'api_key': 'test-key-not-real'}),
    ('/model-review/prepare', {'project_name': 'Draft', 'assessment_id': 'foreign-assessment'}),
    ('/model-review/analyze', {'project_name': 'Draft', 'assessment_id': 'foreign-assessment'}),
])
def test_remaining_json_analysis_routes_require_authentication(isolated_env, url, body):
    from app import main
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant()}))
    assert TestClient(main.app).post(url, json=body).status_code == 401


@pytest.mark.parametrize('url', ['/analyze-documents', '/analyze-iac-project', '/model-review/sources'])
def test_upload_routes_require_authentication_before_extraction(isolated_env, url):
    from app import main
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({'secret': grant()}))
    response = TestClient(main.app).post(url, data={'project_name': 'Upload'},
                                        files={'files': ('notes.md', b'Node.js application')})
    assert response.status_code == 401


def test_main_result_cache_is_private_to_verified_identity(isolated_env):
    from app import main
    from app.models import AnalysisResult, SystemArchitecture
    isolated_env.setenv('AEGIS_WORKSPACE_TOKENS', json.dumps({
        'alice': grant(name='alice'), 'bob': grant(name='bob')}))
    calls = []

    def analyze(*args, **kwargs):
        calls.append(args)
        return AnalysisResult(project_name=args[1], summary=f'Run {len(calls)}', threats=[],
                              architecture=SystemArchitecture(components=[], flows=[]), score=None)

    isolated_env.setattr(main, 'get_shared_analyzer', lambda _: SimpleNamespace(analyze_from_text=analyze))
    main._analysis_cache.clear()
    client = TestClient(main.app)
    body = {'project_name': 'Same project', 'description': 'The same architecture content'}
    alice = client.post('/analyze', json=body, headers={'Authorization': 'Bearer alice'})
    bob = client.post('/analyze', json=body, headers={'Authorization': 'Bearer bob'})
    cached = client.post('/analyze', json=body, headers={'Authorization': 'Bearer alice'})
    assert alice.status_code == bob.status_code == cached.status_code == 200
    assert alice.json()['summary'] == cached.json()['summary'] == 'Run 1'
    assert bob.json()['summary'] == 'Run 2' and len(calls) == 2
    assert bob.json()['diff_summary'] is None
    main._analysis_cache.clear()


def test_legacy_analysis_does_not_compare_another_users_project():
    from app import main
    previous = SimpleNamespace(project_name='Same name', threats=['private-risk'])
    main._latest_analysis_by_project['Same name'] = previous
    result = SimpleNamespace(diff_summary=None)
    analyzer = SimpleNamespace(analyze_from_text=lambda *args, **kwargs: result)
    assert main._analyze_text_payload(analyzer, 'Node.js app', 'Same name').diff_summary is None
    assert main._latest_analysis_by_project.get('Same name') is previous
    assert access.identity_cache_key(identity(name='alice')) != access.identity_cache_key(identity(name='bob'))
    assert access.identity_cache_key(identity({'alpha': 'editor'})) != access.identity_cache_key(identity({'beta': 'editor'}))
