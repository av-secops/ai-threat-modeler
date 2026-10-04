"""Opt-in workspace authentication and product authorization.

This module does not install route guards. Integrators must apply the policy
helpers before every read/write, including report exports and background jobs.
"""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from functools import lru_cache
import hashlib
import hmac
import json
import math
import os
from threading import RLock
import time
from urllib.parse import urlparse

from fastapi import HTTPException
from starlette.requests import HTTPConnection


ROLES = {'viewer': 1, 'editor': 2, 'admin': 3}
ALGORITHMS = frozenset({'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                        'ES256', 'ES384', 'ES512'})
ENV_KEYS = (
    'AEGIS_OIDC_ENABLED', 'AEGIS_OIDC_ISSUER', 'AEGIS_OIDC_AUDIENCE',
    'AEGIS_OIDC_JWKS_URL', 'AEGIS_OIDC_ALGORITHMS', 'AEGIS_OIDC_PRINCIPALS',
    'AEGIS_OIDC_ALLOW_WORKSPACE_TOKENS', 'AEGIS_WORKSPACE_TOKENS',
    'AEGIS_ALLOW_LOCAL_WORKSPACE', 'AEGIS_LOCAL_WORKSPACE_IDENTITY', 'ENVIRONMENT',
)


def _configuration_error():
    return HTTPException(503, 'Workspace access configuration is invalid.')


def _unauthorized():
    return HTTPException(401, 'A valid workspace credential is required.',
                         headers={'WWW-Authenticate': 'Bearer'})


def _text(value, maximum=256):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= maximum
            and not any(ord(char) < 32 for char in value))


def _json_object(value):
    try:
        if not isinstance(value, str) or len(value) > 256_000:
            raise ValueError()
        result = json.loads(value)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise _configuration_error() from None


def _flag(value):
    if value not in {'', 'true', 'false'}:
        raise _configuration_error()
    return value == 'true'


@dataclass(frozen=True, slots=True)
class VerifiedIdentity(Mapping):
    """Server-created identity; no token, arbitrary claims, or mutable grants."""

    name: str
    role: str
    subject: str
    issuer: str
    auth_method: str
    products: tuple[tuple[str, str], ...]
    display_name: str
    scopes_configured: bool = True

    def __post_init__(self):
        if (not isinstance(self.role, str) or self.role not in ROLES or not _text(self.name, 600) or not _text(self.subject)
                or not _text(self.issuer, 2000) or not _text(self.display_name)
                or self.auth_method not in {'oidc', 'token', 'local'} or type(self.scopes_configured) is not bool
                or not isinstance(self.products, tuple)
                or any(not isinstance(pair, tuple) or len(pair) != 2
                       or not _text(pair[0], 100) or not isinstance(pair[1], str)
                       or pair[1] not in ROLES for pair in self.products)
                or len({pair[0] for pair in self.products}) != len(self.products)):
            raise ValueError('Invalid verified identity')

    def __getitem__(self, key):
        if key not in self.__iter__():
            raise KeyError(key)
        return getattr(self, key)

    def __iter__(self):
        return iter(('name', 'role', 'subject', 'issuer', 'auth_method', 'products', 'display_name', 'scopes_configured'))

    def __len__(self):
        return 8


@dataclass(frozen=True, slots=True)
class _Grant:
    name: str
    role: str
    products: tuple[tuple[str, str], ...]
    scopes_configured: bool = True


def _grant(value, *, legacy=False):
    if legacy and isinstance(value, dict) and 'products' not in value:
        grant = _grant({**value, 'products': {'*': value.get('role')}})
        return _Grant(grant.name, grant.role, grant.products, False)
    # Empty grants are valid (deny all); absent grants are a configuration error.
    if (not isinstance(value, dict) or not _text(value.get('name'))
            or not isinstance(value.get('role'), str) or value['role'] not in ROLES
            or not isinstance(value.get('products'), dict)
            or len(value['products']) > 2000
            or any(not _text(key, 100) or not isinstance(role, str) or role not in ROLES
                   for key, role in value['products'].items())):
        raise _configuration_error()
    return _Grant(value['name'], value['role'], tuple(sorted(value['products'].items())))


@dataclass(frozen=True, slots=True)
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ('RS256',)
    cache_seconds: int = 300
    refresh_seconds: int = 30
    leeway_seconds: int = 30
    max_lifetime_seconds: int = 3600

    def __post_init__(self):
        for value in (self.issuer, self.jwks_url):
            if not _text(value, 2000):
                raise _configuration_error()
            try:
                parsed = urlparse(value)
                parsed.port
            except ValueError:
                raise _configuration_error() from None
            if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                    or parsed.password or parsed.fragment):
                raise _configuration_error()
        if (not _text(self.audience, 500) or not isinstance(self.algorithms, tuple)
                or not self.algorithms or len(set(self.algorithms)) != len(self.algorithms)
                or not set(self.algorithms) <= ALGORITHMS):
            raise _configuration_error()
        ranges = ((self.cache_seconds, 30, 900), (self.refresh_seconds, 5, 60),
                  (self.leeway_seconds, 0, 60), (self.max_lifetime_seconds, 60, 86400))
        if any(type(value) is not int or not lower <= value <= upper for value, lower, upper in ranges):
            raise _configuration_error()
        if self.refresh_seconds > self.cache_seconds:
            raise _configuration_error()


def _jwt_library():
    try:
        import jwt
        import cryptography  # noqa: F401: require asymmetric signature support
        return jwt
    except ImportError:
        raise HTTPException(503, 'OIDC requires the PyJWT crypto dependency.') from None


def _fetch_jwks(url):
    """Only a trusted configured URL is used, never a JWT-provided URL."""
    import httpx
    deadline = time.monotonic() + 5
    with httpx.Client(timeout=httpx.Timeout(3), follow_redirects=False, trust_env=False) as client:
        with client.stream('GET', url, headers={'Accept': 'application/json'}) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError('Unexpected JWKS status')
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                body.extend(chunk)
                if len(body) > 256_000 or time.monotonic() > deadline:
                    raise ValueError('JWKS response limit exceeded')
            return json.loads(body)


class JWKSCache:
    """Single issuer, bounded keys/TTL and refresh rate; expired keys fail closed."""

    def __init__(self, config, *, fetcher=None, clock=time.monotonic):
        self.config = config
        self._fetcher = fetcher or _fetch_jwks
        self._clock = clock
        self._keys = {}
        self._expires = 0
        self._next_refresh = 0
        self._lock = RLock()

    def _parse(self, document):
        jwt = _jwt_library()
        if (not isinstance(document, dict) or not isinstance(document.get('keys'), list)
                or not 1 <= len(document['keys']) <= 64):
            raise ValueError('Invalid JWKS')
        result, seen = {}, set()
        for value in document['keys']:
            if not isinstance(value, dict) or not _text(value.get('kid'), 128):
                raise ValueError('Invalid key identifier')
            kid = value['kid']
            if kid in seen:
                raise ValueError('Ambiguous key identifier')
            seen.add(kid)
            if value.get('use') not in (None, 'sig'):
                continue
            if 'key_ops' in value and value['key_ops'] != ['verify']:
                continue
            if any(field in value for field in ('d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k')):
                raise ValueError('JWKS must contain public asymmetric keys only')
            for algorithm in self.config.algorithms:
                if value.get('alg') not in (None, algorithm):
                    continue
                if algorithm.startswith(('RS', 'PS')):
                    if value.get('kty') != 'RSA':
                        continue
                elif (value.get('kty') != 'EC'
                      or value.get('crv') != {'ES256': 'P-256', 'ES384': 'P-384', 'ES512': 'P-521'}[algorithm]):
                    continue
                key = jwt.PyJWK.from_dict(value, algorithm=algorithm).key
                if algorithm.startswith(('RS', 'PS')) and not 2048 <= key.key_size <= 8192:
                    raise ValueError('Unsupported RSA key size')
                result[(kid, algorithm)] = key
        if not result:
            raise ValueError('No supported signing keys')
        return result

    def get(self, kid, algorithm):
        with self._lock:
            now = self._clock()
            key = self._keys.get((kid, algorithm))
            if key is not None and now < self._expires:
                return key
            # Unknown kid floods cannot force one network request per token.
            if now < self._next_refresh:
                if now >= self._expires:
                    raise HTTPException(503, 'OIDC signing keys are temporarily unavailable.')
                raise _unauthorized()
            self._next_refresh = now + self.config.refresh_seconds
            try:
                keys = self._parse(self._fetcher(self.config.jwks_url))
            except Exception:
                raise HTTPException(503, 'OIDC signing keys are temporarily unavailable.') from None
            self._keys = keys
            self._expires = self._clock() + self.config.cache_seconds
            key = self._keys.get((kid, algorithm))
            if key is None:
                raise _unauthorized()
            return key


class WorkspaceAccess:
    """Retain one instance per process, not one JWKS cache per request."""

    def __init__(self, *, oidc=None, oidc_principals=None, tokens=None,
                 allow_tokens_with_oidc=False, local_identity=None, production=False,
                 jwks_fetcher=None, clock=time.monotonic):
        self.oidc = oidc
        self._principals = self._records(oidc_principals or {})
        self._tokens = self._records(tokens or {}, legacy=True)
        self._local = _grant(local_identity, legacy=True) if local_identity is not None else None
        self._production = production
        self._allow_tokens = not oidc or allow_tokens_with_oidc
        self._jwks = JWKSCache(oidc, fetcher=jwks_fetcher, clock=clock) if oidc else None
        if oidc:
            _jwt_library()

    @staticmethod
    def _records(records, *, legacy=False):
        if not isinstance(records, dict) or len(records) > 2000:
            raise _configuration_error()
        result = {}
        for key, value in records.items():
            if not _text(key):
                raise _configuration_error()
            result[key] = _grant(value, legacy=legacy)
        return result

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        enabled = _flag(env.get('AEGIS_OIDC_ENABLED', ''))
        oidc = None
        if enabled:
            oidc = OIDCConfig(
                issuer=env.get('AEGIS_OIDC_ISSUER', ''),
                audience=env.get('AEGIS_OIDC_AUDIENCE', ''),
                jwks_url=env.get('AEGIS_OIDC_JWKS_URL', ''),
                algorithms=tuple(item.strip() for item in (env.get('AEGIS_OIDC_ALGORITHMS') or 'RS256').split(',')),
            )
        local = None
        if env.get('AEGIS_ALLOW_LOCAL_WORKSPACE', '') != 'false':
            _flag(env.get('AEGIS_ALLOW_LOCAL_WORKSPACE', ''))
            local = _json_object(env.get('AEGIS_LOCAL_WORKSPACE_IDENTITY') or
                                 '{"name":"local-user","role":"admin"}')
        return cls(oidc=oidc, oidc_principals=_json_object(env.get('AEGIS_OIDC_PRINCIPALS') or '{}'),
                   tokens=_json_object(env.get('AEGIS_WORKSPACE_TOKENS') or '{}'),
                   allow_tokens_with_oidc=_flag(env.get('AEGIS_OIDC_ALLOW_WORKSPACE_TOKENS', '')),
                   local_identity=local, production=env.get('ENVIRONMENT', '').lower() == 'production')

    @staticmethod
    def _identity(grant, subject, issuer, method):
        # Jobs and audit records use name as their actor key, never a display claim.
        name = (f"oidc:{hashlib.sha256(issuer.encode()).hexdigest()[:16]}:{subject}"
                if method == 'oidc' else grant.name)
        return VerifiedIdentity(name, grant.role, subject, issuer, method, grant.products, grant.name,
                                grant.scopes_configured)

    def _oidc_identity(self, token):
        jwt = _jwt_library()
        try:
            header = jwt.get_unverified_header(token)
            algorithm, kid = header.get('alg'), header.get('kid')
            if (algorithm not in self.oidc.algorithms or not _text(kid, 128)
                    or header.get('typ', 'JWT') not in {'JWT', 'at+jwt'}
                    or header.get('crit') or any(key in header for key in ('jku', 'jwk', 'x5u'))):
                raise _unauthorized()
            key = self._jwks.get(kid, algorithm)
            claims = jwt.decode(token, key, algorithms=list(self.oidc.algorithms),
                                issuer=self.oidc.issuer, audience=self.oidc.audience,
                                leeway=self.oidc.leeway_seconds,
                                options={'require': ['iss', 'sub', 'aud', 'exp', 'iat']})
            dates = [claims.get('iat'), claims.get('exp')]
            if 'nbf' in claims:
                dates.append(claims['nbf'])
            if (any(type(value) is not int or not math.isfinite(value) for value in dates)
                    or not _text(claims.get('sub')) or claims['iss'] != self.oidc.issuer
                    or not 0 < claims['exp'] - claims['iat'] <= self.oidc.max_lifetime_seconds
                    or claims.get('token_use', 'access') != 'access'):
                raise _unauthorized()
        except (jwt.PyJWTError, TypeError, ValueError, OverflowError):
            raise _unauthorized() from None
        grant = self._principals.get(claims['sub'])
        if grant is None:
            raise HTTPException(403, 'This identity has no workspace access grant.')
        return self._identity(grant, claims['sub'], self.oidc.issuer, 'oidc')

    def authenticate(self, request):
        values = request.headers.getlist('authorization')
        token = None
        if values:
            if len(values) != 1 or len(values[0]) > 16_400:
                raise _unauthorized()
            parts = values[0].split(' ')
            if (len(parts) != 2 or parts[0].lower() != 'bearer' or not parts[1]
                    or not parts[1].isascii() or any(char.isspace() for char in parts[1])):
                raise _unauthorized()
            token = parts[1]
            if self._allow_tokens:
                for secret, grant in self._tokens.items():
                    if hmac.compare_digest(secret.encode(), token.encode()):
                        return self._identity(grant, grant.name, 'workspace-token', 'token')
            if self.oidc:
                return self._oidc_identity(token)
            # Invalid credentials never downgrade to unauthenticated local admin.
            raise _unauthorized()
        if self.oidc or self._tokens or self._production or self._local is None:
            raise _unauthorized()
        client = request.client.host if request.client else None
        origin = request.headers.get('origin')
        if client not in {'127.0.0.1', '::1', 'testclient'}:
            raise HTTPException(403, 'Local workspace access requires a loopback client.')
        if origin:
            try:
                parsed = urlparse(origin)
            except ValueError:
                raise HTTPException(403, 'Local workspace access requires a local origin.') from None
            if parsed.scheme not in {'http', 'https'} or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
                raise HTTPException(403, 'Local workspace access requires a local origin.')
        return self._identity(self._local, self._local.name, 'local-workspace', 'local')


@lru_cache(maxsize=1)
def _configured_access(settings):
    return WorkspaceAccess.from_env(dict(settings))


_configuration_lock = RLock()


def authenticate_request(request):
    """Drop-in principal delegate; hot-reload operator grants, reuse JWKS cache."""
    settings = tuple((key, os.getenv(key, '')) for key in ENV_KEYS)
    with _configuration_lock:
        configured = _configured_access(settings)
    return configured.authenticate(request)


def authenticate_websocket_payload(websocket, payload):
    """Consume a browser's first-message bearer token without altering its scope.

    The caller must bound the first message and receive timeout before calling.
    No URL credential, raw identity claim, or role header is accepted.
    """
    token = payload.pop('access_token', None)
    if 'access_token' in websocket.query_params or 'token' in websocket.query_params:
        raise _unauthorized()
    if token is None:
        return authenticate_request(websocket)
    if (not isinstance(token, str) or not token or len(token) > 16_384
            or not token.isascii() or any(char.isspace() for char in token)
            or websocket.headers.getlist('authorization')):
        raise _unauthorized()
    connection = HTTPConnection({**websocket.scope,
                                 'headers': [*websocket.scope.get('headers', []),
                                             (b'authorization', b'Bearer ' + token.encode('ascii'))]})
    return authenticate_request(connection)


def require_role(identity, minimum_role='viewer'):
    if (minimum_role not in ROLES or not isinstance(identity, VerifiedIdentity)
            or ROLES[identity.role] < ROLES[minimum_role]):
        raise HTTPException(403, 'Workspace role does not permit this operation.')
    return identity


def can_access_product(identity, product_id, minimum_role='viewer'):
    if (not isinstance(identity, VerifiedIdentity) or not _text(product_id, 100)
            or product_id == '*' or minimum_role not in ROLES):
        return False
    grants = dict(identity.products)
    # An exact product grant can intentionally narrow an explicit wildcard grant.
    role = grants.get(product_id, grants.get('*'))
    return role in ROLES and min(ROLES[role], ROLES[identity.role]) >= ROLES[minimum_role]


def require_product(identity, product_id, minimum_role='viewer'):
    if not can_access_product(identity, product_id, minimum_role):
        raise HTTPException(403, 'Product access is not permitted.')
    return product_id


def identity_for_product(identity, product_id):
    """Reduce the role passed to stores that make their own admin decisions."""
    require_product(identity, product_id)
    grants = dict(identity.products)
    role = grants.get(product_id, grants.get('*'))
    effective_role = min((identity.role, role), key=ROLES.__getitem__)
    return replace(identity, role=effective_role)


def require_platform_admin(identity):
    require_role(identity, 'admin')
    if dict(identity.products).get('*') != 'admin':
        raise HTTPException(403, 'Explicit installation administrator access is required.')
    return identity


def filter_products(identity, products, minimum_role='viewer'):
    require_role(identity, minimum_role)
    return [product for product in products if can_access_product(identity, product.get('id'), minimum_role)]


RESOURCE_QUERIES = {
    'product': 'SELECT id AS product_id FROM products WHERE id=?',
    'release': 'SELECT product_id FROM releases WHERE id=?',
    'application': 'SELECT product_id FROM applications WHERE id=?',
    'workspace': ('SELECT r.product_id FROM workspaces w JOIN releases r ON r.id=w.release_id '
                  'WHERE w.id=?'),
    'comparison': 'SELECT product_id FROM comparisons WHERE id=?',
}


def _resource_product(db, resource_type, identifier):
    if resource_type not in RESOURCE_QUERIES:
        raise ValueError('Unsupported workspace resource type')
    if not _text(identifier, 100) or identifier == '*':
        raise HTTPException(404, 'Workspace resource not found.')
    row = db.execute(RESOURCE_QUERIES[resource_type], (identifier,)).fetchone()
    if row is None:
        raise HTTPException(404, 'Workspace resource not found.')
    return row['product_id']


def product_for_resource(store, resource_type, identifier):
    """Resolve trusted ownership only. This is NOT an authorization check."""
    with store.read_snapshot() as db:
        return _resource_product(db, resource_type, identifier)


def require_resource(store, identity, resource_type, identifier, minimum_role='viewer'):
    with store.read_snapshot() as db:
        product_id = _resource_product(db, resource_type, identifier)
        if not can_access_product(identity, product_id, minimum_role):
            # Do not distinguish another product's record from a missing record.
            raise HTTPException(404, 'Workspace resource not found.')
        return product_id


def require_comparison_inputs(store, identity, workspace_ids, minimum_role='viewer'):
    if (not isinstance(workspace_ids, (list, tuple)) or not 2 <= len(workspace_ids) <= 100):
        raise HTTPException(400, 'Select between two and 100 comparison workspaces.')
    with store.read_snapshot() as db:
        products = set()
        for identifier in workspace_ids:
            product_id = _resource_product(db, 'workspace', identifier)
            if not can_access_product(identity, product_id, minimum_role):
                raise HTTPException(404, 'Workspace resource not found.')
            products.add(product_id)
        if len(products) != 1:
            raise HTTPException(400, 'Comparison workspaces must belong to the same product.')
        return products.pop()


def require_workspace_save(store, identity, release_id, *, application_id=None, workspace_id=None):
    """Check all referenced ownership, not a caller-provided product_id."""
    with store.read_snapshot() as db:
        product_id = _resource_product(db, 'release', release_id)
        if not can_access_product(identity, product_id, 'editor'):
            raise HTTPException(404, 'Workspace resource not found.')
        if application_id is not None:
            if _resource_product(db, 'application', application_id) != product_id:
                raise HTTPException(404, 'Workspace resource not found.')
        if workspace_id is not None:
            if not _text(workspace_id, 100):
                raise HTTPException(400, 'A valid workspace ID is required.')
            existing = db.execute('SELECT release_id FROM workspaces WHERE id=?', (workspace_id,)).fetchone()
            if existing is not None and existing['release_id'] != release_id:
                raise HTTPException(404, 'Workspace resource not found.')
        return product_id


def _assessment_product(db, identity, assessment_id, minimum_role, *, allow_unassigned_owner=False):
    require_role(identity, minimum_role)
    if not _text(assessment_id, 100):
        raise HTTPException(404, 'Assessment not found.')
    row = db.execute(RESOURCE_QUERIES['workspace'], (assessment_id,)).fetchone()
    if row is not None:
        if not can_access_product(identity, row['product_id'], minimum_role):
            raise HTTPException(404, 'Assessment not found.')
        return row['product_id']
    if not identity.scopes_configured:
        # Legacy single-workspace installations have no saved product binding.
        return None
    if allow_unassigned_owner:
        row = db.execute('SELECT actor FROM assessment_sessions WHERE id=?', (assessment_id,)).fetchone()
        if row is not None and row['actor'] == identity.name:
            return None
    raise HTTPException(404, 'Save the assessment in an authorized product before using it.')


def require_assessment(store, identity, assessment_id, minimum_role='viewer', *, allow_unassigned_owner=False):
    """Assessment IDs bind to saved workspace IDs, never a request's product name.

    Scoped identities cannot claim a new unbound ID. Owner-only legacy sessions
    may be enabled explicitly by an integrator, not by a request parameter.
    """
    with store.read_snapshot() as db:
        return _assessment_product(db, identity, assessment_id, minimum_role,
                                   allow_unassigned_owner=allow_unassigned_owner)


def require_assessment_report(store, identity, report_id, minimum_role='viewer', *, external=False,
                              assessment_id=None, allow_unassigned_owner=False):
    if not _text(report_id, 100):
        raise HTTPException(404, 'Assessment report not found.')
    table = 'security_reports' if external else 'assessment_results'
    with store.read_snapshot() as db:
        row = db.execute(f'SELECT assessment_id FROM {table} WHERE id=?', (report_id,)).fetchone()
        if row is None or (assessment_id is not None and row['assessment_id'] != assessment_id):
            raise HTTPException(404, 'Assessment report not found.')
        _assessment_product(db, identity, row['assessment_id'], minimum_role,
                            allow_unassigned_owner=allow_unassigned_owner)
        return row['assessment_id']


def require_model_review(store, identity, payload):
    """Guard before prepare() creates a session, reads previous answers or saves evidence."""
    require_role(identity, 'editor')
    if payload.assessment_id:
        return require_assessment(store, identity, payload.assessment_id, 'editor')
    if identity.scopes_configured:
        raise HTTPException(400, 'Save the assessment in an authorized product first.')
    return None


def identity_cache_key(identity):
    require_role(identity)
    return hashlib.sha256(json.dumps([identity.issuer, identity.subject, identity.auth_method,
                                     identity.role, identity.products]).encode()).hexdigest()
