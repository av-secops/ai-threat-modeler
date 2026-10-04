# Workspace identity and product access

This foundation validates OIDC JWT access tokens and authorizes saved products,
releases, applications, workspaces, comparisons and assessment reports. It is not
a completed multi-tenant SaaS security boundary. Every new endpoint, export,
background job and integration must apply these guards before reading data.

## Deployment modes

Existing local installations remain usable without credentials, but only from
loopback clients with a local Origin when one is supplied. Forwarded identity and
role headers are ignored. Set `AEGIS_ALLOW_LOCAL_WORKSPACE=false` to disable that
fallback. `ENVIRONMENT=production`, configured workspace tokens, or enabled OIDC
always disable anonymous local fallback. Run the development server on loopback;
do not expose it through a trusted forwarding proxy with authentication disabled.

Existing `AEGIS_WORKSPACE_TOKENS` records with `name` and `role` retain their
installation-wide role for compatibility. **They are not product-isolated.** Add
`products` to migrate a token to explicit grants. An empty object denies every
product; an omitted product is denied. A global admin role is not a bypass.

```json
{
  "<operator-generated-secret>": {
    "name": "release-reviewer",
    "role": "editor",
    "products": {
      "<saved-product-uuid>": "editor",
      "<another-product-uuid>": "viewer"
    }
  }
}
```

Grants use immutable product IDs, not names. `{"*":"admin"}` is an explicit
installation-wide grant; reserve it for administrators who may manage shared
questionnaires, approve training data and see installation audits. Creating a
product requires an explicit wildcard editor-or-admin grant.
An exact product grant can narrow a wildcard grant. Effective permissions are
the lower of the identity role and the product role. Allowed roles are `viewer`,
`editor` and `admin`.

## OIDC configuration

Install the backend dependency `PyJWT[crypto]>=2.10.1,<3`. This work was tested
with PyJWT 2.15.1 and cryptography 50.0.2; dependency declarations are maintained
separately by the integration owner.

```text
AEGIS_OIDC_ENABLED=true
AEGIS_OIDC_ISSUER=https://identity.example/realms/security
AEGIS_OIDC_AUDIENCE=aegis-api
AEGIS_OIDC_JWKS_URL=https://identity.example/realms/security/protocol/openid-connect/certs
AEGIS_OIDC_ALGORITHMS=RS256
AEGIS_OIDC_PRINCIPALS={"<stable-subject-id>":{"name":"Product architect","role":"editor","products":{"<saved-product-uuid>":"editor"}}}
```

Configure an API-specific audience at the provider. Send an **access token** as
`Authorization: Bearer <token>`. This is bearer-token verification, not an OIDC
authorization-code/PKCE browser login implementation. ID tokens are not intended
for the API. A `token_use` claim, when present, must be `access`; providers that
do not emit it must distinguish API access tokens by audience and policy. The
accepted JWT header types are `JWT` and `at+jwt`.

The issuer, audience, signature, expiry, issued-at and subject are required and
verified. Not-before is verified when supplied. Default clock tolerance is 30
seconds; tokens may live at most one hour. `OIDCConfig` supports bounded custom
settings when instantiated by the server. Only explicit RSA/PSS/ECDSA algorithms
are allowed. Symmetric algorithms and unsigned tokens are rejected. Token-supplied
key URLs, inline keys and unsupported critical headers are rejected.

Authorization comes from the operator's exact subject-to-grant mapping after JWT
verification. JWT role, group, product, tenant, name and email claims do not grant
permissions. The configured issuer binds each subject. The audit/job actor is an
issuer-derived stable identifier, not an editable display name. Duplicate static
token names intentionally represent the same legacy identity; use distinct names
for distinct users. Do not reuse OIDC actor names for manually configured tokens.

Static workspace tokens are disabled in OIDC mode unless
`AEGIS_OIDC_ALLOW_WORKSPACE_TOKENS=true` is explicitly configured. OIDC failure
never falls back to anonymous local access. Invalid configuration returns 503;
invalid credentials return 401; a valid but ungranted identity receives 403.

The single-process JWKS cache retains at most 64 keys for five minutes, limits
unknown-key refreshes to once per 30 seconds, and never trusts expired cached
keys after a refresh failure. Downloads use HTTPS, no redirects or environment
proxies, a 256 KB response limit, three-second I/O timeouts and a five-second
stream deadline. The total worst-case wait may include the active I/O timeout.
URLs come only from server configuration. Key rotation may therefore take up to
30 seconds to be recognized. Removed keys can remain valid until the cached
set expires. There is no token introspection/revocation endpoint in this module.
Use short-lived access tokens and manage emergency revocation at the provider
and server configuration. Do not log access tokens.

## Integration calls

The module is `backend/app/services/workspace_access.py`. Keep a verified identity
object server-side; do not reconstruct one from a request body or header fields.
It is an immutable mapping and supports existing `user['name']` / `user['role']`
call sites. `authenticate_request` shares a bounded verifier cache and reloads it
when operator configuration changes; no network request is made per cached-key
authentication.

```python
def principal(request: Request):
    return authenticate_request(request)

def editor(identity=Depends(principal)):
    return require_role(identity, 'editor')

# Filter before aggregating or paginating. Do not return global totals first.
rows = filter_products(user, store.list_products())

# Direct product routes, release/workspace/comparison IDs:
require_product(user, product_id, 'editor')
product_id = require_resource(store, user, 'release', release_id, 'editor')
product_id = require_resource(store, user, 'workspace', workspace_id)
require_resource(store, user, 'comparison', comparison_id)

# Check BOTH comparison sides and every application in an aggregate comparison.
require_comparison_inputs(store, user, [before_workspace, after_workspace])

# Validate references before saving; store still enforces immutable workspace scope.
require_workspace_save(store, user, release_id,
                       application_id=application_id, workspace_id=workspace['id'])

# Before prepare(), jobs, previous-answer reuse or analysis:
product_id = require_model_review(store, user, payload)
reviewer = identity_for_product(user, product_id) if product_id else user
prepared = assessment_store.prepare(payload, reviewer)

# Assessment/report APIs, including external-report links and exports:
require_assessment(store, user, assessment_id, 'editor')
require_assessment_report(store, user, report_id)
require_assessment_report(store, user, external_report_id, 'editor',
                          external=True, assessment_id=assessment_id)

# Installation operations, not merely a product-admin role:
require_platform_admin(user)
```

`require_resource` supports `product`, `release`, `application`, `workspace` and
`comparison`. Ownership is resolved from database relations, never a supplied
product ID or serialized report metadata. Missing and unauthorized indirect
resources both return 404. `product_for_resource` only resolves ownership; it is
**not** an authorization check. Use `identity_for_product` before passing an
identity to store methods that independently check `role == 'admin'`.

For scoped identities, an assessment ID must be the ID of an already saved
workspace in an authorized product. Save that workspace before preparing the
questionnaire. Unknown/unbound assessment IDs are denied even to scoped wildcard
administrators. An integrator can explicitly enable `allow_unassigned_owner=True`
only for an existing assessment session whose recorded actor matches the verified
identity. No existing endpoint opts into this exception; it cannot create or claim
an unbound assessment. Unscoped legacy assessments remain compatible.

The assessment API guards report reads, exports, imports, reviews and links.
Accepting risk, marking a risk verified fixed, and marking a false positive all
require the product's admin grant on both standard review and security-workflow
routes. A global admin with only editor access to the product cannot make these
final decisions. The assessment store also enforces this policy for verified
identities. Editors can record review progress and propose mitigations. Shared questionnaire mutations
require installation admin. Main HTTP analysis routes require editor access;
model review also checks the saved assessment binding. WebSocket clients can
authenticate in the handshake Authorization header. Browsers instead send
`{"access_token":"<token>","description":"...","project_name":"..."}` as the
first message within five seconds. That message is limited to 32,768 characters
and the token to 16,384 ASCII characters; the server removes the token before
analysis. Conflicting header/body credentials are rejected. Configure the server's
WebSocket frame limit as well (for example, Uvicorn `--ws-max-size 65536`); the
application's check happens after a frame has been received. Never put tokens in
URL queries; `token` and `access_token` query parameters are explicitly rejected.
Configured clients cannot run analysis before authentication. Legacy local access
may omit the token only when normal loopback and configuration checks pass.
`/health` returns public liveness/version only. Admin metrics and model training
require installation admin, plus the legacy `ADMIN_API_TOKEN` header if configured.

Automatic comparisons by project name are disabled on every legacy analysis
transport. Explicit saved revisions are the supported comparison boundary.
Analysis cache keys include verified identity and grants. Feedback approval uses
the verified actor, not a submitted reviewer name.

## Limits and release checks

- These are application-level guards over a shared SQLite database, not separate
  tenant databases, encryption keys or operating-system identities. Shared
  questionnaires/KB/model artifacts and training feedback are installation-wide.
- Legacy unscoped identities deliberately retain installation-wide access. Migrate
  every such token and disable local fallback before claiming product isolation.
- Main text/IaC/code routes analyze the submitted content; they do not infer product
  ownership from a project name and do not read another user's previous result.
- Guard portfolio totals, jobs, background retries, integrations, ticket callbacks
  and new routers explicitly. A background service account must not authorize a job
  merely because its worker role is admin; bind and recheck the submitting identity.
- Apply permissions in the same trusted operation as mutation when adding mutable
  ownership. Current workspace product/release ownership cannot be moved in place.
- Configure TLS, allowed browser origins, trusted proxy boundaries, worker resource
  limits, secrets management, backup/restore, audit retention and database access.
  The module does not provide SCIM, MFA enrollment, session management or IdP setup.
- Run the local isolation suite and review every route before deployment. Real IdP
  rotation, organization policy, browser login and production load still require
  integration testing; passing synthetic tests is not an independent security audit.

Validation command: `node scripts/run-backend-python.mjs -m pytest tests/test_workspace_access.py -q`.
The JWT verification API follows the [PyJWT documentation](https://pyjwt.readthedocs.io/en/latest/api.html).
