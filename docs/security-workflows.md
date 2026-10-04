# Organizational security workflows

This service adds versioned organizational patterns, collaborative risk review,
and an opt-in Jira synchronization queue. It uses the existing ProductStore
SQLite database. It does not rerun analysis, rewrite published reports, prove a
control is deployed, or treat a resolved ticket as a verified fix.

## Application integration

After `start_enterprise(app)` has initialized ProductStore and AssessmentStore:

```python
from app.services.security_workflow_api import start_security_workflows, router

start_security_workflows(app)
app.include_router(router)
```

The routes resolve `enterprise_api.principal` at request time. VerifiedIdentity
is authorized with `workspace_access.require_product` and `require_resource`.
A global administrator with only editor access to a product cannot publish its
patterns, accept its risks, mark its findings false positive/verified fixed, or
dispatch its queue. Workspace membership is also checked inside the service.

Nonstandard authentication can supply an access callback to startup. Its keyword
arguments are `store`, `identity`, `product_id`, `workspace_id`, and `write`;
it must return exactly `True` or raise HTTPException. Missing policy fails closed
for non-VerifiedIdentity authenticated users. Only the existing unconfigured
loopback local-admin mode is permitted without a policy. Do not use arbitrary
plain identity dictionaries as a production authentication mechanism.

### Existing register and dashboard integration

Risk review and expiration writes append a canonical `finding_review_events`
record **inside the same SQLite transaction** as the workflow state and audit
event. Canonical records include owner, target date, remarks, status, acceptance
expiry, and passing verification references. The original report is unchanged.
When the canonical review table is unavailable, the service can be tested in
isolation, but production must initialize AssessmentStore first.

For immediate expiry, the parent application must integrate these read helpers:

```python
# product_dashboard._load: after loading canonical review rows, before _build
from app.services.security_workflows import workflow_review_overlays
reviews.update(workflow_review_overlays(db, product_id))

# AssessmentStore.reviews or its response mapper: effective view, not history
from app.services.security_workflows import effective_workflow_review
if decision.get('security_workflow'):
    decision = effective_workflow_review(decision)
```

The dashboard overlay keys are `(report_id, finding_id)` and values match its
existing review-row format. A synthetic read ID includes effective status and
overdue state, invalidating pagination/export fingerprints when time changes a
decision. `canonical_version` retains the integer event ID for optimistic
locking. Do not send the synthetic dashboard ID as an assessment review version.
Expose `acceptance_expired` and `overdue` from the projected body in dashboard
rows and counts. Keep historical event bodies unchanged.

`POST /risks/expire-acceptances` persists up to 100 expired acceptances as pending
review, retaining owner, previous expiry and audit history. It is idempotent and
skips decisions superseded by a newer canonical review. Schedule it using the
application's existing worker if persisted transition notifications are needed;
read-time reopening does not depend on that worker.

The canonical and workflow version checks prevent a review through an older UI
from silently being overwritten. On a 409, reload. The risk GET returns both
`review.version` and `review.canonical_version`; send them back as
`expected_version` and `expected_canonical_version`. If a legacy register has a
newer decision, `superseded_by_risk_register` is true and its current decision is
returned as the body. Comments have the same optimistic-lock contract.

The four files in this change do not install the router, change dashboard
readers, add UI, or modify the existing assessment API. Those are parent
integration points, not claims that these screens are already connected.

## Patterns

Patterns have product-local unique names and immutable content versions. A
version has an accountable owner, an expiry within 366 days, explicit component
types, controls, statements and evidence references. Creating a newer version
does not silently change existing bindings. An administrator publishes or
retires each version; content changes require a new version. All transitions
are version checked and audited.

Applicability is exact for product, application and environment. A null
application means the full-release assessment, not every application. A null
release allows deliberate reuse across releases within the same product,
application and environment. A specific release ID restricts it to that release.
Component IDs must exist in the authoritative assessment and their types must
match the approved list.

Inheritance pins the pattern version and report hash. It produces supporting
evidence with `declared_state`, `observed_state`, component/scope identifiers,
owner and source references. Every claim remains `requires_validation` and
`suppresses_finding: false`. Contradictory architecture controls are surfaced as
`conflicting`; no component property or finding is overwritten. Retired or
expired patterns immediately mark their inherited evidence stale. A reviewer
must validate applicability before any later analysis consumes that evidence.

Base URL: `/enterprise/products/{product_id}/security-workflows`.
Paginated GETs accept `offset=0&limit=50` (maximum 100) and return
`{items, next_offset}`.

| Method | Relative path | Input / result |
| --- | --- | --- |
| GET | `/patterns` | All versions, newest version first per name; includes `expired` |
| POST | `/patterns` | PatternInput; returns `pattern_id`, `version`, `revision`, `status`, `body` |
| POST | `/patterns/{id}/versions` | PatternInput with `expected_version` equal to latest version |
| POST | `/patterns/{id}/versions/{version}/transition` | `{status: published or retired, expected_revision, reason}` |
| GET | `/workspaces/{id}/revisions/{n}/pattern-evidence` | Pinned claims with current `stale` and pattern status |
| POST | `/workspaces/{id}/revisions/{n}/pattern-evidence` | `{pattern_id, pattern_version, component_ids, reason}` |

Example PatternInput, using real IDs from this product:

```json
{
  "name": "Corporate API authentication",
  "owner": "Identity platform team",
  "description": "Managed identity controls for the customer API",
  "application_id": "application-id",
  "release_id": null,
  "environment": "production",
  "component_types": ["API"],
  "controls": [{
    "control": "mfa_enabled",
    "state": "present",
    "statement": "MFA is enforced by the identity provider for privileged users.",
    "source_references": ["identity-policy/revision-3"]
  }],
  "expires_at": "2027-01-01T00:00:00Z",
  "expected_version": 0
}
```

Control states are `present`, `absent`, `partial`, `planned` or `unknown`.
Properties use their exact engine names. Evidence references are stored as text
and are never fetched as URLs. Owners are accountable names/team identifiers;
there is no claim of directory membership validation or notification delivery.

## Risk review

Let `S = /workspaces/{workspace_id}/revisions/{revision}`.

| Method | Relative path | Input / result |
| --- | --- | --- |
| GET | `S/risks` | `{items: [{finding, review}], total, report_id, next_offset}`; includes unreviewed findings |
| PUT | `S/risks/{finding_id}` | RiskReview; returns saved review with version/effective state |
| POST | `S/risks/{finding_id}/comments` | `{expected_version, expected_canonical_version?, comment}` |
| GET | `S/risks/{finding_id}/events` | Paginated, newest-first audit history |
| POST | `/risks/expire-acceptances` | No body; admin-only batch of persisted expiry transitions |

Supported states are `pending_review`, `in_review`, `action_required`,
`mitigation_proposed`, `accepted`, `false_positive`, and `verified_fixed`.
Any state beyond pending review needs an owner. Remarks are required. Due dates
are timezone-aware; overdue is computed rather than manually assigned.

Accepted risk needs product-admin approval and a future acceptance expiry no
more than 366 days away. It is not a verified fix. After expiry its effective
state is pending review. Verified fixed needs product-admin approval,
acceptance criteria and passing verification evidence. Each verification entry
has `{method, reference, result, checked_at}`. Methods are `test`,
`configuration_review`, `code_review`, `independent_report`; results are
`passed`, `failed`, `inconclusive`. Evidence is reviewer-attested, not a claim
that Aegis ran the referenced test. Closed decisions must be reopened before
another terminal decision is made.

```json
{
  "expected_version": 0,
  "expected_canonical_version": 0,
  "status": "in_review",
  "owner": "Payments team",
  "remarks": "Check object-level authorization on invoice download.",
  "target_date": "2026-11-01T17:00:00Z",
  "acceptance_expires_at": null,
  "acceptance_criteria": ["Cross-account invoice access is rejected."],
  "verification": []
}
```

Inputs cannot introduce findings: the service follows the published revision's
assessment ID into the server-owned assessment result, verifies its workspace
and product, then locates exactly one matching finding. Missing/duplicate IDs,
forged client snapshots and cross-workspace reports are rejected.

## Jira synchronization

Jira configuration and credentials are server-only. No route accepts a URL,
project override, token or HTTP headers. `AEGIS_JIRA_CONNECTIONS` is an object:

```json
{
  "corporate": {
    "base_url": "https://company.atlassian.net",
    "project_key": "SEC",
    "product_ids": ["approved-product-id"],
    "username_env": "AEGIS_JIRA_USER",
    "token_env": "AEGIS_JIRA_TOKEN"
  }
}
```

Set the referenced environment variables through the server's secret manager.
They are not persisted in the workspace database or returned by API responses.
Credential rotation is allowed. Changing the origin, project or product scope
invalidates existing links; reconcile under a newly reviewed connector alias
instead of silently sending them to another destination.

| Method | Relative path | Input / result |
| --- | --- | --- |
| GET | `S/risks/{finding_id}/tickets` | Existing links and last observed remote status |
| POST | `S/risks/{finding_id}/tickets` | `{connection, issue_key}`; idempotent link plus initial pull job |
| POST | `/tickets/{link_id}/sync` | `{operation: pull or push, idempotency_key}` |
| GET | `/outbox` | Admin-only paginated job states, attempt counts and safe errors |
| POST | `/outbox/dispatch` | Admin-only `{limit: 1..10}`; also requires server opt-in |

`AEGIS_JIRA_SYNC_ENABLED=true` is required for the HTTP dispatch route. Startup
and link creation do not make remote calls. An operator may instead invoke
`SecurityWorkflows.dispatch` in a worker after explicit deployment opt-in.
No remote Jira calls were performed during implementation or tests.

The adapter validates the issue key/project by reading the existing Jira issue.
A push replaces only the `com.aegis.threat-model` issue property with a bounded
summary of the explicit Aegis review. It does not create tickets, overwrite
human descriptions/comments, change assignees, transition workflow status, or
close risks. The issue property is machine-readable metadata, not a visible
Jira panel unless the organization separately configures one. The Jira account
needs read permission and, for push, permission to edit issue properties.
See the official [issue API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/)
and [issue-property API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-properties/).

Links are product-authorized, one issue per risk/connector and one risk per
connector/issue. A risk must first be assigned/reviewed. A push requires a
successfully verified link. The queue never uploads architecture documents,
credentials, original prompts or raw evidence attachments. Exported remarks may
still be sensitive; operator opt-in and Jira access permissions remain required.

Retries are bounded to five attempts with backoff and bounded Retry-After.
Job leases allow recovery after worker failure. The same property replacement
can safely be retried after an uncertain response; this is at-least-once
delivery, not a claim of exactly-once transport. Reusing an idempotency key for
different content is a conflict. A changed review or expired acceptance makes
an older queued push superseded. Permanent failure needs explicit requeue with
a new idempotency key after fixing the cause.

The HTTP transport validates all DNS results as public, pins a validated IP
while retaining TLS hostname checks, disables redirects/proxy inheritance and
implicit HTTP retries, uses timeouts, rejects compressed replies, and bounds
responses to 256 KB and writes to 24 KB. Private Jira installations are not
supported by this adapter; do not weaken the public-address rule to enable
them. Operator-defined private egress would need a separate reviewed transport.

## Verification

```powershell
node scripts/run-backend-python.mjs -m pytest tests/test_security_workflows.py -q
```

The tests use temporary databases and fake HTTP responses. They cover pattern
versions/scope/expiry/conflicts, authoritative finding lookup, concurrent review
writes, canonical event mirroring and register/dashboard overlays, role scopes,
expiring acceptance, evidence-gated closure, ticket deduplication, stale exports,
lease recovery, retry limits, HTTP contracts and SSRF defenses. Deployment still
needs end-to-end authorization tests against organizational identities and an
approved Jira sandbox before enabling network dispatch.
