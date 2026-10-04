# Model-as-code, interchange and cloud drift

This workstream adds an offline CLI and service functions. It does not start the
web server, modify an assessment, run AI, execute IaC, or access AWS unless the
operator explicitly runs `discover-aws --allow-network`.

## Setup

Use the application's Python environment. Native validation, gates and offline
drift use existing dependencies. External interchange additionally requires
`jsonschema>=4.23,<5` (now declared in the base requirements). Live discovery
optionally requires `boto3>=1.35,<2`, declared in `backend/requirements-cloud.txt`.

From the repository root:

```powershell
node scripts/run-backend-python.mjs -m pip install "jsonschema>=4.23,<5"
node scripts/run-backend-python.mjs tools/aegis_cli.py --help
```

The wrapper runs with `backend` as its working directory. Use absolute input/output
paths or paths relative to that directory. Direct invocation also works:
`python backend/tools/aegis_cli.py --help` (paths then use your current directory).

## Model document

Keep model files in Git alongside the application. Give models and elements stable
IDs; do not use a display name as a resource identity. Native architecture objects
and backend `AnalysisResult` JSON reports are accepted. A normalized document is:

```json
{
  "schema_version": "aegis-model/1",
  "model_id": "orders-service",
  "project_name": "Orders",
  "architecture": {
    "components": [
      {"id": "client", "name": "Web client", "type": "External Entity", "trust_level": "unknown"},
      {"id": "orders", "name": "Orders API", "type": "API", "trust_level": "internal"}
    ],
    "flows": [
      {"id": "submit-order", "flow_number": "F-001", "source_id": "client", "target_id": "orders", "protocol": "HTTPS"}
    ],
    "trust_boundaries": [
      {"id": "application", "name": "Application", "boundary_type": "network", "components": ["orders"]}
    ]
  },
  "threats": []
}
```

Validation rejects duplicate IDs/numbers, dangling references, containment cycles,
unknown native architecture fields and invalid field types. Missing flow IDs are
content-derived; missing numbers are allocated deterministically. Identical
parallel flows without distinct IDs are rejected, not merged. Legacy finding
references such as `API -> DB` resolve only when the referenced flow is unique.
The original labels are retained in the finding explanation.

Inputs are bounded to 8 MiB, 50 levels and 5,000 elements per collection. JSON
duplicate keys, non-finite numbers, executable YAML tags, aliases and merge
references are rejected. Input text, URLs and custom attributes are never executed
or fetched. Output keys are sorted; supplied timestamps remain supplied timestamps.
Native validation deliberately does not invoke canonical enrichment: it must not
turn imported claims into newly inferred evidence.

## CLI commands and CI

```sh
python backend/tools/aegis_cli.py validate models/orders.json
python backend/tools/aegis_cli.py compare models/before.json models/after.json --out comparison.json
python backend/tools/aegis_cli.py compare models/before.json models/after.json --fail-on-change
python backend/tools/aegis_cli.py gate reports/orders.json --fail-severity High
python backend/tools/aegis_cli.py import source.otm.json --format otm --out models/orders.json
python backend/tools/aegis_cli.py import source.td.json --format threat-dragon --diagram-id 0 --out models/orders.json
python backend/tools/aegis_cli.py export models/orders.json --format threat-dragon --out orders.td.json
```

`compare` uses the existing comparison engine, including explicit component mapping
via `--mappings mapping.json` (`{"old-id":"new-id"}`). It includes source hashes,
model IDs and engine/knowledge provenance. A missing finding is **no longer
reported**, never verified fixed. Comparison is of supplied evidence, not runtime
behavior. Review suggested identity matches before accepting design changes.

`gate` evaluates a previously analyzed backend report. It fails on missing quality
gate/knowledge digest, blocked integrity, unresolved review requirements, unknown
severity, confirmed findings without evidence, and findings at/above the threshold.
The default includes all tiers. `--tier Confirmed` or `--allow-review` are explicit,
recorded policy changes, not default bypasses. A generic `closed`, `Mitigated` or
`verified_fixed` label alone does not suppress a risk. A model with zero findings
and no analysis does not pass. This CLI does not perform a new threat analysis.

The gate trusts the supplied report's provenance fields; it does not authenticate
them. Generate reports in a trusted job, pin engine/KB versions, use protected
reviewed baselines, and restrict who can change gate policy or artifacts. Do not
give an untrusted pull-request job production credentials. A passing gate is not
security sign-off or evidence of complete STRIDE coverage.

Example offline CI job (Python/dependencies preinstalled in a pinned runner image):

```yaml
steps:
  - run: python backend/tools/aegis_cli.py validate models/orders.json
  - run: python backend/tools/aegis_cli.py compare models/approved.json models/orders.json --out comparison.json
  - run: python backend/tools/aegis_cli.py gate reports/orders.json --out gate.json
```

Archive `comparison.json` and `gate.json` even on policy failure; require a reviewer
for architecture changes. No credentials or network are needed by these commands.

| Exit | Meaning |
| --- | --- |
| 0 | Command completed and requested policy passed |
| 2 | Invalid/unsupported input, ambiguous references or invalid arguments |
| 3 | Gate failure, disallowed conversion warnings, partial discovery/drift coverage, or changes with `--fail-on-change` |
| 4 | I/O, runtime or optional dependency unavailable |

Without `--out`, stdout is JSON. Conversion warnings and errors are JSON on stderr.
With `--out`, the document is published atomically and stdout identifies the file
and content hash. Existing outputs need `--force`; an input file cannot be
overwritten, even with that flag. A failed gate still writes its result. Conversion
with `--fail-on-loss` refuses to publish if there are conversion warnings.

## External format support

Official schemas are checked into `backend/app/services/schemas/` so validation is
offline and the JSON can be audited directly. `manifest.json` records each upstream
commit, source URL, Apache-2.0 attribution and the SHA-256 of the vendored bytes:

- [OTM 0.2.0 schema](https://github.com/iriusrisk/OpenThreatModel/blob/c88c5a7b4115f0f025e28d5682a2b0d790b389e4/otm_schema.json), pinned to commit `c88c5a7b4115f0f025e28d5682a2b0d790b389e4`.
- [Threat Dragon v2 schema](https://github.com/OWASP/threat-dragon/blob/1753ad0fae42d65c56e754fa8faf8fb57179f9f5/td.vue/src/assets/schema/threat-dragon-v2.schema.json), pinned to commit `1753ad0fae42d65c56e754fa8faf8fb57179f9f5`.

The `pathlib`/JSON loader verifies file hashes, caches the validated bundle and
rejects remote `$ref`, `$dynamicRef` and `$recursiveRef` targets. A missing file,
changed checksum or invalid manifest fails closed. Schema identity URLs do not
cause network requests. Commit the two schemas and manifest together; changing a
pin requires review, an updated byte hash and rerunning the interchange tests.
The directory's `.gitattributes` preserves LF bytes on Windows as well as Linux.
Restart the process after changing a schema bundle; it is cached within a process.

These Apache-2.0 schemas are unchanged except JSON whitespace/escaping. Validation
uses Draft 7. Threat Dragon's `nullable: true` style annotations are honored because
its official example uses null for those values; other types are not relaxed.
The validation dialect and source hash are included in import provenance.

**Supported:** OTM components, parent zones, directed/bidirectional flows and scoped
threat references; Threat Dragon 2.x process/actor/store/flow cells, one explicitly
selected diagram, bidirectional flows, explicit boundary children/parents and
cell threats. Bidirectional flows become two traceable directed flows. Unknown
shapes, coordinate-only flow endpoints, missing references and unsupported format
versions are rejected. Multiple diagrams are never silently combined.

**Deliberate limitations:**

- Imports retain the entire original document in `extensions.interchange_source`.
  Numeric asset/risk/trust ratings, custom attributes, styling and source mitigation
  states are not automatically interpreted as executable Aegis controls.
- Imported threats are pending review and not deployment-confirmed. OTM numeric
  risk has no approved qualitative mapping, so imported severity is `Unknown`.
- Diagram geometry alone never establishes trust-boundary membership. Boundary
  curves and uncertain containment produce review warnings.
- External exports retain the complete native model in an Aegis-specific extension.
  A foreign tool may discard it. Re-import uses actual standard fields, never a
  hidden embedded model that might contradict a user's subsequent diagram edits.
- OTM exports preserve single-parent zone membership. Overlapping membership is
  reported and retained in the extension. OTM's required numeric trust rating is
  emitted as an explicitly unknown placeholder `0`, not a measured rating; strict
  callers can reject this with `--fail-on-loss`. Native findings/assets remain in
  the extension rather than inventing required numeric risk values.
- Threat Dragon exports provide a basic grid layout with component/flow threats.
  Boundaries and unscoped findings remain in the extension with warnings. Review
  that diagram before using it in a foreign tool. Review states are not converted
  to verified closure. Multi-component threats can appear on multiple cells.

This is validated, bounded interchange, **not lossless cross-tool round-tripping**.
All external conversions produce warnings. Native `aegis` import/export preserves
the report and is the preferred Git/CI format.

## Read-only cloud drift

Offline usage:

```sh
python backend/tools/aegis_cli.py drift approved.snapshot.json observed.snapshot.json --fail-on-change --out drift.json
python backend/tools/aegis_cli.py snapshot-model observed.snapshot.json --out inventory-model.json
```

Snapshots use `aegis-cloud-snapshot/1`, `provider: aws`, explicit `account_id`,
`region`, timezone-aware `observed_at`, per-service coverage (`complete`, `partial`,
`not_requested`) and resources with `id` (ARN), `service`, `type`, `properties`.
S3 ARNs lack account/region; S3 rows therefore require separate `account_id` and
`region` bindings. Hashes, timestamps and collector operations support traceability.

An approved Aegis model can replace the baseline snapshot. Set
`architecture.metadata.cloud_scope` to
`{"provider":"aws","account_id":"123456789012","region":"us-east-1"}`.
Bind each component with `properties.arn` and explicitly declare assertions under
`properties.cloud_expected`, for example `{"metadata_HttpTokens":"required"}`.
S3 bindings also require `properties.account_id` and `properties.region`.
No fuzzy resource-name matching or cross-account comparisons are performed.

Drift distinguishes `changed`, `unchanged`, `unknown`, `newly_observed` and
`not_observed`. Missing fields do not become false controls; missing resources
never prove deletion or remediation, even after a complete listing. Old snapshots
cannot be compared as newer observations. Inventory-only models have **no invented
flows or public trust level**. Freshness policy beyond timestamp order remains an
organizational decision; drift does not claim the snapshot is current at execution.

### Optional AWS collection

No real AWS account was accessed during development or tests. An authorized
operator can install the optional SDK and run:

```sh
python backend/tools/aegis_cli.py discover-aws --allow-network --profile aegis-readonly --account-id 123456789012 --region us-east-1 --services ec2 rds lambda s3 --max-resources 500 --max-requests 50 --timeout-seconds 120 --out observed.snapshot.json
```

STS verifies the expected account **before** resource enumeration. The collector
uses only allowlisted read calls. SDK retries are limited to one attempt, socket
timeouts are bounded, and total request/resource/time budgets are enforced.
The deadline is checked between requests; an in-flight SDK call can exceed it by
its socket timeout. SDK credential-provider initialization is outside this budget;
use pre-established authorized credentials for scheduled collection.

Relevant permissions (scope them to the approved account/resources where supported):
`sts:GetCallerIdentity`, `ec2:DescribeInstances`, `rds:DescribeDBInstances`,
`lambda:ListFunctions`, `s3:ListAllMyBuckets`, `s3:GetBucketLocation`,
`s3:GetBucketPublicAccessBlock`, `s3:GetAccountPublicAccessBlock`,
`s3:GetBucketPolicyStatus`, `s3:GetEncryptionConfiguration`.
The SDK honors its normal credential chain. No endpoint URL is accepted and
configured endpoint overrides are ignored. No objects, secrets, environment
variables, object URLs or policy bodies are retained.

S3 general-purpose bucket listing is account-owned and paginated. Owner-checked `GetBucketLocation`
confirms inclusion in the requested region; unknown ownership/location excludes
the bucket and marks coverage partial. `null` location maps to `us-east-1`, `EU`
to `eu-west-1`, following the [AWS location contract](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_location.html).
Account and bucket public-access blocks, bucket policy-public status and default
encryption are **separate observations**. Policy-public status does not prove
effective public access, and unreadable/absent encryption state is not a missing
encryption finding. The collector does not infer S3 provider defaults from absence.

Not covered: IAM/KMS effective permissions, SCP/RCP/session policies, S3 directory
buckets, bucket ACLs or access points, route reachability, WAF evaluation, Azure/GCP,
exploit tests, or
automatic reassessment. These limitations are carried in collector provenance.
Access denial and budget exhaustion retain partial evidence and fail CI coverage
checks rather than returning an apparently clean empty inventory.

## Integration contracts

All functions raise `ModelError` for invalid/unsupported data. Optional dependency
or collection initialization failures use `RuntimeError`; file I/O uses `OSError`.
Functions operate on copies and do not write the database.

| Function | Result |
| --- | --- |
| `validate_model(document)` | Normalized `aegis-model/1` dict |
| `import_model(document, format_name, *, diagram_id=None)` | `{model, warnings, provenance?}` |
| `export_model(document, format_name)` | `{document, warnings, schema?}` |
| `validate_snapshot(document)` | Validated scoped snapshot dict |
| `snapshot_to_model(document)` | Inventory-only Aegis model |
| `compare_drift(baseline, observed)` | Versioned drift result with summary, per-resource changes, hashes, scope and coverage |
| `discover_aws(*, account_id, region, services, profile=None, max_resources=500, max_requests=20, timeout_seconds=60)` | Scoped snapshot; explicit read-only live operation |
| `gate_model(document, *, fail_severity="High", tier="all", allow_review=False)` | `{passed, failures, policy, model_id, model_sha256, notice, schema_version}` |

The parent integration now mounts stateless authenticated routes under
`/enterprise/model-tools`: POST `/validate`, `/import`, `/export`,
`/cloud-snapshot/model` and `/cloud-snapshot/compare`. They require an editor role,
operate only on supplied documents and never read stored products or call AWS.
Requests are size/time bounded; duplicate JSON keys and non-finite constants are
rejected. Conversion warnings remain visible, successful responses use `no-store`,
and missing tool dependencies return 503 rather than an unhandled 500. Partial
drift results retain HTTP 200 with explicit coverage state; clients must inspect
coverage and must not treat that as successful complete collection.

Integration still needed: product/release authorization when attaching a result,
import-warning confirmation, source-evidence attachment, immutable snapshot
storage/retention, scheduled collection with approved read-only identities, and
a UI drift review before any new model revision or reanalysis. There is no live
discovery endpoint. This workstream did not edit `main.py` or dependency files.

## Verification

```powershell
node scripts/run-backend-python.mjs -m pytest tests/test_model_interchange.py tests/test_cloud_drift.py tests/test_aegis_cli.py -q
node scripts/run-backend-python.mjs -m pytest tests/test_model_tools_api.py -q
```

Tests cover positive and negative schema/graph cases, deterministic CLI output,
unsafe/duplicate YAML and JSON, conversion-loss refusal, atomic output protection,
gate failures, ambiguous legacy flow labels, account isolation, read-only operation
sets, pagination, permission failures, budgets, secret exclusion and S3 scope/control
semantics. Cloud tests use fake clients only. The pinned upstream OTM and Threat
Dragon examples were also imported successfully during development; this is not
certification of every third-party application or format feature.

At completion, 102 combined tests passed, including vendored-schema integrity and
17 endpoint tests. A fresh local fast-mode analyzer report
(3 components, 9 findings) also normalized successfully, including legacy asset
flow labels. Endpoint checks cover authentication, conversion, drift, malformed
requests, body limits, role checks, dependency errors and the parent app's mounted
router without starting its database/analyzer lifecycle. Live AWS discovery was
not run. The test run emitted one existing Starlette/httpx deprecation warning.
