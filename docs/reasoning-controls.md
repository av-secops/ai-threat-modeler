# Reasoning Controls and Validation Contracts

This workstream makes the engine more conservative about what submitted input
can establish. It does not test the deployed application or claim complete
vulnerability coverage.

## Implemented

- Control evidence is checked against environment, release, tenant, account,
  region, technology/resource type, and trust boundaries. Missing required scope
  remains unknown. Tenant and boundary identifiers are case-sensitive.
- A WAF declaration cannot establish query parameterization, object authorization,
  or MFA. Control effectiveness requires the same control and applicable scope.
- Planned, partial, contradictory, and wrong-scope evidence cannot confirm a
  missing control. Downgraded findings retain the original threat name with a
  validation prefix, so uncertainty does not erase the attack being considered.
- Source-declared weaknesses and observed control values are different evidence
  types. An exact statement indexed in `stated_weaknesses` or `known_issues` can
  support a finding through the existing `CONTROL_PROPERTIES` vocabulary, without
  fabricating absent control properties. Component, rule, statement and deployment
  scope must match; planned, partial, conflicting or present-control evidence is
  not overridden by this support.
- Internal language models have a Tampering review profile for prompt handling,
  instruction/data separation and output validation. Unspecified controls produce
  Potential validation questions within the existing candidate budget. Ambiguous
  source subjects remain unresolved, and a generic ML classifier is not treated
  as a language model merely because it has AI-scope metadata.
- A path includes per-hop topology, permission and execution-context requirements,
  plus any declared exploit preconditions. A confirmed weakness is not proof of
  exploiting the next component or obtaining its workload identity.
- Explicit, cited evidence contradicting an exploit prerequisite prevents that
  path. Conflicting evidence leaves the prerequisite unresolved.
- Final reports place inferred routes in `attack_chains.hypotheses`, not
  `attack_chains.paths` or its count. Their findings do not retain an attached
  evidence-backed attack path. Explicit paths still mean conditional connectivity,
  not demonstrated access to sensitive data.
- Findings carry machine-readable remediation acceptance criteria, required
  artifacts, component/flow references, deployment scope and a `not_performed`
  status. Unsupported custom controls require an owner-defined acceptance test.
- `engine_status.reasoning_assurance` separates evidence resolution from STRIDE
  category assessment, reports unresolved claims and assumed flows, and returns
  no percentage when there are no applicable cells. It does not estimate recall.

## Policy Reasoning

The IAM evaluator remains deliberately bounded. It evaluates supplied policies,
not AWS runtime permissions. A full, explicitly acknowledged inventory is required
for a static allow/implicit-deny result. Missing request values, unresolved policy
variables, unsupported conditions, malformed policy fields and role/session
semantics produce `unknown`.

Organization policy attachments can be supplied as:

```json
{
  "policy_levels": {
    "scp": [
      {"id": "root", "policies": [{"Statement": []}]},
      {"id": "production-ou", "policies": [{"Statement": []}]},
      {"id": "account", "policies": [{"Statement": []}]}
    ]
  }
}
```

The empty statements above are placeholders, not valid policy evidence. Each level
needs the actual policy documents. Allows union within one attachment level and
intersect across levels; explicit deny wins. Multiple flat SCP/RCP documents with
no level information now abstain instead of inventing their hierarchy. KMS grants,
key policies, STS trust and role/session exceptions require a specialized evaluator.

Primary references:
- [AWS IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS Organizations SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)

Flow `authorization_evidence` must identify a concrete source identity, target
resource, exact required actions and a source reference. Optional `scope` applies
to the target; `source_scope` applies to the source. A cited `policy_query`, when
provided, is evaluated instead of trusting its accompanying decision string.
Neither identity labels nor inferred flows provide authorization evidence.

## Integration

No changes to analyzer, API routes, models or KB files are needed for the current
pipeline: both analysis and report refresh already call `validate_evidence` and
`attach_assurance`. Their existing hooks attach the new contracts and finalize
path counts before report generation.

For other direct consumers:

1. `generate_attack_paths` retains conditional/inferred candidates for compatibility.
   Use `finalize_path_assurance(result)` before publishing or counting those paths.
   `evidence_supported` is about explicit topology, not proven exploitation.
2. Display `explanation.remediation_validation.criteria` in finding details.
   Keep `not_performed` until an authorized reviewer supplies validation results.
3. Display `engine_status.reasoning_assurance.evidence_resolution_percent` as
   evidence resolution, not security coverage or vulnerability recall. A null
   percentage means there is no applicable denominator.
4. If exposing inferred hypotheses, put them in a separate review section and
   retain their inferred-hop labels; do not add them to the attack-path total.

Scope metadata uses exact declared values. Technology aliases and unknown boundary
names are not guessed. An owner must resolve those rather than silently applying
a control from another system.

## UI Metadata Reference

The report schema remains additive. `mapAnalysisResult` already preserves
`engine_status`, `attack_chains`, each finding's `explanation`, and its attached
`attack_path`. No mapper change is required to read these fields. Older saved
reports can lack any of them: show "Not assessed" or omit that section, rather
than replacing missing values with zero or "Passed".

| JSON path | Suggested label | Interpretation |
| --- | --- | --- |
| `engine_status.reasoning_assurance.evidence_resolution_percent` | Evidence resolved | Nullable number. Display an em dash or "Not assessed" for null; do not label it security coverage. |
| `engine_status.reasoning_assurance.unresolved_cells` | Evidence gaps | Modeled STRIDE cells with unresolved controls or potential findings. |
| `engine_status.reasoning_assurance.unresolved_source_claims` | Unmatched statements | Source claims not bound to one modeled subject. |
| `engine_status.reasoning_assurance.conflicting_source_claims` | Conflicting statements | Claims that require reconciliation, not confirmed defects. |
| `engine_status.reasoning_assurance.assumed_flows` | Assumed connections | Connections needing source or owner confirmation. |
| `attack_chains.count` | Modeled paths | Final explicit-topology path count. Still conditional, not demonstrated exploitation. |
| `attack_chains.hypothesis_count` | Paths to review | Inferred candidates, kept separate from modeled paths. |
| `threat.explanation.evidence_validation.status` | Evidence review | `compatible` means compatible with the submitted model; `requires_review` means a scope/evidence problem remains. Neither means runtime verified. |
| `threat.explanation.evidence_validation.source_weakness_support` | Declared weakness | Exact scoped source statements supporting the finding independently of unknown boolean control fields. Not a runtime test. |
| `threat.explanation.remediation_validation.criteria` | How to validate the fix | Read-only acceptance requirements, not test results. |

Use compact status text such as "Matches submitted evidence" and "Needs review".
Do not show a green "Verified" badge based on `compatible`, `effective_for_claim`,
`evidence_supported`, or `supported_by_submitted_evidence`. These represent different
static reasoning checks, not deployed-control effectiveness.

### Finding Details

`evidence_validation.controls` contains one row per affected component/control:

```json
{
  "component": "orders",
  "control": "parameterized_queries",
  "required_control": "parameterized_queries",
  "state": "absent",
  "applicable": true,
  "effective_for_claim": false,
  "basis": "submitted_control_state",
  "runtime_verified": false
}
```

States are `present`, `absent`, `unknown`, or `conflicting`. `applicable` is the
requested-scope match. `effective_for_claim` only matches a declared present
control to the requested control; it is not an exploit test and must not close a
risk automatically. A raw control property can itself represent an unsafe setting,
so do not infer "protected" merely from a property being present.

`source_weakness_support` entries include `component_id`, `rule_id`, `control`,
`scope`, `statement` and `basis: explicit_source_weakness`. Show their statement and
scope as supporting evidence. The corresponding control row can remain `unknown`:
the source establishes a specific weakness, not every remediation control's
configuration. Do not rewrite unknown control fields to false in the UI.

Each remediation criterion has a stable `id`, nullable `control`, `component_ids`,
`flow_refs`, `scope`, `procedure`, `acceptance_condition`, `required_evidence`,
`test_definition_status`, `status`, and `runtime_verified`:

- Render `procedure` and `acceptance_condition` as plain text.
- Link flow references by `id` and display their `number`; never regenerate flow
  numbers from table positions.
- `test_definition_status: defined` means a control-specific procedure exists.
  `owner_definition_required` means the owner must supply a concrete test.
- `status: not_performed` remains unchanged by analysis. Reviewer disposition and
  uploaded test evidence belong to the existing review workflow, not this field.
- The scope includes only supplied deployment dimensions. The `technology` hint
  falls back to component type when an exact technology was not supplied.
- A criterion ID identifies a finding/control/target requirement, not a deployment
  attestation. Always compare its current scope and report revision before reusing
  prior review evidence.

### Path Details

For a displayed modeled path, read `precondition_checks`, not only `steps`:

| Field | Display rule |
| --- | --- |
| `reasoning_status: conditional_route` | "Conditional modeled route" |
| `reasoning_status: inferred_hypothesis` | "Inferred route: review required"; show only in the separate hypotheses section |
| `precondition_checks[].state: supported` | "Supported by submitted evidence" |
| `precondition_checks[].state: unknown` | "Needs evidence" |
| `precondition_checks[].state: contradicted` | "Contradicted by submitted evidence"; such an exploit route is not modeled |
| `permission_status: supported_by_submitted_evidence` | "Permissions documented"; not "Access verified" |
| `permission_status: unresolved` | "Permissions unresolved" |
| `sensitive_data_reached` | "Sensitive-data components on modeled connections"; not "Data compromised" |

Checks have stable per-route `id` values, a `kind`, `requirement`, `state`, and
`runtime_verified: false`, plus applicable component/flow identifiers. Kinds are
`topology`, `authorization`, `execution_context`, `exploit`, and `validation`.
When a route is excluded by a prerequisite, checks are available at
`threat.explanation.precondition_checks` and the reason at
`threat.explanation.attack_path_reason`; `threat.attack_path` may be null.

`hops[].flow_id` locates the flow and `hops[].flow_number` is its display number.
Either can be empty on older reports. `verification_required` lists unresolved
requirements; it is not a list of tests that the engine already ran.

An empty finalized chain retains the existing `{ "paths": [], "count": 0 }`
contract. Optional hypothesis/status metadata is omitted when no paths or
hypotheses survive. Removed findings cannot retain routes in either collection.

### Policy Evaluation Details

`engine_status.policy_evaluations` is a diagnostic list. Each item contains
`component`, `request`, `decision`, `matched_statements`, `limits`, and
`runtime_verified`. Decisions are `allowed_in_supplied_policies`, `implicit_deny`,
`explicit_deny`, or `unknown`. Always retain the `limits` text in the details view.

Malformed `access_queries` are reported as unknown instead of crashing the report.
At most 50 policy requests per component are evaluated. If more are supplied, an
additional unknown diagnostic records `unevaluated_requests`; those requests must
not count as assessed or denied.

### Hook Order and Refresh

Both current analyzer paths use the same order:

1. `validate_evidence` runs after calibration/tier classification and before the
   final coverage assessment and attack-path generation.
2. Final flow references and citations are attached during explanation enrichment.
3. `attach_assurance` finalizes paths, refreshes remediation criteria with those
   final references, and attaches policy/coverage metadata before Markdown export.
4. JSON serialization and history restoration retain these fields. A refresh
   rebuilds the contracts; it does not mark validation procedures completed.

Initial finalization and repeated refresh are regression-tested. No route, schema,
analyzer or shared UI edits were needed for these hooks.

### Shared-Engine Integration Fixes

The scoped contracts do not replace subject resolution. The internal LLM
candidate omission is now fixed in `StrideCoverageEngine`: a modeled language
model's identity enables an AI-specific Tampering profile and question. This
does not reassign ambiguous source declarations, promote unknown controls to
absent, or treat prompt filtering as proof of protection. The existing
`test_ai_ml_deployment` and new unresolved-subject regressions pass.

Parser issue resolution now prefers a literal component or technology alias over
rule-compatible component types. The short canonical name `S3` is recognized;
"The S3 bucket is public and stores customer invoices" maps only to S3, not API
Gateway and DynamoDB. Rule-based scope remains a fallback for statements without
literal matches. These cases are covered in `test_completion_scope_exports.py`.
This does not solve every ambiguous subject: an unmapped declaration still
requires analyst review and must not invent a resource or attack path.

## Efficiency and Verification

Citation normalization/indexing now runs once per document. Claim lookup reuses
that index; the previous repeated normalization of neighboring lines is removed.
The managed-control set is also computed once, not once per component. Extraction
cache entries still contain only immutable text results, never resolved scopes.
Path construction evaluates authorization evidence once per flow per run, rather
than once again for every finding that shares the route. Its cache is discarded
between analyses so changed policies are evaluated again.

The new regression suite is `backend/tests/test_reasoning_contracts_v2.py`. It
covers scope mismatches, WAF non-equivalence, conflicts, unknown controls, IAM
attachment levels, invalid inputs, inferred paths, execution prerequisites,
remediation criteria, empty coverage and citation-index reuse. Existing path,
correlation, control, STRIDE and transport tests are also exercised.

A local synthetic probe of 1,000 lines and 100 claims completed index construction
plus citation lookup in 3.706 ms with all citations correct. This is one local
observation, not end-to-end latency, a production benchmark or an accuracy score.

Independent review of real architectures and deployed-control validation remains
necessary. No external attack, cloud API call or runtime verification is performed
by this workstream.
