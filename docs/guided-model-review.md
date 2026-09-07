# Guided model review

An analysis is now a saved workspace with a draft and report revisions. The
review stage uses the existing parser and STRIDE control assessment. It does not
run a separate threat engine or publish findings before analysis.

## Working with a model

1. Enter the architecture or upload files, then open the review draft.
2. Check the architecture table and diagram. Correct component types, trust and
   data classification; edit flow endpoints, protocol and data; confirm or exclude
   assumed connections. New components and flows can be added here.
3. Answer the priority clarifications. Each answer is scoped to its component or
   flow and records an explanation, reviewer and optional supporting source.
   Unknown is a valid answer. A proposed scope exception does not suppress a rule.
4. The tables and diagram update automatically after changes. Once the preview
   finishes updating, analyze the reviewed model.
5. Use Update this model to add context or replace sources. Successful runs append
   report revisions; failed requests keep the last report and current draft.

Adding or removing a component or flow starts a preview update immediately.
Typing is debounced, and superseded responses cannot overwrite newer edits.
Preview updates do not run the full threat analysis or reset diagram zoom.
If preparation fails, the draft and previous diagram remain available with a
retry action. Analysis stays disabled until the preview matches the current draft.

The Sources tab retains extracted text, file diagnostics, environment and version.
IaC reviews accept related Terraform, Bicep, Pulumi, YAML and JSON sources alongside
prose or extracted document context. IaC code is parsed, not executed. The format
selector applies to a single pasted or uploaded source; mixed projects detect
formats per file. Removing a resource excludes its attached source findings from
the active report and retains them under review exclusions. Findings about a whole
configuration file remain in scope while that file is included.

## Revisions and evidence

Changing relevant source claims, target scope or incident flows invalidates new
clarification answers. Unrelated additions do not. Older saved answers without
per-control evidence digests retain whole-draft invalidation until answered again.
Invalidated answers remain recorded but must be confirmed again before being applied.
Conflicting control claims remain visible. A claimed encrypted protocol cannot
silently erase a stated HTTP or WS connection; correct the source or flow explicitly.
Flow encryption continues to be derived from the protocol by the coverage engine.
The diagram and component evidence icons open source-level control evidence.
See [source correlation](source-correlation.md) for scope, versions and limits.

Reviewer decisions and notes belong to a report revision. Changed findings reopen
for review in the next revision, and a returning finding cannot silently inherit
an old false-positive decision. Earlier reports and their annotations remain
available. A finding that disappears is labelled "no longer reported", not a
verified fix.

PDF confirmed and potential counts exclude findings marked false positive. The
excluded findings remain in their own section with their review status. Accepted
and mitigated findings keep their evidence classification; their disposition is
shown and they are omitted from the priority actions. The security score remains
the original engine score, which the export states when exclusions apply.

## Storage and limits

Workspaces use IndexedDB in the current browser profile. Original PDF and DOCX
binaries are not archived; extracted text and diagnostics are. Reviewer
annotations use the existing local annotation store, keyed by workspace and
revision. Export workspace includes sources, revisions and current annotations in
a JSON archive. There is no workspace import or cross-device synchronization yet.
Clearing browser storage removes local workspaces.

Older reports can be opened as saved model snapshots when their original inputs
are unavailable. The Sources tab can rebuild from newly supplied sources when a
fresh model is required. The old report revision is preserved.

Preview completeness is not a security score. Owner statements are not runtime
verification, and document parsing and question selection remain bounded by the
existing parser, coverage contracts and knowledge base. The copilot can populate
a proposed update for review; the user adds it to the draft explicitly.

## Verification

The completion run on 2026-09-05 passed all 919 backend tests, including PDF/YAML
ingestion, mixed IaC context, scoped answers, source conflicts, endpoint edits,
format hints, duplicate resource identifiers, exclusions and API error handling.
Four frontend revision tests cover preservation, revalidation and returning
findings. The frontend lint and production build also pass.

Browser checks use isolated profiles and keep synthetic reviewer feedback out of
the feedback dataset:

- `scripts/verify-model-review.mjs`: draft recovery, flow corrections, scoped
  answers, PDF export, two revisions, history, failure recovery, dark diagram
  contrast, zoom and mobile overflow.
- `scripts/verify-iac-review.mjs`: pasted Bicep, mixed files and context,
  replacement with preserved source scope, and resource exclusion through analysis.
- `scripts/verify-live-model-review.mjs`: automatic additions, flow edits,
  debounced typing, stale responses, retry recovery, removal and draft persistence.
- `scripts/verify-report-ui.mjs`: legacy report loading, light/dark reports,
  filtering, detail dialogs, diagram controls, PDF export and pagination.

Results and screenshots are in `backend/evaluation_reports/model-review-ui/`,
`iac-review-ui/` and `ui-2026-09-05/`. The reviewed PDF was checked for matching
counts and exclusion status, rendered with Poppler and visually inspected.

The automatic-preview update on 2026-09-07 passed the 24 backend model-review
tests, six frontend workspace tests, and all three review browser scripts
(standard, mixed IaC and live updates). Lint and the production build passed.
Live-update screenshots and results are in
`backend/evaluation_reports/live-review-ui/`.
