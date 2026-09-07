# Prompt, document and diagram correlation

Architecture review and analysis use the same canonical model. The diagram is a
view of that model, not a new source of architectural evidence.

## Evidence contract

Each extracted control claim records its component, original statement, source
ID, filename, page/table and line when available. It also retains document
revision, deployment release, environment, endpoint scope and declared state.
Statements remain unverified against a deployment.

Missing information stays unknown. Compatible statements from another source can
fill a gap in the prompt. Contradictory present/absent claims stay conflicting;
planned controls do not count as implemented protection. Endpoint-specific and
restricted-workflow controls do not silently protect the entire component.
Environment and deployment-release claims require matching model scope.

Aliases map different names to a component without merging ambiguous services.
The existing parser aliases are supplemented by explicit reviewer aliases.
Unassigned statements remain visible in Sources. Extracted node and flow evidence
is retained separately from assumptions, including unknown flow protocols.

`document_version` means the source document revision; `deployment_version`
means the modeled release. Both fields survive reconciliation. Model environment
and deployment release can be set in Sources independently of each file's scope.

## Review and reports

Click a component or flow in the review diagram, or a component's evidence icon,
to inspect its sources. The inspector lists resolved control states, individual
claims and their scope, and links back to editable source text. Correct or exclude
an outdated source in place; both the diagram and review update automatically.
Conflicting reviewer answers do not silently erase source evidence.

Risk details expose correlated control evidence alongside the existing finding
evidence. Related findings shown during draft review are explicitly from the last
report, not a fresh analysis of unsaved changes.

New clarification answers use per-target/control evidence digests. Relevant
control changes, scope changes and incident-flow changes require revalidation;
unrelated component additions do not. Older saved answers retain the conservative
whole-draft digest behavior until answered again.
An answer that explicitly cites a file also records its digest; replacing that
file requires revalidation even when no newly extracted control matches it.

## Efficiency and limits

The preview parser has an isolated, bounded in-memory cache (16 entries, 8 MB).
Edits reuse unchanged source parsing; each caller receives a deep copy. Claim
extraction is cached separately for short source bodies, so changing another file
does not repeat that extraction. Large bodies bypass the claim cache to limit
retention. Cache entries are process-local and are not written to disk.

Canonical validation still checks the whole model. Full threat analysis remains
an explicit action, not a background action on every edit. This does not implement
partial threat-result reuse or infer topology from images. OCR-derived diagram
labels are not evidence of connectors; unreadable diagrams still require review.
Free-text scope and aliases are deterministic and bounded by the parser vocabulary,
not a guarantee of understanding every possible architecture description.

## Regression checks

- `backend/tests/test_claim_correlation.py`: complementary sources, contradictions,
  planned controls, endpoint and environment scope, release versions, aliases,
  IaC conflicts, repeated passages, cache isolation and answer dependencies.
- `scripts/verify-source-correlation.mjs`: document upload, evidence inspection,
  clickable diagram elements, source navigation, conflict exclusion and mobile UI.
- Existing model-review, source-provenance, evaluation corpus and mixed-IaC tests
  remain part of validation.

Verified on 2026-09-07: 1,218 backend tests and six frontend workspace tests passed.
The source-correlation, standard review, mixed-IaC and live-update browser suites
passed, including light/dark and mobile checks. Lint and the production build
passed; the existing bundle-size and Browserslist warnings remain.
