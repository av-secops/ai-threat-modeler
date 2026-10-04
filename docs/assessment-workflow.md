# Assessment workflow

This extends the existing product, release and application workspace. It does not
replace saved models or run external security scanners.

## Running an assessment

1. Choose UI, Frontend, Backend, Web application, Mobile application, API or
   service, or Other. Mixed applications can select more than one type. Business
   domain remains separate; older domain selections are preserved.
2. Enter a description, upload documentation, import a permitted document URL,
   or upload a diagram. A document-only assessment does not need a prompt.
3. Review the preliminary inventory. No generated DFD is shown yet.
4. Review grouped questions under **Needs input**, then confirm selected cited
   proposals under **Suggested answers**. Source excerpts supply a rationale for
   confirmed proposals; manual answers need a short explanation. Unknown is valid;
   Partial does not assert complete protection. Only admins can approve Not
   Applicable, and that answer does not disable security detectors.
5. Generate the DFD, then correct components, flows and trust boundaries. Edits
   refresh automatically. Merge duplicate components only with supporting
   evidence; conflicting controls remain visible. Removing a connected component
   asks for confirmation before excluding its flows.
6. Run analysis. Each success saves an immutable governed report; failed runs
   leave earlier reports and the draft intact.
7. Review findings and add Product Architect / Product Team remarks. Use Security
   Reports for external assessment records and their model links.

Source, environment, release, application type and relevant component/control
changes invalidate dependent questionnaire answers. Layout-only changes do not.
The server enforces completion on reviewed REST analysis and background jobs,
not just on the UI button. Existing low-level analysis/streaming endpoints remain
diagnostics and cannot publish a governed report without this workflow.

## Question administration

Administrators can open **Manage questions** from the questionnaire. Clone a
published template, edit its draft, add/remove/reorder questions, then publish a
new version. Assessments keep their original version. Retiring a template stops
new assessments from choosing it; it does not erase old evidence.

Question types are text, number, choice and control state. Applicability uses
application/component types and optional literal technology names, not executable expressions. State-valued control
questions can map to supported component controls. Architecture text responses
are retained as evidence; they are not silently converted into verified topology.
Use the inventory editor to add or correct the stated actors and connections.

## Shorter questionnaires

- Shared controls appear once per compatible trust boundary, environment, account
  and tenant. Select the components to which an answer applies. Each selected
  component still gets its own attributable answer; exceptions stay unanswered.
- Cited control statements and relevant architecture excerpts appear as proposals,
  with their source and line. Nothing is pre-confirmed. Inferred properties, planned
  controls, conflicting claims and endpoint-only controls are not bulk-confirmable.
- High-priority questions appear first. Optional detail is collapsed. **All checks**
  retains the individual forms and **Answered** allows corrections.
- Administrators can set priority and conditional follow-ups to earlier choice or
  control questions. Conditions apply assessment-wide or to the same component.
  Unknown, partial or stale parent answers keep follow-ups visible. An explicit
  non-triggering answer marks the follow-up not triggered, not securely implemented.
- Unknown answers support a short reason and follow-up owner. They do not assert
  that a protective control exists. Mandatory completion and admin-only exceptions
  still apply; reducing visible prompts does not reduce the underlying checks.
- Cloning a server-saved release can propose unchanged questionnaire answers from
  the original assessment as of clone time. These are not confirmations. They retain
  the earlier reviewer, and reconfirmation records the new reviewer. Relevant source,
  control, flow, boundary, application or environment changes reopen affected checks.
  Unrelated assessments and old answers without dependency records cannot be reused.

There is no fixed question cap: a complex system with genuinely different control
scopes may still need many clarifications. Existing drafts may require a one-time
reconfirmation because the dependency checks now include boundary and parent-answer
context. Previous evidence and reports are retained.

Answers retain question wording, template version, source references, dependency
digest, author, role, rationale and timestamp. Authentication uses the existing
installation-wide viewer/editor/admin roles. Configure `AEGIS_WORKSPACE_TOKENS`
for a shared deployment; unconfigured local mode attributes changes to
`local-user`. This is not per-product authorization or enterprise SSO.

## Diagram import and editing

- draw.io XML and a bounded Mermaid flowchart subset preserve explicit connectors.
  Unsupported syntax, undirected lines and ambiguous visual groups produce warnings.
- PNG/JPEG and PDF diagram pages can use an operator-configured, Ollama-compatible
  vision model. Its proposed flows remain assumptions until reviewed. Model output
  cannot assert security-control properties.
- Without a vision provider, raster inputs supply OCR labels only. The UI says
  connectors still need review; OCR is not advertised as topology extraction.
- In `.env`, set `AEGIS_DIAGRAM_VISION_URL` to the provider base URL and
  `AEGIS_DIAGRAM_VISION_MODEL` to an already installed vision model. Use the Windows
  launcher, which loads `.env`, or pass these variables to the backend process.
  Remote providers additionally require `AEGIS_ALLOW_REMOTE_DIAGRAMS=true`.
  No customer diagram is sent remotely by default and no model is downloaded.

Limits: 8 MB per diagram, 24 million pixels per raster image, 20 draw.io pages,
8 PDF diagram pages, 1,000 components and 3,000 flows. The generated overview shows
at most 80 components and 120 flows and reports omissions. Small raster originals
and up to three PDF previews are retained; this is not a full original-file archive.
Larger originals must remain in the team's document system.

DFD Review includes an editable flow table, nested boundary membership, wheel
zoom and a separate draggable Layout view. Layout positions are saved in the
draft. The final report uses the canonical automatic layout with the same graph,
not a screenshot of the manually positioned draft.

Flow IDs and readable numbers (`F-001`) are distinct. Numbers are unique within
an assessment and are never reused after deletion. An explicit edit preserves the
flow ID. Parallel flows retain separate IDs; an ambiguous endpoint-only risk is
marked unresolved instead of being attached to all parallel flows. Selecting a
linked flow in risk details opens its report diagram and related findings.
Component-local risks legitimately show Not flow-specific.

## Documents and URL import

Existing PDF, DOCX, text and structured IaC extraction remains in use. Source
hashes deduplicate identical uploads; changed files with the same name remain
distinct. The browser reuses existing extracted sources in its current draft.
Existing parser caching avoids repeating text analysis during ordinary edits;
file extraction happens on upload. There is no cross-user persistent binary
extraction cache.

Set `AEGIS_DOCUMENT_IMPORT_HOSTS` to a comma-separated list of exact public HTTPS
documentation hosts. Empty disables URL import. Every redirect and DNS result is
validated; private, local and metadata addresses are blocked. Fetches pin the
validated address for TLS and enforce size, format and timeout limits. Import a
direct document URL, not an HTML login page. SharePoint/GitHub account connectors
and internal URL fetching are not included.

## Risk register and review

The register and details expose risk name/description, origin, severity, STRIDE,
affected components, numbered flow links, controls, evidence and review status.
New governed findings start Pending Review. Remarks are attributed to the
authenticated identity and stored server-side with optimistic concurrency.

Statuses: Pending Review, In Review, Action Required, Accepted Risk, False
Positive, Mitigation Proposed and Verified Fixed. Accepting risk requires admin
approval. Verified Fixed requires a verification note. Neither status changes the
engine's evidence tier. A missing finding is not automatically a verified fix.
Each new governed report starts a fresh review; earlier decisions remain on the
earlier report. Automatic carry-forward of unchanged decisions is not implemented.

CSV/JSON register exports include the complete field set and review event history.
PDF exports include a full register/review appendix. The existing integrity gate
still controls final publication; questionnaire completion alone does not pass it.

## Exploring large diagrams

The Architecture view starts at actual size, with mouse-wheel zoom and drag-to-pan.
Fit shows the entire model; the actual-size control restores readable labels.
Full screen provides more room. Choose a component to show its directly connected
flows, or trace a numbered flow to isolate its endpoints and inspect its evidence.
The searchable, paginated Flow list includes every modeled flow, including those
outside the current diagram scope or rendering limit.

These are display-only views: they preserve direction, flow numbers, trust
boundaries, and assumed-flow markers. They do not remove elements or change
findings. Visible/total counts make partial views explicit. The draft DFD preview
also uses actual-size zoom rather than enlarging an auto-fitted thumbnail.

## Security Reports

Categories: Threat Modeling, SAST, Penetration Testing, SCA, FOSS, Container
Security, Secret Detection and Other. Threat Modeling is native. Other categories
hold imported reports, not scans executed by Aegis.

Supported imports include SARIF 2.1.0 results, CycloneDX/SPDX JSON inventory,
generic findings JSON, and bounded document attachments. Inventory is not a
vulnerability assessment. Secret Detection accepts JSON and discards secret
values and scanner free-text messages; avoid credentials in filenames or remarks.
Imports are limited to 8 MB and 2,000 findings or 10,000 inventory entries.

Reports retain artifact hash, source, date, release and environment. Container
reports require an image digest/tag. Wrong-scope reports are visibly marked.
An editor can record Under Review/Reviewed and explicitly link an imported finding
to components/flows in a specific model revision, with an evidence statement.
Unmatched items remain unlinked. Re-uploading an identical report with the same
scope returns the existing record. Links and reviews retain their history and do
not suppress native findings. Reviewed is not independent exploit verification.

## Storage and rollout

The additional tables live in the existing `AEGIS_WORKSPACE_DB` SQLite database.
Before a production upgrade, stop the service and back up the database together
with its WAL/SHM files, or use SQLite's online backup API. Test restoring the copy.
The application adds tables without rewriting earlier report snapshots. Existing
drafts are upgraded on reopen and require the questionnaire for a new governed run.

The database contains extracted text, answers and report content; Aegis does not
encrypt it. Retention, authenticated team identities, access controls and backup
ownership remain deployment responsibilities.

## Verification and remaining work

The regression suite covers gates, roles, concurrency, stale answers, template
pinning, flow identities, nested boundaries, explicit component merges, malformed
imports, private-address blocking, report links and attributed reviews. The browser
probe is `scripts/verify-assessment-workflow.mjs`; set `PLAYWRIGHT_MODULE` if
Playwright is supplied outside this project's dependencies. Use an isolated
backend/database through `AEGIS_TEST_API_URL` for repeatable tests.

Real vision-provider accuracy/latency has not been benchmarked on a reviewed diagram
corpus. Large-document production benchmarks, customer migration/restore rehearsal,
product-architect acceptance, cancellable background vision import, flow split/merge
lineage and automatic decision carry-forward remain follow-up work. No accuracy or
security-completeness guarantee is inferred from the synthetic test count.
