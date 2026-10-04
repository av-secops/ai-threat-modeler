# Architecture diagram review

An uploaded diagram is design evidence, not a test of a deployed system. The
importer proposes a model; the architecture owner can correct it before analysis.

## Import and review

- Editable draw.io PNGs use embedded XML before OCR or a vision provider. Plain
  draw.io/XML retains cell IDs, nested boundaries, geometry and directed edges.
- Raster images combine local OCR regions, OpenCV line segments and optional
  vision extraction. OCR and vision disagreements are retained for review.
- Large images get an overview and at most four overlapping detail views. A
  repeated label is merged across views only when its image regions overlap.
- Hosting, dependencies, drawing containment and uncertain links are retained
  separately from runtime data flows. A deployment box is not a trust boundary.
- The Inventory / DFD screen places the source image beside the model. Selecting
  an element highlights its source region; the evidence dialog retains its page,
  artifact hash and extraction method. Embedded drawing-to-image alignment is
  approximate because export cropping and padding may differ.
- Diagram questions prioritize ambiguous flows, trust boundaries and conflicting
  labels. Five appear at a time. Decisions require a note and are bound to the
  source artifact. Unanswered visual flows remain assumed.
- Diagram nodes correlate with text and IaC only on unique exact names or
  reviewer aliases with compatible type and deployment scope. Ambiguous matches
  remain separate. Existing control correlation and questionnaire evidence still
  apply; image text never becomes an automatic assertion that a control exists
  or is missing.
- Vision output cannot assign control settings, public exposure or sensitive
  data classifications. Line detection is corroboration only: it cannot verify
  arrow direction, TLS, or authentication.
- Replacing a diagram retains stable source identities and unaffected manual
  corrections. Changed or removed targets suspend their corrections for review,
  with an added/changed/removed summary. Image approvals must be reconfirmed after
  the artifact changes. Earlier report revisions remain unchanged.
- A separate extraction benchmark measures component precision/recall, directed
  flow accuracy, unsupported links, direction errors, boundaries and source-region
  coverage. Repeated-service fixtures also check instance-level endpoints and
  boundary membership, not just matching labels.

## Local processing

OCR, geometry, structured parsing and preview generation run locally. To enable
vision, configure an installed, image-capable Ollama-compatible model:

```dotenv
AEGIS_DIAGRAM_VISION_URL=http://127.0.0.1:11434
AEGIS_DIAGRAM_VISION_MODEL=<installed-vision-model>
AEGIS_ALLOW_REMOTE_DIAGRAMS=false
```

The application does not download model weights or choose a model automatically.
Non-loopback providers require administrator opt-in and HTTPS. Proxy environment
variables and HTTP redirects are disabled for image requests. Provider output is
size-bounded. On provider failure, local OCR is retained with a visible warning.

Uploads are limited to 8 MB and 24 megapixels. PDF diagrams process up to eight
pages, with page-specific evidence and previews. New image views stop starting
after the 120-second per-image processing budget; PDFs share a 240-second budget.
Individual OCR/provider operations have their own timeout where supported, so
these are scheduling budgets, not hard wall-clock guarantees. Unprocessed pages
and incomplete extraction are reported. Nothing from an upload is executed.

## Verification

From the repository root:

```powershell
node scripts/run-backend-python.mjs -m pytest -q tests/test_diagram_intelligence.py
node --test scripts/diagram-review.test.mjs
node scripts/run-backend-python.mjs scripts/evaluate_diagram_extraction.py tests/fixtures/diagrams/manifest.json --output evaluation_reports/diagram-extraction.json
```

The browser check uses a generated isolated fixture, not saved product data:

```powershell
node scripts/run-backend-python.mjs tests/diagram_review_fixture.py
node scripts/verify-diagram-review.mjs
```

It needs the Vite server and Playwright; `PLAYWRIGHT_MODULE` can point to an
existing installation. Screenshots and scores go to ignored
`backend/evaluation_reports/`.

Verification on 2026-09-28: 1,402 backend tests and 60 frontend tests passed;
lint and the production build passed. Browser checks covered desktop light/dark
themes and mobile, source selection, zoom and recording decisions. Live stateless
upload/prepare requests succeeded for draw.io and JPEG. Three structured fixtures
matched their expected topology. One OCR-only raster fixture recovered all three
component labels after separator normalization, but neither arrow; that is a
reported limitation, not a passing topology score. No vision model was configured
on this installation, so vision reconciliation was tested with controlled provider
responses rather than a live model.

The checked-in fixtures and mocked provider tests are regression checks, not an
independent accuracy estimate. Production acceptance still needs reviewed raster
diagrams from the organization, including cloud icons, curved/crossing arrows,
poor scans, multiple pages and repeated services. Without a configured vision
model, plain images yield OCR candidates, not an automatically reconstructed DFD.
Incorrect OCR labels can be excluded or renamed during review. Correlation does
not infer identity from similar technology names, and it does not merge repeated
services across PDF pages without an explicit reviewer decision.
