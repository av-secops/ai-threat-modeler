# Aegis Threat 2.3.1

Aegis Threat is a local React and FastAPI application for building technical threat models from architecture descriptions and uploaded design documents. It combines deterministic security rules, STRIDE coverage, local semantic search, optional LLM review, attack-path analysis, compliance mappings, and report exports.

The deterministic engine remains the source of published findings. Semantic models and optional LLMs rank candidates, identify gaps, and raise review questions; they do not silently create confirmed risks.

## What it does

- Parses components, assets, data flows, trust boundaries, assumptions, and known issues from text, Markdown, DOCX, PDF, JSON, YAML, and related text formats.
- Analyzes related Terraform/HCL projects, Kubernetes and Helm, Kustomize, Compose, CloudFormation, ARM, Bicep, Pulumi, and CI workflows with source-file evidence.
- Runs `fast`, `standard`, or `deep` analysis against web, API, identity, cloud, container, supply-chain, payment, healthcare, AI, LLM, agent, and MCP threat packs.
- Maps findings to STRIDE, affected components and flows, root causes, attack scenarios, evidence, mitigations, and compliance references.
- Produces Mermaid architecture diagrams, attack routes, missing-information questions, coverage summaries, and change summaries.
- Supports SaaS, fintech, healthcare, AI, platform, and general domain profiles.
- Includes an analyst workbench for notes, triage, ownership, action-register export, and local analysis assistance.
- Exports Markdown, JSON, CSV, PNG, and PDF reports.

The report has separate overview, architecture, risk register and assurance
views. Findings can be searched and filtered by evidence, severity, STRIDE and
review status; each opens a detail dialog with evidence and remediation. The
architecture supports wheel zoom, buttons and panning in light and dark mode.

Architecture and IaC analyses now open a review draft first. Check the components
and connections, answer the priority questions you know, then analyze the reviewed
model. You can leave unknowns open and return to them later.

Use **Update this model** to add context, replace a file or correct a connection.
Each successful analysis saves a new report revision. History also restores
unfinished drafts. Sources are kept as extracted text in this browser; use
**Export workspace** for a JSON archive. Details are in
[the guided review notes](docs/guided-model-review.md).

Prompt and document claims are correlated by component, flow, endpoint and
deployment scope. The review diagram updates automatically after an edit, and
its evidence inspector links back to the source text. Conflicts and unassigned
claims remain visible. See [source correlation](docs/source-correlation.md).

Controls can be present, absent, partial, unknown or conflicting. A finding in
one STRIDE category does not resolve every other control in that category.
Submitted Terraform plan JSON is also supported, with explicit unknown-value and
coverage limits. Analysis concurrency defaults to two workers per process;
`AEGIS_THREAT_ANALYSIS_CONCURRENCY` and `AEGIS_THREAT_ANALYSIS_TIMEOUT_SECONDS`
control admission and caller timeouts. Timed-out work retains its slot until it
actually finishes.

## Repository layout

```text
src/                         React frontend
  components/
  hooks/
  services/
  utils/
backend/
  app/
    data/                    technology catalog: vendors, types, control domains
    engine/                  parsing and threat-analysis pipeline
    knowledge_base/          modular threat packs
    services/                document and external LLM integrations
    main.py                  FastAPI application
    models.py                API and analysis contracts
  scripts/                   evaluation, retraining, dataset, and probe tools
  tests/
```

Inside the engine, the passes that read prose and the passes that read the graph
are kept apart:

| Module | Responsibility |
| --- | --- |
| `prose.py` | Where sentences and clauses really begin and end |
| `source_index.py` | Which document, page and line a statement came from |
| `flow_extraction.py` | Which data flows a description states, and in which direction |
| `control_statements.py` | Whether a control is claimed or denied, and about what |
| `source_correlation.py` | Matches source claims to elements, scope and control state |
| `control_contracts.py` | Shared control vocabulary used by correlation and STRIDE |
| `graph.py` | Reachability and how data classification travels |
| `parser.py` | Assembles the canonical architecture from all of the above |
| `stride_coverage_engine.py` | Assesses every element against every STRIDE category |
| `risk_scoring.py` | Turns exposure, classification, and reach into a severity |
| `attack_path_engine.py` | Routes from an entry point to a finding, and onward |

## How it reads an architecture

Everything downstream depends on the model built from your description, so it is
worth knowing what the parser takes from the words you write.

**Flows are either stated or assumed, and always labelled.** A flow the
description states is modelled as written, carries the sentence that states it,
and is marked `origin: stated`. Where a component is left unconnected, a
type-based template supplies one flow so the component is in scope; that flow is
marked `origin: assumed`, carries the assumption in plain words, and is drawn as
a guess in the diagram. Templates only fill in for components whose connections
were left unsaid, so no component ends up with a guessed path alongside one you
described.

**A component is named once and referred to loosely afterwards.** Introduce "a
Node.js REST API" and later sentences can say "the API" or "the backend". A bare
role noun resolves only when exactly one component can answer to it; where two
could, both keep their full names rather than the tool guessing between them.

**Each weakness belongs in its own clause.** These are read as two claims about
two components:

```text
The portal has no MFA and the ingestion bucket is not encrypted at rest.
```

A conjunction is treated as a new claim only when what follows has both a subject
and a predicate, so a list of destinations stays one statement:

```text
The API sends records to the database and the ingestion bucket.
```

**A list of verbs keeps the subject it was given.** All three of these belong to
the API, and all three flows are extracted:

```text
The API authenticates staff against Azure AD, stores patient records in a
PostgreSQL database, and uploads scanned documents to an S3 ingestion bucket.
```

**Data classification travels with the data.** Saying "patient records" once
classifies that store as PHI, and every component the records flow through
inherits it, so the API in front of the database is scored as handling PHI without
you having to repeat it. Each component records whether its classification was
`stated` or `propagated`, and a propagated value never overrides a stated one.

Unspecified controls should remain questions or clearly labelled potential risks,
not confirmed vulnerabilities. Extraction and interpretation still need review;
the known limitations below describe failures observed in a complex scenario.
The gaps report names components whose connections were guessed, and the evidence
requests list every unresolved control.

## Where a finding came from

Uploaded documents and the description you type are assembled into one text
before parsing, so `source_index.py` rebuilds the mapping from that text back to
its sources. Every piece of evidence is then cited with the document, the page or
table, and the line that stated it:

```text
- Evidence:
  - [architecture_input] storage.md, page 4, line 2: The S3 receipts bucket is not encrypted at rest.
```

Each evidence record carries `document`, `locator`, `line`, and a preformatted
`cite`, and the risk details panel lists them under "Cited in". A component also
records the `source_document` that named it, and `source_attribution` in the
architecture metadata counts what each source contributed, which answers whether
one document is carrying the model on its own.

A claim that no source states is marked as inference and cites nothing, rather
than naming a document that happens to have been uploaded. Document headers,
page markers, and section separators are never quoted as design statements, so a
component matched only against a filename such as `orders-service-design.docx`
is treated as inferred rather than as stated by the design.

## How risk is scored

Severity comes from one transparent calculation, published with each report under
`risk_methodology` (currently `technical-v4`). Every finding carries the inputs
that produced its score in `risk_factors`:

- **Reachability**: **exposure** and **privileges required** combined, then capped.
  Every producer derives both from the same trust level, so scoring each at full
  weight let one fact — whether the component faces the internet — decide the
  severity band by itself. The cap keeps the weaker signal meaningful without
  counting the same fact twice.
- **Control state**: whether the control the finding concerns is absent, present,
  or simply not stated. This replaced exploit complexity, which read `medium` on
  97% of findings because a design description carries no evidence of how hard a
  weakness is to exploit. A confirmed gap now outranks an unanswered question,
  which is the distinction a reader actually acts on.
- Whether the finding **crosses a trust boundary**. For a component-scoped finding
  only inbound crossings count: arriving from another trust zone is attack
  surface, whereas calling out to a less trusted place is covered by impact.
- **Asset sensitivity**, taken as the most sensitive classification carried by the
  finding's components and flows.
- **Blast radius**: the finding's own elements plus everything reachable from them
  over the flow graph. It counts toward impact once it covers roughly half the
  architecture, so the term means something in a large design as well as a small
  one.
- **Compensating controls**, up to two, which lower the result.

**Evidence confidence is reported but does not raise likelihood.** How sure we are
that a finding is real and how likely an attacker is to succeed are different
questions, and the Confirmed/Potential tier already carries the first. Findings
resting on an assumed flow are discounted separately.

The calculation runs again each time the architecture is refined, and is free to
fall as well as rise, so a control discovered on a later pass can lower a severity.
A severity authored by a curated rule, a taxonomy entry, or an analyst statement
is a floor the calculation may raise but not lower — a general formula cannot
rederive that, say, a privileged pod with a mounted service account token is
critical. `severity_source` records which applied, and `reported_severity` keeps
the original claim.

Confirmed findings need direct evidence from source, IaC, or the architecture
description. One absent control on one component is reported once: where a
knowledge-base rule, a contextual pattern, and the description itself all report
the same thing, the most specific finding is kept and the others' CWE, OWASP, and
MITRE mappings are folded into it.

Unspecified controls are raised as a capped, risk-ranked set of Potential threats
rather than one per STRIDE category, so a large architecture does not produce five
near-identical questions about whichever element happened to rank highest. The
cap is reported in the coverage `guarantee`, and every cell left out is still
listed in the evidence requests.

An attack path is published only when the validated graph contains a credible
entry, target, at least one hop, and at least one explicitly stated hop. Each hop
is marked `explicit` or `inferred`, cites its evidence, and records trust-boundary
crossings, effective identity, required permissions, authorization transition,
and network protocol. Inferred hops are also listed as assumptions. An isolated finding remains an exploit scenario; its explanation says
why no path was modeled instead of drawing a zero-hop path.

The system security score groups duplicate manifestations of the same root
control gap before calculating impact. `technical-v4` reports the confirmed-risk
score, the smaller uncertainty penalty from Potential findings, the unique root
risk count, and the evidence-determined control ratio separately.

## Requirements

- Node.js 22.13+ or a newer even-numbered LTS release; npm 10+
- Python 3.10+; Python 3.12 is recommended and used for local verification
- On Windows, `py` or `python`, plus `node` and `npm`, available on `PATH`
- Optional Tesseract OCR on `PATH`; RapidOCR provides a local fallback for scanned pages and embedded DOCX images

## Install and run

### Windows

From the repository, run either helper:

```powershell
.\start.ps1
# Or from Command Prompt: start.bat
```

The helpers create `backend/.venv` when needed, install missing dependencies,
and wait for the API and frontend to respond before opening the browser. They
can also be invoked by absolute path from another directory. Background servers
bind only to `127.0.0.1`; output is written to `logs/`.

```powershell
.\start.ps1 -Check                    # Validate dependencies without starting
.\start.ps1 -InstallDependencies      # Refresh pip dependencies and run npm ci
.\start.ps1 -BackendPort 8001 -FrontendPort 5174 -NoBrowser
.\start.ps1 -Stop                     # Stop only launcher-managed processes
```

Batch equivalents are `--check`, `--install`, `-b 8001 -f 5174 --no-browser`,
and `--stop`. `--help` lists the options. Occupied ports cause a clear error;
the launcher does not kill unrelated processes or silently choose a different port.
For a slow first start, use PowerShell's `-StartupTimeout 240`.

If your execution policy blocks the PowerShell script, inspect the downloaded
files and follow your organization's policy. The launcher does not bypass that policy.

### Manual Setup

Create and use a virtual environment, then install from the root manifest:

```bash
python -m venv backend/.venv
# Linux/macOS:
source backend/.venv/bin/activate
# Windows PowerShell: .\backend\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
npm ci
```

Start the frontend and backend together:

```bash
npm start
```

The application will be available at:

- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

For development, run each service in its own terminal:

```bash
# Terminal 1
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```bash
# Terminal 2
npm run dev -- --host 127.0.0.1 --port 5173
```

`npm start` is the terminal-oriented development option, with reload enabled.
It does not install dependencies or manage the Windows launcher's process state.
The helper reads backend settings from a root `.env` file when present; shell
variables take precedence. `.env` and local analysis/feedback output are excluded
from Git. No model weights are downloaded during normal startup.

## Use it on your local network

The helper scripts are local-only. Before any deliberate network deployment,
set `ENVIRONMENT=production`, a narrow `ALLOWED_ORIGINS`, and `ADMIN_API_TOKEN`.
Use a trusted network and an authenticated TLS reverse proxy; do not expose the
Vite development server or an unprotected analysis API to the public Internet.

Find the machine's IPv4 address with `ipconfig`, then bind both services to all interfaces:

```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

PowerShell:

```powershell
$env:VITE_API_URL="http://<YOUR_IP>:8000"
$env:VITE_WS_URL="ws://<YOUR_IP>:8000"
npm run dev -- --host 0.0.0.0 --port 5173
```

Command Prompt:

```bat
set VITE_API_URL=http://<YOUR_IP>:8000
set VITE_WS_URL=ws://<YOUR_IP>:8000
npm run dev -- --host 0.0.0.0 --port 5173
```

Open `http://<YOUR_IP>:5173` from the other device. If it cannot connect, allow ports `5173` and `8000` through the host firewall.

## Configuration

Frontend variables:

- `VITE_API_URL`: REST API base URL
- `VITE_WS_URL`: WebSocket base URL

Backend variables:

- `ENVIRONMENT`: `development` or `production`
- `ALLOWED_ORIGINS`: comma-separated CORS allowlist
- `ADMIN_API_TOKEN`: protects administrative endpoints when set
- `AEGIS_THREAT_ENABLE_TRANSFORMERS`: enables local transformer NER when its model is already cached
- `AEGIS_THREAT_NER_MODEL`: Hugging Face model ID used for NER enrichment
- `AEGIS_THREAT_LOCAL_SLM_MODEL`: locally available checkpoint for the review-only structured SLM
- `AEGIS_THREAT_LOCAL_SLM_TASK`: Transformers pipeline task; defaults to `text2text-generation`
- `AEGIS_THREAT_RETRIEVAL_PROFILE`: `fast`, `balanced`, or `accuracy`; defaults to `balanced`
- `AEGIS_THREAT_EMBEDDING_MODEL`: overrides the profile's local embedding model
- `AEGIS_THREAT_RERANKER_MODEL`: overrides the profile's reranker; balanced mode uses the built-in security-feature reranker, while accuracy mode enables `BAAI/bge-reranker-base`
- `AEGIS_THREAT_CLASSIFIER_EMBEDDING_MODEL`: stable embedding model for the advisory STRIDE classifier; defaults to `all-MiniLM-L6-v2`
- `AEGIS_THREAT_MODEL_CACHE`: local Hugging Face model directory
- `AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD`: set to `1` only while prefetching models; analysis is offline by default
- `AEGIS_THREAT_DENSE_WEIGHT` and `AEGIS_THREAT_LEXICAL_WEIGHT`: optional reciprocal-rank fusion weights

The balanced local stack prefers a promoted `models/aegis-bge-security-v1`
checkpoint when it is installed, otherwise it uses `BAAI/bge-base-en-v1.5`.
It combines dense retrieval with BM25, reciprocal-rank fusion, a lightweight
security-feature reranker, domain indexes, and FAISS. The deterministic STRIDE
engine remains authoritative; retrieval supplies candidates and evidence. If a
checkpoint is unavailable, retrieval remains local and falls back to BM25 plus
deterministic hashing.

Prefetch and verify the pinned models before an offline deployment:

```bash
cd backend
AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD=1 python tools/prefetch_models.py
```

Windows PowerShell equivalent, from the repository root:

```powershell
$env:AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD = '1'
.\backend\.venv\Scripts\python.exe backend\tools\prefetch_models.py
$env:AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD = '0'
```

The retrieval training set is generated from every validated knowledge rule,
with same-domain hard negatives and a separate exhaustive evaluation corpus.
Reviewer decisions are recorded but never enter training until an administrator
approves them.

```bash
cd backend
python tools/build_security_retrieval_dataset.py
python tools/train_security_embeddings.py --output models/aegis-bge-security-v1
python tools/compare_retrieval_models.py
```

Model promotion requires at least 98% retrieval recall, 0.90 mean reciprocal
rank, zero incorrect hard negatives outranking an accepted rule, and a real
embedding backend. Similar secondary candidates may still be retrieved because
the deterministic applicability engine decides whether they become findings. The report
records the model revision, rule version, source module, calibrated threshold,
retrieval sources, cache state, and runtime latency statistics. Fine-tuned model
directories are intentionally excluded from Git; their dataset hashes and
training reports make them reproducible.

## API

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/analyze` | `POST` | Analyze an architecture description |
| `/analyze-documents` | `POST` | Analyze uploaded design documents |
| `/model-review/sources` | `POST` | Extract files into reviewable source records |
| `/model-review/prepare` | `POST` | Prepare or refresh the editable architecture and evidence |
| `/model-review/analyze` | `POST` | Analyze the reviewed model and return a report revision |
| `/analyze-iac` | `POST` | Analyze Terraform, CloudFormation, Kubernetes, or Docker Compose IaC |
| `/analyze-iac-project` | `POST` | Analyze related IaC files together |
| `/analyze-code` | `POST` | Analyze supported source-code inputs |
| `/analyze-with-llm` | `POST` | Add an external LLM challenger with retrieved context |
| `/validate-api-key` | `POST` | Validate a provider API key |
| `/health` | `GET` | Check API and local ML readiness |
| `/feedback/findings` | `POST` | Record an analyst review decision without auto-approving it for training |
| `/admin/retrieval-feedback/approve` | `POST` | Approve feedback and rebuild calibrated thresholds |
| `/admin/retrieval-metrics` | `GET` | Inspect retrieval latency, fallback, cache, and query metrics |
| `/cache` | `DELETE` | Clear analysis caches; admin protected |
| `/admin/retrain-local-models` | `POST` | Reload the knowledge base and retrain local artifacts |
| `/ws/analyze` | `WS` | Stream analysis progress |

Example request:

```json
{
  "project_name": "Payments Platform",
  "description": "React frontend, API gateway, JWT auth, PostgreSQL, Redis, S3, and Stripe integration.",
  "use_local_slm": true,
  "analysis_mode": "standard",
  "domain_profile": "fintech"
}
```

Important response fields include `threats`, `score`, `architecture`, `diagram`, `report_markdown`, `attack_chains`, `architecture_insights`, `coverage`, `risk_methodology`, `diff_summary`, `follow_up_questions`, `review_summary`, and `domain_context`.

Within each threat, `risk_factors` holds the inputs behind the score,
`evidence_details` holds each statement with the `document`, `locator`, `line`,
and `cite` it came from, `explanation.component_flows` holds the flows touching
the affected component, `explanation.flow_context` says why a finding has no flow
of its own, and `attack_path` holds the route in and the data reachable beyond it.

## Knowledge base and local models

Threat packs live in [`backend/app/knowledge_base`](backend/app/knowledge_base). They cover cloud and infrastructure, web and APIs, authentication and identity, containers and Kubernetes, software supply chain, databases, payments, healthcare, and AI/LLM threats including prompt injection, jailbreaks, data poisoning, model extraction, inference abuse, and denial of ML service.

A rule's `resource_types` are matched against component types without regard to
spacing or naming style, so `StorageBucket`, `Storage Bucket`, and `Object Storage`
all match the same components and a rule does not silently fail to fire over a
space.

Semantic retrieval uses domain-specific indexes, component and cloud filters, hard-negative rejection, and second-stage reranking. The STRIDE classifier is advisory. When a classifier or semantic candidate disagrees with a deterministic result, the report keeps the evidence-backed result and creates a review question.

Reload the knowledge base and rebuild local artifacts after changing a threat pack:

```bash
cd backend
python scripts/retrain_local_models.py
```

The same operation is available through `POST /admin/retrain-local-models`.

## Tests and probes

```bash
npm test          # backend suite without the slow tests, across processes
npm run test:all  # the whole backend suite
npm run lint      # frontend
npm run build     # production frontend bundle
node --test scripts/model-workspace.test.mjs
node --test scripts/startup.test.mjs
```

Most of the suite's wall time is engine import rather than assertions, which is
why the fast lane parallelizes.

The probes in `backend/scripts` print what a change did to a real analysis, which
assertions alone do not show. Run them after touching the parser, the risk model,
or the coverage engine:

```bash
cd backend
python scripts/flow_probe.py      # stated versus assumed flows per scenario
python scripts/risk_probe.py      # classification, blast radius, boundary crossing
python scripts/path_probe.py      # which findings got an attack route, and how long
python scripts/severity_probe.py  # severity spread, to catch score inflation
```

## Evaluation and optional training

Run the release evaluation:

```bash
cd backend
python scripts/evaluate_threat_model.py
```

The gate measures overall and per-STRIDE recall, critical-threat recall, severity, component scope, evidence grounding, architecture accuracy, duplicate findings, false positives, technology hallucinations, retrieval ranking, hard-negative leakage, and classifier accuracy.

Build the reviewed instruction-tuning dataset with a named approver:

```bash
cd backend
python scripts/build_security_training_data.py --approved-by <review-group>
```

QLoRA training is optional and kept separate from the application dependencies:

```bash
pip install -r requirements-training.txt
python scripts/train_security_slm.py \
  --model <causal-model> \
  --dataset training/security_threat_training_v1.jsonl \
  --output training/output-adapter
```

The exporter rejects unnamed approval, and the trainer rejects unapproved records. A trained adapter is still a reviewer; deterministic evidence rules control confirmed findings and final publication.

## Report quality

Reports have three publication states:

- `ready`: final exports are available.
- `review`: assumptions or open questions remain, but exports are allowed.
- `blocked`: the architecture is invalid or confirmed findings contain unresolved evidence, scope, component, alias, or classification failures.

A document that could not be read in full marks the report for review rather than
blocking it, and names what was missed. Architecture diagrams are usually images,
and a PDF page with no extractable text contributes nothing to the model, so
`unread_document_content` on the quality gate lists each document and the pages
left unread, and the report states them beside the scope counts they qualify.
Findings from the pages that were read are still published.

The dashboard supports finding states such as open, mitigated, accepted, and false positive. Mermaid labels and IDs are sanitized before rendering, and frontend response normalization is handled in [`src/utils/analysisMapper.js`](src/utils/analysisMapper.js).

### Known Limitations in This 2.3.1 Update

The [Nexora telecom scenario review](docs/scenarios/nexora-telecom-26.09/chrome-review-2026-09-07.md)
found missed declared weaknesses, explanatory sentences misread as absent
controls, incorrect data classification, and a false control conflict that
blocked final export. Large diagrams can also simplify away important flows
and draw boundaries differently from the declared model. These analysis defects
are documented, not fixed by this startup/documentation update.

Treat this release as an assisted review tool, not a security sign-off engine.
"Confirmed" means the engine found supporting input evidence, not that the
deployment was tested. "100% STRIDE assessed" is not complete threat coverage;
check evidence resolution and the original documents as well. Product/release
hierarchy management remains a [saved workplan](docs/product-release-workplan.md).

## License

NA
