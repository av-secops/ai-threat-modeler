# Threat Knowledge Base

Rule packs supply deterministic checks and retrieval candidates. The current
catalog has 252 architecture rules in 24 modules: 115 executable predicates and
137 candidate-only rules. The separate IaC catalog contains 108 checks.
These counts describe the catalog, not independently measured detection recall.

## Modules

Loading is handled by `ThreatKnowledgeBase` in [loader.py](loader.py). Every
`*.json` file here is discovered automatically except those in
`EXCLUDED_KB_FILES`; a new pack needs no registration. Files named in the
loader's priority order load first and everything else follows alphabetically.

Duplicate threat IDs are rejected after the first canonical record and reported
in `validation_issues`; source packs are expected to contain no collisions.
Rules that fail schema validation are dropped and reported the same way. An
auto-detectable rule whose predicate has no authoritative parser producer is
retained as a candidate-only rule and the unsupported fields are reported.

Every normalized rule carries `version`, `source`, `taxonomy_mapping_quality`
and a content digest in finding provenance. Missing CWE, OWASP, or NIST values
receive a visible STRIDE-category fallback so reports never imply a precise
curated mapping where only a general mapping exists.

| Module | Scope |
| --- | --- |
| `cloud_aws_threats.json` | S3, EC2, Lambda, IAM, RDS, and other AWS services |
| `cloud_azure_threats.json` | Azure services |
| `cloud_gcp_threats.json` | GCP services |
| `owasp_web_top10.json` | OWASP Top 10 for web applications |
| `owasp_api_top10.json` | OWASP API Security Top 10 |
| `container_k8s_threats.json` | Containers and Kubernetes |
| `auth_authz_threats.json` | Authentication and authorization |
| `infrastructure_threats.json` | Infrastructure components |
| `database_threats.json` | Databases |
| `supply_chain_threats.json` | Supply chain and CI/CD |
| `emerging_threats.json` | Recent and emerging patterns |
| `custom_ai_llm_threats.json` | Prompt injection, jailbreaks, model extraction |
| `domain_threats.json` | Domain-profile threats |
| `threats.json` | Base catalog |
| `ai_agent_threats.json` | Agent tool use, memory, autonomy, trace leakage |
| `rag_vector_store_threats.json` | RAG, retrieval, embedding corpora |
| `serverless_threats.json` | Function triggers, IAM, events, concurrency |
| `identity_zero_trust_threats.json` | Workload identity, OAuth scope, tenant isolation |
| `data_pipeline_threats.json` | ETL, analytics, streaming, orchestration |
| `secrets_management_threats.json` | Source, CI/CD, cloud key, and rotation risks |
| `professional_threat_catalog.json` | Cross-cutting professional catalog |
| `evidence_scoped_controls.json` | 27 explicit-control checks for identity, SaaS, audit, payments, healthcare, agents and cloud |
| `enterprise_product_controls.json` | 36 explicit-control checks for query handling, identity, tenant boundaries, payments, delivery pipelines, cloud, Kubernetes, agents and devices |
| `enterprise_review_patterns.json` | 8 review hypotheses for native memory safety, mobile deep links, CSRF and consequential AI behavior |
| `iac_security_rules.json` | Validated Terraform, CloudFormation, Kubernetes, and Compose configuration checks |

`schema.json` and `enhanced_schema.json` define the architecture-rule fields.
`iac_security_rules.json` has a separate fail-closed loader in
`engine/iac_security.py` because those rules match source configuration rather
than inferred architecture properties. These files are excluded from the
general architecture-rule discovery. The runtime contract is `contracts.py`;
the two older JSON schemas describe legacy pack formats, not the canonical model.

## Versioned framework references

`app/data/security_frameworks.json` is an offline snapshot of official OWASP
Web 2025, API 2023, LLM 2026, Agentic 2026, CWE Top 25 2025, MITRE ATT&CK
Enterprise 19.2 and ATLAS 2026.08 identifiers. Source URLs and SHA-256 hashes
record the inputs. GitHub sources are pinned to a release or commit. Analysis
does not fetch framework data from the internet.

Rules can declare `framework_mappings` with `framework`, `version` and `id`.
Explicit mappings for existing rules live in `app/data/framework_rule_mappings.json`.
Unknown identifiers or versions generate diagnostics, not invented references.
OWASP Web 2025 mappings use its published CWE membership, excluding fallback
CWEs. Older OWASP values remain unchanged; category numbers must never be
relabelled with a new year. In particular, 2021 SSRF is not 2025 A10, and LLM
resource consumption moved to LLM06 in the 2026 edition.

SANS points to the CWE software weakness list; ranking here is explicitly the
MITRE 2025 list, not an invented separate SANS certification. Every OWASP Top 10
category and CWE Top 25 entry has at least one catalog reference, but many are
review hypotheses. That is taxonomy coverage, not complete detection coverage.
ATT&CK and ATLAS reference catalogs contain many techniques we do not detect.
ASVS is linked as verification guidance, not a completed requirements assessment.

The risk details, PDF and Markdown report carry the versioned references.
An absent control is a documented gap, not proof of a successful exploit.
Public AI access alone no longer triggers a confirmed prompt-injection or
exfiltration check; missing logging no longer implies poisoned training data.

## Writing a rule

Match on architecture facts rather than wording. A rule fires against the
canonical model the parser produced, not the sentence the analyst typed.

**Use `resource_type` for affected types.** The loader normalizes this into
`components`. Matching accepts established type aliases and word boundaries,
not arbitrary substrings or another component's cloud provider. Flow predicates
run only against explicit modeled flows, never paths inferred from templates.

**Test four control states.** Each new explicit-control check has tests for
absent, present, unknown and conflicting evidence. Missing information is not
`false`. CSP does not prove output encoding, and a WAF does not prove application
resource limits. Controls are assessed individually even when they share STRIDE.

**Keep provenance honest.** Include verification guidance, source URLs, rule
version and review status. The new pack is marked `automated_contract_review`,
not independently human-reviewed. Sixteen legacy predicates still lack a
reliable property producer and are visibly demoted to candidates. Broader
framework fallback mappings remain labeled as fallbacks.

**Name the control the rule is about.** A rule that carries `controls` is
recognized as being about that control, so when a contextual pattern and the
description itself report the same absent control on the same component, the
analyzer keeps one finding and folds the others' CWE, OWASP, and MITRE mappings
into it. Without `controls`, the same gap can be reported more than once.

**Keep CWE and OWASP consistent.** Where a rule omits an OWASP category, one is
derived from its primary CWE by `owasp_for` in
[`../engine/owasp_mapping.py`](../engine/owasp_mapping.py). Where a rule declares
both, make them agree with that mapping: a rule stating a logging CWE but an
access-control category will contradict the rest of the report. The equivalent
generic weakness rules are held to this by
`test_declared_owasp_agrees_with_the_cwe_mapping`.

## After changing a pack

Reload the database and rebuild the local artifacts that depend on it:

```bash
cd backend
python scripts/retrain_local_models.py
python scripts/audit_security_knowledge.py
```

`POST /admin/retrain-local-models` reloads the rules and clears runtime caches;
models then initialize on the next model-enabled analysis. The CLI also warms
retrieval and the classifier and reports their actual status. The classifier's
training corpus is derived from these packs; it is not an independent security
training dataset or a fine-tuned language model.

Framework refresh is a separate maintenance operation:
`python tools/refresh_security_frameworks.py`. Review its generated diff,
run the audit and tests, then restart the service before publishing the update.
Versions in that script are deliberately explicit. The coverage audit lists
unmapped IDs and distinguishes predicates from review candidates. Predicate,
control and framework changes also change the retrieval provenance digest.

Then confirm the change did what you meant:

```bash
python -m pytest -q
python scripts/evaluate_threat_model.py
```

## IaC and model limits

Submitted Terraform plan JSON is supported without running Terraform or cloud
providers. It currently implements 11 resolved-value checks plus literal IAM
policy checks; source-IaC coverage is broader. Unknown-until-apply values remain
questions. Module addresses, property locators and analysis limits survive upload.
Security-group permissions and published Compose ports do not by themselves
prove internet reachability. IAM checks do not implement the complete AWS policy
evaluation model, including every condition, boundary and organization policy.

Generated rule-query pairs are catalog regression data, not an independent
accuracy benchmark. Training rejects cross-split query and family leakage.
Model comparison requires reviewed holdouts and a training manifest before a
candidate is eligible for promotion. Feedback approval builds candidate retrieval
thresholds only; it does not change the active thresholds automatically.
