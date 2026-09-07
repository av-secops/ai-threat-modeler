# Enterprise knowledge-base update

Implemented on 5 September 2026. The architecture catalog now contains 252 rules
in 24 modules: 115 executable checks and 137 review candidates. The separate
108-check IaC catalog is unchanged by this update.

## Added coverage

The new enterprise pack adds 36 explicit-control checks covering SQL and NoSQL
query handling, command execution, paths, XML, deserialization, failure handling,
concurrent state changes, OAuth, session rotation, recovery, tenant-scoped caches
and jobs, privileged functions, payment lifecycle and reconciliation, build
integrity and provenance, isolated runners, cloud delegation, key deletion,
protected origins, Kubernetes admission and tokens, agent execution, MCP tools,
agent memory and communication, resource budgets, retention, restores and devices.

Eight additional patterns support review of native memory safety, mobile deep
links, CSRF and consequential AI decisions. These are hypotheses, not confirmed
vulnerabilities. Native memory defects require source review, fuzzing or runtime
evidence. Framework coverage must not turn a language choice into a finding.

The technology catalog also recognizes more enterprise implementation names,
including ASP.NET Core, Jenkins, GitLab CI, Azure Pipelines, Google Compute
Engine, PingFederate, mobile apps and artifact registries.

## Framework references

The offline registry contains OWASP Web 2025, API 2023, LLM 2026 and Agentic 2026,
CWE Top 25 2025, ATT&CK Enterprise 19.2 and ATLAS 2026.08. Each imported source
has its URL and content hash recorded. GitHub inputs use a release or commit.
SANS references the CWE list; it is not treated as a separate certification.

All categories in the four OWASP Top 10 lists and all 25 ranked CWEs have a
catalog mapping. Some mappings are candidate-only. This does not establish
complete detection, compliance or measured real-world recall. Most ATT&CK and
ATLAS techniques remain unmapped and are listed by the coverage audit.

New mappings appear in finding details and exported reports. Existing OWASP
2021 mappings remain versioned as 2021. A new category is derived from the
official CWE membership, never by replacing the year on an old category number.
Fallback CWEs cannot inflate the KB's curated coverage counts.

## False-positive controls

- New predicates require explicitly absent controls on matching component types.
- Unknown, contradictory and affirmative statements do not trigger those checks.
- AWS-specific customer binding does not apply to an Azure identity.
- Public AI access alone does not prove prompt injection or exfiltration.
- Missing logging does not prove training-data poisoning.
- Candidate patterns remain separate from executable checks.
- Sources and framework references are guidance, not proof of exploitability.

## Maintenance and validation

Run `python scripts/audit_security_knowledge.py` from `backend` to see mapped and
unmapped IDs, executable versus candidate coverage, and loader diagnostics.
The generated audit is in `backend/evaluation_reports/security-kb-2026-09-05.json`.
Sixteen pre-existing unsupported predicates remain visible as candidate-only
diagnostics rather than being advertised as executable detections.

Run `python tools/refresh_security_frameworks.py` only as a reviewed maintenance
operation, then tests and `python scripts/retrain_local_models.py`. Restart the
service after publishing changes. Derived index fingerprints now include
predicates, applicability, controls, remediation and framework mappings.

Regression tests cover every new control, parser-to-engine operation, incorrect
technology and cloud scope, framework versions, and complete SaaS, AWS and
AI-agent report pipelines. Browser checks cover evidence references, light and
dark reports, mobile layout and PDF export. These are regression results, not
independently reviewed recall or precision measurements.
