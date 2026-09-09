# Reliability and enterprise implementation

Started 9 September 2026. This tracks implementation separately from independent
security acceptance. Existing reports and reviewer decisions must survive updates.

- [x] 1. Source issue inventory and per-issue dispositions.
- [x] 2. Contextual subjects, exceptions and non-assertion handling.
- [x] 3. Scoped evidence validation before confirmed publication.
- [x] 4. Canonical diagram membership and reconciled metrics.
- [x] 5. Metamorphic and end-to-end regressions.
- [x] 6. Executable KB gaps with explicit evidence contracts.
- [x] 7. Bounded effective cloud-policy evaluation.
- [x] 8. Business-workflow invariant checks.
- [x] 9. Typed, evidence-bound SLM proposals and promotion acceptance gate.
- [x] 10. Dependency-aware result reuse and durable analysis jobs.
- [x] 11. Actionable uncertainty and issue/evidence inspection.
- [x] 12. Persistent products, applications, releases, roles, history and comparison.

## Verification

- Backend: 1,251 tests passed. Frontend workspace and launcher: 13 tests passed.
- ESLint and production build passed. Twenty generated diagrams parsed successfully.
- Browser checks covered product/release creation, saved drafts, workflow inputs,
  durable analysis, report revisions, evidence links, zoom, light/dark themes and
  mobile overflow. The isolated report kept one input-validation finding without
  importing SSRF or privilege-escalation mappings.
- PDF export produced four pages. Rendered cover, diagram/risk and evidence pages
  were inspected for clipping, missing content and source issue accountability.
- The KB loads 252 rules: 129 executable predicates and 123 retrieval candidates.
  Candidate-only rules are not advertised as deterministic detections.

## Boundaries

This is an implemented local workflow, not enterprise deployment certification.
Installation roles do not provide per-product tenant isolation or SSO. SQLite
needs operator-managed access protection and backups. Jobs are bounded local
workers, not a distributed scheduler. Policy reasoning covers a documented AWS
IAM subset and returns unknown for unsupported interactions; Azure/GCP effective
permission simulation is not included. Release comparison uses modeled identities,
not a manual resource-rename reconciliation service.

Rule caching reuses unchanged component predicates; it is not a fully incremental
distributed analysis graph. SLM validation and the existing promotion gate are
implemented, but no independently reviewed training/holdout dataset was supplied.

Independent reviewer labels, production accuracy measurements, and deployed-cloud
verification cannot be established by synthetic tests or by this checklist.
