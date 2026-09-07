# Engine and report improvement workplan

This records implementation and evaluation, not a claim of exhaustive detection.
Existing reviewer decisions and user edits must be preserved.

## Delivery checklist

- [x] P0: Regression tests for policy, CI, control-state and known-issue errors.
- [x] P0: Statement-aware IAM/CI checks and scoped exposure findings.
- [x] P0: Partial/conflicting controls and per-control evidence assessment.
- [x] P1: Shared property contract and executable, tested KB expansion.
- [x] P1: Structured IaC input and explicit unresolved-reference diagnostics.
- [x] P1: Control-property source reconciliation, citations and explicit boundary dimensions.
- [x] P2: Permission-aware attack-path evidence and verification guidance.
- [x] P2: Independent-evaluation contracts, leakage checks and model promotion gates.
- [x] P2: Cleaner interactive report, filtering, evidence and architecture views.
- [x] P3: Phase profiling, bounded shared workers, timeout-slot and unavailable-model regressions.
- [x] Final: Backend, frontend and browser verification; document residual gaps.

## Guided review completion (2026-09-05)

- [x] Review architecture before analysis; edit components and flow endpoints.
- [x] Scoped clarification answers, source replacement and stale-answer detection.
- [x] Draft recovery, immutable report revisions and preserved reviewer decisions.
- [x] Mixed IaC context, format hints, resource-to-finding scope and exclusions.
- [x] Dark diagram contrast, centering, zoom and mobile checks.
- [x] PDF reviewer exclusions and matching confirmed/severity totals.
- [x] Full backend suite, production build, lint and browser verification.

See [guided model review](guided-model-review.md) for behavior, storage limits and
the verification commands. This completes the review-workflow checklist; the
independent security acceptance work below remains separate.

## External acceptance requirements

Human security review is required before calling a benchmark independently
reviewed. Synthetic scenarios and maintainer tests are not substitutes. Model
training/promotion must use separated architecture families and measured
holdout performance, not generated rule-title lookup accuracy. Initial targets
are 95% evidenced-finding precision and 90% explicit high/critical issue recall;
report sample sizes and uncertainty by domain. Start with 100 scenarios and
expand to 300 after review rather than inflating counts with paraphrases.

## Remaining acceptance work

- Obtain independent reviewer labels and measure domain-level precision/recall.
- Train and evaluate an embedding candidate only against a leakage-audited corpus;
  do not replace the active checkpoint on catalog-lookup scores alone.
- Review legacy taxonomy fallbacks and the 126 candidate-only rules. A listed
  threat is not necessarily an executable detector.
- Extend resolved-plan checks and effective cloud-policy reasoning incrementally.
  Submitted evidence does not establish the live deployment or effective access.
- Free-text extraction and cross-document reconciliation remain bounded and
  heuristic; the workbench exposes evidence and ambiguity for analyst correction.
