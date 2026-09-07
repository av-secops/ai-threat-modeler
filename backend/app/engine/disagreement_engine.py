"""Surface model and engine disagreements as review work, never silent overrides."""

from __future__ import annotations

from typing import Any, Dict, List


class DisagreementEngine:
    VERSION = "engine-disagreement-1.0"

    def assess(self, threats, local_diagnostics: Dict[str, Any] | None) -> Dict[str, Any]:
        diagnostics = local_diagnostics or {}
        records: List[Dict[str, Any]] = []
        seen = set()

        for threat in threats:
            review = (threat.explanation or {}).get("local_stride_review") or {}
            deterministic = review.get("deterministic_category")
            predicted = review.get("predicted_category")
            scores = review.get("scores") or {}
            confidence = float(scores.get(predicted, 0) or 0)
            if not predicted or predicted == "Unknown" or predicted == deterministic or confidence < 0.65:
                continue
            key = ("stride", threat.id, predicted)
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "id": f"disagreement-stride-{len(records) + 1}",
                "kind": "stride_classification",
                "finding_id": threat.id,
                "element_id": threat.affected_component or threat.component,
                "deterministic_value": deterministic,
                "challenger_value": predicted,
                "confidence": round(confidence, 4),
                "status": "review_required",
                "resolution": "Deterministic evidence-backed classification retained pending review.",
                "question": (
                    f"Should {threat.title} also be mapped to {predicted}, or does the available evidence "
                    f"support only {deterministic}?"
                ),
            })

        challenger = diagnostics.get("challenger") or {}
        for candidate in challenger.get("review_candidates") or []:
            confidence = float(candidate.get("retrieval_score") or 0)
            if confidence < 0.55:
                continue
            key = ("coverage", candidate.get("candidate_rule_id"), candidate.get("element_id"))
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "id": f"disagreement-coverage-{len(records) + 1}",
                "kind": "coverage_candidate",
                "candidate_rule_id": candidate.get("candidate_rule_id"),
                "element_id": candidate.get("element_id"),
                "deterministic_value": "no evidence-backed finding",
                "challenger_value": candidate.get("stride_category"),
                "confidence": round(confidence, 4),
                "status": "information_required",
                "resolution": "Candidate withheld until applicability evidence is supplied.",
                "question": candidate.get("question"),
                "required_evidence": candidate.get("required_evidence") or [],
                "negating_controls": candidate.get("negating_controls") or [],
            })

        structured = challenger.get("structured_slm") or {}
        for candidate in structured.get("accepted_candidates") or []:
            key = ("slm", candidate.get("element_id"), candidate.get("stride_category"))
            if key in seen:
                continue
            seen.add(key)
            records.append({
                "id": f"disagreement-slm-{len(records) + 1}",
                "kind": "local_slm_candidate",
                "element_id": candidate.get("element_id"),
                "deterministic_value": "unknown coverage cell",
                "challenger_value": candidate.get("stride_category"),
                "confidence": None,
                "status": "information_required",
                "resolution": "Local SLM output cannot create a finding without deterministic validation.",
                "question": candidate.get("question"),
                "evidence": candidate.get("evidence") or [],
            })

        high_confidence = sum(
            item["status"] == "review_required" or float(item.get("confidence") or 0) >= 0.75
            for item in records
        )
        return {
            "version": self.VERSION,
            "status": "review_required" if high_confidence else "informational" if records else "clear",
            "unresolved_count": high_confidence,
            "informational_count": len(records) - high_confidence,
            "high_confidence_count": high_confidence,
            "items": records[:50],
            "authority_policy": (
                "Deterministic evidence rules retain finding authority. Challenger disagreements create "
                "review questions and cannot silently change publication findings."
            ),
        }
