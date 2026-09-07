"""Evidence-based confidence calibration for normalized findings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

from ..models import Threat
from .control_contracts import control_value


SOURCE_WEIGHT = {
    "code": 0.98,
    "iac": 0.98,
    "iac_absence": 0.72,
    "static_analysis": 0.96,
    "architecture_input": 0.9,
    "rule_evaluation": 0.82,
    "coverage_assessment": 0.86,
    "llm_challenger": 0.62,
    "architecture": 0.55,
    "inference": 0.45,
}
DIRECT_SOURCES = {"code", "iac", "static_analysis", "architecture_input", "rule_evaluation", "coverage_assessment"}


class ConfidenceCalibrator:
    def calibrate(self, threats: List[Threat], architecture) -> Tuple[List[Threat], Dict[str, Any]]:
        flows = {
            f"{item.source_id}->{item.target_id}": item for item in architecture.flows or []
        }
        distribution = Counter()
        components = {item.id: item for item in architecture.components or []}
        for threat in threats:
            sources = {
                str(item.get("source_type") or "").lower()
                for item in (threat.evidence_details or [])
            }
            source_score = max((SOURCE_WEIGHT.get(item, 0.5) for item in sources), default=0.35)
            if threat.finding_type in {"code", "iac"}:
                source_score = max(source_score, 0.98)
            source_refs = {str(item.get("source_ref") or "") for item in (threat.evidence_details or [])}
            declared_issue = any(ref.startswith("K") and ref[1:].isdigit() for ref in source_refs)
            reviewer_evidence = any(item.get('evidence_basis') == 'user_declared'
                or item.get('source_ref') == 'reviewer_clarification' for item in (threat.evidence_details or []))
            if declared_issue:
                source_score = max(source_score, 0.97)

            # A finding about the submitted material itself names no component
            # because it is not about one. That is a stated scope, not a missing
            # one, so it does not take the unscoped-inference penalty.
            document_scoped = (threat.explanation or {}).get("scope") == "submitted_material"
            explicit_unmapped = (
                (threat.explanation or {}).get("scope_resolution")
                == "unresolved_explicit_statement"
            )
            scoped = bool(
                threat.affected_components or threat.affected_data_flows or threat.affected_assets
            ) or document_scoped or explicit_unmapped
            score = source_score + (0.04 if scoped else -0.18)
            flow_ref = (threat.data_flow or threat.related_data_flow or "").replace(" → ", "->")
            flow = flows.get(flow_ref)
            # A finding about a path is only as good as the path. This discount
            # was written for that and never applied, because the reference was
            # matched against a corrupted spelling of the arrow that no finding
            # ever carries. The penalty stays on flow-scoped findings alone: a
            # weakness in a component's own configuration is no less true because
            # the paths drawn around it were guessed.
            if flow and flow.assumed:
                score -= 0.12
            if not threat.root_cause or not (threat.attack_scenario or threat.realistic_attack_scenario):
                score -= 0.05
            direct = bool(sources & DIRECT_SOURCES) or threat.finding_type in {"code", "iac"}
            if not direct and threat.explanation and threat.explanation.get("local_stride_review", {}).get("decision"):
                review = threat.explanation["local_stride_review"]
                if review.get("predicted_category") not in {None, "Unknown", threat.stride_category, threat.category}:
                    score -= 0.05
            score = round(min(0.99, max(0.05, score)), 2)

            control_state = (threat.explanation or {}).get("control_state")
            matched = (threat.explanation or {}).get("matched_controls") or []
            conflicting = any(
                control_value(components[component_id].properties or {}, field) == "conflicting"
                for component_id in (threat.affected_components or []) if component_id in components
                for field in matched
            )
            if conflicting:
                control_state = "conflicting"
            unresolved = control_state in {"unknown", "partial", "conflicting"}
            if unresolved:
                score = min(score, 0.74)
            if declared_issue and not unresolved:
                score = max(score, 0.9)

            label = "High" if score >= 0.8 else "Medium" if score >= 0.55 else "Low"
            threat.confidence_score = score
            threat.confidence = label
            threat.tier = "Confirmed" if direct and score >= 0.8 and not unresolved else "Potential"
            threat.explanation = {
                **(threat.explanation or {}),
                "control_state": control_state,
                "evidence_basis": "conflicting_sources" if conflicting else "user_declared" if declared_issue or reviewer_evidence else "static_evidence" if sources & {"code", "iac", "static_analysis"} else "stated_architecture" if direct else "inferred",
                "verification_status": "not_runtime_verified",
                "confidence_calibration": {
                    "score": score,
                    "label": label,
                    "direct_evidence": direct,
                    "evidence_sources": sorted(sources),
                    "scoped": scoped,
                    "assumed_flow": bool(flow and flow.assumed),
                    "version": "confidence-1.0",
                    "method": "evidence_policy",
                    "is_probability": False,
                },
            }
            distribution[f"{threat.tier}:{label}"] += 1

        return threats, {
            "status": "active",
            "method": "evidence_policy",
            "is_probability": False,
            "version": "confidence-1.0",
            "distribution": dict(distribution),
            "policy": (
            "Confirmed requires direct evidence and confidence score >= 0.80. An explicit "
            "source weakness may remain confirmed while its component mapping is separately "
            "flagged for review."
        ),
        }
