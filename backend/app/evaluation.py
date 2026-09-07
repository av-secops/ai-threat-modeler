"""Golden-corpus evaluation for threat-model quality and regressions."""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Sequence

from .engine.analyzer import ThreatAnalyzer
from .engine.stride_coverage_engine import STRIDE_CATEGORIES


@dataclass
class ScenarioScore:
    scenario_id: str
    required_findings: int
    detected_findings: int
    forbidden_findings: int
    architecture_checks: int
    architecture_checks_passed: int
    stride_cells_complete: bool
    grounded_findings: int
    total_findings: int
    critical_severity_checks: int
    critical_severity_passed: int
    component_scope_checks: int
    component_scope_passed: int
    forbidden_technology_checks: int
    hallucinated_technologies: int
    duplicate_findings: int
    stride_checks: Dict[str, int]
    stride_passed: Dict[str, int]
    disagreements: int
    surfaced_disagreements: int
    expected_components: int
    detected_components: int
    predicted_components: int
    expected_flow_edges: int
    detected_flow_edges: int
    predicted_flow_edges: int
    attack_paths_checked: int
    valid_attack_paths: int
    confirmed_tiers_checked: int
    valid_confirmed_tiers: int
    latency_ms: float
    failures: List[str] = field(default_factory=list)

    @property
    def threat_recall(self) -> float:
        return self.detected_findings / self.required_findings if self.required_findings else 1.0

    @property
    def architecture_accuracy(self) -> float:
        return self.architecture_checks_passed / self.architecture_checks if self.architecture_checks else 1.0

    @property
    def evidence_rate(self) -> float:
        return self.grounded_findings / self.total_findings if self.total_findings else 1.0


def load_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Evaluation corpus must be a non-empty JSON array.")
    required = {"id", "description", "expected"}
    for index, scenario in enumerate(corpus):
        missing = required - set(scenario)
        if missing:
            raise ValueError(f"Scenario {index} is missing: {', '.join(sorted(missing))}")
    return corpus


def load_retrieval_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Retrieval corpus must be a non-empty JSON array.")
    for index, scenario in enumerate(corpus):
        missing = {"id", "query", "expected_ids", "forbidden_ids"} - set(scenario)
        if missing:
            raise ValueError(f"Retrieval scenario {index} is missing: {', '.join(sorted(missing))}")
    return corpus


def load_classifier_corpus(path: str | Path) -> List[Dict[str, Any]]:
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("Classifier corpus must be a non-empty JSON array.")
    for index, scenario in enumerate(corpus):
        missing = {"id", "text", "stride_category"} - set(scenario)
        if missing or scenario.get("stride_category") not in STRIDE_CATEGORIES:
            raise ValueError(f"Classifier scenario {index} is invalid.")
    return corpus


def validate_benchmark_manifest(
    records: Sequence[Dict[str, Any]], minimum_reviewed: int = 1,
) -> Dict[str, Any]:
    """Validate provenance and holdout governance independently of test success."""
    required = {
        "id", "domain", "source_format", "reviewed_by", "reviewed_at",
        "split", "scenario_version", "expected",
    }
    issues = []
    ids = set()
    for index, record in enumerate(records):
        missing = required - set(record)
        if missing:
            issues.append(f"record {index} is missing {', '.join(sorted(missing))}")
        record_id = str(record.get("id") or "")
        if record_id in ids:
            issues.append(f"duplicate benchmark id: {record_id}")
        ids.add(record_id)
        if record.get("split") not in {"train", "validation", "holdout"}:
            issues.append(f"{record_id or index} has an invalid split")
        if not str(record.get("reviewed_by") or "").strip():
            issues.append(f"{record_id or index} has no reviewer")
    reviewed = sum(bool(str(item.get("reviewed_by") or "").strip()) for item in records)
    if reviewed < minimum_reviewed:
        issues.append(f"reviewed scenarios {reviewed} is below {minimum_reviewed}")
    return {
        "schema_version": "benchmark-governance-1.0",
        "valid": not issues,
        "records": len(records),
        "reviewed_records": reviewed,
        "holdout_records": sum(item.get("split") == "holdout" for item in records),
        "domains": sorted({str(item.get("domain")) for item in records if item.get("domain")}),
        "source_formats": sorted({str(item.get("source_format")) for item in records if item.get("source_format")}),
        "issues": issues,
    }


def governed_benchmark_records(
    corpus: Sequence[Dict[str, Any]], manifest: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Join expected outputs with separately reviewed benchmark provenance."""
    reviews = {str(item.get("id")): item for item in manifest.get("reviews") or []}
    records = []
    for scenario in corpus:
        scenario_id = str(scenario.get("id") or "")
        review = reviews.get(scenario_id) or {}
        records.append({
            "id": scenario_id,
            "domain": scenario.get("domain"),
            "source_format": review.get("source_format"),
            "reviewed_by": review.get("reviewed_by"),
            "reviewed_at": review.get("reviewed_at"),
            "split": review.get("split"),
            "expected": scenario.get("expected"),
            "scenario_version": review.get("scenario_version"),
        })
    unknown_reviews = sorted(set(reviews) - {str(item.get("id") or "") for item in corpus})
    if unknown_reviews:
        raise ValueError(f"benchmark manifest names unknown scenarios: {', '.join(unknown_reviews)}")
    return records


def evaluate_stride_classifier_corpus(corpus: Sequence[Dict[str, Any]], classifier=None) -> Dict[str, Any]:
    if classifier is None:
        from .engine.stride_classifier import StrideClassifier
        from .knowledge_base.loader import ThreatKnowledgeBase
        classifier = StrideClassifier()
        classifier.load_or_train(ThreatKnowledgeBase().get_all_threats())
    by_category = {category: {"correct": 0, "total": 0} for category in STRIDE_CATEGORIES}
    scenarios = []
    correct = 0
    for item in corpus:
        predicted, scores = classifier.predict(item["text"])
        expected = item["stride_category"]
        matched = predicted == expected
        correct += int(matched)
        by_category[expected]["total"] += 1
        by_category[expected]["correct"] += int(matched)
        scenarios.append({
            "id": item["id"], "expected": expected, "predicted": predicted,
            "correct": matched, "scores": {key: round(value, 4) for key, value in scores.items()},
        })
    per_stride = {
        category: _ratio(values["correct"], values["total"])
        for category, values in by_category.items()
    }
    return {
        "schema_version": "stride-classifier-eval-1.0",
        "metrics": {
            "accuracy": _ratio(correct, len(corpus)),
            "macro_accuracy": round(sum(per_stride.values()) / len(STRIDE_CATEGORIES), 4),
            "per_stride_accuracy": per_stride,
        },
        "scenarios": scenarios,
        "passed": _ratio(correct, len(corpus)) >= 0.9,
    }


def evaluate_retrieval_corpus(
    corpus: Sequence[Dict[str, Any]],
    matcher=None,
    knowledge_base=None,
) -> Dict[str, Any]:
    """Measure semantic candidate recall, rank, and hard-negative leakage."""
    if matcher is None or knowledge_base is None:
        from .engine.semantic_matcher import SemanticThreatMatcher
        from .knowledge_base.loader import ThreatKnowledgeBase
        knowledge_base = knowledge_base or ThreatKnowledgeBase()
        matcher = matcher or SemanticThreatMatcher()
    matcher.vectorize_knowledge_base(knowledge_base.get_all_threats())
    expected_total = 0
    expected_found = 0
    forbidden_total = 0
    forbidden_found = 0
    forbidden_outranked = 0
    reciprocal_rank = 0.0
    retrieved_total = 0
    relevant_retrieved = 0
    normalized_discounted_gain = 0.0
    scenarios = []
    for item in corpus:
        top_k = int(item.get("top_k", 5))
        results = matcher.find_relevant_threats(
            item["query"], item.get("component_type"), top_k,
            item.get("stride_category"), item.get("cloud_provider"),
            item.get("security_domains"),
        )
        ids = [metadata.get("threat_id") for metadata, _ in results]
        expected = item.get("expected_ids") or []
        acceptable = set(expected) | set(item.get("acceptable_ids") or [])
        forbidden = item.get("forbidden_ids") or []
        acceptable_ranks = [ids.index(threat_id) + 1 for threat_id in acceptable if threat_id in ids]
        ranks = [min(acceptable_ranks)] if acceptable_ranks else []
        found_expected = expected if ranks else []
        found_forbidden = [threat_id for threat_id in forbidden if threat_id in ids]
        best_expected_rank = min(ranks) if ranks else math.inf
        outranking_forbidden = [
            threat_id for threat_id in found_forbidden
            if ids.index(threat_id) + 1 < best_expected_rank
        ]
        expected_total += len(expected)
        expected_found += len(found_expected)
        forbidden_total += len(forbidden)
        forbidden_found += len(found_forbidden)
        forbidden_outranked += len(outranking_forbidden)
        reciprocal_rank += 1.0 / min(ranks) if ranks else 0.0
        # Precision@K uses K as the denominator even when the matcher returns
        # fewer candidates, matching the standard information-retrieval metric.
        retrieved_total += top_k
        relevant_retrieved += len(found_expected)
        discounted_gain = sum(1.0 / math.log2(rank + 1) for rank in ranks)
        ideal_count = min(len(expected), top_k)
        ideal_gain = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_count + 1))
        scenario_ndcg = discounted_gain / ideal_gain if ideal_gain else 1.0
        normalized_discounted_gain += scenario_ndcg
        scenarios.append({
            "id": item["id"], "result_ids": ids,
            "missing_expected_ids": [] if found_expected else sorted(expected),
            "leaked_forbidden_ids": found_forbidden,
            "outranking_forbidden_ids": outranking_forbidden,
            "reciprocal_rank": round(1.0 / min(ranks), 4) if ranks else 0.0,
            "ndcg_at_k": round(scenario_ndcg, 4),
        })
    return {
        "schema_version": "retrieval-eval-2.0",
        "metrics": {
            "recall_at_k": _ratio(expected_found, expected_total),
            "precision_at_k": _ratio(relevant_retrieved, retrieved_total),
            "mean_reciprocal_rank": round(reciprocal_rank / len(corpus), 4) if corpus else 1.0,
            "mean_ndcg_at_k": round(normalized_discounted_gain / len(corpus), 4) if corpus else 1.0,
            "hard_negative_leakage_rate": _ratio(forbidden_found, forbidden_total),
            "hard_negative_outrank_rate": _ratio(forbidden_outranked, forbidden_total),
        },
        "scenarios": scenarios,
        "passed": all(
            not item["missing_expected_ids"] and not item["outranking_forbidden_ids"]
            for item in scenarios
        ),
    }


def evaluate_corpus(
    corpus: Sequence[Dict[str, Any]],
    analyzer: ThreatAnalyzer | None = None,
    use_local_intelligence: bool = True,
) -> Dict[str, Any]:
    engine = analyzer or ThreatAnalyzer()
    scores = []
    for scenario in corpus:
        started = time.perf_counter()
        result = engine.analyze_from_text(
            scenario["description"],
            scenario["id"],
            use_local_slm=use_local_intelligence,
            domain_profile=scenario.get("domain", "general"),
        )
        scores.append(_evaluate_scenario(
            scenario, result, latency_ms=(time.perf_counter() - started) * 1000,
        ))

    required = sum(item.required_findings for item in scores)
    detected = sum(item.detected_findings for item in scores)
    total_findings = sum(item.total_findings for item in scores)
    grounded = sum(item.grounded_findings for item in scores)
    architecture_checks = sum(item.architecture_checks for item in scores)
    architecture_passed = sum(item.architecture_checks_passed for item in scores)
    forbidden = sum(item.forbidden_findings for item in scores)
    severity_checks = sum(item.critical_severity_checks for item in scores)
    severity_passed = sum(item.critical_severity_passed for item in scores)
    scope_checks = sum(item.component_scope_checks for item in scores)
    scope_passed = sum(item.component_scope_passed for item in scores)
    technology_checks = sum(item.forbidden_technology_checks for item in scores)
    hallucinated_technologies = sum(item.hallucinated_technologies for item in scores)
    duplicates = sum(item.duplicate_findings for item in scores)
    disagreements = sum(item.disagreements for item in scores)
    surfaced_disagreements = sum(item.surfaced_disagreements for item in scores)
    expected_components = sum(item.expected_components for item in scores)
    detected_components = sum(item.detected_components for item in scores)
    predicted_components = sum(item.predicted_components for item in scores)
    expected_flow_edges = sum(item.expected_flow_edges for item in scores)
    detected_flow_edges = sum(item.detected_flow_edges for item in scores)
    predicted_flow_edges = sum(item.predicted_flow_edges for item in scores)
    attack_paths_checked = sum(item.attack_paths_checked for item in scores)
    valid_attack_paths = sum(item.valid_attack_paths for item in scores)
    confirmed_tiers_checked = sum(item.confirmed_tiers_checked for item in scores)
    valid_confirmed_tiers = sum(item.valid_confirmed_tiers for item in scores)
    latencies = sorted(item.latency_ms for item in scores)
    critical_required = sum(len(item.get("expected", {}).get("critical_finding_ids", [])) for item in corpus)
    critical_detected = 0
    for scenario, score in zip(corpus, scores):
        critical_ids = set(scenario.get("expected", {}).get("critical_finding_ids", []))
        required_ids = set(scenario.get("expected", {}).get("finding_ids", []))
        missing_required = {
            failure.removeprefix("missing finding: ")
            for failure in score.failures if failure.startswith("missing finding: ")
        }
        critical_detected += len((critical_ids & required_ids) - missing_required)

    stride_recall = {
        category: _ratio(
            sum(item.stride_passed.get(category, 0) for item in scores),
            sum(item.stride_checks.get(category, 0) for item in scores),
        )
        for category in STRIDE_CATEGORIES
    }
    metrics = {
        "scenario_count": len(scores),
        "threat_recall": _ratio(detected, required),
        "critical_threat_recall": _ratio(critical_detected, critical_required),
        "precision_proxy": _ratio(detected, detected + forbidden),
        "architecture_accuracy": _ratio(architecture_passed, architecture_checks),
        "component_recall": _ratio(detected_components, expected_components),
        "component_precision": _ratio(detected_components, predicted_components),
        "exact_flow_edge_recall": _ratio(detected_flow_edges, expected_flow_edges),
        "exact_flow_edge_precision": _ratio(detected_flow_edges, predicted_flow_edges),
        "evidence_rate": _ratio(grounded, total_findings),
        "evidence_grounding_rate": _ratio(grounded, total_findings),
        "stride_matrix_completion": _ratio(sum(item.stride_cells_complete for item in scores), len(scores)),
        "stride_recall": stride_recall,
        **{f"stride_recall_{_metric_name(category)}": value for category, value in stride_recall.items()},
        "severity_accuracy": _ratio(severity_passed, severity_checks),
        "component_scope_accuracy": _ratio(scope_passed, scope_checks),
        "false_positive_rate": _ratio(forbidden, total_findings),
        "hallucinated_technology_rate": _ratio(hallucinated_technologies, technology_checks),
        "duplicate_finding_rate": _ratio(duplicates, total_findings),
        "disagreement_surface_rate": _ratio(surfaced_disagreements, disagreements),
        "attack_path_validity": _ratio(valid_attack_paths, attack_paths_checked),
        "confirmed_tier_evidence_precision": _ratio(valid_confirmed_tiers, confirmed_tiers_checked),
        "latency_p50_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "forbidden_findings": forbidden,
    }
    return {
        "schema_version": "threat-eval-2.0",
        "metrics": metrics,
        "scenarios": [{**asdict(item), "threat_recall": round(item.threat_recall, 4),
                       "architecture_accuracy": round(item.architecture_accuracy, 4),
                       "evidence_rate": round(item.evidence_rate, 4)} for item in scores],
        "passed": all(not item.failures for item in scores),
    }


def evaluate_semantic_ablation(
    corpus: Sequence[Dict[str, Any]],
    evaluator: Callable[..., Dict[str, Any]] = evaluate_corpus,
) -> Dict[str, Any]:
    """Compare deterministic-only and semantic-assisted analysis on one corpus."""
    deterministic = evaluator(corpus, use_local_intelligence=False)
    semantic = evaluator(corpus, use_local_intelligence=True)
    left = deterministic["metrics"]
    right = semantic["metrics"]
    recall_gain = round(float(right.get("threat_recall", 0)) - float(left.get("threat_recall", 0)), 4)
    fp_delta = round(float(right.get("false_positive_rate", 0)) - float(left.get("false_positive_rate", 0)), 4)
    latency_delta = round(float(right.get("latency_p50_ms", 0)) - float(left.get("latency_p50_ms", 0)), 2)
    acceptable = recall_gain > 0 and fp_delta <= 0.01
    return {
        "schema_version": "semantic-ablation-1.0",
        "deterministic": left,
        "semantic": right,
        "delta": {
            "threat_recall": recall_gain,
            "false_positive_rate": fp_delta,
            "latency_p50_ms": latency_delta,
        },
        "recommendation": "enable" if acceptable else "deterministic_default",
        "acceptance_rule": "Enable only when recall improves and false-positive rate increases by at most 0.01.",
    }


def assert_thresholds(
    report: Dict[str, Any],
    thresholds: Dict[str, float],
    maximums: Dict[str, float] | None = None,
) -> None:
    failures = []
    for metric, minimum in thresholds.items():
        actual = float(report["metrics"].get(metric, 0))
        if actual < minimum:
            failures.append(f"{metric}={actual:.3f} is below {minimum:.3f}")
    for metric, maximum in (maximums or {}).items():
        actual = float(report["metrics"].get(metric, 1))
        if actual > maximum:
            failures.append(f"{metric}={actual:.3f} exceeds {maximum:.3f}")
    if report["metrics"].get("forbidden_findings", 0):
        failures.append(f"forbidden_findings={report['metrics']['forbidden_findings']}")
    scenario_failures = [
        f"{item['scenario_id']}: {', '.join(item['failures'])}"
        for item in report["scenarios"] if item["failures"]
    ]
    if failures or scenario_failures:
        raise AssertionError("Evaluation quality gate failed:\n" + "\n".join(failures + scenario_failures))


def _evaluate_scenario(
    scenario: Dict[str, Any], result: Any, latency_ms: float = 0.0,
) -> ScenarioScore:
    expected = scenario["expected"]
    findings = result.threats or []
    canonical_ids = {_canonical_finding_id(item.id) for item in findings}
    findings_by_id: Dict[str, List[Any]] = {}
    for item in findings:
        findings_by_id.setdefault(_canonical_finding_id(item.id), []).append(item)
    finding_fingerprints = []
    for item in findings:
        source_refs = tuple(sorted(
            str(detail.get("source_ref") or "") for detail in item.evidence_details or []
        ))
        finding_fingerprints.append((
            _canonical_finding_id(item.id),
            tuple(sorted(item.affected_components or [])),
            tuple(sorted(item.affected_data_flows or [])),
            source_refs,
        ))
    duplicate_findings = len(finding_fingerprints) - len(set(finding_fingerprints))
    required_ids = expected.get("finding_ids", [])
    failures = []
    detected = 0
    for required_id in required_ids:
        if required_id in canonical_ids:
            detected += 1
        else:
            failures.append(f"missing finding: {required_id}")

    forbidden = 0
    for forbidden_id in expected.get("forbidden_finding_ids", []):
        if forbidden_id in canonical_ids:
            forbidden += 1
            failures.append(f"forbidden finding: {forbidden_id}")

    for finding_id in expected.get("confirmed_finding_ids", []):
        if not any(item.tier == "Confirmed" for item in findings_by_id.get(finding_id, [])):
            failures.append(f"finding is not confirmed: {finding_id}")

    component_map = {item.id: item for item in result.architecture.components or []}
    scope_checks = 0
    scope_passed = 0
    for finding_id, expected_terms in expected.get("finding_component_terms", {}).items():
        scope_checks += 1
        scoped = []
        for item in findings_by_id.get(finding_id, []):
            for component_id in item.affected_components or []:
                component = component_map.get(component_id)
                if component:
                    scoped.append(f"{component.id} {component.name} {component.type}".lower())
        if not scoped or not any(term.lower() in " ".join(scoped) for term in expected_terms):
            failures.append(f"incorrect component scope for {finding_id}: expected one of {expected_terms}")
        else:
            scope_passed += 1

    critical_severity_checks = 0
    critical_severity_passed = 0
    for finding_id in expected.get("critical_finding_ids", []):
        critical_severity_checks += 1
        if any(item.severity == "Critical" for item in findings_by_id.get(finding_id, [])):
            critical_severity_passed += 1
        else:
            failures.append(f"critical severity mismatch: {finding_id}")

    expected_known_count = expected.get("known_issue_count")
    if expected_known_count is not None:
        actual_known_count = len((result.architecture.metadata or {}).get("known_issues", []))
        if actual_known_count != expected_known_count:
            failures.append(f"known issue count {actual_known_count} != {expected_known_count}")

    forbidden_ai_types = set(expected.get("forbidden_ai_component_types", []))
    if forbidden_ai_types:
        for item in findings:
            if not (item.id.startswith("KB-AI-") or "Prompt Injection" in item.title or "Inference API" in item.title):
                continue
            component = component_map.get(item.affected_component or item.component or "")
            if component and component.type in forbidden_ai_types:
                failures.append(f"AI finding {item.id} leaked onto {component.type} {component.id}")

    components = result.architecture.components or []
    component_text = " ".join(
        f"{item.id} {item.name} {item.type} {(item.properties or {}).get('technology', '')}"
        for item in components
    ).lower()
    architecture_checks = 0
    architecture_passed = 0
    forbidden_technology_checks = 0
    hallucinated_technologies = 0
    for term in expected.get("component_terms", []):
        architecture_checks += 1
        if _contains_term(component_text, term):
            architecture_passed += 1
        else:
            failures.append(f"missing component term: {term}")
    for term in expected.get("forbidden_component_terms", []):
        architecture_checks += 1
        forbidden_technology_checks += 1
        if not _contains_term(component_text, term):
            architecture_passed += 1
        else:
            hallucinated_technologies += 1
            failures.append(f"invented component term: {term}")

    topology = expected.get("topology", {})
    actual_counts = {
        "components": len(components),
        "flows": len(result.architecture.flows or []),
        "boundaries": len(result.architecture.trust_boundaries or []),
    }
    for key, bounds in topology.items():
        architecture_checks += 1
        minimum = bounds.get("min", bounds) if isinstance(bounds, dict) else bounds
        maximum = bounds.get("max", bounds) if isinstance(bounds, dict) else bounds
        actual = actual_counts[key]
        if minimum <= actual <= maximum:
            architecture_passed += 1
        else:
            failures.append(f"{key} count {actual} outside [{minimum}, {maximum}]")

    expected_component_ids = set(expected.get("component_ids") or [])
    actual_component_ids = {item.id for item in components}
    detected_component_ids = expected_component_ids & actual_component_ids
    evaluated_component_ids = actual_component_ids if "component_ids" in expected else set()
    if expected_component_ids - actual_component_ids:
        failures.append(
            "missing component ids: " + ", ".join(sorted(expected_component_ids - actual_component_ids))
        )
    if evaluated_component_ids - expected_component_ids:
        failures.append(
            "unexpected component ids: " + ", ".join(sorted(evaluated_component_ids - expected_component_ids))
        )

    expected_edges = {
        (str(edge[0]), str(edge[1])) for edge in expected.get("flow_edges", [])
        if isinstance(edge, (list, tuple)) and len(edge) == 2
    }
    actual_edges = {(item.source_id, item.target_id) for item in result.architecture.flows or []}
    detected_edges = expected_edges & actual_edges
    evaluated_edges = actual_edges if "flow_edges" in expected else set()
    if expected_edges - actual_edges:
        failures.append(
            "missing flow edges: " + ", ".join(f"{source}->{target}" for source, target in sorted(expected_edges - actual_edges))
        )
    if evaluated_edges - expected_edges:
        failures.append(
            "unexpected flow edges: " + ", ".join(f"{source}->{target}" for source, target in sorted(evaluated_edges - expected_edges))
        )

    categories = {item.stride_category or item.category for item in findings}
    for item in findings:
        categories.update(item.affected_stride_categories or [])
    stride_checks = {category: 0 for category in STRIDE_CATEGORIES}
    stride_passed = {category: 0 for category in STRIDE_CATEGORIES}
    for category in expected.get("stride_categories", []):
        stride_checks[category] += 1
        if category not in categories:
            failures.append(f"missing STRIDE category: {category}")
        else:
            stride_passed[category] += 1

    coverage = result.stride_coverage or {}
    elements = coverage.get("elements", [])
    cells = coverage.get("cells", [])
    matrix_complete = (
        len(cells) == len(elements) * len(STRIDE_CATEGORIES)
        and all(cell.get("status") in {"finding", "potential", "control_present", "unknown", "not_applicable"} for cell in cells)
    )
    if not matrix_complete:
        failures.append("STRIDE matrix is incomplete")

    grounded = sum(
        1 for item in findings
        if item.evidence_details and all(detail.get("statement") for detail in item.evidence_details)
    )
    if grounded != len(findings):
        failures.append("one or more findings lack structured evidence")

    disagreement_items = (((result.engine_status or {}).get("disagreements") or {}).get("items") or [])
    surfaced_disagreements = sum(bool(item.get("question") and item.get("resolution")) for item in disagreement_items)
    paths = ((result.attack_chains or {}).get("paths") or [])
    valid_paths = sum(
        bool(path.get("entry_point") and (path.get("target") or path.get("target_component_id")) and path.get("hops"))
        and all(hop.get("source") and hop.get("target") and hop.get("evidence_status") for hop in path["hops"])
        for path in paths
    )
    confirmed = [item for item in findings if item.tier == "Confirmed"]
    valid_confirmed = sum(
        bool(item.evidence_details)
        and any(
            detail.get("source_type") in {
                "architecture_input", "known_issue", "iac", "code", "configuration",
            }
            for detail in item.evidence_details
        )
        for item in confirmed
    )

    return ScenarioScore(
        scenario_id=scenario["id"],
        required_findings=len(required_ids),
        detected_findings=detected,
        forbidden_findings=forbidden,
        architecture_checks=architecture_checks,
        architecture_checks_passed=architecture_passed,
        stride_cells_complete=matrix_complete,
        grounded_findings=grounded,
        total_findings=len(findings),
        critical_severity_checks=critical_severity_checks,
        critical_severity_passed=critical_severity_passed,
        component_scope_checks=scope_checks,
        component_scope_passed=scope_passed,
        forbidden_technology_checks=forbidden_technology_checks,
        hallucinated_technologies=hallucinated_technologies,
        duplicate_findings=duplicate_findings,
        stride_checks=stride_checks,
        stride_passed=stride_passed,
        disagreements=len(disagreement_items),
        surfaced_disagreements=surfaced_disagreements,
        expected_components=len(expected_component_ids),
        detected_components=len(detected_component_ids),
        predicted_components=len(evaluated_component_ids),
        expected_flow_edges=len(expected_edges),
        detected_flow_edges=len(detected_edges),
        predicted_flow_edges=len(evaluated_edges),
        attack_paths_checked=len(paths),
        valid_attack_paths=valid_paths,
        confirmed_tiers_checked=len(confirmed),
        valid_confirmed_tiers=valid_confirmed,
        latency_ms=round(latency_ms, 2),
        failures=failures,
    )


def _canonical_finding_id(value: str) -> str:
    normalized = re.sub(r"^KB-", "", str(value or ""))
    normalized = re.sub(r"-(?:K\d+|\d{2}|[a-z][a-z0-9_]*)$", "", normalized, flags=re.IGNORECASE)
    return normalized


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])", text.lower()))


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, math.ceil(len(values) * percentile) - 1))
    return round(float(values[index]), 2)


def _metric_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
