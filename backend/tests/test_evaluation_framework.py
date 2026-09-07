import json
from pathlib import Path

import pytest

from app.evaluation import (
    assert_thresholds, evaluate_corpus, evaluate_retrieval_corpus, evaluate_semantic_ablation,
    governed_benchmark_records,
    evaluate_stride_classifier_corpus, load_classifier_corpus, load_corpus, load_retrieval_corpus,
    validate_benchmark_manifest,
)


CORPUS = Path(__file__).parent / "fixtures" / "evaluation_corpus.json"
RETRIEVAL_CORPUS = Path(__file__).parent / "fixtures" / "retrieval_corpus.json"
CLASSIFIER_CORPUS = Path(__file__).parent / "fixtures" / "stride_classifier_corpus.json"


@pytest.mark.slow
def test_evaluation_corpus_meets_release_gate():
    report = evaluate_corpus(load_corpus(CORPUS))

    assert report["metrics"]["scenario_count"] >= 8
    assert_thresholds(report, {
        "threat_recall": 1.0,
        "critical_threat_recall": 1.0,
        "architecture_accuracy": 1.0,
        "evidence_rate": 1.0,
        "stride_matrix_completion": 1.0,
        "severity_accuracy": 1.0,
        "component_scope_accuracy": 1.0,
        "evidence_grounding_rate": 1.0,
        "disagreement_surface_rate": 1.0,
    }, {
        "false_positive_rate": 0.0,
        "hallucinated_technology_rate": 0.0,
        "duplicate_finding_rate": 0.0,
    })


def test_corpus_has_negative_expectations_for_hallucinations():
    corpus = load_corpus(CORPUS)
    assert all(item["expected"].get("forbidden_component_terms") for item in corpus)
    assert all("topology" in item["expected"] for item in corpus)


def test_semantic_retrieval_meets_recall_and_hard_negative_gate():
    report = evaluate_retrieval_corpus(load_retrieval_corpus(RETRIEVAL_CORPUS))

    assert report["metrics"]["recall_at_k"] == 1.0
    assert report["metrics"]["precision_at_k"] > 0
    assert report["metrics"]["mean_reciprocal_rank"] >= 0.5
    assert report["metrics"]["mean_ndcg_at_k"] >= 0.5
    assert report["metrics"]["hard_negative_leakage_rate"] == 0.0
    assert report["passed"] is True


def test_stride_classifier_meets_holdout_accuracy_gate():
    report = evaluate_stride_classifier_corpus(load_classifier_corpus(CLASSIFIER_CORPUS))

    assert report["metrics"]["accuracy"] >= 0.9
    assert report["metrics"]["macro_accuracy"] >= 0.9
    assert report["passed"] is True


def test_evaluation_measures_exact_components_flows_paths_tiers_and_latency():
    corpus = [{
        "id": "exact-topology",
        "description": (
            "A React web client sends HTTPS requests to a Node.js API. "
            "The API writes customer records to PostgreSQL over TLS."
        ),
        "expected": {
            "finding_ids": [],
            "component_ids": ["react", "node_js", "postgresql"],
            "flow_edges": [["react", "node_js"], ["node_js", "postgresql"]],
            "topology": {"components": 3, "flows": 2, "boundaries": {"min": 1, "max": 3}},
        },
    }]

    report = evaluate_corpus(corpus, use_local_intelligence=False)

    assert report["metrics"]["component_precision"] == 1.0
    assert report["metrics"]["component_recall"] == 1.0
    assert report["metrics"]["exact_flow_edge_precision"] == 1.0
    assert report["metrics"]["exact_flow_edge_recall"] == 1.0
    assert report["metrics"]["attack_path_validity"] == 1.0
    assert report["metrics"]["confirmed_tier_evidence_precision"] == 1.0
    assert report["metrics"]["latency_p50_ms"] > 0


def test_benchmark_manifest_requires_review_provenance_and_holdout_metadata():
    report = validate_benchmark_manifest([{
        "id": "reviewed-1", "domain": "saas", "source_format": "yaml",
        "reviewed_by": "security-review", "reviewed_at": "2026-08-29",
        "split": "holdout", "scenario_version": "1.0", "expected": {},
    }])

    assert report["valid"] is True
    assert report["holdout_records"] == 1


def test_pipeline_corpus_has_reviewed_governance_metadata():
    corpus = load_corpus(CORPUS)
    manifest = json.loads((CORPUS.parent / "benchmark_manifest.json").read_text(encoding="utf-8"))
    records = governed_benchmark_records(corpus, manifest)
    report = validate_benchmark_manifest(records, minimum_reviewed=len(corpus))

    assert report["valid"] is True
    assert report["records"] == len(corpus)
    assert report["holdout_records"] == len(corpus)


def test_semantic_ablation_requires_measured_recall_gain():
    calls = []

    def fake_evaluator(_corpus, use_local_intelligence):
        calls.append(use_local_intelligence)
        return {"metrics": {
            "threat_recall": 0.9 if use_local_intelligence else 0.8,
            "false_positive_rate": 0.01 if use_local_intelligence else 0.0,
            "latency_p50_ms": 90 if use_local_intelligence else 20,
        }}

    report = evaluate_semantic_ablation([{}], evaluator=fake_evaluator)

    assert calls == [False, True]
    assert report["recommendation"] == "enable"
    assert report["delta"] == {
        "threat_recall": 0.1, "false_positive_rate": 0.01, "latency_p50_ms": 70.0,
    }
