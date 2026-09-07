import json
from pathlib import Path
from types import SimpleNamespace

from app.engine.retrieval_quality import (
    RetrievalCalibrator,
    RetrievalFeedbackStore,
    RetrievalMonitor,
    architecture_retrieval_requests,
    audit_knowledge_rules,
    hierarchical_chunks,
    rule_provenance,
)
from app.engine.stride_coverage_engine import STRIDE_CATEGORIES
from app.knowledge_base.loader import ThreatKnowledgeBase
from app.models import Asset, Component, DataFlow, SystemArchitecture, TrustBoundary
from app.retrieval_training import build_security_retrieval_dataset


def test_governed_dataset_covers_every_valid_knowledge_rule():
    rules = ThreatKnowledgeBase().get_all_threats()
    training, evaluation, manifest = build_security_retrieval_dataset(rules)

    assert len(training) >= len(rules) * 3
    assert len(evaluation) >= len(rules) * 3
    assert manifest["missing_rule_ids"] == []
    assert set(manifest["stride_coverage"]) == set(STRIDE_CATEGORIES)
    assert all(item["positive_id"] != item["negative_id"] for item in training)


def test_hierarchical_chunks_preserve_section_and_sentence_boundaries():
    text = "# Identity\n" + "OAuth tokens are validated. " * 30 + "\n# Storage\nS3 contains images."
    chunks = hierarchical_chunks(text, max_chars=180, overlap_sentences=1)

    assert len(chunks) > 2
    assert {item["section"] for item in chunks} == {"Identity", "Storage"}
    assert all(item["sha256"] and item["text"].startswith("Section:") for item in chunks)


def test_structured_queries_include_graph_assets_boundaries_and_controls():
    architecture = SystemArchitecture(
        components=[
            Component(id="web", name="Portal", type="WebClient", trust_level="public"),
            Component(id="api", name="Orders API", type="API", properties={"auth_type": "oidc"}),
        ],
        flows=[DataFlow(source_id="web", target_id="api", protocol="https", data_type="orders")],
        trust_boundaries=[TrustBoundary(name="Internet", boundary_type="external", components=["web"])],
        assets=[Asset(name="Orders", sensitivity="confidential", location="api", related_component_id="api")],
    )
    requests = architecture_retrieval_requests(architecture, ["Spoofing"])
    api_query = next(item.query for item in requests if item.request_id == "api")

    assert "auth_type=oidc" in api_query
    assert "Orders:confidential" in api_query
    assert "Portal -> Orders API over https" in api_query
    assert "reachable attack routes Portal -> Orders API" in api_query


def test_feedback_requires_separate_approval_before_training(tmp_path):
    store = RetrievalFeedbackStore(tmp_path / "feedback.jsonl")
    recorded = store.record({
        "decision": "accepted", "finding_id": "AWS-S3-001",
        "finding": {"rule_id": "AWS-S3-001"}, "query": "public bucket",
    })
    assert store.approved_training_records() == []

    store.approve(recorded["feedback_id"], "security-reviewer")
    assert [item["feedback_id"] for item in store.approved_training_records()] == [recorded["feedback_id"]]


def test_calibration_requires_enough_approved_examples(tmp_path):
    calibrator = RetrievalCalibrator(tmp_path / "calibration.json")
    records = [
        {"decision": "accepted", "retrieval_score": 0.7, "security_domains": ["aws"], "stride_category": "Tampering"},
        {"decision": "false_positive", "retrieval_score": 0.35, "security_domains": ["aws"], "stride_category": "Tampering"},
    ] * 3
    report = calibrator.fit(records, minimum_examples=5)

    assert 0.35 <= report["thresholds"]["domain:aws"] <= 0.7
    assert calibrator.threshold(["aws"], "Tampering") == 0.3
    assert report["status"] == "candidate_only"
    assert not (tmp_path / "calibration.json").exists()
    assert (tmp_path / "calibration.candidate.json").exists()
    assert report["diagnostics"]["domain:aws"]["precision"] == 1.0
    assert report["diagnostics"]["stride:Tampering"]["false_positive_rate"] == 0.0


def test_knowledge_audit_finds_duplicate_and_signal_contradiction():
    base = {
        "stride_category": "Spoofing", "components": ["API"],
        "description": "Tokens are accepted without signature validation",
    }
    report = audit_knowledge_rules([
        {**base, "id": "A", "title": "JWT signature missing", "applicability": {"required_signals": ["unsigned jwt"]}},
        {**base, "id": "B", "title": "JWT signature missing", "applicability": {"excluded_signals": ["unsigned jwt"]}},
    ])
    assert report["near_duplicate_count"] == 1
    assert report["contradiction_count"] == 1


def test_rule_provenance_changes_when_rule_content_changes():
    first = rule_provenance({"id": "R1", "title": "A", "description": "one"})
    second = rule_provenance({"id": "R1", "title": "A", "description": "two"})
    assert first["rule_version"] != second["rule_version"]


def test_retrieval_monitor_reports_latency_and_fallback_rate():
    monitor = RetrievalMonitor()
    monitor.record(latency_ms=10, results=2, fallback=False, cache="loaded")
    monitor.record(latency_ms=30, results=1, fallback=True, cache="miss")
    report = monitor.snapshot()
    assert report["queries"] == 2
    assert report["fallback_rate"] == 0.5
    assert report["latency_ms"]["p95"] == 30
