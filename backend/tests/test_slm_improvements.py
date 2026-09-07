import pickle
from types import SimpleNamespace

from app.engine.disagreement_engine import DisagreementEngine
from app.engine.semantic_matcher import (
    SecurityReranker,
    _hard_negative_reasons,
    _threat_domains,
)
from app.models import Component, SystemArchitecture, Threat
from app.training_data import build_training_records, validate_training_records
from app.engine.stride_classifier import StrideClassifier


def _threat(threat_id="TEST-001", category="Tampering", severity="Critical"):
    return Threat(
        id=threat_id,
        category=category,
        stride_category=category,
        affected_stride_categories=[category],
        title="Reviewed threat",
        description="Reviewed threat description",
        severity=severity,
        tier="Confirmed",
        mitigation="Apply the reviewed control.",
        component="api",
        affected_component="api",
        affected_components=["api"],
        evidence_details=[{"source_ref": "K1", "statement": "Explicit known issue"}],
    )


def test_security_domains_keep_aws_and_ai_threats_separate():
    aws = _threat_domains({
        "title": "Public S3 bucket", "components": ["Object Storage"],
        "cloud_platform": ["aws"], "tags": ["s3"],
    })
    ai = _threat_domains({
        "title": "Indirect prompt injection in RAG", "components": ["ML Service"],
        "tags": ["llm", "rag"],
    })

    assert "aws" in aws
    assert "ai_llm" not in aws
    assert "ai_llm" in ai
    assert "aws" not in ai


def test_hard_negative_filter_rejects_incompatible_component_and_cloud():
    threat = {
        "title": "S3 public access",
        "components": ["Object Storage"],
        "cloud_platform": ["aws"],
        "applicability": {},
    }
    reasons = _hard_negative_reasons(
        "Azure PostgreSQL database", threat, "Database", "azure", {"azure", "data"},
    )

    assert "incompatible_component" in reasons
    assert "incompatible_cloud" in reasons


def test_security_reranker_records_backend_and_score(monkeypatch):
    monkeypatch.setenv("AEGIS_THREAT_RERANKER_MODEL", "disabled")
    reranker = SecurityReranker()
    metadata = {
        "original": {
            "title": "JWT session revocation",
            "description": "Sessions remain active after password change",
            "components": ["Identity Provider"],
            "tags": ["jwt", "session"],
            "applicability": {"required_signals": ["password change", "session remains active"]},
        },
    }
    results = reranker.rerank("JWT session remains active after password change", [(metadata, 0.7)])

    assert results[0][0]["reranker_backend"] == "security_feature_reranker"
    assert results[0][0]["reranker_score"] > 0.5


def test_disagreements_become_review_questions_without_overriding_finding():
    finding = _threat()
    finding.explanation = {
        "local_stride_review": {
            "deterministic_category": "Tampering",
            "predicted_category": "Elevation of Privilege",
            "scores": {"Elevation of Privilege": 0.81},
        },
    }
    result = DisagreementEngine().assess([finding], {"challenger": {"review_candidates": []}})

    assert finding.stride_category == "Tampering"
    assert result["status"] == "review_required"
    assert result["items"][0]["question"]
    assert "retained" in result["items"][0]["resolution"]


def test_training_export_contains_positive_negative_and_hallucination_records():
    architecture = SystemArchitecture(
        components=[Component(id="api", name="API", type="API")], flows=[],
    )
    analyzer = SimpleNamespace(analyze_from_text=lambda *args, **kwargs: SimpleNamespace(
        architecture=architecture,
        threats=[_threat()],
    ))
    corpus = [{
        "id": "reviewed", "domain": "saas", "description": "An API has an explicit known issue.",
        "expected": {
            "finding_ids": ["TEST-001"],
            "forbidden_finding_ids": ["AWS-S3-PUBLIC-ACL-001"],
            "forbidden_component_terms": ["s3"],
        },
    }]

    records = build_training_records(corpus, analyzer, "security-review-board")
    validation = validate_training_records(records)

    assert {item["task"] for item in records} == {
        "architecture_extraction", "applicable_threat", "non_applicable_threat", "hallucination_rejection",
    }
    assert validation["record_count"] == 4
    assert all(item["approval"]["status"] == "approved" for item in records)


def test_stride_classifier_rejects_stale_embedding_dimension(tmp_path):
    model_path = tmp_path / "stride_classifier.pkl"
    model_path.write_bytes(pickle.dumps({
        "version": "2.0",
        "model": SimpleNamespace(n_features_in_=128),
        "label_encoder": SimpleNamespace(),
        "accuracy": 1.0,
        "feature_dimension": 128,
        "embedding_model": "fallback",
        "embedding_backend": "local_hashing",
    }))
    classifier = StrideClassifier(str(tmp_path))
    classifier._embedding_service = SimpleNamespace(
        dimension=384, model_name="all-MiniLM-L6-v2", backend="sentence_transformer",
    )

    assert classifier._load_from_cache() is False
    assert classifier.is_trained is False
