from types import SimpleNamespace

import numpy as np

from app.engine.hybrid_retrieval import BM25Index, reciprocal_rank_fusion, security_tokens
from app.engine.retrieval_config import (
    LOCAL_SECURITY_MODEL,
    configured_embedding_model,
    configured_profile,
    configured_reranker_model,
    fusion_weights,
)
from app.engine.semantic_matcher import SemanticThreatMatcher


def test_security_tokenizer_preserves_cloud_and_framework_identifiers():
    tokens = security_tokens("CWE-89 through sts:AssumeRole and s3:GetObject")

    assert "cwe-89" in tokens
    assert "sts:assumerole" in tokens
    assert "s3:getobject" in tokens
    assert {"cwe", "89", "sts", "assumerole", "s3", "getobject"}.issubset(tokens)


def test_bm25_prioritizes_exact_security_identifiers():
    index = BM25Index()
    index.build([
        "AWS role allows sts:AssumeRole across accounts",
        "Generic session timeout weakness",
        "S3 bucket permits s3:GetObject to a public principal",
    ], [{"id": "iam"}, {"id": "session"}, {"id": "s3"}])

    results = index.search("Review sts:AssumeRole trust policy", top_k=2)

    assert results[0][0]["id"] == "iam"
    assert results[0][1] == 1.0


def test_reciprocal_rank_fusion_rewards_candidates_found_by_both_engines():
    dense = [({"id": "shared"}, 0.8), ({"id": "dense-only"}, 0.7)]
    lexical = [({"id": "lexical-only"}, 1.0), ({"id": "shared"}, 0.8)]

    results = reciprocal_rank_fusion([
        ("dense", dense, 0.6), ("bm25", lexical, 0.4),
    ], identity=lambda item: item["id"])

    assert results[0][0]["id"] == "shared"
    assert set(results[0][0]["retrieval_sources"]) == {"dense", "bm25"}
    assert 0 < results[0][0]["fusion_score"] <= 1


def test_balanced_profile_uses_bge_models_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_THREAT_RETRIEVAL_PROFILE", raising=False)
    monkeypatch.delenv("AEGIS_THREAT_EMBEDDING_MODEL", raising=False)
    monkeypatch.delenv("AEGIS_THREAT_RERANKER_MODEL", raising=False)

    assert configured_profile().name == "balanced"
    expected = str(LOCAL_SECURITY_MODEL) if LOCAL_SECURITY_MODEL.exists() else "BAAI/bge-base-en-v1.5"
    assert configured_embedding_model() == expected
    assert configured_reranker_model() is None


def test_hash_fallback_shifts_fusion_weight_to_lexical_search(monkeypatch):
    monkeypatch.setenv("AEGIS_THREAT_RETRIEVAL_PROFILE", "balanced")

    dense, lexical = fusion_weights("local_hashing")

    assert dense <= 0.25
    assert lexical >= 0.75
    assert round(dense + lexical, 8) == 1.0


def test_vector_store_rejects_embeddings_from_another_model_dimension():
    from app.engine.embedding_service import VectorStore

    store = VectorStore(768)

    try:
        store.add(np.zeros((1, 384), dtype=np.float32), [{"id": "wrong-model"}])
    except ValueError as exc:
        assert "does not match index dimension" in str(exc)
    else:
        raise AssertionError("a vector index must reject embeddings from another model")


def test_matchers_do_not_share_vector_indexes(monkeypatch):
    from app.engine.embedding_service import VectorStore

    class StubEmbedding:
        dimension = 3

    monkeypatch.setattr(
        "app.engine.embedding_service.get_embedding_service",
        lambda: StubEmbedding(),
    )

    first = SemanticThreatMatcher()
    second = SemanticThreatMatcher()

    assert isinstance(first._vector_store, VectorStore)
    assert isinstance(second._vector_store, VectorStore)
    assert first._vector_store is not second._vector_store


def test_hybrid_matcher_returns_fusion_evidence_without_dense_model(monkeypatch):
    monkeypatch.setenv("AEGIS_THREAT_RERANKER_MODEL", "disabled")
    batch_calls = []
    matcher = SemanticThreatMatcher()
    matcher._embedding_service = SimpleNamespace(
        backend="local_hashing", dimension=3, model_name="fallback",
        query_instruction="", index_signature={"model": "fallback", "dimension": 3},
        embed_batch=lambda texts: np.asarray([[1.0, 0.0, 0.0] for _ in texts], dtype=np.float32),
        embed_query=lambda text: np.asarray([1.0, 0.0, 0.0], dtype=np.float32),
        embed_queries=lambda texts: batch_calls.append(list(texts)) or np.asarray(
            [[1.0, 0.0, 0.0] for _ in texts], dtype=np.float32
        ),
    )
    from app.engine.embedding_service import VectorStore
    matcher._vector_store = VectorStore(3)
    matcher.vectorize_knowledge_base([
        {
            "id": "AWS-IAM-ASSUME-001", "title": "Cross-account role assumption",
            "description": "An overly broad sts:AssumeRole trust policy permits role impersonation.",
            "components": ["Identity Provider"], "stride_category": "Elevation of Privilege",
            "severity": "High", "cloud_platform": ["aws"], "tags": ["iam", "sts:AssumeRole"],
            "applicability": {},
        },
        {
            "id": "SESSION-001", "title": "Long-lived session",
            "description": "A session remains active too long.",
            "components": ["Identity Provider"], "stride_category": "Spoofing",
            "severity": "Medium", "tags": ["session"], "applicability": {},
        },
    ])

    results = matcher.find_relevant_threats(
        "AWS IAM trust policy allows sts:AssumeRole", "Identity Provider",
        top_k=1, stride_category="Elevation of Privilege", cloud_provider="aws",
    )

    assert results[0][0]["threat_id"] == "AWS-IAM-ASSUME-001"
    assert "bm25" in results[0][0]["retrieval_sources"]
    assert results[0][0]["fusion_weights"]["bm25"] >= 0.75
    assert matcher.diagnostics()["strategy"].startswith("BM25 + dense")

    batches = matcher.find_relevant_threats_batch([
        {"query": "IAM trust policy", "component_type": "Identity Provider", "top_k": 1},
        {"query": "session timeout", "component_type": "Identity Provider", "top_k": 1},
    ])
    assert len(batches) == 2
    assert len(batch_calls) == 1
    assert len(batch_calls[0]) == 2
