"""An analysis must not reach the network, and must say which models backed it.

"Runs entirely on your machine" is the product's main differentiator, so the
loading policy is treated as a requirement rather than a convention.
"""

import ast
from pathlib import Path

import pytest

from app.engine import model_policy

ENGINE_DIR = Path(model_policy.__file__).parent

# Constructors that will silently download weights unless told otherwise.
DOWNLOADING_CONSTRUCTORS = {"SentenceTransformer", "CrossEncoder", "pipeline", "from_pretrained"}


def _model_loading_calls(path: Path):
    """Yield (function name, keywords) for every model construction in a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name not in DOWNLOADING_CONSTRUCTORS:
            continue
        keywords = {keyword.arg for keyword in node.keywords}
        # `pipeline` is both a constructor and the callable it returns; only the
        # former names a model to resolve.
        if name == "pipeline" and "model" not in keywords:
            continue
        yield name, keywords


@pytest.mark.parametrize("module", sorted(ENGINE_DIR.glob("*.py")), ids=lambda path: path.name)
def test_no_engine_loads_a_model_without_the_offline_policy(module):
    """Every loader must route through model_policy, which enforces offline mode."""
    for name, keywords in _model_loading_calls(module):
        assert keywords & {"local_files_only", "cache_dir", "cache_folder", "revision"} or "**" in keywords or None in keywords, (
            f"{module.name} calls {name} without the model policy; it may download at analysis time"
        )


def test_offline_is_the_default():
    assert model_policy.downloads_allowed() is False
    assert model_policy.sentence_transformer_kwargs("any-model")["local_files_only"] is True
    assert model_policy.transformers_kwargs("any-model")["local_files_only"] is True


def test_downloads_require_an_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD", "1")
    assert model_policy.downloads_allowed() is True
    assert model_policy.sentence_transformer_kwargs("any-model")["local_files_only"] is False


def test_the_embedding_model_is_pinned_to_a_recorded_revision():
    from app.engine.embedding_service import EmbeddingService

    revision = model_policy.locked_revision(EmbeddingService.DEFAULT_MODEL)
    assert revision, "the default embedding model should be pinned in model_locks.json"
    assert len(revision) == 40 and all(character in "0123456789abcdef" for character in revision), (
        "a pin must be a full commit hash, not a mutable tag"
    )
    assert model_policy.sentence_transformer_kwargs(EmbeddingService.DEFAULT_MODEL)["revision"] == revision


def test_a_cache_directory_is_passed_through_when_configured(monkeypatch):
    monkeypatch.setenv("AEGIS_THREAT_MODEL_CACHE", "/opt/aegis/models")
    assert model_policy.sentence_transformer_kwargs("any")["cache_folder"] == "/opt/aegis/models"
    assert model_policy.transformers_kwargs("any")["cache_dir"] == "/opt/aegis/models"


def test_a_report_states_which_models_backed_it():
    model_policy.reset_status_for_tests()
    model_policy.note_model("all-MiniLM-L6-v2", "embeddings", loaded=True)
    model_policy.note_model(
        "cross-encoder/ms-marco", "reranker", loaded=False,
        error="not found locally\nlong guidance follows", fallback="security_feature_reranker",
    )

    status = model_policy.model_status()

    assert status["offline_enforced"] is True
    assert status["status"] == "degraded"
    assert status["degraded_roles"] == ["reranker"]
    reranker = next(entry for entry in status["models"] if entry["role"] == "reranker")
    assert reranker["fallback"] == "security_feature_reranker"
    assert "\n" not in reranker["error"], "multi-line loader guidance should be trimmed for the report"


def test_a_missing_embedding_model_degrades_instead_of_failing(monkeypatch):
    """A restricted network must cost retrieval quality, not the analysis."""
    from app.engine import embedding_service

    monkeypatch.setattr(
        embedding_service, "SentenceTransformer",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("model not found locally")),
        raising=False,
    )
    model_policy.reset_status_for_tests()

    service = embedding_service.EmbeddingService()

    assert service.model is None
    assert service.is_available, "the TF-IDF fallback still produces vectors"
    status = model_policy.model_status()
    assert status["degraded_roles"] == ["embeddings"]
    assert next(entry for entry in status["models"] if entry["role"] == "embeddings")["fallback"] == "bm25_local_hashing"
