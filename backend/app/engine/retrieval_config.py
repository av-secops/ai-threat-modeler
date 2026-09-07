"""Configuration for the local threat-retrieval pipeline.

Profiles provide useful defaults without hiding the exact models that backed an
analysis. Environment overrides remain available for controlled deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class RetrievalProfile:
    name: str
    embedding_model: str
    reranker_model: Optional[str]
    dense_weight: float
    lexical_weight: float
    candidate_multiplier: int


PROFILES = {
    "fast": RetrievalProfile(
        name="fast",
        embedding_model="all-MiniLM-L6-v2",
        reranker_model=None,
        dense_weight=0.45,
        lexical_weight=0.55,
        candidate_multiplier=4,
    ),
    "balanced": RetrievalProfile(
        name="balanced",
        embedding_model="BAAI/bge-base-en-v1.5",
        reranker_model=None,
        dense_weight=0.62,
        lexical_weight=0.38,
        candidate_multiplier=6,
    ),
    "accuracy": RetrievalProfile(
        name="accuracy",
        embedding_model="BAAI/bge-large-en-v1.5",
        reranker_model="BAAI/bge-reranker-base",
        dense_weight=0.68,
        lexical_weight=0.32,
        candidate_multiplier=8,
    ),
}

_DISABLED = {"", "0", "off", "none", "disabled", "false"}
LOCAL_SECURITY_MODEL = Path(__file__).resolve().parents[2] / "models" / "aegis-bge-security-v1"


def configured_profile() -> RetrievalProfile:
    name = os.getenv("AEGIS_THREAT_RETRIEVAL_PROFILE", "balanced").strip().lower()
    return PROFILES.get(name, PROFILES["balanced"])


def configured_embedding_model() -> str:
    configured = os.getenv("AEGIS_THREAT_EMBEDDING_MODEL", "").strip()
    if configured:
        return configured
    if configured_profile().name == "balanced" and LOCAL_SECURITY_MODEL.exists():
        return str(LOCAL_SECURITY_MODEL)
    return configured_profile().embedding_model


def configured_reranker_model() -> Optional[str]:
    configured = os.getenv("AEGIS_THREAT_RERANKER_MODEL")
    if configured is None:
        return configured_profile().reranker_model
    value = configured.strip()
    return None if value.lower() in _DISABLED else value


def fusion_weights(dense_backend: str) -> tuple[float, float]:
    """Return normalized dense/lexical weights, reducing trust in hash vectors."""
    profile = configured_profile()
    dense = _float_env("AEGIS_THREAT_DENSE_WEIGHT", profile.dense_weight)
    lexical = _float_env("AEGIS_THREAT_LEXICAL_WEIGHT", profile.lexical_weight)
    if dense_backend != "sentence_transformer":
        dense = min(dense, 0.25)
        lexical = max(lexical, 0.75)
    total = dense + lexical
    return (dense / total, lexical / total) if total > 0 else (0.5, 0.5)


def _float_env(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.getenv(name, str(default))))
    except ValueError:
        return default
