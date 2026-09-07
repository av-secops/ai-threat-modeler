"""Local lexical retrieval and rank fusion for security knowledge records."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple


_TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.:/-]*")
_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "component", "data",
    "for", "from", "in", "is", "of", "on", "or", "service", "that", "the",
    "this", "to", "uses", "with",
}


def security_tokens(value: str) -> List[str]:
    """Tokenize prose while retaining identifiers such as sts:AssumeRole."""
    tokens: List[str] = []
    for raw in _TOKEN_PATTERN.findall(str(value or "").lower()):
        if raw not in _STOP_WORDS:
            tokens.append(raw)
        if any(separator in raw for separator in (".", "_", ":", "/", "-")):
            tokens.extend(
                part for part in re.split(r"[._:/-]+", raw)
                if len(part) > 1 and part not in _STOP_WORDS
            )
    return tokens


class BM25Index:
    """Small in-memory Okapi BM25 index suited to the bundled threat catalog."""

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.metadata: List[Dict[str, Any]] = []
        self._documents: List[Counter[str]] = []
        self._lengths: List[int] = []
        self._document_frequency: Counter[str] = Counter()
        self._average_length = 0.0

    def build(self, documents: Sequence[str], metadata: Sequence[Dict[str, Any]]) -> None:
        if len(documents) != len(metadata):
            raise ValueError("BM25 documents and metadata must have the same length")
        self.metadata = [dict(item) for item in metadata]
        tokenized = [security_tokens(document) for document in documents]
        self._documents = [Counter(tokens) for tokens in tokenized]
        self._lengths = [len(tokens) for tokens in tokenized]
        self._document_frequency = Counter()
        for document in self._documents:
            self._document_frequency.update(document.keys())
        self._average_length = (
            sum(self._lengths) / len(self._lengths) if self._lengths else 0.0
        )

    def search(self, query: str, top_k: int = 10) -> List[Tuple[Dict[str, Any], float]]:
        if not self.metadata or top_k <= 0:
            return []
        query_terms = Counter(security_tokens(query))
        if not query_terms:
            return []
        scores = [self._score(query_terms, index) for index in range(len(self.metadata))]
        ranked = [index for index in sorted(range(len(scores)), key=scores.__getitem__, reverse=True) if scores[index] > 0]
        ranked = ranked[: min(top_k, len(ranked))]
        if not ranked:
            return []
        top_score = scores[ranked[0]] or 1.0
        return [(self.metadata[index], scores[index] / top_score) for index in ranked]

    def _score(self, query_terms: Counter[str], index: int) -> float:
        document = self._documents[index]
        document_length = self._lengths[index]
        count = len(self._documents)
        score = 0.0
        for term, query_frequency in query_terms.items():
            frequency = document.get(term, 0)
            if not frequency:
                continue
            document_frequency = self._document_frequency[term]
            inverse_frequency = math.log(1 + (count - document_frequency + 0.5) / (document_frequency + 0.5))
            normalizer = frequency + self.k1 * (
                1 - self.b + self.b * document_length / (self._average_length or 1.0)
            )
            score += inverse_frequency * frequency * (self.k1 + 1) / normalizer * (1 + math.log(query_frequency))
        return score

    @property
    def size(self) -> int:
        return len(self.metadata)


def reciprocal_rank_fusion(
    rankings: Sequence[Tuple[str, Sequence[Tuple[Dict[str, Any], float]], float]],
    identity: Callable[[Dict[str, Any]], str],
    rank_constant: int = 60,
) -> List[Tuple[Dict[str, Any], float]]:
    """Fuse independently ranked lists and retain source-specific diagnostics."""
    records: Dict[str, Dict[str, Any]] = {}
    total_weight = sum(max(0.0, weight) for _, _, weight in rankings)
    maximum = total_weight / (rank_constant + 1) if total_weight else 1.0

    for source, results, weight in rankings:
        if weight <= 0:
            continue
        seen = set()
        for rank, (metadata, source_score) in enumerate(results, 1):
            item_id = identity(metadata)
            if not item_id or item_id in seen:
                continue
            seen.add(item_id)
            record = records.setdefault(item_id, {
                "metadata": dict(metadata), "score": 0.0, "sources": {},
            })
            record["score"] += weight / (rank_constant + rank)
            record["sources"][source] = {
                "rank": rank, "score": round(float(source_score), 6),
            }

    fused = []
    for record in records.values():
        metadata = dict(record["metadata"])
        metadata["retrieval_sources"] = record["sources"]
        metadata["fusion_score"] = round(min(1.0, record["score"] / maximum), 6)
        fused.append((metadata, metadata["fusion_score"]))
    return sorted(fused, key=lambda item: item[1], reverse=True)
