"""Truthful local semantic retrieval and STRIDE classification integration."""

from __future__ import annotations

import re
from threading import Lock
from typing import Any, Dict, List, Tuple

from .stride_coverage_engine import STRIDE_CATEGORIES
from .local_challenger import LocalChallenger
from .structured_local_slm import StructuredLocalSLM
from .retrieval_quality import architecture_retrieval_requests


class LocalIntelligence:
    def __init__(self, knowledge_base):
        self.knowledge_base = knowledge_base
        self.matcher = None
        self.classifier = None
        self.initialization_errors: List[str] = []
        self.challenger = LocalChallenger()
        self.structured_slm = None
        self._initialized = False
        self._initialization_lock = Lock()

    def _ensure_initialized(self) -> None:
        with self._initialization_lock:
            if self._initialized:
                return
            self._initialize()
            self.structured_slm = StructuredLocalSLM()
            self._initialized = True

    def _initialize(self) -> None:
        try:
            from .semantic_matcher import get_semantic_matcher
            self.matcher = get_semantic_matcher()
            self.matcher.vectorize_knowledge_base(self.knowledge_base.get_all_threats())
        except Exception as exc:
            self.initialization_errors.append(f"semantic matcher: {exc}")
        try:
            from .stride_classifier import get_stride_classifier
            self.classifier = get_stride_classifier()
            if self.classifier.is_available:
                self.classifier.load_or_train(self.knowledge_base.get_all_threats())
        except Exception as exc:
            self.initialization_errors.append(f"STRIDE classifier: {exc}")

    def enrich(self, architecture, threats, enabled: bool = True) -> Tuple[List, Dict[str, Any]]:
        if not enabled:
            return threats, {
                "status": "disabled", "semantic_retrieval": "disabled",
                "stride_classifier": "disabled", "retrieved_candidates": 0,
            }

        self._ensure_initialized()
        retrieved, retrieval_diagnostics = self._retrieve(architecture)
        retrieved_by_id = {str(item.get("id")): item for item in retrieved}
        classified = 0
        conflicts = 0
        classifier_ready = bool(self.classifier and self.classifier.is_trained)
        for threat in threats:
            normalized_id = re.sub(r"^KB-", "", str(threat.id or ""))
            retrieved_rule = next(
                (item for rule_id, item in retrieved_by_id.items()
                 if normalized_id == rule_id or normalized_id.startswith(f"{rule_id}-")),
                None,
            )
            if retrieved_rule:
                threat.explanation = dict(threat.explanation or {})
                threat.explanation["retrieval_provenance"] = {
                    "rule_id": retrieved_rule.get("id"),
                    "retrieval_score": retrieved_rule.get("retrieval_score"),
                    "semantic_score": retrieved_rule.get("semantic_score"),
                    "lexical_score": retrieved_rule.get("lexical_score"),
                    "fusion_score": retrieved_rule.get("fusion_score"),
                    "retrieval_sources": retrieved_rule.get("retrieval_sources") or {},
                    "reranker_backend": retrieved_rule.get("reranker_backend"),
                    "calibrated_threshold": retrieved_rule.get("calibrated_threshold"),
                    "retrieved_for": retrieved_rule.get("retrieved_for") or [],
                    "rule_provenance": retrieved_rule.get("rule_provenance"),
                }
            text = f"{threat.title}. {threat.description}. {threat.root_cause or ''}"
            scores = {}
            predicted = "Unknown"
            if classifier_ready:
                predicted, scores = self.classifier.predict(text)
            elif self.matcher:
                try:
                    scores = self.matcher.classify_stride(text)
                    predicted = max(scores, key=scores.get) if scores and max(scores.values()) > 0 else "Unknown"
                except Exception:
                    scores = {}
            if predicted != "Unknown":
                classified += 1
                deterministic = threat.stride_category or threat.category
                if predicted != deterministic and scores.get(predicted, 0) >= 0.65:
                    conflicts += 1
                threat.explanation = threat.explanation or {}
                threat.explanation["local_stride_review"] = {
                    "deterministic_category": deterministic,
                    "predicted_category": predicted,
                    "scores": {key: round(value, 4) for key, value in scores.items()},
                    "decision": "deterministic category retained; classifier is advisory",
                }

        embedding_service = getattr(self.matcher, "_embedding_service", None) if self.matcher else None
        embedding_backend = getattr(embedding_service, "backend", "unavailable")
        full_embeddings = embedding_backend == "sentence_transformer"
        retrieval_engine = self.matcher.diagnostics() if self.matcher else {}
        reranker_status = retrieval_engine.get("reranker") or {}
        reranker_ready = not reranker_status.get("model") or reranker_status.get("loaded") is True
        status = "active" if full_embeddings and classifier_ready and reranker_ready else "degraded"
        if not self.matcher and not self.classifier:
            status = "unavailable"
        challenger = self.challenger.challenge(architecture, threats, retrieved)
        challenger["structured_slm"] = self.structured_slm.review(architecture, threats)
        diagnostics = {
            "status": status,
            "semantic_retrieval": "active" if full_embeddings else "hybrid_fallback" if self.matcher else "lexical_fallback",
            "embedding_backend": embedding_backend,
            "retrieval_engine": retrieval_engine,
            "stride_classifier": "active" if classifier_ready else "advisory_zero_shot" if self.matcher else "unavailable",
            "retrieved_candidates": len(retrieved),
            "candidate_threat_ids": [item["id"] for item in retrieved[:50]],
            "retrieval_domains": sorted(getattr(self.matcher, "_domain_stores", {}).keys()) if self.matcher else [],
            "reranker": getattr(getattr(self.matcher, "_reranker", None), "backend", "unavailable"),
            **retrieval_diagnostics,
            "findings_reviewed": classified,
            "classification_conflicts": conflicts,
            "errors": self.initialization_errors,
            "challenger": challenger,
            "claim": "Semantic models rank and review candidates; deterministic evidence rules decide findings.",
        }
        return threats, diagnostics

    def _retrieve(self, architecture) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        candidates: Dict[str, Dict[str, Any]] = {}
        retrieved_by_element: Dict[str, Dict[str, int]] = {}
        requests = architecture_retrieval_requests(architecture, STRIDE_CATEGORIES)
        payloads = [request.__dict__ for request in requests]
        batches = [[] for _ in requests]
        if self.matcher:
            try:
                batches = self.matcher.find_relevant_threats_batch(payloads)
            except Exception as exc:
                self.initialization_errors.append(f"batch retrieval: {exc}")

        for request, results in zip(requests, batches):
            element_id = (
                request.scope.get("component_id")
                if request.scope.get("kind") == "component"
                else f"flow:{request.scope.get('source_id')}->{request.scope.get('target_id')}"
            )
            retrieved_by_element.setdefault(element_id, {category: 0 for category in STRIDE_CATEGORIES})
            if not results:
                results = [
                    ({"original": item}, score)
                    for item, score in self._lexical_candidates(
                        request.query, request.component_type or "Any", None,
                    )
                ]
            accepted = 0
            for metadata, score in results:
                original = metadata.get("original") or metadata
                threshold = float(metadata.get("calibrated_threshold") or 0.3)
                if score < threshold:
                    continue
                item = dict(original)
                previous = candidates.get(item["id"], {})
                item["retrieval_score"] = max(float(score), previous.get("retrieval_score", 0))
                for field in (
                    "semantic_score", "lexical_score", "fusion_score", "fusion_weights",
                    "retrieval_sources", "reranker_score", "reranker_backend",
                    "hard_negative_reasons", "rule_provenance", "calibrated_threshold",
                    "document_chunk",
                ):
                    item[field] = metadata.get(field)
                item_category = item.get("stride_category") or item.get("category") or "Unknown"
                scope_key = f"{request.request_id}:{item_category}"
                item["retrieved_for"] = sorted(set([
                    *(previous.get("retrieved_for") or []), scope_key,
                ]))
                item["retrieval_scores_by_scope"] = {
                    **(previous.get("retrieval_scores_by_scope") or {}),
                    scope_key: max(
                        float(score),
                        float((previous.get("retrieval_scores_by_scope") or {}).get(scope_key, 0)),
                    ),
                }
                item["retrieval_scope"] = request.scope
                candidates[item["id"]] = item
                accepted += 1
                if item_category in retrieved_by_element[element_id]:
                    retrieved_by_element[element_id][item_category] += 1

        ranked = sorted(candidates.values(), key=lambda item: item.get("retrieval_score", 0), reverse=True)
        diagnostics = {
            "retrieval_strategy": "structured graph-aware per-element STRIDE retrieval with domain indexes, BM25, dense vectors, RRF, calibration, and batch reranking",
            "retrieval_queries": len(requests),
            "retrieval_query_batches": 1 if requests else 0,
            "retrieval_by_element": retrieved_by_element,
        }
        return ranked, diagnostics

    def _lexical_candidates(self, query: str, component_type: str, category: str | None = None) -> List[Tuple[Dict[str, Any], float]]:
        query_tokens = _tokens(query)
        ranked = []
        for threat in self.knowledge_base.get_all_threats():
            if category and (threat.get("stride_category") or threat.get("category")) != category:
                continue
            components = {str(value).lower() for value in threat.get("components") or []}
            component_match = "any" in components or component_type.lower() in components
            threat_tokens = _tokens(" ".join([
                threat.get("title", ""), threat.get("description", ""),
                " ".join(threat.get("tags") or []), " ".join(threat.get("components") or []),
            ]))
            overlap = len(query_tokens & threat_tokens)
            if component_match or overlap:
                score = min(0.75, (0.3 if component_match else 0) + overlap * 0.08)
                ranked.append((threat, score))
        ranked.sort(key=lambda item: item[1], reverse=True)
        return ranked[:12]


def _tokens(value: str) -> set[str]:
    stop = {"the", "and", "for", "with", "from", "service", "component", "data"}
    return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2 and token not in stop}
