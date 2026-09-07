"""
Semantic Threat Matcher — Uses embeddings + vector search to match
architecture components against the threat knowledge base.

Replaces brute-force rule iteration with:
1. Embedding-based retrieval (top-K relevant threats per component)
2. Zero-shot STRIDE classification
3. Semantic deduplication for LLM merge
"""

import logging
import re
import time
from typing import List, Dict, Tuple, Optional, Any

from . import model_policy
from .hybrid_retrieval import BM25Index, reciprocal_rank_fusion, security_tokens
from .retrieval_config import (
    configured_profile,
    configured_reranker_model,
    fusion_weights,
)
from .retrieval_quality import (
    RetrievalCalibrator,
    hierarchical_chunks,
    retrieval_monitor,
    rule_provenance,
    security_domains_for_text,
)

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


SECURITY_DOMAINS = {
    "aws", "azure", "gcp", "web_api", "identity", "data", "payments",
    "ai_llm", "agent_mcp", "container", "serverless", "infrastructure",
    "supply_chain", "general",
}
SPECIALIST_DOMAINS = {
    "aws", "azure", "gcp", "identity", "payments", "ai_llm", "agent_mcp",
    "container", "serverless", "infrastructure", "supply_chain", "web_api", "data",
}


class SecurityReranker:
    """Second-stage reranker with an optional cross-encoder and safe fallback."""

    DEFAULT_MODEL = "BAAI/bge-reranker-base"

    def __init__(self):
        self.model_name = configured_reranker_model()
        self.model = None
        self.error = None
        if not self.model_name:
            return
        try:
            from sentence_transformers import CrossEncoder
            self.model = CrossEncoder(
                self.model_name, **model_policy.sentence_transformer_kwargs(self.model_name),
            )
            model_policy.note_model(self.model_name, "reranker", loaded=True)
        except Exception as exc:
            self.error = str(exc)
            model_policy.note_model(
                self.model_name, "reranker", loaded=False, error=str(exc),
                fallback="security_feature_reranker",
            )

    @property
    def backend(self) -> str:
        return "cross_encoder" if self.model is not None else "security_feature_reranker"

    @property
    def status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "model": self.model_name,
            "loaded": self.model is not None,
            "error": self.error,
        }

    def rerank(
        self,
        query: str,
        candidates: List[Tuple[Dict[str, Any], float]],
    ) -> List[Tuple[Dict[str, Any], float]]:
        if not candidates:
            return []
        cross_scores = None
        if self.model is not None:
            documents = [_retrieval_document(item[0].get("original") or item[0]) for item in candidates]
            try:
                cross_scores = self.model.predict([[query, document] for document in documents])
            except Exception as exc:
                logger.warning("Cross-encoder reranking failed: %s", exc)
        reranked = []
        query_tokens = _tokens(query)
        for index, (metadata, retrieval_score) in enumerate(candidates):
            original = metadata.get("original") or metadata
            document_tokens = _tokens(_retrieval_document(original))
            signal_terms = _tokens(" ".join(
                (original.get("applicability") or {}).get("required_signals") or []
            ))
            tag_terms = _tokens(" ".join(original.get("tags") or []))
            signal_overlap = _jaccard(query_tokens, signal_terms)
            tag_overlap = _jaccard(query_tokens, tag_terms)
            lexical_overlap = _jaccard(query_tokens, document_tokens)
            query_coverage = len(query_tokens & document_tokens) / max(1, len(query_tokens))
            title = str(original.get("title") or original.get("threat_name") or "").lower()
            title_match = bool(title and title in query.lower())
            if cross_scores is not None:
                model_score = 1.0 / (1.0 + np.exp(-float(cross_scores[index])))
                score = retrieval_score * 0.55 + model_score * 0.45
            else:
                score = (
                    retrieval_score * 0.58 + lexical_overlap * 0.08
                    + signal_overlap * 0.08 + tag_overlap * 0.04
                    + query_coverage * 0.16 + (0.12 if title_match else 0.0)
                )
            enriched = dict(metadata)
            enriched["retrieval_score"] = round(float(retrieval_score), 6)
            enriched["reranker_backend"] = self.backend
            enriched["reranker_score"] = round(float(score), 6)
            enriched["query_coverage"] = round(float(query_coverage), 6)
            enriched["exact_title_match"] = title_match
            reranked.append((enriched, max(0.0, min(1.0, float(score)))))
        return sorted(reranked, key=lambda item: item[1], reverse=True)

    def rerank_batch(
        self,
        batches: List[Tuple[str, List[Tuple[Dict[str, Any], float]]]],
    ) -> List[List[Tuple[Dict[str, Any], float]]]:
        """Run one cross-encoder call for all queries instead of one per scope."""
        if self.model is None:
            return [self.rerank(query, candidates) for query, candidates in batches]
        pairs, spans = [], []
        for query, candidates in batches:
            start = len(pairs)
            pairs.extend([
                [query, _retrieval_document(item[0].get("original") or item[0])]
                for item in candidates
            ])
            spans.append((start, len(pairs)))
        try:
            scores = self.model.predict(pairs) if pairs else []
        except Exception as exc:
            logger.warning("Batch cross-encoder reranking failed: %s", exc)
            return [self.rerank(query, candidates) for query, candidates in batches]
        output = []
        model, self.model = self.model, None
        try:
            for (query, candidates), (start, end) in zip(batches, spans):
                reranked = []
                for index, (metadata, retrieval_score) in enumerate(candidates):
                    model_score = 1.0 / (1.0 + np.exp(-float(scores[start + index])))
                    score = retrieval_score * 0.55 + model_score * 0.45
                    enriched = dict(metadata)
                    enriched["retrieval_score"] = round(float(retrieval_score), 6)
                    enriched["reranker_backend"] = "cross_encoder"
                    enriched["reranker_score"] = round(float(score), 6)
                    reranked.append((enriched, max(0.0, min(1.0, float(score)))))
                output.append(sorted(reranked, key=lambda item: item[1], reverse=True))
        finally:
            self.model = model
        return output


class SemanticThreatMatcher:
    """
    Matches architecture components against threats using semantic similarity.
    Works alongside the existing rule engine — provides candidate threats
    that the rule engine might miss through keyword matching alone.
    """
    
    def __init__(self):
        self._kb_vectorized = False
        self._vector_store = None
        self._domain_stores: Dict[str, Any] = {}
        self._lexical_index = BM25Index()
        self._embedding_service = None
        self._reranker = SecurityReranker()
        self._calibrator = RetrievalCalibrator()
        self._cache_status = "not_built"
        self._retrieval_schema = "hybrid-bm25-rrf-rerank-4.0"
        self._initialize()
    
    def _initialize(self):
        """Initialize embedding service and vector store."""
        try:
            from .embedding_service import VectorStore, get_embedding_service
            self._embedding_service = get_embedding_service()
            # Each matcher owns its index. A process-global store makes a
            # second matcher append duplicate knowledge-base vectors.
            self._vector_store = VectorStore(self._embedding_service.dimension)
            logger.info("Semantic threat matcher initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize semantic threat matcher: {e}")
    
    def vectorize_knowledge_base(self, threats: List[Dict]):
        """
        Vectorize all threats in the knowledge base for semantic search.
        Should be called once at startup.
        """
        if self._kb_vectorized:
            return
        
        if not threats:
            logger.warning("No threats to vectorize")
            return
        
        logger.info("Indexing %s threats for hybrid retrieval", len(threats))
        texts: List[str] = []
        metadata: List[Dict[str, Any]] = []
        for threat in threats:
            texts.append(_retrieval_document(threat))
            domains = _threat_domains(threat)
            metadata.append({
                'threat_id': threat.get('threat_id', threat.get('id', '')),
                'threat_name': threat.get('threat_name', threat.get('threat', {}).get('title', '')),
                'component': threat.get('component', ''),
                'category': threat.get('stride_category', threat.get('category', '')),
                'severity': threat.get('impact', threat.get('risk', {}).get('severity', 'Medium')),
                'domains': domains,
                'original': threat,
            })

        self._lexical_index.build(texts, metadata)

        import hashlib
        import json
        import pickle
        from pathlib import Path

        cache_file = None
        try:
            signature = self._embedding_service.index_signature if self._embedding_service else None
            kb_hash = hashlib.sha256(json.dumps({
                "retrieval_schema": self._retrieval_schema, "embedding": signature,
            }, sort_keys=True).encode()).hexdigest()[:24]
            cache_dir = Path(__file__).parent.parent / "knowledge_base" / "cache"
            cache_dir.mkdir(exist_ok=True, parents=True)
            cache_file = cache_dir / f"kb_incremental_{kb_hash}.pkl"

            if cache_file.exists() and self._embedding_service and self._vector_store:
                with open(cache_file, 'rb') as f:
                    cached = pickle.load(f)
                if not isinstance(cached, dict):
                    raise ValueError("legacy cache format")
                if cached.get("schema") != self._retrieval_schema:
                    raise ValueError("retrieval schema changed")
                if cached.get("embedding") != self._embedding_service.index_signature:
                    raise ValueError("embedding model signature changed")
                records = cached.get("records") or {}
                vectors, changed_texts, changed_indexes = [None] * len(texts), [], []
                for index, (item, text) in enumerate(zip(metadata, texts)):
                    document_hash = hashlib.sha256(text.encode()).hexdigest()
                    record = records.get(item["threat_id"]) or {}
                    vector = np.asarray(record.get("vector"), dtype=np.float32)
                    if record.get("document_hash") == document_hash and vector.shape == (self._embedding_service.dimension,):
                        vectors[index] = vector
                    else:
                        changed_indexes.append(index)
                        changed_texts.append(text)
                if changed_texts:
                    changed_vectors = self._embedding_service.embed_batch(changed_texts)
                    for index, vector in zip(changed_indexes, changed_vectors):
                        vectors[index] = vector
                embeddings = np.asarray(vectors, dtype=np.float32)
                self._vector_store.add(embeddings, metadata)
                self._build_domain_stores(embeddings, metadata)
                self._kb_vectorized = True
                self._cache_status = f"incremental:{len(changed_indexes)}_changed"
                if changed_indexes:
                    self._write_incremental_cache(cache_file, texts, metadata, embeddings)
                logger.info("Loaded %s vectors; re-embedded %s changed records", len(metadata), len(changed_indexes))
                return
        except Exception as e:
            self._cache_status = "miss"
            logger.info("Embedding cache not reusable: %s", e)

        try:
            if not self._embedding_service or not self._vector_store:
                raise RuntimeError("dense embedding service is unavailable")
            embeddings = self._embedding_service.embed_batch(texts)
            self._vector_store.add(embeddings, metadata)
            self._build_domain_stores(embeddings, metadata)
            self._kb_vectorized = True

            try:
                if cache_file:
                    with open(cache_file, 'wb') as f:
                        pickle.dump(self._incremental_cache_payload(texts, metadata, embeddings), f)
                    self._cache_status = "created"
            except Exception as e:
                logger.warning("Failed to save embeddings cache: %s", e)

            logger.info(
                "Indexed %s dense vectors and %s lexical documents",
                self._vector_store.size, self._lexical_index.size,
            )
        except Exception as e:
            self._kb_vectorized = self._lexical_index.size > 0
            self._cache_status = "lexical_only"
            logger.warning("Dense indexing failed; BM25 retrieval remains active: %s", e)

    def _build_domain_stores(self, embeddings, metadata: List[Dict[str, Any]]) -> None:
        """Build small domain indexes so unrelated security packs do not compete."""
        try:
            from .embedding_service import VectorStore
            grouped: Dict[str, Tuple[List[Any], List[Dict[str, Any]]]] = {}
            for index, item in enumerate(metadata):
                for domain in item.get("domains") or ["general"]:
                    vectors, records = grouped.setdefault(domain, ([], []))
                    vectors.append(embeddings[index])
                    records.append(item)
            self._domain_stores = {}
            for domain, (vectors, records) in grouped.items():
                store = VectorStore(self._embedding_service.dimension)
                store.add(np.asarray(vectors, dtype=np.float32), records)
                self._domain_stores[domain] = store
        except Exception as exc:
            logger.warning("Domain index construction failed: %s", exc)
            self._domain_stores = {}
    
    def find_relevant_threats(
        self, 
        component_description: str, 
        component_type: str = None,
        top_k: int = 15,
        stride_category: str = None,
        cloud_provider: str = None,
        security_domains: Optional[List[str]] = None,
        _rerank: bool = True,
        _query_embedding=None,
    ) -> List[Tuple[Dict, float]]:
        """
        Find the most relevant threats for a component using semantic search.
        
        Args:
            component_description: Text describing the component and its context
            component_type: Optional component type filter
            top_k: Number of results to return
            
        Returns:
            List of (threat_metadata, similarity_score) tuples
        """
        dense_ready = bool(
            self._embedding_service and self._vector_store and self._vector_store.size
        )
        if not dense_ready and self._lexical_index.size == 0:
            return []
        
        # Build query text
        query = _build_query(component_description, component_type)
        
        started = time.perf_counter()
        # Search
        try:
            domains = set(security_domains or _query_domains(query, component_type, cloud_provider))
            candidate_limit = max(top_k * configured_profile().candidate_multiplier, 60)
            dense_results: List[Tuple[Dict[str, Any], float]] = []
            if dense_ready:
                query_embedding = (
                    _query_embedding
                    if _query_embedding is not None
                    else self._embedding_service.embed_query(query)
                )
                stores = [
                    self._domain_stores[name]
                    for name in sorted(domains)
                    if name in self._domain_stores
                ] or [self._vector_store]
                result_by_id: Dict[str, Tuple[Dict[str, Any], float]] = {}
                for store in stores:
                    for meta, score in store.search(query_embedding, top_k=candidate_limit):
                        threat_id = _retrieval_identity(meta)
                        current = result_by_id.get(threat_id)
                        if current is None or score > current[1]:
                            result_by_id[threat_id] = (meta, score)
                dense_results = sorted(
                    result_by_id.values(), key=lambda item: item[1], reverse=True,
                )[:candidate_limit]

            lexical_results = self._lexical_index.search(query, top_k=candidate_limit)
            dense_weight, lexical_weight = fusion_weights(
                getattr(self._embedding_service, "backend", "unavailable")
            )
            results = reciprocal_rank_fusion([
                ("dense", dense_results, dense_weight),
                ("bm25", lexical_results, lexical_weight),
            ], identity=_retrieval_identity)

            filtered = []
            query_tokens = _tokens(query)
            for meta, fusion_score in results:
                original = meta.get("original") or meta
                if component_type and not _component_filter_matches(original, component_type):
                    continue
                category = original.get("stride_category") or original.get("category")
                if stride_category and category != stride_category:
                    continue
                platforms = {str(item).lower() for item in original.get("cloud_platform") or []}
                if cloud_provider and platforms and cloud_provider.lower() not in platforms:
                    continue
                hard_negative_reasons = _hard_negative_reasons(
                    query, original, component_type, cloud_provider, domains,
                )
                if any(reason in hard_negative_reasons for reason in (
                    "incompatible_component", "incompatible_cloud", "unrelated_security_domain",
                )):
                    continue
                source_scores = meta.get("retrieval_sources") or {}
                semantic_score = float((source_scores.get("dense") or {}).get("score") or 0.0)
                lexical_score = float((source_scores.get("bm25") or {}).get("score") or 0.0)
                lexical_overlap = _jaccard(query_tokens, _tokens(_retrieval_document(original)))
                component_bonus = 0.08 if component_type and _component_filter_matches(original, component_type, exact_only=True) else 0.0
                category_bonus = 0.06 if stride_category and category == stride_category else 0.0
                domain_bonus = 0.06 if domains & set(meta.get("domains") or []) else 0.0
                negative_penalty = min(0.35, 0.12 * len(hard_negative_reasons))
                hybrid_score = max(0.0, min(
                    1.0,
                    float(fusion_score) * 0.72
                    + max(0.0, semantic_score) * 0.08
                    + lexical_score * 0.06
                    + lexical_overlap * 0.04
                    + component_bonus + category_bonus + domain_bonus - negative_penalty,
                ))
                enriched = dict(meta)
                enriched["semantic_score"] = float(semantic_score)
                enriched["lexical_score"] = lexical_score
                enriched["lexical_overlap"] = lexical_overlap
                enriched["fusion_score"] = float(fusion_score)
                enriched["fusion_weights"] = {
                    "dense": round(dense_weight, 4),
                    "bm25": round(lexical_weight, 4),
                }
                enriched["retrieval_scope"] = {
                    "component_type": component_type,
                    "stride_category": stride_category,
                    "cloud_provider": cloud_provider,
                    "security_domains": sorted(domains),
                }
                enriched["hard_negative_reasons"] = hard_negative_reasons
                enriched["rule_provenance"] = rule_provenance(original)
                filtered.append((enriched, hybrid_score))
            threshold = self._calibrator.threshold(domains, stride_category)
            reranked = self._reranker.rerank(query, filtered) if _rerank else filtered
            accepted = [item for item in reranked if item[1] >= threshold][:top_k]
            for metadata_item, _ in accepted:
                metadata_item["calibrated_threshold"] = threshold
            retrieval_monitor.record(
                latency_ms=(time.perf_counter() - started) * 1000,
                results=len(accepted),
                fallback=getattr(self._embedding_service, "backend", "") != "sentence_transformer",
                cache=self._cache_status,
            )
            return accepted
        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            return []

    def find_relevant_threats_batch(self, requests: List[Dict[str, Any]]) -> List[List[Tuple[Dict, float]]]:
        """Batch query embeddings and optional neural reranking across all scopes."""
        queries = [_build_query(item["query"], item.get("component_type")) for item in requests]
        embeddings = None
        if self._embedding_service and self._vector_store and self._vector_store.size:
            embeddings = self._embedding_service.embed_queries(queries)
        candidates = []
        for index, request in enumerate(requests):
            candidates.append(self.find_relevant_threats(
                request["query"], request.get("component_type"), request.get("top_k", 5) * 2,
                request.get("stride_category"), request.get("cloud_provider"),
                request.get("security_domains"), _rerank=False,
                _query_embedding=embeddings[index] if embeddings is not None else None,
            ))
        reranked = self._reranker.rerank_batch([
            (request["query"], items) for request, items in zip(requests, candidates)
        ])
        return [items[:request.get("top_k", 5)] for request, items in zip(requests, reranked)]
    def find_threats_for_architecture(
        self,
        architecture_text: str,
        top_k: int = 20
    ) -> List[Tuple[Dict, float]]:
        """
        Find relevant threats for an entire architecture description.
        Useful for RAG — retrieving context for LLM prompts.
        """
        if not self._kb_vectorized:
            return []
        
        try:
            text = architecture_text or ""
            chunks = hierarchical_chunks(text)

            best_by_id: Dict[str, Tuple[Dict, float]] = {}
            for chunk in chunks:
                for metadata, score in self.find_relevant_threats(chunk["text"], top_k=top_k):
                    metadata = dict(metadata)
                    metadata["document_chunk"] = {key: chunk[key] for key in ("id", "section", "sha256")}
                    threat_id = _retrieval_identity(metadata)
                    current = best_by_id.get(threat_id)
                    if current is None or score > current[1]:
                        best_by_id[threat_id] = (metadata, score)
            return sorted(best_by_id.values(), key=lambda item: item[1], reverse=True)[:top_k]
        except Exception as e:
            logger.error(f"Architecture threat search failed: {e}")
            return []

    def diagnostics(self) -> Dict[str, Any]:
        embedding = self._embedding_service
        dense_weight, lexical_weight = fusion_weights(
            getattr(embedding, "backend", "unavailable")
        )
        return {
            "status": "active" if self._kb_vectorized else "not_ready",
            "schema": self._retrieval_schema,
            "profile": configured_profile().name,
            "strategy": "BM25 + dense embeddings + reciprocal-rank fusion + reranking",
            "embedding_model": getattr(embedding, "model_name", None),
            "embedding_backend": getattr(embedding, "backend", "unavailable"),
            "embedding_dimension": getattr(embedding, "dimension", None),
            "query_instruction": bool(getattr(embedding, "query_instruction", "")),
            "dense_vectors": getattr(self._vector_store, "size", 0),
            "lexical_documents": self._lexical_index.size,
            "fusion_weights": {
                "dense": round(dense_weight, 4), "bm25": round(lexical_weight, 4),
            },
            "reranker": self._reranker.status,
            "cache": self._cache_status,
            "monitoring": retrieval_monitor.snapshot(),
            "calibration": self._calibrator.data,
        }

    def _incremental_cache_payload(self, texts, metadata, embeddings) -> Dict[str, Any]:
        import hashlib
        return {
            "schema": self._retrieval_schema,
            "embedding": self._embedding_service.index_signature,
            "records": {
                item["threat_id"]: {
                    "document_hash": hashlib.sha256(text.encode()).hexdigest(),
                    "vector": vector,
                }
                for item, text, vector in zip(metadata, texts, embeddings)
            },
        }

    def _write_incremental_cache(self, cache_file, texts, metadata, embeddings) -> None:
        import pickle
        with open(cache_file, "wb") as handle:
            pickle.dump(self._incremental_cache_payload(texts, metadata, embeddings), handle)
    
    def compute_threat_similarity(self, threat1_text: str, threat2_text: str) -> float:
        """
        Compute semantic similarity between two threat descriptions.
        Used for deduplication.
        
        Returns:
            Similarity score between 0 and 1
        """
        if not self._embedding_service:
            return self._fallback_similarity(threat1_text, threat2_text)
        
        try:
            return self._embedding_service.similarity(threat1_text, threat2_text)
        except Exception as e:
            logger.error(f"Similarity computation failed: {e}")
            return self._fallback_similarity(threat1_text, threat2_text)
    
    def deduplicate_threats(
        self,
        threats: List[Dict],
        similarity_threshold: float = 0.75
    ) -> List[Dict]:
        """
        Remove duplicate/near-duplicate threats using semantic similarity.
        
        Args:
            threats: List of threat dicts with 'title' and 'description' keys
            similarity_threshold: Minimum similarity to consider as duplicate (0-1)
            
        Returns:
            Deduplicated list of threats with duplicates merged
        """
        if not threats:
            return []
        
        if len(threats) == 1:
            return threats
        
        # Create text representations
        texts = [
            f"{t.get('title', '')} {t.get('description', '')}" 
            for t in threats
        ]
        
        # Compute all pairwise similarities
        if self._embedding_service:
            try:
                embeddings = self._embedding_service.embed_batch(texts)
                # Pairwise cosine similarity matrix
                sim_matrix = embeddings @ embeddings.T
            except Exception:
                sim_matrix = self._fallback_similarity_matrix(texts)
        else:
            sim_matrix = self._fallback_similarity_matrix(texts)
        
        # Greedy deduplication — keep first occurrence, merge duplicates
        kept = []
        merged_indices = set()
        
        for i in range(len(threats)):
            if i in merged_indices:
                continue
            
            current = dict(threats[i])  # Copy
            
            # Find duplicates of current threat
            for j in range(i + 1, len(threats)):
                if j in merged_indices:
                    continue
                
                if NUMPY_AVAILABLE:
                    sim = float(sim_matrix[i][j])
                else:
                    sim = self._fallback_similarity(texts[i], texts[j])
                
                if sim >= similarity_threshold:
                    # Merge: keep higher severity, combine evidence
                    merged_indices.add(j)
                    duplicate = threats[j]
                    
                    # Keep higher severity
                    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
                    if severity_order.get(duplicate.get('severity', 'Low'), 0) > \
                       severity_order.get(current.get('severity', 'Low'), 0):
                        current['severity'] = duplicate.get('severity')
                    
                    # Combine evidence
                    existing_evidence = current.get('evidence', [])
                    new_evidence = duplicate.get('evidence', [])
                    if isinstance(existing_evidence, str):
                        existing_evidence = [existing_evidence]
                    if isinstance(new_evidence, str):
                        new_evidence = [new_evidence]
                    current['evidence'] = list(set(existing_evidence + new_evidence))
                    
                    # Note the merge
                    if 'merged_from' not in current:
                        current['merged_from'] = []
                    current['merged_from'].append(duplicate.get('id', duplicate.get('title', 'unknown')))
            
            kept.append(current)
        
        logger.info(f"Deduplication: {len(threats)} → {len(kept)} threats "
                    f"(removed {len(threats) - len(kept)} duplicates)")
        return kept
    
    def classify_stride(self, text: str) -> Dict[str, float]:
        """
        STRIDE classification using trained classifier (primary) or 
        zero-shot embedding similarity (fallback).
        
        Returns:
            Dict mapping STRIDE category to confidence score
        """
        # Try trained classifier first
        try:
            from .stride_classifier import get_stride_classifier
            classifier = get_stride_classifier()
            if classifier.is_trained:
                category, scores = classifier.predict(text)
                if scores:
                    return scores
        except Exception as e:
            logger.debug(f"Trained classifier not available: {e}")
        
        # Fallback to zero-shot embedding similarity
        return self._classify_stride_zero_shot(text)
    
    # Keep old name as alias for backward compat
    classify_stride_zero_shot = classify_stride
    
    def _classify_stride_zero_shot(self, text: str) -> Dict[str, float]:
        """Zero-shot STRIDE classification using embedding similarity (fallback)."""
        stride_descriptions = {
            'Spoofing': 'Identity spoofing, authentication bypass, credential theft, impersonation, unauthorized access through fake identity',
            'Tampering': 'Data tampering, code injection, parameter manipulation, unauthorized data modification, integrity violation',
            'Repudiation': 'Missing audit logs, untracked actions, no accountability, repudiable transactions, missing evidence',
            'Information Disclosure': 'Data leak, sensitive data exposure, information unauthorized access, privacy breach, credential exposure',
            'Denial of Service': 'Service unavailability, resource exhaustion, DDoS, flooding, crash, performance degradation',
            'Elevation of Privilege': 'Privilege escalation, unauthorized admin access, role bypass, permission elevation, root access'
        }
        
        if not self._embedding_service:
            return {cat: 0.0 for cat in stride_descriptions}
        
        # Cache STRIDE embeddings on the instance to avoid re-computing per function call
        if not hasattr(self, '_stride_embeddings'):
            self._stride_embeddings = {}
            for category, desc in stride_descriptions.items():
                self._stride_embeddings[category] = self._embedding_service.embed(desc)
        
        try:
            text_emb = self._embedding_service.embed(text)
            
            scores = {}
            for category, cat_emb in self._stride_embeddings.items():
                if NUMPY_AVAILABLE:
                    import numpy as np
                    scores[category] = float(np.dot(text_emb, cat_emb))
                else:
                    scores[category] = 0.0
            
            return scores
        except Exception as e:
            logger.error(f"Zero-shot classification failed: {e}")
            return {cat: 0.0 for cat in stride_descriptions}
    
    def _fallback_similarity(self, text1: str, text2: str) -> float:
        """Fallback similarity using Jaccard on word sets."""
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 
                      'and', 'or', 'is', 'are', 'was', 'were', 'be', 'been',
                      'with', 'from', 'by', 'as', 'it', 'its', 'that', 'this'}
        words1 -= stop_words
        words2 -= stop_words
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union if union > 0 else 0.0
    
    def _fallback_similarity_matrix(self, texts: List[str]):
        """Build similarity matrix using fallback method."""
        n = len(texts)
        matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i][j] = 1.0
                elif j > i:
                    sim = self._fallback_similarity(texts[i], texts[j])
                    matrix[i][j] = sim
                    matrix[j][i] = sim
        return matrix


def _component_filter_matches(threat: Dict[str, Any], component_type: str, exact_only: bool = False) -> bool:
    expected = threat.get("components") or threat.get("component") or ["Any"]
    if isinstance(expected, str):
        expected = [expected]
    normalized_expected = {_normalize_type(value) for value in expected}
    normalized_actual = _normalize_type(component_type)
    if "any" in normalized_expected or normalized_actual in normalized_expected:
        return True
    if exact_only:
        return False
    aliases = {
        "api gateway": {"api", "load balancer"},
        "webclient": {"web application", "frontend", "client"},
        "ml service": {"llm", "ai agent", "rag", "model"},
        "container platform": {"kubernetes", "container", "k8s"},
        "database": {"data store", "sql database", "nosql database"},
        "object storage": {"storage", "cloud storage", "file storage", "bucket"},
        "data flow": {
            "flow", "interaction", "communication", "api", "service",
            "webclient", "database", "object storage", "queue",
        },
    }
    compatible = aliases.get(normalized_actual, set())
    return bool(normalized_expected & compatible)


def _retrieval_identity(metadata: Dict[str, Any]) -> str:
    original = metadata.get("original") or metadata
    return str(
        metadata.get("threat_id")
        or original.get("id")
        or original.get("threat_id")
        or metadata.get("threat_name")
        or original.get("title")
        or ""
    )


def _build_query(component_description: str, component_type: Optional[str]) -> str:
    parts = [component_description]
    if component_type:
        parts.insert(0, f"Component type: {component_type}")
    return " ".join(parts)


def _retrieval_document(threat: Dict[str, Any]) -> str:
    applicability = threat.get("applicability") or {}
    return " ".join(filter(None, [
        str(threat.get("title") or threat.get("threat_name") or ""),
        str(threat.get("description") or ""),
        " ".join(threat.get("tags") or []),
        " ".join(threat.get("components") or []),
        " ".join(threat.get("cloud_platform") or []),
        " ".join(threat.get("cloud_services") or []),
        " ".join(applicability.get("required_signals") or []),
        " ".join(applicability.get("excluded_signals") or []),
    ]))


def _threat_domains(threat: Dict[str, Any]) -> List[str]:
    domains = set(security_domains_for_text(_retrieval_document(threat)))
    return sorted((domains or {"general"}) & SECURITY_DOMAINS)


def _query_domains(query: str, component_type: Optional[str], cloud_provider: Optional[str]) -> List[str]:
    synthetic = {
        "title": query,
        "description": component_type or "",
        "cloud_platform": [cloud_provider] if cloud_provider else [],
    }
    return _threat_domains(synthetic)


def _hard_negative_reasons(
    query: str,
    threat: Dict[str, Any],
    component_type: Optional[str],
    cloud_provider: Optional[str],
    query_domains: set[str],
) -> List[str]:
    reasons = []
    expected_components = {_normalize_type(item) for item in threat.get("components") or []}
    if component_type and expected_components and "any" not in expected_components:
        if not _component_filter_matches(threat, component_type):
            reasons.append("incompatible_component")
    platforms = {str(item).lower() for item in threat.get("cloud_platform") or []}
    if cloud_provider and platforms and cloud_provider.lower() not in platforms:
        reasons.append("incompatible_cloud")
    threat_domains = set(_threat_domains(threat)) - {"general"}
    scoped_query_domains = query_domains - {"general"}
    threat_specialists = threat_domains & SPECIALIST_DOMAINS
    query_specialists = scoped_query_domains & SPECIALIST_DOMAINS
    if threat_specialists and query_specialists and not threat_specialists & query_specialists:
        reasons.append("unrelated_security_domain")
    elif threat_domains and scoped_query_domains and not threat_domains & scoped_query_domains:
        reasons.append("unrelated_security_domain")
    excluded = (threat.get("applicability") or {}).get("excluded_signals") or []
    lowered_query = query.lower()
    if any(str(signal).lower() in lowered_query for signal in excluded if signal):
        reasons.append("negating_signal_present")
    return reasons


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(r"(?<![a-z0-9])" + re.escape(term.lower()) + r"(?![a-z0-9])", text))


def _normalize_type(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: str) -> set[str]:
    return set(security_tokens(value))


def _jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left and right else 0.0


# Global instance
_matcher_instance: Optional[SemanticThreatMatcher] = None

def get_semantic_matcher() -> SemanticThreatMatcher:
    """Get or create global semantic threat matcher."""
    global _matcher_instance
    if _matcher_instance is None:
        _matcher_instance = SemanticThreatMatcher()
    return _matcher_instance


def reset_semantic_matcher():
    """Reset the semantic matcher so embeddings/indexes can be rebuilt."""
    global _matcher_instance
    _matcher_instance = None
