"""
Embedding Service — Sentence-transformer based embedding generation and similarity.

Provides:
- Text embedding for threat descriptions, architecture descriptions
- Cosine similarity for semantic deduplication
- Batch embedding for knowledge base vectorization
"""

import logging
import os
import numpy as np
from typing import List, Tuple, Optional, Dict, Any

from . import model_policy
from .retrieval_config import configured_embedding_model, configured_profile

logger = logging.getLogger(__name__)

# Try to load sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    logger.warning("sentence-transformers not installed. Semantic features will use fallback.")

# Try to load FAISS for vector search
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logger.warning("FAISS not installed. Vector search will use brute-force NumPy fallback.")


class EmbeddingService:
    """
    Generate and manage text embeddings using sentence-transformers.
    Falls back to deterministic local hashing when sentence-transformers is unavailable.
    """
    
    DEFAULT_MODEL = "BAAI/bge-base-en-v1.5"
    BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "
    FALLBACK_DIMENSION = 128
    
    def __init__(self, model_name: str = None, role: str = "embeddings"):
        self.model = None
        self.model_name = model_name or configured_embedding_model()
        self.role = role
        self._dimension = _known_dimension(self.model_name)
        self._load_model()
    
    def _load_model(self):
        """Load the sentence-transformer model."""
        if not EMBEDDINGS_AVAILABLE:
            logger.info("Sentence-transformers not available. Using local hashing fallback.")
            self._dimension = self.FALLBACK_DIMENSION
            return
        
        try:
            logger.info(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(
                self.model_name,
                **model_policy.sentence_transformer_kwargs(self.model_name),
            )
            self._dimension = self.model.get_sentence_embedding_dimension()
            logger.info(f"Embedding model loaded. Dimension: {self._dimension}")
            model_policy.note_model(self.model_name, self.role, loaded=True)
        except Exception as e:
            logger.warning(f"Failed to load embedding model: {e}. Using local hashing fallback.")
            self.model = None
            self._dimension = self.FALLBACK_DIMENSION
            model_policy.note_model(
                self.model_name, self.role, loaded=False, error=str(e), fallback="bm25_local_hashing",
            )
    
    @property
    def dimension(self) -> int:
        """Get embedding dimension."""
        return self._dimension
    
    @property
    def is_available(self) -> bool:
        """Check whether an embedding backend can produce vectors."""
        return True

    @property
    def backend(self) -> str:
        """Identify the active backend without overstating model capability."""
        return "sentence_transformer" if self.model is not None else "local_hashing"

    @property
    def query_instruction(self) -> str:
        configured = os.getenv("AEGIS_THREAT_EMBEDDING_QUERY_INSTRUCTION")
        if configured is not None:
            return configured
        return self.BGE_QUERY_INSTRUCTION if "bge-" in self.model_name.lower() else ""

    @property
    def index_signature(self) -> Dict[str, Any]:
        return {
            "profile": configured_profile().name,
            "model": self.model_name,
            "revision": model_policy.locked_revision(self.model_name),
            "dimension": self.dimension,
            "backend": self.backend,
            "normalized": True,
            "document_instruction": "",
        }
    
    def embed(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Input text to embed
            
        Returns:
            numpy array of shape (dimension,)
        """
        if self.model:
            return self.model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        return self._fallback_embed(text)

    def embed_query(self, text: str) -> np.ndarray:
        """Embed a retrieval query, applying the model's asymmetric instruction."""
        query = f"{self.query_instruction}{text}" if self.query_instruction else text
        return self.embed(query)

    def embed_queries(self, texts: List[str], batch_size: int = 64) -> np.ndarray:
        """Embed retrieval queries in one model call with query instructions."""
        queries = [
            f"{self.query_instruction}{text}" if self.query_instruction else text
            for text in texts
        ]
        return self.embed_batch(queries, batch_size=batch_size)

    def embed_document(self, text: str) -> np.ndarray:
        """Embed a knowledge document without a query-only instruction."""
        return self.embed(text)
    
    def embed_batch(self, texts: List[str], batch_size: int = 64) -> np.ndarray:
        """
        Generate embeddings for a batch of texts.
        
        Args:
            texts: List of input texts
            batch_size: Batch size for encoding
            
        Returns:
            numpy array of shape (len(texts), dimension)
        """
        if not texts:
            return np.array([])
        
        if self.model:
            return self.model.encode(
                texts, 
                convert_to_numpy=True, 
                normalize_embeddings=True,
                batch_size=batch_size,
                show_progress_bar=False
            )
        return np.array([self._fallback_embed(t) for t in texts])
    
    def similarity(self, text1: str, text2: str) -> float:
        """
        Compute cosine similarity between two texts.
        
        Returns:
            Similarity score between 0 and 1
        """
        emb1 = self.embed(text1)
        emb2 = self.embed(text2)
        return float(np.dot(emb1, emb2))
    
    def similarity_batch(self, query: str, candidates: List[str]) -> List[float]:
        """
        Compute cosine similarity between a query and multiple candidates.
        
        Returns:
            List of similarity scores
        """
        if not candidates:
            return []
        
        query_emb = self.embed(query)
        candidate_embs = self.embed_batch(candidates)
        
        return (candidate_embs @ query_emb).tolist()
    
    def _fallback_embed(self, text: str) -> np.ndarray:
        """
        Fallback embedding using deterministic term hashing.
        Not as good as transformer embeddings but works without dependencies.
        """
        from hashlib import sha256
        
        words = text.lower().split()
        # Use a fixed-size hash-based embedding
        dim = self._dimension
        embedding = np.zeros(dim, dtype=np.float32)
        
        for i, word in enumerate(words):
            h = int(sha256(word.encode()).hexdigest()[:8], 16)
            idx = h % dim
            weight = 1.0 / (1 + i * 0.1)  # Position-decay weighting
            embedding[idx] += weight
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding /= norm
        
        return embedding


class VectorStore:
    """
    Vector store for semantic search over threat knowledge base.
    Uses FAISS when available, falls back to brute-force NumPy.
    """
    
    def __init__(self, dimension: int):
        self.dimension = dimension
        self.index = None
        self.metadata: List[Dict[str, Any]] = []
        self._embeddings: Optional[np.ndarray] = None
        self._build_index()
    
    def _build_index(self):
        """Initialize the vector index."""
        if FAISS_AVAILABLE:
            # Use an IVF index for fast search if we have enough vectors
            self.index = faiss.IndexFlatIP(self.dimension)  # Inner product (cosine sim with normalized vectors)
            logger.info(f"FAISS index created. Dimension: {self.dimension}")
        else:
            self._embeddings = np.zeros((0, self.dimension), dtype=np.float32)
            logger.info("Using NumPy brute-force vector search (FAISS not available)")
    
    def add(self, embeddings: np.ndarray, metadata: List[Dict[str, Any]]):
        """
        Add embeddings with associated metadata.
        
        Args:
            embeddings: numpy array of shape (n, dimension)
            metadata: list of metadata dicts corresponding to each embedding
        """
        if len(embeddings) == 0:
            return
        
        # Ensure embeddings are float32 and 2D
        embeddings = np.asarray(embeddings, dtype=np.float32)
        if embeddings.ndim == 1:
            embeddings = embeddings.reshape(1, -1)
        if embeddings.shape[1] != self.dimension:
            raise ValueError(
                f"Vector dimension {embeddings.shape[1]} does not match index dimension {self.dimension}"
            )
        if embeddings.shape[0] != len(metadata):
            raise ValueError("Embedding and metadata counts must match")
        
        if FAISS_AVAILABLE and self.index is not None:
            self.index.add(embeddings)
        else:
            if self._embeddings is not None and len(self._embeddings) > 0:
                self._embeddings = np.vstack([self._embeddings, embeddings])
            else:
                self._embeddings = embeddings
        
        self.metadata.extend(metadata)
    
    def search(self, query_embedding: np.ndarray, top_k: int = 10) -> List[Tuple[Dict, float]]:
        """
        Search for most similar vectors.
        
        Args:
            query_embedding: query vector of shape (dimension,)
            top_k: number of results to return
            
        Returns:
            List of (metadata, similarity_score) tuples
        """
        query_embedding = np.asarray(query_embedding, dtype=np.float32)
        if query_embedding.ndim == 1:
            query_embedding = query_embedding.reshape(1, -1)
        
        n_items = len(self.metadata)
        if n_items == 0:
            return []
        
        top_k = min(top_k, n_items)
        
        if FAISS_AVAILABLE and self.index is not None:
            scores, indices = self.index.search(query_embedding, top_k)
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx >= 0 and idx < len(self.metadata):
                    results.append((self.metadata[idx], float(score)))
            return results
        else:
            # Brute-force NumPy search
            if self._embeddings is None or len(self._embeddings) == 0:
                return []
            
            scores = self._embeddings @ query_embedding.T
            scores = scores.flatten()
            top_indices = np.argsort(scores)[-top_k:][::-1]
            
            return [
                (self.metadata[i], float(scores[i]))
                for i in top_indices
                if i < len(self.metadata)
            ]
    
    @property
    def size(self) -> int:
        """Number of vectors in the store."""
        return len(self.metadata)


# Global instances
_embedding_service: Optional[EmbeddingService] = None
_vector_store: Optional[VectorStore] = None


def get_embedding_service() -> EmbeddingService:
    """Get or create global embedding service."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service


def get_or_create_vector_store(dimension: int = 384) -> VectorStore:
    """Get or create global vector store."""
    global _vector_store
    if _vector_store is None or _vector_store.dimension != dimension:
        _vector_store = VectorStore(dimension)
    return _vector_store


def reset_vector_store():
    """Reset the global vector store so it can be rebuilt from fresh KB data."""
    global _vector_store
    _vector_store = None


def reset_embedding_service():
    """Reset the model binding so profile changes are applied on reload."""
    global _embedding_service
    _embedding_service = None


def _known_dimension(model_name: str) -> int:
    lowered = model_name.lower()
    if "bge-large" in lowered:
        return 1024
    if "bge-base" in lowered or "mpnet-base" in lowered or "nomic-embed" in lowered:
        return 768
    if "minilm" in lowered or "bge-small" in lowered:
        return 384
    return 384
