"""RAG service: hybrid retrieval from Qdrant with RRF fusion and bge-reranker."""

from __future__ import annotations

from typing import Optional

import structlog

from app.core.config import settings
from app.schemas.schemas import EvidenceChunk

logger = structlog.get_logger(__name__)

# Evidence labels
EVIDENCE_LABELS = ["E1", "E2", "E3", "E4", "E5"]


async def retrieve_evidence(
    function_code: str,
    cwe_id: Optional[str],
    cwe_top3: list[str],
    analyzer_hits: dict,
    top_k: int = 5,
) -> list[EvidenceChunk]:
    """
    Hybrid retrieval: dense + sparse + RRF + reranker.
    
    Returns top_k evidence chunks with E1..E5 labels.
    Gracefully returns empty list if Qdrant/embedder unavailable.
    """
    try:
        from qdrant_client import QdrantClient, models as qdrant_models
    except ImportError:
        logger.warning("qdrant_client_not_installed")
        return []

    # Build query text
    query = _build_retrieval_query(function_code, cwe_id, cwe_top3, analyzer_hits)

    try:
        client = QdrantClient(url=settings.QDRANT_URL, api_key=settings.QDRANT_API_KEY or None)

        # Check collection exists
        collections = client.get_collections()
        if "kb_chunks" not in [c.name for c in collections.collections]:
            logger.warning("qdrant_collection_missing", collection="kb_chunks")
            return []

        # Dense retrieval
        dense_results = await _dense_search(client, query, cwe_id, top_k=20)
        # Sparse retrieval
        sparse_results = await _sparse_search(client, query, cwe_id, top_k=20)
        # RRF fusion
        fused = _reciprocal_rank_fusion(dense_results, sparse_results, k=60)[:20]
        # Rerank top-20 → top-5
        reranked = await _rerank(query, fused, top_k=top_k)

        # Label and return
        chunks = []
        for i, (doc, score) in enumerate(reranked[:top_k]):
            label = EVIDENCE_LABELS[i] if i < len(EVIDENCE_LABELS) else f"E{i+1}"
            chunks.append(EvidenceChunk(
                evidence_label=label,
                source=doc.get("source", "unknown"),
                doc_id=doc.get("doc_id", ""),
                rerank_score=score,
                text=doc.get("text", ""),
                url=doc.get("url"),
            ))
        return chunks

    except Exception as e:
        logger.warning("rag_retrieval_failed", error=str(e))
        return []


async def _dense_search(
    client,
    query: str,
    cwe_id: Optional[str],
    top_k: int = 20,
) -> list[tuple[dict, float]]:
    """Dense vector search using bge-base-en-v1.5 embedding."""
    try:
        from sentence_transformers import SentenceTransformer
        model = _get_dense_model()
        embedding = model.encode(query, normalize_embeddings=True).tolist()
    except Exception as e:
        logger.warning("dense_embedding_failed", error=str(e))
        return []

    filters = None
    if cwe_id:
        from qdrant_client import models as qm
        filters = qm.Filter(
            should=[
                qm.FieldCondition(key="cwe_id", match=qm.MatchValue(value=cwe_id)),
                qm.FieldCondition(key="cwe_id", match=qm.MatchValue(value="")),
            ]
        )

    from qdrant_client import models as qm
    results = client.search(
        collection_name="kb_chunks",
        query_vector=embedding,
        limit=top_k,
        query_filter=filters,
        with_payload=True,
    )

    return [(r.payload, r.score) for r in results]


async def _sparse_search(
    client,
    query: str,
    cwe_id: Optional[str],
    top_k: int = 20,
) -> list[tuple[dict, float]]:
    """Sparse BM25-style search via fastembed."""
    try:
        from fastembed import SparseTextEmbedding
        sparse_model = SparseTextEmbedding(model_name="Qdrant/bm25")
        sparse_vectors = list(sparse_model.embed([query]))
        if not sparse_vectors:
            return []
        sv = sparse_vectors[0]
    except Exception as e:
        logger.warning("sparse_embedding_failed", error=str(e))
        return []

    from qdrant_client import models as qm
    try:
        results = client.search(
            collection_name="kb_chunks",
            query_vector=qm.NamedSparseVector(
                name="sparse",
                vector=qm.SparseVector(indices=sv.indices.tolist(), values=sv.values.tolist()),
            ),
            limit=top_k,
            with_payload=True,
        )
        return [(r.payload, r.score) for r in results]
    except Exception as e:
        logger.warning("sparse_search_failed", error=str(e))
        return []


def _reciprocal_rank_fusion(
    dense_results: list[tuple[dict, float]],
    sparse_results: list[tuple[dict, float]],
    k: int = 60,
) -> list[tuple[dict, float]]:
    """
    Reciprocal Rank Fusion (RRF).
    
    Score = Σ 1/(k + rank_i) for each result list.
    """
    scores: dict[str, float] = {}
    docs: dict[str, dict] = {}

    for rank, (doc, _score) in enumerate(dense_results):
        doc_id = doc.get("chunk_id", str(rank))
        scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank + 1)
        docs[doc_id] = doc

    for rank, (doc, _score) in enumerate(sparse_results):
        doc_id = doc.get("chunk_id", str(rank))
        scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank + 1)
        docs[doc_id] = doc

    sorted_ids = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
    return [(docs[doc_id], scores[doc_id]) for doc_id in sorted_ids]


async def _rerank(
    query: str,
    candidates: list[tuple[dict, float]],
    top_k: int = 5,
) -> list[tuple[dict, float]]:
    """Rerank using bge-reranker-base cross-encoder."""
    if not candidates:
        return candidates[:top_k]

    try:
        from sentence_transformers import CrossEncoder
        reranker = _get_reranker()

        texts = [c[0].get("text", "")[:1000] for c in candidates]
        pairs = [[query, t] for t in texts]
        scores = reranker.predict(pairs)

        scored = list(zip(candidates, scores.tolist()))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [(c[0], float(s)) for (c, s) in scored[:top_k]]

    except Exception as e:
        logger.warning("reranker_failed", error=str(e))
        return candidates[:top_k]


# ─── Model caching (load once per worker process) ─────────────────────────────

_dense_model = None
_reranker_model = None


def _get_dense_model():
    global _dense_model
    if _dense_model is None:
        from sentence_transformers import SentenceTransformer
        _dense_model = SentenceTransformer("BAAI/bge-base-en-v1.5")
    return _dense_model


def _get_reranker():
    global _reranker_model
    if _reranker_model is None:
        from sentence_transformers import CrossEncoder
        _reranker_model = CrossEncoder("BAAI/bge-reranker-base")
    return _reranker_model


def _build_retrieval_query(
    function_code: str,
    cwe_id: Optional[str],
    cwe_top3: list[str],
    analyzer_hits: dict,
) -> str:
    """Build an effective retrieval query from finding context."""
    parts = []

    if cwe_id:
        parts.append(f"CWE {cwe_id} vulnerability")

    for cwe in cwe_top3[:3]:
        if cwe and cwe != cwe_id:
            parts.append(f"CWE {cwe}")

    for tool, hits in analyzer_hits.items():
        for h in (hits if isinstance(hits, list) else [])[:2]:
            rule_id = h.get("rule_id", "")
            msg = h.get("message", "")
            if msg:
                parts.append(msg[:100])

    # Include function head (first 5 lines) for context
    if function_code:
        head_lines = function_code.splitlines()[:5]
        parts.append(" ".join(head_lines))

    return " ".join(parts)[:500]


async def search_knowledge_base(
    query: str,
    top_k: int = 5,
    source: Optional[str] = None,
) -> list[EvidenceChunk]:
    """Public search endpoint for the knowledge base."""
    chunks = await retrieve_evidence(
        function_code="",
        cwe_id=None,
        cwe_top3=[],
        analyzer_hits={},
        top_k=top_k,
    )
    if source:
        chunks = [c for c in chunks if c.source == source]
    return chunks[:top_k]
