"""
RAG Tool for Research Pipeline.

Provides a LangChain-compatible tool for searching local documents.
"""

import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

from langchain_core.tools import tool

from tools.rag.document_loader import DocumentLoader
from tools.rag.embedder import Embedder
from tools.rag.permissions import (
    DocumentPermissions,
    RAGPermissionError,
    collection_for,
    principal_id,
)
from tools.rag.vector_store import VectorStore

logger = logging.getLogger(__name__)

# Global RAG instances (lazy initialized, keyed by collection name)
_RAG_BY_COLLECTION: dict[str, "RAGTool"] = {}


class RAGTool:
    """
    RAG Tool that integrates document loading, embedding, and retrieval.

    Used by the research pipeline to search local documents.
    """

    def __init__(
        self,
        collection_name: str = "weaver_documents",
        persist_directory: str | None = None,
        embedding_model: str = "text-embedding-3-small",
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ):
        """
        Initialize the RAG tool.

        Args:
            collection_name: Name for the vector collection
            persist_directory: Directory for persistent storage
            embedding_model: OpenAI embedding model name
            chunk_size: Document chunk size
            chunk_overlap: Chunk overlap for context
        """
        self.loader = DocumentLoader(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        self.embedder = Embedder(model=embedding_model)
        self.collection_name = collection_name
        self.vector_store = VectorStore(
            collection_name=collection_name,
            persist_directory=persist_directory,
            embedding_function=self.embedder,
        )

    def add_document(
        self,
        file_path: str | None = None,
        content: bytes | None = None,
        filename: str | None = None,
    ) -> dict[str, Any]:
        """
        Add a document to the RAG store.

        Args:
            file_path: Path to document file
            content: Document content as bytes
            filename: Original filename (required if using content)

        Returns:
            Dict with document info
        """
        principal = principal_id()
        if self.collection_name != collection_for(principal):
            raise RAGPermissionError("Uploads must use the owner's collection")
        try:
            if file_path:
                documents = self.loader.load(file_path)
                source = file_path
            elif content and filename:
                documents = self.loader.load_from_bytes(content, filename)
                source = filename
            else:
                raise ValueError("Either file_path or (content, filename) required")

            if not documents:
                return {
                    "success": False,
                    "error": "No content extracted from document",
                    "source": source,
                }

            # Sanitize before either the embedding API or the local vector store sees content.
            from common.security.content import redact, redact_text
            from common.security.runtime import untrusted

            document_id = uuid4().hex
            source = redact_text(source)
            for index, document in enumerate(documents):
                document.content = untrusted(
                    document.content, source=str(filename or file_path or "uploaded_document")
                )
                document.metadata = redact(document.metadata)
                document.metadata.update(document_id=document_id, chunk_index=index)
                document.doc_id = document_id
                document.chunk_id = f"{document_id}_{index}"

            # Generate embeddings
            texts = [doc.content for doc in documents]
            embeddings = self.embedder.embed_documents(texts)

            # Add to vector store
            ids = self.vector_store.add_documents(documents, embeddings)
            DocumentPermissions().register(
                document_id,
                principal,
                self.collection_name,
                source,
                redact_text(filename or Path(source).name),
                documents,
            )

            logger.info(f"Added document: {source} ({len(documents)} chunks)")

            return {
                "success": True,
                "source": source,
                "chunks": len(documents),
                "ids": ids,
                "document_id": document_id,
            }

        except Exception as e:
            logger.error(f"Add document error: {e}")
            return {
                "success": False,
                "error": "Document indexing failed",
                "source": file_path or filename,
            }

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_source: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for relevant document chunks.

        Args:
            query: Search query
            n_results: Number of results
            filter_source: Filter by source file

        Returns:
            List of result dicts with content and metadata
        """
        from common.security.runtime import audit, check_outbound, untrusted

        principal = principal_id()
        if not 1 <= n_results <= 20:
            raise ValueError("n_results must be between 1 and 20")
        permissions = DocumentPermissions()
        allowed = permissions.readable(principal, self.collection_name)
        if filter_source:
            allowed = [d for d in allowed if d["source"] == filter_source]
        if not allowed:
            return []
        allowed_ids = {d["id"] for d in allowed}
        # Resolve permissions before embedding; callers cannot provide an ACL filter.
        check_outbound("rag_search", {"query": query, "n_results": n_results})
        filter_metadata = {"document_id": {"$in": sorted(allowed_ids)}}

        results = self.vector_store.search(
            query=query,
            n_results=n_results,
            filter_metadata=filter_metadata,
        )

        verified = []
        for doc, score in results:
            if doc.metadata.get("document_id") not in allowed_ids:
                continue
            record = permissions.verify_chunk(principal, self.collection_name, doc)
            if record is None:
                audit("rag_chunk_rejected", reason="permission_or_integrity_changed")
                continue
            # Full chunks are inspected before any display truncation. Canonical
            # source fields come from the ACL catalog, not vector metadata.
            verified.append(
                untrusted(
                    {
                        "content": doc.content,
                        "score": score,
                        "source": record["source"],
                        "filename": record["filename"],
                        "chunk_index": record["chunk_index"],
                        "document_id": record["id"],
                        "chunk_id": doc.chunk_id,
                    },
                    source=f"rag:{record['id']}",
                    private=True,
                )
            )
        return verified

    def list_documents(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all documents in the store."""
        from common.security.runtime import untrusted

        return untrusted(
            DocumentPermissions().list_chunks(principal_id(), self.collection_name)[:limit],
            source="rag_document_list",
            private=True,
        )

    def delete_document(self, source: str) -> dict[str, Any]:
        """
        Delete all chunks from a specific source.

        Args:
            source: Source file path to delete

        Returns:
            Result dict
        """
        from common.security.content import redact_text

        principal = principal_id()
        if self.collection_name != collection_for(principal):
            raise RAGPermissionError("Only the owner can delete documents")
        permissions = DocumentPermissions()
        chunks = permissions.list_chunks(principal, self.collection_name)
        document_ids = permissions.deactivate_source(
            principal, self.collection_name, redact_text(source)
        )
        ids = [c["id"] for c in chunks if c["document_id"] in document_ids]
        # Delete by authoritative document IDs, including retry after an earlier
        # failed physical deletion (whose catalog entries are already inactive).
        self.vector_store.delete_documents(filter_metadata={"document_id": {"$in": document_ids}})
        return {"success": True, "deleted": len(ids)}

    def count(self) -> int:
        """Get total number of chunks in store."""
        return len(DocumentPermissions().list_chunks(principal_id(), self.collection_name))


def get_rag_tool(*, collection_name: str | None = None) -> RAGTool | None:
    """
    Get a cached RAG tool instance.

    Weaver can run in either:
    - single-user/dev mode: a single global collection
    - enterprise-internal mode: per-principal isolated collections (caller chooses collection_name)
    """

    from common.config import settings

    if not getattr(settings, "rag_enabled", False):
        return None

    try:
        base_collection = getattr(settings, "rag_collection_name", "weaver_documents")
        resolved_collection = (collection_name or base_collection or "weaver_documents").strip()

        existing = _RAG_BY_COLLECTION.get(resolved_collection)
        if existing is not None:
            return existing

        rag = RAGTool(
            collection_name=resolved_collection,
            persist_directory=getattr(settings, "rag_store_path", None),
            embedding_model=getattr(settings, "rag_embedding_model", "text-embedding-3-small"),
            chunk_size=getattr(settings, "rag_chunk_size", 1000),
            chunk_overlap=getattr(settings, "rag_chunk_overlap", 200),
        )
        _RAG_BY_COLLECTION[resolved_collection] = rag
        return rag
    except Exception as e:
        logger.error(f"Failed to initialize RAG tool: {e}")
        return None


@tool
def rag_search(query: str, n_results: int = 5) -> str:
    """
    Search local documents for information relevant to the query.

    Use this tool when you need to find information from uploaded documents,
    PDFs, or other local files that have been added to the knowledge base.

    Args:
        query: The search query describing what information you need
        n_results: Number of results to return (default 5)

    Returns:
        Relevant excerpts from local documents with source information
    """
    from common.config import settings
    from common.security.runtime import untrusted
    from tools.rag.service import search_documents

    if not settings.rag_enabled:
        return "RAG search is not enabled. Please enable it in settings."

    results = search_documents(query, n_results=n_results)

    if not results:
        return "No relevant documents found."

    output_parts = []
    for i, r in enumerate(results, 1):
        output_parts.append(
            f"[{i}] Source: {r['filename']} (score: {r['score']:.2f})\n{r['content'][:500]}..."
        )

    return untrusted("\n\n---\n\n".join(output_parts), source="rag_retrieval", private=True)
