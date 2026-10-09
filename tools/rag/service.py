"""Shared RAG entry points for HTTP and agent tools."""

from common.security.content import redact
from common.security.runtime import audit, untrusted
from tools.rag.permissions import DocumentPermissions, principal_id


def search_documents(query: str, n_results: int = 5) -> list[dict]:
    from tools.rag.rag_tool import get_rag_tool

    principal = principal_id()
    if not 1 <= n_results <= 20:
        raise ValueError("n_results must be between 1 and 20")
    # No global vector search: collections come only from the authoritative ACL.
    documents = DocumentPermissions().readable(principal)
    results = []
    for collection in sorted({d["collection_name"] for d in documents}):
        rag = get_rag_tool(collection_name=collection)
        if rag is None:
            raise RuntimeError("RAG storage is unavailable")
        results.extend(rag.search(query, n_results=n_results))
    # Each collection has rechecked its ACL; recheck once more after all searches,
    # because a different collection's embedding request may have taken time.
    allowed = {d["id"] for d in DocumentPermissions().readable(principal)}
    results = [r for r in results if r["document_id"] in allowed]
    results.sort(key=lambda r: r["score"], reverse=True)
    selected = results[:n_results]
    audit("rag_retrieval", allowed_documents=len(documents), returned_chunks=len(selected))
    return redact(selected)


def list_documents(limit: int = 100) -> dict:
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    chunks = DocumentPermissions().list_chunks(principal_id())
    return untrusted(
        {"total_chunks": len(chunks), "documents": chunks[:limit]}, source="rag_document_list"
    )


def set_document_readers(document_id: str, readers: list[str]) -> dict:
    principal = principal_id()
    normalized = DocumentPermissions().set_readers(document_id, principal, readers)
    audit("rag_permissions_updated", document_id=document_id, readers_count=len(normalized))
    return {"document_id": document_id, "readers": normalized}
