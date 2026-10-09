"""Authoritative document ACLs, separate from untrusted vector metadata."""

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from common.config import settings
from common.security.context import current_context
from common.security.runtime import SecurityViolation


class RAGPermissionError(SecurityViolation):
    """The caller has no trusted identity or cannot manage this document."""


def principal_id() -> str:
    context = current_context.get()
    if not settings.internal_api_key:
        if settings.app_env in {"prod", "production"}:
            raise RAGPermissionError("RAG requires authenticated access in production")
        # A single local user, regardless of model arguments or supplied headers.
        return "local"
    if not context or not context.principal.strip() or context.principal == "internal":
        raise RAGPermissionError("RAG requires a trusted user identity")
    return context.principal


def collection_for(principal: str) -> str:
    base = (settings.rag_collection_name or "weaver_documents").strip()
    if not settings.internal_api_key:
        return base
    suffix = hashlib.sha256(principal.encode()).hexdigest()[:12]
    return f"{base}__u_{suffix}"


def content_digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


class DocumentPermissions:
    """Persist ownership, grants, and chunk bindings; missing records deny access."""

    def __init__(self):
        self.path = settings.rag_permissions_path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS rag_documents (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, collection_name TEXT NOT NULL,
                    source TEXT NOT NULL, filename TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS rag_readers (
                    document_id TEXT NOT NULL REFERENCES rag_documents(id) ON DELETE CASCADE,
                    principal TEXT NOT NULL, PRIMARY KEY(document_id, principal)
                );
                CREATE TABLE IF NOT EXISTS rag_chunks (
                    id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL REFERENCES rag_documents(id) ON DELETE CASCADE,
                    content_hash TEXT NOT NULL, chunk_index INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS rag_readers_principal ON rag_readers(principal);
                CREATE INDEX IF NOT EXISTS rag_chunks_document ON rag_chunks(document_id);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, document_id, owner, collection, source, filename, chunks):
        # Called only after vector insertion; failed uploads cannot become readable.
        with self.connect() as db:
            db.execute(
                "INSERT INTO rag_documents VALUES (?, ?, ?, ?, ?, 1)",
                (document_id, owner, collection, source, filename),
            )
            db.executemany(
                "INSERT INTO rag_chunks VALUES (?, ?, ?, ?)",
                [
                    (c.chunk_id, document_id, content_digest(c.content), i)
                    for i, c in enumerate(chunks)
                ],
            )

    def readable(self, principal: str, collection: str | None = None) -> list[dict]:
        sql = """SELECT d.* FROM rag_documents d WHERE d.active=1 AND
            (d.owner=? OR EXISTS (SELECT 1 FROM rag_readers r
              WHERE r.document_id=d.id AND r.principal=?))"""
        params = [principal, principal]
        if collection is not None:
            sql += " AND d.collection_name=?"
            params.append(collection)
        sql += " ORDER BY d.id"
        with self.connect() as db:
            return [dict(row) for row in db.execute(sql, params)]

    def verify_chunk(self, principal: str, collection: str, chunk) -> dict | None:
        """Re-read current ACLs and bind content to a registered chunk after retrieval."""
        with self.connect() as db:
            row = db.execute(
                """SELECT d.*, c.chunk_index, c.content_hash FROM rag_documents d
                JOIN rag_chunks c ON c.document_id=d.id
                WHERE c.id=? AND d.id=? AND d.collection_name=? AND d.active=1
                AND (d.owner=? OR EXISTS (SELECT 1 FROM rag_readers r
                  WHERE r.document_id=d.id AND r.principal=?))""",
                (
                    chunk.chunk_id,
                    chunk.metadata.get("document_id"),
                    collection,
                    principal,
                    principal,
                ),
            ).fetchone()
        if row is None or row["content_hash"] != content_digest(chunk.content):
            return None
        return dict(row)

    def list_chunks(self, principal: str, collection: str | None = None) -> list[dict]:
        # One read transaction prevents a grant change between listing and counting.
        sql = """SELECT c.id, d.id AS document_id, d.source, d.filename, c.chunk_index
            FROM rag_documents d JOIN rag_chunks c ON c.document_id=d.id
            WHERE d.active=1 AND (d.owner=? OR EXISTS
              (SELECT 1 FROM rag_readers r WHERE r.document_id=d.id AND r.principal=?))"""
        params = [principal, principal]
        if collection is not None:
            sql += " AND d.collection_name=?"
            params.append(collection)
        with self.connect() as db:
            return [dict(row) for row in db.execute(sql + " ORDER BY d.id, c.chunk_index", params)]

    def set_readers(self, document_id: str, owner: str, readers: list[str]) -> list[str]:
        if len(readers) > 100 or any(
            not isinstance(p, str) or not p.strip() or len(p) > 200 or any(ord(c) < 32 for c in p)
            for p in readers
        ):
            raise ValueError("Provide at most 100 nonempty user identifiers (up to 200 characters)")
        readers = sorted({p.strip() for p in readers} - {owner})
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM rag_documents WHERE id=? AND owner=? AND active=1",
                (document_id, owner),
            ).fetchone():
                raise RAGPermissionError("Document is unavailable or not owned by this user")
            db.execute("DELETE FROM rag_readers WHERE document_id=?", (document_id,))
            db.executemany(
                "INSERT INTO rag_readers VALUES (?, ?)", [(document_id, p) for p in readers]
            )
        return readers

    def deactivate_source(self, owner: str, collection: str, source: str) -> list[str]:
        # Revoke before touching the vector store. A failed physical delete stays denied.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            ids = [
                row[0]
                for row in db.execute(
                    "SELECT id FROM rag_documents WHERE owner=? AND collection_name=? AND source=?",
                    (owner, collection, source),
                )
            ]
            if not ids:
                raise RAGPermissionError("Document is unavailable or not owned by this user")
            db.execute(
                "UPDATE rag_documents SET active=0 WHERE owner=? AND collection_name=? AND source=?",
                (owner, collection, source),
            )
        return ids
