"""Private, durable control-plane state. Never mounted into execution containers."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from common.config import settings


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class SandboxStore:
    def __init__(self, root: Path | None = None):
        self.root = (root or Path(settings.sandbox_state_dir)).absolute()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ValueError("Security state directory must not be a symlink")
        os.chmod(self.root, 0o700)
        self.path = self.root / "control.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Security database must not be a symlink")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, principal TEXT NOT NULL, thread TEXT NOT NULL UNIQUE,
                    workspace TEXT NOT NULL, profile TEXT NOT NULL, container TEXT NOT NULL,
                    baseline TEXT NOT NULL, touched REAL NOT NULL, state TEXT NOT NULL, provider TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    session TEXT NOT NULL, path TEXT NOT NULL, content BLOB NOT NULL,
                    PRIMARY KEY (session, path)
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY, principal TEXT NOT NULL, session TEXT NOT NULL,
                    digest TEXT NOT NULL, payload TEXT NOT NULL, expires REAL NOT NULL,
                    state TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL, principal TEXT NOT NULL,
                    thread TEXT NOT NULL, run TEXT NOT NULL, action TEXT NOT NULL,
                    decision TEXT NOT NULL, reason TEXT NOT NULL, args_hash TEXT NOT NULL
                );
            """)
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('installation', ?)",
                (secrets.token_hex(16),),
            )
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @property
    def installation(self) -> str:
        with self.connect() as db:
            return db.execute("SELECT value FROM metadata WHERE key='installation'").fetchone()[0]

    def audit(
        self,
        *,
        principal: str,
        thread: str,
        run: str,
        action: str,
        decision: str,
        reason: str,
        args: dict,
    ) -> None:
        # Arguments/output may contain secrets. Persist a digest, not their contents.
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit (at,principal,thread,run,action,decision,reason,args_hash) VALUES (?,?,?,?,?,?,?,?)",
                (time.time(), principal, thread, run, action, decision, reason, fingerprint(args)),
            )

    def offer(self, principal: str, session: str, payload: dict, ttl: int = 300) -> str:
        approval_id = secrets.token_urlsafe(24)
        with self.connect() as db:
            db.execute(
                "UPDATE approvals SET state='superseded',payload='{}' WHERE session=? AND state='pending'",
                (session,),
            )
            db.execute(
                "INSERT INTO approvals VALUES (?,?,?,?,?,?,?)",
                (
                    approval_id,
                    principal,
                    session,
                    fingerprint(payload),
                    canonical(payload),
                    time.time() + ttl,
                    "pending",
                ),
            )
        return approval_id

    def consume(self, approval_id: str, principal: str, session: str, digest: str) -> dict:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row or row["principal"] != principal or row["session"] != session:
                raise PermissionError("Approval does not belong to this session")
            if row["state"] != "pending" or row["expires"] < time.time() or row["digest"] != digest:
                raise PermissionError("Approval expired, changed or already used; review again")
            db.execute(
                "UPDATE approvals SET state='consumed',payload='{}' WHERE id=?", (approval_id,)
            )
            return json.loads(row["payload"])

    def preview(self, approval_id: str, principal: str, session: str, digest: str) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row or row["principal"] != principal or row["session"] != session:
                raise PermissionError("Approval does not belong to this session")
            if row["state"] != "pending" or row["expires"] < time.time() or row["digest"] != digest:
                raise PermissionError("Approval expired, changed or already used; review again")
            return json.loads(row["payload"])

    def reject(self, approval_id: str, principal: str, session: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE approvals SET state='rejected',payload='{}' WHERE id=? AND principal=? AND session=? AND state='pending'",
                (approval_id, principal, session),
            )

    def events(self, principal: str, thread: str) -> list[dict]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM audit WHERE principal=? AND thread=? ORDER BY id DESC LIMIT 100",
                    (principal, thread),
                )
            ]
