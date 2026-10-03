"""SQLite approval ledger: durable, atomic single consumption, no raw arguments."""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from common.config import settings
from common.security.content import redact


class ApprovalError(ValueError):
    pass


class SecurityStore:
    def __init__(self, path: str | None = None):
        self.path = path or settings.security_store_path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, binding TEXT UNIQUE NOT NULL, principal TEXT NOT NULL,
                thread TEXT NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY, created REAL NOT NULL, principal TEXT NOT NULL,
                thread TEXT NOT NULL, payload TEXT NOT NULL)""")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def request(self, binding: str, principal: str, thread: str) -> dict:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id, expires, state FROM approvals WHERE binding=?", (binding,)
            ).fetchone()
            if row:
                if row[2] not in {"pending", "edit"} or (
                    row[2] == "pending" and row[1] <= time.time()
                ):
                    raise ApprovalError("Approval expired or already used; start a new action")
                return {"approval_id": row[0], "expires_at": row[1]}
            approval_id = uuid4().hex
            expires = time.time() + settings.security_approval_ttl_s
            db.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, 'pending')",
                (approval_id, binding, principal, thread, expires),
            )
            return {"approval_id": approval_id, "expires_at": expires}

    def validate(self, approval_id: str, principal: str, thread: str) -> None:
        with self.connect() as db:
            row = db.execute(
                "SELECT principal, thread, expires, state FROM approvals WHERE id=?", (approval_id,)
            ).fetchone()
        if (
            not row
            or row[:2] != (principal, thread)
            or row[2] <= time.time()
            or row[3] != "pending"
        ):
            raise ApprovalError("Approval is unavailable, expired, or belongs to another action")

    def consume(
        self, approval_id: str, binding: str, principal: str, thread: str, state: str
    ) -> None:
        with self.connect() as db:
            changed = db.execute(
                """UPDATE approvals SET state=? WHERE id=? AND binding=?
                AND principal=? AND thread=? AND expires>? AND state='pending'""",
                (state, approval_id, binding, principal, thread, time.time()),
            ).rowcount
            if changed != 1:
                # LangGraph replays earlier interrupts when resuming an edited action.
                row = db.execute(
                    "SELECT state FROM approvals WHERE id=? AND binding=? AND principal=? AND thread=?",
                    (approval_id, binding, principal, thread),
                ).fetchone()
                if state != "edit" or row != ("edit",):
                    raise ApprovalError("Approval does not match or has already been consumed")

    def audit(self, principal: str, thread: str, payload: dict) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO security_events(created, principal, thread, payload) VALUES (?, ?, ?, ?)",
                (time.time(), principal, thread, json.dumps(redact(payload), ensure_ascii=False)),
            )

    def events(self, principal: str, thread: str) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT created, payload FROM security_events WHERE principal=?
                AND thread=? ORDER BY id DESC LIMIT 100""",
                (principal, thread),
            ).fetchall()
        return [{"created_at": row[0], **json.loads(row[1])} for row in reversed(rows)]

    def has_risk(self, principal: str, thread: str) -> bool:
        with self.connect() as db:
            return (
                db.execute(
                    """SELECT 1 FROM security_events WHERE principal=? AND thread=?
                AND json_extract(payload, '$.event')='injection_detected' LIMIT 1""",
                    (principal, thread),
                ).fetchone()
                is not None
            )
