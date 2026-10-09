"""Single-process local execution manager with durable ownership and approvals."""

from __future__ import annotations

import base64
import difflib
import json
import logging
import threading
import time
import uuid
from pathlib import Path

from common.config import settings
from common.thread_ownership import set_thread_owner
from tools.sandbox.docker_provider import DockerSandboxProvider
from tools.sandbox.permissions import ExecutionContext, PolicyEngine
from tools.sandbox.provider import SandboxProvider
from tools.sandbox.store import SandboxStore, canonical, fingerprint
from tools.sandbox.workspace_files import (
    digest,
    import_workspace,
    read_host,
    validate_path,
    write_host,
)

logger = logging.getLogger(__name__)


class LocalSandboxService:
    def __init__(self, store: SandboxStore | None = None, provider: SandboxProvider | None = None):
        self.store = store or SandboxStore()
        self.backend = "e2b" if settings.sandbox_mode in {"local", "e2b"} else "docker"
        self._providers = {self.backend: provider} if provider else {}
        self.provider = self._provider(self.backend)
        self._lock = threading.RLock()
        self._session_locks: dict[str, threading.RLock] = {}

    def _provider(self, backend: str) -> SandboxProvider:
        if backend not in self._providers:
            if backend == "docker":
                self._providers[backend] = DockerSandboxProvider(self.store.installation)
            elif backend == "e2b":
                from tools.sandbox.e2b_provider import E2BSandboxProvider

                self._providers[backend] = E2BSandboxProvider(self.store.installation)
            else:
                raise ValueError("Unknown sandbox backend")
        return self._providers[backend]

    def workspace_roots(self) -> dict[str, Path]:
        roots = {}
        for value in settings.sandbox_workspace_roots:
            root = Path(value).expanduser().resolve(strict=True)
            if (
                not root.is_dir()
                or root == Path.home()
                or root == Path(root.anchor)
                or root.is_relative_to(self.store.root.resolve())
            ):
                raise ValueError("Only explicit project directories may be imported")
            roots[fingerprint(str(root))[:24]] = root
        return roots

    def _session_lock(self, session_id: str):
        with self._lock:
            return self._session_locks.setdefault(session_id, threading.RLock())

    def find_thread(self, thread: str, principal: str) -> dict | None:
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE thread=?", (thread,)).fetchone()
        if row and row["principal"] != principal:
            raise PermissionError("Sandbox belongs to another principal")
        return dict(row) if row else None

    def get(self, session_id: str, principal: str) -> dict:
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not row or row["principal"] != principal:
            raise PermissionError("Sandbox not found for this principal")
        return dict(row)

    def _audit(
        self, session: dict, action: str, decision: str, args: dict, reason: str = "", run: str = ""
    ):
        self.store.audit(
            principal=session["principal"],
            thread=session["thread"],
            run=run or session["id"],
            action=action,
            decision=decision,
            reason=reason,
            args=args,
        )

    def create(
        self, principal: str, *, workspace_id: str = "", profile: str = "sandbox", thread: str = ""
    ) -> dict:
        if settings.sandbox_mode not in {"docker", "e2b", "local"}:
            raise PermissionError("Sandbox execution is disabled")
        if getattr(self, "_recovery_pending", False):
            raise RuntimeError("Sandbox recovery is pending; retry when the backend is available")
        if not principal:
            raise PermissionError("Sandbox requires a trusted principal")
        if thread:
            from common.thread_ownership import get_thread_owner

            owner = get_thread_owner(thread)
            if owner and owner != principal:
                raise PermissionError("Thread belongs to another principal")
        if profile not in {"read_only", "sandbox"}:
            raise ValueError("Unknown security profile")
        roots = self.workspace_roots()
        if workspace_id and workspace_id not in roots:
            raise PermissionError("Workspace is not in the server-configured allowlist")
        root = roots.get(workspace_id)
        files = import_workspace(root, exclude=self.store.root.resolve()) if root else {}
        with self._lock:
            if thread:
                existing = self.find_thread(thread, principal)
                if existing:
                    if existing["state"] != "active":
                        raise PermissionError("Sandbox is stopped; create a new session")
                    if existing["profile"] != profile or (
                        workspace_id and existing["workspace"] != str(root)
                    ):
                        raise ValueError(
                            "This thread already has a different sandbox profile or workspace; start a new chat"
                        )
                    return existing
            with self.store.connect() as db:
                count = db.execute(
                    "SELECT count(*) FROM sessions WHERE state!='stopped'"
                ).fetchone()[0]
            if count >= settings.sandbox_max_sessions:
                raise ValueError("Sandbox session limit reached; stop an existing sandbox")
            session_id = uuid.uuid4().hex
            thread = thread or f"sandbox_{session_id}"
            session = {
                "id": session_id,
                "principal": principal,
                "thread": thread,
                "workspace": str(root) if root else "",
                "profile": profile,
                "baseline": canonical({path: digest(data) for path, data in files.items()}),
                "touched": time.time(),
                "state": "active",
                "provider": self.backend,
            }
            self._audit(
                session,
                "sandbox.create",
                "allow",
                {"workspace_id": workspace_id, "profile": profile},
            )
            container = self.provider.create(session_id)
            try:
                if files:
                    self.provider.import_files(container, files)
                session["container"] = container
                with self.store.connect() as db:
                    db.execute(
                        "INSERT INTO sessions VALUES (:id,:principal,:thread,:workspace,:profile,:container,:baseline,:touched,:state,:provider)",
                        session,
                    )
            except Exception:
                self.provider.destroy(container)
                raise
            set_thread_owner(thread, principal)
            return session

    def ensure(self, context: ExecutionContext) -> dict:
        session = self.find_thread(context.thread_id, context.principal_id)
        if session:
            if session["state"] != "active":
                raise PermissionError("Sandbox is stopped; create a new session")
            return session
        return self.create(context.principal_id, profile=context.profile, thread=context.thread_id)

    def execute(
        self,
        context: ExecutionContext,
        command: list[str],
        *,
        stdin: bytes = b"",
        timeout: int | None = None,
    ) -> dict:
        decision = PolicyEngine().evaluate("sandbox.execute", context)
        if decision.effect != "allow":
            raise PermissionError(decision.reason)
        if len(stdin) > settings.sandbox_max_import_bytes:
            raise ValueError("Execution input exceeds configured limits")
        session = self.ensure(context)
        with self._session_lock(session["id"]):
            session = self.get(session["id"], context.principal_id)
            if session["state"] != "active":
                raise PermissionError("Sandbox is stopped")
            current_context = ExecutionContext(
                context.principal_id, session["thread"], context.run_id, session["profile"]
            )
            if PolicyEngine().evaluate("sandbox.execute", current_context).effect != "allow":
                raise PermissionError("Sandbox execution permission was revoked")
            with self.store.connect() as db:
                db.execute("UPDATE sessions SET touched=? WHERE id=?", (time.time(), session["id"]))
            self._audit(
                session,
                "sandbox.execute",
                "allow",
                {"command": command, "stdin_digest": digest(stdin)},
                run=context.run_id,
            )
            try:
                result = self._provider(session["provider"]).execute(
                    session["container"],
                    command,
                    stdin=stdin,
                    timeout=timeout or settings.sandbox_timeout_seconds,
                )
            except TimeoutError:
                self.stop(session["id"], context.principal_id)
                self._audit(
                    session,
                    "sandbox.execute",
                    "error",
                    {},
                    "Timeout destroyed sandbox",
                    context.run_id,
                )
                raise
            with self.store.connect() as db:
                db.execute("UPDATE sessions SET touched=? WHERE id=?", (time.time(), session["id"]))
            self._audit(
                session,
                "sandbox.execute",
                "complete",
                {"exit_code": result.exit_code},
                run=context.run_id,
            )
            output = {
                **result.to_dict(),
                "sandbox_id": session["id"],
                "backend": session["provider"],
            }
            # A bounded snapshot preserves completed outputs across idle cleanup/restarts.
            # Failure to export an oversized workspace must not hide the command result.
            try:
                output["files"] = list(self.files(session["id"], context.principal_id))
            except (ValueError, RuntimeError, TimeoutError, OSError) as exc:
                output["artifact_error"] = str(exc)
            return output

    def files(self, session_id: str, principal: str) -> dict[str, bytes]:
        with self._session_lock(session_id):
            session = self.get(session_id, principal)
            if session["state"] != "active":
                with self.store.connect() as db:
                    return {
                        row["path"]: bytes(row["content"])
                        for row in db.execute(
                            "SELECT path,content FROM artifacts WHERE session=?", (session_id,)
                        )
                    }
            self._audit(session, "sandbox.export", "allow", {})
            try:
                snapshot = self._provider(session["provider"]).snapshot(session["container"])
            except TimeoutError:
                self.stop(session_id, principal)
                raise
            result = {}
            total = 0
            for path, data in snapshot.items():
                try:
                    validate_path(path)
                except (ValueError, PermissionError):
                    continue
                if len(data) > settings.sandbox_max_file_bytes:
                    raise ValueError("File exceeds export limit")
                total += len(data)
                if (
                    total > settings.sandbox_max_import_bytes
                    or len(result) >= settings.sandbox_max_files
                ):
                    raise ValueError("Export exceeds configured limits")
                result[path] = data
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                used = db.execute(
                    "SELECT COALESCE(SUM(length(content)),0) FROM artifacts WHERE session!=?",
                    (session_id,),
                ).fetchone()[0]
                if used + total > settings.sandbox_max_artifact_bytes:
                    raise ValueError(
                        "Installation artifact storage quota exceeded; older snapshots remain available"
                    )
                db.execute("DELETE FROM artifacts WHERE session=?", (session_id,))
                db.executemany(
                    "INSERT INTO artifacts VALUES (?,?,?)",
                    [(session_id, path, data) for path, data in result.items()],
                )
                db.execute("UPDATE sessions SET touched=? WHERE id=?", (time.time(), session_id))
            return result

    def upload(self, session_id: str, principal: str, path: str, data: bytes) -> dict:
        validate_path(path)
        from common.security.content import contains_secret

        if len(data) > settings.sandbox_max_file_bytes or contains_secret(
            data.decode("utf-8", errors="replace")
        ):
            raise ValueError("File is too large or contains sensitive data")
        with self._session_lock(session_id):
            session = self.get(session_id, principal)
            if session["state"] != "active" or session["profile"] != "sandbox":
                raise PermissionError("Sandbox is not writable")
            self._provider(session["provider"]).import_files(session["container"], {path: data})
            self._audit(session, "sandbox.upload", "allow", {"path": path, "sha256": digest(data)})
            with self.store.connect() as db:
                db.execute("UPDATE sessions SET touched=? WHERE id=?", (time.time(), session_id))
        return {"path": path, "size": len(data)}

    def review(self, session_id: str, principal: str) -> dict:
        with self._session_lock(session_id):
            session = self.get(session_id, principal)
            context = ExecutionContext(principal, session["thread"], session_id, session["profile"])
            if PolicyEngine().evaluate("workspace.apply", context).effect != "ask":
                raise PermissionError("This profile cannot apply changes")
            if (
                not session["workspace"]
                or Path(session["workspace"]) not in self.workspace_roots().values()
            ):
                raise PermissionError("Sandbox has no currently authorized host workspace")
            files = self.files(session_id, principal)
            baseline = json.loads(session["baseline"])
            changes, previews = [], []
            root = Path(session["workspace"])
            for path in sorted(set(files) | set(baseline)):
                validate_path(path)
                after = files.get(path)
                before_hash = baseline.get(path)
                if digest(after) == before_hash:
                    continue
                before = read_host(root, path)
                if digest(before) != before_hash:
                    raise ValueError(f"Local file changed since import: {path}")
                kind = "delete" if after is None else "create" if before_hash is None else "modify"
                try:
                    old, new = (before or b"").decode("utf-8"), (after or b"").decode("utf-8")
                    if "\x00" in old or "\x00" in new:
                        raise UnicodeError("binary")
                    diff = "".join(
                        difflib.unified_diff(
                            old.splitlines(True),
                            new.splitlines(True),
                            fromfile=f"a/{path}",
                            tofile=f"b/{path}",
                        )
                    )
                    binary = False
                except UnicodeError:
                    diff, binary = (
                        "Binary file; download the review snapshot before approving.",
                        True,
                    )
                # The immutable payload includes the exact reviewed bytes.
                changes.append(
                    {
                        "path": path,
                        "before": before_hash,
                        "after": base64.b64encode(after).decode() if after is not None else None,
                    }
                )
                previews.append(
                    {
                        "path": path,
                        "kind": kind,
                        "diff": diff,
                        "binary": binary,
                        "sha256": digest(after),
                        "before_sha256": before_hash,
                        "size": len(after or b""),
                    }
                )
            payload = {
                "workspace": session["workspace"],
                "profile": session["profile"],
                "changes": changes,
            }
            approval_id = self.store.offer(principal, session_id, payload)
            self._audit(
                session,
                "workspace.apply",
                "ask",
                {"digest": fingerprint(payload), "paths": [c["path"] for c in changes]},
            )
            return {
                "approval_id": approval_id,
                "digest": fingerprint(payload),
                "expires_in": 300,
                "changes": previews,
            }

    def review_file(
        self, session_id: str, principal: str, approval_id: str, expected_digest: str, path: str
    ) -> bytes:
        with self._session_lock(session_id):
            session = self.get(session_id, principal)
            if session["state"] != "active":
                raise PermissionError("Sandbox is stopped")
            if Path(session["workspace"]) not in self.workspace_roots().values():
                raise PermissionError("Workspace authorization was revoked")
            validate_path(path)
            payload = self.store.preview(approval_id, principal, session_id, expected_digest)
            for change in payload["changes"]:
                if change["path"] != path:
                    continue
                self._audit(
                    session,
                    "workspace.review_download",
                    "allow",
                    {"approval_id": approval_id, "path": path},
                )
                if change["after"] is not None:
                    return base64.b64decode(change["after"], validate=True)
                before = read_host(Path(session["workspace"]), path)
                if before is None or digest(before) != change["before"]:
                    raise ValueError("Local file changed; review again")
                return before
            raise ValueError("File is not in this review")

    def apply(
        self, session_id: str, principal: str, approval_id: str, expected_digest: str
    ) -> dict:
        with self._session_lock(session_id):
            session = self.get(session_id, principal)
            if session["state"] != "active":
                raise PermissionError("Sandbox is stopped; approval is no longer valid")
            context = ExecutionContext(principal, session["thread"], session_id, session["profile"])
            if PolicyEngine().evaluate("workspace.apply", context).effect != "ask":
                raise PermissionError("This profile cannot apply changes")
            if Path(session["workspace"]) not in self.workspace_roots().values():
                raise PermissionError("Workspace authorization was revoked")
            payload = self.store.consume(approval_id, principal, session_id, expected_digest)
            if (
                payload["workspace"] != session["workspace"]
                or payload["profile"] != session["profile"]
            ):
                raise PermissionError("Approval scope changed")
            root = Path(session["workspace"])
            for change in payload["changes"]:
                if digest(read_host(root, change["path"])) != change["before"]:
                    raise ValueError(f"Local file changed; review again: {change['path']}")
            self._audit(
                session,
                "workspace.apply",
                "allow",
                {"approval_id": approval_id, "digest": expected_digest},
            )
            applied, baseline = [], json.loads(session["baseline"])
            try:
                for change in payload["changes"]:
                    data = (
                        base64.b64decode(change["after"], validate=True)
                        if change["after"] is not None
                        else None
                    )
                    write_host(root, change["path"], data, change["before"])
                    applied.append(change["path"])
                    if data is None:
                        baseline.pop(change["path"], None)
                    else:
                        baseline[change["path"]] = digest(data)
            finally:
                with self.store.connect() as db:
                    db.execute(
                        "UPDATE sessions SET baseline=? WHERE id=?",
                        (canonical(baseline), session_id),
                    )
                self._audit(
                    session,
                    "workspace.apply",
                    "complete" if len(applied) == len(payload["changes"]) else "partial",
                    {"paths": applied},
                )
            return {"applied": applied}

    def stop(self, session_id: str, principal: str) -> None:
        # Do not wait for the execution lock: cancellation must kill running code.
        session = self.get(session_id, principal)
        if session["state"] == "stopped":
            return
        self._audit(session, "sandbox.stop", "allow", {})
        with self.store.connect() as db:
            db.execute("UPDATE sessions SET state='stopping' WHERE id=?", (session_id,))
            db.execute(
                "UPDATE approvals SET state='rejected' WHERE session=? AND state='pending'",
                (session_id,),
            )
        self._provider(session["provider"]).destroy(session["container"])
        with self.store.connect() as db:
            db.execute("UPDATE sessions SET state='stopped' WHERE id=?", (session_id,))

    def stop_thread(self, thread: str) -> None:
        with self.store.connect() as db:
            row = db.execute(
                "SELECT id,principal FROM sessions WHERE thread=? AND state!='stopped'", (thread,)
            ).fetchone()
        if row:
            self.stop(row["id"], row["principal"])

    def cleanup(self, *, all_sessions: bool = False) -> int:
        with self.store.connect() as db:
            rows = db.execute("SELECT * FROM sessions WHERE state!='stopped'").fetchall()
        stopped = 0
        for row in rows:
            if (
                all_sessions
                or row["state"] == "stopping"
                or time.time() - row["touched"] > settings.sandbox_idle_seconds
            ):
                lock = self._session_lock(row["id"])
                if not all_sessions and not lock.acquire(blocking=False):
                    continue
                try:
                    current = self.get(row["id"], row["principal"])
                    if (
                        not all_sessions
                        and current["state"] == "active"
                        and time.time() - current["touched"] <= settings.sandbox_idle_seconds
                    ):
                        continue
                    self.stop(row["id"], row["principal"])
                    stopped += 1
                except Exception:
                    logger.exception("Could not clean up managed sandbox %s", row["id"])
                finally:
                    if not all_sessions:
                        lock.release()
        cutoff = time.time() - settings.sandbox_artifact_retention_seconds
        with self.store.connect() as db:
            db.execute(
                "DELETE FROM artifacts WHERE session IN (SELECT id FROM sessions WHERE state='stopped' AND touched<?)",
                (cutoff,),
            )
            db.execute(
                "UPDATE approvals SET payload='{}', state='expired' WHERE expires<?", (time.time(),)
            )
        return stopped

    def recover(self) -> None:
        # Revoke stale approvals even if Docker is currently unavailable. The
        # periodic cleanup retries stopping sessions once Desktop comes back.
        with self.store.connect() as db:
            db.execute("UPDATE sessions SET state='stopping' WHERE state!='stopped'")
            db.execute("UPDATE approvals SET state='rejected' WHERE state='pending'")
        with self.store.connect() as db:
            backends = {
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT provider FROM sessions WHERE state!='stopped'"
                )
            }
        # Docker labels also find containers created before a crash could persist the row.
        backends.add(self.backend)
        for backend in backends:
            self._provider(backend).recover()
            with self.store.connect() as db:
                db.execute(
                    "UPDATE sessions SET state='stopped' WHERE provider=? AND state!='stopped'",
                    (backend,),
                )


_service: LocalSandboxService | None = None
_service_lock = threading.Lock()


def get_local_service() -> LocalSandboxService:
    global _service
    with _service_lock:
        if _service is None:
            candidate = LocalSandboxService()
            import fcntl
            import os

            descriptor = os.open(
                candidate.store.root / "worker.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(descriptor)
                raise RuntimeError(
                    "Sandbox state is managed by another worker; use a single backend worker"
                ) from None
            candidate._process_lock = descriptor
            _service = candidate
    return _service
