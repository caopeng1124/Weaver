"""User-facing control plane. The agent has no tool for these endpoints."""

from __future__ import annotations

import hmac
import os
import secrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from common.config import settings
from tools.sandbox.local_service import get_local_service
from tools.sandbox.permissions import ExecutionContext
from tools.sandbox.workspace_files import validate_path

router = APIRouter(prefix="/api/local-sandbox", tags=["Local sandbox"])


def local_access_token(root=None) -> str:
    path = (root or get_local_service().store.root) / "access-token"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_urlsafe(32))
    except FileExistsError:
        pass
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        return handle.read().strip()


def require_local_user(request: Request) -> str:
    if settings.sandbox_mode not in {"docker", "e2b", "local"}:
        raise HTTPException(409, "Local sandbox mode is disabled")
    origin = request.headers.get("origin")
    if origin and origin not in settings.cors_origins_list:
        raise HTTPException(403, "Untrusted browser origin")
    token = request.headers.get("X-Weaver-Sandbox-Token", "")
    if not token or not hmac.compare_digest(token, local_access_token()):
        raise HTTPException(401, "Pair this browser using the token from make sandbox-token")
    from common.security.context import current_context

    context = current_context.get()
    if context is None:
        raise HTTPException(401, "Trusted request context required")
    return context.principal


def public_session(session: dict) -> dict:
    return {key: session[key] for key in ("id", "thread", "profile", "state", "provider")}


def call(action, *args, **kwargs):
    try:
        return action(*args, **kwargs)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(503, str(exc)) from exc


class CreateSession(BaseModel):
    workspace_id: str = ""
    thread_id: str = Field(default="", max_length=256)
    profile: Literal["read_only", "sandbox"] = "sandbox"


class RunCode(BaseModel):
    code: str = Field(max_length=65536)
    language: Literal["python", "shell"] = "python"


class ApplyReview(BaseModel):
    approval_id: str
    digest: str


@router.get("/config")
def local_config(principal: str = Depends(require_local_user)):
    service = get_local_service()
    roots = call(service.workspace_roots)
    return {
        "workspaces": [{"id": key, "name": path.name} for key, path in roots.items()],
        "default_profile": settings.sandbox_default_profile,
        "network": "enabled"
        if service.backend == "e2b" and settings.sandbox_allow_internet
        else "disabled",
        "backend": service.backend,
        "max_timeout_seconds": settings.sandbox_timeout_seconds,
        "diagnostic": service.provider.diagnose(),
    }


@router.post("/sessions")
def create_session(payload: CreateSession, principal: str = Depends(require_local_user)):
    return public_session(
        call(
            get_local_service().create,
            principal,
            workspace_id=payload.workspace_id,
            profile=payload.profile,
            thread=payload.thread_id,
        )
    )


@router.get("/sessions")
def list_sessions(thread_id: str = "", principal: str = Depends(require_local_user)):
    service = get_local_service()
    with service.store.connect() as db:
        rows = db.execute(
            "SELECT * FROM sessions WHERE principal=? AND (?='' OR thread=?) ORDER BY touched DESC LIMIT 100",
            (principal, thread_id, thread_id),
        ).fetchall()
    return [public_session(dict(row)) for row in rows]


@router.get("/sessions/{session_id}")
def get_session(session_id: str, principal: str = Depends(require_local_user)):
    return public_session(call(get_local_service().get, session_id, principal))


@router.post("/sessions/{session_id}/execute")
def execute(session_id: str, payload: RunCode, principal: str = Depends(require_local_user)):
    service = get_local_service()
    session = call(service.get, session_id, principal)
    context = ExecutionContext(
        principal, session["thread"], secrets.token_hex(16), session["profile"]
    )
    command = ["python3", "-I", "-"] if payload.language == "python" else ["/bin/sh", "-s"]
    return call(service.execute, context, command, stdin=payload.code.encode())


@router.get("/sessions/{session_id}/files")
def list_files(session_id: str, principal: str = Depends(require_local_user)):
    files = call(get_local_service().files, session_id, principal)
    return [{"path": path, "size": len(data)} for path, data in files.items()]


@router.get("/sessions/{session_id}/download")
def download(session_id: str, path: str, principal: str = Depends(require_local_user)):
    call(validate_path, path)
    files = call(get_local_service().files, session_id, principal)
    if path not in files:
        raise HTTPException(404, "File not found")
    # No inline HTML, scripts, or filename interpolation from untrusted output.
    return Response(
        files[path],
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=artifact.bin",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/sessions/{session_id}/review")
def review(session_id: str, principal: str = Depends(require_local_user)):
    return call(get_local_service().review, session_id, principal)


@router.get("/sessions/{session_id}/review/download")
def download_review(
    session_id: str,
    approval_id: str,
    digest: str,
    path: str,
    principal: str = Depends(require_local_user),
):
    data = call(get_local_service().review_file, session_id, principal, approval_id, digest, path)
    return Response(
        data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=review.bin",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/sessions/{session_id}/apply")
def apply(session_id: str, payload: ApplyReview, principal: str = Depends(require_local_user)):
    return call(
        get_local_service().apply, session_id, principal, payload.approval_id, payload.digest
    )


@router.post("/sessions/{session_id}/reject")
def reject(session_id: str, payload: ApplyReview, principal: str = Depends(require_local_user)):
    service = get_local_service()
    call(service.get, session_id, principal)
    service.store.reject(payload.approval_id, principal, session_id)
    return {"status": "rejected"}


@router.delete("/sessions/{session_id}")
def stop(session_id: str, principal: str = Depends(require_local_user)):
    call(get_local_service().stop, session_id, principal)
    return {"status": "stopped"}


@router.get("/sessions/{session_id}/audit")
def audit(session_id: str, principal: str = Depends(require_local_user)):
    service = get_local_service()
    session = call(service.get, session_id, principal)
    return service.store.events(principal, session["thread"])


class UploadFile(BaseModel):
    path: str = Field(max_length=1024)
    content: str = Field(max_length=65536)


@router.post("/sessions/{session_id}/files")
def upload(session_id: str, payload: UploadFile, principal: str = Depends(require_local_user)):
    return call(
        get_local_service().upload, session_id, principal, payload.path, payload.content.encode()
    )
