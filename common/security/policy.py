"""Deterministic authorization, independent of model judgments and tool hints."""

import hashlib
import ipaddress
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from common.config import settings
from common.security.content import contains_secret


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    resource: str = ""


READ_TOOLS = frozenset(
    {
        "tavily_search",
        "fallback_search",
        "multi_search",
        "crawl_url",
        "crawl_urls",
        "rag_search",
        "plan_steps",
        "ask_human",
        "write_todos",
        "task_list_create",
        "task_list_update",
        "task_list_view",
        "create_tasks",
        "view_tasks",
        "update_task",
        "get_next_task",
    }
)
NETWORK_TOOLS = frozenset(
    {"tavily_search", "fallback_search", "multi_search", "crawl_url", "crawl_urls"}
)


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def allowed_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
            return False
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return False
        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            pass
        allowed = {
            x.strip().lower() for x in settings.security_allowed_domains.split(",") if x.strip()
        }
        return not allowed or host in allowed
    except ValueError:
        return False


def resolve_workspace_file(path: str) -> Path:
    root = Path(settings.security_workspace).resolve()
    candidate = Path(path)
    candidate = candidate if candidate.is_absolute() else root / candidate
    # Reject symlinks, including parent components, rather than trusting textual prefixes.
    for part in (candidate, *candidate.parents):
        if part.is_symlink():
            raise ValueError("Symlink paths are outside the file editing policy")
        if part == root:
            break
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("File is outside the authorized workspace")
    relative = resolved.relative_to(root)
    if any(
        part.startswith(".")
        or part.lower() in {"credentials", "secrets", "security.sqlite3"}
        or part.lower().endswith((".pem", ".key", ".p12", ".sqlite3", ".db"))
        for part in relative.parts
    ):
        raise ValueError("Sensitive files cannot be edited by the agent")
    return resolved


@contextmanager
def open_workspace_file(path: str, encoding: str, expected_version: str = ""):
    """Anchor each path component to an open directory; reject symlink/hardlink escapes."""
    root = Path(settings.security_workspace).resolve()
    resolved = resolve_workspace_file(path)
    parts = resolved.relative_to(root).parts
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2_000_000:
                raise ValueError("File is not an isolated, bounded regular file")
            file = os.fdopen(descriptor, "r+", encoding=encoding)
        except BaseException:
            os.close(descriptor)
            raise
        with file:
            if expected_version:
                actual = hashlib.sha256(file.buffer.read()).hexdigest()
                file.seek(0)
                if actual != expected_version:
                    raise ValueError("File changed after approval")
            yield file
    finally:
        os.close(directory)


def evaluate(tool: str, args: dict, *, risk: bool = False) -> Decision:
    # Inspect original arguments before previews, logging, or execution.
    if contains_secret(args):
        return Decision("deny", "sensitive_arguments")
    if tool == "str_replace":
        try:
            path = resolve_workspace_file(str(args.get("path", "")))
            if not path.is_file():
                return Decision("deny", "file_unavailable")
            if path.stat().st_size > 2_000_000:
                return Decision("deny", "file_too_large")
            if contains_secret(path.read_text(encoding=args.get("encoding", "utf-8"))):
                return Decision("deny", "sensitive_file")
        except (ValueError, OSError, UnicodeError, LookupError):
            return Decision("deny", "file_scope_denied")
        if risk:
            return Decision("deny", "untrusted_content_write_restricted", str(path))
        return Decision("require_approval", "workspace_write", str(path))
    if tool in NETWORK_TOOLS:
        urls = (
            args.get("urls", []) if tool == "crawl_urls" else [args["url"]] if "url" in args else []
        )
        if not isinstance(urls, list) or any(
            not isinstance(u, str) or not allowed_url(u) for u in urls
        ):
            return Decision("deny", "destination_denied")
    if tool in READ_TOOLS:
        return Decision("allow", "scoped_read")
    if tool.startswith("mcp_"):
        try:
            mode = json.loads(settings.security_mcp_tools).get(tool)
        except (ValueError, AttributeError):
            return Decision("deny", "invalid_mcp_policy")
        if risk:
            return Decision("deny", "untrusted_content_mcp_restricted")
        if mode in {"read", "approve"}:
            return Decision("allow" if mode == "read" else "require_approval", "configured_mcp")
    return Decision("deny", "tool_not_authorized")


def resource_version(decision: Decision) -> str:
    if decision.reason == "workspace_write":
        return hashlib.sha256(Path(decision.resource).read_bytes()).hexdigest()
    return ""
