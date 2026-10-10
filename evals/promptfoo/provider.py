"""Promptfoo provider for Weaver's real SSE API (no model mocks or auto-approval)."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from uuid import uuid4

import httpx


class IntegrationError(ValueError):
    """An incomplete run must never be graded as a successful defense."""


def _events(response, deadline):
    """Use httpx's incremental UTF-8 decoder, including multibyte chunk boundaries."""
    data_lines, event_name = [], ""
    for line in response.iter_lines():
        if time.monotonic() > deadline:
            raise IntegrationError("Total stream deadline exceeded")
        if not line:
            if data_lines:
                try:
                    data = json.loads("\n".join(data_lines))
                except ValueError as exc:
                    raise IntegrationError("Malformed SSE JSON") from exc
                if isinstance(data, dict) and "type" in data and "data" in data:
                    yield data
                else:
                    yield {"type": event_name, "data": data}
            data_lines, event_name = [], ""
        elif line.startswith("event:"):
            event_name = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        raise IntegrationError("Truncated SSE frame")


def _snapshot(workspace):
    if not workspace:
        return None
    # Only a synthetic fixture is read; hashes, not file contents, enter the report.
    result = {}
    for name in ("note.txt", "../outside-note.txt"):
        path = Path(workspace) / name
        if path.is_symlink() or not path.is_file():
            result[name] = "missing-or-symlink"
        else:
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def call_api(prompt, options, context):
    config = options.get("config", {})
    base_url = os.getenv("WEAVER_BASE_URL", config.get("baseUrl", "http://127.0.0.1:8001"))
    workspace = os.getenv("WEAVER_TEST_WORKSPACE", "")
    timeout = float(config.get("requestTimeoutSeconds", 120))
    headers = {"Accept": "text/event-stream"}
    if key := os.getenv("WEAVER_INTERNAL_API_KEY"):
        headers["X-API-Key"] = key
        # Separate identities prevent long-term memory from contaminating independent cases.
        headers["X-Weaver-User"] = os.getenv("WEAVER_TEST_USER") or f"promptfoo-{uuid4().hex}"
    thread_id = f"promptfoo-{uuid4().hex}"
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "thread_id": thread_id,
        "agent_id": os.getenv("WEAVER_TEST_AGENT", config.get("agentId", "default")),
        "search_mode": {"useAgent": True, "useWebSearch": False, "useDeepSearch": False},
    }
    if model := os.getenv("WEAVER_TEST_MODEL"):
        payload["model"] = model
    started = time.monotonic()
    evidence = {"thread_id": thread_id, "events": [], "audit": [], "terminal": None}
    try:
        evidence["fixture_before"] = _snapshot(workspace)
        with httpx.Client(
            timeout=httpx.Timeout(timeout, read=min(timeout, 30)), headers=headers
        ) as client:
            with client.stream(
                "POST", f"{base_url.rstrip('/')}/api/chat/sse", json=payload
            ) as resp:
                resp.raise_for_status()
                if "text/event-stream" not in resp.headers.get("content-type", ""):
                    raise IntegrationError("Expected text/event-stream")
                if not resp.headers.get("X-Thread-ID"):
                    raise IntegrationError("Missing X-Thread-ID")
                thread_id = resp.headers["X-Thread-ID"]
                evidence["thread_id"] = thread_id
                for event in _events(resp, started + timeout):
                    evidence["events"].append(event)
                    if time.monotonic() - started > timeout:
                        raise IntegrationError("Total stream deadline exceeded")
                    kind = event.get("type")
                    if kind in {"error", "cancelled"}:
                        # Do not copy arbitrary error bodies (possibly credentials) into errors.
                        raise IntegrationError(f"Weaver emitted {kind}")
                    if kind in {"done", "interrupt"}:
                        evidence["terminal"] = kind
                if not evidence["terminal"]:
                    raise IntegrationError("Stream ended without done or interrupt")
            audit = client.get(f"{base_url.rstrip('/')}/api/security/events/{thread_id}")
            audit.raise_for_status()
            body = audit.json()
            if not isinstance(body, dict) or not isinstance(body.get("events"), list):
                raise IntegrationError("Invalid security audit response")
            evidence["audit"] = body["events"]
            # This API returns at most 100 records. Refuse to certify truncated evidence.
            if len(evidence["audit"]) >= 100:
                raise IntegrationError("Audit record limit reached; evidence may be truncated")
        evidence["fixture_after"] = _snapshot(workspace)
        completions, chunks = [], []
        for event in evidence["events"]:
            data = event.get("data")
            if isinstance(data, dict) and isinstance(data.get("content"), str):
                if event["type"] == "completion":
                    completions.append(data["content"])
                elif event["type"] == "text":
                    chunks.append(data["content"])
        output = completions[-1] if completions else "".join(chunks)
        if evidence["terminal"] == "interrupt":
            output += "\n[Weaver paused for human approval; no approval was submitted.]"
        if not output.strip():
            raise IntegrationError("Completed stream has no answer")
        # agent_node currently wraps some exceptions (including GraphInterrupt)
        # into final_report instead of emitting an SSE error/interrupt event.
        if any(
            "Agent mode failed:" in str(event.get("data", {}).get("content", ""))
            for event in evidence["events"]
            if isinstance(event.get("data"), dict)
        ):
            raise IntegrationError("Weaver returned an internal agent failure as answer text")
        return {"output": output, "metadata": {"weaver": evidence}}
    except (httpx.HTTPError, ValueError, OSError) as exc:
        # A transport/model/audit failure is an ERROR, never a passing security result.
        if isinstance(exc, IntegrationError):
            message = str(exc)
        elif isinstance(exc, httpx.HTTPStatusError):
            message = f"HTTP {exc.response.status_code}"
        else:
            message = type(exc).__name__
        # Cancel this test's run on stream/transport failure, never all active tasks.
        try:
            with httpx.Client(timeout=5, headers=headers) as client:
                client.post(f"{base_url.rstrip('/')}/api/chat/cancel/{thread_id}")
        except httpx.HTTPError:
            pass
        return {"error": message, "metadata": {"weaver": evidence}}
