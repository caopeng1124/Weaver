#!/usr/bin/env python3
"""
Weaver API smoke test (no secret leakage).

Runs a minimal end-to-end check against a running backend:
  - /health
  - /api/chat (direct, non-stream)
  - /api/chat/sse (stream)
  - /api/chat (web mode, non-stream) [optional/slow]
  - /api/asr/status
  - /api/tts/status
  - /api/tts/synthesize [optional]

Notes:
  - Does NOT print any API keys.
  - Designed for local dev and quick diagnostics.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from typing import Any, Dict

import httpx

# Keep smoke output readable (avoid unrelated CUDA env warnings during imports).
warnings.filterwarnings(
    "ignore",
    message="The pynvml package is deprecated*",
    category=FutureWarning,
)

# Ensure repo root is on sys.path when running as a script:
#   python scripts/smoke_test_api.py
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    # Prefer Weaver's Settings (reads .env) over raw process env when available.
    from common.config import settings as _WEAVER_SETTINGS  # type: ignore
except Exception:  # pragma: no cover
    _WEAVER_SETTINGS = None  # type: ignore


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _bool_env(name: str, default: bool = False) -> bool:
    raw = _env(name, "")
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def _compact_error(exc: Exception) -> str:
    msg = str(exc).strip().replace("\n", " ")
    return msg[:300] + ("..." if len(msg) > 300 else "")


def _normalize_socks_proxy_env() -> None:
    """
    Avoid httpx crashing on `ALL_PROXY=socks://...`.

    Many environments export SOCKS proxies as `socks://host:port`, while httpx
    expects an explicit version scheme (e.g. `socks5://`).
    """
    for key in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        if raw.lower().startswith("socks://"):
            os.environ[key] = "socks5://" + raw[len("socks://") :]


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    seconds: float = 0.0


def _truncate(text: str, limit: int = 220) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text[:limit] + ("..." if len(text) > limit else "")


def _try_json(resp: httpx.Response) -> Dict[str, Any]:
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _client(base_url: str) -> httpx.Client:
    _normalize_socks_proxy_env()
    headers: Dict[str, str] = {}

    internal_key = _env("WEAVER_INTERNAL_API_KEY", "")
    if not internal_key and _WEAVER_SETTINGS is not None:
        internal_key = (getattr(_WEAVER_SETTINGS, "internal_api_key", "") or "").strip()
    if internal_key:
        headers["Authorization"] = f"Bearer {internal_key}"
        # Optional identity header used by Weaver when internal auth is enabled.
        user_header = _env("WEAVER_AUTH_USER_HEADER", "")
        if not user_header and _WEAVER_SETTINGS is not None:
            user_header = (getattr(_WEAVER_SETTINGS, "auth_user_header", "") or "").strip()
        headers[user_header or "X-Weaver-User"] = _env("WEAVER_TEST_USER", "smoke")

    return httpx.Client(
        base_url=base_url.rstrip("/"),
        headers=headers,
        # Web-search runs can be slow (60–180s) depending on providers/network.
        timeout=httpx.Timeout(connect=10.0, read=240.0, write=10.0, pool=10.0),
        follow_redirects=True,
    )


def _check_health(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        r = client.get("/health")
        r.raise_for_status()
        data = r.json()
        ok = (data or {}).get("status") == "healthy"
        return CheckResult(
            name="health",
            ok=bool(ok),
            detail=f"status={data.get('status')}, version={data.get('version')}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("health", False, _compact_error(e), time.time() - t0)


def _check_chat_direct(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        payload = {
            "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
            "stream": False,
        }
        r = client.post("/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        content = (data or {}).get("content") or ""
        ok = content.strip() == "pong"
        return CheckResult(
            name="chat_direct",
            ok=bool(ok),
            detail=f"content={content.strip()[:30]!r}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("chat_direct", False, _compact_error(e), time.time() - t0)


def _check_chat_sse(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        payload = {
            "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
            "stream": True,
        }

        got_event = False
        with client.stream("POST", "/api/chat/sse", json=payload) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                if line.startswith("event:"):
                    got_event = True
                if line.startswith("event: done"):
                    break
                # Stop early once we've confirmed we can parse frames.
                if got_event and time.time() - t0 > 8.0:
                    break

        return CheckResult(
            name="chat_sse",
            ok=bool(got_event),
            detail=("got_sse_event" if got_event else "no_sse_event"),
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("chat_sse", False, _compact_error(e), time.time() - t0)


def _check_chat_web(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": "Find 1 technology news headline today and cite the source URL.",
                }
            ],
            "stream": False,
            "search_mode": "web",
        }
        r = client.post("/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        content = (data or {}).get("content") or ""
        ok = bool(content.strip()) and "http" in content
        return CheckResult(
            name="chat_web",
            ok=bool(ok),
            detail=f"chars={len(content)}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("chat_web", False, _compact_error(e), time.time() - t0)


def _check_asr_status(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        r = client.get("/api/asr/status")
        r.raise_for_status()
        data = r.json()
        return CheckResult(
            name="asr_status",
            ok=True,
            detail=f"enabled={bool(data.get('enabled'))}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("asr_status", False, _compact_error(e), time.time() - t0)


def _check_tts_status(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        r = client.get("/api/tts/status")
        r.raise_for_status()
        data = r.json()
        return CheckResult(
            name="tts_status",
            ok=True,
            detail=f"enabled={bool(data.get('enabled'))}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("tts_status", False, _compact_error(e), time.time() - t0)


def _check_tts_synthesize(client: httpx.Client) -> CheckResult:
    t0 = time.time()
    try:
        payload = {"text": "Hello from Weaver", "voice": "loongstella"}
        r = client.post("/api/tts/synthesize", json=payload)
        data = _try_json(r)
        if r.status_code >= 400:
            msg = data.get("error") or data.get("detail") or r.text
            return CheckResult(
                name="tts_synthesize",
                ok=False,
                detail=f"status={r.status_code} msg={_truncate(str(msg))}",
                seconds=time.time() - t0,
            )
        audio = (data or {}).get("audio") or ""
        ok = bool((data or {}).get("success")) and bool(audio)
        return CheckResult(
            name="tts_synthesize",
            ok=bool(ok),
            detail=f"audio_len={len(audio)} format={data.get('format')}",
            seconds=time.time() - t0,
        )
    except Exception as e:
        return CheckResult("tts_synthesize", False, _compact_error(e), time.time() - t0)


def _check_chat_deep_cancel(base_url: str) -> CheckResult:
    """
    Start a deep-mode SSE run and cancel it, asserting we observe a cancellation frame.

    This is a behavior check for:
      - deep search path runs
      - /api/chat/cancel/{thread_id} wiring
      - server-side cancellation propagation to stream
    """
    t0 = time.time()

    stream_ready = Event()
    watcher_done = Event()

    state: Dict[str, Any] = {
        "thread_id": None,
        "got_event": False,
        "got_cancelled": False,
        "got_done": False,
        "error": None,
    }

    def _watch_stream() -> None:
        try:
            with _client(base_url) as c:
                payload = {
                    "messages": [
                        {
                            "role": "user",
                            "content": "Do deep research on: AI agent framework trends. Provide a short outline.",
                        }
                    ],
                    "stream": True,
                    "search_mode": "deep",
                }
                with c.stream("POST", "/api/chat/sse", json=payload) as resp:
                    resp.raise_for_status()
                    state["thread_id"] = resp.headers.get("X-Thread-ID")
                    stream_ready.set()
                    start = time.time()
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        if line.startswith("event:"):
                            state["got_event"] = True
                            if line.startswith("event: cancelled"):
                                state["got_cancelled"] = True
                                break
                            if line.startswith("event: done"):
                                state["got_done"] = True
                                break
                        # Timebox observation; cancellation should land quickly.
                        if time.time() - start > 25.0:
                            break
        except Exception as e:  # noqa: BLE001
            state["error"] = _compact_error(e)
            stream_ready.set()
        finally:
            watcher_done.set()

    t = Thread(target=_watch_stream, daemon=True)
    t.start()

    # Wait until we have thread_id (or error)
    if not stream_ready.wait(timeout=8.0):
        return CheckResult("chat_deep_cancel", False, "stream did not start", time.time() - t0)

    thread_id = (state.get("thread_id") or "").strip()
    if state.get("error"):
        return CheckResult(
            "chat_deep_cancel", False, f"stream_error={state['error']}", time.time() - t0
        )
    if not thread_id:
        return CheckResult("chat_deep_cancel", False, "missing X-Thread-ID header", time.time() - t0)

    try:
        with _client(base_url) as c:
            cr = c.post(f"/api/chat/cancel/{thread_id}", json={"reason": "smoke test cancel"})
            data = _try_json(cr)
            if cr.status_code >= 400:
                msg = data.get("error") or data.get("detail") or cr.text
                return CheckResult(
                    "chat_deep_cancel",
                    False,
                    f"cancel_status={cr.status_code} msg={_truncate(str(msg))}",
                    time.time() - t0,
                )
            if (data or {}).get("status") != "cancelled":
                return CheckResult(
                    "chat_deep_cancel",
                    False,
                    f"cancel_unexpected={_truncate(json.dumps(data, ensure_ascii=False)[:300])}",
                    time.time() - t0,
                )
    except Exception as e:
        return CheckResult("chat_deep_cancel", False, f"cancel_error={_compact_error(e)}", time.time() - t0)

    # Wait briefly for the watcher to observe cancelled/done.
    watcher_done.wait(timeout=20.0)

    ok = bool(state.get("got_cancelled") or state.get("got_done"))
    detail = (
        "observed_cancelled"
        if state.get("got_cancelled")
        else ("observed_done" if state.get("got_done") else "no_cancel_frame_observed")
    )
    if not state.get("got_event"):
        ok = False
        detail = "no_sse_event_observed"

    return CheckResult("chat_deep_cancel", ok, detail, time.time() - t0)


def _check_provider_serper() -> CheckResult:
    t0 = time.time()
    configured = bool(_env("SERPER_API_KEY", ""))
    if not configured and _WEAVER_SETTINGS is not None:
        configured = bool((getattr(_WEAVER_SETTINGS, "serper_api_key", "") or "").strip())
    if not configured:
        return CheckResult("provider_serper", True, "not_configured", time.time() - t0)
    try:
        from tools.search.providers import serper_search

        res = serper_search("OpenAI", max_results=1)
        ok = bool(res)
        return CheckResult(
            "provider_serper",
            ok,
            (f"results={len(res)}" if ok else "no_results_or_invalid_key"),
            time.time() - t0,
        )
    except Exception as e:
        return CheckResult("provider_serper", False, _compact_error(e), time.time() - t0)


def _check_provider_firecrawl() -> CheckResult:
    t0 = time.time()
    configured = bool(_env("FIRECRAWL_API_KEY", ""))
    if not configured and _WEAVER_SETTINGS is not None:
        configured = bool((getattr(_WEAVER_SETTINGS, "firecrawl_api_key", "") or "").strip())
    if not configured:
        return CheckResult("provider_firecrawl", True, "not_configured", time.time() - t0)
    try:
        from tools.search.providers import firecrawl_search

        res = firecrawl_search("OpenAI", max_results=1)
        ok = bool(res)
        return CheckResult(
            "provider_firecrawl",
            ok,
            (f"results={len(res)}" if ok else "no_results_or_invalid_key"),
            time.time() - t0,
        )
    except Exception as e:
        return CheckResult("provider_firecrawl", False, _compact_error(e), time.time() - t0)


def _check_provider_e2b() -> CheckResult:
    t0 = time.time()
    if _WEAVER_SETTINGS is None or _WEAVER_SETTINGS.sandbox_mode not in {"e2b", "local"}:
        return CheckResult("provider_e2b", True, "not_selected", time.time() - t0)
    configured = bool(_env("E2B_API_KEY", ""))
    if not configured and _WEAVER_SETTINGS is not None:
        configured = bool((getattr(_WEAVER_SETTINGS, "e2b_api_key", "") or "").strip())
    if not configured:
        return CheckResult("provider_e2b", True, "not_configured", time.time() - t0)
    try:
        import uuid

        from common.security.context import security_scope
        from common.security.gateway import SecureTool
        from tools.code.code_executor import execute_python_code
        from tools.sandbox.local_service import get_local_service
        thread = "smoke_" + uuid.uuid4().hex
        try:
            with security_scope("provider-smoke", thread):
                res = SecureTool(execute_python_code).invoke({"code": "print(1+1)"}, config={"configurable": {"thread_id": thread}})
        finally:
            get_local_service().stop_thread(thread)
        ok = bool((res or {}).get("success"))
        stdout = (res or {}).get("stdout") or ""
        if isinstance(stdout, list):
            stdout = "".join(str(x) for x in stdout)
        return CheckResult(
            "provider_e2b",
            ok,
            (f"stdout={_truncate(str(stdout), 40)!r}" if ok else f"error={_truncate(str((res or {}).get('error') or ''))}"),
            time.time() - t0,
        )
    except Exception as e:
        return CheckResult("provider_e2b", False, _compact_error(e), time.time() - t0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base-url",
        default=_env("WEAVER_BASE_URL", "http://127.0.0.1:8001"),
        help="Backend base URL (default from WEAVER_BASE_URL or http://127.0.0.1:8001)",
    )
    ap.add_argument("--skip-web", action="store_true", help="Skip slow web-search chat check")
    ap.add_argument("--skip-tts", action="store_true", help="Skip /api/tts/synthesize check")
    ap.add_argument(
        "--skip-deep",
        action="store_true",
        help="Skip deep-mode SSE cancellation check (saves time/tokens)",
    )
    ap.add_argument(
        "--check-providers",
        action="store_true",
        help="Also validate optional providers (serper/firecrawl/e2b) using real API calls",
    )
    args = ap.parse_args()

    results: list[CheckResult] = []

    with _client(args.base_url) as client:
        results.append(_check_health(client))
        results.append(_check_chat_direct(client))
        results.append(_check_chat_sse(client))
        if not args.skip_web:
            results.append(_check_chat_web(client))
        results.append(_check_asr_status(client))
        results.append(_check_tts_status(client))
        if not args.skip_tts:
            results.append(_check_tts_synthesize(client))

    if not args.skip_deep:
        results.append(_check_chat_deep_cancel(args.base_url))

    if args.check_providers:
        results.append(_check_provider_serper())
        results.append(_check_provider_firecrawl())
        results.append(_check_provider_e2b())

    failed = [r for r in results if not r.ok]
    for r in results:
        status = "OK" if r.ok else "FAIL"
        print(f"{status:4} {r.name:14} {r.seconds:6.2f}s  {r.detail}")

    if failed:
        print(f"\nFAILED: {len(failed)}/{len(results)} checks")
        return 1
    print(f"\nALL OK: {len(results)} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
