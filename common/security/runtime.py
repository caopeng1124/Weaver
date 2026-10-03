"""Security boundaries used by tools and direct research helpers."""

import json
from dataclasses import asdict
from typing import Any

from common.security.content import contains_secret, enabled, inspect_injection, redact
from common.security.context import current_context
from common.security.policy import evaluate
from common.security.store import SecurityStore


class SecurityViolation(ValueError):
    """Permanent policy failure; callers must not retry this action."""


def audit(event: str, **details) -> None:
    if not enabled():
        return
    ctx = current_context.get()
    payload = redact({"event": event, **details})
    SecurityStore().audit(ctx.principal if ctx else "local", ctx.thread_id if ctx else "", payload)
    if ctx and ctx.thread_id:
        # UI delivery is best effort; durable recording above is not.
        from agent.core.events import get_emitter_sync

        get_emitter_sync(ctx.thread_id).emit_sync("security", payload)


def check_outbound(tool: str, args: dict) -> None:
    if not enabled():
        return
    ctx = current_context.get()
    decision = evaluate(tool, args, risk=ctx.risk if ctx else False)
    if decision.action != "allow":
        audit("blocked", tool=tool, reason=decision.reason)
        raise SecurityViolation(f"Security policy blocked {tool}: {decision.reason}")


def untrusted(value: Any, *, source: str) -> Any:
    """Keep schemas intact; server-owned provenance is out-of-band, not model supplied."""
    if not enabled():
        return value
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    findings = inspect_injection(text)
    ctx = current_context.get()
    if ctx:
        with ctx.lock:
            # Bounded metadata; conservative run-level risk survives summaries.
            if len(ctx.sources) < 256:
                ctx.sources[source] = {
                    "trust": "untrusted",
                    "findings": [asdict(f) for f in findings],
                }
            if findings:
                ctx.risk = True
    if findings:
        audit(
            "injection_detected",
            source=source,
            rules=[f.rule for f in findings],
            action="quarantined" if any(f.severity == "high" for f in findings) else "flagged",
        )
    if contains_secret(value):
        audit("redacted", source=source, reason="sensitive_content")
    if any(f.severity == "high" for f in findings):
        return _quarantine(value)
    return redact(value)


def _quarantine(value: Any) -> Any:
    if isinstance(value, str):
        return "[QUARANTINED: untrusted content attempted to change instructions or disclose credentials]"
    if isinstance(value, dict):
        return {
            "quarantined_key" if inspect_injection(str(k)) else k: _quarantine(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_quarantine(v) for v in value]
    return value
