"""Security boundaries used by tools and direct research helpers."""

import json
from dataclasses import asdict
from typing import Any

from common.security.content import contains_secret, enabled, inspect_injection, redact_sensitive
from common.security.context import current_context
from common.security.policy import evaluate
from common.security.store import SecurityStore


class SecurityViolation(ValueError):
    """Permanent policy failure; callers must not retry this action."""


def audit(event: str, **details) -> None:
    ctx = current_context.get()
    payload = redact_sensitive({"event": event, **details})
    SecurityStore().audit(ctx.principal if ctx else "local", ctx.thread_id if ctx else "", payload)
    if ctx and ctx.thread_id:
        # UI delivery is best effort; durable recording above is not.
        from agent.core.events import get_emitter_sync

        get_emitter_sync(ctx.thread_id).emit_sync("security", payload)


def private_data_present() -> bool:
    ctx = current_context.get()
    return bool(
        ctx
        and (
            ctx.private_data_seen
            or (ctx.thread_id and SecurityStore().has_private_data(ctx.principal, ctx.thread_id))
        )
    )


def risk_present() -> bool:
    ctx = current_context.get()
    return bool(
        ctx
        and (ctx.risk or (ctx.thread_id and SecurityStore().has_risk(ctx.principal, ctx.thread_id)))
    )


def mark_private_data(source: str) -> None:
    ctx = current_context.get()
    if ctx:
        with ctx.lock:
            first = not ctx.private_data_seen
            ctx.private_data_seen = True
        if first:
            audit("private_data_loaded", source=source)


def _matches_outbound(approved: dict | None, tool: str, args: dict) -> bool:
    if not approved:
        return False
    if approved == {"tool": tool, "args": args}:
        return True
    # A batch crawler delegates each approved URL to the single-URL helper.
    return (
        approved["tool"] == "crawl_urls"
        and tool == "crawl_url"
        and set(args) == {"url"}
        and args["url"] in approved["args"].get("urls", [])
    )


def check_outbound(tool: str, args: dict) -> None:
    from common.security.gateway import execution_context, outbound_key

    execution_context(None)
    decision = evaluate(tool, args, risk=risk_present(), private_data=private_data_present())
    if decision.action == "require_approval":
        # Only a gateway-issued permit for this exact outward call can authorize
        # a direct research helper; content/arguments cannot manufacture one.
        from common.security.context import active_call

        permit = active_call.get()
        if (
            permit
            and not permit.consumed
            and _matches_outbound(permit.outbound, tool, args)
            and permit.outbound_key == outbound_key(**permit.outbound)
        ):
            return
    if decision.action != "allow":
        audit("blocked", tool=tool, reason=decision.reason)
        raise SecurityViolation(f"Security policy blocked {tool}: {decision.reason}")


def untrusted(value: Any, *, source: str, private: bool = False) -> Any:
    """Keep schemas intact; server-owned provenance is out-of-band, not model supplied."""
    if private and value:
        mark_private_data(source)
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
    return redact_sensitive(value)


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
