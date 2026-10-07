"""Bounded, deterministic text inspection. Findings never contain secret values."""

import base64
import re
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from common.config import settings


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str


SECRET_PATTERNS = (
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
        ),
    ),
    (
        "API_KEY",
        re.compile(
            r"\b(?:sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"
        ),
    ),
    ("BEARER", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    (
        "CREDENTIAL",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\s*[=:]\s*[\"']?(?!\[REDACTED)[A-Za-z0-9_./+~=-]{8,}"
        ),
    ),
    (
        "CONNECTION_STRING",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|https?)://[^\s/:]+:[^\s/@]+@[^\s]+"
        ),
    ),
)
SENSITIVE_FIELDS = frozenset(
    {
        "api_key",
        "apikey",
        "password",
        "access_token",
        "refresh_token",
        "client_secret",
        "authorization",
        "private_key",
    }
)
INJECTION_PATTERNS = (
    (
        "instruction_override",
        re.compile(
            r"(?i)(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system|user)\s+(?:instructions?|prompts?|requests?)|忽略.{0,12}(?:指令|要求)|绕过.{0,10}(?:审批|权限|安全)"
        ),
    ),
    (
        "role_spoofing",
        re.compile(
            r"(?i)<\|(?:im_start|system|developer)\|>|\[INST\]|(?:system|developer)\s+message\s*:\s*(?:you must|ignore)|系统指令[:\uFF1A]"
        ),
    ),
    (
        "credential_exfiltration",
        re.compile(
            r"(?is)(?:read|extract|send|upload|reveal|读取|提取|上传|发送|泄露).{0,160}(?:\.env|api[_ -]?key|private[_ -]?key|credentials?|密钥|凭据).{0,160}(?:https?://|upload|send|上传|发送)|(?:upload|send|上传|发送).{0,120}(?:\.env|private[_ -]?key|credentials?|密钥|凭据)"
        ),
    ),
    (
        "persistent_instruction",
        re.compile(
            r"(?is)(?:remember|store|save|记住|写入).{0,60}(?:always|future|permanent|以后|永久).{0,100}(?:ignore|bypass|override|忽略|绕过)"
        ),
    ),
)


def enabled() -> bool:
    return bool(settings.security_enabled)


def _configured_secrets() -> list[str]:
    # Connector credentials remain in connector configuration, never in model text.
    return [
        str(value)
        for name, value in settings.__dict__.items()
        if (name.endswith("_api_key") or name in {"internal_api_key", "database_url"})
        and isinstance(value, str)
        and len(value) >= 8
    ]


def _redact_plain(text: str) -> str:
    for secret in sorted(_configured_secrets(), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED:CONFIGURED_SECRET]")
    for label, pattern in SECRET_PATTERNS:
        text = pattern.sub(f"[REDACTED:{label}]", text)
    return text


def _redact_text(text: str) -> str:
    decoded = unquote(text)
    if decoded != text and _redact_plain(decoded) != decoded:
        return "[REDACTED:ENCODED_SECRET]"
    return _redact_plain(text)


def redact_text(text: str) -> str:
    return _redact_text(text) if enabled() else text


def redact_sensitive(value: Any) -> Any:
    """Unconditional sanitizer for execution audits and approval previews."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {
            _redact_text(str(key)): (
                "[REDACTED:CREDENTIAL]"
                if str(key).lower() in SENSITIVE_FIELDS and item
                else redact_sensitive(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    return value


def redact(value: Any) -> Any:
    """Optional model-content sanitation; never changes execution arguments."""
    return redact_sensitive(value) if enabled() else value


def contains_secret(value: Any) -> bool:
    if isinstance(value, str):
        return _redact_text(value) != value
    if isinstance(value, dict):
        return any(
            (str(key).lower() in SENSITIVE_FIELDS and bool(item))
            or contains_secret(str(key))
            or contains_secret(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_secret(item) for item in value)
    return False


def inspect_injection(text: str) -> list[Finding]:
    if not enabled():
        return []
    # Limit decoding work. No recursive/unbounded decoding of attacker-controlled data.
    normalized = unicodedata.normalize("NFKC", text[:200_000])
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    variants = [normalized, unquote(normalized)]
    for match in list(re.finditer(r"[A-Za-z0-9+/]{32,}={0,2}", normalized))[:16]:
        candidate = match.group(0)
        if len(candidate) <= 4096:
            with suppress(ValueError, UnicodeError):
                variants.append(base64.b64decode(candidate, validate=True).decode("utf-8"))
    matches = {
        name for name, pattern in INJECTION_PATTERNS if any(pattern.search(v) for v in variants)
    }
    high = "credential_exfiltration" in matches or len(matches) >= 2
    return [Finding(rule=name, severity="high" if high else "medium") for name in sorted(matches)]
