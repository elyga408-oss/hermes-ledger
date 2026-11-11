"""Secret redaction for tool arguments before they reach the ledger.

Two rules:

1. Any mapping key matching ``(?i)(key|token|secret|password|passwd|auth|cookie|credential)``
   has its value replaced, whatever the value is.
2. Inside every string, values that look like credentials are replaced:
   ``Bearer <token>``, ``sk-...`` API keys, a few other well-known token shapes,
   PEM private-key blocks, and ``NAME=value`` / ``name: value`` assignments
   whose name matches rule 1.

Redaction errs on the side of masking too much: a ledger that hides a harmless
value is fine, one that stores a live key is not.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "[REDACTED]"
MAX_STRING = 4000
MAX_DEPTH = 12
MAX_ITEMS = 200

SENSITIVE_KEY = re.compile(r"(?i)(key|token|secret|password|passwd|auth|cookie|credential)")

_NAME = r"[A-Za-z0-9_.-]*(?i:key|token|secret|password|passwd|auth|cookie|credential)[A-Za-z0-9_.-]*"

_VALUE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     MASK),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 " + MASK),
    # OpenAI / Anthropic / generic "sk-" keys (sk-..., sk-proj-..., sk-ant-...)
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), MASK),
    # GitHub, Slack, AWS access key ids, Google API keys, JWTs
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),
    # NAME=value, NAME: value, --name value / --name=value  (name matches the sensitive-key rule)
    (re.compile(r"(?P<n>(?<![A-Za-z0-9_])" + _NAME + r")(?P<sep>\s*[=:]\s*)"
                r"(?P<v>\"[^\"]*\"|'[^']*'|[^\s,;&|]+)"),
     r"\g<n>\g<sep>" + MASK),
    (re.compile(r"(?P<n>--" + _NAME + r")(?P<sep>[ =])(?P<v>\"[^\"]*\"|'[^']*'|[^\s]+)"),
     r"\g<n>\g<sep>" + MASK),
    # URL credentials: scheme://user:pass@host
    (re.compile(r"(?P<s>[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@"), r"\g<s>" + MASK + "@"),
]


def redact_string(text: str) -> str:
    for pattern, repl in _VALUE_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _truncate(text: str) -> str:
    if len(text) <= MAX_STRING:
        return text
    return text[:MAX_STRING] + f"...[+{len(text) - MAX_STRING} chars]"


def redact(value: Any, *, truncate: bool = True, _depth: int = 0) -> Any:
    """Return a JSON-safe, redacted copy of ``value``. Never raises for odd inputs."""
    if _depth > MAX_DEPTH:
        return "[...depth limit]"
    if isinstance(value, dict):
        out = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_ITEMS:
                out["..."] = f"[+{len(value) - MAX_ITEMS} keys]"
                break
            key = str(k)
            if SENSITIVE_KEY.search(key) and v not in (None, "", [], {}):
                out[key] = MASK
            else:
                out[key] = redact(v, truncate=truncate, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [redact(v, truncate=truncate, _depth=_depth + 1) for v in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"[+{len(value) - MAX_ITEMS} items]")
        return items
    if isinstance(value, str):
        cleaned = redact_string(value)
        return _truncate(cleaned) if truncate else cleaned
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    # bytes, objects, anything else: describe, do not serialise contents
    text = redact_string(repr(value))
    return _truncate(text) if truncate else text
