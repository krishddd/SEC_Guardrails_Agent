"""Loader for the Rust `guardrails_core` extension, with pure-Python fallbacks (ADR-0006).

Every Rust-backed primitive is mirrored here so the control plane runs (slower) when the compiled
extension isn't installed. `backend()` reports which path is active, for audit. The shared
`tests/vectors/` set asserts the two backends agree.
"""

from __future__ import annotations

import re

try:
    import guardrails_core as _rust  # type: ignore
except Exception:  # extension not built/installed — use the Python fallback
    _rust = None

HAVE_RUST = _rust is not None

# Keep these patterns IN SYNC with crates/guardrails-core/src/secrets.rs.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OPENAI_KEY"),
    (re.compile(r"gh[oprsu]_[A-Za-z0-9]{20,}"), "GITHUB_TOKEN"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "SLACK_TOKEN"),
]


_WHITESPACE = re.compile(r"\s+")


def _py_redact_secrets(text: str) -> str:
    for rx, label in _SECRET_PATTERNS:
        text = rx.sub(f"[REDACTED:{label}]", text)
    return text


def _py_datamark(text: str, marker: str) -> str:
    return _WHITESPACE.sub(marker, text.strip())


def redact_secrets(text: str) -> str:
    """Mask recognized credentials in `text`. Uses Rust when available, else the Python fallback."""
    if HAVE_RUST:
        return _rust.redact_secrets(text)
    return _py_redact_secrets(text)


def datamark(text: str, marker: str = "ˆ") -> str:
    """Spotlight untrusted text by replacing interword whitespace with `marker` (T11)."""
    if HAVE_RUST:
        return _rust.datamark(text, marker)
    return _py_datamark(text, marker)


def backend() -> str:
    return "rust" if HAVE_RUST else "python"
