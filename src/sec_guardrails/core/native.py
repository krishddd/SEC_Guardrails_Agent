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
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
_HTML_SCRIPT = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_HTML_STYLE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_HTML_TAG = re.compile(r"<[^>]+>", re.DOTALL)


def _py_redact_secrets(text: str) -> str:
    for rx, label in _SECRET_PATTERNS:
        text = rx.sub(f"[REDACTED:{label}]", text)
    return text


def _py_datamark(text: str, marker: str) -> str:
    return _WHITESPACE.sub(marker, text.strip())


def _host_of(url: str) -> str:
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[1]
    for sep in ("/", "?", "#", ":"):
        idx = u.find(sep)
        if idx != -1:
            u = u[:idx]
    return u.lower()


def _py_sanitize_markup(text: str, allow_hosts: list[str]) -> str:
    allow = {h.lower() for h in allow_hosts}
    text = _MD_IMAGE.sub("", text)

    def _link(m: re.Match[str]) -> str:
        label, url = m.group(1), m.group(2)
        return f"[{label}]({url})" if _host_of(url) in allow else label

    text = _MD_LINK.sub(_link, text)
    text = _HTML_SCRIPT.sub("", text)
    text = _HTML_STYLE.sub("", text)
    text = _HTML_TAG.sub("", text)
    return text


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


def sanitize_markup(text: str, allow_hosts: list[str] | None = None) -> str:
    """Strip exfil markup: markdown images, non-allowlisted links → text, raw HTML (T18)."""
    hosts = list(allow_hosts or [])
    if HAVE_RUST:
        return _rust.sanitize_markup(text, hosts)
    return _py_sanitize_markup(text, hosts)


def backend() -> str:
    return "rust" if HAVE_RUST else "python"
