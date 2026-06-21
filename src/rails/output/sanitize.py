"""T18 — URL/markdown/HTML sanitizer (output rail L6).

Strips exfiltration side-channels from agent output before it reaches a UI: markdown images (a
data-bearing `src` exfil), markdown links to non-allowlisted hosts (reduced to plain text), and raw
HTML/script/style. Rust-backed via `core.native` (ADR-0006) with a pure-Python fallback.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.native import backend, sanitize_markup
from core.rail import Decision, Rail, RailContext


class SanitizeRail(Rail):
    name = "sanitize"

    def __init__(self, allow_hosts: Iterable[str] = ()):
        self.allow_hosts = list(allow_hosts)

    def inspect(self, ctx: RailContext) -> Decision:
        cleaned = sanitize_markup(ctx.text, self.allow_hosts)
        if cleaned != ctx.text:
            return Decision.modify(cleaned, reason=f"sanitized output markup ({backend()} backend)")
        return Decision.allow()
