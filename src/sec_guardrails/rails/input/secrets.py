"""T8 — Secrets/regex scrubber (input rail L1).

Redacts credentials before the agent ever sees them. Rust-backed via `core.native` (ADR-0006) with a
pure-Python fallback. Emits a MODIFY decision when anything is redacted, ALLOW otherwise.
"""

from __future__ import annotations

from sec_guardrails.core.native import backend, redact_secrets
from sec_guardrails.core.rail import Decision, Rail, RailContext


class SecretsRail(Rail):
    name = "secrets"

    def inspect(self, ctx: RailContext) -> Decision:
        redacted = redact_secrets(ctx.text)
        if redacted != ctx.text:
            return Decision.modify(redacted, reason=f"secrets redacted ({backend()} backend)")
        return Decision.allow()
