"""T17 — Output PII/secret/canary-leak rail (output rail L6).

Last line before a response leaves the gateway:
  1. Canary tokens planted in the system prompt → if any appears in the output, the prompt leaked
     (system-prompt exfiltration) → hard BLOCK.
  2. Redact secrets (T8 core) and PII (T10 detector) from the outbound text → MODIFY.
Clean output passes through.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.native import redact_secrets
from core.rail import Decision, Rail, RailContext
from rails.input.pii import HeuristicPIIDetector, PIIDetector


class OutputLeakRail(Rail):
    name = "output_leak"

    def __init__(
        self,
        canaries: Iterable[str] = (),
        pii_detector: PIIDetector | None = None,
    ):
        self.canaries = [c for c in canaries if c]
        self.pii = pii_detector or HeuristicPIIDetector()

    def inspect(self, ctx: RailContext) -> Decision:
        for canary in self.canaries:
            if canary in ctx.text:
                return Decision.block("canary token leaked — possible system-prompt exfiltration")

        redacted = redact_secrets(ctx.text)
        result = self.pii.redact(redacted)
        if result.text != ctx.text:
            return Decision.modify(result.text, reason="redacted secrets/PII from output")
        return Decision.allow()
