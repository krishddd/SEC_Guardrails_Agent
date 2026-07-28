"""Blocked-phrases / word filter (AWS Bedrock Guardrails word-filter pattern, ADR-0010).

A simple, operator-configurable exact-phrase denylist applied to input and/or output. Complements
the semantic topic policy (T14) with a fast, auditable word/phrase block. Empty list = no-op.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sec_guardrails.core.rail import Decision, Rail, RailContext


class WordFilterRail(Rail):
    name = "word_filter"

    def __init__(self, blocked: Iterable[str], *, refusal: str = "blocked phrase"):
        self.refusal = refusal
        self._rules = [
            (phrase, re.compile(rf"\b{re.escape(phrase)}\b", re.IGNORECASE))
            for phrase in blocked
            if phrase
        ]

    def inspect(self, ctx: RailContext) -> Decision:
        for phrase, rx in self._rules:
            if rx.search(ctx.text):
                return Decision.block(f"{self.refusal}: '{phrase}'")
        return Decision.allow()
