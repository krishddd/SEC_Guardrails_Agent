"""T19 — Grounding / hallucination check (output rail L6).

When the response should be grounded in retrieved sources (passed in `ctx.metadata["sources"]`),
verify the output is actually supported. Default is a deterministic token-overlap judge; a RAGAS/NLI
LLM judge (reusing the eval pipeline's `grounding_judge`) plugs in behind the `ml` extra. No sources
in context → nothing to check, so the rail is a no-op (it never penalises free-form chat).
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from sec_guardrails.core.rail import Decision, Rail, RailContext

_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


@runtime_checkable
class GroundingJudge(Protocol):
    name: str

    def is_grounded(self, claim: str, sources: list[str]) -> bool: ...


class OverlapGroundingJudge:
    name = "overlap"

    def __init__(self, min_overlap: float = 0.5):
        self.min_overlap = min_overlap

    def is_grounded(self, claim: str, sources: list[str]) -> bool:
        claim_tokens = _tokens(claim)
        if not claim_tokens:
            return True
        source_tokens: set[str] = set()
        for src in sources:
            source_tokens |= _tokens(src)
        overlap = len(claim_tokens & source_tokens) / len(claim_tokens)
        return overlap >= self.min_overlap


class GroundingRail(Rail):
    name = "grounding"

    def __init__(self, judge: GroundingJudge | None = None, *, enabled: bool = True):
        self.judge = judge or OverlapGroundingJudge()
        self.enabled = enabled

    def inspect(self, ctx: RailContext) -> Decision:
        if not self.enabled:
            return Decision.allow()
        sources = ctx.metadata.get("sources")
        if not sources:
            return Decision.allow()  # nothing to ground against
        if not self.judge.is_grounded(ctx.text, list(sources)):
            return Decision.block(f"ungrounded / unsupported output ({self.judge.name})")
        return Decision.allow()
