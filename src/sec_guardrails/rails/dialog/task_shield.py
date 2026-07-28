"""T13 — Task-Shield off-task detector (dialog rail L2).

Task Shield (arXiv:2412.16682): evaluate each request against the user's stated task and block
off-task ones, even if benign in isolation. This deterministic version enforces an **allowed-task
envelope** (a set of permitted-intent patterns), deny-by-default: a request matching none is
off-task and blocked. A semantic LLM backend can later implement the same `inspect` contract.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sec_guardrails.core.rail import Decision, Rail, RailContext

DEFAULT_REFUSAL = "That request is outside this agent's permitted task scope."


class TaskShieldRail(Rail):
    name = "task_shield"

    def __init__(
        self,
        allowed_intents: Iterable[str],
        *,
        strict: bool = True,
        refusal: str = DEFAULT_REFUSAL,
    ):
        self._patterns = [re.compile(p, re.IGNORECASE) for p in allowed_intents]
        self.strict = strict
        self.refusal = refusal

    def _on_task(self, text: str) -> bool:
        return any(rx.search(text) for rx in self._patterns)

    def inspect(self, ctx: RailContext) -> Decision:
        # No envelope configured → nothing to enforce.
        if not self._patterns:
            return Decision.allow()
        if self._on_task(ctx.text):
            return Decision.allow()
        if self.strict:
            return Decision.block(f"{self.refusal} (off-task)")
        # Advisory mode: record but don't block.
        ctx.metadata["off_task"] = True
        return Decision.allow()
