"""Budget / cost tracking (Pydantic AI Shields CostTracking pattern, ADR-0010).

Per-session caps on tool calls, tokens, and USD. The engine checks-and-charges before allowing a
tool call; exceeding a cap blocks the action (deny-by-default on overrun) — the deterministic
analogue of Pydantic's BudgetExceededError, bounding an agent's blast radius and runaway cost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Budget:
    max_tool_calls: int | None = None
    max_tokens: int | None = None
    max_usd: float | None = None


@dataclass
class BudgetTracker:
    budget: Budget
    tool_calls: int = 0
    tokens: int = 0
    usd: float = 0.0

    def check_and_charge(
        self, *, tool_calls: int = 1, tokens: int = 0, usd: float = 0.0
    ) -> tuple[bool, str]:
        """If charging stays within every cap, apply it and return (True, "ok"); else charge nothing
        and return (False, reason)."""
        b = self.budget
        if b.max_tool_calls is not None and self.tool_calls + tool_calls > b.max_tool_calls:
            return False, f"tool-call budget exceeded (cap {b.max_tool_calls})"
        if b.max_tokens is not None and self.tokens + tokens > b.max_tokens:
            return False, f"token budget exceeded (cap {b.max_tokens})"
        if b.max_usd is not None and self.usd + usd > b.max_usd:
            return False, f"cost budget exceeded (cap ${b.max_usd})"
        self.tool_calls += tool_calls
        self.tokens += tokens
        self.usd += usd
        return True, "ok"

    def spent(self) -> dict:
        return {"tool_calls": self.tool_calls, "tokens": self.tokens, "usd": self.usd}
