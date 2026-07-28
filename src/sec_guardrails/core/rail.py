"""T4 — Rail framework.

The control-plane primitives every rail builds on:
  - `Decision` — allow / block / modify, with a reason.
  - `RailContext` — the inspected payload + trust/taint metadata (treat-all-external-as-untrusted).
  - `Rail` — the interface: `inspect(ctx) -> Decision`.
  - `RailChain` — ordered evaluation that SHORT-CIRCUITS on the first block (deny-by-default)
    and threads MODIFY results forward.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    MODIFY = "modify"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass
class Decision:
    action: Action
    reason: str = ""
    modified: str | None = None  # replacement text when action is MODIFY

    @classmethod
    def allow(cls, reason: str = "") -> Decision:
        return cls(Action.ALLOW, reason)

    @classmethod
    def block(cls, reason: str) -> Decision:
        return cls(Action.BLOCK, reason)

    @classmethod
    def modify(cls, text: str, reason: str = "") -> Decision:
        return cls(Action.MODIFY, reason, modified=text)


@dataclass
class RailContext:
    text: str
    source: str = "user"
    trust: TrustLevel = TrustLevel.UNTRUSTED
    taint: set[str] = field(default_factory=set)
    metadata: dict = field(default_factory=dict)


class Rail(ABC):
    """A single guardrail check. Subclasses set `name` and implement `inspect`."""

    name: str = "rail"

    @abstractmethod
    def inspect(self, ctx: RailContext) -> Decision: ...


@dataclass
class ChainResult:
    allowed: bool
    decision: Decision
    blocked_by: str | None
    ctx: RailContext


class RailChain:
    """Run rails in order; stop at the first BLOCK; apply MODIFYs to the context as we go."""

    def __init__(self, rails: list[Rail] | None = None):
        self.rails: list[Rail] = list(rails or [])

    def run(self, ctx: RailContext) -> ChainResult:
        for rail in self.rails:
            decision = rail.inspect(ctx)
            if decision.action is Action.BLOCK:
                return ChainResult(False, decision, rail.name, ctx)
            if decision.action is Action.MODIFY and decision.modified is not None:
                ctx.text = decision.modified
        return ChainResult(True, Decision.allow(), None, ctx)
