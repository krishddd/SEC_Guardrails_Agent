"""T28 — Information-flow taint + trusted-action invariant (reasoning rail L3).

Borrowed from FIDES / CaMeL: track which tool-call args carry untrusted (tainted) data and enforce
the **trusted-action invariant** — a sensitive tool (write / exec / exfil) may run only if all its
inputs have high integrity (no untrusted taint). A global safety net layered ON TOP of the L4 policy
engine: even a permissive `allow` rule cannot let tainted data reach a sensitive sink.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sec_guardrails.rails.tool.policy import Effect, PolicyEngine, PolicyResult, ToolCall

# Tools whose arguments must be untainted (high integrity) to run.
DEFAULT_SENSITIVE_TOOLS = frozenset({"bash", "api_call", "send_email", "create_document"})


class TaintTracker:
    """Marks args whose string value contains text from a known untrusted origin (tool output,
    retrieved chunk, inbound email, …). A coarse but deterministic data-flow approximation."""

    def __init__(self, untrusted_origins: Iterable[str] = ()):
        self._origins = [o for o in untrusted_origins if o]

    def add_origin(self, text: str) -> None:
        if text:
            self._origins.append(text)

    def taint_of(self, call: ToolCall) -> set[str]:
        tainted = set(call.tainted_args)
        for key, value in call.args.items():
            if isinstance(value, str) and any(origin in value for origin in self._origins):
                tainted.add(key)
        return tainted


@dataclass
class TaintGate:
    """Evaluate the policy, then enforce the trusted-action invariant over the result."""

    engine: PolicyEngine
    tracker: TaintTracker | None = None
    sensitive_tools: frozenset[str] = field(default=DEFAULT_SENSITIVE_TOOLS)

    def decide(self, call: ToolCall) -> PolicyResult:
        tainted = set(call.tainted_args)
        if self.tracker is not None:
            tainted |= self.tracker.taint_of(call)

        result = self.engine.evaluate(call)
        if result.effect is Effect.ALLOW and tainted and call.name in self.sensitive_tools:
            args = sorted(tainted)
            return PolicyResult(
                Effect.BLOCK,
                result.rule_id,
                f"trusted-action invariant: untrusted args {args} on sensitive tool '{call.name}'",
            )
        return result
