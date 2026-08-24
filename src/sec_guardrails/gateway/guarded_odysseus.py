"""T31a — GuardedOdysseusClient: the "via gateway" arm for the live A/B (T31).

Fronts a real `OdysseusClient` with the unified `GuardrailEngine`, so any turn against Odysseus
gets the same rails the reference agent does. An adapter, not a rebuild: it maps Odysseus's
request/response surface onto the agent-agnostic `guard_*` API.

What it can enforce, and the honest limits (CLAUDE.md gotcha):
  - **input  — preventive.** `guard_input` runs *before* the message reaches Odysseus; a blocked
    message is never sent (no `4xx`/cost, no side effects).
  - **tool   — detective only, until T20.** The API token gets **no per-step tool trace**
    (`/api/v1/chat` runs no tools). When a trace *is* present (a future agent-mode build, or once
    the T20 trace-export hook feeds one in), every call is run through `guard_tool` and audited —
    but the tool has already executed server-side, so this is detection/audit, not prevention. Real
    tool-layer *prevention* stays gated on T20.
  - **output — preventive.** `guard_output` runs on the reply before it is returned to the caller.

The message is the trusted command channel (scanned, never datamarked), matching the reference
`GuardedAgent`; prompt-injection/secret/PII rails fire regardless of trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sec_guardrails.core.engine import GuardrailEngine, ToolVerdict
from sec_guardrails.core.rail import TrustLevel
from sec_guardrails.rails.oversight.critic import Trajectory
from sec_guardrails.rails.tool.policy import Effect, ToolCall

from .odysseus_client import OdysseusClient

# Candidate keys for a tool-trace array / its fields — mirrors the eval-pipeline adapter's defensive
# probing, since the live trace JSON shape is not yet pinned (OQ3). Narrow once T20 lands.
_TRACE_LIST_KEYS = ("tool_calls", "steps", "trace", "actions", "events", "history", "tools")
_STEP_NAME_KEYS = ("tool", "name", "tool_name", "action", "function")
_STEP_PARAM_KEYS = ("parameters", "params", "input", "args", "arguments", "tool_input")
_RESPONSE_KEYS = ("response", "output", "text", "content", "message", "reply")


@dataclass
class ToolFinding:
    """A detective verdict on a tool call already executed server-side."""

    tool: str
    effect: Effect
    reason: str
    stage: str


@dataclass
class GuardedReply:
    allowed: bool
    output: str | None
    reason: str
    stage: str  # which guard stage decided: input | tool | output | ok
    session_id: str | None = None
    model: str | None = None
    tool_findings: list[ToolFinding] = field(default_factory=list)
    raw: dict[str, Any] | None = None


class GuardedOdysseusClient:
    """Wraps an `OdysseusClient` with a `GuardrailEngine`."""

    def __init__(
        self,
        client: OdysseusClient,
        engine: GuardrailEngine,
        *,
        input_trust: TrustLevel = TrustLevel.TRUSTED,
    ):
        self.client = client
        self.engine = engine
        self.input_trust = input_trust

    def health_check(self) -> dict[str, Any]:
        """Delegate to the wrapped client so the gateway `/health` route works for either client
        type (a bare `OdysseusClient` or this guarded wrapper)."""
        return self.client.health_check()

    def chat(
        self,
        message: str,
        *,
        now: float = 0.0,
        model: str | None = None,
        session: str | None = None,
    ) -> GuardedReply:
        # 1) Input guard — preventive. A blocked message is never sent to Odysseus. `session` feeds
        # the G9 per-session threat accumulator so multi-turn attacks are caught across turns.
        gin = self.engine.guard_input(
            message, trust=self.input_trust, source="user", session=session
        )
        if not gin.allowed:
            return GuardedReply(False, None, gin.reason, "input")

        # 2) Forward the sanitized message (PII/secrets redacted, spotlight-marked) to Odysseus.
        data = self.client.chat(gin.text or message, model=model, session=session)
        if not isinstance(data, dict):
            data = {"response": str(data)}

        # 3) Tool guard — detective/audit only over any trace present (see module docstring).
        findings = [
            ToolFinding(v.call.name, v.effect, v.reason, v.stage)
            for v in self._guard_trace(data, now=now)
            if v.effect is not Effect.ALLOW
        ]

        # 4) Output guard — preventive, on the reply text.
        reply_text = self._extract_response(data)
        gout = self.engine.guard_output(reply_text)
        if not gout.allowed:
            return GuardedReply(
                False, None, gout.reason, "output", tool_findings=findings, raw=data
            )

        # 5) L7 oversight (detective) — fires the configured critic (e.g. the N8 LLM judge) on the
        # final trajectory; advisory, so it never blocks the reply, but the verdict is audited.
        self.engine.review(
            Trajectory(task=message, steps=[f.tool for f in findings], output=gout.text or "")
        )

        return GuardedReply(
            True,
            gout.text or "",
            "ok",
            "ok",
            session_id=data.get("session_id"),
            model=data.get("model"),
            tool_findings=findings,
            raw=data,
        )

    # ── trace handling (defensive until the T20 shape is pinned) ─────────────────
    def _guard_trace(self, data: dict[str, Any], *, now: float) -> list[ToolVerdict]:
        return [self.engine.guard_tool(call, now=now) for call in self._extract_tool_calls(data)]

    @classmethod
    def _extract_tool_calls(cls, data: dict[str, Any]) -> list[ToolCall]:
        for key in _TRACE_LIST_KEYS:
            val = data.get(key)
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return [cls._normalise_call(step) for step in val if isinstance(step, dict)]
        return []

    @classmethod
    def _normalise_call(cls, step: dict[str, Any]) -> ToolCall:
        name = next((str(step[k]) for k in _STEP_NAME_KEYS if step.get(k)), "unknown")
        params = next((step[k] for k in _STEP_PARAM_KEYS if isinstance(step.get(k), dict)), {})
        # Tool outputs are untrusted; every arg sourced from a tool trace is tainted.
        return ToolCall(name, dict(params), tainted_args=set(params.keys()))

    @staticmethod
    def _extract_response(data: dict[str, Any]) -> str:
        for key in _RESPONSE_KEYS:
            val = data.get(key)
            if isinstance(val, str) and val:
                return val
        return ""
