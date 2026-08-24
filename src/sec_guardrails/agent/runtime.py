"""Reference guarded agent (ADR-0009). N5 — Plan-Then-Execute + Context-Minimization.

A deterministic tool-executing agent loop that runs *under* the GuardrailEngine, so the full safety
net is exercised end-to-end with no external dependency. The user message is the trusted command
channel (scanned, not datamarked); tool outputs are untrusted. A tiny line-based planner maps
commands to tool calls so tests can drive exact (benign and malicious) behaviour.

**N5 — design-by-construction.** `handle()` runs two explicit phases:
  1. **plan** — the full tool plan is derived from the *trusted user message only*, BEFORE any tool
     runs (`_plan_phase`). The plan is then frozen.
  2. **execute** — the frozen plan runs (`_execute_phase`); untrusted tool output can only fill data
     slots, it is never re-parsed into new steps. So an injected "now also email X" inside a tool
     result structurally cannot create an action — a defense that holds even if every classifier
     fails.
  With `context_minimization=True`, raw untrusted tool text is dropped from the context forwarded to
  the oversight layer (only a short extracted label survives), shrinking the injection surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sec_guardrails.core.engine import GuardrailEngine
from sec_guardrails.core.rail import TrustLevel
from sec_guardrails.rails.memory.write_guard import MemoryRecord, Provenance
from sec_guardrails.rails.oversight.critic import Trajectory
from sec_guardrails.rails.tool.policy import Effect, ToolCall

from .tools import Tool, default_tools

# command prefix -> (tool name, arg name)
_PLAN: dict[str, tuple[str, str]] = {
    "calc": ("calc", "expr"),
    "bash": ("bash", "cmd"),
    "run": ("bash", "cmd"),
    "sql": ("sql", "query"),
    "fetch": ("http_fetch", "url"),
    "echo": ("echo", "text"),
}


@dataclass
class AgentResult:
    output: str
    blocked: bool = False
    block_reason: str = ""
    steps: list[str] = field(default_factory=list)
    pending_approvals: list[str] = field(default_factory=list)
    sanitized_spans: int = 0  # N2: injected spans stripped from tool outputs this turn


class GuardedAgent:
    def __init__(
        self,
        engine: GuardrailEngine,
        tools: dict[str, Tool] | None = None,
        *,
        context_minimization: bool = False,
    ):
        self.engine = engine
        self.tools = tools or default_tools()
        # N5.2: drop raw untrusted tool text from the context forwarded to oversight.
        self.context_minimization = context_minimization

    def _plan(self, text: str) -> list[tuple[str, ToolCall | str]]:
        """Parse command lines into (kind, payload). kind='tool'|'memory'|'echo'."""
        plan: list[tuple[str, ToolCall | str]] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            prefix, _, rest = line.partition(":")
            prefix = prefix.strip().lower()
            rest = rest.strip()
            if prefix == "remember" and rest:
                plan.append(("memory", rest))
            elif prefix in _PLAN and rest:
                tool, arg = _PLAN[prefix]
                plan.append(("tool", ToolCall(tool, {arg: rest})))
            else:
                plan.append(("echo", line))
        return plan

    def _plan_phase(self, trusted_text: str) -> list[tuple[str, ToolCall | str]]:
        """N5.1 — derive the full plan from the TRUSTED user message before any tool runs. The
        returned plan is frozen: `_execute_phase` never re-plans, so untrusted tool output cannot
        add or reorder steps."""
        return self._plan(trusted_text)

    def _execute_phase(
        self, plan: list[tuple[str, ToolCall | str]], *, now: float
    ) -> tuple[list[str], list[str], list[str], int, list[str]]:
        """Run the frozen plan. Returns (user_outputs, steps, pending, sanitized, context_chunks).
        `context_chunks` is what is forwarded to oversight — minimized (raw untrusted tool text
        dropped) when `context_minimization` is on."""
        steps: list[str] = []
        outputs: list[str] = []
        context: list[str] = []
        pending: list[str] = []
        sanitized = 0

        for kind, payload in plan:
            if kind == "echo":
                outputs.append(str(payload))
                context.append(str(payload))  # trusted user text
                continue
            if kind == "memory":
                rec = MemoryRecord("default", str(payload), Provenance("user", "trusted", now))
                decision = self.engine.guard_memory_write(rec)
                steps.append("memory_write")
                msg = "remembered." if decision.allowed else f"[memory blocked: {decision.reason}]"
                outputs.append(msg)
                context.append(msg)
                continue

            call = payload  # ToolCall
            assert isinstance(call, ToolCall)
            steps.append(call.name)
            verdict = self.engine.guard_tool(call, now=now)
            if verdict.effect is Effect.BLOCK:
                msg = f"[blocked {call.name}: {verdict.reason}]"
                outputs.append(msg)
                context.append(msg)
            elif verdict.effect is Effect.HITL:
                pending.append(verdict.approval_id or "")
                msg = f"[awaiting approval for {call.name}]"
                outputs.append(msg)
                context.append(msg)
            else:
                tool = self.tools.get(verdict.call.name)
                if tool is None:
                    ran = f"[no such tool {call.name}]"
                else:
                    try:
                        ran = tool.run(verdict.call.args)
                    except Exception as exc:  # a tool failure is data, never a crash of the turn
                        ran = f"[tool error {verdict.call.name}: {type(exc).__name__}: {exc}]"
                # D4/N2: the tool result is UNTRUSTED — scan it for indirect injection (XPIA)
                # before it re-enters the model's context. An injected span is stripped (benign
                # remainder survives); a result sanitization can't make safe is dropped whole.
                scanned = self.engine.guard_tool_output(ran, source=f"tool:{verdict.call.name}")
                sanitized += scanned.removed_spans
                text = (
                    scanned.text if scanned.allowed else f"[tool output blocked: {scanned.reason}]"
                )
                outputs.append(text)
                # N5.2: forward only a minimized label of untrusted tool output, not its raw text.
                if self.context_minimization:
                    context.append(f"[{verdict.call.name} result: {len(text)} chars]")
                else:
                    context.append(text)

        return outputs, steps, pending, sanitized, context

    def handle(self, user_msg: str, *, now: float = 0.0) -> AgentResult:
        # 1) Input guard — user message is the trusted command channel (scanned, not datamarked).
        gin = self.engine.guard_input(user_msg, trust=TrustLevel.TRUSTED, source="user")
        if not gin.allowed:
            return AgentResult("Request blocked by input guardrails.", True, gin.reason)

        # 2) Plan (trusted message only) → freeze → execute (untrusted output fills data slots).
        plan = self._plan_phase(gin.text or "")
        outputs, steps, pending, sanitized, context = self._execute_phase(plan, now=now)

        draft = "\n".join(outputs) if outputs else "(no actions taken)"
        # 3) Output guard.
        gout = self.engine.guard_output(draft)
        if not gout.allowed:
            return AgentResult(
                "Response withheld by output guardrails.",
                True,
                gout.reason,
                steps,
                sanitized_spans=sanitized,
            )

        # 4) Oversight — review the minimized context when N5.2 is on, else the guarded output.
        review_output = "\n".join(context) if self.context_minimization else (gout.text or "")
        self.engine.review(Trajectory(task=user_msg, steps=steps, output=review_output))
        return AgentResult(gout.text or "", False, "", steps, pending, sanitized_spans=sanitized)
