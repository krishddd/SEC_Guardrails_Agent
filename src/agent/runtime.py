"""Reference guarded agent (ADR-0009).

A deterministic tool-executing agent loop that runs *under* the GuardrailEngine, so the full safety
net is exercised end-to-end with no external dependency. The user message is the trusted command
channel (scanned, not datamarked); tool outputs are untrusted. A tiny line-based planner maps
commands to tool calls so tests can drive exact (benign and malicious) behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.engine import GuardrailEngine
from core.rail import TrustLevel
from rails.memory.write_guard import MemoryRecord, Provenance
from rails.oversight.critic import Trajectory
from rails.tool.policy import Effect, ToolCall

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
    def __init__(self, engine: GuardrailEngine, tools: dict[str, Tool] | None = None):
        self.engine = engine
        self.tools = tools or default_tools()

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

    def handle(self, user_msg: str, *, now: float = 0.0) -> AgentResult:
        # 1) Input guard — user message is the trusted command channel (scanned, not datamarked).
        gin = self.engine.guard_input(user_msg, trust=TrustLevel.TRUSTED, source="user")
        if not gin.allowed:
            return AgentResult("Request blocked by input guardrails.", True, gin.reason)

        steps: list[str] = []
        outputs: list[str] = []
        pending: list[str] = []
        sanitized = 0

        for kind, payload in self._plan(gin.text or ""):
            if kind == "echo":
                outputs.append(str(payload))
                continue
            if kind == "memory":
                rec = MemoryRecord("default", str(payload), Provenance("user", "trusted", now))
                decision = self.engine.guard_memory_write(rec)
                steps.append("memory_write")
                msg = "remembered." if decision.allowed else f"[memory blocked: {decision.reason}]"
                outputs.append(msg)
                continue

            call = payload  # ToolCall
            assert isinstance(call, ToolCall)
            steps.append(call.name)
            verdict = self.engine.guard_tool(call, now=now)
            if verdict.effect is Effect.BLOCK:
                outputs.append(f"[blocked {call.name}: {verdict.reason}]")
            elif verdict.effect is Effect.HITL:
                pending.append(verdict.approval_id or "")
                outputs.append(f"[awaiting approval for {call.name}]")
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
                outputs.append(
                    scanned.text if scanned.allowed else f"[tool output blocked: {scanned.reason}]"
                )

        draft = "\n".join(outputs) if outputs else "(no actions taken)"
        # 2) Output guard.
        gout = self.engine.guard_output(draft)
        if not gout.allowed:
            return AgentResult(
                "Response withheld by output guardrails.",
                True,
                gout.reason,
                steps,
                sanitized_spans=sanitized,
            )

        # 3) Oversight.
        self.engine.review(Trajectory(task=user_msg, steps=steps, output=gout.text or ""))
        return AgentResult(gout.text or "", False, "", steps, pending, sanitized_spans=sanitized)
