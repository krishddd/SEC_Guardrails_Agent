"""T5 — Gateway skeleton + T6 observability wiring + T20 trace ingest + G1 rail enforcement.

A FastAPI reverse-proxy for `/api/v1/chat`, emitting an OpenTelemetry span + an append-only audit
record per request. Construct via `create_app(client, audit=..., tracer=..., engine=...)` so tests
can inject a stub client, a temp audit log, and an in-memory span exporter.

**G1 — the chat path enforces rails when a guarded client is wired.** `create_app` accepts *either*
a bare `OdysseusClient` (returns the raw upstream dict — legacy pass-through, used by stub tests) or
a `GuardedOdysseusClient` (returns a typed `GuardedReply` whose input/output rails already ran). The
`/chat` route dispatches on the return type: a `GuardedReply` is mapped to the response and the
**real** decision (allow / block) is audited — the old hardcoded `_emit("allow")` is gone. The
deployed server (`build_default_app` / `sec-guardrails serve`) wires the guarded client, so a client
hitting `:7100` is guarded; the injectable seam is preserved for tests.

`POST /api/_trace` (T20 / ADR-0005) receives the read-only tool-call events the Odysseus
trace-export hook emits and runs each through `engine.guard_tool`. This is **detective**: the tool
already ran server-side, so the verdict is recorded/surfaced, not enforced (preventing irreversible
tools is the gateway-mediated HITL path, P4). Off when no `engine` is wired.

`POST /api/_pretrace` (G6 / ADR-0005 extension) is the **preventive** counterpart: the hook calls it
*before* executing a tool and MUST honor the returned verdict (`allow` / `block` / `hitl`) — it
blocks its tool thread until the gateway answers, so an irreversible tool (bash / SQL DELETE /
send_email) never runs when the verdict is `block`. Same `engine.guard_tool`, same token gate; the
only difference is timing (pre- vs post-execution) and that the caller enforces it. The in-process
reference agent (`agent/runtime.py`) already proves the pattern (execute only on ALLOW).
"""

from __future__ import annotations

import time
from contextlib import nullcontext
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.gateway.guarded_odysseus import GuardedReply
from sec_guardrails.rails.tool.policy import ToolCall

# Odysseus sends the raw tool `content` (a command, query, URL, or JSON); map it onto the arg name
# the rails read, gated by tool family so a benign query is never inspected as a shell command.
_SHELL_TOOLS = frozenset({"bash", "shell", "sh", "exec", "python"})
_SQL_TOOLS = frozenset({"sql", "query", "db_query", "database"})
_URL_TOOLS = frozenset({"http_fetch", "fetch", "web_fetch", "curl", "app_api", "web_search"})


class ChatIn(BaseModel):
    message: str
    model: str | None = None
    session: str | None = None


class TraceEvent(BaseModel):
    """Normalized tool-call event from the Odysseus hook (shape pinned by ADR-0005)."""

    tool_name: str
    args: dict[str, Any] | str | None = None
    result: Any = None
    status: str | None = None
    exit_code: int | None = None
    latency_ms: float | None = None
    session_id: str | None = None
    role: str | None = None


def _event_to_toolcall(event: TraceEvent) -> ToolCall:
    name = event.tool_name
    if isinstance(event.args, dict):
        args = dict(event.args)
        content = args.get("content") or args.get("cmd") or args.get("command") or ""
    else:
        content = str(event.args or "")
        args = {"content": content} if content else {}

    lname = name.lower()
    if content:
        if lname in _SHELL_TOOLS:
            args.setdefault("cmd", content)
        elif lname in _SQL_TOOLS:
            args.setdefault("query", content)
        elif lname in _URL_TOOLS:
            args.setdefault("url", content)
    return ToolCall(name, args, role=event.role)


def create_app(
    client: Any,
    *,
    audit: AuditLog | None = None,
    tracer: Any | None = None,
    engine: Any | None = None,
    trace_token: str | None = None,
) -> FastAPI:
    app = FastAPI(title="sec-guardrails-gateway")
    app.state.client = client
    app.state.audit = audit
    app.state.tracer = tracer
    app.state.engine = engine

    def _emit(decision: str, **fields: Any) -> None:
        if audit is not None:
            audit.record(decision=decision, **fields)

    def _span(name: str):
        return tracer.start_as_current_span(name) if tracer is not None else nullcontext()

    @app.get("/health")
    def health() -> dict:
        return {"gateway": "ok", "odysseus": client.health_check()}

    @app.post("/api/v1/chat")
    def chat(body: ChatIn) -> dict:
        with _span("gateway.chat"):
            try:
                result = client.chat(body.message, model=body.model, session=body.session)
            except Exception as exc:  # upstream/Odysseus failure
                _emit("error", endpoint="/api/v1/chat", error=str(exc))
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            # G1: a guarded client returns a typed GuardedReply whose rails already ran; a bare
            # client returns the raw upstream dict (legacy pass-through, stub tests only).
            if isinstance(result, GuardedReply):
                if not result.allowed:
                    # Blocked pre-send (input) or withheld (output). Never return model output;
                    # audit the REAL decision + stage (no more hardcoded allow).
                    _emit(
                        "block",
                        endpoint="/api/v1/chat",
                        stage=result.stage,
                        reason=result.reason,
                    )
                    return {
                        "response": "Request blocked by guardrails.",
                        "blocked": True,
                        "stage": result.stage,
                        "reason": result.reason,
                    }
                _emit("allow", endpoint="/api/v1/chat", stage=result.stage)
                return {
                    "response": result.output or "",
                    "session_id": result.session_id,
                    "model": result.model,
                }
            # Legacy pass-through: a bare OdysseusClient (or a dict-returning stub).
            _emit("allow", endpoint="/api/v1/chat")
            return result

    @app.post("/api/_pretrace")
    def ingest_pretrace(
        event: TraceEvent, x_trace_token: str | None = Header(default=None)
    ) -> dict:
        # G6 — PREVENTIVE: the hook calls this BEFORE executing the tool and must honor the verdict.
        if trace_token is not None and x_trace_token != trace_token:
            raise HTTPException(status_code=401, detail="invalid trace token")
        with _span("gateway.pretrace"):
            call = _event_to_toolcall(event)
            if engine is None:
                # No engine → cannot vouch for safety. Fail closed on the preventive path: the hook
                # should NOT execute (unlike the observe-only detective path, where the tool already
                # ran regardless).
                _emit("block", endpoint="/api/_pretrace", phase="pre_tool", tool=call.name)
                return {
                    "decision": "block",
                    "stage": "pretrace",
                    "reason": "no engine wired (fail closed)",
                    "tool": call.name,
                    "phase": "pre_tool",
                }
            verdict = engine.guard_tool(call, now=time.time())
            return {
                "decision": verdict.effect.value,
                "stage": verdict.stage,
                "reason": verdict.reason,
                "tool": call.name,
                "phase": "pre_tool",
                "approval_id": verdict.approval_id,
            }

    @app.post("/api/_trace")
    def ingest_trace(event: TraceEvent, x_trace_token: str | None = Header(default=None)) -> dict:
        # Default-deny on a configured token mismatch; open only when no token is set (local dev).
        if trace_token is not None and x_trace_token != trace_token:
            raise HTTPException(status_code=401, detail="invalid trace token")
        with _span("gateway.trace"):
            call = _event_to_toolcall(event)
            if engine is None:
                _emit("observe", endpoint="/api/_trace", tool=call.name)
                return {"decision": "observe", "stage": "ingest", "reason": "no engine wired"}
            # Detective: guard_tool already audits; the tool has already run, so we only surface it.
            verdict = engine.guard_tool(call, now=time.time())
            response = {
                "decision": verdict.effect.value,
                "stage": verdict.stage,
                "reason": verdict.reason,
                "tool": call.name,
            }
            # D4/N2: also scan the tool RESULT for indirect injection (XPIA) before it re-enters
            # the model — the highest-value signal in a real trace. An injected span is stripped
            # ("sanitize", count surfaced); a result that can't be made safe is a "block".
            if isinstance(event.result, str) and event.result:
                out = engine.guard_tool_output(event.result, source=f"tool:{call.name}")
                if not out.allowed:
                    response["output_decision"] = "block"
                    response["output_reason"] = out.reason
                elif out.removed_spans:
                    response["output_decision"] = "sanitize"
                    response["removed_spans"] = out.removed_spans
                else:
                    response["output_decision"] = "allow"
            return response

    return app
