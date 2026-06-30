"""N1 — function-call argument-schema rail (L4).

Validates a tool call against its declared signature (Granite-4.x-style function-call-hallucination
check). Covers: missing-required → BLOCK, type conflict → BLOCK, out-of-domain → HITL, strict
unknown → HITL, extra args ignored when non-strict (the gateway's `content` key must not
false-positive), and end-to-end via `default_engine.guard_tool`.
"""

from core.audit import AuditLog
from core.engine import default_engine
from rails.tool.arg_schema import (
    SchemaDecision,
    ToolArgSchemaRail,
    ToolSchema,
    default_tool_schemas,
)
from rails.tool.policy import Effect, ToolCall


def _rail():
    return ToolArgSchemaRail(default_tool_schemas())


def _eff(call: ToolCall) -> Effect:
    return _rail().inspect(call).effect


# ── unit: the rail in isolation ──────────────────────────────────────────────
def test_valid_call_allowed():
    assert _eff(ToolCall("calc", {"expr": "1+1"})) is Effect.ALLOW


def test_missing_required_blocked():
    d = _rail().inspect(ToolCall("calc", {}))
    assert d.effect is Effect.BLOCK
    assert "expr" in d.reason


def test_type_conflict_blocked():
    d = _rail().inspect(ToolCall("calc", {"expr": 42}))  # int where str declared
    assert d.effect is Effect.BLOCK
    assert "type" in d.reason


def test_unknown_tool_gets_no_opinion():
    assert _eff(ToolCall("mystery_tool", {"x": 1})) is Effect.ALLOW


def test_extra_args_ignored_when_non_strict():
    # The gateway maps raw content onto an arg name AND keeps `content`; must not false-positive.
    assert _eff(ToolCall("bash", {"content": "ls", "cmd": "ls"})) is Effect.ALLOW


def test_strict_unknown_args_hitl():
    rail = ToolArgSchemaRail({"t": ToolSchema("t", required={"a": str}, strict=True)})
    d = rail.inspect(ToolCall("t", {"a": "x", "weird": "y"}))
    assert d.effect is Effect.HITL
    assert "weird" in d.reason


def test_out_of_domain_value_hitl():
    schema = ToolSchema("t", required={"mode": str}, domains={"mode": frozenset({"read", "write"})})
    rail = ToolArgSchemaRail({"t": schema})
    assert rail.inspect(ToolCall("t", {"mode": "read"})).effect is Effect.ALLOW
    assert rail.inspect(ToolCall("t", {"mode": "drop"})).effect is Effect.HITL


def test_decision_is_frozen_value_object():
    d = SchemaDecision(Effect.ALLOW, "ok")
    assert d.effect is Effect.ALLOW and d.reason == "ok"


# ── integration: through the engine's guard_tool ─────────────────────────────
def test_engine_blocks_malformed_call(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"))
    verdict = engine.guard_tool(ToolCall("calc", {}), now=0.0)  # missing required expr
    assert verdict.effect is Effect.BLOCK
    assert verdict.stage == "arg_schema"


def test_engine_allows_wellformed_call(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"))
    verdict = engine.guard_tool(ToolCall("calc", {"expr": "2+2"}), now=0.0)
    assert verdict.effect is Effect.ALLOW
