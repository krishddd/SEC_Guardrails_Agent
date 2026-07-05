"""N1 — Function-call argument-schema rail (L4).

A deterministic "function-calling hallucination" check (cf. IBM Granite Guardian 4.x): validate a
`ToolCall`'s arguments against the tool's *declared* signature before it runs. Catches the malformed
/ hallucinated tool call — a missing required argument, or a value whose type conflicts with the
definition — with no model, on the cheap fail-fast path. Pure-Python; mirrors the deny-by-default
ethos of `policy.py` without touching it.

Strictness is opt-in per tool: extra/unknown argument names are IGNORED by default (the gateway's
arg-mapping legitimately adds keys like `content` alongside `cmd`), and only flagged (HITL) when a
schema sets `strict=True` for a closed signature. Optional `domains` flag an out-of-set value as a
suspicious-value HITL. A tool with no registered schema gets no opinion here (other rails decide).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .policy import Effect, ToolCall


@dataclass(frozen=True)
class ToolSchema:
    name: str
    required: dict[str, type] = field(default_factory=dict)  # arg -> expected type
    optional: dict[str, type] = field(default_factory=dict)
    domains: dict[str, frozenset[str]] = field(default_factory=dict)  # arg -> allowed values
    strict: bool = False  # when True, an unknown arg name is flagged (HITL)


@dataclass(frozen=True)
class SchemaDecision:
    effect: Effect
    reason: str


class ToolArgSchemaRail:
    name = "arg_schema"

    def __init__(self, schemas: dict[str, ToolSchema] | None = None):
        self.schemas = schemas or {}

    def inspect(self, call: ToolCall) -> SchemaDecision:
        schema = self.schemas.get(call.name)
        if schema is None:
            return SchemaDecision(Effect.ALLOW, "no schema for tool")

        # 1) Missing required argument → hard schema violation.
        for arg in schema.required:
            if arg not in call.args:
                return SchemaDecision(Effect.BLOCK, f"missing required arg '{arg}'")

        known = {**schema.required, **schema.optional}
        # 2) Declared argument with a conflicting type → hard schema violation.
        for arg, expected in known.items():
            if arg in call.args and not isinstance(call.args[arg], expected):
                got = type(call.args[arg]).__name__
                return SchemaDecision(
                    Effect.BLOCK, f"arg '{arg}' type {got} conflicts with {expected.__name__}"
                )

        # 3) Out-of-domain value → suspicious, surface for approval (HITL), don't hard-block.
        for arg, allowed in schema.domains.items():
            value = call.args.get(arg)
            if isinstance(value, str) and value not in allowed:
                return SchemaDecision(Effect.HITL, f"arg '{arg}' value '{value}' out of domain")

        # 4) Unknown argument names — only when the schema declares a closed signature.
        if schema.strict:
            unknown = sorted(a for a in call.args if a not in known)
            if unknown:
                return SchemaDecision(Effect.HITL, f"unknown args {unknown}")

        return SchemaDecision(Effect.ALLOW, "ok")


def default_tool_schemas() -> dict[str, ToolSchema]:
    """Signatures for the reference agent's built-in tools (see `agent/tools.py`). Non-strict, so
    the gateway's extra `content` key is ignored; required args + types are still enforced."""
    return {
        "calc": ToolSchema("calc", required={"expr": str}),
        "echo": ToolSchema("echo", required={"text": str}),
        "bash": ToolSchema("bash", required={"cmd": str}),
        "sql": ToolSchema("sql", required={"query": str}),
        "http_fetch": ToolSchema("http_fetch", required={"url": str}),
    }
