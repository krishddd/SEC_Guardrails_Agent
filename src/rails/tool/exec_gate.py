"""Tool-execution gate (ADR-0008) — deterministic hard-stops right before a tool runs.

Distilled from LlamaFirewall (CodeShield), AgentDoG (pre-exec interception), SupraWall/AperionAI
(hard-block destructive actions) and the "tool-execution gates" guidance: intercept the agent's
intent and refuse catastrophic shell/SQL outright, and auto-scope risky DB reads. Runs BEFORE the L4
policy engine; a complementary denylist, not a replacement for deny-by-default allowlisting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rails.tool.policy import Effect, ToolCall

# Catastrophic shell intents → hard block (case-insensitive search).
_DESTRUCTIVE_SHELL = [
    re.compile(r"\brm\s+-[a-z]*[rf][a-z]*\s+(/|~|\*|\.\s*$|\$HOME)", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+-R\s+777\s+/", re.IGNORECASE),
    re.compile(r">\s*/dev/sd[a-z]", re.IGNORECASE),
    re.compile(r"\bmv\b[^\n]*\s+/dev/null\b", re.IGNORECASE),
]

# SQL danger patterns.
_SQL_DDL = re.compile(r"\b(DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b", re.IGNORECASE)
_SQL_DML = re.compile(r"\b(DELETE|UPDATE)\b", re.IGNORECASE)
_SQL_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
_SQL_SELECT = re.compile(r"\bSELECT\b", re.IGNORECASE)
_SQL_LIMIT = re.compile(r"\bLIMIT\b", re.IGNORECASE)

_SHELL_TOOLS = frozenset({"bash", "shell", "sh", "exec"})
_SQL_TOOLS = frozenset({"sql", "query", "db_query", "database"})


@dataclass
class ExecDecision:
    effect: Effect
    reason: str
    new_args: dict | None = None  # rewritten args when effect is ALLOW with a transform


class ExecGate:
    def __init__(self, max_rows: int = 1000):
        self.max_rows = max_rows

    def check_shell(self, cmd: str) -> ExecDecision:
        for rx in _DESTRUCTIVE_SHELL:
            if rx.search(cmd):
                return ExecDecision(Effect.BLOCK, "destructive shell command hard-blocked")
        return ExecDecision(Effect.ALLOW, "ok")

    def check_sql(self, query: str) -> ExecDecision:
        if _SQL_DDL.search(query):
            return ExecDecision(Effect.BLOCK, "SQL DDL/permission statement blocked")
        if _SQL_DML.search(query) and not _SQL_WHERE.search(query):
            return ExecDecision(Effect.BLOCK, "unscoped SQL DELETE/UPDATE (no WHERE) blocked")
        if _SQL_SELECT.search(query) and not _SQL_LIMIT.search(query):
            scoped = f"{query.rstrip().rstrip(';')} LIMIT {self.max_rows}"
            reason = f"auto-injected LIMIT {self.max_rows}"
            return ExecDecision(Effect.ALLOW, reason, {"query": scoped})
        return ExecDecision(Effect.ALLOW, "ok")

    def inspect(self, call: ToolCall) -> ExecDecision:
        if call.name in _SHELL_TOOLS:
            cmd = call.args.get("cmd") or call.args.get("command") or ""
            return self.check_shell(str(cmd))
        if call.name in _SQL_TOOLS:
            query = call.args.get("query") or call.args.get("sql") or ""
            return self.check_sql(str(query))
        return ExecDecision(Effect.ALLOW, "not an exec tool")
