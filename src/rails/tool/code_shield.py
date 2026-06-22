"""CodeShield — insecure-codegen scanner (LlamaFirewall pattern, ADR-0010).

A regex static-analysis rail over code the agent generates/executes, catching high-signal CWE
patterns before they run (LlamaFirewall's CodeShield uses Semgrep+regex; this is the lean regex
core). Complements the exec gate (shell/SQL) with general code-execution risks.
"""

from __future__ import annotations

import re

from core.rail import Decision, Rail, RailContext

_PATTERNS: dict[str, re.Pattern[str]] = {
    "eval_exec": re.compile(r"\b(?:eval|exec)\s*\("),
    "os_system": re.compile(r"\bos\.system\s*\("),
    "subprocess_shell_true": re.compile(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True", re.DOTALL),
    "insecure_deserialization": re.compile(r"\b(?:pickle\.loads?|yaml\.load|marshal\.loads)\s*\("),
    "dynamic_import": re.compile(r"\b__import__\s*\("),
    "tls_verification_disabled": re.compile(r"verify\s*=\s*False"),
}


class CodeShieldRail(Rail):
    name = "code_shield"

    def inspect(self, ctx: RailContext) -> Decision:
        hits = sorted(cat for cat, rx in _PATTERNS.items() if rx.search(ctx.text))
        if hits:
            return Decision.block(f"insecure code pattern(s): {hits}")
        return Decision.allow()
