"""G11 — MCP manifest validation at server-connection time (OPT-IN, out of the default scope).

**Scope note (CLAUDE.md).** Skill/MCP supply-chain guardrails are out of scope for this gateway and
`Reference.md` is canonical; ASI04/EXT11 live in the red-team and are not defended by the default
L1–L7 engine. This module is therefore a **standalone, opt-in** utility — it is deliberately NOT
wired into `default_engine`. Use it at MCP-registration time if a deployment adds MCP; otherwise the
risk is accepted and undefended by design.

MCP tool poisoning arrives through tool *definitions* (name / description / parameter schema), not
tool *results* — so it bypasses every runtime rail because it registers as trusted metadata. This
validator inspects a manifest at connection time: it flags a definition whose description carries
instruction-like text (reusing the L1 injection heuristic — no new detector) or MCP-specific hidden-
instruction markers, and flags any tool not on an explicit allow-list. Registration-phase only; no
MCP protocol support needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sec_guardrails.rails.input.prompt_injection import HeuristicDetector

# MCP-specific tool-poisoning markers: hidden directives aimed at the *assistant*, not the user.
_POISON_MARKERS = re.compile(
    r"(?:<important>|<secret>|<system>|before (?:using|calling) this tool|"
    r"do not (?:tell|mention|inform|reveal to) the user|"
    r"instructions? for the (?:assistant|ai|model|agent)|"
    r"you must (?:also|first|always)|read (?:the |your )?(?:\.ssh|\.env|~/|/etc/)|"
    r"ignore (?:the |all )?(?:previous|prior|user))",
    re.IGNORECASE,
)


@dataclass
class McpToolDef:
    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class McpFinding:
    tool: str
    category: str  # "instruction_like" | "poison_marker" | "not_allowlisted"
    reason: str


class McpManifestGuard:
    """Validate MCP tool definitions at registration. Deny-by-default with an allow-list."""

    def __init__(
        self,
        *,
        allowed_tools: set[str] | None = None,
        injection_threshold: float = 0.4,
        detector: HeuristicDetector | None = None,
    ):
        self.allowed_tools = allowed_tools
        self.injection_threshold = injection_threshold
        self._detector = detector or HeuristicDetector()

    def check(self, tool: McpToolDef) -> list[McpFinding]:
        findings: list[McpFinding] = []
        if self.allowed_tools is not None and tool.name not in self.allowed_tools:
            findings.append(
                McpFinding(
                    tool.name, "not_allowlisted", f"tool '{tool.name}' not on the allow-list"
                )
            )
        text = f"{tool.description} {self._schema_text(tool.parameters)}".strip()
        if _POISON_MARKERS.search(text):
            findings.append(
                McpFinding(
                    tool.name,
                    "poison_marker",
                    "description contains an assistant-directed hidden instruction",
                )
            )
        elif self._detector.score(text) >= self.injection_threshold:
            findings.append(
                McpFinding(
                    tool.name,
                    "instruction_like",
                    "description reads as an instruction, not a tool description",
                )
            )
        return findings

    def validate(self, manifest: list[McpToolDef]) -> list[McpFinding]:
        findings: list[McpFinding] = []
        for tool in manifest:
            findings.extend(self.check(tool))
        return findings

    @staticmethod
    def _schema_text(parameters: dict[str, Any]) -> str:
        """Flatten a JSON-schema-ish params dict to text so poison in field descriptions is seen."""
        parts: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("description", "title") and isinstance(value, str):
                        parts.append(value)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(parameters)
        return " ".join(parts)
