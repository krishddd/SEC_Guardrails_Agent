"""N3 — Capabilities / data-flow policy at the tool call (reasoning×tool rail, L3×L4).

CaMeL-style: data carries a capability label naming its provenance *sources*, and each sensitive
*sink* (egress / write / exec) declares which sources it will accept. A sink deny-by-default rejects
an arg whose label includes an **untrusted** source not on that sink's allow-list — closing the
cross-turn "read untrusted data → exfil over a sink" class that the substring taint invariant misses
(it reasons over provenance labels, not string containment).

Deterministic, no model. Sits alongside the taint gate: taint asks "is this arg tainted at all?";
data-flow asks "is THIS source allowed to reach THIS sink?" — a finer, per-sink authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sec_guardrails.rails.tool.policy import ToolCall

# Source labels considered untrusted for data-flow purposes. A sink only ever needs to allow-list an
# untrusted source it genuinely requires; trusted sources (e.g. "user") are never blocked.
DEFAULT_UNTRUSTED_SOURCES = frozenset(
    {
        "tool:http_fetch",
        "tool:web_fetch",
        "tool:fetch",
        "web",
        "memory:untrusted",
        "email:inbound",
        "tool_output",
    }
)


@dataclass(frozen=True)
class DataFlowResult:
    allowed: bool
    reason: str


@dataclass
class DataFlowPolicy:
    """Per-sink source allow-lists. `sink_allowed_sources[sink]` = the source labels that sink will
    accept; a sink not present is ungoverned (no opinion — other rails decide). Deny-by-default only
    among *untrusted* sources: an arg carrying an untrusted source absent from the sink's allow-list
    is blocked."""

    sink_allowed_sources: dict[str, set[str]] = field(default_factory=dict)
    untrusted_sources: frozenset[str] = DEFAULT_UNTRUSTED_SOURCES

    def check(self, call: ToolCall) -> DataFlowResult:
        allowed = self.sink_allowed_sources.get(call.name)
        if allowed is None:
            return DataFlowResult(True, "not a governed sink")
        for arg, sources in call.arg_sources.items():
            offending = sorted(
                s for s in sources if s in self.untrusted_sources and s not in allowed
            )
            if offending:
                return DataFlowResult(
                    False,
                    f"data-flow: arg '{arg}' carries untrusted source(s) {offending} not permitted "
                    f"for sink '{call.name}'",
                )
        return DataFlowResult(True, "ok")
