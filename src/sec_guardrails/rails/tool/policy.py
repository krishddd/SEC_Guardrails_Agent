"""T21/T22 — L4 tool-authorization policy engine (deny-by-default).

Structured-JSON policy (ADR-0004 refinement), modelled on AgentSpec (arXiv:2503.18666): each rule is
a trigger (`tool`) + predicates (`when`) + enforcement (`effect`: allow/block/hitl). The engine, not
the agent, decides at every tool call (OPA-as-proxy); a call matching no `allow` rule gets the
`default_effect` (block). No text grammar is parsed, so the parser-bypass class is eliminated by
construction; the hardened surface is predicate evaluation (see the adversarial tests).

Hardening choices:
- regex predicates use **fullmatch** (a `^ls` prefix can't let `ls; rm -rf /` through);
- unknown predicate op → the rule fails to match (fail closed), never silently true;
- missing/empty policy → deny-by-default;
- `no_untrusted_taint` predicate supports the FIDES trusted-action invariant (T28).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path(__file__).with_name("tool_policy.json")


class Effect(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    HITL = "hitl"


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    # Names of args carrying untrusted (tainted) data — set by upstream rails (T28).
    tainted_args: set[str] = field(default_factory=set)
    # Calling agent's role, for RBAC scoping (ADR-0008). None = unscoped.
    role: str | None = None
    # N3 (CaMeL): per-arg capability labels — the provenance source(s) of each arg's data
    # (e.g. {"body": {"tool:http_fetch", "memory:untrusted"}}). Consumed by the data-flow sink
    # policy; empty = no provenance recorded (data-flow gate has no opinion).
    arg_sources: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class PolicyResult:
    effect: Effect
    rule_id: str | None
    reason: str


def _match_tool(pattern: str, name: str) -> bool:
    if pattern == "*":
        return True
    # Exact match, or full regex match (anchored) — never a loose search.
    if pattern == name:
        return True
    try:
        return re.fullmatch(pattern, name) is not None
    except re.error:
        return False


def _check_predicate(pred: dict[str, Any], call: ToolCall) -> bool:
    op = pred.get("op")
    # Taint invariant predicates don't reference a specific arg.
    if op == "no_untrusted_taint":
        return not call.tainted_args
    if op == "arg_untrusted":
        return pred.get("arg") in call.tainted_args

    arg = pred.get("arg")
    present = arg in call.args
    value = call.args.get(arg)

    match op:
        case "exists":
            return present
        case "absent":
            return not present
        case "eq":
            return present and value == pred.get("value")
        case "ne":
            return present and value != pred.get("value")
        case "in":
            return present and value in (pred.get("value") or [])
        case "not_in":
            return present and value not in (pred.get("value") or [])
        case "matches":
            if not present or not isinstance(value, str):
                return False
            try:
                return re.fullmatch(pred["value"], value) is not None
            except re.error:
                return False  # bad pattern → fail closed
        case "lt" | "gt" | "le" | "ge":
            if not present or not isinstance(value, (int, float)):
                return False
            threshold = pred.get("value")
            if not isinstance(threshold, (int, float)):
                return False
            return {
                "lt": value < threshold,
                "gt": value > threshold,
                "le": value <= threshold,
                "ge": value >= threshold,
            }[op]
        case _:
            return False  # unknown op → fail closed (never silently allow)


class PolicyEngine:
    def __init__(
        self, policy_path: str | Path | None = None, *, policy: dict[str, Any] | None = None
    ):
        if policy is None:
            path = Path(policy_path or DEFAULT_POLICY_PATH)
            policy = json.loads(path.read_text("utf-8")) if path.exists() else {}
        self.version = str(policy.get("version", "0"))
        # Deny-by-default: anything not explicitly allowed is blocked.
        self.default_effect = Effect(policy.get("default_effect", "block"))
        self.rules: list[dict[str, Any]] = policy.get("rules", [])

    def evaluate(self, call: ToolCall) -> PolicyResult:
        for rule in self.rules:
            if not _match_tool(rule.get("tool", ""), call.name):
                continue
            # RBAC: a rule with a `roles` allowlist only applies to those roles (ADR-0008).
            roles = rule.get("roles")
            if roles is not None and call.role not in roles:
                continue
            predicates = rule.get("when", [])
            if all(_check_predicate(p, call) for p in predicates):
                effect = Effect(rule.get("effect", "block"))
                reason = rule.get("reason", f"matched rule {rule.get('id')}")
                return PolicyResult(effect, rule.get("id"), f"{reason} (policy v{self.version})")
        return PolicyResult(
            self.default_effect,
            None,
            f"deny-by-default: no allow rule matched '{call.name}' (policy v{self.version})",
        )
