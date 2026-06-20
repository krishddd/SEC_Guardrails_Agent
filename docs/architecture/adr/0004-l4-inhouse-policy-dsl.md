# ADR-0004: L4 tool authorization — in-house rule DSL for v1 (OPA/Rego = v2 path)

## Context
L4 needs a deny-by-default policy decision point evaluated at every tool call (who may call which tool
with which args under which conditions). OPA/Rego is the industry standard (Git-versioned, CI-testable)
but adds an external engine + a new language. An in-house Python rule layer ships faster for v1.

## Decision
Implement an **in-house rule DSL** (deny-by-default) over a normalized `ToolCall` for v1. Record OPA/Rego
as the **v2 migration path**. **Mandatory guardrail on the guardrail:** the DSL evaluator must pass a
`security-reviewer` review and a small **adversarial policy-bypass test set** (encoding tricks, arg
smuggling, fail-open probes) — not just happy-path policy tests — **before** it is trusted to gate HITL
or irreversible tools.

## Consequences
- (+) No external dependency; fastest path to a working deny-by-default gate.
- (+) Tight integration with `RailContext` taint labels (trusted-action invariant).
- (−) Home-grown policy engines accumulate parsing edge cases that become bypasses — mitigated by the
  mandatory adversarial test set + security review, and by the v2 OPA path if the DSL outgrows itself.
- (−) Policies aren't Git/CI-testable the way Rego is until the v2 migration.
