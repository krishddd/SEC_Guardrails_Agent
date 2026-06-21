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

## Refinement (2026-06-21, research-informed)
After reviewing **AgentSpec** (arXiv:2503.18666, ICSE'26 — rules as *trigger + predicate + enforcement*,
enforcement ∈ {block, user_inspection/HITL, self-examine}) and the 2026 **OPA-as-tool-call-proxy**
consensus (deny-by-default; the policy engine, not the agent, decides at every tool call), the v1 DSL is
expressed as **structured JSON rules**, not a hand-written text grammar:

- A policy is `{version, default_effect: "block", rules: [...]}`. Each rule is
  `{id, tool (exact/glob/regex), when: [predicates], effect: allow|block|hitl, reason}` — AgentSpec's
  trigger (`tool`) + predicates (`when`) + enforcement (`effect`).
- **Deny-by-default:** a `ToolCall` matching no `allow` rule gets `default_effect` (block).
- **No custom parser** → the parser-bypass class ADR-0004 feared is *eliminated by construction*; the
  adversarial surface is now predicate **evaluation**, which is hardened (regex predicates use
  `fullmatch` to stop prefix/arg-smuggling like `ls; rm -rf /`; missing/empty policy fails closed; a
  `no_untrusted_taint` predicate supports the FIDES trusted-action invariant).
- Implemented + fully CI-tested in **Python** (`src/rails/tool/policy.py`); Rust acceleration of the
  matcher remains optional (low value now — matching structured data is cheap and memory-safe).
- The adversarial bypass test set ships with T22; a formal `security-reviewer` pass runs via `/review`.

