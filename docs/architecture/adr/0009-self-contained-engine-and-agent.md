# ADR-0009: Self-contained GuardrailEngine + reference guarded agent

## Context
The rails were built per-layer and the runtime-enforcement layers (tool/memory/multi-agent) were
"wiring-gated" on a live Odysseus. That left the safety net provable only in pieces. The goal is a
**complete, agent-agnostic safety net** that runs end-to-end *in this repo*, independent of any external
agent — so it is fully developed and demonstrable here.

## Decision
1. **`GuardrailEngine`** (`src/core/engine.py`) composes every layer into one object:
   `guard_input` (secrets → PI → PII → spotlight → Task-Shield → topic), `guard_tool`
   (ExecGate → egress → policy+RBAC → taint trusted-action invariant → HITL), `guard_memory_write`
   (write-time moderation + provenance), `guard_output` (content → leak/canary → sanitize → grounding),
   and `review` (oversight critic). Every decision is audited. A `default_engine()` builder wires
   sensible defaults; everything is injectable.
2. **Reference guarded agent** (`src/agent/`) — a small, real tool-executing agent loop that runs
   *under* the engine with built-in tools (calc, echo, http-fetch sim, bash sim, memory). Tool outputs
   are treated as untrusted and tainted. This is the in-process equivalent of the Odysseus trace hook:
   the engine intercepts every tool call of an agent we control, so L4/L5/oversight are **live**, not
   synthetic.
3. **Self-contained A/B** — a built-in attack corpus + harness runs the guarded agent with the engine
   on vs off, reporting ASR and utility split — the T31 analog without the external red-team.

## Consequences
- (+) The safety net is complete and provable here; not blocked on Odysseus.
- (+) Agent-agnostic: Odysseus (or any agent) plugs in by mapping its calls to the same `guard_*` API.
- (+) Rust core + Python control plane exercised end-to-end on a real (built-in) agent.
- (−) The reference agent is a deterministic demo, not a frontier LLM agent; the LLM-backed rails still
  light up only with the `ml` extra. The *enforcement* path, however, is fully real.
