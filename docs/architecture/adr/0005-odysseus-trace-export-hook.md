# ADR-0005: Minimal read-only trace-export hook in Odysseus

## Context
Odysseus does not expose per-step tool execution to an API token (`/api/v1/chat` runs no tools; task
lifecycle exposes only summaries). Without it, L4/L5/multi-agent rails can only be validated on synthetic
fixtures. Odysseus source is available locally (`odysseus/src/tool_execution.py` is the central dispatch),
and the user approved a minimal modification (B0 resolution, 2026-06-20).

## Decision
Add a **minimal, read-only trace-export hook** at `odysseus/src/tool_execution.py` that emits a
normalized tool-call event — `{tool_name, args, result, status, exit_code, latency_ms, session_id}` —
to the gateway (local socket/HTTP callback). The hook **observes only**; it must not change Odysseus's
control flow or tool behaviour. Enforcement (allow/block/HITL) stays in the gateway's L4/L5 rails. The
event shape reuses the normalization target already in `odysseus_adapter.py` (`_TRACE_LIST_KEYS`,
`_STEP_*`).

## Consequences
- (+) L4/L5/multi-agent rails enforce on the **real** trace, not synthetic-only — roughly doubles real
  coverage vs the gated design.
- (+) Read-only keeps the change small, reviewable, and low-risk to Odysseus behaviour.
- (−) Couples us to one Odysseus internal module; pin the trace schema (OQ3) and re-check on Odysseus
  upgrades. Keep a synthetic-fixture path so rails are testable when Odysseus/hook is absent.
- (−) Block decisions are advisory unless the gateway can also *stop* a tool call — for irreversible
  tools, route through gateway-mediated HITL before Odysseus executes (design in P4).
