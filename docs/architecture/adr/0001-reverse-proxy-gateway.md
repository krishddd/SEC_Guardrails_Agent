# ADR-0001: Non-invasive reverse-proxy gateway (not an in-process patch)

## Context
Guardrails must wrap Odysseus, which we treat as a black box. Two placements: (a) patch Odysseus to run
rails in-process, or (b) an external reverse-proxy in front of `:7000`. Odysseus is a large third-party
FastAPI app; the offensive/eval siblings already integrate with it only over HTTP.

## Decision
Build an external **reverse-proxy guardrail gateway** on `:7100`. Clients repoint from `:7000` to
`:7100`. The only modification to Odysseus is the minimal read-only trace-export hook (ADR-0005);
everything else stays out-of-process.

## Consequences
- (+) Odysseus stays a black box; upgrades don't break the rails. Drop-in for clients.
- (+) Input/dialog/output rails enforce fully at the network boundary today.
- (−) Without the trace hook, tool/memory/multi-agent events aren't visible — hence ADR-0005.
- (−) Adds one network hop (mitigated by the latency budget, spec SC3).
