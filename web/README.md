# web/ — HITL approval + observability dashboard (ADR-0007)

TypeScript + React (Vite) app for the human-facing guardrail surfaces:

- **HITL approval UI** — renders a proposed `ToolCall` + provenance/taint; approve/reject;
  default-deny on timeout (consumes the gateway UI API, task T38/T39).
- **Observability / audit dashboard** — ASR/FPR split, latency budgets, block reasons, and the
  NIST AI RMF / EU AI Act control-map view (task T40).
- **Sanitizer visual harness** — proves the T18 output sanitizer strips exfil vectors in a real DOM.

The UI holds **no** security logic — enforcement stays server-side; the UI only displays and relays an
operator decision.

> Scaffolded in **Phase 9** (T39/T40); until then this directory is a placeholder and the `web` CI lane
> stays skipped (it triggers only when `web/package.json` exists).
