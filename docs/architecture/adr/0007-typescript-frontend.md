# ADR-0007: TypeScript/React for HITL approval + observability dashboard

## Context
Two guardrail capabilities are inherently human-facing and don't belong in a headless Python service:
- **HITL confirmation** (Reference §6.4): a reviewer must see "about to do X with args Y" and
  approve/reject before an irreversible tool runs (plan T23).
- **Observability/governance** (Reference §14, §15.3): per-rail ASR/FPR (split), latency, block reasons,
  and an audit view mapped to NIST AI RMF / EU AI Act controls (plan T36).
Additionally, the output-side exfil defenses (markdown-link/image/HTML sanitization, plan T18) are a
*rendering-context* problem, so their visual regression harness belongs in a real DOM.

## Decision
Build a small **TypeScript + React (Vite)** app in `web/`:
- **HITL approval UI** — subscribes to the gateway's pending-approval API, renders the proposed
  `ToolCall` + provenance/taint, posts approve/reject. Time-boxed; default-deny on timeout.
- **Observability/audit dashboard** — reads the append-only audit log + eval reports; shows ASR/FPR
  split, latency budgets, block reasons, and the control-map view.
- **Sanitizer visual harness** — renders rail input vs sanitized output to prove exfil vectors are
  stripped in a real DOM (Vitest + Testing Library).
The gateway exposes a minimal JSON API for these; the UI holds **no** security logic — enforcement stays
server-side (the UI can only *display* and *relay an operator decision*).

## Consequences
- (+) Real HITL and governance surfaces, which a CLI/JSON-only stack can't provide.
- (+) Output sanitization tested in an actual render context, not by string assertions alone.
- (−) Adds a Node/TS toolchain + a third CI lane (tsc, eslint, vitest).
- (−) A new gateway↔UI API surface to authenticate and rate-limit (treated as untrusted client input).
