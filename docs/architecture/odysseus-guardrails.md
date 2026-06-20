# Architecture — Odysseus Runtime Guardrails

*Produced by the `/design` stage from `docs/specs/odysseus-guardrails-spec.md` +
`docs/architecture/exploration-odysseus-guardrails.md`. B0 trace fork resolved: **trace hook approved**,
so L4/L5/multi-agent enforce live. ADRs in `adr/`.*

## High-level approach
A non-invasive **reverse-proxy guardrail gateway** (FastAPI, `:7100`) fronts Odysseus (`:7000`). Every
client request flows: **input rails → forward to Odysseus → output rails → return**, with an
OpenTelemetry span and an append-only audit record emitted per rail decision. The gateway owns the
**control plane** (rail orchestration, dual-LLM/IFC, spotlighting, Task-Shield, the policy engine);
commodity detectors (deberta-v3, Presidio, Mistral Moderation / ShieldGemma) are **swappable components**
behind a uniform `Rail` interface — this is what "build from scratch" means here (ADR-0002).

Because Odysseus does not expose per-step tool execution to an API client, a **minimal read-only
trace-export hook** is added in `odysseus/src/tool_execution.py` (ADR-0005). It emits a normalized
tool-call event (name, args, result, status, timing) to the gateway, which lets **L4/L5/multi-agent
rails enforce on the real trace** rather than synthetic fixtures. Development proceeds against a **stub
agent** mirroring the `/api/v1/chat` contract until Odysseus is live.

Two cross-cutting principles (Reference §2) govern everything: **defense-in-depth** (no single check is
trusted; layers are independent) and **treat all external content as untrusted** (provenance labels +
taint tracking; data crossing into reasoning is marked, sanitized, or sandboxed).

## Language strategy (polyglot — each language where it earns its place)
The system is **polyglot by design** (ADR-0006, ADR-0007), not Python-only:
- **Python** — control plane + ML orchestration: the FastAPI gateway, classifier integration
  (deberta-v3, Presidio, Mistral Moderation/ShieldGemma), the eval harness, and the `Rail`/`RailChain`
  glue. The default language unless a rail is hot-path-deterministic or human-facing.
- **Rust** — the deterministic, security-critical core compiled to a Python extension
  (`guardrails_core` via PyO3/maturin): secrets/regex scanner, spotlighting/datamarker, URL/HTML/markdown
  sanitizer, the L4 **policy-DSL parser+evaluator**, and taint-propagation primitives. Memory safety at
  the trust boundary is a security requirement; each Rust rail has a pure-Python fallback behind the same
  `Rail` interface. Hits the <30 ms input budget.
- **TypeScript/React (Vite)** — human-facing surfaces in `web/`: the HITL approval app and the
  observability/audit dashboard (ASR/FPR split, latency, block reasons, NIST/EU-AI-Act control map),
  plus the sanitizer visual-regression harness. The UI holds **no** security logic.
- **Rego** — L4 policy v2 path (ADR-0004), once the in-house DSL outgrows itself.
- **Bash** — the pre-edit-guard hook (already in `.claude/hooks/`).

## Component breakdown
- **`crates/guardrails-core/`** — Rust workspace crate (PyO3/maturin) exporting the deterministic core
  to Python as `guardrails_core`; shared test vectors run against both it and the Python fallback.
- **`web/`** — TypeScript/React (Vite) app: HITL approval UI, observability/audit dashboard, sanitizer
  visual harness. Talks to a minimal gateway JSON API (treated as untrusted client input).
- **`src/gateway/`** — FastAPI proxy: request/response interception, rail-chain invocation, Odysseus
  client (4xx-no-retry, header auth), OTel + audit emission, and the HITL + dashboard JSON API.
- **`src/rails/`** — one module per rail, all implementing `Rail.inspect(ctx) -> Decision`:
  - `input/` — secrets scrub, deberta-v3 PI/jailbreak, Presidio PII, spotlighting + boundary-awareness.
  - `dialog/` — Task-Shield off-task detector, deny-by-default topic policy.
  - `output/` — Pydantic schema+reask, Mistral Moderation/ShieldGemma content, grounding (reuse eval
    pipeline's grounding judge), PII/secret/canary redaction, URL/markdown/HTML sanitizer.
  - `tool/` — in-house policy DSL (ADR-0004), HITL gate, SSRF/egress allowlist, trace adapter.
  - `memory/` — write-time moderation, provenance/trust labels, tenant isolation, retrieval validators.
  - `reasoning/` — quarantined-LLM parser (dual-LLM), taint labels + trusted-action invariant.
  - `multiagent/` — signed messages, capability-token delegation, orchestrator mediation (pending OQ1).
  - `oversight/` — post-hoc critic on final trajectory + output.
- **`src/core/`** — `Rail`/`RailChain`/`RailContext` (trust labels, taint), config/secrets loader,
  audit log, OTel setup, `Decision` type.
- **`src/eval/`** — A/B harness (Security_module direct vs gateway), Inspect Evals (AgentDojo/WASP)
  driver, FPR/utility benchmark runner, latency reporter.
- **`tests/`** — unit + adversarial fixtures (Security_module payload corpora), stub agent.

## Data flow (request lifecycle)
```
client → [:7100 gateway]
  1. RailContext built (source=user, trust=untrusted-by-default)
  2. INPUT chain: secrets → PI/jailbreak → PII → spotlight   (block → refusal + audit; <30ms)
  3. DIALOG chain: Task-Shield → topic policy                (block → refusal + audit; <200ms)
  4. forward to Odysseus :7000 (ODYSSEUS_TOKEN)              ──┐
       Odysseus tool_execution.py → trace-export hook ────────┘→ gateway L4/L5 enforce per tool call
  5. OUTPUT chain: schema → content → grounding → redact → sanitize  (block/modify + audit; <50ms)
  6. OVERSIGHT critic on trajectory                          (flag/block + audit)
  → response to client
every step → OTel span + append-only audit record
```

## Layer → offensive-test defense map
| Rail | Defends (Security_module) |
|---|---|
| L1 input | ext10 XPIA, ext01 log-injection, ASI01 goal-hijack, jailbreaks, ASI09 trust-exploit |
| L2 dialog | scope/goal violations, ext07 goal-drift (partial) |
| L3 reasoning/IFC | ext10 escalation, ASI01 |
| L4 tool | ASI02 tool-misuse, ASI03 privilege-abuse, ASI05 code-exec, ext17 delivery-hijack, ext08 sandbox |
| L5 memory | ASI06 memory-poison, ext14 data-poison, ext16 cache-poison |
| multi-agent | ASI07 inter-agent, ASI10 rogue-agents, ext03 consensus-spoof |
| L7 oversight | ext12 alignment, ext07 goal-drift |
| L6 output | ext13 model-extraction, ext15 attribute-inference, sensitive-info disclosure, exfil |
| (out of scope) | ASI04 supply-chain, ext11 MCP poisoning — undefended by design |

## Pinned components (re-verified 2026-06-20)
- Input PI: `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0; English-only, weak on
  jailbreaks → paired with the content classifier). · PII: Presidio 2.2.362.
- Output safety: Mistral Moderation `mistral-moderation-2603` (native; multilingual; jailbreak
  detection) + self-hosted ShieldGemma 2 fallback (ADR-0003).
- L4: in-house rule DSL (ADR-0004). · Schema: Pydantic v2. · Tracing: OTel GenAI semconv (client spans
  stable; agent spans experimental — opt in via `OTEL_SEMCONV_STABILITY_OPT_IN`).
- Eval: Security_module (oracle) + Agent eval pipeline (scorer) + AgentDojo/WASP via Inspect Evals.

## Trade-offs considered & rejected
- **Adopt NeMo Guardrails** instead of building — rejected (ADR-0002): build-from-scratch was a stated
  requirement; NeMo's Colang adds a runtime + DSL we'd fight for fine-grained taint/IFC control.
- **Patch Odysseus internals for full in-process rails** — rejected (ADR-0001): too invasive; the
  reverse-proxy keeps Odysseus a black box except the one minimal trace hook.
- **Single mixed-set F1 metric** — rejected (spec SC1/SC2): hides which failure mode (too loose vs too
  strict) the stack has; we report ASR and FPR/utility split.
- **OPA/Rego for L4 v1** — deferred to v2 (ADR-0004): heavier setup; in-house DSL ships faster, gets an
  adversarial test set + security-reviewer pass before gating irreversible tools.
