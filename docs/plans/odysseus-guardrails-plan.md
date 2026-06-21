# Implementation Plan — Odysseus Runtime Guardrails

*Produced by `/plan` from `docs/architecture/odysseus-guardrails.md`. Supersedes the draft
`guardrails-plan.md`. Each task = one `/implement` run with an explicit done-condition (tests, not
"implement X"). B0 resolved: trace hook approved → L4/L5/multi-agent are **active-now**. Dev against a
**stub agent**; live A/B when Odysseus is up. Metrics always reported **split** (ASR vs FPR/utility).*

## Scaffold needed (run `/scaffold odysseus-guardrails` before T1)
- **Python (control plane):** `pyproject.toml` (maturin build backend), project `sec-guardrails`,
  Python 3.11, deps (fastapi, uvicorn, httpx, pydantic>=2, opentelemetry-sdk/-api, presidio-analyzer,
  transformers, torch (cpu), mistralai), `[dev]` (pytest, ruff). ruff + pytest config.
- Package layout: `src/gateway/`, `src/rails/{input,dialog,output,tool,memory,reasoning,multiagent,oversight}/`,
  `src/core/`, `src/eval/`, `tests/` (+ `tests/fixtures/`, `tests/stub_agent/`).
- **Rust core (ADR-0006):** `crates/guardrails-core/` cargo crate, PyO3 + maturin, module
  `guardrails_core`; `Cargo.toml`, clippy/fmt config; built into the Python wheel. A `tests/vectors/`
  shared fixture set exercised against both the Rust ext and the Python fallback.
- **Frontend (ADR-0007):** `web/` Vite + React + TypeScript app (HITL + dashboard + sanitizer harness);
  `package.json`, tsconfig, eslint/prettier, vitest. No security logic in the UI.
- `tests/stub_agent/` FastAPI stub mirroring `/api/v1/chat` + `/api/health` (+ a fake tool trace).
- **Polyglot CI:** ci.yml gains lanes for Rust (cargo fmt/clippy/test + maturin build) and web
  (tsc/eslint/vitest) alongside Python (ruff/pytest).

---

## Phase 0 — Foundations
- [ ] **T1 — Rotate OPENAI_API_KEY (FIRST).** Rotate the reused key; document in `.env.example` notes.
  **Done:** old key invalidated, new key in local `.env` (untracked), nothing reads a hardcoded key.
- [x] **T2 — Config + secrets loader** (`src/core/config.py`). Resolve `ODYSSEUS_BASE_URL`,
  `ODYSSEUS_TOKEN`, `OPENAI_API_KEY`, `MISTRAL_API_KEY` from env + configurable fallback path.
  **Done:** unit test (monkeypatched env) resolves all; missing `ODYSSEUS_TOKEN` raises a clear error.
- [x] **T3 — Odysseus client** (`src/gateway/odysseus_client.py`). `/api/v1/chat`, `/api/health`,
  header auth, **4xx terminal / 5xx+network retry**. **Done:** health green vs stub; retry-policy unit tests.
- [x] **T4 — Rail framework** (`src/core/rail.py`). `Rail.inspect(ctx)->Decision{allow|block|modify,reason}`,
  ordered `RailChain` (short-circuit on block), `RailContext` (source, trust label, taint set).
  **Done:** unit test proves short-circuit + records the blocking rail. *(blocks all rail tasks)*
- [x] **T5 — Gateway skeleton** (`src/gateway/app.py`). FastAPI `:7100` proxying `/api/v1/chat` → `:7000`,
  no rails yet. **Done:** response through gateway == direct (vs stub). *(needs T3)*
- [x] **T6 — Observability + audit** (`src/core/audit.py`, `src/core/otel.py`). Per-request trace id;
  OTel span + append-only JSONL audit per decision. **Done:** one pass-through call → exactly one span +
  one audit record. *(needs T5)*
- [x] **T6b — Rust core crate (ADR-0006)** (`crates/guardrails-core/`, PyO3/maturin → `guardrails_core`).
  Build skeleton + one trivial exported fn + the shared `tests/vectors/` harness wired to both the Rust
  ext and a Python fallback shim. **Done:** `maturin develop` builds; `import guardrails_core` works;
  the dual-backend test harness runs green. *(blocks T8, T11, T18, T21)*

## Phase 1 — Input rails (L1) + early regression gate
- [ ] **T7 — Latency spike (FIRST in P1).** Bench deberta-v3 + Presidio + secrets-scrub together on the
  host. **Done:** measured warmed p50 recorded in `docs/architecture/`; if >30ms, revise spec SC3 now.
- [x] **T8 — Secrets/regex scrubber (Rust-backed, ADR-0006)** (`crates/guardrails-core/` +
  `src/rails/input/secrets.py` wrapper; Python fallback). **Done:** planted secret detected+redacted+
  audited; benign passes; Rust + fallback agree on the shared vectors. *(needs T4, T6b)*
- [x] **T9 — PI/jailbreak classifier** (`src/rails/input/prompt_injection.py`, deberta-v3, warmed).
  **Done:** blocks ≥ threshold of `Security_module` `injection_payloads`/`xpia_payloads`; FPR measured on
  a benign set; both logged split. *(needs T4)*
- [x] **T10 — PII detect+redact** (`src/rails/input/pii.py`, Presidio). **Done:** email/SSN/phone
  redacted; allowlist honored. *(needs T4)*
- [x] **T11 — Spotlighting + boundary-awareness (Rust-backed, ADR-0006)** (`crates/guardrails-core/` +
  `src/rails/input/spotlight.py`; Python fallback). Datamark/delimit untrusted spans; inject
  boundary-awareness prefix. **Done:** untrusted span marked; Rust + fallback agree on vectors. *(needs T6b)*
- [x] **T12 — Minimal CI regression gate (pulled forward).** CI job: "ASR on the `Security_module`
  fixture set must not regress" vs a committed baseline. **Done:** CI fails on a synthetic regression.
  *(needs T9)*

## Phase 2 — Dialog rails (L2)
- [x] **T13 — Task-Shield off-task detector** (`src/rails/dialog/task_shield.py`). Allowed-task envelope.
  **Done:** off-task request blocked w/ refusal template; on-task passes. *(needs T4)*
- [x] **T14 — Deny-by-default topic policy** (`src/rails/dialog/topics.py`, versioned policy file).
  **Done:** denied topic blocked, allowed passes.

## Phase 3 — Output rails (L6)
- [x] **T15 — Schema validator + reask** (`src/rails/output/schema.py`, Pydantic). **Done:** malformed
  structured output → one reask → block, audited.
- [ ] **T16 — Content classifier** (`src/rails/output/content.py`, Mistral Moderation primary /
  ShieldGemma 2 fallback, `_method` recorded). **Done:** unsafe blocked, benign passes.
- [x] **T17 — PII/secret/canary leak** (`src/rails/output/leak.py`). Plant canary in system prompt;
  detect in output. **Done:** leaked canary → block; output secret redacted.
- [x] **T18 — URL/markdown/HTML sanitizer (Rust-backed, ADR-0006)** (`crates/guardrails-core/` +
  `src/rails/output/sanitize.py`; Python fallback). **Done:** data-bearing image/link stripped;
  allowlisted links kept; raw HTML/script blocked; Rust + fallback agree. Visual harness in `web/` (T40).
- [ ] **T19 — Grounding check** (`src/rails/output/grounding.py`, reuse eval pipeline `grounding_judge`).
  **Done:** ungrounded claim flagged when sources present; toggle honored.

## Phase 4 — Tool/action rails (L4) — active via trace hook
- [ ] **T20 — Trace-export hook in Odysseus** (`odysseus/src/tool_execution.py`, read-only; ADR-0005).
  Emit normalized tool-call events to the gateway. **Done:** stub/live tool call produces a trace event
  the gateway receives; Odysseus behaviour unchanged. *(pins OQ3 schema)*
- [x] **T21 — In-house policy DSL (Rust-backed, ADR-0006/0004)** (parser+evaluator in
  `crates/guardrails-core/` + `src/rails/tool/policy.py` wrapper; Python fallback). Deny-by-default over a
  normalized `ToolCall`. **Done:** `bash`/`api_call` blocked unless policy allows; decision logged w/
  policy id; Rust + fallback agree on the policy vectors. *(needs T6b; the Rust parser is the highest-value
  memory-safety target — see T22)*
- [x] **T22 — DSL adversarial hardening (ADR-0004 gate).** Adversarial bypass test set (encoding, arg
  smuggling, fail-open) + `security-reviewer` pass. **Done:** all bypass tests blocked; review clean.
  *(blocks T23)*
- [ ] **T23 — HITL on irreversible tools** (`src/rails/tool/hitl.py`, risk-tiered; gateway-mediated
  approve/reject before Odysseus executes). **Done:** irreversible tool pauses for approve/reject. *(needs T22)*
- [ ] **T24 — SSRF/egress allowlist + param validation** (`src/rails/tool/egress.py`, mirror
  `Security_module/core/ssrf_guard.py` patterns). **Done:** internal-target/exfil URL blocked; allowlisted passes.

## Phase 5 — Retrieval/memory rails (L5) — active via hook
- [ ] **T25 — Write-time moderation + provenance** (`src/rails/memory/write_guard.py`). **Done:**
  poisoned memory (ASI06/ext14 payload) blocked at write; provenance/trust label recorded.
- [ ] **T26 — Tenant isolation + retrieval validators** (`src/rails/memory/retrieval.py`). Trust/freshness
  threshold, PII mask, cross-tenant block. **Done:** cross-tenant read blocked; low-trust chunk dropped.

## Phase 6 — Reasoning/IFC + multi-agent + oversight
- [ ] **T27 — Quarantined-LLM parser** (`src/rails/reasoning/quarantine.py`, dual-LLM; no tool access).
  **Done:** injected instruction in quarantined text yields no tool request; typed object returned.
- [ ] **T28 — Taint labels + trusted-action invariant** (`src/rails/reasoning/taint.py`). **Done:**
  tool call with any untrusted-tainted arg blocked; clean call passes. *(needs T21)*
- [ ] **T29 — Multi-agent rails** (`src/rails/multiagent/`). Resolve OQ1 first; signed messages +
  capability-token delegation + orchestrator mediation (synthetic MAS if Odysseus single-agent).
  **Done:** tampered inter-agent message rejected.
- [ ] **T30 — Oversight critic** (`src/rails/oversight/critic.py`, post-hoc on trajectory+output).
  **Done:** goal-drift trajectory flagged.

## Phase 7 — Testing methods on security methods
- [ ] **T31 — A/B attack harness** (`src/eval/ab_harness.py`). Security_module direct vs via gateway →
  ASR per attack class + utility retention. **Done:** report shows ASR(gateway) ≤ ASR(direct) per class,
  checked against spec SC1/SC2 thresholds, split (never one F1).
- [ ] **T32 — External benchmarks** (`src/eval/benchmarks.py`, AgentDojo/WASP via Inspect Evals).
  **Done:** ≥1 benchmark runs, reports ASR + utility-under-attack.
- [ ] **T33 — FPR/over-refusal eval** (benign eval-pipeline suite). **Done:** per-rail FPR vs SC2 reported.
- [ ] **T34 — Latency report** (`src/eval/latency.py`). **Done:** per-layer p50 table vs budgets.

## Phase 8 — Hardening & governance
- [ ] **T35 — Adaptive-attack eval** (attacker knows the top input rail; arXiv:2503.00061). **Done:**
  documented results + any threshold retune.
- [ ] **T36 — Audit/governance export** + NIST AI RMF / EU AI Act control map. **Done:** audit export +
  control-map doc in `docs/`.
- [ ] **T37 — Full CI quality gate.** ASR/FPR thresholds blocking (extends T12). **Done:** CI fails on
  ASR regression or FPR over threshold.

## Phase 9 — Frontend: HITL + observability (TypeScript/React, ADR-0007)
- [ ] **T38 — Gateway UI API** (`src/gateway/ui_api.py`). Minimal authenticated JSON API: list pending
  approvals, post approve/reject, read audit log + eval reports. Treat all input as untrusted; rate-limit.
  **Done:** endpoints unit-tested; default-deny on unknown/expired approval id. *(needs T6, T23)*
- [ ] **T39 — HITL approval app** (`web/` — pending-approval view rendering `ToolCall` + provenance/taint;
  approve/reject; default-deny on timeout). **Done:** vitest covers approve, reject, timeout-deny; no
  security logic client-side. *(needs T38)*
- [ ] **T40 — Observability/audit dashboard + sanitizer harness** (`web/`). ASR/FPR split, latency
  budgets, block reasons, NIST/EU-AI-Act control-map view; plus a DOM visual-regression harness for the
  T18 sanitizer. **Done:** dashboard renders from sample audit/eval data; sanitizer harness proves a
  data-bearing image/link is stripped in a real DOM. *(needs T18, T36)*

## Cross-cutting
- [ ] Daily push to `github.com/krishddd/SEC_Guardrails_Agent` at end of each session (`.env` gitignored).
- [ ] Polyglot CI green across all three lanes (Python ruff/pytest, Rust fmt/clippy/test+maturin,
  web tsc/eslint/vitest) — folded into T12/T37 gates.
