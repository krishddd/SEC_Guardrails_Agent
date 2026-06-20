# Odysseus Guardrails — Architecture & Implementation Plan

> Source brief: `AI_Agent_Guardrails_Reference.md` (canonical) + `AI_Agent_Guardrails_Research.md`.
> Scope decisions (confirmed 2026-06-20): **target = Odysseus agent (port 7000, Mistral-backed)**;
> **build-from-scratch**; **full 7-layer topology**; **Reference.md is canonical** → skill/MCP
> supply-chain guardrails are **OUT of scope** (handled by the offensive module separately).
> Defensive only. The offensive red-team (`Agent_security_testing/Security_module`) is NOT rebuilt —
> it is reused as the attack oracle. The `Agent eval pipeline` is reused as the scorer.

---

## 0. The central constraint (read first)

Odysseus's live API (confirmed via `Agent eval pipeline/adapters/odysseus_adapter.py` and the
2026-06-13 live-discovery notes) exposes to an API token:

- `POST /api/v1/chat {"message": ...}` → **plain LLM chat, runs NO tools**, returns `{response, session_id, model}`.
- `GET /api/health`.
- Real tool execution is a server-side async task lifecycle **whose per-step trace is NOT exposed** to an API client.

**Implication:** an *external* guardrail can fully enforce **L1 (input), L2 (dialog), L6 (output)**
at the network boundary today. **L4 (tool/action), L5 (retrieval/memory), and multi-agent rails**
require an enforcement point *inside* Odysseus's tool boundary, which this build does not expose.

We therefore deliver them in two states:
- **Active now** at the boundary: L1, L2, L6, plus the parts of L4/L5 that ride the *input* channel
  (most poisoning/injection payloads — ext10 XPIA, ext14 data poisoning, ASI06 memory poisoning —
  *enter as text*, so input rails catch a large fraction) and the *egress* channel (SSRF/exfil allowlist).
- **Design-complete, wiring-gated** for the rest: implemented + unit-tested against **synthetic traces**,
  with the Odysseus interception point documented. They light up when Odysseus exposes its task-lifecycle
  trace (the eval adapter already has defensive trace extraction staged for exactly this) or via a sidecar.

This is the honest reading of "full 7-layer" against the current Odysseus build. No layer is faked; the
gated ones ship as tested modules with a single documented wiring TODO each.

---

## 1. Architecture

### Deployment shape — non-invasive reverse-proxy gateway
A standalone FastAPI **guardrail gateway** on a new port (default `:7100`). Clients point at `:7100`
instead of `:7000`. The gateway:
1. runs the **input rail chain** on the request,
2. forwards allowed requests to Odysseus `:7000` using `ODYSSEUS_TOKEN`,
3. runs the **output rail chain** on the response,
4. returns the (possibly modified) response, emitting a trace + audit record for every decision.

Rationale: we do not control the Odysseus container, so enforcement must be external and drop-in.
The same API surface is proxied unchanged.

### "Build from scratch" — what that means here
We implement the **rail orchestration, IFC/dual-LLM, spotlighting, Task-Shield, policy engine, and
all enforcement logic** ourselves. We do **not** retrain commodity classifiers from zero — the
reference doc itself treats those as *components* (deberta-v3, ShieldGemma, Presidio). Building a PI
model from scratch is not "building a guardrail." So: our code = the control plane; small pretrained
models = swappable detectors behind a uniform `Rail` interface.

### Layer map (→ defends which offensive tests)
| Layer | Enforcement point | Built from | Defends (Security_module) |
|---|---|---|---|
| **L1 Input** (<30ms) | gateway, on request | secrets/regex scrub, `protectai/deberta-v3-base-prompt-injection-v2`, Presidio PII, spotlighting/datamarking, boundary-awareness prefix | ext10 XPIA, ASI01 goal-hijack, jailbreaks, ASI09 trust-exploit, ext01 log-injection |
| **L2 Dialog/topic** (<200ms) | gateway | in-house Task-Shield (allowed-task envelope) + deny-by-default topic policy + refusal templates | scope/goal violations, ext07 goal-drift (partial) |
| **L3 Reasoning / IFC** | gateway (multi-turn) | dual-LLM: Quarantined-LLM parses untrusted text → typed objects; capability/taint labels; trusted-action invariant | ext10 XPIA escalation, ASI01 |
| **L4 Tool/action** | Odysseus trace (gated) + egress (now) | deny-by-default policy engine, HITL on irreversible tools, param validation, SSRF/egress allowlist | ASI02 tool-misuse, ASI03 privilege-abuse, ASI05 code-exec, ext17 delivery-hijack |
| **L5 Retrieval/memory** | Odysseus memory hook (gated) + input (now) | write-time moderation, provenance/trust labels, tenant isolation, memory-write critic | ASI06 memory-poison, ext14 data-poison, ext16 cache-poison |
| **Multi-agent** | inter-agent channel (gated) | signed messages, capability-token delegation, orchestrator mediation | ASI07 inter-agent, ASI10 rogue-agents, ext03 consensus-spoof |
| **L7 Verify/oversight** | gateway, post-hoc | critic pass on final trajectory + output | ext12 alignment, ext07 goal-drift |
| **L6 Output** (<50ms) | gateway, on response | schema/Pydantic + reask, content classifier (Mistral Moderation `mistral-moderation-2603` primary / ShieldGemma 2 fallback), grounding check, PII/secret redaction, canary-leak detect, URL/markdown/HTML sanitize | ext13 model-extraction, ext15 attribute-inference, sensitive-info disclosure, output exfil side-channels |
| **Observability** (cross-cutting) | every rail | OpenTelemetry GenAI semconv (client spans stable; agent spans experimental-but-usable), append-only JSONL audit log, per-rail ASR/FPR/latency | evidence for NIST AI RMF / EU AI Act |

### Out of scope (Reference.md canonical)
Skill/MCP supply-chain guardrails → **not built here**. The offensive tests ASI04 (supply-chain) and
ext11 (MCP tool poisoning) remain in the red-team module but are not defended by this gateway.

---

## 2. Version-pinned tech decisions (researched 2026-06-20)
- **Input PI/jailbreak:** `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, English-only,
  weak on jailbreaks → pair with the content classifier for jailbreak coverage). Self-hosted via `transformers`.
- **PII:** Microsoft Presidio `presidio-analyzer` 2.2.362 (Mar 2026), MIT. Analyzer + Anonymizer.
- **Output content safety:** Mistral **Moderation API** `mistral-moderation-2603` (native to the
  Mistral-backed agent, multilingual, adds jailbreak detection; `mistral-moderation-2411` deprecated
  2026-03-31). Self-hosted **ShieldGemma 2** (2B/9B) as offline fallback.
- **Policy engine (L4):** OPA/Rego as the deny-by-default decision point (policies in Git, CI-tested),
  with a thin in-house rule layer if OPA is too heavy for v1.
- **Schema:** Pydantic v2.
- **Eval:** reuse `Agent eval pipeline` as scorer; AgentDojo + WASP via **Inspect Evals** for external
  benchmarking; Security_module as the in-house attack oracle.
- **Tracing:** OpenTelemetry; opt into dual-emission via `OTEL_SEMCONV_STABILITY_OPT_IN` during the
  experimental→stable transition for agent spans.
- **Secrets:** reuse `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` from `Agent eval pipeline/.env` via a shared
  loader. ⚠️ The OpenAI key was shared in plaintext previously — **rotate before first push**.

---

## 3. Task list (ordered; each = one sitting, with a done-condition)

### Phase 0 — Foundations
- [ ] **T0.1 Repo + remote + hygiene.** `git init`, remote `https://github.com/krishddd/SEC_Guardrails_Agent`, `.gitignore` (`.env`, model caches, `reports/`), README. **Done:** `git push` succeeds; `git ls-files` contains no secret/env.
- [ ] **T0.2 Config + secrets loader.** Zero-dep loader resolving `ODYSSEUS_BASE_URL`, `ODYSSEUS_TOKEN`, `OPENAI_API_KEY` from the sibling `.env` (path override) + process env. **Done:** unit test with monkeypatched env resolves token + base_url; missing token raises a clear error.
- [ ] **T0.3 Odysseus client.** Thin client mirroring the proven contract (`/api/v1/chat`, `/api/health`, header auth, **4xx = no retry**, 5xx/network = retry). **Done:** `health_check()` green against a local stub agent; unit tests for retry policy.
- [ ] **T0.4 Gateway skeleton.** FastAPI proxy on `:7100` forwarding `/api/v1/chat` to `:7000` unchanged (no rails yet). **Done:** response through gateway == direct response against the stub.
- [ ] **T0.5 Observability + audit scaffold.** Per-request trace id; rail decisions appended to JSONL audit log; OTel span per request. **Done:** one pass-through call emits exactly one span + one audit record.
- [ ] **T0.6 Rail framework.** `Rail.inspect(ctx) -> Decision{allow|block|modify, reason}`, ordered `RailChain` (short-circuit on block), `RailContext` carrying trust labels. **Done:** unit test proves chain short-circuits and records the blocking rail.
- [ ] **T0.7 CI.** GitHub Actions: ruff + pytest on push/PR. **Done:** green check on a PR.

### Phase 1 — Input rails (L1, active now)
- [ ] **T1.1 Secrets/regex scrubber.** **Done:** planted secret detected + redacted + audited; benign passes.
- [ ] **T1.2 PI/jailbreak classifier.** deberta-v3 behind the `Rail` interface, warmed at startup. **Done:** blocks ≥X% of `injection_payloads.py` + `xpia_payloads.py` at threshold; FPR measured on a benign set; both numbers logged (split, never one F1).
- [ ] **T1.3 PII detect+redact (Presidio).** **Done:** email/SSN/phone redacted; allowlist honored.
- [ ] **T1.4 Spotlighting + boundary-awareness.** Datamark/delimit untrusted spans; inject boundary-awareness prefix. **Done:** untrusted span wrapped; unit test confirms marking + prefix.
- [ ] **T1.5 Input latency budget.** **Done:** warmed-classifier p50 < 30ms recorded in a bench report.

### Phase 2 — Dialog/topic rails (L2, active now)
- [ ] **T2.1 Task-Shield (off-task detector).** Allowed-task envelope; block off-task requests. **Done:** off-task request blocked with refusal template; on-task passes.
- [ ] **T2.2 Deny-by-default topic policy.** **Done:** denied topic blocked, allowed topic passes; policy is a versioned file.

### Phase 3 — Output rails (L6, active now)
- [ ] **T3.1 Schema validator + reask.** Pydantic validate structured outputs; one reask then block. **Done:** malformed output → one reask → block, all audited.
- [ ] **T3.2 Content classifier.** Mistral Moderation primary, ShieldGemma 2 fallback; method recorded. **Done:** unsafe output blocked, benign passes, `_method` field populated.
- [ ] **T3.3 PII/secret redaction + canary-leak.** Plant canary token in system prompt; detect in output. **Done:** leaked canary → block; secret in output redacted.
- [ ] **T3.4 URL/markdown/HTML sanitization.** **Done:** data-bearing image/link stripped (exfil), allowlisted links kept, raw HTML/script blocked.
- [ ] **T3.5 Grounding/hallucination check.** Reuse the eval pipeline's `grounding_judge` approach. **Done:** ungrounded claim flagged when sources present; toggle env honored.

### Phase 4 — Tool/action rails (L4; egress active now, trace gated)
- [ ] **T4.1 Policy engine (deny-by-default).** OPA/Rego (or in-house DSL) over a normalized `ToolCall`. **Done:** `bash`/`api_call` blocked unless policy allows; decision logged with policy id.
- [ ] **T4.2 HITL on irreversible tools.** Risk-tiered routing (read-only auto, write/destructive gate). **Done:** irreversible tool pauses for approve/reject in a synthetic-trace test.
- [ ] **T4.3 SSRF/egress allowlist + param validation.** Defensive egress guard. **Done:** internal-target/exfil URL blocked; allowlisted host passes.
- [ ] **T4.4 Trace interception adapter (gated).** Consume Odysseus task-lifecycle trace when present; run against synthetic traces until then; document the exact wiring point. **Done:** synthetic trace flows through L4; one wiring TODO documented in code + this plan.

### Phase 5 — Retrieval/memory rails (L5; input active now, hooks gated)
- [ ] **T5.1 Write-time moderation + provenance labels.** **Done:** poisoned memory (ASI06/ext14 payload) blocked at write in the synthetic harness; provenance recorded.
- [ ] **T5.2 Tenant isolation + retrieval validators.** Trust/freshness threshold, PII mask, cross-tenant block. **Done:** cross-tenant read blocked; low-trust chunk dropped.

### Phase 6 — IFC + multi-agent + oversight (L3 / multi-agent / L7)
- [ ] **T6.1 Quarantined-LLM parser (dual-LLM).** Untrusted text → typed object, no tool access (uses `OPENAI_API_KEY`). **Done:** injected instruction in quarantined text yields no tool request; structured object returned.
- [ ] **T6.2 Capability/taint labels + trusted-action invariant.** Block a tool call if any arg is untrusted-tainted. **Done:** tainted-arg call blocked; clean call passes.
- [ ] **T6.3 Multi-agent rails (gated).** Signed messages + capability-token delegation + orchestrator mediation, tested on a synthetic MAS; mark wiring-pending if Odysseus is single-agent. **Done:** tampered inter-agent message rejected in harness.
- [ ] **T6.4 Verification/oversight critic.** Post-hoc critic on final trajectory + output. **Done:** goal-drift trajectory flagged.

### Phase 7 — Testing methods on security methods (§13)
- [ ] **T7.1 A/B attack harness.** Run Security_module against Odysseus **direct vs. via gateway**; compute **ASR per attack class** + **utility retention**. **Done:** report shows ASR(direct) ≥ ASR(gateway) with per-class numbers, reported split (never one F1).
- [ ] **T7.2 External benchmarks.** AgentDojo + WASP via Inspect Evals against the gateway. **Done:** ≥1 benchmark runs, reporting ASR + utility-under-attack.
- [ ] **T7.3 FPR / over-refusal eval.** Benign suite (reuse eval pipeline tasks). **Done:** per-rail FPR reported.
- [ ] **T7.4 Latency report.** Per-layer budgets (input<30 / dialog<200 / output<50 ms). **Done:** table emitted.

### Phase 8 — Hardening & governance
- [ ] **T8.1 Adaptive-attack eval.** Attacker that knows the top input rail (arXiv:2503.00061). **Done:** documented results + any threshold retune.
- [ ] **T8.2 Audit/governance.** Append-only decision log export + mapping table to NIST AI RMF / EU AI Act controls. **Done:** audit export + control-map doc committed.
- [ ] **T8.3 CI quality gate.** A/B ASR + FPR thresholds as a blocking CI job. **Done:** CI fails if ASR regresses past threshold.

### Cross-cutting workflow
- [ ] **Daily push** to `https://github.com/krishddd/SEC_Guardrails_Agent` at end of each working session (`.env` always gitignored; key rotated first).

---

## 4. Open questions to resolve before/while building
1. **Repo name** under `krishddd` — assumed `SEC_Guardrails_Agent`; confirm or rename.
2. **OPA vs in-house policy DSL** for L4 v1 (OPA = heavier but standards-aligned).
3. **Is Odysseus actually multi-agent?** Determines whether the multi-agent rail is real or synthetic-only.
4. **Can the Odysseus container be modified** even slightly (to expose the tool trace)? If yes, L4/L5
   move from "gated" to "active" and the plan's value roughly doubles.
5. **Self-hosted model budget** — running deberta-v3 + ShieldGemma locally needs GPU/CPU headroom;
   confirm the host can warm them, else lean on Mistral Moderation API for both.
