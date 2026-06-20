# Spec — Odysseus Runtime Guardrails

*Distilled from `research/2026-06-20-odysseus-guardrails.md` (which frames `AI_Agent_Guardrails_Reference.md`,
canonical). Produced by the `/research-distill` stage.*

## Problem statement
The Odysseus autonomous agent (Mistral-backed, Docker `:7000`) plans, calls tools (bash, document
creation, web/API calls), reads untrusted external data, and holds memory — a large attack surface with
no runtime control plane. An existing offensive module (`Security_module`) can already compromise it
(ASI01–10, ext01–17). We need a **defensive, build-from-scratch, 7-layer runtime guardrail** that sits
in front of and around Odysseus, decides at every boundary whether what the agent is about to read, say,
or do is allowed, and measurably reduces attack success without destroying task utility.

## Goals (testable)
- **G1** A reverse-proxy **guardrail gateway** on `:7100` proxies Odysseus's API unchanged; clients
  repoint from `:7000` to `:7100` with no behavioural change on benign traffic.
- **G2** **Input rails (L1)** block prompt-injection / jailbreak / secrets / PII before the agent sees them.
- **G3** **Dialog rails (L2)** keep the agent on its allowed task/topics (Task-Shield + deny-by-default).
- **G4** **Output rails (L6)** enforce schema, content safety, grounding, PII/secret/canary redaction,
  and strip exfiltration side-channels (data-bearing links/images, raw HTML).
- **G5** **Tool/action rails (L4)** enforce a deny-by-default policy + HITL on irreversible tools +
  SSRF/egress allowlist, attached to a live Odysseus tool trace via a minimal trace-export hook.
- **G6** **Retrieval/memory rails (L5)** moderate memory writes, tag provenance, isolate tenants.
- **G7** **Reasoning/IFC (L3)** dual-LLM quarantined parser + taint labels + trusted-action invariant.
- **G8** **Multi-agent + oversight** rails (signed messages / capability delegation; critic pass).
- **G9** **Observability**: OpenTelemetry trace + append-only audit record for every rail decision.
- **G10** An **A/B evaluation harness** that runs `Security_module` direct vs via gateway and reports
  ASR per attack class and utility retention, **split** — plus AgentDojo/WASP via Inspect Evals.
- **G11 (polyglot)** The security-critical deterministic core (secrets scanner, spotlighting/datamarker,
  URL/HTML sanitizer, L4 policy-DSL evaluator, taint primitives) is implemented in **Rust** (PyO3 ext
  `guardrails_core`, pure-Python fallback; ADR-0006); the **HITL approval app** and **observability/
  audit dashboard** are a **TypeScript/React** app (ADR-0007). Python remains the control plane.

## Non-goals (explicit exclusions)
- **Skill/MCP supply-chain guardrails** — out of scope (Reference.md canonical). Offensive ASI04
  (supply-chain) and ext11 (MCP tool poisoning) remain in the red-team but are **not defended**.
- **Rebuilding** the offensive `Security_module` or the `Agent eval pipeline` — both are reused as-is.
- **Retraining** foundation classifiers from zero — commodity detectors are swappable components.
- **Modifying Odysseus beyond a minimal read-only trace-export hook** at the tool-execution boundary.

## Constraints
- **C1** Odysseus `/api/v1/chat {message}` runs no tools; tool execution is server-side. Live L4/L5
  enforcement depends on the **trace-export hook** in `odysseus/src/tool_execution.py` (approved).
- **C2** Odysseus `4xx` is terminal (no retry); request bodies must match schema exactly (`422` else).
- **C3** Odysseus is **currently down**; build/test against a **stub agent**, live A/B later.
- **C4** Per-layer latency budgets (Reference §13.2): input <30 ms, dialog <200 ms, output <50 ms.
- **C5** Secrets reused from the eval pipeline `.env` (`ODYSSEUS_TOKEN`, `OPENAI_API_KEY`); the OpenAI
  key **must be rotated** before use. `.env` never committed.
- **C6** Python 3.11 / FastAPI / httpx / Pydantic v2 / pytest / ruff (see CLAUDE.md).
- **C7** Defense-in-depth: no single classifier is trusted; deny-by-default; treat all external content
  as untrusted.
- **C8** Polyglot toolchain: Python 3.11 (control plane), Rust stable + maturin/PyO3 (`guardrails_core`),
  Node 20 + TypeScript/Vite (`web/`). CI must lint+test all three lanes; Rust and Python fallback share a
  test-vector set and must agree. The gateway↔UI API is treated as untrusted client input.

## Open questions
- **OQ1** Is Odysseus genuinely multi-agent (does it coordinate sub-agents)? Determines whether the
  multi-agent rail enforces real inter-agent traffic or is validated on a synthetic MAS. *(Resolve while
  reading `odysseus/src/agent_loop.py` / `agent_runs.py`.)*
- **OQ2** Local model-hosting budget for deberta + ShieldGemma vs leaning on the Mistral Moderation API
  — informed by the input-rail latency spike (T-spike).
- **OQ3** Exact Odysseus tool-trace schema to export from the hook (tool name, args, result, status,
  timing) — pin against `tool_execution.py` before wiring L4 metrics.

## Success criteria
- **SC1 (security):** For each `Security_module` attack class, **ASR(via gateway) ≤ ASR(direct)**, with
  a target of **≥50% relative ASR reduction** on the input-deliverable classes (injection, XPIA, goal
  hijack) at v1; report per-class, never blended.
- **SC2 (utility — concrete threshold):** On a fixed **benign-task benchmark** (reuse the eval
  pipeline's benign Odysseus suite, chat-mode tasks), the gateway must hold **task-completion drop ≤ 5%**
  and **over-refusal (FPR) ≤ 3%** vs direct. These are acceptance gates, not just measurements; the P7
  A/B harness checks against them.
- **SC3 (latency):** Warmed per-layer p50 within budget (input <30 / dialog <200 / output <50 ms);
  if unmet, the budget is revised in this spec during the latency spike, before it is load-bearing.
- **SC4 (observability):** 100% of rail decisions emit an OTel span + an append-only audit record.
- **SC5 (governance):** Audit log exportable and mapped to NIST AI RMF / EU AI Act controls.
