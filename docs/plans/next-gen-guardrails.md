# Plan — next-generation guardrails (N-series)

**Status:** proposed (planning only — no code yet). **Source of truth for rationale:**
[`docs/research/advanced-guardrails-2026.md`](../research/advanced-guardrails-2026.md).
**Predecessors:** [`defense-improvements.md`](defense-improvements.md) (D1–D6),
[`odysseus-guardrails-plan.md`](odysseus-guardrails-plan.md) (T-series).

This plan promotes the gateway from a **detection-only** posture toward the 2025 **design-by-
construction** frontier (CaMeL / FIDES / CommandSans / Granite 4.x), *grounded in the existing code*
— every task is an upgrade to or composition of rails we already have. Per `CLAUDE.md`: each task is
one `/implement` unit, ends with **passing tests** + a **checked box**, reports metrics **split**
(ASR/interception vs FPR/utility), and **never blends F1**.

> **Scope guard.** Defensive only. We reuse `Agent_security_testing/Security_module` as the attack
> oracle and the `Agent eval pipeline` as the scorer — never rebuilt. Rust-backed rails must agree
> with their Python fallback on the shared `tests/vectors/`.

---

## Priority order (value × tractability)
`N2 → N1 → N5 → N3 → N6 → N4 → N7`. Do them one at a time; re-measure after each.

---

## N1 — Function-call schema/argument validation rail (L4)
*Granite Guardian 4.x "function-calling hallucination", deterministic version.*

- [ ] **N1.1** Add `src/rails/tool/arg_schema.py` — a `ToolArgSchemaRail` that, given a registry of
  declared tool signatures (name → required args, types, optional value-domains), flags a `ToolCall`
  whose args have **unknown names**, **missing required**, or **type-mismatched values**. Pure-Python,
  deterministic, no model. Decision: `BLOCK` (hard schema violation) vs `HITL` (suspicious value).
- [ ] **N1.2** Wire into `GuardrailEngine.guard_tool` *before* the egress/taint checks (cheap, fail
  fast). Add a `tool_schemas` field on `default_engine` (defaults to the reference agent's tools).
- [ ] **N1.3** Tests: malformed call blocked; valid call passes; type-mismatch (e.g. `calc.expr=42`
  as int where str expected) flagged. Report interception on a synthetic malformed-call set + FPR on
  the benign tool-call corpus.
- **Defends:** tool/action misuse, hallucinated tool calls. **Effort:** S.

## N2 — Token-level tool-output sanitization (L5×L1)  ⭐ first
*CommandSans — surgical strip of injected-instruction spans, not block-all.*

- [ ] **N2.1** Add a `sanitize_tool_output(text) -> (clean_text, removed_spans)` primitive in
  `src/rails/input/` (heuristic first: sentence/line-level instruction detection reusing the D1
  `_HEURISTIC_PATTERNS` + `_PERSONA_TRIGGER`; optional ML backend behind the `ml` extra mirroring
  `load_deberta_detector`). Strip only the spans that match instruction patterns; keep benign data.
- [ ] **N2.2** Upgrade `GuardrailEngine.guard_tool_output`: instead of block-all on a detected
  injection, **sanitize** → return cleaned text + an audit record of removed spans; **block only**
  when sanitization can't make the text safe (e.g. secrets present). Keep the existing block path as
  the fallback for the `scan_chain`'s hard rails (Secrets/PII).
- [ ] **N2.3** Wire `runtime.py` + gateway `/api/_trace` to surface `removed_spans` count.
- [ ] **N2.4** Tests: poisoned-but-useful tool result → injected line removed, benign data survives,
  agent still completes the task (utility win); pure-injection result → fully stripped/blocked.
  Report **ASR (injected instruction reaching the model)** and **utility (benign data retained)**.
- **Defends:** indirect injection / XPIA. **Effort:** M. **Biggest utility upgrade in the plan.**

## N3 — Capabilities / data-flow policy at the tool call (L3×L4)
*CaMeL — provenance labels + sink policy; promote `taint.py`/`quarantine.py` primitives.*

- [ ] **N3.1** Extend the value model: attach a **capability label** `{provenance, sources, sinks}`
  to data produced by tool outputs and memory reads (build on `ToolCall.tainted_args` + `taint.py`).
- [ ] **N3.2** Add a **data-flow policy** to `policy.py`: a tool sink (e.g. `http_fetch`, `email`,
  `sql` write) **rejects** args whose capability label includes an untrusted source not on that
  sink's allow-list (prevents "read secret → exfil over URL"). Deterministic; deny-by-default.
- [ ] **N3.3** Tests built from the Security_module exfiltration payloads: untrusted-data→sink flow
  blocked; legitimate same-source flow allowed. Report interception on exfil suite + FPR on benign
  multi-step tasks. **Effort:** L.

## N4 — Two-axis IFC labels: confidentiality + integrity (L3)
*FIDES — labeled lattice + declassify/endorse, replacing the single taint bit.*

- [ ] **N4.1** Refactor `taint.py` from a boolean taint to a **(confidentiality, integrity)** label
  pair with a small lattice; define `declassify`/`endorse` as explicit, audited operations.
- [ ] **N4.2** Make N3's sink policy consume the two-axis label (e.g. block high-confidentiality data
  into a low-confidentiality sink; block low-integrity data into a high-integrity action).
- [ ] **N4.3** Parity: Rust `taint` primitive + Python fallback agree on `tests/vectors/`.
- [ ] **N4.4** Tests for label propagation, declassify gating, and the formal properties from the
  FIDES paper that the lattice should enforce. **Effort:** L. **Depends on N3.**

## N5 — Plan-Then-Execute + Context-Minimization in the reference agent
*Design-patterns paper — structural ASR reduction independent of detection.*

- [ ] **N5.1** `runtime.py`: split `handle()` into **plan** (derive the full tool plan from the
  *trusted* user message *before* any tool runs) then **execute** (run the frozen plan). Untrusted
  tool output **cannot add or alter** steps — only fill data slots.
- [ ] **N5.2** **Context-Minimization:** after a tool result's needed data is extracted, drop the raw
  untrusted text from the context passed forward (keep only the extracted, labeled value).
- [ ] **N5.3** Tests: an injected "now also email X" inside a tool result does **not** create a new
  action (plan frozen); benign multi-step tasks still complete. Report ASR on indirect-action-
  injection + utility on benign multi-step. **Effort:** M.

## N6 — Spotlighting encoding variant + 3-way measurement (L1)
*Microsoft Spotlighting — add encoding mode; measure delimiting vs datamarking vs encoding.*

- [ ] **N6.1** Add an `encoding` mode (base64) to `spotlight.py` alongside the existing datamarking.
- [ ] **N6.2** Bench the three modes on the XPIA suite; write `docs/eval/N6-spotlight-variants.md`
  with **ASR per mode** and **FPR/utility per mode** (split). **Effort:** S.

## N7 — Public guard-classifier benchmark lane (cross-cutting)
*GuardBench-style external benchmark, reused not rebuilt.*

- [ ] **N7.1** Add a benchmark driver (mirroring `eval/benchmarks.py`'s AgentDojo lazy-import
  pattern) for a public guard dataset; record interception + FPR. Skipped-not-crashed if the dataset
  isn't installed. **Effort:** M.

---

## Cross-cutting acceptance criteria (apply to every N-task)
- Split metrics only (ASR/interception **and** FPR/utility), never blended.
- New deterministic rails get a Rust path + Python fallback agreeing on `tests/vectors/` *if*
  they're on the <30 ms hot path (N1, N3, N4); pure-eval/measurement tasks (N6, N7) are Python-only.
- Every task ends green: `ruff check` + `ruff format --check` + `pytest`.
- Update `docs/eval/` with measured results; check the task box; one task per `/implement`.

## Verification debt (carry-over from the research run)
- [ ] **N0** Re-run the `deep-research` verify panel after the account session limit resets (claims
  in the digest are `[unverified-by-panel]`). Upgrade confirmed claims; drop any that fail 2/3.
