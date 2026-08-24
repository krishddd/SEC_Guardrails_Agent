# Plan — deployment hardening (G-series)

**Status:** proposed (planning only — no code yet).
**Source:** the *SEC_Guardrails_Agent architectural assessment* (end-to-end source review, 2026-08-24)
— one P0 pass-through finding + 10 further gaps, each verified against source in this repo.
**Predecessors:** [`odysseus-guardrails-plan.md`](odysseus-guardrails-plan.md) (T-series),
[`next-gen-guardrails.md`](next-gen-guardrails.md) (N-series).

The T/N series built a **correct 7-layer library** — `GuardrailEngine` composes every layer and the
`GuardedOdysseusClient` / reference agent enforce it. This plan closes the gap between that library
and what a client hitting `:7100` via `sec-guardrails serve` **actually receives today**. The
headline: the deployed `/api/v1/chat` route runs **zero rails** — it forwards to a raw
`OdysseusClient` and hardcodes an `allow` audit record. Everything else is second-order until that
line ships.

> **Scope guard.** Defensive only. Reuse `Agent_security_testing/Security_module` as the attack
> oracle and the `Agent eval pipeline` as the scorer — never rebuilt. Rust-backed rails must agree
> with their Python fallback on the shared `tests/vectors/`. Metrics always reported **split**
> (ASR/interception vs FPR/utility), never a blended F1. Each task = one `/implement` run that ends
> with **passing tests** + a **checked box**, and does not cascade into the next.

---

## Priority order (from the assessment roadmap)
`G1 → G3 → G4 → G2 → G6 → G5 → {N3, N5} → G8 → G9 → G10 → G11`

G1 and G3 are both **P0** (deployment is unguarded / SSRF is advisory-only). G2/G4/G5/G6 are P1.
N3 and N5 (Gap #7) are **already planned** in [`next-gen-guardrails.md`](next-gen-guardrails.md) — do
not duplicate them here; this plan only re-points at them for sequencing. G8–G11 are P2/P3.

---

## P0 — the deployment is unguarded

### G1 — Wire the rail engine into the deployed `/api/v1/chat` path
*Assessment Gap #1 (P0, verified). The single highest-impact change in the whole report.*

- [x] **G1.1** [`build_default_app`](../../src/sec_guardrails/__init__.py) now wraps the raw client:
  `client = GuardedOdysseusClient(OdysseusClient(...), engine)`. Same engine that was already built.
- [x] **G1.2** `POST /api/v1/chat` in [`gateway/app.py`](../../src/sec_guardrails/gateway/app.py)
  dispatches on the return type: a `GuardedReply` with `allowed=False` emits `_emit("block",
  stage=..., reason=...)` and returns a safe refusal body (`{"response": "Request blocked by
  guardrails.", "blocked": True, "stage", "reason"}`, HTTP 200 — never the model output);
  `allowed=True` emits `_emit("allow", stage=...)` and returns the guarded output. The hardcoded
  `_emit("allow")` for the guarded path is gone; the 502-on-upstream path is preserved.
- [x] **G1.3** `create_app` stays uncoupled: it accepts a raw client (returns the upstream dict —
  legacy/stub path, still covered by `test_gateway.py`) or a `GuardedOdysseusClient` (returns a
  `GuardedReply`). `GuardedOdysseusClient` gained a `health_check` delegate so `/health` works for
  both. The wiring choice lives only in `build_default_app`.
- [x] **Done:** [`tests/test_gateway_guarded.py`](../../tests/test_gateway_guarded.py) proves
  (a) benign forwarded + `allow` audit with real stage `ok`; (b) injection **blocked pre-send**
  (upstream `.chat` never called) + `block`/`input` audit; (c) leaked-canary withheld at `output`;
  (d) upstream 500 still → 502 when guarded; (e) the flagged pass-through comment line is gone;
  (f) `build_default_app` wires a `GuardedOdysseusClient`. Full suite **283 passed, 14 skipped**;
  ruff check + format clean. The deployed path and the eval arm now share the **same**
  `GuardedOdysseusClient`, so `ab_harness`'s split ASR/FPR numbers now describe the deployment, not a
  separate arm.

---

## P0 — SSRF is advisory documentation, not enforcement

### G3 — Resolve-time IP checks in the egress guard
*Assessment Gap #3 (P0, verified — [`egress.py`](../../src/sec_guardrails/rails/tool/egress.py)
docstring literally states "hostname → IP resolution happens at request time (DNS rebinding); this
guard inspects the URL literal").*

- [x] **G3.1** `EgressGuard` gained `resolve_hosts: bool` + an injectable `resolver`. When enabled,
  a hostname (not an IP literal) is resolved and the loopback/private/link-local/reserved/multicast/
  unspecified predicate is applied to **every resolved IP**; resolution error/timeout/empty → block
  (fail-closed). The IP-literal path short-circuits before any DNS lookup (verified: resolver not
  called for `10.0.0.5`). Default `resolve_hosts=False` keeps the offline literal path — and the
  <30 ms hot path — unchanged; `default_engine` is untouched (opt-in), so no CI network dependency.
- [x] **G3.2** Shipped `GuardrailHttpSession`: resolves once, validates, and hands the caller's
  `fetch(url, resolved_ips)` the **pinned** IPs — so a real client connects to the validated IP
  rather than re-resolving at connect time (closing the TOCTOU window). Blocks with `PermissionError`
  before `fetch` runs. Module docstring now states what is enforced vs. the residual TOCTOU the
  wrapper closes.
- [x] **Done:** [`tests/test_egress_guard.py`](../../tests/test_egress_guard.py) proves a host
  resolving to `169.254.169.254` / RFC1918 is **blocked** (DNS rebinding), a public-resolving host
  passes and pins its IPs, resolution failure/empty → fail-closed, the IP-literal path is unchanged
  and does no DNS, and the session wrapper blocks-before-fetch / passes pinned IPs / requires a
  resolving guard. 24 egress tests pass; ruff clean. **Latency note:** resolver stays off the default
  engine hot path (opt-in). SSRF-interception vs. benign-FPR remains **split** by the existing egress
  suite; rebinding is now enforcement, not advisory.

---

## P1 — degradation, taint, preventive tool enforcement, tamper-evidence

### G4 — L7 critic: degradation alert + optional fail-closed mode
*Assessment Gap #4 (P1, verified — [`llm_critic.py`](../../src/sec_guardrails/rails/oversight/llm_critic.py)
fails open with `ok=True` on error/unparseable, no operator-visible signal).*

- [x] **G4.1** `Verdict` gained a `degraded` flag; `LLMCritic` sets it on judge error **and** on
  no-JSON/unparseable output. `GuardrailEngine.review` now records a distinct `critic_degraded`
  audit decision + an `oversight.critic_degraded` OTel health event (opt-in `tracer`) instead of an
  indistinguishable `allow`. Default behaviour stays fail-open, but the degradation is **visible** —
  an attacker forcing API timeouts can no longer silently disable L7.
- [x] **G4.2** `fail_open=False` on `LLMCritic` already yields `ok=False` on degradation (now also
  `degraded=True`); the engine additionally fires an opt-in `on_critic_degraded(verdict)` operator
  hook to route degradations to a HITL queue / SIEM. Defaults leave behaviour unchanged.
- [x] **G4.3** Added [`eval/critic_calibration.py`](../../src/sec_guardrails/eval/critic_calibration.py):
  a labeled seed corpus (benign vs. goal-drift/exfil) + `measure_critic` → `CriticCalibration`
  reporting **FP/FN split** (never blended), with degraded verdicts excluded from the denominators.
- [x] **Done:** [`tests/test_critic_degradation.py`](../../tests/test_critic_degradation.py) proves
  error/unparseable → `degraded` (fail-open ok / fail-closed flagged), the engine emits the
  `critic_degraded` audit + OTel span + hook, a genuine verdict does **not**, and calibration
  reports fpr/fnr split (always-ok critic → fnr 1.0/fpr 0.0; oracle → 0/0; all-degraded excluded).
  11 new tests + existing critic suite green; ruff clean.

### G2 — Taint propagation through memory + paraphrase-resistant sink check
*Assessment Gap #2 (Critical, verified — `TaintTracker.taint_of` is substring `any(origin in value)`;
taint is not carried on `MemoryRecord` write→retrieval). **Overlaps N3/N4** — coordinate, don't fork.*

- [x] **G2.1** `TaintTracker.add_memory(record)` carries an untrusted-provenance `MemoryRecord`'s
  taint forward: the record's content becomes an untrusted origin on retrieval (trust `!= "trusted"`),
  so a tainted write is **not** laundered clean on read — it taints any downstream tool arg it fills.
  (Provenance/trust already lives on `MemoryRecord`; this connects it to the L3 taint invariant.)
- [x] **G2.2** `TaintTracker` gained an opt-in `embedder` + `sensitive_texts` + `similarity_threshold`.
  `taint_of` now also flags an arg whose embedding cosine ≥ threshold against any registered
  sensitive text (`_is_paraphrase_of_sensitive`), catching paraphrase the substring test misses. The
  existing `TaintGate` invariant then blocks the sensitive sink. Off by default (no embedder) → the
  deterministic path is byte-for-byte unchanged.
- [x] **Done:** [`tests/test_taint_memory_paraphrase.py`](../../tests/test_taint_memory_paraphrase.py)
  proves (a) an untrusted `MemoryRecord` taints a downstream `send_email` across write→retrieve→arg,
  while a trusted record does not; (b) a paraphrase of sensitive content is blocked at the sink with
  the embedder present, a benign arg is not, and paraphrase is **not** caught when the embedder is
  absent (opt-in); (c) a non-sink tool with a tainted arg is unaffected. 6 tests + existing
  taint/memory suites green; ruff clean. **Note:** this is a detective backstop; the durable closure
  of the paraphrase/cross-turn class is structural — N3 (sink policy) + N5 (plan-then-execute).

### G6 — Preventive L4 tool enforcement (pre-execution trace)
*Assessment Gap #6 (High). Even after G1, the Odysseus trace hook (T20) is **detective** — it fires
post-execution, so an irreversible tool (bash / SQL DELETE / send_email) has already run when the
gateway sees it. The in-process reference agent already enforces preventively; this extends that to
the production trace path.*

- [x] **G6.1/G6.2** Added `POST /api/_pretrace` to
  [`gateway/app.py`](../../src/sec_guardrails/gateway/app.py): the preventive counterpart to
  `/api/_trace`. It runs the same `engine.guard_tool` synchronously and returns `{decision, stage,
  reason, tool, phase: "pre_tool", approval_id}`; the hook honors the verdict before executing. Same
  token gate as `/api/_trace`. **Fails closed** when no engine is wired (returns `block`) — the
  opposite of the detective path's `observe`, because on the preventive path a tool that hasn't run
  yet must not run without a vouch. The Odysseus-side `pre_tool` emission stays on the local
  `feat/guardrail-trace-export` branch (third-party remote), consistent with T20.
- [x] **Done:** [`tests/test_gateway_pretrace.py`](../../tests/test_gateway_pretrace.py) simulates
  the hook (execute only on `allow`): a destructive `rm -rf /` and an SSRF URL are **prevented**
  (executor never runs), a benign `pwd` runs, a non-allowlisted command returns `hitl` + an
  `approval_id` and is not executed, the no-engine path fails closed, and the token gate holds. 15
  pretrace/trace tests pass; ruff clean. This is a trace-protocol extension, not an architecture
  change — the reference agent (`agent/runtime.py:92`) already proves "execute only on ALLOW".

### G5 — Tamper-evident audit chain + `verify` CLI
*Assessment Gap #5 (High, verified — [`audit.py`](../../src/sec_guardrails/core/audit.py) is JSONL
append + thread lock; the docstring claims it is the "SOC2 / EU-AI-Act evidence trail" but anyone
with write access can rewrite history undetected).*

- [x] **G5.1** Each record now carries `prev` (previous record's hash) + `hash` (SHA-256 over the
  record's canonical serialization incl. `prev`). Editing/deleting/reordering breaks the chain. The
  append-only write + thread lock are unchanged; the record shape only gained fields; the chain
  continues across restarts (seeded from the last record's hash).
- [x] **G5.2** Optional per-record HMAC: `AuditLog(path, hmac_key=...)` adds `sig` = HMAC-SHA256 of
  the hash; key is env-loaded via the CLI (`--hmac-key-env`, default `AUDIT_HMAC_KEY`), never
  hardcoded. Absent key → chaining still active, signing skipped.
- [x] **G5.3** `sec-guardrails audit verify PATH` ([`cli.py`](../../src/sec_guardrails/cli.py) →
  `verify_audit_chain`) walks the chain and reports modified records / broken links / malformed
  lines / bad signatures with the offending line number; exits non-zero on any failure.
- [x] **Done:** [`tests/test_audit_chain.py`](../../tests/test_audit_chain.py) proves clean verify,
  per-record linkage, and detection of a modified record (right line), a deleted line, reordering, a
  malformed line, and — with a key — a fully-rebuilt chain caught by HMAC; plus restart continuity
  and CLI exit codes (0 clean / 1 tampered). Full suite **326 passed, 14 skipped**; ruff clean.

### (Gap #7) N3 + N5 — data-flow sink policy + Plan-Then-Execute
*Already planned — see [`next-gen-guardrails.md`](next-gen-guardrails.md) N3 (CaMeL sink policy) and
N5 (plan-then-execute). N3 closes the cross-turn exfiltration class G2's substring/similarity checks
only approximate; N5 is a structural defense that holds even when every classifier fails. Do N3
first, then N5, per that plan's priority order. **No new task here — this line exists so the
assessment's Gap #7 maps to an owned item.**

---

## P2 — coverage breadth

### G8 — Multilingual input detection (L1)
*Assessment Gap #8 (High). deberta-v3 + heuristic patterns are English-only; PromptGuard 2 is
HF-gated. Non-English "ignore your previous instructions" reaches Odysseus unfiltered.*

- [x] **G8.1** Added `detect_language` (offline: >20% non-ASCII letters → `non-en`, robust for
  non-Latin scripts) + `MultilingualInjectionDetector` in
  [`prompt_injection.py`](../../src/sec_guardrails/rails/input/prompt_injection.py): English text
  → English detector; non-English → a multilingual backend MAX-combined with the English detector
  (catches embedded-English attacks). `load_multilingual_detector`/`load_mistral_injection_detector`
  wire Mistral Moderation (ADR-0003) as the non-English arm; `language_detector` is injectable.
- [x] **G8.2** Coverage gap documented inline: pure-ASCII Latin-script non-English needs a real
  language detector injected via `language_detector` (test demonstrates the injection path).
- [x] **Done:** [`tests/test_multilingual_injection.py`](../../tests/test_multilingual_injection.py)
  proves the English heuristic **misses** a Cyrillic injection, `detect_language` flags it, the
  routed detector + rail **block** it while clearing benign non-English, English attacks still use
  the English arm (ML not consulted), and an injected language detector handles Latin-script Spanish.
  7 tests + injection-rail suite green; ruff clean. Interception/FPR stay **split** per the rail's
  existing measurement contract.

### G9 — Session-level threat accumulation (L2)
*Assessment Gap #9 (High). Each turn is evaluated independently, so a distributed multi-turn attack
(persona → boundary probe → payload) stays under per-turn thresholds throughout.*

- [x] **G9.1** Added `SessionThreatTracker`
  ([`rails/dialog/session_threat.py`](../../src/sec_guardrails/rails/dialog/session_threat.py)):
  a per-session score from **existing** signals (gray-band heuristic score + blocked turns, no new
  detector). Crossing the threshold escalates the session → `gray_high()` drops from 0.6 to 0.4
  (a previously-passing gray input now blocks) and `force_critic()` → True. Wired into
  `GuardrailEngine.guard_input(session=...)` via opt-in `default_engine(session_threat=...)`; the
  engine audits `session_escalated` on the crossing turn. `GuardedOdysseusClient` passes `session`
  through, so it is live on the deployed path when enabled.
- [x] **Done:** [`tests/test_session_threat.py`](../../tests/test_session_threat.py) proves a 3-turn
  gray escalation that passes turn-by-turn is **caught** on the crossing turn (`stage ==
  session_threat`), a benign 10-turn session never trips, a blocked turn weighs more, sessions are
  isolated, escalation is audited, and no-session / default-engine are per-turn only. 8 tests +
  dialog/agent suites green; ruff clean. Multi-turn ASR vs. benign-session FPR stay **split**.

---

## P3 — service hardening (developer tool → operable service)

### G10 — CI latency gates + policy hot-reload + SIEM export
*Assessment Gap #10 (High). The <30/<200/<50 ms budgets are design targets with no CI regression
gate; policy changes need a restart; block/redact decisions have no SIEM forwarding path.*

- [x] **G10.1** Added [`eval/latency.py`](../../src/sec_guardrails/eval/latency.py) (`measure_latency`
  → p50/p95 + `within_budget`) and a **pytest** latency gate
  ([`tests/test_service_hardening.py`](../../tests/test_service_hardening.py)) asserting the
  deterministic hot-path rails (secrets, spotlight) stay within the <30 ms p50 budget — CI runs it
  and fails on regression. (A pytest test, not `.github/workflows` YAML, which is hook-blocked +
  human-committed per CLAUDE.md.)
- [x] **G10.2** Added `ReloadablePolicyEngine`
  ([`rails/tool/policy_reload.py`](../../src/sec_guardrails/rails/tool/policy_reload.py)): mtime-based
  hot-reload (OS-independent, no inotify dep) with versioned activation + an `on_reload` audit hook;
  a malformed policy on disk **fails safe** (keeps the last-good engine, never opens up).
- [x] **G10.3** `AuditLog(siem_sink=..., siem_decisions=...)` forwards security decisions
  (block/redact/sanitize/hitl/error/critic_degraded/session_escalated) to a webhook/OTLP sink,
  separate from trace spans; a sink outage never breaks enforcement (record still written locally).
- [x] **Done:** deterministic rails within the 30 ms budget; a policy edit takes effect without
  restart and emits a versioned reload event; malformed policy keeps last-good; block/redact
  forwarded to a stub SIEM while routine allows are not; SIEM outage tolerated. 5 new tests +
  policy suite green; ruff clean.

### G11 — MCP manifest validation at registration
*Assessment Gap #11 (High). ASI04/EXT11 are out of scope for the Odysseus target, but malicious MCP
servers inject via **tool definitions** (not results), arriving as trusted registrations that bypass
L1–L7. Per CLAUDE.md this is normally out of scope (Reference.md canonical) — include only if the
deployment target adds MCP; otherwise track as accepted risk.*

- [x] **G11.1** Added `McpManifestGuard`
  ([`rails/tool/mcp_manifest.py`](../../src/sec_guardrails/rails/tool/mcp_manifest.py)): validates
  tool definitions at registration against an optional allow-list (deny-by-default) and flags
  descriptions carrying assistant-directed hidden instructions (`_POISON_MARKERS`) or instruction-
  like text (reusing the L1 heuristic — no new detector); walks parameter-schema field descriptions
  too. Registration-phase only.
- [x] **Done:** [`tests/test_mcp_manifest.py`](../../tests/test_mcp_manifest.py) — clean tool passes,
  hidden `<important>…read ~/.ssh…</important>` flagged, instruction-like description flagged, non-
  allowlisted tool flagged, poison in a param description caught, whole-manifest validation, and a
  scope guard asserting it is **not** wired into `default_engine`. 7 tests green; ruff clean.
  **Scope (CLAUDE.md):** MCP/skill supply-chain is out of the default gateway scope; this ships as an
  **opt-in, standalone** utility (not in the L1–L7 default path) — the residual runtime MCP risk
  stays accepted-by-design until a deployment explicitly adopts MCP and wires this in.

---

## Cross-cutting acceptance criteria (apply to every G-task)
- Split metrics only (ASR/interception **and** FPR/utility), never blended.
- New deterministic rails on the <30 ms hot path (G3 literal path, G5 chain) get a Rust path +
  Python fallback agreeing on `tests/vectors/`; measurement/service tasks are Python-only.
- Every task ends green: `ruff check` + `ruff format --check` + `pytest`.
- Update `docs/eval/` with measured results; check the task box; **one task per `/implement`**.
- `/ship` is the only command allowed to push to `main` or release; day's work pushes to a feature
  branch on `github.com/krishddd/SEC_Guardrails_Agent`.

## Implementation deviations (honest record)
- **Rust parity not added for G3/G5.** The cross-cutting note aspired to a Rust path + Python
  fallback for the G3 egress literal check and the G5 hash chain. Both extend rails that were already
  **Python-only** in this repo (`egress.py`, `audit.py` — not among the Rust-backed rails: secrets,
  spotlight, sanitize, policy DSL). They stay Python; no `tests/vectors/` parity applies.
- **Latency gate is a pytest test, not CI YAML** (G10.1). `.github/workflows/*` is hook-blocked and
  human-committed per CLAUDE.md, so the gate ships as `tests/test_service_hardening.py` (CI runs it).
- **Opt-in/ML arms are not exercised in CI** by design: G2 embedder, G8 Mistral, G3 live resolver,
  G4 real LLM critic, N3/G9/G10 wirings — all off in `default_engine`, tested via fakes/stubs.
- **G6 Odysseus-side `pre_tool` emission** stays on the local `feat/guardrail-trace-export` branch
  (third-party remote); only the gateway endpoint + handshake are in this repo.

## Deferred / accepted-risk register
- **G4.3 critic calibration** and **G10** may each split into multiple `/implement` units.
- **G11 (MCP)** is out of the current Odysseus scope per CLAUDE.md; carry as accepted risk unless the
  target adds MCP.
- The **paraphrase/cross-turn exfiltration class** is only *approximated* by G2's detective checks;
  its durable closure is N3 + N5 (design-by-construction), tracked in the N-series.
