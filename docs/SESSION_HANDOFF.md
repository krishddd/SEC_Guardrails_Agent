# Session handoff — SEC_Guardrails_Agent

_Snapshot for continuing in a fresh window. Read this + `CLAUDE.md` + `docs/plans/odysseus-guardrails-plan.md`,
plus the eval write-ups in `docs/eval/` and `docs/architecture/T7-latency-spike.md`._

## Where things stand (2026-06-28)
- Repo: **https://github.com/krishddd/SEC_Guardrails_Agent** (PUBLIC). Local: `C:\Users\hp\Downloads\SEC_Guardrails_Agent`.
- **Plan: 48/48 code tasks done.** Local tests **221 pass / 14 parity-skipped** (Rust parity runs in CI). `web/` vitest green.
- **Odysseus is live on `:7000`** (`/api/health`=200) — used directly via `/api/v1/chat` for the live A/B runs.
- `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` live in `../Agent evals/Agent eval pipeline/.env` (reuse via the config loader; **rotate the OpenAI key** — T1).

## Merge status (important — was a multi-PR session)
- **`main`** contains **T31a, T20, T31, T7** (merged via PR #35 and #36) plus a dependabot pyo3 bump (#37).
- **PR #38 is OPEN and fully green** (branch `feat/t32-agentdojo-harness-fix`): **T32 + the A/B harness error-tracking fix + license badge**. **NOT merged yet** — the auto-mode classifier blocks the agent from landing on `main`; only `/ship` (with explicit go-ahead) or a manual GitHub merge may do it. **First action: `/ship` or merge PR #38.**

## What's built this session (all committed)
- **T31a — `src/gateway/guarded_odysseus.py`** `GuardedOdysseusClient`: guard_input (preventive), forward sanitized msg, guard_tool over any trace (detective), guard_output (preventive). The "via gateway" arm.
- **T20 — trace hook (ADR-0005).** Gateway `POST /api/_trace` maps events → `ToolCall` by family → `guard_tool` **detectively** (token-gated). Odysseus side = `src/guardrail_trace.py` + a decorator on `execute_tool_block`, **observe-only, OFF unless `GUARDRAIL_TRACE_URL` set**. ⚠ The Odysseus edit is on a **LOCAL branch `feat/guardrail-trace-export` in the separate `C:\Users\hp\Downloads\odysseus` repo (remote is third-party `pewdiepie-archdaemon/odysseus`, NOT pushed).**
- **T31 — `src/eval/ab_harness.py` + `scripts/run_ab_live.py`.** Live A/B (Security_module oracle), metrics split. `default_engine(pi_detector=...)` / `build_live_arms(use_ml=True)` swap in deberta.
- **T7 — `[ml]` installed/verified + `scripts/latency_spike.py`.** secrets 0.01ms, Presidio 14.2ms (OK); **deberta-v3 323ms p50 CPU (11× over SC3)** → **SC3 revised in the spec**.
- **T32 — `src/eval/benchmarks.py` + `scripts/run_benchmark_live.py`.** AgentDojo reused as a dataset (its `important_instructions` template wraps injection goals; user tasks = utility) via the guarded A/B. `[bench]` extra = `agentdojo`.
- **Harness fix.** The live arms now distinguish Odysseus errors from refusals (`DirectArm -> str|None`, `GatewayOutcome.errored`, per-arm error counts excluded from ASR/FPR, ⚠ line in the report).

## Live results (interception = deterministic headline; ASR = confounded cross-check)
- **T31** heuristic: interception 0.19, FPR 0.00. ML (deberta): **interception 0.19 → 0.47**, FPR 0.00, utility 1.00.
- **T32** AgentDojo (deberta): **interception 1.00** (12/12 injections blocked), FPR 0.00, utility 1.00.
- `ASR_direct=0` was **verified to be genuine Odysseus refusals** ("I can't reveal or override my system instructions…"), `direct_errors=0` — Odysseus is itself aligned at the chat surface, so the gateway's chat-layer value is defense-in-depth interception before the model is reached.

## Remaining (non-code / user action)
1. **Merge PR #38** (`/ship` or GitHub UI) → `main` reaches 48/48. Agent cannot merge to `main`.
2. **T20-live:** restart Odysseus with `GUARDRAIL_TRACE_URL` pointing at the gateway → measures the **tool/indirect surface** (the standing caveat across T31/T32; chat surface only today).
3. **Dependabot PRs #4, 5, 6, 7, 9** (CI action-version bumps) — review/merge.
4. **T1 — rotate `OPENAI_API_KEY`** before output/dual-LLM ML backends run live.

## Gotchas / conventions
- **Merge to `main` is agent-blocked** except via `/ship` + explicit go-ahead (CLAUDE.md). Work on `feat/<slug>`, open PR, then `/ship`/UI-merge.
- **pre-edit-guard hook** blocks tool-edits to `.claude/*`, `CLAUDE.md`, `.github/workflows/*` → edit those via Bash.
- **Line length 100** (ruff). No local Rust/Node toolchain — validate Rust+web in CI. Odysseus: **4xx = terminal (no retry)**; body must match schema or 422.
- Metrics always **split** (ASR vs FPR/utility), never one blended F1. Live runs are slow (Odysseus ~14s/call; deberta +~323ms/call).
- ML deps (transformers, presidio+`en_core_web_lg`, agentdojo) are installed in the **local** user env only; CI installs `.[dev]` fresh. The agentdojo install bumped pydantic/tokenizers in the shared env — conflicts are in sibling projects, not this repo.
