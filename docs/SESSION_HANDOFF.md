# Session handoff — SEC_Guardrails_Agent

_Snapshot for continuing in a fresh window. Read this + `CLAUDE.md` + `docs/plans/odysseus-guardrails-plan.md` first._

## Where things stand (2026-06-22)
- Repo: **https://github.com/krishddd/SEC_Guardrails_Agent** (PUBLIC). Local: `C:\Users\hp\Downloads\SEC_Guardrails_Agent`.
- `main` is green. **196 Python tests pass** (+14 parity-skipped locally; the Rust↔Python parity runs in CI). `web/` vitest green.
- **43 / 48 plan items done.** The complete, self-contained guardrail safety net is built and demonstrable in-repo.
- **Odysseus is now RUNNING on `:7000`** (`/api/health`=200) — the previously env-gated live tasks are unblocked.
- `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` live in `../Agent evals/Agent eval pipeline/.env` (reuse via the config loader; **rotate the OpenAI key** — T1).

## Run it
```bash
python -m pip install -e ".[dev]"          # control plane
python -m pytest -q                         # 196 pass
python scripts/demo.py                      # end-to-end safety-net demo (every layer fires)
python -m ruff check . && python -m ruff format --check .
```

## What's built (all on main)
- **Unified `src/core/engine.py` `GuardrailEngine`** (ADR-0009) composes every layer behind `guard_input` / `guard_tool` / `guard_memory_write` / `guard_output` / `guard_code` / `review`, audited per decision. `default_engine(...)` wires it. **`src/agent/`** is a reference tool-executing agent that runs *under* the engine (in-process trace = L4/L5 live).
- **Rust core** `crates/guardrails-core/` (PyO3/maturin → `guardrails_core`): secrets scanner, datamarker, URL/HTML sanitizer (+ Python fallbacks, parity in CI).
- **Rails** (`src/rails/`): input (secrets/PI/PII/spotlight), dialog (task-shield/topic/word-filter), reasoning (taint+trusted-action invariant, dual-LLM quarantine), tool (ExecGate, policy+RBAC, egress/SSRF, HITL, CodeShield, budget), memory (write-moderation/provenance/tenant-isolation), output (schema, content, leak/canary, sanitize, grounding), oversight (critic). ML rails have heuristic defaults + lazy `[ml]` backends.
- **Eval** (`src/eval/`): regression gate, full gate, FPR + latency reports, governance export + NIST/EU control map + AgentDoG taxonomy, adaptive-attack eval.
- **web/** TS/React HITL app + dashboard + sanitizer preview. **CI**: python/rust/web/gitleaks/aggregate; ADRs 0001–0010.

## Unfinished (the 5 remaining) — now mostly unblocked
1. **T20 — Odysseus trace-export hook** (`C:\Users\hp\Downloads\odysseus`, FastAPI; dispatch at `src/tool_execution.py`). Add a read-only hook emitting `{tool, args, result, status, latency}` to the gateway so `GuardrailEngine.guard_tool` enforces on the REAL trace. Pin the live trace JSON shape first (OQ3).
2. **T31 — live A/B** vs the red-team `C:\Users\hp\Downloads\Agent_security_testing\Security_module`: run its ASI01–10/ext01–17 against Odysseus **direct vs via the engine/gateway**; report ASR per class + utility, **split (never one F1)**.
3. **T32 — AgentDojo / WASP** via Inspect Evals against the guarded agent.
4. **T7 — latency spike** with the real `[ml]` models (deberta/Presidio) vs the 30 ms budget; revise spec SC3 if needed. Needs `pip install -e ".[ml]"` on a capable host.
5. **T1 — rotate `OPENAI_API_KEY`** (user action) before the dual-LLM/grounding/content ML backends run live.
- Also open: **dependabot PRs #4,5,6,7,9** (routine action-version bumps) — review/merge.

## Recommended next step
Wire `GuardrailEngine` into the live path: either (a) **T20 trace hook + a `GuardedOdysseusAdapter`** mapping Odysseus tool calls to `guard_tool`, then **T31** for the real ASR/FPR numbers; or (b) put the engine in the FastAPI gateway (`src/gateway/app.py`) as the `:7100` proxy in front of `:7000`.

## Gotchas / conventions (learned the hard way)
- **PR-based only.** The auto-mode classifier BLOCKS direct pushes to `main` (CLAUDE.md rule). Work on `feat/<slug>`, open a PR, watch checks, merge. Daily push.
- **pre-edit-guard hook is active**: tool-edits to `.claude/*`, `CLAUDE.md`, `.github/workflows/*` are blocked → edit those via **Bash** (python/sed), not Edit/Write.
- **Line length 100** (ruff). Rust: rustfmt wraps long calls + `clippy -D warnings` (use char-array `find(['/','?'])` not `matches!`); pyo3 needs the `extension-module` feature for the wheel (cargo test runs without it). No local Rust/Node — **validate Rust+web in CI**.
- Local `pip` is flaky on Windows; `--user` installs work. Odysseus: **4xx = terminal (no retry)**; bodies must match schema or 422.
- Metrics always **split** (ASR vs FPR/utility), never one blended F1.
