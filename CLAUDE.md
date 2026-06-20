# Project: SEC_Guardrails_Agent

Defensive, build-from-scratch 7-layer runtime guardrails for the **Odysseus** agent. A reverse-proxy
**guardrail gateway** on `:7100` fronts Odysseus on `:7000`, enforcing rails on every turn.

## Stack
- **Language:** Python 3.11
- **Web/gateway:** FastAPI + Uvicorn
- **HTTP client:** httpx
- **Validation:** Pydantic v2
- **Tests:** pytest
- **Lint/format:** ruff (lint + format)
- **Tracing:** OpenTelemetry (GenAI semconv)
- **Package manager:** pip + `pyproject.toml` (editable install: `pip install -e .`)
- **Deploy target:** local guardrail gateway process on `:7100` in front of Odysseus Docker `:7000`.
  `/ship` is the only command allowed to tag/release.

## Conventions
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`).
- **Branches:** `feat/<slug>`, `fix/<slug>`; default branch is `main`.
- **Docs trail:** specs → `docs/specs/`, exploration + architecture + ADRs → `docs/architecture/`
  (ADRs in `docs/architecture/adr/<NNNN>-<slug>.md`), task plans → `docs/plans/`.
- **Source:** gateway in `src/gateway/`, rails in `src/rails/`, tests in `tests/`.

## Workflow rules
- **Never implement without a task** in a `docs/plans/*.md` file to point at.
- Every `/implement` run must end with **passing tests** and a **checked-off** task box.
- `/implement` does **one** task, then stops — it must not cascade into the next task.
- `/ship` is the **only** command allowed to push to `main` or trigger a release/deploy, and only on
  an explicit go-ahead in the conversation.
- **Daily push:** at the end of each working session, push the day's work to
  `https://github.com/krishddd/SEC_Guardrails_Agent` (feature branch; never force-push `main`).
- `.env` is **never** committed (enforced by `.gitignore`); the `pre-edit-guard` hook blocks automated
  edits to `.claude/*`, `CLAUDE.md`, and `.github/workflows/*`.
- Security metrics are always reported **split** — ASR and FPR/utility separately, **never a single
  blended F1**.

## Scope boundaries
- **Defensive only.** The offensive red-team lives in `Agent_security_testing/Security_module` and is
  **reused as the attack oracle, never rebuilt here**.
- **Out of scope:** skill/MCP supply-chain guardrails (Reference.md is canonical). Offensive tests
  ASI04 / ext11 remain in the red-team but are not defended by this gateway.
- The `Agent eval pipeline` is the **scorer** and is reused, not rebuilt.

## Known gotchas (grows over time)
- **Odysseus `4xx` = terminal — do NOT retry.** Only retry `5xx`/network. (A 4xx means bad endpoint or
  bad body; retrying just spams the server. See `Agent eval pipeline/adapters/odysseus_adapter.py`.)
- **Odysseus exposes no per-step tool trace to an API token.** `/api/v1/chat` runs *no* tools and
  returns `{response, session_id, model}`; real tool execution is a server-side async task lifecycle.
  → L4/L5/multi-agent rails are **wiring-gated** (tested vs synthetic fixtures) until/unless the
  container is changed to expose its trace.
- **Odysseus request bodies must match the schema exactly** or every call dies at `422`.
- **Rotate the reused `OPENAI_API_KEY`** (it was previously shared in plaintext) before wiring it
  anywhere reachable. Reuse `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` from the eval pipeline `.env` via the
  config loader — never hardcode.
- Model IDs (`mistral-moderation-2603`, `deberta-v3-base-prompt-injection-v2`, ShieldGemma 2) drift —
  re-verify availability before an ADR locks a version.
