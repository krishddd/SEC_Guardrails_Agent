---
name: guardrails-research
description: >-
  Research the current state of the art in LLM/agent runtime guardrails (vendor products + arXiv),
  adversarially verify the findings, and turn them into a grounded development plan for this repo's
  7-layer gateway. Use when the user wants to refresh the defense roadmap, evaluate a new guardrail
  technique/paper/product, or plan the next generation of rails. Produces a cited research digest in
  docs/research/, a split-metric technique→layer mapping, and an ordered checkable plan in
  docs/plans/ — never code (planning only; implementation goes through /implement).
---

# guardrails-research

Turn "what's the most advanced guardrail tech and what should we build next?" into three
version-controlled artifacts, grounded in *this* codebase. Defensive only.

## When to use
- Refreshing the defense roadmap with new industry/academic methods.
- Evaluating a specific paper, product, or technique for adoption (e.g. "should we add CaMeL-style
  capabilities?").
- Producing a *plan before developing* — the user wants tasks to point `/implement` at.

## Inputs
- A research question (default: SOTA runtime guardrails for agents — prompt injection incl. indirect/
  XPIA, tool/action misuse, memory/RAG poisoning, data exfiltration; vendors IBM/Google/Microsoft/
  Meta/NVIDIA/OpenAI/Anthropic + recent arXiv).
- The current repo state (rails under `src/rails/`, plans under `docs/plans/`).

## Procedure

1. **Survey the codebase first.** List `src/rails/**`, read `docs/plans/*.md` and the latest
   `docs/eval/*`. Build a map of *what already exists* (e.g. spotlight, taint, quarantine, grounding,
   critic) so the plan is **additive, not a rebuild**. This step is mandatory — it's what makes the
   output grounded rather than generic.

2. **Run deep research.** Invoke the `deep-research` workflow (fan-out web/arXiv search → fetch →
   adversarial 3-vote verify → synthesize). Pass a question scoped to *defensive, production-grade,
   runtime* methods, naming the vendors/labs and the four attack classes.
   - **Rate-limit guard:** if the verify phase fails (agents abstain `0-0` on a session limit), do
     **not** report "all claims refuted" — that's a failure-scored-as-result artifact. Mark claims
     `[unverified-by-panel]`, corroborate against the cited primary sources + known facts, and add an
     **N0 verification-debt task** to re-run the panel after the limit resets.

3. **Write the research digest** → `docs/research/<topic>-<year>.md`:
   - A provenance/confidence header (which phases ran, verification status).
   - Per technique: source (arXiv ID / official URL), what it defends, how it works, **split**
     measured metrics (ASR/interception vs FPR/utility — never blended), deployment maturity, and
     **adoptability into this gateway** (which existing rail it upgrades, effort S/M/L).
   - A synthesis table mapping techniques → the 7 layers → current state → gap → task id.

4. **Write the plan** → `docs/plans/<topic>.md`:
   - Ordered by value × tractability. Each task is **one `/implement` unit**, ends with passing
     tests + a checked box, names the exact file(s) it touches, and states which attack it defends.
   - Cross-cutting acceptance criteria: split metrics; Rust+Python parity on `tests/vectors/` for
     deterministic hot-path rails; `ruff` + `pytest` green; one task per `/implement`.
   - Reference the digest for rationale; reference predecessor plans (D-series, T-series).

5. **Stop before coding.** This skill plans; it does not implement. Hand off to `/implement` per
   `CLAUDE.md` ("never implement without a task in a docs/plans/*.md file to point at").

## Conventions (from CLAUDE.md — must hold)
- Defensive only; reuse `Agent_security_testing/Security_module` (oracle) + `Agent eval pipeline`
  (scorer), never rebuild them.
- Metrics always split — ASR and FPR/utility separately, never a single blended F1.
- Docs trail: research → `docs/research/` & `docs/specs/`, plans → `docs/plans/`.
- Conventional Commits; feature branch; PR-only (the agent cannot merge to `main`; `/ship` does).

## Output checklist
- [ ] Codebase surveyed; existing rails enumerated.
- [ ] `docs/research/<topic>-<year>.md` written, cited, verification status flagged.
- [ ] `docs/plans/<topic>.md` written, ordered, checkable, file-scoped, split-metric.
- [ ] No code changed. Handoff to `/implement` noted.
