<!-- Keep PRs scoped to one task/concern. Daily work goes on a feature branch; only /ship touches main. -->

## What & why
<!-- One or two sentences. Link the plan task id (e.g. T4) and any ADR. -->

Plan task(s):
Related ADR(s):

## Changes
-

## Testing
<!-- Commands run + results. Security metrics must be split (ASR vs FPR/utility), never one F1. -->
- [ ] `ruff check .` and `ruff format --check .` clean
- [ ] `pytest -q` green
- [ ] (if Rust touched) `cargo fmt --check && cargo clippy -D warnings && cargo test`
- [ ] (if web touched) `tsc --noEmit && eslint . && vitest run`

## Guardrail checklist
- [ ] No rail can fail **open**; deny-by-default preserved
- [ ] No secrets committed (`.env` stays ignored)
- [ ] Untrusted data does not reach a tool/sink without a taint check
- [ ] Scope respected: no skill/MCP supply-chain defense (out of scope); offensive module not modified
