# Plan — CI/CD pipeline + repo hygiene improvements (P-series)

**Status:** in progress (2026-07-05). **Scope:** the GitHub pipeline (`.github/`) and repo
housekeeping — no rail/engine code. The runtime roadmap stays in
[`next-gen-guardrails.md`](next-gen-guardrails.md) (N2 next).

Rationale: the pipeline already *blocks* regressions (T37 gate runs in pytest with committed
ASR/FPR caps) but several outputs are invisible or wasteful — the weekly audit writes an artifact
nobody opens, Claude reviews Dependabot version bumps, the react 18→19 bumps arrive as three
mutually-conflicting PRs, and third-party actions are tag-pinned in a repo whose whole point is
supply-chain-conscious defense.

## Tasks

- [x] **P1 — Dependabot grouping** (`.github/dependabot.yml`): group `react`/`react-dom`/
  `@types/react*` into one npm PR (root cause of the ERESOLVE failures on PRs #50–52); group all
  GitHub-Actions bumps into a single weekly PR.
- [x] **P2 — Skip Claude review on Dependabot PRs** (`claude-review.yml`): version bumps get CI +
  human eyes; spending review tokens on lockfile diffs is waste. Job-level actor guard.
- [x] **P3 — Weekly audit opens/updates a GitHub issue** (`claude-audit.yml`): when pip-audit or
  the Claude sweep reports findings, create or update a `Weekly security audit` issue with the
  summary (needs `issues: write`). Artifact stays for the raw JSON. A report-only pipeline whose
  output is an unread artifact fails silently.
- [x] **P4 — Split-metric gate summary in CI** (`ci.yml` + `scripts/gate_summary.py`): print the
  T37 input/output gate **ASR and FPR (split, never blended)** plus the committed caps into
  `$GITHUB_STEP_SUMMARY` on every run, so every PR shows its guardrail delta without digging.
- [x] **P5 — CI hardening**: pin third-party actions by commit SHA (`gitleaks-action`,
  `rust-cache`, `rust-toolchain`, `claude-code-action`); `persist-credentials: false` on all
  checkouts (nothing pushes from CI).
- [ ] **P6 — Dependabot PR triage**: merged the green bumps (#4 gitleaks v3, #6 setup-node 6,
  #7 setup-python 6, #9 upload-artifact 7, #53 vitest 4; #54 typescript 6 pending Dependabot
  rebase). **User action:** close the conflicting react trio (#50/51/52) — the permission
  classifier blocks the agent from closing PRs it didn't open; the P1 group regenerates them as
  one PR on the next weekly run.
- [ ] **P7 — Branch hygiene**: pruned `feat/n1-arg-schema-rail` (local + remote). **User
  action:** deleting other merged remote branches (`docs/session-handoff-2026-06-28`,
  `fix/polish-bugs`, `feat/tool-output-scan`) is classifier-blocked; delete from the GitHub
  branches page or allow the rule.

## Acceptance
- All workflows still green on the PR (`ci-ok` aggregate).
- Python gates green locally: `ruff check` + `ruff format --check` + `pytest -q`.
- Split metrics visible in the Actions job summary of the PR run.

## Non-goals
- React 19 upgrade itself (Dependabot's grouped PR + CI decide; web code fixes are a separate task
  if tsc fails).
- The eval-vs-live-Odysseus lane (T31) — cannot run on a GitHub runner; Odysseus is local-only.
- Branch protection rules (repo-settings change, not a file in the repo — flagged to the user).
