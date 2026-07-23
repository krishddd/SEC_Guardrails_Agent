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

## P8–P13 — pipeline gaps found 2026-07-23

Second-pass audit of the CI/CD pipeline. P8 is a **fail-open security bug**; the rest close
supply-chain and hygiene gaps in a repo whose whole framing is supply-chain-conscious defense.

- [x] **P8 — weekly CVE scan scans nothing (BUG, highest value)** (`claude-audit.yml`): the
  `pip-audit` step installs only `pip-audit`, never the project, so it audits an empty environment
  and reports ~0 vulns forever — the P3 "open an issue on findings" logic silently never fires for
  dependency CVEs. Fix: `pip install -e ".[dev]"` (plus any extras worth scanning) before
  `pip-audit`, so the real dependency tree is scanned. The pipeline currently **fails open**.
- [x] **P9 — commit lockfiles + `npm ci`**: no `web/package-lock.json` and no crate `Cargo.lock`
  are committed, and CI runs `npm install` (fresh resolve every run — a poisoned patch release
  walks in). Commit `web/package-lock.json` and `crates/guardrails-core/Cargo.lock`; switch the
  web lane (`ci.yml`) from `npm install` to `npm ci`.
- [x] **P10 — web eslint lane**: CLAUDE.md's per-language gate is `tsc --noEmit` + `eslint` +
  `vitest`, but eslint is absent from `web/package.json` and CI runs only typecheck + tests. Add
  eslint (+ prettier) to `web/` and wire `npm run lint` into the web lane so the convention is real.
- [x] **P11 — polyglot audit coverage** (`claude-audit.yml`): the weekly audit is Python-only. Add
  `cargo audit` (Rust core) and `npm audit` (web) as report-only steps feeding the same findings
  issue, so the audit matches the polyglot stack.
- [x] **P12 — pin Claude Code in the audit + workflow hardening**: the audit installs
  `@anthropic-ai/claude-code` unpinned in a repo that SHA-pins every third-party action — pin a
  version. Add `timeout-minutes` to every job (~15 min lanes, ~30 min audit) so a wedged build or a
  hung LLM call can't burn the 6-hour default. Add a `concurrency` group with
  `cancel-in-progress: true` to `claude-review.yml` (it triggers on `synchronize`; three quick
  pushes queue three billed reviews of superseded diffs — `ci.yml` already has the pattern).
- [x] **P13 — workflow-lint lane** (`ci.yml`): added a `workflow-lint` job running pinned
  `actionlint` v1.7.7 + shellcheck (preinstalled on the runner) over `.github/`, wired into the
  `ci-ok` aggregate. Verified locally (actionlint+shellcheck exit 0 on all three workflows). CodeQL
  default setup stays a **repo-settings toggle** (Security → Code scanning), flagged to the user —
  it is not a committable file.

**CLAUDE.md drift (user action):** CLAUDE.md says the Rust crate holds the L4 policy-DSL evaluator
and taint primitives, but the crate implements only secrets/spotlight/sanitize (which is why the CI
parity step covers exactly those three). The claim is aspirational; the `pre-edit-guard` hook blocks
the agent from editing CLAUDE.md, so this correction is the user's to make.

**Applied 2026-07-23** on branch `feat/pipeline-p8-p13`: P8–P12 landed (workflow edits went
through — the `pre-edit-guard` hook did not block them this session). Verified locally: web lane
green (`tsc --noEmit` + `eslint` + `prettier --check` + `vitest`, 4 tests), Python `pytest -q` 277
passed, all three workflow YAMLs parse, `web/package-lock.json` + `crates/guardrails-core/Cargo.lock`
committed (the former un-ignored in `.gitignore`). `cargo audit`/`npm audit` flags and jq paths
verified against upstream schemas. P13 left open (optional).

## Acceptance
- All workflows still green on the PR (`ci-ok` aggregate).
- Python gates green locally: `ruff check` + `ruff format --check` + `pytest -q`.
- Split metrics visible in the Actions job summary of the PR run.

## Non-goals
- React 19 upgrade itself (Dependabot's grouped PR + CI decide; web code fixes are a separate task
  if tsc fails).
- The eval-vs-live-Odysseus lane (T31) — cannot run on a GitHub runner; Odysseus is local-only.
- Branch protection rules (repo-settings change, not a file in the repo — flagged to the user).
