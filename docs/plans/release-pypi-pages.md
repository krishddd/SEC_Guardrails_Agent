# Plan: Release `sec-guardrails` to PyPI + docs on GitHub Pages

Goal: publish the guardrail gateway as an installable, harnessable tool (`pip install sec-guardrails`),
with GitHub **Releases** (tag-driven), a **pypi** Deployment via Trusted Publishing (OIDC), and a
**github-pages** Deployment hosting a docs site — mirroring the setup on
`krishddd/Trajectory_Causal_Attribution`.

Decisions (from the requesting session): license **MIT**; Pages hosts a **docs site**; add a **CLI +
public API** so any agentic pipeline can harness the tool.

## Constraints honored
- `/ship` is the only command allowed to tag/release — this plan sets everything up *to* the tag; it
  does **not** cut the tag or create the GitHub Release.
- The `pre-edit-guard` hook blocks automated edits to `.github/workflows/*`. The two new workflows
  (`publish.yml`, `docs.yml`) are authored as reviewable YAML and committed by a human.
- Metrics unaffected (no rail logic changes). Defensive-only scope unchanged.

## Tasks

- [x] **T1 — LICENSE.** Add MIT `LICENSE` (already advertised by the README badge). Author: repo owner.
- [x] **T2 — Public package `sec_guardrails`.** Add `src/sec_guardrails/` exposing a stable API
      (`__version__`, `create_gateway_app`, `build_default_app`) that wraps the existing
      `gateway`/`core` modules without refactoring internals.
- [x] **T3 — CLI entry point.** `src/sec_guardrails/cli.py` with `sec-guardrails serve` (runs the
      gateway) and `sec-guardrails version`; register via `[project.scripts]`.
- [x] **T4 — Packaging metadata.** `pyproject.toml`: bump to `0.1.0`, add `license`, `authors`,
      `readme`, `keywords`, `classifiers`, `[project.urls]`, and `[project.scripts]`. Restrict
      `packages.find` include-list so the wheel ships only the intended top-level packages.
- [x] **T5 — README harness section + badges.** `pip install` block, a "harness in your pipeline"
      snippet, PyPI + Pages badges.
- [x] **T6 — Docs site.** `mkdocs.yml` + `docs/site/` (or reuse existing docs) building to static HTML
      for the github-pages Deployment.
- [x] **T7 — `publish.yml` (HUMAN-COMMITTED).** Tag-triggered build (sdist+wheel) → publish to PyPI via
      Trusted Publishing under the `pypi` environment. Provided as YAML for the owner to commit.
- [x] **T8 — `docs.yml` (HUMAN-COMMITTED).** Build mkdocs → deploy to the `github-pages` environment.
      Provided as YAML for the owner to commit.

## PyPI Trusted Publisher form values
| Field | Value |
|---|---|
| PyPI Project Name | `sec-guardrails` |
| Owner | `krishddd` |
| Repository name | `SEC_Guardrails_Agent` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

## Follow-up (not in this plan)
- ~~Rename generic internal packages under `sec_guardrails.*`~~ — **DONE.** All five packages
  (`core`, `gateway`, `rails`, `eval`, `agent`) moved to `src/sec_guardrails/`, ~214 imports rewritten,
  wheel now ships only `sec_guardrails`. 277 tests green.
- maturin backend switch (T6b) so wheels bundle the Rust `guardrails_core` extension; until then the
  pure-Python fallback ships and the wheel is pure-Python.
