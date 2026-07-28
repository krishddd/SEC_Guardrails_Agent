# Changelog

All notable changes to `sec-guardrails` are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow the project's Conventional Commits.

## [0.1.0] — 2026-07-28

First public release — the defensive 7-layer runtime guardrails gateway, now installable and
harnessable from any agentic pipeline.

### Added
- Installable package `sec-guardrails` with a single clean top-level import namespace
  (`sec_guardrails`); the five internal packages (agent/core/eval/gateway/rails) live under it, so no
  generic module names leak into a consumer's environment.
- Public API: `sec_guardrails.build_default_app`, `sec_guardrails.create_gateway_app`, `__version__`.
- Console entry point: `sec-guardrails serve` / `sec-guardrails version`.
- `LICENSE` (MIT); packaging metadata (authors, urls, keywords, classifiers) and a `docs` extra.
- mkdocs-material documentation site (`docs/site/`) published to GitHub Pages.
- CI workflows for PyPI Trusted Publishing (`publish.yml`) and Pages deploy (`docs.yml`).

### Notes
- Published to PyPI via GitHub Actions Trusted Publishing (OIDC) — no stored token.
- The Rust `guardrails_core` extension ships its pure-Python fallback in this release; the
  maturin-built native wheel lands later.

[0.1.0]: https://github.com/krishddd/SEC_Guardrails_Agent/releases/tag/v0.1.0
