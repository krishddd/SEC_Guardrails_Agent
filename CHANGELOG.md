# Changelog

All notable changes to `sec-guardrails` are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow the project's Conventional Commits.

## [Unreleased]

## [0.2.0] — 2026-08-24

Deployment hardening (G-series) + next-gen rails N3/N5. Closes the gap between the guardrail
*library* and the deployed *gateway*. All opt-in additions default off, so existing behaviour is
unchanged; full suite **366 passed, 14 skipped**. See
[`docs/plans/deployment-hardening.md`](https://github.com/krishddd/SEC_Guardrails_Agent/blob/main/docs/plans/deployment-hardening.md).

### Added
- **G1** — the deployed `/api/v1/chat` path now enforces rails: `build_default_app` fronts the raw
  Odysseus client with `GuardedOdysseusClient`, and the route audits the real allow/block decision
  (no more hardcoded pass-through).
- **G3** — DNS-rebinding egress defense: `EgressGuard(resolve_hosts=…)` validates every resolved
  A/AAAA IP (fail-closed) and `GuardrailHttpSession` pins the validated IPs at connect time.
- **G4** — L7 critic degradation surfaced as a `critic_degraded` audit decision + OTel health event
  + operator hook; `eval/critic_calibration.py` reports the critic's FP/FN split.
- **G2** — `TaintTracker.add_memory` carries untrusted-memory taint on retrieval; opt-in embedding
  similarity catches paraphrase at sensitive sinks.
- **G6** — `POST /api/_pretrace`: a preventive tool verdict the hook honors before execution (fails
  closed with no engine wired).
- **G5** — tamper-evident, hash-chained audit log with optional HMAC, and `sec-guardrails audit
  verify`.
- **N3** — CaMeL data-flow sink policy (`DataFlowPolicy`, `ToolCall.arg_sources`).
- **N5** — plan-then-execute split + opt-in context-minimization in the reference agent.
- **G8** — multilingual injection routing (`detect_language`, `MultilingualInjectionDetector`).
- **G9** — session-level threat accumulation (`SessionThreatTracker`).
- **G10** — per-rail latency gate (`eval/latency.py`), policy hot-reload (`ReloadablePolicyEngine`),
  and SIEM forwarding (`AuditLog(siem_sink=…)`).
- **G11** — opt-in MCP manifest validation (`McpManifestGuard`); standalone, deliberately not wired
  into the default engine (MCP is out of the default gateway scope).

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

[Unreleased]: https://github.com/krishddd/SEC_Guardrails_Agent/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/krishddd/SEC_Guardrails_Agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/krishddd/SEC_Guardrails_Agent/releases/tag/v0.1.0
