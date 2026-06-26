# SEC_Guardrails_Agent

[![CI](https://github.com/krishddd/SEC_Guardrails_Agent/actions/workflows/ci.yml/badge.svg)](https://github.com/krishddd/SEC_Guardrails_Agent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](pyproject.toml)

Defensive, build-from-scratch **7-layer runtime guardrails** for the **Odysseus** autonomous agent
(Docker, local port `7000`, Mistral-backed). A non-invasive reverse-proxy **guardrail gateway** runs on
port `7100` in front of Odysseus, enforces a chain of rails on every turn, and emits an OpenTelemetry
trace + an append-only audit record for each rail decision.

> **Defensive only.** This repo defends an agent; it does not attack one. The offensive red-team and the
> scorer are separate, existing projects — reused here, never rebuilt (see [Ecosystem](#ecosystem)).

---

## Why

An LLM agent that plans, runs tools (bash, document creation, web/API calls), reads untrusted external
data, and holds memory has a large attack surface — prompt injection, tool misuse, memory poisoning,
data exfiltration. Guardrails are the runtime control plane that decides, at every boundary, whether
what the agent is about to **read, say, or do** is allowed. The design follows two principles
throughout: **defense-in-depth** (no single check is trusted) and **treat all external content as
untrusted** (provenance labels + taint tracking).

## Architecture

```
                    client
                      │
                      ▼
        ┌─────────────────────────────┐
        │  Guardrail Gateway  :7100    │   FastAPI reverse-proxy
        │  ── input rails  (L1, <30ms) │   secrets · PI/jailbreak · PII · spotlighting
        │  ── dialog rails (L2, <200ms)│   Task-Shield · deny-by-default topics
        │            │                 │
        │            ▼  forward (token)│
        │     Odysseus  :7000  ────────┼──▶ tool trace (export hook, ADR-0005)
        │            │   ◀─────────────┤    L4 tool · L5 memory · multi-agent rails
        │            ▼                 │
        │  ── output rails (L6, <50ms) │   schema · content · grounding · redact · sanitize
        │  ── oversight critic (L7)    │
        └─────────────────────────────┘
                      │   every decision → OTel span + append-only audit
                      ▼
                   client
```

The **7 control layers**: L1 input · L2 dialog/topic · L3 reasoning/IFC (dual-LLM + taint) · L4
tool/action · L5 retrieval/memory · multi-agent comms · L7 verification/oversight · (+ L6 output) ·
cross-cutting observability. Each layer maps to specific attacks it defends — see
[`docs/architecture/odysseus-guardrails.md`](docs/architecture/odysseus-guardrails.md).

## Polyglot stack — each language where it earns its place

| Language | Role | Why |
|---|---|---|
| **Python 3.11** | Control plane: FastAPI gateway, classifier orchestration, eval harness | Glue + ML ecosystem |
| **Rust** (PyO3/maturin → `guardrails_core`) | Deterministic security core: secrets scanner, spotlighting, URL/HTML sanitizer, **L4 policy-DSL parser+evaluator**, taint primitives | Memory safety *is* a security property at a trust boundary; meets the <30 ms budget. Pure-Python fallback included |
| **TypeScript/React** (Vite, `web/`) | HITL approval app + observability/audit dashboard | Human-facing surfaces a headless service can't provide. No security logic client-side |
| **Rego/OPA** | L4 policy v2 path | Git-versioned, CI-testable policy when the in-house DSL outgrows itself |

See [ADR-0006](docs/architecture/adr/0006-polyglot-rust-core.md) and
[ADR-0007](docs/architecture/adr/0007-typescript-frontend.md).

## Ecosystem (sibling projects — reused, not rebuilt)

- **Offensive oracle** — `Agent_security_testing/Security_module` (ASI01–10 + ext01–17). The attack
  suite the guardrails are evaluated against (A/B: direct vs. via gateway).
- **Scorer** — `Agent eval pipeline` (Odysseus quality/safety metrics, grounding judge).
- **Target** — `odysseus/` (the agent under protection).

## How it's built — research-doc-driven pipeline

Every phase reads/writes a structured markdown artifact under `docs/`, driven by Claude Code skills:

```
research/ → docs/specs/ → docs/architecture/ (+adr) → docs/plans/ → code
/research-distill → /explore → /design → /plan → /scaffold → /implement → /test → /review → /docs-sync → /ship
```

## Quickstart

```bash
# 1. Install (control plane only; Rust core + ML detectors are extras)
python -m pip install -e ".[dev]"

# 2. Run the test suite
pytest -q
ruff check . && ruff format --check .

# 3. Run the offline Odysseus stub (Odysseus itself is a separate Docker service)
uvicorn tests.stub_agent.app:app --port 7000

# (later) run the gateway in front of it
# uvicorn gateway.app:app --port 7100
```

Configuration is via environment variables (see [`.env.example`](.env.example)); `.env` is never
committed. Reuses `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` from the eval pipeline — **rotate the OpenAI key
before use**.

## Repository layout

| Path | Purpose |
|---|---|
| `research/` | Raw research / intake digests |
| `docs/specs/` | Distilled, structured specs |
| `docs/architecture/` | Exploration notes, architecture doc, ADRs |
| `docs/plans/` | Ordered, checkable task lists (`T1–T40`) |
| `src/gateway/` | FastAPI reverse-proxy gateway (`:7100`) |
| `src/rails/` | Rail implementations (input/dialog/output/tool/memory/reasoning/multiagent/oversight) |
| `src/core/` | Rail framework, config, audit, observability |
| `src/eval/` | A/B attack harness, benchmark drivers, latency/FPR reporting |
| `crates/guardrails-core/` | Rust security core (PyO3/maturin) — *lands at T6b* |
| `web/` | TypeScript/React HITL + dashboard — *Phase 9* |
| `tests/` | Unit + adversarial fixtures, offline Odysseus stub |
| `.claude/` | Skills, subagents, pre-edit guard hook, settings |

## Evaluation

Security metrics are always reported **split** — Attack Success Rate (ASR) and false-positive /
utility separately, **never a single blended F1**. The A/B harness runs the Security_module attacks
direct vs. through the gateway and checks against the thresholds in
[`docs/specs/odysseus-guardrails-spec.md`](docs/specs/odysseus-guardrails-spec.md); external benchmarks
(AgentDojo, WASP) run via Inspect Evals.

## Status & roadmap

- ✅ **Phase A** — research-doc pipeline (skills, subagents, hook, CI)
- ✅ **Phase B** — spec, exploration, architecture + ADRs 0001–0007, plan `T1–T40`
- ✅ **Scaffold** — Python package, offline stub agent, smoke tests
- 🔜 **Phase C** — foundations (config, client, rail framework, gateway, observability), then the rails

Track progress in [`docs/plans/odysseus-guardrails-plan.md`](docs/plans/odysseus-guardrails-plan.md).

## Security

Found a vulnerability? See [`SECURITY.md`](SECURITY.md). Do not open a public issue for sensitive
reports.

## License

License: **TBD** — until a license file is added, all rights reserved by the author.
