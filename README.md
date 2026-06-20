# SEC_Guardrails_Agent

Defensive, build-from-scratch, **7-layer runtime guardrails** for the **Odysseus** autonomous agent
(Docker, local port `7000`, Mistral-backed). A non-invasive reverse-proxy **guardrail gateway** sits on
port `7100` in front of Odysseus, runs input → dialog → output rails on every turn, and emits an
OpenTelemetry trace + append-only audit record for each rail decision.

This repo is the **defensive** counterpart to two existing sibling projects (not rebuilt here):

- `Agent_security_testing/Security_module` — the **offensive** red-team (ASI01–10 + ext01–17). Reused
  as the **attack oracle** that the guardrails are evaluated against.
- `Agent eval pipeline` — the **scorer** (Odysseus quality/safety metrics).

## How it's built — research-doc-driven pipeline

Every phase reads/writes a structured markdown artifact under `docs/`, driven by Claude Code commands:

```
research/  →  docs/specs/  →  docs/architecture/ (+adr)  →  docs/plans/  →  code
/research-distill → /explore → /design → /plan → /scaffold → /implement → /test → /review → /docs-sync → /ship
```

See [`CLAUDE.md`](CLAUDE.md) for the project constitution and `docs/plans/` for the active task breakdown.

## Layout

| Path | Purpose |
|---|---|
| `research/` | Raw research / intake digests |
| `docs/specs/` | Distilled, structured specs |
| `docs/architecture/` | Exploration notes, architecture docs, ADRs |
| `docs/plans/` | Ordered, checkable task lists |
| `src/gateway/` | FastAPI reverse-proxy gateway (`:7100`) |
| `src/rails/` | Rail implementations (input / dialog / output / tool / memory / …) |
| `tests/` | Unit + adversarial fixtures (incl. Security_module payloads) |
| `.claude/` | Skills, subagents, hooks, settings |

## Status

Bootstrapping — Phase A (pipeline infrastructure). Not yet runnable.
