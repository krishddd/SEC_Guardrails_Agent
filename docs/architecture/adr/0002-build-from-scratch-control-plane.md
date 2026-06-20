# ADR-0002: Build the control plane from scratch (not adopt NeMo Guardrails)

## Context
Build-from-scratch was a stated project requirement. The alternative is adopting NVIDIA NeMo Guardrails
(Colang flows, 5 rail types, event-driven runtime). We need fine-grained taint tracking, a dual-LLM/IFC
layer, and Task-Shield-style off-task checks that don't map cleanly onto Colang.

## Decision
We own the **control plane** — rail orchestration (`Rail`/`RailChain`/`RailContext`), IFC/dual-LLM,
spotlighting, Task-Shield, the policy engine. We do **not** retrain foundation classifiers; commodity
detectors (deberta-v3, Presidio, Mistral Moderation, ShieldGemma) are swappable components behind the
`Rail` interface. "From scratch" = the orchestration + enforcement logic, not the ML models.

## Consequences
- (+) Full control over trust labels, taint propagation, and the trusted-action invariant.
- (+) No second runtime/DSL to fight; pure Python/FastAPI per CLAUDE.md.
- (−) More code to write and test than wiring NeMo.
- (−) We reimplement some things NeMo gives free (dialog flows) — acceptable for control.
