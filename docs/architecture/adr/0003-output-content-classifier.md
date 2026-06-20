# ADR-0003: Output content classifier — Mistral Moderation primary, ShieldGemma 2 fallback

## Context
The output rail needs a content-safety classifier. Odysseus is Mistral-backed, so a native Mistral
option minimizes new infra. Self-hosted options (Llama Guard 4, ShieldGemma 2) avoid a per-call API
dependency but need GPU/CPU headroom. Model IDs drift — verified 2026-06-20.

## Decision
Use **Mistral Moderation `mistral-moderation-2603`** as primary (multilingual, adds jailbreak detection,
native to the stack; `-2411` deprecated 2026-03-31). Use self-hosted **ShieldGemma 2** as an offline
fallback when the API is unavailable or for air-gapped runs. The active method is recorded per decision
(`_method`) for audit.

## Consequences
- (+) Cheap, low-infra primary path aligned with the agent's own provider.
- (+) Offline resilience via ShieldGemma 2; both behind the same `Rail` interface.
- (−) Primary path adds an external API dependency + latency (within the <50ms output budget? verify in
  the latency spike; fall back to local if not).
- (−) Two classifiers to keep calibrated; track FPR for each.
