# sec-guardrails

Defensive, build-from-scratch **7-layer runtime guardrails** for the **Odysseus** autonomous agent.
A non-invasive reverse-proxy **guardrail gateway** runs in front of Odysseus, enforces a chain of
rails on every turn, and emits an OpenTelemetry trace + an append-only audit record for each rail
decision.

> **Defensive only.** This project defends an agent; it does not attack one. The offensive red-team and
> the scorer are separate, existing projects — reused, never rebuilt.

## The 7 layers

| Layer | Concern |
|------:|---------|
| L1 | Input rails — prompt-injection / jailbreak detection, PII, secrets |
| L2 | Dialog rails — turn-level policy, canary / spotlighting |
| L3 | Output rails — exfiltration side-channel stripping, sanitization |
| L4 | Tool rails — policy-DSL over tool calls (allow/deny, taint) |
| L5 | Memory rails — poisoning defense on stored context |
| L6 | Multi-agent rails — cross-agent trust boundaries |
| L7 | Oversight — opt-in LLM critic on the final action |

## Install

```bash
pip install sec-guardrails
```

See [Install & harness](install.md) to wire it into your pipeline, [CLI](cli.md) for the console
entry point, and [Python API](api.md) for the stable programmatic surface.

## Metrics

Security metrics are always reported **split** — attack success rate (ASR) and false-positive
rate / utility separately, never a single blended F1.
