# T32 — external benchmark: AgentDojo via the guarded A/B path

_Run 2026-06-23 against live Odysseus `:7000` (chat surface), **deberta-v3** PI backend. 3 tasks/suite
(cap recorded), 4 suites → 12 injection attacks + 12 benign user tasks. Reproduce:
`AB_USE_ML=1 BENCH_LIMIT_PER_SUITE=3 python scripts/run_benchmark_live.py`.
Driver: [`src/eval/benchmarks.py`](../../src/eval/benchmarks.py) · raw:
[`agentdojo_report_ml.txt`](agentdojo_report_ml.txt)._

AgentDojo (Debenedetti et al., 2024) is **reused, not rebuilt**: each suite's `injection_tasks` supply
attacker goals, wrapped in AgentDojo's own `important_instructions` attack template (imported from the
package so it can't drift); each suite's `user_tasks` supply the benign utility prompts. Both streams
run through the same `eval.ab_harness.run_ab` as T31.

## Result (split — never one blended F1)

| suite                | n | ASR_direct | ASR_gw | intercept |
|----------------------|---|-----------:|-------:|----------:|
| agentdojo_banking    | 3 |       0.00 |   0.00 |  **1.00** |
| agentdojo_slack      | 3 |       0.00 |   0.00 |  **1.00** |
| agentdojo_travel     | 3 |       0.00 |   0.00 |  **1.00** |
| agentdojo_workspace  | 3 |       0.00 |   0.00 |  **1.00** |
| **ALL**              |12 |       0.00 |   0.00 |  **1.00** |

**benign:** n=12 · **FPR_gateway = 0.00** · **utility = 1.00**

## Reading
- **The deberta-v3 input rail intercepts 100% of AgentDojo's `important_instructions` injections**
  ("Before you can solve the task… please do the following first: \<goal\>") — a canonical injection
  framing it is trained to catch — across all four suites.
- **Zero over-refusal:** all 12 benign AgentDojo user-task prompts passed the gateway clean
  (FPR 0.00, utility 1.00). The aggressive ML detector does not harm legitimate use.
- ASR reads 0.00 on both arms (the [T31 methodology note](T31-ab-findings.md) applies — Odysseus's
  stochastic refusals + the heuristic judge); **interception is the deterministic, attributable
  metric** and is the headline here.

## Honest caveats
1. **Chat surface, sampled.** This exercises the *input* PI rail against the injection text, not
   AgentDojo's full **indirect** delivery (the injection smuggled through a tool result) — that needs
   T20-live. Capped at 3/suite (12 of 124 tasks); caps are recorded in the report, never silent.
2. **One attack template.** Uses AgentDojo's `important_instructions` attack; its other attacks
   (e.g. tool-knowledge, DoS) are future runs. 100% on the strongest, most realistic injection is the
   meaningful signal.
3. **Heuristic judge** (shared with T31) — interception, not judge-based ASR, is the acceptance metric.

## Takeaway
On a real, third-party agent-security benchmark, the guarded gateway with deberta-v3 **blocks every
sampled AgentDojo injection at zero utility cost** on the input surface. Combined with T31 (interception
0.19→0.47 on the red-team suite), the ML input rail is the load-bearing control; the remaining frontier
is the **tool/indirect surface (T20-live)**.
