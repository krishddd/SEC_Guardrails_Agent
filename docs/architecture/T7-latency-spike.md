# T7 — latency spike (warmed p50/p95)

_Run 2026-06-23 on the dev host (**CPU-only**, no CUDA; torch present, `[ml]` extra installed).
Reproduce: `python scripts/latency_spike.py`. Each detector is warmed before timing; p50/p95 over
250 inferences across 5 representative inputs._

SC3 input-layer budget is **< 30 ms** warmed p50.

| component       | p50 (ms) | p95 (ms) | status        |
|-----------------|---------:|---------:|---------------|
| secrets (Rust)  |     0.01 |     0.02 | OK            |
| presidio-pii    |    14.24 |    17.82 | OK            |
| **deberta-v3**  | **323.5**| **398.7**| **OVER (11×)**|
| CHAIN (all)     |    337.6 |    439.4 | OVER          |

## Reading
- **The deterministic rails and Presidio fit the budget.** Secrets scrub is ~free (Rust); Presidio
  NER PII redaction lands at **14 ms p50** — comfortably under 30 ms, and it catches semantic PII the
  heuristic misses (e.g. `PERSON` "Bob"). No SC3 problem here.
- **The deberta-v3 prompt-injection classifier is the one breach: 323 ms p50 on CPU — 11× over.**
  CHAIN p50 (338 ms) is just deberta plus the cheap rails. This is inherent to a 184M-param
  transformer on CPU, not a code defect.

## SC3 revision (the spike's mandate)
SC3 says the budget "is revised in this spec during the latency spike, before it is load-bearing."
The deterministic input budget holds; the ML PI classifier needs its **own** budget and placement:

1. **Split the budget.** Keep **input deterministic rails < 30 ms p50** (met: secrets + heuristic PI +
   Presidio ≈ 15 ms). Give the **ML PI classifier a separate budget**: **< 30 ms p50 on GPU**, or
   **≤ 350 ms p50 on CPU** as a documented degraded mode.
2. **Don't run deberta inline on every turn at CPU latency.** Options, cheapest first:
   - **GPU host** — deberta-v3 runs ~5–15 ms on GPU; the right home for the live gateway.
   - **Second-stage / conditional** — run the cheap heuristic inline; invoke deberta only on inputs the
     heuristic scores in a gray band, so the 323 ms is paid on a fraction of turns.
   - **Distill/quantize** — an ONNX-int8 or smaller PI model to claw back most of the latency on CPU.
3. **Until a GPU host exists**, the gateway should default to the heuristic detector inline (the
   `default_engine` default) and treat deberta as an opt-in (`build_live_arms(use_ml=True)`) for the
   A/B and for GPU deployments.

## Cross-link
The ML detector's **ASR lift** (what the 323 ms buys) is measured in the T31 A/B re-run —
see [`../eval/T31-ab-findings.md`](../eval/T31-ab-findings.md) (heuristic vs deberta).
