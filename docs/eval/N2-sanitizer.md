# N2 — token-level tool-output sanitization: measured results

**Date:** 2026-07-05. **Scope:** heuristic backend (D1 patterns via `HeuristicDetector`,
threshold 0.6) on the fixture mini-suite in `tests/test_tool_sanitizer.py`
(`test_split_metrics_on_the_suite` recomputes these numbers in CI — a regression fails the build).
Corpus-scale numbers vs the live Security_module belong to T31.

Metrics reported **split** (per CLAUDE.md — never one blended F1):

| metric | value | suite |
|---|---|---|
| ASR (injected marker reaching model context) | **0.00** (0/4) | 3 poisoned-but-useful + 1 pure injection |
| Utility (benign facts retained) | **1.00** (6/6) | facts embedded in the poisoned samples |
| FPR (benign outputs touched at all) | **0.00** (0/3) | benign suite, byte-for-byte unchanged |

## What changed vs D4 (block-all)

Under D4 the three poisoned-but-useful samples were **blocked whole** — ASR 0 but utility 0 (all
6 benign facts lost). N2 strips only the instruction spans and re-scans the remainder, so ASR
stays 0 while utility goes 0 → 1.0 on this suite. The pure-injection sample still blocks (strips
to nothing → the D4 block path is unchanged).

## Fail-closed properties (adversarially tested)

- A sanitizer that claims success but returns poisoned text: the **re-scan blocks** — the chain,
  never the sanitizer, is the authority (`test_broken_sanitizer_cannot_bypass_the_rescan`).
- A sanitizer returning empty text is not a success (`test_sanitizer_returning_empty_text_blocks`).
- Secrets/PII redaction still applies on the sanitize path (hard rails keep their block/redact
  precedence).

## Caveats

- Heuristic segment scoring inherits D1's pattern coverage; an instruction split across segments
  that only trips on whole-text normalization falls back to **block** (safe, utility loss only).
- The ML backend (`load_ml_sanitizer`, deberta-v3 per segment) is wired but unmeasured here —
  measure in T7/T31 on a host with the `ml` extra.
