# D1 — heuristic PI recall upgrade (deterministic, inline, zero latency)

_Closes the role-reassignment / extraction / injection-framing blind spots T31 exposed, in the
**cheap inline** detector — no model, no latency, measured FPR 0. See
[`docs/plans/defense-improvements.md`](../plans/defense-improvements.md) for the roadmap._

## What changed
`rails/input/prompt_injection.py` `HeuristicDetector`:
- **persona-trigger × bypass-marker combo** — `you are now / act as / pretend to be / roleplay as /
  from now on you / your new role` co-occurring with `full access / unrestricted / uncensored /
  no rules|safety / without (validation|sanitization|safety) / admin|root / bypass / do anything /
  DAN`. A persona shift *demanding a bypass* is high-confidence role-reassignment; a benign roleplay
  (no bypass marker) does **not** trip it.
- **ignore/disregard … rules|safety|guidelines|policies** (not just "instructions") — catches the
  indirect-feedback framing.
- **important-instructions framing** — `before you can solve/continue …`, `this is an important
  message/instruction/update`.
- **flexible extraction** verb→target gap (`output your complete configuration`, `reveal the
  instructions`, `what is your system prompt`, `… verbatim`) + more forged-tag variants
  (`[system]`, `<|system|>`).

## Recall (block-rate) on `Security_module`, heuristic detector only — before → after

| class               | before | after | Δ |
|---------------------|-------:|------:|---|
| direct_override     |   0.67 |  1.00 | +0.33 |
| role_reassignment   |   0.00 |  1.00 | **+1.00** |
| extraction          |   0.33 |  1.00 | +0.67 |
| indirect            |   0.00 |  0.50 | +0.50 |
| jailbreak           |   0.33 |  0.33 | 0 (social-engineering — D2/deberta's job) |

**FPR = 0.00** on the benign corpus (incl. persona-shaped benign roleplay like "act as a translator").

## Why it matters
The cheap deterministic path now **matches or beats deberta-v3 on the hard classes** (role_reassignment
1.00 vs deberta 0.33) at **0 ms and 0 FPR** — so most of the T31 interception gap is closed without the
323 ms ML cost (T7/SC3). It also makes the planned conditional second-stage (D2) cheaper: deberta need
only run on what the heuristic leaves uncertain (jailbreak/novel indirect).

## Limits / next
- `jailbreak` social-engineering ("my grandmother used to read me…") and novel indirect attacks remain
  for **D2** (conditional deberta/PromptGuard) and **D4** (scan tool outputs through this rail).
- Recall here is the **input PI rail in isolation**; full-engine interception also benefits from the
  other rails. Re-run the live A/B (`scripts/run_ab_live.py`) after merge to confirm end-to-end.
