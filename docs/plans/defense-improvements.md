# Defense improvement plan — lower ASR (catch more attacks)

_Goal (user-set): raise interception/recall on the hard classes — **role-reassignment, indirect
injection, XPIA, tool-misuse** — without inflating over-refusal (FPR). Grounded in our own T31/T32
empirical data + established SOTA (the codebase already implements CaMeL/FIDES taint, dual-LLM
quarantine, spotlighting, deny-by-default policy, HITL). A web-research pass was attempted but
rate-limited; re-run for fresh citations is optional — the techniques below are well-established._

## Where the gaps are (from T31, deterministic interception)
| class | heuristic | deberta | gap owner |
|---|---:|---:|---|
| role_reassignment | 0.00 | 0.33 | **detector recall** |
| indirect | 0.00 | 0.50 | **detector recall + tool-output scanning** |
| xpia_document/api | 0.00–0.25 | 0.50 | **tool-output scanning (T20-live)** |
| jailbreak | 0.33 | 0.33 | detector recall |
| sqli (chat) | 0.00 | 0.00 | tool-layer prevention (not an input PI) |

## Prioritized roadmap (cheapest, highest-recall first)

### D1 — Heuristic PI recall upgrade *(THIS PR — deterministic, inline, zero latency)*
Expand `rails/input/prompt_injection.py` so the **cheap inline path** catches role-reassignment and
injection-framing the current patterns miss:
- **persona-trigger × bypass-marker** combination (low-FPR): `you are now / act as / pretend to be /
  roleplay as / from now on` co-occurring with `full access / unrestricted / uncensored / no
  rules|safety|restrictions / without (validation|sanitization|safety) / admin|root / bypass / do
  anything / DAN`.
- standalone: `ignore/disregard … (rules|safety|guidelines|policies)` (not just "instructions");
  important-instructions framing (`before you can solve/continue …`, `this is an important
  message/instruction/update`); more forged-tag variants (`[system]`, `<|system|>`).
**Done:** recall lift on `Security_module` role_reassignment/indirect/jailbreak measured offline
(`evaluate_blocking_rail`), **FPR unchanged (0)** on the benign corpus. Deterministic, no model.

### D2 — Conditional second-stage detector *(DONE — `EscalatingDetector`)*
Run the cheap heuristic inline; invoke deberta/PromptGuard only on **gray-band** inputs (heuristic
score in `[gray_low, gray_high)`). A new weak/gray tier in the heuristic (`GRAY_SCORE=0.4` for lone
persona / internal-probing markers) feeds it. `load_escalating_detector()` wires heuristic→deberta.
**Measured:** ordinary benign **escalation 0.00** (deberta never runs → zero added latency on the
common case); jailbreak recall **0.33→0.67** by escalating the gray band; D1 hard-blocks skip the
model. Confident-clean and confident-injection never call the model. Lone benign roleplay ("act as a
translator") *does* escalate (ambiguous) but the model clears it → no FPR, only latency. CI-safe
tests (fake secondary). Input layer, model-on-demand.

### D3 — Stronger detector / ensemble
Add Meta **PromptGuard 2 (86M)** as a selectable backend and an **ensemble = max(heuristic, model)**.
PromptGuard 2 targets injection incl. indirect; ensemble raises recall over any single detector.

### D4 — Scan tool/retrieval OUTPUTS with the input PI rail + spotlight *(biggest indirect/XPIA lever)*
Today the PI rail runs only on user input. Route **tool results and retrieved chunks** through the
same PI detector + datamarking before they re-enter the model. Directly attacks indirect/XPIA. Needs
the tool surface (gateway `/api/_trace`, T20-live) or the in-process reference agent.

### D5 — Tool-layer PREVENTION on the real trace *(activate existing controls)*
Wire taint + trusted-action invariant + deny-by-default policy on the **live** trace (T20-live) so a
tainted tool arg can't reach a sensitive sink. Controls already exist (`reasoning/taint.py`,
`tool/policy.py`); this is wiring + a live A/B, not new logic.

### D6 — Known-answer / canary-instruction detection (indirect)
Prepend a secret instruction to untrusted content; if the model would follow it, flag the content as
injection-bearing. Output/tool layer, model-based. Good recall on novel indirect attacks.

## Sequencing
D1 now (this PR) → D4 + D5 (need T20-live; highest indirect/XPIA payoff) → D2/D3 (detector quality &
latency) → D6 (research-grade indirect detector). Each lands as its own PR with split ASR/FPR.
