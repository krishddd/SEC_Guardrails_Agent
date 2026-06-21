# Compliance control map (T36)

How each guardrail layer maps to **NIST AI RMF** functions and **EU AI Act** articles. The append-only
audit log (T6) is the evidence source; `src/eval/governance.py` exports a machine-readable version of
the decision→control mapping below.

| Guardrail layer / control | What it enforces | NIST AI RMF | EU AI Act |
|---|---|---|---|
| **Audit log** (cross-cutting, T6) | append-only record of every rail decision | GOVERN 4.1, MEASURE 1.1 | Art. 12 (record-keeping), Art. 19 (logs) |
| **L1 input** (T8–T11) | block injection/jailbreak; redact secrets/PII; spotlight untrusted | MEASURE 2.7 (robustness), MANAGE 2.1 | Art. 15 (accuracy, robustness, cybersecurity) |
| **L2 dialog** (T13–T14) | keep agent on-task; deny disallowed topics | MAP 1.1, MANAGE 2.1 | Art. 15 |
| **L3 reasoning / IFC** (T28) | taint tracking + trusted-action invariant | MEASURE 2.6 | Art. 15 |
| **L4 tool / action** (T21–T24) | deny-by-default policy; SSRF/egress; HITL on irreversible | GOVERN 1.2 (accountability), MANAGE 2.1 | Art. 14 (human oversight), Art. 15 |
| **L5 memory** (T25–T26) | write-time moderation; provenance; tenant isolation | MAP 5.1, MEASURE 2.7 | Art. 10 (data governance) |
| **Multi-agent** (T29) | signed messages; capability delegation; orchestrator mediation | MANAGE 2.1 | Art. 15 |
| **L6 output** (T15–T18) | schema; content safety; leak/canary; URL/HTML sanitize | MEASURE 2.7, MAP 5.1 | Art. 13 (transparency), Art. 15 |
| **HITL** (T23) | human approval for irreversible actions | GOVERN 1.2 | Art. 14 (human oversight) |
| **Eval split metrics** (T12, T31–T34) | ASR vs FPR/utility reported separately, regression-gated | MEASURE 2.1, MEASURE 2.3 | Art. 15 |

> Metrics are always reported **split** (ASR and FPR/utility separately) — never a blended F1 — so the
> evidence distinguishes "too loose" from "too strict" failure modes (Reference §13).

## Notes
- This map is indicative, not legal advice; article numbers track the EU AI Act high-risk obligations
  (applicable from 2026-08-02). Re-verify against the current consolidated text before an audit.
- The machine-readable mapping lives in `CONTROL_MAP` (`src/eval/governance.py`) and is included in
  every `export()` so a report is self-describing.
