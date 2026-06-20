# Research digest — Odysseus runtime guardrails (intake)

*Raw intake for the research-doc-driven pipeline. Frames the two source surveys + the confirmed scope
decisions as the starting point for `/research-distill`. Messy-but-complete is fine here.*

## What we're building
Defensive, **build-from-scratch**, **7-layer runtime guardrails** for the **Odysseus** autonomous
agent (Docker, local `:7000`, Mistral-backed), deployed as a non-invasive **reverse-proxy guardrail
gateway** on `:7100`. This is the *defensive* half of an existing loop:
- **Offensive** (already built, NOT rebuilt): `Agent_security_testing/Security_module` — red-team with
  ASI01–10 + ext01–17. Reused as the **attack oracle**.
- **Scorer** (reused): `Agent eval pipeline` — Odysseus quality/safety metrics.

## Source material
- `AI_Agent_Guardrails_Reference.md` — **canonical**. Practitioner's reference, 7 control layers,
  defense-in-depth ("Swiss-cheese"), treat-all-external-content-as-untrusted, per-layer latency budgets,
  §13 eval methodology (ASR vs utility, split — never one F1), §14 reference architecture.
  **Scope note (line 5): skill/MCP supply-chain is OUT** (handled separately).
- `AI_Agent_Guardrails_Research.md` — secondary; identical except it *keeps* skill/MCP supply-chain.
  Where the two differ, Reference.md wins.

## The 7 layers (Reference §2)
L1 input · L2 dialog/topic · L3 reasoning/IFC · L4 tool/action · L5 retrieval/memory ·
multi-agent comms · L7 verification/oversight · (+ L6 output) · cross-cutting observability.

## Confirmed scope decisions (2026-06-20)
1. Target = **Odysseus** (`:7000`, Mistral). 2. **Build-from-scratch** control plane (commodity
   detectors as swappable components). 3. **Full 7-layer** topology. 4. **Reference.md canonical** →
   MCP/skill supply-chain excluded (offensive ASI04/ext11 stay in the red-team, undefended here).
5. **Trace fork = YES:** Odysseus source is local (`C:\Users\hp\Downloads\odysseus`, FastAPI +
   `src/tool_execution.py`), so we may add a **minimal read-only trace-export hook** → L4/L5/multi-agent
   enforce **live**, not synthetic-only. 6. Dev against a **stub agent**; user starts Odysseus for live A/B.
7. Pipeline infra = **full build-out** (done — Phase A). 8. L4 policy = **in-house DSL** (OPA = v2).
9. Code **pushed daily** to `github.com/krishddd/SEC_Guardrails_Agent`.

## Key constraints discovered
- Odysseus `/api/v1/chat {message}` = plain chat, **no tools**, returns `{response, session_id, model}`.
- Real tools run server-side; **not exposed to an API token** → hence the trace-export hook.
- Odysseus `4xx` = terminal (no retry); bodies must match schema or `422`.
- Reuse `ODYSSEUS_TOKEN` + `OPENAI_API_KEY` from the eval pipeline `.env`. **Rotate the OpenAI key**
  (previously shared in plaintext).

## Pinned components (verified 2026-06-20)
deberta-v3-base-prompt-injection-v2 (input PI; weak on jailbreaks → pair w/ content classifier) ·
Presidio 2.2.362 (PII) · Mistral Moderation `mistral-moderation-2603` + ShieldGemma 2 fallback (output) ·
in-house rule DSL (L4) · Pydantic v2 (schema) · OpenTelemetry GenAI semconv (tracing) ·
AgentDojo/WASP via Inspect Evals + Security_module (eval).

## Success shape
ASR(via gateway) ≤ ASR(direct) per attack class, with utility retained above a concrete threshold,
metrics reported **split**; per-layer latency within budget (input<30 / dialog<200 / output<50 ms).
