# Research digest — advanced runtime guardrails for LLM agents (2024–2026)

> **Provenance & confidence.** Produced by the `deep-research` workflow on 2026-06-30
> (run `wf_681ebd83-f1b`). The **search + claim-extraction phase succeeded** — 6 angles, 13 sources
> (11 arXiv primary + IBM/Google/NVIDIA official docs), 61 extracted claims. The **adversarial
> verification phase did not run**: every verifier agent hit the account session limit, so all 25
> top claims were recorded `0-0 (3 abstain)` and the harness *defaulted them to "refuted."* That
> "all refuted" verdict is a **rate-limit artifact, not a real refutation** — the kind of
> failure-scored-as-result this project explicitly guards against. The claims below are therefore
> marked **`[unverified-by-panel]`** but are **corroborated against primary sources** (each carries
> its arXiv ID / official-doc URL) and against the author's domain knowledge. Re-run the verify pass
> after the limit resets to upgrade them to panel-confirmed.

This digest feeds [`docs/plans/next-gen-guardrails.md`](../plans/next-gen-guardrails.md). Metrics are
reported **split** (ASR/interception vs FPR/utility), never blended, per `CLAUDE.md`.

---

## 0. The big picture — where the field moved

Two paradigms now coexist, and the strongest production systems combine them:

1. **Detection-based guardrails** (classifiers + heuristics on input/output). Mature, cheap, easy to
   deploy as a gateway rail — but fundamentally *probabilistic*: a sufficiently novel injection
   evades them. This is what most vendors ship (Llama Guard, Prompt Guard, Granite Guardian, Azure
   Prompt Shields, Model Armor, NeMo Guardrails). Our gateway already lives here (L1/L6 rails).
2. **Design-based / by-construction defenses** (information-flow control, capabilities, dual-LLM,
   constrained planning). Newer, research-grade, *provable* resistance to whole attack classes — but
   they constrain the agent architecture and cost utility. This is the 2025 frontier: **CaMeL**,
   **FIDES**, and the **six design patterns** paper.

**Strategic takeaway for this repo:** we have the detection layer and the *primitives* for the
design layer (`taint.py`, `quarantine.py`, `policy.py`). The high-value next step is to **promote the
primitives into a real capabilities/IFC enforcement path** (CaMeL/FIDES-style) and to **upgrade
tool-output defense from block-all to surgical token-level sanitization** (CommandSans-style).

---

## 1. Design-by-construction defenses (the 2025 frontier)

### 1.1 CaMeL — capabilities + dual-LLM information-flow control  `[unverified-by-panel]`
- **Source:** *Defeating Prompt Injections by Design*, Google DeepMind — arXiv
  [2503.18813](https://arxiv.org/abs/2503.18813); analysis variant
  [2505.22852](https://arxiv.org/html/2505.22852v1).
- **What it defends:** prompt injection (direct + indirect/XPIA) **and** data exfiltration, *by
  construction* rather than detection.
- **How it works:** a **Privileged LLM** receives the trusted user query and emits a plan/program
  over data *it never reads directly*; a **Quarantined LLM** parses untrusted content and has **no
  tool access**. A custom (non-LLM) Python interpreter executes the plan and enforces
  **capabilities**: every value carries provenance + access metadata, and every tool call must pass
  an explicit policy check, so untrusted data can neither alter control flow nor flow into an
  unauthorized sink (e.g. an email tool).
- **Measured (split):** ~**67% AgentDojo task completion with *provable* security** (one reported
  config; a tiered-risk variant claims >90% of legitimate workflows preserved while blocking all
  simulated attacks). Undefended baseline ≈ 84% completion → the **utility cost of provable security
  is the headline tradeoff.**
- **Adoptability → this gateway:** **High value, medium effort.** We already have `quarantine.py`
  (dual-LLM) and `taint.py`. The gap is a **capability layer**: attach provenance/label metadata to
  every data value and gate `guard_tool` on a **data-flow policy** (does this sink accept data tainted
  by *that* source?). This is L3 (reasoning/IFC) × L4 (tool/action).

### 1.2 FIDES — IFC planner with confidentiality + integrity labels  `[unverified-by-panel]`
- **Source:** arXiv [2505.23643](https://arxiv.org/abs/2505.23643).
- **What it defends:** prompt injection against the *planner* — the step where injected text hijacks
  the agent's next action.
- **How it works:** a runtime planner that tracks **confidentiality and integrity labels** on data,
  **deterministically enforces** security policies, and formally characterizes *which* security
  properties dynamic **taint-tracking** can and cannot enforce in an agent planner. Introduces
  primitives for declassification/endorsement under control.
- **Adoptability:** **High value, higher effort.** Directly informs upgrading our `taint.py` from a
  single taint bit to a **two-axis label (confidentiality, integrity)** with explicit
  declassify/endorse operations — the theoretically-grounded version of what we approximate today.

### 1.3 Six design patterns for prompt-injection-resistant agents  `[unverified-by-panel]`
- **Source:** *Design Patterns for Securing LLM Agents against Prompt Injections* — arXiv
  [2506.08837](https://arxiv.org/abs/2506.08837) (Beurer-Kellner et al.).
- **The six patterns** (each constrains how untrusted content can influence actions):
  **Action-Selector**, **Plan-Then-Execute**, **LLM Map-Reduce**, **Dual-LLM**,
  **Code-Then-Execute**, **Context-Minimization**.
- **Adoptability:** **High value, low-to-medium effort, architectural.** These are *agent-loop*
  patterns, not rails — but our reference agent (`src/agent/runtime.py`) can adopt
  **Plan-Then-Execute** (freeze the tool plan from the *trusted* prompt before any untrusted tool
  output is seen → injected output can't add new actions) and **Context-Minimization** (drop the
  untrusted text from context once its data is extracted). These give *structural* ASR reduction the
  detection rails can't.

---

## 2. Tool-output / indirect-injection defenses

### 2.1 CommandSans — token-level surgical sanitization of tool outputs  `[unverified-by-panel]`
- **Source:** arXiv [2510.08829](https://arxiv.org/html/2510.08829v1).
- **What it defends:** indirect/XPIA — injected instructions hidden inside tool/retrieval results.
- **How it works:** reframes defense as **instruction *detection* at token granularity**. A small
  **XLM-RoBERTa (~279M) classifier**, fine-tuned on instruction-tuning data, tags each token as
  *instruction* vs *non-instruction* and **surgically removes the injected-instruction spans** from
  tool output *before the agent sees it* — instead of sample-level blocking of the whole result.
  Training on generic instruction data (not injection-specific corpora) is the novelty.
- **Why it matters here:** our D4 `guard_tool_output` is **block-all** today (a detected injection
  drops the entire result). Token-level sanitization is strictly better for **utility**: it strips
  the malicious span and keeps the benign data, so a poisoned-but-useful document still serves its
  legitimate purpose. **Direct upgrade to `scan_chain` / `guard_tool_output`.**
- **Adoptability:** **High value, medium effort.** L5 (retrieval) × L1 (detection). Pairs naturally
  with our existing spotlighting (datamark what survives sanitization).

### 2.2 Microsoft Spotlighting — delimiting / datamarking / encoding  `[unverified-by-panel]`
- **Source:** *Defending Against Indirect Prompt Injection with Spotlighting* — arXiv
  [2403.14720](https://arxiv.org/abs/2403.14720).
- **How it works:** three provenance transforms on untrusted text so the model can separate trusted
  instructions from untrusted data: **delimiting** (wrap in unique markers), **datamarking**
  (interleave a marker token between words), **encoding** (base64/ROT13). Reported large ASR
  reductions with low utility loss.
- **Status here:** **Already implemented** (`spotlight.py`, datamarking). Gap: we don't yet offer the
  **encoding** variant or measure delimiting-vs-datamarking-vs-encoding ASR on our suite. Low-effort
  enhancement + measurement.

---

## 3. Production classifier / guardrail suites (the detection layer)

### 3.1 IBM Granite Guardian  `[unverified-by-panel]`
- **Sources:** arXiv [2412.07724](https://arxiv.org/abs/2412.07724);
  [IBM Granite docs](https://www.ibm.com/granite/docs/models/guardian);
  [GuardBench blog](https://research.ibm.com/blog/granite-guardian-tops-guardbench).
- **What it is:** open-sourced classifier suite; runtime risk detection on **both prompts and
  responses**, usable with any LLM.
- **Coverage:** harm, social bias, profanity, violence, sexual content, unethical behavior,
  **jailbreaking**, and **RAG checks** — *context relevance, groundedness, answer relevance*. Newer
  **Granite Guardian 4.x** adds a **"Function-Calling Hallucination"** check that flags tool calls
  with wrong argument names / invalid values / type mismatches vs the tool definition.
- **Measured:** reportedly tops the **GuardBench** leaderboard (top-4 models ~85–86% across 40
  datasets vs competitors 76–82%). *(Leaderboard claim `[unverified-by-panel]` — verify before
  citing as fact.)*
- **Adoptability:** the **function-calling-hallucination** idea is a clean **new L4 rail** —
  validate every tool call's args against the tool's declared schema (a deterministic check we can
  do *without* the model). The **RAG groundedness** trio overlaps our `grounding.py`.

### 3.2 Google Cloud Model Armor  `[unverified-by-panel]`
- **Source:** [cloud.google.com/security/products/model-armor](https://cloud.google.com/security/products/model-armor).
- **What it is:** **GA** production service screening prompts **and** responses; deployable
  standalone or via Vertex AI / REST, with **"floor settings"** (org-wide baseline protections).
- **Coverage:** prompt-injection & jailbreak detection (block prompt or response on detection);
  **DLP / data-exfiltration** — detects PII (credit cards, US SSNs, GCP credentials) flowing in/out.
- **Adoptability:** validates our gateway shape (screen both directions; org-baseline = our default
  chain). The **floor-settings** concept → a config tier of non-overridable rails.

### 3.3 Meta Llama Guard 3/4 + Prompt Guard 2  (context: ADR-0003 pairing)
- Llama Guard = response/prompt safety classifier; **Prompt Guard 2 (86M)** = injection/jailbreak
  detector. We already wire **Prompt Guard 2** (`load_promptguard_detector`, HF-gated) and
  **deberta-v3** as ensemble members. No new work beyond enabling/measuring once `HF_TOKEN` is set.

### 3.4 NVIDIA NeMo Guardrails  `[unverified-by-panel]`
- **Source:** [github.com/NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails).
- **What it is:** mature open-source programmable-guardrails toolkit between app and LLM.
- **Five rail categories:** **input, dialog, retrieval, execution, output** — which **map almost
  1:1 onto our layers** (L1, L2, L5, L4, L6). Built-in jailbreak/injection detection, self-check
  moderation, fact-checking, hallucination rails; ships an HTTP guardrails server.
- **Adoptability:** primarily a **cross-check on our taxonomy** (we independently arrived at the same
  five surfaces + reasoning/oversight/multi-agent). Their **retrieval rail** is the named analogue of
  the CommandSans/scan_chain work in §2.

---

## 4. Synthesis — what to build next (feeds the plan)

Mapped to the existing 7 layers and the current code:

| # | Technique (source) | Layer | Current state | Gap → task |
|---|---|---|---|---|
| N1 | **Function-calling schema/hallucination check** (Granite 4.x) | L4 tool | `policy.py`, `exec_gate.py` exist | new deterministic rail: args vs declared tool schema |
| N2 | **Token-level tool-output sanitization** (CommandSans) | L5×L1 | D4 `guard_tool_output` is block-all | surgical strip of injected spans, keep benign data |
| N3 | **Capabilities / data-flow policy at tool call** (CaMeL) | L3×L4 | `taint.py`, `quarantine.py` primitives | provenance labels + sink-policy gate on `guard_tool` |
| N4 | **Two-axis IFC labels (confidentiality+integrity)** (FIDES) | L3 | single taint bit | upgrade taint to labeled lattice + declassify/endorse |
| N5 | **Plan-Then-Execute + Context-Minimization** (6 patterns) | agent loop | linear planner in `runtime.py` | freeze plan from trusted prompt; drop untrusted text post-extract |
| N6 | **Spotlighting encoding variant + measurement** (MSFT) | L1 | datamarking only | add encoding mode; measure 3 variants' ASR/FPR |
| N7 | **GuardBench-style eval harness** (IBM) | x-cut | A/B + AgentDojo | add a public guard-classifier benchmark lane |

**Priority order (value × tractability):** N2 → N1 → N5 → N3 → N6 → N4 → N7. N2/N1/N5 are
self-contained and high-impact; N3/N4 are the deeper architectural bets; N6/N7 are measurement.

## 5. Open questions / caveats
- **Verification debt:** re-run the verify panel after the session limit resets to upgrade every
  `[unverified-by-panel]` claim. Treat all *measured numbers* (CaMeL 67/77%, GuardBench 85–86%) as
  **author-reported** until independently reproduced on our suite.
- **Utility cost is real:** CaMeL-style provable defenses cost task completion. Adopt them
  **tiered** (full IFC only for irreversible/high-risk tool sinks; detection rails elsewhere).
- **No single number:** every technique must be reported ASR/interception **and** FPR/utility
  separately when we measure it here.

## Sources
- arXiv 2503.18813 — CaMeL, *Defeating Prompt Injections by Design* (Google DeepMind)
- arXiv 2505.22852 — CaMeL analysis / tiered-risk variant
- arXiv 2505.23643 — FIDES, IFC planner with confidentiality+integrity labels
- arXiv 2506.08837 — *Design Patterns for Securing LLM Agents against Prompt Injections*
- arXiv 2510.08829 — CommandSans, token-level tool-output sanitization
- arXiv 2403.14720 — Microsoft Spotlighting (delimiting / datamarking / encoding)
- arXiv 2412.07724 — IBM Granite Guardian
- arXiv 2510.05244, 2503.00061 — additional primary sources (extraction stage; not in top-25)
- IBM Granite docs — https://www.ibm.com/granite/docs/models/guardian
- IBM Research — https://research.ibm.com/blog/granite-guardian-tops-guardbench
- Google Cloud — https://cloud.google.com/security/products/model-armor
- NVIDIA NeMo Guardrails — https://github.com/NVIDIA-NeMo/Guardrails
