# Exploration — Odysseus guardrails integration surface

*Flat findings with file references. Produced by the `/explore` stage. Sibling projects are read-only
references this repo integrates with but does NOT modify (except the approved Odysseus trace hook).*

## Odysseus agent (`C:\Users\hp\Downloads\odysseus`) — the target
- FastAPI app: `app.py` + `routes/*.py`. Mistral-backed (`mistral-medium-2505` per eval notes).
- Tool/task execution path (L4/L5 enforcement point):
  - `src/tool_execution.py` — **central tool dispatch → attach the trace-export hook here.**
  - `src/tool_implementations.py`, `src/tool_index.py`, `src/tool_parsing.py`, `src/tool_schemas.py`
  - `src/tool_security.py` — Odysseus already has *some* tool security; review for overlap/reuse.
  - `src/agent_loop.py`, `src/agent_runs.py` — autonomous loop / runs (check for multi-agent → OQ1).
  - `routes/task_routes.py`, `routes/assistant_routes.py`, `routes/chat_routes.py` (+ `chat_helpers.py`).
- MCP servers (memory/RAG = L5 surface): `mcp_servers/memory_server.py`, `rag_server.py`,
  `email_server.py`, `image_gen_server.py`. (Note: MCP supply-chain is OUT of guardrail scope.)
- Deploy: `Dockerfile`, `docker-compose.yml` (+ gpu variants). Currently **not running** (`:7000` dead).
- Security docs present: `THREAT_MODEL.md`, `SECURITY.md` — read before designing rails.

## Odysseus API contract (from `Agent eval pipeline/adapters/odysseus_adapter.py`)
- `chat_endpoint` default `/api/v1/chat`, body field `message`; returns `{response, session_id, model}`
  — **plain chat, runs no tools** (`odysseus_adapter.py:60,82-89`).
- `agent_endpoint` default `/api/agent/run` **404s on this build** → sticky chat fallback
  (`odysseus_adapter.py:198-214`).
- Real tools = async task lifecycle (`POST /api/tasks` → `/api/tasks/{id}/run` → poll), **no per-step
  trace exposed to an API token** — the gap the trace hook closes.
- `health_endpoint` `/api/health` (`:259-272`). Header auth via `_build_headers()` + `ODYSSEUS_TOKEN`.
- **`4xx` terminal, only retry `5xx`/network** (`odysseus_adapter.py:105-111`) — mirror in our client.
- Defensive trace-key candidates already enumerated (`_TRACE_LIST_KEYS`, `_STEP_*` at `:44-51`) — reuse
  as the normalization target for the hook's exported trace.

## Offensive oracle (`Agent_security_testing/Security_module`) — attacks to defend
- ASI suite `tests_asi/`: `asi01_goal_hijack`, `asi02_tool_misuse`, `asi03_privilege_abuse`,
  `asi04_supply_chain` *(OUT of scope)*, `asi05_code_execution`, `asi06_memory_poisoning`,
  `asi07_interagent_comms`, `asi08_cascading_failures`, `asi09_trust_exploitation`, `asi10_rogue_agents`.
- ext suite: `ext01_log_injection`, `ext02_ltl_chain`, `ext03_consensus_spoofer`, `ext04_entropy_boundary`,
  `ext05_metamorphic_consistency`, `ext06_z3_constraint_prober`, `ext07_goal_drift`,
  `ext08_sandbox_isolation`, `ext09_fol_axiom_enforcer`, `ext10_xpia_indirect_injection`,
  `ext11_mcp_tool_poisoning` *(OUT)*, `ext12_alignment_checker`, `ext13_model_extraction`,
  `ext14_data_poisoning`, `ext15_attribute_inference`, `ext16_cache_poisoning`, `ext17_delivery_hijack`.
- Reusable payload corpora (→ test fixtures): `payloads/injection_payloads.py`, `xpia_payloads.py`,
  `poisoning_payloads.py`, `sql_payloads.py`, `encoding_payloads.py`.
- Reusable defensive helpers (patterns to mirror, not import): `core/ssrf_guard.py`,
  `core/redaction.py`, `discovery/openapi_parser.py`, `core/http_client.py`.
- Config: `config/settings.py` — `ASI_*` env vars, rate-limit/token-bucket, `ALLOW_INTERNAL_TARGETS`,
  budget caps. Uses Anthropic + OpenAI providers (`llm/`).

## Scorer (`Agent eval pipeline`) — reuse for utility/grounding measurement
- `adapters/odysseus_adapter.py` (contract above), `evals/grounding_judge.py` (RAGAS/NLI grounding —
  reuse for output-rail grounding check, SC2/G4), `evals/odysseus_metrics*.py` (33-metric pack),
  benign chat-quality task suite (→ utility benchmark for SC2).

## Credentials / config available
- `Agent eval pipeline/.env`: `ODYSSEUS_TOKEN`, `OPENAI_API_KEY` *(ROTATE)*, `ODYSSEUS_JUDGE_MODEL`,
  `ODYSSEUS_LLM_GROUNDING`.
- `Security_module/.env`: `OPENAI_API_KEY`, `LLM_HOST`, `SEARXNG_INSTANCE`; `settings.py` also reads
  `ANTHROPIC_API_KEY`.
- Our loader (T-P0) resolves these via env + a configurable fallback path; never hardcoded/committed.

## Risk areas / notes
- Odysseus down → all live validation deferred; build on a stub mirroring the `:60` contract.
- `src/tool_security.py` may duplicate intended L4 logic — reconcile to avoid double-enforcement.
- Long-context defense flattening (Reference §15.4) — classifiers degrade past ~4k tokens.
- OQ1 (multi-agent?) unresolved — confirm in `agent_loop.py` / `agent_runs.py` before the multi-agent rail.
