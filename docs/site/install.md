# Install & harness

## Install

```bash
pip install sec-guardrails
```

Optional extras:

| Extra | Adds |
|-------|------|
| `sec-guardrails[ml]` | deberta prompt-injection detector + Presidio PII |
| `sec-guardrails[mistral]` | Mistral moderation backend |
| `sec-guardrails[llm]` | L7 opt-in LLM oversight critic (OpenAI-compatible) |
| `sec-guardrails[bench]` | AgentDojo benchmark harness |
| `sec-guardrails[otel]` | OpenTelemetry exporter |

## Harness it in a pipeline

The public surface lives at the top level of `sec_guardrails` and is stable:

```python
from sec_guardrails import build_default_app, create_gateway_app

# Fully-wired: real Odysseus client + default rail engine + audit log, config from env.
app = build_default_app()

# Bring your own wiring (custom client / engine / audit):
app = create_gateway_app(my_client, audit=my_audit, engine=my_engine)
```

`app` is a FastAPI application. Mount it inside a larger service, or serve it directly:

```python
import uvicorn

uvicorn.run(build_default_app(), host="127.0.0.1", port=7100)
```

Then point Odysseus at the trace-ingest hook:

```
GUARDRAIL_TRACE_URL=http://localhost:7100/api/_trace
```

## Configuration

Configuration is via environment variables. Key ones:

| Variable | Meaning |
|----------|---------|
| `ODYSSEUS_TOKEN` | Odysseus API token (required) |
| `GUARDRAILS_ENV_FALLBACK` | path to a fallback `.env` for config |
| `GATEWAY_PORT` | gateway bind port (default `7100`) |
| `GATEWAY_TRACE_TOKEN` | optional bearer token guarding `/api/_trace` |
| `GATEWAY_LLM_CRITIC` | `1` to enable the L7 oversight critic |
| `GATEWAY_AUDIT_PATH` | audit-log path (default `gateway_audit.jsonl`) |

`.env` is never committed.
