# Python API

The stable public surface is the top level of `sec_guardrails`. Internals live in
`sec_guardrails.gateway`, `sec_guardrails.core`, and `sec_guardrails.rails`; import those directly
only for low-level use.

## `sec_guardrails.__version__`

The installed package version (string).

## `build_default_app(env_fallback=None)`

Build the fully-wired default gateway: the real `OdysseusClient` fronted by `GuardedOdysseusClient`
(so the deployed `/api/v1/chat` path enforces `guard_input` → forward → `guard_output` → L7 review —
rails on the main path, not just the eval harness), plus the default rail engine and an append-only,
hash-chained audit log. Enables the opt-in L7 LLM oversight critic when `GATEWAY_LLM_CRITIC` is set.
`env_fallback` overrides the `GUARDRAILS_ENV_FALLBACK` config path. Returns a FastAPI application.

```python
from sec_guardrails import build_default_app

app = build_default_app()
```

## `create_gateway_app(client, *, audit=None, tracer=None, engine=None, trace_token=None)`

Build a gateway app around a caller-supplied Odysseus `client`. Thin, stable re-export of
`sec_guardrails.gateway.app.create_app`; accepts the same keyword arguments. Use this to bring your own
client, audit sink, tracer, or rail engine.

```python
from sec_guardrails import create_gateway_app

app = create_gateway_app(my_client, audit=my_audit, engine=my_engine)
```

## Endpoints exposed by the app

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | gateway + Odysseus health |
| `POST` | `/api/v1/chat` | guarded proxy to Odysseus (input/output rails enforced; blocked turns never reach the model) |
| `POST` | `/api/_pretrace` | **preventive** tool verdict — the hook calls this *before* executing a tool and honors allow/block/hitl (fails closed with no engine) |
| `POST` | `/api/_trace` | **detective** tool-trace ingest; runs each executed event through the tool rails |
