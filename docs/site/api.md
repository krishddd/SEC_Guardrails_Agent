# Python API

The stable public surface is the top level of `sec_guardrails`. Internals live in
`sec_guardrails.gateway`, `sec_guardrails.core`, and `sec_guardrails.rails`; import those directly
only for low-level use.

## `sec_guardrails.__version__`

The installed package version (string).

## `build_default_app(env_fallback=None)`

Build the fully-wired default gateway: a real `OdysseusClient` (base URL + token from config), the
default rail engine, and an append-only audit log. Enables the opt-in L7 LLM oversight critic when
`GATEWAY_LLM_CRITIC` is set. `env_fallback` overrides the `GUARDRAILS_ENV_FALLBACK` config path.
Returns a FastAPI application.

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
| `POST` | `/api/v1/chat` | guarded proxy to Odysseus |
| `POST` | `/api/_trace` | tool-trace ingest; runs each event through the tool rails |
