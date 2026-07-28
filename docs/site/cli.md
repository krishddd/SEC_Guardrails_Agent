# CLI

Installing the package registers the `sec-guardrails` console entry point.

```text
sec-guardrails --help
usage: sec-guardrails [-h] [--version] {serve,version} ...
```

## `serve`

Run the guardrail gateway in front of Odysseus.

```bash
sec-guardrails serve --port 7100
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--host` | `127.0.0.1` / `$GATEWAY_HOST` | bind host |
| `--port` | `7100` / `$GATEWAY_PORT` | bind port |
| `--env-fallback` | `$GUARDRAILS_ENV_FALLBACK` | path to a fallback `.env` |
| `--log-level` | `warning` | uvicorn log level |

## `version`

```bash
sec-guardrails version
```
