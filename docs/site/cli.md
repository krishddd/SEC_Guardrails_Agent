# CLI

Installing the package registers the `sec-guardrails` console entry point.

```text
sec-guardrails --help
usage: sec-guardrails [-h] [--version] {serve,audit,version} ...
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

## `audit verify`

Verify the tamper-evident audit hash chain (G5). Walks the chain and reports the first modified
record, broken link, malformed line, or bad HMAC signature; exits non-zero on any failure.

```bash
sec-guardrails audit verify gateway_audit.jsonl
```

| Flag | Default | Meaning |
|------|---------|---------|
| `path` | — | path to the audit JSONL file (required) |
| `--hmac-key-env` | `AUDIT_HMAC_KEY` | env var holding the operator HMAC key; signature checks are skipped if unset |

## `version`

```bash
sec-guardrails version
```
