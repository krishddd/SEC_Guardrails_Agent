"""T2 — Config + secrets loader.

Resolves runtime config from the process environment, optionally backfilled from a fallback `.env`
file (e.g. the eval pipeline's). Never hardcodes secrets; `.env` is gitignored. `ODYSSEUS_TOKEN` is
required — its absence is a hard, clear error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _parse_env_file(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE .env parser (ignores blanks/comments, strips quotes)."""
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            out[key] = value
    return out


@dataclass(frozen=True)
class Config:
    odysseus_base_url: str
    odysseus_token: str
    openai_api_key: str | None = None
    mistral_api_key: str | None = None


def load_config(
    env: dict[str, str] | None = None,
    fallback_path: str | os.PathLike[str] | None = None,
) -> Config:
    """Build a Config from `env` (defaults to os.environ), backfilled from a fallback .env file.

    Fallback path comes from `fallback_path` or `GUARDRAILS_ENV_FALLBACK`. Values in `env` win over
    the fallback file. Raises ConfigError if `ODYSSEUS_TOKEN` is unset.
    """
    resolved = dict(os.environ) if env is None else dict(env)

    fb = fallback_path if fallback_path is not None else resolved.get("GUARDRAILS_ENV_FALLBACK")
    if fb:
        p = Path(fb)
        if p.exists():
            for key, value in _parse_env_file(p).items():
                resolved.setdefault(key, value)

    token = resolved.get("ODYSSEUS_TOKEN")
    if not token:
        raise ConfigError(
            "ODYSSEUS_TOKEN is required — set it in the environment or a fallback .env "
            "(GUARDRAILS_ENV_FALLBACK)."
        )

    return Config(
        odysseus_base_url=resolved.get("ODYSSEUS_BASE_URL", "http://localhost:7000").rstrip("/"),
        odysseus_token=token,
        openai_api_key=resolved.get("OPENAI_API_KEY") or None,
        mistral_api_key=resolved.get("MISTRAL_API_KEY") or None,
    )
