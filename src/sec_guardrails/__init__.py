"""sec-guardrails — defensive 7-layer runtime guardrails gateway for the Odysseus agent.

Stable public surface for harnessing the gateway from any agentic pipeline. Internals live under
``sec_guardrails.gateway`` / ``.core`` / ``.rails``; import those directly only for low-level use.

Typical use::

    from sec_guardrails import build_default_app
    app = build_default_app()          # a FastAPI app you can mount or serve with uvicorn

Or wire your own Odysseus client / engine::

    from sec_guardrails import create_gateway_app
    app = create_gateway_app(my_client, audit=my_audit, engine=my_engine)
"""

from __future__ import annotations

from importlib import metadata as _metadata
from typing import Any

try:
    __version__ = _metadata.version("sec-guardrails")
except _metadata.PackageNotFoundError:  # running from a source checkout without an install
    __version__ = "0.1.1"

__all__ = ["__version__", "create_gateway_app", "build_default_app"]


def create_gateway_app(client: Any, **kwargs: Any):
    """Build a guardrail-gateway FastAPI app around a caller-supplied Odysseus ``client``.

    Thin, stable re-export of :func:`gateway.app.create_app`. Accepts the same keyword arguments
    (``audit``, ``tracer``, ``engine``, ``trace_token``).
    """
    from sec_guardrails.gateway.app import create_app

    return create_app(client, **kwargs)


def build_default_app(env_fallback: str | None = None):
    """Build the fully-wired default gateway (real Odysseus client + rail engine + audit log).

    Mirrors ``scripts/run_gateway.py``: reads config (Odysseus base URL/token) via the shared config
    loader, attaches an append-only audit log, and enables the opt-in LLM oversight critic when
    ``GATEWAY_LLM_CRITIC`` is set. ``env_fallback`` overrides the ``GUARDRAILS_ENV_FALLBACK`` path.
    """
    import os

    from sec_guardrails.core.audit import AuditLog
    from sec_guardrails.core.config import load_config
    from sec_guardrails.core.engine import default_engine
    from sec_guardrails.gateway.guarded_odysseus import GuardedOdysseusClient
    from sec_guardrails.gateway.odysseus_client import OdysseusClient

    fallback = env_fallback or os.getenv("GUARDRAILS_ENV_FALLBACK")
    config = load_config(fallback_path=fallback) if fallback else load_config()
    audit = AuditLog(os.getenv("GATEWAY_AUDIT_PATH", "gateway_audit.jsonl"))
    engine = default_engine(audit, critic=_maybe_critic(config))
    # G1: the deployed chat path is guarded. Front the raw Odysseus client with the rail engine so
    # `/api/v1/chat` runs guard_input (preventive) → forward → guard_output (preventive) → L7
    # review — the difference between a guardrail *library* and a deployed guardrail *gateway*.
    client = GuardedOdysseusClient(
        OdysseusClient(config.odysseus_base_url, config.odysseus_token), engine
    )
    return create_gateway_app(
        client, audit=audit, engine=engine, trace_token=os.getenv("GATEWAY_TRACE_TOKEN")
    )


def _maybe_critic(config: Any):
    """Opt-in L7 LLM oversight critic — enabled by ``GATEWAY_LLM_CRITIC``. Never fatal."""
    import os

    if os.getenv("GATEWAY_LLM_CRITIC", "").lower() not in ("1", "true", "yes"):
        return None
    try:
        from sec_guardrails.rails.oversight.llm_critic import load_llm_critic

        return load_llm_critic(config)
    except Exception:  # missing key / `llm` extra not installed — degrade, don't crash
        return None
