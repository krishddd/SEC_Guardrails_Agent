"""Run the guardrail gateway on :7100 in front of Odysseus :7000.

Wires a real `OdysseusClient` + `default_engine` into `create_app`, so:
  - `POST /api/v1/chat` proxies to Odysseus,
  - `POST /api/_trace` receives the Odysseus trace-export hook's events (T20) and runs each through
    `guard_tool` (the call) + `guard_tool_output` (the result, D4) — the live indirect/XPIA path.

Point the Odysseus process at it with `GUARDRAIL_TRACE_URL=http://localhost:7100/api/_trace`.

    python scripts/run_gateway.py            # serves on :7100
Env: GUARDRAILS_ENV_FALLBACK, GATEWAY_PORT (default 7100), GATEWAY_TRACE_TOKEN (optional).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

if hasattr(sys.stdout, "reconfigure"):  # Windows cp1252 consoles choke on non-ASCII
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.audit import AuditLog  # noqa: E402
from core.config import load_config  # noqa: E402
from core.engine import default_engine  # noqa: E402
from gateway.app import create_app  # noqa: E402
from gateway.odysseus_client import OdysseusClient  # noqa: E402

_DEFAULT_ENV = "../Agent evals/Agent eval pipeline/.env"


def _maybe_critic(config):
    """N8 — opt-in LLM oversight critic. Enabled by GATEWAY_LLM_CRITIC=1 + a configured LLM key.
    Never fatal: a missing key or the `llm` extra not installed -> log and run without the critic.
    """
    if os.getenv("GATEWAY_LLM_CRITIC", "").lower() not in ("1", "true", "yes"):
        return None
    try:
        from rails.oversight.llm_critic import load_llm_critic

        critic = load_llm_critic(config)
        print(f"[gateway] LLM oversight critic ON ({config.llm_model})")
        return critic
    except Exception as exc:  # missing key / `llm` extra not installed — degrade, don't crash
        print(f"[gateway] LLM critic requested but unavailable ({type(exc).__name__}: {exc})")
        return None


def build() -> object:
    config = load_config(fallback_path=os.getenv("GUARDRAILS_ENV_FALLBACK", _DEFAULT_ENV))
    client = OdysseusClient(config.odysseus_base_url, config.odysseus_token)
    audit = AuditLog(str(ROOT / "gateway_audit.jsonl"))
    engine = default_engine(audit, critic=_maybe_critic(config))
    return create_app(
        client, audit=audit, engine=engine, trace_token=os.getenv("GATEWAY_TRACE_TOKEN")
    )


def main() -> int:
    import uvicorn

    port = int(os.getenv("GATEWAY_PORT", "7100"))
    print(f"[gateway] serving on :{port} -> Odysseus; trace ingest at POST /api/_trace")
    uvicorn.run(build(), host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
