"""Minimal Odysseus stand-in for local dev/tests (Odysseus itself is offline).

Mirrors the contract the gateway depends on (see
`Agent eval pipeline/adapters/odysseus_adapter.py`):
  - GET  /api/health           -> {"status": "ok"}
  - POST /api/v1/chat {message} -> {"response", "session_id", "model"}  (plain chat, no tools)

A fake tool-trace endpoint is included so L4/L5 rails can be exercised before the real
Odysseus trace-export hook (ADR-0005) is wired.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="odysseus-stub")

MODEL = "mistral-medium-2505"


class ChatIn(BaseModel):
    message: str
    model: str | None = None
    session: str | None = None


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/chat")
def chat(body: ChatIn) -> dict:
    # Echo-style stub: deterministic, runs no tools (matches the real /api/v1/chat).
    return {
        "response": f"[stub reply] {body.message}",
        "session_id": "stub-session",
        "model": body.model or MODEL,
    }


@app.post("/api/_stub/tool-trace")
def tool_trace() -> dict:
    """Synthetic tool trace for L4/L5 development until the real hook lands."""
    return {
        "tool_calls": [
            {"tool": "bash", "parameters": {"cmd": "ls"}, "result": "a\nb", "status": "ok"},
        ]
    }
