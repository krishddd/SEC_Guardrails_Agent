"""T5 — Gateway skeleton (pass-through) + T6 observability wiring.

A FastAPI reverse-proxy that forwards `/api/v1/chat` to Odysseus unchanged (no rails yet — those
land in later tasks), emitting an OpenTelemetry span + an append-only audit record per request.
Construct via `create_app(client, audit=..., tracer=...)` so tests can inject a stub client, a temp
audit log, and an in-memory span exporter.
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.audit import AuditLog


class ChatIn(BaseModel):
    message: str
    model: str | None = None
    session: str | None = None


def create_app(client: Any, *, audit: AuditLog | None = None, tracer: Any | None = None) -> FastAPI:
    app = FastAPI(title="sec-guardrails-gateway")
    app.state.client = client
    app.state.audit = audit
    app.state.tracer = tracer

    def _emit(decision: str, **fields: Any) -> None:
        if audit is not None:
            audit.record(decision=decision, **fields)

    def _span(name: str):
        return tracer.start_as_current_span(name) if tracer is not None else nullcontext()

    @app.get("/health")
    def health() -> dict:
        return {"gateway": "ok", "odysseus": client.health_check()}

    @app.post("/api/v1/chat")
    def chat(body: ChatIn) -> dict:
        with _span("gateway.chat"):
            try:
                result = client.chat(body.message, model=body.model, session=body.session)
            except Exception as exc:  # upstream/Odysseus failure
                _emit("error", endpoint="/api/v1/chat", error=str(exc))
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            # Pass-through for now; rail chains attach in later tasks.
            _emit("allow", endpoint="/api/v1/chat")
            return result

    return app
