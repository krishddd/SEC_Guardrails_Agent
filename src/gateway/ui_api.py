"""T38 — Gateway UI API (for the HITL app + dashboard, ADR-0007).

A minimal, authenticated JSON API the `web/` frontend consumes: list pending HITL approvals, resolve
one, and read the governance/audit report. All requests are untrusted client input — bearer auth on
every route, default-deny on an unknown approval id. The UI holds no security logic; this API only
surfaces state and relays an operator's approve/reject.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from core.audit import AuditLog
from eval.governance import export as governance_export
from rails.tool.hitl import HITLManager


class ApprovalAction(BaseModel):
    approved: bool


def create_ui_app(hitl: HITLManager, audit: AuditLog, *, ui_token: str) -> FastAPI:
    app = FastAPI(title="sec-guardrails-ui")

    def _auth(authorization: str) -> None:
        if not ui_token or authorization != f"Bearer {ui_token}":
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/ui/approvals")
    def list_approvals(authorization: str = Header(default="")) -> list[dict]:
        _auth(authorization)
        return [
            {"id": a.id, "tool": a.tool, "args": a.args, "expires_at": a.expires_at}
            for a in hitl.pending()
        ]

    @app.post("/ui/approvals/{approval_id}")
    def resolve_approval(
        approval_id: str, action: ApprovalAction, authorization: str = Header(default="")
    ) -> dict:
        _auth(authorization)
        try:
            approval = hitl.resolve(approval_id, approved=action.approved)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="unknown approval id") from exc
        return {"id": approval.id, "status": approval.status}

    @app.get("/ui/report")
    def governance_report(authorization: str = Header(default="")) -> dict:
        _auth(authorization)
        return governance_export(audit.read_all())

    return app
