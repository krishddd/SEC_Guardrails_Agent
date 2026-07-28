from fastapi.testclient import TestClient

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.gateway.ui_api import create_ui_app
from sec_guardrails.rails.tool.hitl import HITLManager
from sec_guardrails.rails.tool.policy import ToolCall

TOKEN = "ui-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _client(tmp_path):
    hitl = HITLManager()
    hitl.request(ToolCall("send_email", {"to": "x"}), now=0.0, approval_id="a1")
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.record(decision="block", endpoint="/api/v1/chat", reason="prompt-injection suspected")
    return TestClient(create_ui_app(hitl, audit, ui_token=TOKEN)), hitl


def test_requires_auth(tmp_path):
    client, _ = _client(tmp_path)
    assert client.get("/ui/approvals").status_code == 401
    assert client.get("/ui/approvals", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_lists_pending_approvals(tmp_path):
    client, _ = _client(tmp_path)
    rows = client.get("/ui/approvals", headers=AUTH).json()
    assert len(rows) == 1
    assert rows[0]["id"] == "a1"
    assert rows[0]["tool"] == "send_email"


def test_resolve_approval(tmp_path):
    client, hitl = _client(tmp_path)
    resp = client.post("/ui/approvals/a1", json={"approved": True}, headers=AUTH)
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert hitl.is_allowed("a1", now=1.0) is True


def test_unknown_approval_is_404(tmp_path):
    client, _ = _client(tmp_path)
    resp = client.post("/ui/approvals/nope", json={"approved": True}, headers=AUTH)
    assert resp.status_code == 404


def test_governance_report(tmp_path):
    client, _ = _client(tmp_path)
    report = client.get("/ui/report", headers=AUTH).json()
    assert report["summary"]["total"] == 1
    assert report["summary"]["block_count"] == 1
    assert "control_map" in report
