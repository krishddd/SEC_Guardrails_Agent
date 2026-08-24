"""G6 — preventive L4 tool enforcement via the pre-execution trace hook.

`POST /api/_pretrace` returns a verdict the Odysseus hook calls BEFORE executing a tool. Unlike the
detective `/api/_trace` (tool already ran server-side), a `block` here means the tool never runs.
These tests simulate the hook: a fake executor runs a tool ONLY when the gateway says `allow`, so a
destructive command is prevented, not merely surfaced after the fact.
"""

from fastapi.testclient import TestClient

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.engine import default_engine
from sec_guardrails.gateway.app import create_app
from test_gateway import FakeOdysseus


def _client(tmp_path, *, with_engine=True, trace_token=None):
    engine = default_engine(AuditLog(tmp_path / "audit.jsonl")) if with_engine else None
    return TestClient(create_app(FakeOdysseus(), engine=engine, trace_token=trace_token))


class _Hook:
    """Simulates the Odysseus pre-tool hook: ask the gateway, execute only on allow."""

    def __init__(self, client, **headers):
        self.client = client
        self.headers = headers
        self.executed: list[str] = []

    def run_tool(self, tool_name, args):
        verdict = self.client.post(
            "/api/_pretrace", json={"tool_name": tool_name, "args": args}, headers=self.headers
        ).json()
        if verdict["decision"] == "allow":
            self.executed.append(f"{tool_name}:{args}")
            return "executed"
        return f"[{verdict['decision']}] {verdict['reason']}"


def test_destructive_shell_prevented_before_execution(tmp_path):
    hook = _Hook(_client(tmp_path))
    result = hook.run_tool("bash", "rm -rf /")
    assert result.startswith("[block]")
    assert hook.executed == []  # PREVENTIVE: the tool never ran


def test_benign_tool_allowed_and_executed(tmp_path):
    hook = _Hook(_client(tmp_path))
    result = hook.run_tool("bash", "pwd")
    assert result == "executed"
    assert hook.executed == ["bash:pwd"]


def test_ssrf_url_prevented(tmp_path):
    hook = _Hook(_client(tmp_path))
    result = hook.run_tool("http_fetch", "http://169.254.169.254/latest/meta-data/")
    assert result.startswith("[block]")
    assert hook.executed == []


def test_nonallowlisted_shell_is_hitl_not_executed(tmp_path):
    hook = _Hook(_client(tmp_path))
    verdict = hook.client.post(
        "/api/_pretrace", json={"tool_name": "bash", "args": "ls -la /etc"}
    ).json()
    assert verdict["decision"] == "hitl"
    assert verdict["approval_id"]  # an approval to await before executing
    assert hook.run_tool("bash", "ls -la /etc").startswith("[hitl]")
    assert hook.executed == []  # waits for approval; does not run


def test_pretrace_fails_closed_without_engine(tmp_path):
    hook = _Hook(_client(tmp_path, with_engine=False))
    result = hook.run_tool("bash", "pwd")  # benign, but no engine to vouch → blocked
    assert result.startswith("[block]")
    assert hook.executed == []


def test_pretrace_token_gate(tmp_path):
    client = _client(tmp_path, trace_token="s3cret")
    assert (
        client.post("/api/_pretrace", json={"tool_name": "bash", "args": "pwd"}).status_code == 401
    )
    ok = client.post(
        "/api/_pretrace",
        json={"tool_name": "bash", "args": "pwd"},
        headers={"x-trace-token": "s3cret"},
    )
    assert ok.json()["decision"] == "allow"
