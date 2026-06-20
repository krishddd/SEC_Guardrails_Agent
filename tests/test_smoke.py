"""Scaffold smoke tests — prove the package imports and the stub agent answers.

These are placeholders that real tasks (T2+) replace/expand with per-rail tests.
"""

from fastapi.testclient import TestClient

from stub_agent.app import app


def test_core_imports():
    import core

    assert core.__version__


def test_stub_health():
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_stub_chat_contract():
    client = TestClient(app)
    resp = client.post("/api/v1/chat", json={"message": "hello"})
    assert resp.status_code == 200
    body = resp.json()
    # The gateway depends on exactly these keys.
    assert set(body) == {"response", "session_id", "model"}
    assert "hello" in body["response"]
