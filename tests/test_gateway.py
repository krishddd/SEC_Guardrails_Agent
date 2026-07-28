from fastapi.testclient import TestClient

from sec_guardrails.gateway.app import create_app


class FakeOdysseus:
    """Stand-in upstream that records what the gateway forwarded."""

    def __init__(self):
        self.last = None

    def chat(self, message, *, model=None, session=None):
        self.last = (message, model, session)
        return {"response": f"echo:{message}", "session_id": "s", "model": model or "m"}

    def health_check(self):
        return {"status_code": 200, "reachable": True, "body": {"status": "ok"}}


def test_passthrough_returns_upstream_unchanged():
    fake = FakeOdysseus()
    out = TestClient(create_app(fake)).post("/api/v1/chat", json={"message": "hi"}).json()
    assert out == {"response": "echo:hi", "session_id": "s", "model": "m"}
    assert fake.last == ("hi", None, None)  # forwarded faithfully, unmutated


def test_passthrough_forwards_model_and_session():
    fake = FakeOdysseus()
    TestClient(create_app(fake)).post(
        "/api/v1/chat", json={"message": "hi", "model": "x", "session": "sess"}
    )
    assert fake.last == ("hi", "x", "sess")


def test_health_reports_odysseus():
    body = TestClient(create_app(FakeOdysseus())).get("/health").json()
    assert body["gateway"] == "ok"
    assert body["odysseus"]["reachable"] is True


def test_upstream_error_becomes_502():
    class Boom:
        def chat(self, *a, **k):
            raise RuntimeError("down")

        def health_check(self):
            return {"reachable": False}

    resp = TestClient(create_app(Boom())).post("/api/v1/chat", json={"message": "hi"})
    assert resp.status_code == 502
