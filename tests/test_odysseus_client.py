import httpx
import pytest

from gateway.odysseus_client import OdysseusClient, OdysseusError


def make_client(handler, **kw):
    transport = httpx.MockTransport(handler)
    hc = httpx.Client(transport=transport)
    return OdysseusClient("http://odyssey", "tok", client=hc, sleep=lambda *_: None, **kw)


def test_chat_success():
    def handler(req):
        assert req.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={"response": "hi", "session_id": "s", "model": "m"})

    assert make_client(handler).chat("yo")["response"] == "hi"


def test_4xx_terminal_no_retry():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(422, text="bad body")

    client = make_client(handler, max_retries=3)
    with pytest.raises(OdysseusError) as exc:
        client.chat("yo")
    assert exc.value.status == 422
    assert calls["n"] == 1  # 4xx is terminal — no retries


def test_5xx_retried_then_error():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(503, text="busy")

    with pytest.raises(OdysseusError):
        make_client(handler, max_retries=2).chat("yo")
    assert calls["n"] == 3  # initial + 2 retries


def test_network_error_retried_then_error():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        raise httpx.ConnectError("down")

    with pytest.raises(OdysseusError):
        make_client(handler, max_retries=1).chat("yo")
    assert calls["n"] == 2  # initial + 1 retry
