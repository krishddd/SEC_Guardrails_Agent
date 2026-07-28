import pytest
from fastapi.testclient import TestClient

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.otel import setup_tracing
from sec_guardrails.gateway.app import create_app


class FakeClient:
    def chat(self, message, **kw):
        return {"response": message, "session_id": "s", "model": "m"}

    def health_check(self):
        return {"reachable": True}


def test_audit_one_record_per_call(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    gateway = create_app(FakeClient(), audit=audit)
    TestClient(gateway).post("/api/v1/chat", json={"message": "hi"})
    records = audit.read_all()
    assert len(records) == 1
    assert records[0]["decision"] == "allow"
    assert records[0]["endpoint"] == "/api/v1/chat"
    assert "ts" in records[0] and "id" in records[0]


def test_one_span_per_call(tmp_path):
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    tracer = setup_tracing(exporter)
    assert tracer is not None
    audit = AuditLog(tmp_path / "a.jsonl")
    gateway = create_app(FakeClient(), audit=audit, tracer=tracer)
    TestClient(gateway).post("/api/v1/chat", json={"message": "hi"})
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "gateway.chat"
