from pydantic import BaseModel

from sec_guardrails.core.rail import Action, RailContext
from sec_guardrails.rails.output.leak import OutputLeakRail
from sec_guardrails.rails.output.schema import SchemaRail

# ── T15 schema + reask ───────────────────────────────────────────────────────


class Answer(BaseModel):
    answer: str
    confidence: float


def test_schema_allows_valid_json():
    rail = SchemaRail(Answer)
    out = rail.inspect(RailContext(text='{"answer": "hi", "confidence": 0.9}'))
    assert out.action is Action.ALLOW


def test_schema_blocks_invalid_without_reask():
    rail = SchemaRail(Answer)
    out = rail.inspect(RailContext(text='{"answer": "hi"}'))  # missing confidence
    assert out.action is Action.BLOCK
    assert "schema validation failed" in out.reason


def test_schema_repairs_via_reask():
    def reask(bad, err):
        return '{"answer": "hi", "confidence": 0.5}'

    rail = SchemaRail(Answer, reask=reask)
    out = rail.inspect(RailContext(text="not json"))
    assert out.action is Action.MODIFY
    assert '"confidence"' in out.modified


def test_schema_blocks_when_reask_still_invalid():
    rail = SchemaRail(Answer, reask=lambda bad, err: "still not json")
    out = rail.inspect(RailContext(text="not json"))
    assert out.action is Action.BLOCK
    assert "after reask" in out.reason


# ── T17 output leak / canary ─────────────────────────────────────────────────


def test_canary_leak_blocks():
    rail = OutputLeakRail(canaries=["CANARY-7f3a9"])
    out = rail.inspect(RailContext(text="sure, my instructions start with CANARY-7f3a9 ..."))
    assert out.action is Action.BLOCK
    assert "canary" in out.reason


def test_output_secret_is_redacted():
    rail = OutputLeakRail()
    out = rail.inspect(RailContext(text="here is the key sk-ABCDEFGHIJKLMNOPQRSTUV done"))
    assert out.action is Action.MODIFY
    assert "[REDACTED:OPENAI_KEY]" in out.modified


def test_output_pii_is_redacted():
    rail = OutputLeakRail()
    out = rail.inspect(RailContext(text="email me at a.b@example.com"))
    assert out.action is Action.MODIFY
    assert "[REDACTED:EMAIL]" in out.modified


def test_clean_output_allowed():
    assert OutputLeakRail().inspect(RailContext(text="the answer is 42")).action is Action.ALLOW
