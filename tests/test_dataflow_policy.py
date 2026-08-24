"""N3 — CaMeL data-flow / sink capability policy.

A sink deny-by-default rejects an arg whose capability label carries an untrusted source not on that
sink's allow-list — blocking "read untrusted data → exfil over a sink" while allowing a legitimate
same-source flow. Exercised standalone and via the engine.
"""

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.engine import default_engine
from sec_guardrails.rails.reasoning.dataflow import DataFlowPolicy, DataFlowResult
from sec_guardrails.rails.tool.policy import Effect, ToolCall


def _policy():
    # send_email may carry user data only; http_fetch may carry web/user data.
    return DataFlowPolicy(
        sink_allowed_sources={
            "send_email": {"user"},
            "http_fetch": {"user", "web", "tool:http_fetch"},
        }
    )


def test_untrusted_source_to_sink_blocked():
    call = ToolCall(
        "send_email",
        {"body": "here is the leaked page"},
        arg_sources={"body": {"tool:http_fetch"}},  # web data flowing into email
    )
    result = _policy().check(call)
    assert isinstance(result, DataFlowResult)
    assert not result.allowed
    assert "tool:http_fetch" in result.reason


def test_same_source_flow_allowed():
    # Web data flowing back to a web fetch (same trust domain) is fine.
    call = ToolCall(
        "http_fetch",
        {"url": "https://api.example.com"},
        arg_sources={"url": {"web"}},
    )
    assert _policy().check(call).allowed


def test_trusted_user_source_always_allowed():
    call = ToolCall("send_email", {"body": "hello"}, arg_sources={"body": {"user"}})
    assert _policy().check(call).allowed


def test_ungoverned_sink_has_no_opinion():
    call = ToolCall("calc", {"expr": "1+1"}, arg_sources={"expr": {"tool:http_fetch"}})
    assert _policy().check(call).allowed  # calc isn't a governed sink


def test_no_arg_sources_means_no_opinion():
    call = ToolCall("send_email", {"body": "x"})  # no provenance recorded
    assert _policy().check(call).allowed


def test_engine_blocks_cross_source_exfil(tmp_path):
    engine = default_engine(
        AuditLog(tmp_path / "a.jsonl"),
        dataflow=_policy(),
    )
    call = ToolCall(
        "send_email",
        {"body": "secret contents from a fetched page"},
        arg_sources={"body": {"tool:http_fetch"}},
    )
    verdict = engine.guard_tool(call, now=0.0)
    assert verdict.effect is Effect.BLOCK
    assert verdict.stage == "dataflow"


def test_engine_default_has_no_dataflow(tmp_path):
    # Backward-compatible: without an explicit policy, the data-flow gate is a no-op.
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"))
    assert engine.dataflow is None
