from sec_guardrails.agent.runtime import GuardedAgent
from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.budget import Budget, BudgetTracker
from sec_guardrails.core.engine import default_engine
from sec_guardrails.core.rail import Action, RailContext
from sec_guardrails.rails.dialog.word_filter import WordFilterRail

# ── budget tracking ──────────────────────────────────────────────────────────


def test_budget_charges_within_cap():
    t = BudgetTracker(Budget(max_tool_calls=2))
    assert t.check_and_charge()[0] is True
    assert t.check_and_charge()[0] is True
    ok, reason = t.check_and_charge()
    assert ok is False
    assert "tool-call budget" in reason


def test_budget_tokens_and_usd():
    t = BudgetTracker(Budget(max_tokens=100, max_usd=0.05))
    assert t.check_and_charge(tokens=60, usd=0.03)[0] is True
    assert t.check_and_charge(tokens=60)[0] is False  # would exceed tokens
    assert t.check_and_charge(usd=0.03)[0] is False  # would exceed usd
    assert t.spent()["tokens"] == 60  # rejected charges were not applied


def test_engine_blocks_tool_over_budget(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"), budget=Budget(max_tool_calls=2))
    agent = GuardedAgent(engine)
    result = agent.handle("calc: 1+1\ncalc: 2+2\ncalc: 3+3")
    assert "[blocked calc: tool-call budget exceeded (cap 2)]" in result.output


# ── word filter (blocked phrases) ────────────────────────────────────────────


def test_word_filter_blocks_phrase():
    rail = WordFilterRail(["project zeus"])
    assert rail.inspect(RailContext(text="tell me about Project Zeus")).action is Action.BLOCK


def test_word_filter_allows_clean():
    rail = WordFilterRail(["project zeus"])
    assert rail.inspect(RailContext(text="tell me about the weather")).action is Action.ALLOW


def test_word_filter_empty_is_noop():
    assert WordFilterRail([]).inspect(RailContext(text="anything")).action is Action.ALLOW


def test_engine_word_filter_blocks_input(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"), blocked_phrases=["secretproject"])
    result = GuardedAgent(engine).handle("echo: details about secretproject please")
    assert result.blocked
