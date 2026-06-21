from core.rail import Action, RailContext
from rails.input.pii import HeuristicPIIDetector, PIIDetector, PIIRail


def test_heuristic_is_a_detector():
    assert isinstance(HeuristicPIIDetector(), PIIDetector)


def test_redacts_email_and_ssn():
    ctx = RailContext(text="reach me at jane.doe@example.com, SSN 123-45-6789")
    decision = PIIRail().inspect(ctx)
    assert decision.action is Action.MODIFY
    assert "jane.doe@example.com" not in decision.modified
    assert "123-45-6789" not in decision.modified
    assert "[REDACTED:EMAIL]" in decision.modified
    assert "[REDACTED:SSN]" in decision.modified
    assert set(ctx.metadata["pii_entities"]) >= {"EMAIL", "SSN"}


def test_redacts_credit_card_and_phone():
    out = PIIRail().inspect(RailContext(text="card 4111 1111 1111 1111 call 555-123-4567"))
    assert out.action is Action.MODIFY
    assert "[REDACTED:CREDIT_CARD]" in out.modified
    assert "[REDACTED:PHONE]" in out.modified


def test_allows_clean_text():
    assert PIIRail().inspect(RailContext(text="let's meet on Tuesday")).action is Action.ALLOW


def test_allowlist_exempts_entity_type():
    # A network-ops agent may keep IPs; they should pass through unredacted.
    rail = PIIRail(allow={"IP"})
    out = rail.inspect(RailContext(text="server at 10.0.0.5"))
    assert out.action is Action.ALLOW
