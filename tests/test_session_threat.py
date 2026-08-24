"""G9 — session-level threat accumulation.

A distributed multi-turn attack whose turns each pass the per-turn checks is caught once the session
threat score crosses the threshold; a benign long session never trips it. Uses only signals the
rails already produce (gray-band heuristic + blocked turns) — no new detector.
"""

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.engine import default_engine
from sec_guardrails.core.rail import TrustLevel
from sec_guardrails.rails.dialog.session_threat import SessionThreatTracker

# A gray-band probe: a lone persona shift / weak marker scores ~0.4 (below the 0.6 block threshold),
# so it passes per-turn but accumulates session threat.
GRAY_PROBE = "act as a friendly assistant"
BENIGN = "what's the weather today?"


def _engine(tmp_path, **kw):
    return default_engine(
        AuditLog(tmp_path / "audit.jsonl"),
        session_threat=SessionThreatTracker(),
        **kw,
    )


# ── the tracker unit ──────────────────────────────────────────────────────────


def test_tracker_escalates_after_repeated_gray_turns():
    t = SessionThreatTracker()
    s1 = t.observe("sess", text=GRAY_PROBE)
    s2 = t.observe("sess", text=GRAY_PROBE)
    assert not s1.escalated and not s2.escalated
    s3 = t.observe("sess", text=GRAY_PROBE)
    assert s3.escalated and s3.just_escalated
    assert t.is_escalated("sess")


def test_tracker_lowers_gray_threshold_and_forces_critic():
    t = SessionThreatTracker()
    assert t.gray_high("sess") == t.normal_gray_high
    for _ in range(3):
        t.observe("sess", text=GRAY_PROBE)
    assert t.gray_high("sess") == t.escalated_gray_high  # lowered
    assert t.force_critic("sess") is True


def test_benign_session_never_escalates():
    t = SessionThreatTracker()
    for _ in range(10):
        t.observe("sess", text=BENIGN)
    assert not t.is_escalated("sess")


def test_blocked_turn_weighs_more():
    t = SessionThreatTracker()
    s1 = t.observe("sess", text="x", blocked=True)  # +2
    assert not s1.escalated
    s2 = t.observe("sess", text=GRAY_PROBE)  # +1 → 3 → escalated
    assert s2.escalated


def test_sessions_are_isolated():
    t = SessionThreatTracker()
    for _ in range(3):
        t.observe("attacker", text=GRAY_PROBE)
    assert t.is_escalated("attacker")
    assert not t.is_escalated("victim")


# ── engine integration ────────────────────────────────────────────────────────


def test_engine_blocks_escalated_session_gray_input(tmp_path):
    engine = _engine(tmp_path)
    # Turns 1 & 2: gray probes pass per-turn.
    assert engine.guard_input(GRAY_PROBE, trust=TrustLevel.UNTRUSTED, session="s").allowed
    assert engine.guard_input(GRAY_PROBE, trust=TrustLevel.UNTRUSTED, session="s").allowed
    # Turn 3 crosses the threshold → the same gray input is now blocked under the lowered threshold.
    third = engine.guard_input(GRAY_PROBE, trust=TrustLevel.UNTRUSTED, session="s")
    assert not third.allowed
    assert third.stage == "session_threat"


def test_engine_audits_escalation(tmp_path):
    engine = _engine(tmp_path)
    for _ in range(3):
        engine.guard_input(GRAY_PROBE, trust=TrustLevel.UNTRUSTED, session="s")
    recs = engine.audit.read_all()
    assert any(r.get("decision") == "session_escalated" for r in recs)


def test_engine_without_session_is_per_turn_only(tmp_path):
    engine = _engine(tmp_path)
    # No session id → no accumulation; gray probes always pass.
    for _ in range(5):
        assert engine.guard_input(GRAY_PROBE, trust=TrustLevel.UNTRUSTED).allowed


def test_default_engine_has_no_session_threat(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"))
    assert engine.session_threat is None
