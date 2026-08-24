"""G4 — L7 critic degradation is surfaced, not silent; + critic calibration (FP/FN split).

Covers: the LLM critic marks judge errors / unparseable output as `degraded`; the engine emits a
distinct CRITIC_DEGRADED audit decision, an OTel health event, and an operator hook (so an attacker
who forces the judge to time out can't silently disable L7); and `measure_critic` reports the
critic's own FP/FN rate split.
"""

from types import SimpleNamespace

import pytest

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.engine import default_engine
from sec_guardrails.core.otel import setup_tracing
from sec_guardrails.eval.critic_calibration import default_corpus, measure_critic
from sec_guardrails.rails.oversight.critic import Trajectory, Verdict
from sec_guardrails.rails.oversight.llm_critic import LLMCritic, _parse_verdict


class _FakeCompletions:
    def __init__(self, outer):
        self._outer = outer

    def create(self, **kwargs):
        if self._outer.raise_exc is not None:
            raise self._outer.raise_exc
        msg = SimpleNamespace(content=self._outer.content)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


class FakeLLM:
    def __init__(self, content='{"ok": true, "reason": "on task"}', raise_exc=None):
        self.content = content
        self.raise_exc = raise_exc
        self.chat = SimpleNamespace(completions=_FakeCompletions(self))


# ── the critic marks degradation ──────────────────────────────────────────────


def test_error_fail_open_is_degraded_but_ok():
    v = LLMCritic(FakeLLM(raise_exc=RuntimeError("timeout")), model="m").review(Trajectory("x"))
    assert v.ok is True and v.degraded is True


def test_error_fail_closed_is_degraded_and_flagged():
    v = LLMCritic(FakeLLM(raise_exc=RuntimeError("timeout")), model="m", fail_open=False).review(
        Trajectory("x")
    )
    assert v.ok is False and v.degraded is True


def test_unparseable_is_degraded():
    v = LLMCritic(FakeLLM(content="the model rambled, no json"), model="m").review(Trajectory("x"))
    assert v.degraded is True


def test_genuine_verdict_is_not_degraded():
    v = LLMCritic(FakeLLM(content='{"ok": false, "reason": "drift"}'), model="m").review(
        Trajectory("x")
    )
    assert v.ok is False and v.degraded is False


def test_parse_verdict_fail_closed_marks_degraded():
    v = _parse_verdict("no json here", fail_open=False)
    assert v.ok is False and v.degraded is True


# ── the engine surfaces degradation ───────────────────────────────────────────


def test_engine_records_critic_degraded_and_fires_hook(tmp_path):
    seen = {}
    engine = default_engine(
        AuditLog(tmp_path / "a.jsonl"),
        critic=LLMCritic(FakeLLM(raise_exc=RuntimeError("boom")), model="m"),
        on_critic_degraded=lambda v: seen.setdefault("v", v),
    )
    engine.review(Trajectory(task="t", steps=["calc"], output="x"))
    recs = engine.audit.read_all()
    degraded = [r for r in recs if r.get("decision") == "critic_degraded"]
    assert len(degraded) == 1
    assert degraded[0]["stage"] == "oversight"
    assert seen["v"].degraded is True  # operator hook received the degraded verdict


def test_engine_does_not_record_degraded_for_genuine_verdict(tmp_path):
    engine = default_engine(
        AuditLog(tmp_path / "a.jsonl"),
        critic=LLMCritic(FakeLLM(content='{"ok": true, "reason": "fine"}'), model="m"),
    )
    engine.review(Trajectory(task="t", output="x"))
    recs = engine.audit.read_all()
    assert not any(r.get("decision") == "critic_degraded" for r in recs)
    assert any(r.get("decision") == "allow" and r.get("stage") == "oversight" for r in recs)


def test_engine_emits_otel_health_event_on_degradation(tmp_path):
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    tracer = setup_tracing(exporter)
    engine = default_engine(
        AuditLog(tmp_path / "a.jsonl"),
        critic=LLMCritic(FakeLLM(raise_exc=RuntimeError("boom")), model="m"),
        tracer=tracer,
    )
    engine.review(Trajectory(task="t", output="x"))
    names = [s.name for s in exporter.get_finished_spans()]
    assert "oversight.critic_degraded" in names


# ── calibration: FP/FN reported split ─────────────────────────────────────────


class _AlwaysOK:
    name = "always-ok"

    def review(self, traj):
        return Verdict(True, "ok")


class _Oracle:
    """A perfect critic (uses a heuristic keyword) — for the calibration floor."""

    name = "oracle"

    def review(self, traj):
        text = (traj.output + " " + " ".join(traj.steps)).lower()
        bad = any(k in text for k in ("rm -rf", "drop table", "api keys", "attacker@", "offsite"))
        return Verdict(not bad, "drift" if bad else "on-task")


def test_always_ok_critic_has_high_fnr_zero_fpr():
    cal = measure_critic(_AlwaysOK())
    assert cal.fpr == 0.0
    assert cal.fnr == 1.0  # misses every unsafe trajectory
    assert cal.false_negatives == cal.unsafe


def test_oracle_critic_is_clean():
    cal = measure_critic(_Oracle())
    assert cal.fpr == 0.0 and cal.fnr == 0.0
    assert cal.as_dict()["degraded"] == 0


def test_degraded_verdicts_excluded_from_rates():
    class _AllDegraded:
        name = "degraded"

        def review(self, traj):
            return Verdict(True, "unavailable", degraded=True)

    cal = measure_critic(_AllDegraded())
    corpus = default_corpus()
    assert cal.degraded == len(corpus)
    # every row degraded → no judged rows → rates are 0 (not counted as passes)
    assert cal.false_negatives == 0 and cal.false_positives == 0
    assert cal.fnr == 0.0 and cal.fpr == 0.0
