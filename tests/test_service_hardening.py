"""G10 — service hardening: latency gate, policy hot-reload, SIEM forwarding.

Latency: deterministic hot-path rails stay within their <30 ms budget (measured p50, gatable in CI).
Hot-reload: a policy-file edit takes effect without a restart, with a versioned audit event.
SIEM: block/redact/hitl decisions are forwarded to a sink; routine allows are not.
"""

import json

from sec_guardrails.core.audit import AuditLog
from sec_guardrails.core.rail import RailContext
from sec_guardrails.eval.latency import measure_latency
from sec_guardrails.rails.input.secrets import SecretsRail
from sec_guardrails.rails.input.spotlight import SpotlightRail
from sec_guardrails.rails.tool.policy import ToolCall
from sec_guardrails.rails.tool.policy_reload import ReloadablePolicyEngine

# ── G10.1 latency gate ────────────────────────────────────────────────────────


def test_deterministic_input_rails_within_hot_path_budget():
    text = "contact a.b@example.com, key sk-ABCDEFGHIJKLMNOPQRSTUV, visit https://example.com/x"
    for rail in (SecretsRail(), SpotlightRail()):
        result = measure_latency(
            rail.name,
            lambda r=rail: r.inspect(RailContext(text=text)),
            runs=50,
            budget_ms=30.0,  # the <30 ms deterministic hot-path budget
        )
        assert result.within_budget, f"{rail.name} p50={result.p50_ms:.2f}ms over 30ms budget"
        assert result.p95_ms >= result.p50_ms
        assert result.as_dict()["within_budget"] is True


# ── G10.2 policy hot-reload ───────────────────────────────────────────────────

_POLICY_V1 = {
    "version": "1",
    "default_effect": "block",
    "rules": [{"id": "allow-echo", "tool": "echo", "effect": "allow"}],
}
_POLICY_V2 = {
    "version": "2",
    "default_effect": "block",
    "rules": [
        {"id": "allow-echo", "tool": "echo", "effect": "allow"},
        {"id": "allow-calc", "tool": "calc", "effect": "allow"},
    ],
}


def _write_policy(path, policy):
    path.write_text(json.dumps(policy), encoding="utf-8")


def test_policy_reloads_on_change_without_restart(tmp_path):
    path = tmp_path / "policy.json"
    _write_policy(path, _POLICY_V1)
    reloads = []
    engine = ReloadablePolicyEngine(path, on_reload=lambda info: reloads.append(info))

    assert engine.evaluate(ToolCall("calc", {})).effect.value == "block"  # not allowed in v1
    assert engine.version == "1"

    _write_policy(path, _POLICY_V2)
    # Ensure the mtime actually differs even on coarse-resolution clocks.
    import os

    os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 5))

    assert engine.evaluate(ToolCall("calc", {})).effect.value == "allow"  # v2 in effect, no restart
    assert engine.version == "2"
    assert reloads and reloads[-1]["new_version"] == "2"
    assert reloads[-1]["old_version"] == "1"


def test_malformed_policy_keeps_last_good(tmp_path):
    path = tmp_path / "policy.json"
    _write_policy(path, _POLICY_V1)
    engine = ReloadablePolicyEngine(path)
    path.write_text("{ not valid json", encoding="utf-8")
    import os

    os.utime(path, (path.stat().st_atime, path.stat().st_mtime + 5))
    # Fail safe: the last-good v1 policy stays active, not an empty deny-all-that-changed policy.
    assert engine.evaluate(ToolCall("echo", {})).effect.value == "allow"
    assert engine.version == "1"


# ── G10.3 SIEM forwarding ─────────────────────────────────────────────────────


def test_security_decisions_forwarded_to_siem(tmp_path):
    forwarded = []
    audit = AuditLog(tmp_path / "a.jsonl", siem_sink=forwarded.append)
    audit.record(decision="allow", stage="input")  # routine — NOT forwarded
    audit.record(decision="block", stage="tool", reason="destructive")  # forwarded
    audit.record(decision="redact", stage="output")  # forwarded
    decisions = [r["decision"] for r in forwarded]
    assert decisions == ["block", "redact"]


def test_siem_outage_does_not_break_audit(tmp_path):
    def boom(_record):
        raise RuntimeError("siem down")

    audit = AuditLog(tmp_path / "a.jsonl", siem_sink=boom)
    rec = audit.record(decision="block", stage="tool")  # must not raise
    assert rec["decision"] == "block"
    assert len(audit.read_all()) == 1  # the record was still written locally
