from rails.reasoning.taint import TaintGate, TaintTracker
from rails.tool.hitl import ApprovalStatus, HITLManager
from rails.tool.policy import Effect, PolicyEngine, ToolCall

# ── T28 taint + trusted-action invariant ─────────────────────────────────────


def test_invariant_blocks_tainted_sensitive_tool():
    # bash "ls" is allowed by policy, but a tainted arg trips the trusted-action invariant.
    gate = TaintGate(PolicyEngine())
    call = ToolCall("bash", {"cmd": "ls"}, tainted_args={"cmd"})
    assert gate.decide(call).effect is Effect.BLOCK


def test_invariant_allows_untainted_sensitive_tool():
    gate = TaintGate(PolicyEngine())
    assert gate.decide(ToolCall("bash", {"cmd": "ls"})).effect is Effect.ALLOW


def test_invariant_ignores_nonsensitive_tool():
    gate = TaintGate(PolicyEngine())
    # read_file is allowed and not in the sensitive set → taint doesn't downgrade it.
    call = ToolCall("read_file", {"path": "x"}, tainted_args={"path"})
    assert gate.decide(call).effect is Effect.ALLOW


def test_tracker_marks_args_from_untrusted_origin():
    tracker = TaintTracker(["SECRET-FROM-EMAIL"])
    call = ToolCall("bash", {"cmd": "echo SECRET-FROM-EMAIL"})
    assert tracker.taint_of(call) == {"cmd"}


def test_gate_uses_tracker_to_block():
    tracker = TaintTracker(["evil.com"])
    gate = TaintGate(PolicyEngine(), tracker=tracker)
    # api_call to an allowlisted host, but body carries untrusted text → invariant blocks.
    call = ToolCall("api_call", {"host": "good.com", "body": "see evil.com"})
    assert gate.decide(call).effect is Effect.BLOCK


# ── T23 HITL approval lifecycle ──────────────────────────────────────────────


def test_request_is_pending():
    mgr = HITLManager()
    ap = mgr.request(ToolCall("send_email", {"to": "x"}), now=1000.0)
    assert ap.status is ApprovalStatus.PENDING
    assert mgr.is_allowed(ap.id, now=1000.0) is False  # pending != allowed


def test_approved_then_allowed():
    mgr = HITLManager()
    mgr.request(ToolCall("send_email", {}), now=0.0, approval_id="a1")
    mgr.resolve("a1", approved=True)
    assert mgr.is_allowed("a1", now=10.0) is True


def test_rejected_is_not_allowed():
    mgr = HITLManager()
    mgr.request(ToolCall("bash", {}), now=0.0, approval_id="a2")
    mgr.resolve("a2", approved=False)
    assert mgr.is_allowed("a2", now=10.0) is False


def test_timeout_defaults_to_deny():
    mgr = HITLManager(ttl_seconds=60.0)
    mgr.request(ToolCall("bash", {}), now=0.0, approval_id="a3")
    mgr.resolve("a3", approved=True)
    assert mgr.is_allowed("a3", now=10.0) is True  # within ttl
    assert mgr.is_allowed("a3", now=120.0) is False  # expired → default deny


def test_unknown_id_denied():
    assert HITLManager().is_allowed("nope", now=0.0) is False
