"""T21 happy-path + T22 adversarial bypass tests for the L4 policy engine.

The adversarial set (per ADR-0004) probes guardrail failure modes: deny-by-default, arg-smuggling,
tainted args, SSRF/internal hosts, and fail-closed on bad input.
"""

from sec_guardrails.rails.tool.policy import Effect, PolicyEngine, ToolCall

# ── T21 happy path (default versioned policy) ────────────────────────────────


def test_read_only_allowed():
    assert PolicyEngine().evaluate(ToolCall("read_file")).effect is Effect.ALLOW


def test_safe_bash_allowed():
    assert PolicyEngine().evaluate(ToolCall("bash", {"cmd": "ls"})).effect is Effect.ALLOW


def test_irreversible_tool_requires_hitl():
    assert PolicyEngine().evaluate(ToolCall("create_document", {"name": "x"})).effect is Effect.HITL


def test_allowlisted_api_untainted_allowed():
    call = ToolCall("api_call", {"host": "good.com"})
    assert PolicyEngine().evaluate(call).effect is Effect.ALLOW


# ── T22 adversarial / fail-closed ────────────────────────────────────────────


def test_unknown_tool_denied_by_default():
    res = PolicyEngine().evaluate(ToolCall("delete_everything"))
    assert res.effect is Effect.BLOCK
    assert "deny-by-default" in res.reason


def test_bash_arg_smuggling_not_auto_allowed():
    # "ls; rm -rf /" must NOT satisfy the safe-bash regex (fullmatch), so it can't be auto-allowed.
    res = PolicyEngine().evaluate(ToolCall("bash", {"cmd": "ls; rm -rf /"}))
    assert res.effect is not Effect.ALLOW
    assert res.effect is Effect.HITL  # falls through to the bash-other rule


def test_tainted_args_block_allowlisted_api():
    # Right host, but a tainted arg → the no_untrusted_taint predicate fails → default deny.
    call = ToolCall("api_call", {"host": "good.com", "body": "x"}, tainted_args={"body"})
    assert PolicyEngine().evaluate(call).effect is Effect.BLOCK


def test_internal_host_denied():
    # SSRF/exfil: non-allowlisted host (e.g. cloud metadata) is not allowed → default deny.
    call = ToolCall("api_call", {"host": "169.254.169.254"})
    assert PolicyEngine().evaluate(call).effect is Effect.BLOCK


def test_empty_policy_fails_closed():
    engine = PolicyEngine(policy={})
    assert engine.evaluate(ToolCall("read_file")).effect is Effect.BLOCK


def _bash_ls_effect(rules: list) -> Effect:
    policy = {"version": "t", "default_effect": "block", "rules": rules}
    return PolicyEngine(policy=policy).evaluate(ToolCall("bash", {"cmd": "ls"})).effect


def test_unknown_predicate_op_fails_closed():
    rules = [{"id": "x", "tool": "bash", "when": [{"op": "totally_bogus"}], "effect": "allow"}]
    assert _bash_ls_effect(rules) is Effect.BLOCK


def test_bad_regex_predicate_fails_closed():
    rules = [
        {
            "id": "x",
            "tool": "bash",
            "when": [{"arg": "cmd", "op": "matches", "value": "("}],
            "effect": "allow",
        }
    ]
    assert _bash_ls_effect(rules) is Effect.BLOCK


def test_regex_tool_match_is_anchored():
    # A rule for tool "bash" must not match "bashful" (fullmatch, not search).
    policy = {
        "version": "t",
        "default_effect": "block",
        "rules": [{"id": "x", "tool": "bash", "effect": "allow"}],
    }
    assert PolicyEngine(policy=policy).evaluate(ToolCall("bashful")).effect is Effect.BLOCK
