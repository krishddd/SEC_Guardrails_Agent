import pytest

from rails.tool.exec_gate import ExecGate
from rails.tool.policy import Effect, PolicyEngine, ToolCall

# ── destructive shell (hard block) ───────────────────────────────────────────

DESTRUCTIVE = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf *",
    "sudo rm -fr /home",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:",
    "shutdown -h now",
    "chmod -R 777 /",
]


@pytest.mark.parametrize("cmd", DESTRUCTIVE, ids=[c[:18] for c in DESTRUCTIVE])
def test_destructive_shell_blocked(cmd):
    assert ExecGate().check_shell(cmd).effect is Effect.BLOCK


def test_safe_shell_allowed():
    assert ExecGate().check_shell("ls -la /tmp").effect is Effect.ALLOW


def test_inspect_dispatches_shell():
    gate = ExecGate()
    assert gate.inspect(ToolCall("bash", {"cmd": "rm -rf /"})).effect is Effect.BLOCK


# ── SQL safety ───────────────────────────────────────────────────────────────


def test_sql_ddl_blocked():
    assert ExecGate().check_sql("DROP TABLE users").effect is Effect.BLOCK


def test_unscoped_delete_blocked():
    assert ExecGate().check_sql("DELETE FROM users").effect is Effect.BLOCK


def test_scoped_delete_allowed():
    assert ExecGate().check_sql("DELETE FROM users WHERE id=1").effect is Effect.ALLOW


def test_select_gets_limit_injected():
    decision = ExecGate(max_rows=500).check_sql("SELECT * FROM users")
    assert decision.effect is Effect.ALLOW
    assert decision.new_args == {"query": "SELECT * FROM users LIMIT 500"}


def test_select_with_limit_untouched():
    decision = ExecGate().check_sql("SELECT * FROM users LIMIT 10")
    assert decision.new_args is None


# ── RBAC on the policy engine (ADR-0008) ─────────────────────────────────────


def test_rbac_rule_applies_only_to_listed_roles():
    policy = {
        "version": "t",
        "default_effect": "block",
        "rules": [
            {"id": "admin-bash", "tool": "bash", "roles": ["admin"], "effect": "allow"},
        ],
    }
    engine = PolicyEngine(policy=policy)
    assert engine.evaluate(ToolCall("bash", {"cmd": "ls"}, role="admin")).effect is Effect.ALLOW
    # A non-admin role hits no matching rule → deny-by-default.
    assert engine.evaluate(ToolCall("bash", {"cmd": "ls"}, role="guest")).effect is Effect.BLOCK
    assert engine.evaluate(ToolCall("bash", {"cmd": "ls"})).effect is Effect.BLOCK  # no role
