from core.audit import AuditLog
from core.engine import default_engine
from core.rail import Action, RailContext
from eval.governance import export, taxonomy_breakdown
from eval.taxonomy import classify
from rails.tool.code_shield import CodeShieldRail


def _shield(code: str) -> Action:
    return CodeShieldRail().inspect(RailContext(text=code)).action


# ── CodeShield ───────────────────────────────────────────────────────────────


def test_codeshield_blocks_dangerous_codegen():
    assert _shield("result = eval(user_input)") is Action.BLOCK
    assert _shield("pickle.loads(data)") is Action.BLOCK
    assert _shield("subprocess.run(cmd, shell=True)") is Action.BLOCK
    assert _shield("os.system('rm x')") is Action.BLOCK
    assert _shield("requests.get(u, verify=False)") is Action.BLOCK


def test_codeshield_allows_clean_code():
    assert _shield("def add(a, b):\n    return a + b") is Action.ALLOW


def test_engine_guard_code(tmp_path):
    engine = default_engine(AuditLog(tmp_path / "a.jsonl"))
    assert engine.guard_code("x = eval(y)").allowed is False
    assert engine.guard_code("total = a + b").allowed is True


# ── AgentDoG taxonomy ────────────────────────────────────────────────────────


def test_classify_maps_stages_to_failure_modes():
    assert classify("exec_gate", "destructive shell")["failure_mode"] == "unsafe_command"
    assert classify("egress", "non-public ip")["failure_mode"] == "ssrf"
    assert classify("input", "prompt-injection")["failure_mode"] == "instruction_hijack"
    assert classify("memory", "poison")["failure_mode"] == "memory_poisoning"
    assert classify("output", "canary")["failure_mode"] == "sensitive_disclosure"


def test_governance_export_includes_taxonomy():
    records = [
        {"decision": "block", "stage": "exec_gate", "reason": "destructive shell command"},
        {"decision": "block", "stage": "input", "reason": "prompt-injection suspected"},
        {"decision": "allow", "stage": "tool"},
    ]
    breakdown = taxonomy_breakdown(records)
    assert breakdown["unsafe_command"] == 1
    assert breakdown["instruction_hijack"] == 1
    assert "taxonomy" in export(records)
