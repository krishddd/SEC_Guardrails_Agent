from eval.governance import CONTROL_MAP, export, summarize

RECORDS = [
    {"decision": "allow", "endpoint": "/api/v1/chat"},
    {"decision": "block", "endpoint": "/api/v1/chat", "reason": "prompt-injection suspected"},
    {"decision": "modify", "endpoint": "/api/v1/chat", "reason": "redacted secrets"},
    {"decision": "hitl", "endpoint": "/api/tools", "reason": "irreversible tool"},
    {"decision": "error", "endpoint": "/api/v1/chat", "reason": "odysseus down"},
]


def test_summary_counts():
    rep = summarize(RECORDS)
    assert rep.total == 5
    assert rep.by_decision["block"] == 1
    assert rep.by_decision["allow"] == 1
    assert rep.by_endpoint["/api/v1/chat"] == 4


def test_block_reasons_include_errors():
    rep = summarize(RECORDS)
    assert "prompt-injection suspected" in rep.block_reasons
    assert "odysseus down" in rep.block_reasons  # error counts as a block-class reason
    assert len(rep.block_reasons) == 2


def test_controls_evidenced_cover_record_keeping_and_oversight():
    rep = summarize(RECORDS)
    assert "Art. 12 (record-keeping)" in rep.controls_evidenced  # any record
    assert "Art. 14 (human oversight)" in rep.controls_evidenced  # from the hitl decision
    assert "GOVERN 4.1" in rep.controls_evidenced


def test_empty_audit_evidences_nothing():
    rep = summarize([])
    assert rep.total == 0
    assert rep.controls_evidenced == []


def test_export_is_self_describing():
    out = export(RECORDS)
    assert out["summary"]["total"] == 5
    assert out["summary"]["block_count"] == 2
    assert out["control_map"] == CONTROL_MAP  # the report carries its own mapping
