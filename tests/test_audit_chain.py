"""G5 — tamper-evident audit hash chain + `sec-guardrails audit verify`.

Proves an unmodified log verifies clean, and that editing, deleting, reordering, or corrupting a
record is detected (with the offending line reported); that HMAC signatures catch a fully-rebuilt
chain when a key is set; that the chain continues across a restart; and that the CLI exits non-zero
on tampering.
"""

import json

from sec_guardrails.cli import main
from sec_guardrails.core.audit import AuditLog, verify_audit_chain


def _log(tmp_path, n=3, **kw):
    audit = AuditLog(tmp_path / "audit.jsonl", **kw)
    for i in range(n):
        audit.record(decision="allow", stage="input", seq=i)
    return audit


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _write(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_clean_chain_verifies(tmp_path):
    _log(tmp_path)
    report = verify_audit_chain(tmp_path / "audit.jsonl")
    assert report.ok
    assert report.checked == 3
    assert report.errors == []


def test_each_record_links_to_previous(tmp_path):
    _log(tmp_path)
    recs = AuditLog(tmp_path / "audit.jsonl").read_all()
    assert recs[0]["prev"] == "0" * 64  # genesis
    assert recs[1]["prev"] == recs[0]["hash"]
    assert recs[2]["prev"] == recs[1]["hash"]


def test_modified_record_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path)
    lines = _lines(path)
    rec = json.loads(lines[1])
    rec["decision"] = "block"  # tamper with the field, leave the (now-stale) hash
    lines[1] = json.dumps(rec)
    _write(path, lines)
    report = verify_audit_chain(path)
    assert not report.ok
    assert any("modified" in e and "line 2" in e for e in report.errors)


def test_deleted_record_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path)
    lines = _lines(path)
    del lines[1]  # remove the middle record
    _write(path, lines)
    report = verify_audit_chain(path)
    assert not report.ok
    assert any("broken link" in e for e in report.errors)


def test_reordered_records_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write(path, lines)
    report = verify_audit_chain(path)
    assert not report.ok


def test_malformed_line_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path)
    lines = _lines(path)
    lines[1] = "{not valid json"
    _write(path, lines)
    report = verify_audit_chain(path)
    assert not report.ok
    assert any("malformed" in e for e in report.errors)


def test_chain_continues_across_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    a1 = AuditLog(path)
    a1.record(decision="allow", seq=0)
    a2 = AuditLog(path)  # new process/object, same file
    a2.record(decision="allow", seq=1)
    recs = a2.read_all()
    assert recs[1]["prev"] == recs[0]["hash"]  # chain not restarted
    assert verify_audit_chain(path).ok


# ── HMAC signing ──────────────────────────────────────────────────────────────


def test_hmac_signed_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path, hmac_key="operator-secret")
    assert all("sig" in r for r in AuditLog(path).read_all())
    assert verify_audit_chain(path, hmac_key="operator-secret").ok


def test_rebuilt_chain_without_key_caught_by_hmac(tmp_path):
    """An attacker edits a record AND recomputes the hash chain — but can't forge the HMAC."""
    path = tmp_path / "audit.jsonl"
    _log(tmp_path, hmac_key="operator-secret")
    lines = _lines(path)
    rec = json.loads(lines[1])
    rec["decision"] = "block"
    # Recompute a valid-looking hash the way the honest code would (attacker has no key).
    from sec_guardrails.core.audit import _hash_record

    rec.pop("sig", None)
    rec["hash"] = _hash_record(rec)
    lines[1] = json.dumps(rec)
    _write(path, lines)
    report = verify_audit_chain(path, hmac_key="operator-secret")
    assert not report.ok
    assert any("HMAC" in e for e in report.errors)


# ── CLI ───────────────────────────────────────────────────────────────────────


def test_cli_verify_exit_codes(tmp_path):
    path = tmp_path / "audit.jsonl"
    _log(tmp_path)
    assert main(["audit", "verify", str(path)]) == 0
    lines = _lines(path)
    rec = json.loads(lines[0])
    rec["decision"] = "tampered"
    lines[0] = json.dumps(rec)
    _write(path, lines)
    assert main(["audit", "verify", str(path)]) == 1
