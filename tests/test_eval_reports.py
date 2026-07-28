"""T33 over-refusal (FPR) + T34 latency reports for the deterministic rails."""

import json
from pathlib import Path

from sec_guardrails.eval.reports import fpr_report, latency_report

BENIGN = json.loads(
    (Path(__file__).parent / "fixtures" / "injection_samples.json").read_text("utf-8")
)["benign"]


def test_fpr_report_low_over_refusal():
    report = fpr_report(BENIGN)
    assert set(report) == {"prompt_injection", "content"}
    for rail, fpr in report.items():
        assert fpr <= 0.05, f"{rail} over-refuses benign input: FPR={fpr:.2f}"


def test_latency_report_is_fast():
    report = latency_report(BENIGN)
    assert set(report) == {"secrets", "prompt_injection", "content", "sanitize"}
    for rail, p50 in report.items():
        assert p50 > 0.0
        # Deterministic rails are sub-millisecond; a generous bound avoids CI flakiness.
        assert p50 < 50.0, f"{rail} unexpectedly slow: p50={p50:.2f}ms"
