"""T37 — full CI quality gate. Fails CI if the input (PI) or output (content) blockers regress past
the committed ASR/FPR caps. Metrics reported split, never one F1."""

import json
from pathlib import Path

from eval.gate import input_gate_metrics, output_gate_metrics

_FIX = Path(__file__).parent / "fixtures"
INJECTION = json.loads((_FIX / "injection_samples.json").read_text("utf-8"))
CONTENT = json.loads((_FIX / "content_samples.json").read_text("utf-8"))
BASELINE = json.loads((_FIX / "asr_baseline.json").read_text("utf-8"))


def test_input_gate_within_caps():
    m = input_gate_metrics(INJECTION["injection"], INJECTION["benign"])
    cap = BASELINE["prompt_injection_heuristic"]
    assert m.asr <= cap["asr_max"], f"input ASR regressed: {m.asr:.2f}"
    assert m.fpr <= cap["fpr_max"], f"input FPR regressed: {m.fpr:.2f}"


def test_output_gate_within_caps():
    m = output_gate_metrics(CONTENT["unsafe"], CONTENT["benign"])
    cap = BASELINE["content_heuristic"]
    assert m.asr <= cap["asr_max"], f"output ASR regressed: {m.asr:.2f}"
    assert m.fpr <= cap["fpr_max"], f"output FPR regressed: {m.fpr:.2f}"
