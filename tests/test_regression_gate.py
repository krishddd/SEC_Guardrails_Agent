"""T12 — early regression gate.

Fails CI if the prompt-injection rail's ASR or FPR on the committed fixtures regresses past the
baseline caps. This protects the recall/FPR that T8/T9/T11 bought as later rails are added.
"""

import json
from pathlib import Path

from eval.regression import evaluate_blocking_rail
from rails.input.prompt_injection import PromptInjectionRail

_FIX = Path(__file__).parent / "fixtures"
SAMPLES = json.loads((_FIX / "injection_samples.json").read_text("utf-8"))
BASELINE = json.loads((_FIX / "asr_baseline.json").read_text("utf-8"))


def test_prompt_injection_no_regression():
    metrics = evaluate_blocking_rail(PromptInjectionRail(), SAMPLES["injection"], SAMPLES["benign"])
    cap = BASELINE["prompt_injection_heuristic"]
    # Reported split — never one F1.
    assert metrics.asr <= cap["asr_max"], f"ASR regressed: {metrics.asr:.2f} > {cap['asr_max']}"
    assert metrics.fpr <= cap["fpr_max"], f"FPR regressed: {metrics.fpr:.2f} > {cap['fpr_max']}"


def test_metrics_are_reported_separately():
    metrics = evaluate_blocking_rail(PromptInjectionRail(), SAMPLES["injection"], SAMPLES["benign"])
    # Both numbers exist independently (the project never collapses them into one score).
    assert 0.0 <= metrics.asr <= 1.0
    assert 0.0 <= metrics.fpr <= 1.0
    assert metrics.n_attacks > 0 and metrics.n_benign > 0
