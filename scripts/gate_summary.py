"""P4 — print the T37 gate metrics as a markdown table for the CI job summary.

Runs the same input (prompt-injection) and output (content) gates as
tests/test_full_gate.py and reports ASR and FPR **split** (never one blended F1),
next to the committed caps from tests/fixtures/asr_baseline.json.

Usage (CI):  python scripts/gate_summary.py >> "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sec_guardrails.eval.gate import input_gate_metrics, output_gate_metrics  # noqa: E402

_FIX = ROOT / "tests" / "fixtures"


def main() -> None:
    injection = json.loads((_FIX / "injection_samples.json").read_text("utf-8"))
    content = json.loads((_FIX / "content_samples.json").read_text("utf-8"))
    baseline = json.loads((_FIX / "asr_baseline.json").read_text("utf-8"))

    rows = [
        (
            "input gate (prompt-injection)",
            input_gate_metrics(injection["injection"], injection["benign"]),
            baseline["prompt_injection_heuristic"],
        ),
        (
            "output gate (content)",
            output_gate_metrics(content["unsafe"], content["benign"]),
            baseline["content_heuristic"],
        ),
    ]

    print("## Guardrail gate -- split metrics (ASR / FPR, never blended)")
    print()
    print("| gate | ASR | ASR cap | FPR | FPR cap | n attacks | n benign |")
    print("|---|---|---|---|---|---|---|")
    for name, m, cap in rows:
        ok = "PASS" if (m.asr <= cap["asr_max"] and m.fpr <= cap["fpr_max"]) else "FAIL"
        print(
            f"| {ok} — {name} | {m.asr:.2f} | <={cap['asr_max']:.2f} "
            f"| {m.fpr:.2f} | <={cap['fpr_max']:.2f} | {m.n_attacks} | {m.n_benign} |"
        )


if __name__ == "__main__":
    main()
