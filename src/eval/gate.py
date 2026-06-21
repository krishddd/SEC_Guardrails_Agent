"""T37 — full quality gate across the deterministic blocking rails.

Extends the T12 regression gate from one rail to the composed input (prompt-injection) and output
(content-safety) blockers, reporting ASR and FPR **split** for each. Run in the Python CI lane; the
`ci-ok` aggregate makes a regression past the committed caps a blocking failure.
"""

from __future__ import annotations

from eval.regression import RailMetrics, evaluate_blocking_rail
from rails.input.prompt_injection import PromptInjectionRail
from rails.output.content import ContentRail


def input_gate_metrics(injection: list[str], benign: list[str]) -> RailMetrics:
    return evaluate_blocking_rail(PromptInjectionRail(), injection, benign)


def output_gate_metrics(unsafe: list[str], benign: list[str]) -> RailMetrics:
    return evaluate_blocking_rail(ContentRail(), unsafe, benign)
