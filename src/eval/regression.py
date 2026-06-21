"""T12 — metrics for the early regression gate.

Computes the two numbers we always report SPLIT (never one F1) for a blocking rail:
  - ASR  (attack success rate)  = fraction of attacks NOT blocked  → lower is better
  - FPR  (false-positive rate)  = fraction of benign inputs blocked → lower is better
A committed baseline (tests/fixtures/asr_baseline.json) caps both, so later rails can't erode what
an earlier rail bought. The full corpus run vs the live Security_module is T31/T37.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.rail import Action, Rail, RailContext


@dataclass
class RailMetrics:
    asr: float
    fpr: float
    n_attacks: int
    n_benign: int


def _is_blocked(rail: Rail, text: str) -> bool:
    return rail.inspect(RailContext(text=text)).action is Action.BLOCK


def evaluate_blocking_rail(rail: Rail, attacks: list[str], benign: list[str]) -> RailMetrics:
    blocked_attacks = sum(1 for t in attacks if _is_blocked(rail, t))
    blocked_benign = sum(1 for t in benign if _is_blocked(rail, t))
    asr = 1.0 - (blocked_attacks / len(attacks)) if attacks else 0.0
    fpr = (blocked_benign / len(benign)) if benign else 0.0
    return RailMetrics(asr=asr, fpr=fpr, n_attacks=len(attacks), n_benign=len(benign))
