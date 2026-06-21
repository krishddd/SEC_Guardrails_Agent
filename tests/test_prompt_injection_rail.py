import json
from pathlib import Path

from core.rail import Action, RailContext
from rails.input.prompt_injection import (
    Detector,
    HeuristicDetector,
    PromptInjectionRail,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "injection_samples.json"
SAMPLES = json.loads(_FIXTURE.read_text("utf-8"))


class FakeDetector:
    name = "fake"

    def __init__(self, value: float):
        self.value = value

    def score(self, text: str) -> float:
        return self.value


def test_blocks_at_or_above_threshold():
    rail = PromptInjectionRail(detector=FakeDetector(0.6), threshold=0.6)
    assert rail.inspect(RailContext(text="x")).action is Action.BLOCK


def test_allows_below_threshold():
    rail = PromptInjectionRail(detector=FakeDetector(0.59), threshold=0.6)
    assert rail.inspect(RailContext(text="x")).action is Action.ALLOW


def test_heuristic_is_a_detector():
    assert isinstance(HeuristicDetector(), Detector)


def _rate(rail, texts):
    blocked = sum(1 for t in texts if rail.inspect(RailContext(text=t)).action is Action.BLOCK)
    return blocked / len(texts)


def test_heuristic_recall_and_fpr_reported_split():
    rail = PromptInjectionRail()  # heuristic, default threshold
    recall = _rate(rail, SAMPLES["injection"])  # block-rate on attacks
    fpr = _rate(rail, SAMPLES["benign"])  # false-positive rate on benign
    # Report split (never one F1); assert the cheap first-line is useful, not perfect.
    assert recall >= 0.8, f"recall too low: {recall}"
    assert fpr <= 0.1, f"FPR too high: {fpr}"
