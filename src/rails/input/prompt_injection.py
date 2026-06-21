"""T9 — Prompt-injection / jailbreak input rail (L1).

Pluggable `Detector` interface so the cheap deterministic first-line (HeuristicDetector) and the
fine-tuned model (deberta-v3, ADR-0003 pairing) sit behind one API. The rail BLOCKs when the
injection score meets the threshold. Per CLAUDE.md, recall (block-rate on attacks) and FPR (on
benign) are reported separately — never one F1. Full ASR/FPR vs the live Security_module is T31.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from core.rail import Decision, Rail, RailContext


@runtime_checkable
class Detector(Protocol):
    name: str

    def score(self, text: str) -> float:
        """Return injection likelihood in [0, 1]."""
        ...


# Cheap first-line markers for direct injection / jailbreaks (Reference §3.2).
_HEURISTIC_PATTERNS = [
    r"ignore (?:all |the |your )?(?:previous|prior|above) (?:instructions|prompts?|context)",
    r"disregard (?:all |the |your )?(?:previous|prior|above)",
    r"forget (?:everything|all|your) (?:instructions|rules|prompts?)",
    r"you are now (?:a |an )?(?:dan\b|developer mode|unrestricted)",
    r"developer mode",
    r"\bdo anything now\b",
    r"(?:reveal|print|show|repeat) (?:me )?(?:the |your )?(?:system prompt|instructions|prompt)",
    r"</?(?:system|instructions?)>",  # forged role/markup tags
    r"new instructions:\s",
    r"\boverride\b.{0,20}\b(?:safety|guardrails?|rules)\b",
]


# Leetspeak fold for adaptive-evasion resistance (T35).
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)


def _normalize(text: str) -> str:
    """Fold common obfuscations so spacing/leetspeak/punctuation can't bypass the patterns."""
    t = text.lower().translate(_LEET)
    t = re.sub(r"[^a-z0-9\s]", " ", t)  # strip punctuation
    t = re.sub(r"\s+", " ", t).strip()  # collapse whitespace
    return t


class HeuristicDetector:
    name = "heuristic"

    def __init__(self) -> None:
        self._rx = [re.compile(p, re.IGNORECASE) for p in _HEURISTIC_PATTERNS]

    def score(self, text: str) -> float:
        # Check the raw text AND a normalized variant (defeats spacing/leet/punctuation evasion).
        variants = (text, _normalize(text))
        hits = sum(1 for rx in self._rx if any(rx.search(v) for v in variants))
        if hits == 0:
            return 0.0
        return min(0.7 + 0.25 * (hits - 1), 0.99)  # 1 hit→0.70, 2→0.95, 3+→0.99


class PromptInjectionRail(Rail):
    name = "prompt_injection"

    def __init__(self, detector: Detector | None = None, threshold: float = 0.6):
        self.detector = detector or HeuristicDetector()
        self.threshold = threshold

    def inspect(self, ctx: RailContext) -> Decision:
        score = self.detector.score(ctx.text)
        if score >= self.threshold:
            return Decision.block(
                f"prompt-injection suspected (score={score:.2f}, detector={self.detector.name})"
            )
        return Decision.allow()


def load_deberta_detector(
    model: str = "protectai/deberta-v3-base-prompt-injection-v2",
) -> Detector:
    """Optional ML backend. Lazy-imports transformers (install the `ml` extra); not exercised in
    unit tests to avoid a model download in CI — its real ASR/FPR is measured in T31's A/B harness.
    """
    from transformers import pipeline  # lazy: heavy dep

    clf = pipeline("text-classification", model=model, truncation=True)

    class _DebertaDetector:
        name = "deberta-v3"

        def score(self, text: str) -> float:
            out = clf(text)[0]
            label = str(out["label"]).upper()
            prob = float(out["score"])
            is_injection = "INJECT" in label or label == "1"
            return prob if is_injection else 1.0 - prob

    return _DebertaDetector()
