"""T16 — Output content-safety classifier (output rail L6).

Pluggable `ContentDetector` so the cheap deterministic default and a model backend share one API
(same pattern as the input PI rail). The active backend is recorded for audit. Default is a small,
high-precision heuristic; the real coverage comes from the Mistral Moderation / ShieldGemma backend
(lazy-imported behind the `ml` extra — no model download in CI).
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from sec_guardrails.core.rail import Decision, Rail, RailContext


@runtime_checkable
class ContentDetector(Protocol):
    name: str

    def flag(self, text: str) -> set[str]:
        """Return the set of violated safety categories (empty = safe)."""
        ...


# High-precision patterns only (keep FPR low; the ML backend is the real classifier).
_CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "cbrn": re.compile(
        r"\b(synthesi[sz]e|make|produce|build)\b.{0,40}\b(nerve agent|sarin|vx gas|bioweapon|"
        r"dirty bomb|chemical weapon)\b",
        re.IGNORECASE,
    ),
    "malware": re.compile(
        r"\b(here('| i)s|complete|working|functional)\b.{0,30}\b(ransomware|keylogger|rootkit|"
        r"botnet|trojan)\b",
        re.IGNORECASE,
    ),
    "self_harm": re.compile(
        r"\b(how to|best way to|easiest way to)\b.{0,25}\b(kill yourself|end your life|"
        r"hurt yourself)\b",
        re.IGNORECASE,
    ),
}


class HeuristicContentDetector:
    name = "heuristic"

    def flag(self, text: str) -> set[str]:
        return {cat for cat, rx in _CATEGORY_PATTERNS.items() if rx.search(text)}


class ContentRail(Rail):
    name = "content"

    def __init__(self, detector: ContentDetector | None = None):
        self.detector = detector or HeuristicContentDetector()

    def inspect(self, ctx: RailContext) -> Decision:
        categories = self.detector.flag(ctx.text)
        if categories:
            cats = sorted(categories)
            return Decision.block(f"unsafe content {cats} ({self.detector.name})")
        return Decision.allow()


def load_mistral_moderation(model: str = "mistral-moderation-2603") -> ContentDetector:
    """Optional ML backend (native to the Mistral-backed agent). Lazy-imports mistralai (`mistral`
    extra); not exercised in CI. Maps the API's category scores to violated categories.
    """
    import os

    from mistralai import Mistral  # lazy: external dep

    client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])

    class _MistralDetector:
        name = "mistral-moderation"

        def flag(self, text: str) -> set[str]:
            resp = client.classifiers.moderate(model=model, inputs=[text])
            scores = resp.results[0].category_scores
            return {cat for cat, score in scores.items() if score >= 0.5}

    return _MistralDetector()
