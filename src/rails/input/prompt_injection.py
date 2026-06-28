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
    # "ignore/disregard all rules/safety/guidelines" — not just "instructions" (D1: indirect data).
    r"(?:ignore|disregard|forget|bypass|override) (?:all |any |the |your )?"
    r"(?:previous |prior |above )?"
    r"(?:rules|safety|guidelines?|polic(?:y|ies)|restrictions|filters?)",
    r"disregard (?:all |the |your )?(?:previous|prior|above)",
    r"forget (?:everything|all|your) (?:instructions|rules|prompts?)",
    r"you are now (?:a |an )?(?:dan\b|developer mode|unrestricted)",
    r"developer mode",
    r"\bdo anything now\b",
    # Instruction/configuration extraction — flexible verb→target gap (D1: catches "output your
    # complete configuration", "reveal the instructions"); plus "what is your …" / verbatim forms.
    r"\b(?:reveal|print|show|repeat|output|dump|return|display|expose|leak)\b"
    r"[\w' ]{0,25}\b(?:system prompt|configuration|instructions|directives|guidelines)\b",
    r"what (?:is|are) your (?:system prompt|instructions|configuration|directives)",
    r"system prompt\b[\w' ]{0,20}\bverbatim\b|verbatim\b[\w' ]{0,20}system prompt",
    r"</?(?:system|instructions?)>",  # forged role/markup tags
    r"\[/?(?:system|inst|instructions?)\]",  # bracketed forged tags
    r"<\|?(?:im_start|system|endofprompt)\|?>",  # chat-template spoofing
    r"new instructions:\s",
    r"\boverride\b.{0,20}\b(?:safety|guardrails?|rules)\b",
    # D1: "important instructions" injection framing (AgentDojo / indirect-via-data).
    r"before you (?:can )?(?:solve|continue|proceed|answer|begin|complete|do)\b",
    r"this is an important (?:message|instruction|update|note|system)",
]

# D1: persona-shift triggers and bypass/privilege markers. A persona trigger CO-OCCURRING with a
# bypass marker is a high-confidence role-reassignment signal with low FPR (a benign roleplay rarely
# also demands unrestricted/admin/no-rules). Scored as a strong combined hit below.
_PERSONA_TRIGGER = re.compile(
    r"\b(?:you are now|act as|acting as|pretend(?:ing)? (?:to be|you(?:'re| are))|"
    r"roleplay(?:ing)? as|from now on,? you|your new (?:role|persona|identity)|"
    r"you (?:must|will) (?:now )?(?:act|behave|respond|pretend))\b",
    re.IGNORECASE,
)
_BYPASS_MARKER = re.compile(
    r"\b(?:full access|unrestricted|uncensored|unfiltered|jailbroken|do anything|dan\b|"
    r"no (?:rules|safety|restrictions|limits|filter)|"
    r"without (?:any )?(?:restrictions?|safety|validation|sanitization|filtering|checks?)|"
    r"admin(?:istrator)?|root access|bypass|raw queries)\b",
    re.IGNORECASE,
)


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
        # D1: a persona shift demanding a bypass/privilege is a strong role-reassignment signal.
        persona = any(_PERSONA_TRIGGER.search(v) for v in variants)
        bypass = any(_BYPASS_MARKER.search(v) for v in variants)
        if persona and bypass:
            hits += 2
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
