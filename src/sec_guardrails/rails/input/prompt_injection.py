"""T9 — Prompt-injection / jailbreak input rail (L1).

Pluggable `Detector` interface so the cheap deterministic first-line (HeuristicDetector) and the
fine-tuned model (deberta-v3, ADR-0003 pairing) sit behind one API. The rail BLOCKs when the
injection score meets the threshold. Per CLAUDE.md, recall (block-rate on attacks) and FPR (on
benign) are reported separately — never one F1. Full ASR/FPR vs the live Security_module is T31.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from sec_guardrails.core.rail import Decision, Rail, RailContext


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


# D2: weak (gray-band) markers — suspicious but not conclusive on their own. When one of these is
# present and no HARD pattern fired, the heuristic returns GRAY_SCORE so a conditional second stage
# (EscalatingDetector) can escalate just this ambiguous middle to the expensive model.
_WEAK_MARKERS = re.compile(
    r"\b(?:system prompt|your instructions|system tables|hidden (?:tables|schema)|"
    r"your (?:rules|guidelines|configuration|directives)|jailbreak|do anything)\b",
    re.IGNORECASE,
)
GRAY_SCORE = 0.4  # below the 0.6 block threshold → never blocks alone, only flags for escalation


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
        if hits:
            return min(0.7 + 0.25 * (hits - 1), 0.99)  # 1 hit→0.70, 2→0.95, 3+→0.99
        # D2: no hard hit — a weak/ambiguous signal returns the gray score (escalate, don't block).
        weak = (persona and not bypass) or any(_WEAK_MARKERS.search(v) for v in variants)
        return GRAY_SCORE if weak else 0.0


class EscalatingDetector:
    """D2 — conditional second-stage detection. Runs a cheap `primary` (heuristic) inline; only when
    its score lands in the GRAY BAND `[gray_low, gray_high)` does it call the expensive `secondary`
    (e.g. deberta-v3). Confident-clean (<gray_low) and confident-injection (>=gray_high) skip the
    model entirely, so the heavy detector runs on a small fraction of turns — most of the ML recall
    at a fraction of the latency (T7/SC3). `escalations`/`calls` expose the escalation rate.
    """

    name = "escalating"

    def __init__(
        self,
        primary: Detector,
        secondary: Detector,
        *,
        gray_low: float = 0.35,
        gray_high: float = 0.6,
    ):
        self.primary = primary
        self.secondary = secondary
        self.gray_low = gray_low
        self.gray_high = gray_high
        self.calls = 0
        self.escalations = 0

    def score(self, text: str) -> float:
        self.calls += 1
        p = self.primary.score(text)
        if p >= self.gray_high or p < self.gray_low:
            return p  # confident either way — no model call
        self.escalations += 1
        return self.secondary.score(text)

    @property
    def escalation_rate(self) -> float:
        return (self.escalations / self.calls) if self.calls else 0.0


class EnsembleDetector:
    """D3 — combine detectors and take the MAX score (logical OR of "is this an injection?").

    Recall is monotonically ≥ any single member, so adding a detector can only catch *more* —
    at the cost of FPR being the union of members' false positives (keep members high-precision) and
    latency being the sum (use the deterministic heuristic + at most one model, or wrap in
    `EscalatingDetector` for the conditional-cost version). `last_scores` aids triage.
    """

    name = "ensemble"

    def __init__(self, detectors: list[Detector]):
        if not detectors:
            raise ValueError("EnsembleDetector needs at least one detector")
        self.detectors = detectors
        self.last_scores: dict[str, float] = {}

    def score(self, text: str) -> float:
        # Max over the LIST (not the dict) so detectors sharing a name don't collapse the result.
        scored = [(d.name, d.score(text)) for d in self.detectors]
        self.last_scores = dict(scored)  # for triage/display; may collapse same-named members
        return max(score for _, score in scored)


def detect_language(text: str) -> str:
    """G8 — a cheap, offline language gate: return "en" or "non-en".

    Robust for non-Latin scripts (Cyrillic/CJK/Arabic/…): a text whose letters are >20% non-ASCII
    is "non-en". Pure-ASCII Latin-script non-English (Spanish/French/German without diacritics) is a
    documented gap — inject a real detector (langdetect / fastText) via `language_detector` there.
    """
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "en"
    non_ascii = sum(1 for c in letters if ord(c) > 127)
    return "non-en" if non_ascii / len(letters) > 0.2 else "en"


class MultilingualInjectionDetector:
    """G8 — route by language. English text goes to the (English-tuned) `english` detector; non-
    English text is scored by a `multilingual` detector (e.g. Mistral Moderation, ADR-0003) and
    MAX-combined with the English detector so an embedded-English attack in an otherwise non-English
    message is still caught. `language_detector` is injectable (default `detect_language`)."""

    name = "multilingual-routed"

    def __init__(
        self,
        english: Detector,
        multilingual: Detector,
        *,
        language_detector: Callable[[str], str] = detect_language,
        is_english: Callable[[str], bool] = lambda lang: lang == "en",
    ):
        self.english = english
        self.multilingual = multilingual
        self.language_detector = language_detector
        self.is_english = is_english
        self.last_language: str | None = None

    def score(self, text: str) -> float:
        lang = self.language_detector(text)
        self.last_language = lang
        if self.is_english(lang):
            return self.english.score(text)
        return max(self.english.score(text), self.multilingual.score(text))


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


def load_escalating_detector(**kwargs) -> EscalatingDetector:
    """D2 — the recommended ML wiring: heuristic primary + deberta-v3 secondary, escalating only the
    gray band. Far cheaper than running deberta on every turn (T7/SC3) at comparable recall. Pass to
    `default_engine(audit, pi_detector=load_escalating_detector())`.
    """
    return EscalatingDetector(HeuristicDetector(), load_deberta_detector(), **kwargs)


def load_promptguard_detector(
    model: str = "meta-llama/Llama-Prompt-Guard-2-86M",
) -> Detector:
    """D3 — Meta Llama PromptGuard 2 (86M) backend; strong on injection incl. indirect. Lazy-imports
    transformers (`ml` extra). NOTE: the model repo is **HF-gated** (Llama license) — needs an
    accepted license + `HF_TOKEN`; if unavailable it raises, so call it behind a try/except.
    """
    from transformers import pipeline  # lazy: heavy dep

    clf = pipeline("text-classification", model=model, truncation=True)

    class _PromptGuardDetector:
        name = "promptguard-2"

        def score(self, text: str) -> float:
            out = clf(text)[0]
            label = str(out["label"]).upper()
            prob = float(out["score"])
            # PromptGuard 2 labels: LABEL_1 / "MALICIOUS" = injection, LABEL_0 / "BENIGN" = clean.
            is_injection = label in ("LABEL_1", "1", "MALICIOUS", "INJECTION", "JAILBREAK")
            return prob if is_injection else 1.0 - prob

    return _PromptGuardDetector()


def load_mistral_injection_detector(model: str = "mistral-moderation-2603") -> Detector:
    """G8 — a multilingual injection/abuse backend built on Mistral Moderation (ADR-0003,
    multilingual and already licensed). Lazy-imports mistralai (`mistral` extra); not exercised in
    CI. Maps the max moderation category score to an injection-likelihood score. Use as the
    `multilingual` arm of `MultilingualInjectionDetector`.
    """
    import os

    from mistralai import Mistral  # lazy: external dep

    client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])

    class _MistralInjectionDetector:
        name = "mistral-moderation"

        def score(self, text: str) -> float:
            resp = client.classifiers.moderate(model=model, inputs=[text])
            scores = resp.results[0].category_scores
            return max(scores.values()) if scores else 0.0

    return _MistralInjectionDetector()


def load_multilingual_detector(**kwargs) -> MultilingualInjectionDetector:
    """G8 — the recommended multilingual wiring: heuristic (English) + Mistral Moderation routed by
    language. Pass to `default_engine(audit, pi_detector=load_multilingual_detector())`. Lazy —
    requires `MISTRAL_API_KEY` + the `mistral` extra for the non-English arm.
    """
    return MultilingualInjectionDetector(
        HeuristicDetector(), load_mistral_injection_detector(), **kwargs
    )


def load_ensemble_detector(*, use_deberta: bool = True, use_promptguard: bool = False) -> Detector:
    """D3 — heuristic (D1) ∪ model detectors, MAX-combined for best recall. deberta on by default;
    PromptGuard 2 opt-in (HF-gated). Wrap the result in `EscalatingDetector` if you need the model
    calls to be conditional. Pass to `default_engine(audit, pi_detector=load_ensemble_detector())`.
    """
    detectors: list[Detector] = [HeuristicDetector()]
    if use_deberta:
        detectors.append(load_deberta_detector())
    if use_promptguard:
        detectors.append(load_promptguard_detector())
    return EnsembleDetector(detectors)
