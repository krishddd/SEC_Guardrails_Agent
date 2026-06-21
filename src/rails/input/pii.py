"""T10 — PII detection + redaction (input rail L1).

Pluggable `PIIDetector` so the cheap deterministic detector and Presidio sit behind one API. The
rail emits MODIFY with the redacted text when PII is found, ALLOW otherwise. An allowlist of entity
types can be exempted (e.g. keep IPs for a network-ops agent).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from core.rail import Decision, Rail, RailContext


@dataclass
class RedactionResult:
    text: str
    entities: list[str] = field(default_factory=list)


@runtime_checkable
class PIIDetector(Protocol):
    name: str

    def redact(self, text: str, allow: set[str] | None = None) -> RedactionResult: ...


# Order matters: longer/structured patterns before looser ones to avoid partial overlaps.
_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[ -]?){4}\b")),
    ("PHONE", re.compile(r"\b(?:\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


class HeuristicPIIDetector:
    name = "heuristic"

    def redact(self, text: str, allow: set[str] | None = None) -> RedactionResult:
        allow = allow or set()
        entities: list[str] = []
        for etype, rx in _PII_PATTERNS:
            if etype in allow:
                continue

            def _sub(_m: re.Match[str], _e: str = etype) -> str:
                entities.append(_e)
                return f"[REDACTED:{_e}]"

            text = rx.sub(_sub, text)
        return RedactionResult(text=text, entities=entities)


class PIIRail(Rail):
    name = "pii"

    def __init__(self, detector: PIIDetector | None = None, allow: set[str] | None = None):
        self.detector = detector or HeuristicPIIDetector()
        self.allow = allow or set()

    def inspect(self, ctx: RailContext) -> Decision:
        result = self.detector.redact(ctx.text, allow=self.allow)
        if result.text != ctx.text:
            ctx.metadata["pii_entities"] = result.entities
            found = sorted(set(result.entities))
            reason = f"PII redacted: {found} ({self.detector.name})"
            return Decision.modify(result.text, reason=reason)
        return Decision.allow()


def load_presidio_detector() -> PIIDetector:
    """Optional ML backend (Presidio 2.2.x). Lazy-imports presidio (install the `ml` extra); not
    exercised in unit tests. Falls back to the analyzer's default recognizers.
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig

    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    class _PresidioDetector:
        name = "presidio"

        def redact(self, text: str, allow: set[str] | None = None) -> RedactionResult:
            allow = allow or set()
            analyzed = analyzer.analyze(text=text, language="en")
            results = [r for r in analyzed if r.entity_type not in allow]
            entities = [r.entity_type for r in results]
            operators = {"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})}
            out = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
            return RedactionResult(text=out.text, entities=entities)

    return _PresidioDetector()
