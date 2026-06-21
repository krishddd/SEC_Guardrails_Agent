"""T25 — Write-time memory moderation + provenance (memory rail L5).

The memory index is part of the trust boundary: a single poisoned write can bias every future
session (ASI06 / ext14 / ext16). So every write is moderated BEFORE it is indexed — injection /
poisoning content is blocked, secrets and PII are redacted — and each record is tagged with
provenance (origin, trust, ingestion time) for downstream retrieval policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.native import redact_secrets
from rails.input.pii import HeuristicPIIDetector, PIIDetector
from rails.input.prompt_injection import Detector, HeuristicDetector


@dataclass
class Provenance:
    origin: str  # e.g. "user", "web:evil.com", "tool:bash"
    trust: str  # "trusted" | "untrusted"
    ts: float  # ingestion timestamp (injected)


@dataclass
class MemoryRecord:
    tenant: str
    content: str
    provenance: Provenance
    id: str = ""


@dataclass
class WriteDecision:
    allowed: bool
    record: MemoryRecord | None
    reason: str


class MemoryWriteGuard:
    def __init__(
        self,
        pi_detector: Detector | None = None,
        pii_detector: PIIDetector | None = None,
        pi_threshold: float = 0.6,
    ):
        self.pi = pi_detector or HeuristicDetector()
        self.pii = pii_detector or HeuristicPIIDetector()
        self.pi_threshold = pi_threshold

    def moderate(self, record: MemoryRecord) -> WriteDecision:
        # 1) Block injection / poisoning payloads from ever entering the bank.
        score = self.pi.score(record.content)
        if score >= self.pi_threshold:
            reason = f"memory write blocked: injection/poisoning (score={score:.2f})"
            return WriteDecision(False, None, reason)
        # 2) Redact secrets + PII before storing.
        clean = redact_secrets(record.content)
        clean = self.pii.redact(clean).text
        moderated = MemoryRecord(record.tenant, clean, record.provenance, record.id)
        return WriteDecision(True, moderated, "moderated + provenance-tagged")
