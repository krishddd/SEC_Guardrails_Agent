"""T26 — Tenant isolation + retrieval validators (memory rail L5).

A `MemoryStore` that moderates on write (T25) and, on read, enforces:
  - **tenant isolation** — a tenant only ever sees its own records;
  - **trust threshold** — optionally drop untrusted-provenance chunks;
  - **freshness** — optionally drop chunks older than a max age.
"""

from __future__ import annotations

from dataclasses import dataclass

from rails.memory.write_guard import MemoryRecord, MemoryWriteGuard, WriteDecision


@dataclass
class RetrievalPolicy:
    min_trust: str = "untrusted"  # set to "trusted" to drop untrusted-provenance chunks
    max_age_seconds: float | None = None


class MemoryStore:
    def __init__(
        self, write_guard: MemoryWriteGuard | None = None, *, policy: RetrievalPolicy | None = None
    ):
        self.guard = write_guard or MemoryWriteGuard()
        self.policy = policy or RetrievalPolicy()
        self._records: list[MemoryRecord] = []

    def write(self, record: MemoryRecord) -> WriteDecision:
        decision = self.guard.moderate(record)
        if decision.allowed and decision.record is not None:
            self._records.append(decision.record)
        return decision

    def read(self, tenant: str, *, now: float) -> list[MemoryRecord]:
        results: list[MemoryRecord] = []
        for record in self._records:
            if record.tenant != tenant:
                continue  # tenant isolation
            if self.policy.min_trust == "trusted" and record.provenance.trust != "trusted":
                continue  # trust threshold
            if (
                self.policy.max_age_seconds is not None
                and (now - record.provenance.ts) > self.policy.max_age_seconds
            ):
                continue  # freshness
            results.append(record)
        return results
