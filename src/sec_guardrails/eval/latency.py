"""G10.1 — per-rail latency measurement + budget gate.

Turns the design latency budgets into a measurable, CI-gatable number: measure a rail's p50 over N
runs and compare to its budget. Deterministic rails (the <30 ms hot path) are the ones worth gating
in CI; model-backed rails are measured but not hard-gated (their latency depends on the backend /
hardware). Reported as a latency number per rail — never blended with ASR/FPR.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class LatencyResult:
    name: str
    p50_ms: float
    p95_ms: float
    runs: int
    budget_ms: float | None = None

    @property
    def within_budget(self) -> bool:
        return self.budget_ms is None or self.p50_ms <= self.budget_ms

    def as_dict(self) -> dict[str, float | int | str | bool | None]:
        return {
            "name": self.name,
            "p50_ms": round(self.p50_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "runs": self.runs,
            "budget_ms": self.budget_ms,
            "within_budget": self.within_budget,
        }


def _percentile(sorted_ms: list[float], pct: float) -> float:
    if not sorted_ms:
        return 0.0
    k = max(0, min(len(sorted_ms) - 1, int(round((pct / 100) * (len(sorted_ms) - 1)))))
    return sorted_ms[k]


def measure_latency(
    name: str,
    fn: Callable[[], object],
    *,
    runs: int = 50,
    warmup: int = 5,
    budget_ms: float | None = None,
) -> LatencyResult:
    """Time `fn` `runs` times (after `warmup` untimed runs) and report p50/p95 in milliseconds."""
    for _ in range(max(0, warmup)):
        fn()
    samples: list[float] = []
    for _ in range(max(1, runs)):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    return LatencyResult(
        name=name,
        p50_ms=_percentile(samples, 50),
        p95_ms=_percentile(samples, 95),
        runs=len(samples),
        budget_ms=budget_ms,
    )
