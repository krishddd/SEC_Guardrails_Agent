"""T33/T34 — over-refusal (FPR) and per-rail latency reports for the deterministic blockers.

FPR (over-refusal) and latency are reported separately, per the project's split-metrics rule. These
cover the deterministic rails (CI-runnable); the ML-backed rails extend the same reports once the
`ml` extra is installed, and the live numbers come from the A/B harness (T31).
"""

from __future__ import annotations

import time

from sec_guardrails.core.rail import Rail, RailContext
from sec_guardrails.eval.regression import evaluate_blocking_rail
from sec_guardrails.rails.input.prompt_injection import PromptInjectionRail
from sec_guardrails.rails.input.secrets import SecretsRail
from sec_guardrails.rails.output.content import ContentRail
from sec_guardrails.rails.output.sanitize import SanitizeRail


def fpr_report(benign: list[str]) -> dict[str, float]:
    """False-positive (over-refusal) rate of each blocking rail on a benign corpus."""
    return {
        "prompt_injection": evaluate_blocking_rail(PromptInjectionRail(), [], benign).fpr,
        "content": evaluate_blocking_rail(ContentRail(), [], benign).fpr,
    }


def _p50_ms(rail: Rail, samples: list[str], repeats: int = 50) -> float:
    timings: list[float] = []
    for _ in range(repeats):
        for sample in samples:
            start = time.perf_counter()
            rail.inspect(RailContext(text=sample))
            timings.append((time.perf_counter() - start) * 1000.0)
    timings.sort()
    return timings[len(timings) // 2]


def latency_report(samples: list[str]) -> dict[str, float]:
    """Per-rail p50 latency (ms) for the deterministic rails."""
    rails: dict[str, Rail] = {
        "secrets": SecretsRail(),
        "prompt_injection": PromptInjectionRail(),
        "content": ContentRail(),
        "sanitize": SanitizeRail(),
    }
    return {name: _p50_ms(rail, samples) for name, rail in rails.items()}
