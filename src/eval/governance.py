"""T36 — Audit/governance export + compliance control map.

Turns the append-only audit log (T6) into governance evidence: decision/endpoint counts, block
reasons, and the NIST AI RMF / EU AI Act controls those decisions evidence. The mapping is data, so
it is reviewed and exported alongside the report (SOC2 / EU AI Act record-keeping).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

# Audit decision/category → compliance controls it provides evidence for.
CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    "record_keeping": {
        "nist_ai_rmf": ["GOVERN 4.1", "MEASURE 1.1"],
        "eu_ai_act": ["Art. 12 (record-keeping)", "Art. 19 (logs)"],
    },
    "block": {
        "nist_ai_rmf": ["MANAGE 2.1 (risk response)", "MEASURE 2.7 (robustness)"],
        "eu_ai_act": ["Art. 15 (accuracy, robustness, cybersecurity)"],
    },
    "modify": {
        "nist_ai_rmf": ["MAP 5.1 (impacts)"],
        "eu_ai_act": ["Art. 10 (data governance)"],
    },
    "hitl": {
        "nist_ai_rmf": ["GOVERN 1.2 (accountability)"],
        "eu_ai_act": ["Art. 14 (human oversight)"],
    },
}


@dataclass
class GovernanceReport:
    total: int
    by_decision: dict[str, int]
    by_endpoint: dict[str, int]
    block_reasons: list[str]
    controls_evidenced: list[str]


def summarize(records: list[dict]) -> GovernanceReport:
    by_decision = Counter(str(r.get("decision", "unknown")) for r in records)
    by_endpoint = Counter(str(r.get("endpoint", "unknown")) for r in records)
    block_reasons = [
        str(r.get("reason", "")) for r in records if r.get("decision") in ("block", "error")
    ]

    controls: set[str] = set()
    if records:  # any audit record evidences record-keeping
        controls |= _controls_for("record_keeping")
    for decision in by_decision:
        controls |= _controls_for(decision)

    return GovernanceReport(
        total=len(records),
        by_decision=dict(by_decision),
        by_endpoint=dict(by_endpoint),
        block_reasons=block_reasons,
        controls_evidenced=sorted(controls),
    )


def _controls_for(category: str) -> set[str]:
    entry = CONTROL_MAP.get(category)
    if not entry:
        return set()
    return set(entry["nist_ai_rmf"]) | set(entry["eu_ai_act"])


def export(records: list[dict]) -> dict:
    """JSON-serializable governance export: the summary + the control map used to derive it."""
    report = summarize(records)
    return {
        "summary": {
            "total": report.total,
            "by_decision": report.by_decision,
            "by_endpoint": report.by_endpoint,
            "block_count": len(report.block_reasons),
            "controls_evidenced": report.controls_evidenced,
        },
        "control_map": CONTROL_MAP,
    }
