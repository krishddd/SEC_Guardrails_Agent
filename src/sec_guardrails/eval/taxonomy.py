"""AgentDoG-style incident taxonomy (ADR-0010).

Classifies a decision on three dimensions (risk source, failure mode, real-world harm) so the
governance export reads as security evidence, not just raw counts (AI45Lab/AgentDoG).
"""

from __future__ import annotations


def classify(stage: str, reason: str = "") -> dict[str, str]:
    r = (reason or "").lower()
    if stage in ("input", "dialog") or "injection" in r or "blocked phrase" in r:
        return _t("untrusted_input", "instruction_hijack", "unauthorized_action")
    if stage == "exec_gate" or "destructive" in r or "ddl" in r or "insecure code" in r:
        return _t("agent_action", "unsafe_command", "data_destruction")
    if stage == "egress" or "ssrf" in r or "non-public ip" in r:
        return _t("agent_action", "ssrf", "data_exfiltration")
    if stage in ("policy", "tool") or "taint" in r or "budget" in r or "out of token scope" in r:
        return _t("agent_action", "excessive_agency", "unauthorized_action")
    if stage == "memory":
        return _t("untrusted_data", "memory_poisoning", "persistent_compromise")
    if stage in ("output", "oversight") or "canary" in r or "ungrounded" in r:
        return _t("agent_output", "sensitive_disclosure", "data_leak")
    return _t("unknown", "unknown", "unknown")


def _t(risk_source: str, failure_mode: str, harm: str) -> dict[str, str]:
    return {"risk_source": risk_source, "failure_mode": failure_mode, "harm": harm}
