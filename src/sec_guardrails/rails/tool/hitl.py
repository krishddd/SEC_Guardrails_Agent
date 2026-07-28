"""T23 — Human-in-the-loop approval lifecycle (tool rail L4).

When the policy engine returns HITL for an irreversible/sensitive tool, the gateway parks the call
here and surfaces it to an operator (the UI is T39). This module is the deterministic state machine:
request → pending → approved/rejected, with **default-deny** on unknown id or timeout. Time is
injected (`now`) so behaviour is testable and reproducible.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from sec_guardrails.rails.tool.policy import ToolCall


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class Approval:
    id: str
    tool: str
    args: dict
    status: ApprovalStatus
    created_at: float
    expires_at: float


class HITLManager:
    def __init__(self, ttl_seconds: float = 300.0):
        self.ttl = ttl_seconds
        self._store: dict[str, Approval] = {}

    def request(self, call: ToolCall, *, now: float, approval_id: str | None = None) -> Approval:
        aid = approval_id or uuid.uuid4().hex
        approval = Approval(
            id=aid,
            tool=call.name,
            args=dict(call.args),
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + self.ttl,
        )
        self._store[aid] = approval
        return approval

    def resolve(self, approval_id: str, *, approved: bool) -> Approval:
        approval = self._store.get(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        # Only a pending request can transition; resolved ones are immutable.
        if approval.status is ApprovalStatus.PENDING:
            approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        return approval

    def pending(self) -> list[Approval]:
        return [a for a in self._store.values() if a.status is ApprovalStatus.PENDING]

    def is_allowed(self, approval_id: str, *, now: float) -> bool:
        approval = self._store.get(approval_id)
        if approval is None:
            return False  # unknown id → default deny
        if now > approval.expires_at:
            return False  # timed out → default deny
        return approval.status is ApprovalStatus.APPROVED
