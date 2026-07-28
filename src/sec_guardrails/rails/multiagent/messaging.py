"""T29 — Multi-agent communication rails.

Defends the inter-agent channel (AiTM arXiv:2502.14847, rogue agents, consensus spoofing):
  - **signed messages** — HMAC over the message; a tampered body fails verification;
  - **capability-token delegation** — an agent hands a downscoped, signed, expiring token (not its
    own credentials); the holder may only invoke in-scope actions;
  - **orchestrator mediation** — all traffic flows through a supervisor that verifies signatures and
    re-applies an input rail to every relayed body.

Synthetic-MAS implementation (CI-verifiable); wiring to a live multi-agent Odysseus is gated on OQ1.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from sec_guardrails.core.rail import RailChain, RailContext


def _hmac(key: str, data: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign(payload: dict, key: str) -> str:
    return _hmac(key, _canonical(payload))


def verify(payload: dict, signature: str, key: str) -> bool:
    return hmac.compare_digest(sign(payload, key), signature)


@dataclass
class AgentMessage:
    sender: str
    recipient: str
    body: str
    signature: str = ""


@dataclass
class CapabilityToken:
    issuer: str
    holder: str
    scope: list[str]
    expires_at: float
    signature: str = ""


def _token_payload(tok: CapabilityToken) -> dict:
    return {
        "issuer": tok.issuer,
        "holder": tok.holder,
        "scope": tok.scope,
        "expires_at": tok.expires_at,
    }


def issue_token(
    issuer: str, holder: str, scope: list[str], expires_at: float, key: str
) -> CapabilityToken:
    tok = CapabilityToken(issuer, holder, sorted(scope), expires_at)
    tok.signature = sign(_token_payload(tok), key)
    return tok


def verify_token(tok: CapabilityToken, key: str, *, now: float, action: str) -> tuple[bool, str]:
    if not verify(_token_payload(tok), tok.signature, key):
        return False, "bad token signature"
    if now > tok.expires_at:
        return False, "token expired"
    if action not in tok.scope:
        return False, f"action '{action}' out of token scope"
    return True, "ok"


@dataclass
class Orchestrator:
    """Supervisor that mediates all inter-agent traffic (no arbitrary agent-to-agent messages)."""

    key: str
    input_rail: RailChain | None = None

    def send(self, sender: str, recipient: str, body: str) -> AgentMessage:
        payload = {"sender": sender, "recipient": recipient, "body": body}
        return AgentMessage(sender, recipient, body, sign(payload, self.key))

    def relay(self, msg: AgentMessage) -> tuple[bool, str]:
        payload = {"sender": msg.sender, "recipient": msg.recipient, "body": msg.body}
        if not verify(payload, msg.signature, self.key):
            return False, "tampered or unsigned inter-agent message"
        if self.input_rail is not None:
            result = self.input_rail.run(RailContext(text=msg.body))
            if not result.allowed:
                return False, f"relayed body blocked by {result.blocked_by}"
        return True, "ok"
