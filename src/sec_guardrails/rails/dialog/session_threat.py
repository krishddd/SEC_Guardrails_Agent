"""G9 — session-level threat accumulation (dialog rail L2).

Each turn is otherwise evaluated independently, so a distributed multi-turn attack (persona
establishment → boundary probe → payload) can stay under every per-turn threshold. This tracks a
per-session threat score from signals the rails ALREADY produce — gray-band injection scores and
blocked turns — no new detector. When the score crosses a threshold the session is *escalated*: the
gray-band block threshold is lowered (a previously-passing gray input now blocks) and callers should
force the L7 critic every turn. Deterministic; in-memory per process.
"""

from __future__ import annotations

from dataclasses import dataclass

from sec_guardrails.rails.input.prompt_injection import Detector, HeuristicDetector


@dataclass
class SessionState:
    turns: int
    score: float
    gray_turns: int
    blocked_turns: int
    escalated: bool
    just_escalated: bool  # True only on the turn the score first crosses the threshold


class SessionThreatTracker:
    def __init__(
        self,
        *,
        threshold: float = 3.0,
        gray_weight: float = 1.0,
        block_weight: float = 2.0,
        gray_low: float = 0.35,
        normal_gray_high: float = 0.6,
        escalated_gray_high: float = 0.4,
        detector: Detector | None = None,
    ):
        self.threshold = threshold
        self.gray_weight = gray_weight
        self.block_weight = block_weight
        self.gray_low = gray_low
        self.normal_gray_high = normal_gray_high
        self.escalated_gray_high = escalated_gray_high
        self._detector = detector or HeuristicDetector()
        self._sessions: dict[str, SessionState] = {}

    def gray_score(self, text: str) -> float:
        return self._detector.score(text) if text else 0.0

    def observe(self, session_id: str, *, text: str = "", blocked: bool = False) -> SessionState:
        s = self._sessions.get(session_id) or SessionState(0, 0.0, 0, 0, False, False)
        was_escalated = s.escalated
        s.turns += 1
        gray = self.gray_score(text)
        if self.gray_low <= gray < self.normal_gray_high:
            s.gray_turns += 1
            s.score += self.gray_weight
        if blocked:
            s.blocked_turns += 1
            s.score += self.block_weight
        s.escalated = s.score >= self.threshold
        s.just_escalated = s.escalated and not was_escalated
        self._sessions[session_id] = s
        return s

    def is_escalated(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        return bool(s and s.escalated)

    def gray_high(self, session_id: str) -> float:
        """The gray-band block threshold for this session — lowered once escalated."""
        return self.escalated_gray_high if self.is_escalated(session_id) else self.normal_gray_high

    def force_critic(self, session_id: str) -> bool:
        """Escalated sessions should run the L7 critic every turn."""
        return self.is_escalated(session_id)
