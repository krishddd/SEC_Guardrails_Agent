"""T30 — Verification / oversight critic (rail L7).

A post-hoc check on the whole trajectory (cf. Reflexion / CRITIC / AgentDoG trajectory inspection):
given the user's stated task and the sequence of actions + final output, decide whether the agent
stayed on task or drifted into unrequested/forbidden actions. Deterministic default; an LLM critic
plugs in behind the `ml` extra.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Trajectory:
    task: str
    steps: list[str] = field(default_factory=list)  # tool/action names taken
    output: str = ""


@dataclass
class Verdict:
    ok: bool
    reason: str


@runtime_checkable
class Critic(Protocol):
    name: str

    def review(self, traj: Trajectory) -> Verdict: ...


class HeuristicCritic:
    """Flags goal drift: any action outside the allowed set is drift (deny-by-default)."""

    name = "heuristic"

    def __init__(self, allowed_steps: Iterable[str]):
        self.allowed = set(allowed_steps)

    def review(self, traj: Trajectory) -> Verdict:
        drift = [s for s in traj.steps if s not in self.allowed]
        if drift:
            return Verdict(False, f"goal drift: unrequested actions {sorted(set(drift))}")
        return Verdict(True, "on-task")


class OversightRail:
    name = "oversight"

    def __init__(self, critic: Critic):
        self.critic = critic

    def review(self, traj: Trajectory) -> Verdict:
        return self.critic.review(traj)
