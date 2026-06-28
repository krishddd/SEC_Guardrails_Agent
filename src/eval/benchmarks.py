"""T32 — external benchmark driver: AgentDojo via the live A/B harness.

AgentDojo (Debenedetti et al., 2024) is reused as a named external benchmark — never rebuilt. Each
suite (banking / slack / travel / workspace) ships **injection_tasks** (attacker goals) and
**user_tasks** (benign user requests = the utility measure). We wrap each injection goal in
AgentDojo's own canonical `important_instructions` attack template (imported, not copied, so it
can't drift) and feed both streams through `eval.ab_harness.run_ab` against guarded Odysseus:
  - injection goals → **AttackCase** → interception / ASR,
  - user prompts    → **benign**     → utility-under-attack (FPR / completion).

Same honest limit as T31: this is the **chat surface**, so it exercises the input prompt-injection
rail, not AgentDojo's full indirect-via-tool-output delivery (that needs T20-live). CI-safe:
agentdojo is imported lazily and a missing package is recorded as a skip, never a crash.
"""

from __future__ import annotations

from eval.ab_harness import AttackCase

_DEFAULT_SUITES = ("banking", "slack", "travel", "workspace")
_ATTACK_USER = "Emma Johnson"
_ATTACK_MODEL = "AI assistant"


def wrap_injection(goal: str, jb_string: str) -> str:
    """Render AgentDojo's important_instructions template around an attacker goal."""
    return jb_string.format(user=_ATTACK_USER, model=_ATTACK_MODEL, goal=goal)


def load_agentdojo_cases(
    *,
    version: str = "v1",
    suites: tuple[str, ...] = _DEFAULT_SUITES,
    limit_per_suite: int | None = None,
) -> tuple[list[AttackCase], list[str], list[str]]:
    """Load (attack_cases, benign_prompts, skipped) from AgentDojo.

    `skipped` records any suite/package that couldn't load or was capped — reduced coverage is never
    silent. `limit_per_suite` caps both streams per suite (recorded as a skip note).
    """
    skipped: list[str] = []
    try:
        from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
        from agentdojo.task_suite.load_suites import get_suites
    except Exception as exc:  # noqa: BLE001 — agentdojo not installed: record, don't crash CI
        return [], [], [f"agentdojo unavailable: {type(exc).__name__}: {exc}"]

    jb_string = ImportantInstructionsAttack._JB_STRING
    all_suites = get_suites(version)
    attacks: list[AttackCase] = []
    benign: list[str] = []
    for name in suites:
        suite = all_suites.get(name)
        if suite is None:
            skipped.append(f"suite '{name}' not found in agentdojo {version}")
            continue
        inj = list(suite.injection_tasks.values())
        usr = list(suite.user_tasks.values())
        if limit_per_suite is not None:
            if len(inj) > limit_per_suite:
                skipped.append(f"{name} injection capped {len(inj)}->{limit_per_suite}")
            if len(usr) > limit_per_suite:
                skipped.append(f"{name} user capped {len(usr)}->{limit_per_suite}")
            inj, usr = inj[:limit_per_suite], usr[:limit_per_suite]
        for task in inj:
            text = wrap_injection(task.GOAL, jb_string)
            attacks.append(AttackCase(f"agentdojo-{name}-{task.ID}", f"agentdojo_{name}", text))
        benign.extend(task.PROMPT for task in usr)
    return attacks, benign, skipped
