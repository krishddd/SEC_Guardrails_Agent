# Repo skills

Version-controlled Claude Code skills authored for this project. They live here (not in `.claude/`)
because the `pre-edit-guard` hook blocks automated edits to `.claude/*`; keeping the source here lets
the skills be reviewed and diffed like any other code.

## Activate a skill

Copy it into a skills directory Claude Code loads:

```bash
# project scope (this repo only) — or omit the hook by copying manually:
cp -r skills/guardrails-research .claude/skills/

# user scope (all your projects):
cp -r skills/guardrails-research ~/.claude/skills/      # Windows: %USERPROFILE%\.claude\skills\
```

Then invoke with `/guardrails-research`.

## Available

| Skill | Purpose |
|---|---|
| [`guardrails-research`](guardrails-research/SKILL.md) | Research SOTA agent guardrails (vendors + arXiv), adversarially verify, and produce a grounded `docs/research/` digest + `docs/plans/` task plan. Planning only — no code. |
