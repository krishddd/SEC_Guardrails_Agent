---
description: Set up repo structure, Python package manifest, lint/test config from a plan
argument-hint: [spec-name]
allowed-tools: Read, Write, Bash(mkdir:*), Bash(git:*)
---
Read the "scaffold needed" section of docs/plans/$ARGUMENTS-plan.md and
CLAUDE.md's Stack section. Create the directory structure, the Python package
manifest (`pyproject.toml` configured for ruff + pytest, editable install),
the `src/` package layout and `tests/`, and a minimal CI skeleton (don't fill
in real jobs yet — that already exists under .github/workflows). Use Python
tooling only — there is NO npm/Node in this project. Stop and report what you
created; don't start implementing tasks.
