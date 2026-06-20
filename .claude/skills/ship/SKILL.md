---
description: Pre-deploy checklist, changelog, tag, trigger deploy
argument-hint: [spec-name]
allowed-tools: Bash(git:*), Read, Write
disable-model-invocation: true
---
Verify: all tasks in docs/plans/$ARGUMENTS-plan.md are checked, tests are
green, /review has no blocker findings. If any of that isn't true, stop and
report — do not proceed.

If clean: update CHANGELOG.md, bump version per CLAUDE.md convention, tag,
push. Do not merge to main or trigger deploy without an explicit go-ahead
from me in this conversation, even if everything above passed.
