---
description: Implement a single task from a plan, with tests
argument-hint: [spec-name] [task-id]
allowed-tools: Read, Write, Edit, Bash, Grep, Glob
---
Read docs/plans/$ARGUMENTS-plan.md, find the task by id (second argument).
Implement only that task. Write tests that match its "done" definition
(use pytest; place tests under tests/).
Run the tests with `pytest`. If they fail, fix and re-run until green.
When green, check the box for that task in the plan file and stop —
do not cascade into the next task automatically.

Never weaken a rail or a test to make it pass. If a task gates HITL or irreversible-tool behaviour,
include adversarial (bypass-attempt) tests, not just happy-path.
