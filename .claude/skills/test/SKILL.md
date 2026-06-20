---
description: Run tests, optionally filtered, and fix failures
argument-hint: [pattern]
allowed-tools: Bash, Read, Edit
---
Run the project's test suite with pytest, matching: $ARGUMENTS
(e.g. `pytest -k "$ARGUMENTS"`; bare `pytest` if no pattern given).
If anything fails, read the failure, fix the root cause (not the assertion),
and re-run until green or until you hit something that needs a design
decision — in that case stop and explain rather than guessing.
