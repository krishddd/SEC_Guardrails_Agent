---
description: Regenerate README and architecture docs to match current code
allowed-tools: Read, Write, Bash(git log:*)
---
Compare docs/architecture/*.md against current code. Update anything that's
drifted. Regenerate README.md: what this does, how to run it, how to test it,
where the specs/plans/ADRs live. This is also what onboarding a new
teammate should run first.
