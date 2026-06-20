---
description: Distill a raw research markdown doc into a structured spec
argument-hint: [research-file]
allowed-tools: Read, Write, Grep, Glob
---
Read research/$ARGUMENTS.

Extract and write docs/specs/$ARGUMENTS-spec.md with these sections:
- Problem statement (1 paragraph)
- Goals (bulleted, testable)
- Non-goals (explicit exclusions)
- Constraints (technical, timeline, dependencies)
- Open questions (anything underspecified — flag, don't guess)
- Success criteria (how we'll know this is done)

For this project specifically: success criteria MUST give utility-retention a concrete threshold —
name a fixed benign-task benchmark and a max-acceptable degradation (e.g. task-completion drop %,
over-refusal %) alongside the ASR-reduction target. Report metrics split (ASR vs FPR/utility), never
a single blended F1.

Do not invent requirements that aren't in the source doc or reasonably implied.
If the research doc contradicts itself, surface the contradiction instead of
silently picking one interpretation.
