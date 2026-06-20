---
description: Map the existing codebase relevant to a spec before designing
argument-hint: [spec-name]
allowed-tools: Read, Write
context: fork
agent: explorer
---
Using the explorer subagent, investigate everything relevant to
docs/specs/$ARGUMENTS-spec.md. Write findings to
docs/architecture/exploration-$ARGUMENTS.md.

Cover at minimum: the Odysseus API contract (see the sibling
`Agent eval pipeline/adapters/odysseus_adapter.py`), the offensive attack files in
`Agent_security_testing/Security_module` (ASI01–10, ext01–17) that the guardrails must defend,
reuse points in the eval pipeline (scorer, grounding judge), and available credentials/config.
Report as a flat list with file:line references. No prose padding.
