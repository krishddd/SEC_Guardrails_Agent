---
description: Run quality and security review on the current diff
allowed-tools: Read
context: fork
---
Run the reviewer subagent and the security-reviewer subagent against the
current diff. Merge findings into one severity-ranked list. Block on any
"blocker"-severity finding — don't soften it.
