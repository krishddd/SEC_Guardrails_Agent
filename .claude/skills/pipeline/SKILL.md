---
description: Run research → explore → design → plan end to end, then stop for approval
argument-hint: [research-file]
allowed-tools: Read, Write, Grep, Glob
---
Run in sequence, stopping immediately if any step flags an open question or
contradiction instead of guessing through it:
1. /research-distill $ARGUMENTS
2. /explore (using the spec name)
3. /design (using the spec name) — but FIRST confirm the "trace fork" question is resolved; if not,
   stop and ask before designing.
4. /plan (using the spec name)

When done, summarize the plan and ask me to confirm before any /scaffold or
/implement work begins.
