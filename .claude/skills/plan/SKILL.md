---
description: Break an architecture doc into an ordered, checkable task list
argument-hint: [spec-name]
allowed-tools: Read, Write
---
Read docs/architecture/$ARGUMENTS.md. Write docs/plans/$ARGUMENTS-plan.md as
an ordered checklist of tasks, each one:
- Small enough to implement and test in one /implement run
- Tagged with a short id (T1, T2, ...)
- Noting dependencies on earlier tasks
- Noting what "done" looks like for that task specifically (tests to pass,
  not just "implement X")

Pull a minimal CI regression gate forward right after the input-rail tasks ("ASR on the
Security_module fixture set must not regress"), so later layers can't silently erode it. Put a latency
spike as the first sub-task of the input-rail layer (benchmark the classifier + PII + scrub stack
against the budget before the budget is load-bearing).

End with a "scaffold needed" section listing any new repo structure, config,
or CI changes /scaffold should set up before T1 starts.
