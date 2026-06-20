---
description: Produce an architecture doc and ADRs from a spec and exploration notes
argument-hint: [spec-name]
allowed-tools: Read, Write
---
Read docs/specs/$ARGUMENTS-spec.md and docs/architecture/exploration-$ARGUMENTS.md.

GATE: do not run until the "trace fork" question is resolved (can the Odysseus container be modified
to expose its per-step tool trace?). That answer sets whether L4/L5/multi-agent rails are active-now or
permanently wiring-gated. If unresolved, design on the basis of "permanently gated for v1".

Write docs/architecture/$ARGUMENTS.md containing:
- High-level approach (2-3 paragraphs)
- Component breakdown
- Data flow / sequence (describe it; use a diagram if the project has a
  diagramming convention already)
- Key trade-offs considered and rejected, with why

For every decision with real alternatives, also write a short ADR to
docs/architecture/adr/<NNNN>-<slug>.md (Context / Decision / Consequences format).
At minimum: external-proxy vs container-patch; build-from-scratch control plane vs adopt-NeMo; output
classifier choice; in-house policy DSL for L4 (OPA/Rego = v2 path). Before any ADR locks a model/version,
re-verify the artifact still exists (model IDs drift). The L4-DSL ADR must require a security-reviewer
pass + an adversarial policy-bypass test set before the DSL gates HITL/irreversible tools.

Flag anything from "Open questions" in the spec that blocks design — don't
silently resolve it.
