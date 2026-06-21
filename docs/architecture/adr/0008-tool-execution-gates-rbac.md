# ADR-0008: Research-distilled tool-execution gates + RBAC

## Context
Reviewing several agent-guardrail systems surfaced one control they *all* converge on, which our stack
was missing: a **deterministic tool-execution gate** that intercepts the agent's *intent* immediately
before a function runs, plus **role-based** scoping of which tools an agent may call at all.
- **LlamaFirewall** (arXiv:2505.03574) — PromptGuard 2, Agent Alignment Checks, and **CodeShield**, a
  static analysis layer that blocks insecure generated code before it executes.
- **AgentDoG** (AI45Lab) — pre-execution **trajectory inspection**: flag/intercept unsafe actions
  *before* they run, with rationale.
- **SupraWall / AperionAI / Agent-Guardrails (MCP)** — deterministic zero-trust gates that **hard-block
  destructive actions** (`rm -rf`, unscoped SQL `DELETE`/`DROP`).
- **Kore.ai / the "Tool-Execution Gates" guidance** — intercept before the call; **auto-inject row
  limits and restrict DDL** on DB queries; **RBAC** limiting which tools each agent is authorized to use.

## Decision
Add a compact, deterministic **`ExecGate`** (`src/rails/tool/exec_gate.py`) that runs *before* the L4
policy engine and hard-stops catastrophic intents regardless of policy:
- **Shell:** denylist of catastrophic commands (`rm -rf /`, `mkfs`, `dd of=/dev/*`, fork bomb,
  `shutdown`/`reboot`, `chmod -R 777 /`, …) → **hard BLOCK** (CodeShield/AperionAI pattern).
- **SQL:** **DDL** (`DROP`/`TRUNCATE`/`ALTER`/`GRANT`) and **unscoped DML** (`DELETE`/`UPDATE` with no
  `WHERE`) → **BLOCK**; a `SELECT` with no `LIMIT` → **MODIFY** (auto-inject `LIMIT n`).
Add **RBAC** to the policy engine (ADR-0004): `ToolCall.role` + an optional `roles` allowlist on a rule,
so a rule only matches for authorized roles (compile-time topology / least privilege).

Order of the tool pipeline: **ExecGate → PolicyEngine (RBAC, deny-by-default) → TaintGate (invariant)**.

## Consequences
- (+) Catastrophic actions are stopped deterministically, in microseconds, even if a policy rule or the
  model would have allowed them — the consensus "best solution" from 4+ frameworks, in ~one module.
- (+) RBAC narrows blast radius per agent role without new infrastructure.
- (+) No new heavy dependencies; keeps the stack lean (the "compact" goal).
- (−) Denylists/regex are heuristic — they complement, never replace, deny-by-default allowlisting; the
  adversarial test set guards against the obvious bypasses (quoting, casing, path variants).
- (−) SQL `LIMIT` injection is a naive transform (no full SQL parse); documented as best-effort, with a
  proper sqlglot-based rewrite noted as a follow-up.
