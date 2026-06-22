# ADR-0010: Round-2 research-distilled controls (budget, word-filter, CodeShield, incident taxonomy)

## Context
A second pass over the shared references surfaced four more controls that the stack lacked, each cheap,
deterministic, and distinct from what we already had:
- **Budget / cost tracking** — Pydantic AI Shields' `CostTracking` (`budget_usd`, raises on overrun).
- **Blocked-phrases / word filter** — AWS Bedrock Guardrails' word-filter policies.
- **CodeShield** — LlamaFirewall (arXiv:2505.03574): static analysis of LLM-*generated code* for
  insecure patterns (CWE taxonomy), beyond the shell/SQL exec gate.
- **Incident taxonomy** — AgentDoG's three-dimensional classification (risk-source / failure-mode /
  real-world harm) attached to each block for richer governance.

## Decision
Add all four as compact modules behind the existing interfaces (no new heavy deps):
- `core/budget.py` — `Budget` + `BudgetTracker.check_and_charge`; the engine charges per allowed tool
  call and blocks on overrun (deny-by-default on budget). Bounds blast radius + runaway cost.
- `rails/dialog/word_filter.py` — `WordFilterRail` exact-phrase denylist; wired into the input AND
  output chains (empty = no-op).
- `rails/tool/code_shield.py` — `CodeShieldRail` regex scan for dangerous codegen
  (`eval`/`exec`/`os.system`/`subprocess(..., shell=True)`/`pickle.loads`/`yaml.load`/SQL string concat).
- `eval/taxonomy.py` — map a block's `stage`/reason to (risk-source, failure-mode, harm); surfaced in
  the governance export.

## Consequences
- (+) Budget/cost + word-filter + codegen safety + taxonomy round out the parity with Bedrock /
  Pydantic-Shields / LlamaFirewall / AgentDoG, in a few hundred lines.
- (+) Everything stays deterministic and CI-verifiable behind the unified engine.
- (−) Word-filter and CodeShield are denylists (heuristic) — they complement, never replace, the
  allowlist/deny-by-default core; token/USD charges are estimates until real model usage is wired.
