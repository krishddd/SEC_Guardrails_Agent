# Security Policy

## Scope

This project is a **defensive** runtime guardrail for the Odysseus agent. It is research/educational
security tooling. It does **not** include offensive capabilities (those live in a separate red-team
project and are reused only as an evaluation oracle).

## Reporting a vulnerability

If you find a security issue — especially a **guardrail bypass** (a rail that can be made to fail open,
an encoding/obfuscation that slips past a detector, untrusted data reaching a tool without a taint
check, or a policy-DSL parser edge case) — please report it privately:

- Use **GitHub Security Advisories** ("Report a vulnerability" on the Security tab), or
- email the maintainer.

Please do **not** open a public issue for a sensitive report. Include reproduction steps and, if
possible, the affected rail/layer.

## Handling

- We aim to acknowledge reports promptly and to fix confirmed guardrail bypasses on priority, since a
  bypass defeats the purpose of the project.
- Fixes ship through the normal PR flow with an adversarial regression test added for the bypass.

## Out of scope

- Skill/MCP supply-chain attacks (handled separately; see `CLAUDE.md`).
- Vulnerabilities in the upstream Odysseus agent, the offensive `Security_module`, or the
  `Agent eval pipeline` — report those to their respective projects.
