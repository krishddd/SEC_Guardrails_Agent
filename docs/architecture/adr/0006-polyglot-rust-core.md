# ADR-0006: Rust for the deterministic, security-critical guardrail core

## Context
Several rails are (a) on the hot path under a <30 ms input budget, and (b) security-critical parsers
where a bug is itself a bypass: the secrets/regex scanner, the spotlighting/datamarking transformer, the
URL/HTML/markdown sanitizer, and the L4 **policy-DSL evaluator** (ADR-0004 explicitly flagged that a
home-grown policy parser accumulates edge cases that become bypasses). Python is fine for orchestration
and ML, but a memory-unsafe or slow parser at a trust boundary is exactly where we don't want it.

## Decision
Implement the deterministic security core in **Rust**, compiled to a Python extension module
(`guardrails_core`) via **PyO3 + maturin**, and called behind the same `Rail` interface as everything
else. Scope of the Rust core:
- secrets/regex scanner, spotlighting/datamarker, URL/HTML/markdown sanitizer,
- the policy-DSL parser + evaluator (deny-by-default `ToolCall` matching),
- the taint-label propagation primitives.

Each Rust-backed rail keeps a **pure-Python fallback** so the system runs (slower) where the compiled
extension is unavailable; the active backend is recorded per decision for audit. Memory safety in the
sanitizer/policy parser is treated as a security requirement, not an optimization.

## Consequences
- (+) Memory-safe parsers at the trust boundary; no buffer/UAF class of bypass.
- (+) Headroom for the <30 ms input budget; the policy evaluator runs in microseconds.
- (+) Directly strengthens ADR-0004 (the DSL evaluator is the highest-value Rust target).
- (−) Multi-toolchain build/CI (cargo + maturin) and a PyO3 FFI boundary to test.
- (−) Two implementations (Rust + Python fallback) to keep behaviourally identical — covered by a shared
  test vector set run against both backends.
