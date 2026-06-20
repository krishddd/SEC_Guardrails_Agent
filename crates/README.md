# crates/ — Rust security core (ADR-0006)

Home of `guardrails-core/`, the Rust crate compiled via **PyO3 + maturin** to the `guardrails_core`
Python extension. It implements the deterministic, security-critical, hot-path rails:

- secrets/regex scanner
- spotlighting / datamarking transformer
- URL / HTML / markdown sanitizer
- the L4 **policy-DSL parser + evaluator** (deny-by-default `ToolCall` matching)
- taint-label propagation primitives

Each has a **pure-Python fallback** in `src/rails/…` behind the same `Rail` interface, and a shared
`tests/vectors/` set is run against both backends (they must agree). Memory safety at the trust
boundary is treated as a security requirement (see ADR-0004/0006).

> The crate itself is created in task **T6b**; until then this directory is a placeholder and the
> `rust-core` CI lane stays skipped (it triggers only when `crates/guardrails-core/Cargo.toml` exists).
