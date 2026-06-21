//! `guardrails_core` — the Rust security core exposed to Python via PyO3 (ADR-0006).
//! Deterministic, security-critical, hot-path primitives. Each has a pure-Python fallback in
//! `src/core/native.py`; the shared `tests/vectors/` set must agree across both backends.

use pyo3::prelude::*;

mod sanitize;
mod secrets;
mod spotlight;

/// Redact common secret patterns from `text`, returning the masked string.
#[pyfunction]
fn redact_secrets(text: &str) -> String {
    secrets::redact(text)
}

/// Datamark untrusted text: trim, then replace interword whitespace with `marker`.
#[pyfunction]
fn datamark(text: &str, marker: &str) -> String {
    spotlight::datamark(text, marker)
}

/// Sanitize markup: strip images, reduce non-allowlisted links to text, strip HTML.
#[pyfunction]
fn sanitize_markup(text: &str, allow_hosts: Vec<String>) -> String {
    sanitize::sanitize_markup(text, &allow_hosts)
}

/// Crate version — a trivial smoke export to confirm the extension loaded.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn guardrails_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(redact_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(datamark, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_markup, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
