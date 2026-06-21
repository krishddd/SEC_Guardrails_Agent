//! Secrets scanner (T8). Deterministic, pattern-based redaction of common credential formats.
//! Mirrored by the pure-Python fallback in `src/core/native.py`; both are exercised by the shared
//! vectors in `tests/vectors/secrets.json`.

use regex::Regex;
use std::sync::OnceLock;

fn patterns() -> &'static Vec<(Regex, &'static str)> {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(), "OPENAI_KEY"),
            (
                Regex::new(r"gh[oprsu]_[A-Za-z0-9]{20,}").unwrap(),
                "GITHUB_TOKEN",
            ),
            (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS_ACCESS_KEY"),
            (
                Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
                "SLACK_TOKEN",
            ),
        ]
    })
}

/// Replace every recognized secret with `[REDACTED:<LABEL>]`. Returns the input unchanged when clean.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for (re, label) in patterns() {
        let replacement = format!("[REDACTED:{label}]");
        out = re.replace_all(&out, replacement.as_str()).into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_secrets() {
        let r = redact("k sk-ABCDEFGHIJKLMNOPQRSTUV and AKIAIOSFODNN7EXAMPLE end");
        assert!(r.contains("[REDACTED:OPENAI_KEY]"));
        assert!(r.contains("[REDACTED:AWS_ACCESS_KEY]"));
        assert!(!r.contains("sk-ABCDEF"));
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let s = "nothing secret here";
        assert_eq!(redact(s), s);
    }
}
