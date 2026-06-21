//! Spotlighting / datamarking (T11). Makes untrusted-data provenance salient by replacing interword
//! whitespace with an unguessable marker token, disrupting injected instructions (Hines et al.,
//! arXiv:2403.14720). Mirrored by the Python fallback; shared vectors in tests/vectors/spotlight.json.

use regex::Regex;
use std::sync::OnceLock;

fn whitespace() -> &'static Regex {
    static WS: OnceLock<Regex> = OnceLock::new();
    WS.get_or_init(|| Regex::new(r"\s+").unwrap())
}

/// Trim, then replace each run of whitespace with `marker`.
pub fn datamark(text: &str, marker: &str) -> String {
    whitespace().replace_all(text.trim(), marker).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_interword_whitespace() {
        assert_eq!(
            datamark("ignore  previous\tinstructions", "^"),
            "ignore^previous^instructions"
        );
    }

    #[test]
    fn trims_and_leaves_single_token() {
        assert_eq!(datamark("  hello  ", "^"), "hello");
    }
}
