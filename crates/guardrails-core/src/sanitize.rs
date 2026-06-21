//! URL/markdown/HTML sanitizer (T18). Strips exfiltration side-channels from agent output: markdown
//! images (data-bearing `src`), non-allowlisted markdown links, and raw HTML/script/style. Mirrored
//! by the Python fallback; shared vectors in tests/vectors/sanitize.json.

use regex::Regex;
use std::sync::OnceLock;

struct Patterns {
    image: Regex,
    link: Regex,
    script: Regex,
    style: Regex,
    tag: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        image: Regex::new(r"!\[[^\]]*\]\([^)]*\)").unwrap(),
        link: Regex::new(r"\[([^\]]*)\]\(([^)]+)\)").unwrap(),
        script: Regex::new(r"(?is)<script\b[^>]*>.*?</script>").unwrap(),
        style: Regex::new(r"(?is)<style\b[^>]*>.*?</style>").unwrap(),
        tag: Regex::new(r"(?s)<[^>]+>").unwrap(),
    })
}

fn host_of(url: &str) -> String {
    let mut u = url.trim();
    if let Some(i) = u.find("://") {
        u = &u[i + 3..];
    }
    if let Some(i) = u.find('@') {
        u = &u[i + 1..];
    }
    let end = u.find(|c| matches!(c, '/' | '?' | '#' | ':')).unwrap_or(u.len());
    u[..end].to_lowercase()
}

/// Remove markdown images, reduce non-allowlisted links to their text, strip HTML.
pub fn sanitize_markup(text: &str, allow_hosts: &[String]) -> String {
    let p = patterns();
    let mut s: String = p.image.replace_all(text, "").into_owned();
    s = p
        .link
        .replace_all(&s, |c: &regex::Captures| {
            let label = &c[1];
            let url = &c[2];
            let host = host_of(url);
            if allow_hosts.iter().any(|a| a.eq_ignore_ascii_case(host.as_str())) {
                format!("[{label}]({url})")
            } else {
                label.to_string()
            }
        })
        .into_owned();
    s = p.script.replace_all(&s, "").into_owned();
    s = p.style.replace_all(&s, "").into_owned();
    s = p.tag.replace_all(&s, "").into_owned();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_images_and_disallowed_links() {
        let out = sanitize_markup("a ![i](http://e.com/p) [x](http://e.com) b", &[]);
        assert_eq!(out, "a  x b");
    }

    #[test]
    fn keeps_allowlisted_link() {
        let allow = vec!["good.com".to_string()];
        assert_eq!(sanitize_markup("[d](https://good.com/p)", &allow), "[d](https://good.com/p)");
    }

    #[test]
    fn strips_html() {
        assert_eq!(sanitize_markup("<script>x()</script>hi<b>!</b>", &[]), "hi!");
    }
}
