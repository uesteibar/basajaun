//! Keeping the Cloudflare token out of text that bsjn relays. The pinned `caddy-dns/cloudflare`
//! module echoes a malformed token into its error (`API token '<value>' appears invalid ...`),
//! and Caddy's admin API passes that error on.

const MASK: &str = "[redacted]";
const ECHO_START: &str = "API token '";
const ECHO_END: &str = "' appears invalid";

/// `text` without any of `secrets` and without the value the plugin echoes. Empty secrets are
/// ignored.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        out = out.replace(secret, MASK);
    }
    // The echoed value is removed even when it is not the stored token (a different malformed
    // value in the environment).
    let mut rest = out.as_str();
    let mut clean = String::new();
    while let Some(start) = rest.find(ECHO_START) {
        let value_at = start + ECHO_START.len();
        let Some(len) = rest[value_at..].find(ECHO_END) else {
            break;
        };
        clean.push_str(&rest[..value_at]);
        clean.push_str(MASK);
        rest = &rest[value_at + len..];
    }
    clean.push_str(rest);
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stored_token_is_removed_wherever_it_appears() {
        let text = "bad header Bearer abc123SECRET and again abc123SECRET";
        let out = redact(text, &["abc123SECRET"]);
        assert!(!out.contains("abc123SECRET"), "{out}");
        assert_eq!(out.matches("[redacted]").count(), 2);
    }

    #[test]
    fn the_value_the_plugin_echoes_is_removed_even_when_unknown() {
        let body = r#"{"error":"provision dns.providers.cloudflare: API token 'Not A Token!' appears invalid; ensure it's correctly entered and not wrapped in braces nor quotes"}"#;
        let out = redact(body, &[]);
        assert!(!out.contains("Not A Token"), "{out}");
        assert!(
            out.contains("API token '[redacted]' appears invalid"),
            "{out}"
        );
    }

    #[test]
    fn plain_text_and_empty_secrets_are_left_alone() {
        assert_eq!(
            redact("listen tcp: bind: permission denied", &[""]),
            "listen tcp: bind: permission denied"
        );
        // An unterminated echo is not cut at random.
        assert_eq!(redact("API token 'abc", &[]), "API token 'abc");
    }
}
