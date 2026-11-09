//! Route names, tags, domains and URLs.

use crate::usage;
use anyhow::Result;

const MAX_LABEL: usize = 63;

fn is_label_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

/// A DNS label: `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`.
pub fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    !s.is_empty()
        && s.len() <= MAX_LABEL
        && s.chars().all(|c| is_label_char(c) || c == '-')
        && is_label_char(b[0] as char)
        && is_label_char(b[b.len() - 1] as char)
}

pub fn validate_name(name: &str) -> Result<()> {
    if is_label(name) {
        return Ok(());
    }
    Err(usage(format!(
        "invalid name {name:?}: use 1 to 63 characters from a-z, 0-9 and '-', starting and ending with a letter or digit"
    )))
}

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() || tag.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(usage(format!(
            "invalid tag {tag:?}: it must not be empty or contain whitespace"
        )));
    }
    Ok(())
}

/// At least two labels, lowercase, e.g. `dev.example.com`.
pub fn validate_domain(domain: &str) -> Result<()> {
    let ok =
        domain.len() <= 253 && domain.split('.').count() >= 2 && domain.split('.').all(is_label);
    if ok {
        Ok(())
    } else {
        Err(usage(format!(
            "invalid base domain {domain:?}: expected something like dev.example.com (lowercase, dot separated)"
        )))
    }
}

/// Fails on a control character (CR, LF, NUL, ...): text that ends up in a generated Caddyfile
/// or systemd unit must not be able to start a new line there.
pub fn reject_control(what: &str, s: &str) -> Result<()> {
    if s.chars().any(char::is_control) {
        anyhow::bail!("{what} contains a control character: {s:?}");
    }
    Ok(())
}

pub fn host(name: &str, base: &str) -> String {
    format!("{name}.{base}")
}

/// `https://<name>.<base>`, with `:<port>` unless the port is 443.
pub fn url(name: &str, base: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{}", host(name, base))
    } else {
        format!("https://{}:{port}", host(name, base))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dns_labels() {
        for ok in ["a", "web", "my-app-2", "0x", &"a".repeat(63)] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_everything_else() {
        let long = "a".repeat(64);
        for bad in [
            "", "-a", "a-", "Web", "a_b", "a.b", "a b", "é", "a/b", "--", &long,
        ] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn name_errors_are_usage_errors() {
        let e = validate_name("A").unwrap_err();
        assert!(e.downcast_ref::<crate::UsageError>().is_some());
        assert!(e.to_string().contains("invalid name"));
    }

    #[test]
    fn urls_carry_the_port_unless_443() {
        assert_eq!(
            url("web", "dev.example.com", 443),
            "https://web.dev.example.com"
        );
        assert_eq!(
            url("web", "dev.example.com", 8443),
            "https://web.dev.example.com:8443"
        );
    }

    #[test]
    fn domains_need_two_labels() {
        assert!(validate_domain("dev.example.com").is_ok());
        assert!(validate_domain("localhost").is_err());
        assert!(validate_domain("Dev.example.com").is_err());
        assert!(validate_domain("a..com").is_err());
    }

    #[test]
    fn control_characters_are_rejected() {
        assert!(reject_control("x", "/a b/c").is_ok());
        for bad in ["a\nb", "a\rb", "a\0b", "a\u{1b}b"] {
            assert!(reject_control("x", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tags_have_no_whitespace() {
        assert!(validate_tag("feature/x").is_ok());
        assert!(validate_tag("").is_err());
        assert!(validate_tag("a b").is_err());
    }
}
