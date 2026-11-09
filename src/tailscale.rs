//! Asking the local Tailscale daemon through the `tailscale` CLI.

use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use std::process::Command;

/// The tailnet IPv4 of this host (`tailscale ip -4`).
pub fn ipv4() -> Result<Ipv4Addr> {
    let out = Command::new("tailscale")
        .args(["ip", "-4"])
        .output()
        .context("cannot run `tailscale` (is it installed and on PATH?)")?;
    if !out.status.success() {
        bail!(
            "`tailscale ip -4` failed: {}",
            crate::redact::redact(String::from_utf8_lossy(&out.stderr).trim(), &[])
        );
    }
    parse_ip(&String::from_utf8_lossy(&out.stdout))
}

/// Tailscale's IPv4 range, 100.64.0.0/10 (the CGNAT block).
pub fn is_tailnet_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && b & 0b1100_0000 == 64
}

/// `Ok` for a tailnet address, otherwise an error that names what is wrong with it. This guards
/// the one address the proxy binds: never unspecified, loopback or public.
pub fn require_tailnet_ipv4(ip: Ipv4Addr) -> Result<Ipv4Addr> {
    if is_tailnet_ipv4(ip) {
        Ok(ip)
    } else {
        bail!("{ip} is not a Tailscale address (expected 100.64.0.0/10)")
    }
}

fn parse_ip(text: &str) -> Result<Ipv4Addr> {
    let ip = text
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok())
        .context("`tailscale ip -4` printed no IPv4 address")?;
    require_tailnet_ipv4(ip).context("`tailscale ip -4` printed an unusable address")
}

/// `Ok(())` when the backend state is `Running`.
pub fn ensure_running() -> Result<()> {
    let out = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .context("cannot run `tailscale` (is it installed and on PATH?)")?;
    // Tailscale prints the JSON status even when it is stopped; only a missing daemon fails.
    let state = parse_state(&String::from_utf8_lossy(&out.stdout)).with_context(|| {
        format!(
            "cannot read the Tailscale status: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    })?;
    if state == "Running" {
        Ok(())
    } else {
        bail!("Tailscale is {state}")
    }
}

fn parse_state(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    Some(v.get("BackendState")?.as_str()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_first_line() {
        assert_eq!(
            parse_ip("100.64.0.1\n").unwrap(),
            Ipv4Addr::new(100, 64, 0, 1)
        );
        assert!(parse_ip("").is_err());
        assert!(parse_ip("fd7a::1\n").is_err());
    }

    #[test]
    fn only_the_tailscale_range_is_accepted() {
        for ok in ["100.64.0.0", "100.64.0.1", "100.127.255.255"] {
            assert!(parse_ip(ok).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "127.0.0.1",
            "8.8.8.8",
            "192.168.1.5",
            "100.63.255.255",
            "100.128.0.0",
            "10.64.0.1",
        ] {
            assert!(parse_ip(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reads_the_backend_state() {
        assert_eq!(
            parse_state(r#"{"Version":"1","BackendState":"Stopped"}"#).as_deref(),
            Some("Stopped")
        );
        assert_eq!(parse_state("not json"), None);
    }
}
