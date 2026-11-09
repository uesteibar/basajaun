//! Keeping the running proxy in line with the registry.
//!
//! The Caddyfile is written atomically and then pushed through Caddy's admin API (a unix socket
//! in the state directory) with `POST /load`, which swaps the configuration without dropping
//! connections. If the proxy is not running, the file is still written: the systemd unit starts
//! Caddy from it.

use crate::caddyfile::{self, Settings};
use crate::cloudflare;
use crate::config::Config;
use crate::paths::Paths;
use crate::redact::redact;
use crate::registry::{self, Route};
use crate::tailscale;
use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Loaded,
    /// Nothing answers on the admin socket.
    ProxyDown(String),
}

/// The address to bind: the live tailnet IP, else the one `setup` saw (both are checked to be in
/// the Tailscale range). Never anything wider.
pub fn bind_ip(cfg: &Config) -> Result<Ipv4Addr> {
    match tailscale::ipv4() {
        Ok(ip) => Ok(ip),
        Err(e) => cfg
            .tailnet_ip
            .with_context(|| format!("cannot find the tailnet IP: {e:#}")),
    }
}

pub fn render(paths: &Paths, cfg: &Config, routes: &[Route]) -> Result<String> {
    let ip = bind_ip(cfg)?;
    caddyfile::generate(
        &Settings {
            base_domain: &cfg.base_domain,
            port: cfg.port,
            bind_ip: ip,
            admin_socket: &paths.admin_socket(),
            storage_dir: &paths.storage_dir(),
            acme_ca: cfg.acme_ca.as_deref(),
            restrict_source: cfg.restrict_source,
        },
        routes,
    )
}

/// Write the Caddyfile for `routes` without touching the running proxy.
pub fn write_caddyfile(paths: &Paths, cfg: &Config, routes: &[Route]) -> Result<String> {
    let text = render(paths, cfg, routes)?;
    registry::create_private_dir(&paths.state_dir)?;
    registry::write_atomic(&paths.caddyfile(), text.as_bytes(), 0o644)?;
    Ok(text)
}

/// Write the Caddyfile for `routes` and load it into the running proxy (a hot apply: fine for
/// route changes, but a process cannot gain a port or a capability this way).
pub fn apply(paths: &Paths, cfg: &Config, routes: &[Route]) -> Result<Outcome> {
    let text = write_caddyfile(paths, cfg, routes)?;
    let token = cloudflare::stored_token(paths).unwrap_or_default();
    post_load(&paths.admin_socket(), &text, &[&token])
}

/// What to do when Caddy could not bind an address of the new configuration.
fn bind_hint(body: &str) -> Option<&'static str> {
    (body.contains("bind:") || body.contains("address already in use")).then_some(
        "the running proxy process cannot bind the configured address (a process keeps the capabilities it started with, and a port change needs a new listener it may not be allowed to open); once the port is allowed (`bsjn doctor` says how), run `bsjn setup` again: it restarts the service",
    )
}

/// `POST /load` with a Caddyfile body. Caddy's error text is passed on without `secrets`.
pub fn post_load(socket: &Path, caddyfile: &str, secrets: &[&str]) -> Result<Outcome> {
    let mut stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(e) => return Ok(Outcome::ProxyDown(format!("{}: {e}", socket.display()))),
    };
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let request = format!(
        "POST /load HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/caddyfile\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{caddyfile}",
        caddyfile.len()
    );
    stream
        .write_all(request.as_bytes())
        .context("cannot send the configuration to the proxy")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("cannot read the proxy's answer")?;
    let status: u16 = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("the proxy's admin API sent something that is not HTTP")?;
    if status == 200 {
        return Ok(Outcome::Loaded);
    }
    let body = redact(
        response
            .split_once("\r\n\r\n")
            .map_or("", |(_, b)| b.trim()),
        secrets,
    );
    let body = body.as_str();
    match bind_hint(body) {
        Some(hint) => bail!("the proxy rejected the configuration (HTTP {status}): {body}\n{hint}"),
        None => bail!("the proxy rejected the configuration (HTTP {status}): {body}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn serve_once(socket: &Path, reply: &'static str) -> std::thread::JoinHandle<String> {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            // The request is complete once the body announced by Content-Length arrived.
            loop {
                let n = conn.read(&mut buf).unwrap();
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if body.len() >= len || n == 0 {
                        break;
                    }
                }
            }
            conn.write_all(reply.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        })
    }

    #[test]
    fn posts_the_caddyfile_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("admin.sock");
        let server = serve_once(&sock, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(post_load(&sock, "a {\n}\n", &[]).unwrap(), Outcome::Loaded);
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /load HTTP/1.1\r\n"));
        assert!(request.contains("Content-Type: text/caddyfile\r\n"));
        assert!(request.ends_with("\r\n\r\na {\n}\n"));
    }

    #[test]
    fn a_rejected_configuration_is_an_error_with_caddys_reason() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("admin.sock");
        let server = serve_once(
            &sock,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 9\r\n\r\nbad stuff",
        );
        let err = post_load(&sock, "x", &[]).unwrap_err().to_string();
        server.join().unwrap();
        assert!(err.contains("400") && err.contains("bad stuff"), "{err}");
    }

    #[test]
    fn the_token_does_not_come_back_in_a_rejected_configuration_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("admin.sock");
        let body = "loading config: provision dns.providers.cloudflare: API token 'DUMMY value' appears invalid; ensure it's correctly entered";
        let reply: &'static str = Box::leak(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let server = serve_once(&sock, reply);
        let err = format!("{:#}", post_load(&sock, "x", &["DUMMY value"]).unwrap_err());
        server.join().unwrap();
        assert!(
            err.contains("400") && err.contains("appears invalid"),
            "{err}"
        );
        assert!(!err.contains("DUMMY"), "{err}");
    }

    #[test]
    fn a_bind_error_says_to_run_setup_again() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("admin.sock");
        let body = r#"{"error":"loading config: starting: listen tcp 100.64.0.1:443: bind: permission denied"}"#;
        let reply: &'static str = Box::leak(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let server = serve_once(&sock, reply);
        let err = post_load(&sock, "x", &[]).unwrap_err().to_string();
        server.join().unwrap();
        assert!(err.contains("permission denied"), "{err}");
        assert!(
            err.contains("run `bsjn setup` again") && err.contains("restarts the service"),
            "{err}"
        );
        assert_eq!(bind_hint("some other problem"), None);
    }

    #[test]
    fn a_missing_socket_means_the_proxy_is_down() {
        let dir = tempfile::tempdir().unwrap();
        let out = post_load(&dir.path().join("nope.sock"), "x", &[]).unwrap();
        assert!(matches!(out, Outcome::ProxyDown(_)));
    }
}
