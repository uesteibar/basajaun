//! `bsjn doctor`: read-only checks, each failure with the exact fix.

use crate::cloudflare::{self, Client};
use crate::config::Config;
use crate::paths::Paths;
use crate::{firewall, service, tailscale};
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

/// `ok` and `fail` are what they say. `warn` is "could not be determined": it does not fail the
/// run (`ok` stays true) but is not a pass either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    /// False only for `Level::Fail`; `--json` consumers keep reading this.
    pub ok: bool,
    pub level: Level,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn pass(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok: true,
        level: Level::Ok,
        detail: detail.into(),
        fix: None,
    }
}

/// Could not be determined; `verify` is the command that settles it.
fn warn(name: &'static str, detail: impl Into<String>, verify: impl Into<String>) -> Check {
    Check {
        name,
        ok: true,
        level: Level::Warn,
        detail: detail.into(),
        fix: Some(verify.into()),
    }
}

fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        name,
        ok: false,
        level: Level::Fail,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}

pub fn run(json: bool) -> Result<i32> {
    let checks = run_checks(&Paths::from_env()?);
    print_checks(&checks, json)?;
    Ok(if checks.iter().all(|c| c.ok) { 0 } else { 1 })
}

pub fn print_checks(checks: &[Check], json: bool) -> Result<()> {
    if json {
        let ok = checks.iter().all(|c| c.ok);
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"ok": ok, "checks": checks}))?
        );
        return Ok(());
    }
    for c in checks {
        let (label, hint) = match c.level {
            Level::Ok => ("ok  ", "fix: "),
            Level::Warn => ("WARN", "verify: "),
            Level::Fail => ("FAIL", "fix: "),
        };
        println!("{label}  {:<12} {}", c.name, c.detail);
        if let Some(fix) = &c.fix {
            for (i, line) in fix.lines().enumerate() {
                let lead = if i == 0 {
                    hint
                } else {
                    &" ".repeat(hint.len())
                };
                println!("      {lead}{line}");
            }
        }
    }
    Ok(())
}

pub fn run_checks(paths: &Paths) -> Vec<Check> {
    let mut checks = Vec::new();

    let ip = match tailscale::ensure_running().and_then(|()| tailscale::ipv4()) {
        Ok(ip) => {
            checks.push(pass("tailscale", format!("up, tailnet IP {ip}")));
            Some(ip.to_string())
        }
        Err(e) => {
            checks.push(fail(
                "tailscale",
                format!("{e:#}"),
                "start Tailscale: `sudo tailscale up` (or `tailscale up` if you are the operator)",
            ));
            None
        }
    };

    let cfg = match Config::try_load(paths) {
        Ok(Some(cfg)) => {
            checks.push(pass(
                "config",
                format!(
                    "{}: base domain {}, port {}",
                    paths.config_file().display(),
                    cfg.base_domain,
                    cfg.port
                ),
            ));
            Some(cfg)
        }
        Ok(None) => {
            checks.push(fail("config", "no config file", "run `bsjn setup`"));
            None
        }
        Err(e) => {
            checks.push(fail(
                "config",
                format!("{e:#}"),
                "fix the file or run `bsjn setup`",
            ));
            None
        }
    };
    let Some(cfg) = cfg else {
        return checks;
    };

    checks.push(check_token(paths, &cfg));
    checks.push(check_dns(&cfg, ip.as_deref()));
    checks.push(check_proxy(&cfg, ip.as_deref()));
    checks.push(check_certificate(&cfg, ip.as_deref()));
    checks.push(check_port(paths, &cfg));
    checks.push(check_firewall(&firewall::System, &cfg));
    checks
}

/// Does the host firewall drop other ingress? Read-only and best effort, see `firewall`.
fn check_firewall(probe: &dyn firewall::Probe, cfg: &Config) -> Check {
    match firewall::assess(probe, cfg.port) {
        firewall::Verdict::Ok(detail) => pass("firewall", detail),
        firewall::Verdict::Fail { detail, fix } => fail("firewall", detail, fix),
        firewall::Verdict::Unknown { detail, verify } => warn("firewall", detail, verify),
    }
}

fn check_token(paths: &Paths, cfg: &Config) -> Check {
    let file = paths.token_file();
    let mode = match std::fs::metadata(&file) {
        Ok(m) => m.permissions().mode() & 0o777,
        Err(_) => {
            return fail(
                "token",
                format!("{} is missing", file.display()),
                "run `bsjn setup` (create the token as described there)",
            );
        }
    };
    if mode != 0o600 {
        return fail(
            "token",
            format!("{} has mode {mode:o}, expected 600", file.display()),
            format!("chmod 600 {}", file.display()),
        );
    }
    let token = match std::fs::read_to_string(&file) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            return fail(
                "token",
                format!("cannot read {}: {e}", file.display()),
                "run `bsjn setup`",
            );
        }
    };
    let client = Client::new(&token);
    let result = client.verify().and_then(|()| client.zones());
    match result {
        Ok(zones) => match cloudflare::pick_zone(&zones, &cfg.base_domain) {
            Some(z) => pass("token", format!("valid, zone {} readable", z.name)),
            None => fail(
                "token",
                format!("valid, but it cannot see a zone for {}", cfg.base_domain),
                "create a token whose zone resources include the zone, then `bsjn setup --token-stdin`",
            ),
        },
        Err(e) => fail(
            "token",
            format!("{e:#}"),
            "create a new token (see `bsjn setup`) and run `bsjn setup --token-stdin`",
        ),
    }
}

fn check_dns(cfg: &Config, ip: Option<&str>) -> Check {
    let probe = format!("bsjn-doctor-probe.{}", cfg.base_domain);
    let fix = format!(
        "`bsjn setup` creates the wildcard record *.{} -> your tailnet IP (DNS only)",
        cfg.base_domain
    );
    let Some(ip) = ip else {
        return fail(
            "dns",
            "cannot compare without the tailnet IP",
            "fix the tailscale check first",
        );
    };
    match (probe.as_str(), 0).to_socket_addrs() {
        Ok(addrs) => {
            let found: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if found.iter().any(|a| a == ip) {
                pass("dns", format!("*.{} resolves to {ip}", cfg.base_domain))
            } else {
                fail(
                    "dns",
                    format!("{probe} resolves to {}, expected {ip}", found.join(", ")),
                    fix,
                )
            }
        }
        Err(e) => fail("dns", format!("{probe} does not resolve: {e}"), fix),
    }
}

/// One listening socket from `ss -H -lntu[p]`.
#[derive(Debug, PartialEq, Eq)]
pub struct Listener {
    pub proto: String,
    pub host: String,
    pub port: u16,
    /// Only when `ss` can show the owner. A binary with file capabilities (the proxy on a
    /// privileged port) is not dumpable, so the owner is then hidden even from the same user.
    pub pid: Option<u32>,
}

impl Listener {
    fn show(&self) -> String {
        format!("{}:{} ({})", self.host, self.port, self.proto)
    }
}

pub fn parse_ss(output: &str) -> Vec<Listener> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (host, port) = f.get(4)?.rsplit_once(':')?;
            let pid = f
                .iter()
                .find(|x| x.starts_with("users:"))
                .and_then(|u| u.split("pid=").nth(1))
                .and_then(|p| p.split(',').next())
                .and_then(|p| p.parse().ok());
            Some(Listener {
                proto: f[0].to_string(),
                host: host.trim_matches(['[', ']']).to_string(),
                port: port.parse().ok()?,
                pid,
            })
        })
        .collect()
}

/// Is a TCP socket listening on exactly `ip:port`, whoever owns it?
pub fn tcp_listening(ss_output: &str, ip: &str, port: u16) -> bool {
    parse_ss(ss_output)
        .iter()
        .any(|l| l.proto == "tcp" && l.host == ip && l.port == port)
}

pub fn listening_now(ip: &str, port: u16) -> bool {
    tcp_listening(&ss_listeners(), ip, port)
}

fn ss_listeners() -> String {
    Command::new("ss")
        .args(["-H", "-l", "-n", "-t", "-u", "-p"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Is the proxy bound to `ip:port` and nothing wider? Decided from the sockets (address and
/// port), not from who owns them. Where `ss` does show the owner, the proxy's other sockets
/// must be on `ip` too. `Err` is (detail, fix).
fn judge_listeners(
    ss_output: &str,
    pid: u32,
    ip: &str,
    port: u16,
) -> std::result::Result<(), (String, String)> {
    let listeners = parse_ss(ss_output);
    let mut stray: Vec<String> = listeners
        .iter()
        .filter(|l| l.host != ip && (l.port == port || l.pid == Some(pid)))
        .map(Listener::show)
        .collect();
    stray.sort();
    stray.dedup();
    if !stray.is_empty() {
        return Err((
            format!("bound on {} instead of only {ip}", stray.join(", ")),
            format!(
                "find the owner with `ss -tulnp | grep :{port}`; if it is the proxy, stop it (`systemctl --user stop bsjn-proxy`) and run `bsjn setup`"
            ),
        ));
    }
    if tcp_listening(ss_output, ip, port) {
        return Ok(());
    }
    Err((
        format!("running (pid {pid}) but not listening on {ip}:{port}"),
        "wait a few seconds; if it stays like this the process predates the port or the capability: run `bsjn setup` (it restarts the service), or see: journalctl --user -u bsjn-proxy -n 50 --no-pager".into(),
    ))
}

fn check_proxy(cfg: &Config, ip: Option<&str>) -> Check {
    let logs = "journalctl --user -u bsjn-proxy -n 50 --no-pager";
    if !service::is_active() {
        return fail(
            "proxy",
            "the bsjn-proxy service is not running",
            format!("`bsjn setup` (re)installs and starts it; see why it stopped: {logs}"),
        );
    }
    let Some(pid) = service::main_pid() else {
        return fail("proxy", "no main process", logs);
    };
    let Some(ip) = ip else {
        return fail(
            "proxy",
            "cannot check the bind address without the tailnet IP",
            "fix the tailscale check first",
        );
    };
    match judge_listeners(&ss_listeners(), pid, ip, cfg.port) {
        Ok(()) => pass(
            "proxy",
            format!("running (pid {pid}), bound only to {ip}:{}", cfg.port),
        ),
        Err((detail, fix)) => fail("proxy", detail, fix),
    }
}

/// What `openssl s_client` and `openssl x509` tell about the certificate on `addr`.
pub fn check_certificate(cfg: &Config, ip: Option<&str>) -> Check {
    let fix = "wait for issuance after `bsjn setup` (DNS-01 takes about a minute), then see: journalctl --user -u bsjn-proxy -n 100 --no-pager";
    let Some(ip) = ip else {
        return fail(
            "certificate",
            "cannot connect without the tailnet IP",
            "fix the tailscale check first",
        );
    };
    let probe = format!("bsjn-doctor-probe.{}", cfg.base_domain);
    let addr = format!("{ip}:{}", cfg.port);
    let text = match tls_session(&addr, &probe) {
        Ok(text) => text,
        Err(e) => return fail("certificate", format!("{e:#}"), "install openssl"),
    };
    let Some(pem) = first_pem(&text) else {
        return fail(
            "certificate",
            format!("no certificate served on {addr}"),
            fix,
        );
    };
    let verify = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Verify return code: "))
        .unwrap_or("unknown");
    if !verify.starts_with("0 ") {
        return fail(
            "certificate",
            format!("{addr} serves a certificate that does not verify for {probe}: {verify}"),
            "if acme_ca is set in the config (a staging CA), remove it and run `bsjn setup`; otherwise check that the system trusts Let's Encrypt",
        );
    }
    let x509 = |args: &[&str]| -> Option<std::process::Output> {
        let mut child = Command::new("openssl")
            .arg("x509")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(pem.as_bytes()).ok()?;
        child.wait_with_output().ok()
    };
    let end = x509(&["-noout", "-enddate"])
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .and_then(|l| l.strip_prefix("notAfter=").map(String::from))
        .unwrap_or_else(|| "unknown".into());
    // Caddy renews 30 days before expiry; under 7 days left means renewal is failing.
    let soon = x509(&["-noout", "-checkend", "604800"]).is_some_and(|o| !o.status.success());
    if soon {
        return fail(
            "certificate",
            format!("expires soon ({end})"),
            "renewal is failing: journalctl --user -u bsjn-proxy -n 100 --no-pager",
        );
    }
    pass(
        "certificate",
        format!("valid for *.{}, expires {end}", cfg.base_domain),
    )
}

/// The output of `openssl s_client` against `addr`, asking for `host`. The handshake is not
/// aborted on a bad chain, so the certificate is shown either way and the verdict is read from
/// the "Verify return code" line.
fn tls_session(addr: &str, host: &str) -> Result<String> {
    let out = Command::new("openssl")
        .args(["s_client", "-connect", addr, "-servername", host])
        .args(["-verify_hostname", host])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("`openssl` is not installed")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Does the proxy answer TLS with some certificate? (Whether it is a good one is the doctor's job.)
pub fn certificate_served(cfg: &Config, ip: &str) -> bool {
    let host = format!("bsjn-doctor-probe.{}", cfg.base_domain);
    tls_session(&format!("{ip}:{}", cfg.port), &host).is_ok_and(|t| first_pem(&t).is_some())
}

fn first_pem(text: &str) -> Option<String> {
    let start = text.find("-----BEGIN CERTIFICATE-----")?;
    let end_marker = "-----END CERTIFICATE-----";
    let end = start + text[start..].find(end_marker)? + end_marker.len();
    Some(format!("{}\n", &text[start..end]))
}

fn check_port(paths: &Paths, cfg: &Config) -> Check {
    match port_status(paths, cfg.port) {
        Ok(why) => pass("port", why),
        Err(why) => fail("port", why, root_step(paths, cfg.port)),
    }
}

/// Can an unprivileged process bind `port`? `Ok` says why, `Err` says what is missing.
pub fn port_status(paths: &Paths, port: u16) -> std::result::Result<String, String> {
    if port >= 1024 {
        return Ok(format!("{port} is unprivileged, nothing to do"));
    }
    // BSJN_UNPRIV_PORT_FILE replaces the /proc file in tests.
    let start_file = std::env::var_os("BSJN_UNPRIV_PORT_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/proc/sys/net/ipv4/ip_unprivileged_port_start".into());
    let start: u16 = std::fs::read_to_string(start_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1024);
    if start <= port {
        return Ok(format!(
            "net.ipv4.ip_unprivileged_port_start={start} allows port {port}"
        ));
    }
    let caddy = paths.caddy_bin();
    let has_cap = Command::new("getcap")
        .arg(&caddy)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("cap_net_bind_service"))
        .unwrap_or(false);
    if has_cap {
        return Ok(format!("{} has cap_net_bind_service", caddy.display()));
    }
    Err(format!(
        "port {port} is privileged and {} cannot bind it",
        caddy.display()
    ))
}

/// What to do about a privileged port; the doctor's fix and the end of a failed `setup`.
pub fn root_step(paths: &Paths, port: u16) -> String {
    format!(
        "run: bsjn setup --port {port}\n(in a terminal it runs `sudo setcap` for you and asks for the password itself; a rebuilt Caddy loses the capability, so run it again after an update)\nby hand instead, once, as root: sudo setcap cap_net_bind_service=+ep {}\nsystem-wide instead: bsjn setup --port {port} --sysctl\n(by hand: echo net.ipv4.ip_unprivileged_port_start={port} | sudo tee /etc/sysctl.d/99-bsjn.conf && sudo sysctl -w net.ipv4.ip_unprivileged_port_start={port})",
        paths.caddy_bin().display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // `ss -H -lntu`: no process column, as for a process with file capabilities.
    const SS_NO_OWNER: &str = "\
udp UNCONN 0 0 100.64.0.1:443 0.0.0.0:*
tcp LISTEN 0 4096 100.64.0.1:443 0.0.0.0:*
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 128 [::]:22 [::]:*
tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*
";

    #[test]
    fn listening_is_decided_from_the_socket_without_an_owner_column() {
        assert!(judge_listeners(SS_NO_OWNER, 4242, "100.64.0.1", 443).is_ok());
        let l = parse_ss(SS_NO_OWNER);
        assert_eq!(l.len(), 5);
        assert_eq!(l[3].host, "::");
        assert!(l.iter().all(|l| l.pid.is_none()));
        assert!(tcp_listening(SS_NO_OWNER, "100.64.0.1", 443));
        assert!(!tcp_listening(SS_NO_OWNER, "100.64.0.1", 8443));
    }

    #[test]
    fn a_wider_or_other_address_on_the_port_fails_even_without_an_owner() {
        for stray in [
            "tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*",
            "tcp LISTEN 0 4096 *:443 *:*",
            "tcp LISTEN 0 4096 [::]:443 [::]:*",
            "udp UNCONN 0 0 192.168.1.5:443 0.0.0.0:*",
        ] {
            let ss = format!("{SS_NO_OWNER}{stray}\n");
            let (detail, _) = judge_listeners(&ss, 4242, "100.64.0.1", 443).unwrap_err();
            assert!(
                detail.contains("instead of only 100.64.0.1"),
                "{stray}: {detail}"
            );
        }
    }

    #[test]
    fn the_proxys_own_sockets_elsewhere_are_checked_when_the_owner_is_shown() {
        let ss = format!(
            "{SS_NO_OWNER}tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:((\"caddy\",pid=4242,fd=9))\n\
tcp LISTEN 0 4096 0.0.0.0:81 0.0.0.0:* users:((\"other\",pid=7,fd=9))\n"
        );
        let (detail, _) = judge_listeners(&ss, 4242, "100.64.0.1", 443).unwrap_err();
        assert!(detail.contains("0.0.0.0:80"), "{detail}");
        assert!(!detail.contains("0.0.0.0:81"), "{detail}");
        assert_eq!(parse_ss(&ss)[5].pid, Some(4242));
    }

    #[test]
    fn no_socket_on_the_configured_port_means_not_listening() {
        // An old process still on 8443 while the config says 443.
        let ss = "tcp LISTEN 0 4096 100.64.0.1:8443 0.0.0.0:*\n";
        let (detail, fix) = judge_listeners(ss, 4242, "100.64.0.1", 443).unwrap_err();
        assert!(
            detail.contains("not listening on 100.64.0.1:443"),
            "{detail}"
        );
        assert!(fix.contains("bsjn setup"));
    }

    #[test]
    fn a_warning_keeps_ok_true_so_existing_json_consumers_and_the_exit_code_are_unaffected() {
        let checks = [
            pass("a", "fine"),
            warn("b", "cannot tell", "sudo something"),
            fail("c", "broken", "fix it"),
        ];
        let json = serde_json::to_value(&checks).unwrap();
        assert_eq!(json[0]["ok"], true);
        assert_eq!(json[0]["level"], "ok");
        assert_eq!(json[1]["ok"], true);
        assert_eq!(json[1]["level"], "warn");
        assert_eq!(json[1]["fix"], "sudo something");
        assert_eq!(json[2]["ok"], false);
        assert_eq!(json[2]["level"], "fail");
        assert!(checks[..2].iter().all(|c| c.ok));
    }

    #[test]
    fn the_first_certificate_is_cut_out_of_the_session_text() {
        let text = "CONNECTED\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n---\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        assert_eq!(
            first_pem(text).unwrap(),
            "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(first_pem("no cert"), None);
    }

    #[test]
    fn the_root_step_says_to_run_setup_and_names_the_manual_alternatives() {
        let paths = Paths {
            config_dir: "/c".into(),
            state_dir: "/s".into(),
            data_dir: "/d".into(),
            unit_dir: "/u".into(),
        };
        let step = root_step(&paths, 443);
        assert!(step.starts_with("run: bsjn setup --port 443\n"));
        assert!(step.contains("sudo setcap cap_net_bind_service=+ep /d/bin/caddy"));
        assert!(step.contains("sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443"));
        assert!(step.contains("a rebuilt Caddy loses the capability"));
    }
}
