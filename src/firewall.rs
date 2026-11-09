//! Best-effort reading of the host firewall for `bsjn doctor`. It never changes anything and
//! never needs root: it reads what an ordinary user can (ufw's files, `nft`/`iptables` when they
//! work unprivileged) and says "unknown" when the rules cannot be read.
//!
//! The question is: is the default for incoming traffic "deny", and does no rule accept the
//! proxy port on an interface other than `tailscale0`? Only IPv4 matters, because the proxy
//! binds an IPv4 address. Rule matching is deliberately simple (interface, protocol, destination
//! ports, and jumps into other chains with the conditions of the jump); it does not simulate
//! rule order.

use std::io;

const TAILSCALE_IFACE: &str = "tailscale0";

/// What the check can look at; tests use fixtures instead of the live system.
pub trait Probe {
    fn read(&self, path: &str) -> io::Result<String>;
    fn run(&self, cmd: &str, args: &[&str]) -> Run;
}

pub enum Run {
    /// The program is not installed.
    Missing,
    /// It ran and failed (typically: not root).
    Failed,
    Output(String),
}

pub struct System;

impl Probe for System {
    fn read(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn run(&self, cmd: &str, args: &[&str]) -> Run {
        match std::process::Command::new(cmd).args(args).output() {
            Err(_) => Run::Missing,
            Ok(o) if o.status.success() => Run::Output(String::from_utf8_lossy(&o.stdout).into()),
            Ok(_) => Run::Failed,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok(String),
    Fail {
        detail: String,
        fix: String,
    },
    /// The rules cannot be read without root.
    Unknown {
        detail: String,
        verify: String,
    },
}

fn allow_command(port: u16) -> String {
    format!("sudo ufw allow in on {TAILSCALE_IFACE} to any port {port}")
}

fn fix_no_firewall(port: u16) -> String {
    format!(
        "{}\nsudo ufw default deny incoming\n(if you log in over SSH, allow it first: sudo ufw allow ssh)\nsudo ufw enable\n(or the same with nftables/iptables: default policy drop, accept port {port} only on {TAILSCALE_IFACE})",
        allow_command(port)
    )
}

fn fix_open_rule(port: u16) -> String {
    format!(
        "remove the rule: sudo ufw status numbered, then sudo ufw delete <number>\nthen allow only the tailnet: {}\n(with nftables/iptables: the accept rule for port {port} needs `iifname \"{TAILSCALE_IFACE}\"` / `-i {TAILSCALE_IFACE}`)",
        allow_command(port)
    )
}

/// Look at the host and judge it for `port`.
pub fn assess(probe: &dyn Probe, port: u16) -> Verdict {
    if let Some(v) = assess_ufw(probe, port) {
        return v;
    }
    let mut readable = Vec::new();
    let mut unreadable = false;
    for (cmd, args) in [("nft", &["list", "ruleset"][..]), ("iptables", &["-S"][..])] {
        match probe.run(cmd, args) {
            Run::Missing => {}
            Run::Failed => unreadable = true,
            Run::Output(text) => readable.push(if cmd == "nft" {
                evaluate(&parse_nft(&text), port)
            } else {
                evaluate(&parse_iptables(&text), port)
            }),
        }
    }
    if let Some(rule) = readable.iter().flat_map(|a| &a.opens).next() {
        return Verdict::Fail {
            detail: format!(
                "a firewall rule accepts port {port} on more than {TAILSCALE_IFACE}: {rule}"
            ),
            fix: fix_open_rule(port),
        };
    }
    if readable.iter().any(|a| a.default_deny) {
        return Verdict::Ok(format!(
            "default-deny input policy (nftables/iptables), no rule opens port {port} outside {TAILSCALE_IFACE}"
        ));
    }
    if !readable.is_empty() {
        return Verdict::Fail {
            detail: "the firewall rules do not drop incoming traffic by default".into(),
            fix: fix_no_firewall(port),
        };
    }
    if unreadable {
        return Verdict::Unknown {
            detail: "cannot read the firewall rules without root".into(),
            verify: "sudo nft list ruleset   (or: sudo iptables -S, sudo ufw status verbose): the input policy must be drop and no rule may accept the proxy port outside tailscale0".into(),
        };
    }
    Verdict::Fail {
        detail:
            "no active firewall found (ufw is not enabled, no nftables or iptables rules readable)"
                .into(),
        fix: fix_no_firewall(port),
    }
}

/// `None` when ufw is not enabled (so another firewall may still be active).
fn assess_ufw(probe: &dyn Probe, port: u16) -> Option<Verdict> {
    let conf = probe.read("/etc/ufw/ufw.conf").ok()?;
    if setting(&conf, "ENABLED").as_deref() != Some("yes") {
        return None;
    }
    let unknown = |what: &str| {
        Some(Verdict::Unknown {
            detail: format!("ufw is enabled, but {what} cannot be read without root"),
            verify: format!(
                "sudo ufw status verbose   (default: deny (incoming), and no rule for {port} except `on {TAILSCALE_IFACE}`)"
            ),
        })
    };
    let Ok(defaults) = probe.read("/etc/default/ufw") else {
        return unknown("/etc/default/ufw");
    };
    let policy = setting(&defaults, "DEFAULT_INPUT_POLICY").unwrap_or_default();
    if !matches!(policy.as_str(), "DROP" | "REJECT") {
        return Some(Verdict::Fail {
            detail: format!(
                "ufw is enabled but its default for incoming traffic is {policy:?}, not deny"
            ),
            fix: format!("sudo ufw default deny incoming\n{}", allow_command(port)),
        });
    }
    let Ok(rules) = probe.read("/etc/ufw/user.rules") else {
        return unknown("/etc/ufw/user.rules");
    };
    let a = evaluate_from(&parse_iptables(&rules), "ufw-user-input", port);
    if let Some(rule) = a.opens.first() {
        return Some(Verdict::Fail {
            detail: format!(
                "a ufw rule accepts port {port} on more than {TAILSCALE_IFACE}: {rule}"
            ),
            fix: fix_open_rule(port),
        });
    }
    Some(Verdict::Ok(format!(
        "ufw is enabled, default input policy {policy}, no rule opens port {port} outside {TAILSCALE_IFACE} (from /etc/ufw, best effort)"
    )))
}

/// `KEY=value` or `KEY="value"` (ignoring comments).
fn setting(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string())
}

// ---------------------------------------------------------------------------------------------
// A tiny rule model shared by the iptables and nft parsers.

type Ranges = Vec<(u16, u16)>;

#[derive(Clone, Debug, Default)]
struct Cond {
    /// Interfaces named with `-i` / `iifname` (not negated).
    ifaces: Vec<String>,
    /// One entry per destination-port condition; the packet's port must be in every one.
    ports: Vec<Ranges>,
    /// Something this check cannot judge (a protocol other than tcp/udp, connection state, ...).
    other: bool,
}

impl Cond {
    fn and(&self, inner: &Cond) -> Cond {
        let mut c = self.clone();
        c.ifaces.extend(inner.ifaces.iter().cloned());
        c.ports.extend(inner.ports.iter().cloned());
        c.other |= inner.other;
        c
    }

    /// Could a packet for `port` arriving on some interface other than tailscale0 (or lo) match?
    fn opens(&self, port: u16) -> bool {
        !self.other
            && self
                .ports
                .iter()
                .all(|r| r.iter().any(|&(a, b)| (a..=b).contains(&port)))
            && self
                .ifaces
                .iter()
                .all(|i| i != TAILSCALE_IFACE && i != "lo")
    }
}

enum Target {
    Accept,
    Deny,
    Jump(String),
    Other,
}

struct Rule {
    cond: Cond,
    target: Target,
    text: String,
}

#[derive(Default)]
struct Chain {
    name: String,
    /// A built-in input chain (iptables INPUT, an nft `hook input` chain).
    input_base: bool,
    policy_deny: bool,
    rules: Vec<Rule>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Assessment {
    default_deny: bool,
    opens: Vec<String>,
}

fn parse_ports(s: &str) -> Ranges {
    s.trim_matches(['{', '}', ' '])
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            let (a, b) = p.split_once([':', '-']).unwrap_or((p, p));
            Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
        })
        .collect()
}

fn chain_index(chains: &mut Vec<Chain>, name: &str) -> usize {
    match chains.iter().position(|c| c.name == name) {
        Some(i) => i,
        None => {
            chains.push(Chain {
                name: name.into(),
                ..Chain::default()
            });
            chains.len() - 1
        }
    }
}

/// `iptables -S` / iptables-save syntax (also ufw's `user.rules`).
fn parse_iptables(text: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = Vec::new();
    for line in text.lines().map(str::trim) {
        let t: Vec<&str> = line.split_whitespace().collect();
        match t.as_slice() {
            ["-P", name, policy] => {
                let i = chain_index(&mut chains, name);
                chains[i].input_base = *name == "INPUT";
                chains[i].policy_deny = matches!(*policy, "DROP" | "REJECT");
            }
            ["-N", name] => {
                chain_index(&mut chains, name);
            }
            ["-A", name, rest @ ..] => {
                let i = chain_index(&mut chains, name);
                chains[i].input_base |= *name == "INPUT";
                chains[i].rules.push(parse_iptables_rule(rest, line));
            }
            _ => {}
        }
    }
    chains
}

fn parse_iptables_rule(t: &[&str], line: &str) -> Rule {
    let mut cond = Cond::default();
    let mut target = Target::Other;
    let mut negate = false;
    let mut i = 0;
    while i < t.len() {
        let next = t.get(i + 1).copied().unwrap_or("");
        let was_negation = t[i] == "!";
        match t[i] {
            "!" => negate = true,
            "-i" | "--in-interface" => {
                if !negate {
                    cond.ifaces.push(next.into());
                }
                i += 1;
            }
            "-p" | "--protocol" => {
                if !matches!(next, "tcp" | "udp" | "all") {
                    cond.other = true;
                }
                i += 1;
            }
            "--dport" | "--destination-port" | "--dports" | "--destination-ports" => {
                cond.ports.push(parse_ports(next));
                i += 1;
            }
            "-m" | "--match" => {
                if !matches!(next, "tcp" | "udp" | "multiport" | "comment") {
                    cond.other = true;
                }
                i += 1;
            }
            "-j" | "--jump" | "-g" | "--goto" => {
                target = match next {
                    "ACCEPT" => Target::Accept,
                    "DROP" | "REJECT" => Target::Deny,
                    "RETURN" | "LOG" | "" => Target::Other,
                    chain => Target::Jump(chain.into()),
                };
                break;
            }
            _ => {}
        }
        if !was_negation {
            negate = false;
        }
        i += 1;
    }
    Rule {
        cond,
        target,
        text: line.to_string(),
    }
}

/// `nft list ruleset` (IPv4 and `inet` tables; `ip6` tables are skipped).
fn parse_nft(text: &str) -> Vec<Chain> {
    let mut chains: Vec<Chain> = Vec::new();
    let mut skip_table = false;
    let mut current: Option<usize> = None;
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("table ") {
            skip_table = rest.starts_with("ip6 ");
        } else if let Some(name) = line
            .strip_prefix("chain ")
            .and_then(|r| r.strip_suffix(" {"))
        {
            current = (!skip_table).then(|| {
                chains.push(Chain {
                    name: name.into(),
                    ..Chain::default()
                });
                chains.len() - 1
            });
        } else if line == "}" {
            current = None;
        } else if let Some(i) = current {
            if line.starts_with("type ") {
                chains[i].input_base = line.contains("hook input");
                chains[i].policy_deny =
                    line.contains("policy drop") || line.contains("policy reject");
            } else if !line.is_empty() {
                chains[i].rules.push(parse_nft_rule(line));
            }
        }
    }
    chains
}

fn parse_nft_rule(line: &str) -> Rule {
    // Interface names and comments are quoted; the quotes only get in the way.
    let flat = line.replace('"', "");
    let t: Vec<&str> = flat.split_whitespace().collect();
    let mut cond = Cond::default();
    let mut target = Target::Other;
    let mut i = 0;
    while i < t.len() {
        let next = t.get(i + 1).copied().unwrap_or("");
        match t[i] {
            "iifname" | "iif" => {
                // `iifname != x` is not a positive constraint.
                if next != "!=" {
                    cond.ifaces.push(next.into());
                }
                i += 1;
            }
            "dport" => {
                // `dport 443`, `dport 80-90` or a set `dport { 80, 443 }`.
                let value = if next == "{" {
                    let end = t[i..]
                        .iter()
                        .position(|x| *x == "}")
                        .map_or(t.len(), |e| i + e + 1);
                    let set = t[i + 1..end].join(" ");
                    i = end - 1;
                    set
                } else {
                    i += 1;
                    next.to_string()
                };
                cond.ports.push(parse_ports(&value));
            }
            // `tcp dport` and `ip saddr` carry no limitation of their own; the rest is state or
            // protocol matching that this check does not judge.
            "ct" | "icmp" | "icmpv6" | "fib" | "ether" | "meta" | "limit" | "ip6" => {
                cond.other = true;
            }
            "accept" => target = Target::Accept,
            "drop" | "reject" => target = Target::Deny,
            "jump" | "goto" => {
                target = Target::Jump(next.into());
                break;
            }
            _ => {}
        }
        i += 1;
    }
    Rule {
        cond,
        target,
        text: line.to_string(),
    }
}

fn walk(chains: &[Chain], name: &str, cond: &Cond, port: u16, depth: u8, opens: &mut Vec<String>) {
    let Some(chain) = chains.iter().find(|c| c.name == name) else {
        return;
    };
    if depth > 8 {
        return;
    }
    for rule in &chain.rules {
        let c = cond.and(&rule.cond);
        match &rule.target {
            Target::Accept if c.opens(port) => opens.push(rule.text.clone()),
            Target::Jump(next) => walk(chains, next, &c, port, depth + 1, opens),
            _ => {}
        }
    }
}

/// Judge the built-in input chains.
fn evaluate(chains: &[Chain], port: u16) -> Assessment {
    let mut a = Assessment::default();
    for chain in chains.iter().filter(|c| c.input_base) {
        let ends_in_drop = chain.rules.last().is_some_and(|r| {
            matches!(r.target, Target::Deny) && r.cond.ifaces.is_empty() && r.cond.ports.is_empty()
        });
        a.default_deny |= chain.policy_deny || ends_in_drop;
        walk(chains, &chain.name, &Cond::default(), port, 0, &mut a.opens);
    }
    a.opens.dedup();
    a
}

/// Like `evaluate`, for a chain that is not a base chain (ufw's user rules); the default
/// policy comes from elsewhere.
fn evaluate_from(chains: &[Chain], root: &str, port: u16) -> Assessment {
    let mut a = Assessment::default();
    walk(chains, root, &Cond::default(), port, 0, &mut a.opens);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Files and command outputs by name; anything else is missing.
    #[derive(Default)]
    struct Fake {
        files: HashMap<&'static str, io::Result<String>>,
        cmds: HashMap<&'static str, Run>,
    }

    impl Probe for Fake {
        fn read(&self, path: &str) -> io::Result<String> {
            match self.files.get(path) {
                Some(Ok(t)) => Ok(t.clone()),
                Some(Err(e)) => Err(io::Error::new(e.kind(), "fixture")),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        fn run(&self, cmd: &str, _args: &[&str]) -> Run {
            match self.cmds.get(cmd) {
                Some(Run::Output(t)) => Run::Output(t.clone()),
                Some(Run::Failed) => Run::Failed,
                _ => Run::Missing,
            }
        }
    }

    fn ufw(conf: &str, defaults: &str, rules: io::Result<&str>) -> Fake {
        let mut f = Fake::default();
        f.files.insert("/etc/ufw/ufw.conf", Ok(conf.into()));
        f.files.insert("/etc/default/ufw", Ok(defaults.into()));
        f.files
            .insert("/etc/ufw/user.rules", rules.map(String::from));
        f
    }

    const UFW_CONF: &str = "# comment\nENABLED=yes\nLOGLEVEL=low\n";
    const UFW_DEFAULTS: &str =
        "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n";
    // Shaped like a real /etc/ufw/user.rules: a plain allow, ufw's `limit`, source-restricted
    // multiport rules, a rule for a docker bridge address and an interface-bound rule.
    const UFW_RULES: &str = "\
*filter
:ufw-user-input - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 53317 -j ACCEPT

### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in
-A ufw-user-input -p udp -d 172.17.0.1 --dport 53 -s 172.16.0.0/12 -j ACCEPT

### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept

### tuple ### allow tcp 47984,47989 0.0.0.0/0 any 192.168.1.0/24 in
-A ufw-user-input -p tcp -m multiport --dports 47984,47989 -s 192.168.1.0/24 -j ACCEPT

### tuple ### allow udp 47998:48000 0.0.0.0/0 any 192.168.1.0/24 in
-A ufw-user-input -p udp -m multiport --dports 47998:48000 -s 192.168.1.0/24 -j ACCEPT

### tuple ### allow tcp 9119 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
-A ufw-user-input -i tailscale0 -p tcp --dport 9119 -j ACCEPT

### END RULES ###
-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix \"[UFW LIMIT BLOCK] \"
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
COMMIT
";

    fn with_rule(rule: &str) -> String {
        UFW_RULES.replace("### END RULES ###", &format!("{rule}\n### END RULES ###"))
    }

    #[test]
    fn ufw_with_default_deny_and_no_rule_for_the_port_is_ok() {
        for port in [443, 8443] {
            let f = ufw(UFW_CONF, UFW_DEFAULTS, Ok(UFW_RULES));
            assert!(matches!(assess(&f, port), Verdict::Ok(_)), "{port}");
        }
        // A rule on tailscale0 only, for the proxy port itself, is what we want.
        let rules = with_rule("-A ufw-user-input -i tailscale0 -p tcp --dport 443 -j ACCEPT");
        let f = ufw(UFW_CONF, UFW_DEFAULTS, Ok(&rules));
        assert!(matches!(assess(&f, 443), Verdict::Ok(_)));
    }

    #[test]
    fn ufw_rules_that_open_the_port_to_other_interfaces_fail_with_the_fix() {
        for rule in [
            "-A ufw-user-input -p tcp --dport 443 -j ACCEPT",
            "-A ufw-user-input -p udp --dport 443 -j ACCEPT",
            "-A ufw-user-input -p tcp -m multiport --dports 80,443 -j ACCEPT",
            "-A ufw-user-input -p tcp --dport 400:500 -s 192.168.1.0/24 -j ACCEPT",
            "-A ufw-user-input -i eth0 -p tcp --dport 443 -j ACCEPT",
            "-A ufw-user-input -s 192.168.1.0/24 -j ACCEPT",
            "-A ufw-user-input -j ACCEPT",
            "-A ufw-user-input -p tcp --dport 443 -j ufw-user-limit-accept",
        ] {
            let rules = with_rule(rule);
            let f = ufw(UFW_CONF, UFW_DEFAULTS, Ok(&rules));
            match assess(&f, 443) {
                Verdict::Fail { detail, fix } => {
                    assert!(detail.contains("443"), "{rule}: {detail}");
                    assert!(
                        fix.contains("sudo ufw allow in on tailscale0 to any port 443"),
                        "{rule}: {fix}"
                    );
                }
                other => panic!("{rule}: {other:?}"),
            }
        }
    }

    #[test]
    fn ufw_with_a_permissive_default_or_disabled_fails() {
        let f = ufw(UFW_CONF, "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n", Ok(UFW_RULES));
        assert!(
            matches!(assess(&f, 443), Verdict::Fail { detail, .. } if detail.contains("not deny"))
        );
        // Disabled ufw and nothing else installed: no firewall at all.
        let f = ufw("ENABLED=no\n", UFW_DEFAULTS, Ok(UFW_RULES));
        match assess(&f, 8443) {
            Verdict::Fail { detail, fix } => {
                assert!(detail.contains("no active firewall"), "{detail}");
                assert!(fix.contains("sudo ufw allow in on tailscale0 to any port 8443"));
                assert!(fix.contains("sudo ufw enable"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unreadable_ufw_rules_are_unknown_not_failed() {
        let denied = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let f = ufw(UFW_CONF, UFW_DEFAULTS, denied);
        match assess(&f, 443) {
            Verdict::Unknown { detail, verify } => {
                assert!(detail.contains("/etc/ufw/user.rules"), "{detail}");
                assert!(verify.starts_with("sudo ufw status verbose"), "{verify}");
            }
            other => panic!("{other:?}"),
        }
    }

    // `iptables -S` on a host with ufw's chains and Tailscale's, trimmed.
    const IPTABLES: &str = "\
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N ts-input
-N ufw-user-input
-A INPUT -j ts-input
-A INPUT -j ufw-user-input
-A ts-input -i lo -j ACCEPT
-A ts-input -s 100.115.92.0/23 ! -i tailscale0 -j RETURN
-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP
-A ts-input -i tailscale0 -j ACCEPT
-A ufw-user-input -p tcp --dport 22 -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
";

    #[test]
    fn iptables_default_drop_with_tailscale_chain_is_ok() {
        let mut f = Fake::default();
        f.cmds.insert("iptables", Run::Output(IPTABLES.into()));
        assert!(matches!(assess(&f, 443), Verdict::Ok(_)));
        // An accept rule for the port on another interface, behind a jump, is found.
        let open = format!("{IPTABLES}-A ufw-user-input -p tcp --dport 443 -j ACCEPT\n");
        f.cmds.insert("iptables", Run::Output(open));
        assert!(matches!(assess(&f, 443), Verdict::Fail { .. }));
        // Policy ACCEPT and no final drop: no default deny.
        let accept = IPTABLES.replace("-P INPUT DROP", "-P INPUT ACCEPT");
        f.cmds.insert("iptables", Run::Output(accept));
        assert!(
            matches!(assess(&f, 443), Verdict::Fail { detail, .. } if detail.contains("by default"))
        );
    }

    // `nft list ruleset`, trimmed.
    const NFT: &str = "\
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname \"lo\" accept
		iifname \"tailscale0\" tcp dport { 80, 443 } accept
		tcp dport 22 accept
		icmp type echo-request accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
table ip6 filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 443 accept
	}
}
";

    #[test]
    fn nft_default_drop_with_tailscale_only_accept_is_ok_and_other_accepts_fail() {
        let mut f = Fake::default();
        f.cmds.insert("nft", Run::Output(NFT.into()));
        assert!(
            matches!(assess(&f, 443), Verdict::Ok(_)),
            "ip6 tables are ignored"
        );
        for rule in [
            "tcp dport 443 accept",
            "iifname != \"tailscale0\" tcp dport 443 accept",
            "ip saddr 192.168.1.0/24 tcp dport 440-450 accept",
            "iifname \"eth0\" accept",
            "accept",
        ] {
            let text = NFT.replacen("\t\ticmp type", &format!("\t\t{rule}\n\t\ticmp type"), 1);
            f.cmds.insert("nft", Run::Output(text));
            assert!(matches!(assess(&f, 443), Verdict::Fail { .. }), "{rule}");
        }
    }

    #[test]
    fn commands_that_need_root_make_it_unknown_and_no_tools_at_all_a_failure() {
        let mut f = Fake::default();
        f.cmds.insert("nft", Run::Failed);
        f.cmds.insert("iptables", Run::Failed);
        assert!(
            matches!(assess(&f, 443), Verdict::Unknown { verify, .. } if verify.contains("sudo nft list ruleset"))
        );
        assert!(matches!(
            assess(&Fake::default(), 443),
            Verdict::Fail { .. }
        ));
    }

    #[test]
    fn settings_ignore_comments_and_quotes() {
        assert_eq!(
            setting("# ENABLED=no\nENABLED=yes\n", "ENABLED").as_deref(),
            Some("yes")
        );
        assert_eq!(setting("A=\"DROP\"\n", "A").as_deref(), Some("DROP"));
        assert_eq!(setting("B=1\n", "A"), None);
    }
}
