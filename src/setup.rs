//! `bsjn setup`: everything between "a Cloudflare token" and "a running proxy with a
//! certificate". Safe to repeat; it only changes what differs.

use crate::cli::SetupArgs;
use crate::cloudflare::{self, Client, Zone};
use crate::config::{Config, DEFAULT_PORT};
use crate::converge::{self, Steps};
use crate::paths::Paths;
use crate::prompt::{ask, confirm};
use crate::registry::{self, Lock};
use crate::service::Changed;
use crate::{doctor, names, privilege, proxy, service, tailscale, usage};
use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Read};
use std::time::{Duration, Instant};

const TOKEN_PAGE: &str = "https://dash.cloudflare.com/profile/api-tokens";

fn step(text: &str) {
    println!("==> {text}");
}

fn print_token_instructions() {
    println!(
        "Create a Cloudflare API token for bsjn:
  1. Open {TOKEN_PAGE}
  2. Create Token, template \"Edit zone DNS\"
  3. Permissions: Zone:DNS:Edit and Zone:Zone:Read
  4. Zone resources: Include, Specific zone, your zone
  5. Optional: a client IP filter
  6. Create, and copy the value now (Cloudflare shows it once)
"
    );
}

/// A token that Cloudflare accepts, and the zones it can see.
fn obtain_token(args: &SetupArgs, paths: &Paths, tty: bool) -> Result<(String, Vec<Zone>)> {
    let check = |token: &str| -> Result<Vec<Zone>> {
        let client = Client::new(token);
        client.verify()?;
        client.zones()
    };
    if args.token_stdin {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        let token = text.trim().to_string();
        if token.is_empty() {
            bail!("--token-stdin: stdin is empty");
        }
        let zones = check(&token)?;
        return Ok((token, zones));
    }
    if let Some(token) = cloudflare::stored_token(paths) {
        match check(&token) {
            Ok(zones) => {
                println!("Using the stored token ({}).", paths.token_file().display());
                return Ok((token, zones));
            }
            Err(e) if !tty => {
                return Err(e)
                    .context("the stored token no longer works; run `bsjn setup --token-stdin`");
            }
            Err(e) => println!("The stored token does not work ({e:#}). Enter a new one."),
        }
    } else if !tty {
        return Err(usage(
            "no Cloudflare token: pass it with --token-stdin (for example `bsjn setup --token-stdin < token-file`) or run setup in a terminal",
        ));
    }
    print_token_instructions();
    for attempt in 1..=3 {
        let token = rpassword::prompt_password("Cloudflare token (hidden): ")?
            .trim()
            .to_string();
        match check(&token) {
            Ok(zones) => return Ok((token, zones)),
            Err(e) if attempt < 3 => println!("That token does not work: {e:#}. Try again."),
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn store_token(paths: &Paths, token: &str) -> Result<bool> {
    registry::create_private_dir(&paths.config_dir)?;
    registry::write_if_different(&paths.token_file(), format!("{token}\n").as_bytes(), 0o600)
}

pub fn run(args: &SetupArgs) -> Result<i32> {
    let paths = Paths::from_env()?;
    let existing = Config::try_load(&paths)?;
    let tty =
        !args.token_stdin && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();

    step("Cloudflare token");
    let (token, zones) = obtain_token(args, &paths, tty)?;
    if store_token(&paths, &token)? {
        println!(
            "Stored the token in {} (mode 600).",
            paths.token_file().display()
        );
    }

    step("Base domain");
    let base = match (&args.domain, &existing, tty) {
        (Some(d), _, _) => d.clone(),
        (None, Some(c), false) => c.base_domain.clone(),
        (None, c, true) => ask(
            "Base domain, for example dev.example.com",
            c.as_ref().map(|c| c.base_domain.as_str()),
        )?,
        (None, None, false) => {
            return Err(usage("--domain is required when setup is not interactive"));
        }
    };
    names::validate_domain(&base)?;
    let Some(zone) = cloudflare::pick_zone(&zones, &base) else {
        let seen: Vec<_> = zones.iter().map(|z| z.name.as_str()).collect();
        bail!(
            "the token cannot see a Cloudflare zone for {base} (it sees: {}); the zone must be one of its zone resources",
            if seen.is_empty() {
                "none".into()
            } else {
                seen.join(", ")
            }
        );
    };
    println!("{base} belongs to the zone {}.", zone.name);
    let port = args
        .port
        .or(existing.as_ref().map(|c| c.port))
        .unwrap_or(DEFAULT_PORT);
    if port == 0 {
        return Err(usage("--port must be between 1 and 65535"));
    }

    step("DNS");
    tailscale::ensure_running()?;
    let ip = tailscale::ipv4()?;
    ensure_wildcard_record(
        &Client::new(&token),
        zone,
        &base,
        &ip.to_string(),
        args.yes,
        tty,
    )?;

    let cfg = Config {
        base_domain: base,
        port,
        tailnet_ip: Some(ip),
        acme_ca: existing.as_ref().and_then(|c| c.acme_ca.clone()),
        restrict_source: existing.as_ref().is_none_or(|c| c.restrict_source),
    };
    let config_changed = existing.as_ref() != Some(&cfg);
    cfg.save(&paths)?;

    step("Proxy (Caddy)");
    let mut rebuilt = false;
    if service::caddy_is_current(&paths.caddy_bin()) {
        println!("{} is current.", paths.caddy_bin().display());
    } else {
        println!(
            "Building Caddy {} with the Cloudflare DNS module (a few minutes the first time)...",
            service::CADDY_VERSION
        );
        service::build_caddy(&paths)?;
        rebuilt = true;
        println!("Installed {}.", paths.caddy_bin().display());
    }

    step("Service (systemd --user)");
    let mut steps = RealSteps {
        paths: &paths,
        cfg: &cfg,
        token: &token,
        opts: privilege::Options {
            tty,
            yes: args.yes,
            sysctl: args.sysctl,
        },
    };
    let done = converge::converge(&mut steps, rebuilt, config_changed)?;
    let not_done = done == converge::Done::NotDone;
    if not_done {
        println!("The service was left as it is until this is done.");
    } else {
        wait_for_certificate(&paths, &cfg, &ip.to_string());
    }

    step("Doctor");
    let checks = doctor::run_checks(&paths);
    doctor::print_checks(&checks, false)?;
    if not_done {
        println!();
        privilege::print_not_done(&paths, cfg.port);
        return Ok(1);
    }
    Ok(if checks.iter().all(|c| c.ok) { 0 } else { 1 })
}

/// The real effects behind `converge`.
struct RealSteps<'a> {
    paths: &'a Paths,
    cfg: &'a Config,
    token: &'a str,
    opts: privilege::Options,
}

impl Steps for RealSteps<'_> {
    fn ensure_port(&mut self) -> Result<privilege::Outcome> {
        privilege::ensure(self.paths, self.cfg.port, &self.opts)
    }

    fn write_files(&mut self) -> Result<Changed> {
        let changed = service::write_unit_files(self.paths, self.token)?;
        {
            // The Caddyfile comes from the registry; the service starts from this file.
            let _lock = Lock::acquire(self.paths)?;
            let reg = registry::load(self.paths)?;
            proxy::write_caddyfile(self.paths, self.cfg, &reg.routes)?;
        }
        if changed.unit {
            service::daemon_reload()?;
        }
        service::enable()?;
        Ok(changed)
    }

    fn is_active(&mut self) -> bool {
        service::is_active()
    }

    fn listening_as_configured(&mut self) -> bool {
        self.cfg
            .tailnet_ip
            .is_some_and(|ip| doctor::listening_now(&ip.to_string(), self.cfg.port))
    }

    fn start(&mut self) -> Result<()> {
        service::start()?;
        println!("Started bsjn-proxy.");
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        service::restart()?;
        println!("Restarted bsjn-proxy (the running process predates this configuration).");
        Ok(())
    }

    fn hot_apply(&mut self) -> Result<()> {
        let _lock = Lock::acquire(self.paths)?;
        let reg = registry::load(self.paths)?;
        match proxy::apply(self.paths, self.cfg, &reg.routes)? {
            proxy::Outcome::Loaded => {
                println!("bsjn-proxy is running; nothing to restart.");
                Ok(())
            }
            // Active, but the admin socket does not answer: a new process is the way out.
            proxy::Outcome::ProxyDown(_) => self.restart(),
        }
    }
}

fn ensure_wildcard_record(
    client: &Client,
    zone: &Zone,
    base: &str,
    ip: &str,
    yes: bool,
    tty: bool,
) -> Result<()> {
    let name = format!("*.{base}");
    match client.find_record(&zone.id, &name)? {
        Some(r) if r.kind == "A" && r.content == ip => {
            println!("{name} already points to {ip}.");
        }
        Some(r) if r.kind == "A" => {
            println!("{name} points to {}, but this host is {ip}.", r.content);
            if yes || (tty && confirm(&format!("Update it to {ip}?"), false)?) {
                client.update_a(&zone.id, &r.id, &name, ip)?;
                println!("Updated {name} -> {ip} (DNS only, TTL 300).");
            } else {
                println!("Left as is; `bsjn doctor` will keep reporting it.");
            }
        }
        Some(r) => bail!(
            "{name} exists as a {} record; replace it with an A record to {ip} in the Cloudflare dashboard",
            r.kind
        ),
        None => {
            println!("{name} does not exist.");
            if yes
                || (tty
                    && confirm(
                        &format!("Create the A record {name} -> {ip} (DNS only)?"),
                        false,
                    )?)
            {
                client.create_a(&zone.id, &name, ip)?;
                println!("Created {name} -> {ip} (DNS only, TTL 300).");
            } else {
                println!("Not created; `bsjn doctor` will keep reporting it.");
            }
        }
    }
    Ok(())
}

/// DNS-01 issuance takes a minute or so on the first start. Waiting here lets the doctor
/// run afterwards report the final state instead of a transient one.
fn wait_for_certificate(paths: &Paths, cfg: &Config, ip: &str) {
    let deadline = Instant::now() + Duration::from_secs(240);
    println!("Waiting for the wildcard certificate (the first issuance takes about a minute)...");
    while Instant::now() < deadline {
        // A staging CA's certificate never verifies; any certificate will do then. Otherwise a
        // certificate left over from an earlier CA must not end the wait.
        let ready = if cfg.acme_ca.is_some() {
            doctor::certificate_served(cfg, ip)
        } else {
            doctor::check_certificate(cfg, Some(ip)).ok
        };
        if ready {
            return;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    println!(
        "Still no certificate; see: journalctl --user -u bsjn-proxy -n 100 --no-pager (state: {})",
        paths.state_dir.display()
    );
}
