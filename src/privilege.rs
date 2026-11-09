//! The one privileged step: letting an unprivileged Caddy bind a port below 1024.
//!
//! The only root program involved is `sudo`, started with the terminal's own stdin, stdout and
//! stderr, so sudo prompts for the password directly on the terminal. bsjn never reads,
//! captures or forwards it, and never writes to sudo's stdin. Without a terminal, sudo is not
//! started at all.

use crate::config::Config;
use crate::doctor;
use crate::paths::Paths;
use crate::prompt::confirm;
use anyhow::Result;
use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

const SYSCTL_FILE: &str = "/etc/sysctl.d/99-bsjn.conf";

pub struct Options {
    /// Are stdin and stdout both a terminal (so that sudo can ask for a password)?
    pub tty: bool,
    /// Accept the default (run sudo for setcap). Does not apply to `sysctl`.
    pub yes: bool,
    /// Lower the system-wide port limit instead of giving Caddy a capability.
    pub sysctl: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Caddy can bind the port. `changed`: this run gave it the right to (sudo ran). A running
    /// process keeps the capabilities it had at exec, so it must then be restarted.
    Ready { changed: bool },
    /// It cannot yet; the manual steps have been printed.
    NotDone,
}

fn sudo_line(args: &[String]) -> String {
    format!("sudo {}", args.join(" "))
}

fn setcap_args(paths: &Paths) -> Vec<String> {
    vec![
        "setcap".into(),
        "cap_net_bind_service=+ep".into(),
        paths.caddy_bin().display().to_string(),
    ]
}

/// Make sure Caddy can bind `port`, asking to run sudo when that is what it takes.
pub fn ensure(paths: &Paths, port: u16, opts: &Options) -> Result<Outcome> {
    let why = match doctor::port_status(paths, port) {
        Ok(why) => {
            println!("Port {port}: {why}.");
            return Ok(Outcome::Ready { changed: false });
        }
        Err(why) => why,
    };
    println!("Port {port}: {why}.");
    if opts.sysctl {
        sysctl_flow(paths, port, opts)
    } else {
        setcap_flow(paths, port, opts)
    }
}

fn setcap_flow(paths: &Paths, port: u16, opts: &Options) -> Result<Outcome> {
    let args = setcap_args(paths);
    println!("This one-time step needs root:\n  {}", sudo_line(&args));
    if !opts.tty {
        println!("This is not a terminal, so bsjn does not run sudo.");
        return Ok(Outcome::NotDone);
    }
    if !(opts.yes || confirm("Run it now with sudo?", true)?) {
        return Ok(Outcome::NotDone);
    }
    if !run_sudo(&[args]) {
        return Ok(Outcome::NotDone);
    }
    recheck(paths, port)
}

fn sysctl_flow(paths: &Paths, port: u16, opts: &Options) -> Result<Outcome> {
    println!(
        "Warning: this lowers the unprivileged port limit for every program on this machine, not only Caddy.\n  sudo install -m 644 <file with net.ipv4.ip_unprivileged_port_start={port}> {SYSCTL_FILE}\n  sudo sysctl -w net.ipv4.ip_unprivileged_port_start={port}"
    );
    if !opts.tty {
        println!("This is not a terminal, so bsjn does not run sudo.");
        return Ok(Outcome::NotDone);
    }
    // Deliberately not skipped by --yes: it changes the whole system.
    if !confirm("Apply it system-wide now with sudo?", false)? {
        return Ok(Outcome::NotDone);
    }
    // The setting goes to a file that root copies, so nothing is piped into sudo's stdin. The
    // file is created exclusively, with a random name, in a private directory we own.
    crate::registry::create_private_dir(&paths.state_dir)?;
    let mut source = tempfile::Builder::new()
        .prefix("sysctl-")
        .suffix(".conf")
        .tempfile_in(&paths.state_dir)?;
    source.write_all(format!("net.ipv4.ip_unprivileged_port_start={port}\n").as_bytes())?;
    source.as_file().sync_all()?;
    let ok = run_sudo(&[
        vec![
            "install".into(),
            "-m".into(),
            "644".into(),
            source.path().display().to_string(),
            SYSCTL_FILE.into(),
        ],
        vec![
            "sysctl".into(),
            "-w".into(),
            format!("net.ipv4.ip_unprivileged_port_start={port}"),
        ],
    ]);
    drop(source); // removes the temporary file
    if !ok {
        return Ok(Outcome::NotDone);
    }
    recheck(paths, port)
}

/// Run each command under `sudo` on the user's terminal. False if one fails.
fn run_sudo(commands: &[Vec<String>]) -> bool {
    println!("sudo asks for your password on this terminal; bsjn does not see it.");
    for args in commands {
        let status = Command::new("sudo")
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                println!("`{}` failed ({s}).", sudo_line(args));
                return false;
            }
            Err(e) => {
                println!("cannot run sudo: {e}.");
                return false;
            }
        }
    }
    true
}

fn recheck(paths: &Paths, port: u16) -> Result<Outcome> {
    match doctor::port_status(paths, port) {
        Ok(why) => {
            println!("Port {port}: {why}.");
            Ok(Outcome::Ready { changed: true })
        }
        Err(why) => {
            println!("Still not possible after sudo: {why}.");
            Ok(Outcome::NotDone)
        }
    }
}

pub fn print_not_done(paths: &Paths, port: u16) {
    println!("NOT DONE until the port is allowed:");
    for line in doctor::root_step(paths, port).lines() {
        println!("  {line}");
    }
}

/// `bsjn port-access` (hidden): just this step, for tests.
pub fn run(yes: bool, sysctl: bool) -> Result<i32> {
    let paths = Paths::from_env()?;
    let cfg = Config::load(&paths)?;
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    match ensure(&paths, cfg.port, &Options { tty, yes, sysctl })? {
        Outcome::Ready { .. } => Ok(0),
        Outcome::NotDone => {
            print_not_done(&paths, cfg.port);
            Ok(1)
        }
    }
}
