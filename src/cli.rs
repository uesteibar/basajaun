//! Command line definition.

use clap::{Args, Parser, Subcommand};

/// Stable HTTPS URLs for dev servers, reachable only inside the tailnet.
#[derive(Parser)]
#[command(name = "bsjn", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-time and repeatable: token, DNS record, Caddy build, systemd unit.
    Setup(SetupArgs),
    /// Route <name>.<base-domain> to 127.0.0.1:<port> until `bsjn rm`. Prints the URL.
    Add {
        name: String,
        port: u16,
        /// Group routes; select them later with `ls --tag` or `rm --tag`.
        #[arg(long)]
        tag: Option<String>,
        /// Replace an existing route of the same name that points to another port.
        #[arg(long)]
        force: bool,
    },
    /// Run a command with a free PORT and a temporary route; remove the route when it exits.
    Run {
        name: String,
        #[arg(long)]
        tag: Option<String>,
        /// The command, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// List routes and whether something answers on their port.
    Ls {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Remove routes by name, by tag or all of them.
    Rm(RmCli),
    /// Print the URL for a name without registering anything.
    Url { name: String },
    /// Only the privileged-port step of `setup`, for tests.
    #[command(hide = true)]
    PortAccess {
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        sysctl: bool,
    },
    /// Check Tailscale, token, DNS, proxy, certificate and port. Read-only.
    Doctor {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
pub struct SetupArgs {
    /// Read the Cloudflare token from stdin instead of prompting.
    #[arg(long)]
    pub token_stdin: bool,
    /// Base domain, e.g. dev.example.com.
    #[arg(long)]
    pub domain: Option<String>,
    /// Port the proxy listens on (default 443, or what the config says). Below 1024 needs root once.
    #[arg(long)]
    pub port: Option<u16>,
    /// Answer yes to confirmations (creating the wildcard DNS record, running sudo for setcap).
    #[arg(long)]
    pub yes: bool,
    /// For a privileged port: lower the system-wide unprivileged port limit with sysctl instead
    /// of giving Caddy a capability. Always asks, even with --yes.
    #[arg(long)]
    pub sysctl: bool,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("what").required(true).args(["names", "tag", "all"])))]
pub struct RmCli {
    pub names: Vec<String>,
    #[arg(long)]
    pub tag: Option<String>,
    #[arg(long)]
    pub all: bool,
}
