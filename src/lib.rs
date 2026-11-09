//! `bsjn` (Basajaun): a stable HTTPS URL for every dev server on a machine in your tailnet.
//!
//! Pure modules: `names`, `registry` (data and locking), `caddyfile`.
//! The rest talks to the outside: `proxy` (Caddy admin API), `cloudflare`, `tailscale`,
//! `service` (systemd and the Caddy build), `setup`, `doctor`.

pub mod caddyfile;
pub mod cli;
pub mod cloudflare;
pub mod config;
pub mod converge;
pub mod doctor;
pub mod firewall;
pub mod names;
pub mod paths;
pub mod privilege;
pub mod proc;
pub mod prompt;
pub mod proxy;
pub mod redact;
pub mod registry;
pub mod routes;
pub mod run;
pub mod service;
pub mod setup;
pub mod tailscale;

/// A mistake in how the command was called (exit code 2), as opposed to a failure (exit code 1).
#[derive(Debug)]
pub struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

pub fn usage(message: impl Into<String>) -> anyhow::Error {
    UsageError(message.into()).into()
}
