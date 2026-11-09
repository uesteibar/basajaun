//! Where bsjn keeps its files. Each directory can be overridden for tests.

use anyhow::{Result, anyhow};
use std::path::PathBuf;

pub const UNIT_NAME: &str = "bsjn-proxy.service";

#[derive(Debug, Clone)]
pub struct Paths {
    /// `~/.config/basajaun`: config.toml, cloudflare-token, caddy.env.
    pub config_dir: PathBuf,
    /// `~/.local/state/basajaun`: routes.json, Caddyfile, admin socket, certificates.
    pub state_dir: PathBuf,
    /// `~/.local/share/basajaun`: bin/caddy.
    pub data_dir: PathBuf,
    /// `~/.config/systemd/user`.
    pub unit_dir: PathBuf,
}

fn dir(var: &str, xdg: &str, fallback: &str, leaf: &str) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let base = match std::env::var_os(xdg).filter(|v| !v.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?)
            .join(fallback),
    };
    Ok(base.join(leaf))
}

impl Paths {
    /// Overrides: `BSJN_CONFIG_DIR`, `BSJN_STATE_DIR`, `BSJN_DATA_DIR`, `BSJN_UNIT_DIR`.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            config_dir: dir("BSJN_CONFIG_DIR", "XDG_CONFIG_HOME", ".config", "basajaun")?,
            state_dir: dir(
                "BSJN_STATE_DIR",
                "XDG_STATE_HOME",
                ".local/state",
                "basajaun",
            )?,
            data_dir: dir("BSJN_DATA_DIR", "XDG_DATA_HOME", ".local/share", "basajaun")?,
            unit_dir: dir(
                "BSJN_UNIT_DIR",
                "XDG_CONFIG_HOME",
                ".config",
                "systemd/user",
            )?,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn token_file(&self) -> PathBuf {
        self.config_dir.join("cloudflare-token")
    }
    /// `CLOUDFLARE_API_TOKEN=...` for the unit's `EnvironmentFile`.
    pub fn env_file(&self) -> PathBuf {
        self.config_dir.join("caddy.env")
    }
    pub fn routes_file(&self) -> PathBuf {
        self.state_dir.join("routes.json")
    }
    pub fn lock_file(&self) -> PathBuf {
        self.state_dir.join("routes.lock")
    }
    pub fn caddyfile(&self) -> PathBuf {
        self.state_dir.join("Caddyfile")
    }
    pub fn admin_socket(&self) -> PathBuf {
        self.state_dir.join("admin.sock")
    }
    /// Caddy's storage root: certificates and ACME account.
    pub fn storage_dir(&self) -> PathBuf {
        self.state_dir.join("caddy")
    }
    pub fn caddy_bin(&self) -> PathBuf {
        self.data_dir.join("bin").join("caddy")
    }
    pub fn unit_file(&self) -> PathBuf {
        self.unit_dir.join(UNIT_NAME)
    }
}
