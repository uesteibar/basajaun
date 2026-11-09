//! `~/.config/basajaun/config.toml`.

use crate::paths::Paths;
use crate::{names, tailscale};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;

pub const DEFAULT_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub base_domain: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Last tailnet IPv4 seen by `setup`. Only a fallback for when `tailscale` cannot be asked;
    /// a stale value makes the proxy fail to bind, never bind more widely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailnet_ip: Option<Ipv4Addr>,
    /// ACME directory URL, for trying things against Let's Encrypt staging. Default: Caddy's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_ca: Option<String>,
    /// Reject every request whose client address is outside the Tailscale ranges, before any
    /// route is evaluated. On by default; `false` only for a different network design.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub restrict_source: bool,
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Config {
    pub fn load(paths: &Paths) -> Result<Self> {
        Self::try_load(paths)?.ok_or_else(|| {
            anyhow::anyhow!(
                "bsjn is not set up (no {}): run `bsjn setup`",
                paths.config_file().display()
            )
        })
    }

    pub fn try_load(paths: &Paths) -> Result<Option<Self>> {
        let file = paths.config_file();
        let text = match fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", file.display())),
        };
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("cannot parse {}", file.display()))?;
        cfg.validate()
            .with_context(|| format!("invalid {}", file.display()))?;
        Ok(Some(cfg))
    }

    /// What loading checks: a hand-edited or copied file must fail loudly here instead of
    /// turning into a wider bind address or extra Caddyfile lines.
    fn validate(&self) -> Result<()> {
        if self.port == 0 {
            bail!("port must not be 0");
        }
        names::validate_domain(&self.base_domain).map_err(|e| anyhow!("{e}"))?;
        if let Some(ip) = self.tailnet_ip {
            tailscale::require_tailnet_ipv4(ip).context("tailnet_ip")?;
        }
        if let Some(ca) = &self.acme_ca {
            names::reject_control("acme_ca", ca)?;
        }
        Ok(())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        crate::registry::create_private_dir(&paths.config_dir)?;
        let text = toml::to_string_pretty(self)?;
        crate::registry::write_atomic(&paths.config_file(), text.as_bytes(), 0o644)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_defaults_to_443_and_round_trips() {
        let cfg: Config = toml::from_str("base_domain = \"dev.example.com\"").unwrap();
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.tailnet_ip, None);
        assert!(cfg.restrict_source);
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), cfg);
    }

    #[test]
    fn restrict_source_is_on_by_default_and_can_be_turned_off() {
        let off: Config =
            toml::from_str("base_domain = \"dev.example.com\"\nrestrict_source = false").unwrap();
        assert!(!off.restrict_source);
        assert!(
            toml::to_string_pretty(&off)
                .unwrap()
                .contains("restrict_source = false")
        );
        // Not written when on, so a saved default stays a default.
        let on: Config = toml::from_str("base_domain = \"dev.example.com\"").unwrap();
        assert!(
            !toml::to_string_pretty(&on)
                .unwrap()
                .contains("restrict_source")
        );
    }

    fn load(text: &str) -> Result<Option<Config>> {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config_dir: dir.path().into(),
            state_dir: dir.path().into(),
            data_dir: dir.path().into(),
            unit_dir: dir.path().into(),
        };
        std::fs::write(paths.config_file(), text).unwrap();
        Config::try_load(&paths)
    }

    #[test]
    fn a_bad_file_is_an_error_never_a_wider_bind() {
        let base = "base_domain = \"dev.example.com\"\n";
        assert!(load(&format!("{base}tailnet_ip = \"100.64.0.1\"")).is_ok());
        for bad in [
            "tailnet_ip = \"0.0.0.0\"",
            "tailnet_ip = \"127.0.0.1\"",
            "tailnet_ip = \"203.0.113.7\"",
            "tailnet_ip = \"100.64.0.1\\nbind 0.0.0.0\"",
            "tailnet_ip = \"not an ip\"",
            "acme_ca = \"https://x\\n}\"",
        ] {
            assert!(load(&format!("{base}{bad}")).is_err(), "{bad}");
        }
        assert!(load("base_domain = \"a.com\\n}\"").is_err());
        assert!(load("base_domain = \"Dev.Example.com\"").is_err());
        let err = format!(
            "{:#}",
            load(&format!("{base}tailnet_ip = \"0.0.0.0\"")).unwrap_err()
        );
        assert!(
            err.contains("config.toml") && err.contains("not a Tailscale address"),
            "{err}"
        );
    }
}
