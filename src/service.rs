//! The proxy as a program and as a `systemd --user` service: building Caddy with the Cloudflare
//! DNS module, writing the unit, and talking to `systemctl`.

use crate::paths::{Paths, UNIT_NAME};
use crate::redact::redact;
use crate::registry::{create_private_dir, write_if_different};
use anyhow::{Context, Result, bail};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, Stdio};

// Pinned, so the proxy is the same everywhere. Go's module checksum database verifies the
// sources of xcaddy, Caddy and the DNS module.
pub const CADDY_VERSION: &str = "v2.11.9";
pub const XCADDY_VERSION: &str = "v0.4.7";
pub const CLOUDFLARE_MODULE: &str = "github.com/caddy-dns/cloudflare@v0.2.4";
pub const GO_VERSION: &str = "1.27.3";
const CLOUDFLARE_MODULE_ID: &str = "dns.providers.cloudflare";

/// The version part of `CLOUDFLARE_MODULE` (`v0.2.4`).
fn cloudflare_version() -> &'static str {
    CLOUDFLARE_MODULE.rsplit_once('@').map_or("", |(_, v)| v)
}

/// Does `caddy list-modules --versions` list the Cloudflare module at the pinned version?
/// A line is `<module id> <version>`; a plugin-only pin change must therefore trigger a rebuild.
fn has_pinned_cloudflare(list_modules: &str) -> bool {
    list_modules.lines().any(|l| {
        let mut f = l.split_whitespace();
        f.next() == Some(CLOUDFLARE_MODULE_ID) && f.next() == Some(cloudflare_version())
    })
}

/// Is the installed Caddy the pinned version, with the pinned Cloudflare module?
pub fn caddy_is_current(bin: &Path) -> bool {
    let run_args = |args: &[&str]| {
        Command::new(bin)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    run_args(&["version"]).is_some_and(|v| v.split_whitespace().next() == Some(CADDY_VERSION))
        && run_args(&["list-modules", "--versions"]).is_some_and(|m| has_pinned_cloudflare(&m))
}

/// xcaddy runs `sudo setcap` after a build when `XCADDY_SETCAP=1` is in its environment. Every
/// privileged step belongs to `privilege::ensure`, so the child never inherits that setting.
fn without_xcaddy_setcap(cmd: &mut Command) -> &mut Command {
    cmd.env("XCADDY_SETCAP", "0")
}

/// Build Caddy with xcaddy under a mise-managed Go and install it to `paths.caddy_bin()`.
/// No root, nothing downloaded outside the Go toolchain and the Go module proxy.
pub fn build_caddy(paths: &Paths) -> Result<()> {
    if Command::new("mise")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
    {
        bail!(
            "`mise` is needed to build Caddy (it provides Go); install it from https://mise.jdx.dev"
        );
    }
    let bin_dir = paths.caddy_bin().parent().unwrap().to_path_buf();
    create_private_dir(&paths.data_dir)?;
    std::fs::create_dir_all(&bin_dir)?;
    let work = tempfile_dir(&paths.data_dir)?;
    let go = format!("go@{GO_VERSION}");

    let step = |what: &str, cmd: &mut Command| -> Result<()> {
        eprintln!("  {what}");
        // Build output goes to stderr so that stdout stays readable.
        let status = cmd
            .stdout(Stdio::from(std::io::stderr().as_fd().try_clone_to_owned()?))
            .status()
            .with_context(|| format!("cannot run {what}"))?;
        if !status.success() {
            bail!("{what} failed ({status})");
        }
        Ok(())
    };

    let result = (|| {
        step(
            &format!("installing xcaddy {XCADDY_VERSION} with Go {GO_VERSION}"),
            Command::new("mise")
                .args(["exec", &go, "--", "go", "install"])
                .arg(format!(
                    "github.com/caddyserver/xcaddy/cmd/xcaddy@{XCADDY_VERSION}"
                ))
                .env("GOBIN", work.join("bin")),
        )?;
        let out = work.join("caddy");
        step(
            &format!("building Caddy {CADDY_VERSION} with {CLOUDFLARE_MODULE}"),
            without_xcaddy_setcap(
                Command::new("mise")
                    .args(["exec", &go, "--"])
                    .arg(work.join("bin/xcaddy"))
                    .args([
                        "build",
                        CADDY_VERSION,
                        "--with",
                        CLOUDFLARE_MODULE,
                        "--output",
                    ])
                    .arg(&out),
            ),
        )?;
        if !caddy_is_current(&out) {
            bail!("the built Caddy is not {CADDY_VERSION} with {CLOUDFLARE_MODULE}");
        }
        // Rename over the target: a running Caddy keeps its old file undisturbed.
        std::fs::rename(&out, paths.caddy_bin()).context("cannot install the new Caddy")
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn tempfile_dir(parent: &Path) -> Result<std::path::PathBuf> {
    let dir = parent.join(format!("build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// systemd: `%` starts a specifier, whitespace splits arguments. A control character (a newline
/// would start a new unit line) is an error.
fn unit_arg(s: &str) -> Result<String> {
    crate::names::reject_control("a path for the systemd unit", s)?;
    let s = s.replace('%', "%%").replace('\\', "\\\\");
    Ok(if s.contains(char::is_whitespace) || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s
    })
}

pub fn unit_text(paths: &Paths) -> Result<String> {
    let caddy = paths.caddy_bin();
    Ok(format!(
        "[Unit]\n\
Description=Basajaun proxy (Caddy on the tailnet IP)\n\
# Keep retrying until Tailscale is up: Caddy cannot bind the tailnet IP before that,\n\
# and it never falls back to another address.\n\
StartLimitIntervalSec=0\n\
\n\
[Service]\n\
ExecStart={} run --config {} --adapter caddyfile\n\
# The Cloudflare token, in a mode 600 file: keeps it out of argv and out of this unit.\n\
EnvironmentFile={}\n\
Environment=XDG_DATA_HOME={}\n\
Environment=XDG_CONFIG_HOME={}\n\
Restart=always\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        unit_arg(&caddy.display().to_string())?,
        unit_arg(&paths.caddyfile().display().to_string())?,
        unit_arg(&paths.env_file().display().to_string())?,
        unit_arg(&paths.state_dir.join("xdg-data").display().to_string())?,
        unit_arg(&paths.state_dir.join("xdg-config").display().to_string())?,
    ))
}

/// What `write_unit_files` changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changed {
    pub unit: bool,
    pub env: bool,
}

/// Write the unit and the token's environment file (mode 600); report what differed.
pub fn write_unit_files(paths: &Paths, token: &str) -> Result<Changed> {
    std::fs::create_dir_all(&paths.unit_dir)
        .with_context(|| format!("cannot create {}", paths.unit_dir.display()))?;
    create_private_dir(&paths.config_dir)?;
    create_private_dir(&paths.state_dir)?;
    Ok(Changed {
        unit: write_if_different(&paths.unit_file(), unit_text(paths)?.as_bytes(), 0o644)?,
        env: write_if_different(
            &paths.env_file(),
            format!("CLOUDFLARE_API_TOKEN={token}\n").as_bytes(),
            0o600,
        )?,
    })
}

fn systemctl(args: &[&str]) -> Result<std::process::Output> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .context("cannot run `systemctl --user`")
}

fn systemctl_ok(args: &[&str]) -> Result<()> {
    let out = systemctl(args)?;
    if out.status.success() {
        return Ok(());
    }
    bail!(
        "`systemctl --user {}` failed: {}",
        args.join(" "),
        redact(String::from_utf8_lossy(&out.stderr).trim(), &[])
    )
}

pub fn daemon_reload() -> Result<()> {
    systemctl_ok(&["daemon-reload"])
}

pub fn enable() -> Result<()> {
    systemctl_ok(&["enable", UNIT_NAME])
}

pub fn start() -> Result<()> {
    systemctl_ok(&["start", UNIT_NAME])
}

pub fn restart() -> Result<()> {
    systemctl_ok(&["restart", UNIT_NAME])
}

pub fn is_active() -> bool {
    systemctl(&["is-active", "--quiet", UNIT_NAME]).is_ok_and(|o| o.status.success())
}

/// Main pid of the service, when it runs.
pub fn main_pid() -> Option<u32> {
    let out = systemctl(&["show", "-p", "MainPID", "--value", UNIT_NAME]).ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .ok()
        .filter(|p| *p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn paths(root: &Path) -> Paths {
        Paths {
            config_dir: root.join("cfg"),
            state_dir: root.join("state"),
            data_dir: root.join("data"),
            unit_dir: root.join("units"),
        }
    }

    #[test]
    fn the_unit_runs_our_caddy_and_reads_the_token_from_a_file() {
        let p = paths(&PathBuf::from("/h"));
        let text = unit_text(&p).unwrap();
        assert!(text.contains(
            "ExecStart=/h/data/bin/caddy run --config /h/state/Caddyfile --adapter caddyfile\n"
        ));
        assert!(text.contains("EnvironmentFile=/h/cfg/caddy.env\n"));
        assert!(text.contains("StartLimitIntervalSec=0"));
        assert!(!text.contains("CLOUDFLARE_API_TOKEN="));
    }

    const MODULES: &str = "\
tls.stek.standard v2.11.9

  Standard modules: 136

dns.providers.cloudflare v0.2.4

  Non-standard modules: 1
";

    #[test]
    fn the_cloudflare_module_must_be_the_pinned_version() {
        assert!(has_pinned_cloudflare(MODULES));
        assert!(!has_pinned_cloudflare(
            &MODULES.replace("cloudflare v0.2.4", "cloudflare v0.2.3")
        ));
        // Without --versions, or without the module at all.
        assert!(!has_pinned_cloudflare("dns.providers.cloudflare\n"));
        assert!(!has_pinned_cloudflare("tls.stek.standard v2.11.9\n"));
        assert_eq!(cloudflare_version(), "v0.2.4");
    }

    #[test]
    fn an_inherited_xcaddy_setcap_does_not_reach_the_child() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-mise");
        std::fs::write(&fake, "#!/bin/sh\nprintf %s \"$XCADDY_SETCAP\"\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The explicit `1` stands for a value inherited from the caller's environment.
        let out = without_xcaddy_setcap(Command::new(&fake).env("XCADDY_SETCAP", "1"))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "0");
    }

    #[test]
    fn unit_arguments_are_quoted_when_needed() {
        assert_eq!(unit_arg("/a b/c").unwrap(), "\"/a b/c\"");
        assert_eq!(unit_arg("/a%b").unwrap(), "/a%%b");
        // A newline would start a new line of the unit.
        assert!(unit_arg("/a\nExecStartPre=/bin/evil").is_err());
        assert!(unit_arg("/a\rb").is_err());
    }

    #[test]
    fn loose_modes_on_existing_secret_files_and_dirs_are_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write_unit_files(&p, "secret").unwrap();
        let mode = |f: &Path| std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
        let loosen = |f: &Path, m| std::fs::set_permissions(f, Permissions::from_mode(m)).unwrap();
        use std::fs::Permissions;
        loosen(&p.config_dir, 0o777);
        loosen(&p.env_file(), 0o644);
        // Same content: nothing to restart, but the modes are put right.
        assert_eq!(write_unit_files(&p, "secret").unwrap(), Changed::default());
        assert_eq!(mode(&p.config_dir), 0o700);
        assert_eq!(mode(&p.env_file()), 0o600);
    }

    #[test]
    fn writing_the_files_is_idempotent_and_the_token_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let first = write_unit_files(&p, "secret").unwrap();
        assert_eq!(
            first,
            Changed {
                unit: true,
                env: true
            }
        );
        let mode = std::fs::metadata(p.env_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(write_unit_files(&p, "secret").unwrap(), Changed::default());
        let rotated = write_unit_files(&p, "other").unwrap();
        assert_eq!(
            rotated,
            Changed {
                unit: false,
                env: true
            }
        );
        assert!(
            !std::fs::read_to_string(p.unit_file())
                .unwrap()
                .contains("secret")
        );
    }
}
