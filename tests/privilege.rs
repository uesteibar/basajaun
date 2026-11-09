//! The privileged-port step, driven through the hidden `bsjn port-access` command with fake
//! `sudo`, `getcap`, `setcap` and `sysctl` programs first on PATH. The real sudo is never
//! called. Terminal cases run on a pty; the no-terminal case runs on plain pipes.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const SUDO: &str = r#"#!/bin/sh
in=$(readlink /proc/$$/fd/0)
out=$(readlink /proc/$$/fd/1)
{
  echo "sudo $*"
  echo "stdin=$in stdout=$out"
} >> "$FAKE_LOG"
[ -n "$FAKE_SUDO_FAIL" ] && exit 1
case "$1" in
  setcap|sysctl) exec "$@" ;;
  install) cp "$4" "$FAKE_ETC/$(basename "$5")" ;;
  *) echo "unexpected sudo command: $*" >> "$FAKE_LOG"; exit 3 ;;
esac
"#;
const SETCAP: &str =
    "#!/bin/sh\necho \"$1\" > \"$FAKE_STATE/cap-flags\"\necho \"$2\" > \"$FAKE_STATE/cap-file\"\n";
const GETCAP: &str = "#!/bin/sh\nif [ -f \"$FAKE_STATE/cap-file\" ] && [ \"$(cat \"$FAKE_STATE/cap-file\")\" = \"$1\" ]; then echo \"$1 cap_net_bind_service=ep\"; fi\nexit 0\n";
const SYSCTL: &str = "#!/bin/sh\necho \"${2#*=}\" > \"$BSJN_UNPRIV_PORT_FILE\"\n";

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for d in ["config", "shims", "state", "etc"] {
            fs::create_dir_all(p.join(d)).unwrap();
        }
        fs::write(
            p.join("config/config.toml"),
            "base_domain = \"dev.example.com\"\nport = 443\n",
        )
        .unwrap();
        fs::write(p.join("port-start"), "1024\n").unwrap();
        for (name, body) in [
            ("sudo", SUDO),
            ("setcap", SETCAP),
            ("getcap", GETCAP),
            ("sysctl", SYSCTL),
        ] {
            let file = p.join("shims").join(name);
            fs::write(&file, body).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn caddy(&self) -> PathBuf {
        self.path().join("data/bin/caddy")
    }

    fn command(&self, args: &[&str], sudo_fails: bool) -> Command {
        let p = self.path();
        let mut c = Command::new(env!("CARGO_BIN_EXE_bsjn"));
        c.arg("port-access")
            .args(args)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    p.join("shims").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("BSJN_CONFIG_DIR", p.join("config"))
            .env("BSJN_STATE_DIR", p.join("state"))
            .env("BSJN_DATA_DIR", p.join("data"))
            .env("BSJN_UNPRIV_PORT_FILE", p.join("port-start"))
            .env("FAKE_LOG", p.join("sudo.log"))
            .env("FAKE_STATE", p.join("state"))
            .env("FAKE_ETC", p.join("etc"));
        if sudo_fails {
            c.env("FAKE_SUDO_FAIL", "1");
        }
        c
    }

    fn sudo_log(&self) -> String {
        fs::read_to_string(self.path().join("sudo.log")).unwrap_or_default()
    }

    fn setcap_command(&self) -> String {
        format!(
            "sudo setcap cap_net_bind_service=+ep {}",
            self.caddy().display()
        )
    }
}

/// A child process on its own pseudo terminal.
struct Pty {
    master: File,
    child: Child,
    slave_name: String,
    output: String,
}

impl Pty {
    fn spawn(mut cmd: Command) -> Self {
        let (mut m, mut s) = (0, 0);
        // SAFETY: plain libc calls on descriptors we own; the child side only calls
        // setsid and ioctl between fork and exec.
        unsafe {
            assert_eq!(
                libc::openpty(
                    &mut m,
                    &mut s,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                0
            );
            let mut buf = [0 as libc::c_char; 128];
            assert_eq!(libc::ttyname_r(s, buf.as_mut_ptr(), buf.len()), 0);
            let name = std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_string_lossy()
                .into_owned();
            let dup = || OwnedFd::from_raw_fd(libc::dup(s));
            cmd.stdin(Stdio::from(dup()))
                .stdout(Stdio::from(dup()))
                .stderr(Stdio::from(dup()));
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
            let child = cmd.spawn().unwrap();
            libc::close(s);
            Self {
                master: File::from_raw_fd(m),
                child,
                slave_name: name,
                output: String::new(),
            }
        }
    }

    /// Read until `needle` has appeared in the output.
    fn expect(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.output.contains(needle) {
            assert!(
                Instant::now() < deadline && self.read_some(200),
                "waiting for {needle:?}; got:\n{}",
                self.output
            );
        }
    }

    /// False at end of output.
    fn read_some(&mut self, wait_ms: i32) -> bool {
        let mut fds = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut fds, 1, wait_ms) };
        if fds.revents == 0 {
            return true;
        }
        let mut buf = [0u8; 4096];
        match self.master.read(&mut buf) {
            Ok(n) if n > 0 => {
                self.output.push_str(&String::from_utf8_lossy(&buf[..n]));
                true
            }
            _ => false, // EIO once the child side is closed
        }
    }

    fn send(&mut self, text: &str) {
        self.master.write_all(text.as_bytes()).unwrap();
    }

    /// Everything the child printed and its exit code.
    fn finish(mut self) -> (i32, String) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.read_some(200) {
            assert!(
                Instant::now() < deadline,
                "child did not exit:\n{}",
                self.output
            );
        }
        let code = self.child.wait().unwrap().code().unwrap();
        (code, self.output.replace('\r', ""))
    }
}

#[test]
fn accepting_the_default_runs_sudo_setcap_on_the_terminal_and_finishes() {
    let fx = Fixture::new();
    let mut pty = Pty::spawn(fx.command(&[], false));
    pty.expect("Run it now with sudo? [Y/n]");
    let tty = pty.slave_name.clone();
    pty.send("\n");
    let (code, out) = pty.finish();
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&fx.setcap_command()),
        "the command is shown: {out}"
    );
    assert!(!out.contains("NOT DONE"));
    assert!(
        out.contains("has cap_net_bind_service"),
        "re-checked: {out}"
    );

    let log = fx.sudo_log();
    assert!(log.contains(&fx.setcap_command()), "{log}");
    // sudo got the terminal itself on all three streams: no pipe, nothing written to its stdin.
    assert!(log.contains(&format!("stdin={tty} stdout={tty}")), "{log}");
}

#[test]
fn declining_prints_the_steps_and_is_not_done() {
    let fx = Fixture::new();
    let mut pty = Pty::spawn(fx.command(&[], false));
    pty.expect("Run it now with sudo? [Y/n]");
    pty.send("n\n");
    let (code, out) = pty.finish();
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("NOT DONE"));
    assert!(out.contains(&fx.setcap_command()));
    assert!(out.contains("run: bsjn setup --port 443"));
    assert_eq!(fx.sudo_log(), "", "sudo must not run");
}

#[test]
fn a_failing_sudo_is_not_done() {
    let fx = Fixture::new();
    let mut pty = Pty::spawn(fx.command(&[], true));
    pty.expect("Run it now with sudo? [Y/n]");
    pty.send("y\n");
    let (code, out) = pty.finish();
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("failed"), "{out}");
    assert!(out.contains("NOT DONE"));
    assert!(fx.sudo_log().contains("sudo setcap"));
}

#[test]
fn yes_on_a_terminal_runs_sudo_without_asking() {
    let fx = Fixture::new();
    let pty = Pty::spawn(fx.command(&["--yes"], false));
    let (code, out) = pty.finish();
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("Run it now"));
    assert!(
        fx.sudo_log()
            .contains("sudo setcap cap_net_bind_service=+ep")
    );
}

#[test]
fn without_a_terminal_sudo_is_never_started() {
    let fx = Fixture::new();
    for args in [&[][..], &["--yes"][..], &["--sysctl", "--yes"][..]] {
        let out = fx
            .command(args, false)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {text}");
        assert!(text.contains("NOT DONE"), "{text}");
        assert!(text.contains("not a terminal"), "{text}");
        assert!(text.contains("sudo "), "the command is printed: {text}");
        assert_eq!(fx.sudo_log(), "", "{args:?}: sudo must not run");
    }
}

#[test]
fn nothing_to_do_when_the_port_is_already_allowed() {
    let fx = Fixture::new();
    fs::write(fx.path().join("port-start"), "80\n").unwrap();
    let out = fx
        .command(&[], false)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(fx.sudo_log(), "");
}

#[test]
fn sysctl_always_asks_with_no_as_the_default_even_with_yes() {
    let fx = Fixture::new();
    let mut pty = Pty::spawn(fx.command(&["--sysctl", "--yes"], false));
    pty.expect("Apply it system-wide now with sudo? [y/N]");
    pty.send("\n");
    let (code, out) = pty.finish();
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("every program on this machine"));
    assert!(out.contains("NOT DONE"));
    assert_eq!(fx.sudo_log(), "");
}

#[test]
fn sysctl_confirmed_sets_the_limit_and_persists_it_without_piping_into_sudo() {
    let fx = Fixture::new();
    let mut pty = Pty::spawn(fx.command(&["--sysctl"], false));
    pty.expect("[y/N]");
    let tty = pty.slave_name.clone();
    pty.send("y\n");
    let (code, out) = pty.finish();
    assert_eq!(code, 0, "{out}");

    let log = fx.sudo_log();
    assert!(log.contains("sudo install -m 644 "), "{log}");
    assert!(log.contains("99-bsjn.conf"), "{log}");
    assert!(
        log.contains("sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443"),
        "{log}"
    );
    assert_eq!(
        log.matches(&format!("stdin={tty} stdout={tty}")).count(),
        2,
        "{log}"
    );
    assert_eq!(
        fs::read_to_string(fx.path().join("etc/99-bsjn.conf")).unwrap(),
        "net.ipv4.ip_unprivileged_port_start=443\n"
    );
    assert_eq!(
        fs::read_to_string(fx.path().join("port-start"))
            .unwrap()
            .trim(),
        "443"
    );
    let leftovers: Vec<_> = fs::read_dir(fx.path().join("state"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("sysctl-"))
        .collect();
    assert!(leftovers.is_empty(), "the temporary file is removed");
    let mode = fs::metadata(fx.path().join("state"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "the directory holding the sysctl source is private"
    );
}
