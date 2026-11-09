//! End-to-end tests of the route commands against a temporary home. No proxy runs: the admin
//! socket does not exist, so `bsjn` warns and carries on. Nothing here touches the real
//! config, state, Cloudflare or Tailscale.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

struct Env {
    dir: TempDir,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("config.toml"),
            "base_domain = \"dev.example.com\"\nport = 8443\ntailnet_ip = \"100.64.0.1\"\n",
        )
        .unwrap();
        Self { dir }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let p = self.dir.path();
        let mut c = Command::new(env!("CARGO_BIN_EXE_bsjn"));
        c.args(args)
            .env("BSJN_CONFIG_DIR", p.join("config"))
            .env("BSJN_STATE_DIR", p.join("state"))
            .env("BSJN_DATA_DIR", p.join("data"))
            .env("BSJN_UNIT_DIR", p.join("units"));
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn caddyfile(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("state/Caddyfile")).unwrap_or_default()
    }

    fn ls_names(&self) -> Vec<String> {
        let out = self.run(&["ls", "--json"]);
        assert!(out.status.success());
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
        rows.iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn add_prints_only_the_url_and_is_idempotent() {
    let env = Env::new();
    let out = env.run(&["add", "web", "5173"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "https://web.dev.example.com:8443\n");
    let again = env.run(&["add", "web", "5173"]);
    assert!(again.status.success());
    assert_eq!(stdout(&again), stdout(&out));
    assert_eq!(env.ls_names(), ["web"]);
    assert!(env.caddyfile().contains("reverse_proxy 127.0.0.1:5173"));
}

#[test]
fn another_port_needs_force() {
    let env = Env::new();
    env.run(&["add", "web", "5173"]);
    let out = env.run(&["add", "web", "5174"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--force"));
    assert!(env.caddyfile().contains("127.0.0.1:5173"));
    let forced = env.run(&["add", "web", "5174", "--force"]);
    assert!(forced.status.success());
    assert!(env.caddyfile().contains("127.0.0.1:5174"));
    assert!(!env.caddyfile().contains("127.0.0.1:5173"));
}

#[test]
fn bad_names_and_ports_are_usage_errors() {
    let env = Env::new();
    for args in [
        ["add", "Web", "1"],
        ["add", "-x", "1"],
        ["add", "a.b", "1"],
        ["add", "ok", "0"],
    ] {
        let out = env.run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
    }
    assert_eq!(env.run(&["add", "ok", "70000"]).status.code(), Some(2));
    assert_eq!(env.run(&["rm"]).status.code(), Some(2));
}

#[test]
fn url_works_before_the_route_exists() {
    let env = Env::new();
    let out = env.run(&["url", "later"]);
    assert_eq!(stdout(&out), "https://later.dev.example.com:8443\n");
    assert!(env.ls_names().is_empty());
}

#[test]
fn rm_by_name_tag_and_all() {
    let env = Env::new();
    env.run(&["add", "a", "1001", "--tag", "wt1"]);
    env.run(&["add", "b", "1002", "--tag", "wt1"]);
    env.run(&["add", "c", "1003", "--tag", "wt2"]);
    env.run(&["add", "d", "1004"]);

    let ls = env.run(&["ls", "--json", "--tag", "wt1"]);
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&ls.stdout).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["kind"], "persistent");
    assert_eq!(rows[0]["listening"], false);

    assert!(env.run(&["rm", "--tag", "wt1"]).status.success());
    assert_eq!(env.ls_names(), ["c", "d"]);

    let missing = env.run(&["rm", "c", "nope"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(stderr(&missing).contains("nope"));
    assert_eq!(env.ls_names(), ["d"], "existing names are still removed");

    assert!(env.run(&["rm", "--all"]).status.success());
    assert!(env.run(&["rm", "--all"]).status.success(), "empty is fine");
    assert!(env.ls_names().is_empty());
    assert!(!env.caddyfile().contains("reverse_proxy"));
}

#[test]
fn run_sets_the_environment_returns_the_exit_code_and_removes_the_route() {
    let env = Env::new();
    let out = env.run(&[
        "run",
        "job",
        "--",
        "sh",
        "-c",
        "echo $BSJN_NAME $BSJN_URL $PORT; exit 7",
    ]);
    assert_eq!(out.status.code(), Some(7));
    let line = stdout(&out);
    let parts: Vec<_> = line.split_whitespace().collect();
    assert_eq!(parts[0], "job");
    assert_eq!(parts[1], "https://job.dev.example.com:8443");
    let port: u16 = parts[2].parse().unwrap();
    assert!(stderr(&out).contains(&format!(
        "https://job.dev.example.com:8443 -> 127.0.0.1:{port}"
    )));
    assert!(env.ls_names().is_empty());
}

#[test]
fn run_refuses_a_taken_name_and_a_missing_command() {
    let env = Env::new();
    env.run(&["add", "taken", "4000"]);
    let out = env.run(&["run", "taken", "--", "true"]);
    assert_eq!(out.status.code(), Some(1));
    let out = env.run(&["run", "gone", "--", "/nonexistent/program"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(env.ls_names(), ["taken"], "a failed run leaves no route");
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..100 {
        if ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn signal(pid: u32, sig: &str) {
    Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .status()
        .unwrap();
}

#[test]
fn sigterm_stops_the_child_and_removes_the_route() {
    let env = Env::new();
    let mut run = env
        .cmd(&["run", "svc", "--", "sleep", "30"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("the route", || env.ls_names() == ["svc"]);
    signal(run.id(), "TERM");
    let status = run.wait().unwrap();
    assert_eq!(status.code(), Some(143));
    assert!(env.ls_names().is_empty());
}

#[test]
fn a_killed_run_leaves_a_stale_route_that_ls_cleans() {
    let env = Env::new();
    let mut run = env
        .cmd(&["run", "svc", "--", "sleep", "30"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("the route", || env.ls_names() == ["svc"]);
    run.kill().unwrap();
    run.wait().unwrap();
    let out = env.run(&["ls"]);
    assert_eq!(stdout(&out), "no routes\n");
    assert!(stderr(&out).contains("removed stale route svc"));
    assert!(!env.caddyfile().contains("@r_svc"));
}

#[test]
fn two_runs_at_the_same_time_both_work() {
    let env = Env::new();
    let spawn = |name: &str| {
        env.cmd(&["run", name, "--", "sh", "-c", "sleep 0.5; echo $PORT"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let (a, b) = (spawn("one"), spawn("two"));
    wait_for("both routes", || env.ls_names() == ["one", "two"]);
    let (a, b) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    assert!(a.status.success() && b.status.success());
    assert_ne!(stdout(&a), stdout(&b), "each run got its own port");
    assert!(env.ls_names().is_empty());
}

#[test]
fn concurrent_adds_lose_no_routes() {
    let env = Env::new();
    let children: Vec<_> = (0..12)
        .map(|i| {
            env.cmd(&["add", &format!("w{i}"), &format!("{}", 2000 + i)])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for mut c in children {
        assert!(c.wait().unwrap().success());
    }
    assert_eq!(env.ls_names().len(), 12);
    let caddyfile = env.caddyfile();
    for i in 0..12 {
        assert!(caddyfile.contains(&format!("127.0.0.1:{}", 2000 + i)));
    }
}

#[test]
fn commands_need_setup_first() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bsjn"))
        .args(["add", "x", "1"])
        .env("BSJN_CONFIG_DIR", dir.path())
        .env("BSJN_STATE_DIR", dir.path().join("s"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("bsjn setup"));
    let _: &Path = dir.path();
}
