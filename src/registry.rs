//! The route registry: `routes.json`, guarded by a file lock. It is the source of truth;
//! the Caddyfile is always generated from it.

use crate::names;
use crate::paths::Paths;
use crate::proc;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Persistent,
    Run,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Persistent => "persistent",
            Kind::Run => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub name: String,
    pub port: u16,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Owner of a `run` route: the `bsjn run` process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
}

impl Route {
    /// A `run` route whose owner is gone.
    pub fn is_stale(&self) -> bool {
        self.kind == Kind::Run && !self.pid.is_some_and(|p| proc::alive(p, self.start_time))
    }

    pub fn owned_by(&self, pid: u32) -> bool {
        self.kind == Kind::Run && self.pid == Some(pid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    pub version: u32,
    pub routes: Vec<Route>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            routes: Vec::new(),
        }
    }
}

impl Registry {
    pub fn get(&self, name: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.name == name)
    }

    /// Insert or replace by name; routes stay sorted by name.
    pub fn upsert(&mut self, route: Route) {
        self.routes.retain(|r| r.name != route.name);
        self.routes.push(route);
        self.routes.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn remove(&mut self, name: &str) -> Option<Route> {
        let i = self.routes.iter().position(|r| r.name == name)?;
        Some(self.routes.remove(i))
    }

    /// Drop `run` routes whose owner died. Returns them.
    pub fn prune_stale(&mut self) -> Vec<Route> {
        let (stale, live): (Vec<_>, Vec<_>) = self.routes.drain(..).partition(Route::is_stale);
        self.routes = live;
        stale
    }
}

/// Make `dir` a private directory: create it with mode 0700 when missing; when it exists it must
/// be a real directory (not a symlink) owned by this user, and gets mode 0700.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        // A symlink to a directory, or a file: the checks below say which.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", dir.display())),
    }
    // O_NOFOLLOW: a symlink is refused rather than followed; the checks are on the descriptor.
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .with_context(|| {
            format!(
                "{} must be a real directory, not a symlink or a file",
                dir.display()
            )
        })?;
    let meta = handle.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        bail!(
            "{} belongs to another user (uid {}); refusing to keep secrets there",
            dir.display(),
            meta.uid()
        );
    }
    if meta.mode() & 0o7777 != 0o700 {
        handle
            .set_permissions(fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot set mode 700 on {}", dir.display()))?;
    }
    Ok(())
}

/// Write `data` next to `path` and rename it over, so readers never see a partial file. The
/// temporary file has a random name and is created exclusively (never through a symlink), and
/// gets its final mode before any data is written. The caller makes the directory private when
/// the content is secret.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let result = (|| -> Result<()> {
        let mut tmp = tempfile::Builder::new().prefix(".bsjn-").tempfile_in(dir)?;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
        tmp.write_all(data)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path)?;
        Ok(())
    })();
    result.with_context(|| format!("cannot write {}", path.display()))
}

/// `write_atomic` unless `path` is already a regular file of ours with exactly this content.
/// Then only its mode is repaired. Returns whether the content was written.
pub fn write_if_different(path: &Path, data: &[u8], mode: u32) -> Result<bool> {
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    let existing = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()
        .filter(|f| f.metadata().is_ok_and(|m| m.is_file() && m.uid() == me));
    if let Some(mut f) = existing {
        let mut old = Vec::new();
        if f.read_to_end(&mut old).is_ok() && old == data {
            if f.metadata()?.mode() & 0o7777 != mode {
                f.set_permissions(fs::Permissions::from_mode(mode))
                    .with_context(|| format!("cannot set the mode of {}", path.display()))?;
            }
            return Ok(false);
        }
    }
    write_atomic(path, data, mode)?;
    Ok(true)
}

/// Exclusive lock on the registry, released on drop.
pub struct Lock {
    _file: File,
}

impl Lock {
    pub fn acquire(paths: &Paths) -> Result<Self> {
        create_private_dir(&paths.state_dir)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(paths.lock_file())
            .with_context(|| format!("cannot open {}", paths.lock_file().display()))?;
        file.lock().context("cannot lock the registry")?;
        Ok(Self { _file: file })
    }
}

impl Route {
    /// What loading checks: names and tags end up in the Caddyfile, so they must be as clean as
    /// when the CLI accepted them.
    fn validate(&self) -> Result<()> {
        names::validate_name(&self.name).map_err(|e| anyhow!("{e}"))?;
        if let Some(tag) = &self.tag {
            names::validate_tag(tag).map_err(|e| anyhow!("{e}"))?;
        }
        if self.port == 0 {
            bail!("route {}: port must not be 0", self.name);
        }
        Ok(())
    }
}

pub fn load(paths: &Paths) -> Result<Registry> {
    let file = paths.routes_file();
    match fs::read_to_string(&file) {
        Ok(text) => {
            let reg: Registry = serde_json::from_str(&text)
                .with_context(|| format!("cannot parse {}", file.display()))?;
            for r in &reg.routes {
                r.validate()
                    .with_context(|| format!("invalid {}", file.display()))?;
            }
            Ok(reg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", file.display())),
    }
}

pub fn save(paths: &Paths, reg: &Registry) -> Result<()> {
    let mut text = serde_json::to_string_pretty(reg)?;
    text.push('\n');
    write_atomic(&paths.routes_file(), text.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &tempfile::TempDir) -> Paths {
        let p = dir.path();
        Paths {
            config_dir: p.join("config"),
            state_dir: p.join("state"),
            data_dir: p.join("data"),
            unit_dir: p.join("units"),
        }
    }

    fn route(name: &str, port: u16) -> Route {
        Route {
            name: name.into(),
            port,
            kind: Kind::Persistent,
            tag: None,
            pid: None,
            start_time: None,
        }
    }

    #[test]
    fn upsert_replaces_and_keeps_order() {
        let mut reg = Registry::default();
        reg.upsert(route("b", 2));
        reg.upsert(route("a", 1));
        reg.upsert(route("b", 3));
        let names: Vec<_> = reg.routes.iter().map(|r| (&r.name[..], r.port)).collect();
        assert_eq!(names, [("a", 1), ("b", 3)]);
        assert!(reg.remove("a").is_some());
        assert!(reg.remove("a").is_none());
    }

    #[test]
    fn only_dead_run_routes_are_pruned() {
        let me = std::process::id();
        let mut reg = Registry::default();
        reg.upsert(route("persistent", 1));
        reg.upsert(Route {
            kind: Kind::Run,
            pid: Some(me),
            start_time: proc::start_time(me),
            ..route("alive", 2)
        });
        reg.upsert(Route {
            kind: Kind::Run,
            pid: Some(me),
            start_time: proc::start_time(me).map(|s| s + 1), // pid reused
            ..route("reused", 3)
        });
        reg.upsert(Route {
            kind: Kind::Run,
            pid: None,
            ..route("orphan", 4)
        });
        let stale: Vec<_> = reg.prune_stale().into_iter().map(|r| r.name).collect();
        assert_eq!(stale, ["orphan", "reused"]);
        let left: Vec<_> = reg.routes.iter().map(|r| &r.name[..]).collect();
        assert_eq!(left, ["alive", "persistent"]);
    }

    #[test]
    fn missing_file_is_an_empty_registry_and_save_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        assert_eq!(load(&p).unwrap(), Registry::default());
        create_private_dir(&p.state_dir).unwrap();
        let mut reg = Registry::default();
        reg.upsert(route("a", 1));
        save(&p, &reg).unwrap();
        assert_eq!(load(&p).unwrap(), reg);
    }

    #[test]
    fn invalid_routes_are_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        create_private_dir(&p.state_dir).unwrap();
        let load_json = |json: &str| {
            fs::write(p.routes_file(), json).unwrap();
            load(&p)
        };
        let good = r#"{"version":1,"routes":[{"name":"web","port":5173,"kind":"persistent","tag":"feature/x"}]}"#;
        assert!(load_json(good).is_ok());
        for bad in [
            r#"{"name":"we b","port":1,"kind":"persistent"}"#,
            r#"{"name":"web\n}","port":1,"kind":"persistent"}"#,
            r#"{"name":"Web","port":1,"kind":"persistent"}"#,
            r#"{"name":"web","port":0,"kind":"persistent"}"#,
            r#"{"name":"web","port":1,"kind":"persistent","tag":"a\nb"}"#,
        ] {
            let json = format!(r#"{{"version":1,"routes":[{bad}]}}"#);
            assert!(load_json(&json).is_err(), "{bad}");
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn an_existing_private_dir_is_repaired_and_a_symlink_or_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        create_private_dir(&open).unwrap();
        assert_eq!(mode(&open), 0o700);

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&open, &link).unwrap();
        let err = format!("{:#}", create_private_dir(&link).unwrap_err());
        assert!(err.contains("not a symlink"), "{err}");

        let file = dir.path().join("file");
        fs::write(&file, "").unwrap();
        assert!(create_private_dir(&file).is_err());
    }

    #[test]
    fn a_symlink_at_the_old_predictable_temp_name_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "untouched").unwrap();
        let target = dir.path().join("secret.env");
        for planted in [
            format!("secret.tmp{}", std::process::id()),
            format!("secret.env.tmp{}", std::process::id()),
        ] {
            std::os::unix::fs::symlink(&victim, dir.path().join(planted)).unwrap();
        }
        write_atomic(&target, b"token", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
        assert_eq!(fs::read_to_string(&target).unwrap(), "token");
        assert_eq!(mode(&target), 0o600);
    }

    #[test]
    fn matching_content_still_gets_its_mode_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("caddy.env");
        fs::write(&f, "TOKEN=x\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!write_if_different(&f, b"TOKEN=x\n", 0o600).unwrap());
        assert_eq!(mode(&f), 0o600);
        assert!(write_if_different(&f, b"TOKEN=y\n", 0o600).unwrap());
        assert_eq!(fs::read_to_string(&f).unwrap(), "TOKEN=y\n");
    }

    #[test]
    fn a_symlink_in_place_of_a_secret_file_is_replaced_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "TOKEN=x\n").unwrap();
        let f = dir.path().join("caddy.env");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, &f).unwrap();
        assert!(write_if_different(&f, b"TOKEN=x\n", 0o600).unwrap());
        assert!(!fs::symlink_metadata(&f).unwrap().is_symlink());
        assert_eq!(mode(&victim), 0o644, "the link target is left alone");
        assert_eq!(mode(&f), 0o600);
    }

    #[test]
    fn concurrent_read_modify_write_loses_no_routes() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(&dir);
        let handles: Vec<_> = (0..16u16)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let _lock = Lock::acquire(&p).unwrap();
                    let mut reg = load(&p).unwrap();
                    // Widen the race window between read and write.
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    reg.upsert(route(&format!("r{i}"), 1000 + i));
                    save(&p, &reg).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(load(&p).unwrap().routes.len(), 16);
    }
}
