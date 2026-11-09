//! The route commands: add, rm, ls, url.

use crate::config::Config;
use crate::names;
use crate::paths::Paths;
use crate::proc;
use crate::proxy::{self, Outcome};
use crate::registry::{self, Kind, Lock, Registry, Route};
use crate::usage;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct Ctx {
    pub paths: Paths,
    pub cfg: Config,
}

impl Ctx {
    pub fn load() -> Result<Self> {
        let paths = Paths::from_env()?;
        let cfg = Config::load(&paths)?;
        Ok(Self { paths, cfg })
    }

    pub fn url(&self, name: &str) -> String {
        names::url(name, &self.cfg.base_domain, self.cfg.port)
    }

    /// Change the registry under its lock, then bring the proxy in line with it.
    ///
    /// Routes of dead `bsjn run` processes are dropped first. Everything happens under the
    /// lock, so concurrent callers apply their configurations one after the other and the last
    /// one always reflects every route.
    pub fn mutate<T>(&self, f: impl FnOnce(&mut Registry) -> Result<T>) -> Result<T> {
        let _lock = Lock::acquire(&self.paths)?;
        let mut reg = registry::load(&self.paths)?;
        let before = reg.clone();
        for stale in reg.prune_stale() {
            eprintln!("bsjn: removed stale route {}", stale.name);
        }
        let value = f(&mut reg);
        if reg != before {
            registry::save(&self.paths, &reg)?;
            let applied = proxy::apply(&self.paths, &self.cfg, &reg.routes)
                .context("the registry is updated but the proxy configuration is not")?;
            if let Outcome::ProxyDown(why) = applied {
                eprintln!(
                    "bsjn: warning: the proxy is not running ({why}); routes go live when it starts: systemctl --user start bsjn-proxy"
                );
            }
        }
        value
    }
}

pub fn add(ctx: &Ctx, name: &str, port: u16, tag: Option<&str>, force: bool) -> Result<()> {
    names::validate_name(name)?;
    if let Some(t) = tag {
        names::validate_tag(t)?;
    }
    if port == 0 {
        return Err(usage("port must be between 1 and 65535"));
    }
    ctx.mutate(|reg| {
        let tag = tag.map(str::to_string);
        match reg.get(name) {
            None => {}
            Some(r) if r.kind == Kind::Persistent && r.port == port => {
                let mut r = r.clone();
                if tag.is_some() {
                    r.tag = tag;
                }
                reg.upsert(r);
                return Ok(());
            }
            Some(r) if !force => bail!(
                "{name} already routes to port {} ({}); use --force to replace it",
                r.port,
                r.kind.as_str()
            ),
            Some(r) => {
                let tag = tag.clone().or_else(|| r.tag.clone());
                reg.upsert(persistent(name, port, tag));
                return Ok(());
            }
        }
        reg.upsert(persistent(name, port, tag));
        Ok(())
    })?;
    println!("{}", ctx.url(name));
    Ok(())
}

fn persistent(name: &str, port: u16, tag: Option<String>) -> Route {
    Route {
        name: name.into(),
        port,
        kind: Kind::Persistent,
        tag,
        pid: None,
        start_time: None,
    }
}

pub struct RmArgs {
    pub names: Vec<String>,
    pub tag: Option<String>,
    pub all: bool,
}

pub fn rm(ctx: &Ctx, args: &RmArgs) -> Result<i32> {
    for n in &args.names {
        names::validate_name(n)?;
    }
    let (removed, missing) = ctx.mutate(|reg| {
        let mut removed = Vec::new();
        let mut missing = Vec::new();
        if args.all {
            removed.extend(reg.routes.drain(..).map(|r| r.name));
        } else if let Some(tag) = &args.tag {
            let (hit, keep): (Vec<_>, Vec<_>) = reg
                .routes
                .drain(..)
                .partition(|r| r.tag.as_deref() == Some(tag));
            reg.routes = keep;
            removed.extend(hit.into_iter().map(|r| r.name));
        } else {
            for n in &args.names {
                match reg.remove(n) {
                    Some(r) => removed.push(r.name),
                    None => missing.push(n.clone()),
                }
            }
        }
        Ok((removed, missing))
    })?;
    for n in &removed {
        println!("removed {n}");
    }
    for n in &missing {
        eprintln!("bsjn: error: no route named {n}");
    }
    Ok(if missing.is_empty() { 0 } else { 1 })
}

#[derive(Serialize)]
struct Row {
    name: String,
    url: String,
    port: u16,
    kind: &'static str,
    tag: Option<String>,
    listening: bool,
}

fn listening(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

pub fn ls(ctx: &Ctx, tag: Option<&str>, json: bool) -> Result<()> {
    let routes = ctx.mutate(|reg| Ok(reg.routes.clone()))?;
    let rows: Vec<Row> = routes
        .into_iter()
        .filter(|r| tag.is_none() || r.tag.as_deref() == tag)
        .map(|r| Row {
            url: ctx.url(&r.name),
            listening: listening(r.port),
            kind: r.kind.as_str(),
            name: r.name,
            port: r.port,
            tag: r.tag,
        })
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("no routes");
        return Ok(());
    }
    print!("{}", table(&rows));
    Ok(())
}

fn table(rows: &[Row]) -> String {
    let cells: Vec<[String; 6]> =
        std::iter::once(["NAME", "URL", "PORT", "KIND", "TAG", "LISTENING"].map(String::from))
            .chain(rows.iter().map(|r| {
                [
                    r.name.clone(),
                    r.url.clone(),
                    r.port.to_string(),
                    r.kind.to_string(),
                    r.tag.clone().unwrap_or_else(|| "-".into()),
                    if r.listening { "yes" } else { "no" }.to_string(),
                ]
            }))
            .collect();
    let widths: Vec<usize> = (0..6)
        .map(|c| cells.iter().map(|row| row[c].len()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in &cells {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

pub fn url(ctx: &Ctx, name: &str) -> Result<()> {
    names::validate_name(name)?;
    println!("{}", ctx.url(name));
    Ok(())
}

/// A free port on 127.0.0.1 that no registered route uses.
pub fn pick_free_port(reg: &Registry) -> Result<u16> {
    for _ in 0..50 {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        if !reg.routes.iter().any(|r| r.port == port) {
            return Ok(port);
        }
    }
    bail!("cannot find a free port")
}

/// A `run` route for this process, or an error when the name is taken.
pub fn claim_run_route(reg: &mut Registry, name: &str, tag: Option<&str>) -> Result<u16> {
    if let Some(r) = reg.get(name) {
        bail!(
            "{name} is already routed to port {} ({}); pick another name or `bsjn rm {name}`",
            r.port,
            r.kind.as_str()
        );
    }
    let pid = std::process::id();
    let port = pick_free_port(reg)?;
    reg.upsert(Route {
        name: name.into(),
        port,
        kind: Kind::Run,
        tag: tag.map(str::to_string),
        pid: Some(pid),
        start_time: proc::start_time(pid),
    });
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, tag: Option<&str>, up: bool) -> Row {
        Row {
            name: name.into(),
            url: format!("https://{name}.d.example.com"),
            port: 5173,
            kind: "persistent",
            tag: tag.map(String::from),
            listening: up,
        }
    }

    #[test]
    fn the_table_aligns_columns() {
        let t = table(&[row("a", None, true), row("longer", Some("x"), false)]);
        let lines: Vec<_> = t.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME    URL"));
        assert!(lines[1].starts_with("a       https://a.d.example.com"));
        assert!(lines[2].ends_with("x    no"));
    }

    #[test]
    fn a_run_route_never_reuses_a_registered_port_or_name() {
        let mut reg = Registry::default();
        let p1 = claim_run_route(&mut reg, "one", Some("t")).unwrap();
        let p2 = claim_run_route(&mut reg, "two", None).unwrap();
        assert_ne!(p1, p2);
        assert_eq!(reg.get("one").unwrap().tag.as_deref(), Some("t"));
        assert!(reg.get("one").unwrap().owned_by(std::process::id()));
        assert!(claim_run_route(&mut reg, "one", None).is_err());
    }
}
