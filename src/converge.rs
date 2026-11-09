//! Bringing the proxy service in line with the configuration, in the right order.
//!
//! 1. The privileged-port step comes first. A process keeps the capabilities it had when it
//!    was exec'd, so nothing may be pushed to the running proxy before the port is allowed.
//! 2. Files are written (unit, token file, Caddyfile) without touching the running process.
//! 3. Then the service is started, restarted, or hot-applied. Hot apply (Caddy's admin API) is
//!    only right for route changes; anything that changes what the process must be able to do
//!    needs a restart.

use crate::privilege::Outcome;
use crate::service::Changed;
use anyhow::Result;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action {
    Start,
    Restart,
    HotApply,
}

#[derive(Debug, Default)]
pub struct Facts {
    pub active: bool,
    /// Is a TCP socket listening on the configured tailnet IP and port?
    pub listening_as_configured: bool,
    pub unit_changed: bool,
    pub env_changed: bool,
    /// The Caddy binary was replaced by this run.
    pub binary_replaced: bool,
    /// The config (port, bind IP, domain, CA) differs from the saved one.
    pub config_changed: bool,
    /// This run gave Caddy the capability for the port.
    pub capability_added: bool,
}

pub fn decide(f: &Facts) -> Action {
    if !f.active {
        return Action::Start;
    }
    let needs_new_process = f.unit_changed
        || f.env_changed
        || f.binary_replaced
        || f.config_changed
        || f.capability_added
        // A failed earlier setup saved the new config but left the old process: the process is
        // what must change, whatever this run's diff says.
        || !f.listening_as_configured;
    if needs_new_process {
        Action::Restart
    } else {
        Action::HotApply
    }
}

pub trait Steps {
    /// Allow Caddy to bind the configured port (may run sudo).
    fn ensure_port(&mut self) -> Result<Outcome>;
    /// Write unit, token file and Caddyfile; reload systemd; enable. Never touches the
    /// running proxy.
    fn write_files(&mut self) -> Result<Changed>;
    fn is_active(&mut self) -> bool;
    fn listening_as_configured(&mut self) -> bool;
    fn start(&mut self) -> Result<()>;
    fn restart(&mut self) -> Result<()>;
    fn hot_apply(&mut self) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Done {
    /// The port is not allowed yet; the running service was left alone.
    NotDone,
    Did(Action),
}

pub fn converge(
    steps: &mut dyn Steps,
    binary_replaced: bool,
    config_changed: bool,
) -> Result<Done> {
    let capability_added = match steps.ensure_port()? {
        Outcome::Ready { changed } => changed,
        Outcome::NotDone => {
            steps.write_files()?;
            return Ok(Done::NotDone);
        }
    };
    let changed = steps.write_files()?;
    let facts = Facts {
        active: steps.is_active(),
        listening_as_configured: steps.listening_as_configured(),
        unit_changed: changed.unit,
        env_changed: changed.env,
        binary_replaced,
        config_changed,
        capability_added,
    };
    let action = decide(&facts);
    match action {
        Action::Start => steps.start()?,
        Action::Restart => steps.restart()?,
        Action::HotApply => steps.hot_apply()?,
    }
    Ok(Done::Did(action))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        calls: Vec<&'static str>,
        port: Option<Outcome>,
        facts: Facts,
    }

    impl Steps for Fake {
        fn ensure_port(&mut self) -> Result<Outcome> {
            self.calls.push("ensure_port");
            Ok(self.port.take().unwrap())
        }
        fn write_files(&mut self) -> Result<Changed> {
            self.calls.push("write_files");
            Ok(Changed {
                unit: self.facts.unit_changed,
                env: self.facts.env_changed,
            })
        }
        fn is_active(&mut self) -> bool {
            self.facts.active
        }
        fn listening_as_configured(&mut self) -> bool {
            self.facts.listening_as_configured
        }
        fn start(&mut self) -> Result<()> {
            self.calls.push("start");
            Ok(())
        }
        fn restart(&mut self) -> Result<()> {
            self.calls.push("restart");
            Ok(())
        }
        fn hot_apply(&mut self) -> Result<()> {
            self.calls.push("hot_apply");
            Ok(())
        }
    }

    fn running() -> Facts {
        Facts {
            active: true,
            listening_as_configured: true,
            ..Facts::default()
        }
    }

    fn fake(port: Outcome, facts: Facts) -> Fake {
        Fake {
            calls: Vec::new(),
            port: Some(port),
            facts,
        }
    }

    #[test]
    fn the_privileged_step_comes_before_anything_reaches_the_proxy() {
        let mut f = fake(Outcome::Ready { changed: true }, running());
        converge(&mut f, false, true).unwrap();
        assert_eq!(f.calls, ["ensure_port", "write_files", "restart"]);
    }

    #[test]
    fn without_the_port_nothing_is_started_restarted_or_applied() {
        let mut f = fake(Outcome::NotDone, running());
        assert_eq!(converge(&mut f, false, true).unwrap(), Done::NotDone);
        assert_eq!(f.calls, ["ensure_port", "write_files"]);
    }

    #[test]
    fn a_stopped_service_is_started_and_route_only_changes_are_hot_applied() {
        let mut f = fake(Outcome::Ready { changed: false }, Facts::default());
        assert_eq!(
            converge(&mut f, false, false).unwrap(),
            Done::Did(Action::Start)
        );
        let mut f = fake(Outcome::Ready { changed: false }, running());
        assert_eq!(
            converge(&mut f, false, false).unwrap(),
            Done::Did(Action::HotApply)
        );
        assert_eq!(f.calls, ["ensure_port", "write_files", "hot_apply"]);
    }

    #[test]
    fn anything_that_changes_the_process_restarts_it() {
        let base = running;
        let cases = [
            Facts {
                config_changed: true,
                ..base()
            }, // port, bind IP, domain
            Facts {
                capability_added: true,
                ..base()
            },
            Facts {
                binary_replaced: true,
                ..base()
            },
            Facts {
                unit_changed: true,
                ..base()
            },
            Facts {
                env_changed: true,
                ..base()
            },
            // An earlier failed setup saved the new port; the old process is still on the old one.
            Facts {
                listening_as_configured: false,
                ..base()
            },
        ];
        for facts in &cases {
            assert_eq!(decide(facts), Action::Restart, "{facts:?}");
        }
        assert_eq!(decide(&base()), Action::HotApply);
    }
}
