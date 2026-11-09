//! `bsjn run`: a temporary route for the lifetime of a foreground command.

use crate::names;
use crate::routes::{self, Ctx};
use crate::usage;
use anyhow::{Context, Result};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// First termination signal received (0: none).
static RECEIVED: AtomicI32 = AtomicI32::new(0);
/// A signal that still has to be passed on to the child (0: none).
static FORWARD: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // Ctrl+C from the terminal reaches the child through the foreground process group already;
    // forwarding it again would deliver it twice. A SIGINT sent by `kill` reaches only us.
    // SAFETY: the kernel passes a valid siginfo_t when SA_SIGINFO is set.
    let from_terminal = sig == libc::SIGINT && unsafe { (*info).si_code } == libc::SI_KERNEL;
    let _ = RECEIVED.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
    if !from_terminal {
        FORWARD.store(sig, Ordering::SeqCst);
    }
}

fn install_handlers() {
    // SAFETY: the handler only touches atomics. No SA_RESTART, so a blocked call wakes up.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_signal as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

pub fn run(ctx: &Ctx, name: &str, tag: Option<&str>, cmd: &[String]) -> Result<i32> {
    names::validate_name(name)?;
    if let Some(t) = tag {
        names::validate_tag(t)?;
    }
    let Some((program, args)) = cmd.split_first() else {
        return Err(usage("give a command to run after `--`"));
    };
    install_handlers();
    let pid = std::process::id();

    let port = match ctx.mutate(|reg| routes::claim_run_route(reg, name, tag)) {
        Ok(port) => port,
        Err(e) => {
            // The route may be saved even though the proxy rejected it: do not leave it behind.
            release(ctx, name, pid);
            return Err(e);
        }
    };
    let url = ctx.url(name);
    eprintln!("bsjn: {url} -> 127.0.0.1:{port}");

    let result = if RECEIVED.load(Ordering::SeqCst) != 0 {
        Ok(128 + RECEIVED.load(Ordering::SeqCst))
    } else {
        run_child(program, args, name, port, &url)
    };
    release(ctx, name, pid);
    result
}

/// Remove the route of this run, unless it was replaced by something else meanwhile.
fn release(ctx: &Ctx, name: &str, pid: u32) {
    let result = ctx.mutate(|reg| {
        if reg.get(name).is_some_and(|r| r.owned_by(pid)) {
            reg.remove(name);
        }
        Ok(())
    });
    if let Err(e) = result {
        eprintln!("bsjn: warning: cannot remove the route {name}: {e:#}");
    }
}

fn run_child(program: &str, args: &[String], name: &str, port: u16, url: &str) -> Result<i32> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env("PORT", port.to_string())
        .env("BSJN_URL", url)
        .env("BSJN_NAME", name);
    // SAFETY: only async-signal-safe calls between fork and exec. If bsjn is killed outright
    // (SIGKILL), the child gets SIGTERM instead of running on without its route.
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot run `{program}`"))?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(exit_code(status));
        }
        let sig = FORWARD.swap(0, Ordering::SeqCst);
        if sig != 0 {
            // SAFETY: plain kill(2) on our own child.
            unsafe { libc::kill(child.id() as libc::pid_t, sig) };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
