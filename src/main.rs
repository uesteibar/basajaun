use anyhow::Result;
use bsjn::UsageError;
use bsjn::cli::{Cli, Command};
use bsjn::routes::{self, Ctx, RmArgs};
use bsjn::{doctor, privilege, run, setup};
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    match dispatch(Cli::parse().command) {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(e) => {
            eprintln!("bsjn: error: {e:#}");
            if e.downcast_ref::<UsageError>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn dispatch(command: Command) -> Result<i32> {
    match command {
        Command::Setup(args) => setup::run(&args),
        Command::Doctor { json } => doctor::run(json),
        Command::PortAccess { yes, sysctl } => privilege::run(yes, sysctl),
        Command::Add {
            name,
            port,
            tag,
            force,
        } => {
            routes::add(&Ctx::load()?, &name, port, tag.as_deref(), force)?;
            Ok(0)
        }
        Command::Run { name, tag, cmd } => run::run(&Ctx::load()?, &name, tag.as_deref(), &cmd),
        Command::Ls { tag, json } => {
            routes::ls(&Ctx::load()?, tag.as_deref(), json)?;
            Ok(0)
        }
        Command::Rm(args) => routes::rm(
            &Ctx::load()?,
            &RmArgs {
                names: args.names,
                tag: args.tag,
                all: args.all,
            },
        ),
        Command::Url { name } => {
            routes::url(&Ctx::load()?, &name)?;
            Ok(0)
        }
    }
}
