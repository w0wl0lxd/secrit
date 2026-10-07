//! secrit: store secrets in a sops + age file, with no value on the command
//! line. See `docs/PLAN.md` for the design and the threat model.

mod agent;
mod backend;
mod cli;
mod cmd;
mod config;
mod display;
mod error;
mod harden;
mod lock;
mod name;
mod secret;
mod signals;
mod tools;
mod trust;
mod tty;

use std::process::ExitCode;

use clap::CommandFactory;

use crate::cli::{Cli, Command};
use crate::cmd::{Ctx, StoreArgs, parse_name};
use crate::error::Error;

fn main() -> ExitCode {
    // Before any input is read (PLAN 8.5).
    let hardened = harden::harden();
    harden::install_panic_hook();

    let cli = match cli::parse(std::env::args_os()) {
        Ok(cli) => cli,
        Err(outcome) => return ExitCode::from(outcome.exit_code()),
    };
    if !cli.quiet {
        for warning in hardened.warnings() {
            eprintln!("secrit: warning: {warning}");
        }
    }
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secrit: {e}");
            ExitCode::from(e.exit().code())
        }
    }
}

fn dispatch(cli: Cli) -> Result<(), Error> {
    let Cli {
        config,
        store,
        quiet,
        command,
    } = cli;
    // Inside a critical section INT, TERM, HUP and QUIT only set a flag that
    // the wait polls; elsewhere they keep their default action (PLAN 8.1,
    // step 8).
    signals::defer()
        .map_err(|e| Error::Failed(format!("could not install signal handlers: {e}")))?;
    let ctx = || Ctx::load(config.as_deref(), store.as_deref(), quiet);
    match command {
        Command::Store {
            name,
            replace,
            multiline,
            raw,
            extra,
        } => {
            let args = StoreArgs {
                name,
                replace,
                multiline,
                raw,
                extra,
            };
            cmd::store::check_argv(&args)?;
            // The name rules come before the config (PLAN 4.1, step 1).
            let name = parse_name(&args.name)?;
            cmd::store::run(&ctx()?, &name, &args)
        }
        Command::Get { name, stdout } => {
            let name = parse_name(&name)?;
            cmd::get::run(&ctx()?, &name, stdout)
        }
        Command::Ls { json } => cmd::ls::run(&ctx()?, json),
        Command::Rm { name, yes } => {
            let name = parse_name(&name)?;
            cmd::rm::run(&ctx()?, &name, yes)
        }
        Command::Run { .. } => Err(Error::NotImplemented {
            command: "run",
            milestone: "M3",
        }),
        Command::Init { .. } => Err(Error::NotImplemented {
            command: "init",
            milestone: "M4",
        }),
        Command::Doctor { .. } => Err(Error::NotImplemented {
            command: "doctor",
            milestone: "M1",
        }),
        Command::Wire { .. } => Err(Error::NotImplemented {
            command: "wire",
            milestone: "M4",
        }),
        Command::Completions { shell } => {
            clap_complete::generate(
                clap_complete::Shell::from(shell),
                &mut Cli::command(),
                "secrit",
                &mut std::io::stdout(),
            );
            Ok(())
        }
    }
}
