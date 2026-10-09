//! secrit: store secrets in a sops + age file, with no value on the command
//! line. See `docs/PLAN.md` for the design and the threat model.

mod agent;
mod backend;
mod child;
mod cli;
mod cmd;
mod config;
mod display;
mod error;
mod git;
mod harden;
mod lock;
mod name;
mod paths;
mod report;
mod secret;
mod signals;
mod testhook;
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
    match dispatch(cli, hardened) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secrit: {e}");
            ExitCode::from(e.exit().code())
        }
    }
}

fn dispatch(cli: Cli, hardened: harden::HardenReport) -> Result<(), Error> {
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
        Command::Init {
            sops_file,
            sops_config,
            age_key,
            write_sops_config,
            dry_run,
        } => cmd::init::run(
            config.as_deref(),
            store.as_deref(),
            quiet,
            &cmd::init::InitArgs {
                sops_file,
                sops_config,
                age_key,
                write_sops_config,
                dry_run,
            },
        ),
        Command::Doctor { json } => {
            cmd::doctor::run(config.as_deref(), store.as_deref(), json, quiet, hardened)
        }
        Command::Wire {
            name,
            owner,
            format,
        } => {
            let name = parse_name(&name)?;
            cmd::wire::run(&ctx()?, &name, owner.as_deref(), format)
        }
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
