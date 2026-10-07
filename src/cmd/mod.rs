//! Subcommand handlers. Status goes to stderr, data to stdout (PLAN 8.4).

pub mod get;
pub mod ls;
pub mod rm;
pub mod store;

use std::ffi::OsString;

use crate::backend::Backend;
use crate::backend::sops::SopsBackend;
use crate::config::{BackendKind, Config, StoreConfig, config_path, home};
use crate::error::Error;
use crate::name::Name;
use crate::tools::{self, ResolvedTool, ToolSource};

/// What every store-backed command needs.
pub struct Ctx {
    pub quiet: bool,
    pub store: StoreConfig,
    pub backend: Box<dyn Backend>,
}

impl Ctx {
    /// Load the config, pick the store, and build its backend.
    pub fn load(
        config_flag: Option<&std::path::Path>,
        store_flag: Option<&str>,
        quiet: bool,
    ) -> Result<Self, Error> {
        let env = |k: &str| std::env::var_os(k);
        let path = config_path(config_flag, &env)?;
        let config = Config::load(&path, &home(&env)?)?;
        let store = config.store(store_flag)?.clone();
        let backend: Box<dyn Backend> = match store.backend {
            BackendKind::Sops => {
                let sops = tools::resolve(
                    tools::SOPS,
                    &config.tools.sops,
                    std::env::var_os("PATH").as_deref(),
                )?;
                warn_on_path_fallback(&sops, quiet);
                Box::new(SopsBackend::new(
                    &store,
                    sops.path,
                    config.lock_timeout,
                    &env,
                )?)
            }
        };
        Ok(Self {
            quiet,
            store,
            backend,
        })
    }

    pub fn status(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("store", &self.store.name)
            .finish_non_exhaustive()
    }
}

fn warn_on_path_fallback(tool: &ResolvedTool, quiet: bool) {
    if tool.source == ToolSource::Path && !quiet {
        eprintln!(
            "secrit: warning: using {} from PATH; set tools.sops to an absolute path, or install secrit with Nix to pin it",
            tool.path.display()
        );
    }
}

pub fn parse_name(s: &str) -> Result<Name, Error> {
    Ok(Name::parse(s)?)
}

/// The arguments to `store`, after clap.
#[derive(Debug)]
pub struct StoreArgs {
    pub name: String,
    pub replace: bool,
    pub multiline: bool,
    pub raw: bool,
    pub extra: Vec<OsString>,
}
