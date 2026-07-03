//! `toolsets uninstall` subcommand.
//!
//! Uninstalls a previously-installed toolset by name.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_install::uninstall_toolset;
use tracing::error;

/// Arguments for `toolsets uninstall`.
#[derive(Debug, Args)]
pub struct ToolsetUninstallArgs {
    /// Package name to uninstall (`[a-z0-9-]`).
    #[arg(value_name = "PACKAGE")]
    pub package: String,

    /// Override the toolsets root directory (default: OS-conventional toolsets dir).
    #[arg(long, value_name = "PATH")]
    pub toolsets_dir: Option<PathBuf>,
}

/// JSON output for `toolsets uninstall`.
#[derive(Debug, Serialize)]
struct UninstallResult {
    status: &'static str,
    package: String,
}

/// JSON error output.
#[derive(Debug, Serialize)]
struct UninstallError {
    status: &'static str,
    error: String,
}

/// Runs the `toolsets uninstall` subcommand.
///
/// # Exit codes
///
/// - `0` on success.
/// - `1` on any error.
pub async fn run(args: &ToolsetUninstallArgs) -> i32 {
    match run_inner(args) {
        Ok(result) => match serde_json::to_string_pretty(&result) {
            Ok(json) => {
                #[allow(clippy::print_stdout)]
                {
                    println!("{json}");
                }
                0
            }
            Err(e) => {
                error!(error = %e, "failed to serialise uninstall result");
                1
            }
        },
        Err(e) => {
            let err_output = UninstallError {
                status: "error",
                error: e.to_string(),
            };
            match serde_json::to_string_pretty(&err_output) {
                Ok(json) => {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("{json}");
                    }
                }
                Err(_) => {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("error: {e}");
                    }
                }
            }
            1
        }
    }
}

fn run_inner(args: &ToolsetUninstallArgs) -> Result<UninstallResult, Box<dyn std::error::Error>> {
    let toolsets_root = match &args.toolsets_dir {
        Some(p) => p.clone(),
        None => default_toolsets_dir().map_err(|_| "cannot resolve toolsets directory")?,
    };

    uninstall_toolset(&args.package, &toolsets_root)?;

    Ok(UninstallResult {
        status: "ok",
        package: args.package.clone(),
    })
}
