//! `toolset list` subcommand.
//!
//! Canonical scriptable enumeration of installed toolsets and their declared
//! actions.  Emits JSON (not parsed from `--help`).

use clap::Args;
use serde::Serialize;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_runtime::{ToolsetListEntry, list_pinned_toolsets};
use tracing::error;

/// Arguments for `toolset list`.
#[derive(Debug, Args)]
pub struct ToolsetListArgs {
    /// Override the toolsets root directory (default: OS-conventional toolsets dir).
    #[arg(long, value_name = "PATH")]
    pub toolsets_dir: Option<std::path::PathBuf>,
}

/// JSON output for `toolset list`.
#[derive(Debug, Serialize)]
struct ListResult {
    /// Always `"ok"` on success.
    status: &'static str,
    /// Installed toolsets.
    toolsets: Vec<ToolsetListEntry>,
}

/// JSON error output.
#[derive(Debug, Serialize)]
struct ListError {
    status: &'static str,
    error: String,
}

/// Runs the `toolset list` subcommand.
///
/// # Exit codes
///
/// - `0` on success (prints JSON array of installed-toolset entries to stdout).
/// - `1` on any error.
pub async fn run(args: &ToolsetListArgs) -> i32 {
    let toolsets_root = if let Some(dir) = &args.toolsets_dir {
        dir.clone()
    } else {
        match default_toolsets_dir() {
            Ok(d) => d,
            Err(e) => {
                let err_output = ListError {
                    status: "error",
                    error: format!("cannot resolve toolsets dir: {e}"),
                };
                match serde_json::to_string_pretty(&err_output) {
                    Ok(json) => {
                        #[allow(clippy::print_stdout)]
                        {
                            println!("{json}");
                        }
                    }
                    Err(e2) => {
                        error!(error = %e2, "failed to serialise list error");
                    }
                }
                return 1;
            }
        }
    };

    match list_pinned_toolsets(&toolsets_root) {
        Ok(toolsets) => {
            let result = ListResult {
                status: "ok",
                toolsets,
            };
            match serde_json::to_string_pretty(&result) {
                Ok(json) => {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{json}");
                    }
                    0
                }
                Err(e) => {
                    error!(error = %e, "failed to serialise list result");
                    1
                }
            }
        }
        Err(e) => {
            let err_output = ListError {
                status: "error",
                error: e.to_string(),
            };
            match serde_json::to_string_pretty(&err_output) {
                Ok(json) => {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{json}");
                    }
                }
                Err(e2) => {
                    error!(error = %e2, "failed to serialise list error");
                }
            }
            1
        }
    }
}
