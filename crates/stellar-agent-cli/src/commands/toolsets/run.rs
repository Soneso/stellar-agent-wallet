//! `toolsets run <name> <action>` subcommand.
//!
//! Runs the four-part capability enforcement check for an installed toolset action
//! and reports the resolved trusted tool name.
//!
//! ## Scope
//!
//! This command performs the full enforcement check but does NOT execute the
//! routed tool.  Full execution requires wiring the WalletServer / profile / MCP
//! context into the CLI binary.
//!
//! The output reports `status: "resolved"` (not `"ok"` / `"executed"`) to
//! make clear that enforcement passed and routing was resolved, but no tool was run.
//!
//! The toolset gate is ADDITIVE: operator policy + chain gates of the routed
//! tool also apply when wired through the MCP surface.
//!
//! Note: this command performs the enforcement check and resolves the routed
//! tool but does NOT execute it; use the MCP surface for execution.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_runtime::resolve_toolset_and_check;
use tracing::error;

/// Arguments for `toolsets run`.
#[derive(Debug, Args)]
pub struct ToolsetRunArgs {
    /// Package name of the installed toolset to invoke.
    ///
    /// Example: `balance-reporter`
    #[arg(value_name = "TOOLSET-NAME")]
    pub name: String,

    /// Action to invoke — must be an exact registry tool name that the toolset's
    /// declared capabilities grant.
    ///
    /// Example: `stellar_balances`
    #[arg(value_name = "ACTION")]
    pub action: String,

    /// Override the toolsets root directory (default: OS-conventional toolsets dir).
    #[arg(long, value_name = "PATH")]
    pub toolsets_dir: Option<std::path::PathBuf>,
}

/// JSON output for `toolsets run` enforcement-check pass.
///
/// Reports `status: "resolved"` — enforcement passed and routing was resolved,
/// but the routed tool is NOT executed by this command.
#[derive(Debug, Serialize)]
struct RunResult {
    /// Always `"resolved"` (enforcement passed; tool not executed).
    ///
    /// Use the MCP surface (`stellar_toolset_invoke`) for actual execution.
    status: &'static str,
    toolset: String,
    action: String,
    routed_to: String,
    /// Human-readable note explaining that enforcement passed but execution
    /// is not wired in this command — prevents misreading `status` as a
    /// successful run.
    note: &'static str,
}

/// JSON error output for `toolsets run`.
#[derive(Debug, Serialize)]
struct RunError {
    status: &'static str,
    error: String,
    code: String,
}

/// Runs the `toolsets run <name> <action>` subcommand.
///
/// Performs the four-part capability enforcement check and prints the
/// resolved trusted tool name with `status: "resolved"` on success.
///
/// ## Scope
///
/// This command is an enforcement-check + routing-resolution command only.
/// The routed tool is NOT executed.  Use the MCP surface
/// (`stellar_toolset_invoke`) for actual tool execution.
///
/// ## Exit codes
///
/// - `0` — enforcement passed; `status: "resolved"` in JSON output.
/// - `1` — enforcement failure or I/O error; `status: "error"` in JSON output.
pub async fn run(args: &ToolsetRunArgs) -> i32 {
    let toolsets_root = if let Some(dir) = &args.toolsets_dir {
        dir.clone()
    } else {
        match default_toolsets_dir() {
            Ok(d) => d,
            Err(e) => {
                print_error(
                    "toolsets_dir_error",
                    &format!("cannot resolve toolsets dir: {e}"),
                );
                return 1;
            }
        }
    };

    match resolve_toolset_and_check(&args.name, &args.action, &toolsets_root) {
        Ok((tool_name, _pin)) => {
            let result = RunResult {
                // "resolved": enforcement passed; tool NOT executed by this command.
                status: "resolved",
                toolset: args.name.clone(),
                action: args.action.clone(),
                routed_to: tool_name.to_owned(),
                note: "enforcement passed; CLI execution not wired — use the MCP surface (stellar_toolset_invoke) for actual execution",
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
                    error!(error = %e, "failed to serialise run result");
                    1
                }
            }
        }
        Err(e) => {
            use stellar_agent_toolsets_runtime::ToolsetRuntimeError;
            let code = match &e {
                ToolsetRuntimeError::ToolsetNotInstalled { .. } => "toolset.not_installed",
                ToolsetRuntimeError::UnknownToolsetAction { .. } => "toolset.unknown_action",
                ToolsetRuntimeError::CapabilityNotDeclared { .. } => {
                    "toolset.capability_not_declared"
                }
                ToolsetRuntimeError::ToolNotAllowed { .. } => "toolset.tool_not_allowed",
                ToolsetRuntimeError::Io(_) => "toolset.io_error",
                _ => "toolset.error",
            };
            print_error(code, &e.to_string());
            1
        }
    }
}

fn print_error(code: &str, message: &str) {
    let err_output = RunError {
        status: "error",
        error: message.to_owned(),
        code: code.to_owned(),
    };
    match serde_json::to_string_pretty(&err_output) {
        Ok(json) => {
            #[allow(clippy::print_stdout)]
            {
                println!("{json}");
            }
        }
        Err(e) => {
            error!(error = %e, "failed to serialise run error");
        }
    }
}
