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
//! The success envelope's `data` carries `routed_to` plus a `note` making
//! clear that enforcement passed and routing was resolved, but no tool was
//! run.
//!
//! The toolset gate is ADDITIVE: operator policy + chain gates of the routed
//! tool also apply when wired through the MCP surface.
//!
//! Note: this command performs the enforcement check and resolves the routed
//! tool but does NOT execute it; use the MCP surface for execution.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_runtime::resolve_toolset_and_check;

use crate::common::render::render_json;

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

/// JSON success payload for `toolsets run`'s enforcement-check pass, carried
/// under the envelope `data` field.
///
/// Reaching this payload means enforcement passed and routing was resolved,
/// but the routed tool is NOT executed by this command.
#[derive(Debug, Serialize)]
struct RunResult {
    toolset: String,
    action: String,
    routed_to: String,
    /// Human-readable note explaining that enforcement passed but execution
    /// is not wired in this command — prevents misreading `ok: true` as a
    /// completed tool invocation.
    note: &'static str,
}

/// Runs the `toolsets run <name> <action>` subcommand.
///
/// Performs the four-part capability enforcement check and prints the
/// resolved trusted tool name under `data.routed_to` on success.
///
/// ## Scope
///
/// This command is an enforcement-check + routing-resolution command only.
/// The routed tool is NOT executed. Use the MCP surface
/// (`stellar_toolset_invoke`) for actual tool execution.
///
/// ## Exit codes
///
/// - `0` — enforcement passed (`{ ok: true, data: {...}, request_id }`).
/// - `1` — enforcement failure or I/O error (`{ ok: false, error: { code,
///   message }, request_id }`), `code` one of the `toolset.*` enforcement
///   codes shared with the MCP `stellar_toolset_invoke` tool, or
///   `toolsets.dir_resolve_failed`.
pub async fn run(args: &ToolsetRunArgs) -> i32 {
    let toolsets_root = if let Some(dir) = &args.toolsets_dir {
        dir.clone()
    } else {
        match default_toolsets_dir() {
            Ok(d) => d,
            Err(e) => {
                render_json(&Envelope::<()>::err_raw(
                    "toolsets.dir_resolve_failed",
                    format!("cannot resolve toolsets dir: {e}"),
                ));
                return 1;
            }
        }
    };

    match resolve_toolset_and_check(&args.name, &args.action, &toolsets_root) {
        Ok((tool_name, _pin)) => {
            let result = RunResult {
                toolset: args.name.clone(),
                action: args.action.clone(),
                routed_to: tool_name.to_owned(),
                note: "enforcement passed; CLI execution not wired — use the MCP surface (stellar_toolset_invoke) for actual execution",
            };
            render_json(&Envelope::ok(result));
            0
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
            render_json(&Envelope::<()>::err_raw(code, e.to_string()));
            1
        }
    }
}
