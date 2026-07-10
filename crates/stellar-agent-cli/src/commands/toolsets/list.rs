//! `toolset list` subcommand.
//!
//! Canonical scriptable enumeration of installed toolsets and their declared
//! actions.  Emits JSON (not parsed from `--help`).

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_runtime::{ToolsetListEntry, list_pinned_toolsets};

use crate::common::render::render_json;

/// Arguments for `toolset list`.
#[derive(Debug, Args)]
pub struct ToolsetListArgs {
    /// Override the toolsets root directory (default: OS-conventional toolsets dir).
    #[arg(long, value_name = "PATH")]
    pub toolsets_dir: Option<std::path::PathBuf>,
}

/// JSON success payload for `toolset list`, carried under the envelope `data` field.
#[derive(Debug, Serialize)]
struct ListSuccess {
    /// Installed toolsets.
    toolsets: Vec<ToolsetListEntry>,
}

/// Runs the `toolset list` subcommand.
///
/// # Exit codes
///
/// - `0` on success (prints the standard `{ ok: true, data: {...}, request_id }`
///   envelope to stdout, `data.toolsets` carrying the installed-toolset entries).
/// - `1` on any error (prints `{ ok: false, error: { code, message }, request_id }`).
pub async fn run(args: &ToolsetListArgs) -> i32 {
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

    match list_pinned_toolsets(&toolsets_root) {
        Ok(toolsets) => {
            render_json(&Envelope::ok(ListSuccess { toolsets }));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "toolsets.list_failed",
                e.to_string(),
            ));
            1
        }
    }
}
