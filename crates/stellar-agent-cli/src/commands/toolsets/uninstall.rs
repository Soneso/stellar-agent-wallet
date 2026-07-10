//! `toolsets uninstall` subcommand.
//!
//! Uninstalls a previously-installed toolset by name.

use std::path::PathBuf;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::schema::default_toolsets_dir;
use stellar_agent_toolsets_install::uninstall_toolset;

use crate::common::render::render_json;

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

/// JSON success payload for `toolsets uninstall`, carried under the envelope
/// `data` field.
#[derive(Debug, Serialize)]
struct UninstallSuccess {
    package: String,
}

/// Runs the `toolsets uninstall` subcommand.
///
/// # Exit codes
///
/// - `0` on success (`{ ok: true, data: { package }, request_id }`).
/// - `1` on any error (`{ ok: false, error: { code, message }, request_id }`).
pub async fn run(args: &ToolsetUninstallArgs) -> i32 {
    match run_inner(args) {
        Ok(result) => {
            render_json(&Envelope::ok(result));
            0
        }
        Err((code, message)) => {
            render_json(&Envelope::<()>::err_raw(code, message));
            1
        }
    }
}

fn run_inner(args: &ToolsetUninstallArgs) -> Result<UninstallSuccess, (&'static str, String)> {
    let toolsets_root = match &args.toolsets_dir {
        Some(p) => p.clone(),
        None => {
            default_toolsets_dir().map_err(|e| ("toolsets.dir_resolve_failed", e.to_string()))?
        }
    };

    uninstall_toolset(&args.package, &toolsets_root)
        .map_err(|e| ("toolsets.uninstall_failed", e.to_string()))?;

    Ok(UninstallSuccess {
        package: args.package.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use tempfile::TempDir;

    use super::*;

    /// Uninstalling a package that was never installed is a business refusal
    /// carrying the dotted `toolsets.uninstall_failed` code (never a bare
    /// string or a `{status:"error"}` shape).
    #[test]
    fn uninstall_missing_package_returns_typed_error_code() {
        let tmp = TempDir::new().unwrap();
        let args = ToolsetUninstallArgs {
            package: "never-installed".to_owned(),
            toolsets_dir: Some(tmp.path().to_path_buf()),
        };

        let (code, _message) =
            run_inner(&args).expect_err("uninstalling an absent package must fail");
        assert_eq!(code, "toolsets.uninstall_failed");
    }
}
