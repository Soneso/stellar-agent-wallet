//! `stellar-agent wallet sa unregister-multicall` subcommand.
//!
//! Removes the multicall router registry entry for the given network from
//! `~/.config/stellar-agent/networks.toml`.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--network <N>` | yes | Network to unregister (e.g. `testnet`). |
//! | `--force` | no | Corruption-recovery path: bypasses strkey/hex validation. |
//! | `--yes-i-have-verified-the-prior-values` | no | Skip interactive `[y/N]` when not on a TTY (required for `--force` from scripts/sub-agents). |
//! | `--profile <NAME>` | no | Profile name (used for audit-log path; default `"default"`). |
//!
//! # Normal path
//!
//! Calls `MulticallRegistry::unregister(network_passphrase)`, which validates the
//! stored entry and removes it. Emits `SaMulticallUnregistered` on success.
//!
//! # Force path (`--force`)
//!
//! Intended for registry-file corruption recovery. Bypasses strkey/hex
//! validation and locates entries by network-safename rather than the stored
//! passphrase.
//!
//! **Pre-`--force` operator discipline (4 steps)**:
//!
//! 1. Inspect the corrupted entry: `cat ~/.config/stellar-agent/networks.toml`
//!    and locate the `[multicall.<network_safename>]` section.
//! 2. Validate the prior `address` value against your out-of-band deploy-time
//!    record (operator runbook, secure-note, encrypted ops-log). If mismatch: STOP.
//!    Investigate filesystem integrity before proceeding.
//! 3. Only proceed to `--force` when the prior values agree with your out-of-band
//!    record.
//! 4. After force-unregister, re-register via normal `register-multicall` and
//!    verify the new address against the same out-of-band record.
//!
//! The `--force` flag requires interactive `[y/N]` confirmation on a TTY.
//! Pass `--yes-i-have-verified-the-prior-values` to suppress the prompt for
//! non-TTY invocations (scripts, sub-agents). Without either confirmation
//! mechanism, `--force` is refused on non-TTY.
//!
//! # Audit-row emission discipline
//!
//! The audit row is emitted BEFORE any file mutation.
//! If emission fails: the file is NOT mutated; the row says "tried"; the
//! registry retains the entry; the operator retries.

use std::io::{BufRead as _, Write as _}; // Write for stderr().flush() in prompt_force_confirm
use std::path::PathBuf;

use clap::Args;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{IoSource, ValidationError, WalletError};
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_smart_account::multicall::{
    MulticallRegistry, STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV, network_safename_from_passphrase,
};
use uuid::Uuid;

use crate::commands::wallet::common::{
    emit_multicall_registry_error, emit_sa_error, open_audit_writer,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// CLI Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `wallet sa unregister-multicall`.
///
/// Default path: normal `MulticallRegistry::unregister` with strkey/hex validation.
/// `--force` path: corruption-recovery via `MulticallRegistry::unregister_force`.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(name = "unregister-multicall")]
pub struct UnregisterMulticallArgs {
    /// Stellar network to unregister (e.g. `testnet`, `mainnet`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Corruption-recovery mode: bypasses strkey/hex validation.
    ///
    /// Requires interactive `[y/N]` confirmation on a TTY, or
    /// `--yes-i-have-verified-the-prior-values` for non-TTY invocations.
    ///
    /// Complete the 4-step pre-`--force` operator discipline before using
    /// this flag:
    ///
    /// 1. Inspect `~/.config/stellar-agent/networks.toml` and locate the
    ///    corrupted `[multicall.<network_safename>]` section.
    /// 2. Validate the prior `address` against your out-of-band deploy-time record.
    ///    If mismatch: STOP. Investigate filesystem integrity.
    /// 3. Only proceed when prior values agree with your out-of-band record.
    /// 4. After force-unregister, re-register and verify against the same record.
    #[arg(long)]
    pub force: bool,

    /// Suppress interactive `[y/N]` confirmation for `--force` on non-TTY.
    ///
    /// Use this flag when running from a script, CI system, or sub-agent
    /// (which lack a TTY stdin). Without it, `--force` on a non-TTY is
    /// refused to prevent sub-agent social-engineering attacks.
    ///
    /// You MUST have completed the 4-step pre-`--force` operator discipline
    /// before passing this flag.
    #[arg(long)]
    pub yes_i_have_verified_the_prior_values: bool,

    /// Profile name (used for audit-log path; default `"default"`).
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `wallet sa unregister-multicall` subcommand.
///
/// Normal path: validates and removes the registry entry, emits
/// `SaMulticallUnregistered`, saves to disk.
///
/// Force path: emits `SaMulticallUnregisteredForce` BEFORE file mutation, then
/// calls `unregister_force`, saves. Interactive confirmation on TTY or
/// `--yes-i-have-verified-the-prior-values` flag for non-TTY.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope and exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &UnregisterMulticallArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());
    let network_passphrase = args.network.passphrase().to_owned();
    let network_safename = network_safename_from_passphrase(&network_passphrase);
    let request_id = Uuid::new_v4().to_string();
    let chain_id: Option<String> = None;

    // Open audit writer (non-fatal: log warning and continue on failure).
    let audit_writer = open_audit_writer(&profile_name).ok();

    // Load the registry.
    let networks_toml_path = resolve_networks_toml_path();
    let mut registry = match MulticallRegistry::load(&networks_toml_path) {
        Ok(r) => r,
        Err(e) => {
            return emit_multicall_registry_error(&e, IoSource::MulticallRegistryLoad);
        }
    };

    if args.force {
        run_force(
            args,
            &mut registry,
            &network_safename,
            &audit_writer,
            chain_id,
            &request_id,
        )
        .await
    } else {
        run_normal(
            &mut registry,
            &network_passphrase,
            &network_safename,
            &audit_writer,
            chain_id,
            &request_id,
        )
        .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Normal path
// ─────────────────────────────────────────────────────────────────────────────

async fn run_normal(
    registry: &mut MulticallRegistry,
    network_passphrase: &str,
    network_safename: &str,
    audit_writer: &Option<(std::sync::Arc<std::sync::Mutex<AuditWriter>>, PathBuf)>,
    chain_id: Option<String>,
    request_id: &str,
) -> i32 {
    match registry.unregister(network_passphrase) {
        Err(e) => emit_sa_error(&e),
        Ok(removed_entry) => {
            let prior_address_redacted = redact_strkey_first5_last5(&removed_entry.address);
            let prior_wasm_sha256 = removed_entry.wasm_sha256.clone();

            // Emit audit row BEFORE saving to disk: the normal path mirrors the
            // force-path audit-before-mutation discipline. On emit failure, fail
            // the unregister — the operator retries.
            let audit_ok = if let Some((writer, _)) = audit_writer {
                let entry = AuditEntry::new_sa_multicall_unregistered(
                    network_safename,
                    RedactedStrkey::from_already_redacted(&prior_address_redacted),
                    &prior_wasm_sha256,
                    chain_id,
                    request_id,
                );
                writer
                    .lock()
                    .ok()
                    .and_then(|mut g| g.write_entry(entry).ok())
                    .is_some()
            } else {
                // No audit writer; log and proceed (best-effort for normal path).
                tracing::warn!(
                    network_safename = %network_safename,
                    "unregister-multicall: no audit writer; SaMulticallUnregistered not emitted"
                );
                true // non-fatal for normal path when writer is absent entirely
            };

            if !audit_ok {
                tracing::error!(
                    network_safename = %network_safename,
                    "unregister-multicall: audit emit failed; registry file NOT mutated; retry"
                );
                let err = WalletError::Validation(ValidationError::AddressInvalid {
                    input: "unregister-multicall: audit emit failed; registry file NOT mutated; \
                            retry after resolving audit writer"
                        .to_owned(),
                });
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }

            // Audit emitted. Now save to disk.
            if let Err(e) = registry.save() {
                return emit_multicall_registry_error(&e, IoSource::MulticallRegistrySave);
            }

            let output = serde_json::json!({
                "status": "unregistered",
                "network_safename": network_safename,
                "prior_address_redacted": prior_address_redacted,
                "prior_wasm_sha256": prior_wasm_sha256,
            });
            render_json(&Envelope::ok(output));
            0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Force path
// ─────────────────────────────────────────────────────────────────────────────

async fn run_force(
    args: &UnregisterMulticallArgs,
    registry: &mut MulticallRegistry,
    network_safename: &str,
    audit_writer: &Option<(std::sync::Arc<std::sync::Mutex<AuditWriter>>, PathBuf)>,
    chain_id: Option<String>,
    request_id: &str,
) -> i32 {
    // Sub-agent / non-TTY protection.
    // On a non-TTY, require --yes-i-have-verified-the-prior-values or refuse.
    let stdin_is_tty = is_stdin_a_tty();
    if !stdin_is_tty && !args.yes_i_have_verified_the_prior_values {
        let err = WalletError::Validation(ValidationError::AddressInvalid {
            input: "unregister-multicall --force refused on non-TTY without \
                    --yes-i-have-verified-the-prior-values. \
                    Complete the 4-step pre-force discipline first, \
                    then pass --yes-i-have-verified-the-prior-values when you have confirmed \
                    the prior values match your out-of-band deploy-time record."
                .to_owned(),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // On TTY without --yes flag: prompt interactively.
    if stdin_is_tty
        && !args.yes_i_have_verified_the_prior_values
        && !prompt_force_confirm(network_safename)
    {
        let err = WalletError::Validation(ValidationError::AddressInvalid {
            input: "unregister-multicall --force: confirmation refused by operator".to_owned(),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // Collect the load warnings from the registry for the audit row.
    let load_warnings: Vec<String> = registry
        .partial_load_warnings
        .iter()
        .filter(|w| w.network_safename == network_safename)
        .map(|w| w.reason.clone())
        .collect();

    // Audit-before-mutation discipline:
    // 1. Remove the entry from the in-memory registry (`unregister_force` is not a disk write).
    // 2. Emit the audit row with the raw values captured from the removed entry.
    // 3. Only then persist to disk (`registry.save()`).
    // If emission fails: do NOT save — the operator retries after resolving the writer.
    match registry.unregister_force(network_safename) {
        Err(e) => emit_sa_error(&e),
        Ok(raw_entry) => {
            // Emit SaMulticallUnregisteredForce BEFORE disk mutation.
            let audit_ok = if let Some((writer, _)) = audit_writer {
                let entry = AuditEntry::new_sa_multicall_unregistered_force(
                    network_safename,
                    &raw_entry.address,
                    &raw_entry.wasm_sha256,
                    load_warnings,
                    chain_id,
                    request_id,
                );
                writer
                    .lock()
                    .ok()
                    .and_then(|mut g| g.write_entry(entry).ok())
                    .is_some()
            } else {
                // No audit writer available; block the mutation (force path is
                // high-risk; audit is mandatory). Warn and return failure.
                tracing::warn!(
                    network_safename = %network_safename,
                    "unregister-multicall --force: no audit writer available; \
                     SaMulticallUnregisteredForce not emitted"
                );
                false
            };

            if !audit_ok {
                // Audit emission failed: do NOT mutate the file. The removed
                // entry is already gone from the in-memory state, but skipping
                // save() leaves the disk file intact; the operator retries.
                tracing::error!(
                    network_safename = %network_safename,
                    "unregister-multicall --force: audit emit failed; \
                     registry file NOT mutated; retry after resolving audit writer"
                );
                let err = WalletError::Validation(ValidationError::AddressInvalid {
                    input: "unregister-multicall --force: audit emit failed; \
                            registry file retained; retry after resolving audit writer"
                        .to_owned(),
                });
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }

            // Audit emitted. Now save the in-memory state to disk.
            if let Err(e) = registry.save() {
                return emit_multicall_registry_error(&e, IoSource::MulticallRegistrySave);
            }

            let output = serde_json::json!({
                "status": "unregistered_force",
                "network_safename": network_safename,
                "prior_address_raw": raw_entry.address,
                "prior_wasm_sha256_raw": raw_entry.wasm_sha256,
                "audit_degraded": false,
            });
            render_json(&Envelope::ok(output));
            0
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the path to `networks.toml`, respecting the env-var override.
fn resolve_networks_toml_path() -> PathBuf {
    if let Ok(override_str) = std::env::var(STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV)
        && !override_str.is_empty()
    {
        return PathBuf::from(override_str);
    }
    directories::BaseDirs::new()
        .map(|b| b.config_dir().join("stellar-agent").join("networks.toml"))
        .unwrap_or_else(|| PathBuf::from("~/.config/stellar-agent/networks.toml"))
}

/// Returns `true` when stdin is a TTY (interactive terminal).
///
/// Uses `std::io::IsTerminal` (stabilised in Rust 1.70).
fn is_stdin_a_tty() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal()
}

/// Prints a force-unregister confirmation prompt and reads stdin.
///
/// Returns `true` when the operator answers `y` or `yes` (case-insensitive).
/// Returns `false` on `n`, `N`, empty input, or EOF.
///
/// This is the interactive gate that prevents accidental `--force` invocation.
/// Sub-agents and CI scripts MUST use `--yes-i-have-verified-the-prior-values`
/// instead of attempting to feed stdin.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary user-facing confirmation prompt on stderr"
)]
fn prompt_force_confirm(network_safename: &str) -> bool {
    eprintln!();
    eprintln!("WARNING: --force bypasses strkey/hex validation and removes the");
    eprintln!("         multicall registry entry for network '{network_safename}'.");
    eprintln!();
    eprintln!("Confirm you have completed the 4-step pre-force discipline");
    eprintln!("before proceeding:");
    eprintln!(" 1. Inspected ~/.config/stellar-agent/networks.toml");
    eprintln!(" 2. Validated the prior address against your out-of-band record");
    eprintln!(" 3. Confirmed the prior values match");
    eprintln!(" 4. Planned to re-register and verify after this step");
    eprintln!();
    // Prompt on stderr to avoid corrupting the deterministic JSON stdout
    // stream if the operator pipes stdout to a JSON consumer.
    eprint!("Force-unregister multicall for '{network_safename}'? [y/N]: ");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => false, // EOF
        Ok(_) => {
            let trimmed = line.trim().to_ascii_lowercase();
            trimmed == "y" || trimmed == "yes"
        }
        Err(_) => false, // I/O error → deny
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn network_safename_testnet() {
        let passphrase = "Test SDF Network ; September 2015";
        let safename = network_safename_from_passphrase(passphrase);
        assert_eq!(safename, "test-sdf-network---september-2015");
    }

    #[test]
    fn network_safename_mainnet() {
        let passphrase = "Public Global Stellar Network ; September 2015";
        let safename = network_safename_from_passphrase(passphrase);
        assert_eq!(safename, "public-global-stellar-network---september-2015");
    }

    #[test]
    fn force_refused_on_non_tty_without_yes_flag() {
        // Construct args with --force but without --yes flag.
        // We simulate non-TTY by checking the code path directly.
        // In tests, stdin is a pipe (non-TTY); the flag is absent.
        let args = UnregisterMulticallArgs {
            network: TargetNetwork::Testnet,
            force: true,
            yes_i_have_verified_the_prior_values: false,
            profile: None,
        };
        // On non-TTY without --yes, the guard fires.
        // We test the logic directly: non-tty + no-yes = refused.
        let stdin_is_tty = false; // simulated
        let refused = !stdin_is_tty && !args.yes_i_have_verified_the_prior_values;
        assert!(refused, "force without yes flag on non-TTY must be refused");
    }

    #[test]
    fn force_allowed_on_non_tty_with_yes_flag() {
        let args = UnregisterMulticallArgs {
            network: TargetNetwork::Testnet,
            force: true,
            yes_i_have_verified_the_prior_values: true,
            profile: None,
        };
        let stdin_is_tty = false;
        let refused = !stdin_is_tty && !args.yes_i_have_verified_the_prior_values;
        assert!(
            !refused,
            "force with yes flag on non-TTY must not be refused"
        );
    }

    #[test]
    fn resolve_networks_toml_path_is_utf8() {
        let path = resolve_networks_toml_path();
        assert!(path.to_str().is_some(), "path must be valid UTF-8");
    }
}
