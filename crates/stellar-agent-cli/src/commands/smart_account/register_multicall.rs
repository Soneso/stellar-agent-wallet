//! `stellar-agent smart-account register-multicall` subcommand.
//!
//! Registers a deployed multicall router contract address in the local
//! registry (`<canonical_data_root>/networks.toml`).
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--network <N>` | yes | Network to register for. |
//! | `--address <C_STRKEY>` | yes | Deployed multicall router C-strkey. |
//! | `--wasm-sha256 <HEX>` | yes | 64-char hex SHA-256 of the router WASM. |
//!
//! # Binary-const trust-anchor check
//!
//! The CLI handler refuses `--wasm-sha256 <HEX>` if `<HEX> != MULTICALL_WASM_SHA256`
//! with a typed error before calling `MulticallRegistry::register`. This is a
//! defence-in-depth layer: even a filesystem-attacker who plants a config file with
//! a different SHA cannot induce registration of an untrusted router through the
//! normal `register-multicall` path.
//!
//! # Audit emission
//!
//! - `SaMulticallRegistered` — on success.
//! - `SaMulticallRegistrationRefused` — on CLI-level SHA mismatch or registry-level
//!   drift refusal.
//!
//! # Idempotency
//!
//! `MulticallRegistry::register` is idempotent: re-registering the same address
//! with the same SHA is a no-op (returns `Ok(())`).

use clap::Args;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{IoSource, ValidationError, WalletError};
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_smart_account::multicall::{
    MULTICALL_WASM_SHA256, MulticallRegistry, MulticallRegistryEntry,
    network_safename_from_passphrase,
};
use stellar_agent_smart_account::verifiers::default_networks_toml_path;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    emit_multicall_registry_error, emit_sa_error, open_profile_audit_writer,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// CLI Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account register-multicall`.
///
/// Registers the given multicall router contract address in the local registry.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(name = "register-multicall")]
pub struct RegisterMulticallArgs {
    /// Stellar network to register for (e.g. `testnet`, `mainnet`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Deployed multicall router contract C-strkey (56-char, starts with `C`).
    #[arg(long, value_name = "C_STRKEY")]
    pub address: String,

    /// SHA-256 of the vendored multicall WASM as 64-char lowercase hex.
    ///
    /// MUST equal the `MULTICALL_WASM_SHA256` binary constant compiled into
    /// this wallet binary. Any other value is refused at the CLI layer as a
    /// typo-defence and filesystem-attacker config-plant defence.
    #[arg(long, value_name = "HEX", value_parser = parse_wasm_sha256)]
    pub wasm_sha256: String,

    /// Profile name (used for audit-log path; default `"default"`).
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `smart-account register-multicall` subcommand.
///
/// Validates the `--wasm-sha256` against the binary const, then calls
/// `MulticallRegistry::register` and saves to disk. Emits a
/// `SaMulticallRegistered` or `SaMulticallRegistrationRefused` audit row.
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
pub async fn run(args: &RegisterMulticallArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());
    let network_passphrase = args.network.passphrase().to_owned();
    let address_redacted = redact_strkey_first5_last5(&args.address);
    let network_safename = network_safename_from_passphrase(&network_passphrase);
    let request_id = Uuid::new_v4().to_string();

    // Open audit writer (non-fatal: log warning and continue on failure).
    let audit_writer = open_profile_audit_writer(&profile_name)
        .map(|(_, w, p)| (w, p))
        .ok();

    // CLI-level binary-const check: refuse if --wasm-sha256 != MULTICALL_WASM_SHA256.
    if args.wasm_sha256 != MULTICALL_WASM_SHA256 {
        // Emit SaMulticallRegistrationRefused before returning.
        if let Some((writer, _)) = &audit_writer {
            let refused = AuditEntry::new_sa_multicall_registration_refused(
                &network_safename,
                RedactedStrkey::from_already_redacted(&address_redacted),
                &args.wasm_sha256,
                None,
                "cli_sha256_check_failed",
                None::<String>,
                &request_id,
            );
            if let Ok(mut g) = writer.lock() {
                let _ = g.write_entry(refused);
            }
        }
        let err = WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--wasm-sha256 does not match the MULTICALL_WASM_SHA256 binary constant \
                 ({}). This wallet binary expects SHA-256 = {}. \
                 Verify your wallet binary version is up-to-date with the deployed router.",
                &MULTICALL_WASM_SHA256[..8],
                MULTICALL_WASM_SHA256
            ),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // Load the registry.
    let networks_toml_path = match default_networks_toml_path() {
        Ok(p) => p,
        Err(e) => return emit_multicall_registry_error(&e, IoSource::MulticallRegistryLoad),
    };
    let mut registry = match MulticallRegistry::load(&networks_toml_path) {
        Ok(r) => r,
        Err(e) => {
            return emit_multicall_registry_error(&e, IoSource::MulticallRegistryLoad);
        }
    };

    let entry = MulticallRegistryEntry {
        network_passphrase: network_passphrase.clone(),
        address: args.address.clone(),
        wasm_sha256: args.wasm_sha256.clone(),
    };

    // Call MulticallRegistry::register (validates sha256 again + drift guard).
    if let Err(e) = registry.register(entry) {
        // Emit SaMulticallRegistrationRefused audit row on register failure.
        if let Some((writer, _)) = &audit_writer {
            let refused = AuditEntry::new_sa_multicall_registration_refused(
                &network_safename,
                RedactedStrkey::from_already_redacted(&address_redacted),
                &args.wasm_sha256,
                None,
                "registry_register_failed",
                None::<String>,
                &request_id,
            );
            if let Ok(mut g) = writer.lock() {
                let _ = g.write_entry(refused);
            }
        }
        return emit_sa_error(&e);
    }

    // Emit SaMulticallRegistered BEFORE saving to disk (audit-before-mutation
    // discipline). On emit failure, return early without saving.
    let audit_ok = if let Some((writer, _)) = &audit_writer {
        let success_entry = AuditEntry::new_sa_multicall_registered(
            &network_safename,
            RedactedStrkey::from_already_redacted(&address_redacted),
            &args.wasm_sha256,
            None::<String>,
            &request_id,
        );
        writer
            .lock()
            .ok()
            .and_then(|mut g| g.write_entry(success_entry).ok())
            .is_some()
    } else {
        // No audit writer; log and proceed (best-effort — registration path is
        // lower-risk than force-unregister; no audit writer on first run is expected).
        tracing::warn!(
            network_safename = %network_safename,
            "register-multicall: no audit writer; SaMulticallRegistered not emitted"
        );
        true
    };

    if !audit_ok {
        // Audit emission failed: return failure without saving to disk.
        tracing::error!(
            network_safename = %network_safename,
            "register-multicall: audit emit failed; registry file NOT written; \
             retry after resolving audit writer"
        );
        let err = WalletError::Validation(ValidationError::AddressInvalid {
            input: "register-multicall: audit emit failed; registry file NOT written; \
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
        "status": "registered",
        "network_safename": network_safename,
        "address_redacted": address_redacted,
        "wasm_sha256": args.wasm_sha256,
    });
    render_json(&Envelope::ok(output));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn parse_wasm_sha256(input: &str) -> Result<String, String> {
    if input.len() != 64 {
        return Err(format!(
            "--wasm-sha256 must be exactly 64 hex characters; got {}",
            input.len()
        ));
    }
    for (i, c) in input.char_indices() {
        if !c.is_ascii_hexdigit() {
            return Err(format!(
                "--wasm-sha256 must be 64 ASCII hex characters; got non-hex character at offset {i}"
            ));
        }
        if c.is_ascii_uppercase() {
            return Err(format!(
                "--wasm-sha256 must be 64 lowercase hex characters; got uppercase character at offset {i}"
            ));
        }
    }
    Ok(input.to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;
    use stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256;

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
    fn wasm_sha256_const_length() {
        // MULTICALL_WASM_SHA256 must be exactly 64 lowercase hex characters.
        assert_eq!(
            MULTICALL_WASM_SHA256.len(),
            64,
            "MULTICALL_WASM_SHA256 must be 64 hex chars"
        );
        assert!(
            MULTICALL_WASM_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
            "MULTICALL_WASM_SHA256 must be lowercase hex"
        );
    }

    #[test]
    fn parse_wasm_sha256_accepts_lowercase_hex() {
        let parsed =
            parse_wasm_sha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        assert_eq!(
            parsed,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn parse_wasm_sha256_rejects_uppercase_hex() {
        let err =
            parse_wasm_sha256("ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
                .unwrap_err();
        assert!(
            err.contains("uppercase character at offset 0"),
            "error should identify uppercase by offset without echoing input: {err}"
        );
        assert!(!err.contains("ABCDEF"));
    }

    #[test]
    fn parse_wasm_sha256_rejects_non_hex() {
        let err =
            parse_wasm_sha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg")
                .unwrap_err();
        assert_eq!(
            err,
            "--wasm-sha256 must be 64 ASCII hex characters; got non-hex character at offset 63"
        );
    }

    #[test]
    fn parse_wasm_sha256_rejects_wrong_length() {
        let err = parse_wasm_sha256("abcdef").unwrap_err();
        assert!(
            err.contains("64 hex characters"),
            "error should describe length without echoing input: {err}"
        );
        assert!(!err.contains("abcdef"));
    }
}
