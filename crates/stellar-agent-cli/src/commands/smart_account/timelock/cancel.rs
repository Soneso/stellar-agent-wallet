//! `stellar-agent smart-account timelock cancel` — cancel a pending timelock operation.
//!
//! Submits a `Timelock::cancel` transaction to the OZ timelock contract and
//! cross-confirms the `OperationCancelled` event before returning.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--timelock <C_STRKEY>` | yes | Timelock contract C-strkey. |
//! | `--operation-id <HEX>` | yes | 64-char lowercase hex operation identifier. |
//! | `--rpc-url <URL>` | no | Primary Soroban RPC (default: testnet). |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation. |
//! | `--network {testnet\|mainnet}` | no | Target network (default: `testnet`). |
//! | `--signer-secret-env <VAR>` | no | Env var holding the canceller S-strkey. |
//! | `--profile <NAME>` | no | Profile name. |
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "operation_id_redacted": "abcdef12...34567890",
//!   "timelock_contract_redacted": "CTLCK...ABCDE",
//!   "request_id": "…"
//! }
//! ```
//!
//! Provides event-emission integrity: the cancellation is cross-confirmed
//! against the emitted on-chain event before the command returns success.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::timelock::TimelockOperationId;
use tracing::info;
use url::Url;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    SignerSourceFlags, emit_sa_error, open_profile_audit_writer, resolve_signer,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::record_mlock_degradation;

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Arguments for `smart-account timelock cancel`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent smart-account timelock cancel \
        --timelock <C_STRKEY> --operation-id <HEX> \
        [--rpc-url <URL>] [--network {testnet|mainnet}] \
        [--signer-secret-env <VAR> | --sign-with-ledger]",
    after_help = "Cancels a pending timelock operation. The signer must hold \
                  CANCELLER_ROLE on the timelock contract. \
                  Emits SaTimelockCancelled audit row on success."
)]
pub struct CancelArgs {
    /// Timelock contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub timelock: String,

    /// 64-char lowercase hex operation identifier.
    ///
    /// Returned by `timelock schedule` as `operation_id_full_hex`.
    #[arg(long, value_name = "HEX", required = true)]
    pub operation_id: String,

    /// Primary Soroban RPC endpoint (default: testnet).
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC for cross-RPC event confirmation (dual-RPC defence).
    ///
    /// When omitted, defaults to `--rpc-url` and both RPCs are the same endpoint.
    /// A warning is emitted in that case because the cross-RPC divergence defence
    /// is degraded: a single compromised RPC can satisfy both confirmation checks.
    /// Provide an independent RPC endpoint for production use.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Target network: `testnet` (default) or `mainnet`.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Profile name for audit-log lookup.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer source flags (canceller key).
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,
}

/// JSON envelope for a successful `cancel` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CancelResult {
    /// Redacted operation identifier (first-8-last-8 hex).
    pub operation_id_redacted: String,
    /// Redacted timelock contract address.
    pub timelock_contract_redacted: String,
    /// Per-request correlation identifier.
    pub request_id: String,
}

/// Decodes a 64-char hex string to a `[u8; 32]` array.
///
/// Delegates to [`stellar_agent_core::hex::decode_hex32`].
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    stellar_agent_core::hex::decode_hex32(s).ok()
}

/// Returns the structural mainnet-write-forbidden error if `network` is mainnet,
/// or `None` if the network is testnet.
///
/// Extracted so tests can assert the exact `wire_code` without going through
/// stdout. The read-only `list_pending` verb is exempt from this guard.
pub(crate) fn mainnet_forbidden_error(network: TargetNetwork) -> Option<WalletError> {
    if network == TargetNetwork::Mainnet {
        Some(WalletError::Network(NetworkError::MainnetWriteForbidden))
    } else {
        None
    }
}

/// Runs `smart-account timelock cancel`.
///
/// Returns exit code `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &CancelArgs) -> i32 {
    // Structural mainnet pre-reject: refuse before loading any signer key.
    // The downstream submit_transaction_and_wait passphrase check also
    // blocks mainnet writes, but rejecting here avoids key access for a
    // doomed submission and makes the refusal explicit at the CLI layer.
    if let Some(err) = mainnet_forbidden_error(args.network) {
        let envelope: Envelope<()> = Envelope::err(&err);
        render_json(&envelope);
        return 1;
    }

    let profile_name = resolve_profile_name(args.profile.as_deref());
    let request_id = Uuid::new_v4().to_string();

    // Decode operation_id before hitting the network.
    let op_bytes = match decode_hex32(&args.operation_id) {
        Some(b) => b,
        None => {
            let wallet_err = WalletError::Validation(
                stellar_agent_core::error::ValidationError::AddressInvalid {
                    input: format!(
                        "--operation-id must be a 64-char lowercase hex string; got '{}' ({} chars)",
                        args.operation_id,
                        args.operation_id.len()
                    ),
                },
            );
            let envelope: Envelope<()> = Envelope::err(&wallet_err);
            render_json(&envelope);
            return 1;
        }
    };
    let operation_id = TimelockOperationId::from_bytes(op_bytes);

    let (signer, mlock_degradation) =
        match resolve_signer(&args.signer_source, Some(&profile_name)).await {
            Ok(pair) => pair,
            Err(e) => {
                let envelope: Envelope<()> = Envelope::err(&e);
                render_json(&envelope);
                return 1;
            }
        };

    let (_audit_profile, audit_writer, _audit_log_path) =
        match open_profile_audit_writer(&profile_name) {
            Ok(triple) => triple,
            Err(e) => {
                let envelope: Envelope<()> = Envelope::err(&e);
                render_json(&envelope);
                return 1;
            }
        };
    record_mlock_degradation(
        &audit_writer,
        mlock_degradation.as_ref(),
        &profile_name,
        &request_id,
    );

    let secondary_rpc_url = args
        .secondary_rpc_url
        .clone()
        .unwrap_or_else(|| args.rpc_url.clone());

    // Warn when secondary == primary: the dual-RPC divergence defence is
    // degraded. A single compromised RPC can satisfy both confirmation checks.
    // Provide --secondary-rpc-url pointing to an independent endpoint.
    // Log host-only at INFO; full URL at DEBUG.
    let rpc_host = Url::parse(&args.rpc_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());

    if secondary_rpc_url == args.rpc_url {
        info!(
            request_id = %request_id,
            rpc_host = %rpc_host,
            "smart-account timelock cancel: --secondary-rpc-url not set or equals \
             --rpc-url; cross-RPC divergence defence is degraded — \
             provide an independent secondary RPC endpoint for production use"
        );
    }
    tracing::debug!(rpc_url = %args.rpc_url, "cancel rpc_url (full, debug-only)");

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);

    info!(
        timelock = %timelock_redacted,
        operation_id = %operation_id.redacted(),
        network = %args.network,
        request_id = %request_id,
        "smart-account timelock cancel: submitting"
    );

    match stellar_agent_smart_account::timelock::cancel(
        stellar_agent_smart_account::timelock::TimelockCancelArgs::builder()
            .timelock_contract_strkey(&args.timelock)
            .operation_id(&operation_id)
            .signer(signer.as_ref())
            .primary_rpc_url(&args.rpc_url)
            .secondary_rpc_url(&secondary_rpc_url)
            .network_passphrase(args.network.passphrase())
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            .build(),
    )
    .await
    {
        Ok(()) => {}
        // Route through emit_sa_error to apply redact_path_in_message before emission.
        Err(e) => return emit_sa_error(&e),
    }

    info!(
        operation_id = %operation_id.redacted(),
        request_id = %request_id,
        "smart-account timelock cancel: confirmed on-chain"
    );

    let result = CancelResult {
        operation_id_redacted: operation_id.redacted(),
        timelock_contract_redacted: timelock_redacted,
        request_id,
    };
    let envelope = Envelope::ok(result);
    render_json(&envelope);
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only: panics are correct failure mode")]

    use super::*;

    // ── Mainnet structural pre-reject ──────────────────────────────────────────

    /// Mainnet pre-reject emits `network.mainnet_write_forbidden` before any
    /// signer key access.
    ///
    /// Tests the guard function directly so we can assert the exact wire code
    /// rather than just `exit_code == 1`.
    #[test]
    fn cancel_mainnet_guard_emits_correct_wire_code() {
        use crate::common::network::TargetNetwork;
        let err = mainnet_forbidden_error(TargetNetwork::Mainnet)
            .expect("mainnet must yield Some(WalletError)");
        assert_eq!(
            err.code(),
            "network.mainnet_write_forbidden",
            "mainnet pre-reject must emit network.mainnet_write_forbidden; got: {}",
            err.code()
        );
        assert!(
            mainnet_forbidden_error(TargetNetwork::Testnet).is_none(),
            "testnet must not trigger the mainnet guard"
        );
    }

    /// `run()` with `network = Mainnet` must return exit code 1.
    #[tokio::test]
    async fn cancel_rejects_mainnet_before_signer_access() {
        use crate::common::network::TargetNetwork;
        let args = CancelArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            operation_id: "a".repeat(64),
            rpc_url: "https://soroban-testnet.stellar.org".to_owned(),
            secondary_rpc_url: None,
            network: TargetNetwork::Mainnet,
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: None,
                sign_with_ledger: false,
                account_index: None,
            },
        };
        let exit_code = run(&args).await;
        assert_eq!(
            exit_code, 1,
            "mainnet cancel must return exit code 1 (structural pre-reject)"
        );
    }

    #[test]
    fn decode_hex32_accepts_valid_hex() {
        let hex = "a".repeat(64);
        let bytes = decode_hex32(&hex).expect("valid 64-char hex must decode");
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn decode_hex32_rejects_short_hex() {
        assert!(decode_hex32("aabb").is_none(), "short hex must return None");
    }

    #[test]
    fn decode_hex32_rejects_odd_length() {
        let odd = "a".repeat(63);
        assert!(
            decode_hex32(&odd).is_none(),
            "odd-length hex must return None"
        );
    }

    #[test]
    fn cancel_result_json_round_trip() {
        let result = CancelResult {
            operation_id_redacted: "abcdef12...34567890".to_owned(),
            timelock_contract_redacted: "CTLCK...ABCDE".to_owned(),
            request_id: "req-id-001".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CancelResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_id_redacted, "abcdef12...34567890");
        assert_eq!(back.request_id, "req-id-001");
    }
}
