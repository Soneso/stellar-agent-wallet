//! `stellar-agent smart-account timelock schedule` — schedule a timelock operation.
//!
//! Builds and submits a `Timelock::schedule` transaction to the OZ timelock contract,
//! then cross-confirms the emitted `OperationScheduled` event before returning.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--timelock <C_STRKEY>` | yes | Timelock contract C-strkey. |
//! | `--target <C_STRKEY>` | yes | Target contract C-strkey for the scheduled call. |
//! | `--function <NAME>` | yes | Function name on the target contract. |
//! | `--delay-ledgers <N>` | yes | Minimum delay in ledgers before execution. |
//! | `--rpc-url <URL>` | no | Primary Soroban RPC (default: testnet). |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation. |
//! | `--network {testnet\|mainnet}` | no | Target network (default: `testnet`). |
//! | `--signer-secret-env <VAR>` | no | Env var holding the proposer S-strkey. |
//! | `--profile <NAME>` | no | Profile name. |
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "operation_id": "abcdef12...34567890",
//!   "operation_id_full_hex": "abcdef1234567890…",
//!   "salt": "1122334455667788…aabbccddeeff0011",
//!   "delay_ledgers": 1440,
//!   "timelock_contract_redacted": "CTLCK...ABCDE",
//!   "target_redacted": "CTARG...12345",
//!   "function": "upgrade",
//!   "request_id": "…"
//! }
//! ```
//!
//! Enforces proposer authorisation, derives a non-deterministic operation salt,
//! and cross-confirms the emitted on-chain event before returning success.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
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

/// Arguments for `smart-account timelock schedule`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent smart-account timelock schedule \
        --timelock <C_STRKEY> --target <C_STRKEY> --function <NAME> \
        --delay-ledgers <N> [--rpc-url <URL>] [--network {testnet|mainnet}] \
        [--signer-secret-env <VAR> | --sign-with-ledger]",
    after_help = "Schedules a timelock operation. The proposer signer must hold the \
                  PROPOSER_ROLE on the timelock contract. \
                  The operation salt is derived non-deterministically \
                  (sha256(request_id || timestamp_nanos)) and is returned in the \
                  JSON output as `salt`. Record it — it is required by the matching \
                  `execute` and `cancel` calls and cannot be recomputed later."
)]
pub struct ScheduleArgs {
    /// Timelock contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub timelock: String,

    /// Target contract C-strkey for the scheduled operation.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub target: String,

    /// Function name on the target contract to call on execute.
    #[arg(long, value_name = "NAME", required = true)]
    pub function: String,

    /// Minimum delay in ledgers before the operation can be executed.
    ///
    /// OZ timelock minimum delay is configured at contract deployment time.
    /// This value must be >= the contract's `min_delay`.
    #[arg(long, value_name = "N", required = true)]
    pub delay_ledgers: u32,

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

    /// Signer source flags (proposer key).
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,
}

/// JSON envelope for a successful `schedule` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScheduleResult {
    /// Redacted operation identifier (first-8-last-8 hex).
    pub operation_id: String,
    /// Full 64-char lowercase hex operation identifier.
    ///
    /// Required for the corresponding `cancel` or `execute` calls.
    pub operation_id_full_hex: String,
    /// 64-char lowercase hex salt required by the matching `execute` or `cancel`.
    ///
    /// The salt is derived non-deterministically at schedule time and is not
    /// stored on-chain — record it now, as it cannot be recomputed later.
    pub salt: String,
    /// Minimum ledger delay before the operation can be executed.
    pub delay_ledgers: u32,
    /// Redacted timelock contract address.
    pub timelock_contract_redacted: String,
    /// Redacted target contract address.
    pub target_redacted: String,
    /// Function name on the target contract.
    pub function: String,
    /// Per-request correlation identifier.
    pub request_id: String,
}

/// Returns the structural mainnet-write-forbidden error if `network` is mainnet,
/// or `None` if the network is testnet.
///
/// Extracted so tests can assert the exact `wire_code` without going through
/// stdout. The production path in [`run`] calls this helper and writes the error
/// to stdout; the test path calls it directly. Separating the guard from the I/O
/// lets the test assert `error.code() == "network.mainnet_write_forbidden"`.
///
/// The read-only `list_pending` verb is exempt from this guard.
pub(crate) fn mainnet_forbidden_error(network: TargetNetwork) -> Option<WalletError> {
    if network == TargetNetwork::Mainnet {
        Some(WalletError::Network(NetworkError::MainnetWriteForbidden))
    } else {
        None
    }
}

/// Runs `smart-account timelock schedule`.
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
pub async fn run(args: &ScheduleArgs) -> i32 {
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

    // Log host-only at INFO; full URL at DEBUG.
    // Self-hosted RPC at an internal hostname is non-public infrastructure.
    let rpc_host = Url::parse(&args.rpc_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());

    // Warn when secondary == primary: the dual-RPC divergence defence is
    // degraded. A single compromised RPC can satisfy both confirmation checks.
    // Provide --secondary-rpc-url pointing to an independent endpoint.
    if secondary_rpc_url == args.rpc_url {
        info!(
            request_id = %request_id,
            rpc_host = %rpc_host,
            "smart-account timelock schedule: --secondary-rpc-url not set or equals \
             --rpc-url; cross-RPC divergence defence is degraded — \
             provide an independent secondary RPC endpoint for production use"
        );
    }
    tracing::debug!(rpc_url = %args.rpc_url, "schedule rpc_url (full, debug-only)");

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);
    let target_redacted = redact_strkey_first5_last5(&args.target);

    info!(
        timelock = %timelock_redacted,
        target = %target_redacted,
        function = %args.function,
        delay_ledgers = args.delay_ledgers,
        network = %args.network,
        request_id = %request_id,
        "smart-account timelock schedule: submitting"
    );

    let outcome = match stellar_agent_smart_account::timelock::schedule_upgrade(
        stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
            .timelock_contract_strkey(&args.timelock)
            .target_strkey(&args.target)
            .function(&args.function)
            // No target-function args at CLI level; advanced users extend via JSON.
            .delay_ledgers(args.delay_ledgers)
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
        Ok(o) => o,
        // Route through emit_sa_error to apply redact_path_in_message before
        // JSON emission (path-leak guard).
        Err(e) => return emit_sa_error(&e),
    };

    info!(
        operation_id = %outcome.operation_id.redacted(),
        request_id = %request_id,
        "smart-account timelock schedule: confirmed on-chain"
    );

    let salt_hex: String = outcome.salt.iter().map(|b| format!("{b:02x}")).collect();

    let result = ScheduleResult {
        operation_id: outcome.operation_id.redacted(),
        operation_id_full_hex: outcome.operation_id.to_hex(),
        salt: salt_hex,
        delay_ledgers: args.delay_ledgers,
        timelock_contract_redacted: timelock_redacted,
        target_redacted,
        function: args.function.clone(),
        request_id,
    };
    let envelope = Envelope::ok(result);
    render_json(&envelope);
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(
        clippy::expect_used,
        reason = "test-only: expects are correct failure mode"
    )]
    #![allow(clippy::panic, reason = "test-only: panics are correct failure mode")]

    use super::*;

    // ── Mainnet structural pre-reject ──────────────────────────────────────────

    /// Mainnet pre-reject emits `network.mainnet_write_forbidden` before any
    /// signer key access.
    ///
    /// Tests the guard function directly so we can assert the exact wire code
    /// rather than just `exit_code == 1`. Exit code 1 is also asserted via the
    /// async `run()` test below; the two together prove ordering (guard fires
    /// FIRST, before signer resolution) and correct code emission.
    #[test]
    fn schedule_mainnet_guard_emits_correct_wire_code() {
        use crate::common::network::TargetNetwork;
        let err = mainnet_forbidden_error(TargetNetwork::Mainnet)
            .expect("mainnet must yield Some(WalletError)");
        assert_eq!(
            err.code(),
            "network.mainnet_write_forbidden",
            "mainnet pre-reject must emit network.mainnet_write_forbidden; \
             got: {}",
            err.code()
        );
        // Verify testnet does NOT trigger the guard.
        assert!(
            mainnet_forbidden_error(TargetNetwork::Testnet).is_none(),
            "testnet must not trigger the mainnet guard"
        );
    }

    /// `run()` with `network = Mainnet` must return exit code 1.
    ///
    /// Combined with `schedule_mainnet_guard_emits_correct_wire_code`, this
    /// proves the guard fires before signer resolution (no signer flags set).
    #[tokio::test]
    async fn schedule_rejects_mainnet_before_signer_access() {
        use crate::common::network::TargetNetwork;
        let args = ScheduleArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            target: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            function: "upgrade".to_owned(),
            delay_ledgers: 1_440,
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
            "mainnet schedule must return exit code 1 (structural pre-reject)"
        );
    }

    #[test]
    fn schedule_result_json_round_trip() {
        let result = ScheduleResult {
            operation_id: "abcdef12...34567890".to_owned(),
            operation_id_full_hex: "a".repeat(64),
            salt: "b".repeat(64),
            delay_ledgers: 1_440,
            timelock_contract_redacted: "CTLCK...ABCDE".to_owned(),
            target_redacted: "CTARG...12345".to_owned(),
            function: "upgrade".to_owned(),
            request_id: "req-id-000".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"delay_ledgers\":1440"));
        assert!(json.contains("\"function\":\"upgrade\""));
        assert!(json.contains("\"salt\":\"bbbbbbbb"));
        let back: ScheduleResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.delay_ledgers, 1_440);
        assert_eq!(back.function, "upgrade");
        assert_eq!(
            back.salt.len(),
            64,
            "salt must round-trip as 64-char hex string"
        );
    }
}
