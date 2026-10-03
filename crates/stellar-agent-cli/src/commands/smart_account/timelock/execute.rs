//! `stellar-agent smart-account timelock execute` — execute a ready timelock operation.
//!
//! Submits a `Timelock::execute` transaction to the OZ timelock contract.
//! Performs a pre-flight cross-RPC `get_operation_state` check (guards against
//! the ready-window race) before submitting, then cross-confirms the
//! `OperationExecuted` event.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--timelock <C_STRKEY>` | yes | Timelock contract C-strkey. |
//! | `--target <C_STRKEY>` | yes | Target contract C-strkey (must match scheduled). |
//! | `--function <NAME>` | yes | Function name (must match scheduled). |
//! | `--operation-id <HEX>` | yes | 64-char hex operation identifier. |
//! | `--salt <HEX>` | yes | 64-char hex salt used when scheduling. |
//! | `--rpc-url <URL>` | no | Primary Soroban RPC; the profile endpoint when absent; refused on mainnet. |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation; the profile value when absent; refused on mainnet. |
//! | `--network {testnet\|mainnet}` | no | Must equal the profile's chain when given. |
//! | `--signer-secret-env <VAR>` | no | Env var holding the executor S-strkey. |
//! | `--profile <NAME>` | no | Profile name. |
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "operation_id_redacted": "abcdef12...34567890",
//!   "tx_hash_redacted": "aabb1122...ccdd3344",
//!   "timelock_contract_redacted": "CTLCK...ABCDE",
//!   "request_id": "…"
//! }
//! ```
//!
//! # Ready-window race
//!
//! `execute()` validates the operation is `Ready` via dual-RPC
//! `get_operation_state` BEFORE submitting. Fail-CLOSED if not `Ready`.
//! This avoids wasted network round-trips and operator timing-pattern leakage.
//!
//! The execution is also cross-confirmed against the emitted on-chain event
//! before the command returns success.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::caip2::Caip2;
use tracing::info;
use url::Url;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    SignerSourceFlags, emit_sa_error, load_command_profile, map_access_error, open_audit_writer,
    resolve_signer,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, network_context_for_command,
};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::record_mlock_degradation;

/// Arguments for `smart-account timelock execute`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent smart-account timelock execute \
        --timelock <C_STRKEY> --target <C_STRKEY> --function <NAME> \
        --operation-id <HEX> --salt <HEX> \
        [--rpc-url <URL>] [--network {testnet|mainnet}] \
        [--signer-secret-env <VAR> | --sign-with-ledger]",
    after_help = "Executes a ready timelock operation. The signer must hold \
                  EXECUTOR_ROLE (or open-execution mode must be enabled). \
                  The --target, --function, --operation-id, and --salt must \
                  exactly match the scheduled operation — OZ derives the \
                  operation_id from these fields. Pre-flight dual-RPC state \
                  check prevents submission against a not-yet-ready operation."
)]
pub struct ExecuteArgs {
    /// Timelock contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub timelock: String,

    /// Target contract C-strkey (must match the value used in `schedule`).
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub target: String,

    /// Function name (must match the value used in `schedule`).
    #[arg(long, value_name = "NAME", required = true)]
    pub function: String,

    /// 64-char lowercase hex operation identifier.
    ///
    /// Returned by `timelock schedule` as `operation_id_full_hex`.
    #[arg(long, value_name = "HEX", required = true)]
    pub operation_id: String,

    /// 64-char lowercase hex salt used when the operation was scheduled.
    ///
    /// Required by OZ `Timelock::execute` to reconstruct the operation_id
    /// for on-chain validation.
    #[arg(long, value_name = "HEX", required = true)]
    pub salt: String,

    /// The RPC endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub rpc_url: Option<String>,

    /// The secondary endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub secondary_rpc_url: Option<String>,

    /// The network comes from the profile when absent.
    /// When supplied, this flag must equal the profile's chain.
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<TargetNetwork>,

    /// Profile name for audit-log lookup.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer source flags (executor key).
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,
}

/// JSON envelope for a successful `execute` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecuteResult {
    /// Redacted operation identifier (first-8-last-8 hex).
    pub operation_id_redacted: String,
    /// Redacted transaction hash (first-8-last-8 hex).
    pub tx_hash_redacted: String,
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
pub(crate) fn mainnet_forbidden_error(network: Caip2) -> Option<WalletError> {
    if network.is_mainnet() {
        Some(WalletError::Network(NetworkError::MainnetWriteForbidden))
    } else {
        None
    }
}

/// Runs `smart-account timelock execute`.
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
pub async fn run(args: &ExecuteArgs) -> i32 {
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let (profile, origin) = match load_command_profile(&resolved_profile) {
        Ok(loaded) => loaded,
        Err(error) => {
            let e = map_access_error(&error, &resolved_profile.name);
            let envelope: Envelope<()> = Envelope::err(&e);
            render_json(&envelope);
            return 1;
        }
    };
    let context = match network_context_for_command(
        &profile,
        &resolved_profile.name,
        EndpointFlags {
            network: args.network,
            rpc_url: args.rpc_url.as_deref(),
            secondary_rpc_url: args.secondary_rpc_url.as_deref(),
        },
    ) {
        Ok(context) => context,
        Err(e) => {
            let envelope: Envelope<()> = Envelope::err(&e);
            render_json(&envelope);
            return 1;
        }
    };
    // Structural mainnet pre-reject: refuse before loading any signer key.
    // The downstream submit_transaction_and_wait passphrase check also
    // blocks mainnet writes, but rejecting here avoids key access for a
    // doomed submission and makes the refusal explicit at the CLI layer.
    if let Some(err) = mainnet_forbidden_error(context.chain_id) {
        let envelope: Envelope<()> = Envelope::err(&err);
        render_json(&envelope);
        return 1;
    }

    let profile_name = resolved_profile.name.clone();
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

    // Decode salt before hitting the network.
    let salt_bytes = match decode_hex32(&args.salt) {
        Some(b) => b,
        None => {
            let wallet_err = WalletError::Validation(
                stellar_agent_core::error::ValidationError::AddressInvalid {
                    input: format!(
                        "--salt must be a 64-char lowercase hex string; got '{}' ({} chars)",
                        args.salt,
                        args.salt.len()
                    ),
                },
            );
            let envelope: Envelope<()> = Envelope::err(&wallet_err);
            render_json(&envelope);
            return 1;
        }
    };

    let (audit_writer, _audit_log_path) =
        match open_audit_writer(&profile, origin, &resolved_profile.name) {
            Ok(opened) => opened,
            Err(e) => {
                let envelope: Envelope<()> = Envelope::err(&e);
                render_json(&envelope);
                return 1;
            }
        };

    let (signer, mlock_degradation) = match resolve_signer(
        &args.signer_source,
        &profile,
        &resolved_profile.name,
        "smart-account-write",
    )
    .await
    {
        Ok(pair) => pair,
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

    let secondary_rpc_url = context
        .secondary_rpc_url
        .clone()
        .unwrap_or_else(|| context.rpc_url.clone());

    // Warn when secondary == primary: the dual-RPC divergence defence is
    // degraded. A single compromised RPC can satisfy both confirmation checks.
    // Provide --secondary-rpc-url pointing to an independent endpoint.
    // Log host-only at INFO; full URL at DEBUG.
    let rpc_host = Url::parse(&context.rpc_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());

    if secondary_rpc_url == context.rpc_url {
        info!(
            request_id = %request_id,
            rpc_host = %rpc_host,
            "smart-account timelock execute: --secondary-rpc-url not set or equals \
             --rpc-url; cross-RPC divergence defence is degraded — \
             provide an independent secondary RPC endpoint for production use"
        );
    }
    tracing::debug!(
        rpc_url = %stellar_agent_core::redact::redact_url_authority(&context.rpc_url),
        "execute rpc_url"
    );

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);

    info!(
        timelock = %timelock_redacted,
        operation_id = %&args.operation_id[..8],
        function = %args.function,
        network = %context.chain_id,
        request_id = %request_id,
        "smart-account timelock execute: submitting"
    );

    // Build the caller-supplied operation_id for the pre-check and validation.
    let user_supplied_op_id =
        stellar_agent_smart_account::timelock::TimelockOperationId::from_bytes(op_bytes);

    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(now) => now,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "wallet.clock_error",
                e.to_string(),
            ));
            return 1;
        }
    };
    // Settle open reservations before this operation records or signs a submission.
    if let Ok(reconcile_client) = stellar_agent_network::StellarRpcClient::new(&context.rpc_url) {
        crate::commands::submission_record::reconcile_open_reservations(
            &profile,
            &profile_name,
            &reconcile_client,
            now_ms,
        )
        .await;
    }
    let chain_id = profile.chain_id.caip2_str();
    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile: &profile,
            profile_name: profile_name.clone(),
            verb: "timelock execute",
            tool: "stellar_smart_account_timelock_execute",
            chain_id,
            effects: None,
            audit: Some(std::sync::Arc::clone(&audit_writer)),
            now_ms,
        },
    ) {
        Ok(recorder) => recorder,
        Err(e) => {
            render_json(&crate::commands::submission_record::error_envelope(
                &e,
                "",
                "timelock execute",
            ));
            return 1;
        }
    };

    let tx_hash = match stellar_agent_smart_account::timelock::execute(
        stellar_agent_smart_account::timelock::TimelockExecuteArgs::builder()
            .timelock_contract_strkey(&args.timelock)
            .target_strkey(&args.target)
            .function(&args.function)
            // No target-function args at CLI level.
            .salt(salt_bytes)
            .signer(signer.as_ref())
            .primary_rpc_url(&context.rpc_url)
            .secondary_rpc_url(&secondary_rpc_url)
            .network_passphrase(context.network_passphrase())
            .audit_writer(&audit_writer)
            .request_id(&request_id)
            .expected_operation_id(&user_supplied_op_id)
            .submission_recorder(&recorder)
            .build(),
    )
    .await
    {
        Ok(h) => h,
        // Route through emit_sa_error to apply redact_path_in_message before emission.
        Err(e) => return emit_sa_error(&e),
    };

    // Redact tx hash (first-8-last-8).
    let tx_hash_redacted = if tx_hash.len() >= 16 {
        format!("{}...{}", &tx_hash[..8], &tx_hash[tx_hash.len() - 8..])
    } else {
        tx_hash.clone()
    };

    let operation_id_redacted = {
        let hex = stellar_agent_core::hex::encode(&op_bytes);
        format!("{}...{}", &hex[..8], &hex[hex.len() - 8..])
    };

    info!(
        operation_id = %operation_id_redacted,
        tx_hash = %tx_hash_redacted,
        request_id = %request_id,
        "smart-account timelock execute: confirmed on-chain"
    );

    let result = ExecuteResult {
        operation_id_redacted,
        tx_hash_redacted,
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
    /// Tests the guard function directly to assert the exact wire code rather
    /// than just `exit_code == 1`.
    #[test]
    fn execute_mainnet_guard_emits_correct_wire_code() {
        use crate::common::network::TargetNetwork;
        let err = mainnet_forbidden_error(TargetNetwork::Mainnet.caip2())
            .expect("mainnet must yield Some(WalletError)");
        assert_eq!(
            err.code(),
            "network.mainnet_write_forbidden",
            "mainnet pre-reject must emit network.mainnet_write_forbidden; got: {}",
            err.code()
        );
        assert!(
            mainnet_forbidden_error(TargetNetwork::Testnet.caip2()).is_none(),
            "testnet must not trigger the mainnet guard"
        );
    }

    /// A mainnet profile exits 1 before any request reaches its endpoint.
    /// The binary tests in `tests/profile_env_var_resolution.rs` pin the
    /// refusal's wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn execute_mainnet_profile_reaches_no_endpoint() {
        let guard_rpc =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &guard_rpc.https_uri(),
            );
        use crate::common::network::TargetNetwork;
        let args = ExecuteArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            target: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            function: "upgrade".to_owned(),
            operation_id: "b".repeat(64),
            salt: "c".repeat(64),
            rpc_url: None,
            secondary_rpc_url: None,
            network: Some(TargetNetwork::Mainnet),
            profile: Some("guard-mainnet".into()),
            signer_source: SignerSourceFlags {
                signer_secret_env: None,
                sign_with_ledger: false,
                account_index: None,
            },
        };
        let exit_code = run(&args).await;
        assert_eq!(exit_code, 1, "a mainnet execute must exit 1");
        assert_eq!(
            guard_rpc.accepted().expect("connection count"),
            0,
            "no connection may reach the profile's endpoint"
        );
    }

    /// `--network mainnet` with no profile exits 1 before any request reaches
    /// the endpoint `--rpc-url` names. The binary tests pin the wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn execute_mainnet_flag_without_profile_reaches_no_endpoint() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        use crate::common::network::TargetNetwork;
        let args = ExecuteArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            target: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            function: "upgrade".to_owned(),
            operation_id: "b".repeat(64),
            salt: "c".repeat(64),
            rpc_url: Some(guard_rpc.uri()),
            secondary_rpc_url: None,
            network: Some(TargetNetwork::Mainnet),
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: None,
                sign_with_ledger: false,
                account_index: None,
            },
        };
        let exit_code = run(&args).await;
        assert_eq!(exit_code, 1, "a mainnet execute must exit 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    #[test]
    fn decode_hex32_accepts_valid() {
        let s = "b".repeat(64);
        let bytes = decode_hex32(&s).expect("valid 64-char hex");
        assert_eq!(bytes, [0xbb; 32]);
    }

    #[test]
    fn decode_hex32_rejects_65_chars() {
        let s = "a".repeat(65);
        assert!(decode_hex32(&s).is_none());
    }

    #[test]
    fn execute_result_json_round_trip() {
        let result = ExecuteResult {
            operation_id_redacted: "abcdef12...34567890".to_owned(),
            tx_hash_redacted: "aabb1122...ccdd3344".to_owned(),
            timelock_contract_redacted: "CTLCK...ABCDE".to_owned(),
            request_id: "req-id-002".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ExecuteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tx_hash_redacted, "aabb1122...ccdd3344");
        assert_eq!(back.request_id, "req-id-002");
    }
}
