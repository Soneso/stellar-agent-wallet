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
//! | `--rpc-url <URL>` | no | Primary Soroban RPC; the profile endpoint when absent; refused on mainnet. |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation; the profile value when absent; refused on mainnet. |
//! | `--network {testnet\|mainnet}` | no | Must equal the profile's chain when given. |
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
use stellar_agent_core::observability::redact_strkey_first5_last5;
use tracing::info;
use url::Url;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    SignerSourceFlags, emit_sa_error, load_command_profile, map_access_error, open_audit_writer,
    resolve_signer,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, mainnet_write_refusal,
    network_context_for_command,
};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::record_mlock_degradation;

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
    if let Some(err) = mainnet_write_refusal(context.chain_id) {
        let envelope: Envelope<()> = Envelope::err(&err);
        render_json(&envelope);
        return 1;
    }

    let profile_name = resolved_profile.name.clone();
    let request_id = Uuid::new_v4().to_string();

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

    // Log host-only at INFO; full URL at DEBUG.
    // Self-hosted RPC at an internal hostname is non-public infrastructure.
    let rpc_host = Url::parse(&context.rpc_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "<unparseable>".to_owned());

    // Warn when secondary == primary: the dual-RPC divergence defence is
    // degraded. A single compromised RPC can satisfy both confirmation checks.
    // Provide --secondary-rpc-url pointing to an independent endpoint.
    if secondary_rpc_url == context.rpc_url {
        info!(
            request_id = %request_id,
            rpc_host = %rpc_host,
            "smart-account timelock schedule: --secondary-rpc-url not set or equals \
             --rpc-url; cross-RPC divergence defence is degraded — \
             provide an independent secondary RPC endpoint for production use"
        );
    }
    tracing::debug!(
        rpc_url = %stellar_agent_core::redact::redact_url_authority(&context.rpc_url),
        "schedule rpc_url"
    );

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);
    let target_redacted = redact_strkey_first5_last5(&args.target);

    info!(
        timelock = %timelock_redacted,
        target = %target_redacted,
        function = %args.function,
        delay_ledgers = args.delay_ledgers,
        network = %context.chain_id,
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
            .primary_rpc_url(&context.rpc_url)
            .secondary_rpc_url(&secondary_rpc_url)
            .network_passphrase(context.network_passphrase())
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

    /// A mainnet profile exits 1 before any request reaches its endpoint.
    /// The binary tests in `tests/profile_env_var_resolution.rs` pin the
    /// refusal's wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn schedule_mainnet_profile_reaches_no_endpoint() {
        let guard_rpc =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &guard_rpc.https_uri(),
            );
        use crate::common::network::TargetNetwork;
        let args = ScheduleArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            target: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            function: "upgrade".to_owned(),
            delay_ledgers: 1_440,
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
        assert_eq!(exit_code, 1, "a mainnet schedule must exit 1");
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
    async fn schedule_mainnet_flag_without_profile_reaches_no_endpoint() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        use crate::common::network::TargetNetwork;
        let args = ScheduleArgs {
            timelock: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            target: "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK".to_owned(),
            function: "upgrade".to_owned(),
            delay_ledgers: 1_440,
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
        assert_eq!(exit_code, 1, "a mainnet schedule must exit 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
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
