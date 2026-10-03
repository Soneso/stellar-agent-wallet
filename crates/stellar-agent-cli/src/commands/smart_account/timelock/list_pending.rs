//! `stellar-agent smart-account timelock list-pending` — enumerate pending timelock operations.
//!
//! Reads the local audit log for `SaTimelockScheduled` rows that have no
//! corresponding `SaTimelockCancelled` or `SaTimelockExecuted` row, then
//! cross-confirms each candidate's state via dual-RPC `get_operation_state`
//! query.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--timelock <C_STRKEY>` | yes | Timelock contract C-strkey. |
//! | `--rpc-url <URL>` | no | Primary Soroban RPC; the profile endpoint when absent; refused on mainnet. |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation; the profile value when absent; refused on mainnet. |
//! | `--network {testnet\|mainnet}` | no | Must equal the profile's chain when given. |
//! | `--profile <NAME>` | no | Profile name for audit-log lookup. |
//!
//! # JSON envelope
//!
//! ```json
//! {
//!   "operations": [
//!     {
//!       "operation_id": "abcdef12...34567890",
//!       "state": "waiting",
//!       "ready_ledger": 5000000,
//!       "current_ledger": 4900000,
//!       "scheduled_at_request_id": "…"
//!     }
//!   ],
//!   "pending_count": 1,
//!   "timelock_contract_redacted": "CTLCK...ABCDE"
//! }
//! ```
//!
//! # Read-only behaviour
//!
//! No signer required. Issues only `simulate_transaction` RPC calls.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader::ProfileLoadError;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_smart_account::timelock::{PendingTimelockOperation, TimelockOperationStateView};
use tracing::info;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    emit_sa_error, map_access_error, open_audit_writer_read_only,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, network_context_for_command,
};
use crate::common::profile_access::{
    injected_profile_load, load_profile_or_synthesize_testnet_with,
};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for `smart-account timelock list-pending`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent smart-account timelock list-pending \
        --timelock <C_STRKEY> [--rpc-url <URL>] [--network {testnet|mainnet}]",
    after_help = "Lists pending timelock operations via audit-log cross-confirmation \
                  and dual-RPC state validation. No signing required (read-only)."
)]
pub struct ListPendingArgs {
    /// Timelock contract C-strkey to query.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub timelock: String,

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
    ///
    /// Defaults to `STELLAR_AGENT_PROFILE` env var, or `"default"`.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

/// One pending operation in the `list-pending` JSON envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PendingOperationEntry {
    /// Redacted operation identifier (first-8-last-8 hex).
    pub operation_id: String,
    /// State: `"waiting"`, `"ready"`, or `"done"`.
    pub state: String,
    /// Ledger at which the operation becomes or became ready.
    ///
    /// `null` for `"done"` or `"unset"` states.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_ledger: Option<u32>,
    /// Current ledger at the time of query.
    ///
    /// `null` for `"done"` or `"unset"` states.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_ledger: Option<u32>,
    /// Request ID of the originating `schedule_upgrade` call.
    pub scheduled_at_request_id: String,
}

/// Top-level JSON envelope for `smart-account timelock list-pending`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListPendingResult {
    /// Pending operations in audit-log order.
    pub operations: Vec<PendingOperationEntry>,
    /// Number of pending operations.
    pub pending_count: usize,
    /// Redacted timelock contract address (first-5-last-5 C-strkey).
    pub timelock_contract_redacted: String,
}

fn pending_op_to_entry(op: PendingTimelockOperation) -> PendingOperationEntry {
    let (state_label, ready_ledger, current_ledger) = match op.state {
        TimelockOperationStateView::Waiting {
            ready_ledger,
            current_ledger,
        } => (
            "waiting".to_owned(),
            Some(ready_ledger),
            Some(current_ledger),
        ),
        TimelockOperationStateView::Ready {
            ready_ledger,
            current_ledger,
        } => ("ready".to_owned(), Some(ready_ledger), Some(current_ledger)),
        TimelockOperationStateView::Done => ("done".to_owned(), None, None),
        TimelockOperationStateView::Unset => ("unset".to_owned(), None, None),
        // TimelockOperationStateView is #[non_exhaustive]; handle future variants gracefully.
        _ => ("unknown".to_owned(), None, None),
    };

    PendingOperationEntry {
        operation_id: op.operation_id.redacted(),
        state: state_label,
        ready_ledger,
        current_ledger,
        scheduled_at_request_id: op.scheduled_at_request_id,
    }
}

/// Runs `smart-account timelock list-pending`.
///
/// Returns exit code `0` on success, `1` on any error.
///
/// # Mainnet
///
/// Unlike `schedule`, `cancel`, and `execute`, `list-pending` does NOT apply
/// the `TargetNetwork::Mainnet` structural pre-reject. Rationale: `list-pending`
/// is a pure read operation — it issues only `simulate_transaction` RPC calls,
/// accesses no signer key, and modifies no on-chain state. Applying the
/// mainnet block here would make the operator unable to inspect pending
/// operations before they expire, which defeats the observability goal of the
/// command. The pre-reject is appropriate only for write-path verbs.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ListPendingArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load).await
}

/// Testable core of [`run`] with the profile load step injected.
///
/// Production callers use [`run`], which supplies the real profile loader.
/// Tests substitute an in-memory profile, so a mainnet profile can point at a
/// plaintext mock endpoint that the loader would refuse to read from a file.
///
/// The injected closure loads only. The synthesis decision and the
/// reconciliation run in [`load_profile_or_synthesize_testnet_with`], outside
/// the closure, on the injected path exactly as in production.
async fn run_with_dependencies<LoadProfile>(
    args: &ListPendingArgs,
    load_profile: LoadProfile,
) -> i32
where
    LoadProfile: FnOnce(&str) -> Result<Profile, ProfileLoadError>,
{
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let (profile, _origin) =
        match load_profile_or_synthesize_testnet_with(&resolved_profile, load_profile) {
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
    let request_id = Uuid::new_v4().to_string();

    let (audit_writer, _audit_log_path) =
        match open_audit_writer_read_only(&profile, &resolved_profile.name) {
            Ok(opened) => opened,
            Err(e) => {
                let envelope: Envelope<()> = Envelope::err(&e);
                render_json(&envelope);
                return 1;
            }
        };

    let secondary_rpc_url = context
        .secondary_rpc_url
        .clone()
        .unwrap_or_else(|| context.rpc_url.clone());

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);

    info!(
        timelock = %timelock_redacted,
        network = %context.chain_id,
        request_id = %request_id,
        "smart-account timelock list-pending: querying pending operations"
    );

    let pending = match stellar_agent_smart_account::timelock::list_pending(
        &args.timelock,
        &audit_writer,
        &context.rpc_url,
        &secondary_rpc_url,
        context.network_passphrase(),
        &request_id,
    )
    .await
    {
        Ok(v) => v,
        // Route through emit_sa_error to apply redact_path_in_message before emission.
        Err(e) => return emit_sa_error(&e),
    };

    let pending_count = pending.len();
    let operations: Vec<PendingOperationEntry> =
        pending.into_iter().map(pending_op_to_entry).collect();

    info!(
        pending_count,
        timelock = %timelock_redacted,
        request_id = %request_id,
        "smart-account timelock list-pending: complete"
    );

    let result = ListPendingResult {
        operations,
        pending_count,
        timelock_contract_redacted: timelock_redacted,
    };
    let envelope = Envelope::ok(result);
    render_json(&envelope);
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test fixture assertions")]
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;

    #[test]
    fn pending_op_entry_json_shape() {
        let entry = PendingOperationEntry {
            operation_id: "abcdef12...34567890".to_owned(),
            state: "waiting".to_owned(),
            ready_ledger: Some(5_000_000),
            current_ledger: Some(4_900_000),
            scheduled_at_request_id: "req-id-000".to_owned(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"state\":\"waiting\""));
        assert!(json.contains("\"ready_ledger\":5000000"));
        assert!(json.contains("\"current_ledger\":4900000"));
    }

    #[test]
    fn pending_op_entry_done_omits_ledger_fields() {
        let entry = PendingOperationEntry {
            operation_id: "abcdef12...34567890".to_owned(),
            state: "done".to_owned(),
            ready_ledger: None,
            current_ledger: None,
            scheduled_at_request_id: "req-id-001".to_owned(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("ready_ledger"),
            "done state must omit ready_ledger"
        );
        assert!(
            !json.contains("current_ledger"),
            "done state must omit current_ledger"
        );
    }

    #[test]
    fn list_pending_result_json_round_trip() {
        let result = ListPendingResult {
            operations: vec![],
            pending_count: 0,
            timelock_contract_redacted: "CTLCK...ABCDE".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ListPendingResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pending_count, 0);
        assert_eq!(back.timelock_contract_redacted, "CTLCK...ABCDE");
    }

    // ── list_pending mainnet-survival invariant ────────────────────────────────

    /// `list_pending` is a read-only operation that MUST NOT fire the mainnet
    /// structural pre-reject.
    ///
    /// Locks the exemption invariant: `run()` with `network = Mainnet` must NOT
    /// return `network.mainnet_write_forbidden`. `list_pending` accesses no signer
    /// key and mutates no on-chain state; blocking it on mainnet would prevent
    /// operators from inspecting pending operations before they expire.
    ///
    /// Prevents copy-paste of the `schedule`/`cancel`/`execute` pre-reject
    /// pattern into `list_pending`.
    ///
    /// The mainnet profile is injected in memory: the mock serves plaintext
    /// HTTP, which the loader refuses for a mainnet profile file.
    #[tokio::test]
    #[serial_test::serial]
    async fn list_pending_mainnet_profile_reaches_inspection_rpc() {
        let rpc = wiremock::MockServer::start().await;
        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let audit_log_path = home.path().join("audit.jsonl");
        let args = ListPendingArgs {
            timelock: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".into(),
            rpc_url: None,
            secondary_rpc_url: None,
            network: None,
            profile: Some("guard-mainnet".into()),
        };
        let _ = run_with_dependencies(&args, |name| {
            Ok(
                Profile::builder_mainnet_named(name, rpc.uri(), "s", "default", "n", "a")
                    .audit_log_path(audit_log_path)
                    .with_noop_engine()
                    .build(),
            )
        })
        .await;
        assert!(
            !rpc.received_requests().await.expect("requests").is_empty(),
            "mainnet inspection must reach the endpoint without a signer"
        );
    }
}
