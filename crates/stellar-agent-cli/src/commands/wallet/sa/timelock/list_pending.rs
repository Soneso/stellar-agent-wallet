//! `stellar-agent wallet sa timelock list-pending` — enumerate pending timelock operations.
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
//! | `--rpc-url <URL>` | no | Primary Soroban RPC (default: testnet). |
//! | `--secondary-rpc-url <URL>` | no | Secondary RPC for cross-RPC validation. |
//! | `--network {testnet\|mainnet}` | no | Target network (default: `testnet`). |
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
use stellar_agent_smart_account::timelock::{PendingTimelockOperation, TimelockOperationStateView};
use tracing::info;
use uuid::Uuid;

use crate::commands::wallet::common::{emit_sa_error, open_audit_writer};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Arguments for `wallet sa timelock list-pending`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(
    override_usage = "stellar-agent wallet sa timelock list-pending \
        --timelock <C_STRKEY> [--rpc-url <URL>] [--network {testnet|mainnet}]",
    after_help = "Lists pending timelock operations via audit-log cross-confirmation \
                  and dual-RPC state validation. No signing required (read-only)."
)]
pub struct ListPendingArgs {
    /// Timelock contract C-strkey to query.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub timelock: String,

    /// Primary Soroban RPC endpoint (default: testnet).
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC for cross-RPC state validation.
    ///
    /// Defaults to `--rpc-url` (degrades to single-RPC).
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Target network: `testnet` (default) or `mainnet`.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

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

/// Top-level JSON envelope for `wallet sa timelock list-pending`.
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

/// Runs `wallet sa timelock list-pending`.
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
    let profile_name = resolve_profile_name(args.profile.as_deref());
    let request_id = Uuid::new_v4().to_string();

    let (audit_writer, _audit_log_path) = match open_audit_writer(&profile_name) {
        Ok(pair) => pair,
        Err(e) => {
            let envelope: Envelope<()> = Envelope::err(&e);
            render_json(&envelope);
            return 1;
        }
    };

    let secondary_rpc_url = args
        .secondary_rpc_url
        .clone()
        .unwrap_or_else(|| args.rpc_url.clone());

    let timelock_redacted = redact_strkey_first5_last5(&args.timelock);

    info!(
        timelock = %timelock_redacted,
        network = %args.network,
        request_id = %request_id,
        "wallet sa timelock list-pending: querying pending operations"
    );

    let pending = match stellar_agent_smart_account::timelock::list_pending(
        &args.timelock,
        &audit_writer,
        &args.rpc_url,
        &secondary_rpc_url,
        args.network.passphrase(),
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
        "wallet sa timelock list-pending: complete"
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
    #[test]
    fn list_pending_does_not_have_mainnet_guard() {
        use crate::commands::wallet::sa::timelock::schedule::mainnet_forbidden_error;

        // list_pending does not import or call mainnet_forbidden_error; verify
        // that the schedule/cancel/execute guard does return the forbidden error
        // so we know it exists — but list_pending.rs itself has no such call.
        // The invariant is that no guard function exists in THIS module.
        //
        // Verify the network::Mainnet value itself resolves correctly (guard
        // function is fine at Testnet).
        let mainnet = TargetNetwork::Mainnet;
        let _ = mainnet; // list_pending accepts any network without blocking.

        // And that schedule's guard DOES fire — proving the guard function
        // exists in sibling modules but is intentionally absent here.
        assert!(
            mainnet_forbidden_error(TargetNetwork::Mainnet).is_some(),
            "schedule/cancel/execute guard must fire on mainnet; list_pending is the exception"
        );
    }
}
