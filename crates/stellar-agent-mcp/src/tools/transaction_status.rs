//! `stellar_transaction_status` MCP tool: reconciles one submission against
//! the chain.
//!
//! This is how an agent resolves `submission.tx_timeout`. The submission was
//! recorded before it was sent, so the wallet holds a receipt and, under a
//! policy with a stateful criterion, a spending-window reservation for it;
//! asking the chain what happened records a reported success on both.
//! Re-simulating or resubmitting the same intent never resolves it: the
//! transaction may still apply, and the sequence it consumes may already be
//! spent by it.
//!
//! The tool reconciles a submission by its receipt, or by its reservation when
//! the receipt is missing, the way `stellar-agent tx status` does. A reported
//! failure or missing transaction does not release possible spending, and a
//! reported success writes no submitted row. A reservation ends once its
//! accounting horizon has passed, with the outcome unknown. A pending or
//! ambiguous `record` then carries `release_code`
//! `submission.accounting_expired`, and a record with another status keeps its
//! status and code. That expiry owes
//! one `submission_accounting_expired` audit event, which the call delivers
//! from the verified window state. The receipt is display data: `record`
//! carries `settlement_evidence: "unavailable"`, and no receipt status writes
//! an audit row. A hold that remains is reported as `reservation`. One marked
//! `operator_required` ends at its accounting horizon when it has a time
//! bound. Once its execution bound has passed, the operator's
//! `stellar-agent tx receipt clear --acknowledge` clears an eligible receipt,
//! and the bounded spend stays charged through the horizon. An untimed hold
//! clears with `--acknowledge --acknowledge-unbounded`. No step sends the
//! transaction again.
//!
//! # Why a read tool is not read-only
//!
//! The lookup changes wallet state: it records a reported success on the
//! receipt and the reservation, and ends a reservation whose accounting
//! horizon has passed. A reported failure leaves both as they were. An untimed
//! reservation's receipt that already records another network answer keeps
//! it. Both annotations say so, because the pairing is legal but unusual:
//! `read_only_hint = false` because state changes, and
//! `ToolValueKind::ReadOnly` because no value moves as a result of the call.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReleaseEvidence, SubmissionReceipt};
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submission_flow::{self, StatusFailure, StatusRequest, is_tx_hash};

use crate::server::WalletServer;
use crate::tools::common::business_error_result;

/// Arguments for the `stellar_transaction_status` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarTransactionStatusArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// The transaction hash to reconcile, 64 lowercase hex characters. This is
    /// the `details.tx_hash` a `submission.tx_timeout` response carries.
    pub tx_hash: String,
}

#[mcp_tool_router]
#[tool_router(router = transaction_status_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Reconciles one recorded submission against the chain.
    #[mcp_tool_item(
        name = "stellar_transaction_status",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = true,
        value_kind = "read_only"
    )]
    #[tool(
        name = "stellar_transaction_status",
        description = "Reconcile one submitted transaction against the chain and update the \
                       wallet's record of it. Pass the tx_hash from a submission.tx_timeout \
                       response. Endpoint success, failure, and absence are reports. Possible \
                       spending remains charged through the later of the signed deadline and \
                       the first success observation, plus every affected window; untimed \
                       exposure requires explicit operator acknowledgement. \
                       Accounting expiry leaves the outcome unknown, records \
                       submission.accounting_expired in record.release_code of a pending or \
                       ambiguous record, keeps any other status and code, and writes no failed \
                       value-action row. record is display data: settlement_evidence is \
                       unavailable, and settlement_decision_id only locates an accounting \
                       decision. A hold that remains is returned as \
                       reservation {envelope_hash, operator_required}; operator_required means no \
                       endpoint answer resolves it. A time-bounded hold still ends at its \
                       accounting horizon; otherwise only the operator's tx receipt clear \
                       resolves it, with --acknowledge-unbounded as well for an untimed hold. \
                       This is the only way to resolve a timed-out submission: never \
                       re-simulate or resubmit, because \
                       the transaction may still apply and its sequence may already be spent. \
                       read_only_hint=false (the wallet's record changes); the call moves no \
                       value. destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_transaction_status(
        &self,
        Parameters(args): Parameters<StellarTransactionStatusArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({ "chain_id": &args.chain_id });
        if let Err(error) = self
            .dispatch_gate("stellar_transaction_status", &args_value, &args.chain_id)
            .await
        {
            return error.into_result();
        }

        if !is_tx_hash(&args.tx_hash) {
            return Ok(business_error_result(
                "validation.address_invalid",
                "tx_hash must be 64 lowercase hex characters",
            ));
        }

        let profile_name = self.profile_name_for_approval();
        let window = PersistedWindowStore::for_profile(&profile_name);
        let client = match self.context.primary_client() {
            Ok(client) => client,
            Err(err) => {
                // An unreadable window file refuses before a client failure,
                // as the window is read first.
                if let Err(error) = window.pending_reservations(&self.profile) {
                    return Ok(status_error_result(StatusFailure::WindowUnreadable(error)));
                }
                return crate::tools::common::rpc_client_failure(&err);
            }
        };

        let oracle = self.settlement_oracle();
        let outcome = match submission_flow::transaction_status(
            StatusRequest {
                profile: &self.profile,
                profile_name: &profile_name,
                tx_hash: &args.tx_hash,
                window: &window,
                client: &client,
                oracle: oracle.as_ref(),
            },
            || self.resolve_approval_dir(),
            || {
                crate::tools::value_audit::require_value_audit_writer(
                    &self.profile,
                    &profile_name,
                    self.audit_binding,
                )
            },
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => return Ok(status_error_result(error)),
        };

        let view = json!({
            "tx_hash": args.tx_hash,
            "chain_status": outcome.chain_status,
            "ledger": outcome.ledger,
            "record": outcome.record.as_ref().map(|record| receipt_view(record, outcome.reservation_open)),
            "reservation": outcome.reservation.as_ref().map(|held| json!({
                "envelope_hash": held.id,
                "operator_required": held.operator_required,
            })),
        });
        let envelope = Envelope::ok(view);
        let json_out = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json_out)]))
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_transaction_status` directly for integration tests.
    #[doc(hidden)]
    pub async fn call_stellar_transaction_status(
        &self,
        args: StellarTransactionStatusArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_transaction_status(Parameters(args)).await
    }
}

/// Renders the wallet's record of a submission.
///
/// The record is display data. `settlement_evidence` is always
/// `"unavailable"`: no receipt field authenticates a settlement.
/// `release_code` names a display observation or the accounting disposition
/// of a submission whose outcome is unknown, such as
/// `submission.accounting_expired` once its accounting horizon passed; it is
/// not a chain outcome. `settlement_decision_id` locates the authenticated
/// accounting decision a projection recorded; a copied identifier proves
/// nothing. A reported failure or missing transaction does not release
/// possible spending.
fn receipt_view(receipt: &SubmissionReceipt, reservation_open: bool) -> serde_json::Value {
    json!({
        "settlement_evidence": "unavailable",
        "settlement_decision_id": receipt.settlement_decision_id,
        "reservation_open": reservation_open,
        "envelope_hash": receipt.envelope_hash,
        "status": receipt.status.label(),
        "failure_code": match &receipt.status {
            ReceiptStatus::Failed { code } => Some(code.clone()),
            _ => None,
        },
        "release_code": receipt.release_code.map(ReleaseEvidence::code),
        "ledger": receipt.ledger,
        "source_redacted": stellar_agent_core::observability::redact_strkey_first5_last5(
            &receipt.source,
        ),
        "sequence": receipt.sequence,
        "submitted": receipt.submitted,
    })
}

fn status_error_result(error: StatusFailure) -> CallToolResult {
    match error {
        StatusFailure::WindowUnreadable(e) => business_error_result(
            e.submission_code(),
            format!("the spending-window file could not be read: {e}"),
        ),
        StatusFailure::ReceiptStoreOpen { detail } => {
            business_error_result("submission.record_unavailable", detail)
        }
        StatusFailure::ApprovalDirUnavailable(e) => {
            business_error_result("submission.record_unavailable", e.to_string())
        }
        StatusFailure::ReceiptStoreRead(e) => business_error_result(
            "submission.record_unavailable",
            format!("the submission receipt store could not be read: {e}"),
        ),
        StatusFailure::ClockUnavailable(_) => {
            business_error_result("wallet.clock_error", "the system clock is unavailable")
        }
        StatusFailure::ReconcileRefused(e) => {
            business_error_result(e.submission_code(), e.to_string())
        }
        StatusFailure::RepairRefused(e) => business_error_result(e.code(), e.message()),
        StatusFailure::ChainQueryFailed(e) => business_error_result(
            "network.rpc_unreachable",
            format!("the endpoint could not be asked about this transaction: {e}"),
        ),
    }
}
