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
//! accounting horizon has passed, with `record.release_code`
//! `submission.accounting_expired` and the outcome unknown. That expiry owes
//! one `submission_accounting_expired` audit event, which the call delivers
//! from the verified window state. The receipt is display data: `record`
//! carries `settlement_evidence: "unavailable"`, and no receipt status writes
//! an audit row. A hold that remains is reported as `reservation`. One marked
//! `operator_required` ends at its accounting horizon when it has a time
//! bound. Before that, or without a time bound, the operator's
//! `stellar-agent tx receipt clear` resolves it, and an untimed one needs
//! `--acknowledge-unbounded` as well. No step sends the transaction again.
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
use stellar_agent_core::profile::receipt::{
    ReceiptStatus, ReceiptStore, ReleaseEvidence, SubmissionReceipt,
};
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::policy_state::PersistedWindowStore;

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
                       Accounting expiry leaves the outcome unknown and records \
                       submission.accounting_expired in record.release_code without a failed \
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
        let held = match self.open_reservation_for(&window, &args.tx_hash) {
            Ok(held) => held,
            Err(result) => return Ok(result),
        };

        let client = match self.context.primary_client() {
            Ok(client) => client,
            Err(err) => return crate::tools::common::rpc_client_failure(&err),
        };

        let receipts = match ReceiptStore::open(&profile_name) {
            Ok(store) => store,
            Err(e) => {
                return Ok(business_error_result(
                    "submission.record_unavailable",
                    format!("the submission receipt store could not be opened: {e}"),
                ));
            }
        };

        let receipt = match receipts.find_by_tx_hash(&args.tx_hash) {
            Ok(r) => r,
            Err(e) => {
                return Ok(business_error_result(
                    "submission.record_unavailable",
                    format!("the submission receipt store could not be read: {e}"),
                ));
            }
        };

        let envelope_hash = receipt
            .as_ref()
            .map(|r| r.envelope_hash.clone())
            .or_else(|| held.as_ref().map(|r| r.id.clone()));

        // The reconciliation pass settles this submission's reservation and
        // its receipt together, with no budget: the agent asked about this
        // transaction by name. A submission whose receipt is missing is
        // settled by its authenticated reservation.
        if let Some(envelope_hash) = &envelope_hash {
            let Ok(now_ms) = stellar_agent_core::timefmt::now_unix_ms() else {
                return Ok(business_error_result(
                    "wallet.clock_error",
                    "the system clock is unavailable",
                ));
            };
            // On a mainnet profile the oracle witnesses the primary's negative
            // answers before the reservation settles on them.
            let oracle = self.settlement_oracle();
            match window
                .reconcile_one(
                    &self.profile,
                    &client,
                    oracle.as_ref(),
                    Some(&receipts),
                    envelope_hash,
                    now_ms,
                )
                .await
            {
                Ok(report) if report.receipt_write_failed > 0 => tracing::warn!(
                    receipt_write_failed = report.receipt_write_failed,
                    "stellar_transaction_status: reconciliation could not record the receipt"
                ),
                Ok(_) => {}
                Err(e) => {
                    // A refused pass leaves the obligations of earlier calls
                    // in place; they are delivered before the refusal returns.
                    self.deliver_owed(&profile_name, &window, &receipts);
                    return Ok(business_error_result(e.submission_code(), e.to_string()));
                }
            }
        }

        self.deliver_owed(&profile_name, &window, &receipts);

        if let Some(record) = &receipt
            && record.approval_nonce.is_some()
        {
            let approval_dir = match self.resolve_approval_dir() {
                Ok(dir) => dir,
                Err(e) => {
                    return Ok(business_error_result(
                        "submission.record_unavailable",
                        e.to_string(),
                    ));
                }
            };
            if let Err(e) = stellar_agent_network::submission_record::repair_approval_consumption(
                &receipts,
                &record.envelope_hash,
                &approval_dir,
                &profile_name,
            ) {
                return Ok(business_error_result(e.code(), e.message()));
            }
        }

        // Report the chain's own answer alongside the settled record, so an
        // agent sees both what happened and what the wallet now holds.
        let chain = match client.get_transaction_status(&args.tx_hash).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(business_error_result(
                    "network.rpc_unreachable",
                    format!("the endpoint could not be asked about this transaction: {e}"),
                ));
            }
        };

        // Reconciliation can restore a receipt from the authenticated hold and
        // can release the hold, so both are read again.
        let reservation = match self.open_reservation_for(&window, &args.tx_hash) {
            Ok(held) => held,
            Err(result) => return Ok(result),
        };
        let settled = match receipts.find_by_tx_hash(&args.tx_hash) {
            Ok(record) => record,
            Err(e) => {
                return Ok(business_error_result(
                    "submission.record_unavailable",
                    format!("the submission receipt store could not be read: {e}"),
                ));
            }
        };

        let view = json!({
            "tx_hash": args.tx_hash,
            "chain_status": chain.status,
            "ledger": chain.ledger,
            "record": settled.as_ref().map(|record| {
                let reservation_open = reservation
                    .as_ref()
                    .is_some_and(|held| held.id == record.envelope_hash);
                receipt_view(record, reservation_open)
            }),
            "reservation": reservation.as_ref().map(|held| json!({
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

impl WalletServer {
    /// Delivers the accounting obligations the verified window state owes,
    /// including those of earlier calls.
    ///
    /// The audit writer is acquired the way every value verb acquires it,
    /// and only when an audit event is unacknowledged, so a projection-only
    /// retry runs without it. A refusal, an unavailable writer included, is
    /// logged at WARN and leaves the obligations owed; the status answer does
    /// not depend on it.
    fn deliver_owed(
        &self,
        profile_name: &str,
        window: &PersistedWindowStore,
        receipts: &ReceiptStore,
    ) {
        let _ = stellar_agent_network::policy_state::drain_accounting_obligations(
            window,
            &self.profile,
            profile_name,
            Some(receipts),
            || {
                crate::tools::value_audit::require_value_audit_writer(
                    &self.profile,
                    profile_name,
                    self.audit_binding,
                )
            },
        );
    }

    /// The reservation the window file holds pending for `tx_hash`, or the
    /// error result for a file that cannot be read.
    fn open_reservation_for(
        &self,
        window: &PersistedWindowStore,
        tx_hash: &str,
    ) -> Result<Option<stellar_agent_network::policy_state::SubmissionHold>, CallToolResult> {
        match window.pending_reservations(&self.profile) {
            Ok(open) => Ok(open.into_iter().find(|r| r.tx_hash == tx_hash)),
            Err(e) => Err(business_error_result(
                e.submission_code(),
                format!("the spending-window file could not be read: {e}"),
            )),
        }
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

/// Returns true when `value` is 64 lowercase hex characters.
fn is_tx_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn accepts_a_lowercase_64_hex_hash() {
        assert!(is_tx_hash(&"ab".repeat(32)));
    }

    #[test]
    fn refuses_uppercase_wrong_length_and_non_hex() {
        assert!(!is_tx_hash(&"AB".repeat(32)));
        assert!(!is_tx_hash(&"ab".repeat(31)));
        assert!(!is_tx_hash(&"zz".repeat(32)));
    }
}
