//! `stellar_transaction_status` MCP tool: reconciles one submission against
//! the chain.
//!
//! This is how an agent resolves `submission.tx_timeout`. The submission was
//! recorded before it was sent, so the wallet holds a receipt and a
//! spending-window reservation for it; asking the chain what happened settles
//! both. Re-simulating the same intent never does: the sequence the
//! transaction consumes may already be spent by it.
//!
//! # Why a read tool is not read-only
//!
//! The lookup changes wallet state: a confirmed transaction turns its
//! reservation into recorded spend and writes the value-action row the
//! submission never got to write, and a transaction that can no longer apply
//! releases its reservation. Both annotations say so, because the pairing is
//! legal but unusual: `read_only_hint = false` because state changes, and
//! `ToolValueKind::ReadOnly` because no value moves as a result of the call.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, SubmissionReceipt};
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::PersistedWindowStore;

use crate::server::WalletServer;
use crate::tools::common::{business_error_result, redact_rpc_error_detail};

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
        description = "Reconcile one submitted transaction against the chain and settle the \
                       wallet's record of it. Pass the tx_hash from a submission.tx_timeout \
                       response. A confirmed transaction records its spend and its value-action \
                       row; one that can no longer apply releases its spending-window \
                       reservation. This is the only way to resolve a timed-out submission — \
                       never re-simulate, because the sequence may already be spent. \
                       read_only_hint=false (the wallet's record changes); the call moves no \
                       value. destructive_hint=false.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn stellar_transaction_status(
        &self,
        Parameters(args): Parameters<StellarTransactionStatusArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({ "chain_id": &args.chain_id });
        let reconciliation_decision = match self
            .dispatch_gate("stellar_transaction_status", &args_value, &args.chain_id)
            .await
        {
            Ok(outcome) => outcome.audit_decision(),
            Err(error) => return error.into_result(),
        };

        if !is_tx_hash(&args.tx_hash) {
            return Ok(business_error_result(
                "validation.address_invalid",
                "tx_hash must be 64 lowercase hex characters",
            ));
        }

        // The audit writer is acquired the same way every value verb acquires
        // it: a reconciliation that confirms a submission writes the
        // value-action row that submission never got to write, so the chain
        // key has to be available before anything is settled.
        let profile_name = self.profile_name_for_approval();
        let audit_writer = match crate::tools::value_audit::require_value_audit_writer(
            &self.profile,
            &profile_name,
        ) {
            Ok(writer) => writer,
            Err(err) => {
                let envelope = Envelope::<()>::err(&err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                return Ok(result);
            }
        };

        let client = StellarRpcClient::new(&self.profile.rpc_url).map_err(|err| {
            rmcp::ErrorData::internal_error(redact_rpc_error_detail("rpc_client_error", &err), None)
        })?;

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

        let window = PersistedWindowStore::for_profile(&profile_name);

        // With a receipt, the reconciliation pass settles this submission's
        // reservation and its receipt together, with no budget: the operator
        // asked about this transaction by name.
        if let Some(receipt) = &receipt {
            let Ok(now_ms) = stellar_agent_core::timefmt::now_unix_ms() else {
                return Ok(business_error_result(
                    "wallet.clock_error",
                    "the system clock is unavailable",
                ));
            };
            if let Err(e) = window
                .reconcile_one(
                    &self.profile,
                    &client,
                    Some(&receipts),
                    &receipt.envelope_hash,
                    now_ms,
                )
                .await
            {
                tracing::debug!(
                    error = ?e,
                    "stellar_transaction_status: reconciliation pass failed; the record stands"
                );
            }
        }

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

        let settled = match receipt {
            Some(r) => receipts.get(&r.envelope_hash).ok().flatten().or(Some(r)),
            None => None,
        };

        // A submission the chain has now answered for gets the value-action
        // row it never got to write, carrying the legs the gate sized.
        if let Some(record) = settled.as_ref() {
            crate::tools::submission_record::write_settled_row(
                &self.profile,
                &profile_name,
                &audit_writer,
                &record.envelope_hash,
                &record.tx_hash,
                &record.status,
                record.ledger.or(chain.ledger),
                reconciliation_decision,
            );
        }

        let view = json!({
            "tx_hash": args.tx_hash,
            "chain_status": chain.status,
            "ledger": chain.ledger,
            "record": settled.as_ref().map(|record| {
                let reservation_open = window
                    .pending_reservations(&self.profile)
                    .map(|open| open.iter().any(|r| r.id == record.envelope_hash))
                    .unwrap_or(false);
                receipt_view(record, reservation_open)
            }),
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

/// Renders the wallet's settled record of a submission.
fn receipt_view(receipt: &SubmissionReceipt, reservation_open: bool) -> serde_json::Value {
    json!({
        "reservation_open": reservation_open,
        "envelope_hash": receipt.envelope_hash,
        "status": receipt.status.label(),
        "failure_code": match &receipt.status {
            ReceiptStatus::Failed { code } => Some(code.clone()),
            _ => None,
        },
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
