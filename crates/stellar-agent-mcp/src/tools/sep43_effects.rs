//! The payment decision for a transaction a SEP-43 tool signs.
//!
//! Both transaction tools run, in order: mainnet refusal, address forms, the
//! tool's own rule, this effects decision, audit pre-flight, admission,
//! signer, signature. The decoder in
//! [`stellar_agent_core::policy::transaction_effects`] classifies every
//! operation. Each payment leg is then decided by the rule of its payment
//! tool, with its signed asset, amount, recipient and memo, inside the frame
//! of the tool's own allowed decision.
//!
//! Admission records the usage of every allowed leg in one durable batch
//! before the signer is loaded. A later signer, signing or send failure keeps
//! that usage: the signature can exist once the signer runs, and the wallet
//! cannot prove it was never released.

use std::collections::HashMap;

use rmcp::model::{CallToolResult, ErrorData};
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::error::FeeSource;
use stellar_agent_core::payment_accounts::PaymentAccount;
use stellar_agent_core::policy::transaction_effects::{
    FeeEffect, RefusedEffect, TransactionEffectsError, transaction_effects,
};
use stellar_agent_core::policy::v1::value::derive_value_class;
use stellar_agent_core::policy::v1::{
    AccountObservation, AccountReserveLookupError, AccountReservesView, ValueClass,
};
use stellar_agent_core::policy::{Decision, DenyReason, ToolDescriptor};
use stellar_agent_network::AccountView;
use stellar_agent_network::policy_state::{WindowStoreError, record_authorized_window_states};

use crate::policy_adapter::AccountViewAdapter;
use crate::server::WalletServer;
use crate::tools::common::{
    GateSnapshot, ToolError, business_error_result, endpoint_refusal_result, ledger_err_result,
    policy_denial_error_result, rpc_client_failure, single_shot_require_approval_error,
};

/// The audit legs and window admissions of an allowed transaction.
pub(crate) struct Sep43Effects {
    /// Audit legs of every allowed payment leg, in operation order.
    pub legs: Vec<ValueLegRecord>,
    admissions: Vec<(ToolDescriptor, ValueClass)>,
}

/// A business refusal of the effects gate.
fn refusal(result: CallToolResult) -> ToolError {
    ToolError::Business(result)
}

fn invalid_xdr(detail: impl Into<String>) -> ToolError {
    let error = stellar_agent_sep43::Sep43Error::InvalidXdr {
        detail: detail.into(),
    };
    refusal(business_error_result(error.wire_code(), error.to_string()))
}

fn unsizable(detail: impl Into<String>) -> ToolError {
    refusal(policy_denial_error_result(
        &DenyReason::UnsizableValueEffect {
            detail: detail.into(),
        },
    ))
}

/// Maps a decoder error to the refusal it gives before any account read.
fn decoder_refusal(error: TransactionEffectsError) -> ToolError {
    match error {
        TransactionEffectsError::UnreadableMemo => {
            invalid_xdr("the text memo of a valued transaction is not valid UTF-8")
        }
        TransactionEffectsError::Refused { effect, .. } => unsizable(match effect {
            RefusedEffect::AccountMerge => {
                "the transaction merges an account; a merge moves the balance the account \
                 holds when it applies, which no signed limit bounds"
            }
            RefusedEffect::AuthorityChange => {
                "the transaction changes a signer, the master weight or a threshold; the \
                 change gives another key authority outside every signed limit"
            }
            other => other.label(),
        }),
        // Decode, legacy-envelope and negative-field errors render their own
        // index, kind and field; a decoder error of a later build refuses alike.
        other => invalid_xdr(other.to_string()),
    }
}

/// The account view after the wallet's fee and earlier native debits.
///
/// The `balance_floor` and `minimum_reserve` criteria read the fee from
/// their own arguments too, so each evaluation copy carries a zero fee and
/// this view subtracts the fee once.
struct SpentAccountView<'a> {
    inner: &'a dyn AccountReservesView,
    spent_stroops: i128,
}

impl AccountReservesView for SpentAccountView<'_> {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        self.inner.reserves_stroops(base_reserve_stroops)
    }

    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        let unrepresentable = || AccountReserveLookupError {
            detail: "the balance after earlier debits is not representable".to_owned(),
        };
        let balance = i128::from(self.inner.balance_stroops()?)
            .checked_sub(self.spent_stroops)
            .ok_or_else(unrepresentable)?;
        i64::try_from(balance.max(0)).map_err(|_| unrepresentable())
    }

    fn observation(&self) -> Option<AccountObservation> {
        self.inner.observation()
    }

    fn effective_native_reservations_stroops(&self) -> Option<u64> {
        self.inner.effective_native_reservations_stroops()
    }
}

impl WalletServer {
    /// Decides every effect of `transaction_xdr` before the audit pre-flight.
    ///
    /// Every evaluation reads the outer allowed dispatch's `snapshot`, so all
    /// of them see one policy state, cache and instant. With
    /// `charge_own_rule`, admission also charges the tool's own count limits.
    /// A transaction without a payment leg sends no account read.
    ///
    /// # Errors
    ///
    /// Business refusals for invalid envelopes, refused or unopted effects,
    /// fee caps, account reads and payment-rule decisions; protocol errors
    /// for registry and argument faults.
    pub(crate) async fn sep43_effects_gate(
        &self,
        tool: &'static str,
        transaction_xdr: &str,
        chain_id: &str,
        charge_own_rule: bool,
        snapshot: &GateSnapshot,
    ) -> Result<Sep43Effects, ToolError> {
        let wallet = stellar_strkey::ed25519::PublicKey::from_string(
            &self.profile.mcp_signer_default.account,
        )
        .ok()
        .map(|key| key.0);
        let effects = transaction_effects(
            transaction_xdr,
            wallet.as_ref(),
            self.context.network_passphrase(),
        )
        .map_err(decoder_refusal)?;
        let descriptor = self.registered_descriptor(tool)?;
        if let Some(operation) = effects.unvalued.first()
            && !self.policy_engine.opaque_signing_opted_in(&descriptor)
        {
            return Err(unsizable(format!(
                "the transaction holds an effect the wallet cannot value ({}); the rule for \
                 this tool does not set allow_opaque_signing",
                operation.effect.label()
            )));
        }
        if let Some(fee) = &effects.fee {
            self.sep43_fee_check(fee)?;
        }
        let mut gated = Sep43Effects {
            legs: Vec::new(),
            admissions: Vec::new(),
        };
        if charge_own_rule {
            gated.admissions.push((descriptor, ValueClass::ReadOnly));
        }
        let payment_legs = effects.payment_legs();
        if payment_legs.is_empty() {
            return Ok(gated);
        }

        let client =
            self.write_primary_client()
                .map_err(|error| match rpc_client_failure(&error) {
                    Ok(result) => ToolError::Business(result),
                    Err(data) => ToolError::Protocol(data),
                })?;
        self.probe_write_endpoint(
            &client,
            tokio::time::Instant::now() + stellar_agent_network::PRE_SEND_BUDGET,
        )
        .await
        .map_err(|error| refusal(endpoint_refusal_result(&error)))?;
        let source = match wallet {
            Some(_) => Some(
                stellar_agent_network::fetch_account(
                    &client,
                    &self.profile.mcp_signer_default.account,
                    &[],
                )
                .await
                .map_err(|error| refusal(ledger_err_result(&error)))?,
            ),
            None => None,
        };
        let source = source.as_ref().map(AccountViewAdapter::new);
        let mut spent_stroops = i128::from(effects.fee.as_ref().map_or(0, |fee| fee.total_stroops));
        let mut recipients: HashMap<String, Option<AccountView>> = HashMap::new();

        for operation in payment_legs {
            let route_tool = operation.route.commit_tool();
            let mut arguments = operation.policy_args.clone();
            arguments["chain_id"] = chain_id.into();
            arguments["total_fee_stroops"] = 0.into();
            let class = match &operation.value {
                Some(value) => ValueClass::Value(value.clone()),
                None => derive_value_class(route_tool, &arguments),
            };
            let recipient = match arguments["destination"]
                .as_str()
                .and_then(|destination| PaymentAccount::parse(destination).ok())
            {
                Some(destination) => {
                    let base = destination.base_account();
                    if !recipients.contains_key(base) {
                        let view = match stellar_agent_network::fetch_account(&client, base, &[])
                            .await
                        {
                            Ok(view) => Some(view),
                            Err(stellar_agent_core::WalletError::Network(
                                stellar_agent_core::error::NetworkError::AccountNotFound { .. },
                            )) => None,
                            Err(error) => return Err(refusal(ledger_err_result(&error))),
                        };
                        recipients.insert(base.to_owned(), view);
                    }
                    recipients[base].as_ref()
                }
                None => None,
            };
            let identity = recipient.map(AccountViewAdapter::new);
            let spent = source.as_ref().map(|inner| SpentAccountView {
                inner,
                spent_stroops,
            });
            let evaluation = self
                .evaluate_policy_in_snapshot(
                    route_tool,
                    &arguments,
                    chain_id,
                    Some(class),
                    spent.as_ref().map(|view| view as &dyn AccountReservesView),
                    identity.as_ref().map(|view| {
                        view as &dyn stellar_agent_core::policy::v1::AccountIdentityView
                    }),
                    snapshot,
                )
                .await?;
            match evaluation.decision {
                Decision::Allow => {}
                Decision::Deny(reason) => return Err(refusal(policy_denial_error_result(&reason))),
                Decision::RequireApproval(_) => {
                    return Err(refusal(single_shot_require_approval_error()));
                }
                _ => {
                    return Err(refusal(business_error_result(
                        "policy.unexpected_decision",
                        "the policy engine returned a decision this build does not recognise; \
                         the operation is refused fail-closed",
                    )));
                }
            }
            let Some(value) = evaluation.value_effects else {
                continue;
            };
            for leg in value.legs() {
                gated.legs.push(ValueLegRecord::from(leg));
                if let Some(amount) = leg.amount.filter(|_| leg.is_native_debit()) {
                    spent_stroops = spent_stroops.checked_add(amount).ok_or_else(|| {
                        unsizable(
                            "the native debits of the transaction exceed the representable amount",
                        )
                    })?;
                }
            }
            gated.admissions.push((
                self.registered_descriptor(route_tool)?,
                ValueClass::Value(value),
            ));
        }
        Ok(gated)
    }

    /// Admits every staged item in one durable batch.
    ///
    /// # Errors
    ///
    /// A limit denial keeps its policy code; every other store failure
    /// refuses with `policy.engine_required`. A refused batch records nothing.
    pub(crate) fn sep43_admit(&self, effects: &Sep43Effects) -> Result<(), CallToolResult> {
        record_authorized_window_states(
            self.policy_engine.as_ref(),
            &effects.admissions,
            &self.profile,
            &self.profile_name_for_approval(),
        )
        .map_err(|error| match error {
            WindowStoreError::PolicyDenied { reason } => policy_denial_error_result(&reason),
            _ => business_error_result(
                "policy.engine_required",
                "authorized payment accounting is unavailable",
            ),
        })
    }

    fn registered_descriptor(&self, tool: &str) -> Result<ToolDescriptor, ToolError> {
        self.policy_descriptor(tool).ok_or_else(|| {
            ToolError::Protocol(ErrorData::internal_error(
                format!("tool.registry_missing: {tool} not found in registry"),
                None,
            ))
        })
    }

    /// Checks the fee the wallet account pays.
    ///
    /// The per-operation inclusion fee rounds up and passes the classic cap.
    /// A transaction with a resource fee also passes its full total through
    /// the contract transfer fee cap.
    fn sep43_fee_check(&self, fee: &FeeEffect) -> Result<(), ToolError> {
        // The decoder refuses a negative resource fee.
        let resource = fee.resource_fee_stroops.map_or(0, i64::unsigned_abs);
        let inclusion = fee
            .total_stroops
            .checked_sub(resource)
            .ok_or_else(|| invalid_xdr("the resource fee exceeds the transaction fee"))?;
        let per_op = inclusion.div_ceil(u64::from(fee.operation_count));
        match u32::try_from(per_op) {
            Ok(per_op) => self
                .check_write_fee(per_op, FeeSource::Envelope)
                .map_err(|error| refusal(ledger_err_result(&error)))?,
            Err(_) => {
                let profile = self.security_profile();
                let cap = match self.signed_classic_fee_cap() {
                    Some(signed) => Some(stellar_agent_network::fees::effective_classic_fee_cap(
                        profile, signed,
                    )),
                    None => profile.classic_max_fee_per_op_stroops,
                };
                if let Some(cap) = cap {
                    return Err(refusal(business_error_result(
                        "fees.percentile_exceeds_cap",
                        format!(
                            "the envelope's per-operation fee {per_op} stroops exceeds the \
                             profile cap of {cap} stroops; prepare the transaction again with \
                             a fee within the cap"
                        ),
                    )));
                }
            }
        }
        if fee.resource_fee_stroops.is_some() {
            let cap = stellar_agent_network::contract_transfer_fee_cap(
                self.context.chain_id,
                self.verified_policy.as_deref(),
            )
            .and_then(|cap| {
                stellar_agent_network::check_contract_transfer_fee_cap(fee.total_stroops, cap)
            });
            cap.map_err(|error| refusal(ledger_err_result(&error)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "sep43_effects_tests.rs"]
pub(crate) mod tests;
