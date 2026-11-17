//! The payment decision for a transaction a SEP-43 tool signs.
//!
//! Both transaction tools run, in order: mainnet refusal, address forms, the
//! tool's own rule, this effects decision, audit pre-flight, admission,
//! signer, signature. The decoder in
//! [`stellar_agent_core::policy::transaction_effects`] classifies every
//! operation of the wallet and of each other source whose signer set, read
//! in this call, lists the wallet key. Each payment leg is then decided by the
//! rule of its payment tool, with its signed asset, amount, recipient and
//! memo, inside the frame of the tool's own allowed decision.
//!
//! Admission records the usage of every allowed leg in one durable batch
//! before the signer is loaded. A later signer, signing or send failure keeps
//! that usage: the signature can exist once the signer runs, and the wallet
//! cannot prove it was never released.
//!
//! An approval requirement of the tool rule or of the payment rule is met in
//! two calls for a transaction of one payment, path payment, account creation
//! or trustline change. The first call stores a pending approval over the
//! exact envelope text and signs nothing. The repeat with the attested proof
//! signs, and the signature spends the approval. Every other shape refuses
//! with `policy.approval_required_unsupported`.
//!
//! The auth-entry tool runs the same steps for an authorization preimage.
//! The preimage passes the SEP-43 input checks for the profile signer before
//! anything is read. Each token leg the signer's account authorizes in the
//! invocation tree is decided by the pay rule; an approval requirement
//! refuses with `policy.approval_required_unsupported`.

use std::collections::HashMap;

use rmcp::model::{CallToolResult, Content, ErrorData};
use stellar_agent_core::audit_log::PolicyDecision;
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::envelope_decode::{
    ClassicOperation, ClassicSummary, ClassicTransactionKind, classic_summary,
};
use stellar_agent_core::error::FeeSource;
use stellar_agent_core::payment_accounts::PaymentAccount;
use stellar_agent_core::policy::transaction_effects::{
    FeeEffect, PaymentRoute, RefusedEffect, SourceCandidates, SourceMembership, TransactionEffects,
    TransactionEffectsError, UnvaluedEffect, ValuedOperation, authorized_invocation_effects,
    transaction_effects_for_sources, transaction_source_candidates,
};
use stellar_agent_core::policy::v1::value::{ValueLeg, derive_value_class};
use stellar_agent_core::policy::v1::{
    AccountObservation, AccountReserveLookupError, AccountReservesView, ValueClass, ValueEffects,
};
use stellar_agent_core::policy::{ApprovalRequest, Decision, DenyReason, ToolDescriptor};
use stellar_agent_network::policy_state::{WindowStoreError, record_authorized_window_states};
use stellar_agent_network::{AccountView, StellarRpcClient};
use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

use crate::policy_adapter::AccountViewAdapter;
use crate::server::WalletServer;
use crate::tools::common::{
    ApprovalOutcome, DispatchOutcome, GateSnapshot, GatedApprovalKind, SuppliedProof, ToolError,
    business_error_result, endpoint_refusal_result, ledger_err_result, policy_denial_error_result,
    rpc_client_failure, single_shot_require_approval_error, verify_attestation_gate,
};

/// The audit legs and window admissions of an allowed transaction.
pub(crate) struct Sep43Effects {
    /// Audit legs of every allowed payment leg, in operation order.
    pub legs: Vec<ValueLegRecord>,
    admissions: Vec<(ToolDescriptor, ValueClass)>,
    /// The verified approval nonce the signature spends.
    pub approval_nonce: Option<String>,
    /// `RequireApproval` exactly when an approval was verified.
    pub decision: PolicyDecision,
}

/// A transaction the approval surfaces show, with the fields its pending
/// approval stores.
enum Approvable {
    /// A payment; its pending approval reads the envelope.
    Payment,
    /// A path payment or an account creation, stored as a payment of its
    /// send asset and amount.
    Send {
        destination: String,
        asset: String,
        amount_stroops: i64,
        fee_stroops: u32,
        seq_num: i64,
    },
    /// A trustline change.
    Trustline {
        holder: String,
        asset_code: String,
        asset_issuer: String,
        limit_stroops: Option<i64>,
        fee_stroops: u32,
        seq_num: i64,
    },
}

/// The approvable form of a transaction: one operation, valued by its
/// payment rule from the signed arguments, that `classic_summary` shows.
fn approvable(transaction_xdr: &str, effects: &TransactionEffects) -> Option<Approvable> {
    let [operation] = effects.valued.as_slice() else {
        return None;
    };
    if !effects.unvalued.is_empty() || operation.value.is_some() {
        return None;
    }
    let kind = match operation.route {
        PaymentRoute::Pay | PaymentRoute::CreateAccount => ClassicTransactionKind::Payment,
        PaymentRoute::Trustline => ClassicTransactionKind::Trustline,
        _ => return None,
    };
    // The summary decode refuses a fee bump, a legacy envelope and every
    // operation count other than one.
    let ClassicSummary {
        source,
        fee_stroops,
        seq_num,
        operation,
        ..
    } = classic_summary(transaction_xdr, kind).ok()?;
    let send = |destination, asset, amount_stroops| Approvable::Send {
        destination,
        asset,
        amount_stroops,
        fee_stroops,
        seq_num,
    };
    match operation {
        ClassicOperation::Payment { .. } => Some(Approvable::Payment),
        ClassicOperation::PathPayment {
            destination,
            send_asset,
            send_amount_stroops,
            ..
        } => Some(send(destination, send_asset, send_amount_stroops)),
        ClassicOperation::CreateAccount {
            destination,
            starting_balance_stroops,
        } => Some(send(
            destination,
            "XLM".to_owned(),
            starting_balance_stroops,
        )),
        ClassicOperation::ChangeTrust {
            asset_code,
            asset_issuer,
            limit_stroops,
        } => Some(Approvable::Trustline {
            holder: source,
            asset_code,
            asset_issuer,
            limit_stroops,
            fee_stroops,
            seq_num,
        }),
        _ => None,
    }
}

/// An approval requirement: the request and its governing lifetime.
type Requirement = (ApprovalRequest, u64);

/// A payment rule's approval requirement, its returned effects and the
/// approvable shape it applies to.
type OperationRequirement<'shape> = (Requirement, Option<ValueEffects>, &'shape Approvable);

fn store_error(detail: impl std::fmt::Display) -> ToolError {
    ToolError::Protocol(ErrorData::internal_error(
        format!("approval.store_error: {detail}"),
        None,
    ))
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

/// Refuses a caller `address` that is not the signer `account`, with the
/// shape and match refusals of the SEP-43 module's own address check.
fn sep43_check_address(
    address: &str,
    account: &str,
) -> Result<(), stellar_agent_sep43::Sep43Error> {
    stellar_agent_sep43::validate_strkey(address)?;
    if address == account {
        return Ok(());
    }
    Err(stellar_agent_sep43::Sep43Error::signing_key_mismatch(
        account,
    ))
}

/// The pay-route evaluation of a token leg `account` authorizes in an
/// authorization entry: the signed asset, quantity and recipient, with no
/// memo, since a preimage carries none.
fn auth_entry_leg(account: &str, leg: ValueLeg) -> ValuedOperation {
    let mut policy_args = serde_json::json!({
        "source": account,
        "amount_stroops": leg.amount.map(|amount| amount.to_string()),
        "asset": leg.asset,
        "memo": null,
    });
    if let Some(destination) = &leg.destination {
        policy_args["destination"] = destination.as_str().into();
    }
    ValuedOperation {
        operation_index: 0,
        route: PaymentRoute::Pay,
        policy_args,
        value: Some(ValueEffects::single(leg)),
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
    /// The signer sets of other operation sources are read first, once; a
    /// transaction without such a source or a payment leg sends no read.
    ///
    /// An approval requirement of `outcome` or of a payment rule needs an
    /// approvable transaction. Without `proof`, the gate stores a pending
    /// approval and returns its response through the business channel; the
    /// handler returns it unchanged and signs nothing.
    ///
    /// # Errors
    ///
    /// Business refusals for invalid envelopes, refused or unopted effects,
    /// fee caps, account reads, payment-rule decisions and approval proofs;
    /// protocol errors for registry, argument and approval-store faults.
    pub(crate) async fn sep43_effects_gate(
        &self,
        tool: &'static str,
        transaction_xdr: &str,
        chain_id: &str,
        charge_own_rule: bool,
        outcome: &DispatchOutcome,
        proof: &SuppliedProof,
    ) -> Result<Sep43Effects, ToolError> {
        let snapshot = outcome.snapshot()?;
        let wallet = stellar_strkey::ed25519::PublicKey::from_string(
            &self.profile.mcp_signer_default.account,
        )
        .ok()
        .map(|key| key.0);
        let candidates = transaction_source_candidates(transaction_xdr, wallet.as_ref())
            .map_err(decoder_refusal)?;
        let (membership, client) = self.sep43_observe_sources(&candidates).await?;
        let effects = transaction_effects_for_sources(
            transaction_xdr,
            &membership,
            self.context.network_passphrase(),
        )
        .map_err(decoder_refusal)?;
        let shape = approvable(transaction_xdr, &effects);
        let tool_requirement = match (outcome, &shape) {
            (DispatchOutcome::RequireApproval(_), None) => {
                return Err(refusal(single_shot_require_approval_error()));
            }
            (DispatchOutcome::RequireApproval(approval), Some(shape)) => {
                Some(((approval.request.clone(), approval.governing_ttl_ms), shape))
            }
            (DispatchOutcome::Allow(_), _) => None,
        };
        let descriptor = self.registered_descriptor(tool)?;
        if let Some(operation) = effects.unvalued.first() {
            self.sep43_require_opt_in(&descriptor, "transaction", operation.effect)?;
        }
        if let Some(fee) = &effects.fee {
            self.sep43_fee_check(fee)?;
        }
        let mut gated = Sep43Effects {
            legs: Vec::new(),
            admissions: Vec::new(),
            approval_nonce: None,
            decision: PolicyDecision::Allow,
        };
        if charge_own_rule {
            gated.admissions.push((descriptor, ValueClass::ReadOnly));
        }
        let spent_stroops = i128::from(effects.fee.as_ref().map_or(0, |fee| fee.total_stroops));
        let operation_requirement = self
            .sep43_decide_legs(
                effects.payment_legs(),
                chain_id,
                spent_stroops,
                shape.as_ref(),
                snapshot,
                client,
                &mut gated,
            )
            .await?;
        // The shorter lifetime governs; on a tie, the operation's request.
        let ((request, governing_ttl_ms), value_effects, shape) =
            match (tool_requirement, operation_requirement) {
                (None, None) => return Ok(gated),
                (Some((own, shape)), Some((operation, _, _)))
                    if own.0.ttl_seconds < operation.0.ttl_seconds =>
                {
                    (own, None, shape)
                }
                (_, Some((operation, value_effects, shape))) => (operation, value_effects, shape),
                (Some((own, shape)), None) => (own, None, shape),
            };
        let now_ms = snapshot.now_ms();
        if proof.nonce.is_none() && proof.attestation.is_none() {
            return Err(refusal(self.sep43_pending_approval(
                transaction_xdr,
                shape,
                &request,
                now_ms,
                governing_ttl_ms,
            )?));
        }
        let kind = match shape {
            Approvable::Payment | Approvable::Send { .. } => GatedApprovalKind::Payment,
            Approvable::Trustline { .. } => GatedApprovalKind::Trustline,
        };
        let required = DispatchOutcome::RequireApproval(ApprovalOutcome {
            request,
            governing_ttl_ms,
            value_effects,
            now_ms: Some(now_ms),
            decision: None,
            snapshot: None,
        });
        verify_attestation_gate(
            self,
            &required,
            kind,
            transaction_xdr,
            proof.nonce.as_deref(),
            proof.attestation.as_deref(),
            tool,
        )
        .await
        .map_err(refusal)?;
        gated.approval_nonce.clone_from(&proof.nonce);
        gated.decision = PolicyDecision::RequireApproval;
        Ok(gated)
    }

    /// Decides the authorization entry `preimage_xdr` before the audit
    /// pre-flight, for the account of the profile signer.
    ///
    /// The preimage passes the SEP-43 input checks for that account first,
    /// and a caller `address` must name that account before any read or
    /// admission. Every token leg the account authorizes is then decided by
    /// the pay rule in the outer allowed dispatch's `snapshot`, with the
    /// signed asset, quantity and recipient and without a memo or fee. A call
    /// the wallet cannot value needs the tool rule's `allow_opaque_signing`.
    /// Admission always charges the tool's own count limits. An approval
    /// requirement of a pay rule refuses with
    /// `policy.approval_required_unsupported`.
    ///
    /// # Errors
    ///
    /// `policy.engine_required` when the profile signer is not a G-strkey;
    /// the SEP-43 refusals of an invalid preimage; `sep43.invalid_address`
    /// when `address` is not the profile signer's G-strkey; business
    /// refusals for unopted calls, account reads and pay-rule decisions;
    /// protocol errors for registry and argument faults.
    pub(crate) async fn sep43_auth_entry_gate(
        &self,
        tool: &'static str,
        preimage_xdr: &str,
        network_passphrase: Option<&str>,
        address: Option<&str>,
        chain_id: &str,
        outcome: &DispatchOutcome,
    ) -> Result<Sep43Effects, ToolError> {
        let snapshot = outcome.snapshot()?;
        let account = &self.profile.mcp_signer_default.account;
        let Ok(signer) = stellar_strkey::ed25519::PublicKey::from_string(account) else {
            return Err(refusal(business_error_result(
                "policy.engine_required",
                "the profile signer account is not a G-strkey, so the account an \
                 authorization entry debits is unknown",
            )));
        };
        let invocation = stellar_agent_sep43::signing::validate_soroban_auth_entry(
            preimage_xdr,
            &signer,
            self.context.network_passphrase(),
            network_passphrase,
        )
        .map_err(|error| refusal(business_error_result(error.wire_code(), error.to_string())))?;
        if let Some(address) = address {
            sep43_check_address(address, account).map_err(|error| {
                refusal(business_error_result(error.wire_code(), error.to_string()))
            })?;
        }
        let effects = authorized_invocation_effects(
            &invocation,
            &ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                signer.0,
            )))),
        );
        let descriptor = self.registered_descriptor(tool)?;
        if effects.unvalued {
            self.sep43_require_opt_in(
                &descriptor,
                "authorization entry",
                UnvaluedEffect::ContractInvocation,
            )?;
        }
        let mut gated = Sep43Effects {
            legs: Vec::new(),
            admissions: vec![(descriptor, ValueClass::ReadOnly)],
            approval_nonce: None,
            decision: PolicyDecision::Allow,
        };
        let legs: Vec<ValuedOperation> = effects
            .legs
            .into_iter()
            .map(|leg| auth_entry_leg(account, leg))
            .collect();
        self.sep43_decide_legs(
            legs.iter().collect(),
            chain_id,
            0,
            None,
            snapshot,
            None,
            &mut gated,
        )
        .await?;
        Ok(gated)
    }

    /// The primary write endpoint, probed under the pre-send budget.
    async fn sep43_probed_client(&self) -> Result<StellarRpcClient, ToolError> {
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
        Ok(client)
    }

    /// Reads the signer sets of `candidates` in one request on the probed
    /// endpoint and returns the membership with that endpoint.
    ///
    /// Without a candidate, nothing is read. Each call reads again; a read
    /// error refuses with its own code and excludes no source.
    async fn sep43_observe_sources(
        &self,
        candidates: &SourceCandidates,
    ) -> Result<(SourceMembership, Option<StellarRpcClient>), ToolError> {
        // The reader refuses a response without every requested account, so
        // a missing set is a malformed answer, never a nonmember.
        let unobserved = || {
            refusal(business_error_result(
                "network.rpc_response_malformed",
                "the signer set of an operation source is missing from the response",
            ))
        };
        let (sets, client) = match candidates.keys().len() {
            0 => (std::collections::BTreeMap::new(), None),
            _ => {
                let client = self.sep43_probed_client().await?;
                let (sets, _) = stellar_agent_network::account::fetch_account_signers(
                    &client,
                    &candidates.account_ids(),
                    tokio::time::Instant::now() + stellar_agent_network::PRE_SEND_BUDGET,
                )
                .await
                .map_err(|error| refusal(ledger_err_result(&error)))?;
                (sets, Some(client))
            }
        };
        let membership = candidates
            .observe(|key| {
                sets.get(
                    stellar_strkey::ed25519::PublicKey(*key)
                        .to_string()
                        .as_str(),
                )
                .map(Vec::as_slice)
            })
            .ok_or_else(unobserved)?;
        Ok((membership, client))
    }

    /// Refuses an effect the wallet cannot value unless the first rule that
    /// matches `descriptor` sets `allow_opaque_signing`.
    fn sep43_require_opt_in(
        &self,
        descriptor: &ToolDescriptor,
        subject: &str,
        effect: UnvaluedEffect,
    ) -> Result<(), ToolError> {
        if self.policy_engine.opaque_signing_opted_in(descriptor) {
            return Ok(());
        }
        Err(unsizable(format!(
            "the {subject} holds an effect the wallet cannot value ({}); the rule for this \
             tool does not set allow_opaque_signing",
            effect.label()
        )))
    }

    /// Decides each payment leg under the rule of its route in `snapshot` and
    /// stages the returned effects of every allowed leg in `gated`.
    ///
    /// `spent_stroops` is the native amount the wallet already pays, such as
    /// the fee. Each native debit reduces the balance later legs see. A
    /// wallet account the profile names is read once; each recipient base
    /// account at most once. Without a leg, nothing is read.
    ///
    /// An approval requirement of a leg is returned with the `approvable`
    /// shape; without one it refuses with
    /// `policy.approval_required_unsupported`. `client` is an endpoint this
    /// call already probed.
    #[allow(
        clippy::too_many_arguments,
        reason = "one frame of the effects decision"
    )]
    async fn sep43_decide_legs<'shape>(
        &self,
        payment_legs: Vec<&ValuedOperation>,
        chain_id: &str,
        mut spent_stroops: i128,
        approvable: Option<&'shape Approvable>,
        snapshot: &GateSnapshot,
        client: Option<StellarRpcClient>,
        gated: &mut Sep43Effects,
    ) -> Result<Option<OperationRequirement<'shape>>, ToolError> {
        let mut operation_requirement = None;
        if payment_legs.is_empty() {
            return Ok(operation_requirement);
        }
        let wallet = stellar_strkey::ed25519::PublicKey::from_string(
            &self.profile.mcp_signer_default.account,
        )
        .ok();
        let client = match client {
            Some(client) => client,
            None => self.sep43_probed_client().await?,
        };
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
                // An approvable transaction holds this one leg.
                Decision::RequireApproval(request) => match approvable {
                    Some(shape) => {
                        operation_requirement = Some((
                            (request, evaluation.governing_ttl_ms),
                            evaluation.value_effects.clone(),
                            shape,
                        ));
                    }
                    None => return Err(refusal(single_shot_require_approval_error())),
                },
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
        Ok(operation_requirement)
    }

    /// Stores the pending approval of an approvable transaction and returns
    /// the approval response. The summary values come from the envelope.
    fn sep43_pending_approval(
        &self,
        transaction_xdr: &str,
        shape: &Approvable,
        request: &ApprovalRequest,
        created_at_ms: u64,
        governing_ttl_ms: u64,
    ) -> Result<CallToolResult, ToolError> {
        let profile_name = self.profile_name_for_approval();
        let entry = match shape {
            Approvable::Send {
                destination,
                asset,
                amount_stroops,
                fee_stroops,
                seq_num,
            } => self
                .persist_send_pending_approval(
                    transaction_xdr,
                    destination,
                    asset,
                    *amount_stroops,
                    *fee_stroops,
                    *seq_num,
                    &profile_name,
                    request,
                    None,
                )
                .map_err(store_error)?,
            Approvable::Payment => {
                let expires_at_ms = created_at_ms
                    .checked_add(governing_ttl_ms)
                    .ok_or_else(|| store_error("the approval lifetime overflows"))?;
                self.persist_pay_pending_approval(
                    transaction_xdr,
                    created_at_ms,
                    expires_at_ms,
                    &profile_name,
                    request,
                    crate::tools::pay::PaymentQueue::Forced,
                )
                .map_err(|error| {
                    match crate::tools::common::payment_recovery_wire_error(&error, &profile_name) {
                        Some(result) => refusal(result),
                        None => store_error(error),
                    }
                })?
            }
            Approvable::Trustline {
                holder,
                asset_code,
                asset_issuer,
                limit_stroops,
                fee_stroops,
                seq_num,
            } => self
                .persist_trustline_pending_approval(
                    transaction_xdr,
                    holder,
                    asset_code,
                    asset_issuer,
                    *limit_stroops,
                    *fee_stroops,
                    *seq_num,
                    &profile_name,
                    request,
                    None,
                )
                .map_err(store_error)?,
        };
        let approval = serde_json::json!({
            "approval_nonce": entry.approval_nonce,
            "profile": &profile_name,
            "chain_id": self.context.chain_id.caip2_str(),
            "expires_at_unix_ms": entry.expires_at_unix_ms,
            "reason": entry.reason,
            "instructions": format!(
                "Run {} in a terminal, then repeat this call with approval_nonce and \
                 approval_attestation",
                stellar_agent_core::approval::approve_hint(&entry.approval_nonce, &profile_name)
            ),
        });
        let text = stellar_agent_core::envelope::Envelope::ok(serde_json::json!({
            "approval": approval
        }))
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Spends the verified approval `nonce` on the signed envelope of a
    /// sign-only call before its signature is returned.
    ///
    /// The store's writer lock covers the liveness check and the tombstone,
    /// so one approval releases one signature.
    ///
    /// # Errors
    ///
    /// `submission.record_unavailable` when the hash, the store or the
    /// tombstone fails, or the entry is no longer live.
    pub(crate) fn sep43_spend_approval(
        &self,
        nonce: &str,
        signed_xdr: &str,
    ) -> Result<(), CallToolResult> {
        use stellar_agent_core::approval::{
            ApprovalKind, ConsumedOutcome, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF,
            open_with_retry,
        };
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
        let unavailable = |detail: String| {
            business_error_result(
                "submission.record_unavailable",
                format!("the approval cannot be spent, so the signature is withheld: {detail}"),
            )
        };
        let envelope = TransactionEnvelope::from_xdr_base64(signed_xdr, Limits::none())
            .map_err(|error| unavailable(error.to_string()))?;
        let tx_hash = stellar_agent_network::submit::compute_local_tx_hash_hex(
            &envelope,
            self.context.network_passphrase(),
        )
        .map_err(|error| unavailable(error.to_string()))?;
        let path = self
            .resolve_approval_dir()
            .map_err(|error| unavailable(error.to_string()))?
            .join(format!("{}.toml", self.profile_name_for_approval()));
        let mut store = open_with_retry(&path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|error| unavailable(error.to_string()))?;
        let live = store.get(nonce).is_some_and(|entry| {
            !matches!(
                entry.kind,
                ApprovalKind::Consumed { .. } | ApprovalKind::Rejected { .. }
            )
        });
        if !live {
            return Err(unavailable("the approval is no longer pending".to_owned()));
        }
        #[cfg(test)]
        if tests::SPEND_FAULT.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(unavailable("injected tombstone fault".to_owned()));
        }
        store
            .consume(nonce, &tx_hash, ConsumedOutcome::Unknown)
            .map(drop)
            .map_err(|error| unavailable(error.to_string()))
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
