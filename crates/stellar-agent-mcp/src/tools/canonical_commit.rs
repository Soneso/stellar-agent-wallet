//! The commit of a canonical classic operation.
//!
//! A canonical preparation stores the lasting intent under its business id.
//! The commit looks the id up, rebuilds the envelope from the stored intent
//! with a fresh sequence, deadline and oracle witness at the prepared
//! envelope's fee per operation, and signs under the authority of the stored
//! record: its approval record or a fresh policy decision. The deadline is
//! the earlier of 120 seconds after the rebuild and the last whole second
//! strictly before the authority's end, which for a successor is also
//! bounded by the record's execution end. The preparation's process nonce, envelope and expiry take no
//! part, so a commit after a server restart proceeds.

use rmcp::model::{CallToolResult, Content};
use serde_json::{Value, json};
use stellar_agent_core::approval::ClassicIntent;
use stellar_agent_core::audit_log::ValueLegRecord;
use stellar_agent_core::policy::v1::AccountIdentityView;
use stellar_agent_core::profile::receipt::DestinationFields;
use stellar_agent_network::cross_check::{AccountObservation, ClassicInputs};
use stellar_agent_network::fees::ClassicFeeChoice;
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::policy_state::{BusinessId, FloorSource, OperationHandle};

use crate::server::{MainnetWriteGuard, WalletServer};
use crate::tools::common::{DispatchOutcome, SuppliedProof, ledger_err_result};

/// A canonical operation a commit continues, with its validated stored intent.
#[derive(Debug)]
pub(crate) struct CanonicalTarget {
    /// The business id the commit named, which the result echoes.
    pub(crate) business_id: BusinessId,
    /// The operation the commit begins its next attempt for.
    pub(crate) handle: OperationHandle,
    /// The stored intent the envelope is rebuilt from.
    pub(crate) intent: ClassicIntent,
}

/// The facts of one tool's canonical commit.
pub(crate) struct CanonicalCommit<'a> {
    /// The mainnet consumer the signing runs under.
    pub(crate) consumer: MainnetConsumer,
    /// The preparation tool, whose decision the commit's stricter one joins.
    pub(crate) prepare_tool: &'static str,
    /// The commit tool.
    pub(crate) commit_tool: &'static str,
    /// The call's chain id.
    pub(crate) chain_id: &'a str,
    /// The call's approval proof.
    pub(crate) proof: SuppliedProof,
    /// The oracle observations of the operation; the rebuild replaces the
    /// source observation with its own read.
    pub(crate) witness_inputs: ClassicInputs,
    /// The account the policy's identity criteria read: a payment's
    /// destination base account; `None` for the other tools and for a
    /// destination that does not exist.
    pub(crate) identity_view: Option<&'a dyn AccountIdentityView>,
    /// Whether the commit is a payment, whose audit legs record the SHA-256
    /// of the complete destination and whose result names the destination of
    /// the sent envelope.
    pub(crate) payment: bool,
}

/// The source observation a commit hands to the rebuild, which replaces it
/// with the account it reads.
pub(crate) fn placeholder_source(intent: &ClassicIntent) -> AccountObservation {
    AccountObservation {
        account_id: intent.base().source().to_owned(),
        sequence: 0,
        native_balance: 0,
        subentry_count: 0,
        flags: None,
    }
}

impl WalletServer {
    /// The primary client, once its endpoint proved to serve the profile's
    /// network, and the canonical operation a commit under `business_id`
    /// continues: [`WalletServer::canonical_commit_target`] after the probe,
    /// as the envelope route looks its record up after the probe.
    ///
    /// # Errors
    ///
    /// The call's whole answer: the client and probe refusals, and the
    /// lookup's.
    pub(crate) async fn canonical_entry(
        &self,
        guard: &MainnetWriteGuard<'_>,
        business_id: BusinessId,
        source: &str,
        matches: impl FnOnce(&ClassicIntent) -> bool,
    ) -> Result<
        (stellar_agent_network::StellarRpcClient, CanonicalTarget),
        Result<CallToolResult, rmcp::ErrorData>,
    > {
        let client = match self.write_primary_client() {
            Ok(client) => client,
            Err(error) => return Err(crate::tools::common::rpc_client_failure(&error)),
        };
        if let Err(error) = self
            .probe_write_endpoint(
                &client,
                tokio::time::Instant::now() + stellar_agent_network::PRE_SEND_BUDGET,
            )
            .await
        {
            return Err(Ok(crate::tools::common::endpoint_refusal_result(&error)));
        }
        let target = self
            .canonical_commit_target(guard.policy, business_id, source, matches)
            .map_err(Ok)?;
        Ok((client, target))
    }

    /// Commits `target` under `guard` through `client`, the endpoint the
    /// call probed.
    ///
    /// The envelope is rebuilt from the stored intent. The fee per operation
    /// is the one of the prepared envelope the record stores; a fee above the
    /// current caps refuses as on the envelope route. The
    /// policy gate evaluates the rebuilt envelope's arguments with the source
    /// read before the rebuild, which requests a trustline intent's trustline
    /// as the envelope route does, and a payment's destination view; the
    /// stricter of the commit's and the preparation's decisions governs. A
    /// proof must be the consent to the stored intent. The signed deadline is
    /// the earlier of 120 seconds after the rebuild and the last whole second
    /// strictly before the authority's end, which for a successor is also
    /// bounded by the record's execution end. The authorization is minted
    /// inside the attempt's begin.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result: the rebuild's endpoint, fee
    /// and oracle refusals, the policy and authority refusals, and the
    /// submission's refusals. A field the rebuilt envelope does not carry as
    /// the stored intent states renders `simulation.divergence`.
    pub(crate) async fn canonical_commit(
        &self,
        guard: &MainnetWriteGuard<'_>,
        client: &stellar_agent_network::StellarRpcClient,
        target: &CanonicalTarget,
        commit: CanonicalCommit<'_>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let profile = self.security_profile();
        let intent = &target.intent;
        // The rebuild pays the fee per operation of the prepared envelope the
        // record stores, which the current caps still bound as on the
        // envelope route.
        let prepared_fee = match stellar_agent_network::operation_entry::envelope_facts(
            target.handle.envelope_xdr().unwrap_or_default(),
        ) {
            Ok(facts) => facts.fee_per_op_stroops,
            Err(error) => return Ok(ledger_err_result(&error)),
        };
        if let Err(error) =
            self.check_write_fee(prepared_fee, stellar_agent_core::error::FeeSource::Envelope)
        {
            return Ok(ledger_err_result(&error));
        }
        let fee_cap = match stellar_agent_network::operation_entry::fee_bound(
            profile.classic_max_fee_per_op_stroops,
            self.signed_classic_fee_cap(),
            ClassicFeeChoice::ProfileDefault,
        ) {
            Ok(cap) => cap,
            Err(error) => return Ok(ledger_err_result(&error)),
        };
        // A trustline intent requests its trustline in every source read, so
        // the gate counts no reserve for one the account already holds.
        let requested = match intent.payload() {
            stellar_agent_core::approval::IntentPayload::Trustline { issuer, code, .. } => {
                stellar_agent_network::Asset::trustline_request(code, issuer)
            }
            _ => Vec::new(),
        };
        // The rebuild reads the source once the endpoint shows the sequence
        // this process last confirmed for it, as the envelope route reads it.
        // This read is the policy gate's account view.
        let source_view = match crate::sequence_floor::fetch_account_with_sequence_catchup(
            &self.sequence_floor,
            client,
            intent.base().source(),
            &requested,
        )
        .await
        {
            Ok(view) => view,
            Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
        };
        let network = guard.context.network_context();
        let thresholds = self.mainnet_thresholds(guard.context);
        let rebuild = |authority_end_ms: u64| {
            stellar_agent_network::operation_entry::rebuild_canonical(
                stellar_agent_network::operation_entry::CanonicalRebuildRequest {
                    profile: guard.context.profile(),
                    network: &network,
                    client,
                    deadline: stellar_agent_network::operational::readiness_deadline(),
                    intent,
                    fee_choice: ClassicFeeChoice::ProfileDefault,
                    default_fee_per_op_stroops: prepared_fee,
                    fee_cap_stroops: fee_cap,
                    witness_inputs: commit.witness_inputs.clone(),
                    thresholds: &thresholds,
                    tool: commit.commit_tool,
                    authority_end_ms,
                },
            )
        };
        // The policy gate reads this rebuild's arguments; the
        // authority, and so its end, is known only after the gate.
        let rebuilt = match rebuild(u64::MAX).await {
            Ok(rebuilt) => rebuilt,
            Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
        };
        let envelope = rebuilt.unsigned_envelope_b64.as_str();
        // The builder's output decodes; the gate reads its arguments.
        let mut args = stellar_agent_core::envelope_decode::decode_authoritative_args(
            envelope,
            commit.commit_tool,
        )
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        args["chain_id"] = serde_json::Value::String(commit.chain_id.to_owned());
        let floor = match self
            .classic_floor_source_requesting(
                client,
                &rebuilt.account.account_id,
                &requested,
                &[commit.commit_tool, commit.prepare_tool],
            )
            .await
        {
            Ok(floor) => floor,
            Err(error) => return error.into_result(),
        };
        let adapter = crate::policy_adapter::AccountViewAdapter::new(&source_view);
        let view = FloorSource::view_or(floor.as_ref(), &adapter);
        let identity_view = commit.identity_view;
        let outcome = match self
            .dispatch_gate_with_views(
                commit.commit_tool,
                &args,
                commit.chain_id,
                Some(view),
                identity_view,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        let outcome = match self
            .commit_governing_outcome(
                outcome,
                commit.prepare_tool,
                &args,
                commit.chain_id,
                Some(view),
                identity_view,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => return error.into_result(),
        };
        let mut witness = None;
        let expected = stellar_agent_core::approval::witness::ApprovalExpectation {
            kind: intent.approved_kind(),
            subject: *intent.digest().as_bytes(),
        };
        let authority = match crate::tools::common::mainnet_authority(
            self,
            &outcome,
            expected,
            Some(intent),
            &commit.proof,
            Some(target.handle.id()),
            commit.commit_tool,
            &mut witness,
        )
        .await
        {
            Ok(authority) => authority,
            Err(refusal) => {
                return Ok(crate::tools::common::authority_refusal_result(
                    self, refusal,
                ));
            }
        };
        // The signed deadline is the earlier of 120 seconds after the rebuild
        // and the last whole second strictly before the authority's end: an
        // approval's execution end, or a policy decision's governing end. The
        // authority holds strictly before its end, and a ledger closing at
        // the deadline can include the transaction. A later deadline rebuilds
        // under that end.
        // A successor also stays inside the record's execution window, which
        // the first attempt's authority set.
        let authority_end_ms = match &authority {
            stellar_agent_network::mainnet::authority::MainnetAuthority::Approval(approval) => {
                approval.expires_at_ms()
            }
            stellar_agent_network::mainnet::authority::MainnetAuthority::Policy(policy) => {
                policy.governing_until_ms()
            }
        }
        .min(target.handle.execution_expires_at_ms().unwrap_or(u64::MAX));
        let rebuilt = if rebuilt.max_time_s > authority_end_ms.saturating_sub(1) / 1000 {
            match rebuild(authority_end_ms).await {
                Ok(rebuilt) => rebuilt,
                Err(error) => return Ok(crate::tools::common::endpoint_refusal_result(&error)),
            }
        } else {
            rebuilt
        };
        let envelope = rebuilt.unsigned_envelope_b64.as_str();
        let effects = match &outcome {
            DispatchOutcome::Allow(allowed) => allowed.value_effects.clone(),
            DispatchOutcome::RequireApproval(approval) => approval.value_effects.clone(),
        };
        let legs = effects
            .as_ref()
            .map_or(&[][..], |effects| effects.legs())
            .iter()
            .map(|leg| {
                if commit.payment && leg.destination.is_some() {
                    ValueLegRecord::from_payment_leg(leg)
                } else {
                    Ok(leg.into())
                }
            })
            .collect::<Result<Vec<_>, _>>();
        let legs = match legs {
            Ok(legs) => legs,
            Err(error) => return Ok(ledger_err_result(&error)),
        };
        let (audit_writer, readiness) = match self.write_audit() {
            Ok(write) => write,
            Err(error) => return Ok(ledger_err_result(&error)),
        };
        let now_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let floor_hook = crate::sequence_floor::hook(&self.sequence_floor);
        let submitted = crate::tools::submission_record::sign_and_submit_classic(
            self,
            Some(guard),
            Some(&authority),
            readiness,
            commit.consumer,
            client,
            envelope,
            intent.base().source(),
            crate::tools::submission_record::CommitRecord {
                policy_decision: outcome.audit_decision(),
                profile,
                profile_name: self.profile_name_for_approval(),
                tool: commit.commit_tool,
                chain_id: commit.chain_id.to_owned(),
                legs,
                engine: self.policy_engine.as_ref(),
                registry: &self.tool_registry,
                value_class: effects.map_or(
                    stellar_agent_core::policy::v1::ValueClass::ReadOnly,
                    stellar_agent_core::policy::v1::ValueClass::Value,
                ),
                audit: std::sync::Arc::clone(&audit_writer),
                nonce_id: None,
                approval_nonce: commit.proof.nonce.clone(),
                approval_dir: self.resolve_approval_dir().ok(),
                now_ms,
                provenance: outcome
                    .mainnet_decision()
                    .map(stellar_agent_core::mainnet::decision::MainnetDecision::provenance),
            },
            rebuilt.cross_check.witness(),
            Some(&floor_hook),
            Some(&target.handle),
            None,
        )
        .await;
        let result = match submitted {
            Ok(result) => result,
            Err(result) => return Ok(result),
        };
        let mut view = json!({
            "tx_hash": result.tx_hash,
            "ledger": result.ledger,
            "cross_check": rebuilt.cross_check.view(),
        });
        if commit.payment
            && let (Some(view), Ok(Value::Object(fields))) = (
                view.as_object_mut(),
                serde_json::to_value(DestinationFields(
                    stellar_agent_network::operation_entry::envelope_result_destinations(envelope),
                )),
            )
        {
            view.extend(fields);
        }
        crate::tools::business_entry::echo_business_id(&mut view, Some(&target.business_id));
        let json = stellar_agent_core::envelope::Envelope::ok(view)
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}
