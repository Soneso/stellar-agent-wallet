//! Mainnet proof resolution and one-use intent continuation.
//!
//! A consumed intent receipt cannot be copied to create another continuation.
//! ```compile_fail
//! use stellar_agent_network::mainnet::resolve::IntentUseReceipt;
//! fn requires_clone<T: Clone>() {}
//! requires_clone::<IntentUseReceipt>();
//! ```

use super::audit_readiness::AuditReadiness;
use super::authorization::{
    MainnetMessageSignAuthorization, MainnetSignedSorobanIntent, MainnetSorobanIntentAuthorization,
    MainnetSubmitAuthorization, MainnetTxSignAuthorization,
};
use super::message::{MessageFacts, MessageUseReceipt};
use super::{AuthorizationId, MainnetAuthorizationError, MainnetConsumer};
use crate::{
    MainnetWriteContext, StellarRpcClient, cross_check::CrossCheckWitness, keyring::EnrolledSigner,
    policy_state::PersistedWindowStore,
};
use std::time::Duration;
use stellar_agent_core::approval::witness::{ApprovalWitness, ApprovedKind};
use stellar_agent_core::mainnet::{enablement::EnablementRecord, verified_policy::VerifiedPolicy};
use stellar_xdr::{SorobanAuthorizationEntry, SorobanAuthorizedInvocation};

/// Default lifetime of a mainnet authorization, in seconds.
pub const MAINNET_AUTHORIZATION_TTL_SECONDS_DEFAULT: u32 = 120;
/// Maximum age of an audit readiness proof, in seconds.
pub const MAINNET_AUDIT_READINESS_TTL_SECONDS: u64 = 120;

/// The tools and the approval kind of one classic consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassicConsumerTools {
    /// The tool name `decode_authoritative_args` decodes the consumer's
    /// envelope under.
    pub decoder_tool: &'static str,
    /// The tool name the policy evaluates the consumer's operation under.
    pub policy_tool: &'static str,
    /// The approval kind that approves the consumer's operation.
    pub approved_kind: ApprovedKind,
}

/// The consumer table: the tools and the approval kind of each classic
/// consumer, and `None` for a consumer of another domain.
///
/// The resolver and the CLI confirmation read the one table, so an approval
/// the confirmation writes has the kind the resolver expects.
#[must_use]
pub fn classic_consumer_tools(consumer: MainnetConsumer) -> Option<ClassicConsumerTools> {
    let (decoder_tool, policy_tool, approved_kind) = match consumer {
        MainnetConsumer::CliPay => ("stellar_pay_commit", "stellar_pay", ApprovedKind::Payment),
        MainnetConsumer::CliCreateAccount => (
            "stellar_create_account_commit",
            "stellar_create_account",
            ApprovedKind::Payment,
        ),
        MainnetConsumer::CliTrustline => (
            "stellar_trustline_commit",
            "stellar_trustline",
            ApprovedKind::Trustline,
        ),
        MainnetConsumer::CliClaim => ("stellar_claim_commit", "stellar_claim", ApprovedKind::Claim),
        MainnetConsumer::McpPay => (
            "stellar_pay_commit",
            "stellar_pay_commit",
            ApprovedKind::Payment,
        ),
        MainnetConsumer::McpCreateAccount => (
            "stellar_create_account_commit",
            "stellar_create_account_commit",
            ApprovedKind::Payment,
        ),
        MainnetConsumer::McpTrustline => (
            "stellar_trustline_commit",
            "stellar_trustline_commit",
            ApprovedKind::Trustline,
        ),
        MainnetConsumer::McpClaim => (
            "stellar_claim_commit",
            "stellar_claim_commit",
            ApprovedKind::Claim,
        ),
        _ => return None,
    };
    Some(ClassicConsumerTools {
        decoder_tool,
        policy_tool,
        approved_kind,
    })
}

/// Inputs for resolving one classic transaction signing.
pub struct TxSignRequest<'a> {
    /// Validated stored profile and endpoint.
    pub context: &'a MainnetWriteContext,
    /// The verb that will consume the authorization.
    pub consumer: MainnetConsumer,
    /// Unsigned envelope as base64 text.
    pub unsigned_envelope_xdr: &'a str,
    /// The context's primary client.
    pub client: &'a StellarRpcClient,
    /// Budget for the endpoint identity probe.
    pub probe_deadline: Duration,
    /// Independent observation bound to the transaction.
    pub witness: Option<&'a CrossCheckWitness>,
    /// Enrolled signer identity, without signing-key access.
    pub signer: &'a EnrolledSigner,
    /// Verified signed policy.
    pub policy: &'a VerifiedPolicy,
    /// Enablement bound to the signed policy.
    pub enablement: &'a EnablementRecord,
    /// Operator approval of the envelope.
    pub approval: &'a ApprovalWitness,
    /// Anchored audit writer lease.
    pub audit: AuditReadiness,
    /// Durable holds and authorization store.
    pub store: &'a PersistedWindowStore,
}

/// The network-bound invocation a Soroban payment authorizes.
pub struct SorobanIntent<'a> {
    /// The consuming x402 verb.
    pub consumer: MainnetConsumer,
    /// Exactly one token transfer with no sub-invocations.
    pub root_invocation: &'a SorobanAuthorizedInvocation,
    /// SHA-256 of the network passphrase.
    pub network_id: [u8; 32],
}

/// Inputs for resolving a Soroban payment intent.
pub struct SorobanIntentRequest<'a> {
    /// Validated stored profile and endpoint.
    pub context: &'a MainnetWriteContext,
    /// Payment intent derived from the enrolled public key.
    pub intent: &'a SorobanIntent<'a>,
    /// The nonce of the authorization entry the signing must carry.
    pub nonce: i64,
    /// The signature expiration ledger of the authorization entry the
    /// signing must carry.
    pub signature_expiration_ledger: u32,
    /// The context's primary client.
    pub client: &'a StellarRpcClient,
    /// Budget for the endpoint identity probe.
    pub probe_deadline: Duration,
    /// Independent observation bound to the intent.
    pub witness: Option<&'a CrossCheckWitness>,
    /// Enrolled signer identity.
    pub signer: &'a EnrolledSigner,
    /// Verified signed policy.
    pub policy: &'a VerifiedPolicy,
    /// Enablement bound to the signed policy.
    pub enablement: &'a EnablementRecord,
    /// Operator approval of the intent.
    pub approval: &'a ApprovalWitness,
    /// Anchored audit writer lease.
    pub audit: AuditReadiness,
    /// Durable holds and authorization store.
    pub store: &'a PersistedWindowStore,
    /// The consumed SEP-10 message authorization an authenticated payment
    /// continues: `Some` exactly for the
    /// [`MainnetConsumer::X402Authenticated`] consumer, whose intent record
    /// names the used message record as its parent. Borrowed, not consumed.
    pub authenticated: Option<&'a MessageUseReceipt>,
}

/// Inputs for resolving one SEP-10 challenge signing for an authenticated
/// x402 payment.
///
/// The request names no client, endpoint, witness, or enrolled signer: a
/// message signing reaches no RPC endpoint, binds no endpoint, and its signer
/// is the ephemeral key the message facts name. The context supplies the
/// profile name and the stored profile.
pub struct MessageSignRequest<'a> {
    /// Validated stored profile.
    pub context: &'a MainnetWriteContext,
    /// The verb that will consume the authorization.
    pub consumer: MainnetConsumer,
    /// The payment intent the operator approved together with the message.
    pub intent: &'a SorobanIntent<'a>,
    /// The challenge facts the SEP-10 client proposes.
    pub message: &'a MessageFacts,
    /// Verified signed policy.
    pub policy: &'a VerifiedPolicy,
    /// Enablement bound to the signed policy.
    pub enablement: &'a EnablementRecord,
    /// Operator approval of the authenticated payment.
    pub approval: &'a ApprovalWitness,
    /// Anchored audit writer lease.
    pub audit: AuditReadiness,
    /// Durable authorization store.
    pub store: &'a PersistedWindowStore,
}

/// Proof that an intent was consumed, retaining its audit lease and debit.
pub struct IntentUseReceipt {
    #[cfg(feature = "mainnet-write")]
    header: super::authorization::Header,
    #[cfg(feature = "mainnet-write")]
    intent: [u8; 32],
    #[cfg(feature = "mainnet-write")]
    root: [u8; 32],
    #[cfg(feature = "mainnet-write")]
    facts: super::digest::BindingFacts,
    #[cfg(feature = "mainnet-write")]
    authorization_ttl_ms: u64,
    #[cfg(not(feature = "mainnet-write"))]
    never: Never,
}
#[cfg(not(feature = "mainnet-write"))]
enum Never {}

impl std::fmt::Debug for IntentUseReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "mainnet-write")]
        {
            f.debug_struct("IntentUseReceipt").finish_non_exhaustive()
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            let _ = f;
            match self.never {}
        }
    }
}

/// Inputs for deriving a final payload authorization from a consumed intent.
pub struct SorobanSubmitRequest<'a> {
    /// The stored mainnet profile.
    pub context: &'a MainnetWriteContext,
    /// Consumed intent, moved into this continuation.
    pub receipt: IntentUseReceipt,
    /// Final envelope as base64 text.
    pub final_envelope_xdr: &'a str,
    /// Signed authorization entries expected in the final envelope.
    pub signed_auth_entries: &'a [SorobanAuthorizationEntry],
    /// Durable authorization store.
    pub store: &'a PersistedWindowStore,
}

/// Resolves checked proofs into authority to sign one classic transaction.
///
/// # Errors
/// Returns a logged authorization refusal or the policy's denial code.
pub async fn resolve_tx_sign(
    req: TxSignRequest<'_>,
) -> Result<MainnetTxSignAuthorization, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        let mut detail = None;
        let result = enabled::tx(req, &mut detail).await;
        report_detail("resolve_tx_sign", result, detail.as_deref())
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        req.context.absurd()
    }
}

/// Resolves checked proofs into authority to sign one Soroban payment intent.
///
/// # Errors
/// Returns a logged authorization refusal or the policy's denial code.
pub async fn resolve_soroban_intent(
    req: SorobanIntentRequest<'_>,
) -> Result<MainnetSorobanIntentAuthorization, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report("resolve_soroban_intent", enabled::intent(req).await)
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        req.context.absurd()
    }
}

/// Consumes a signed intent once and retains its debit before payload
/// construction.
///
/// It takes the [`MainnetSignedSorobanIntent`] the authorized signing
/// returned, so the intent it consumes is one whose single signature was
/// produced.
///
/// # Errors
/// Refuses changed intent or audit facts, and failed store transitions.
pub fn consume_soroban_intent(
    context: &MainnetWriteContext,
    auth: MainnetSignedSorobanIntent,
    intent: &SorobanIntent<'_>,
    store: &PersistedWindowStore,
) -> Result<IntentUseReceipt, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report(
            "consume_soroban_intent",
            enabled::consume_intent(context, auth, intent, store),
        )
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = (auth, intent, store);
        context.absurd()
    }
}

/// Resolves checked proofs into authority to sign one SEP-10 challenge for an
/// authenticated x402 payment.
///
/// The checks run in this order: the clock; both consumers are
/// [`MainnetConsumer::X402Authenticated`]; the policy has a mainnet body
/// bound to the context's profile and the enablement; the intent is for the
/// mainnet network id and its digest encodes; the approval is the profile's,
/// for mainnet, of the x402 kind, for the authenticated subject over the
/// intent digest and the message's home domain, created no later than now
/// and not expired; the audit lease is the profile's and fresh. The mint then
/// records a zero-value message record with no holds and no parent. The
/// resolver evaluates no policy and makes no network request.
///
/// # Errors
/// Returns a logged authorization refusal: the first failed check, or the
/// store's refusal of the mint. A store failure refuses with
/// `StoreUnavailable`.
#[cfg_attr(
    not(feature = "mainnet-write"),
    expect(
        clippy::needless_pass_by_value,
        reason = "the request is consumed by the enabled API"
    )
)]
pub fn resolve_message_sign(
    req: MessageSignRequest<'_>,
) -> Result<MainnetMessageSignAuthorization, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report("resolve_message_sign", enabled::message(req))
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        req.context.absurd()
    }
}

/// Consumes a message authorization once and returns the receipt of its
/// bound facts.
///
/// The consume proves durable single use: it rechecks the audit lease and
/// moves the record to used with a message consumption binding. It compares
/// no challenge; the signing point checks the challenge against the receipt.
/// A refused consume invalidates the record with the reason
/// `consume_refused`; a record already settled or unknown is left as it is,
/// and a cleanup that fails is logged and never replaces the refusal.
///
/// # Errors
/// Returns the logged refusal: a binding of another domain, changed audit
/// provenance or an uncovered tip, and every refusal of the store's consume.
pub fn consume_message_sign(
    context: &MainnetWriteContext,
    auth: MainnetMessageSignAuthorization,
    store: &PersistedWindowStore,
) -> Result<MessageUseReceipt, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        enabled::consume_message(context, auth, store)
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = (auth, store);
        context.absurd()
    }
}

/// Derives a one-use final payload authorization from the consumed intent.
///
/// # Errors
/// Refuses a changed derivation, authorization entries, or parent record.
#[cfg_attr(
    not(feature = "mainnet-write"),
    expect(
        clippy::needless_pass_by_value,
        reason = "the receipt is consumed by the enabled API"
    )
)]
pub fn resolve_soroban_submit(
    req: SorobanSubmitRequest<'_>,
) -> Result<MainnetSubmitAuthorization, MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report("resolve_soroban_submit", enabled::submit(req))
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        req.context.absurd()
    }
}

/// Consumes the final payload authorization before releasing its bytes.
///
/// # Errors
/// Refuses changed payload or audit facts, and failed store transitions.
#[cfg_attr(
    feature = "mainnet-write",
    expect(
        clippy::needless_pass_by_value,
        reason = "taking the authorization by value makes it one-use"
    )
)]
pub fn consume_soroban_submit(
    context: &MainnetWriteContext,
    auth: MainnetSubmitAuthorization,
    final_envelope_xdr: &str,
    store: &PersistedWindowStore,
) -> Result<(), MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report(
            "consume_soroban_submit",
            enabled::consume_submit(context, &auth, final_envelope_xdr, store),
        )
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = (auth, final_envelope_xdr, store);
        context.absurd()
    }
}

/// The stage at which an unused authorization became unusable.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum InvalidationStage {
    /// The signing handle could not be opened.
    SignerUnavailable,
    /// Signing refused.
    SignRefused,
    /// Preparation refused before transmission.
    PreSendRefused,
    /// The submit gate refused.
    SubmitGateRefused,
    /// Intent preparation refused before transmission.
    IntentPreTransmitRefused,
    /// Intent consumption refused.
    IntentConsumeRefused,
    /// Final payload release refused.
    PayloadReleaseRefused,
    /// The consumption of a message authorization refused.
    ConsumeRefused,
}
impl InvalidationStage {
    #[cfg(feature = "mainnet-write")]
    fn reason(self) -> &'static str {
        match self {
            Self::SignerUnavailable => "signer_unavailable",
            Self::SignRefused => "sign_refused",
            Self::PreSendRefused => "pre_send_refused",
            Self::SubmitGateRefused => "submit_gate_refused",
            Self::IntentPreTransmitRefused => "intent_pre_transmit_refused",
            Self::IntentConsumeRefused => "intent_consume_refused",
            Self::PayloadReleaseRefused => "payload_release_refused",
            Self::ConsumeRefused => "consume_refused",
        }
    }
}

/// Invalidates an open authorization, releasing its unused holds.
///
/// # Errors
/// Returns `NotOpen` for a settled record, or the store's refusal.
pub fn invalidate_unconsumed(
    store: &PersistedWindowStore,
    context: &MainnetWriteContext,
    id: AuthorizationId,
    stage: InvalidationStage,
) -> Result<(), MainnetAuthorizationError> {
    #[cfg(feature = "mainnet-write")]
    {
        report(
            "invalidate_unconsumed",
            invalidate(store, context, id, stage),
        )
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = (store, id, stage);
        context.absurd()
    }
}

/// The invalidation [`invalidate_unconsumed`] reports: `NotOpen` for a
/// settled record, the store's refusal otherwise. Logs nothing.
#[cfg(feature = "mainnet-write")]
fn invalidate(
    store: &PersistedWindowStore,
    context: &MainnetWriteContext,
    id: AuthorizationId,
    stage: InvalidationStage,
) -> Result<(), MainnetAuthorizationError> {
    store
        .invalidate_authorization(context.profile(), id, stage.reason())
        .map_err(super::mint::store_error)
        .and_then(|changed| super::refusal::require(changed, super::MainnetPrecondition::NotOpen))
}

/// Invalidates the message record `id` after its consume refused.
///
/// A used, expired, or invalidated record (`NotOpen`) and an unknown record
/// are left as they are, silently. Any other failure, such as an I/O,
/// keyring, lock, or integrity failure of the store, is logged once at warn
/// as a cleanup failure and leaves the record open until its lifetime ends;
/// the caller returns its own refusal either way.
#[cfg(feature = "mainnet-write")]
pub(crate) fn invalidate_after_refused_consume(
    store: &PersistedWindowStore,
    context: &MainnetWriteContext,
    id: AuthorizationId,
) {
    use super::MainnetPrecondition as P;
    match invalidate(store, context, id, InvalidationStage::ConsumeRefused) {
        Ok(()) | Err(MainnetAuthorizationError::Refused(P::NotOpen | P::UnknownAuthorization)) => {}
        Err(error) => {
            // An invalidation admits no holds, so its only failures are
            // refusals; the store's own failures arrive as `StoreUnavailable`.
            let precondition = match &error {
                MainnetAuthorizationError::Refused(precondition) => precondition.label(),
                _ => P::StoreUnavailable.label(),
            };
            tracing::warn!(
                path = "consume_message_sign",
                precondition,
                id = ?id,
                "mainnet authorization cleanup failed"
            );
        }
    }
}

#[cfg(feature = "mainnet-write")]
fn report<T>(
    path: &'static str,
    result: Result<T, MainnetAuthorizationError>,
) -> Result<T, MainnetAuthorizationError> {
    report_detail(path, result, None)
}

#[cfg(feature = "mainnet-write")]
fn report_detail<T>(
    path: &'static str,
    result: Result<T, MainnetAuthorizationError>,
    detail: Option<&str>,
) -> Result<T, MainnetAuthorizationError> {
    if let Err(MainnetAuthorizationError::Refused(precondition)) = &result {
        tracing::warn!(
            path,
            precondition = precondition.label(),
            detail,
            "mainnet authorization refused"
        );
    }
    result
}

#[cfg(feature = "mainnet-write")]
mod enabled {
    use super::super::{
        AuthorizationDomain, MainnetPrecondition as P, RecomputedFacts,
        authorization::{SorobanIntentInner, SubmitInner, TxSignInner},
        digest::{BindingFacts, content_digest, entries_digest},
        mint,
        refusal::require,
    };
    use super::*;
    use crate::{
        account::fetch_account,
        endpoint_identity::EndpointIdentity,
        keyring::EnrolledRole,
        policy_state::{ConsumptionBinding, DomainBinding, MintRequest},
        policy_view::AccountViewAdapter,
    };
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::{
        approval::{
            store::governing_ttl_ms,
            subject::{
                approval_subject_classic, approval_subject_x402,
                approval_subject_x402_authenticated, root_invocation_digest, soroban_intent_digest,
            },
            witness::ApprovedKind,
        },
        asset_id::CanonicalAsset,
        cross_check::{
            CrossCheckRequirement, CrossCheckSkip, CrossCheckValue, ThresholdSet,
            cross_check_requirement,
        },
        envelope_decode::{MemoKind, decode_authoritative_args, payment_memo_shape},
        error::{FeeSource, NetworkError, WalletError, WitnessUnavailableReason},
        mainnet::{enablement::normalize_endpoint_host, verified_policy::MainnetBody},
        policy::{
            Decision, Evaluation, McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
            v1::{ActionKind, ValueClass, ValueLeg, criteria::state_store::WindowEntry},
        },
        profile::schema::same_provider_host,
    };
    use stellar_xdr::{
        HostFunction, MuxedAccount, OperationBody, ReadXdr as _, ScAddress, ScVal,
        SorobanAuthorizedFunction, TransactionEnvelope,
    };

    fn refused(p: P) -> MainnetAuthorizationError {
        MainnetAuthorizationError::Refused(p)
    }
    fn now() -> Result<u64, MainnetAuthorizationError> {
        super::super::clock::now_ms().map_err(|_| refused(P::ClockUnavailable))
    }
    fn decode(text: &str, p: P) -> Result<TransactionEnvelope, MainnetAuthorizationError> {
        TransactionEnvelope::from_xdr_base64(
            text,
            stellar_agent_xdr_limits::untrusted_decode_limits(text.len()),
        )
        .map_err(|_| refused(p))
    }
    fn descriptor(name: &'static str) -> ToolDescriptor {
        let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        tool.chain_id = "stellar:mainnet".to_owned();
        tool
    }
    fn classic_tools(
        consumer: MainnetConsumer,
    ) -> Result<(&'static str, &'static str, ApprovedKind), MainnetAuthorizationError> {
        let tools = classic_consumer_tools(consumer).ok_or_else(|| refused(P::ConsumerMismatch))?;
        Ok((tools.decoder_tool, tools.policy_tool, tools.approved_kind))
    }
    fn policy_body<'a>(
        context: &MainnetWriteContext,
        policy: &'a VerifiedPolicy,
        enablement: &EnablementRecord,
    ) -> Result<&'a MainnetBody, MainnetAuthorizationError> {
        let body = policy
            .mainnet()
            .ok_or_else(|| refused(P::PolicyNotMainnet))?;
        require(
            context.profile_name() == body.profile
                && context.profile_name() == enablement.profile(),
            P::ProfileMismatch,
        )?;
        require(
            enablement.policy_sequence() == policy.sequence(),
            P::EnablementSequenceMismatch,
        )?;
        Ok(body)
    }
    async fn endpoint(
        context: &MainnetWriteContext,
        client: &StellarRpcClient,
        deadline: tokio::time::Instant,
        enablement: &EnablementRecord,
    ) -> Result<EndpointIdentity, MainnetAuthorizationError> {
        let identity = client
            .mainnet_endpoint_identity(deadline)
            .await
            .map_err(|error| {
                refused(match error {
                    WalletError::Network(NetworkError::UnsupportedProtocolVersion { .. }) => {
                        P::EndpointProtocolUnsupported
                    }
                    WalletError::Network(NetworkError::EndpointNetworkMismatch { .. }) => {
                        P::EndpointNotMainnet
                    }
                    _ => P::EndpointUnavailable,
                })
            })?;
        require(
            identity.authority() == context.authority(),
            P::EndpointAuthority,
        )?;
        let host = normalize_endpoint_host(context.authority())
            .map_err(|_| refused(P::EnablementHostMismatch))?;
        let stored = normalize_endpoint_host(&context.profile().rpc_url)
            .map_err(|_| refused(P::EnablementHostMismatch))?;
        require(
            enablement.endpoint_host() == host && host == stored,
            P::EnablementHostMismatch,
        )?;
        Ok(identity)
    }
    fn check_evaluation(evaluation: &Evaluation) -> Result<ValueClass, MainnetAuthorizationError> {
        match &evaluation.decision {
            Decision::Deny(reason) => Err(MainnetAuthorizationError::PolicyDenied(Box::new(
                reason.clone(),
            ))),
            Decision::Allow | Decision::RequireApproval(_) => Ok(evaluation
                .value_effects
                .clone()
                .map_or(ValueClass::ReadOnly, ValueClass::Value)),
            _ => Err(refused(P::PolicyEvaluationFailed)),
        }
    }
    fn witness(
        context: &MainnetWriteContext,
        body: &MainnetBody,
        value: CrossCheckValue<'_>,
        memo: bool,
        content: [u8; 32],
        witness: Option<&CrossCheckWitness>,
    ) -> Result<(), MainnetAuthorizationError> {
        let thresholds = ThresholdSet::from_profile_and_signed(
            context.profile(),
            body.cross_check_thresholds.as_ref(),
        );
        let requirement = cross_check_requirement(
            context.chain(),
            value,
            &thresholds,
            context.profile().oracle_provider_url.is_some(),
            memo,
        )
        .map_err(|error| {
            refused(match error {
                NetworkError::WitnessUnavailable {
                    reason: WitnessUnavailableReason::NoThresholdForAsset { .. },
                } => P::WitnessThresholdMissing,
                _ => P::WitnessOracleMissing,
            })
        })?;
        match requirement {
            CrossCheckRequirement::Required => require(witness.is_some(), P::WitnessRequired)?,
            CrossCheckRequirement::Skipped(CrossCheckSkip::NoThresholdForAsset) => {
                return Err(refused(P::WitnessThresholdMissing));
            }
            CrossCheckRequirement::Skipped(CrossCheckSkip::OracleNotConfigured) => {
                return Err(refused(P::WitnessOracleMissing));
            }
            CrossCheckRequirement::NotRequired => {}
        }
        if let Some(witness) = witness {
            require(witness.subject() == Some(content), P::WitnessSubject)?;
            require(
                !same_provider_host(witness.authority(), context.authority()),
                P::WitnessSameHost,
            )?;
            require(
                context
                    .profile()
                    .oracle_provider_url
                    .as_ref()
                    .is_some_and(|oracle| same_provider_host(witness.authority(), oracle.as_str())),
                P::WitnessOracleUnbound,
            )?;
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "approval, audit and signer checks share one clock and context"
    )]
    pub(super) fn final_checks(
        context: &MainnetWriteContext,
        approval: &ApprovalWitness,
        subject: [u8; 32],
        kind: ApprovedKind,
        evaluation: &Evaluation,
        audit: &AuditReadiness,
        signer: &EnrolledSigner,
        now: u64,
    ) -> Result<(), MainnetAuthorizationError> {
        require(
            approval.profile() == context.profile_name(),
            P::ApprovalProfileMismatch,
        )?;
        require(approval.chain().is_mainnet(), P::ApprovalChainMismatch)?;
        require(approval.subject() == subject, P::ApprovalSubjectMismatch)?;
        require(approval.kind() == kind, P::ApprovalKindMismatch)?;
        require(approval.created_at_ms() <= now, P::NotYetValid)?;
        require(now < approval.expires_at_ms(), P::ApprovalExpired)?;
        let lifetime = approval
            .expires_at_ms()
            .checked_sub(approval.created_at_ms())
            .ok_or_else(|| refused(P::ApprovalTtlExceedsRule))?;
        require(
            lifetime <= governing_ttl_ms(evaluation),
            P::ApprovalTtlExceedsRule,
        )?;
        require(
            audit.profile() == context.profile_name(),
            P::AuditProfileMismatch,
        )?;
        require(
            now.saturating_sub(audit.verified_at_ms())
                <= MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000,
            P::AuditStale,
        )?;
        require(signer.role() == EnrolledRole::Agent, P::SignerRoleMismatch)?;
        require(
            signer.seed_entry() == context.signer_coordinate(),
            P::SignerCoordinateMismatch,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "the mint binds every proof and the sized holds"
    )]
    fn request(
        context: &MainnetWriteContext,
        binding: DomainBinding,
        consumer: MainnetConsumer,
        policy: &VerifiedPolicy,
        body: &MainnetBody,
        endpoint: &EndpointIdentity,
        signer: &EnrolledSigner,
        enablement: &EnablementRecord,
        approval: &ApprovalWitness,
        witness: Option<&CrossCheckWitness>,
        audit: &AuditReadiness,
        holds: Vec<WindowEntry>,
    ) -> MintRequest {
        MintRequest {
            chain: context.chain(),
            binding,
            consumer,
            policy_sequence: policy.sequence(),
            policy_digest: policy.digest(),
            approval_nonce: approval.nonce().to_owned(),
            approval_expires_at_ms: approval.expires_at_ms(),
            authorization_ttl_ms: u64::from(
                body.authorization_ttl_seconds
                    .unwrap_or(MAINNET_AUTHORIZATION_TTL_SECONDS_DEFAULT),
            ) * 1000,
            bindings: BindingFacts {
                endpoint: Some(endpoint.fact_digest()),
                signer: signer.fact_digest(),
                policy: policy.fact_digest(),
                enablement: enablement.fact_digest(),
                witness: witness.map(CrossCheckWitness::fact_digest),
                reservation: None,
                approval: approval.fact_digest(),
                audit: audit.fact_digest(),
            },
            holds,
            parent: None,
        }
    }
    /// The key of an unmuxed source; a muxed source names no G-strkey and
    /// has none.
    fn source_key(source: &MuxedAccount) -> Option<[u8; 32]> {
        match source {
            MuxedAccount::Ed25519(key) => Some(key.0),
            MuxedAccount::MuxedEd25519(_) => None,
        }
    }
    pub(super) async fn tx(
        req: TxSignRequest<'_>,
        detail: &mut Option<String>,
    ) -> Result<MainnetTxSignAuthorization, MainnetAuthorizationError> {
        let now = now()?;
        let deadline = tokio::time::Instant::now() + req.probe_deadline;
        let body = policy_body(req.context, req.policy, req.enablement)?;
        let (decoder_tool, policy_tool, kind) = classic_tools(req.consumer)?;
        let endpoint = endpoint(req.context, req.client, deadline, req.enablement).await?;
        let envelope = decode(req.unsigned_envelope_xdr, P::EnvelopeShape)?;
        let tx = match &envelope {
            TransactionEnvelope::Tx(tx) => tx,
            TransactionEnvelope::TxFeeBump(_) => return Err(refused(P::FeeBumpRefused)),
            _ => return Err(refused(P::EnvelopeShape)),
        };
        let args = decode_authoritative_args(req.unsigned_envelope_xdr, decoder_tool).map_err(
            |error| {
                *detail = Some(error.to_string());
                refused(P::EnvelopeShape)
            },
        )?;
        require(tx.signatures.is_empty(), P::EnvelopePreSigned)?;
        let hash =
            crate::submit::compute_local_tx_hash_hex(&envelope, req.context.network_passphrase())
                .map_err(|_| refused(P::EnvelopeShape))?;
        let tx_hash =
            stellar_agent_core::hex::decode_hex32(&hash).map_err(|_| refused(P::EnvelopeShape))?;
        let source = stellar_strkey::ed25519::PublicKey(req.signer.public_key())
            .to_string()
            .to_string();
        require(
            source_key(&tx.tx.source_account) == Some(req.signer.public_key())
                && args["source"].as_str() == Some(&source),
            P::SourceAccount,
        )?;
        crate::fees::check_classic_fee_cap_signed(
            tx.tx.fee,
            FeeSource::Envelope,
            req.context.profile(),
            Some(body.classic_max_fee_per_op_stroops),
        )
        .map_err(|_| refused(P::FeeAboveCap))?;
        let view = fetch_account(req.client, &source, &[])
            .await
            .map_err(|_| refused(P::AccountUnavailable))?;
        let descriptor = descriptor(policy_tool);
        let engine = req.policy.engine();
        let evaluation = engine
            .evaluate_full(
                &descriptor,
                &args,
                req.context.profile(),
                Some(&AccountViewAdapter::new(&view)),
                None,
                None,
                None,
                None,
            )
            .map_err(|_| refused(P::PolicyEvaluationFailed))?;
        let value = check_evaluation(&evaluation)?;
        let entries = engine
            .size_window_entries(&descriptor, req.context.profile(), &value, now)
            .map_err(|_| refused(P::PolicyEvaluationFailed))?;
        let asset = match req.consumer {
            MainnetConsumer::CliPay | MainnetConsumer::McpPay => {
                Some(match args["asset"].as_str().unwrap_or("") {
                    "XLM" | "native" => CanonicalAsset::Native,
                    asset => CanonicalAsset::parse_threshold_key(asset)
                        .map_err(|_| refused(P::EnvelopeShape))?,
                })
            }
            MainnetConsumer::CliCreateAccount | MainnetConsumer::McpCreateAccount => {
                Some(CanonicalAsset::Native)
            }
            _ => None,
        };
        let amount = if asset.is_some() {
            args["amount_stroops"]
                .as_str()
                .or_else(|| args["starting_balance_stroops"].as_str())
                .and_then(|a| a.parse::<i128>().ok())
                .ok_or_else(|| refused(P::EnvelopeShape))?
        } else {
            0
        };
        let cross_value =
            asset
                .as_ref()
                .map_or(CrossCheckValue::Unvalued, |asset| CrossCheckValue::Amount {
                    asset,
                    base_units: amount,
                });
        let memo = if matches!(
            req.consumer,
            MainnetConsumer::CliPay | MainnetConsumer::McpPay
        ) {
            let shape = payment_memo_shape(req.unsigned_envelope_xdr, decoder_tool)
                .map_err(|_| refused(P::EnvelopeShape))?;
            shape.memo == MemoKind::None && !shape.destination_muxed
        } else {
            false
        };
        witness(req.context, body, cross_value, memo, tx_hash, req.witness)?;
        let digest = approval_subject_classic(req.unsigned_envelope_xdr);
        final_checks(
            req.context,
            req.approval,
            digest,
            kind,
            &evaluation,
            &req.audit,
            req.signer,
            now,
        )?;
        let request = request(
            req.context,
            DomainBinding::Transaction {
                unsigned_envelope_sha256: digest,
                tx_hash,
                source,
                sequence: tx.tx.seq_num.0,
            },
            req.consumer,
            req.policy,
            body,
            &endpoint,
            req.signer,
            req.enablement,
            req.approval,
            req.witness,
            &req.audit,
            entries,
        );
        let minted = req
            .store
            .mint_authorization(req.context.profile(), &request)
            .map_err(mint::store_error)?;
        let header = mint::header(
            req.context,
            &request,
            minted,
            &endpoint,
            req.signer,
            req.enablement,
            req.approval,
            req.witness,
            req.audit,
        );
        Ok(MainnetTxSignAuthorization(TxSignInner {
            header,
            binding: request.binding,
            entries: request.holds,
        }))
    }
    fn network_id(context: &MainnetWriteContext) -> [u8; 32] {
        Sha256::digest(context.network_passphrase().as_bytes()).into()
    }
    fn address_string(address: &ScAddress) -> Result<String, MainnetAuthorizationError> {
        match address {
            ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(key),
            )) => Ok(stellar_strkey::ed25519::PublicKey(key.0)
                .to_string()
                .to_string()),
            ScAddress::Contract(key) => {
                Ok(stellar_strkey::Contract(key.0.0).to_string().to_string())
            }
            _ => Err(refused(P::IntentShape)),
        }
    }
    pub(super) async fn intent(
        req: SorobanIntentRequest<'_>,
    ) -> Result<MainnetSorobanIntentAuthorization, MainnetAuthorizationError> {
        let now = now()?;
        let deadline = tokio::time::Instant::now() + req.probe_deadline;
        let body = policy_body(req.context, req.policy, req.enablement)?;
        // An authenticated payment continues its consumed message
        // authorization; a plain payment has none.
        let authenticated = match (req.intent.consumer, req.authenticated) {
            (MainnetConsumer::X402Create, None) => None,
            (MainnetConsumer::X402Authenticated, Some(receipt)) => Some(receipt),
            (MainnetConsumer::X402Authenticated, None) => {
                return Err(refused(P::IntentRecordMismatch));
            }
            _ => return Err(refused(P::ConsumerMismatch)),
        };
        let endpoint = endpoint(req.context, req.client, deadline, req.enablement).await?;
        require(
            req.intent.network_id == network_id(req.context),
            P::IntentNetworkMismatch,
        )?;
        let root = req.intent.root_invocation;
        require(root.sub_invocations.is_empty(), P::IntentShape)?;
        let SorobanAuthorizedFunction::ContractFn(function) = &root.function else {
            return Err(refused(P::IntentShape));
        };
        require(
            function.function_name.0.as_slice() == b"transfer",
            P::IntentShape,
        )?;
        let ScAddress::Contract(_) = function.contract_address else {
            return Err(refused(P::IntentShape));
        };
        let [
            ScVal::Address(from),
            ScVal::Address(to),
            ScVal::I128(amount),
        ] = function.args.as_slice()
        else {
            return Err(refused(P::IntentShape));
        };
        let payer = stellar_strkey::ed25519::PublicKey(req.signer.public_key())
            .to_string()
            .to_string();
        require(
            matches!(from, ScAddress::Account(_)) && address_string(from)? == payer,
            P::IntentPayerMismatch,
        )?;
        let amount = (i128::from(amount.hi) << 64) | i128::from(amount.lo);
        require(amount > 0, P::IntentShape)?;
        let asset = address_string(&function.contract_address)?;
        let canonical = CanonicalAsset::contract(&asset).map_err(|_| refused(P::IntentShape))?;
        let digest = soroban_intent_digest(&req.intent.network_id, root)
            .map_err(|_| refused(P::IntentShape))?;
        let view = fetch_account(req.client, &payer, &[])
            .await
            .map_err(|_| refused(P::AccountUnavailable))?;
        let value = ValueClass::single(ValueLeg {
            kind: ActionKind::X402Payment,
            amount: Some(amount),
            asset: Some(asset),
            destination: Some(address_string(to)?),
        });
        // The policy evaluates the rule of the tool the operator approved.
        let descriptor = descriptor(if authenticated.is_some() {
            "stellar_x402_authenticated_payment"
        } else {
            "stellar_x402_create_payment"
        });
        let engine = req.policy.engine();
        let evaluation = engine
            .evaluate_with_value_full(
                &descriptor,
                &serde_json::json!({"chain_id": "stellar:mainnet"}),
                req.context.profile(),
                value.clone(),
                Some(&AccountViewAdapter::new(&view)),
                None,
                None,
                None,
                None,
            )
            .map_err(|_| refused(P::PolicyEvaluationFailed))?;
        check_evaluation(&evaluation)?;
        let entries = engine
            .size_window_entries(&descriptor, req.context.profile(), &value, now)
            .map_err(|_| refused(P::PolicyEvaluationFailed))?;
        witness(
            req.context,
            body,
            CrossCheckValue::Amount {
                asset: &canonical,
                base_units: amount,
            },
            false,
            digest,
            req.witness,
        )?;
        final_checks(
            req.context,
            req.approval,
            authenticated.map_or_else(
                || approval_subject_x402(&digest),
                |receipt| approval_subject_x402_authenticated(&digest, receipt.home_domain()),
            ),
            ApprovedKind::X402Payment,
            &evaluation,
            &req.audit,
            req.signer,
            now,
        )?;
        let mut request = request(
            req.context,
            DomainBinding::Soroban {
                intent_digest: digest,
            },
            req.intent.consumer,
            req.policy,
            body,
            &endpoint,
            req.signer,
            req.enablement,
            req.approval,
            req.witness,
            &req.audit,
            entries,
        );
        // The ledger checks, under its lock, that the parent is the used
        // message record of the same approval.
        request.parent = authenticated.map(MessageUseReceipt::id);
        let minted = req
            .store
            .mint_authorization(req.context.profile(), &request)
            .map_err(mint::store_error)?;
        let header = mint::header(
            req.context,
            &request,
            minted,
            &endpoint,
            req.signer,
            req.enablement,
            req.approval,
            req.witness,
            req.audit,
        );
        Ok(MainnetSorobanIntentAuthorization(SorobanIntentInner {
            header,
            binding: request.binding,
            entries: request.holds,
            facts: request.bindings,
            authorization_ttl_ms: request.authorization_ttl_ms,
            nonce: req.nonce,
            signature_expiration_ledger: req.signature_expiration_ledger,
        }))
    }
    pub(super) fn message(
        req: MessageSignRequest<'_>,
    ) -> Result<MainnetMessageSignAuthorization, MainnetAuthorizationError> {
        let now = now()?;
        require(
            req.consumer == MainnetConsumer::X402Authenticated
                && req.intent.consumer == MainnetConsumer::X402Authenticated,
            P::ConsumerMismatch,
        )?;
        let body = policy_body(req.context, req.policy, req.enablement)?;
        require(
            req.intent.network_id == network_id(req.context),
            P::IntentNetworkMismatch,
        )?;
        let digest = soroban_intent_digest(&req.intent.network_id, req.intent.root_invocation)
            .map_err(|_| refused(P::IntentShape))?;
        let approval = req.approval;
        require(
            approval.profile() == req.context.profile_name(),
            P::ApprovalProfileMismatch,
        )?;
        require(approval.chain().is_mainnet(), P::ApprovalChainMismatch)?;
        require(
            approval.kind() == ApprovedKind::X402Payment,
            P::ApprovalKindMismatch,
        )?;
        // The approval binds the SEP-10 counterparty: a challenge for another
        // home domain cannot satisfy it.
        require(
            approval.subject()
                == approval_subject_x402_authenticated(&digest, &req.message.domain.home_domain),
            P::ApprovalSubjectMismatch,
        )?;
        require(approval.created_at_ms() <= now, P::NotYetValid)?;
        require(now < approval.expires_at_ms(), P::ApprovalExpired)?;
        require(
            req.audit.profile() == req.context.profile_name(),
            P::AuditProfileMismatch,
        )?;
        require(
            now.saturating_sub(req.audit.verified_at_ms())
                <= MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000,
            P::AuditStale,
        )?;
        let message = req.message;
        let request = MintRequest {
            chain: req.context.chain(),
            binding: DomainBinding::Message {
                domain: message.domain.clone(),
                content_digest: message.content_digest,
                ephemeral_public_key: message.ephemeral_public_key,
            },
            consumer: MainnetConsumer::X402Authenticated,
            policy_sequence: req.policy.sequence(),
            policy_digest: req.policy.digest(),
            approval_nonce: approval.nonce().to_owned(),
            approval_expires_at_ms: approval.expires_at_ms(),
            authorization_ttl_ms: u64::from(
                body.authorization_ttl_seconds
                    .unwrap_or(MAINNET_AUTHORIZATION_TTL_SECONDS_DEFAULT),
            ) * 1000,
            bindings: BindingFacts {
                endpoint: None,
                signer: super::super::message::ephemeral_signer_fact(message.ephemeral_public_key),
                policy: req.policy.fact_digest(),
                enablement: req.enablement.fact_digest(),
                witness: None,
                reservation: None,
                approval: approval.fact_digest(),
                audit: req.audit.fact_digest(),
            },
            holds: vec![],
            parent: None,
        };
        let minted = req
            .store
            .mint_authorization(req.context.profile(), &request)
            .map_err(mint::store_error)?;
        Ok(mint::message(
            req.context,
            request,
            minted,
            message.ephemeral_public_key,
            req.enablement,
            approval,
            req.audit,
        ))
    }
    pub(super) fn consume_message(
        context: &MainnetWriteContext,
        auth: MainnetMessageSignAuthorization,
        store: &PersistedWindowStore,
    ) -> Result<MessageUseReceipt, MainnetAuthorizationError> {
        let id = auth.id();
        let result = (|| {
            let inner = auth.inner();
            let DomainBinding::Message {
                domain,
                content_digest: content,
                ephemeral_public_key,
            } = &inner.binding
            else {
                return Err(refused(P::BindingMismatch));
            };
            let facts = RecomputedFacts {
                content_digest: content_digest(AuthorizationDomain::Message, content),
                entries_digest: entries_digest(&[]),
                audit: inner.header.audit.fresh_facts()?,
            };
            store
                .consume_authorization(
                    context.profile(),
                    id,
                    &auth.consume_expect(&facts),
                    &ConsumptionBinding::Message {
                        domain: domain.clone(),
                        content_digest: *content,
                        ephemeral_public_key: *ephemeral_public_key,
                    },
                )
                .map_err(mint::store_error)?;
            Ok(MessageFacts {
                domain: domain.clone(),
                content_digest: *content,
                ephemeral_public_key: *ephemeral_public_key,
            })
        })();
        match report("consume_message_sign", result) {
            Ok(facts) => Ok(MessageUseReceipt::new(auth.into_inner(), facts)),
            Err(error) => {
                super::invalidate_after_refused_consume(store, context, id);
                Err(error)
            }
        }
    }
    pub(super) fn consume_intent(
        context: &MainnetWriteContext,
        signed: MainnetSignedSorobanIntent,
        intent: &SorobanIntent<'_>,
        store: &PersistedWindowStore,
    ) -> Result<IntentUseReceipt, MainnetAuthorizationError> {
        // The bound facts are compared through the authorization's checks;
        // the rebuilt value lives inside this function and signs nothing.
        let auth = MainnetSorobanIntentAuthorization(signed.into_inner());
        let digest = soroban_intent_digest(&intent.network_id, intent.root_invocation)
            .map_err(|_| refused(P::IntentShape))?;
        auth.check_intent_digest(&digest)?;
        let root =
            root_invocation_digest(intent.root_invocation).map_err(|_| refused(P::IntentShape))?;
        let facts = RecomputedFacts {
            content_digest: content_digest(AuthorizationDomain::Soroban, &digest),
            entries_digest: entries_digest(auth.entries()),
            audit: auth.0.header.audit.fresh_facts()?,
        };
        let id = auth.id();
        let expect = auth.consume_expect(&facts);
        let receipt = IntentUseReceipt {
            header: auth.0.header,
            intent: digest,
            root,
            facts: auth.0.facts,
            authorization_ttl_ms: auth.0.authorization_ttl_ms,
        };
        store
            .consume_authorization(
                context.profile(),
                id,
                &expect,
                &ConsumptionBinding::RetainedIntent {
                    intent_digest: digest,
                },
            )
            .map_err(mint::store_error)?;
        Ok(receipt)
    }
    pub(super) fn submit(
        req: SorobanSubmitRequest<'_>,
    ) -> Result<MainnetSubmitAuthorization, MainnetAuthorizationError> {
        let envelope = decode(req.final_envelope_xdr, P::DerivationMismatch)?;
        let TransactionEnvelope::Tx(tx) = envelope else {
            return Err(refused(P::DerivationMismatch));
        };
        let [operation] = tx.tx.operations.as_slice() else {
            return Err(refused(P::DerivationMismatch));
        };
        let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
            return Err(refused(P::DerivationMismatch));
        };
        let HostFunction::InvokeContract(args) = &invoke.host_function else {
            return Err(refused(P::DerivationMismatch));
        };
        require(
            invoke.auth.as_slice() == req.signed_auth_entries,
            P::AuthEntriesMismatch,
        )?;
        let mut roots = Vec::new();
        for entry in req.signed_auth_entries {
            let digest = soroban_intent_digest(&network_id(req.context), &entry.root_invocation)
                .map_err(|_| refused(P::IntentShape))?;
            if digest == req.receipt.intent {
                roots.push(&entry.root_invocation);
            }
        }
        let [root] = roots.as_slice() else {
            return Err(refused(P::DerivationMismatch));
        };
        require(
            matches!(&root.function, SorobanAuthorizedFunction::ContractFn(function) if function == args),
            P::DerivationMismatch,
        )?;
        let root_digest = root_invocation_digest(root).map_err(|_| refused(P::IntentShape))?;
        require(root_digest == req.receipt.root, P::DerivationMismatch)?;
        let mut header = req.receipt.header;
        require(
            header.profile == req.context.profile_name(),
            P::ProfileMismatch,
        )?;
        let parent = header.id;
        let request = MintRequest {
            chain: header.chain,
            binding: DomainBinding::X402Submit {
                final_envelope_sha256: approval_subject_classic(req.final_envelope_xdr),
                root_invocation_digest: root_digest,
            },
            consumer: header.consumer,
            policy_sequence: header.policy.sequence,
            policy_digest: header.policy.digest,
            approval_nonce: header.approval.nonce.clone(),
            approval_expires_at_ms: header.approval.expires_at_ms,
            authorization_ttl_ms: req.receipt.authorization_ttl_ms,
            bindings: req.receipt.facts,
            holds: vec![],
            parent: Some(parent),
        };
        let minted = req
            .store
            .mint_authorization(req.context.profile(), &request)
            .map_err(mint::store_error)?;
        header.id = minted.id;
        header.domain = AuthorizationDomain::X402Submit;
        header.issued_at_ms = minted.issued_at_ms;
        header.expires_at_ms = minted.expires_at_ms;
        header.reservation = minted.reservation;
        header.bindings_digest = minted.bindings_digest;
        Ok(MainnetSubmitAuthorization(SubmitInner {
            header,
            binding: request.binding,
            intent_record: parent,
        }))
    }
    pub(super) fn consume_submit(
        context: &MainnetWriteContext,
        auth: &MainnetSubmitAuthorization,
        envelope: &str,
        store: &PersistedWindowStore,
    ) -> Result<(), MainnetAuthorizationError> {
        let digest = approval_subject_classic(envelope);
        auth.check_final_envelope(&digest)?;
        let DomainBinding::X402Submit {
            root_invocation_digest: root,
            ..
        } = &auth.0.binding
        else {
            return Err(refused(P::FinalEnvelope));
        };
        let facts = RecomputedFacts {
            content_digest: content_digest(AuthorizationDomain::X402Submit, &digest),
            entries_digest: entries_digest(&[]),
            audit: auth.0.header.audit.fresh_facts()?,
        };
        store
            .consume_authorization(
                context.profile(),
                auth.id(),
                &auth.consume_expect(&facts),
                &ConsumptionBinding::PayloadRelease {
                    intent_record: Some(auth.0.intent_record),
                    final_envelope_sha256: digest,
                    root_invocation_digest: Some(*root),
                },
            )
            .map_err(mint::store_error)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "mainnet-write"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    use super::super::{MainnetPrecondition as P, fixtures::ResolverFixture};
    use super::*;

    /// The entry nonce every intent request in this module names.
    const INTENT_NONCE: i64 = 41;
    /// The signature expiration ledger every intent request in this module
    /// names.
    const INTENT_EXPIRATION_LEDGER: u32 = 1_060;

    fn request<'a>(
        f: &'a ResolverFixture,
        context: &'a MainnetWriteContext,
        client: &'a StellarRpcClient,
        approval: &'a ApprovalWitness,
    ) -> TxSignRequest<'a> {
        TxSignRequest {
            context,
            consumer: MainnetConsumer::CliPay,
            unsigned_envelope_xdr: &f.envelope,
            client,
            probe_deadline: Duration::from_secs(1),
            witness: None,
            signer: &f.signer,
            policy: &f.policy,
            enablement: &f.enablement,
            approval,
            audit: f.audit(),
            store: &f.window,
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_tx_sign_accepts() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = crate::NetworkContext::mainnet_write(
            &f.profile,
            &stellar_agent_core::profile::name::ResolvedProfileName::from_flag("operator"),
            &f.dir.path().join("profiles"),
            crate::MainnetEndpointFlags::default(),
        )
        .unwrap()
        .with_test_transport_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let auth = resolve_tx_sign(request(&f, &context, &client, &approval))
            .await
            .unwrap();
        assert!(!auth.entries().is_empty());
        assert_eq!(auth.0.header.issued_at_ms, f.now);
        assert_eq!(auth.expires_at_ms(), f.now + 60_000);
        let wire = f.wire();
        let holds = wire["holds"].as_array().unwrap();
        assert_eq!(holds.len(), auth.entries().len());
        for (ordinal, (hold, entry)) in holds.iter().zip(auth.entries()).enumerate() {
            assert_eq!(hold["ordinal"], ordinal);
            assert_eq!(hold["bucket"], entry.key().bucket());
            assert_eq!(hold["scope_specificity"], entry.key().scope_specificity());
            assert_eq!(hold["window_secs"], entry.key().window_secs());
            assert_eq!(hold["ts_ms"], entry.timestamp_ms());
            assert_eq!(hold["amount"], entry.amount().to_string());
        }
        assert_eq!(
            wire["authorizations"][0]["minted_ms"],
            auth.0.header.issued_at_ms
        );
        assert_eq!(
            wire["authorizations"][0]["expires_ms"],
            auth.expires_at_ms()
        );
        assert_eq!(
            f.window
                .open_authorizations(&f.profile, f.now)
                .unwrap()
                .len(),
            1
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].body_json::<serde_json::Value>().unwrap()["method"],
            "getNetwork"
        );
        assert_eq!(
            requests[1].body_json::<serde_json::Value>().unwrap()["method"],
            "getLedgerEntries"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn clock_unavailable_refuses() {
        let f = ResolverFixture::new();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let client = f.context.primary_client().unwrap();
        let req = request(&f, &f.context, &client, &approval);
        let guard = super::super::clock::set_clock_error_for_test();
        assert!(matches!(
            resolve_tx_sign(req).await,
            Err(MainnetAuthorizationError::Refused(P::ClockUnavailable))
        ));
        drop(guard);
        f.clock.set(f.now);
        assert!(
            f.window
                .open_authorizations(&f.profile, f.now)
                .unwrap()
                .is_empty()
        );
    }
    use sha2::{Digest as _, Sha256};
    use stellar_xdr::{
        Limits, OperationBody, ReadXdr as _, ScAddress, ScVal, SorobanAuthorizedFunction,
        TransactionEnvelope, WriteXdr as _,
    };

    fn changed_envelope(
        f: &ResolverFixture,
        edit: impl FnOnce(&mut stellar_xdr::TransactionV1Envelope),
    ) -> String {
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&f.envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        edit(&mut tx);
        TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    fn assert_refused<T: std::fmt::Debug>(
        result: Result<T, MainnetAuthorizationError>,
        expected: P,
        f: &ResolverFixture,
        before: &serde_json::Value,
    ) {
        let error = result.unwrap_err();
        assert!(
            matches!(error, MainnetAuthorizationError::Refused(actual) if actual == expected),
            "expected {expected:?}, got {error:?}"
        );
        assert_eq!(
            &f.wire(),
            before,
            "refusal changed records, holds, or debits"
        );
    }

    async fn envelope_refusal(case: &str, expected: P) {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let mut envelope = changed_envelope(&f, |tx| match case {
            "two_operations" => {
                tx.tx.operations = vec![tx.tx.operations[0].clone(), tx.tx.operations[0].clone()]
                    .try_into()
                    .unwrap()
            }
            "wrong_operation" => {
                let mut op = tx.tx.operations[0].clone();
                op.body = OperationBody::ManageData(stellar_xdr::ManageDataOp {
                    data_name: stellar_xdr::String64("name".try_into().unwrap()),
                    data_value: None,
                });
                tx.tx.operations = vec![op].try_into().unwrap();
            }
            "pre_signed" => {
                tx.signatures = vec![stellar_xdr::DecoratedSignature {
                    hint: stellar_xdr::SignatureHint([0; 4]),
                    signature: vec![0; 64].try_into().unwrap(),
                }]
                .try_into()
                .unwrap()
            }
            "transaction_source" | "muxed_transaction_source" => {
                let mut op = tx.tx.operations[0].clone();
                op.source_account = Some(stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
                    f.signer.public_key(),
                )));
                tx.tx.operations = vec![op].try_into().unwrap();
                tx.tx.source_account = if case == "transaction_source" {
                    stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([5; 32]))
                } else {
                    stellar_xdr::MuxedAccount::MuxedEd25519(stellar_xdr::MuxedAccountMed25519 {
                        id: 1,
                        ed25519: stellar_xdr::Uint256(f.signer.public_key()),
                    })
                };
            }
            "operation_source" => {
                let mut op = tx.tx.operations[0].clone();
                op.source_account = Some(stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(
                    [5; 32],
                )));
                tx.tx.operations = vec![op].try_into().unwrap();
            }
            "fee" => tx.tx.fee = 501,
            _ => {}
        });
        if case == "fee_bump" {
            let TransactionEnvelope::Tx(tx) =
                TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
            else {
                unreachable!()
            };
            envelope = TransactionEnvelope::TxFeeBump(stellar_xdr::FeeBumpTransactionEnvelope {
                tx: stellar_xdr::FeeBumpTransaction {
                    fee_source: tx.tx.source_account.clone(),
                    fee: 200,
                    inner_tx: stellar_xdr::FeeBumpTransactionInnerTx::Tx(tx),
                    ext: stellar_xdr::FeeBumpTransactionExt::V0,
                },
                signatures: vec![].try_into().unwrap(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
        }
        if case == "v0" {
            let TransactionEnvelope::Tx(tx) =
                TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
            else {
                unreachable!()
            };
            envelope = TransactionEnvelope::TxV0(stellar_xdr::TransactionV0Envelope {
                tx: stellar_xdr::TransactionV0 {
                    source_account_ed25519: stellar_xdr::Uint256(f.signer.public_key()),
                    fee: tx.tx.fee,
                    seq_num: tx.tx.seq_num,
                    time_bounds: None,
                    memo: tx.tx.memo,
                    operations: tx.tx.operations,
                    ext: stellar_xdr::TransactionV0Ext::V0,
                },
                signatures: vec![].try_into().unwrap(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
        }
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.unsigned_envelope_xdr = &envelope;
        assert_refused(resolve_tx_sign(req).await, expected, &f, &before);
    }

    macro_rules! envelope_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                envelope_refusal($case, P::$expected).await;
            }
        };
    }
    envelope_case!(fee_bump_refuses, "fee_bump", FeeBumpRefused);
    envelope_case!(v0_envelope_refuses, "v0", EnvelopeShape);
    envelope_case!(two_operations_refuse, "two_operations", EnvelopeShape);
    envelope_case!(another_operation_refuses, "wrong_operation", EnvelopeShape);
    envelope_case!(pre_signed_envelope_refuses, "pre_signed", EnvelopePreSigned);
    envelope_case!(
        transaction_source_refuses,
        "transaction_source",
        SourceAccount
    );
    envelope_case!(
        muxed_transaction_source_refuses,
        "muxed_transaction_source",
        SourceAccount
    );
    envelope_case!(operation_source_refuses, "operation_source", SourceAccount);
    envelope_case!(fee_above_cap_refuses, "fee", FeeAboveCap);

    async fn endpoint_refusal(case: &str, expected: P) {
        use stellar_agent_test_support::{EchoIdResponder, signed_envelope::get_network_result};
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let f = ResolverFixture::new();
        let server = MockServer::start().await;
        // A pooled mock server keeps listening after it is dropped, so the
        // transport case routes to a loopback port with no listener.
        let uri = if case == "transport" {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            format!("http://{address}")
        } else {
            server.uri()
        };
        let context = f.context_with_routes(&[("rpc.example.invalid", &uri)]);
        let client = if case == "authority" {
            StellarRpcClient::with_test_transport("https://other.example.invalid", &uri).unwrap()
        } else {
            context.primary_client().unwrap()
        };
        let approval = f.approval(&f.envelope, f.now, 600_000);
        match case {
            "401" | "403" => {
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(case.parse::<u16>().unwrap()))
                    .mount(&server)
                    .await
            }
            "malformed" => {
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(200).set_body_string("not JSON"))
                    .mount(&server)
                    .await
            }
            "timeout" => {
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
                    .mount(&server)
                    .await
            }
            _ => {
                let mut body = get_network_result(if case == "testnet" {
                    stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE
                } else {
                    stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE
                });
                if case == "protocol" {
                    body["protocolVersion"] = serde_json::json!(1);
                }
                Mock::given(body_partial_json(
                    serde_json::json!({"method":"getNetwork"}),
                ))
                .respond_with(EchoIdResponder::new(body))
                .mount(&server)
                .await;
            }
        }
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.probe_deadline = Duration::from_millis(20);
        assert_refused(resolve_tx_sign(req).await, expected, &f, &before);
    }
    macro_rules! endpoint_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                endpoint_refusal($case, P::$expected).await;
            }
        };
    }
    endpoint_case!(endpoint_401_refuses, "401", EndpointUnavailable);
    endpoint_case!(endpoint_403_refuses, "403", EndpointUnavailable);
    endpoint_case!(endpoint_timeout_refuses, "timeout", EndpointUnavailable);
    endpoint_case!(endpoint_transport_refuses, "transport", EndpointUnavailable);
    endpoint_case!(
        endpoint_malformed_body_refuses,
        "malformed",
        EndpointUnavailable
    );
    endpoint_case!(
        endpoint_protocol_refuses,
        "protocol",
        EndpointProtocolUnsupported
    );
    endpoint_case!(endpoint_testnet_refuses, "testnet", EndpointNotMainnet);
    endpoint_case!(endpoint_authority_refuses, "authority", EndpointAuthority);
    endpoint_case!(account_read_failure_refuses, "account", AccountUnavailable);

    #[tokio::test]
    #[serial_test::serial]
    async fn classic_resolver_refuses_x402_consumer() {
        let f = ResolverFixture::new();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let client = f.context.primary_client().unwrap();
        let before = f.wire();
        let mut req = request(&f, &f.context, &client, &approval);
        req.consumer = MainnetConsumer::X402Create;
        assert_refused(resolve_tx_sign(req).await, P::ConsumerMismatch, &f, &before);
    }

    async fn approval_time_refusal(created_offset: i64, ttl: u64, expected: P) {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let created = f.now.checked_add_signed(created_offset).unwrap();
        let approval = f.approval(&f.envelope, created, ttl);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            expected,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn allow_rule_bounds_approval_to_confirmation_ttl() {
        approval_time_refusal(0, 601_000, P::ApprovalTtlExceedsRule).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn future_created_approval_refuses() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let created = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let approval = f.approval(&f.envelope, created, 600_000);
        let time = created - 8 * 24 * 60 * 60 * 1000;
        f.clock.set(time);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            P::NotYetValid,
            &f,
            &before,
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn expired_approval_refuses() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        f.clock.set(f.now + 600_000);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            P::ApprovalExpired,
            &f,
            &before,
        );
    }

    fn token() -> String {
        stellar_strkey::Contract([3; 32]).to_string().to_string()
    }
    fn soroban_fixture() -> ResolverFixture {
        let token = token();
        ResolverFixture::configured(
            |_| {},
            |raw| {
                raw.replace("stellar_pay", "stellar_x402_create_payment")
                    .replace("\"native\"", &format!("\"{token}\""))
                    .replace("native =", &format!("\"{token}\" ="))
            },
        )
    }
    fn root(f: &ResolverFixture) -> SorobanAuthorizedInvocation {
        use stellar_xdr::{
            AccountId, ContractId, Hash, Int128Parts, InvokeContractArgs, PublicKey, Uint256,
        };
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256(f.signer.public_key())),
                    ))),
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256(
                            stellar_strkey::ed25519::PublicKey::from_string(f.source.destination())
                                .unwrap()
                                .0,
                        )),
                    ))),
                    ScVal::I128(Int128Parts { hi: 0, lo: 10 }),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        }
    }
    fn intent<'a>(root: &'a SorobanAuthorizedInvocation) -> SorobanIntent<'a> {
        SorobanIntent {
            consumer: MainnetConsumer::X402Create,
            root_invocation: root,
            network_id: Sha256::digest(
                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes(),
            )
            .into(),
        }
    }
    fn intent_approval(
        f: &ResolverFixture,
        root: &SorobanAuthorizedInvocation,
        domain: Option<&str>,
    ) -> ApprovalWitness {
        use stellar_agent_core::approval::{
            PendingApproval,
            subject::{
                approval_subject_x402, approval_subject_x402_authenticated, soroban_intent_digest,
            },
            witness::ApprovedKind,
        };
        let intent = intent(root);
        let mut entry = PendingApproval::new_x402_pending(
            &intent.network_id,
            root,
            domain.map(str::to_owned),
            "1000".into(),
            600_000,
        )
        .unwrap();
        entry.created_at_unix_ms = f.now;
        entry.expires_at_unix_ms = f.now + 600_000;
        let digest = soroban_intent_digest(&intent.network_id, root).unwrap();
        let subject = domain.map_or_else(
            || approval_subject_x402(&digest),
            |domain| approval_subject_x402_authenticated(&digest, domain),
        );
        f.attested(
            &entry,
            &f.profile,
            "operator",
            ApprovedKind::X402Payment,
            subject,
            f.now,
        )
    }
    fn intent_request<'a>(
        f: &'a ResolverFixture,
        context: &'a MainnetWriteContext,
        client: &'a StellarRpcClient,
        intent: &'a SorobanIntent<'a>,
        approval: &'a ApprovalWitness,
    ) -> SorobanIntentRequest<'a> {
        SorobanIntentRequest {
            context,
            intent,
            nonce: INTENT_NONCE,
            signature_expiration_ledger: INTENT_EXPIRATION_LEDGER,
            client,
            probe_deadline: Duration::from_secs(1),
            witness: None,
            signer: &f.signer,
            policy: &f.policy,
            enablement: &f.enablement,
            approval,
            audit: f.audit(),
            store: &f.window,
            authenticated: None,
        }
    }
    async fn resolved_intent(
        f: &ResolverFixture,
        context: &MainnetWriteContext,
        root: &SorobanAuthorizedInvocation,
    ) -> MainnetSorobanIntentAuthorization {
        let client = context.primary_client().unwrap();
        let intent = intent(root);
        let approval = intent_approval(f, root, None);
        resolve_soroban_intent(intent_request(f, context, &client, &intent, &approval))
            .await
            .unwrap()
    }
    fn final_envelope(
        f: &ResolverFixture,
        root: &SorobanAuthorizedInvocation,
    ) -> (String, Vec<SorobanAuthorizationEntry>) {
        let SorobanAuthorizedFunction::ContractFn(args) = &root.function else {
            unreachable!()
        };
        let entries = vec![SorobanAuthorizationEntry {
            credentials: stellar_xdr::SorobanCredentials::SourceAccount,
            root_invocation: root.clone(),
        }];
        let envelope = changed_envelope(f, |tx| {
            tx.tx.operations = vec![stellar_xdr::Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(stellar_xdr::InvokeHostFunctionOp {
                    host_function: stellar_xdr::HostFunction::InvokeContract(args.clone()),
                    auth: entries.clone().try_into().unwrap(),
                }),
            }]
            .try_into()
            .unwrap();
        });
        (envelope, entries)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_soroban_intent_accepts() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        assert!(!auth.entries().is_empty());
        let wire = f.wire();
        assert_eq!(wire["authorizations"][0]["state"], "open");
        assert_eq!(
            wire["holds"].as_array().unwrap().len(),
            auth.entries().len()
        );
    }

    async fn intent_refusal(case: &str, expected: P) {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = intent_approval(
            &f,
            &root,
            if case == "authenticated_approval" {
                Some("merchant.example.invalid")
            } else {
                None
            },
        );
        let mut changed = root.clone();
        if case == "child" {
            changed.sub_invocations = vec![root.clone()].try_into().unwrap();
        }
        let SorobanAuthorizedFunction::ContractFn(function) = &mut changed.function else {
            unreachable!()
        };
        if case == "function" {
            function.function_name = "approve".try_into().unwrap();
        }
        if case == "payer" {
            let mut args = function.args.to_vec();
            args[0] = ScVal::Address(ScAddress::Contract(stellar_xdr::ContractId(
                stellar_xdr::Hash([4; 32]),
            )));
            function.args = args.try_into().unwrap();
        }
        let mut intent = intent(&changed);
        match case {
            "network" => intent.network_id = [8; 32],
            "authenticated" => intent.consumer = MainnetConsumer::X402Authenticated,
            "classic" => intent.consumer = MainnetConsumer::CliPay,
            _ => {}
        }
        let before = f.wire();
        assert_refused(
            resolve_soroban_intent(intent_request(&f, &context, &client, &intent, &approval)).await,
            expected,
            &f,
            &before,
        );
        if matches!(case, "classic" | "authenticated") {
            // A wrong consumer is refused before the endpoint probe.
            assert!(server.received_requests().await.unwrap().is_empty());
        }
    }
    macro_rules! intent_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                intent_refusal($case, P::$expected).await;
            }
        };
    }
    intent_case!(intent_sub_invocation_refuses, "child", IntentShape);
    intent_case!(intent_function_refuses, "function", IntentShape);
    intent_case!(intent_network_refuses, "network", IntentNetworkMismatch);
    intent_case!(intent_payer_refuses, "payer", IntentPayerMismatch);
    intent_case!(
        intent_authenticated_consumer_refuses,
        "authenticated",
        IntentRecordMismatch
    );
    intent_case!(intent_classic_consumer_refuses, "classic", ConsumerMismatch);
    intent_case!(
        authenticated_approval_refuses_plain_intent,
        "authenticated_approval",
        ApprovalSubjectMismatch
    );

    #[tokio::test]
    #[serial_test::serial]
    async fn consume_soroban_intent_returns_receipt() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let id = auth.id();
        let receipt =
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                .unwrap();
        assert_eq!(receipt.header.id, id);
        assert_eq!(f.wire()["authorizations"][0]["state"], "used");
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn other_intent_refuses() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let mut changed = root.clone();
        changed.sub_invocations = vec![root.clone()].try_into().unwrap();
        let before = f.wire();
        assert_refused(
            consume_soroban_intent(&context, auth.into_signed(), &intent(&changed), &f.window),
            P::IntentDigest,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn expired_intent_refuses_consume() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let expires = auth.expires_at_ms();
        f.clock.set(expires);
        let before = f.wire();
        assert!(matches!(
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window),
            Err(MainnetAuthorizationError::Refused(P::NotOpen))
        ));
        assert_eq!(f.wire(), before, "a refused consumption writes nothing");
        assert!(
            f.window
                .open_authorizations(&f.profile, expires)
                .unwrap()
                .is_empty()
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn resolve_soroban_submit_accepts() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let id = auth.id();
        let receipt =
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                .unwrap();
        let (envelope, entries) = final_envelope(&f, &root);
        let child = resolve_soroban_submit(SorobanSubmitRequest {
            context: &context,
            receipt,
            final_envelope_xdr: &envelope,
            signed_auth_entries: &entries,
            store: &f.window,
        })
        .unwrap();
        assert_eq!(child.0.intent_record, id);
        let wire = f.wire();
        assert_eq!(
            wire["authorizations"][1]["parent"],
            serde_json::to_value(id).unwrap()
        );
        assert_eq!(wire["authorizations"][1]["state"], "open");
        assert!(wire["holds"].as_array().is_none_or(Vec::is_empty));
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn x402_chain_retains_one_debit() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let receipt =
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                .unwrap();
        let before = f.wire()["entries"].clone();
        let buckets = before.as_array().unwrap();
        let debit = buckets
            .iter()
            .find(|bucket| {
                bucket["bucket"]
                    .as_str()
                    .is_some_and(|key| key.contains(&token()))
            })
            .unwrap();
        assert_eq!(debit["records"].as_array().unwrap().len(), 1);
        assert_eq!(debit["records"][0]["amount"], "10");
        let (envelope, entries) = final_envelope(&f, &root);
        let child = resolve_soroban_submit(SorobanSubmitRequest {
            context: &context,
            receipt,
            final_envelope_xdr: &envelope,
            signed_auth_entries: &entries,
            store: &f.window,
        })
        .unwrap();
        consume_soroban_submit(&context, child, &envelope, &f.window).unwrap();
        let wire = f.wire();
        assert_eq!(wire["entries"], before);
        assert_eq!(wire["authorizations"][0]["state"], "used");
        assert_eq!(wire["authorizations"][1]["state"], "used");
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn release_consume_refuses_other_envelope() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let receipt =
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                .unwrap();
        let (envelope, entries) = final_envelope(&f, &root);
        let child = resolve_soroban_submit(SorobanSubmitRequest {
            context: &context,
            receipt,
            final_envelope_xdr: &envelope,
            signed_auth_entries: &entries,
            store: &f.window,
        })
        .unwrap();
        let before = f.wire();
        assert_refused(
            consume_soroban_submit(&context, child, &f.envelope, &f.window),
            P::FinalEnvelope,
            &f,
            &before,
        );
    }

    fn oracle_profile(profile: &mut stellar_agent_core::profile::schema::Profile) {
        profile
            .providers
            .get_or_insert_with(Default::default)
            .primary = Some(
            stellar_agent_core::profile::schema::PrimaryProviderRecord::new(
                "primary",
                "rpc.example.invalid",
            ),
        );
        profile.oracle_provider_url = Some("https://oracle.example.invalid".parse().unwrap());
        profile
            .providers
            .get_or_insert_with(Default::default)
            .oracle = Some(stellar_agent_core::profile::schema::ProviderRecord::new(
            "oracle",
            "oracle.example.invalid",
            true,
        ));
    }
    fn set_amount(f: &mut ResolverFixture, amount: i64) {
        f.envelope = changed_envelope(f, |tx| {
            let mut op = tx.tx.operations[0].clone();
            let OperationBody::Payment(payment) = &mut op.body else {
                unreachable!()
            };
            payment.amount = amount;
            tx.tx.operations = vec![op].try_into().unwrap();
        });
    }
    fn large_payment_fixture(with_oracle: bool) -> ResolverFixture {
        let mut f = ResolverFixture::configured(
            |profile| {
                if with_oracle {
                    oracle_profile(profile);
                }
            },
            |raw| {
                raw.replace("max_stroops = \"100\"", "max_stroops = \"1000000000000\"")
                    .replace("max_stroops = \"200\"", "max_stroops = \"1000000000000\"")
            },
        );
        set_amount(&mut f, 10_000_000_000);
        f
    }
    /// A bound witness from a copy of the snapshot whose oracle is on `host`,
    /// built through `context`'s own routes.
    async fn witness_for(
        f: &ResolverFixture,
        context: &MainnetWriteContext,
        envelope: &str,
        host: &str,
    ) -> CrossCheckWitness {
        use crate::cross_check::{
            AccountObservation, CrossCheckOutcome, DestinationObservation, MemoObservation,
            PayWitnessInputs, obtain_classic_witness_bound,
        };
        use stellar_agent_core::{
            asset_id::CanonicalAsset,
            cross_check::{CrossCheckValue, ThresholdSet},
        };
        let mut profile = context.profile().clone();
        profile.oracle_provider_url = Some(format!("https://{host}").parse().unwrap());
        profile
            .providers
            .get_or_insert_with(Default::default)
            .oracle = Some(stellar_agent_core::profile::schema::ProviderRecord::new(
            "oracle", host, true,
        ));
        let network = context.network_context();
        let data = f.source.ledger_entries_result();
        let stellar_xdr::LedgerEntryData::Account(account) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(
                data["entries"][0]["xdr"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap()
        else {
            unreachable!()
        };
        let view = crate::account::project_account_entry(f.source.source(), &account).unwrap();
        let inputs = PayWitnessInputs {
            source: AccountObservation::from_view(&view).unwrap(),
            destination: DestinationObservation::from_view(f.source.destination(), None),
            memo: MemoObservation::NotRead,
            trustline: None,
        };
        profile.cross_check_threshold_stroops = 0;
        let thresholds = ThresholdSet::from_profile(&profile);
        let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
            envelope,
            "stellar_pay_commit",
        )
        .unwrap();
        let outcome = obtain_classic_witness_bound(
            &profile,
            &network,
            CrossCheckValue::Amount {
                asset: &CanonicalAsset::Native,
                base_units: args["amount_stroops"].as_str().unwrap().parse().unwrap(),
            },
            inputs,
            envelope,
            &thresholds,
            "stellar_pay",
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = outcome else {
            panic!("bound witness required")
        };
        witness
    }

    async fn witness_case(case: &str, expected: Option<P>) {
        let mut f = large_payment_fixture(true);
        if case == "not_required" {
            set_amount(&mut f, 10);
        }
        let primary = f.server().await;
        let oracle = f.server().await;
        let context = f.context_with_routes(&[
            ("rpc.example.invalid", &primary.uri()),
            ("oracle.example.invalid", &oracle.uri()),
            ("third.example.invalid", &oracle.uri()),
        ]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let other = changed_envelope(&f, |tx| {
            tx.tx.memo = stellar_xdr::Memo::Text(b"other".to_vec().try_into().unwrap());
            let mut op = tx.tx.operations[0].clone();
            let OperationBody::Payment(payment) = &mut op.body else {
                unreachable!()
            };
            payment.amount = 10_000_000_000;
            tx.tx.operations = vec![op].try_into().unwrap();
        });
        let host = match case {
            "same_host" => "rpc.example.invalid",
            "third_host" => "third.example.invalid",
            _ => "oracle.example.invalid",
        };
        let witness = witness_for(
            &f,
            &context,
            if matches!(case, "subject" | "not_required") {
                &other
            } else {
                &f.envelope
            },
            host,
        )
        .await;
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.witness = Some(&witness);
        let result = resolve_tx_sign(req).await;
        if let Some(expected) = expected {
            assert_refused(result, expected, &f, &before);
        } else {
            let auth = result.unwrap();
            assert_eq!(auth.0.header.witness_subject, witness.subject());
            assert_eq!(f.wire()["authorizations"][0]["state"], "open");
        }
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn required_witness_accepts() {
        witness_case("required", None).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn witness_subject_refuses() {
        witness_case("subject", Some(P::WitnessSubject)).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn same_host_witness_refuses_before_oracle_binding() {
        witness_case("same_host", Some(P::WitnessSameHost)).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn witness_oracle_binding_refuses() {
        witness_case("third_host", Some(P::WitnessOracleUnbound)).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn not_required_witness_still_checked() {
        witness_case("not_required", Some(P::WitnessSubject)).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn test_transport_keeps_profile_authority() {
        let f = large_payment_fixture(true);
        let primary = f.server().await;
        let oracle = f.server().await;
        let context = f.context_with_routes(&[
            ("rpc.example.invalid", &primary.uri()),
            ("oracle.example.invalid", &oracle.uri()),
        ]);
        let client = context.primary_client().unwrap();
        assert_eq!(client.url(), "https://rpc.example.invalid");
        let witness = witness_for(&f, &context, &f.envelope, "oracle.example.invalid").await;
        assert_eq!(witness.authority(), "https://oracle.example.invalid");
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let mut req = request(&f, &context, &client, &approval);
        req.witness = Some(&witness);
        resolve_tx_sign(req).await.unwrap();
        assert_eq!(f.wire()["authorizations"][0]["state"], "open");
        let methods = |requests: Vec<wiremock::Request>| {
            requests
                .iter()
                .map(|request| {
                    request.body_json::<serde_json::Value>().unwrap()["method"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            methods(primary.received_requests().await.unwrap()),
            ["getNetwork", "getLedgerEntries"]
        );
        assert_eq!(
            methods(oracle.received_requests().await.unwrap()),
            ["getNetwork", "getLedgerEntries"]
        );
        let identity = client
            .mainnet_endpoint_identity(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(identity.authority(), context.authority());
        assert_eq!(primary.received_requests().await.unwrap().len(), 3);
        assert_eq!(oracle.received_requests().await.unwrap().len(), 2);
    }

    async fn requirement_refusal(with_oracle: bool, expected: P) {
        let f = large_payment_fixture(with_oracle);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            expected,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn witness_required_refuses() {
        requirement_refusal(true, P::WitnessRequired).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn witness_oracle_missing_refuses() {
        requirement_refusal(false, P::WitnessOracleMissing).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolver_fetches_account_from_checked_client() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        resolve_tx_sign(request(&f, &context, &client, &approval))
            .await
            .unwrap();
        let methods: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                r.body_json::<serde_json::Value>().unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(methods, ["getNetwork", "getLedgerEntries"]);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn resolver_counts_the_envelope_fee_in_reserve() {
        let f = ResolverFixture::configured(
            |_| {},
            |raw| {
                raw.replace("criteria = [", "criteria = [\n    { kind = \"minimum_reserve\", margin_stroops = 99989999980 },")
            },
        );
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        let result = resolve_tx_sign(request(&f, &context, &client, &approval)).await;
        let Err(MainnetAuthorizationError::PolicyDenied(reason)) = result else {
            panic!("reserve denial required: {result:?}")
        };
        assert!(reason.wire_code().contains("minimum_reserve_breached"));
        assert_eq!(f.wire(), before);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn policy_denial_keeps_policy_code() {
        let f = ResolverFixture::configured(
            |_| {},
            |raw| raw.replace("max_stroops = \"100\"", "max_stroops = \"9\""),
        );
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        let result = resolve_tx_sign(request(&f, &context, &client, &approval)).await;
        let Err(MainnetAuthorizationError::PolicyDenied(reason)) = result else {
            panic!("policy denial required: {result:?}")
        };
        let code = reason.wire_code();
        let error: stellar_agent_core::error::WalletError =
            MainnetAuthorizationError::PolicyDenied(reason).into();
        assert_eq!(error.code(), code);
        assert_eq!(f.wire(), before);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn admission_refusal_keeps_policy_code() {
        let f = ResolverFixture::configured(
            |_| {},
            |raw| raw.replace("max_stroops = \"200\"", "max_stroops = \"15\""),
        );
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        resolve_tx_sign(request(&f, &context, &client, &approval))
            .await
            .unwrap();
        let other = changed_envelope(&f, |tx| {
            tx.tx.memo = stellar_xdr::Memo::Text(b"second".to_vec().try_into().unwrap())
        });
        let approval = f.approval(&other, f.now, 600_000);
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.unsigned_envelope_xdr = &other;
        let result = resolve_tx_sign(req).await;
        let Err(MainnetAuthorizationError::PolicyDenied(reason)) = result else {
            panic!("admission denial required: {result:?}")
        };
        assert!(reason.wire_code().starts_with("policy.deny."));
        assert_eq!(f.wire(), before);
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn duplicate_open_refuses() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let first = f.approval(&f.envelope, f.now, 600_000);
        resolve_tx_sign(request(&f, &context, &client, &first))
            .await
            .unwrap();
        let second = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &second)).await,
            P::DuplicateOpen,
            &f,
            &before,
        );
    }
    async fn pin_refusal(mismatch: bool, expected: P) {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &f.profile.policy_window_state_key_id,
        );
        let entry = keyring_core::Entry::new(&pin.service, &pin.account).unwrap();
        if mismatch {
            let mut value: serde_json::Value =
                serde_json::from_str(&entry.get_password().unwrap()).unwrap();
            value["sequence"] = serde_json::json!(8);
            entry.set_password(&value.to_string()).unwrap();
        } else {
            entry.delete_credential().unwrap();
        }
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            expected,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_pin_absent_refuses() {
        pin_refusal(false, P::PolicyPinAbsent).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_pin_mismatch_refuses() {
        pin_refusal(true, P::PolicyPinMismatch).await;
    }

    async fn final_binding_refusal(case: &str, expected: P) {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let mut profile = f.profile.clone();
        if case == "chain" {
            profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        }
        let envelope = if case == "subject" {
            changed_envelope(&f, |tx| {
                tx.tx.memo = stellar_xdr::Memo::Text(b"other".to_vec().try_into().unwrap())
            })
        } else if case == "trustline_approval" {
            stellar_agent_core::approval::fixtures::change_trust_envelope(
                f.source.source(),
                "USD",
                f.source.destination(),
                Some(10),
                100,
                1,
            )
        } else {
            f.envelope.clone()
        };
        let mut entry = stellar_agent_core::approval::PendingApproval::new_payment_pending(
            envelope.clone(),
            envelope.as_bytes(),
            f.source.destination().into(),
            10,
            "XLM".into(),
            None,
            100,
            1,
            "1000".into(),
            600_000,
        )
        .unwrap();
        entry.created_at_unix_ms = f.now;
        entry.expires_at_unix_ms = f.now + 600_000;
        let mut kind = stellar_agent_core::approval::witness::ApprovedKind::Payment;
        if case == "trustline_approval" {
            entry = stellar_agent_core::approval::PendingApproval::new_trustline_pending(
                envelope.clone(),
                envelope.as_bytes(),
                f.source.source().into(),
                "USD".into(),
                f.source.destination().into(),
                Some(10),
                100,
                1,
                "1000".into(),
                600_000,
            )
            .unwrap();
            entry.created_at_unix_ms = f.now;
            entry.expires_at_unix_ms = f.now + 600_000;
            kind = stellar_agent_core::approval::witness::ApprovedKind::Trustline;
        }
        let name = if case == "profile" {
            "other"
        } else {
            "operator"
        };
        let subject = stellar_agent_core::approval::subject::approval_subject_classic(&envelope);
        let approval = f.attested(&entry, &profile, name, kind, subject, f.now);
        let signer = crate::keyring::enrolled_signer(
            "operator",
            &f.dir.path().join("profiles"),
            &f.profile,
            crate::keyring::EnrolledRole::FeePayer,
            &f.signer.public_key(),
        )
        .unwrap();
        let mut req = request(&f, &context, &client, &approval);
        if case == "signer_role" {
            req.signer = &signer;
        }
        if case == "audit_age" {
            f.clock
                .set(f.now - MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000 - 1);
            req.audit = f.audit();
            f.clock.set(f.now);
        }
        if case == "audit_profile" {
            let mut profile = f.profile.clone();
            profile.audit_log_path = f.dir.path().join("other-audit.jsonl");
            req.audit =
                super::super::audit_readiness::audit_readiness(&profile, "other-audit").unwrap();
        }
        let before = f.wire();
        assert_refused(resolve_tx_sign(req).await, expected, &f, &before);
    }
    macro_rules! binding_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                final_binding_refusal($case, P::$expected).await;
            }
        };
    }
    binding_case!(approval_profile_refuses, "profile", ApprovalProfileMismatch);
    binding_case!(approval_chain_refuses, "chain", ApprovalChainMismatch);
    binding_case!(approval_subject_refuses, "subject", ApprovalSubjectMismatch);
    binding_case!(
        a_trustline_approval_does_not_authorize_a_payment,
        "trustline_approval",
        ApprovalSubjectMismatch
    );
    binding_case!(audit_stale_refuses, "audit_age", AuditStale);
    binding_case!(audit_profile_refuses, "audit_profile", AuditProfileMismatch);
    binding_case!(signer_role_refuses, "signer_role", SignerRoleMismatch);

    /// The kind check refuses a verified approval whose subject is the
    /// request's subject when the consumer expects another kind. The same
    /// call with the approval's own kind passes, so the kind is the only
    /// difference.
    #[test]
    #[serial_test::serial]
    fn approval_kind_refuses() {
        use stellar_agent_core::approval::witness::ApprovedKind;
        use stellar_agent_core::policy::{
            Decision, McpToolRegistration, NoopPolicyEngine, PolicyEngine as _, ToolDescriptor,
            ToolValueKind,
        };
        let f = ResolverFixture::new();
        let read_only = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_balances",
            destructive_hint: false,
            read_only_hint: true,
            chain_id_required: true,
            value_kind: ToolValueKind::ReadOnly,
        });
        let evaluation = NoopPolicyEngine
            .evaluate_full(
                &read_only,
                &serde_json::Value::Null,
                &f.profile,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(evaluation.decision, Decision::Allow);
        let approval = f.approval(
            &f.envelope,
            f.now,
            stellar_agent_core::approval::store::governing_ttl_ms(&evaluation),
        );
        let subject = stellar_agent_core::approval::subject::approval_subject_classic(&f.envelope);
        let audit = f.audit();
        let check = |kind| {
            enabled::final_checks(
                &f.context,
                &approval,
                subject,
                kind,
                &evaluation,
                &audit,
                &f.signer,
                f.now,
            )
        };
        assert_eq!(approval.kind(), ApprovedKind::Payment);
        check(ApprovedKind::Payment).unwrap();
        let error = check(ApprovedKind::Trustline).unwrap_err();
        assert!(
            matches!(
                error,
                MainnetAuthorizationError::Refused(P::ApprovalKindMismatch)
            ),
            "expected ApprovalKindMismatch, got {error:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn audit_at_its_ttl_accepts() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let mut req = request(&f, &context, &client, &approval);
        f.clock
            .set(f.now - MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000);
        req.audit = f.audit();
        f.clock.set(f.now);
        resolve_tx_sign(req).await.unwrap();
        assert_eq!(f.wire()["authorizations"][0]["state"], "open");
    }

    fn append_audit(f: &ResolverFixture) {
        use stellar_agent_core::audit_log::{
            AuditEntry, AuditOutbox, NewToolInvocation, PolicyDecision,
        };
        AuditOutbox::for_log(
            &f.profile.audit_log_path,
            crate::keyring::KeyringTipAnchorStore::shared(
                &f.profile.audit_log_hash_chain_key_id,
                &f.profile.audit_log_path,
            ),
        )
        .append(&AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_x402_create_payment",
            "stellar:mainnet",
            vec![],
            PolicyDecision::Allow,
            "00000000-0000-4000-8000-000000000000",
        )))
        .unwrap();
    }
    async fn anchor_consume(repair: bool, release: bool) {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        if release {
            let receipt =
                consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                    .unwrap();
            let (envelope, entries) = final_envelope(&f, &root);
            let child = resolve_soroban_submit(SorobanSubmitRequest {
                context: &context,
                receipt,
                final_envelope_xdr: &envelope,
                signed_auth_entries: &entries,
                store: &f.window,
            })
            .unwrap();
            f.anchor_failure
                .store(true, std::sync::atomic::Ordering::SeqCst);
            append_audit(&f);
            let before = f.wire();
            assert_refused(
                consume_soroban_submit(&context, child, &envelope, &f.window),
                P::AuditNotAnchored,
                &f,
                &before,
            );
        } else {
            f.anchor_failure
                .store(true, std::sync::atomic::Ordering::SeqCst);
            append_audit(&f);
            if repair {
                assert!(auth.0.header.audit.fresh_facts().is_err());
                f.anchor_failure
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            let before = f.wire();
            let result =
                consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window);
            if repair {
                result.unwrap();
                assert_eq!(f.wire()["authorizations"][0]["state"], "used");
            } else {
                assert_refused(result, P::AuditNotAnchored, &f, &before);
            }
        }
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn lagging_anchor_refuses_intent_consume() {
        anchor_consume(false, false).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn repaired_anchor_passes_intent_consume() {
        anchor_consume(true, false).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn release_consume_refuses_lagging_anchor() {
        anchor_consume(false, true).await;
    }

    async fn submit_refusal(case: &str, expected: P) {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let receipt =
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window)
                .unwrap();
        let (envelope, mut entries) = final_envelope(&f, &root);
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        if case == "two_operations" {
            tx.tx.operations = vec![tx.tx.operations[0].clone(), tx.tx.operations[0].clone()]
                .try_into()
                .unwrap();
        } else {
            let mut op = tx.tx.operations[0].clone();
            let OperationBody::InvokeHostFunction(invoke) = &mut op.body else {
                unreachable!()
            };
            match case {
                "host_function" => {
                    invoke.host_function =
                        stellar_xdr::HostFunction::UploadContractWasm(vec![1].try_into().unwrap())
                }
                "entries" => entries.clear(),
                "no_root" => {
                    entries.clear();
                    invoke.auth = vec![].try_into().unwrap();
                }
                "function" => {
                    let stellar_xdr::HostFunction::InvokeContract(args) = &mut invoke.host_function
                    else {
                        unreachable!()
                    };
                    args.function_name = "other".try_into().unwrap();
                }
                _ => unreachable!(),
            }
            tx.tx.operations = vec![op].try_into().unwrap();
        }
        let envelope = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let before = f.wire();
        assert_refused(
            resolve_soroban_submit(SorobanSubmitRequest {
                context: &context,
                receipt,
                final_envelope_xdr: &envelope,
                signed_auth_entries: &entries,
                store: &f.window,
            }),
            expected,
            &f,
            &before,
        );
    }
    macro_rules! submit_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                submit_refusal($case, P::$expected).await;
            }
        };
    }
    submit_case!(
        submit_two_operations_refuse,
        "two_operations",
        DerivationMismatch
    );
    submit_case!(
        submit_other_host_function_refuses,
        "host_function",
        DerivationMismatch
    );
    submit_case!(submit_auth_entries_refuse, "entries", AuthEntriesMismatch);
    submit_case!(submit_missing_root_refuses, "no_root", DerivationMismatch);
    submit_case!(
        submit_other_function_refuses,
        "function",
        DerivationMismatch
    );

    #[tokio::test]
    #[serial_test::serial]
    async fn invalidate_unconsumed_records_stage() {
        for (stage, reason) in [
            (InvalidationStage::SignerUnavailable, "signer_unavailable"),
            (InvalidationStage::SignRefused, "sign_refused"),
            (InvalidationStage::PreSendRefused, "pre_send_refused"),
            (InvalidationStage::SubmitGateRefused, "submit_gate_refused"),
            (
                InvalidationStage::IntentPreTransmitRefused,
                "intent_pre_transmit_refused",
            ),
            (
                InvalidationStage::IntentConsumeRefused,
                "intent_consume_refused",
            ),
            (
                InvalidationStage::PayloadReleaseRefused,
                "payload_release_refused",
            ),
            (InvalidationStage::ConsumeRefused, "consume_refused"),
        ] {
            let f = soroban_fixture();
            let root = root(&f);
            let server = f.server().await;
            let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
            let auth = resolved_intent(&f, &context, &root).await;
            invalidate_unconsumed(&f.window, &context, auth.id(), stage).unwrap();
            let wire = f.wire();
            assert_eq!(wire["authorizations"][0]["state"], "invalidated");
            assert_eq!(wire["authorizations"][0]["invalidation"], reason);
            assert!(wire["holds"].as_array().is_none_or(Vec::is_empty));
        }
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn invalidate_unconsumed_refuses_used_record() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let id = auth.id();
        consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window).unwrap();
        let before = f.wire();
        assert_refused(
            invalidate_unconsumed(
                &f.window,
                &context,
                id,
                InvalidationStage::PayloadReleaseRefused,
            ),
            P::NotOpen,
            &f,
            &before,
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn invalidate_unconsumed_reports_store_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let before = f.wire();
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = invalidate_unconsumed(
            &f.window,
            &context,
            auth.id(),
            InvalidationStage::SignRefused,
        );
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_refused(result, P::StoreUnavailable, &f, &before);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn bound_witness_identifies_mainnet_oracle() {
        let f = large_payment_fixture(true);
        let server = f.server().await;
        let context = f.context_with_routes(&[("oracle.example.invalid", &server.uri())]);
        let witness = witness_for(&f, &context, &f.envelope, "oracle.example.invalid").await;
        assert!(witness.subject().is_some());
        assert_eq!(witness.authority(), "https://oracle.example.invalid");
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn legacy_witness_still_refuses_mainnet_oracle() {
        use crate::cross_check::{
            AccountObservation, CreateAccountWitnessInputs, obtain_classic_witness,
        };
        use stellar_agent_core::{asset_id::CanonicalAsset, cross_check::CrossCheckValue};
        let f = ResolverFixture::configured(oracle_profile, str::to_owned);
        let server = f.server().await;
        let mut profile = f.profile.clone();
        profile.cross_check_threshold_stroops = 0;
        let context = f
            .context_with_routes(&[("oracle.example.invalid", &server.uri())])
            .network_context();
        let data = f.source.ledger_entries_result();
        let stellar_xdr::LedgerEntryData::Account(account) =
            stellar_xdr::LedgerEntryData::from_xdr_base64(
                data["entries"][0]["xdr"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap()
        else {
            unreachable!()
        };
        let view = crate::account::project_account_entry(f.source.source(), &account).unwrap();
        let inputs = CreateAccountWitnessInputs {
            source: AccountObservation::from_view(&view).unwrap(),
        };
        let error = obtain_classic_witness(
            &profile,
            &context,
            CrossCheckValue::Amount {
                asset: &CanonicalAsset::Native,
                base_units: i128::from(profile.effective_cross_check_threshold_stroops()),
            },
            inputs,
            "stellar_create_account",
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "network.mainnet_write_forbidden");
    }

    #[test]
    #[serial_test::serial]
    fn soroban_fixture_verifies_its_proofs() {
        let f = soroban_fixture();
        let root = root(&f);
        let approval = intent_approval(&f, &root, None);
        assert_eq!(
            approval.kind(),
            stellar_agent_core::approval::witness::ApprovedKind::X402Payment
        );
        assert_eq!(
            f.policy.mainnet().unwrap().profile,
            f.context.profile_name()
        );
        assert_eq!(f.enablement.policy_sequence(), f.policy.sequence());
    }

    fn alternate_policy(
        f: &ResolverFixture,
        edit: impl FnOnce(&mut toml_edit::DocumentMut),
        profile: &stellar_agent_core::profile::schema::Profile,
        name: &str,
    ) -> VerifiedPolicy {
        use stellar_agent_core::policy::v1::{
            canonical, signature,
            verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
        };
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let mut raw = std::fs::read_to_string(f.dir.path().join("policy.toml"))
            .unwrap()
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        raw.remove("signature");
        edit(&mut raw);
        let canonical = canonical::canonical_bytes(&raw.to_string()).unwrap();
        let signature = signature::sign(&signature::digest(&canonical), &owner);
        let path = f.dir.path().join("alternate-policy.toml");
        std::fs::write(
            &path,
            format!(
                "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&signature)
            ),
        )
        .unwrap();
        let mut profile = profile.clone();
        profile
            .policy_window_state_key_id
            .account
            .push_str("-alternate");
        load_verified_policy(
            &PolicyLoad {
                path: &path,
                profile: &profile,
                profile_name: name,
                owner_pubkey: &owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &f.dir.path().join("alternate.window"),
            },
            stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap()
    }
    async fn policy_binding_refusal(case: &str, expected: P) {
        let f = ResolverFixture::new();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let profile = f.profile.clone();
        let policy = alternate_policy(
            &f,
            |doc| match case {
                "body" => {
                    doc.remove("mainnet");
                }
                "name" => {
                    doc["scope"] = toml_edit::value("profile:other");
                    doc["mainnet"]["profile"] = toml_edit::value("other");
                }
                "sequence" => doc["sequence"] = toml_edit::value(8),
                _ => unreachable!(),
            },
            &profile,
            if case == "name" { "other" } else { "operator" },
        );
        let client = StellarRpcClient::with_test_transport(
            "https://rpc.example.invalid",
            "http://127.0.0.1:1",
        )
        .unwrap();
        let before = f.wire();
        let mut req = request(&f, &f.context, &client, &approval);
        req.policy = &policy;
        assert_refused(resolve_tx_sign(req).await, expected, &f, &before);
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_without_mainnet_body_refuses() {
        policy_binding_refusal("body", P::PolicyNotMainnet).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_profile_refuses() {
        policy_binding_refusal("name", P::ProfileMismatch).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn enablement_sequence_refuses() {
        policy_binding_refusal("sequence", P::EnablementSequenceMismatch).await;
    }

    async fn enablement_binding_refusal(other_name: bool) {
        let f = ResolverFixture::new();
        let name = if other_name { "other" } else { "operator" };
        let mut profile = f.profile.clone();
        if !other_name {
            profile.rpc_url = "https://other.example.invalid".into();
        }
        let policy = alternate_policy(
            &f,
            |doc| {
                doc["scope"] = toml_edit::value(format!("profile:{name}"));
                doc["mainnet"]["profile"] = toml_edit::value(name);
                if !other_name {
                    doc["mainnet"]["endpoint_host"] = toml_edit::value("other.example.invalid");
                }
            },
            &profile,
            name,
        );
        let profiles = f.dir.path().join("alternate-profiles");
        stellar_agent_core::profile::loader::save_to_dir(name, &profile, &profiles).unwrap();
        let enablement = stellar_agent_core::mainnet::enablement::verify_enablement(
            &policy,
            name,
            stellar_agent_core::profile::name::ProfileNameSource::Flag,
            &profile,
            &profiles,
            &|_| Ok("installation-nonce".to_owned()),
        )
        .unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        if other_name {
            let client = StellarRpcClient::with_test_transport(
                "https://rpc.example.invalid",
                "http://127.0.0.1:1",
            )
            .unwrap();
            let mut req = request(&f, &f.context, &client, &approval);
            req.enablement = &enablement;
            assert_refused(resolve_tx_sign(req).await, P::ProfileMismatch, &f, &before);
        } else {
            let server = f.server().await;
            let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
            let client = context.primary_client().unwrap();
            let mut req = request(&f, &context, &client, &approval);
            req.enablement = &enablement;
            assert_refused(
                resolve_tx_sign(req).await,
                P::EnablementHostMismatch,
                &f,
                &before,
            );
        }
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn enablement_profile_refuses() {
        enablement_binding_refusal(true).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn enablement_host_refuses() {
        enablement_binding_refusal(false).await;
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn policy_evaluation_error_refuses() {
        use stellar_agent_core::policy::v1::criteria::state_store::StateKey;
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        f.policy
            .engine()
            .state_store()
            .append_pending(
                &StateKey::new("operator", 1, "rate_limit", 86400),
                stellar_agent_core::timefmt::now_unix_ms().unwrap() + 60_000,
                1,
            )
            .unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            P::PolicyEvaluationFailed,
            &f,
            &before,
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn snapshot_ignores_merged_threshold() {
        let f = ResolverFixture::configured(
            |profile| {
                oracle_profile(profile);
                profile.cross_check_threshold_stroops = 0;
            },
            |raw| {
                raw.replace("native = \"10000000000\"", "native = \"100000000000\"")
                    .replace("max_stroops = \"100\"", "max_stroops = \"1000000000000\"")
                    .replace("max_stroops = \"200\"", "max_stroops = \"1000000000000\"")
            },
        );
        let server = f.server().await;
        let mut merged = f.profile.clone();
        merged.cross_check_threshold_stroops = 100_000_000_000;
        let context = crate::NetworkContext::mainnet_write(
            &merged,
            &stellar_agent_core::profile::name::ResolvedProfileName::from_flag("operator"),
            &f.dir.path().join("profiles"),
            crate::MainnetEndpointFlags::default(),
        )
        .unwrap()
        .with_test_transport_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let amount = f.profile.effective_cross_check_threshold_stroops();
        let envelope = changed_envelope(&f, |tx| {
            let mut op = tx.tx.operations[0].clone();
            let OperationBody::Payment(payment) = &mut op.body else {
                unreachable!()
            };
            payment.amount = i64::try_from(amount).unwrap();
            tx.tx.operations = vec![op].try_into().unwrap();
        });
        let approval = f.approval(&envelope, f.now, 600_000);
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.unsigned_envelope_xdr = &envelope;
        assert_refused(resolve_tx_sign(req).await, P::WitnessRequired, &f, &before);
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn witness_threshold_missing_refuses() {
        let token = token();
        let f = ResolverFixture::configured(
            |_| {},
            |raw| {
                raw.replace("stellar_pay", "stellar_x402_create_payment")
                    .replace("\"native\"", &format!("\"{token}\""))
            },
        );
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = intent_approval(&f, &root, None);
        let before = f.wire();
        assert_refused(
            resolve_soroban_intent(intent_request(
                &f,
                &context,
                &client,
                &intent(&root),
                &approval,
            ))
            .await,
            P::WitnessThresholdMissing,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn approval_outliving_shortened_rule_refuses() {
        let mut f = ResolverFixture::configured(
            |_| {},
            |raw| {
                raw.replace(
                    "decision = \"allow\"",
                    "decision = \"require_approval\"\nttl_secs = 3600\nreason = \"review\"",
                )
            },
        );
        let approval = f.approval(&f.envelope, f.now, 3_600_000);
        let policy = alternate_policy(
            &f,
            |doc| {
                doc["sequence"] = toml_edit::value(8);
                doc["rules"][0]["ttl_secs"] = toml_edit::value(600);
            },
            &f.profile,
            "operator",
        );
        f.enablement = stellar_agent_core::mainnet::enablement::verify_enablement(
            &policy,
            "operator",
            stellar_agent_core::profile::name::ProfileNameSource::Flag,
            &f.profile,
            &f.dir.path().join("profiles"),
            &|_| Ok("installation-nonce".to_owned()),
        )
        .unwrap();
        use stellar_agent_core::policy::v1::verified::{
            OwnerKeySource, PinMode, PolicyLoad, load_verified_policy,
        };
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        f.policy = load_verified_policy(
            &PolicyLoad {
                path: &f.dir.path().join("alternate-policy.toml"),
                profile: &f.profile,
                profile_name: "operator",
                owner_pubkey: &owner.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &f.dir.path().join("state.window"),
            },
            stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let before = f.wire();
        assert_refused(
            resolve_tx_sign(request(&f, &context, &client, &approval)).await,
            P::ApprovalTtlExceedsRule,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn open_authorization_limit_refuses() {
        let f = ResolverFixture::configured(
            |_| {},
            |raw| {
                raw.replace("max_stroops = \"200\"", "max_stroops = \"1000\"")
                    .replace("max_calls = 10", "max_calls = 100")
            },
        );
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        for n in 0..=crate::policy_state::MAX_OPEN_AUTHORIZATIONS {
            let envelope = changed_envelope(&f, |tx| {
                tx.tx.memo = stellar_xdr::Memo::Text(n.to_string().into_bytes().try_into().unwrap())
            });
            let approval = f.approval(&envelope, f.now, 600_000);
            let before = f.wire();
            let mut req = request(&f, &context, &client, &approval);
            req.unsigned_envelope_xdr = &envelope;
            let result = resolve_tx_sign(req).await;
            if n < crate::policy_state::MAX_OPEN_AUTHORIZATIONS {
                result.unwrap();
            } else {
                assert_refused(result, P::TooManyOpen, &f, &before);
            }
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn mint_store_failure_refuses() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let before = f.wire();
        let req = request(&f, &context, &client, &approval);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = resolve_tx_sign(req).await;
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_refused(result, P::StoreUnavailable, &f, &before);
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn signer_coordinate_refuses() {
        let f = ResolverFixture::new();
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let approval = f.approval(&f.envelope, f.now, 600_000);
        let mut other = f.profile.clone();
        other.mcp_signer_default.service.push_str("-other");
        let identity = stellar_agent_core::profile::schema::signer_identity_entry_ref(
            &other.mcp_signer_default,
        );
        keyring_core::Entry::new(&identity.service, &identity.account)
            .unwrap()
            .set_password(
                &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
                    f.signer.public_key(),
                )
                .render(),
            )
            .unwrap();
        let path = f.dir.path().join("other-profiles");
        stellar_agent_core::profile::loader::save_to_dir("operator", &other, &path).unwrap();
        let signer = crate::keyring::enrolled_signer(
            "operator",
            &path,
            &other,
            crate::keyring::EnrolledRole::Agent,
            &f.signer.public_key(),
        )
        .unwrap();
        let before = f.wire();
        let mut req = request(&f, &context, &client, &approval);
        req.signer = &signer;
        assert_refused(
            resolve_tx_sign(req).await,
            P::SignerCoordinateMismatch,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn soroban_future_created_approval_refuses() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let intent = intent(&root);
        let entry = stellar_agent_core::approval::PendingApproval::new_x402_pending(
            &intent.network_id,
            &root,
            None,
            "1000".into(),
            600_000,
        )
        .unwrap();
        let created = entry.created_at_unix_ms;
        let digest =
            stellar_agent_core::approval::subject::soroban_intent_digest(&intent.network_id, &root)
                .unwrap();
        let subject = stellar_agent_core::approval::subject::approval_subject_x402(&digest);
        let approval = f.attested(
            &entry,
            &f.profile,
            "operator",
            stellar_agent_core::approval::witness::ApprovedKind::X402Payment,
            subject,
            created,
        );
        f.clock.set(created - 8 * 24 * 60 * 60 * 1000);
        let before = f.wire();
        assert_refused(
            resolve_soroban_intent(intent_request(&f, &context, &client, &intent, &approval)).await,
            P::NotYetValid,
            &f,
            &before,
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn nonce_held_in_any_state_refuses_root_mint() {
        use super::super::{
            AuthorizationDomain, RecomputedFacts,
            digest::{content_digest, entries_digest},
        };
        use crate::policy_state::{ConsumptionBinding, DomainBinding, SubmissionBinding};
        for state in ["open", "used", "expired", "invalidated"] {
            let f = ResolverFixture::new();
            let server = f.server().await;
            let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
            let client = context.primary_client().unwrap();
            let approval = f.approval(&f.envelope, f.now, 600_000);
            let auth = resolve_tx_sign(request(&f, &context, &client, &approval))
                .await
                .unwrap();
            match state {
                "used" => {
                    let DomainBinding::Transaction {
                        tx_hash,
                        source,
                        sequence,
                        ..
                    } = &auth.0.binding
                    else {
                        unreachable!()
                    };
                    let facts = RecomputedFacts {
                        content_digest: content_digest(AuthorizationDomain::Transaction, tx_hash),
                        entries_digest: entries_digest(auth.entries()),
                        audit: auth.0.header.audit.fresh_facts().unwrap(),
                    };
                    f.window
                        .consume_authorization(
                            &f.profile,
                            auth.id(),
                            &auth.consume_expect(&facts),
                            &ConsumptionBinding::Transaction(SubmissionBinding {
                                fee_bump: None,
                                envelope_hash:
                                    stellar_agent_core::approval::subject::approval_subject_classic(
                                        &f.envelope,
                                    ),
                                tx_hash: *tx_hash,
                                source: source.clone(),
                                sequence: *sequence,
                                max_time: 0,
                                pending_since_ms: f.now,
                                submission_ledger: 100,
                            }),
                        )
                        .unwrap();
                }
                "expired" => {
                    f.clock.set(auth.expires_at_ms());
                    f.window
                        .open_authorizations(&f.profile, auth.expires_at_ms())
                        .unwrap();
                }
                "invalidated" => invalidate_unconsumed(
                    &f.window,
                    &context,
                    auth.id(),
                    InvalidationStage::SignRefused,
                )
                .unwrap(),
                _ => {}
            }
            let envelope = changed_envelope(&f, |tx| {
                tx.tx.memo = stellar_xdr::Memo::Text(b"second".to_vec().try_into().unwrap())
            });
            let mut entry = stellar_agent_core::approval::PendingApproval::new_payment_pending(
                envelope.clone(),
                envelope.as_bytes(),
                f.source.destination().into(),
                10,
                "XLM".into(),
                None,
                100,
                1,
                "1000".into(),
                600_000,
            )
            .unwrap();
            entry.approval_nonce = approval.nonce().to_owned();
            entry.created_at_unix_ms = f.now;
            entry.expires_at_unix_ms = f.now + 600_000;
            let second = f.attested(
                &entry,
                &f.profile,
                "operator",
                stellar_agent_core::approval::witness::ApprovedKind::Payment,
                stellar_agent_core::approval::subject::approval_subject_classic(&envelope),
                f.now,
            );
            let before = f.wire();
            let mut req = request(&f, &context, &client, &second);
            req.unsigned_envelope_xdr = &envelope;
            assert_refused(
                resolve_tx_sign(req).await,
                P::ApprovalNonceReused,
                &f,
                &before,
            );
        }
    }
    async fn soroban_approval_refusal(case: &str, expected: P) {
        use stellar_agent_core::approval::{
            PendingApproval,
            subject::{approval_subject_x402, soroban_intent_digest},
            witness::ApprovedKind,
        };
        let f = soroban_fixture();
        let root = root(&f);
        let mut approved = root.clone();
        if case == "subject" {
            let SorobanAuthorizedFunction::ContractFn(args) = &mut approved.function else {
                unreachable!()
            };
            let mut values = args.args.to_vec();
            values[2] = ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 11 });
            args.args = values.try_into().unwrap();
        }
        let mut profile = f.profile.clone();
        if case == "chain" {
            profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        }
        let network_id = Sha256::digest(profile.chain_id.network_passphrase().as_bytes()).into();
        let mut entry = PendingApproval::new_x402_pending(
            &network_id,
            &approved,
            None,
            "1000".into(),
            if case == "ttl" { 601_000 } else { 600_000 },
        )
        .unwrap();
        entry.created_at_unix_ms = f.now;
        entry.expires_at_unix_ms = f.now + if case == "ttl" { 601_000 } else { 600_000 };
        let subject =
            approval_subject_x402(&soroban_intent_digest(&network_id, &approved).unwrap());
        let approval = f.attested(
            &entry,
            &profile,
            if case == "profile" {
                "other"
            } else {
                "operator"
            },
            ApprovedKind::X402Payment,
            subject,
            f.now,
        );
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        if case == "expired" {
            f.clock.set(f.now + 600_000);
        }
        let before = f.wire();
        assert_refused(
            resolve_soroban_intent(intent_request(
                &f,
                &context,
                &client,
                &intent(&root),
                &approval,
            ))
            .await,
            expected,
            &f,
            &before,
        );
    }
    macro_rules! soroban_approval_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                soroban_approval_refusal($case, P::$expected).await;
            }
        };
    }
    soroban_approval_case!(
        soroban_approval_profile_refuses,
        "profile",
        ApprovalProfileMismatch
    );
    soroban_approval_case!(
        soroban_approval_chain_refuses,
        "chain",
        ApprovalChainMismatch
    );
    soroban_approval_case!(
        soroban_approval_subject_refuses,
        "subject",
        ApprovalSubjectMismatch
    );
    soroban_approval_case!(soroban_approval_expired_refuses, "expired", ApprovalExpired);
    soroban_approval_case!(soroban_approval_ttl_refuses, "ttl", ApprovalTtlExceedsRule);

    async fn soroban_witness_case(case: &str, expected: Option<P>) {
        use crate::cross_check::{
            BoundSorobanInputs, CrossCheckOutcome, SorobanWitnessInputs,
            obtain_soroban_witness_bound,
        };
        use stellar_agent_core::{
            asset_id::CanonicalAsset,
            cross_check::{CrossCheckValue, ThresholdSet},
        };
        let token = token();
        let f = ResolverFixture::configured(oracle_profile, |raw| {
            raw.replace("stellar_pay", "stellar_x402_create_payment")
                .replace("\"native\"", &format!("\"{token}\""))
                .replace("native = \"10000000000\"", &format!("\"{token}\" = \"1\""))
        });
        let root = root(&f);
        let mut approved = root.clone();
        if case == "subject" {
            let SorobanAuthorizedFunction::ContractFn(args) = &mut approved.function else {
                unreachable!()
            };
            let mut values = args.args.to_vec();
            values[2] = ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 11 });
            args.args = values.try_into().unwrap();
        }
        let primary_server = f.server().await;
        let oracle_server = f.server().await;
        let context = f.context_with_routes(&[
            ("rpc.example.invalid", &primary_server.uri()),
            ("oracle.example.invalid", &oracle_server.uri()),
            ("third.example.invalid", &oracle_server.uri()),
        ]);
        let client = context.primary_client().unwrap();
        let approval = intent_approval(&f, &root, None);
        let host = match case {
            "same_host" => "rpc.example.invalid",
            "third_host" => "third.example.invalid",
            _ => "oracle.example.invalid",
        };
        let mut profile = f.profile.clone();
        profile.oracle_provider_url = Some(format!("https://{host}").parse().unwrap());
        profile.providers.as_mut().unwrap().oracle = Some(
            stellar_agent_core::profile::schema::ProviderRecord::new("oracle", host, true),
        );
        let (encoded, _) = final_envelope(&f, &approved);
        let envelope = TransactionEnvelope::from_xdr_base64(encoded, Limits::none()).unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: stellar_xdr::SorobanCredentials::Address(
                stellar_xdr::SorobanAddressCredentials {
                    address: ScAddress::Account(stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            f.signer.public_key(),
                        )),
                    )),
                    nonce: 7,
                    signature_expiration_ledger: 0,
                    signature: ScVal::Void,
                },
            ),
            root_invocation: approved.clone(),
        };
        let simulation = serde_json::json!({"transactionData":"AAAA", "minResourceFee":"1000", "latestLedger":1000,
            "results":[{"auth":[entry.to_xdr_base64(Limits::none()).unwrap()], "xdr":ScVal::Void.to_xdr_base64(Limits::none()).unwrap()}]});
        wiremock::Mock::given(wiremock::matchers::body_partial_json(
            serde_json::json!({"method":"simulateTransaction"}),
        ))
        .respond_with(stellar_agent_test_support::EchoIdResponder::new(
            simulation.clone(),
        ))
        .mount(if case == "same_host" {
            &primary_server
        } else {
            &oracle_server
        })
        .await;
        let primary = serde_json::from_value(simulation).unwrap();
        let inputs = SorobanWitnessInputs {
            envelope: &envelope,
            primary: &primary,
            expiration_ledger: 1060,
            resource_fee_ceiling: 10_000_000,
        };
        let thresholds = ThresholdSet::from_profile_and_signed(
            &profile,
            f.policy.mainnet().unwrap().cross_check_thresholds.as_ref(),
        );
        let witness = obtain_soroban_witness_bound(
            &profile,
            &context.network_context(),
            CrossCheckValue::Amount {
                asset: &CanonicalAsset::contract(&token).unwrap(),
                base_units: 10,
            },
            &thresholds,
            &BoundSorobanInputs {
                inputs: &inputs,
                expected_root: &approved,
                payer: f.source.source(),
            },
            "stellar_x402_create_payment",
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = witness else {
            panic!("bound witness required")
        };
        let payment = intent(&root);
        let mut req = intent_request(&f, &context, &client, &payment, &approval);
        req.witness = if case == "missing" {
            None
        } else {
            Some(&witness)
        };
        let before = f.wire();
        let result = resolve_soroban_intent(req).await;
        if let Some(expected) = expected {
            assert_refused(result, expected, &f, &before);
        } else {
            let auth = result.unwrap();
            assert_eq!(auth.0.header.witness_subject, witness.subject());
        }
    }
    macro_rules! soroban_witness_case_test {
        ($name:ident, $case:literal, $expected:expr) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                soroban_witness_case($case, $expected).await;
            }
        };
    }
    soroban_witness_case_test!(soroban_required_witness_accepts, "accept", None);
    soroban_witness_case_test!(
        soroban_witness_required_refuses,
        "missing",
        Some(P::WitnessRequired)
    );
    soroban_witness_case_test!(
        soroban_witness_subject_refuses,
        "subject",
        Some(P::WitnessSubject)
    );
    soroban_witness_case_test!(
        soroban_same_host_witness_refuses,
        "same_host",
        Some(P::WitnessSameHost)
    );
    soroban_witness_case_test!(
        soroban_witness_oracle_binding_refuses,
        "third_host",
        Some(P::WitnessOracleUnbound)
    );

    /// How the oracle of a below-threshold payment answers.
    enum BelowThresholdOracle {
        /// The oracle reports mainnet and answers `getLatestLedger` with this
        /// ledger.
        Ledger(u32),
        /// The profile names no oracle.
        Unconfigured,
        /// The oracle reports the testnet passphrase and answers
        /// `getLatestLedger` with the primary's ledger.
        Testnet,
    }

    /// The methods `server` received, in order.
    async fn received_methods(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                request.body_json::<serde_json::Value>().unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// Runs the bound Soroban witness of the `soroban_witness_case` payment
    /// with a value of 10 below the token's threshold of 1000. The primary
    /// simulated at ledger 1000 and the signature expires at ledger 1060.
    /// Returns the outcome with the methods the primary and the oracle
    /// received.
    async fn below_threshold_case(
        oracle: BelowThresholdOracle,
    ) -> (
        Result<crate::cross_check::CrossCheckOutcome, stellar_agent_core::error::WalletError>,
        Vec<String>,
        Vec<String>,
    ) {
        use crate::cross_check::{
            BoundSorobanInputs, SorobanWitnessInputs, obtain_soroban_witness_bound,
        };
        use stellar_agent_core::{
            asset_id::CanonicalAsset,
            cross_check::{
                CrossCheckRequirement, CrossCheckValue, ThresholdSet, cross_check_requirement,
            },
            profile::caip2::{Caip2, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE},
        };
        use stellar_agent_test_support::{EchoIdResponder, signed_envelope::get_network_result};
        use wiremock::matchers::body_partial_json;
        let token = token();
        let f = ResolverFixture::configured(oracle_profile, |raw| {
            raw.replace("stellar_pay", "stellar_x402_create_payment")
                .replace("\"native\"", &format!("\"{token}\""))
                .replace(
                    "native = \"10000000000\"",
                    &format!("\"{token}\" = \"1000\""),
                )
        });
        let root = root(&f);
        let primary_server = f.server().await;
        let oracle_server = wiremock::MockServer::start().await;
        let (passphrase, ledger) = match oracle {
            BelowThresholdOracle::Ledger(ledger) => (MAINNET_PASSPHRASE, ledger),
            BelowThresholdOracle::Unconfigured => (MAINNET_PASSPHRASE, 1000),
            BelowThresholdOracle::Testnet => (TESTNET_PASSPHRASE, 1000),
        };
        wiremock::Mock::given(body_partial_json(
            serde_json::json!({"method": "getNetwork"}),
        ))
        .respond_with(EchoIdResponder::new(get_network_result(passphrase)))
        .mount(&oracle_server)
        .await;
        wiremock::Mock::given(body_partial_json(
            serde_json::json!({"method": "getLatestLedger"}),
        ))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "id": "0".repeat(64),
            "protocolVersion": 23,
            "sequence": ledger,
        })))
        .mount(&oracle_server)
        .await;
        let context = f.context_with_routes(&[
            ("rpc.example.invalid", &primary_server.uri()),
            ("oracle.example.invalid", &oracle_server.uri()),
        ]);
        let mut profile = f.profile.clone();
        if matches!(oracle, BelowThresholdOracle::Unconfigured) {
            profile.oracle_provider_url = None;
            profile.providers.as_mut().unwrap().oracle = None;
        } else {
            profile.oracle_provider_url = Some("https://oracle.example.invalid".parse().unwrap());
            profile.providers.as_mut().unwrap().oracle =
                Some(stellar_agent_core::profile::schema::ProviderRecord::new(
                    "oracle",
                    "oracle.example.invalid",
                    true,
                ));
        }
        let (encoded, _) = final_envelope(&f, &root);
        let envelope = TransactionEnvelope::from_xdr_base64(encoded, Limits::none()).unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: stellar_xdr::SorobanCredentials::Address(
                stellar_xdr::SorobanAddressCredentials {
                    address: ScAddress::Account(stellar_xdr::AccountId(
                        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(
                            f.signer.public_key(),
                        )),
                    )),
                    nonce: 7,
                    signature_expiration_ledger: 0,
                    signature: ScVal::Void,
                },
            ),
            root_invocation: root.clone(),
        };
        let primary = serde_json::from_value(serde_json::json!({
            "transactionData": "AAAA",
            "minResourceFee": "1000",
            "latestLedger": 1000,
            "results": [{
                "auth": [entry.to_xdr_base64(Limits::none()).unwrap()],
                "xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
            }],
        }))
        .unwrap();
        let inputs = SorobanWitnessInputs {
            envelope: &envelope,
            primary: &primary,
            expiration_ledger: 1060,
            resource_fee_ceiling: 10_000_000,
        };
        let thresholds = ThresholdSet::from_profile_and_signed(
            &profile,
            f.policy.mainnet().unwrap().cross_check_thresholds.as_ref(),
        );
        let asset = CanonicalAsset::contract(&token).unwrap();
        let value = CrossCheckValue::Amount {
            asset: &asset,
            base_units: 10,
        };
        assert_eq!(
            cross_check_requirement(
                Caip2::Mainnet,
                value,
                &thresholds,
                profile.oracle_provider_url.is_some(),
                false,
            )
            .unwrap(),
            CrossCheckRequirement::NotRequired
        );
        let outcome = obtain_soroban_witness_bound(
            &profile,
            &context.network_context(),
            value,
            &thresholds,
            &BoundSorobanInputs {
                inputs: &inputs,
                expected_root: &root,
                payer: f.source.source(),
            },
            "stellar_x402_create_payment",
        )
        .await;
        (
            outcome,
            received_methods(&primary_server).await,
            received_methods(&oracle_server).await,
        )
    }

    /// The `simulation.divergence` field of a refused below-threshold payment.
    fn divergence_field(
        outcome: Result<
            crate::cross_check::CrossCheckOutcome,
            stellar_agent_core::error::WalletError,
        >,
    ) -> stellar_agent_core::cross_check::WitnessField {
        match outcome {
            Err(stellar_agent_core::error::WalletError::Network(
                stellar_agent_core::error::NetworkError::WitnessDivergence {
                    entry: stellar_agent_core::cross_check::WitnessEntry::SorobanSimulation,
                    field,
                    sequence_delta: None,
                },
            )) => field,
            other => panic!("expected a Soroban simulation divergence, got {other:?}"),
        }
    }

    /// Below the threshold on mainnet the oracle answers its identity and its
    /// latest ledger, and simulates nothing; a current ledger passes as
    /// `NotRequired`.
    #[tokio::test]
    #[serial_test::serial]
    async fn below_threshold_mainnet_payment_reads_the_oracle_ledger() {
        let (outcome, primary, oracle) =
            below_threshold_case(BelowThresholdOracle::Ledger(1000)).await;
        assert!(
            matches!(
                outcome,
                Ok(crate::cross_check::CrossCheckOutcome::NotRequired)
            ),
            "{outcome:?}"
        );
        assert!(primary.is_empty(), "{primary:?}");
        assert_eq!(oracle, ["getNetwork", "getLatestLedger"]);
    }

    /// An oracle three ledgers behind the primary's simulation cannot vouch
    /// for it: a primary that inflates its ledger is refused before signing.
    #[tokio::test]
    #[serial_test::serial]
    async fn below_threshold_oracle_three_ledgers_behind_refuses() {
        let (outcome, _, oracle) = below_threshold_case(BelowThresholdOracle::Ledger(997)).await;
        assert_eq!(
            divergence_field(outcome),
            stellar_agent_core::cross_check::WitnessField::LedgerSkew
        );
        assert_eq!(oracle, ["getNetwork", "getLatestLedger"]);
    }

    /// An oracle already at the signature expiration ledger refuses.
    #[tokio::test]
    #[serial_test::serial]
    async fn below_threshold_oracle_at_the_expiration_refuses() {
        let (outcome, _, _) = below_threshold_case(BelowThresholdOracle::Ledger(1060)).await;
        assert_eq!(
            divergence_field(outcome),
            stellar_agent_core::cross_check::WitnessField::Expiration
        );
    }

    /// A mainnet profile without an oracle refuses a payment below the
    /// threshold before any request, naming `oracle_provider_url`.
    #[tokio::test]
    #[serial_test::serial]
    async fn below_threshold_mainnet_without_an_oracle_refuses() {
        let (outcome, primary, oracle) =
            below_threshold_case(BelowThresholdOracle::Unconfigured).await;
        let error = outcome.unwrap_err();
        assert!(
            matches!(
                &error,
                stellar_agent_core::error::WalletError::Network(
                    stellar_agent_core::error::NetworkError::WitnessUnavailable {
                        reason:
                            stellar_agent_core::error::WitnessUnavailableReason::OracleNotConfigured,
                    }
                )
            ),
            "{error:?}"
        );
        assert_eq!(error.code(), "network.witness_unavailable");
        assert!(error.to_string().contains("oracle_provider_url"), "{error}");
        assert!(primary.is_empty(), "{primary:?}");
        assert!(oracle.is_empty(), "{oracle:?}");
    }

    /// An oracle that reports another network refuses at its identity check
    /// and is never asked for its ledger.
    #[tokio::test]
    #[serial_test::serial]
    async fn below_threshold_oracle_on_another_network_refuses() {
        let (outcome, _, oracle) = below_threshold_case(BelowThresholdOracle::Testnet).await;
        let error = outcome.unwrap_err();
        assert!(
            matches!(
                &error,
                stellar_agent_core::error::WalletError::Network(
                    stellar_agent_core::error::NetworkError::WitnessUnavailable {
                        reason: stellar_agent_core::error::WitnessUnavailableReason::IdentityNetworkMismatch { .. },
                    }
                )
            ),
            "{error:?}"
        );
        assert!(
            !oracle.iter().any(|method| method == "getLatestLedger"),
            "{oracle:?}"
        );
        assert!(
            oracle.iter().all(|method| method == "getNetwork"),
            "{oracle:?}"
        );
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn changed_audit_provenance_refuses_intent_consume() {
        let f = soroban_fixture();
        let root = root(&f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let auth = resolved_intent(&f, &context, &root).await;
        let writer = auth.0.header.audit.writer().clone();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = writer.lock().unwrap();
            panic!("writer unavailable");
        }));
        assert!(poisoned.is_err());
        let before = f.wire();
        assert_refused(
            consume_soroban_intent(&context, auth.into_signed(), &intent(&root), &f.window),
            P::AuditProvenance,
            &f,
            &before,
        );
    }

    // ── The message domain ─────────────────────────────────────────────

    use super::super::RecomputedFacts;
    use super::super::digest::BindingFacts;
    use super::super::fixtures::{
        MESSAGE_HOME_DOMAIN, message_facts, x402_fixture, x402_intent, x402_policy, x402_root,
    };
    use crate::policy_state::ConsumptionBinding;

    const EPHEMERAL: [u8; 32] = [0xe1; 32];

    /// The message record of the fixture's ledger.
    fn message_record(f: &ResolverFixture) -> serde_json::Value {
        f.wire()["authorizations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["domain"] == "message")
            .unwrap()
            .clone()
    }

    /// The operator's attestation of the authenticated payment `root` for
    /// `home_domain`, bound to `profile` under `name`.
    fn bound_x402_approval(
        f: &ResolverFixture,
        root: &SorobanAuthorizedInvocation,
        profile: &stellar_agent_core::profile::schema::Profile,
        name: &str,
    ) -> ApprovalWitness {
        use stellar_agent_core::approval::subject::{
            approval_subject_x402_authenticated, soroban_intent_digest,
        };
        let network_id = Sha256::digest(profile.chain_id.network_passphrase().as_bytes()).into();
        let mut entry = stellar_agent_core::approval::PendingApproval::new_x402_pending(
            &network_id,
            root,
            Some(MESSAGE_HOME_DOMAIN.to_owned()),
            "1000".into(),
            600_000,
        )
        .unwrap();
        entry.created_at_unix_ms = f.now;
        entry.expires_at_unix_ms = f.now + 600_000;
        let subject = approval_subject_x402_authenticated(
            &soroban_intent_digest(&network_id, root).unwrap(),
            MESSAGE_HOME_DOMAIN,
        );
        f.attested(
            &entry,
            profile,
            name,
            ApprovedKind::X402Payment,
            subject,
            f.now,
        )
    }

    /// The accepted record of each lifetime source: the policy's
    /// `authorization_ttl_seconds`, the default, and an approval that
    /// expires first.
    #[test]
    #[serial_test::serial]
    fn message_resolver_mints_a_zero_value_record() {
        use super::super::digest::bindings_digest;
        for case in ["policy_ttl", "default_ttl", "approval_first"] {
            let f = if case == "default_ttl" {
                ResolverFixture::configured(
                    |_| {},
                    |raw| x402_policy(&raw.replace("authorization_ttl_seconds = 60\n", ""), |r| r),
                )
            } else {
                x402_fixture()
            };
            let root = x402_root(&f);
            let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
            let message = message_facts([1; 32], EPHEMERAL);
            let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
            // The approval is attested against the wall clock, so the case
            // where it expires before the record moves the resolver's clock
            // to ten seconds before the approval's expiry.
            let minted_at = if case == "approval_first" {
                f.now + 590_000
            } else {
                f.now
            };
            f.clock.set(minted_at);
            let auth =
                resolve_message_sign(f.message_request(&intent, &message, &approval)).unwrap();
            let wire = f.wire();
            let records = wire["authorizations"].as_array().unwrap();
            assert_eq!(records.len(), 1, "{case}");
            let record = &records[0];
            assert_eq!(record["domain"], "message", "{case}");
            assert_eq!(record["consumer"], "x402_authenticated", "{case}");
            assert_eq!(record["state"], "open", "{case}");
            assert!(record.get("reservation").is_none(), "{case}");
            assert!(record.get("parent").is_none(), "{case}");
            assert!(wire["holds"].as_array().is_none_or(Vec::is_empty), "{case}");
            assert_eq!(auth.signer_public_key(), EPHEMERAL, "{case}");
            assert_eq!(auth.signer_role(), super::super::SignerRole::Sep10Ephemeral);
            assert_eq!(auth.endpoint(), None, "{case}");
            let header = &auth.inner().header;
            assert_eq!(header.issued_at_ms, minted_at, "{case}");
            let ttl = if case == "default_ttl" {
                120_000
            } else {
                60_000
            };
            let expected = (header.issued_at_ms + ttl).min(approval.expires_at_ms());
            assert_eq!(auth.expires_at_ms(), expected, "{case}");
            assert_eq!(record["expires_ms"], expected, "{case}");
            if case == "approval_first" {
                assert_eq!(expected, approval.expires_at_ms());
            } else {
                assert_eq!(expected, f.now + ttl);
            }
            let facts = BindingFacts {
                endpoint: None,
                signer: super::super::message::ephemeral_signer_fact(EPHEMERAL),
                policy: f.policy.fact_digest(),
                enablement: f.enablement.fact_digest(),
                witness: None,
                reservation: None,
                approval: approval.fact_digest(),
                audit: header.audit.fact_digest(),
            };
            assert_eq!(header.bindings_digest, bindings_digest(&facts), "{case}");
        }
    }

    fn message_refusal(case: &str, expected: P) {
        let f = x402_fixture();
        let root = x402_root(&f);
        let mut intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        match case {
            "intent_consumer" => intent.consumer = MainnetConsumer::X402Create,
            "network" => {
                intent.network_id = Sha256::digest(
                    stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.as_bytes(),
                )
                .into();
            }
            _ => {}
        }
        let message = message_facts([1; 32], EPHEMERAL);
        let mut chain_profile = f.profile.clone();
        chain_profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        let approval = match case {
            "approval_profile" => bound_x402_approval(&f, &root, &f.profile, "other"),
            "approval_chain" => bound_x402_approval(&f, &root, &chain_profile, "operator"),
            "approval_kind" => f.approval(&f.envelope, f.now, 600_000),
            "approval_other_domain" => f.x402_approval(&root, Some("other.example.com"), f.now),
            "approval_plain" => f.x402_approval(&root, None, f.now),
            _ => f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now),
        };
        let policy = match case {
            "policy_body" => Some(alternate_policy(
                &f,
                |doc| {
                    doc.remove("mainnet");
                },
                &f.profile,
                "operator",
            )),
            "enablement_sequence" => Some(alternate_policy(
                &f,
                |doc| doc["sequence"] = toml_edit::value(8),
                &f.profile,
                "operator",
            )),
            _ => None,
        };
        let other_enablement = (case == "enablement_profile").then(|| {
            let profile = f.profile.clone();
            let policy = alternate_policy(
                &f,
                |doc| {
                    doc["scope"] = toml_edit::value("profile:other");
                    doc["mainnet"]["profile"] = toml_edit::value("other");
                },
                &profile,
                "other",
            );
            let profiles = f.dir.path().join("alternate-profiles");
            stellar_agent_core::profile::loader::save_to_dir("other", &profile, &profiles).unwrap();
            stellar_agent_core::mainnet::enablement::verify_enablement(
                &policy,
                "other",
                stellar_agent_core::profile::name::ProfileNameSource::Flag,
                &profile,
                &profiles,
                &|_| Ok("installation-nonce".to_owned()),
            )
            .unwrap()
        });
        let mut req = f.message_request(&intent, &message, &approval);
        match case {
            "consumer" => req.consumer = MainnetConsumer::X402Create,
            "audit_profile" => {
                // The writer registry keeps one log path per profile name, so
                // this case owns its name and starts without an entry.
                const OTHER: &str = "other-message-audit";
                stellar_agent_core::audit_log::writer::AuditWriterRegistry::remove_for_test(OTHER);
                let mut profile = f.profile.clone();
                profile.audit_log_path = f.dir.path().join("other-message-audit.jsonl");
                req.audit =
                    super::super::audit_readiness::audit_readiness(&profile, OTHER).unwrap();
            }
            "audit_stale" => {
                f.clock
                    .set(f.now - MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000 - 1);
                req.audit = f.audit();
                f.clock.set(f.now);
            }
            "approval_expired" => {
                // The readiness is acquired under the advanced clock, so the
                // expired approval is the only invalid input.
                f.clock.set(f.now + 600_000);
                req.audit = f.audit();
            }
            _ => {}
        }
        if let Some(policy) = &policy {
            req.policy = policy;
        }
        if let Some(enablement) = &other_enablement {
            req.enablement = enablement;
        }
        let before = f.wire();
        assert_refused(resolve_message_sign(req), expected, &f, &before);
    }
    macro_rules! message_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[test]
            #[serial_test::serial]
            fn $name() {
                message_refusal($case, P::$expected);
            }
        };
    }
    message_case!(message_consumer_refuses, "consumer", ConsumerMismatch);
    message_case!(
        message_intent_consumer_refuses,
        "intent_consumer",
        ConsumerMismatch
    );
    message_case!(message_policy_body_refuses, "policy_body", PolicyNotMainnet);
    message_case!(
        message_enablement_profile_refuses,
        "enablement_profile",
        ProfileMismatch
    );
    message_case!(
        message_enablement_sequence_refuses,
        "enablement_sequence",
        EnablementSequenceMismatch
    );
    message_case!(message_network_refuses, "network", IntentNetworkMismatch);
    message_case!(
        message_approval_profile_refuses,
        "approval_profile",
        ApprovalProfileMismatch
    );
    message_case!(
        message_approval_chain_refuses,
        "approval_chain",
        ApprovalChainMismatch
    );
    message_case!(
        message_approval_kind_refuses,
        "approval_kind",
        ApprovalKindMismatch
    );
    message_case!(
        message_approval_other_domain_refuses,
        "approval_other_domain",
        ApprovalSubjectMismatch
    );
    message_case!(
        message_approval_plain_subject_refuses,
        "approval_plain",
        ApprovalSubjectMismatch
    );
    message_case!(
        message_approval_expired_refuses,
        "approval_expired",
        ApprovalExpired
    );
    message_case!(
        message_audit_profile_refuses,
        "audit_profile",
        AuditProfileMismatch
    );
    message_case!(message_audit_stale_refuses, "audit_stale", AuditStale);

    /// A request whose every input is invalid refuses at the consumer, the
    /// first check. Repairing the inputs one at a time in the resolver's
    /// order reports each later check in turn, down to the mint.
    ///
    /// The creation time and the expiry of one approval cannot both be
    /// invalid under one clock: the approvals are created after the clock,
    /// the creation repair moves the clock to the approval's expiry, and the
    /// expiry repair moves it to the approval's creation.
    #[test]
    #[serial_test::serial]
    fn message_resolver_refusals_follow_the_check_order() {
        use stellar_agent_core::profile::caip2::{Caip2, TESTNET_PASSPHRASE};
        const OTHER: &str = "other-message-audit";
        let f = x402_fixture();
        let root = x402_root(&f);
        let message = message_facts([1; 32], EPHEMERAL);
        let mainnet = x402_intent(&root, MainnetConsumer::X402Authenticated).network_id;
        let testnet: [u8; 32] = Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into();
        let without_mainnet = alternate_policy(
            &f,
            |doc| {
                doc.remove("mainnet");
            },
            &f.profile,
            "operator",
        );
        let mut testnet_profile = f.profile.clone();
        testnet_profile.chain_id = Caip2::Testnet;
        stellar_agent_core::audit_log::writer::AuditWriterRegistry::remove_for_test(OTHER);
        let mut other_audit_profile = f.profile.clone();
        other_audit_profile.audit_log_path = f.dir.path().join("other-message-audit.jsonl");
        // An approval created now is created after the fixture's clock.
        let created = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        assert!(created > f.now);
        let other_profile =
            f.approval_under(&f.envelope, created, 600_000, &testnet_profile, "other");
        let other_chain =
            f.approval_under(&f.envelope, created, 600_000, &testnet_profile, "operator");
        let other_kind = f.approval(&f.envelope, created, 600_000);
        let other_subject = f.x402_approval(&root, Some("other.example.com"), created);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), created);
        // A readiness verified one millisecond past its freshness before the
        // fixture's clock, the clock then set to `now`.
        let stale = |profile: &stellar_agent_core::profile::schema::Profile,
                     name: &str,
                     now: u64| {
            f.clock
                .set(f.now - MAINNET_AUDIT_READINESS_TTL_SECONDS * 1000 - 1);
            let readiness = super::super::audit_readiness::audit_readiness(profile, name).unwrap();
            f.clock.set(now);
            readiness
        };
        let attempt = |consumer: MainnetConsumer,
                       policy: &VerifiedPolicy,
                       network_id: [u8; 32],
                       approval: &ApprovalWitness,
                       audit: AuditReadiness| {
            let mut intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
            intent.network_id = network_id;
            let mut req = f.message_request(&intent, &message, approval);
            req.consumer = consumer;
            req.policy = policy;
            req.audit = audit;
            resolve_message_sign(req)
        };
        let before = f.wire();
        let refused = |result, expected| assert_refused(result, expected, &f, &before);
        let create = MainnetConsumer::X402Create;
        let authenticated = MainnetConsumer::X402Authenticated;

        let audit = stale(&other_audit_profile, OTHER, f.now);
        refused(
            attempt(create, &without_mainnet, testnet, &other_profile, audit),
            P::ConsumerMismatch,
        );
        let audit = stale(&other_audit_profile, OTHER, f.now);
        refused(
            attempt(
                authenticated,
                &without_mainnet,
                testnet,
                &other_profile,
                audit,
            ),
            P::PolicyNotMainnet,
        );
        let audit = stale(&other_audit_profile, OTHER, f.now);
        refused(
            attempt(authenticated, &f.policy, testnet, &other_profile, audit),
            P::IntentNetworkMismatch,
        );
        for (witness, expected) in [
            (&other_profile, P::ApprovalProfileMismatch),
            (&other_chain, P::ApprovalChainMismatch),
            (&other_kind, P::ApprovalKindMismatch),
            (&other_subject, P::ApprovalSubjectMismatch),
            (&approval, P::NotYetValid),
        ] {
            let audit = stale(&other_audit_profile, OTHER, f.now);
            refused(
                attempt(authenticated, &f.policy, mainnet, witness, audit),
                expected,
            );
        }
        let audit = stale(&other_audit_profile, OTHER, approval.expires_at_ms());
        refused(
            attempt(authenticated, &f.policy, mainnet, &approval, audit),
            P::ApprovalExpired,
        );
        let audit = stale(&other_audit_profile, OTHER, approval.created_at_ms());
        refused(
            attempt(authenticated, &f.policy, mainnet, &approval, audit),
            P::AuditProfileMismatch,
        );
        let audit = stale(&f.profile, "operator", approval.created_at_ms());
        refused(
            attempt(authenticated, &f.policy, mainnet, &approval, audit),
            P::AuditStale,
        );
        attempt(authenticated, &f.policy, mainnet, &approval, f.audit()).unwrap();
        assert_eq!(message_record(&f)["state"], "open");
    }

    /// An approval created after the resolver's clock refuses: the creation
    /// time is checked against the clock before the expiry.
    #[test]
    #[serial_test::serial]
    fn message_future_created_approval_refuses() {
        use stellar_agent_core::approval::subject::{
            approval_subject_x402_authenticated, soroban_intent_digest,
        };
        let f = x402_fixture();
        let root = x402_root(&f);
        let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        let entry = stellar_agent_core::approval::PendingApproval::new_x402_pending(
            &intent.network_id,
            &root,
            Some(MESSAGE_HOME_DOMAIN.to_owned()),
            "1000".into(),
            600_000,
        )
        .unwrap();
        let created = entry.created_at_unix_ms;
        let subject = approval_subject_x402_authenticated(
            &soroban_intent_digest(&intent.network_id, &root).unwrap(),
            MESSAGE_HOME_DOMAIN,
        );
        let approval = f.attested(
            &entry,
            &f.profile,
            "operator",
            ApprovedKind::X402Payment,
            subject,
            created,
        );
        f.clock.set(created - 8 * 24 * 60 * 60 * 1000);
        let message = message_facts([1; 32], EPHEMERAL);
        let req = f.message_request(&intent, &message, &approval);
        let before = f.wire();
        assert_refused(resolve_message_sign(req), P::NotYetValid, &f, &before);
        assert!(
            f.wire()["authorizations"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
    }

    #[test]
    #[serial_test::serial]
    fn message_clock_unavailable_refuses() {
        let f = x402_fixture();
        let root = x402_root(&f);
        let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        let message = message_facts([1; 32], EPHEMERAL);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        let req = f.message_request(&intent, &message, &approval);
        let before = f.wire();
        let guard = super::super::clock::set_clock_error_for_test();
        let result = resolve_message_sign(req);
        drop(guard);
        f.clock.set(f.now);
        assert_refused(result, P::ClockUnavailable, &f, &before);
    }

    /// The store's mint rules hold for message records: the approval nonce
    /// is single use, an open content cannot be minted twice, and the policy
    /// pin must name the authorization's policy.
    #[test]
    #[serial_test::serial]
    fn message_mint_keeps_the_store_rules() {
        let f = x402_fixture();
        let root = x402_root(&f);
        let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        let first = message_facts([1; 32], EPHEMERAL);
        let other = message_facts([2; 32], EPHEMERAL);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        resolve_message_sign(f.message_request(&intent, &first, &approval)).unwrap();
        let before = f.wire();
        assert_refused(
            resolve_message_sign(f.message_request(&intent, &other, &approval)),
            P::ApprovalNonceReused,
            &f,
            &before,
        );
        let fresh = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        assert_refused(
            resolve_message_sign(f.message_request(&intent, &first, &fresh)),
            P::DuplicateOpen,
            &f,
            &before,
        );
        let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &f.profile.policy_window_state_key_id,
        );
        let entry = keyring_core::Entry::new(&pin.service, &pin.account).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&entry.get_password().unwrap()).unwrap();
        value["sequence"] = serde_json::json!(8);
        entry.set_password(&value.to_string()).unwrap();
        assert_refused(
            resolve_message_sign(f.message_request(&intent, &other, &fresh)),
            P::PolicyPinMismatch,
            &f,
            &before,
        );
    }

    /// The consume returns the receipt of the record it settles, also after
    /// an anchored append grew the log between the mint and the consume.
    #[test]
    #[serial_test::serial]
    fn consume_message_sign_returns_the_receipt() {
        for grown in [false, true] {
            let f = x402_fixture();
            let root = x402_root(&f);
            let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
            let message = message_facts([1; 32], EPHEMERAL);
            let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
            let auth =
                resolve_message_sign(f.message_request(&intent, &message, &approval)).unwrap();
            let id = auth.id();
            if grown {
                append_audit(&f);
            }
            let receipt = consume_message_sign(&f.context, auth, &f.window).unwrap();
            assert_eq!(receipt.id(), id, "{grown}");
            assert_eq!(receipt.home_domain(), MESSAGE_HOME_DOMAIN);
            assert_eq!(receipt.content_digest(), message.content_digest);
            assert_eq!(receipt.ephemeral_public_key(), message.ephemeral_public_key);
            let record = message_record(&f);
            assert_eq!(record["id"], serde_json::to_value(id).unwrap());
            assert_eq!(record["state"], "used", "{grown}");
            assert_eq!(
                record["consumption"],
                serde_json::to_value(ConsumptionBinding::Message {
                    domain: message.domain.clone(),
                    content_digest: message.content_digest,
                    ephemeral_public_key: message.ephemeral_public_key,
                })
                .unwrap()
            );
            assert!(f.wire()["holds"].as_array().is_none_or(Vec::is_empty));
        }
    }

    /// A consume that the audit refuses invalidates its record with the
    /// reason `consume_refused`.
    #[test]
    #[serial_test::serial]
    fn audit_refusal_at_the_message_consume_invalidates_the_record() {
        use stellar_agent_core::audit_log::{AuditWriter, tip_anchor::InMemoryTipAnchorStore};
        for (case, expected) in [
            ("anchor_lag", P::AuditNotAnchored),
            ("replaced_writer", P::AuditProvenance),
        ] {
            let f = x402_fixture();
            let root = x402_root(&f);
            let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
            let message = message_facts([1; 32], EPHEMERAL);
            let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
            let auth =
                resolve_message_sign(f.message_request(&intent, &message, &approval)).unwrap();
            if case == "anchor_lag" {
                f.anchor_failure
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                append_audit(&f);
            } else {
                let replacement = AuditWriter::open_with_tip_anchor(
                    f.dir.path().join("injected.jsonl"),
                    None,
                    std::sync::Arc::new(InMemoryTipAnchorStore::new()),
                    stellar_agent_core::audit_log::BindingHistory::NotRecorded,
                )
                .unwrap();
                let original = std::mem::replace(
                    &mut *auth.inner().header.audit.writer().lock().unwrap(),
                    replacement,
                );
                drop(original);
            }
            let result = consume_message_sign(&f.context, auth, &f.window);
            f.anchor_failure
                .store(false, std::sync::atomic::Ordering::SeqCst);
            assert!(
                matches!(result, Err(MainnetAuthorizationError::Refused(actual)) if actual == expected),
                "{case}: {result:?}"
            );
            let record = message_record(&f);
            assert_eq!(record["state"], "invalidated", "{case}");
            assert_eq!(record["invalidation"], "consume_refused", "{case}");
        }
    }

    /// The warnings the mainnet module logs while `f` runs.
    fn mainnet_warnings<T>(
        f: impl FnOnce() -> T,
    ) -> (T, Vec<std::collections::BTreeMap<String, String>>) {
        let (warnings, _guard) =
            stellar_agent_test_support::WarningCapture::capture(Some("stellar_agent_network"));
        (f(), warnings.seen())
    }

    fn field<'a>(warning: &'a std::collections::BTreeMap<String, String>, name: &str) -> &'a str {
        warning
            .get(name)
            .map_or("", |value| value.trim_matches('"'))
    }

    /// A record consumed already refuses its consume with `NotOpen`, stays
    /// used, and needs no cleanup: the refusal is the one line logged.
    #[test]
    #[serial_test::serial]
    fn consuming_a_used_message_record_refuses_without_cleanup() {
        let f = x402_fixture();
        let root = x402_root(&f);
        let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        let message = message_facts([1; 32], EPHEMERAL);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        let auth = resolve_message_sign(f.message_request(&intent, &message, &approval)).unwrap();
        let facts = RecomputedFacts {
            content_digest: content_digest_of_message(&message),
            entries_digest: super::super::digest::entries_digest(&[]),
            audit: auth.inner().header.audit.fresh_facts().unwrap(),
        };
        f.window
            .consume_authorization(
                &f.profile,
                auth.id(),
                &auth.consume_expect(&facts),
                &ConsumptionBinding::Message {
                    domain: message.domain.clone(),
                    content_digest: message.content_digest,
                    ephemeral_public_key: message.ephemeral_public_key,
                },
            )
            .unwrap();
        let before = f.wire();
        let (result, warnings) =
            mainnet_warnings(|| consume_message_sign(&f.context, auth, &f.window));
        assert!(
            matches!(result, Err(MainnetAuthorizationError::Refused(P::NotOpen))),
            "{result:?}"
        );
        assert_eq!(f.wire(), before);
        assert_eq!(message_record(&f)["state"], "used");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert_eq!(
            field(&warnings[0], "message"),
            "mainnet authorization refused"
        );
        assert_eq!(field(&warnings[0], "path"), "consume_message_sign");
        assert_eq!(field(&warnings[0], "precondition"), "not_open");
    }

    fn content_digest_of_message(message: &super::super::message::MessageFacts) -> [u8; 32] {
        super::super::digest::content_digest(
            super::super::AuthorizationDomain::Message,
            &message.content_digest,
        )
    }

    /// The cleanup leaves a used record and an unknown identity as they
    /// are, and logs nothing for either.
    #[test]
    #[serial_test::serial]
    fn the_message_cleanup_ignores_settled_and_unknown_records() {
        let f = x402_fixture();
        let root = x402_root(&f);
        let receipt = f.message_receipt(&root, &message_facts([1; 32], EPHEMERAL));
        for id in [receipt.id(), AuthorizationId::from_bytes([0xcd; 32])] {
            let before = f.wire();
            let ((), warnings) = mainnet_warnings(|| {
                invalidate_after_refused_consume(&f.window, &f.context, id);
            });
            assert_eq!(f.wire(), before, "{id:?}");
            assert!(warnings.is_empty(), "{id:?}: {warnings:?}");
        }
        assert_eq!(message_record(&f)["state"], "used");
    }

    /// A refused consume whose cleanup fails returns the refusal, logs the
    /// refusal and one cleanup failure, and leaves the record open.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn a_failed_message_cleanup_keeps_the_primary_refusal() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = x402_fixture();
        let root = x402_root(&f);
        let intent = x402_intent(&root, MainnetConsumer::X402Authenticated);
        let message = message_facts([1; 32], EPHEMERAL);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        let auth = resolve_message_sign(f.message_request(&intent, &message, &approval)).unwrap();
        f.anchor_failure
            .store(true, std::sync::atomic::Ordering::SeqCst);
        append_audit(&f);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let (result, warnings) =
            mainnet_warnings(|| consume_message_sign(&f.context, auth, &f.window));
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        f.anchor_failure
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            matches!(
                result,
                Err(MainnetAuthorizationError::Refused(P::AuditNotAnchored))
            ),
            "{result:?}"
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(
            field(&warnings[0], "message"),
            "mainnet authorization refused"
        );
        assert_eq!(field(&warnings[0], "path"), "consume_message_sign");
        assert_eq!(field(&warnings[0], "precondition"), "audit_not_anchored");
        assert_eq!(
            field(&warnings[1], "message"),
            "mainnet authorization cleanup failed"
        );
        assert_eq!(field(&warnings[1], "path"), "consume_message_sign");
        assert_eq!(field(&warnings[1], "precondition"), "store_unavailable");
        assert_eq!(message_record(&f)["state"], "open");
    }

    // ── The authenticated intent ──────────────────────────────────────

    /// A resolver fixture with the RPC double routed, and the parts of an
    /// authenticated payment.
    async fn authenticated_intent_case(
        f: &ResolverFixture,
        case: &str,
    ) -> Result<MainnetSorobanIntentAuthorization, MainnetAuthorizationError> {
        let root = x402_root(f);
        let server = f.server().await;
        let context = f.context_with_routes(&[("rpc.example.invalid", &server.uri())]);
        let client = context.primary_client().unwrap();
        let message = message_facts([1; 32], EPHEMERAL);
        let approval = f.x402_approval(&root, Some(MESSAGE_HOME_DOMAIN), f.now);
        let receipt = match case {
            "other_receipt_domain" => {
                let mut other = message_facts([2; 32], EPHEMERAL);
                other.domain.home_domain = "other.example.com".to_owned();
                f.message_receipt(&root, &other)
            }
            _ => f.message_receipt_for(&root, &message, &approval),
        };
        let plain = f.x402_approval(&root, None, f.now);
        let consumer = if matches!(case, "create_with_receipt" | "create_plain") {
            MainnetConsumer::X402Create
        } else {
            MainnetConsumer::X402Authenticated
        };
        let intent = x402_intent(&root, consumer);
        let mut req = SorobanIntentRequest {
            context: &context,
            intent: &intent,
            nonce: INTENT_NONCE,
            signature_expiration_ledger: INTENT_EXPIRATION_LEDGER,
            client: &client,
            probe_deadline: Duration::from_secs(1),
            witness: None,
            signer: &f.signer,
            policy: &f.policy,
            enablement: &f.enablement,
            approval: &approval,
            audit: f.audit(),
            store: &f.window,
            authenticated: Some(&receipt),
        };
        match case {
            "no_receipt" => req.authenticated = None,
            "plain_subject" => req.approval = &plain,
            "create_plain" => {
                req.authenticated = None;
                req.approval = &plain;
            }
            _ => {}
        }
        let result = resolve_soroban_intent(req).await;
        if let Ok(auth) = &result {
            let wire = f.wire();
            let record = wire["authorizations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| record["id"] == serde_json::to_value(auth.id()).unwrap())
                .unwrap()
                .clone();
            let expected_parent = (consumer == MainnetConsumer::X402Authenticated)
                .then(|| serde_json::to_value(receipt.id()).unwrap());
            assert_eq!(record.get("parent").cloned(), expected_parent, "{case}");
        }
        result
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn authenticated_intent_names_its_message_parent() {
        let f = x402_fixture();
        let auth = authenticated_intent_case(&f, "accept").await.unwrap();
        let wire = f.wire();
        let record = &wire["authorizations"][1];
        assert_eq!(record["id"], serde_json::to_value(auth.id()).unwrap());
        assert_eq!(record["domain"], "soroban");
        assert_eq!(record["consumer"], "x402_authenticated");
        assert_eq!(record["state"], "open");
        assert_eq!(record["parent"], wire["authorizations"][0]["id"]);
        assert_eq!(wire["authorizations"][0]["domain"], "message");
    }

    async fn authenticated_intent_refusal(case: &str, expected: P) {
        let f = x402_fixture();
        let result = authenticated_intent_case(&f, case).await;
        let error = result.unwrap_err();
        assert!(
            matches!(error, MainnetAuthorizationError::Refused(actual) if actual == expected),
            "{case}: expected {expected:?}, got {error:?}"
        );
        assert!(
            f.wire()["authorizations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|record| record["domain"] == "message"),
            "{case}: no intent record"
        );
    }
    macro_rules! authenticated_intent_case {
        ($name:ident, $case:literal, $expected:ident) => {
            #[tokio::test]
            #[serial_test::serial]
            async fn $name() {
                authenticated_intent_refusal($case, P::$expected).await;
            }
        };
    }
    authenticated_intent_case!(
        authenticated_intent_without_receipt_refuses,
        "no_receipt",
        IntentRecordMismatch
    );
    authenticated_intent_case!(
        create_intent_with_receipt_refuses,
        "create_with_receipt",
        ConsumerMismatch
    );
    authenticated_intent_case!(
        authenticated_intent_plain_subject_refuses,
        "plain_subject",
        ApprovalSubjectMismatch
    );
    authenticated_intent_case!(
        authenticated_intent_other_receipt_domain_refuses,
        "other_receipt_domain",
        ApprovalSubjectMismatch
    );

    /// The authenticated intent evaluates the authenticated tool's rule: it
    /// denies while the create tool's rule allows the same payment.
    #[tokio::test]
    #[serial_test::serial]
    async fn authenticated_intent_evaluates_the_authenticated_rule() {
        let f = ResolverFixture::configured(
            |_| {},
            |raw| {
                x402_policy(raw, |rule| {
                    rule.replace("max_stroops = \"100\"", "max_stroops = \"5\"")
                })
            },
        );
        let result = authenticated_intent_case(&f, "accept").await;
        assert!(
            matches!(result, Err(MainnetAuthorizationError::PolicyDenied(_))),
            "{result:?}"
        );
        authenticated_intent_case(&f, "create_plain").await.unwrap();
    }
}
