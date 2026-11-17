//! The business-id entry both binaries share on their value paths.
//!
//! A mainnet value call names itself with a business id. The helpers here build
//! the canonical intent of a classic request and the record slot that binds it.
//! They look the record up and open it, and render the answer a retry of a
//! retained operation receives. On every other chain a business id is validated
//! and echoed, and no record exists.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::{
    AttestationBinding, ClassicIntent, IntentAsset, IntentBase, IntentPayload, MemoFact,
    PendingApproval, PendingApprovalStore, VerifiedConsentPublication, load_attestation_key,
    verify_consent_publication,
    witness::{
        ApprovalExpectation, ApprovalWitness, ApprovedKind, verify_approval,
        verify_approval_admitted, verify_intent_consent_admitted,
    },
};
use stellar_agent_core::audit_log::{
    AuditEntry, AuditOutbox, AuditWriter, EvidenceReservation, WriterError, audit_writer_refusal,
};
use stellar_agent_core::error::{
    ApprovalFailure, InternalError, SubmissionError, ValidationError, WalletError,
};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::receipt::{DestinationFields, PaymentDestinations};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::profile::{name::profile_name_for_approval, owner_key::OwnerKeyContext};
use stellar_agent_core::sac_payment::{ContractTransferFeeCap, SacPaymentError};
use stellar_xdr::{Limits, Memo, ReadXdr as _, TransactionEnvelope};

use crate::fees::ClassicFeeChoice;
use crate::mainnet::MainnetAuthorizationError;
use crate::mainnet::canonical::{CanonicalPart, CanonicalRefusal};
use crate::policy_state::approvals::{
    ConsentDeliveryV1, require_consent_evidence_inventory, sweep_ended_consent_evidence,
};
use crate::policy_state::{
    ApprovalRecorder, ApprovalStatus, ApprovalView, AttemptAuthorization, AttemptEnvelope,
    AttemptRequest, BusinessId, CommitBinding, CommitTarget, CommittedBatch, ConsentPayload,
    ConsentRow, IntentSlot, LookupOutcome, OpenOutcome, OpenRequest, OperationAudit,
    OperationHandle, OperationId, OperationKind, OperationLink, OperationRecorder, OperationState,
    OperationStatus, OperationView, PendingApprovalFacts, PersistedWindowStore, SlotKind,
    WindowStoreError, WireApproval,
};
use crate::submission_record::{AuditWriterHandle, OperationAttempt};

mod preparation;
pub use preparation::{
    Preparation, approval_producer_lock, intent_for_consent, lookup_canonical, preparation_intent,
    stage_pending,
};

/// The facts every classic intent shares, as the prepare step knows them.
#[derive(Debug, Clone)]
pub struct IntentBaseFacts<'a> {
    /// The CAIP-2 chain identifier.
    pub chain_id: &'a str,
    /// The effective source account, a G strkey.
    pub source: &'a str,
    /// The digest of the verified policy the operation runs under.
    pub policy_digest: [u8; 32],
    /// The signed policy's classic fee cap per operation, when it sets one.
    pub signed_fee_cap: Option<u32>,
    /// The profile's classic fee cap per operation, when it sets one.
    pub profile_fee_cap: Option<u32>,
    /// The caller's fee choice.
    pub fee_choice: ClassicFeeChoice,
    /// The memo.
    pub memo: MemoFact,
}

impl<'a> IntentBaseFacts<'a> {
    /// The facts of a request under `policy` from `profile`: the policy's
    /// digest and signed fee cap, and the profile's fee cap.
    #[must_use]
    pub fn new(
        profile: &Profile,
        source: &'a str,
        policy: &VerifiedPolicy,
        fee_choice: ClassicFeeChoice,
        memo: MemoFact,
    ) -> Self {
        Self {
            chain_id: profile.chain_id.caip2_str(),
            source,
            policy_digest: policy.digest(),
            signed_fee_cap: policy
                .mainnet()
                .map(|body| body.classic_max_fee_per_op_stroops),
            profile_fee_cap: profile.classic_max_fee_per_op_stroops,
            fee_choice,
            memo,
        }
    }
}

/// The fee bound of a classic intent: an explicit fee choice, otherwise the
/// tighter of the profile cap and the signed policy cap.
///
/// # Errors
///
/// `validation.mainnet_fee_cap_required` when neither the profile nor the
/// signed policy sets a cap and the caller chose no explicit fee.
pub fn fee_bound(
    profile_fee_cap: Option<u32>,
    signed_fee_cap: Option<u32>,
    fee_choice: ClassicFeeChoice,
) -> Result<u32, WalletError> {
    if let ClassicFeeChoice::Explicit(fee) = fee_choice {
        return Ok(fee);
    }
    match (profile_fee_cap, signed_fee_cap) {
        (Some(profile), Some(signed)) => Ok(profile.min(signed)),
        (Some(cap), None) | (None, Some(cap)) => Ok(cap),
        (None, None) => Err(ValidationError::MainnetFeeCapRequired.into()),
    }
}

/// The canonical intent of one classic request.
///
/// The policy digest is [`VerifiedPolicy::digest`]; the fee bound follows
/// [`fee_bound`]. Two requests with the same facts give the same digest
/// whatever sequence, time bound or exact fee their envelopes carry.
///
/// # Errors
///
/// `validation.mainnet_fee_cap_required` from [`fee_bound`],
/// `validation.contract_payment_unavailable` for a contract payment, whose
/// bound is [`contract_pay_base`]'s total cap, and `internal.unexpected_state`
/// for facts the argument checks before this call admit but the intent refuses.
pub fn classic_intent(
    base: IntentBaseFacts<'_>,
    payload: IntentPayload,
) -> Result<ClassicIntent, WalletError> {
    if matches!(payload, IntentPayload::ContractPay { .. }) {
        return Err(SacPaymentError::Unavailable.into());
    }
    let bound = fee_bound(base.profile_fee_cap, base.signed_fee_cap, base.fee_choice)?;
    let unexpected = |error: stellar_agent_core::approval::IntentError| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("the request facts form no canonical intent: {error}"),
        })
    };
    let base = IntentBase::new(
        base.chain_id.to_owned(),
        base.source.to_owned(),
        base.policy_digest,
        bound,
        base.memo,
    )
    .map_err(unexpected)?;
    ClassicIntent::new(base, payload).map_err(unexpected)
}

/// The base facts of a contract payment intent, whose fee bound is the total
/// fee cap and never an explicit inclusion bid.
///
/// # Errors
///
/// `validation.contract_payment_invalid` for a source that is not a
/// canonical G account or a text memo above 28 bytes.
pub fn contract_pay_base(
    chain: Caip2,
    source: &str,
    policy_digest: [u8; 32],
    memo: MemoFact,
    cap: ContractTransferFeeCap,
) -> Result<IntentBase, WalletError> {
    IntentBase::new(
        chain.caip2_str().to_owned(),
        source.to_owned(),
        policy_digest,
        cap.stroops,
        memo,
    )
    .map_err(|_| SacPaymentError::Invalid.into())
}

/// The identity digest of a contract payment intent: its canonical digest.
///
/// # Errors
///
/// `validation.contract_payment_invalid` for another payload kind.
pub fn contract_pay_identity(intent: &ClassicIntent) -> Result<[u8; 32], WalletError> {
    match intent.payload() {
        IntentPayload::ContractPay { .. } => Ok(*intent.digest().as_bytes()),
        _ => Err(SacPaymentError::Invalid.into()),
    }
}

/// The facts a canonical record is used under: the profile's CAIP-2 chain,
/// the signing account, and the digest of the policy in force.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalUse<'a> {
    /// The CAIP-2 chain identifier.
    pub chain_id: &'a str,
    /// The signing account, a G strkey.
    pub source: &'a str,
    /// The digest of the verified policy in force.
    pub policy_digest: [u8; 32],
}

/// The validated intent a canonical slot stores, for a use under `admitted`.
///
/// The store compares slot kinds and digests and never reads the intent, so
/// every use rereads it. The stored value must be the JSON form of a valid
/// [`ClassicIntent`], hash to the slot's digest, and name `admitted`'s chain,
/// source and policy digest. The check reads and writes no store.
///
/// # Errors
///
/// [`CanonicalRefusal::NotCanonical`] for another slot kind,
/// [`CanonicalRefusal::Malformed`], [`CanonicalRefusal::StoredDigest`], and
/// [`CanonicalRefusal::Mismatch`] naming the chain, source or policy.
pub fn canonical_slot_intent(
    slot: &IntentSlot,
    admitted: &CanonicalUse<'_>,
) -> Result<ClassicIntent, CanonicalRefusal> {
    let IntentSlot::Canonical {
        intent_digest,
        intent,
    } = slot
    else {
        return Err(CanonicalRefusal::NotCanonical);
    };
    let parsed = serde_json::from_value::<ClassicIntent>(intent.clone())
        .map_err(|_| CanonicalRefusal::Malformed)?;
    // Unknown fields and noncanonical spellings parse; the round trip refuses them.
    if serde_json::to_value(&parsed).ok().as_ref() != Some(intent) {
        return Err(CanonicalRefusal::Malformed);
    }
    if parsed.digest().as_bytes() != intent_digest {
        return Err(CanonicalRefusal::StoredDigest);
    }
    let base = parsed.base();
    for (holds, part) in [
        (base.chain_id() == admitted.chain_id, CanonicalPart::Chain),
        (base.source() == admitted.source, CanonicalPart::Source),
        (
            base.policy_digest() == &admitted.policy_digest,
            CanonicalPart::Policy,
        ),
    ] {
        if !holds {
            return Err(CanonicalRefusal::Mismatch(part));
        }
    }
    Ok(parsed)
}

/// The domain label of a claim's identity digest.
pub const CLAIM_IDENTITY_DIGEST_LABEL: &[u8] = b"stellar-agent-wallet/claim-identity/v1";

/// The request facts a business id binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityFacts {
    /// A request whose whole canonical intent is known before any read.
    Intent(IntentPayload),
    /// A claim, named by its balance and claimant. The amount and asset
    /// come from the ledger read at execution, so they stay outside the
    /// identity and a retry binds the same claim before any read.
    Claim {
        /// The balance id, 72 lowercase hexadecimal characters.
        balance_id: String,
        /// The claimant, the effective source.
        claimant: String,
    },
}

/// The identity digest a record binds for a classic request under its
/// business id.
///
/// A request named by its canonical intent binds that intent's digest. A claim
/// binds the digest of its base facts, balance id and claimant. The digest is
/// the same for [`IdentityFacts::Claim`] and for a whole claim intent, so the
/// ledger's amount and asset never change which claim an id names.
///
/// # Errors
///
/// `validation.mainnet_fee_cap_required` from [`fee_bound`], and
/// `internal.unexpected_state` for facts the argument checks before this
/// call admit but the intent refuses.
pub fn operation_identity(
    base: IntentBaseFacts<'_>,
    facts: IdentityFacts,
) -> Result<[u8; 32], WalletError> {
    let (balance_id, claimant) = match facts {
        IdentityFacts::Intent(IntentPayload::Claim {
            balance_id,
            claimant,
            ..
        })
        | IdentityFacts::Claim {
            balance_id,
            claimant,
        } => (balance_id, claimant),
        IdentityFacts::Intent(payload) => {
            return Ok(*classic_intent(base, payload)?.digest().as_bytes());
        }
    };
    claim_identity(base, &balance_id, &claimant)
}

/// The identity digest of a claim of `balance_id` by `claimant`: the label,
/// then the base facts and the two strings in the canonical intent layout.
fn claim_identity(
    base: IntentBaseFacts<'_>,
    balance_id: &str,
    claimant: &str,
) -> Result<[u8; 32], WalletError> {
    let unexpected = |reason: &str| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("the claim facts form no identity: {reason}"),
        })
    };
    if balance_id.len() != 72
        || !balance_id.starts_with("00000000")
        || !balance_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unexpected(
            "the balance id is not 72 lowercase hex characters",
        ));
    }
    if claimant != base.source {
        return Err(unexpected("the claimant is not the effective source"));
    }
    let bound = fee_bound(base.profile_fee_cap, base.signed_fee_cap, base.fee_choice)?;
    let base = IntentBase::new(
        base.chain_id.to_owned(),
        base.source.to_owned(),
        base.policy_digest,
        bound,
        base.memo,
    )
    .map_err(|error| unexpected(&error.to_string()))?;
    let mut hash = Sha256::new();
    hash.update(CLAIM_IDENTITY_DIGEST_LABEL);
    let put = |hash: &mut Sha256, bytes: &[u8]| {
        hash.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hash.update(bytes);
    };
    put(&mut hash, base.chain_id().as_bytes());
    put(&mut hash, base.source().as_bytes());
    put(&mut hash, base.policy_digest());
    hash.update(u64::from(base.fee_bound_stroops()).to_be_bytes());
    match base.memo() {
        MemoFact::None => hash.update([0]),
        MemoFact::Text(text) => {
            hash.update([1]);
            put(&mut hash, text.as_bytes());
        }
        MemoFact::Id(id) => {
            hash.update([2]);
            hash.update(id.to_be_bytes());
        }
        MemoFact::Hash(bytes) => {
            hash.update([3]);
            put(&mut hash, bytes);
        }
        MemoFact::Return(bytes) => {
            hash.update([4]);
            put(&mut hash, bytes);
        }
    }
    put(&mut hash, balance_id.as_bytes());
    put(&mut hash, claimant.as_bytes());
    Ok(hash.finalize().into())
}

/// The SHA-256 digest of an unsigned envelope's base64 text, the digest an
/// envelope record and its attempts bind.
#[must_use]
pub fn unsigned_envelope_sha256(unsigned_envelope_b64: &str) -> [u8; 32] {
    Sha256::digest(unsigned_envelope_b64.as_bytes()).into()
}

/// The slot a classic record binds: the [`operation_identity`] of the
/// request facts and the digest and `max_time` of the envelope prepared
/// for them.
#[must_use]
pub fn envelope_slot(
    identity: &[u8; 32],
    unsigned_envelope_b64: &str,
    max_time_s: u64,
) -> IntentSlot {
    IntentSlot::Envelope {
        unsigned_envelope_sha256: unsigned_envelope_sha256(unsigned_envelope_b64),
        intent_digest: *identity,
        max_time: max_time_s,
    }
}

/// The `max_time` of an unsigned envelope in Unix seconds; zero for none.
///
/// # Errors
///
/// `internal.unexpected_state` for text that is not a transaction envelope.
pub fn envelope_max_time(unsigned_envelope_b64: &str) -> Result<u64, WalletError> {
    Ok(crate::idempotent_submit::extract_max_time(
        &decode_envelope(unsigned_envelope_b64)?,
    ))
}

/// The facts a preparation reports about an envelope it returns. They are
/// the source sequence before the envelope, the fee per operation and the
/// total fee, all read from the envelope itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeFacts {
    /// The source account's sequence the envelope builds on, one below the
    /// envelope's own sequence.
    pub source_sequence: i64,
    /// The fee per operation in stroops.
    pub fee_per_op_stroops: u32,
    /// The envelope's total fee in stroops.
    pub total_fee_stroops: u32,
}

/// The [`EnvelopeFacts`] of a stored single-transaction envelope.
///
/// # Errors
///
/// `internal.unexpected_state` for text that is not a transaction envelope
/// with at least one operation.
pub fn envelope_facts(unsigned_envelope_b64: &str) -> Result<EnvelopeFacts, WalletError> {
    let TransactionEnvelope::Tx(envelope) = decode_envelope(unsigned_envelope_b64)? else {
        return Err(unexpected_envelope("it is not a transaction envelope"));
    };
    let operations = u32::try_from(envelope.tx.operations.len())
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| unexpected_envelope("it holds no operation"))?;
    Ok(EnvelopeFacts {
        source_sequence: envelope.tx.seq_num.0.saturating_sub(1),
        fee_per_op_stroops: envelope.tx.fee / operations,
        total_fee_stroops: envelope.tx.fee,
    })
}

/// Refuses an account sequence with no successor, the envelope's sequence.
fn require_sequence_successor(sequence: i64) -> Result<(), WalletError> {
    if sequence.checked_add(1).is_none() {
        return Err(WalletError::Protocol(
            stellar_agent_core::error::ProtocolError::XdrCodecFailed {
                detail: "the source account's sequence has no successor".to_owned(),
            },
        ));
    }
    Ok(())
}

/// The unsigned envelope of `intent` on `network_passphrase`: the next
/// transaction after the account sequence `sequence`, at
/// `fee_per_op_stroops`, valid from zero through `max_time_s`.
///
/// # Errors
///
/// - `protocol.xdr_codec_failed` for a `sequence` with no successor.
/// - `validation.contract_payment_unavailable` for a contract payment, which
///   no classic operation builds.
/// - The builder's refusals.
pub fn intent_envelope(
    intent: &ClassicIntent,
    network_passphrase: &str,
    sequence: i64,
    fee_per_op_stroops: u32,
    max_time_s: u64,
) -> Result<String, WalletError> {
    use stellar_agent_core::amount::StellarAmount;
    require_sequence_successor(sequence)?;
    let base = intent.base();
    let mut builder = crate::ClassicOpBuilder::new(
        base.source(),
        sequence,
        network_passphrase,
        fee_per_op_stroops,
    );
    let asset = |asset: &IntentAsset| match asset {
        IntentAsset::Native => crate::Asset::Native,
        IntentAsset::Issued { code, issuer } => crate::Asset::Credit {
            code: code.clone(),
            issuer: issuer.clone(),
        },
    };
    match intent.payload() {
        IntentPayload::Pay {
            destination,
            asset: sent,
            amount_stroops,
        } => builder.payment(
            destination,
            StellarAmount::from_stroops(*amount_stroops),
            &asset(sent),
        )?,
        IntentPayload::CreateAccount {
            destination,
            starting_balance_stroops,
        } => builder.create_account(
            destination,
            StellarAmount::from_stroops(*starting_balance_stroops),
        )?,
        IntentPayload::Trustline {
            issuer,
            code,
            limit_stroops,
        } => builder.change_trust(
            &crate::Asset::Credit {
                code: code.clone(),
                issuer: issuer.clone(),
            },
            Some(*limit_stroops),
        )?,
        IntentPayload::Claim { balance_id, .. } => builder
            .claim_claimable_balance(balance_id.strip_prefix("00000000").unwrap_or(balance_id))?,
        IntentPayload::ContractPay { .. } => return Err(SacPaymentError::Unavailable.into()),
    };
    let memo = match base.memo() {
        MemoFact::None => None,
        MemoFact::Text(text) => Some(Memo::Text(text.as_bytes().to_vec().try_into().map_err(
            |_| unexpected_envelope("the intent's memo text exceeds the protocol limit"),
        )?)),
        MemoFact::Id(id) => Some(Memo::Id(*id)),
        MemoFact::Hash(hash) => Some(Memo::Hash(stellar_xdr::Hash(*hash))),
        MemoFact::Return(hash) => Some(Memo::Return(stellar_xdr::Hash(*hash))),
    };
    if let Some(memo) = memo {
        builder.memo(&memo)?;
    }
    builder.with_time_bounds(0, max_time_s);
    builder.build()
}

/// The inputs of [`rebuild_canonical`].
pub struct CanonicalRebuildRequest<'a> {
    /// The profile the rebuild runs under.
    pub profile: &'a Profile,
    /// The network the envelope is built for and the oracle reads.
    pub network: &'a crate::NetworkContext,
    /// The primary client.
    pub client: &'a crate::StellarRpcClient,
    /// The readiness deadline, which also bounds the account read.
    pub deadline: tokio::time::Instant,
    /// The validated stored intent.
    pub intent: &'a ClassicIntent,
    /// The caller's fee choice.
    pub fee_choice: ClassicFeeChoice,
    /// The fee per operation a [`ClassicFeeChoice::ProfileDefault`] gives.
    pub default_fee_per_op_stroops: u32,
    /// The current effective classic fee cap per operation.
    pub fee_cap_stroops: u32,
    /// The oracle observations of the operation; the fresh source read
    /// replaces their source observation.
    pub witness_inputs: crate::cross_check::ClassicInputs,
    /// The cross-check thresholds.
    pub thresholds: &'a stellar_agent_core::cross_check::ThresholdSet<'a>,
    /// The policy tool the oracle check is logged under.
    pub tool: &'static str,
}

/// An envelope rebuilt from a canonical intent, with the reads behind it.
#[derive(Debug, Clone)]
pub struct CanonicalRebuild {
    /// The unsigned envelope text.
    pub unsigned_envelope_b64: String,
    /// The source account read after the readiness check.
    pub account: crate::account::AccountView,
    /// The fee per operation in stroops.
    pub fee_per_op_stroops: u32,
    /// The deadline in Unix seconds.
    pub max_time_s: u64,
    /// The oracle outcome bound to the rebuilt envelope.
    pub cross_check: crate::cross_check::CrossCheckOutcome,
}

/// Rebuilds the envelope of a canonical intent from reads made now.
///
/// The reads run in order: the readiness check, the source account, the fee
/// statistics when the choice is a percentile, then the oracle check bound
/// to the rebuilt envelope. The envelope takes the account's next sequence,
/// the chosen fee, and a deadline [`MAINNET_CLASSIC_DEADLINE_SECONDS`] after
/// the mainnet clock. Nothing is signed or stored.
///
/// [`MAINNET_CLASSIC_DEADLINE_SECONDS`]: crate::mainnet::resolve::MAINNET_CLASSIC_DEADLINE_SECONDS
///
/// # Errors
///
/// - `network.endpoint_not_ready` and the readiness errors, before any
///   other read.
/// - `fees.percentile_exceeds_cap` for a fee above the intent's bound or
///   the current cap.
/// - `protocol.xdr_codec_failed` for an account sequence with no successor.
/// - The account, fee, clock, builder and oracle errors.
pub async fn rebuild_canonical(
    request: CanonicalRebuildRequest<'_>,
) -> Result<CanonicalRebuild, WalletError> {
    use crate::cross_check::{AccountObservation, ClassicInputs};
    use stellar_agent_core::cross_check::CrossCheckValue;
    use stellar_agent_core::error::DerivedFee;
    let intent = request.intent;
    crate::operational::operational_check(request.client, request.deadline).await?;
    let account = crate::operational::read_within_readiness_deadline(
        request.deadline,
        crate::account::fetch_account(request.client, intent.base().source(), &[]),
    )
    .await?;
    let fee = crate::fees::resolve_classic_fee_selection(
        request.client,
        request.default_fee_per_op_stroops,
        request.fee_choice,
    )
    .await?
    .per_op_stroops;
    let cap = intent
        .base()
        .fee_bound_stroops()
        .min(request.fee_cap_stroops);
    if fee > cap {
        let fee_source = crate::fees::classic_fee_source(
            request.fee_choice,
            stellar_agent_core::error::FeeSource::ProfileDefault,
        );
        return Err(WalletError::Validation(ValidationError::FeeAboveCap {
            per_op: DerivedFee::new(fee, &fee_source),
            cap,
            fee_source,
        }));
    }
    require_sequence_successor(account.sequence_number)?;
    let max_time_s = (crate::mainnet::clock::now_ms()? / 1000)
        .saturating_add(crate::mainnet::resolve::MAINNET_CLASSIC_DEADLINE_SECONDS);
    let envelope = intent_envelope(
        intent,
        request.network.network_passphrase(),
        account.sequence_number,
        fee,
        max_time_s,
    )?;
    let mut inputs = request.witness_inputs;
    let source = AccountObservation::from_view(&account)?;
    match &mut inputs {
        ClassicInputs::Pay(inputs) => inputs.source = source,
        ClassicInputs::CreateAccount(inputs) => inputs.source = source,
        ClassicInputs::Trustline(inputs) => inputs.source = source,
        ClassicInputs::Claim(inputs) => inputs.source = source,
        ClassicInputs::PoolInit(_) => {
            return Err(unexpected_envelope("pool creation has no canonical intent"));
        }
    }
    let native = stellar_agent_core::asset_id::CanonicalAsset::Native;
    let issued;
    let value = match intent.payload() {
        IntentPayload::Pay {
            asset,
            amount_stroops,
            ..
        } => CrossCheckValue::Amount {
            asset: match asset {
                IntentAsset::Native => &native,
                IntentAsset::Issued { code, issuer } => {
                    issued = stellar_agent_core::asset_id::CanonicalAsset::classic(code, issuer)
                        .map_err(|_| unexpected_envelope("the intent's asset is not canonical"))?;
                    &issued
                }
            },
            base_units: i128::from(*amount_stroops),
        },
        IntentPayload::CreateAccount {
            starting_balance_stroops,
            ..
        } => CrossCheckValue::Amount {
            asset: &native,
            base_units: i128::from(*starting_balance_stroops),
        },
        IntentPayload::Trustline { .. } | IntentPayload::Claim { .. } => CrossCheckValue::Unvalued,
        IntentPayload::ContractPay { .. } => return Err(SacPaymentError::Unavailable.into()),
    };
    let cross_check = crate::cross_check::obtain_classic_witness_bound(
        request.profile,
        request.network,
        value,
        inputs,
        &envelope,
        request.thresholds,
        request.tool,
    )
    .await?;
    Ok(CanonicalRebuild {
        unsigned_envelope_b64: envelope,
        account,
        fee_per_op_stroops: fee,
        max_time_s,
        cross_check,
    })
}

/// The destinations a result shows for `envelope`. One destination shared by
/// every payment operation gives `Single`, differing destinations give the
/// whole list, and an envelope without a payment operation gives `None`.
#[must_use]
pub fn result_destinations(envelope: &TransactionEnvelope) -> PaymentDestinations {
    let entries = crate::submit::payment_operation_destinations(envelope);
    match entries.first() {
        None => PaymentDestinations::None,
        Some(first)
            if entries
                .iter()
                .all(|entry| entry.destination == first.destination) =>
        {
            PaymentDestinations::Single(first.destination.clone())
        }
        Some(_) => PaymentDestinations::PerOperation(entries),
    }
}

/// The [`result_destinations`] of base64 envelope XDR; `None` for bytes that
/// do not decode.
#[must_use]
pub fn envelope_result_destinations(envelope_b64: &str) -> PaymentDestinations {
    decode_envelope(envelope_b64).map_or(PaymentDestinations::None, |envelope| {
        result_destinations(&envelope)
    })
}

fn decode_envelope(unsigned_envelope_b64: &str) -> Result<TransactionEnvelope, WalletError> {
    TransactionEnvelope::from_xdr_base64(unsigned_envelope_b64, Limits::none())
        .map_err(|error| unexpected_envelope(&format!("it does not decode: {error}")))
}

fn unexpected_envelope(reason: &str) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!("the prepared envelope is unusable: {reason}"),
    })
}

/// The canonical asset of a classic builder asset.
#[must_use]
pub fn intent_asset(asset: &crate::Asset) -> IntentAsset {
    match asset {
        crate::Asset::Native => IntentAsset::Native,
        crate::Asset::Credit { code, issuer } => IntentAsset::Issued {
            code: code.clone(),
            issuer: issuer.clone(),
        },
    }
}

/// The memo fact of a transaction memo.
#[must_use]
pub fn memo_fact(memo: &Memo) -> MemoFact {
    match memo {
        Memo::None => MemoFact::None,
        Memo::Text(text) => MemoFact::Text(String::from_utf8_lossy(text.as_slice()).into_owned()),
        Memo::Id(id) => MemoFact::Id(*id),
        Memo::Hash(hash) => MemoFact::Hash(hash.0),
        Memo::Return(hash) => MemoFact::Return(hash.0),
    }
}

/// The identities a classic commit of `kind` with the unsigned envelope
/// `unsigned_envelope_b64` carries under `policy`: the digests a preparation
/// of the same facts binds.
///
/// The envelope names the source, the memo and the facts of its one
/// operation. Its fee does not tell an explicit fee choice from the cap bound,
/// so the result holds the identity under each reading. These are the cap
/// bound a default or percentile choice gives, and the envelope's own fee per
/// operation as an explicit choice. A reading [`operation_identity`] refuses
/// gives no identity. An envelope of another shape, or one that decodes to no
/// classic intent of `kind`, gives none at all, so it matches no record.
#[must_use]
pub fn commit_identities(
    profile: &Profile,
    policy: &VerifiedPolicy,
    kind: OperationKind,
    unsigned_envelope_b64: &str,
) -> Vec<[u8; 32]> {
    let Some(facts) = commit_facts(unsigned_envelope_b64, kind) else {
        return Vec::new();
    };
    [
        ClassicFeeChoice::ProfileDefault,
        ClassicFeeChoice::Explicit(facts.fee_per_op_stroops),
    ]
    .into_iter()
    .filter_map(|fee_choice| {
        operation_identity(
            IntentBaseFacts::new(
                profile,
                &facts.source,
                policy,
                fee_choice,
                facts.memo.clone(),
            ),
            facts.identity.clone(),
        )
        .ok()
    })
    .collect()
}

/// The request facts an unsigned classic envelope carries.
struct CommitFacts {
    source: String,
    memo: MemoFact,
    fee_per_op_stroops: u32,
    identity: IdentityFacts,
}

/// The [`CommitFacts`] of a single-transaction envelope with one operation of
/// `kind` on the transaction's own source; `None` for any other envelope.
fn commit_facts(unsigned_envelope_b64: &str, kind: OperationKind) -> Option<CommitFacts> {
    use stellar_xdr::{ChangeTrustAsset, ClaimableBalanceId, OperationBody};
    let TransactionEnvelope::Tx(envelope) = decode_envelope(unsigned_envelope_b64).ok()? else {
        return None;
    };
    let tx = envelope.tx;
    let [operation] = tx.operations.as_slice() else {
        return None;
    };
    let source = muxed_strkey(&tx.source_account);
    if operation
        .source_account
        .as_ref()
        .is_some_and(|account| muxed_strkey(account) != source)
    {
        return None;
    }
    let identity = match (kind, &operation.body) {
        (OperationKind::Pay, OperationBody::Payment(payment)) => {
            IdentityFacts::Intent(IntentPayload::Pay {
                destination: muxed_strkey(&payment.destination),
                asset: xdr_intent_asset(&payment.asset),
                amount_stroops: payment.amount,
            })
        }
        (OperationKind::CreateAccount, OperationBody::CreateAccount(create)) => {
            IdentityFacts::Intent(IntentPayload::CreateAccount {
                destination: account_strkey(&create.destination),
                starting_balance_stroops: create.starting_balance,
            })
        }
        (OperationKind::Trustline, OperationBody::ChangeTrust(change)) => {
            let (code, issuer) = match &change.line {
                ChangeTrustAsset::CreditAlphanum4(asset) => {
                    (asset_code(&asset.asset_code.0), &asset.issuer)
                }
                ChangeTrustAsset::CreditAlphanum12(asset) => {
                    (asset_code(&asset.asset_code.0), &asset.issuer)
                }
                ChangeTrustAsset::Native | ChangeTrustAsset::PoolShare(_) => return None,
            };
            IdentityFacts::Intent(IntentPayload::Trustline {
                issuer: account_strkey(issuer),
                code,
                limit_stroops: change.limit,
            })
        }
        (OperationKind::Claim, OperationBody::ClaimClaimableBalance(claim)) => {
            let ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) = &claim.balance_id;
            IdentityFacts::Claim {
                balance_id: format!("00000000{}", stellar_agent_core::hex::encode(&hash.0)),
                claimant: source.clone(),
            }
        }
        _ => return None,
    };
    Some(CommitFacts {
        source,
        memo: memo_fact(&tx.memo),
        fee_per_op_stroops: tx.fee,
        identity,
    })
}

/// The strkey of a transaction account: a G strkey, or an M strkey for a
/// multiplexed account.
pub(crate) fn muxed_strkey(account: &stellar_xdr::MuxedAccount) -> String {
    match account {
        stellar_xdr::MuxedAccount::Ed25519(key) => stellar_strkey::ed25519::PublicKey(key.0)
            .to_string()
            .as_str()
            .to_owned(),
        stellar_xdr::MuxedAccount::MuxedEd25519(muxed) => stellar_strkey::ed25519::MuxedAccount {
            ed25519: muxed.ed25519.0,
            id: muxed.id,
        }
        .to_string()
        .as_str()
        .to_owned(),
    }
}

/// The G strkey of an account id.
pub(crate) fn account_strkey(account: &stellar_xdr::AccountId) -> String {
    let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = &account.0;
    stellar_strkey::ed25519::PublicKey(key.0)
        .to_string()
        .as_str()
        .to_owned()
}

/// An asset code without the zero bytes that pad it.
pub(crate) fn asset_code(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The canonical asset of a transaction asset.
fn xdr_intent_asset(asset: &stellar_xdr::Asset) -> IntentAsset {
    match asset {
        stellar_xdr::Asset::Native => IntentAsset::Native,
        stellar_xdr::Asset::CreditAlphanum4(credit) => IntentAsset::Issued {
            code: asset_code(&credit.asset_code.0),
            issuer: account_strkey(&credit.issuer),
        },
        stellar_xdr::Asset::CreditAlphanum12(credit) => IntentAsset::Issued {
            code: asset_code(&credit.asset_code.0),
            issuer: account_strkey(&credit.issuer),
        },
    }
}

/// The send-by time an attempt records for an envelope with `max_time_s`:
/// the authorized submission's own bound, the deadline less the mainnet send
/// margin. An envelope without a deadline leaves the bound to the
/// authorization's expiry.
#[must_use]
pub fn attempt_send_by_ms(max_time_s: u64) -> u64 {
    if max_time_s == 0 {
        return u64::MAX;
    }
    max_time_s
        .saturating_mul(1000)
        .saturating_sub(crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS.saturating_mul(1000))
}

/// The authorization link of the next attempt of `handle`'s operation, which
/// the mint of that attempt's authorization carries.
#[must_use]
pub fn next_attempt_link(handle: &OperationHandle) -> OperationLink {
    OperationLink {
        operation_id: handle.id(),
        attempt_index: handle.attempts().saturating_add(1),
    }
}

/// Opens the next attempt of `handle`'s classic operation for the unsigned
/// envelope `unsigned_envelope_b64`, under the open authorization the mint
/// linked to it. The attempt commits as `Sending` before any signature.
///
/// The attempt's send-by is the submission's own: the envelope's `max_time`
/// less the mainnet send margin. The writer lock is taken before the window
/// lock.
///
/// # Errors
///
/// - `operation.business_id_conflict` for an envelope other than the one the
///   record binds.
/// - `operation.attempt_open` and `operation.attempt_limit`.
/// - The expiry refusal of a record past its window, and the store's other
///   refusals.
/// - `submission.record_unavailable` for a poisoned writer.
pub fn begin_classic_attempt(
    store: &PersistedWindowStore,
    profile: &Profile,
    writer: &AuditWriterHandle,
    request_id: &str,
    handle: &OperationHandle,
    unsigned_envelope_b64: &str,
) -> Result<OperationAttempt, WalletError> {
    begin_classic_attempt_committed(
        store,
        profile,
        writer,
        request_id,
        handle,
        unsigned_envelope_b64,
        &mut CommittedBatch::default(),
    )
}

/// [`begin_classic_attempt`], appending the transitions it commits to
/// `committed`. An error adds no entries; it does not establish rollback.
///
/// # Errors
///
/// The errors of [`begin_classic_attempt`].
pub fn begin_classic_attempt_committed(
    store: &PersistedWindowStore,
    profile: &Profile,
    writer: &AuditWriterHandle,
    request_id: &str,
    handle: &OperationHandle,
    unsigned_envelope_b64: &str,
    committed: &mut CommittedBatch,
) -> Result<OperationAttempt, WalletError> {
    let send_by_ms = attempt_send_by_ms(envelope_max_time(unsigned_envelope_b64)?);
    let mut guard = writer.lock().map_err(|_| {
        WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: "the audit writer mutex is poisoned, so the attempt cannot be recorded"
                .to_owned(),
        })
    })?;
    let mut recorder = OperationRecorder::new(store, profile, &mut *guard, request_id);
    let started = recorder.begin_attempt(
        handle,
        &AttemptRequest {
            envelope: Some(AttemptEnvelope {
                xdr: unsigned_envelope_b64.to_owned(),
                unsigned_envelope_sha256: unsigned_envelope_sha256(unsigned_envelope_b64),
            }),
            authorization: AttemptAuthorization::Linked,
            send_by_ms,
        },
    );
    committed.append(recorder.take_committed());
    let started = started.map_err(operation_refusal)?;
    Ok(OperationAttempt {
        operation_id: handle.id(),
        attempt_index: started.attempt_index,
    })
}

/// What a caller should do next about a retained operation. It is `none` once
/// the operation ended, `wait` while it is prepared, sending or of unknown
/// outcome, and `approve` while it awaits approval. It is `retry` while an
/// authorized or not-included operation may make its next attempt.
#[must_use]
pub fn replay_next(view: &OperationView) -> &'static str {
    use OperationState as S;
    if view.compacted || view.state.is_terminal() {
        return "none";
    }
    match view.state {
        S::AwaitingApproval => "approve",
        S::Authorized | S::NotIncluded => "retry",
        _ => "wait",
    }
}

/// The answer a call under a retained business id receives in place of new
/// work: `{status: "replayed", business_id, operation: {id, state, tx_hash,
/// ledger, error_code}, next}`. A payment record also carries `destination`
/// or `destinations`; a tombstone carries neither.
#[must_use]
pub fn replay_json(view: &OperationView) -> Value {
    let result = view.result.as_ref();
    let mut replay = json!({
        "status": "replayed",
        "business_id": view.business_id.as_str(),
        "operation": {
            "id": view.operation_id.to_hex(),
            "state": view.state.wire_name(),
            "tx_hash": result
                .and_then(|result| result.tx_hash)
                .map(|hash| stellar_agent_core::hex::encode(&hash)),
            "ledger": result.and_then(|result| result.ledger),
            "error_code": result.and_then(|result| result.error_code.clone()),
        },
        "next": replay_next(view),
    });
    if view.destinations != PaymentDestinations::None
        && let (Value::Object(replay), Ok(Value::Object(fields))) = (
            &mut replay,
            serde_json::to_value(DestinationFields(view.destinations.clone())),
        )
    {
        replay.extend(fields);
    }
    replay
}

/// The business id a value call enters with.
///
/// A mainnet profile requires one; every other chain validates a supplied id
/// and keeps no record of it.
///
/// # Errors
///
/// `validation.business_id_required` for a mainnet call without an id, and
/// `validation.business_id_invalid` for a malformed one.
pub fn entry_business_id(
    profile: &Profile,
    raw: Option<&str>,
) -> Result<Option<BusinessId>, WalletError> {
    match raw {
        Some(raw) => BusinessId::parse(raw).map(Some),
        None if profile.chain_id.is_mainnet() => BusinessId::parse("").map(Some),
        None => Ok(None),
    }
}

/// How a classic call proceeds under its business id.
#[derive(Debug)]
pub enum ClassicEntry {
    /// The id is unknown: build the envelope, then open the record.
    Build,
    /// The record holds the envelope to sign; nothing is built.
    Resume(OperationHandle),
    /// The operation needs no further work; answer with [`replay_json`].
    Replay(OperationView),
}

/// Looks up `business_id` before the request builds its envelope, for a
/// request whose [`operation_identity`] is `intent_digest`.
///
/// # Errors
///
/// `operation.business_id_conflict` when the id names an operation bound to
/// another intent or slot kind, and the store's refusals.
pub fn lookup_classic(
    recorder: &mut OperationRecorder<'_>,
    business_id: &BusinessId,
    intent_digest: &[u8; 32],
) -> Result<ClassicEntry, WalletError> {
    let Some(found) = recorder.lookup(business_id).map_err(operation_refusal)? else {
        return Ok(ClassicEntry::Build);
    };
    if found.binding() != (SlotKind::Envelope, *intent_digest) {
        return Err(operation_refusal(WindowStoreError::BusinessIdConflict));
    }
    Ok(match found {
        LookupOutcome::Replay(view) => ClassicEntry::Replay(view),
        LookupOutcome::Resumable(handle) => ClassicEntry::Resume(resumable(handle)?),
    })
}

/// How a classic call proceeds once the record of its envelope is open.
#[derive(Debug)]
pub enum OpenedEntry {
    /// The record holds the envelope to sign.
    Resume(OperationHandle),
    /// The operation needs no further work; answer with [`replay_json`].
    Replay(OperationView),
}

/// Opens the record of a classic request whose envelope was just built.
///
/// A record another call opened between the lookup and this open answers as
/// [`lookup_classic`] would: its stored envelope or its replay.
///
/// # Errors
///
/// `operation.business_id_conflict`, `operation.capacity` and the store's
/// refusals.
pub fn open_classic(
    recorder: &mut OperationRecorder<'_>,
    request: &OpenRequest,
) -> Result<OpenedEntry, WalletError> {
    match recorder.open(request).map_err(operation_refusal)? {
        OpenOutcome::New(handle) | OpenOutcome::Resumable(handle) => {
            resumable(handle).map(OpenedEntry::Resume)
        }
        OpenOutcome::Replay(view) => Ok(OpenedEntry::Replay(view)),
        OpenOutcome::Conflict => Err(operation_refusal(WindowStoreError::BusinessIdConflict)),
    }
}

fn resumable(handle: OperationHandle) -> Result<OperationHandle, WalletError> {
    if handle.envelope_xdr().is_none() {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "a resumable envelope record holds no envelope".to_owned(),
        }));
    }
    Ok(handle)
}

/// The facts of the durable record that the pending inbox `entry` opens for
/// the operation of `handle`. The record keeps the entry's signed clocks.
#[must_use]
pub fn pending_approval_facts(
    entry: &PendingApproval,
    handle: &OperationHandle,
    kind: ApprovedKind,
    subject: [u8; 32],
    rule_ttl_ms: u64,
) -> PendingApprovalFacts {
    PendingApprovalFacts {
        nonce: entry.approval_nonce.clone(),
        kind,
        subject_kind: entry.subject_kind,
        subject: if entry.subject_kind
            == stellar_agent_core::approval::subject::SubjectKind::IntentDigest
        {
            handle.intent().intent_digest()
        } else {
            subject
        },
        intent_digest: handle.intent().intent_digest(),
        created_at_ms: entry.created_at_unix_ms,
        waiting_expires_at_ms: entry.expires_at_unix_ms,
        rule_ttl_ms,
    }
}

/// The refusal of an approval open for a handle whose operation is not
/// `Prepared`, which the open itself would give.
#[must_use]
pub fn approval_requires_prepared() -> WalletError {
    operation_refusal(crate::policy_state::operations::approval_requires_prepared())
}

/// A verified consent and the durable record it completes.
#[derive(Debug)]
pub struct ConsentCompletion {
    id: [u8; 32],
    witness: ApprovalWitness,
    payload: ConsentPayload,
    /// The sink a verified publication handoff proves; `None` on the
    /// compatibility completion.
    delivery: Option<ConsentDeliveryV1>,
}

impl ConsentCompletion {
    /// The witness of the verified consent.
    #[must_use]
    pub fn into_witness(self) -> ApprovalWitness {
        self.witness
    }
}

/// The attestation persisted for `nonce` in `pending`.
///
/// # Errors
///
/// `approval.attestation_invalid` when it is absent, not base64url, or not
/// 32 bytes.
pub fn persisted_attestation(
    pending: &PendingApprovalStore,
    nonce: &str,
) -> Result<[u8; 32], WalletError> {
    let invalid = |detail: &str| {
        WalletError::Approval(ApprovalFailure::AttestationInvalid {
            detail: detail.to_owned(),
        })
    };
    let encoded = pending
        .get(nonce)
        .and_then(|entry| entry.attestation_blob_b64.as_deref())
        .ok_or_else(|| invalid("the persisted attestation is missing"))?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid("the persisted attestation is not base64url"))?
        .try_into()
        .map_err(|_| invalid("the persisted attestation has the wrong length"))
}

/// Verifies the attested inbox entry `nonce` against the durable record that
/// names it, and builds the consent from a copy of that entry. `row` states
/// where the consent audit row went.
///
/// The expectation is the record's kind and subject, so the entry consents
/// only to what the record opened.
///
/// # Errors
///
/// `approval.not_found` when no record or entry names the nonce,
/// `approval.presence_required` for an entry without a receipt, the
/// refusals of [`persisted_attestation`] and admitted consent verification, and the
/// store's refusals.
#[allow(
    clippy::too_many_arguments,
    reason = "completion retains its policy admission"
)]
pub fn consent_completion(
    pending: &PendingApprovalStore,
    store: &PersistedWindowStore,
    profile: &Profile,
    name: &str,
    nonce: &str,
    policy: &VerifiedPolicy,
    row: ConsentRow,
    admission: &stellar_agent_core::approval::presence_policy::PolicyAdmission,
) -> Result<ConsentCompletion, WalletError> {
    complete(
        pending,
        store,
        profile,
        name,
        nonce,
        policy,
        Some(admission),
        |_, _| Ok((row, None)),
    )
}

/// Resolves consent intent under the current policy and the original envelope's source.
/// The durable nonce and operation links are authenticated by [`intent_for_consent`].
///
/// # Errors
/// Returns inconsistent-entry and authenticated intent lookup refusals.
pub fn consent_intent(
    store: &PersistedWindowStore,
    profile: &Profile,
    entry: &PendingApproval,
    policy: &VerifiedPolicy,
) -> Result<Option<ClassicIntent>, WalletError> {
    let summary = stellar_agent_core::approval::classic_entry_summary(&entry.kind).transpose()?;
    intent_for_consent(
        store,
        profile,
        entry,
        &CanonicalUse {
            chain_id: profile.chain_id.caip2_str(),
            source: summary
                .as_ref()
                .map_or("", |summary| summary.source.as_str()),
            policy_digest: policy.digest(),
        },
    )
}

/// [`consent_completion`] for a strict consent: the sink and queued
/// reference come only from the entry's verified publication handoff.
///
/// The handoff must bind the record's subject. A direct anchor completes as
/// a written row with direct delivery, and a queued sink as its exact
/// reference with queued delivery. A recovered or written row claim never
/// supplies either.
///
/// # Errors
///
/// The refusals of [`consent_completion`], the attestation key's refusals,
/// and `approval.attestation_invalid` for a missing, edited or foreign
/// handoff.
pub fn publication_completion(
    pending: &PendingApprovalStore,
    store: &PersistedWindowStore,
    profile: &Profile,
    name: &str,
    nonce: &str,
    policy: &VerifiedPolicy,
) -> Result<ConsentCompletion, WalletError> {
    complete(
        pending,
        store,
        profile,
        name,
        nonce,
        policy,
        None,
        |record, entry| {
            let key = load_attestation_key(
                &profile.attestation_key_id,
                &OwnerKeyContext::for_profile(name, profile),
            )?;
            let verified = verify_consent_publication(
                entry,
                &key,
                &AttestationBinding::new(name, profile.chain_id.caip2_str()),
            )?;
            if verified.subject() != record.subject {
                return Err(WalletError::Approval(ApprovalFailure::AttestationInvalid {
                    detail: "the consent publication names another subject".to_owned(),
                }));
            }
            Ok(match verified.outbox_row() {
                Some(reference) => (
                    ConsentRow::Queued(*reference),
                    Some(ConsentDeliveryV1::queued(record.id)),
                ),
                None => (
                    ConsentRow::Written,
                    Some(ConsentDeliveryV1::direct_anchored(record.id)),
                ),
            })
        },
    )
}

/// The shared body of the completions: `sink` names the row and delivery
/// from the authenticated record and the inbox entry. With `admission`, an
/// authenticated stored intent verifies as an intent consent and any other
/// entry as an envelope consent, both under that admission.
#[allow(
    clippy::too_many_arguments,
    reason = "the completion inputs and optional admission are explicit"
)]
fn complete(
    pending: &PendingApprovalStore,
    store: &PersistedWindowStore,
    profile: &Profile,
    name: &str,
    nonce: &str,
    policy: &VerifiedPolicy,
    admission: Option<&stellar_agent_core::approval::presence_policy::PolicyAdmission>,
    sink: impl FnOnce(
        &WireApproval,
        &PendingApproval,
    ) -> Result<(ConsentRow, Option<ConsentDeliveryV1>), WalletError>,
) -> Result<ConsentCompletion, WalletError> {
    let not_found = || {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no durable approval record and inbox entry name this nonce".to_owned(),
        })
    };
    let record = ApprovalStatus::new(store, profile)
        .find_by_nonce(nonce)
        .map_err(operation_refusal)?
        .ok_or_else(not_found)?
        .record;
    let entry = pending.get(nonce).cloned().ok_or_else(not_found)?;
    let attestation = persisted_attestation(pending, nonce)?;
    let intent = admission
        .map(|_| consent_intent(store, profile, &entry, policy))
        .transpose()?
        .flatten();
    let receipt = entry
        .mainnet_presence
        .clone()
        .ok_or(WalletError::Approval(ApprovalFailure::PresenceRequired))?;
    let now = stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
        WalletError::Approval(ApprovalFailure::ClockError {
            detail: error.to_string(),
        })
    })?;
    let expectation = ApprovalExpectation {
        kind: record.kind,
        subject: record.subject,
    };
    let witness = match (admission, intent.as_ref()) {
        (Some(admission), Some(intent)) => verify_intent_consent_admitted(
            pending,
            profile,
            name,
            nonce,
            &attestation,
            intent,
            policy,
            now,
            admission,
        )?,
        (Some(admission), None) => verify_approval_admitted(
            pending,
            profile,
            name,
            nonce,
            &attestation,
            &expectation,
            policy,
            now,
            admission,
        )?,
        (None, _) => verify_approval(
            pending,
            profile,
            name,
            nonce,
            &attestation,
            &expectation,
            policy,
            now,
        )?,
    };
    let (row, delivery) = sink(&record, &entry)?;
    Ok(ConsentCompletion {
        id: record.id,
        witness,
        payload: ConsentPayload::new(attestation, receipt, entry.process_uid, row),
        delivery,
    })
}

/// The completion of the durable record that names the nonce of `witness`,
/// for a consent its caller verified, or `None` when no record names it.
///
/// The read holds no inbox lock. [`commit_consent`] then checks the witness
/// against the record's kind, subject and clocks. The completion carries no
/// delivery: the payload's row claim never supplies a sink.
///
/// # Errors
///
/// The store's refusals, rendered through [`operation_refusal`].
pub fn witnessed_completion(
    store: &PersistedWindowStore,
    profile: &Profile,
    witness: ApprovalWitness,
    payload: ConsentPayload,
) -> Result<Option<ConsentCompletion>, WalletError> {
    Ok(ApprovalStatus::new(store, profile)
        .find_by_nonce(witness.nonce())
        .map_err(operation_refusal)?
        .map(|view| ConsentCompletion {
            id: view.record.id,
            witness,
            payload,
            delivery: None,
        }))
}

/// Completes a witnessed consent using its verified publication handoff.
/// The caller verifies both from the same inbox entry under policy admission,
/// then releases the writer, inbox and admission before calling this builder.
/// Only the handoff supplies delivery and the exact queued reference.
///
/// # Errors
/// Returns store refusals, `approval.not_found` without a durable record,
/// and `approval.attestation_invalid` when the handoff names another subject.
pub fn witnessed_publication_completion(
    store: &PersistedWindowStore,
    profile: &Profile,
    witness: ApprovalWitness,
    mut payload: ConsentPayload,
    publication: &VerifiedConsentPublication,
) -> Result<ConsentCompletion, WalletError> {
    let record = ApprovalStatus::new(store, profile)
        .find_by_nonce(witness.nonce())
        .map_err(operation_refusal)?
        .ok_or_else(|| {
            WalletError::Approval(ApprovalFailure::NotFound {
                detail: "the publication has no durable approval record".to_owned(),
            })
        })?
        .record;
    if publication.subject() != record.subject {
        return Err(WalletError::Approval(ApprovalFailure::AttestationInvalid {
            detail: "the consent publication names another subject".to_owned(),
        }));
    }
    payload.outbox_row = publication.outbox_row().copied();
    payload.row_provenance = publication
        .outbox_row()
        .is_none()
        .then_some(crate::policy_state::RowProvenance::Written);
    Ok(ConsentCompletion {
        id: record.id,
        witness,
        payload,
        delivery: Some(if publication.is_direct_anchored() {
            ConsentDeliveryV1::direct_anchored(record.id)
        } else {
            ConsentDeliveryV1::queued(record.id)
        }),
    })
}

/// The audit sink of a consent commit, which appends no row. An append is a
/// defect and fails the step as `audit.append_failed`.
pub(crate) struct ConsentOnlyAudit;

impl OperationAudit for ConsentOnlyAudit {
    fn append(&mut self, _entry: AuditEntry) -> Result<(), String> {
        Err("a consent commit appends no audit row".to_owned())
    }
}

/// Commits `completion` to its durable record under the window lock alone.
///
/// The step takes no audit writer, so a process that cannot hold the writer
/// still commits; the consent audit row keeps its own route. A repeated
/// commit of the same receipt changes nothing. A completion from
/// [`publication_completion`] commits its delivery with the consent.
///
/// # Errors
///
/// The refusals of [`ApprovalRecorder::record_consent`] and
/// [`ApprovalRecorder::record_consent_with_delivery`], rendered through
/// [`operation_refusal`].
pub fn commit_consent(
    store: &PersistedWindowStore,
    profile: &Profile,
    completion: &ConsentCompletion,
) -> Result<ApprovalView, WalletError> {
    let mut audit = ConsentOnlyAudit;
    let mut recorder =
        ApprovalRecorder::new(store, profile, &mut audit, uuid::Uuid::new_v4().to_string());
    match &completion.delivery {
        Some(delivery) => recorder.record_consent_with_delivery(
            completion.id,
            &completion.witness,
            &completion.payload,
            delivery.clone(),
        ),
        None => recorder.record_consent(completion.id, &completion.witness, &completion.payload),
    }
    .map_err(operation_refusal)
}

/// The stores an integrated approval request is admitted under.
pub struct ConsentAdmission<'a> {
    /// The policy-window store of the profile.
    pub store: &'a PersistedWindowStore,
    /// The profile of the request.
    pub profile: &'a Profile,
    /// The keyed audit writer that initializes the owner's evidence.
    pub writer: &'a mut AuditWriter,
    /// The keyed outbox that reserves the evidence slot.
    pub outbox: &'a AuditOutbox,
}

impl ConsentAdmission<'_> {
    /// Admits an integrated approval request for `operation`, then runs
    /// `present` with the committed record and its reservation.
    ///
    /// In order: the owner-scope inventory, the pending record, the owner's
    /// evidence initialization, the release of evidence whose records ended,
    /// and the reservation. The record is the one
    /// already committed for the operation, else the one `open` commits from
    /// `facts`, else the committed winner of a conflicting open. Its stored
    /// nonce, clocks and facts govern a retry, never the retry's own facts.
    /// Each step after the open runs outside the window lock. A refusal
    /// keeps the committed record and any reservation.
    ///
    /// # Errors
    ///
    /// The refusals of [`require_consent_evidence_inventory`], of `open`
    /// when no record names the operation, of evidence initialization, of
    /// [`sweep_ended_consent_evidence`],
    /// `audit.outbox_evidence_unusable` while a migration pin remains, the
    /// refusals of [`ApprovalRecorder::reserve_consent_evidence`], and those
    /// of `present`.
    pub fn admit<T>(
        &mut self,
        operation: OperationId,
        facts: &PendingApprovalFacts,
        open: impl FnOnce(&mut AuditWriter, &PendingApprovalFacts) -> Result<ApprovalView, WalletError>,
        present: impl FnOnce(&WireApproval, &EvidenceReservation) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let name = profile_name_for_approval(self.profile);
        require_consent_evidence_inventory(&name)?;
        let status = ApprovalStatus::new(self.store, self.profile);
        let committed = || {
            status
                .find_by_operation(operation)
                .map_err(operation_refusal)
        };
        let record = match committed()? {
            Some(view) => view.record,
            None => match open(self.writer, facts) {
                Ok(view) => view.record,
                Err(error) => committed()?.ok_or(error)?.record,
            },
        };
        let evidence_refusal = |error: WriterError| audit_writer_refusal(&name, &error);
        self.writer
            .initialize_consent_evidence()
            .map_err(evidence_refusal)?;
        sweep_ended_consent_evidence(self.store, self.profile, self.outbox)?;
        let reservation = Self::reacquire(
            self.store,
            self.profile,
            record.operation_id,
            &record.facts(),
            self.outbox,
        )?;
        present(&record, &reservation)
    }

    /// Reacquires an existing record's slot without acquiring an audit writer.
    /// Inventory, initialized evidence and authenticated facts must all agree.
    /// This path never initializes from absent ownership or evidence files.
    ///
    /// # Errors
    /// Returns inventory, evidence and authenticated record refusals, including
    /// `approval.evidence_capacity`. Unresolved migration pins refuse admission.
    pub fn reacquire(
        store: &PersistedWindowStore,
        profile: &Profile,
        operation: OperationId,
        facts: &PendingApprovalFacts,
        outbox: &AuditOutbox,
    ) -> Result<EvidenceReservation, WalletError> {
        let name = profile_name_for_approval(profile);
        require_consent_evidence_inventory(&name)?;
        let evidence_refusal = |error: WriterError| audit_writer_refusal(&name, &error);
        if outbox
            .evidence()
            .map_err(evidence_refusal)?
            .is_none_or(|evidence| evidence.holds_migration_pins())
        {
            return Err(evidence_refusal(WriterError::OutboxEvidenceUnusable {
                reason: "unresolved migration pin",
            }));
        }
        let reservation = ApprovalRecorder::new(
            store,
            profile,
            &mut ConsentOnlyAudit,
            uuid::Uuid::new_v4().to_string(),
        )
        .reserve_consent_evidence(operation, facts, outbox)?;
        Ok(reservation)
    }
}

/// How a classic commit proceeds under its business id.
#[derive(Debug)]
pub enum CommitEntry {
    /// Sign and send under this record.
    Proceed(OperationHandle),
    /// The operation needs no further work; answer with [`replay_json`].
    Replay(OperationView),
}

/// Looks up the record a commit of `unsigned_envelope_b64` under
/// `business_id` continues. The record under the id must bind that envelope,
/// and no record under another id may own it alone. A tombstone under the id
/// must hold an envelope slot whose digest is one of `identities`, the
/// [`commit_identities`] of the envelope.
///
/// # Errors
///
/// `operation.business_id_mismatch` for an id without a record or an
/// envelope only other ids bind. `operation.business_id_conflict` for a
/// record that binds another envelope or none, or a tombstone of another
/// intent. The store's refusals.
pub fn commit_classic(
    store: &PersistedWindowStore,
    recorder: &mut OperationRecorder<'_>,
    profile: &Profile,
    business_id: &BusinessId,
    unsigned_envelope_b64: &str,
    identities: &[[u8; 32]],
) -> Result<CommitEntry, WalletError> {
    let envelope_sha256 = unsigned_envelope_sha256(unsigned_envelope_b64);
    let binding = OperationStatus::new(store, profile)
        .commit_binding(business_id, &envelope_sha256)
        .map_err(operation_refusal)?;
    checked_commit_target(binding, business_id, &envelope_sha256, identities)?;
    match recorder.lookup(business_id).map_err(operation_refusal)? {
        None => Err(operation_refusal(WindowStoreError::BusinessIdMismatch)),
        Some(LookupOutcome::Replay(view)) => Ok(CommitEntry::Replay(view)),
        Some(LookupOutcome::Resumable(handle)) => Ok(CommitEntry::Proceed(handle)),
    }
}

/// Answers a classic commit of `unsigned_envelope_b64` under `business_id`
/// from the store, before the commit verifies its approval, rebuilds its
/// envelope or consumes its nonce.
///
/// The read takes no lock and writes nothing. It refuses an envelope the
/// id does not bind as [`commit_classic`] refuses it, with `identities` the
/// [`commit_identities`] of the envelope. A record or
/// tombstone that does no further work answers with its view, so a commit
/// retried after a lost reply does no new work. A record that continues
/// gives `None`: the commit runs its gates, and [`commit_classic`] then
/// decides under the recorder. A window this read cannot read gives `None`
/// too, so the gates, which read the same window, refuse it with their own
/// codes.
///
/// # Errors
///
/// `operation.business_id_mismatch` and `operation.business_id_conflict`.
pub fn commit_replay(
    store: &PersistedWindowStore,
    profile: &Profile,
    business_id: &BusinessId,
    unsigned_envelope_b64: &str,
    identities: &[[u8; 32]],
) -> Result<Option<OperationView>, WalletError> {
    let envelope_sha256 = unsigned_envelope_sha256(unsigned_envelope_b64);
    let Ok(binding) =
        OperationStatus::new(store, profile).commit_binding(business_id, &envelope_sha256)
    else {
        return Ok(None);
    };
    let view = checked_commit_target(binding, business_id, &envelope_sha256, identities)?;
    Ok((view.compacted || !view.state.resumes()).then_some(view))
}

/// Admits a classic commit of the unsigned envelope with digest
/// `envelope_sha256` under `business_id` from the facts of one window read.
/// It returns the view of the operation the id names.
///
/// The preparation of an envelope opened the record that binds it. An
/// envelope that only records under other ids bind, and an id no record or
/// tombstone carries, both name an id other than the preparation's. A record
/// under the id that binds another envelope, or binds none, holds another
/// intent. A tombstone keeps no envelope binding, only its slot kind and
/// intent digest. It answers with its view only for an envelope slot whose
/// digest is one of `identities`; any other tombstone holds another intent.
///
/// # Errors
///
/// `operation.business_id_mismatch` for an id other than the preparation's,
/// and `operation.business_id_conflict` for a record or tombstone of another
/// intent.
fn checked_commit_target(
    binding: CommitBinding,
    business_id: &BusinessId,
    envelope_sha256: &[u8; 32],
    identities: &[[u8; 32]],
) -> Result<OperationView, WalletError> {
    refuse_foreign_envelope(&binding.owners, business_id)?;
    match binding.target {
        None => Err(operation_refusal(WindowStoreError::BusinessIdMismatch)),
        Some(CommitTarget::Tombstone(view))
            if view.slot_kind == SlotKind::Envelope && identities.contains(&view.intent_digest) =>
        {
            Ok(view)
        }
        Some(CommitTarget::Tombstone(_)) => {
            Err(operation_refusal(WindowStoreError::BusinessIdConflict))
        }
        Some(CommitTarget::Record {
            view,
            envelope_sha256: bound,
        }) if bound.as_ref() == Some(envelope_sha256) => Ok(view),
        Some(CommitTarget::Record { .. }) => {
            Err(operation_refusal(WindowStoreError::BusinessIdConflict))
        }
    }
}

/// Refuses a commit under `business_id` of an envelope that only the
/// records `owners` under other ids bind.
fn refuse_foreign_envelope(
    owners: &[OperationView],
    business_id: &BusinessId,
) -> Result<(), WalletError> {
    if !owners.is_empty() && owners.iter().all(|owner| &owner.business_id != business_id) {
        return Err(operation_refusal(WindowStoreError::BusinessIdMismatch));
    }
    Ok(())
}

/// The wallet refusal an operation store failure names. It is the failure's own
/// operation code, a chain validation refusal or a mainnet precondition. A
/// store the wallet could not read or write gives
/// `submission.record_unavailable`.
#[must_use]
pub fn operation_refusal(error: WindowStoreError) -> WalletError {
    if let Some(refusal) = error.operation_error() {
        return refusal;
    }
    if let Some(refusal) = error.chain_validation_error() {
        return refusal.into();
    }
    match error {
        WindowStoreError::AuthorizationRefused { precondition } => {
            MainnetAuthorizationError::Refused(precondition).into()
        }
        other => WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: format!(
                "the operation record could not be read or written: {}",
                other.with_recovery_notice(other.to_string())
            ),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use super::*;
    use crate::policy_state::{OperationId, OperationResult};
    use stellar_agent_core::approval::IntentAsset;

    const SOURCE: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    pub(crate) const DESTINATION: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const OTHER: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

    /// The base facts under the policy with digest `policy`.
    fn base(policy: [u8; 32], memo: MemoFact) -> IntentBaseFacts<'static> {
        IntentBaseFacts {
            chain_id: "stellar:mainnet",
            source: SOURCE,
            policy_digest: policy,
            signed_fee_cap: Some(1_000),
            profile_fee_cap: Some(500),
            fee_choice: ClassicFeeChoice::ProfileDefault,
            memo,
        }
    }

    fn pay(policy: [u8; 32], destination: &str, amount: i64, memo: MemoFact) -> [u8; 32] {
        let intent = classic_intent(
            base(policy, memo),
            IntentPayload::Pay {
                destination: destination.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: amount,
            },
        )
        .unwrap();
        *intent.digest().as_bytes()
    }

    /// The envelope text of a 1 XLM payment at `sequence` with `max_time`.
    fn envelope(sequence: i64, max_time: u64) -> String {
        let mut builder = crate::ClassicOpBuilder::new(
            SOURCE,
            sequence,
            "Public Global Stellar Network ; September 2015",
            100,
        );
        builder
            .payment(
                DESTINATION,
                stellar_agent_core::StellarAmount::from_stroops(10_000_000),
                &crate::Asset::Native,
            )
            .unwrap();
        builder.with_presented_deadline(max_time);
        builder.build().unwrap()
    }

    /// A contract payment's base binds the total cap and its identity is the
    /// canonical digest; the classic helpers refuse to build one. The digest
    /// literal is the core contract intent vector.
    #[test]
    fn b1_contract_pay_base_and_identity() {
        let source = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
        let cap = ContractTransferFeeCap {
            stroops: 1_000_000,
            signed: false,
        };
        let contract_base =
            contract_pay_base(Caip2::Testnet, source, [0x11; 32], MemoFact::None, cap).unwrap();
        assert_eq!(contract_base.fee_bound_stroops(), 1_000_000, "cap bound");
        assert_eq!(contract_base.chain_id(), "stellar:testnet");
        let payload = IntentPayload::ContractPay {
            destination: "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ".to_owned(),
            asset: IntentAsset::Issued {
                code: "USD".to_owned(),
                issuer: "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC".to_owned(),
            },
            amount_stroops: 1,
            explicit_inclusion_bid_stroops: Some(100),
        };
        let intent = ClassicIntent::new(contract_base.clone(), payload.clone()).unwrap();
        assert_eq!(
            stellar_agent_core::hex::encode(&contract_pay_identity(&intent).unwrap()),
            "68018e1f2c0b5516a051f4e12eb28c8706897da35168895690f4750241c2a6db",
            "identity literal"
        );
        let invalid = "validation.contract_payment_invalid";
        let bad_source = contract_pay_base(Caip2::Testnet, "GBAD", [0x11; 32], MemoFact::None, cap);
        assert_eq!(bad_source.unwrap_err().code(), invalid);
        let classic = ClassicIntent::new(
            contract_base,
            IntentPayload::Pay {
                destination: DESTINATION.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 1,
            },
        )
        .unwrap();
        assert_eq!(contract_pay_identity(&classic).unwrap_err().code(), invalid);
        let unavailable = "validation.contract_payment_unavailable";
        let classic_build = classic_intent(base([0x11; 32], MemoFact::None), payload);
        assert_eq!(
            classic_build.unwrap_err().code(),
            unavailable,
            "classic intent"
        );
        let rebuild = intent_envelope(&intent, "Test SDF Network ; September 2015", 1, 100, 0);
        assert_eq!(rebuild.unwrap_err().code(), unavailable, "classic rebuild");
    }

    /// Two builds of the same facts at different times and sequences give
    /// one digest; another amount, destination, memo or policy gives
    /// another.
    #[test]
    fn classic_intent_digest_is_stable_across_rebuilds() {
        let signed = [0x11; 32];
        let first_envelope = envelope(41, 1_900_000_000);
        let second_envelope = envelope(57, 1_900_000_090);
        assert_ne!(first_envelope, second_envelope);
        let digest = pay(signed, DESTINATION, 10_000_000, MemoFact::None);
        let first = classic_intent(
            base(signed, MemoFact::None),
            IntentPayload::Pay {
                destination: DESTINATION.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 10_000_000,
            },
        )
        .unwrap();
        let identity = *first.digest().as_bytes();
        let first_slot = envelope_slot(&identity, &first_envelope, 1_900_000_000);
        let second_slot = envelope_slot(&identity, &second_envelope, 1_900_000_090);
        assert_eq!(first_slot.intent_digest(), digest);
        assert_eq!(second_slot.intent_digest(), digest);
        assert_ne!(
            first_slot, second_slot,
            "the slots bind their own envelopes"
        );

        assert_ne!(pay(signed, DESTINATION, 10_000_001, MemoFact::None), digest);
        assert_ne!(pay(signed, OTHER, 10_000_000, MemoFact::None), digest);
        assert_ne!(
            pay(signed, DESTINATION, 10_000_000, MemoFact::Id(7)),
            digest
        );
        assert_ne!(
            pay([0x12; 32], DESTINATION, 10_000_000, MemoFact::None),
            digest
        );
    }

    const BALANCE: &str =
        "00000000cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    /// The identity of a claim of `balance_id` by `claimant` holding `asset`
    /// and `amount`, under the policy with digest `policy`.
    fn claim(
        policy: [u8; 32],
        balance_id: &str,
        claimant: &str,
        asset: IntentAsset,
        amount: i64,
    ) -> [u8; 32] {
        operation_identity(
            base(policy, MemoFact::None),
            IdentityFacts::Intent(IntentPayload::Claim {
                balance_id: balance_id.to_owned(),
                asset,
                amount_stroops: amount,
                claimant: claimant.to_owned(),
            }),
        )
        .unwrap()
    }

    /// A claim's identity binds its base facts, balance and claimant. The
    /// identity from the arguments alone equals the one of every whole claim
    /// intent of that balance, whatever amount and asset the ledger reports.
    /// Another balance, policy or fee bound gives another. A request of another
    /// kind binds its whole intent digest.
    #[test]
    fn a_claim_identity_binds_the_balance_and_the_claimant() {
        let signed = [0x11; 32];
        let identity = operation_identity(
            base(signed, MemoFact::None),
            IdentityFacts::Claim {
                balance_id: BALANCE.to_owned(),
                claimant: SOURCE.to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            claim(signed, BALANCE, SOURCE, IntentAsset::Native, 100),
            identity
        );
        let issued = IntentAsset::Issued {
            code: "USDC".to_owned(),
            issuer: OTHER.to_owned(),
        };
        assert_eq!(claim(signed, BALANCE, SOURCE, issued, 7), identity);

        let other_balance = format!("00000000{}", "ab".repeat(32));
        assert_ne!(
            claim(signed, &other_balance, SOURCE, IntentAsset::Native, 100),
            identity
        );
        assert_ne!(
            claim([0x12; 32], BALANCE, SOURCE, IntentAsset::Native, 100),
            identity
        );
        let mut explicit = base(signed, MemoFact::None);
        explicit.fee_choice = ClassicFeeChoice::Explicit(300);
        let other_fee = operation_identity(
            explicit,
            IdentityFacts::Claim {
                balance_id: BALANCE.to_owned(),
                claimant: SOURCE.to_owned(),
            },
        )
        .unwrap();
        assert_ne!(other_fee, identity);
        for (balance_id, claimant) in [(BALANCE, OTHER), ("00000000ab", SOURCE)] {
            let refused = operation_identity(
                base(signed, MemoFact::None),
                IdentityFacts::Claim {
                    balance_id: balance_id.to_owned(),
                    claimant: claimant.to_owned(),
                },
            )
            .unwrap_err();
            assert_eq!(refused.code(), "internal.unexpected_state", "{balance_id}");
        }

        assert_eq!(
            operation_identity(
                base(signed, MemoFact::None),
                IdentityFacts::Intent(IntentPayload::Pay {
                    destination: DESTINATION.to_owned(),
                    asset: IntentAsset::Native,
                    amount_stroops: 10_000_000,
                }),
            )
            .unwrap(),
            pay(signed, DESTINATION, 10_000_000, MemoFact::None)
        );
    }

    /// The claim identity hashes the label, then the chain, the source, the
    /// policy digest, the fee bound and the memo tag. The balance id and the
    /// claimant follow, each string and digest behind its big-endian length. An
    /// independent encoding of this layout supplies the expected digest.
    /// Changing a field or its position changes the digest.
    #[test]
    fn a_claim_identity_matches_its_golden_vector() {
        let identity = operation_identity(
            base([0x11; 32], MemoFact::None),
            IdentityFacts::Claim {
                balance_id: BALANCE.to_owned(),
                claimant: SOURCE.to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            stellar_agent_core::hex::encode(&identity),
            "100b4943a2ec041cfa9490ce4973973c5fd4a366e9cec20890d937362581603b"
        );
    }

    #[test]
    fn fee_bound_takes_the_explicit_choice_or_the_tighter_cap() {
        let signed = Some(1_000);
        assert_eq!(
            fee_bound(Some(500), signed, ClassicFeeChoice::Explicit(700)).unwrap(),
            700
        );
        assert_eq!(
            fee_bound(Some(500), signed, ClassicFeeChoice::ProfileDefault).unwrap(),
            500
        );
        assert_eq!(
            fee_bound(Some(5_000), signed, ClassicFeeChoice::ProfileDefault).unwrap(),
            1_000
        );
        assert_eq!(
            fee_bound(None, signed, ClassicFeeChoice::ProfileDefault).unwrap(),
            1_000
        );
        assert_eq!(
            fee_bound(None, None, ClassicFeeChoice::ProfileDefault)
                .unwrap_err()
                .code(),
            "validation.mainnet_fee_cap_required"
        );
    }

    fn view(state: OperationState, compacted: bool) -> OperationView {
        OperationView {
            operation_id: OperationId::from_bytes([0x5a; 16]),
            business_id: BusinessId::parse("order-7").unwrap(),
            state,
            tool: None,
            kind: None,
            slot_kind: SlotKind::Envelope,
            intent_digest: [1; 32],
            attempts: 1,
            result: Some(OperationResult {
                tx_hash: Some([0xab; 32]),
                ledger: Some(1005),
                error_code: None,
                payload_released: false,
            }),
            created_at_ms: None,
            closed_at_ms: None,
            waiting_expires_at_ms: None,
            execution_expires_at_ms: None,
            compacted,
            history_incomplete: false,
            destinations: PaymentDestinations::None,
        }
    }

    #[test]
    fn replay_json_next_follows_the_state() {
        use OperationState as S;
        for state in OperationState::ALL {
            let expected = if state.is_terminal() {
                "none"
            } else {
                match state {
                    S::AwaitingApproval => "approve",
                    S::Authorized | S::NotIncluded => "retry",
                    S::Prepared | S::Sending | S::SentOutcomeUnknown => "wait",
                    other => panic!("unclassified state {other:?}"),
                }
            };
            assert_eq!(
                replay_json(&view(state, false))["next"],
                expected,
                "{state:?}"
            );
        }
        assert_eq!(replay_json(&view(S::Sending, false))["next"], "wait");
        assert_eq!(
            replay_json(&view(S::SentOutcomeUnknown, false))["next"],
            "wait"
        );
        assert_eq!(replay_json(&view(S::Succeeded, true))["next"], "none");
        assert_eq!(
            replay_json(&view(S::SentOutcomeUnknown, false)),
            json!({
                "status": "replayed",
                "business_id": "order-7",
                "operation": {
                    "id": "5a".repeat(16),
                    "state": "sent_outcome_unknown",
                    "tx_hash": "ab".repeat(32),
                    "ledger": 1005,
                    "error_code": null,
                },
                "next": "wait",
            })
        );
    }

    /// Every result shape of `result_destinations` and its literal members.
    #[test]
    fn result_destinations_follow_the_payment_operations() {
        use crate::submit::destination_tests::{envelope_for_destinations, payment};
        use stellar_agent_core::profile::receipt::OperationDestination;
        use stellar_xdr::{
            Asset, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
            FeeBumpTransactionInnerTx, ManageDataOp, MuxedAccount, Operation, OperationBody,
            PathPaymentStrictReceiveOp, PathPaymentStrictSendOp, Uint256, WriteXdr as _,
        };
        const G: &str = "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI";
        const G_OTHER: &str = "GAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEARIHQ";
        const M_MAX: &str = "MADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP77777777777754MA";
        let account = |text: &str| {
            stellar_agent_core::payment_accounts::PaymentAccount::parse(text)
                .unwrap()
                .to_muxed_account()
        };
        let manage_data = Operation {
            source_account: None,
            body: OperationBody::ManageData(ManageDataOp {
                data_name: "k".as_bytes().to_vec().try_into().unwrap(),
                data_value: None,
            }),
        };
        let strict_receive = Operation {
            source_account: None,
            body: OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                send_asset: Asset::Native,
                send_max: 10,
                destination: account(G),
                dest_asset: Asset::Native,
                dest_amount: 5,
                path: Default::default(),
            }),
        };
        let strict_send = Operation {
            source_account: None,
            body: OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_asset: Asset::Native,
                send_amount: 10,
                destination: account(M_MAX),
                dest_asset: Asset::Native,
                dest_min: 5,
                path: Default::default(),
            }),
        };
        let entry = |operation: u32, destination: &str| OperationDestination {
            operation,
            destination: destination.to_owned(),
        };
        let wire = |value: &PaymentDestinations| {
            serde_json::to_value(DestinationFields(value.clone())).unwrap()
        };

        let none = result_destinations(&envelope_for_destinations(vec![manage_data.clone()]));
        assert_eq!(none, PaymentDestinations::None);
        assert_eq!(wire(&none), json!({}));

        let single_g = result_destinations(&envelope_for_destinations(vec![payment(G)]));
        assert_eq!(single_g, PaymentDestinations::Single(G.to_owned()));
        assert_eq!(wire(&single_g), json!({ "destination": G }));

        let shared = result_destinations(&envelope_for_destinations(vec![
            payment(M_MAX),
            payment(M_MAX),
        ]));
        assert_eq!(shared, PaymentDestinations::Single(M_MAX.to_owned()));
        assert_eq!(wire(&shared), json!({ "destination": M_MAX }));

        let mixed = envelope_for_destinations(vec![payment(G), manage_data, payment(M_MAX)]);
        let listed = result_destinations(&mixed);
        assert_eq!(
            listed,
            PaymentDestinations::PerOperation(vec![entry(0, G), entry(2, M_MAX)])
        );
        assert_eq!(
            wire(&listed),
            json!({ "destinations": [
                { "operation": 0, "destination": G },
                { "operation": 2, "destination": M_MAX },
            ] })
        );

        let two_g = result_destinations(&envelope_for_destinations(vec![
            payment(G),
            payment(G_OTHER),
        ]));
        assert_eq!(
            wire(&two_g),
            json!({ "destinations": [
                { "operation": 0, "destination": G },
                { "operation": 1, "destination": G_OTHER },
            ] })
        );

        let paths = result_destinations(&envelope_for_destinations(vec![
            strict_receive,
            strict_send,
        ]));
        assert_eq!(
            paths,
            PaymentDestinations::PerOperation(vec![entry(0, G), entry(1, M_MAX)])
        );

        let TransactionEnvelope::Tx(inner) = mixed.clone() else {
            panic!("expected a v1 envelope")
        };
        let fee_bump = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([9; 32])),
                fee: 1_000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        });
        assert_eq!(result_destinations(&fee_bump), listed);

        let text = mixed.to_xdr_base64(Limits::none()).unwrap();
        assert_eq!(envelope_result_destinations(&text), listed);
        assert_eq!(
            envelope_result_destinations("not an envelope"),
            PaymentDestinations::None
        );
        assert_eq!(envelope_result_destinations(""), PaymentDestinations::None);
    }

    /// A canonical slot read back from the authenticated store yields its
    /// intent only when the stored value is the canonical JSON of a valid
    /// intent, hashes to the stored digest, and names the admitted chain,
    /// source and policy. Each refused record still looks up and shows its
    /// status, and the check leaves the store file unchanged.
    #[test]
    #[serial_test::serial]
    fn canonical_slot_is_validated_before_use() {
        use crate::policy_state::operations::tests::Fx;
        use crate::policy_state::{OperationTool, OperationView};
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut fx = Fx::new();
        let intent = classic_intent(
            base([0x11; 32], MemoFact::Id(7)),
            IntentPayload::Pay {
                destination: DESTINATION.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 10,
            },
        )
        .unwrap();
        let json = serde_json::to_value(&intent).unwrap();
        let digest = *intent.digest().as_bytes();
        let slot = |intent: Value, intent_digest: [u8; 32]| IntentSlot::Canonical {
            intent_digest,
            intent,
        };
        let mut missing = json.clone();
        missing["payload"]["pay"]
            .as_object_mut()
            .unwrap()
            .remove("amount_stroops");
        let mut unknown = json.clone();
        unknown["base"]["note"] = json!("extra");
        let mut invalid = json.clone();
        invalid["payload"]["pay"]["amount_stroops"] = json!("0");
        let other = json!({"base": json["base"], "payload": {"pay": {
            "destination": OTHER, "asset": "native", "amount_stroops": "10"}}});
        let cases = [
            ("valid", slot(json.clone(), digest), None),
            (
                "missing field",
                slot(missing, digest),
                Some(CanonicalRefusal::Malformed),
            ),
            (
                "unknown field",
                slot(unknown, digest),
                Some(CanonicalRefusal::Malformed),
            ),
            (
                "invalid amount",
                slot(invalid, digest),
                Some(CanonicalRefusal::Malformed),
            ),
            (
                "other intent",
                slot(other, digest),
                Some(CanonicalRefusal::StoredDigest),
            ),
            (
                "envelope slot",
                envelope_slot(&digest, &envelope(41, 1_900_000_000), 1_900_000_000),
                Some(CanonicalRefusal::NotCanonical),
            ),
        ];
        let admitted = CanonicalUse {
            chain_id: "stellar:mainnet",
            source: SOURCE,
            policy_digest: [0x11; 32],
        };
        for (index, (name, intent_slot, _)) in cases.iter().enumerate() {
            let opened = fx
                .recorder()
                .open(&OpenRequest {
                    business_id: BusinessId::parse(&format!("order-{index}")).unwrap(),
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: intent_slot.clone(),
                    envelope_xdr: Some(envelope(41, 1_900_000_000)),
                    prepared_decision: None,
                    rule_ttl_ms: None,
                })
                .unwrap();
            assert!(matches!(opened, OpenOutcome::New(_)), "{name}");
        }
        for (index, (name, _, expected)) in cases.iter().enumerate() {
            let business_id = BusinessId::parse(&format!("order-{index}")).unwrap();
            let Some(LookupOutcome::Resumable(handle)) =
                fx.recorder().lookup(&business_id).unwrap()
            else {
                panic!("{name}: the record stays resumable")
            };
            let status = OperationStatus::new(&fx.store, &fx.profile);
            assert!(status.view(&business_id).unwrap().is_some(), "{name}");
            let listed: Vec<OperationView> = status.list_since(0).unwrap();
            assert!(listed.iter().any(|view| view.business_id == business_id));
            let before = std::fs::read(fx.store.path()).unwrap();
            let result = canonical_slot_intent(handle.intent(), &admitted);
            assert_eq!(std::fs::read(fx.store.path()).unwrap(), before, "{name}");
            match expected {
                None => assert_eq!(result.unwrap(), intent, "{name}"),
                Some(refusal) => assert_eq!(result.unwrap_err(), *refusal, "{name}"),
            }
        }
        let valid = slot(json, digest);
        for (name, changed, part) in [
            (
                "chain",
                CanonicalUse {
                    chain_id: "stellar:testnet",
                    ..admitted
                },
                CanonicalPart::Chain,
            ),
            (
                "source",
                CanonicalUse {
                    source: OTHER,
                    ..admitted
                },
                CanonicalPart::Source,
            ),
            (
                "policy",
                CanonicalUse {
                    policy_digest: [0x12; 32],
                    ..admitted
                },
                CanonicalPart::Policy,
            ),
        ] {
            assert_eq!(
                canonical_slot_intent(&valid, &changed).unwrap_err(),
                CanonicalRefusal::Mismatch(part),
                "{name}"
            );
        }
    }

    /// The `getLedgerEntries` answer of the fixture's source account at
    /// `sequence`.
    #[cfg(feature = "mainnet-write")]
    fn source_at(f: &crate::mainnet::fixtures::ResolverFixture, sequence: i64) -> Value {
        use stellar_xdr::{LedgerEntryData, WriteXdr as _};
        let mut answer = f.source.ledger_entries_result();
        let text = answer["entries"][0]["xdr"].as_str().unwrap().to_owned();
        let LedgerEntryData::Account(mut account) =
            LedgerEntryData::from_xdr_base64(&text, Limits::none()).unwrap()
        else {
            panic!("an account entry")
        };
        account.seq_num = stellar_xdr::SequenceNumber(sequence);
        answer["entries"][0]["xdr"] = json!(
            LedgerEntryData::Account(account)
                .to_xdr_base64(Limits::none())
                .unwrap()
        );
        answer
    }

    /// Mounts a ready primary endpoint serving the source at `sequence`, and
    /// an oracle serving the same account.
    #[cfg(feature = "mainnet-write")]
    async fn serve_chain(
        f: &crate::mainnet::fixtures::ResolverFixture,
        primary: &wiremock::MockServer,
        oracle: &wiremock::MockServer,
        sequence: i64,
        health: &str,
    ) {
        use stellar_agent_test_support::{EchoIdResponder, signed_envelope::get_network_result};
        use wiremock::Mock;
        use wiremock::matchers::{body_partial_json, method};
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000;
        primary.reset().await;
        oracle.reset().await;
        let answers = [
            (
                "getHealth",
                json!({"status": health, "latestLedger": 100, "oldestLedger": 1,
                    "ledgerRetentionWindow": 99}),
            ),
            (
                "getLedgers",
                json!({"latestLedger": 100, "latestLedgerCloseTime": now.to_string(),
                    "oldestLedger": 1, "oldestLedgerCloseTime": 1, "cursor": "100",
                    "ledgers": []}),
            ),
            (
                "getNetwork",
                get_network_result(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE),
            ),
            ("getLedgerEntries", source_at(f, sequence)),
        ];
        for (rpc, answer) in answers {
            for server in [primary, oracle] {
                Mock::given(method("POST"))
                    .and(body_partial_json(json!({ "method": rpc })))
                    .respond_with(EchoIdResponder::new(answer.clone()))
                    .mount(server)
                    .await;
            }
        }
    }

    /// The JSON-RPC methods `server` received, in order.
    #[cfg(feature = "mainnet-write")]
    async fn methods(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// A rebuild after consent reads readiness, then the source account, then
    /// the oracle, and binds the envelope and the oracle proof to the account
    /// read then. A sequence that moves during consent gives a new envelope,
    /// hash and proof. A readiness refusal reads nothing further, and a fee
    /// above the bound or an exhausted sequence asks the oracle nothing. An
    /// exhausted sequence refuses before the deadline clock is read.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn rebuild_reads_after_consent_and_rebinds_oracle() {
        use crate::cross_check::{
            AccountObservation, CrossCheckOutcome, DestinationObservation, MemoObservation,
            PayWitnessInputs,
        };
        use crate::mainnet::canonical::{CanonicalCheck, match_envelope};
        use crate::mainnet::fixtures::ResolverFixture;
        let f = ResolverFixture::configured(
            |profile| {
                use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
                let providers = profile.providers.get_or_insert_with(Default::default);
                providers.primary =
                    Some(PrimaryProviderRecord::new("primary", "rpc.example.invalid"));
                providers.oracle = Some(ProviderRecord::new(
                    "oracle",
                    "oracle.example.invalid",
                    true,
                ));
                profile.oracle_provider_url =
                    Some("https://oracle.example.invalid".parse().unwrap());
                profile.cross_check_threshold_stroops = 0;
            },
            str::to_owned,
        );
        let primary = wiremock::MockServer::start().await;
        let oracle = wiremock::MockServer::start().await;
        let context = f.context_with_routes(&[
            ("rpc.example.invalid", &primary.uri()),
            ("oracle.example.invalid", &oracle.uri()),
        ]);
        let network = context.network_context();
        let client = context.primary_client().unwrap();
        let thresholds = stellar_agent_core::cross_check::ThresholdSet::from_profile(&f.profile);
        let intent = classic_intent(
            IntentBaseFacts {
                chain_id: "stellar:mainnet",
                source: f.source.source(),
                policy_digest: f.policy.digest(),
                signed_fee_cap: Some(500),
                profile_fee_cap: None,
                fee_choice: ClassicFeeChoice::ProfileDefault,
                memo: MemoFact::None,
            },
            IntentPayload::Pay {
                destination: f.source.destination().to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 10,
            },
        )
        .unwrap();
        let prepared = AccountObservation {
            account_id: f.source.source().to_owned(),
            sequence: 1,
            native_balance: 0,
            subentry_count: 0,
            flags: None,
        };
        let rebuild = |fee_choice| {
            rebuild_canonical(CanonicalRebuildRequest {
                profile: &f.profile,
                network: &network,
                client: &client,
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(10),
                intent: &intent,
                fee_choice,
                default_fee_per_op_stroops: 100,
                fee_cap_stroops: 500,
                witness_inputs: PayWitnessInputs {
                    source: prepared.clone(),
                    destination: DestinationObservation::from_view(f.source.destination(), None),
                    memo: MemoObservation::Read(false),
                    trustline: None,
                }
                .into(),
                thresholds: &thresholds,
                tool: "stellar_pay",
            })
        };
        let subject = |rebuilt: &CanonicalRebuild| match &rebuilt.cross_check {
            CrossCheckOutcome::Passed(witness) => witness.subject().unwrap(),
            other => panic!("a bound witness, got {other:?}"),
        };
        let tx_hash = |envelope: &str| {
            let decoded = TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap();
            stellar_agent_core::hex::decode_hex32(
                &crate::submit::compute_local_tx_hash_hex(&decoded, network.network_passphrase())
                    .unwrap(),
            )
            .unwrap()
        };
        let now_ms = crate::mainnet::clock::now_ms().unwrap();
        let check = CanonicalCheck {
            intent: &intent,
            fee_cap_stroops: 500,
            now_ms,
            claim_entry: None,
        };

        serve_chain(&f, &primary, &oracle, 1, "healthy").await;
        let first = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap();
        assert_eq!(
            methods(&primary).await,
            ["getHealth", "getLedgers", "getLedgerEntries"]
        );
        assert!(
            methods(&oracle)
                .await
                .contains(&"getLedgerEntries".to_owned())
        );
        let matched = match_envelope(&first.unsigned_envelope_b64, &check).unwrap();
        assert_eq!(
            (matched.sequence, matched.fee_stroops, matched.max_time_s),
            (2, 100, now_ms / 1000 + 120)
        );
        assert_eq!(subject(&first), tx_hash(&first.unsigned_envelope_b64));

        serve_chain(&f, &primary, &oracle, 5, "healthy").await;
        let second = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap();
        assert_eq!(second.account.sequence_number, 5);
        assert_eq!(
            match_envelope(&second.unsigned_envelope_b64, &check)
                .unwrap()
                .sequence,
            6
        );
        assert_ne!(second.unsigned_envelope_b64, first.unsigned_envelope_b64);
        assert_eq!(subject(&second), tx_hash(&second.unsigned_envelope_b64));
        assert_ne!(subject(&second), subject(&first));

        serve_chain(&f, &primary, &oracle, 5, "unhealthy").await;
        let refused = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap_err();
        assert_eq!(refused.code(), "network.endpoint_not_ready");
        assert_eq!(methods(&primary).await, ["getHealth"]);
        assert!(methods(&oracle).await.is_empty());

        serve_chain(&f, &primary, &oracle, 5, "healthy").await;
        let above = rebuild(ClassicFeeChoice::Explicit(501)).await.unwrap_err();
        assert_eq!(above.code(), "fees.percentile_exceeds_cap");
        assert!(rebuild(ClassicFeeChoice::Explicit(500)).await.is_ok());
        for selected in [240_u32, 500, 501] {
            use stellar_agent_test_support::EchoIdResponder;
            use wiremock::{Mock, matchers::body_partial_json};
            serve_chain(&f, &primary, &oracle, 5, "healthy").await;
            let mut distribution = json!({"transactionCount": "1", "ledgerCount": 1});
            for key in [
                "min", "max", "mode", "p10", "p20", "p30", "p40", "p50", "p60", "p70", "p80",
                "p90", "p95", "p99",
            ] {
                distribution[key] = json!(selected.to_string());
            }
            Mock::given(body_partial_json(json!({"method": "getFeeStats"})))
                .respond_with(EchoIdResponder::new(json!({
                    "inclusionFee": distribution,
                    "sorobanInclusionFee": distribution,
                    "latestLedger": 100,
                })))
                .mount(&primary)
                .await;
            let result = rebuild(ClassicFeeChoice::Auto(crate::fees::FeePercentile::P95)).await;
            assert_eq!(
                methods(&primary).await,
                ["getHealth", "getLedgers", "getLedgerEntries", "getFeeStats"],
                "Auto reads fresh fees after readiness and the account"
            );
            if selected <= 500 {
                let rebuilt = result.unwrap();
                assert_eq!(
                    match_envelope(&rebuilt.unsigned_envelope_b64, &check)
                        .unwrap()
                        .fee_stroops,
                    selected,
                    "the envelope binds the fresh percentile"
                );
                assert_eq!(subject(&rebuilt), tx_hash(&rebuilt.unsigned_envelope_b64));
            } else {
                assert_eq!(result.unwrap_err().code(), "fees.percentile_exceeds_cap");
                assert!(methods(&oracle).await.is_empty());
            }
        }
        serve_chain(&f, &primary, &oracle, i64::MAX, "healthy").await;
        let exhausted = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap_err();
        assert_eq!(exhausted.code(), "protocol.xdr_codec_failed");
        assert!(methods(&oracle).await.is_empty());

        let clock = crate::mainnet::clock::set_clock_error_for_test();
        serve_chain(&f, &primary, &oracle, 5, "healthy").await;
        let unread = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap_err();
        assert_eq!(unread.code(), "wallet.clock_error");
        serve_chain(&f, &primary, &oracle, i64::MAX, "healthy").await;
        let exhausted = rebuild(ClassicFeeChoice::ProfileDefault).await.unwrap_err();
        assert_eq!(exhausted.code(), "protocol.xdr_codec_failed");
        drop(clock);
    }

    #[test]
    fn attempt_send_by_keeps_the_send_margin() {
        assert_eq!(attempt_send_by_ms(1_000), 970_000);
        assert_eq!(attempt_send_by_ms(0), u64::MAX);
    }

    /// The operation-store fixture with a keyed audit writer, an envelope
    /// record of `order-1` and an open policy authorization linked to its
    /// first attempt. It uses no `mainnet-write` fixture, so the adapter
    /// batch tests also run without that feature.
    pub(crate) struct StoreLinked {
        pub(crate) fx: crate::policy_state::operations::tests::Fx,
        pub(crate) writer: AuditWriterHandle,
        pub(crate) handle: OperationHandle,
        pub(crate) unsigned: String,
        _anchors: std::sync::Arc<stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore>,
    }

    impl StoreLinked {
        pub(crate) fn new() -> Self {
            use stellar_agent_core::audit_log::AuditWriter;
            use stellar_agent_core::audit_log::tip_anchor::{
                InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
            };
            use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
            use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;

            let mut fx = crate::policy_state::operations::tests::Fx::new();
            let anchors = std::sync::Arc::new(InMemoryTipAnchorStore::new());
            let writer = AuditWriter::open(
                fx.profile.audit_log_path.clone(),
                Some(KeyedAuditAccess::new(
                    zeroize::Zeroizing::new([0x5c; 32]),
                    std::sync::Arc::clone(&anchors) as std::sync::Arc<dyn TipAnchorStore>,
                )),
            )
            .unwrap();
            let unsigned = SignedTestEnvelope::builder([3; 32])
                .network_passphrase(MAINNET_PASSPHRASE)
                .time_bounds(0, crate::mainnet::clock::now_ms().unwrap() / 1000 + 120)
                .sequence(101)
                .unsigned()
                .build()
                .envelope_xdr()
                .to_owned();
            let opened = fx
                .recorder()
                .open(&OpenRequest {
                    business_id: BusinessId::parse("order-1").unwrap(),
                    tool: crate::policy_state::OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Envelope {
                        unsigned_envelope_sha256: unsigned_envelope_sha256(&unsigned),
                        intent_digest: [7; 32],
                        max_time: envelope_max_time(&unsigned).unwrap(),
                    },
                    envelope_xdr: Some(unsigned.clone()),
                    prepared_decision: None,
                    rule_ttl_ms: None,
                })
                .unwrap();
            let OpenOutcome::New(handle) = opened else {
                panic!("a new business id opens a record: {opened:?}")
            };
            let mut linked = fx.mint_request(
                crate::policy_state::ledger::DomainBinding::Transaction {
                    unsigned_envelope_sha256: unsigned_envelope_sha256(&unsigned),
                    tx_hash: [0x81; 32],
                    source: SOURCE.to_owned(),
                    sequence: 101,
                },
                fx.policy(),
                vec![],
            );
            linked.operation = Some(next_attempt_link(&handle));
            fx.store.mint_authorization(&fx.profile, &linked).unwrap();
            Self {
                fx,
                writer: std::sync::Arc::new(std::sync::Mutex::new(writer)),
                handle,
                unsigned,
                _anchors: anchors,
            }
        }

        /// Begins the record's next attempt, appending its edges to
        /// `committed`.
        pub(crate) fn begin(
            &self,
            committed: &mut CommittedBatch,
        ) -> Result<OperationAttempt, WalletError> {
            begin_classic_attempt_committed(
                &self.fx.store,
                &self.fx.profile,
                &self.writer,
                "request",
                &self.handle,
                &self.unsigned,
                committed,
            )
        }
    }

    /// The operation, state and attempt of each edge `committed` holds.
    pub(crate) fn batch_edges(
        committed: &CommittedBatch,
    ) -> Vec<(OperationId, OperationState, Option<u32>)> {
        committed
            .clone()
            .into_iter()
            .map(|edge| (edge.operation_id(), edge.state(), edge.attempt_index()))
            .collect()
    }

    /// Without `mainnet-write` the committed attempt entry appends the
    /// adoption and `Sending` edges it commits; a refused second entry
    /// adds none and keeps the batch's earlier edges.
    #[test]
    #[serial_test::serial]
    fn attempt_wrapper_batches_without_the_mainnet_feature() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let linked = StoreLinked::new();
        let mut committed = CommittedBatch::default();
        let attempt = linked.begin(&mut committed).unwrap();
        let started = vec![
            (linked.handle.id(), OperationState::Authorized, None),
            (
                linked.handle.id(),
                OperationState::Sending,
                Some(attempt.attempt_index),
            ),
        ];
        assert_eq!(batch_edges(&committed), started);
        let refused = linked.begin(&mut committed).unwrap_err();
        assert_eq!(refused.code(), "operation.attempt_open");
        assert_eq!(batch_edges(&committed), started);
    }

    #[cfg(feature = "mainnet-write")]
    mod committed {
        use serial_test::serial;

        use super::*;
        use crate::mainnet::fixtures::{self, LedgerFixture};

        /// The committed attempt entry appends the adoption and `Sending`
        /// edges it commits; a refused second entry commits nothing and
        /// keeps the batch's earlier edges.
        #[test]
        #[serial]
        fn attempt_wrappers_preserve_commits_on_success_and_refusal() {
            let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
            let _storage_home =
                stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
            let fx = LedgerFixture::new("attempt-committed", 1_800_000_000_000);
            let unsigned = fixtures::unsigned_envelope();
            let binding = fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex());
            let (handle, _authorization) = fx.linked_record(binding, &[], "order-1");
            let mut committed = CommittedBatch::default();
            let begin = |committed: &mut CommittedBatch| {
                begin_classic_attempt_committed(
                    &fx.window,
                    &fx.profile,
                    &fx.writer,
                    "request",
                    &handle,
                    unsigned.envelope_xdr(),
                    committed,
                )
            };
            let attempt = begin(&mut committed).unwrap();
            let edges = |committed: &CommittedBatch| -> Vec<_> {
                committed
                    .clone()
                    .into_iter()
                    .map(|edge| (edge.operation_id(), edge.state(), edge.attempt_index()))
                    .collect()
            };
            let started = vec![
                (handle.id(), OperationState::Authorized, None),
                (
                    handle.id(),
                    OperationState::Sending,
                    Some(attempt.attempt_index),
                ),
            ];
            assert_eq!(edges(&committed), started);
            let refused = begin(&mut committed).unwrap_err();
            assert_eq!(refused.code(), "operation.attempt_open");
            assert_eq!(edges(&committed), started);
        }
    }
}
