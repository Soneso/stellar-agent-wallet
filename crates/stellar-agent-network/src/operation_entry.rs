//! The business-id entry both binaries share on their value paths.
//!
//! A mainnet value call names itself with a business id. The helpers here build
//! the canonical intent of a classic request and the record slot that binds it.
//! They look the record up and open it, and render the answer a retry of a
//! retained operation receives. On every other chain a business id is validated
//! and echoed, and no record exists.

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::{
    ClassicIntent, IntentAsset, IntentBase, IntentPayload, MemoFact,
};
use stellar_agent_core::error::{InternalError, SubmissionError, ValidationError, WalletError};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::profile::schema::Profile;
use stellar_xdr::{Limits, Memo, ReadXdr as _, TransactionEnvelope};

use crate::fees::ClassicFeeChoice;
use crate::mainnet::MainnetAuthorizationError;
use crate::policy_state::{
    AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId, CommitBinding, CommitTarget,
    IntentSlot, LookupOutcome, OpenOutcome, OpenRequest, OperationHandle, OperationKind,
    OperationLink, OperationRecorder, OperationState, OperationStatus, OperationView,
    PersistedWindowStore, SlotKind, WindowStoreError,
};
use crate::submission_record::{AuditWriterHandle, OperationAttempt};

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
/// `validation.mainnet_fee_cap_required` from [`fee_bound`], and
/// `internal.unexpected_state` for facts the argument checks before this
/// call admit but the intent refuses.
pub fn classic_intent(
    base: IntentBaseFacts<'_>,
    payload: IntentPayload,
) -> Result<ClassicIntent, WalletError> {
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
fn muxed_strkey(account: &stellar_xdr::MuxedAccount) -> String {
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
fn account_strkey(account: &stellar_xdr::AccountId) -> String {
    let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = &account.0;
    stellar_strkey::ed25519::PublicKey(key.0)
        .to_string()
        .as_str()
        .to_owned()
}

/// An asset code without the zero bytes that pad it.
fn asset_code(bytes: &[u8]) -> String {
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
    let send_by_ms = attempt_send_by_ms(envelope_max_time(unsigned_envelope_b64)?);
    let mut guard = writer.lock().map_err(|_| {
        WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: "the audit writer mutex is poisoned, so the attempt cannot be recorded"
                .to_owned(),
        })
    })?;
    let started = OperationRecorder::new(store, profile, &mut *guard, request_id)
        .begin_attempt(
            handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: unsigned_envelope_b64.to_owned(),
                    unsigned_envelope_sha256: unsigned_envelope_sha256(unsigned_envelope_b64),
                }),
                authorization: AttemptAuthorization::Linked,
                send_by_ms,
            },
        )
        .map_err(operation_refusal)?;
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
/// ledger, error_code}, next}`.
#[must_use]
pub fn replay_json(view: &OperationView) -> Value {
    let result = view.result.as_ref();
    json!({
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
    })
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

    #[test]
    fn attempt_send_by_keeps_the_send_margin() {
        assert_eq!(attempt_send_by_ms(1_000), 970_000);
        assert_eq!(attempt_send_by_ms(0), u64::MAX);
    }
}
