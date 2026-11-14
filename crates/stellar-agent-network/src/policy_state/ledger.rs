//! The mainnet authorization ledger inside the window-state store.
//!
//! A mainnet authorization is recorded in the same HMAC-protected,
//! generation-committed file as the window's spend, so its holds and the
//! window's records are admitted under one lock against one total.
//!
//! # Records and holds
//!
//! Each authorization has one record: its identity, profile, chain, domain,
//! consuming verb, content digest, the typed facts of its domain, its state,
//! its mint, expiry, and settlement times, the policy and approval it was
//! minted under, its aggregate bindings digest, its holds digest, and, when
//! it holds entries, its reservation, whose identity is the authorization's.
//! An open authorization of a holding domain owns one hold per window entry,
//! keyed by `(authorization id, ordinal)` and kept outside the window's
//! bucket records. A hold counts against the window from the mint until the
//! authorization is consumed or expires. Invalidation releases only unclaimed holds.
//! An expired claim retains its spend as confirmed records dated at the claim.
//!
//! Every hold belongs to exactly one open or claimed authorization; a hold of a settled
//! or unknown authorization, a duplicate identity or ordinal, a reservation
//! other than the authorization's own, a hold kind other than the domain's,
//! or authorization history in a snapshot below version 4 refuses the read.
//!
//! # Freshness
//!
//! Every transition reads the mainnet clock, [`crate::mainnet::clock::now_ms`],
//! itself; no caller supplies the time a transition is checked against. Under
//! the lock, a transition first marks every open authorization whose expiry
//! has passed as expired and sets its settlement time. Claimed holds become
//! confirmed spend; unclaimed holds are released.
//! The spend admission of the window's own writers does the same before it
//! counts. One transaction is one lock and one generation commit.
//!
//! # The sealing boundary
//!
//! The transitions are public and yield ledger results: a [`MintedRecord`]
//! with an optional [`WindowReservation`] proof, and [`ConsumeReceipt`]s.
//! None of them yields signing authority. Only this crate's authorization
//! header can assemble a mainnet authorization, and only from the proofs its
//! producers return.
//!
//! # Settlement isolation
//!
//! Reservations, confirmation, release, reconciliation, and hydration read
//! the window's submission records only. A consumed transaction
//! authorization's holds become ordinary pending records of its submission
//! and settle from there; holds never reach the engine's in-memory view.

use serde::{Deserialize, Serialize};
use stellar_agent_core::mainnet::decision::AuthorityScope;
use stellar_agent_core::policy::pin::{self, PinError, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::criteria::state_store::{CLOCK_SKEW_TOLERANCE_MS, WindowEntry};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::Profile;

use super::WindowStoreError;
use super::operations::{
    self, CommitId, Disposition, OperationId, OperationLink, ReleaseClass, ReleaseRow,
};
use super::store::{
    PersistedWindowStore, RecordStatus, WIRE_VERSION_LEDGER, WireBucket, WireFile, WireRecord,
    admit, check_total_shape, file_holds_id, find_or_insert_bucket, generation_entry_ref,
    i128_decimal_str, is_total_entry, is_total_hold, now_ms, prune_stale,
};
use crate::mainnet::digest::{BindingFacts, bindings_digest};
use crate::mainnet::digest::{content_digest, entries_digest};
use crate::mainnet::types::{
    AuditFacts, AuthorizationDomain, AuthorizationId, HoldOwner, MainnetConsumer, MessageDomain,
    hex32,
};
use crate::mainnet::{MainnetPrecondition, refusal::require};

/// The most authorizations one profile holds open at once.
pub const MAX_OPEN_AUTHORIZATIONS: usize = 16;

/// The longest invalidation reason a record keeps, in characters.
const INVALIDATION_REASON_MAX: usize = 128;

fn refused(precondition: MainnetPrecondition) -> WindowStoreError {
    WindowStoreError::AuthorizationRefused { precondition }
}

fn check(holds: bool, precondition: MainnetPrecondition) -> Result<(), WindowStoreError> {
    require(holds, precondition).map_err(|_| refused(precondition))
}

/// Serde adapter for an optional 32-byte value stored as lowercase hex,
/// shared by the ledger and the operation records.
pub(super) mod opt_hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    #[allow(
        clippy::ref_option,
        reason = "serde's field adapter receives a reference to the field"
    )]
    pub(in crate::policy_state) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => super::hex32::serialize(bytes, s),
            None => s.serialize_none(),
        }
    }

    pub(in crate::policy_state) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        text.map(|text| {
            if text.len() != 64 || text.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(serde::de::Error::custom(
                    "expected 64 lowercase hex characters",
                ));
            }
            stellar_agent_core::hex::decode_hex32(&text)
                .map_err(|_| serde::de::Error::custom("expected 64 lowercase hex characters"))
        })
        .transpose()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain facts and consumption bindings
// ─────────────────────────────────────────────────────────────────────────────

/// The facts of one domain an authorization is minted over, stored with its
/// record and compared at consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DomainBinding {
    /// A classic transaction.
    Transaction {
        /// [`crate::mainnet::digest::approval_subject_classic`] of the unsigned
        /// envelope.
        #[serde(with = "hex32")]
        unsigned_envelope_sha256: [u8; 32],
        /// The network transaction hash.
        #[serde(with = "hex32")]
        tx_hash: [u8; 32],
        /// The account whose sequence the transaction consumes.
        source: String,
        /// The sequence the transaction consumes.
        sequence: i64,
    },
    /// The inner transaction of a fee bump, before the outer exists.
    FeeBumpInner {
        /// The inner transaction hash.
        #[serde(with = "hex32")]
        inner_tx_hash: [u8; 32],
        /// The inner transaction's source.
        inner_source: String,
        /// The inner transaction's sequence.
        inner_sequence: i64,
        /// The fee source.
        fee_source: String,
        /// The bound fee, in stroops.
        max_fee: i64,
    },
    /// The outer fee-bump transaction.
    FeeBumpOuter {
        /// The inner transaction hash.
        #[serde(with = "hex32")]
        inner_tx_hash: [u8; 32],
        /// The outer transaction hash.
        #[serde(with = "hex32")]
        outer_tx_hash: [u8; 32],
        /// The inner transaction's source.
        inner_source: String,
        /// The inner transaction's sequence.
        inner_sequence: i64,
        /// The fee source.
        fee_source: String,
        /// The bound fee, in stroops.
        max_fee: i64,
    },
    /// The submission of a signed fee bump.
    FeeBumpSubmit {
        /// The inner transaction hash.
        #[serde(with = "hex32")]
        inner_tx_hash: [u8; 32],
        /// The outer transaction hash.
        #[serde(with = "hex32")]
        outer_tx_hash: [u8; 32],
        /// The inner transaction's source.
        inner_source: String,
        /// The inner transaction's sequence.
        inner_sequence: i64,
        /// The fee source.
        fee_source: String,
        /// The bound fee, in stroops.
        max_fee: i64,
        /// The submission envelope identity of the signed outer envelope.
        #[serde(with = "hex32")]
        final_envelope_sha256: [u8; 32],
    },
    /// The release of a signed x402 payment payload.
    X402Submit {
        /// The submission envelope identity of the final envelope.
        #[serde(with = "hex32")]
        final_envelope_sha256: [u8; 32],
        /// The root invocation digest of the payment.
        #[serde(with = "hex32")]
        root_invocation_digest: [u8; 32],
    },
    /// A Soroban authorization for an x402 payment intent.
    Soroban {
        /// The Soroban intent digest.
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
    },
    /// A message signing.
    Message {
        /// The domains and server key the message binds.
        domain: MessageDomain,
        /// The message content digest.
        #[serde(with = "hex32")]
        content_digest: [u8; 32],
        /// The ephemeral key that signs.
        #[serde(with = "hex32")]
        ephemeral_public_key: [u8; 32],
    },
}

impl DomainBinding {
    /// The domain these facts belong to.
    #[must_use]
    pub fn domain(&self) -> AuthorizationDomain {
        match self {
            Self::Transaction { .. } => AuthorizationDomain::Transaction,
            Self::FeeBumpInner { .. } => AuthorizationDomain::FeeBumpInner,
            Self::FeeBumpOuter { .. } => AuthorizationDomain::FeeBumpOuter,
            Self::FeeBumpSubmit { .. } => AuthorizationDomain::FeeBumpSubmit,
            Self::X402Submit { .. } => AuthorizationDomain::X402Submit,
            Self::Soroban { .. } => AuthorizationDomain::Soroban,
            Self::Message { .. } => AuthorizationDomain::Message,
        }
    }

    /// The subject the domain's content digest names.
    #[must_use]
    pub fn subject(&self) -> [u8; 32] {
        match self {
            Self::Transaction { tx_hash, .. } => *tx_hash,
            Self::FeeBumpInner { inner_tx_hash, .. } => *inner_tx_hash,
            Self::FeeBumpOuter { outer_tx_hash, .. }
            | Self::FeeBumpSubmit { outer_tx_hash, .. } => *outer_tx_hash,
            Self::X402Submit {
                final_envelope_sha256,
                ..
            } => *final_envelope_sha256,
            Self::Soroban { intent_digest } => *intent_digest,
            Self::Message { content_digest, .. } => *content_digest,
        }
    }

    /// The content digest of these facts.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        content_digest(self.domain(), &self.subject())
    }
}

/// Facts decoded from the final fee-bump envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeBumpFacts {
    /// The network hash of the inner transaction.
    #[serde(with = "hex32")]
    pub inner_tx_hash: [u8; 32],
    /// The outer fee source.
    pub fee_source: String,
    /// The exact outer fee, in stroops.
    pub max_fee: i64,
}

/// The submission a consumed transaction authorization's holds become, as
/// the recorder derives it from the final envelope and the endpoint's
/// observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionBinding {
    /// The network for hashing and validating the submitted envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_scope: Option<super::store::ChainScope>,
    /// Facts from a fee-bump envelope; absent for a transaction envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_bump: Option<FeeBumpFacts>,
    /// [`crate::mainnet::digest::envelope_hash_hex`] of the signed envelope,
    /// as bytes: the receipt and reservation identity.
    #[serde(with = "hex32")]
    pub envelope_hash: [u8; 32],
    /// The network transaction hash.
    #[serde(with = "hex32")]
    pub tx_hash: [u8; 32],
    /// The account whose sequence the transaction consumes; for a fee bump,
    /// the inner transaction's source.
    pub source: String,
    /// The sequence the transaction consumes; for a fee bump, the inner
    /// transaction's.
    pub sequence: i64,
    /// `TimeBounds.maxTime` in Unix seconds; `0` means no bound.
    pub max_time: u64,
    /// When the submission took its records, in Unix milliseconds.
    pub pending_since_ms: u64,
    /// The endpoint's latest ledger when the submission took its records.
    pub submission_ledger: u32,
    /// Independent provenance bound to this submission.
    ///
    /// Deserializing a binding never yields an anchor: input naming one is
    /// refused as an unknown field. The window file reads the anchor of a
    /// stored consumption back through its authenticated load.
    #[serde(default, skip_serializing_if = "Option::is_none", skip_deserializing)]
    pub submission_anchor: Option<Box<super::store::SubmissionAnchor>>,
}

/// The stored form of a [`SubmissionBinding`], read only inside the
/// authenticated window-file load, where its anchor is restored.
#[derive(Deserialize)]
#[serde(remote = "SubmissionBinding", deny_unknown_fields)]
struct StoredSubmissionBinding {
    #[serde(default)]
    chain_scope: Option<super::store::ChainScope>,
    #[serde(default)]
    fee_bump: Option<FeeBumpFacts>,
    #[serde(with = "hex32")]
    envelope_hash: [u8; 32],
    #[serde(with = "hex32")]
    tx_hash: [u8; 32],
    source: String,
    sequence: i64,
    max_time: u64,
    pending_since_ms: u64,
    submission_ledger: u32,
    #[serde(
        default,
        deserialize_with = "super::store::stored_anchor::boxed_option"
    )]
    submission_anchor: Option<Box<super::store::SubmissionAnchor>>,
}

/// The stored form of a [`ConsumptionBinding`], read only inside the
/// authenticated window-file load.
#[derive(Deserialize)]
#[serde(
    remote = "ConsumptionBinding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum StoredConsumptionBinding {
    Transaction(
        #[serde(deserialize_with = "StoredSubmissionBinding::deserialize")] SubmissionBinding,
    ),
    RetainedIntent {
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
    },
    PayloadRelease {
        #[serde(default)]
        intent_record: Option<AuthorizationId>,
        #[serde(with = "hex32")]
        final_envelope_sha256: [u8; 32],
        #[serde(default, with = "opt_hex32")]
        root_invocation_digest: Option<[u8; 32]>,
    },
    Message {
        domain: MessageDomain,
        #[serde(with = "hex32")]
        content_digest: [u8; 32],
        #[serde(with = "hex32")]
        ephemeral_public_key: [u8; 32],
    },
}

/// Reads a stored authorization's consumption, anchor included.
fn stored_consumption<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ConsumptionBinding>, D::Error> {
    #[derive(Deserialize)]
    struct Stored(
        #[serde(deserialize_with = "StoredConsumptionBinding::deserialize")] ConsumptionBinding,
    );
    Ok(Option::<Stored>::deserialize(d)?.map(|stored| stored.0))
}

/// How an authorization is consumed, by domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsumptionBinding {
    /// The holds become the pending records of this submission.
    Transaction(SubmissionBinding),
    /// The holds become retained authorized spend.
    RetainedIntent {
        /// The Soroban intent digest the authorization was minted over.
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
    },
    /// The signed payload is released with no second spend.
    PayloadRelease {
        /// The used parent intent of an x402 submission; absent for a fee
        /// bump.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent_record: Option<AuthorizationId>,
        /// The submission envelope identity of the released envelope.
        #[serde(with = "hex32")]
        final_envelope_sha256: [u8; 32],
        /// The root invocation digest of an x402 submission; absent for a fee
        /// bump.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
        root_invocation_digest: Option<[u8; 32]>,
    },
    /// A zero-debit message record settles.
    Message {
        /// The domains and server key.
        domain: MessageDomain,
        /// The message content digest.
        #[serde(with = "hex32")]
        content_digest: [u8; 32],
        /// The ephemeral key that signed.
        #[serde(with = "hex32")]
        ephemeral_public_key: [u8; 32],
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire records
// ─────────────────────────────────────────────────────────────────────────────

/// Where an authorization is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AuthorizationState {
    /// Minted and neither used, invalidated, nor expired.
    Open,
    /// Its signature is being or was produced; its holds stay until settlement.
    Claimed,
    /// Consumed once.
    Used,
    /// Its expiry passed before it was used.
    Expired,
    /// Abandoned by its holder before use.
    Invalidated,
}

impl AuthorizationState {
    pub(super) fn holds(self) -> bool {
        matches!(self, Self::Open | Self::Claimed)
    }
}

/// Which entries a hold carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HoldKind {
    /// An entry of the action's value.
    Value,
    /// An entry of the fee payer's fee.
    Fee,
}

impl HoldKind {
    fn of(domain: AuthorizationDomain) -> Option<Self> {
        match domain.hold_owner() {
            HoldOwner::ValueHolds => Some(Self::Value),
            HoldOwner::FeeHolds => Some(Self::Fee),
            HoldOwner::NoHolds => None,
        }
    }
}

/// One authorization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAuthorization {
    pub(super) id: AuthorizationId,
    pub(super) profile: String,
    pub(super) chain: Caip2,
    pub(super) domain: AuthorizationDomain,
    pub(super) consumer: MainnetConsumer,
    #[serde(with = "hex32")]
    pub(super) content_digest: [u8; 32],
    pub(super) binding: DomainBinding,
    pub(super) state: AuthorizationState,
    pub(super) minted_ms: u64,
    pub(super) expires_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) settled_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) claimed_ms: Option<u64>,
    pub(super) policy_sequence: i64,
    #[serde(with = "hex32")]
    pub(super) policy_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) approval_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) approval_expires_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) policy_authority: Option<WirePolicyAuthorityBinding>,
    #[serde(with = "hex32")]
    pub(super) bindings_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub(super) entries_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reservation: Option<AuthorizationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) parent: Option<AuthorizationId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "stored_consumption"
    )]
    pub(super) consumption: Option<ConsumptionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) invalidation: Option<String>,
    /// The operation attempt the authorization was minted for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) operation: Option<OperationLink>,
    /// How the authorization ended: used once, or ended unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) disposition: Option<Disposition>,
    /// The release row of the authorization's native reservation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_release: Option<ReleaseRow>,
    /// The native amounts the authorization reserves; absent for a record
    /// minted without them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_reservation: Option<NativeReservation>,
}

/// The native amounts one authorization reserves against the account
/// balance, counted once per authorization whatever its buckets and epochs.
///
/// Both amounts come from the authenticated action facts. The debit is the
/// action's native amount, zero for a non-native action. The fee is the
/// envelope's fee cap, zero for an x402 authorization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReservation {
    /// The native amount the action debits, in stroops.
    pub debit_stroops: i64,
    /// The fee the envelope may charge, in stroops.
    pub fee_stroops: i64,
}

impl NativeReservation {
    /// The reserved total in stroops: the debit plus the fee.
    #[must_use]
    pub fn total_stroops(self) -> i128 {
        i128::from(self.debit_stroops) + i128::from(self.fee_stroops)
    }

    fn well_formed(self) -> bool {
        self.debit_stroops >= 0 && self.fee_stroops >= 0
    }
}

impl WireAuthorization {
    /// The authority the record was minted under.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Invalid`] with the [`WireAuthorizationShape`]
    /// detail unless the record carries exactly an approval nonce with its
    /// expiry, or exactly a policy authority.
    pub(super) fn authority(&self) -> Result<MintAuthority, WindowStoreError> {
        match (
            &self.approval_nonce,
            self.approval_expires_ms,
            &self.policy_authority,
        ) {
            (Some(nonce), Some(expires_at_ms), None) => Ok(MintAuthority::Approval {
                nonce: nonce.clone(),
                expires_at_ms,
            }),
            (None, None, Some(policy)) => Ok(MintAuthority::Policy(policy.clone().into())),
            _ => Err(WindowStoreError::Invalid {
                detail: WireAuthorizationShape.to_string(),
            }),
        }
    }

    /// The end of the record's authority in Unix milliseconds: the
    /// approval's expiry or the policy authority's governing end. A record
    /// without a single authority has none and keeps nothing alive.
    pub(super) fn authority_end_ms(&self) -> u64 {
        self.authority()
            .map_or(0, |authority| authority.expires_at_ms())
    }
}

/// The wire fields of `authority`: the approval nonce and expiry, or the
/// policy authority, each in its own optional field.
fn wire_authority(
    authority: &MintAuthority,
) -> (
    Option<String>,
    Option<u64>,
    Option<WirePolicyAuthorityBinding>,
) {
    match authority {
        MintAuthority::Approval {
            nonce,
            expires_at_ms,
        } => (Some(nonce.clone()), Some(*expires_at_ms), None),
        MintAuthority::Policy(binding) => (None, None, Some(binding.clone().into())),
    }
}

/// The detail of a record whose authority fields do not hold exactly one
/// authority: an approval nonce with its expiry, or a policy authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WireAuthorizationShape;

impl std::fmt::Display for WireAuthorizationShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "an authorization carries neither exactly an approval nonce with its expiry \
             nor exactly a policy authority",
        )
    }
}

/// The persisted policy authority of a record.
///
/// Every field is required and an unknown field refuses the read; the digest
/// is 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WirePolicyAuthorityBinding {
    #[serde(with = "hex32")]
    pub(super) policy_digest: [u8; 32],
    pub(super) policy_sequence: i64,
    pub(super) rule_index: u32,
    pub(super) evaluated_at_ms: u64,
    pub(super) governing_until_ms: u64,
    pub(super) scope: WireAuthorityScope,
}

/// The persisted scope of a policy authority:
/// `{"kind":"classic"}` or
/// `{"kind":"x402_authenticated","home_domain":"...","tool":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WireAuthorityScope {
    /// A write whose authority binds to its own transaction. A struct
    /// variant, so an unknown field beside the tag refuses.
    Classic {},
    /// An authenticated x402 payment for one home domain by one tool.
    X402Authenticated { home_domain: String, tool: String },
}

impl From<PolicyAuthorityBinding> for WirePolicyAuthorityBinding {
    fn from(binding: PolicyAuthorityBinding) -> Self {
        Self {
            policy_digest: binding.policy_digest,
            policy_sequence: binding.policy_sequence,
            rule_index: binding.rule_index,
            evaluated_at_ms: binding.evaluated_at_ms,
            governing_until_ms: binding.governing_until_ms,
            scope: match binding.scope {
                AuthorityScope::Classic => WireAuthorityScope::Classic {},
                AuthorityScope::X402Authenticated { home_domain, tool } => {
                    WireAuthorityScope::X402Authenticated { home_domain, tool }
                }
            },
        }
    }
}

impl From<WirePolicyAuthorityBinding> for PolicyAuthorityBinding {
    fn from(wire: WirePolicyAuthorityBinding) -> Self {
        Self {
            policy_digest: wire.policy_digest,
            policy_sequence: wire.policy_sequence,
            rule_index: wire.rule_index,
            evaluated_at_ms: wire.evaluated_at_ms,
            governing_until_ms: wire.governing_until_ms,
            scope: match wire.scope {
                WireAuthorityScope::Classic {} => AuthorityScope::Classic,
                WireAuthorityScope::X402Authenticated { home_domain, tool } => {
                    AuthorityScope::X402Authenticated { home_domain, tool }
                }
            },
        }
    }
}

/// One hold an open authorization owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAuthorizationHold {
    pub(super) kind: HoldKind,
    pub(super) authorization_id: AuthorizationId,
    pub(super) ordinal: u32,
    pub(super) scope_specificity: u8,
    pub(super) bucket: String,
    pub(super) window_secs: u64,
    pub(super) ts_ms: u64,
    #[serde(with = "i128_decimal_str")]
    pub(super) amount: i128,
    /// The policy digest a total-budget hold counts against. Only a hold of
    /// a total bucket carries one.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub(super) epoch: Option<[u8; 32]>,
}

/// Validates the authorization history of one snapshot.
///
/// # Errors
///
/// [`WindowStoreError::Invalid`] naming the first broken invariant.
pub(super) fn validate(wire: &WireFile) -> Result<(), WindowStoreError> {
    let invalid = |detail: String| WindowStoreError::Invalid { detail };
    if wire.version < WIRE_VERSION_LEDGER
        && (!wire.authorizations.is_empty() || !wire.holds.is_empty())
    {
        return Err(invalid(format!(
            "a version {} snapshot carries authorization history",
            wire.version
        )));
    }
    let mut ids = std::collections::HashSet::new();
    for auth in &wire.authorizations {
        if !ids.insert(auth.id) {
            return Err(invalid("an authorization identity repeats".to_owned()));
        }
        if auth
            .native_reservation
            .is_some_and(|amounts| !amounts.well_formed())
        {
            return Err(invalid(
                "an authorization's native amounts are negative".to_owned(),
            ));
        }
        if auth.binding.domain() != auth.domain
            || auth.content_digest != auth.binding.content_digest()
        {
            return Err(invalid(
                "an authorization's content does not match its domain facts".to_owned(),
            ));
        }
        if auth.state.holds() == auth.settled_ms.is_some() {
            return Err(invalid(
                "an authorization's settlement time disagrees with its state".to_owned(),
            ));
        }
        if (auth.state == AuthorizationState::Claimed && auth.claimed_ms.is_none())
            || (matches!(
                auth.state,
                AuthorizationState::Open | AuthorizationState::Invalidated
            ) && auth.claimed_ms.is_some())
            || auth.claimed_ms.is_some_and(|claimed| {
                wire.version < super::store::WIRE_VERSION_CLAIM
                    || claimed < auth.minted_ms
                    || claimed >= auth.expires_ms
            })
        {
            return Err(invalid(
                "an authorization's claim time disagrees with its state or lifetime".to_owned(),
            ));
        }
        if (auth.state == AuthorizationState::Used) != auth.consumption.is_some() {
            return Err(invalid(
                "an authorization's consumption disagrees with its state".to_owned(),
            ));
        }
        if let Some(reservation) = auth.reservation
            && (reservation != auth.id || HoldKind::of(auth.domain).is_none())
        {
            return Err(invalid(
                "an authorization holds a reservation other than its own".to_owned(),
            ));
        }
        if auth.parent.is_some() != requires_parent(auth.domain, auth.consumer) {
            return Err(invalid(
                "an authorization's parent disagrees with its domain".to_owned(),
            ));
        }
        if let MintAuthority::Policy(policy) = auth.authority()?
            && (policy.policy_digest != auth.policy_digest
                || policy.policy_sequence != auth.policy_sequence)
        {
            return Err(invalid(
                "an authorization's policy authority names another policy".to_owned(),
            ));
        }
    }
    let mut keys = std::collections::HashSet::new();
    let mut holding = std::collections::HashSet::new();
    for hold in &wire.holds {
        if !keys.insert((hold.authorization_id, hold.ordinal)) {
            return Err(invalid("a hold identity repeats".to_owned()));
        }
        let Some(owner) = wire
            .authorizations
            .iter()
            .find(|auth| auth.id == hold.authorization_id)
        else {
            return Err(invalid("a hold names no authorization".to_owned()));
        };
        if !owner.state.holds() {
            return Err(invalid("a hold belongs to settled history".to_owned()));
        }
        if HoldKind::of(owner.domain) != Some(hold.kind) || owner.reservation != Some(owner.id) {
            return Err(invalid(
                "a hold's kind or reservation disagrees with its authorization".to_owned(),
            ));
        }
        holding.insert(hold.authorization_id);
    }
    for auth in &wire.authorizations {
        if auth.state.holds() && auth.reservation.is_some() != holding.contains(&auth.id) {
            return Err(invalid(
                "an open authorization's reservation disagrees with its holds".to_owned(),
            ));
        }
    }
    Ok(())
}

/// What one expiry sweep changed.
#[derive(Debug, Default)]
pub(super) struct SweepOutcome {
    /// Whether any authorization expired.
    pub(super) swept: bool,
    /// The waiting operations the sweep adopted into `Authorized`.
    pub(super) adopted: Vec<OperationId>,
}

/// Expires open and claimed authorizations for a writer that keeps no
/// operation audit, under a fresh commit identifier. An authorization that
/// links a retained operation which has not ended stays untouched, holds
/// included, until an operation step sweeps it; see [`sweep_expired_with`].
pub(super) fn sweep_expired(wire: &mut WireFile, now_ms: u64) -> bool {
    sweep(
        wire,
        now_ms,
        CommitId::random(),
        SweepScope::OutsideLiveOperations,
    )
    .swept
}

/// Expires open and claimed authorizations. A claim's holds become confirmed
/// spend dated at the claim, so only window aging releases that spend; a
/// claimed authorization keeps that conversion and gets no disposition.
///
/// An authorization expiring from `Open` first adopts the waiting operation
/// it links into `Authorized`, then becomes expired with disposition
/// `unused` and an `Always` release row of class `proved_unspent` under
/// `commit`, all in the caller's commit. An authorization a committed
/// exposure names gets neither: its reservation stays counted, and its holds
/// become confirmed spend as a claim's do.
pub(super) fn sweep_expired_with(
    wire: &mut WireFile,
    now_ms: u64,
    commit: CommitId,
) -> SweepOutcome {
    sweep(wire, now_ms, commit, SweepScope::All)
}

/// Which expired authorizations one sweep settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepScope {
    /// Every expired authorization; the operation step that runs it audits
    /// each adoption.
    All,
    /// Every expired authorization except those linking a retained
    /// operation that has not ended.
    OutsideLiveOperations,
}

fn sweep(wire: &mut WireFile, now_ms: u64, commit: CommitId, scope: SweepScope) -> SweepOutcome {
    let live = match scope {
        SweepScope::All => Vec::new(),
        SweepScope::OutsideLiveOperations => operations::live_operations(wire),
    };
    let exposed = operations::exposed_authorizations(wire);
    let mut swept = Vec::new();
    let mut adopted = Vec::new();
    for auth in &mut wire.authorizations {
        if !auth.state.holds() || auth.expires_ms > now_ms {
            continue;
        }
        if auth
            .operation
            .is_some_and(|link| live.contains(&link.operation_id))
        {
            continue;
        }
        let is_exposed = exposed.contains(&auth.id);
        if auth.claimed_ms.is_none() && !is_exposed {
            if operations::adopt_on_expiry(&mut wire.operations, auth, now_ms, commit)
                && let Some(link) = auth.operation
            {
                adopted.push(link.operation_id);
            }
            auth.disposition = Some(Disposition::Unused);
            auth.native_release = Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit));
        } else {
            let spent_ms = auth.claimed_ms.unwrap_or(auth.minted_ms);
            for hold in wire
                .holds
                .iter()
                .filter(|hold| hold.authorization_id == auth.id)
            {
                retain_hold(
                    &mut wire.entries,
                    hold,
                    WireRecord {
                        chain_scope: Some(super::store::ChainScope::for_chain(auth.chain)),
                        ts_ms: spent_ms,
                        amount: hold.amount,
                        epoch: hold.epoch,
                        authorization_id: hold.epoch.map(|_| auth.id),
                        ..WireRecord::confirmed_defaults()
                    },
                );
            }
        }
        auth.state = AuthorizationState::Expired;
        auth.settled_ms = Some(now_ms);
        swept.push(auth.id);
    }
    wire.holds
        .retain(|hold| !swept.contains(&hold.authorization_id));
    SweepOutcome {
        swept: !swept.is_empty(),
        adopted,
    }
}

/// Records `record` as retained spend in the window bucket `hold` reserved.
fn retain_hold(entries: &mut Vec<WireBucket>, hold: &WireAuthorizationHold, record: WireRecord) {
    let key = stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
        "",
        hold.scope_specificity,
        &hold.bucket,
        hold.window_secs,
    );
    find_or_insert_bucket(entries, &key).records.push(record);
}

/// Whether settled history ages out: settled before `cutoff`, with an
/// authority that ends at or before `now_ms`. Open and claimed records never
/// do.
pub(super) fn prunable(auth: &WireAuthorization, cutoff: u64, now_ms: u64) -> bool {
    !(auth.state.holds()
        || auth.authority_end_ms() > now_ms
        || auth.settled_ms.is_some_and(|t| t >= cutoff))
}

/// Drops settled authorization history older than `cutoff` whose authority
/// ends at or before `now_ms`: the approval's expiry, or a policy authority's
/// governing end. Open and claimed records stay whatever their age, and so
/// does an authorization an operation links until it has a release row. The
/// removal raises the window's admissible floors.
pub(super) fn prune_history(wire: &mut WireFile, cutoff: u64, now_ms: u64) {
    operations::remove_authorizations(wire, |auth| {
        prunable(auth, cutoff, now_ms) && !operations::unreleased_link(auth)
    });
}

/// The authorization records a window state reset keeps: every record whose
/// authority can still be presented at `now_ms`, by the approval's expiry or
/// a policy authority's governing end, and every record an operation links
/// that has no release row. The successor holds no holds, so a record that
/// holds capacity becomes expired at `now_ms`. As in the sweep, a record that
/// was never claimed and that no committed exposure names also becomes
/// unused with an `Always` release row. A record linking a retained
/// operation that has not ended stays as it is, since the reset keeps no
/// operation audit.
pub(super) fn reset_survivors(wire: &WireFile, now_ms: u64) -> Vec<WireAuthorization> {
    let commit = CommitId::random();
    let exposed = operations::exposed_authorizations(wire);
    let live = operations::live_operations(wire);
    wire.authorizations
        .iter()
        .filter_map(|auth| {
            if auth
                .operation
                .is_some_and(|link| live.contains(&link.operation_id))
            {
                return Some(auth.clone());
            }
            if auth.authority_end_ms() <= now_ms && !operations::unreleased_link(auth) {
                return None;
            }
            let mut kept = auth.clone();
            if kept.state.holds() {
                if kept.claimed_ms.is_none() && !exposed.contains(&kept.id) {
                    kept.disposition = Some(Disposition::Unused);
                    kept.native_release =
                        Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit));
                }
                kept.state = AuthorizationState::Expired;
                kept.settled_ms = Some(now_ms);
            }
            Some(kept)
        })
        .collect()
}

/// Releases the total-budget debits of authorization `auth_id`, whose
/// transaction a checked recovery decision proves failed or never included.
///
/// Every counted total row the authorization wrote becomes `proved_unspent`
/// and keeps its amount for audit. An authorization that still holds is
/// settled as expired at `now_ms`: its total holds become `proved_unspent`
/// rows, and its other holds become confirmed spend dated at the claim, as an
/// expiry retains them. Rows and holds of every other authorization stay. A
/// repeated call changes nothing.
pub(super) fn release_total_debits(wire: &mut WireFile, auth_id: AuthorizationId, now_ms: u64) {
    let holding = wire
        .authorizations
        .iter()
        .find(|auth| auth.id == auth_id && auth.state.holds())
        .map(|auth| (auth.chain, auth.claimed_ms.unwrap_or(auth.minted_ms)));
    if let Some((chain, spent_ms)) = holding
        && wire
            .holds
            .iter()
            .any(|hold| hold.authorization_id == auth_id && is_total_hold(hold))
    {
        let holds: Vec<WireAuthorizationHold> = wire
            .holds
            .iter()
            .filter(|hold| hold.authorization_id == auth_id)
            .cloned()
            .collect();
        for hold in &holds {
            let total = is_total_hold(hold);
            retain_hold(
                &mut wire.entries,
                hold,
                WireRecord {
                    chain_scope: Some(super::store::ChainScope::for_chain(chain)),
                    ts_ms: spent_ms,
                    amount: hold.amount,
                    status: if total {
                        RecordStatus::ProvedUnspent
                    } else {
                        RecordStatus::Confirmed
                    },
                    epoch: hold.epoch,
                    authorization_id: hold.epoch.map(|_| auth_id),
                    ..WireRecord::confirmed_defaults()
                },
            );
        }
        wire.holds.retain(|hold| hold.authorization_id != auth_id);
        if let Some(auth) = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == auth_id)
        {
            auth.state = AuthorizationState::Expired;
            auth.settled_ms = Some(now_ms);
        }
    }
    for bucket in wire
        .entries
        .iter_mut()
        .filter(|bucket| super::store::is_total_budget_bucket(bucket))
    {
        for record in &mut bucket.records {
            if record.authorization_id == Some(auth_id) {
                record.status = RecordStatus::ProvedUnspent;
            }
        }
    }
}

/// Converts each total-budget hold of `original` into the reset successor's
/// `entries` once. A hold of a claimed authorization, or of one a committed
/// exposure names, becomes counted spend dated at the claim, or at the mint
/// when no claim is recorded. An unclaimed, unexposed hold is released. The
/// conversion reads the holds of `original`, so an authorization the reset
/// drops still keeps its counted spend.
pub(super) fn retain_total_holds_on_reset(original: &WireFile, entries: &mut Vec<WireBucket>) {
    let exposed = operations::exposed_authorizations(original);
    for hold in original.holds.iter().filter(|hold| is_total_hold(hold)) {
        let Some(auth) = original
            .authorizations
            .iter()
            .find(|auth| auth.id == hold.authorization_id)
        else {
            continue;
        };
        if auth.claimed_ms.is_none() && !exposed.contains(&auth.id) {
            continue;
        }
        retain_hold(
            entries,
            hold,
            WireRecord {
                chain_scope: Some(super::store::ChainScope::for_chain(auth.chain)),
                ts_ms: auth.claimed_ms.unwrap_or(auth.minted_ms),
                amount: hold.amount,
                epoch: hold.epoch,
                authorization_id: hold.epoch.map(|_| auth.id),
                ..WireRecord::confirmed_defaults()
            },
        );
    }
}

/// Whether `auth` is open or claimed and inside its lifetime at `now_ms`.
pub(super) fn effective(auth: &WireAuthorization, now_ms: u64) -> bool {
    auth.state.holds() && auth.minted_ms <= now_ms && now_ms < auth.expires_ms
}

/// The number of effective open authorizations in `wire` at `now_ms`.
#[cfg(feature = "mainnet-write")]
pub(super) fn effective_open_count(wire: &WireFile, now_ms: u64) -> usize {
    wire.authorizations
        .iter()
        .filter(|auth| effective(auth, now_ms))
        .count()
}

// ─────────────────────────────────────────────────────────────────────────────
// Transition inputs and results
// ─────────────────────────────────────────────────────────────────────────────

/// What a mint records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
    /// The chain the authorization is for: the profile's, and mainnet.
    pub chain: Caip2,
    /// The domain facts.
    pub binding: DomainBinding,
    /// The verb that may consume it.
    pub consumer: MainnetConsumer,
    /// The verified policy's sequence, which must equal the policy pin's.
    pub policy_sequence: i64,
    /// The verified policy's digest, which must equal the policy pin's.
    pub policy_digest: [u8; 32],
    /// The authority the action proceeds under; the authorization expires no
    /// later than its end.
    pub authority: MintAuthority,
    /// The signed envelope's on-chain deadline; the authorization expires no later.
    pub chain_deadline_ms: Option<u64>,
    /// The authorization's lifetime, in milliseconds.
    pub authorization_ttl_ms: u64,
    /// Per-proof fact digests. The reservation must be absent; mint computes it.
    pub bindings: BindingFacts,
    /// The window entries the authorization holds: the value entries of a
    /// transaction, an inner fee bump, or a Soroban intent, and the fee
    /// entries of an outer fee bump. Empty for every other domain.
    pub holds: Vec<WindowEntry>,
    /// The used authorization a continuation names: the used Soroban intent
    /// of an x402 submission, and the used message record of an
    /// authenticated x402 intent, which shares its approval. Absent for every
    /// other record.
    pub parent: Option<AuthorizationId>,
    /// The operation attempt the authorization serves; the operation must
    /// be retained and open. Absent for a mint outside an operation.
    pub operation: Option<OperationLink>,
    /// The native amounts the authorization reserves, stored with the
    /// record whether or not it holds window entries.
    pub native_reservation: Option<NativeReservation>,
}

/// How a mint inside an operation step relaxes the stand-alone rules.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct MintOptions {
    /// A successor attempt's mint does not count against
    /// [`MAX_OPEN_AUTHORIZATIONS`].
    pub(super) exempt_cap: bool,
    /// The operation whose earlier, unused authorizations may carry the
    /// same approval nonce.
    pub(super) lineage: Option<OperationId>,
}

/// The policy authority a record is minted under: the decision that allowed
/// the action without an approval, and the end of the authority it grants.
///
/// Its digest, [`crate::mainnet::digest::policy_authority_digest`], binds the
/// record's authority into the header's bindings and its expectations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAuthorityBinding {
    /// The BLAKE3 digest of the verified policy's canonical bytes.
    pub policy_digest: [u8; 32],
    /// The verified policy's signed sequence.
    pub policy_sequence: i64,
    /// The zero-based document position of the deciding rule.
    pub rule_index: u32,
    /// The evaluation instant, in Unix milliseconds.
    pub evaluated_at_ms: u64,
    /// The end of the authority, in Unix milliseconds; an authorization under
    /// it expires no later.
    pub governing_until_ms: u64,
    /// The scope the decision covers.
    pub scope: AuthorityScope,
}

impl PolicyAuthorityBinding {
    /// The policy-authority digest of this binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        crate::mainnet::digest::policy_authority_digest(self)
    }
}

/// The authority a mint records: an operator approval or a policy authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintAuthority {
    /// An operator approval.
    Approval {
        /// The approval nonce, single use within retention.
        nonce: String,
        /// The approval's expiry, in Unix milliseconds.
        expires_at_ms: u64,
    },
    /// A policy authority.
    Policy(PolicyAuthorityBinding),
}

impl MintAuthority {
    /// The end of the authority in Unix milliseconds: the approval's expiry
    /// or the policy authority's governing end.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        match self {
            Self::Approval { expires_at_ms, .. } => *expires_at_ms,
            Self::Policy(binding) => binding.governing_until_ms,
        }
    }
}

/// Compares the authority a transition presents with the one the record was
/// minted under: an approval by nonce and then expiry, a policy authority by
/// its digest. Two authorities of different variants never match.
fn compare_authority(
    recorded: &MintAuthority,
    expected: &MintAuthority,
) -> Result<(), WindowStoreError> {
    use MainnetPrecondition as P;
    match (recorded, expected) {
        (
            MintAuthority::Approval {
                nonce,
                expires_at_ms,
            },
            MintAuthority::Approval {
                nonce: expected_nonce,
                expires_at_ms: expected_expiry,
            },
        ) => {
            check(nonce == expected_nonce, P::ApprovalNonce)?;
            check(expires_at_ms == expected_expiry, P::ApprovalExpiry)
        }
        (MintAuthority::Policy(binding), MintAuthority::Policy(expected)) => {
            check(binding.digest() == expected.digest(), P::AuthorityMismatch)
        }
        _ => Err(refused(P::AuthorityMismatch)),
    }
}

/// Whether a record of `domain` minted for `consumer` continues a parent: an
/// x402 submission always does, and so does the Soroban intent of an
/// authenticated x402 payment.
fn requires_parent(domain: AuthorizationDomain, consumer: MainnetConsumer) -> bool {
    domain == AuthorizationDomain::X402Submit
        || (domain == AuthorizationDomain::Soroban
            && consumer == MainnetConsumer::X402Authenticated)
}

/// The domain of the parent a `child` record continues, or `None` for a
/// domain without one.
fn parent_domain(child: AuthorizationDomain) -> Option<AuthorizationDomain> {
    match child {
        AuthorizationDomain::X402Submit => Some(AuthorizationDomain::Soroban),
        AuthorizationDomain::Soroban => Some(AuthorizationDomain::Message),
        _ => None,
    }
}

/// Proof that the store reserved window headroom for an authorization's
/// holds under its lock.
///
/// Only [`PersistedWindowStore::mint_authorization`] produces one, and its
/// fields are private:
///
/// ```compile_fail,E0451
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn forge(p: WindowReservation) -> WindowReservation { WindowReservation { ..p } }
/// ```
///
/// The import alone resolves:
///
/// ```
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need(_: Option<WindowReservation>) {}
/// need(None);
/// ```
///
/// It implements none of `Serialize`, `Deserialize`, `Default`, or `Clone`:
///
/// ```compile_fail,E0277
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need<T: serde::Serialize>() {}
/// need::<WindowReservation>();
/// ```
///
/// ```compile_fail,E0277
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need<T: serde::de::DeserializeOwned>() {}
/// need::<WindowReservation>();
/// ```
///
/// ```compile_fail,E0277
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need<T: Default>() {}
/// need::<WindowReservation>();
/// ```
///
/// ```compile_fail,E0277
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need<T: Clone>() {}
/// need::<WindowReservation>();
/// ```
/// The `id` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn inspect(p: &WindowReservation) { let _ = &p.id; }
/// ```
///
/// ```
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need(_: Option<WindowReservation>) {}
/// need(None);
/// ```
///
/// The `profile` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn inspect(p: &WindowReservation) { let _ = &p.profile; }
/// ```
///
/// ```
/// use stellar_agent_network::policy_state::WindowReservation;
/// fn need(_: Option<WindowReservation>) {}
/// need(None);
/// ```
///
pub struct WindowReservation {
    id: AuthorizationId,
    profile: String,
}

impl std::fmt::Debug for WindowReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowReservation")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl WindowReservation {
    /// A reservation proof for this crate's tests of the types that hold one.
    #[cfg(test)]
    pub(crate) fn for_crate_tests(id: AuthorizationId, profile: &str) -> Self {
        Self {
            id,
            profile: profile.to_owned(),
        }
    }

    /// The reservation's identity: its authorization's.
    #[must_use]
    pub fn id(&self) -> AuthorizationId {
        self.id
    }

    /// The profile whose window holds the reservation.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The fact digest under `stellar-agent-authz-fact:reservation:v1`.
    ///
    /// Fields, in order: `lp(profile)` and the 32-byte identity.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        use stellar_agent_core::mainnet::fact::{FACT_LABEL_RESERVATION, FactDigest};
        let mut digest = FactDigest::new(FACT_LABEL_RESERVATION);
        digest
            .bytes(self.profile.as_bytes())
            .fixed(self.id.as_bytes());
        digest.finish()
    }
}

/// What a mint recorded.
#[derive(Debug)]
pub struct MintedRecord {
    /// The aggregate over the supplied proofs and the minted reservation.
    pub bindings_digest: [u8; 32],
    /// The authorization's identity.
    pub id: AuthorizationId,
    /// When the store issued it, in Unix milliseconds on its clock.
    pub issued_at_ms: u64,
    /// When it expires: the earliest of the issue time plus the lifetime, the
    /// end of its authority, and the envelope's on-chain deadline.
    pub expires_at_ms: u64,
    /// The window reservation of its holds; absent when it holds nothing.
    pub reservation: Option<WindowReservation>,
}

/// The sealed header facts a signing claim must match.
/// Only the authorization header assembles this expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimExpect {
    pub(crate) domain: AuthorizationDomain,
    pub(crate) consumer: MainnetConsumer,
    pub(crate) bindings_digest: [u8; 32],
    pub(crate) policy_sequence: i64,
    pub(crate) policy_digest: [u8; 32],
    pub(crate) authority: MintAuthority,
}

/// The expectation a consumption is compared against: an authorization's
/// bound facts with the consumer's recomputed digests and fresh audit facts.
///
/// Built by an authorization's `consume_expect`; its fields are private, so
/// the bound facts never leave the authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumeExpect {
    profile: String,
    chain: Caip2,
    domain: AuthorizationDomain,
    consumer: MainnetConsumer,
    content_digest: [u8; 32],
    binding: DomainBinding,
    policy_sequence: i64,
    policy_digest: [u8; 32],
    authority: MintAuthority,
    reservation: Option<AuthorizationId>,
    entries_digest: [u8; 32],
    bindings_digest: [u8; 32],
    recorded_audit: AuditFacts,
    fresh_audit: AuditFacts,
}

impl ConsumeExpect {
    /// Assembles an expectation from an authorization's bound facts and the
    /// consumer's recomputed ones. The domain is the binding's.
    #[cfg(any(test, feature = "mainnet-write"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "every compared fact is a separate input"
    )]
    pub(crate) fn new(
        profile: String,
        chain: Caip2,
        consumer: MainnetConsumer,
        binding: DomainBinding,
        policy_sequence: i64,
        policy_digest: [u8; 32],
        authority: MintAuthority,
        reservation: Option<AuthorizationId>,
        bindings_digest: [u8; 32],
        recorded_audit: AuditFacts,
        recomputed: &crate::mainnet::types::RecomputedFacts,
    ) -> Self {
        Self {
            profile,
            chain,
            domain: binding.domain(),
            consumer,
            content_digest: recomputed.content_digest,
            binding,
            policy_sequence,
            policy_digest,
            authority,
            reservation,
            entries_digest: recomputed.entries_digest,
            bindings_digest,
            recorded_audit,
            fresh_audit: recomputed.audit,
        }
    }
}

/// What one consumption settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeReceipt {
    /// The consumed authorization; for a Soroban intent, the identity an x402
    /// submission names as its parent.
    pub authorization_id: AuthorizationId,
    /// Its domain.
    pub domain: AuthorizationDomain,
    /// When the store consumed it, in Unix milliseconds on its clock.
    pub consumed_at_ms: u64,
}

/// One effective open authorization, for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAuthorization {
    /// Its identity.
    pub id: AuthorizationId,
    /// Its domain.
    pub domain: AuthorizationDomain,
    /// The verb that may consume it.
    pub consumer: MainnetConsumer,
    /// When it was minted, in Unix milliseconds.
    pub minted_at_ms: u64,
    /// When signing is claimed, in Unix milliseconds, if claimed.
    pub claimed_at_ms: Option<u64>,
    /// When it expires, in Unix milliseconds.
    pub expires_at_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Transitions
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn pin_refusal(error: PinError) -> WindowStoreError {
    match error {
        PinError::InstallationKeyCoordinate => WindowStoreError::InstallationKeyCoordinate,
        PinError::Absent => refused(MainnetPrecondition::PolicyPinAbsent),
        PinError::Mismatch { .. } => refused(MainnetPrecondition::PolicyPinMismatch),
        PinError::Keyring { detail } => WindowStoreError::Keyring { detail },
        PinError::Malformed { .. } => refused(MainnetPrecondition::PolicyPinMalformed),
        other => WindowStoreError::Invalid {
            detail: other.to_string(),
        },
    }
}

fn check_profile_handle(
    auth: &WireAuthorization,
    profile: &Profile,
) -> Result<(), WindowStoreError> {
    check(
        auth.profile == stellar_agent_core::profile::name::profile_name_for_approval(profile),
        MainnetPrecondition::ProfileMismatch,
    )
}

fn compare_expectation(
    auth: &WireAuthorization,
    expect: &ConsumeExpect,
) -> Result<(), WindowStoreError> {
    use MainnetPrecondition as P;
    check(auth.profile == expect.profile, P::ProfileMismatch)?;
    check(expect.chain.is_mainnet(), P::ChainNotMainnet)?;
    check(auth.chain == expect.chain, P::ChainMismatch)?;
    check(auth.domain == expect.domain, P::DomainMismatch)?;
    check(auth.consumer == expect.consumer, P::ConsumerMismatch)?;
    check(
        auth.content_digest == expect.content_digest,
        P::ContentDigest,
    )?;
    check(auth.binding == expect.binding, P::BindingMismatch)?;
    check(
        auth.policy_sequence == expect.policy_sequence,
        P::PolicySequence,
    )?;
    check(auth.policy_digest == expect.policy_digest, P::PolicyDigest)?;
    let recorded = auth.authority()?;
    compare_authority(&recorded, &expect.authority)?;
    check(
        auth.expires_ms <= recorded.expires_at_ms(),
        P::LifetimeInvalid,
    )?;
    check(
        auth.reservation == expect.reservation,
        P::ReservationMismatch,
    )?;
    check(
        auth.entries_digest == expect.entries_digest,
        P::EntriesDigest,
    )?;
    check(
        auth.bindings_digest == expect.bindings_digest,
        P::BindingsDigest,
    )?;
    check(
        expect.fresh_audit.log_path_digest == expect.recorded_audit.log_path_digest,
        P::AuditLogPath,
    )?;
    check(
        expect.fresh_audit.segment == expect.recorded_audit.segment,
        P::AuditSegment,
    )?;
    check(
        expect.fresh_audit.anchored_count >= expect.recorded_audit.anchored_count,
        P::AuditCount,
    )
}

/// Checks that `binding` consumes `auth`, and for an x402 submission that its
/// parent is a used Soroban intent of the same profile and chain.
fn check_consumption(
    wire: &WireFile,
    auth: &WireAuthorization,
    binding: &ConsumptionBinding,
) -> Result<(), WindowStoreError> {
    use MainnetPrecondition as P;
    if let ConsumptionBinding::Transaction(submission) = binding {
        let scope = submission
            .chain_scope
            .ok_or(WindowStoreError::ChainUnverifiable)?;
        if submission
            .submission_anchor
            .as_ref()
            .is_some_and(|anchor| !anchor.matches(scope, submission.tx_hash))
        {
            return Err(WindowStoreError::ChainUnverifiable);
        }
        if scope.chain() != auth.chain || Some(scope) != wire.chain_scope {
            return Err(WindowStoreError::ChainMismatch);
        }
    }
    match (binding, &auth.binding) {
        (
            ConsumptionBinding::Transaction(submission),
            DomainBinding::Transaction {
                tx_hash,
                source,
                sequence,
                ..
            },
        ) => {
            check(submission.fee_bump.is_none(), P::BindingMismatch)?;
            check(submission.tx_hash == *tx_hash, P::TxHash)?;
            check(submission.source == *source, P::SourceAccount)?;
            check(submission.sequence == *sequence, P::Sequence)
        }
        (
            ConsumptionBinding::Transaction(submission),
            DomainBinding::FeeBumpInner {
                inner_source,
                inner_sequence,
                inner_tx_hash,
                fee_source,
                max_fee,
            },
        ) => {
            check(submission.source == *inner_source, P::SourceAccount)?;
            check(submission.sequence == *inner_sequence, P::Sequence)?;
            let facts = submission
                .fee_bump
                .as_ref()
                .ok_or_else(|| refused(P::BindingMismatch))?;
            check(facts.inner_tx_hash == *inner_tx_hash, P::InnerTxHash)?;
            check(facts.fee_source == *fee_source, P::FeeSource)?;
            check(facts.max_fee == *max_fee, P::MaxFee)
        }
        (
            ConsumptionBinding::Transaction(submission),
            DomainBinding::FeeBumpOuter {
                outer_tx_hash,
                inner_source,
                inner_sequence,
                inner_tx_hash,
                fee_source,
                max_fee,
            },
        ) => {
            check(submission.tx_hash == *outer_tx_hash, P::OuterTxHash)?;
            check(submission.source == *inner_source, P::SourceAccount)?;
            check(submission.sequence == *inner_sequence, P::Sequence)?;
            let facts = submission
                .fee_bump
                .as_ref()
                .ok_or_else(|| refused(P::BindingMismatch))?;
            check(facts.inner_tx_hash == *inner_tx_hash, P::InnerTxHash)?;
            check(facts.fee_source == *fee_source, P::FeeSource)?;
            check(facts.max_fee == *max_fee, P::MaxFee)
        }
        (
            ConsumptionBinding::RetainedIntent { intent_digest },
            DomainBinding::Soroban {
                intent_digest: bound,
            },
        ) => check(intent_digest == bound, P::IntentDigest),
        (
            ConsumptionBinding::PayloadRelease {
                intent_record,
                final_envelope_sha256,
                root_invocation_digest,
            },
            DomainBinding::X402Submit {
                final_envelope_sha256: bound_final,
                root_invocation_digest: bound_root,
            },
        ) => {
            check(*intent_record == auth.parent, P::IntentRecordMismatch)?;
            let parent =
                intent_record.and_then(|id| wire.authorizations.iter().find(|a| a.id == id));
            check(
                parent.is_some_and(|parent| {
                    parent.state == AuthorizationState::Used
                        && parent.domain == AuthorizationDomain::Soroban
                        && parent.profile == auth.profile
                        && parent.chain == auth.chain
                }),
                P::IntentRecordMismatch,
            )?;
            check(final_envelope_sha256 == bound_final, P::FinalEnvelope)?;
            check(
                *root_invocation_digest == Some(*bound_root),
                P::RootInvocation,
            )
        }
        (
            ConsumptionBinding::PayloadRelease {
                intent_record,
                final_envelope_sha256,
                root_invocation_digest,
            },
            DomainBinding::FeeBumpSubmit {
                final_envelope_sha256: bound_final,
                ..
            },
        ) => {
            check(intent_record.is_none(), P::IntentRecordMismatch)?;
            check(final_envelope_sha256 == bound_final, P::FinalEnvelope)?;
            check(root_invocation_digest.is_none(), P::RootInvocation)
        }
        (
            ConsumptionBinding::Message {
                domain,
                content_digest,
                ephemeral_public_key,
            },
            DomainBinding::Message {
                domain: bound_domain,
                content_digest: bound_content,
                ephemeral_public_key: bound_key,
            },
        ) => {
            check(
                domain.home_domain == bound_domain.home_domain,
                P::MessageHomeDomain,
            )?;
            check(
                domain.web_auth_domain == bound_domain.web_auth_domain,
                P::MessageWebAuthDomain,
            )?;
            check(
                domain.server_key == bound_domain.server_key,
                P::MessageServerKey,
            )?;
            check(content_digest == bound_content, P::MessageContent)?;
            check(ephemeral_public_key == bound_key, P::SignerKeyMismatch)
        }
        _ => Err(refused(P::BindingMismatch)),
    }
}

/// Applies one checked consumption to `wire`: converts the holds, marks the
/// record used, and stores the binding.
fn apply_consumption(
    wire: &mut WireFile,
    id: AuthorizationId,
    binding: &ConsumptionBinding,
    now: u64,
) {
    let holds: Vec<WireAuthorizationHold> = wire
        .holds
        .iter()
        .filter(|hold| hold.authorization_id == id)
        .cloned()
        .collect();
    wire.holds.retain(|hold| hold.authorization_id != id);
    for hold in holds {
        let record = match binding {
            ConsumptionBinding::Transaction(submission) => WireRecord {
                chain_scope: submission.chain_scope,
                ts_ms: hold.ts_ms,
                amount: hold.amount,
                id: stellar_agent_core::hex::encode(&submission.envelope_hash),
                status: RecordStatus::Pending,
                tx_hash: stellar_agent_core::hex::encode(&submission.tx_hash),
                source: submission.source.clone(),
                sequence: submission.sequence,
                max_time: submission.max_time,
                pending_since_ms: submission.pending_since_ms,
                submission_ledger: submission.submission_ledger,
                submission_anchor: submission.submission_anchor.as_deref().cloned(),
                operator_required: false,
                execution_bound: (submission.max_time > 0)
                    .then(|| submission.max_time.saturating_mul(1000)),
                admitted_window_ms: Some(hold.window_secs.saturating_mul(1000)),
                accounting_until_ms: (submission.max_time > 0).then(|| {
                    submission
                        .max_time
                        .saturating_mul(1000)
                        .saturating_add(hold.window_secs.saturating_mul(1000))
                }),
                epoch: hold.epoch,
                authorization_id: hold.epoch.map(|_| id),
                ..WireRecord::confirmed_defaults()
            },
            // Retained authorized spend: confirmed at the moment the store
            // released it, as an authorized external settlement is.
            _ => WireRecord {
                ts_ms: now,
                amount: hold.amount,
                epoch: hold.epoch,
                authorization_id: hold.epoch.map(|_| id),
                ..WireRecord::confirmed_defaults()
            },
        };
        retain_hold(&mut wire.entries, &hold, record);
    }
    if let Some(auth) = wire.authorizations.iter_mut().find(|auth| auth.id == id) {
        auth.state = AuthorizationState::Used;
        auth.settled_ms = Some(now);
        auth.consumption = Some(binding.clone());
        if auth.operation.is_some() {
            auth.disposition = Some(Disposition::Used);
        }
    }
}

/// Records a checked mint in `wire`: the authorization, its holds and its
/// reservation, expiring at `expires`, on the store clock `now`.
///
/// No open authorization may name the same domain and content; a
/// continuation must continue a used parent of the same profile, chain,
/// consumer, policy and authority that has no child yet; every other request
/// under an approval carries a nonce that appears on no record within
/// retention, except on earlier unused records of `options.lineage`'s
/// operation; at most [`MAX_OPEN_AUTHORIZATIONS`] may be open unless
/// `options.exempt_cap`; a link must name a retained, open operation; and
/// the holds must be admitted against the window.
///
/// # Errors
///
/// [`WindowStoreError::AuthorizationRefused`] naming the broken
/// precondition, [`WindowStoreError::PolicyDenied`] when the window cannot
/// admit the holds, and [`WindowStoreError::UnexpectedState`] for a link to
/// an operation the window does not hold open.
pub(super) fn mint_into(
    wire: &mut WireFile,
    profile: &Profile,
    request: &MintRequest,
    now: u64,
    expires: u64,
    options: MintOptions,
) -> Result<MintedRecord, WindowStoreError> {
    use MainnetPrecondition as P;
    // Both public mint entries ran `check_total_shape` before their lock.
    // The mint's prechecks compared `policy_digest` with the pin under the
    // lock, so a total hold binds to the pin through it.
    if request
        .holds
        .iter()
        .any(|entry| is_total_entry(entry) && entry.epoch() != Some(request.policy_digest))
    {
        return Err(WindowStoreError::TotalEpochStale);
    }
    let domain = request.binding.domain();
    let content = request.binding.content_digest();
    check(
        !wire.authorizations.iter().any(|auth| {
            auth.state.holds() && auth.domain == domain && auth.content_digest == content
        }),
        P::DuplicateOpen,
    )?;
    match request.parent {
        Some(parent_id) => {
            let parent = wire.authorizations.iter().find(|auth| auth.id == parent_id);
            check(
                parent.is_some_and(|parent| {
                    parent.state == AuthorizationState::Used
                        && Some(parent.domain) == parent_domain(domain)
                        && parent.profile
                            == stellar_agent_core::profile::name::profile_name_for_approval(profile)
                        && parent.chain == request.chain
                        && parent.consumer == request.consumer
                        && parent.policy_sequence == request.policy_sequence
                        && parent.policy_digest == request.policy_digest
                        && parent
                            .authority()
                            .is_ok_and(|authority| authority == request.authority)
                }),
                P::IntentRecordMismatch,
            )?;
            check(
                !wire
                    .authorizations
                    .iter()
                    .any(|auth| auth.parent == Some(parent_id)),
                P::IntentRecordMismatch,
            )?;
        }
        None => {
            if let MintAuthority::Approval { nonce, .. } = &request.authority {
                let exposed = operations::exposed_authorizations(wire);
                check(
                    !wire.authorizations.iter().any(|auth| {
                        auth.approval_nonce.as_ref() == Some(nonce)
                            && !earlier_unused_carrier(auth, options.lineage, &exposed)
                    }),
                    P::ApprovalNonceReused,
                )?;
                super::approvals::consume(wire, nonce, request.operation, now)?;
            }
        }
    }
    if let Some(link) = request.operation {
        operations::check_mint_link(wire, link)?;
    }
    check(
        options.exempt_cap
            || wire
                .authorizations
                .iter()
                .filter(|auth| auth.state.holds())
                .count()
                < MAX_OPEN_AUTHORIZATIONS,
        P::TooManyOpen,
    )?;
    admit(wire, &request.holds)?;

    let id = loop {
        let candidate = AuthorizationId::random();
        if !wire.authorizations.iter().any(|auth| auth.id == candidate) {
            break candidate;
        }
    };
    let profile_name = stellar_agent_core::profile::name::profile_name_for_approval(profile);
    let reservation = match HoldKind::of(domain) {
        Some(kind) if !request.holds.is_empty() => {
            for (ordinal, entry) in request.holds.iter().enumerate() {
                let entry_key = entry.key();
                wire.holds.push(WireAuthorizationHold {
                    kind,
                    authorization_id: id,
                    ordinal: u32::try_from(ordinal).map_err(|_| refused(P::HoldsMismatch))?,
                    scope_specificity: entry_key.scope_specificity(),
                    bucket: entry_key.bucket().to_owned(),
                    window_secs: entry_key.window_secs(),
                    ts_ms: entry.timestamp_ms(),
                    amount: entry.amount(),
                    epoch: if is_total_entry(entry) {
                        entry.epoch()
                    } else {
                        None
                    },
                });
            }
            Some(id)
        }
        _ => None,
    };
    let mut bindings = request.bindings;
    bindings.reservation = reservation.map(|id| {
        WindowReservation {
            id,
            profile: profile_name.clone(),
        }
        .fact_digest()
    });
    let bindings_digest = bindings_digest(&bindings);
    let (approval_nonce, approval_expires_ms, policy_authority) =
        wire_authority(&request.authority);
    wire.authorizations.push(WireAuthorization {
        id,
        profile: profile_name.clone(),
        chain: request.chain,
        domain,
        consumer: request.consumer,
        content_digest: content,
        binding: request.binding.clone(),
        state: AuthorizationState::Open,
        minted_ms: now,
        expires_ms: expires,
        settled_ms: None,
        claimed_ms: None,
        policy_sequence: request.policy_sequence,
        policy_digest: request.policy_digest,
        approval_nonce,
        approval_expires_ms,
        policy_authority,
        bindings_digest,
        entries_digest: entries_digest(&request.holds),
        reservation,
        parent: request.parent,
        consumption: None,
        invalidation: None,
        operation: request.operation,
        disposition: None,
        native_release: None,
        native_reservation: request.native_reservation,
    });
    Ok(MintedRecord {
        bindings_digest,
        id,
        issued_at_ms: now,
        expires_at_ms: expires,
        reservation: reservation.map(|id| WindowReservation {
            id,
            profile: profile_name,
        }),
    })
}

/// Whether `auth` is an earlier authorization of `lineage`'s operation that
/// ended unused: never claimed, with disposition `unused`, and named by no
/// committed exposure, so no transaction was signed under it and its
/// approval nonce may carry a remint of the same operation.
fn earlier_unused_carrier(
    auth: &WireAuthorization,
    lineage: Option<OperationId>,
    exposed: &[AuthorizationId],
) -> bool {
    lineage.is_some_and(|operation| {
        auth.operation
            .is_some_and(|link| link.operation_id == operation)
            && auth.claimed_ms.is_none()
            && auth.disposition == Some(Disposition::Unused)
            && !exposed.contains(&auth.id)
    })
}

#[cfg(test)]
thread_local! {
    /// A test's interleaving, run once in the mint on this thread right after
    /// it reads the verified snapshot, while it holds the lock.
    static MINT_AFTER_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

impl PersistedWindowStore {
    fn ledger_lock(&self, profile: &Profile) -> Result<WindowStoreLock, WindowStoreError> {
        self.ensure_parent_dir()?;
        Ok(WindowStoreLock::acquire_for(
            self.path(),
            &profile.policy_window_state_key_id,
        )?)
    }

    /// Mints a mainnet authorization: records it, its holds, and its
    /// reservation, under the store's lock.
    ///
    /// In one transaction, on the store's clock: the chain must be the
    /// profile's and mainnet; the request's bindings must not carry a
    /// reservation digest; a Soroban intent's consumer must be an x402 verb;
    /// a domain that holds nothing refuses entries; an x402 submission names a
    /// parent and no other request does; no hold may be dated past the store
    /// clock plus [`CLOCK_SKEW_TOLERANCE_MS`]; a policy authority must name
    /// the request's policy; the lifetime is the earliest of the issue time
    /// plus `authorization_ttl_ms`, the end of the authority, and the
    /// envelope's on-chain deadline, and a zero, an overflowing, or an
    /// already elapsed lifetime refuses; the policy pin must be present and
    /// equal to the request's policy. These checks precede the window key, so
    /// a refusal among them mints no key. Then expired authorizations are
    /// swept; no open authorization may name the same domain and content,
    /// whatever its authority; a continuation must continue a used parent of
    /// the same profile, chain, consumer, policy, and authority that has no
    /// child yet; and every other request under an approval must carry a
    /// nonce that appears on no record within retention;
    /// at most [`MAX_OPEN_AUTHORIZATIONS`] may be open; and the holds must be
    /// admitted against the window's spend, its pending records, and every
    /// other hold.
    ///
    /// After the identity is allocated, a record that holds entries sets its
    /// reservation's fact digest in the bindings, and the aggregate bindings
    /// digest is computed over them, stored on the record, and returned in
    /// [`MintedRecord::bindings_digest`].
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::AuthorizationRefused`] naming the broken
    ///   precondition; the store file is not written.
    /// - [`WindowStoreError::PolicyDenied`] when the window cannot admit the
    ///   holds.
    /// - Every integrity, keyring, lock, and I/O error of the store.
    pub fn mint_authorization(
        &self,
        profile: &Profile,
        request: &MintRequest,
    ) -> Result<MintedRecord, WindowStoreError> {
        // A malformed entry refuses before the lock, the key, and any read.
        check_total_shape(&request.holds)?;
        let lock = self.ledger_lock(profile)?;
        let now = now_ms()?;
        let expires = self.mint_prechecks(&lock, profile, request, now)?;

        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        #[cfg(test)]
        if let Some(hook) = MINT_AFTER_READ.with_borrow_mut(Option::take) {
            hook();
        }
        let mut wire = self.retired_successor(&lock, profile, &original)?;
        sweep_expired(&mut wire, now);
        let minted = mint_into(
            &mut wire,
            profile,
            request,
            now,
            expires,
            MintOptions::default(),
        )?;
        prune_stale(&mut wire, now);
        self.commit_generation(&key, &gen_entry, original, wire)?;
        drop(lock);
        Ok(minted)
    }

    /// The mint checks that precede the window key, on the store clock
    /// `now`, under `lock`: the chain, the bindings, the consumer, the holds,
    /// the parent, the policy authority, the lifetime and the policy pin.
    /// Returns the authorization's expiry: the earliest of `now` plus the
    /// lifetime, the end of the authority, and the envelope's on-chain
    /// deadline.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::AuthorizationRefused`] naming the broken
    /// precondition, and the pin's keyring and integrity errors.
    pub(super) fn mint_prechecks(
        &self,
        lock: &WindowStoreLock,
        profile: &Profile,
        request: &MintRequest,
        now: u64,
    ) -> Result<u64, WindowStoreError> {
        use MainnetPrecondition as P;
        check(request.chain.is_mainnet(), P::ChainNotMainnet)?;
        check(request.chain == profile.chain_id, P::ChainMismatch)?;
        let domain = request.binding.domain();
        check(
            request.bindings.reservation.is_none(),
            P::ReservationMismatch,
        )?;
        check(
            domain != AuthorizationDomain::Soroban
                || matches!(
                    request.consumer,
                    MainnetConsumer::X402Create | MainnetConsumer::X402Authenticated
                ),
            P::ConsumerMismatch,
        )?;
        check(
            domain != AuthorizationDomain::Message
                || request.consumer == MainnetConsumer::X402Authenticated,
            P::ConsumerMismatch,
        )?;
        check(
            HoldKind::of(domain).is_some() || request.holds.is_empty(),
            P::HoldsMismatch,
        )?;
        check(
            request
                .native_reservation
                .is_none_or(NativeReservation::well_formed),
            P::HoldsMismatch,
        )?;
        check(
            request.parent.is_some() == requires_parent(domain, request.consumer),
            P::IntentRecordMismatch,
        )?;
        check(
            request
                .holds
                .iter()
                .all(|entry| entry.timestamp_ms() <= now.saturating_add(CLOCK_SKEW_TOLERANCE_MS)),
            P::HoldsMismatch,
        )?;
        if let MintAuthority::Policy(binding) = &request.authority {
            check(
                binding.policy_sequence == request.policy_sequence,
                P::PolicySequence,
            )?;
            check(
                binding.policy_digest == request.policy_digest,
                P::PolicyDigest,
            )?;
        }
        check(request.authorization_ttl_ms > 0, P::LifetimeInvalid)?;
        let ttl_end = now
            .checked_add(request.authorization_ttl_ms)
            .ok_or_else(|| refused(P::LifetimeInvalid))?;
        let expires = ttl_end
            .min(request.authority.expires_at_ms())
            .min(request.chain_deadline_ms.unwrap_or(u64::MAX));
        check(expires > now, P::LifetimeInvalid)?;

        pin::compare(
            lock,
            &PinScope::for_profile(self.path(), profile),
            request.policy_sequence,
            &request.policy_digest,
        )
        .map_err(pin_refusal)?;
        Ok(expires)
    }

    /// Durably claims an open authorization before its signature is requested.
    /// The claim retains its holds and commits under the window-state lock.
    /// The lock is released before this method returns.
    ///
    /// # Errors
    ///
    /// Refuses a missing, non-open, or stale record, mismatched header facts,
    /// or a changed policy pin. Store integrity, keyring, lock, and I/O errors
    /// also refuse the claim.
    pub fn claim_authorization(
        &self,
        profile: &Profile,
        id: AuthorizationId,
        expect: &ClaimExpect,
    ) -> Result<u64, WindowStoreError> {
        use MainnetPrecondition as P;
        let lock = self.ledger_lock(profile)?;
        let now = now_ms()?;
        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        // State and lifetime are checked on the record as read, before the
        // sweep marks an expired record `Expired`, so an expired record
        // reports `Expired`.
        let as_read = original
            .authorizations
            .iter()
            .find(|auth| auth.id == id)
            .ok_or_else(|| refused(P::UnknownAuthorization))?;
        check(as_read.state == AuthorizationState::Open, P::NotOpen)?;
        check(as_read.minted_ms <= now, P::NotYetValid)?;
        check(now < as_read.expires_ms, P::Expired)?;
        let mut wire = self.retired_successor(&lock, profile, &original)?;
        sweep_expired(&mut wire, now);
        let auth = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == id)
            .ok_or_else(|| refused(P::UnknownAuthorization))?;
        check_profile_handle(auth, profile)?;
        check(auth.chain == profile.chain_id, P::ChainMismatch)?;
        check(auth.chain.is_mainnet(), P::ChainNotMainnet)?;
        check(auth.domain == expect.domain, P::DomainMismatch)?;
        check(auth.consumer == expect.consumer, P::ConsumerMismatch)?;
        check(
            auth.bindings_digest == expect.bindings_digest,
            P::BindingsDigest,
        )?;
        check(
            auth.policy_sequence == expect.policy_sequence,
            P::PolicySequence,
        )?;
        check(auth.policy_digest == expect.policy_digest, P::PolicyDigest)?;
        compare_authority(&auth.authority()?, &expect.authority)?;
        pin::compare(
            &lock,
            &PinScope::for_profile(self.path(), profile),
            auth.policy_sequence,
            &auth.policy_digest,
        )
        .map_err(pin_refusal)?;
        auth.state = AuthorizationState::Claimed;
        auth.claimed_ms = Some(now);
        self.commit_generation(&key, &gen_entry, original, wire)?;
        drop(lock);
        Ok(now)
    }

    /// Consumes one authorization; see [`Self::consume_authorizations`].
    ///
    /// # Errors
    ///
    /// The errors of [`Self::consume_authorizations`].
    pub fn consume_authorization(
        &self,
        profile: &Profile,
        id: AuthorizationId,
        expect: &ConsumeExpect,
        binding: &ConsumptionBinding,
    ) -> Result<ConsumeReceipt, WindowStoreError> {
        let mut receipts =
            self.consume_authorizations(profile, &[(id, expect.clone(), binding.clone())])?;
        receipts.pop().ok_or_else(|| WindowStoreError::Invalid {
            detail: "a consumption returned no receipt".to_owned(),
        })
    }

    /// Consumes one authorization for the recorder about to send a
    /// transaction's bytes, as [`Self::consume_authorization`] does, or with
    /// `exposure` as [`Self::consume_authorization_exposing`] does.
    ///
    /// A transaction binding also returns the capability of the reservation
    /// its holds became, named by the binding's envelope hash. Only the
    /// recorder that holds it before the bytes leave can release that
    /// reservation's total-budget debits.
    ///
    /// # Errors
    ///
    /// The errors of the two consumptions.
    pub(crate) fn consume_authorization_unsent(
        &self,
        profile: &Profile,
        id: AuthorizationId,
        expect: &ConsumeExpect,
        binding: &ConsumptionBinding,
        exposure: Option<super::operations::ConsumptionExposure<'_>>,
    ) -> Result<(ConsumeReceipt, Option<super::store::UnsentReservation>), WindowStoreError> {
        let mut receipts =
            self.consume_batch(profile, &[(id, expect.clone(), binding.clone())], exposure)?;
        let receipt = receipts.pop().ok_or_else(|| WindowStoreError::Invalid {
            detail: "a consumption returned no receipt".to_owned(),
        })?;
        let unsent = match binding {
            ConsumptionBinding::Transaction(submission) => {
                Some(super::store::UnsentReservation::of_reservation(
                    stellar_agent_core::hex::encode(&submission.envelope_hash),
                ))
            }
            _ => None,
        };
        Ok((receipt, unsent))
    }

    /// Consumes one authorization and commits the exposure of the operation
    /// attempt it serves in the same generation commit.
    ///
    /// The consumption runs as in [`Self::consume_authorizations`]. The
    /// exposure follows it under the same lock, with the checks of
    /// [`super::operations::OperationRecorder::expose`], and its audit row is
    /// appended through `exposure.audit` before the window write. A refused
    /// exposure or append commits neither.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::consume_authorizations`];
    /// `internal.unexpected_state` for an exposure the attempt does not
    /// admit; [`WindowStoreError::AuditAppendFailed`] when the row cannot be
    /// appended.
    pub fn consume_authorization_exposing(
        &self,
        profile: &Profile,
        id: AuthorizationId,
        expect: &ConsumeExpect,
        binding: &ConsumptionBinding,
        exposure: super::operations::ConsumptionExposure<'_>,
    ) -> Result<ConsumeReceipt, WindowStoreError> {
        let mut receipts = self.consume_batch(
            profile,
            &[(id, expect.clone(), binding.clone())],
            Some(exposure),
        )?;
        receipts.pop().ok_or_else(|| WindowStoreError::Invalid {
            detail: "a consumption returned no receipt".to_owned(),
        })
    }

    /// Consumes every listed authorization in one transaction, all or
    /// nothing.
    ///
    /// Under one lock, the store sweeps expired authorizations on its clock.
    /// The duplicate check runs first. A transaction envelope held by a reservation
    /// or named by an earlier consumption refuses with a distinct cause, so the
    /// caller can preserve a reserved submission's row or close a settled resend.
    ///
    /// Each record must exist, be open or claimed, and be inside its lifetime. The supplied
    /// profile's name and chain must be the record's. Every expectation must equal
    /// the record. The policy pin, read under the same lock, must still equal the
    /// record's policy. The binding must match the domain's consumption and facts.
    ///
    /// Then each consumption is applied: transaction holds become pending records,
    /// Soroban holds become retained authorized spend, and every record is marked
    /// used with its binding. One generation commit covers the batch. A second
    /// consumption of a record, in the same batch or later, refuses.
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::AuthorizationRefused`] naming the broken
    ///   precondition; the store file is not written.
    /// - [`WindowStoreError::DuplicateReservation`] for an envelope the window
    ///   already holds.
    /// - [`WindowStoreError::DuplicateConsumption`] for an envelope an earlier
    ///   authorization consumed.
    /// - Every integrity, keyring, lock, and I/O error of the store.
    pub fn consume_authorizations(
        &self,
        profile: &Profile,
        batch: &[(AuthorizationId, ConsumeExpect, ConsumptionBinding)],
    ) -> Result<Vec<ConsumeReceipt>, WindowStoreError> {
        self.consume_batch(profile, batch, None)
    }

    /// The consumption of [`Self::consume_authorizations`], with the
    /// exposure of [`Self::consume_authorization_exposing`] when one is
    /// given.
    fn consume_batch(
        &self,
        profile: &Profile,
        batch: &[(AuthorizationId, ConsumeExpect, ConsumptionBinding)],
        exposure: Option<super::operations::ConsumptionExposure<'_>>,
    ) -> Result<Vec<ConsumeReceipt>, WindowStoreError> {
        use MainnetPrecondition as P;
        let lock = self.ledger_lock(profile)?;
        let now = now_ms()?;
        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        let mut wire = self.retired_successor(&lock, profile, &original)?;
        sweep_expired(&mut wire, now);
        let scope = PinScope::for_profile(self.path(), profile);
        let mut receipts = Vec::with_capacity(batch.len());
        for (id, expect, binding) in batch {
            // Establish ownership before any authorization refusal can close
            // a submission's pending audit row, even for a grant without holds.
            if let ConsumptionBinding::Transaction(submission) = binding {
                let envelope = stellar_agent_core::hex::encode(&submission.envelope_hash);
                if file_holds_id(&original, &envelope) {
                    return Err(WindowStoreError::DuplicateReservation);
                }
                if original.authorizations.iter().any(|auth| {
                    matches!(
                        &auth.consumption,
                        Some(ConsumptionBinding::Transaction(consumed))
                            if consumed.envelope_hash == submission.envelope_hash
                    )
                }) {
                    return Err(WindowStoreError::DuplicateConsumption);
                }
            }
            let auth = wire
                .authorizations
                .iter()
                .find(|auth| auth.id == *id)
                .ok_or_else(|| refused(P::UnknownAuthorization))?;
            check(auth.state.holds(), P::NotOpen)?;
            // The sweep above leaves an authorization that links a live
            // operation to that operation's own step. Its lifetime is
            // checked here: an authorization past its expiry is not open.
            check(now < auth.expires_ms, P::NotOpen)?;
            check(auth.minted_ms <= now, P::NotYetValid)?;
            check_profile_handle(auth, profile)?;
            compare_expectation(auth, expect)?;
            pin::compare(&lock, &scope, auth.policy_sequence, &auth.policy_digest)
                .map_err(pin_refusal)?;
            check_consumption(&wire, auth, binding)?;
            let domain = auth.domain;
            apply_consumption(&mut wire, *id, binding, now);
            receipts.push(ConsumeReceipt {
                authorization_id: *id,
                domain,
                consumed_at_ms: now,
            });
        }
        if let Some(exposure) = exposure {
            let rows = super::operations::expose_in_consumption(
                &mut wire, profile, &original, now, &exposure,
            )?;
            for row in rows {
                exposure
                    .audit
                    .append(row)
                    .map_err(|detail| WindowStoreError::AuditAppendFailed { detail })?;
            }
        }
        prune_stale(&mut wire, now);
        self.commit_generation(&key, &gen_entry, original, wire)?;
        drop(lock);
        Ok(receipts)
    }

    /// Abandons an open authorization before its signing claim: marks it invalidated with a
    /// bounded `reason`, sets its settlement time, and drops its holds.
    ///
    /// Returns `Ok(false)` for a claimed, settled or expired record; this may still commit
    /// the expiry sweep. A used record is never reopened.
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::AuthorizationRefused`] with
    ///   [`MainnetPrecondition::UnknownAuthorization`] for an unknown identity,
    ///   and with [`MainnetPrecondition::ProfileMismatch`] when the name is not the record's.
    /// - [`WindowStoreError::ChainMismatch`] when the network is not the store's.
    ///   On refusal the store file is not written.
    /// - Every integrity, keyring, lock, and I/O error of the store.
    pub fn invalidate_authorization(
        &self,
        profile: &Profile,
        id: AuthorizationId,
        reason: &str,
    ) -> Result<bool, WindowStoreError> {
        let lock = self.ledger_lock(profile)?;
        let now = now_ms()?;
        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        let mut wire = self.retired_successor(&lock, profile, &original)?;
        let swept = sweep_expired(&mut wire, now);
        let auth = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == id)
            .ok_or_else(|| refused(MainnetPrecondition::UnknownAuthorization))?;
        check_profile_handle(auth, profile)?;
        // An authorization past its expiry is settled by its expiry, never
        // invalidated. The sweep above expires it, or, while it links a live
        // operation, leaves it to that operation's step, which expires it.
        let invalidated = auth.state == AuthorizationState::Open && now < auth.expires_ms;
        if invalidated {
            auth.state = AuthorizationState::Invalidated;
            auth.settled_ms = Some(now);
            auth.invalidation = Some(reason.chars().take(INVALIDATION_REASON_MAX).collect());
            wire.holds.retain(|hold| hold.authorization_id != id);
        }
        if invalidated || swept {
            prune_stale(&mut wire, now);
            self.commit_generation(&key, &gen_entry, original, wire)?;
        }
        drop(lock);
        Ok(invalidated)
    }

    /// Lists the authorizations effective at `now_ms`: open or claimed and inside their
    /// lifetime. Reads and verifies the file and writes nothing.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring, and I/O error of the store's reads.
    pub fn open_authorizations(
        &self,
        profile: &Profile,
        now_ms: u64,
    ) -> Result<Vec<OpenAuthorization>, WindowStoreError> {
        let Some(wire) = self.read_for_inspection(profile)? else {
            return Ok(Vec::new());
        };
        Ok(wire
            .authorizations
            .iter()
            .filter(|auth| effective(auth, now_ms))
            .map(|auth| OpenAuthorization {
                id: auth.id,
                domain: auth.domain,
                consumer: auth.consumer,
                minted_at_ms: auth.minted_ms,
                claimed_at_ms: auth.claimed_ms,
                expires_at_ms: auth.expires_ms,
            })
            .collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::cell::Cell;
    use std::fs;

    use serial_test::serial;
    use stellar_agent_core::policy::pin::Pin;
    use stellar_agent_core::policy::v1::criteria::state_store::{
        PolicyStateStore, StateKey, WindowLimit,
    };
    use stellar_agent_core::profile::name::profile_name_for_approval;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    use super::super::reset_test::{owner_of, signed_by};
    use super::super::store::{
        RETENTION_MS, ResetConsent, ResetError, ResetOutcome, Settlement, SubmissionHold,
        WIRE_VERSION_POLICY_AUTHORITY, deliver_accounting_expiries,
    };
    use super::*;
    use crate::mainnet::clock::{TestClockGuard, set_now_ms_for_test};
    use crate::mainnet::types::RecomputedFacts;

    impl MintAuthority {
        /// The nonce of an approval authority.
        fn nonce(&self) -> &String {
            match self {
                Self::Approval { nonce, .. } => nonce,
                Self::Policy(_) => panic!("a policy authority carries no nonce"),
            }
        }

        /// The nonce of an approval authority, for a test to change.
        fn nonce_mut(&mut self) -> &mut String {
            match self {
                Self::Approval { nonce, .. } => nonce,
                Self::Policy(_) => panic!("a policy authority carries no nonce"),
            }
        }

        /// The expiry of an approval authority, for a test to change.
        fn approval_expiry_mut(&mut self) -> &mut u64 {
            match self {
                Self::Approval { expires_at_ms, .. } => expires_at_ms,
                Self::Policy(_) => panic!("a policy authority carries no approval expiry"),
            }
        }
    }

    /// A change to a mint request that breaks one continuation requirement.
    type Mutation = fn(&mut MintRequest);

    /// A change to a valid snapshot that breaks one ledger invariant.
    type Breakage = fn(&mut WireFile);

    /// A [`Breakage`] that captures the positions of the records it edits.
    type RecordBreakage = Box<dyn Fn(&mut WireFile)>;

    /// A change to a submission that breaks one fact its consumption compares.
    type SubmissionChange = fn(&mut SubmissionBinding);

    const T0: u64 = 1_800_000_000_000;
    const CAP: i128 = 1_000;
    const TTL_MS: u64 = 120_000;
    const APPROVAL_MS: u64 = 600_000;
    const SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM";
    const FEE_SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGN";
    const AUDIT: AuditFacts = AuditFacts {
        segment: [0; 32],
        log_path_digest: [5; 32],
        anchored_count: 10,
    };

    struct Ledger {
        _dir: TempDir,
        profile: Profile,
        store: PersistedWindowStore,
        clock: TestClockGuard,
        nonces: Cell<u32>,
    }

    impl Ledger {
        /// A mainnet profile whose policy pin names sequence 7, digest `[7; 32]`.
        fn new() -> Self {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let mut profile = Profile::builder_mainnet_named(
                "ledger",
                "https://rpc.example",
                "stellar-agent-signer-ledger",
                "acct",
                "n-svc",
                "n-acct",
            )
            .build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            let store = PersistedWindowStore::at_path(dir.path().join("ledger.window"));
            let ledger = Self {
                _dir: dir,
                profile,
                store,
                clock: set_now_ms_for_test(T0),
                nonces: Cell::new(0),
            };
            ledger.pin(7, [7; 32]);
            ledger
        }

        fn pin(&self, sequence: i64, digest: [u8; 32]) {
            let lock = WindowStoreLock::acquire_for(
                self.store.path(),
                &self.profile.policy_window_state_key_id,
            )
            .unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(self.store.path(), &self.profile),
                &Pin::new(sequence, digest, owner_of(11)).unwrap(),
            )
            .unwrap();
        }

        fn name(&self) -> String {
            profile_name_for_approval(&self.profile)
        }

        fn request(&self, binding: DomainBinding, holds: Vec<WindowEntry>) -> MintRequest {
            let n = self.nonces.get() + 1;
            self.nonces.set(n);
            MintRequest {
                chain: Caip2::Mainnet,
                consumer: match binding.domain() {
                    AuthorizationDomain::Soroban | AuthorizationDomain::X402Submit => {
                        MainnetConsumer::X402Create
                    }
                    AuthorizationDomain::Message => MainnetConsumer::X402Authenticated,
                    _ => MainnetConsumer::CliPay,
                },
                binding,
                policy_sequence: 7,
                policy_digest: [7; 32],
                authority: MintAuthority::Approval {
                    nonce: format!("nonce-{n}"),
                    expires_at_ms: T0 + APPROVAL_MS,
                },
                chain_deadline_ms: None,
                authorization_ttl_ms: TTL_MS,
                bindings: BindingFacts {
                    endpoint: None,
                    signer: [2; 32],
                    policy: [3; 32],
                    enablement: [4; 32],
                    witness: None,
                    reservation: None,
                    authority: [7; 32],
                    audit: [8; 32],
                },
                holds,
                parent: None,
                operation: None,
                native_reservation: None,
            }
        }

        fn mint(&self, request: &MintRequest) -> Result<MintedRecord, WindowStoreError> {
            self.store.mint_authorization(&self.profile, request)
        }

        fn claim_expect(&self, request: &MintRequest, minted: &MintedRecord) -> ClaimExpect {
            ClaimExpect {
                domain: request.binding.domain(),
                consumer: request.consumer,
                bindings_digest: minted.bindings_digest,
                policy_sequence: request.policy_sequence,
                policy_digest: request.policy_digest,
                authority: request.authority.clone(),
            }
        }

        fn claim(
            &self,
            request: &MintRequest,
            minted: &MintedRecord,
        ) -> Result<u64, WindowStoreError> {
            self.store.claim_authorization(
                &self.profile,
                minted.id,
                &self.claim_expect(request, minted),
            )
        }

        fn expect(&self, request: &MintRequest, minted: &MintedRecord) -> ConsumeExpect {
            ConsumeExpect::new(
                self.name(),
                request.chain,
                request.consumer,
                request.binding.clone(),
                request.policy_sequence,
                request.policy_digest,
                request.authority.clone(),
                minted.reservation.as_ref().map(WindowReservation::id),
                minted.bindings_digest,
                AUDIT,
                &RecomputedFacts {
                    content_digest: request.binding.content_digest(),
                    entries_digest: entries_digest(&request.holds),
                    audit: AUDIT,
                },
            )
        }

        fn consume(
            &self,
            request: &MintRequest,
            minted: &MintedRecord,
            binding: &ConsumptionBinding,
        ) -> Result<ConsumeReceipt, WindowStoreError> {
            self.store.consume_authorization(
                &self.profile,
                minted.id,
                &self.expect(request, minted),
                binding,
            )
        }

        fn wire(&self) -> WireFile {
            self.store
                .read_for_inspection(&self.profile)
                .unwrap()
                .unwrap()
        }

        fn record(&self, id: AuthorizationId) -> WireAuthorization {
            self.wire()
                .authorizations
                .into_iter()
                .find(|auth| auth.id == id)
                .unwrap()
        }

        fn bytes(&self) -> Vec<u8> {
            fs::read(self.store.path()).unwrap()
        }

        /// Resets under the fixture's name with its pinned owner's signature.
        fn reset(&self, now_ms: u64) -> Result<ResetOutcome, ResetError<()>> {
            self.store.reset(
                &self.profile,
                &self.name(),
                now_ms,
                "repair",
                "reset-request",
                |row| Ok(signed_by(11, row)),
                |_, _| Ok(()),
            )
        }

        /// Records a pending reservation on a 60-second window and commits its
        /// accounting expiry, which owes an undelivered audit event.
        fn owe_expiry(&self) {
            let mut reservation = SubmissionHold {
                id: "cd".repeat(32),
                tx_hash: "ab".repeat(32),
                source: SOURCE.to_owned(),
                sequence: 9,
                max_time: 0,
                pending_since_ms: T0,
                submission_ledger: 1_000,
                submission_anchor: None,
                operator_required: false,
                chain_scope: crate::policy_state::ChainScope::for_chain(Caip2::Mainnet),
            };
            reservation.max_time = T0 / 1000 + 60;
            let entry = WindowEntry::new(
                StateKey::new("ledger", 1, "native", 60),
                T0,
                300,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: CAP,
                },
            );
            self.store
                .record_pending(&self.profile, &[entry], &reservation)
                .unwrap();
            let expire_at = reservation.max_time * 1000 + 60_001;
            let settled = self
                .store
                .expire_accounting(&self.profile, None, &reservation, expire_at)
                .unwrap();
            assert!(
                matches!(settled, Some(Settlement::AccountingExpired { .. })),
                "{settled:?}"
            );
        }

        /// A bound keyed writer over the fixture's audit log.
        fn delivery_writer(&self) -> stellar_agent_core::audit_log::AuditWriter {
            use base64::Engine as _;
            let coordinate = &self.profile.audit_log_hash_chain_key_id;
            let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
            if entry.get_password().is_err() {
                entry
                    .set_password(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4_u8; 32]),
                    )
                    .unwrap();
            }
            let access = crate::keyring::keyed_audit_access(
                &self.profile,
                &self.name(),
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
            .unwrap();
            stellar_agent_core::audit_log::AuditWriter::open(
                self.profile.audit_log_path.clone(),
                Some(access),
            )
            .unwrap()
        }
    }

    fn refusal<T: std::fmt::Debug>(result: Result<T, WindowStoreError>) -> MainnetPrecondition {
        match result {
            Err(WindowStoreError::AuthorizationRefused { precondition }) => precondition,
            other => panic!("expected an authorization refusal, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn a_claim_moves_an_open_record_and_keeps_its_holds() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        let before = l.wire();
        l.clock.set(T0 + 7);
        assert_eq!(l.claim(&request, &minted).unwrap(), T0 + 7);
        let wire = l.wire();
        assert_eq!(wire.generation, before.generation + 1);
        assert_eq!(wire.holds, before.holds);
        assert_eq!(l.record(minted.id).state, AuthorizationState::Claimed);
        assert_eq!(l.record(minted.id).claimed_ms, Some(T0 + 7));
        assert_eq!(
            l.store.open_authorizations(&l.profile, T0 + 7).unwrap()[0].claimed_at_ms,
            Some(T0 + 7)
        );
        assert!(admit(&wire, &[hold(CAP - 70)]).is_ok());
        assert!(matches!(
            admit(&wire, &[hold(CAP - 69)]),
            Err(WindowStoreError::PolicyDenied { .. })
        ));
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        assert_eq!(l.record(minted.id).state, AuthorizationState::Used);
    }

    #[test]
    #[serial]
    fn an_invalidation_after_the_claim_keeps_the_holds() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        l.claim(&request, &minted).unwrap();
        let before = l.bytes();
        assert!(
            !l.store
                .invalidate_authorization(&l.profile, minted.id, "cancel")
                .unwrap()
        );
        assert_eq!(l.bytes(), before);
        assert_eq!(l.wire().holds[0].amount, 70);
        assert!(matches!(
            admit(&l.wire(), &[hold(CAP - 69)]),
            Err(WindowStoreError::PolicyDenied { .. })
        ));
    }

    #[test]
    #[serial]
    fn a_claim_after_the_invalidation_refuses() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        assert!(
            l.store
                .invalidate_authorization(&l.profile, minted.id, "cancel")
                .unwrap()
        );
        assert_eq!(
            refusal(l.claim(&request, &minted)),
            MainnetPrecondition::NotOpen
        );
    }

    #[test]
    #[serial]
    fn an_expired_claim_keeps_its_spend_counted() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(700), hold_in("fee", 30)]);
        let minted = l.mint(&request).unwrap();
        l.clock.set(T0 + 7);
        l.claim(&request, &minted).unwrap();
        l.clock.set(minted.expires_at_ms);
        assert!(
            !l.store
                .invalidate_authorization(&l.profile, minted.id, "expire")
                .unwrap()
        );
        let wire = l.wire();
        let auth = l.record(minted.id);
        assert_eq!(auth.state, AuthorizationState::Expired);
        assert_eq!(auth.claimed_ms, Some(T0 + 7));
        assert_eq!(auth.settled_ms, Some(minted.expires_at_ms));
        assert!(wire.holds.is_empty());
        let records: Vec<_> = wire
            .entries
            .iter()
            .flat_map(|bucket| &bucket.records)
            .collect();
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.ts_ms, T0 + 7);
            assert_eq!(record.status, RecordStatus::Confirmed);
            assert_eq!(
                record.chain_scope,
                Some(super::super::store::ChainScope::for_chain(Caip2::Mainnet))
            );
        }
        let memory = PolicyStateStore::new();
        l.store.load_into("ledger", &l.profile, &memory).unwrap();
        assert_eq!(
            memory
                .query_window(&state_key("native"), minted.expires_at_ms)
                .unwrap(),
            (700, 1)
        );
        assert_eq!(
            memory
                .query_window(&state_key("fee"), minted.expires_at_ms)
                .unwrap(),
            (30, 1)
        );
        assert!(matches!(
            l.mint(&l.request(tx(2), vec![hold(301)])),
            Err(WindowStoreError::PolicyDenied { .. })
        ));
        l.mint(&l.request(tx(2), vec![hold(300)])).unwrap();
    }

    #[test]
    #[serial]
    fn a_reopened_store_cannot_claim_twice_or_mint_the_approval_again() {
        let l = Ledger::new();
        let mut request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        l.claim(&request, &minted).unwrap();
        let reopened = PersistedWindowStore::at_path(l.store.path().to_path_buf());
        assert_eq!(
            refusal(reopened.claim_authorization(
                &l.profile,
                minted.id,
                &l.claim_expect(&request, &minted)
            )),
            MainnetPrecondition::NotOpen
        );
        request.binding = tx(2);
        assert_eq!(
            refusal(reopened.mint_authorization(&l.profile, &request)),
            MainnetPrecondition::ApprovalNonceReused
        );
    }

    #[test]
    #[serial]
    fn a_claim_round_trips_under_the_claim_version() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        assert_eq!(
            l.wire().version,
            super::super::store::WIRE_VERSION_TOTAL_EPOCH
        );
        l.claim(&request, &minted).unwrap();
        let wire = l.wire();
        assert_eq!(wire.version, super::super::store::WIRE_VERSION_TOTAL_EPOCH);
        let reopened = PersistedWindowStore::at_path(l.store.path().to_path_buf());
        let read = reopened.read_for_inspection(&l.profile).unwrap().unwrap();
        assert_eq!(read.authorizations, wire.authorizations);
        assert_eq!(read.holds, wire.holds);
        let mut wrong_version = wire;
        wrong_version.version = super::super::store::WIRE_VERSION_CHAIN;
        assert!(validate(&wrong_version).is_err());
    }

    #[test]
    #[serial]
    fn a_claim_time_on_an_open_record_is_refused() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![]);
        l.mint(&request).unwrap();
        let mut wire = l.wire();
        wire.version = super::super::store::WIRE_VERSION_CLAIM;
        wire.authorizations[0].claimed_ms = Some(T0);
        assert!(validate(&wire).is_err());
    }

    /// A claim time belongs to a claimed record or to the used or expired
    /// record a claim settles into, and lies inside the record's lifetime.
    #[test]
    #[serial]
    fn claim_times_follow_the_record_state_and_lifetime() {
        let l = Ledger::new();
        let claimed_request = l.request(tx(1), vec![hold(70)]);
        let claimed = l.mint(&claimed_request).unwrap();
        let dropped = l.mint(&l.request(tx(2), vec![])).unwrap();
        assert!(
            l.store
                .invalidate_authorization(&l.profile, dropped.id, "cancel")
                .unwrap()
        );
        l.clock.set(T0 + 7);
        l.claim(&claimed_request, &claimed).unwrap();
        let valid = l.wire();
        validate(&valid).unwrap();
        let at = |id: AuthorizationId| {
            valid
                .authorizations
                .iter()
                .position(|auth| auth.id == id)
                .unwrap()
        };
        let (c, d) = (at(claimed.id), at(dropped.id));
        let (minted_ms, expires_ms) = (
            valid.authorizations[c].minted_ms,
            valid.authorizations[c].expires_ms,
        );
        let broken: Vec<(&str, RecordBreakage)> = vec![
            (
                "a claimed record without its claim time",
                Box::new(move |w| w.authorizations[c].claimed_ms = None),
            ),
            (
                "an invalidated record with a claim time",
                Box::new(move |w| w.authorizations[d].claimed_ms = Some(T0 + 7)),
            ),
            (
                "a claim time before the mint",
                Box::new(move |w| w.authorizations[c].claimed_ms = Some(minted_ms - 1)),
            ),
            (
                "a claim time at the expiry",
                Box::new(move |w| w.authorizations[c].claimed_ms = Some(expires_ms)),
            ),
        ];
        for (name, mutate) in broken {
            let mut wire = valid.clone();
            mutate(&mut wire);
            assert!(
                matches!(validate(&wire), Err(WindowStoreError::Invalid { .. })),
                "{name}"
            );
        }
    }

    #[test]
    #[serial]
    fn a_claimed_content_refuses_a_duplicate_mint() {
        let l = Ledger::new();
        let first = l.request(tx(1), vec![]);
        let minted = l.mint(&first).unwrap();
        l.claim(&first, &minted).unwrap();
        let before = l.bytes();
        assert_eq!(
            refusal(l.mint(&l.request(tx(1), vec![]))),
            MainnetPrecondition::DuplicateOpen
        );
        assert_eq!(l.bytes(), before);
    }

    #[test]
    #[serial]
    fn claimed_records_count_toward_the_open_limit() {
        let l = Ledger::new();
        for n in 0..16u8 {
            let request = l.request(message(n), vec![]);
            let minted = l.mint(&request).unwrap();
            l.claim(&request, &minted).unwrap();
        }
        assert_eq!(
            refusal(l.mint(&l.request(message(16), vec![]))),
            MainnetPrecondition::TooManyOpen
        );
    }

    #[test]
    #[serial]
    fn a_claim_holds_to_the_lifetime_on_the_store_clock() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        l.clock.set(T0 - 1);
        assert_eq!(
            refusal(l.claim(&request, &minted)),
            MainnetPrecondition::NotYetValid
        );
        l.clock.set(minted.expires_at_ms);
        assert_eq!(
            refusal(l.claim(&request, &minted)),
            MainnetPrecondition::Expired
        );
        assert_eq!(l.bytes(), before);
        l.clock.set(minted.expires_at_ms - 1);
        assert_eq!(
            l.claim(&request, &minted).unwrap(),
            minted.expires_at_ms - 1
        );
    }

    #[test]
    #[serial]
    fn a_claim_refuses_a_mismatched_expectation() {
        type ExpectChange = fn(&mut ClaimExpect);
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        let cases: [(ExpectChange, MainnetPrecondition); 6] = [
            (
                |e| e.domain = AuthorizationDomain::Soroban,
                MainnetPrecondition::DomainMismatch,
            ),
            (
                |e| e.consumer = MainnetConsumer::X402Create,
                MainnetPrecondition::ConsumerMismatch,
            ),
            (
                |e| e.bindings_digest = [0; 32],
                MainnetPrecondition::BindingsDigest,
            ),
            (
                |e| e.policy_sequence = 8,
                MainnetPrecondition::PolicySequence,
            ),
            (
                |e| e.policy_digest = [8; 32],
                MainnetPrecondition::PolicyDigest,
            ),
            (
                |e| *e.authority.nonce_mut() = "another".to_owned(),
                MainnetPrecondition::ApprovalNonce,
            ),
        ];
        for (change, expected) in cases {
            let mut expect = l.claim_expect(&request, &minted);
            change(&mut expect);
            assert_eq!(
                refusal(l.store.claim_authorization(&l.profile, minted.id, &expect)),
                expected
            );
            assert_eq!(l.bytes(), before, "{expected:?}");
        }
        l.claim(&request, &minted).unwrap();
    }

    #[test]
    #[serial]
    fn a_claim_refuses_a_changed_policy_pin() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        l.pin(7, [8; 32]);
        assert_eq!(
            refusal(l.claim(&request, &minted)),
            MainnetPrecondition::PolicyPinMismatch
        );
        assert_eq!(l.bytes(), before);
        l.pin(7, [7; 32]);
        l.claim(&request, &minted).unwrap();
    }

    #[test]
    #[serial]
    fn a_claim_that_fails_to_persist_leaves_the_record_open() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        let armed = super::super::store::fail_store_writes();
        assert!(matches!(
            l.claim(&request, &minted),
            Err(WindowStoreError::Io { .. })
        ));
        drop(armed);
        assert_eq!(l.bytes(), before);
        let record = l.record(minted.id);
        assert_eq!(record.state, AuthorizationState::Open);
        assert_eq!(record.claimed_ms, None);
        l.claim(&request, &minted).unwrap();
        assert_eq!(l.record(minted.id).state, AuthorizationState::Claimed);
    }

    fn state_key(bucket: &str) -> StateKey {
        StateKey::new("ledger", 1, bucket, 86_400)
    }

    fn hold(amount: i128) -> WindowEntry {
        hold_in("native", amount)
    }

    fn hold_in(bucket: &str, amount: i128) -> WindowEntry {
        WindowEntry::new(
            state_key(bucket),
            T0,
            amount,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: CAP,
            },
        )
    }

    fn tx(n: u8) -> DomainBinding {
        DomainBinding::Transaction {
            unsigned_envelope_sha256: [n; 32],
            tx_hash: [n ^ 0x80; 32],
            source: SOURCE.to_owned(),
            sequence: 100 + i64::from(n),
        }
    }

    fn soroban(n: u8) -> DomainBinding {
        DomainBinding::Soroban {
            intent_digest: [n; 32],
        }
    }

    fn x402(n: u8) -> DomainBinding {
        DomainBinding::X402Submit {
            final_envelope_sha256: [n; 32],
            root_invocation_digest: [n ^ 0x40; 32],
        }
    }

    fn message(n: u8) -> DomainBinding {
        DomainBinding::Message {
            domain: MessageDomain {
                home_domain: "example.com".to_owned(),
                web_auth_domain: "auth.example.com".to_owned(),
                server_key: [3; 32],
            },
            content_digest: [n; 32],
            ephemeral_public_key: [4; 32],
        }
    }

    fn fee_inner(n: u8) -> DomainBinding {
        DomainBinding::FeeBumpInner {
            inner_tx_hash: [n; 32],
            inner_source: SOURCE.to_owned(),
            inner_sequence: 300,
            fee_source: FEE_SOURCE.to_owned(),
            max_fee: 1_000,
        }
    }

    fn fee_outer(n: u8) -> DomainBinding {
        DomainBinding::FeeBumpOuter {
            inner_tx_hash: [n; 32],
            outer_tx_hash: [n ^ 0x20; 32],
            inner_source: SOURCE.to_owned(),
            inner_sequence: 300,
            fee_source: FEE_SOURCE.to_owned(),
            max_fee: 1_000,
        }
    }

    fn fee_submit(n: u8) -> DomainBinding {
        DomainBinding::FeeBumpSubmit {
            inner_tx_hash: [n; 32],
            outer_tx_hash: [n ^ 0x20; 32],
            inner_source: SOURCE.to_owned(),
            inner_sequence: 300,
            fee_source: FEE_SOURCE.to_owned(),
            max_fee: 1_000,
            final_envelope_sha256: [n ^ 0x10; 32],
        }
    }

    /// Keeps envelope and transaction identities distinct in the fixtures.
    fn submission(
        tx_hash: [u8; 32],
        source: &str,
        sequence: i64,
        fee_bump: Option<FeeBumpFacts>,
    ) -> ConsumptionBinding {
        ConsumptionBinding::Transaction(SubmissionBinding {
            chain_scope: Some(crate::policy_state::ChainScope::for_chain(Caip2::Mainnet)),
            fee_bump,
            envelope_hash: tx_hash.map(|byte| byte ^ 0x5a),
            tx_hash,
            source: source.to_owned(),
            sequence,
            max_time: 1_800_000_300,
            pending_since_ms: T0 + 5,
            submission_ledger: 512,
            submission_anchor: None,
        })
    }

    /// The fee-bump facts of the `fee_inner(n)` and `fee_outer(n)` fixtures.
    fn fee_facts(n: u8) -> FeeBumpFacts {
        FeeBumpFacts {
            inner_tx_hash: [n; 32],
            fee_source: FEE_SOURCE.to_owned(),
            max_fee: 1_000,
        }
    }

    /// The final envelope's submission that consumes both `fee_inner(n)` and
    /// `fee_outer(n)`: the outer hash, the inner source and sequence, and the
    /// fee-bump facts.
    fn fee_bump_submission(n: u8) -> ConsumptionBinding {
        submission([n ^ 0x20; 32], SOURCE, 300, Some(fee_facts(n)))
    }

    fn fee_of(submission: &mut SubmissionBinding) -> &mut FeeBumpFacts {
        submission.fee_bump.as_mut().unwrap()
    }

    fn consumption_of(binding: &DomainBinding) -> ConsumptionBinding {
        match binding {
            DomainBinding::Transaction {
                tx_hash,
                source,
                sequence,
                ..
            } => submission(*tx_hash, source, *sequence, None),
            DomainBinding::Soroban { intent_digest } => ConsumptionBinding::RetainedIntent {
                intent_digest: *intent_digest,
            },
            DomainBinding::Message {
                domain,
                content_digest,
                ephemeral_public_key,
            } => ConsumptionBinding::Message {
                domain: domain.clone(),
                content_digest: *content_digest,
                ephemeral_public_key: *ephemeral_public_key,
            },
            other => panic!("no default consumption for {other:?}"),
        }
    }

    // ── mint ─────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn a_mint_records_the_authorization_its_holds_and_its_reservation() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(100), hold(50)]);
        let minted = l.mint(&request).unwrap();
        assert_eq!(minted.issued_at_ms, T0);
        assert_eq!(minted.expires_at_ms, T0 + TTL_MS);
        let reservation = minted.reservation.as_ref().unwrap();
        assert_eq!(reservation.id(), minted.id);
        assert_eq!(reservation.profile(), l.name());

        let wire = l.wire();
        assert_eq!(wire.version, 12);
        let record = l.record(minted.id);
        assert_eq!(record.state, AuthorizationState::Open);
        assert_eq!(record.domain, AuthorizationDomain::Transaction);
        assert_eq!(record.content_digest, tx(1).content_digest());
        assert_eq!(record.entries_digest, entries_digest(&request.holds));
        assert_eq!(record.reservation, Some(minted.id));
        assert_eq!((record.minted_ms, record.expires_ms), (T0, T0 + TTL_MS));
        assert_eq!(record.approval_expires_ms, Some(T0 + APPROVAL_MS));
        let holds: Vec<_> = wire
            .holds
            .iter()
            .map(|h| (h.authorization_id, h.ordinal, h.kind, h.amount))
            .collect();
        assert_eq!(
            holds,
            vec![
                (minted.id, 0, HoldKind::Value, 100),
                (minted.id, 1, HoldKind::Value, 50)
            ]
        );
        assert!(
            wire.entries.iter().all(|bucket| bucket.records.is_empty()),
            "holds stay outside the bucket records"
        );
        let open = l.store.open_authorizations(&l.profile, T0).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, minted.id);
    }

    #[test]
    #[serial]
    fn mint_caps_the_authorization_at_the_chain_deadline() {
        let ledger = Ledger::new();
        let mut request = ledger.request(message(1), vec![]);
        request.authorization_ttl_ms = 120_000;
        request.chain_deadline_ms = Some(T0 + 30_000);
        let minted = ledger.mint(&request).unwrap();
        assert_eq!(minted.expires_at_ms, T0 + 30_000);
        assert_eq!(ledger.record(minted.id).expires_ms, T0 + 30_000);
    }

    #[test]
    #[serial]
    fn the_lifetime_is_the_earlier_of_the_ttl_and_the_approval_expiry() {
        let l = Ledger::new();
        let mut short_approval = l.request(message(1), vec![]);
        *short_approval.authority.approval_expiry_mut() = T0 + 30_000;
        assert_eq!(l.mint(&short_approval).unwrap().expires_at_ms, T0 + 30_000);

        let longer = l.request(message(2), vec![]);
        assert_eq!(l.mint(&longer).unwrap().expires_at_ms, T0 + TTL_MS);

        let mut zero = l.request(message(3), vec![]);
        zero.authorization_ttl_ms = 0;
        assert_eq!(refusal(l.mint(&zero)), MainnetPrecondition::LifetimeInvalid);

        let mut overflow = l.request(message(4), vec![]);
        overflow.authorization_ttl_ms = u64::MAX;
        assert_eq!(
            refusal(l.mint(&overflow)),
            MainnetPrecondition::LifetimeInvalid
        );

        let mut elapsed = l.request(message(5), vec![]);
        *elapsed.authority.approval_expiry_mut() = T0;
        assert_eq!(
            refusal(l.mint(&elapsed)),
            MainnetPrecondition::LifetimeInvalid
        );
    }

    #[test]
    #[serial]
    fn a_mint_requires_the_mainnet_profile_chain() {
        let l = Ledger::new();
        let mut testnet = l.request(message(1), vec![]);
        testnet.chain = Caip2::Testnet;
        assert_eq!(
            refusal(l.mint(&testnet)),
            MainnetPrecondition::ChainNotMainnet
        );

        let mut testnet_profile = l.profile.clone();
        testnet_profile.chain_id = Caip2::Testnet;
        let request = l.request(message(2), vec![]);
        assert_eq!(
            refusal(l.store.mint_authorization(&testnet_profile, &request)),
            MainnetPrecondition::ChainMismatch
        );
        assert!(!l.store.exists(), "a refused mint writes nothing");
    }

    #[test]
    #[serial]
    fn a_mint_requires_a_present_matching_pin() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let pin_ref = PinScope::for_profile(l.store.path(), &l.profile).pin_entry_ref();
        let entry = keyring_core::Entry::new(&pin_ref.service, &pin_ref.account).unwrap();

        entry.delete_credential().unwrap();
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::PolicyPinAbsent
        );

        entry.set_password("{\"v\":1}").unwrap();
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::PolicyPinMalformed
        );

        l.pin(8, [7; 32]);
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::PolicyPinMismatch
        );
        l.pin(7, [8; 32]);
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::PolicyPinMismatch
        );
        l.pin(7, [7; 32]);
        l.mint(&request).unwrap();
    }

    #[test]
    #[serial]
    fn a_duplicate_open_content_refuses_until_the_record_settles() {
        let l = Ledger::new();
        let first = l.request(tx(1), vec![]);
        let minted = l.mint(&first).unwrap();
        let again = l.request(tx(1), vec![]);
        assert_eq!(refusal(l.mint(&again)), MainnetPrecondition::DuplicateOpen);

        // The content digest is tagged by domain: the same subject under
        // another domain is other content.
        let DomainBinding::Transaction { tx_hash, .. } = tx(1) else {
            unreachable!()
        };
        l.mint(&l.request(
            DomainBinding::Soroban {
                intent_digest: tx_hash,
            },
            vec![],
        ))
        .unwrap();

        l.consume(&first, &minted, &consumption_of(&first.binding))
            .unwrap();
        let reminted = l.mint(&again).unwrap();

        l.clock.set(reminted.expires_at_ms);
        let after_expiry = l.request(tx(1), vec![]);
        l.mint(&after_expiry).unwrap();
        assert_eq!(l.record(reminted.id).state, AuthorizationState::Expired);
    }

    #[test]
    #[serial]
    fn an_approval_nonce_is_single_use_within_retention() {
        let l = Ledger::new();
        let first = l.request(message(1), vec![]);
        let minted = l.mint(&first).unwrap();
        let mut reuse = l.request(message(2), vec![]);
        *reuse.authority.nonce_mut() = first.authority.nonce().clone();
        assert_eq!(
            refusal(l.mint(&reuse)),
            MainnetPrecondition::ApprovalNonceReused
        );
        assert!(
            l.store
                .invalidate_authorization(&l.profile, minted.id, "abandoned")
                .unwrap()
        );
        assert_eq!(
            refusal(l.mint(&reuse)),
            MainnetPrecondition::ApprovalNonceReused,
            "a settled record keeps its nonce spent"
        );
    }

    #[test]
    #[serial]
    fn approval_mint_without_a_record_keeps_its_body() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![]);
        let minted = l.mint(&request).unwrap();
        for consumed in [false, true] {
            if consumed {
                l.consume(&request, &minted, &consumption_of(&request.binding))
                    .unwrap();
            }
            let wire = l.store.read_for_inspection(&l.profile).unwrap().unwrap();
            assert_eq!(wire.version, 12);
            let body = serde_json::to_value(&wire).unwrap();
            assert!(body.get("approvals").is_none());
            assert_eq!(
                body["authorizations"][0]["state"],
                if consumed { "used" } else { "open" }
            );
        }
    }

    #[test]
    #[serial]
    fn at_most_sixteen_authorizations_are_open() {
        let l = Ledger::new();
        let mut minted = Vec::new();
        for n in 0..16u8 {
            minted.push(l.mint(&l.request(message(n), vec![])).unwrap());
        }
        let seventeenth = l.request(message(16), vec![]);
        assert_eq!(
            refusal(l.mint(&seventeenth)),
            MainnetPrecondition::TooManyOpen
        );
        l.store
            .invalidate_authorization(&l.profile, minted[0].id, "make room")
            .unwrap();
        l.mint(&seventeenth).unwrap();
    }

    #[test]
    #[serial]
    fn a_domain_without_holds_refuses_entries_and_records_no_reservation() {
        let l = Ledger::new();
        for binding in [message(1), x402(1), fee_submit(1)] {
            let mut request = l.request(binding, vec![hold(1)]);
            request.parent = (request.binding.domain() == AuthorizationDomain::X402Submit)
                .then(|| AuthorizationId::from_bytes([1; 32]));
            assert_eq!(
                refusal(l.mint(&request)),
                MainnetPrecondition::HoldsMismatch
            );
        }
        let zero_debit = l.mint(&l.request(message(2), vec![])).unwrap();
        assert!(zero_debit.reservation.is_none());
        assert_eq!(l.record(zero_debit.id).reservation, None);
        let empty_holds = l.mint(&l.request(tx(2), vec![])).unwrap();
        assert!(
            empty_holds.reservation.is_none(),
            "a holding domain with no entries reserves nothing"
        );
    }

    // ── admission and accounting ────────────────────────────────────────

    #[test]
    #[serial]
    fn holds_count_against_spend_pending_records_and_other_holds() {
        let l = Ledger::new();
        l.store
            .record_and_persist(&l.profile, &[hold(300)])
            .unwrap();
        l.store
            .record_pending(
                &l.profile,
                &[hold(200)],
                &SubmissionHold {
                    chain_scope: crate::policy_state::ChainScope::for_chain(
                        stellar_agent_core::profile::caip2::Caip2::Mainnet,
                    ),
                    id: "a".repeat(64),
                    tx_hash: "b".repeat(64),
                    source: SOURCE.to_owned(),
                    sequence: 9,
                    max_time: 0,
                    pending_since_ms: T0,
                    submission_ledger: 1,
                    submission_anchor: None,
                    operator_required: false,
                },
            )
            .unwrap();
        l.mint(&l.request(tx(1), vec![hold(300)])).unwrap();
        let over = l.request(tx(2), vec![hold(150), hold(51)]);
        assert!(
            matches!(l.mint(&over), Err(WindowStoreError::PolicyDenied { .. })),
            "300 spent, 200 pending, 300 held: 201 more exceeds 1000"
        );
        l.mint(&l.request(tx(3), vec![hold(150), hold(50)]))
            .unwrap();
        let other_bucket = l.request(tx(4), vec![hold_in("other", 1_000)]);
        l.mint(&other_bucket).unwrap();
    }

    #[test]
    #[serial]
    fn hydration_and_reconciliation_never_see_holds() {
        let l = Ledger::new();
        l.store.record_and_persist(&l.profile, &[hold(10)]).unwrap();
        let minted = l.mint(&l.request(tx(1), vec![hold(400)])).unwrap();
        let memory = PolicyStateStore::new();
        l.store.load_into("ledger", &l.profile, &memory).unwrap();
        assert_eq!(
            memory.query_window(&state_key("native"), T0).unwrap(),
            (10, 1)
        );
        assert!(l.store.pending_reservations(&l.profile).unwrap().is_empty());
        assert!(
            !l.store
                .holds_reservation(&l.profile, &minted.id.to_hex())
                .unwrap()
        );
    }

    #[test]
    #[serial]
    fn expiry_at_equality_drops_only_the_expired_holds() {
        let l = Ledger::new();
        l.store.record_and_persist(&l.profile, &[hold(5)]).unwrap();
        let mut short = l.request(tx(1), vec![hold(100)]);
        short.authorization_ttl_ms = 10_000;
        let short = (l.mint(&short).unwrap(), short);
        let long = l.mint(&l.request(tx(2), vec![hold(200)])).unwrap();

        l.clock.set(T0 + 9_999);
        let open: Vec<_> = l
            .store
            .open_authorizations(&l.profile, T0 + 9_999)
            .unwrap()
            .into_iter()
            .map(|open| open.id)
            .collect();
        assert_eq!(open, vec![short.0.id, long.id]);

        l.clock.set(T0 + 10_000);
        l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
        let wire = l.wire();
        let expired = l.record(short.0.id);
        assert_eq!(expired.state, AuthorizationState::Expired);
        assert_eq!(expired.settled_ms, Some(T0 + 10_000));
        assert_eq!(l.record(long.id).state, AuthorizationState::Open);
        assert!(wire.holds.iter().all(|h| h.authorization_id == long.id));
        assert_eq!(wire.holds.len(), 1);
        let confirmed: i128 = wire
            .entries
            .iter()
            .flat_map(|bucket| &bucket.records)
            .map(|record| record.amount)
            .sum();
        assert_eq!(confirmed, 6, "ordinary spend survives the sweep");
        assert_eq!(
            refusal(l.consume(&short.1, &short.0, &consumption_of(&short.1.binding))),
            MainnetPrecondition::NotOpen
        );
    }

    // ── consumption ─────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn a_transaction_consume_converts_its_holds_into_the_submission() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(100), hold(20)]);
        let minted = l.mint(&request).unwrap();
        l.clock.set(T0 + 50);
        let receipt = l
            .consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        assert_eq!(receipt.authorization_id, minted.id);
        assert_eq!(receipt.domain, AuthorizationDomain::Transaction);
        assert_eq!(receipt.consumed_at_ms, T0 + 50);

        let wire = l.wire();
        assert!(wire.holds.is_empty());
        let records: Vec<_> = wire.entries.iter().flat_map(|b| &b.records).collect();
        assert_eq!(records.len(), 2);
        for (record, amount) in records.iter().zip([100, 20]) {
            assert_eq!(record.amount, amount);
            assert_eq!(record.status, RecordStatus::Pending);
            assert_eq!(record.id, "db".repeat(32));
            assert_eq!(record.tx_hash, stellar_agent_core::hex::encode(&[0x81; 32]));
            assert_eq!(record.source, SOURCE);
            assert_eq!(record.sequence, 101);
            assert_eq!(record.max_time, 1_800_000_300);
            assert_eq!(record.pending_since_ms, T0 + 5);
            assert_eq!(record.submission_ledger, 512);
            assert!(!record.operator_required);
            assert_eq!(record.ts_ms, T0);
        }
        let used = l.record(minted.id);
        assert_eq!(used.state, AuthorizationState::Used);
        assert_eq!(used.settled_ms, Some(T0 + 50));
        assert_eq!(used.consumption, Some(consumption_of(&request.binding)));
        let pending = l.store.pending_reservations(&l.profile).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "db".repeat(32));

        // The consumed debit outlives the authorization's lifetime.
        l.clock.set(minted.expires_at_ms + 1);
        l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
        assert_eq!(l.store.pending_reservations(&l.profile).unwrap().len(), 1);
        assert_eq!(l.record(minted.id).state, AuthorizationState::Used);
    }

    #[test]
    #[serial]
    fn a_second_consume_refuses() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        let binding = consumption_of(&request.binding);
        l.consume(&request, &minted, &binding).unwrap();
        let before = l.bytes();
        assert_eq!(
            refusal(l.consume(&request, &minted, &binding)),
            MainnetPrecondition::NotOpen
        );
        assert_eq!(l.bytes(), before);
        assert_eq!(
            refusal(l.store.consume_authorization(
                &l.profile,
                AuthorizationId::from_bytes([0xab; 32]),
                &l.expect(&request, &minted),
                &binding,
            )),
            MainnetPrecondition::UnknownAuthorization
        );
    }

    #[test]
    #[serial]
    fn a_consume_compares_every_expectation() {
        use MainnetPrecondition as P;
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(10)]);
        let minted = l.mint(&request).unwrap();
        let binding = consumption_of(&request.binding);
        let base = l.expect(&request, &minted);
        let cases: Vec<(&str, ConsumeExpect, P)> = vec![
            (
                "profile",
                ConsumeExpect {
                    profile: "other".to_owned(),
                    ..base.clone()
                },
                P::ProfileMismatch,
            ),
            (
                "chain",
                ConsumeExpect {
                    chain: Caip2::Testnet,
                    ..base.clone()
                },
                P::ChainNotMainnet,
            ),
            (
                "domain",
                ConsumeExpect {
                    domain: AuthorizationDomain::Soroban,
                    ..base.clone()
                },
                P::DomainMismatch,
            ),
            (
                "consumer",
                ConsumeExpect {
                    consumer: MainnetConsumer::McpPay,
                    ..base.clone()
                },
                P::ConsumerMismatch,
            ),
            (
                "content",
                ConsumeExpect {
                    content_digest: [0; 32],
                    ..base.clone()
                },
                P::ContentDigest,
            ),
            (
                "binding",
                ConsumeExpect {
                    binding: tx(2),
                    ..base.clone()
                },
                P::BindingMismatch,
            ),
            (
                "policy sequence",
                ConsumeExpect {
                    policy_sequence: 8,
                    ..base.clone()
                },
                P::PolicySequence,
            ),
            (
                "policy digest",
                ConsumeExpect {
                    policy_digest: [8; 32],
                    ..base.clone()
                },
                P::PolicyDigest,
            ),
            (
                "approval nonce",
                ConsumeExpect {
                    authority: MintAuthority::Approval {
                        nonce: "other".to_owned(),
                        expires_at_ms: T0 + APPROVAL_MS,
                    },
                    ..base.clone()
                },
                P::ApprovalNonce,
            ),
            (
                "approval expiry",
                ConsumeExpect {
                    authority: MintAuthority::Approval {
                        nonce: base.authority.nonce().clone(),
                        expires_at_ms: T0 + APPROVAL_MS + 1,
                    },
                    ..base.clone()
                },
                P::ApprovalExpiry,
            ),
            (
                "reservation",
                ConsumeExpect {
                    reservation: None,
                    ..base.clone()
                },
                P::ReservationMismatch,
            ),
            (
                "entries",
                ConsumeExpect {
                    entries_digest: [0; 32],
                    ..base.clone()
                },
                P::EntriesDigest,
            ),
            (
                "bindings",
                ConsumeExpect {
                    bindings_digest: [0; 32],
                    ..base.clone()
                },
                P::BindingsDigest,
            ),
            (
                "audit path",
                ConsumeExpect {
                    fresh_audit: AuditFacts {
                        segment: [0; 32],
                        log_path_digest: [6; 32],
                        ..AUDIT
                    },
                    ..base.clone()
                },
                P::AuditLogPath,
            ),
            (
                "audit count below",
                ConsumeExpect {
                    fresh_audit: AuditFacts {
                        segment: [0; 32],
                        anchored_count: AUDIT.anchored_count - 1,
                        ..AUDIT
                    },
                    ..base.clone()
                },
                P::AuditCount,
            ),
        ];
        let before = l.bytes();
        for (name, expect, precondition) in cases {
            let result = l
                .store
                .consume_authorization(&l.profile, minted.id, &expect, &binding);
            assert_eq!(refusal(result), precondition, "{name}");
            assert_eq!(l.bytes(), before, "{name}: a refusal writes nothing");
        }
        let above = ConsumeExpect {
            fresh_audit: AuditFacts {
                segment: [0; 32],
                anchored_count: AUDIT.anchored_count + 3,
                ..AUDIT
            },
            ..base
        };
        l.store
            .consume_authorization(&l.profile, minted.id, &above, &binding)
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_consume_accepts_the_audit_count_at_equality() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_consume_checks_the_binding_against_the_domain_facts() {
        use MainnetPrecondition as P;
        let l = Ledger::new();
        let request = l.request(tx(1), vec![]);
        let minted = l.mint(&request).unwrap();
        let cases = [
            (submission([0; 32], SOURCE, 101, None), P::TxHash),
            (
                submission([0x81; 32], FEE_SOURCE, 101, None),
                P::SourceAccount,
            ),
            (submission([0x81; 32], SOURCE, 102, None), P::Sequence),
            (
                ConsumptionBinding::RetainedIntent {
                    intent_digest: [1; 32],
                },
                P::BindingMismatch,
            ),
        ];
        for (binding, precondition) in cases {
            assert_eq!(
                refusal(l.consume(&request, &minted, &binding)),
                precondition
            );
        }
        l.consume(
            &request,
            &minted,
            &submission([0x81; 32], SOURCE, 101, None),
        )
        .unwrap();

        let message_request = l.request(message(2), vec![]);
        let message_minted = l.mint(&message_request).unwrap();
        let ConsumptionBinding::Message {
            domain,
            content_digest,
            ephemeral_public_key,
        } = consumption_of(&message_request.binding)
        else {
            unreachable!()
        };
        let variants = [
            (
                MessageDomain {
                    home_domain: "other.com".to_owned(),
                    ..domain.clone()
                },
                content_digest,
                ephemeral_public_key,
                P::MessageHomeDomain,
            ),
            (
                MessageDomain {
                    web_auth_domain: "other.example.com".to_owned(),
                    ..domain.clone()
                },
                content_digest,
                ephemeral_public_key,
                P::MessageWebAuthDomain,
            ),
            (
                MessageDomain {
                    server_key: [0; 32],
                    ..domain.clone()
                },
                content_digest,
                ephemeral_public_key,
                P::MessageServerKey,
            ),
            (
                domain.clone(),
                [0; 32],
                ephemeral_public_key,
                P::MessageContent,
            ),
            (
                domain.clone(),
                content_digest,
                [0; 32],
                P::SignerKeyMismatch,
            ),
        ];
        for (domain, content_digest, ephemeral_public_key, precondition) in variants {
            let binding = ConsumptionBinding::Message {
                domain,
                content_digest,
                ephemeral_public_key,
            };
            assert_eq!(
                refusal(l.consume(&message_request, &message_minted, &binding)),
                precondition
            );
        }
    }

    #[test]
    #[serial]
    fn a_consume_rereads_the_pin_under_its_lock() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        l.pin(8, [8; 32]);
        assert_eq!(
            refusal(l.consume(&request, &minted, &consumption_of(&request.binding))),
            MainnetPrecondition::PolicyPinMismatch
        );
        l.pin(7, [7; 32]);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_consume_holds_to_the_lifetime_on_the_store_clock() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        let binding = consumption_of(&request.binding);

        l.clock.set(T0 - 1);
        assert_eq!(
            refusal(l.consume(&request, &minted, &binding)),
            MainnetPrecondition::NotYetValid
        );
        l.clock.set(minted.expires_at_ms);
        assert_eq!(
            refusal(l.consume(&request, &minted, &binding)),
            MainnetPrecondition::NotOpen,
            "the record expires at its expiry"
        );

        let live = l.request(message(2), vec![]);
        l.clock.set(T0);
        let live_minted = l.mint(&live).unwrap();
        l.clock.set(live_minted.expires_at_ms - 1);
        l.consume(&live, &live_minted, &consumption_of(&live.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_soroban_consume_retains_its_holds_as_authorized_spend() {
        let l = Ledger::new();
        let request = l.request(soroban(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        l.clock.set(T0 + 7);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        let wire = l.wire();
        assert!(wire.holds.is_empty());
        let records: Vec<_> = wire.entries.iter().flat_map(|b| &b.records).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].amount, 70);
        assert_eq!(records[0].status, RecordStatus::Confirmed);
        assert_eq!(records[0].ts_ms, T0 + 7);
        assert!(records[0].id.is_empty());
        assert!(l.store.pending_reservations(&l.profile).unwrap().is_empty());
        let memory = PolicyStateStore::new();
        l.store.load_into("ledger", &l.profile, &memory).unwrap();
        assert_eq!(
            memory.query_window(&state_key("native"), T0 + 7).unwrap(),
            (70, 1)
        );
        assert_eq!(
            refusal(l.consume(
                &request,
                &minted,
                &ConsumptionBinding::RetainedIntent {
                    intent_digest: [1; 32]
                }
            )),
            MainnetPrecondition::NotOpen
        );
    }

    // ── x402 continuation ───────────────────────────────────────────────

    /// A used Soroban intent and a continuation request for it.
    fn used_intent(l: &Ledger) -> (MintRequest, MintedRecord, MintRequest) {
        let intent = l.request(soroban(1), vec![hold(40)]);
        let minted = l.mint(&intent).unwrap();
        l.consume(&intent, &minted, &consumption_of(&intent.binding))
            .unwrap();
        let mut child = l.request(x402(1), vec![]);
        *child.authority.nonce_mut() = intent.authority.nonce().clone();
        child.parent = Some(minted.id);
        (intent, minted, child)
    }

    #[test]
    #[serial]
    fn an_x402_submission_continues_its_used_intent_once() {
        let l = Ledger::new();
        let (_intent, parent, child) = used_intent(&l);
        let minted = l.mint(&child).unwrap();
        assert!(minted.reservation.is_none());
        assert_eq!(l.record(minted.id).parent, Some(parent.id));
        let records_before: usize = l.wire().entries.iter().map(|b| b.records.len()).sum();
        let release = ConsumptionBinding::PayloadRelease {
            intent_record: Some(parent.id),
            final_envelope_sha256: [1; 32],
            root_invocation_digest: Some([1 ^ 0x40; 32]),
        };
        l.consume(&child, &minted, &release).unwrap();
        let records_after: usize = l.wire().entries.iter().map(|b| b.records.len()).sum();
        assert_eq!(records_before, records_after, "a release adds no spend");

        let mut second = l.request(x402(2), vec![]);
        *second.authority.nonce_mut() = child.authority.nonce().clone();
        second.parent = Some(parent.id);
        assert_eq!(
            refusal(l.mint(&second)),
            MainnetPrecondition::IntentRecordMismatch,
            "a parent has one child"
        );
    }

    #[test]
    #[serial]
    fn a_continuation_breaking_a_requirement_refuses() {
        use MainnetPrecondition as P;
        // The parent is used.
        {
            let l = Ledger::new();
            let intent = l.request(soroban(1), vec![]);
            let open = l.mint(&intent).unwrap();
            let mut child = l.request(x402(1), vec![]);
            *child.authority.nonce_mut() = intent.authority.nonce().clone();
            child.parent = Some(open.id);
            assert_eq!(refusal(l.mint(&child)), P::IntentRecordMismatch);
        }
        // The fields are equal.
        let mutations: [(&str, Mutation); 4] = [
            ("consumer", |c| {
                c.consumer = MainnetConsumer::X402Authenticated
            }),
            ("nonce", |c| *c.authority.nonce_mut() = "other".to_owned()),
            ("approval expiry", |c| {
                *c.authority.approval_expiry_mut() -= 1
            }),
            ("unknown parent", |c| {
                c.parent = Some(AuthorizationId::from_bytes([0xcd; 32]));
            }),
        ];
        for (name, mutate) in mutations {
            let l = Ledger::new();
            let (_, _, mut child) = used_intent(&l);
            mutate(&mut child);
            assert_eq!(refusal(l.mint(&child)), P::IntentRecordMismatch, "{name}");
        }
        // The policy is equal: the pin moves on and the child names it.
        for (sequence, digest) in [(8, [7; 32]), (7, [8; 32])] {
            let l = Ledger::new();
            let (_, _, mut child) = used_intent(&l);
            l.pin(sequence, digest);
            child.policy_sequence = sequence;
            child.policy_digest = digest;
            assert_eq!(refusal(l.mint(&child)), P::IntentRecordMismatch);
        }
        // The profile is equal.
        {
            let l = Ledger::new();
            let (_, _, child) = used_intent(&l);
            let mut other = l.profile.clone();
            other.attestation_key_id =
                stellar_agent_core::profile::schema::KeyringEntryRef::default_attestation_key(
                    "other",
                );
            other.policy_owner_key_id =
                stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key("other");
            assert_ne!(profile_name_for_approval(&other), l.name());
            assert_eq!(
                refusal(l.store.mint_authorization(&other, &child)),
                P::IntentRecordMismatch
            );
        }
        // The pair is allowed: a used transaction is no parent.
        {
            let l = Ledger::new();
            let tx_request = l.request(tx(1), vec![]);
            let used = l.mint(&tx_request).unwrap();
            l.consume(&tx_request, &used, &consumption_of(&tx_request.binding))
                .unwrap();
            let mut child = l.request(x402(1), vec![]);
            *child.authority.nonce_mut() = tx_request.authority.nonce().clone();
            child.parent = Some(used.id);
            assert_eq!(refusal(l.mint(&child)), P::IntentRecordMismatch);
        }
        // Only an x402 submission names a parent, and it always does.
        {
            let l = Ledger::new();
            let mut orphan = l.request(x402(1), vec![]);
            orphan.parent = None;
            assert_eq!(refusal(l.mint(&orphan)), P::IntentRecordMismatch);
            let mut adopted = l.request(tx(1), vec![]);
            adopted.parent = Some(AuthorizationId::from_bytes([1; 32]));
            assert_eq!(refusal(l.mint(&adopted)), P::IntentRecordMismatch);
        }
    }

    #[test]
    #[serial]
    fn a_release_checks_its_parent_and_payload() {
        use MainnetPrecondition as P;
        let l = Ledger::new();
        let (_intent, parent, child) = used_intent(&l);
        let minted = l.mint(&child).unwrap();
        let release = |intent_record, final_envelope_sha256, root_invocation_digest| {
            ConsumptionBinding::PayloadRelease {
                intent_record,
                final_envelope_sha256,
                root_invocation_digest,
            }
        };
        let cases = [
            (
                release(None, [1; 32], Some([0x41; 32])),
                P::IntentRecordMismatch,
            ),
            (
                release(Some(minted.id), [1; 32], Some([0x41; 32])),
                P::IntentRecordMismatch,
            ),
            (
                release(Some(parent.id), [2; 32], Some([0x41; 32])),
                P::FinalEnvelope,
            ),
            (release(Some(parent.id), [1; 32], None), P::RootInvocation),
            (
                release(Some(parent.id), [1; 32], Some([0; 32])),
                P::RootInvocation,
            ),
        ];
        for (binding, precondition) in cases {
            assert_eq!(refusal(l.consume(&child, &minted, &binding)), precondition);
        }
        l.consume(
            &child,
            &minted,
            &release(Some(parent.id), [1; 32], Some([0x41; 32])),
        )
        .unwrap();
    }

    // ── fee bumps and batches ───────────────────────────────────────────

    #[test]
    #[serial]
    fn the_fee_bump_roles_split_value_and_fee_holds() {
        let l = Ledger::new();
        let inner = l.request(fee_inner(1), vec![hold(100)]);
        let inner_minted = l.mint(&inner).unwrap();
        let outer = l.request(fee_outer(1), vec![hold_in("fee", 2)]);
        let outer_minted = l.mint(&outer).unwrap();
        let submit = l.request(fee_submit(1), vec![]);
        let submit_minted = l.mint(&submit).unwrap();
        assert!(submit_minted.reservation.is_none());
        let kinds: Vec<_> = l
            .wire()
            .holds
            .iter()
            .map(|h| (h.authorization_id, h.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (inner_minted.id, HoldKind::Value),
                (outer_minted.id, HoldKind::Fee)
            ]
        );

        let final_submission = fee_bump_submission(1);
        let receipts = l
            .store
            .consume_authorizations(
                &l.profile,
                &[
                    (
                        inner_minted.id,
                        l.expect(&inner, &inner_minted),
                        final_submission.clone(),
                    ),
                    (
                        outer_minted.id,
                        l.expect(&outer, &outer_minted),
                        final_submission.clone(),
                    ),
                ],
            )
            .unwrap();
        assert_eq!(receipts.len(), 2);
        let wire = l.wire();
        assert!(wire.holds.is_empty());
        let mut converted: Vec<_> = wire
            .entries
            .iter()
            .flat_map(|b| {
                b.records
                    .iter()
                    .map(move |r| (b.bucket.clone(), r.amount, r.id.clone()))
            })
            .collect();
        converted.sort();
        assert_eq!(
            converted,
            vec![
                ("fee".to_owned(), 2, "7b".repeat(32)),
                ("native".to_owned(), 100, "7b".repeat(32))
            ],
            "each owned debit converts once to the one submission"
        );
        assert_eq!(l.store.pending_reservations(&l.profile).unwrap().len(), 1);

        let release = ConsumptionBinding::PayloadRelease {
            intent_record: None,
            final_envelope_sha256: [1 ^ 0x10; 32],
            root_invocation_digest: None,
        };
        l.consume(&submit, &submit_minted, &release).unwrap();
    }

    #[test]
    #[serial]
    fn a_fee_bump_consume_checks_its_role_facts() {
        use MainnetPrecondition as P;
        let l = Ledger::new();
        let outer = l.request(fee_outer(1), vec![hold_in("fee", 2)]);
        let minted = l.mint(&outer).unwrap();
        for (binding, precondition) in [
            (
                submission([1; 32], SOURCE, 300, Some(fee_facts(1))),
                P::OuterTxHash,
            ),
            (
                submission([1 ^ 0x20; 32], FEE_SOURCE, 300, Some(fee_facts(1))),
                P::SourceAccount,
            ),
            (
                submission([1 ^ 0x20; 32], SOURCE, 301, Some(fee_facts(1))),
                P::Sequence,
            ),
        ] {
            assert_eq!(refusal(l.consume(&outer, &minted, &binding)), precondition);
        }
        let submit = l.request(fee_submit(1), vec![]);
        let submit_minted = l.mint(&submit).unwrap();
        for (binding, precondition) in [
            (
                ConsumptionBinding::PayloadRelease {
                    intent_record: Some(minted.id),
                    final_envelope_sha256: [1 ^ 0x10; 32],
                    root_invocation_digest: None,
                },
                P::IntentRecordMismatch,
            ),
            (
                ConsumptionBinding::PayloadRelease {
                    intent_record: None,
                    final_envelope_sha256: [0; 32],
                    root_invocation_digest: None,
                },
                P::FinalEnvelope,
            ),
            (
                ConsumptionBinding::PayloadRelease {
                    intent_record: None,
                    final_envelope_sha256: [1 ^ 0x10; 32],
                    root_invocation_digest: Some([0; 32]),
                },
                P::RootInvocation,
            ),
        ] {
            assert_eq!(
                refusal(l.consume(&submit, &submit_minted, &binding)),
                precondition
            );
        }
    }

    #[test]
    #[serial]
    fn a_batch_consume_is_all_or_nothing() {
        let l = Ledger::new();
        let inner = l.request(fee_inner(1), vec![hold(100)]);
        let inner_minted = l.mint(&inner).unwrap();
        let outer = l.request(fee_outer(1), vec![hold_in("fee", 2)]);
        let outer_minted = l.mint(&outer).unwrap();
        let final_submission = fee_bump_submission(1);
        let before = l.bytes();
        let wrong = ConsumeExpect {
            bindings_digest: [0; 32],
            ..l.expect(&outer, &outer_minted)
        };
        assert_eq!(
            refusal(l.store.consume_authorizations(
                &l.profile,
                &[
                    (
                        inner_minted.id,
                        l.expect(&inner, &inner_minted),
                        final_submission.clone()
                    ),
                    (outer_minted.id, wrong, final_submission.clone()),
                ],
            )),
            MainnetPrecondition::BindingsDigest
        );
        assert_eq!(l.bytes(), before, "a refused batch writes nothing");
        assert_eq!(l.record(inner_minted.id).state, AuthorizationState::Open);

        assert_eq!(
            refusal(l.store.consume_authorizations(
                &l.profile,
                &[
                    (
                        inner_minted.id,
                        l.expect(&inner, &inner_minted),
                        final_submission.clone()
                    ),
                    (
                        inner_minted.id,
                        l.expect(&inner, &inner_minted),
                        final_submission.clone()
                    ),
                ],
            )),
            MainnetPrecondition::NotOpen,
            "a record consumed twice in one batch refuses the batch"
        );
        assert_eq!(l.bytes(), before);
    }

    #[test]
    #[serial]
    fn a_consume_of_an_envelope_the_window_holds_is_a_duplicate() {
        let l = Ledger::new();
        l.store
            .record_pending(
                &l.profile,
                &[hold(1)],
                &SubmissionHold {
                    chain_scope: crate::policy_state::ChainScope::for_chain(
                        stellar_agent_core::profile::caip2::Caip2::Mainnet,
                    ),
                    id: "db".repeat(32),
                    tx_hash: "b".repeat(64),
                    source: SOURCE.to_owned(),
                    sequence: 9,
                    max_time: 0,
                    pending_since_ms: T0,
                    submission_ledger: 1,
                    submission_anchor: None,
                    operator_required: false,
                },
            )
            .unwrap();
        let request = l.request(tx(1), vec![hold(5)]);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        assert!(matches!(
            l.consume(&request, &minted, &consumption_of(&request.binding)),
            Err(WindowStoreError::DuplicateReservation)
        ));
        assert_eq!(l.bytes(), before);
    }

    /// A consumed binding preserves ownership even when it reserved no window
    /// entries. The duplicate check runs before authorization expectations.
    #[test]
    #[serial]
    fn a_consumed_envelope_without_holds_is_a_duplicate() {
        let l = Ledger::new();
        let first = l.request(tx(1), vec![]);
        let used = l.mint(&first).unwrap();
        let binding = consumption_of(&first.binding);
        l.consume(&first, &used, &binding).unwrap();
        assert!(l.store.pending_reservations(&l.profile).unwrap().is_empty());
        let mut second = l.request(tx(1), vec![]);
        *second.authority.nonce_mut() = "fresh-approval".to_owned();
        let open = l.mint(&second).unwrap();
        let before = l.bytes();
        let ConsumptionBinding::Transaction(mut different_tx_hash) = binding.clone() else {
            panic!("the fixture is a transaction");
        };
        assert_ne!(different_tx_hash.envelope_hash, different_tx_hash.tx_hash);
        different_tx_hash.tx_hash = [0xff; 32];
        for expect in [
            l.expect(&second, &open),
            ConsumeExpect {
                entries_digest: [0xff; 32],
                ..l.expect(&second, &open)
            },
        ] {
            for duplicate in [
                binding.clone(),
                ConsumptionBinding::Transaction(different_tx_hash.clone()),
            ] {
                assert!(matches!(
                    l.store
                        .consume_authorization(&l.profile, open.id, &expect, &duplicate),
                    Err(WindowStoreError::DuplicateConsumption)
                ));
                assert_eq!(l.bytes(), before, "a duplicate writes nothing");
                assert_eq!(l.record(used.id).state, AuthorizationState::Used);
                assert_eq!(l.record(open.id).state, AuthorizationState::Open);
            }
        }
        let fresh = l.request(tx(2), vec![]);
        let minted = l.mint(&fresh).unwrap();
        let fresh_binding = consumption_of(&fresh.binding);
        l.consume(&fresh, &minted, &fresh_binding).unwrap();
        assert_eq!(l.record(minted.id).state, AuthorizationState::Used);
    }

    // ── contention, invalidation, pruning, versions ─────────────────────

    #[test]
    #[serial]
    fn concurrent_mints_of_one_content_yield_one_open_record() {
        let l = Ledger::new();
        let first = l.request(tx(1), vec![hold(1)]);
        let second = l.request(tx(1), vec![hold(1)]);
        let (store, profile) = (&l.store, &l.profile);
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| store.mint_authorization(profile, &first).map(|m| m.id));
            let b = scope.spawn(|| store.mint_authorization(profile, &second).map(|m| m.id));
            [a.join().unwrap(), b.join().unwrap()]
        });
        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "{results:?}");
        for (request, result) in [&first, &second].into_iter().zip(&results) {
            if let Err(error) = result {
                assert!(
                    matches!(
                        error,
                        WindowStoreError::WriterLocked
                            | WindowStoreError::AuthorizationRefused {
                                precondition: MainnetPrecondition::DuplicateOpen
                            }
                    ),
                    "{error:?}"
                );
                assert_eq!(refusal(l.mint(request)), MainnetPrecondition::DuplicateOpen);
            }
        }
        assert_eq!(
            l.store.open_authorizations(&l.profile, T0).unwrap().len(),
            1
        );
    }

    #[test]
    #[serial]
    fn an_invalidation_releases_the_holds_and_never_reopens() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(100)]);
        let minted = l.mint(&request).unwrap();
        let reason = "r".repeat(300);
        assert!(
            l.store
                .invalidate_authorization(&l.profile, minted.id, &reason)
                .unwrap()
        );
        let record = l.record(minted.id);
        assert_eq!(record.state, AuthorizationState::Invalidated);
        assert_eq!(record.invalidation.as_deref().map(str::len), Some(128));
        assert!(l.wire().holds.is_empty());
        let before = l.bytes();
        assert!(
            !l.store
                .invalidate_authorization(&l.profile, minted.id, "again")
                .unwrap()
        );
        assert_eq!(l.bytes(), before);

        let used_request = l.request(message(1), vec![]);
        let used = l.mint(&used_request).unwrap();
        l.consume(&used_request, &used, &consumption_of(&used_request.binding))
            .unwrap();
        assert!(
            !l.store
                .invalidate_authorization(&l.profile, used.id, "late")
                .unwrap()
        );
        assert_eq!(l.record(used.id).state, AuthorizationState::Used);
        assert_eq!(
            refusal(l.store.invalidate_authorization(
                &l.profile,
                AuthorizationId::from_bytes([0xab; 32]),
                "unknown"
            )),
            MainnetPrecondition::UnknownAuthorization
        );
    }

    #[test]
    #[serial]
    fn settled_history_is_pruned_after_retention_and_the_version_follows() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        assert_eq!(l.wire().version, 12, "settled history retains its scope");

        l.clock.set(T0 + RETENTION_MS);
        l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
        assert_eq!(l.wire().authorizations.len(), 1, "inside retention");

        l.clock.set(T0 + RETENTION_MS + 1);
        let mut late = hold(1);
        late = WindowEntry::new(
            late.key().clone(),
            T0 + RETENTION_MS + 1,
            1,
            late.limit().clone(),
        );
        l.store.record_and_persist(&l.profile, &[late]).unwrap();
        let wire = l.wire();
        assert!(wire.authorizations.is_empty());
        assert_eq!(
            wire.version, 12,
            "pruning retains authenticated network scope"
        );
        let body: serde_json::Value = serde_json::from_slice(&l.bytes()[32..]).unwrap();
        assert!(body.get("authorizations").is_none());
        assert!(body.get("holds").is_none());
    }

    #[test]
    fn pruning_never_drops_an_open_record() {
        let mut wire = WireFile {
            version: 4,
            ..WireFile::default()
        };
        let open = sample(AuthorizationState::Open, 0, None);
        let old_settled = sample(AuthorizationState::Expired, 0, Some(5));
        let recent_settled = sample(AuthorizationState::Expired, 0, Some(100));
        wire.authorizations = vec![open.clone(), old_settled, recent_settled.clone()];
        prune_history(&mut wire, 100, 1_000);
        assert_eq!(
            wire.authorizations,
            vec![open.clone(), recent_settled.clone()]
        );

        // An old settlement stays while its approval can still be presented,
        // and goes once the approval ends at the pruning time.
        let mut presentable = sample(AuthorizationState::Expired, 3, Some(5));
        presentable.approval_expires_ms = Some(1_001);
        let mut ended = presentable.clone();
        ended.approval_expires_ms = Some(1_000);
        for (old, kept) in [(presentable.clone(), true), (ended, false)] {
            wire.authorizations = vec![open.clone(), old.clone(), recent_settled.clone()];
            prune_history(&mut wire, 100, 1_000);
            let expected = if kept {
                vec![open.clone(), old, recent_settled.clone()]
            } else {
                vec![open.clone(), recent_settled.clone()]
            };
            assert_eq!(wire.authorizations, expected);
        }
    }

    // ── window state reset retention ────────────────────────────────────

    /// How a reset keeps a record.
    #[derive(Debug, Clone, Copy)]
    enum Kept {
        /// Equal to the record before the reset.
        Unchanged,
        /// Expired and settled at the store clock, unused, with an `Always`
        /// release row.
        Settled,
        /// Expired and settled at the store clock after a claim, without a
        /// disposition.
        SettledClaimed,
    }

    /// A mint of another binding that copies `request`'s approval nonce.
    fn nonce_copy(l: &Ledger, request: &MintRequest) -> MintRequest {
        let mut reuse = l.request(tx(2), vec![hold(1)]);
        *reuse.authority.nonce_mut() = request.authority.nonce().clone();
        reuse
    }

    /// A reset keeps every record whose approval can still be presented on
    /// the store clock, so its nonce stays single use. A record that holds
    /// capacity becomes expired; the mainnet rules refuse while it is open.
    #[test]
    #[serial]
    fn a_reset_keeps_every_record_whose_approval_can_be_presented() {
        type Setup = fn(&Ledger) -> (MintRequest, AuthorizationId);
        let used: Setup = |l| {
            let request = l.request(soroban(1), vec![hold(70)]);
            let minted = l.mint(&request).unwrap();
            l.clock.set(T0 + 5);
            l.claim(&request, &minted).unwrap();
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
            (request, minted.id)
        };
        let invalidated: Setup = |l| {
            let request = l.request(tx(1), vec![hold(70)]);
            let minted = l.mint(&request).unwrap();
            l.store
                .invalidate_authorization(&l.profile, minted.id, "cancel")
                .unwrap();
            (request, minted.id)
        };
        let open: Setup = |l| {
            let request = l.request(tx(1), vec![hold(70)]);
            let minted = l.mint(&request).unwrap();
            (request, minted.id)
        };
        let claimed: Setup = |l| {
            let request = l.request(tx(1), vec![hold(70)]);
            let minted = l.mint(&request).unwrap();
            l.clock.set(T0 + 7);
            l.claim(&request, &minted).unwrap();
            (request, minted.id)
        };
        let cases: [(&str, Setup, u64, Kept, bool); 5] = [
            ("used", used, T0 + 10_000, Kept::Unchanged, false),
            (
                "invalidated",
                invalidated,
                T0 + 10_000,
                Kept::Unchanged,
                false,
            ),
            ("expired", open, T0 + TTL_MS, Kept::Settled, false),
            ("open", open, T0 + 10_000, Kept::Settled, true),
            ("claimed", claimed, T0 + 10_000, Kept::SettledClaimed, true),
        ];
        for (name, setup, clock, kept, holds_capacity) in cases {
            let l = Ledger::new();
            let (request, id) = setup(&l);
            l.clock.set(clock);
            let before = l.record(id);
            let bytes = l.bytes();
            let result = l.reset(T0 + APPROVAL_MS + 1);
            if holds_capacity && cfg!(feature = "mainnet-write") {
                #[cfg(feature = "mainnet-write")]
                assert!(
                    matches!(
                        result,
                        Err(ResetError::Store {
                            error: WindowStoreError::OpenAuthorizations { open: 1 },
                            minted: false,
                        })
                    ),
                    "{name}: {result:?}"
                );
                assert_eq!(l.bytes(), bytes, "{name}");
                continue;
            }
            let outcome = result.unwrap();
            assert_eq!(outcome.accrual.retained_authorizations, 1, "{name}");
            let wire = l.wire();
            assert!(wire.entries.is_empty(), "{name}");
            assert!(wire.holds.is_empty(), "{name}");
            let expected = match kept {
                Kept::Unchanged => before,
                Kept::Settled => WireAuthorization {
                    state: AuthorizationState::Expired,
                    settled_ms: Some(clock),
                    disposition: Some(Disposition::Unused),
                    native_release: Some(ReleaseRow::always(
                        ReleaseClass::ProvedUnspent,
                        wire.authorizations[0].native_release.unwrap().commit_id,
                    )),
                    ..before
                },
                Kept::SettledClaimed => WireAuthorization {
                    state: AuthorizationState::Expired,
                    settled_ms: Some(clock),
                    ..before
                },
            };
            assert_eq!(wire.authorizations, vec![expected], "{name}");
            assert_eq!(
                refusal(l.mint(&nonce_copy(&l, &request))),
                MainnetPrecondition::ApprovalNonceReused,
                "{name}"
            );
        }
    }

    /// A record whose approval ends at or before the store clock does not
    /// survive the reset, and the store clock, not the caller's, decides.
    #[test]
    #[serial]
    fn a_reset_drops_records_whose_approval_expired() {
        for (clock, kept) in [(T0 + APPROVAL_MS, 0), (T0 + APPROVAL_MS - 1, 1)] {
            let l = Ledger::new();
            let request = l.request(soroban(1), vec![hold(70)]);
            let minted = l.mint(&request).unwrap();
            l.clock.set(T0 + 5);
            l.claim(&request, &minted).unwrap();
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
            l.clock.set(clock);
            let outcome = l.reset(T0).unwrap();
            assert_eq!(outcome.accrual.retained_authorizations, kept, "{clock}");
            let wire = l.wire();
            assert_eq!(wire.authorizations.len(), kept as usize, "{clock}");
            if kept == 0 {
                let mut again = l.request(soroban(2), vec![]);
                *again.authority.nonce_mut() = request.authority.nonce().clone();
                assert_eq!(
                    refusal(l.mint(&again)),
                    MainnetPrecondition::LifetimeInvalid
                );
            } else {
                assert_eq!(wire.authorizations[0].id, minted.id);
            }
        }
    }

    /// A record minted ahead of the store clock is settled at the reset, and
    /// pruning keeps it while its approval can still be presented, even when
    /// the settlement lies before its retention window.
    #[test]
    #[serial]
    fn a_reset_settles_a_record_minted_ahead_of_the_store_clock() {
        let l = Ledger::new();
        let mut request = l.request(tx(1), vec![hold(70)]);
        *request.authority.approval_expiry_mut() = T0 + RETENTION_MS;
        let minted = l.mint(&request).unwrap();
        l.clock.set(T0 - 1_000);
        let outcome = l.reset(T0 - 1_000).unwrap();
        assert_eq!(outcome.accrual.retained_authorizations, 1);
        let wire = l.wire();
        assert!(wire.holds.is_empty());
        let [kept] = wire.authorizations.as_slice() else {
            panic!("one kept record: {:?}", wire.authorizations);
        };
        assert_eq!(kept.id, minted.id);
        assert_eq!(kept.state, AuthorizationState::Expired);
        assert_eq!(kept.settled_ms, Some(T0 - 1_000));

        let late_ms = T0 + RETENTION_MS - 500;
        l.clock.set(late_ms);
        let late = hold(1);
        let late = WindowEntry::new(late.key().clone(), late_ms, 1, late.limit().clone());
        l.store.record_and_persist(&l.profile, &[late]).unwrap();
        assert_eq!(
            l.wire()
                .authorizations
                .iter()
                .map(|auth| auth.id)
                .collect::<Vec<_>>(),
            vec![minted.id],
            "pruning keeps a record whose approval can still be presented"
        );
        let mut reuse = nonce_copy(&l, &request);
        *reuse.authority.approval_expiry_mut() = request.authority.expires_at_ms();
        assert_eq!(
            refusal(l.mint(&reuse)),
            MainnetPrecondition::ApprovalNonceReused
        );
    }

    /// A reset keeps a used intent and its child, so the intent continues
    /// once.
    #[test]
    #[serial]
    fn a_reset_keeps_a_continued_intent_and_its_child() {
        let l = Ledger::new();
        let (_intent, parent, child) = used_intent(&l);
        let minted = l.mint(&child).unwrap();
        let release = ConsumptionBinding::PayloadRelease {
            intent_record: Some(parent.id),
            final_envelope_sha256: [1; 32],
            root_invocation_digest: Some([1 ^ 0x40; 32]),
        };
        l.consume(&child, &minted, &release).unwrap();
        let parent_before = l.record(parent.id);
        let child_before = l.record(minted.id);
        l.clock.set(T0 + 10_000);
        l.reset(T0 + 10_000).unwrap();
        let find = |id: AuthorizationId| {
            l.wire()
                .authorizations
                .into_iter()
                .find(|auth| auth.id == id)
        };
        assert_eq!(find(parent.id), Some(parent_before));
        let mut second = l.request(x402(2), vec![]);
        *second.authority.nonce_mut() = child.authority.nonce().clone();
        second.parent = Some(parent.id);
        assert_eq!(
            refusal(l.mint(&second)),
            MainnetPrecondition::IntentRecordMismatch,
            "a parent has one child across the reset"
        );
        assert_eq!(find(minted.id), Some(child_before));
    }

    /// A reset keeps the acknowledged, unprojected expiry records and the
    /// presentable authorization records together.
    #[test]
    #[serial]
    fn a_reset_keeps_both_retained_collections() {
        let l = Ledger::new();
        l.owe_expiry();
        let mut writer = l.delivery_writer();
        deliver_accounting_expiries(&mut writer, &l.store, &l.profile, &l.name(), None).unwrap();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        let before = l.wire();
        let [expiry] = before.accounting_expiries.as_slice() else {
            panic!("one expiry record: {:?}", before.accounting_expiries);
        };
        let flags = serde_json::to_value(expiry).unwrap();
        assert_eq!(flags["audit_acknowledged"], true, "{flags}");
        assert_eq!(flags["receipt_projected"], false, "{flags}");
        let used = l.record(minted.id);
        l.clock.set(T0 + 10_000);
        let outcome = l.reset(T0 + 10_000).unwrap();
        assert_eq!(outcome.accrual.retained_authorizations, 1);
        let wire = l.wire();
        assert_eq!(wire.accounting_expiries, before.accounting_expiries);
        assert_eq!(wire.authorizations, vec![used]);
        assert_eq!(
            refusal(l.mint(&nonce_copy(&l, &request))),
            MainnetPrecondition::ApprovalNonceReused
        );
    }

    /// The owed expiry refuses first, the open authorization second, and the
    /// owner consent only after both: `authorize` runs only in the third
    /// reset and `record` never runs.
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial]
    fn the_snapshot_refusals_precede_the_owner_consent() {
        let l = Ledger::new();
        let nonce = stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
            &l.profile.policy_window_state_key_id,
        );
        keyring_core::Entry::new(&nonce.service, &nonce.account)
            .unwrap()
            .set_password("enablement-nonce")
            .unwrap();
        l.owe_expiry();
        let request = l.request(tx(1), vec![hold(70)]);
        let minted = l.mint(&request).unwrap();
        l.clock.set(T0 + 7);
        l.claim(&request, &minted).unwrap();
        let authorized = Cell::new(0);
        let recorded = Cell::new(0);
        let attempt = || match l.store.reset(
            &l.profile,
            &l.name(),
            T0 + 7,
            "repair",
            "reset-request",
            |_| {
                authorized.set(authorized.get() + 1);
                Ok::<_, ()>(ResetConsent::default())
            },
            |_, _| {
                recorded.set(recorded.get() + 1);
                Ok(())
            },
        ) {
            Err(ResetError::Store {
                error,
                minted: false,
            }) => error,
            other => panic!("expected a refusal without minting: {other:?}"),
        };

        let first = attempt();
        assert!(
            matches!(first, WindowStoreError::AccountingAuditOwed),
            "{first:?}"
        );
        let mut writer = l.delivery_writer();
        deliver_accounting_expiries(&mut writer, &l.store, &l.profile, &l.name(), None).unwrap();
        let delivered = l.bytes();
        let expiries = l.wire().accounting_expiries;
        assert!(
            expiries.iter().all(|record| {
                serde_json::to_value(record).unwrap()["audit_acknowledged"] == true
            })
        );

        let second = attempt();
        assert!(
            matches!(second, WindowStoreError::OpenAuthorizations { open: 1 }),
            "{second:?}"
        );
        assert_eq!(authorized.get(), 0);

        l.clock.set(T0 + TTL_MS);
        let third = attempt();
        assert!(
            matches!(third, WindowStoreError::ResetOwnerRequired),
            "{third:?}"
        );
        assert_eq!(authorized.get(), 1);
        assert_eq!(recorded.get(), 0);
        assert_eq!(l.bytes(), delivered);
        assert_eq!(l.wire().accounting_expiries, expiries);
    }

    #[test]
    fn the_sweep_marks_expiry_at_equality_and_keeps_history() {
        let mut wire = WireFile {
            version: 4,
            ..WireFile::default()
        };
        let mut due = sample(AuthorizationState::Open, 1, None);
        due.expires_ms = 50;
        due.reservation = Some(due.id);
        let mut later = sample(AuthorizationState::Open, 2, None);
        later.expires_ms = 51;
        later.reservation = Some(later.id);
        wire.holds = vec![sample_hold(due.id, 0), sample_hold(later.id, 0)];
        wire.authorizations = vec![due.clone(), later.clone()];
        assert!(!sweep_expired(&mut wire, 49));
        assert!(sweep_expired(&mut wire, 50));
        assert_eq!(wire.authorizations[0].state, AuthorizationState::Expired);
        assert_eq!(wire.authorizations[0].settled_ms, Some(50));
        assert_eq!(wire.authorizations[1].state, AuthorizationState::Open);
        assert_eq!(wire.holds, vec![sample_hold(later.id, 0)]);
        validate(&wire).unwrap();
    }

    fn sample(state: AuthorizationState, n: u8, settled_ms: Option<u64>) -> WireAuthorization {
        let binding = tx(n);
        WireAuthorization {
            id: AuthorizationId::from_bytes([n.wrapping_add(0x60); 32]),
            profile: "ledger".to_owned(),
            chain: Caip2::Mainnet,
            domain: AuthorizationDomain::Transaction,
            consumer: MainnetConsumer::CliPay,
            content_digest: binding.content_digest(),
            binding,
            state,
            minted_ms: 0,
            expires_ms: 1_000,
            settled_ms,
            claimed_ms: None,
            policy_sequence: 7,
            policy_digest: [7; 32],
            approval_nonce: Some(format!("n{n}")),
            approval_expires_ms: Some(1_000),
            policy_authority: None,
            bindings_digest: [9; 32],
            entries_digest: entries_digest(&[]),
            reservation: None,
            parent: None,
            consumption: None,
            invalidation: None,
            operation: None,
            disposition: None,
            native_release: None,
            native_reservation: None,
        }
    }

    fn sample_hold(id: AuthorizationId, ordinal: u32) -> WireAuthorizationHold {
        WireAuthorizationHold {
            kind: HoldKind::Value,
            authorization_id: id,
            ordinal,
            scope_specificity: 1,
            bucket: "native".to_owned(),
            window_secs: 86_400,
            ts_ms: 0,
            amount: 1,
            epoch: None,
        }
    }

    #[test]
    fn reading_refuses_every_broken_ledger_invariant() {
        let mut held = sample(AuthorizationState::Open, 1, None);
        held.reservation = Some(held.id);
        let valid = WireFile {
            version: 4,
            authorizations: vec![
                held.clone(),
                sample(AuthorizationState::Expired, 2, Some(9)),
            ],
            holds: vec![sample_hold(held.id, 0), sample_hold(held.id, 1)],
            ..WireFile::default()
        };
        validate(&valid).unwrap();
        validate(&WireFile {
            version: 4,
            ..WireFile::default()
        })
        .unwrap();

        let broken: Vec<(&str, Breakage)> = vec![
            ("history below version 4", |w| w.version = 3),
            ("repeated identity", |w| {
                let copy = w.authorizations[1].clone();
                w.authorizations.push(copy);
            }),
            ("content not of its facts", |w| {
                w.authorizations[1].content_digest = [0; 32];
            }),
            ("domain not of its facts", |w| {
                w.authorizations[1].domain = AuthorizationDomain::Soroban;
            }),
            ("open with a settlement time", |w| {
                w.authorizations[0].settled_ms = Some(1);
            }),
            ("settled without a settlement time", |w| {
                w.authorizations[1].settled_ms = None;
            }),
            ("used without its consumption", |w| {
                w.authorizations[1].state = AuthorizationState::Used;
            }),
            ("a reservation other than its own", |w| {
                w.authorizations[0].reservation = Some(AuthorizationId::from_bytes([0; 32]));
            }),
            ("a reservation on a domain without holds", |w| {
                let mut message_record = w.authorizations[1].clone();
                message_record.binding = message(1);
                message_record.domain = AuthorizationDomain::Message;
                message_record.content_digest = message(1).content_digest();
                message_record.reservation = Some(message_record.id);
                w.authorizations[1] = message_record;
            }),
            ("a parent outside an x402 submission", |w| {
                w.authorizations[1].parent = Some(AuthorizationId::from_bytes([1; 32]));
            }),
            ("an authenticated intent without a parent", |w| {
                w.authorizations[1] = authenticated_intent_record(&w.authorizations[1], None);
            }),
            ("a message record with a parent", |w| {
                let mut message_record = w.authorizations[1].clone();
                message_record.binding = message(1);
                message_record.domain = AuthorizationDomain::Message;
                message_record.content_digest = message(1).content_digest();
                message_record.consumer = MainnetConsumer::X402Authenticated;
                message_record.parent = Some(AuthorizationId::from_bytes([1; 32]));
                w.authorizations[1] = message_record;
            }),
            ("a repeated hold", |w| {
                let copy = w.holds[0].clone();
                w.holds.push(copy);
            }),
            ("a hold of no authorization", |w| {
                w.holds[0].authorization_id = AuthorizationId::from_bytes([0; 32]);
            }),
            ("a hold of settled history", |w| {
                let settled = w.authorizations[1].id;
                let mut extra = w.holds[0].clone();
                extra.authorization_id = settled;
                w.holds.push(extra);
            }),
            ("a hold of the wrong kind", |w| {
                w.holds[0].kind = HoldKind::Fee
            }),
            ("an open reservation without holds", |w| w.holds.clear()),
            ("holds without a reservation", |w| {
                w.authorizations[0].reservation = None;
            }),
        ];
        for (name, mutate) in broken {
            let mut wire = valid.clone();
            mutate(&mut wire);
            assert!(
                matches!(validate(&wire), Err(WindowStoreError::Invalid { .. })),
                "{name}"
            );
        }
    }

    #[test]
    #[serial]
    fn open_authorizations_reads_without_writing() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        let used_request = l.request(message(2), vec![]);
        let used = l.mint(&used_request).unwrap();
        l.consume(&used_request, &used, &consumption_of(&used_request.binding))
            .unwrap();
        let before = l.bytes();
        let open = l.store.open_authorizations(&l.profile, T0).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, minted.id);
        assert_eq!(open[0].domain, AuthorizationDomain::Message);
        assert_eq!(open[0].consumer, MainnetConsumer::X402Authenticated);
        assert_eq!(
            (open[0].minted_at_ms, open[0].expires_at_ms),
            (T0, minted.expires_at_ms)
        );
        assert!(
            l.store
                .open_authorizations(&l.profile, minted.expires_at_ms)
                .unwrap()
                .is_empty()
        );
        assert_eq!(l.bytes(), before, "inspection writes nothing");
    }

    #[test]
    fn the_reservation_fact_digest_is_frozen() {
        let reservation =
            WindowReservation::for_crate_tests(AuthorizationId::from_bytes([0x2a; 32]), "ledger");
        assert_eq!(
            stellar_agent_core::hex::encode(&reservation.fact_digest()),
            "e7204387d43c1802d68094adce78ad2f0e33c54a6f77a7021aa51724f62e59a4"
        );
    }

    #[test]
    #[serial]
    fn mint_computes_the_reservation_aggregate() {
        let l = Ledger::new();
        for holds in [vec![hold(1)], vec![]] {
            let request = l.request(tx(holds.len() as u8), holds);
            let minted = l.mint(&request).unwrap();
            let mut facts = request.bindings;
            facts.reservation = minted
                .reservation
                .as_ref()
                .map(WindowReservation::fact_digest);
            assert_eq!(minted.bindings_digest, bindings_digest(&facts));
            assert_eq!(l.record(minted.id).bindings_digest, bindings_digest(&facts));
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
        }
    }

    #[test]
    #[serial]
    fn mint_refuses_a_supplied_reservation() {
        let l = Ledger::new();
        let mut request = l.request(tx(1), vec![hold(1)]);
        request.bindings.reservation = Some([1; 32]);
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::ReservationMismatch
        );
        assert!(!l.store.path().exists());
        request.bindings.reservation = None;
        l.mint(&request).unwrap();
    }

    #[test]
    #[serial]
    fn an_absent_pin_mints_no_window_key() {
        let l = Ledger::new();
        let pin = PinScope::for_profile(l.store.path(), &l.profile).pin_entry_ref();
        keyring_core::Entry::new(&pin.service, &pin.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let request = l.request(tx(1), vec![]);
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::PolicyPinAbsent
        );
        assert_eq!(
            crate::keyring::read_keyring_string(&l.profile.policy_window_state_key_id).unwrap(),
            None
        );
        assert!(!l.store.path().exists());
        l.pin(7, [7; 32]);
        l.mint(&request).unwrap();
        assert!(
            crate::keyring::read_keyring_string(&l.profile.policy_window_state_key_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    #[serial]
    fn a_future_hold_refuses_before_key_creation() {
        let l = Ledger::new();
        let skew = CLOCK_SKEW_TOLERANCE_MS;
        let entry = |ts| {
            WindowEntry::new(
                StateKey::new("ledger", 1, "native", 86_400),
                ts,
                1,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: CAP,
                },
            )
        };
        let mut request = l.request(tx(1), vec![entry(T0 + skew + 1)]);
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::HoldsMismatch
        );
        assert_eq!(
            crate::keyring::read_keyring_string(&l.profile.policy_window_state_key_id).unwrap(),
            None,
            "the refusal precedes the window key"
        );
        assert!(!l.store.path().exists());
        request.holds = vec![entry(T0 + skew)];
        l.mint(&request).unwrap();
    }

    #[test]
    #[serial]
    fn soroban_mint_requires_an_x402_consumer() {
        let l = Ledger::new();
        for consumer in [
            MainnetConsumer::X402Create,
            MainnetConsumer::X402Authenticated,
        ] {
            let mut request = l.request(
                DomainBinding::Soroban {
                    intent_digest: [consumer as u8; 32],
                },
                vec![],
            );
            request.consumer = MainnetConsumer::CliPay;
            let before = l.store.path().exists().then(|| l.bytes());
            assert_eq!(
                refusal(l.mint(&request)),
                MainnetPrecondition::ConsumerMismatch
            );
            assert_eq!(l.store.path().exists().then(|| l.bytes()), before);
            request.consumer = consumer;
            if consumer == MainnetConsumer::X402Authenticated {
                // An authenticated intent continues its used message record.
                assert_eq!(
                    refusal(l.mint(&request)),
                    MainnetPrecondition::IntentRecordMismatch
                );
                let (message_request, parent) = used_message(&l);
                *request.authority.nonce_mut() = message_request.authority.nonce().clone();
                request.parent = Some(parent.id);
            }
            l.mint(&request).unwrap();
        }
    }

    /// A used message record whose approval an authenticated intent shares.
    fn used_message(l: &Ledger) -> (MintRequest, MintedRecord) {
        let request = l.request(message(0x40), vec![]);
        let minted = l.mint(&request).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        (request, minted)
    }

    /// An authenticated Soroban intent request continuing `parent`, the used
    /// message record of `message_request`.
    fn authenticated_child(
        l: &Ledger,
        message_request: &MintRequest,
        parent: &MintedRecord,
        n: u8,
    ) -> MintRequest {
        let mut child = l.request(soroban(n), vec![hold(40)]);
        child.consumer = MainnetConsumer::X402Authenticated;
        *child.authority.nonce_mut() = message_request.authority.nonce().clone();
        child.parent = Some(parent.id);
        child
    }

    /// `record` as a settled authenticated Soroban intent naming `parent`.
    fn authenticated_intent_record(
        record: &WireAuthorization,
        parent: Option<AuthorizationId>,
    ) -> WireAuthorization {
        let mut intent = record.clone();
        intent.binding = soroban(1);
        intent.domain = AuthorizationDomain::Soroban;
        intent.content_digest = soroban(1).content_digest();
        intent.consumer = MainnetConsumer::X402Authenticated;
        intent.parent = parent;
        intent
    }

    /// A snapshot with an authenticated intent that names its parent is
    /// valid; the invariant breakage above is the parent's absence alone.
    #[test]
    fn an_authenticated_intent_with_its_parent_reads() {
        let mut wire = WireFile {
            version: 4,
            authorizations: vec![sample(AuthorizationState::Expired, 2, Some(9))],
            ..WireFile::default()
        };
        wire.authorizations[0] = authenticated_intent_record(
            &wire.authorizations[0],
            Some(AuthorizationId::from_bytes([1; 32])),
        );
        validate(&wire).unwrap();
    }

    #[test]
    #[serial]
    fn a_message_record_is_minted_only_for_the_authenticated_consumer() {
        let l = Ledger::new();
        let mut request = l.request(message(1), vec![]);
        request.consumer = MainnetConsumer::CliPay;
        let before = l.store.path().exists().then(|| l.bytes());
        assert_eq!(
            refusal(l.mint(&request)),
            MainnetPrecondition::ConsumerMismatch
        );
        assert_eq!(l.store.path().exists().then(|| l.bytes()), before);
        request.consumer = MainnetConsumer::X402Authenticated;
        l.mint(&request).unwrap();
    }

    #[test]
    #[serial]
    fn an_authenticated_intent_continues_its_used_message_once() {
        let l = Ledger::new();
        let (message_request, parent) = used_message(&l);
        let child = authenticated_child(&l, &message_request, &parent, 1);
        let minted = l.mint(&child).unwrap();
        assert_eq!(l.record(minted.id).parent, Some(parent.id));
        assert_eq!(l.record(parent.id).state, AuthorizationState::Used);
    }

    #[test]
    #[serial]
    fn an_authenticated_continuation_breaking_a_requirement_refuses() {
        use MainnetPrecondition as P;
        let assert_unchanged_refusal = |l: &Ledger, request: &MintRequest, name: &str| {
            let before = l.bytes();
            assert_eq!(refusal(l.mint(request)), P::IntentRecordMismatch, "{name}");
            assert_eq!(l.bytes(), before, "{name}");
        };
        // An authenticated intent always names a parent.
        {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let mut child = authenticated_child(&l, &message_request, &parent, 1);
            child.parent = None;
            assert_unchanged_refusal(&l, &child, "no parent");
        }
        // The parent is used.
        {
            let l = Ledger::new();
            let message_request = l.request(message(0x40), vec![]);
            let open = l.mint(&message_request).unwrap();
            let child = authenticated_child(&l, &message_request, &open, 1);
            assert_unchanged_refusal(&l, &child, "open parent");
        }
        // The fields are equal.
        let mutations: [(&str, Mutation); 2] = [
            ("nonce", |c| *c.authority.nonce_mut() = "other".to_owned()),
            ("approval expiry", |c| {
                *c.authority.approval_expiry_mut() -= 1
            }),
        ];
        for (name, mutate) in mutations {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let mut child = authenticated_child(&l, &message_request, &parent, 1);
            mutate(&mut child);
            assert_unchanged_refusal(&l, &child, name);
        }
        // The profile is equal.
        {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let child = authenticated_child(&l, &message_request, &parent, 1);
            let mut other = l.profile.clone();
            other.attestation_key_id =
                stellar_agent_core::profile::schema::KeyringEntryRef::default_attestation_key(
                    "other",
                );
            other.policy_owner_key_id =
                stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key("other");
            assert_ne!(profile_name_for_approval(&other), l.name());
            let before = l.bytes();
            assert_eq!(
                refusal(l.store.mint_authorization(&other, &child)),
                P::IntentRecordMismatch
            );
            assert_eq!(l.bytes(), before);
        }
        // The policy is equal: the pin moves on and the child names it.
        for (sequence, digest) in [(8, [7; 32]), (7, [8; 32])] {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let mut child = authenticated_child(&l, &message_request, &parent, 1);
            l.pin(sequence, digest);
            child.policy_sequence = sequence;
            child.policy_digest = digest;
            assert_unchanged_refusal(&l, &child, "policy");
        }
        // A parent has one child, whatever the second child's content.
        {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            l.mint(&authenticated_child(&l, &message_request, &parent, 1))
                .unwrap();
            let second = authenticated_child(&l, &message_request, &parent, 2);
            assert_unchanged_refusal(&l, &second, "second child");
        }
        // The parent domain is the message domain: a used authenticated
        // intent without a child is no parent of another intent.
        {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let intent = authenticated_child(&l, &message_request, &parent, 1);
            let used = l.mint(&intent).unwrap();
            l.consume(&intent, &used, &consumption_of(&intent.binding))
                .unwrap();
            let mut child = l.request(soroban(2), vec![hold(40)]);
            child.consumer = MainnetConsumer::X402Authenticated;
            *child.authority.nonce_mut() = message_request.authority.nonce().clone();
            child.parent = Some(used.id);
            assert_unchanged_refusal(&l, &child, "intent parent of an intent");
        }
        // A submission continues an intent, never a message record.
        {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let mut child = l.request(x402(1), vec![]);
            child.consumer = MainnetConsumer::X402Authenticated;
            *child.authority.nonce_mut() = message_request.authority.nonce().clone();
            child.parent = Some(parent.id);
            assert_unchanged_refusal(&l, &child, "message parent of a submission");
        }
        // A plain intent and a message record name no parent.
        for binding in [soroban(1), message(1)] {
            let l = Ledger::new();
            let (message_request, parent) = used_message(&l);
            let mut child = l.request(binding, vec![]);
            *child.authority.nonce_mut() = message_request.authority.nonce().clone();
            child.parent = Some(parent.id);
            assert_unchanged_refusal(&l, &child, "parent of a parentless record");
        }
    }

    /// A message consume compares the recomputed content digest before the
    /// consumption binding.
    #[test]
    #[serial]
    fn a_message_consume_compares_the_content_before_the_binding() {
        let l = Ledger::new();
        let request = l.request(message(1), vec![]);
        let minted = l.mint(&request).unwrap();
        let expect = ConsumeExpect::new(
            l.name(),
            request.chain,
            request.consumer,
            request.binding.clone(),
            request.policy_sequence,
            request.policy_digest,
            request.authority.clone(),
            None,
            minted.bindings_digest,
            AUDIT,
            &RecomputedFacts {
                content_digest: message(2).content_digest(),
                entries_digest: entries_digest(&[]),
                audit: AUDIT,
            },
        );
        let before = l.bytes();
        assert_eq!(
            refusal(l.store.consume_authorization(
                &l.profile,
                minted.id,
                &expect,
                &consumption_of(&message(2)),
            )),
            MainnetPrecondition::ContentDigest
        );
        assert_eq!(l.bytes(), before);
    }

    #[test]
    #[serial]
    fn an_open_soroban_consume_checks_the_intent() {
        let l = Ledger::new();
        let request = l.request(
            DomainBinding::Soroban {
                intent_digest: [1; 32],
            },
            vec![hold(1)],
        );
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        assert_eq!(
            refusal(l.consume(
                &request,
                &minted,
                &ConsumptionBinding::RetainedIntent {
                    intent_digest: [2; 32]
                }
            )),
            MainnetPrecondition::IntentDigest
        );
        assert_eq!(l.bytes(), before);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_changed_audit_segment_refuses_even_after_the_count_recovers() {
        let l = Ledger::new();
        for count in [0, 10] {
            let request = l.request(tx(count as u8), vec![]);
            let minted = l.mint(&request).unwrap();
            let mut expected = l.expect(&request, &minted);
            expected.recorded_audit.anchored_count = count;
            expected.fresh_audit.anchored_count = count + 1;
            expected.fresh_audit.segment = [1; 32];
            let before = l.bytes();
            assert_eq!(
                refusal(l.store.consume_authorization(
                    &l.profile,
                    minted.id,
                    &expected,
                    &consumption_of(&request.binding)
                )),
                MainnetPrecondition::AuditSegment
            );
            assert_eq!(l.bytes(), before);
            expected.fresh_audit.segment = expected.recorded_audit.segment;
            l.store
                .consume_authorization(
                    &l.profile,
                    minted.id,
                    &expected,
                    &consumption_of(&request.binding),
                )
                .unwrap();
        }
    }

    #[test]
    #[serial]
    fn consume_refuses_another_profile_name() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(1)]);
        let minted = l.mint(&request).unwrap();
        let mut other = l.profile.clone();
        other.policy_owner_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key("other");
        let before = l.bytes();
        assert_eq!(
            refusal(l.store.consume_authorization(
                &other,
                minted.id,
                &l.expect(&request, &minted),
                &consumption_of(&request.binding)
            )),
            MainnetPrecondition::ProfileMismatch
        );
        assert_eq!(l.bytes(), before);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn consume_refuses_another_profile_chain() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(1)]);
        let minted = l.mint(&request).unwrap();
        let mut other = l.profile.clone();
        other.chain_id = Caip2::Testnet;
        let before = l.bytes();
        assert!(matches!(
            l.store.consume_authorization(
                &other,
                minted.id,
                &l.expect(&request, &minted),
                &consumption_of(&request.binding)
            ),
            Err(WindowStoreError::ChainMismatch)
        ));
        assert_eq!(l.bytes(), before);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn invalidate_refuses_another_profile_name() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(1)]);
        let minted = l.mint(&request).unwrap();
        let mut other = l.profile.clone();
        other.policy_owner_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key("other");
        let before = l.bytes();
        assert_eq!(
            refusal(l.store.invalidate_authorization(&other, minted.id, "test")),
            MainnetPrecondition::ProfileMismatch
        );
        assert_eq!(l.bytes(), before);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn invalidate_refuses_another_profile_chain() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(1)]);
        let minted = l.mint(&request).unwrap();
        let mut other = l.profile.clone();
        other.chain_id = Caip2::Testnet;
        let before = l.bytes();
        assert!(matches!(
            l.store.invalidate_authorization(&other, minted.id, "test"),
            Err(WindowStoreError::ChainMismatch)
        ));
        assert_eq!(l.bytes(), before);
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
    }

    #[test]
    #[serial]
    fn every_fee_bump_fact_is_compared_at_consumption() {
        use MainnetPrecondition as P;
        let breakages: [(&str, DomainBinding, SubmissionChange, P); 11] = [
            (
                "inner: inner hash",
                fee_inner(1),
                |s| fee_of(s).inner_tx_hash = [2; 32],
                P::InnerTxHash,
            ),
            (
                "inner: fee source",
                fee_inner(1),
                |s| fee_of(s).fee_source = "other".to_owned(),
                P::FeeSource,
            ),
            (
                "inner: maximum fee",
                fee_inner(1),
                |s| fee_of(s).max_fee += 1,
                P::MaxFee,
            ),
            (
                "inner: no fee-bump facts",
                fee_inner(1),
                |s| s.fee_bump = None,
                P::BindingMismatch,
            ),
            (
                "inner: inner source",
                fee_inner(1),
                |s| s.source = "other".to_owned(),
                P::SourceAccount,
            ),
            (
                "inner: inner sequence",
                fee_inner(1),
                |s| s.sequence += 1,
                P::Sequence,
            ),
            (
                "outer: inner hash",
                fee_outer(1),
                |s| fee_of(s).inner_tx_hash = [2; 32],
                P::InnerTxHash,
            ),
            (
                "outer: fee source",
                fee_outer(1),
                |s| fee_of(s).fee_source = "other".to_owned(),
                P::FeeSource,
            ),
            (
                "outer: maximum fee",
                fee_outer(1),
                |s| fee_of(s).max_fee += 1,
                P::MaxFee,
            ),
            (
                "outer: no fee-bump facts",
                fee_outer(1),
                |s| s.fee_bump = None,
                P::BindingMismatch,
            ),
            (
                "plain: fee-bump facts",
                tx(1),
                |s| s.fee_bump = Some(fee_facts(1)),
                P::BindingMismatch,
            ),
        ];
        for (name, binding, change, precondition) in breakages {
            let l = Ledger::new();
            let request = l.request(binding, vec![hold(1)]);
            let minted = l.mint(&request).unwrap();
            let good = match &request.binding {
                DomainBinding::Transaction { .. } => consumption_of(&request.binding),
                _ => fee_bump_submission(1),
            };
            let mut bad = good.clone();
            let ConsumptionBinding::Transaction(submission) = &mut bad else {
                panic!("{name}: a transaction consumption");
            };
            change(submission);
            let before = l.bytes();
            assert_eq!(
                refusal(l.consume(&request, &minted, &bad)),
                precondition,
                "{name}"
            );
            assert_eq!(l.bytes(), before, "{name}");
            l.consume(&request, &minted, &good).unwrap();
        }
    }

    #[test]
    #[serial]
    fn only_the_inner_hash_carried_by_the_envelope_consumes() {
        let l = Ledger::new();
        let first = l.request(fee_inner(1), vec![hold(1)]);
        let second = l.request(fee_inner(2), vec![hold(1)]);
        let a = l.mint(&first).unwrap();
        let b = l.mint(&second).unwrap();
        let final_envelope = fee_bump_submission(1);
        let before = l.bytes();
        assert_eq!(
            refusal(l.consume(&second, &b, &final_envelope)),
            MainnetPrecondition::InnerTxHash
        );
        assert_eq!(l.bytes(), before);
        l.consume(&first, &a, &final_envelope).unwrap();
    }

    #[test]
    #[serial]
    fn a_held_lock_refuses_a_mint() {
        let l = Ledger::new();
        let second = l.request(tx(1), vec![hold(1)]);
        {
            let _held =
                WindowStoreLock::acquire_for(l.store.path(), &l.profile.policy_window_state_key_id)
                    .unwrap();
            assert!(
                matches!(l.mint(&second), Err(WindowStoreError::WriterLocked)),
                "a mint while another holder keeps the lock refuses without waiting"
            );
        }
    }

    /// A second handle over the ledger's keyring entry, at a byte copy of its
    /// committed file in the same directory.
    fn second_path(l: &Ledger) -> PersistedWindowStore {
        let path = l._dir.path().join("second.window");
        fs::copy(l.store.path(), &path).unwrap();
        PersistedWindowStore::at_path(path)
    }

    /// The generation commitment both handles of [`second_path`] share.
    fn commitment(l: &Ledger) -> String {
        let entry = generation_entry_ref(&l.profile);
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .get_password()
            .unwrap()
    }

    #[test]
    #[serial]
    fn a_second_path_over_one_entry_cannot_mint_while_the_first_holds_the_lock() {
        let l = Ledger::new();
        l.mint(&l.request(tx(1), vec![hold(1)])).unwrap();
        let second = second_path(&l);
        let request = l.request(tx(2), vec![hold(1)]);
        let committed = commitment(&l);
        let held =
            WindowStoreLock::acquire_for(l.store.path(), &l.profile.policy_window_state_key_id)
                .unwrap();
        assert!(matches!(
            second.mint_authorization(&l.profile, &request),
            Err(WindowStoreError::WriterLocked)
        ));
        drop(held);
        assert_eq!(commitment(&l), committed);
    }

    #[test]
    #[serial]
    fn a_second_path_over_one_entry_cannot_admit_cancel_or_bind_while_the_first_holds_the_lock() {
        let l = Ledger::new();
        let plan = crate::SignedIntentPlan::new(
            l.profile.chain_id.network_passphrase(),
            "fixture",
            stellar_strkey::ed25519::PublicKey([0; 32])
                .to_string()
                .as_str(),
            1,
            [7; 32],
            vec![],
            None,
        )
        .unwrap()
        .with_legs(&[hold(1)]);
        let proof = l.store.admit_signed_intent(&l.profile, &plan).unwrap();
        let id = proof.intent_id.clone().unwrap();
        let second = second_path(&l);
        let facts = crate::BindFacts {
            host: stellar_xdr::HostFunction::InvokeContract(stellar_xdr::InvokeContractArgs {
                contract_address: stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
                    stellar_xdr::Hash([1; 32]),
                )),
                function_name: stellar_xdr::ScSymbol::try_from("call").unwrap(),
                args: Default::default(),
            }),
            subjects: Vec::new(),
            facts: plan.facts.clone(),
            envelope_hash: "ab".repeat(32),
            tx_hash: "cd".repeat(32),
        };
        let committed = commitment(&l);
        let _guard =
            WindowStoreLock::acquire_for(l.store.path(), &l.profile.policy_window_state_key_id)
                .unwrap();
        assert!(matches!(
            second.admit_signed_intent(&l.profile, &plan),
            Err(WindowStoreError::WriterLocked)
        ));
        assert!(matches!(
            second.cancel_signed_intent(&l.profile, proof),
            Err(WindowStoreError::WriterLocked)
        ));
        assert!(matches!(
            second.bind_signed_intent(&l.profile, &id, &facts, plan.legs()),
            Err(WindowStoreError::WriterLocked)
        ));
        let instant = tokio::time::Instant::now();
        let capability = crate::signing::ledger_witness::LedgerWitnessCapability::for_test(
            crate::policy_state::ChainScope::for_chain(l.profile.chain_id),
            [
                "https://primary.example/rpc",
                "https://secondary.example/rpc",
            ],
            [1001, 1001],
            [instant, instant],
            [T0, T0],
            instant + std::time::Duration::from_secs(10),
        )
        .unwrap();
        assert!(matches!(
            second.observe_signed_intents(&l.profile, &capability),
            Err(WindowStoreError::WriterLocked)
        ));
        assert_eq!(commitment(&l), committed);
    }

    /// Two handles at two paths over one entry both start from one committed
    /// snapshot, and one approval names two different contents, so neither
    /// the nonce check nor the duplicate content check of the other's file
    /// can stop the second mint. The lock of the entry is what stops it.
    #[test]
    #[serial]
    fn two_paths_mint_one_approval_once() {
        let l = Ledger::new();
        l.mint(&l.request(tx(1), vec![hold(1)])).unwrap();
        let second = second_path(&l);
        let request = l.request(tx(2), vec![hold(1)]);
        let mut rival = l.request(tx(3), vec![hold(1)]);
        rival
            .authority
            .nonce_mut()
            .clone_from(request.authority.nonce());

        let outcome = std::rc::Rc::new(std::cell::RefCell::new(None));
        let observed = outcome.clone();
        let profile = l.profile.clone();
        MINT_AFTER_READ.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || {
                *observed.borrow_mut() = Some(second.mint_authorization(&profile, &rival));
            }));
        });

        l.mint(&request).unwrap();
        assert!(
            matches!(
                outcome.borrow_mut().take(),
                Some(Err(WindowStoreError::WriterLocked))
            ),
            "the rival mint ran under the first mint's lock and refused"
        );
        let wire = l.wire();
        assert_eq!(
            wire.authorizations
                .iter()
                .filter(|auth| auth.approval_nonce.as_ref() == Some(request.authority.nonce()))
                .count(),
            1
        );
    }

    /// Each transition through a second path refuses while the entry's lock is
    /// held through the first, and neither file nor the commitment moves.
    #[test]
    #[serial]
    fn every_store_transition_takes_the_entry_lock() {
        type Transition<'a> = (
            &'static str,
            Box<dyn Fn() -> Result<(), WindowStoreError> + 'a>,
        );

        let l = Ledger::new();
        let profile = &l.profile;
        let reservation = |id: &str| SubmissionHold {
            id: id.to_owned(),
            tx_hash: "ab".repeat(32),
            source: SOURCE.to_owned(),
            sequence: 9,
            max_time: 0,
            pending_since_ms: T0,
            submission_ledger: 1_000,
            submission_anchor: None,
            operator_required: false,
            chain_scope: crate::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Mainnet,
            ),
        };
        let pending = "cd".repeat(32);
        l.store
            .record_pending(profile, &[hold(1)], &reservation(&pending))
            .unwrap();
        let open = l.request(tx(1), vec![hold(1)]);
        let minted = l.mint(&open).unwrap();
        let next = l.request(tx(2), vec![hold(1)]);
        let expect = l.expect(&open, &minted);
        let claim_expect = l.claim_expect(&open, &minted);
        let binding = consumption_of(&open.binding);
        let second = second_path(&l);
        let second = &second;

        let plan = crate::SignedIntentPlan::new(
            profile.chain_id.network_passphrase(),
            "fixture",
            stellar_strkey::ed25519::PublicKey([0; 32])
                .to_string()
                .as_str(),
            1,
            [7; 32],
            vec![],
            None,
        )
        .unwrap()
        .with_legs(&[hold(1)]);
        let proof = std::cell::RefCell::new(Some(crate::IntentProof::new(
            Some(plan.facts.intent_id()),
            plan.clone(),
        )));
        let facts = crate::BindFacts {
            host: stellar_xdr::HostFunction::InvokeContract(stellar_xdr::InvokeContractArgs {
                contract_address: stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(
                    stellar_xdr::Hash([1; 32]),
                )),
                function_name: stellar_xdr::ScSymbol::try_from("call").unwrap(),
                args: Default::default(),
            }),
            subjects: Vec::new(),
            facts: plan.facts.clone(),
            envelope_hash: "ab".repeat(32),
            tx_hash: "cd".repeat(32),
        };
        let instant = tokio::time::Instant::now();
        let capability = crate::signing::ledger_witness::LedgerWitnessCapability::for_test(
            crate::policy_state::ChainScope::for_chain(profile.chain_id),
            [
                "https://primary.example/rpc",
                "https://secondary.example/rpc",
            ],
            [1001, 1001],
            [instant, instant],
            [T0, T0],
            instant + std::time::Duration::from_secs(10),
        )
        .unwrap();
        let transitions: Vec<Transition<'_>> = vec![
            (
                "acknowledge_accounting_expiry",
                Box::new(|| {
                    second.mark_accounting_expiry(profile, "fixture", |record| {
                        &mut record.audit_acknowledged
                    })
                }),
            ),
            (
                "mark_accounting_projection",
                Box::new(|| {
                    second.mark_accounting_expiry(profile, "fixture", |record| {
                        &mut record.receipt_projected
                    })
                }),
            ),
            (
                "observe_signed_intents",
                Box::new(|| second.observe_signed_intents(profile, &capability)),
            ),
            (
                "admit_signed_intent",
                Box::new(|| second.admit_signed_intent(profile, &plan).map(drop)),
            ),
            (
                "cancel_signed_intent",
                Box::new(|| {
                    second.cancel_signed_intent(profile, proof.borrow_mut().take().unwrap())
                }),
            ),
            (
                "bind_signed_intent",
                Box::new(|| {
                    second.bind_signed_intent(profile, &plan.facts.intent_id(), &facts, plan.legs())
                }),
            ),
            (
                "record_pending_linked",
                Box::new(|| {
                    second
                        .record_pending_linked(
                            profile,
                            plan.legs(),
                            &reservation(&facts.envelope_hash),
                            &plan.facts.intent_id(),
                        )
                        .map(drop)
                }),
            ),
            (
                "record_and_persist",
                Box::new(|| second.record_and_persist(profile, &[hold(1)]).map(drop)),
            ),
            (
                "record_authorized",
                Box::new(|| second.record_authorized(profile, &[hold(1)]).map(drop)),
            ),
            (
                "record_pending",
                Box::new(|| {
                    second
                        .record_pending(profile, &[hold(1)], &reservation(&"ef".repeat(32)))
                        .map(drop)
                }),
            ),
            (
                "confirm",
                Box::new(|| second.confirm(profile, &pending, Some(1_800_000_000))),
            ),
            ("release", Box::new(|| second.release(profile, &pending))),
            (
                "reset",
                Box::new(|| {
                    match second.reset(
                        profile,
                        "ledger",
                        T0,
                        "repair",
                        "reset-request",
                        |_| Ok::<_, WindowStoreError>(ResetConsent::default()),
                        |_, _| Ok(()),
                    ) {
                        Ok(_) => Ok(()),
                        Err(ResetError::Store { error, .. } | ResetError::Recorder(error)) => {
                            Err(error)
                        }
                    }
                }),
            ),
            ("resign", Box::new(|| second.resign(profile, &[9; 32]))),
            (
                "mint_authorization",
                Box::new(|| second.mint_authorization(profile, &next).map(drop)),
            ),
            (
                "claim_authorization",
                Box::new(|| {
                    second
                        .claim_authorization(profile, minted.id, &claim_expect)
                        .map(drop)
                }),
            ),
            (
                "consume_authorizations",
                Box::new(|| {
                    second
                        .consume_authorizations(
                            profile,
                            &[(minted.id, expect.clone(), binding.clone())],
                        )
                        .map(drop)
                }),
            ),
            (
                "invalidate_authorization",
                Box::new(|| {
                    second
                        .invalidate_authorization(profile, minted.id, "held")
                        .map(drop)
                }),
            ),
        ];

        let first_bytes = l.bytes();
        let second_bytes = fs::read(second.path()).unwrap();
        let committed = commitment(&l);
        let _held =
            WindowStoreLock::acquire_for(l.store.path(), &profile.policy_window_state_key_id)
                .unwrap();
        for (name, transition) in &transitions {
            assert!(
                matches!(transition(), Err(WindowStoreError::WriterLocked)),
                "{name}"
            );
            assert_eq!(l.bytes(), first_bytes, "{name}");
            assert_eq!(fs::read(second.path()).unwrap(), second_bytes, "{name}");
            assert_eq!(commitment(&l), committed, "{name}");
        }
    }

    #[test]
    fn a_wrong_pin_guard_is_an_invalid_request() {
        assert!(matches!(
            pin_refusal(PinError::WrongGuard),
            WindowStoreError::Invalid { .. }
        ));
    }

    /// The ledger consumes each domain by exactly the consumption kind the
    /// domain table names: the consumption whose facts match is accepted, and
    /// every consumption of another kind refuses as a binding mismatch.
    #[test]
    fn each_domain_is_consumed_by_the_kind_its_table_names() {
        use crate::mainnet::types::ConsumeBindingKind;
        fn kind_of(binding: &ConsumptionBinding) -> ConsumeBindingKind {
            match binding {
                ConsumptionBinding::Transaction(_) => ConsumeBindingKind::Transaction,
                ConsumptionBinding::RetainedIntent { .. } => ConsumeBindingKind::RetainedIntent,
                ConsumptionBinding::PayloadRelease { .. } => ConsumeBindingKind::PayloadRelease,
                ConsumptionBinding::Message { .. } => ConsumeBindingKind::Message,
            }
        }
        let mut parent = sample(AuthorizationState::Used, 1, Some(1));
        parent.domain = AuthorizationDomain::Soroban;
        parent.binding = soroban(1);
        parent.content_digest = parent.binding.content_digest();
        let wire = WireFile {
            chain_scope: Some(crate::policy_state::ChainScope::for_chain(Caip2::Mainnet)),
            version: 5,
            authorizations: vec![parent.clone()],
            ..WireFile::default()
        };
        let cases: Vec<(WireAuthorization, ConsumptionBinding)> = AuthorizationDomain::ALL
            .into_iter()
            .map(|domain| {
                let (binding, consumption) = match domain {
                    AuthorizationDomain::Transaction => (tx(2), consumption_of(&tx(2))),
                    AuthorizationDomain::FeeBumpInner => (fee_inner(2), fee_bump_submission(2)),
                    AuthorizationDomain::FeeBumpOuter => (fee_outer(2), fee_bump_submission(2)),
                    AuthorizationDomain::FeeBumpSubmit => (
                        fee_submit(2),
                        ConsumptionBinding::PayloadRelease {
                            intent_record: None,
                            final_envelope_sha256: [2 ^ 0x10; 32],
                            root_invocation_digest: None,
                        },
                    ),
                    AuthorizationDomain::X402Submit => (
                        x402(2),
                        ConsumptionBinding::PayloadRelease {
                            intent_record: Some(parent.id),
                            final_envelope_sha256: [2; 32],
                            root_invocation_digest: Some([2 ^ 0x40; 32]),
                        },
                    ),
                    AuthorizationDomain::Soroban => (soroban(2), consumption_of(&soroban(2))),
                    AuthorizationDomain::Message => (message(2), consumption_of(&message(2))),
                };
                let mut auth = sample(AuthorizationState::Open, 2, None);
                auth.domain = domain;
                auth.content_digest = binding.content_digest();
                auth.binding = binding;
                auth.parent = (domain == AuthorizationDomain::X402Submit).then_some(parent.id);
                (auth, consumption)
            })
            .collect();
        for (auth, consumption) in &cases {
            let expected = auth.domain.consume_binding();
            assert_eq!(kind_of(consumption), expected, "{:?}", auth.domain);
            check_consumption(&wire, auth, consumption).unwrap();
            for (_, other) in &cases {
                if kind_of(other) != expected {
                    assert!(
                        matches!(
                            check_consumption(&wire, auth, other),
                            Err(WindowStoreError::AuthorizationRefused {
                                precondition: MainnetPrecondition::BindingMismatch
                            })
                        ),
                        "{:?} consumed by {:?}",
                        auth.domain,
                        kind_of(other)
                    );
                }
            }
        }
    }
    #[test]
    #[serial]
    fn consumption_requires_the_submission_scope() {
        for scope in [
            None,
            Some(crate::policy_state::ChainScope::for_chain(Caip2::Testnet)),
        ] {
            let l = Ledger::new();
            let request = l.request(tx(1), vec![hold(100)]);
            let minted = l.mint(&request).unwrap();
            let mut binding = consumption_of(&request.binding);
            let ConsumptionBinding::Transaction(submission) = &mut binding else {
                panic!("transaction fixture")
            };
            submission.chain_scope = scope;
            let before = l.bytes();
            let generation = keyring_core::Entry::new(
                &generation_entry_ref(&l.profile).service,
                &generation_entry_ref(&l.profile).account,
            )
            .unwrap()
            .get_password()
            .unwrap();
            let result = l.consume(&request, &minted, &binding);
            if scope.is_none() {
                assert!(matches!(result, Err(WindowStoreError::ChainUnverifiable)));
            } else {
                assert!(matches!(result, Err(WindowStoreError::ChainMismatch)));
            }
            assert_eq!(l.bytes(), before);
            assert_eq!(
                keyring_core::Entry::new(
                    &generation_entry_ref(&l.profile).service,
                    &generation_entry_ref(&l.profile).account
                )
                .unwrap()
                .get_password()
                .unwrap(),
                generation
            );
            assert_eq!(l.record(minted.id).state, AuthorizationState::Open);
        }
    }

    /// A submission anchor serializes into the window file and is read back
    /// only through the stored consumption the authenticated load uses: the
    /// public `Deserialize` of a binding refuses input that names one.
    #[test]
    fn an_anchor_is_read_back_only_through_the_stored_consumption() {
        let scope = super::super::store::ChainScope::for_chain(Caip2::Mainnet);
        let witness_binding = [1_u8; 32];
        let subject = [2_u8; 32];
        let anchor = super::super::store::stored_anchor::option(serde_json::json!({
            "chain_scope": scope,
            "ledger": 123,
            "observed_at_ms": 77,
            "witness_authority": "https://oracle.example",
            "witness_binding": witness_binding,
            "subject": subject,
        }))
        .unwrap()
        .expect("a stored anchor");
        let binding = SubmissionBinding {
            chain_scope: Some(scope),
            fee_bump: None,
            envelope_hash: [3; 32],
            tx_hash: [4; 32],
            source: SOURCE.to_owned(),
            sequence: 7,
            max_time: 0,
            pending_since_ms: T0,
            submission_ledger: 100,
            submission_anchor: Some(Box::new(anchor)),
        };
        let stored =
            serde_json::to_value(ConsumptionBinding::Transaction(binding.clone())).unwrap();
        assert!(
            stored["transaction"]["submission_anchor"].is_object(),
            "the anchor is written: {stored}"
        );

        let public = serde_json::from_value::<ConsumptionBinding>(stored.clone()).unwrap_err();
        assert!(
            public
                .to_string()
                .contains("unknown field `submission_anchor`"),
            "{public}"
        );
        let bare =
            serde_json::from_value::<SubmissionBinding>(stored["transaction"].clone()).unwrap_err();
        assert!(
            bare.to_string()
                .contains("unknown field `submission_anchor`"),
            "{bare}"
        );

        assert_eq!(
            stored_consumption(stored).unwrap(),
            Some(ConsumptionBinding::Transaction(binding)),
            "the stored form restores the anchor"
        );
    }

    /// A version 9 snapshot of approval authorizations, as this build's
    /// writer serialized it: a used transaction record with its claim and
    /// consumption, a used message record, and an open transaction record
    /// with its hold.
    const VERSION_NINE_BODY: &str = concat!(
        r#"{"chain_scope":{"chain":"stellar:mainnet","network_passphrase_sha256":[122,195,57,151,84,"#,
        r#"78,49,117,210,102,189,2,36,57,178,44,219,22,80,140,1,22,63,38,229,203,42,62,16,69,169,"#,
        r#"121]},"version":9,"generation":6,"entries":[{"scope_specificity":1,"bucket":"native","#,
        r#""window_secs":86400,"records":[{"chain_scope":{"chain":"stellar:mainnet","#,
        r#""network_passphrase_sha256":[122,195,57,151,84,78,49,117,210,102,189,2,36,57,178,44,219,"#,
        r#"22,80,140,1,22,63,38,229,203,42,62,16,69,169,121]},"execution_bound":1800000300000,"#,
        r#""accounting_until_ms":1800086700000,"admitted_window_ms":86400000,"ts_ms":1800000000000,"#,
        r#""amount":"70","id":"dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb","#,
        r#""status":"pending","#,
        r#""tx_hash":"8181818181818181818181818181818181818181818181818181818181818181","#,
        r#""source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":101,"#,
        r#""max_time":1800000300,"pending_since_ms":1800000000005,"submission_ledger":512,"#,
        r#""operator_required":false}]}],"#,
        r#""authorizations":[{"id":"af8a9f4c233fab4521e9592e640c6eb66c17ef8ee54e9372bbce098e99bd878f","#,
        r#""profile":"ledger","chain":"stellar:mainnet","domain":"transaction","consumer":"cli_pay","#,
        r#""content_digest":"9e27c27f47fdf65289eef198a7d4c281ee1d6a4edb829573008964de73313ae5","#,
        r#""binding":{"transaction":{"unsigned_envelope_sha256":"0101010101010101010101010101010101010101010101010101010101010101","#,
        r#""tx_hash":"8181818181818181818181818181818181818181818181818181818181818181","#,
        r#""source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":101}},"#,
        r#""state":"used","minted_ms":1800000000000,"expires_ms":1800000120000,"#,
        r#""settled_ms":1800000000000,"claimed_ms":1800000000000,"policy_sequence":7,"#,
        r#""policy_digest":"0707070707070707070707070707070707070707070707070707070707070707","#,
        r#""approval_nonce":"nonce-1","approval_expires_ms":1800000600000,"#,
        r#""bindings_digest":"c1d6092063cba806b8ced30b9e9d821f64f16141dd4a46c55fcebb363a283a7f","#,
        r#""entries_digest":"72f52439d5854828c8c2365172dedcd280588791f347495f7c87af3cdde4fbfb","#,
        r#""reservation":"af8a9f4c233fab4521e9592e640c6eb66c17ef8ee54e9372bbce098e99bd878f","#,
        r#""consumption":{"transaction":{"chain_scope":{"chain":"stellar:mainnet","#,
        r#""network_passphrase_sha256":[122,195,57,151,84,78,49,117,210,102,189,2,36,57,178,44,219,"#,
        r#"22,80,140,1,22,63,38,229,203,42,62,16,69,169,121]},"#,
        r#""envelope_hash":"dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb","#,
        r#""tx_hash":"8181818181818181818181818181818181818181818181818181818181818181","#,
        r#""source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":101,"#,
        r#""max_time":1800000300,"pending_since_ms":1800000000005,"submission_ledger":512}}},"#,
        r#"{"id":"15c01edd3ec574572628f3c991668dd82de560427bfd2119405121710964bbe2","#,
        r#""profile":"ledger","chain":"stellar:mainnet","domain":"message","#,
        r#""consumer":"x402_authenticated","#,
        r#""content_digest":"31bbb00ecdf7732570a9dc038a99ef499265b080e7b11a408dfcf50a699cea0e","#,
        r#""binding":{"message":{"domain":{"home_domain":"example.com","#,
        r#""web_auth_domain":"auth.example.com","#,
        r#""server_key":"0303030303030303030303030303030303030303030303030303030303030303"},"#,
        r#""content_digest":"0202020202020202020202020202020202020202020202020202020202020202","#,
        r#""ephemeral_public_key":"0404040404040404040404040404040404040404040404040404040404040404"}},"#,
        r#""state":"used","minted_ms":1800000000000,"expires_ms":1800000120000,"#,
        r#""settled_ms":1800000000000,"policy_sequence":7,"#,
        r#""policy_digest":"0707070707070707070707070707070707070707070707070707070707070707","#,
        r#""approval_nonce":"nonce-2","approval_expires_ms":1800000600000,"#,
        r#""bindings_digest":"3e7ec0e8166269e268cb355e89f608a878ff317dee2a7a5d35168ab6f4abd475","#,
        r#""entries_digest":"7f5c3895b5a03f8439bd58a8878102768b3fc053bb9b0c9aa110c84e1b1823e2","#,
        r#""consumption":{"message":{"domain":{"home_domain":"example.com","#,
        r#""web_auth_domain":"auth.example.com","#,
        r#""server_key":"0303030303030303030303030303030303030303030303030303030303030303"},"#,
        r#""content_digest":"0202020202020202020202020202020202020202020202020202020202020202","#,
        r#""ephemeral_public_key":"0404040404040404040404040404040404040404040404040404040404040404"}}},"#,
        r#"{"id":"88191b1272cc480aca17360b43b1605934dc9da050437963efcd9cb3d05cc8d7","#,
        r#""profile":"ledger","chain":"stellar:mainnet","domain":"transaction","consumer":"cli_pay","#,
        r#""content_digest":"a3d3fdb483cee56fce1758da1714b2cc680d470a550f39a5a38a4c34f07f115e","#,
        r#""binding":{"transaction":{"unsigned_envelope_sha256":"0303030303030303030303030303030303030303030303030303030303030303","#,
        r#""tx_hash":"8383838383838383838383838383838383838383838383838383838383838383","#,
        r#""source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":103}},"#,
        r#""state":"open","minted_ms":1800000000000,"expires_ms":1800000120000,"policy_sequence":7,"#,
        r#""policy_digest":"0707070707070707070707070707070707070707070707070707070707070707","#,
        r#""approval_nonce":"nonce-3","approval_expires_ms":1800000600000,"#,
        r#""bindings_digest":"eb2b57ce5a080a8aedae04e674e9fd9c077e31d5b9905127cc8e59a5fccafe99","#,
        r#""entries_digest":"6fadf72103004d189a93177f819b04c78ec215cbfa0309b60067922a36ca682a","#,
        r#""reservation":"88191b1272cc480aca17360b43b1605934dc9da050437963efcd9cb3d05cc8d7"}],"#,
        r#""holds":[{"kind":"value","#,
        r#""authorization_id":"88191b1272cc480aca17360b43b1605934dc9da050437963efcd9cb3d05cc8d7","#,
        r#""ordinal":0,"scope_specificity":1,"bucket":"native","window_secs":86400,"#,
        r#""ts_ms":1800000000000,"amount":"5"}]}"#,
    );

    /// A version 9 snapshot whose authorizations carry approval authority
    /// loads, validates, and serializes back to the same bytes, so its HMAC
    /// tag and generation commitment still verify.
    #[test]
    fn version_nine_authorizations_reserialize_byte_identically() {
        let wire: WireFile = serde_json::from_str(VERSION_NINE_BODY).unwrap();
        assert_eq!(wire.version, 9);
        assert_eq!(wire.authorizations.len(), 3);
        validate(&wire).unwrap();
        assert_eq!(serde_json::to_string(&wire).unwrap(), VERSION_NINE_BODY);
    }

    // ── Policy authority ────────────────────────────────────────────────

    /// A classic policy authority over the fixture's pinned policy,
    /// governing until `governing_until_ms`.
    fn policy_binding(governing_until_ms: u64) -> PolicyAuthorityBinding {
        PolicyAuthorityBinding {
            policy_digest: [7; 32],
            policy_sequence: 7,
            rule_index: 0,
            evaluated_at_ms: T0,
            governing_until_ms,
            scope: AuthorityScope::Classic,
        }
    }

    /// `request` under the policy authority of [`policy_binding`].
    fn under_policy(mut request: MintRequest, governing_until_ms: u64) -> MintRequest {
        request.authority = MintAuthority::Policy(policy_binding(governing_until_ms));
        request
    }

    /// An open record blocks the same domain and content under either
    /// authority until it settles.
    #[test]
    #[serial]
    fn a_duplicate_open_policy_content_refuses_until_the_record_settles() {
        let l = Ledger::new();
        let first = under_policy(l.request(tx(1), vec![]), T0 + APPROVAL_MS);
        let minted = l.mint(&first).unwrap();
        let again = under_policy(l.request(tx(1), vec![]), T0 + APPROVAL_MS);
        assert_eq!(refusal(l.mint(&again)), MainnetPrecondition::DuplicateOpen);
        assert_eq!(
            refusal(l.mint(&l.request(tx(1), vec![]))),
            MainnetPrecondition::DuplicateOpen,
            "an approval does not bypass an open policy record"
        );
        l.consume(&first, &minted, &consumption_of(&first.binding))
            .unwrap();
        let reminted = l.mint(&again).unwrap();
        assert_eq!(
            refusal(l.mint(&under_policy(l.request(tx(1), vec![]), T0 + APPROVAL_MS))),
            MainnetPrecondition::DuplicateOpen
        );
        l.clock.set(reminted.expires_at_ms);
        l.mint(&under_policy(
            l.request(tx(1), vec![]),
            T0 + 2 * APPROVAL_MS,
        ))
        .unwrap();
        assert_eq!(l.record(reminted.id).state, AuthorizationState::Expired);
    }

    /// A continuation keeps its parent's authority: a policy child of an
    /// approval parent refuses, and so does an approval child of a policy
    /// parent. A policy child of a policy parent under the same authority
    /// continues it.
    #[test]
    #[serial]
    fn policy_child_under_approval_parent_refuses() {
        {
            let l = Ledger::new();
            let (_intent, _parent, child) = used_intent(&l);
            let child = under_policy(child, T0 + APPROVAL_MS);
            assert_eq!(
                refusal(l.mint(&child)),
                MainnetPrecondition::IntentRecordMismatch
            );
        }
        let l = Ledger::new();
        let intent = under_policy(l.request(soroban(1), vec![hold(40)]), T0 + APPROVAL_MS);
        let parent = l.mint(&intent).unwrap();
        l.consume(&intent, &parent, &consumption_of(&intent.binding))
            .unwrap();
        let mut approval_child = l.request(x402(1), vec![]);
        approval_child.parent = Some(parent.id);
        assert_eq!(
            refusal(l.mint(&approval_child)),
            MainnetPrecondition::IntentRecordMismatch
        );
        let mut other_policy = under_policy(l.request(x402(1), vec![]), T0 + APPROVAL_MS - 1);
        other_policy.parent = Some(parent.id);
        assert_eq!(
            refusal(l.mint(&other_policy)),
            MainnetPrecondition::IntentRecordMismatch,
            "another policy authority is another authority"
        );
        let mut child = under_policy(l.request(x402(1), vec![]), T0 + APPROVAL_MS);
        child.parent = Some(parent.id);
        let minted = l.mint(&child).unwrap();
        assert_eq!(l.record(minted.id).parent, Some(parent.id));
        assert_eq!(l.record(minted.id).authority().unwrap(), intent.authority);
    }

    /// A record carries exactly one authority: an approval nonce with its
    /// expiry, or a policy authority. Every other shape refuses the read, and
    /// a mainnet load reports the state unverifiable.
    #[test]
    #[serial]
    fn wire_authorization_refuses_both_projections() {
        let approval = sample(AuthorizationState::Expired, 2, Some(9));
        let mut policy = approval.clone();
        policy.approval_nonce = None;
        policy.approval_expires_ms = None;
        policy.policy_authority = Some(policy_binding(1_000).into());
        let wire = |record: &WireAuthorization| WireFile {
            version: WIRE_VERSION_POLICY_AUTHORITY,
            authorizations: vec![record.clone()],
            ..WireFile::default()
        };
        validate(&wire(&approval)).unwrap();
        validate(&wire(&policy)).unwrap();

        let shape = WireAuthorizationShape.to_string();
        let mut both = approval.clone();
        both.policy_authority = policy.policy_authority.clone();
        let mut neither = approval.clone();
        neither.approval_nonce = None;
        neither.approval_expires_ms = None;
        let mut nonce_only = approval.clone();
        nonce_only.approval_expires_ms = None;
        let mut expiry_only = approval.clone();
        expiry_only.approval_nonce = None;
        let mut nonce_and_policy = policy.clone();
        nonce_and_policy.approval_nonce = approval.approval_nonce.clone();
        let mut expiry_and_policy = policy.clone();
        expiry_and_policy.approval_expires_ms = approval.approval_expires_ms;
        for (name, record) in [
            ("both", both.clone()),
            ("neither", neither),
            ("nonce only", nonce_only),
            ("expiry only", expiry_only),
            ("nonce and policy", nonce_and_policy),
            ("expiry and policy", expiry_and_policy),
        ] {
            assert!(
                matches!(validate(&wire(&record)), Err(WindowStoreError::Invalid { detail }) if detail == shape),
                "{name}"
            );
        }
        let mut other_policy = policy.clone();
        other_policy.policy_digest = [8; 32];
        assert!(matches!(
            validate(&wire(&other_policy)),
            Err(WindowStoreError::Invalid { .. })
        ));

        #[cfg(feature = "mainnet-write")]
        {
            let l = Ledger::new();
            let request = l.request(tx(1), vec![]);
            let minted = l.mint(&request).unwrap();
            let mut sealed = l.wire();
            let record = sealed
                .authorizations
                .iter_mut()
                .find(|auth| auth.id == minted.id)
                .unwrap();
            record.policy_authority = Some(policy_binding(T0 + APPROVAL_MS).into());
            sealed.version = WIRE_VERSION_POLICY_AUTHORITY;
            l.store.seal_unchecked_for_test(&l.profile, &sealed);
            let error = l
                .store
                .load_into("ledger", &l.profile, &PolicyStateStore::new())
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    WindowStoreError::MainnetStateUnverifiable {
                        defect: super::super::StateDefect::Malformed
                    }
                ),
                "{error:?}"
            );
            assert!(
                error
                    .to_string()
                    .starts_with("policy.window_state_unverifiable"),
                "{error}"
            );
        }
    }

    /// Every successor is written as version 12, with or without a policy
    /// authority, and a version below 10 carrying one refuses the read.
    #[test]
    #[serial]
    fn version_ten_only_with_policy_authority() {
        let l = Ledger::new();
        let approval = l.request(tx(1), vec![hold(5)]);
        l.mint(&approval).unwrap();
        let version = l.wire().version;
        assert_eq!(
            version,
            super::super::store::WIRE_VERSION_TOTAL_EPOCH,
            "{version}"
        );
        let policy = under_policy(l.request(tx(2), vec![hold(5)]), T0 + APPROVAL_MS);
        let minted = l.mint(&policy).unwrap();
        let wire = l.wire();
        assert_eq!(wire.version, super::super::store::WIRE_VERSION_TOTAL_EPOCH);
        let record = l.record(minted.id);
        assert_eq!(record.approval_nonce, None);
        assert_eq!(record.approval_expires_ms, None);
        assert_eq!(
            record.authority().unwrap(),
            MintAuthority::Policy(policy_binding(T0 + APPROVAL_MS))
        );
        let body = serde_json::to_value(&record).unwrap();
        assert!(body.get("approval_nonce").is_none());
        assert!(body.get("approval_expires_ms").is_none());
        assert_eq!(
            body["policy_authority"],
            serde_json::json!({
                "policy_digest": "07".repeat(32),
                "policy_sequence": 7,
                "rule_index": 0,
                "evaluated_at_ms": T0,
                "governing_until_ms": T0 + APPROVAL_MS,
                "scope": {"kind": "classic"},
            })
        );

        let mut lowered = wire;
        lowered.version = WIRE_VERSION_POLICY_AUTHORITY - 1;
        l.store.seal_unchecked_for_test(&l.profile, &lowered);
        let result = l.store.read_for_inspection(&l.profile);
        #[cfg(feature = "mainnet-write")]
        assert!(
            matches!(
                &result,
                Err(WindowStoreError::MainnetStateUnverifiable {
                    defect: super::super::StateDefect::Malformed
                })
            ),
            "{result:?}"
        );
        #[cfg(not(feature = "mainnet-write"))]
        assert!(
            matches!(
                &result,
                Err(WindowStoreError::Invalid { detail })
                    if detail == "a policy authority requires wire version 10"
            ),
            "{result:?}"
        );
    }

    /// The persisted policy authority denies unknown fields and requires
    /// every field; its scopes have the documented shapes.
    #[test]
    fn the_wire_policy_authority_is_closed() {
        let scoped = PolicyAuthorityBinding {
            scope: AuthorityScope::X402Authenticated {
                home_domain: "pay.example.org".to_owned(),
                tool: "stellar_x402_authenticated_payment".to_owned(),
            },
            ..policy_binding(1_000)
        };
        let wire = WirePolicyAuthorityBinding::from(scoped.clone());
        let body = serde_json::to_value(&wire).unwrap();
        assert_eq!(
            body["scope"],
            serde_json::json!({
                "kind": "x402_authenticated",
                "home_domain": "pay.example.org",
                "tool": "stellar_x402_authenticated_payment",
            })
        );
        let back: WirePolicyAuthorityBinding = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(PolicyAuthorityBinding::from(back), scoped);
        for field in [
            "policy_digest",
            "policy_sequence",
            "rule_index",
            "evaluated_at_ms",
            "governing_until_ms",
            "scope",
        ] {
            let mut missing = body.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<WirePolicyAuthorityBinding>(missing).is_err(),
                "{field}"
            );
        }
        let mut unknown = body.clone();
        unknown["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<WirePolicyAuthorityBinding>(unknown).is_err());
        let mut unknown_scope = body.clone();
        unknown_scope["scope"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<WirePolicyAuthorityBinding>(unknown_scope).is_err());
        let mut upper = body;
        upper["policy_digest"] = serde_json::json!("AB".repeat(32));
        assert!(serde_json::from_value::<WirePolicyAuthorityBinding>(upper).is_err());
        assert!(
            serde_json::from_value::<WireAuthorityScope>(
                serde_json::json!({"kind": "classic", "extra": 1})
            )
            .is_err()
        );
    }

    /// A claim and a consumption compare the record's authority: another
    /// variant or another policy authority refuses, the record's own
    /// proceeds.
    #[test]
    #[serial]
    fn a_policy_record_compares_its_authority() {
        let l = Ledger::new();
        let request = under_policy(l.request(tx(1), vec![]), T0 + APPROVAL_MS);
        let minted = l.mint(&request).unwrap();
        let before = l.bytes();
        let approval = MintAuthority::Approval {
            nonce: "nonce".to_owned(),
            expires_at_ms: T0 + APPROVAL_MS,
        };
        let other = MintAuthority::Policy(policy_binding(T0 + APPROVAL_MS - 1));
        for authority in [approval.clone(), other.clone()] {
            let mut claim = l.claim_expect(&request, &minted);
            claim.authority = authority.clone();
            assert_eq!(
                refusal(l.store.claim_authorization(&l.profile, minted.id, &claim)),
                MainnetPrecondition::AuthorityMismatch
            );
            let mut consume = l.expect(&request, &minted);
            consume.authority = authority;
            assert_eq!(
                refusal(l.store.consume_authorization(
                    &l.profile,
                    minted.id,
                    &consume,
                    &consumption_of(&request.binding)
                )),
                MainnetPrecondition::AuthorityMismatch
            );
        }
        assert_eq!(l.bytes(), before);
        l.claim(&request, &minted).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();

        let approved = l.request(tx(2), vec![]);
        let minted = l.mint(&approved).unwrap();
        let mut consume = l.expect(&approved, &minted);
        consume.authority = MintAuthority::Policy(policy_binding(T0 + APPROVAL_MS));
        assert_eq!(
            refusal(l.store.consume_authorization(
                &l.profile,
                minted.id,
                &consume,
                &consumption_of(&approved.binding)
            )),
            MainnetPrecondition::AuthorityMismatch
        );
    }

    /// A policy authority bounds the record: the mint expires no later than
    /// its governing end, a mint whose policy authority names another policy
    /// refuses, and a consumption refuses a record that outlives its
    /// authority.
    #[test]
    #[serial]
    fn a_policy_record_lives_within_its_governing_end() {
        let l = Ledger::new();
        let request = under_policy(l.request(tx(1), vec![]), T0 + 30_000);
        let minted = l.mint(&request).unwrap();
        assert_eq!(minted.expires_at_ms, T0 + 30_000);

        let mut foreign = under_policy(l.request(tx(2), vec![]), T0 + APPROVAL_MS);
        if let MintAuthority::Policy(binding) = &mut foreign.authority {
            binding.policy_digest = [8; 32];
        }
        assert_eq!(refusal(l.mint(&foreign)), MainnetPrecondition::PolicyDigest);
        let mut foreign = under_policy(l.request(tx(2), vec![]), T0 + APPROVAL_MS);
        if let MintAuthority::Policy(binding) = &mut foreign.authority {
            binding.policy_sequence = 8;
        }
        assert_eq!(
            refusal(l.mint(&foreign)),
            MainnetPrecondition::PolicySequence
        );

        let mut sealed = l.wire();
        sealed
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == minted.id)
            .unwrap()
            .expires_ms = T0 + 30_001;
        l.store.seal_unchecked_for_test(&l.profile, &sealed);
        assert_eq!(
            refusal(l.consume(&request, &minted, &consumption_of(&request.binding))),
            MainnetPrecondition::LifetimeInvalid
        );
    }

    /// Settled history and a reset keep a policy record while its governing
    /// end lies after the time, and drop it once the end is reached.
    #[test]
    fn policy_records_survive_by_their_governing_end() {
        let open = sample(AuthorizationState::Open, 0, None);
        let recent_settled = sample(AuthorizationState::Expired, 0, Some(100));
        let mut presentable = sample(AuthorizationState::Expired, 3, Some(5));
        presentable.approval_nonce = None;
        presentable.approval_expires_ms = None;
        presentable.policy_authority = Some(policy_binding(1_001).into());
        let mut ended = presentable.clone();
        ended.policy_authority = Some(policy_binding(1_000).into());
        for (old, kept) in [(presentable, true), (ended, false)] {
            let mut wire = WireFile {
                version: WIRE_VERSION_POLICY_AUTHORITY,
                authorizations: vec![open.clone(), old.clone(), recent_settled.clone()],
                ..WireFile::default()
            };
            prune_history(&mut wire, 100, 1_000);
            assert_eq!(wire.authorizations.contains(&old), kept);
            let survivors = reset_survivors(
                &WireFile {
                    authorizations: vec![old.clone()],
                    ..WireFile::default()
                },
                1_000,
            );
            assert_eq!(survivors.len(), usize::from(kept));
        }
    }

    /// Discards every row, for a test that only reads the window.
    struct NullAudit;

    #[test]
    #[serial]
    fn first_mint_consumes_the_record_for_its_operation() {
        use super::super::approvals::{ApprovalState, tests::Fx};
        let mut fx = Fx::new(86_400_000);
        fx.open();
        fx.consent();
        let before = fx.wire();
        let request = fx.mint_request();
        let minted = fx
            .store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        let after = fx.wire();
        assert_eq!(after.generation, before.generation + 1);
        let record = &after.approvals.as_ref().unwrap().records[0];
        assert_eq!(record.state, ApprovalState::Consumed);
        assert_eq!(
            record.consumed_at_ms,
            Some(fx.payload.receipt.verified_at_unix_ms())
        );
        assert!(record.consent.as_ref().unwrap().payload.is_some());
        assert_eq!(after.authorizations[0].id, minted.id);
        assert_eq!(after.authorizations[0].operation, request.operation);
    }

    const NATIVE: NativeReservation = NativeReservation {
        debit_stroops: 25,
        fee_stroops: 300,
    };

    /// A mint persists its native amounts with or without window entries,
    /// zero amounts included, and refuses negative amounts unwritten.
    #[test]
    #[serial]
    fn mint_persists_native_amounts_including_zero_buckets() {
        let l = Ledger::new();
        let mut bucketless = l.request(tx(1), vec![]);
        bucketless.native_reservation = Some(NativeReservation {
            debit_stroops: 0,
            fee_stroops: 300,
        });
        let first = l.mint(&bucketless).unwrap();
        let mut held = l.request(tx(2), vec![hold(25), hold_in("other", 25)]);
        held.native_reservation = Some(NATIVE);
        let second = l.mint(&held).unwrap();
        let mut x402 = l.request(soroban(3), vec![hold(5)]);
        x402.native_reservation = Some(NativeReservation::default());
        let third = l.mint(&x402).unwrap();
        assert!(first.reservation.is_none());
        assert_eq!(
            l.record(first.id).native_reservation,
            bucketless.native_reservation
        );
        assert_eq!(l.record(second.id).native_reservation, Some(NATIVE));
        assert_eq!(
            l.record(third.id).native_reservation,
            Some(NativeReservation::default())
        );
        let stored = serde_json::to_string(&l.record(third.id)).unwrap();
        assert!(
            stored.contains(r#""native_reservation":{"debit_stroops":0,"fee_stroops":0}"#),
            "{stored}"
        );
        assert!(l.wire().version >= WIRE_VERSION_POLICY_AUTHORITY);

        let before = l.bytes();
        for (debit, fee) in [(-1, 0), (0, -1)] {
            let mut negative = l.request(tx(9), vec![]);
            negative.native_reservation = Some(NativeReservation {
                debit_stroops: debit,
                fee_stroops: fee,
            });
            assert_eq!(
                refusal(l.mint(&negative)),
                MainnetPrecondition::HoldsMismatch
            );
        }
        assert_eq!(l.bytes(), before);
        let mut wire = l.wire();
        wire.authorizations[0].native_reservation = Some(NativeReservation {
            debit_stroops: -5,
            fee_stroops: 0,
        });
        assert!(validate(&wire).is_err());
    }

    /// Each authorization's amounts count once across its buckets and
    /// epochs. A row releases only at or past its bound. `used` alone
    /// releases nothing, and an absent observation keeps bounded rows.
    #[test]
    #[serial]
    fn native_amounts_count_once_per_reservation() {
        use super::super::operations::{
            ReleaseBound, ReleaseClass, ReleaseRow, WindowObservation, native_reserved,
        };
        let l = Ledger::new();
        let mut request = l.request(
            tx(1),
            vec![hold(25), hold_in("other", 25), hold_in("third", 25)],
        );
        request.native_reservation = Some(NATIVE);
        let minted = l.mint(&request).unwrap();
        let mut plain = l.request(tx(2), vec![hold(1)]);
        plain.native_reservation = None;
        l.mint(&plain).unwrap();
        let wire = l.wire();
        assert_eq!(native_reserved(&wire, None), 325);
        let at = |ledger: u32, close: u64| WindowObservation {
            ledger,
            close_time_floor_ms: close,
            observed_at_ms: T0,
        };
        let commit = super::super::operations::CommitId::from_bytes([1; 16]);
        let cases = [
            (ReleaseBound::Always, None, 0),
            (ReleaseBound::Ledger(50), None, 325),
            (ReleaseBound::Ledger(50), Some(at(49, u64::MAX)), 325),
            (ReleaseBound::Ledger(50), Some(at(50, 0)), 0),
            (
                ReleaseBound::CloseTime(9_000),
                Some(at(u32::MAX, 8_999)),
                325,
            ),
            (ReleaseBound::CloseTime(9_000), Some(at(0, 9_000)), 0),
        ];
        for (bound, observation, expected) in cases {
            let mut released = wire.clone();
            let auth = released
                .authorizations
                .iter_mut()
                .find(|auth| auth.id == minted.id)
                .unwrap();
            auth.native_release = Some(ReleaseRow {
                class: ReleaseClass::Settled,
                bound,
                observed_ledger: None,
                commit_id: commit,
            });
            assert_eq!(
                native_reserved(&released, observation.as_ref()),
                expected,
                "{bound:?} at {observation:?}"
            );
        }
        let mut used = wire;
        let auth = used
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == minted.id)
            .unwrap();
        auth.state = AuthorizationState::Used;
        auth.disposition = Some(Disposition::Used);
        assert_eq!(native_reserved(&used, Some(&at(u32::MAX, u64::MAX))), 325);
    }

    /// Consumption keeps the authorization's native amounts and writes no
    /// release row.
    #[test]
    #[serial]
    fn consumption_keeps_native_amounts() {
        let l = Ledger::new();
        let mut request = l.request(tx(1), vec![hold(25)]);
        request.native_reservation = Some(NATIVE);
        let minted = l.mint(&request).unwrap();
        l.claim(&request, &minted).unwrap();
        l.consume(&request, &minted, &consumption_of(&request.binding))
            .unwrap();
        let record = l.record(minted.id);
        assert_eq!(record.state, AuthorizationState::Used);
        assert_eq!(record.native_reservation, Some(NATIVE));
        assert_eq!(record.native_release, None);
        assert_eq!(
            super::super::operations::native_reserved(&l.wire(), None),
            325
        );
    }

    /// A remint under the same operation stores the successor's amounts and
    /// leaves the retired record's amounts beside it.
    #[test]
    #[serial]
    fn remint_carries_native_amounts() {
        use super::super::approvals::tests::Fx;
        use super::super::operations::{ReleaseClass, ReleaseRow, native_reserved};
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let mut request = fx.mint_request();
        request.native_reservation = Some(NATIVE);
        let now = fx.payload.receipt.verified_at_unix_ms();
        let mut wire = fx.wire();
        mint_into(
            &mut wire,
            fx.fixture.profile(),
            &request,
            now,
            now + 1,
            MintOptions::default(),
        )
        .unwrap();
        let first = &mut wire.authorizations[0];
        first.state = AuthorizationState::Expired;
        first.settled_ms = Some(now + 1);
        first.disposition = Some(Disposition::Unused);
        first.native_release = Some(ReleaseRow::always(
            ReleaseClass::RetiredUnused,
            super::super::operations::CommitId::from_bytes([1; 16]),
        ));
        let mut successor = request.clone();
        successor.native_reservation = Some(NativeReservation {
            debit_stroops: 25,
            fee_stroops: 400,
        });
        mint_into(
            &mut wire,
            fx.fixture.profile(),
            &successor,
            now + 1,
            now + 100,
            MintOptions {
                exempt_cap: true,
                lineage: Some(fx.operation),
            },
        )
        .unwrap();
        assert_eq!(wire.authorizations.len(), 2);
        assert_eq!(wire.authorizations[0].native_reservation, Some(NATIVE));
        assert_eq!(
            wire.authorizations[1].native_reservation,
            successor.native_reservation
        );
        assert_eq!(native_reserved(&wire, None), 425);
    }

    /// A record minted without amounts keeps them absent: its bytes hold no
    /// amount field and round-trip unchanged.
    #[test]
    #[serial]
    fn legacy_authorization_without_amounts_keeps_its_bytes() {
        let l = Ledger::new();
        let request = l.request(tx(1), vec![hold(25)]);
        assert_eq!(request.native_reservation, None);
        let minted = l.mint(&request).unwrap();
        let record = l.record(minted.id);
        assert_eq!(record.native_reservation, None);
        let bytes = serde_json::to_string(&record).unwrap();
        assert!(!bytes.contains("native_reservation"), "{bytes}");
        let back: WireAuthorization = serde_json::from_str(&bytes).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), bytes);
        assert_eq!(
            l.wire().version,
            super::super::store::WIRE_VERSION_TOTAL_EPOCH
        );
        assert_eq!(
            super::super::operations::native_reserved(&l.wire(), None),
            0
        );
    }

    #[test]
    #[serial]
    fn remint_under_the_same_operation_passes() {
        use super::super::approvals::tests::Fx;
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let request = fx.mint_request();
        let now = fx.payload.receipt.verified_at_unix_ms();
        let mut wire = fx.wire();
        mint_into(
            &mut wire,
            fx.fixture.profile(),
            &request,
            now,
            now + 1,
            MintOptions::default(),
        )
        .unwrap();
        let before = wire.approvals.clone();
        let first = &mut wire.authorizations[0];
        first.state = AuthorizationState::Expired;
        first.settled_ms = Some(now + 1);
        first.disposition = Some(Disposition::Unused);
        let options = MintOptions {
            exempt_cap: true,
            lineage: Some(fx.operation),
        };
        mint_into(
            &mut wire,
            fx.fixture.profile(),
            &request,
            now + 1,
            now + 100,
            options,
        )
        .unwrap();
        assert_eq!(wire.approvals, before);
        assert_eq!(wire.authorizations.len(), 2);
    }

    #[test]
    #[serial]
    fn mint_without_an_operation_link_refuses_under_a_record() {
        use super::super::approvals::tests::Fx;
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let before = fx.bytes();
        let mut request = fx.mint_request();
        request.operation = None;
        assert_eq!(
            refusal(fx.store.mint_authorization(fx.fixture.profile(), &request)),
            MainnetPrecondition::ApprovalNonceReused
        );
        assert_eq!(fx.bytes(), before);
    }

    #[test]
    #[serial]
    fn a_second_operation_cannot_mint_under_a_consumed_record() {
        use super::super::approvals::{ApprovalState, tests::Fx};
        let mut fx = Fx::new(86_400_000);
        fx.open();
        let expiry = fx.consent().record.consent.unwrap().execution_expires_at_ms;
        let request = fx.mint_request();
        let now = fx.payload.receipt.verified_at_unix_ms();
        let mut wire = fx.wire();
        mint_into(
            &mut wire,
            fx.fixture.profile(),
            &request,
            now,
            now + 1,
            MintOptions::default(),
        )
        .unwrap();
        assert_eq!(
            wire.approvals.as_ref().unwrap().records[0].state,
            ApprovalState::Consumed
        );
        let auth = &mut wire.authorizations[0];
        auth.state = AuthorizationState::Expired;
        auth.settled_ms = Some(now + 1);
        auth.disposition = Some(Disposition::Unused);
        auth.approval_expires_ms = Some(expiry);
        auth.native_release = Some(ReleaseRow::always(
            ReleaseClass::RetiredUnused,
            CommitId::random(),
        ));
        let mut other = request.clone();
        other.operation.as_mut().unwrap().operation_id = OperationId::random();
        for at in [now + 2, expiry + RETENTION_MS + 1] {
            let mut next = wire.clone();
            prune_history(&mut next, at.saturating_sub(RETENTION_MS), at);
            if at > expiry {
                assert!(next.authorizations.is_empty());
            } else {
                // Isolate the consumed record's operation check inside its execution window.
                next.authorizations.clear();
            }
            let result = mint_into(
                &mut next,
                fx.fixture.profile(),
                &other,
                at,
                at + 100,
                MintOptions::default(),
            );
            assert!(
                matches!(
                    result,
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalNonceReused
                    })
                ),
                "mint at {at}, execution expiry {expiry}: {result:?}"
            );
        }
    }

    /// Collecting the consumed inbox row leaves the durable approval record
    /// untouched: the window file keeps its bytes and generation, another
    /// operation still refuses, and so does a revoked record.
    #[test]
    #[serial]
    fn inbox_gc_leaves_the_durable_approval_record() {
        use super::super::approvals::{ApprovalState, tests::Fx};
        use stellar_agent_core::approval::store::{
            ApprovalKind, ConsumedOutcome, PendingApprovalStore,
        };
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let request = fx.mint_request();
        let now = fx.payload.receipt.verified_at_unix_ms();
        fx.store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        let wire = fx.wire();
        assert_eq!(
            wire.approvals.as_ref().unwrap().records[0].state,
            ApprovalState::Consumed
        );
        let before = fx.bytes();
        let generation = wire.generation;

        let inbox_path = fx.fixture.home().join("first.toml");
        let mut inbox = PendingApprovalStore::open(inbox_path.clone()).unwrap();
        assert!(
            inbox
                .consume(
                    &fx.facts.nonce,
                    &"ab".repeat(32),
                    ConsumedOutcome::Confirmed
                )
                .unwrap()
        );
        assert!(matches!(
            inbox.get(&fx.facts.nonce).unwrap().kind,
            ApprovalKind::Consumed { .. }
        ));
        assert_eq!(inbox.gc_expired_and_consumed(now).unwrap(), 1);
        drop(inbox);
        assert!(
            PendingApprovalStore::open(inbox_path)
                .unwrap()
                .get(&fx.facts.nonce)
                .is_none(),
            "the inbox row is gone"
        );
        assert_eq!(fx.bytes(), before, "the window file keeps its bytes");
        assert_eq!(fx.wire().generation, generation);

        // Isolate the consumed record's operation check from the live
        // authorization of the first operation.
        let mut other = request.clone();
        other.operation.as_mut().unwrap().operation_id = OperationId::random();
        let mut isolated = fx.wire();
        isolated.authorizations.clear();
        assert_eq!(
            refusal(mint_into(
                &mut isolated,
                fx.fixture.profile(),
                &other,
                now + 1,
                now + 100,
                MintOptions::default()
            )),
            MainnetPrecondition::ApprovalNonceReused,
            "another operation still refuses"
        );
        assert_eq!(fx.bytes(), before);

        let id = fx.id();
        assert_eq!(
            fx.recorder().revoke(id).unwrap().record.state,
            ApprovalState::Revoked
        );
        let mut wire = fx.wire();
        wire.authorizations[0].state = AuthorizationState::Expired;
        wire.authorizations[0].disposition = Some(Disposition::Unused);
        let options = MintOptions {
            exempt_cap: false,
            lineage: Some(fx.operation),
        };
        assert_eq!(
            refusal(mint_into(
                &mut wire,
                fx.fixture.profile(),
                &request,
                now + 1,
                now + 100,
                options
            )),
            MainnetPrecondition::ApprovalRevoked,
            "a revoked record still refuses"
        );
    }

    #[test]
    #[serial]
    fn revoked_record_refuses_every_mint() {
        use super::super::approvals::{ApprovalState, tests::Fx};
        for consumed in [false, true] {
            let mut fx = Fx::new(300_000);
            fx.open();
            fx.consent();
            let request = fx.mint_request();
            let now = fx.payload.receipt.verified_at_unix_ms();
            if consumed {
                fx.store
                    .mint_authorization(fx.fixture.profile(), &request)
                    .unwrap();
            }
            let id = fx.id();
            let revoked = fx.recorder().revoke(id).unwrap();
            assert_eq!(revoked.record.state, ApprovalState::Revoked);
            assert_eq!(revoked.record.revoked_at_ms, Some(now));
            let mut wire = fx.wire();
            if consumed {
                wire.authorizations[0].state = AuthorizationState::Expired;
                wire.authorizations[0].disposition = Some(Disposition::Unused);
            }
            let options = MintOptions {
                exempt_cap: false,
                lineage: Some(fx.operation),
            };
            assert_eq!(
                refusal(mint_into(
                    &mut wire,
                    fx.fixture.profile(),
                    &request,
                    now + 1,
                    now + 100,
                    options
                )),
                MainnetPrecondition::ApprovalRevoked
            );
        }
    }

    #[test]
    #[serial]
    fn pending_record_without_consent_refuses_the_mint() {
        use super::super::approvals::tests::Fx;
        let mut fx = Fx::new(300_000);
        fx.open();
        let before = fx.bytes();
        assert_eq!(
            refusal(
                fx.store
                    .mint_authorization(fx.fixture.profile(), &fx.mint_request())
            ),
            MainnetPrecondition::ApprovalConsentMissing
        );
        assert_eq!(fx.bytes(), before);
    }

    #[test]
    #[serial]
    fn execution_boundary_is_exclusive() {
        use super::super::approvals::tests::Fx;
        for (ttl, duration) in [(86_400_000, 900_000), (300_000, 300_000)] {
            let mut fx = Fx::new(ttl);
            fx.open();
            fx.consent();
            let expiry = fx.payload.receipt.verified_at_unix_ms() + duration;
            let request = fx.mint_request();
            for (at, accepted) in [(expiry - 1, true), (expiry, false), (expiry + 1, false)] {
                fx.clock.set(at);
                let before = fx.bytes();
                let result = fx.store.mint_authorization(fx.fixture.profile(), &request);
                if accepted {
                    assert!(result.is_ok(), "{result:?}");
                } else {
                    // Remove the earlier carrier in memory to isolate the durable clock check.
                    let mut wire = fx.wire();
                    wire.authorizations.clear();
                    assert_eq!(
                        refusal(mint_into(
                            &mut wire,
                            fx.fixture.profile(),
                            &request,
                            at,
                            at + 100,
                            MintOptions::default()
                        )),
                        MainnetPrecondition::ApprovalExpired
                    );
                    assert!(result.is_err());
                    assert_eq!(fx.bytes(), before);
                }
            }
        }
    }

    impl crate::policy_state::operations::OperationAudit for NullAudit {
        fn append(
            &mut self,
            _entry: stellar_agent_core::audit_log::AuditEntry,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// A mint stores the operation link it names, and a link to an
    /// operation the window does not hold, or to an attempt outside the
    /// allowance, refuses without a write.
    #[test]
    #[serial]
    fn mint_stores_the_operation_link() {
        use crate::policy_state::operations::{
            BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationKind, OperationRecorder,
            OperationTool,
        };
        let l = Ledger::new();
        let mut audit = NullAudit;
        let opened = OperationRecorder::new(&l.store, &l.profile, &mut audit, "request-1")
            .open(&OpenRequest {
                business_id: BusinessId::parse("order-1").unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: IntentSlot::Canonical {
                    intent_digest: [1; 32],
                    intent: serde_json::json!({ "op": "pay" }),
                },
                envelope_xdr: Some("AAAASTORED".to_owned()),
                prepared_decision: None,
                rule_ttl_ms: None,
            })
            .unwrap();
        let OpenOutcome::New(handle) = opened else {
            panic!("expected a new record, got {opened:?}");
        };
        let link = OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        };
        let before = l.bytes();
        for stray in [
            OperationLink {
                operation_id: OperationId::random(),
                attempt_index: 1,
            },
            OperationLink {
                attempt_index: 0,
                ..link
            },
            OperationLink {
                attempt_index: 9,
                ..link
            },
        ] {
            let mut request = l.request(tx(1), vec![]);
            request.operation = Some(stray);
            assert!(
                matches!(
                    l.mint(&request),
                    Err(WindowStoreError::UnexpectedState { .. })
                ),
                "{stray:?}"
            );
            assert_eq!(l.bytes(), before);
        }
        let mut request = l.request(tx(1), vec![]);
        request.operation = Some(link);
        let minted = l.mint(&request).unwrap();
        assert_eq!(l.record(minted.id).operation, Some(link));
        let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
        let stored = reopened
            .read_for_inspection(&l.profile)
            .unwrap()
            .unwrap()
            .authorizations
            .into_iter()
            .find(|auth| auth.id == minted.id)
            .unwrap();
        assert_eq!(stored.operation, Some(link));
    }

    /// Total-budget accounting on the mainnet authorization path: the gate
    /// of an engine hydrated from the window file, and the durable admission
    /// `resolve::tx` runs after it, each checked on its own.
    mod total_budget {
        use super::super::super::store::{retire_earlier_build, total_in_file};
        use super::*;
        use ed25519_dalek::{Signer as _, SigningKey};
        use stellar_agent_core::policy::v1::PolicyEngineV1;
        use stellar_agent_core::policy::v1::canonical::canonical_bytes;
        use stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test;
        use stellar_agent_core::policy::v1::loader::load_signed_policy_text;
        use stellar_agent_core::policy::v1::signature::digest;
        use stellar_agent_core::policy::v1::value::{ActionKind, ValueClass, ValueLeg};
        use stellar_agent_core::policy::{
            Decision, DenyReason, McpToolRegistration, PolicyEngine as _, ToolDescriptor,
            ToolValueKind,
        };

        const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        /// Past every horizon the store knows: retention, the exposure
        /// horizon, and the authorization and approval lifetimes.
        const LATE: u64 = T0 + RETENTION_MS + 30 * 86_400_000;
        /// The fixture's pinned digest, which `Ledger::request` names.
        const P7: [u8; 32] = [7; 32];

        fn owner() -> SigningKey {
            SigningKey::from_bytes(&[11; 32])
        }

        struct Policy {
            text: String,
            digest: [u8; 32],
            sequence: i64,
        }

        /// A signed v2 policy with a native `total_budget` of 10.
        fn policy(sequence: i64) -> Policy {
            let body = format!(
                "version = 2\nscope = \"profile:ledger\"\nsequence = {sequence}\n\n\
                 [[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\n\
                 criteria = [{{ kind = \"total_budget\", asset = \"native\", max_stroops = 10 }}]\n\
                 decision = \"allow\"\n"
            );
            let d = digest(&canonical_bytes(&body).unwrap());
            let key = owner();
            let text = format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&key.sign(&d).to_bytes())
            );
            Policy {
                text,
                digest: d,
                sequence,
            }
        }

        fn pay_tool() -> ToolDescriptor {
            ToolDescriptor::from_registration(&McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: ToolValueKind::MovesValue,
            })
        }

        fn payment(amount: i128) -> ValueClass {
            ValueClass::single(ValueLeg {
                kind: ActionKind::Payment,
                amount: Some(amount),
                asset: Some("native".to_owned()),
                destination: Some(DEST.to_owned()),
            })
        }

        /// The engine a CLI process builds, or an MCP dispatch refreshes:
        /// the window file hydrated into a fresh in-memory store.
        fn hydrated(l: &Ledger, store: &PersistedWindowStore, p: &Policy) -> PolicyEngineV1 {
            let memory = PolicyStateStore::new();
            store.load_into("ledger", &l.profile, &memory).unwrap();
            let document = load_signed_policy_text(
                &p.text,
                "ledger",
                &owner().verifying_key().to_bytes(),
                &l.profile.network_passphrase,
            )
            .unwrap();
            PolicyEngineV1::new_with_store(document, "ledger".to_owned(), memory)
                .with_policy_digest_for_test(p.digest)
        }

        fn gate(engine: &PolicyEngineV1, l: &Ledger, amount: i128, now: u64) -> Decision {
            let _q = set_query_time_for_test(now);
            engine
                .evaluate_with_value_full(
                    &pay_tool(),
                    &serde_json::Value::Null,
                    &l.profile,
                    payment(amount),
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                )
                .unwrap()
                .decision
        }

        fn gate_denies(decision: &Decision) -> bool {
            matches!(
                decision,
                Decision::Deny(DenyReason::TotalBudgetExhausted { .. })
            )
        }

        fn durable_denies<T>(result: &Result<T, WindowStoreError>) -> bool {
            matches!(
                result,
                Err(WindowStoreError::PolicyDenied { reason })
                    if matches!(**reason, DenyReason::TotalBudgetExhausted { .. })
            )
        }

        /// The engine's sized holds for `amount`, minted under `p` at `now`
        /// for `binding`.
        fn admit_holds(
            l: &Ledger,
            store: &PersistedWindowStore,
            engine: &PolicyEngineV1,
            p: &Policy,
            binding: DomainBinding,
            amount: i128,
            now: u64,
        ) -> (MintRequest, Result<MintedRecord, WindowStoreError>) {
            let holds = engine
                .size_window_entries(&pay_tool(), &l.profile, &payment(amount), now)
                .unwrap();
            assert_eq!(holds.len(), 1, "one total hold");
            assert_eq!(holds[0].epoch(), Some(p.digest));
            let mut request = l.request(binding, holds);
            request.policy_sequence = p.sequence;
            request.policy_digest = p.digest;
            *request.authority.approval_expiry_mut() = now + APPROVAL_MS;
            let minted = store.mint_authorization(&l.profile, &request);
            (request, minted)
        }

        /// Both layers at `now` for `amount`, through a fresh hydration.
        fn both(l: &Ledger, p: &Policy, n: u8, amount: i128, now: u64) -> (Decision, bool) {
            l.clock.set(now);
            let engine = hydrated(l, &l.store, p);
            let decision = gate(&engine, l, amount, now);
            let (_, minted) = admit_holds(l, &l.store, &engine, p, tx(n), amount, now);
            assert!(
                minted.is_ok() || durable_denies(&minted),
                "unexpected {minted:?}"
            );
            (decision, minted.is_ok())
        }

        fn assert_denied((decision, admitted): (Decision, bool), label: &str) {
            assert!(gate_denies(&decision), "{label}: gate {decision:?}");
            assert!(!admitted, "{label}: the durable admission admits");
        }

        fn assert_admitted((decision, admitted): (Decision, bool), label: &str) {
            assert_eq!(decision, Decision::Allow, "{label}: gate");
            assert!(admitted, "{label}: the durable admission refuses");
        }

        /// Pays 6 under `p`: gate, mint, consume, confirm, and record.
        fn first_payment(l: &Ledger, p: &Policy) -> PolicyEngineV1 {
            let engine = hydrated(l, &l.store, p);
            assert_eq!(gate(&engine, l, 6, T0), Decision::Allow);
            let (request, minted) = admit_holds(l, &l.store, &engine, p, tx(1), 6, T0);
            let minted = minted.unwrap();
            l.clock.set(T0 + 50);
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
            l.clock.set(T0 + 100);
            let envelope = stellar_agent_core::hex::encode(&[(1_u8 ^ 0x80) ^ 0x5a; 32]);
            l.store
                .confirm(&l.profile, &envelope, Some(1_800_000_000))
                .unwrap();
            let _q = set_query_time_for_test(T0 + 100);
            engine
                .record_confirmed_checked(&pay_tool(), &l.profile, &payment(6))
                .unwrap();
            engine
        }

        /// A total entry of `amount` under `epoch` against a limit of 10.
        fn total(amount: i128, epoch: [u8; 32]) -> WindowEntry {
            total_in("total:native", amount, epoch)
        }

        fn total_in(bucket: &str, amount: i128, epoch: [u8; 32]) -> WindowEntry {
            WindowEntry::new(
                StateKey::new("ledger", 1, bucket, 0),
                T0,
                amount,
                WindowLimit::Total {
                    asset: "native".to_owned(),
                    max_stroops: 10,
                },
            )
            .with_epoch(Some(epoch))
        }

        /// The total an ordinary writer admits against at `now`: the file
        /// after the sweep that writer commits before it counts.
        fn sum(l: &Ledger, epoch: [u8; 32], now: u64) -> i128 {
            let mut wire = l.wire();
            sweep_expired(&mut wire, now);
            total_in_file(&wire, &StateKey::new("ledger", 1, "total:native", 0), epoch)
                .unwrap()
                .0
        }

        // ── probes on the mainnet route ──────────────────────────────────

        #[test]
        #[serial]
        fn total_survives_the_mcp_refresh() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            let engine = first_payment(&l, &p);
            l.clock.set(LATE);
            engine.state_store().clear().unwrap();
            l.store
                .load_into("ledger", &l.profile, engine.state_store())
                .unwrap();
            assert_eq!(
                gate(&engine, &l, 6, LATE),
                Decision::Deny(DenyReason::TotalBudgetExhausted {
                    asset: "native".to_owned(),
                    max_stroops: 10,
                    remaining_stroops: 4,
                })
            );
            let (_, minted) = admit_holds(&l, &l.store, &engine, &p, tx(4), 6, LATE);
            assert!(durable_denies(&minted), "{minted:?}");
        }

        #[test]
        #[serial]
        fn total_survives_a_reopen_past_every_horizon() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            drop(first_payment(&l, &p));
            for (n, now) in [(2_u8, T0 + 1_000), (3, T0 + 300_001), (4, LATE)] {
                l.clock.set(now);
                let reopened = PersistedWindowStore::at_path(l.store.path().to_owned());
                let engine = hydrated(&l, &reopened, &p);
                let decision = gate(&engine, &l, 6, now);
                let (_, minted) = admit_holds(&l, &reopened, &engine, &p, tx(n), 6, now);
                assert!(gate_denies(&decision), "{now}: {decision:?}");
                assert!(durable_denies(&minted), "{now}: {minted:?}");
            }
        }

        #[test]
        #[serial]
        fn a_new_epoch_starts_at_zero() {
            let l = Ledger::new();
            let first = policy(7);
            l.pin(first.sequence, first.digest);
            drop(first_payment(&l, &first));
            let resigned = policy(8);
            assert_ne!(resigned.digest, first.digest);
            l.pin(resigned.sequence, resigned.digest);
            assert_denied(both(&l, &resigned, 2, 11, T0 + 1_000), "11 under D2");
            assert_admitted(both(&l, &resigned, 3, 10, T0 + 1_000), "10 under D2");
        }

        #[test]
        #[serial]
        fn an_expired_signed_claim_stays_counted() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            let engine = hydrated(&l, &l.store, &p);
            let (request, minted) = admit_holds(&l, &l.store, &engine, &p, tx(1), 6, T0);
            let minted = minted.unwrap();
            l.clock.set(T0 + 7);
            l.claim(&request, &minted).unwrap();
            assert_denied(
                both(&l, &p, 2, 6, minted.expires_at_ms + 1),
                "expired claim",
            );
        }

        #[test]
        #[serial]
        fn an_unresolved_send_stays_counted() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            let engine = hydrated(&l, &l.store, &p);
            let (request, minted) = admit_holds(&l, &l.store, &engine, &p, tx(1), 6, T0);
            let minted = minted.unwrap();
            l.clock.set(T0 + 50);
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
            assert_denied(both(&l, &p, 2, 6, T0 + 1_000), "within maxTime");
            assert_denied(both(&l, &p, 3, 6, T0 + 300_001), "past maxTime");
            let reservation = l.store.pending_reservations(&l.profile).unwrap().remove(0);
            l.clock.set(T0 + 300_002);
            l.store
                .expire_accounting(&l.profile, None, &reservation, T0 + 300_002)
                .unwrap()
                .unwrap();
            assert_denied(both(&l, &p, 4, 6, T0 + 300_003), "after accounting expiry");
        }

        #[test]
        #[serial]
        fn an_unused_hold_releases() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            let engine = hydrated(&l, &l.store, &p);
            admit_holds(&l, &l.store, &engine, &p, tx(1), 6, T0)
                .1
                .unwrap();
            assert_denied(both(&l, &p, 2, 6, T0 + 1_000), "while open");
            assert_admitted(both(&l, &p, 3, 6, T0 + TTL_MS + 1), "after the TTL");
        }

        #[test]
        #[serial]
        fn concurrent_admissions_admit_one() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            let engines = [hydrated(&l, &l.store, &p), hydrated(&l, &l.store, &p)];
            assert_eq!(gate(&engines[0], &l, 6, T0), Decision::Allow);
            assert_eq!(gate(&engines[1], &l, 6, T0), Decision::Allow);
            let path = l.store.path().to_owned();
            let barrier = std::sync::Barrier::new(2);
            let requests: Vec<MintRequest> = [(1_u8, &engines[0]), (2_u8, &engines[1])]
                .into_iter()
                .map(|(n, engine)| {
                    let holds = engine
                        .size_window_entries(&pay_tool(), &l.profile, &payment(6), T0)
                        .unwrap();
                    let mut request = l.request(tx(n), holds);
                    request.policy_sequence = p.sequence;
                    request.policy_digest = p.digest;
                    request
                })
                .collect();
            let profile = l.profile.clone();
            let results: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = requests
                    .iter()
                    .map(|request| {
                        let path = path.clone();
                        let barrier = &barrier;
                        let profile = &profile;
                        scope.spawn(move || {
                            let store = PersistedWindowStore::at_path(path);
                            barrier.wait();
                            store.mint_authorization(profile, request).map(|_| ())
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let admitted = results.iter().filter(|r| r.is_ok()).count();
            assert!(
                admitted <= 1,
                "both admissions of 6 against 10: {results:?}"
            );
            if admitted == 1 {
                assert_denied(both(&l, &p, 3, 6, T0 + 10), "the retry");
            }
        }

        // ── durable admission ────────────────────────────────────────────

        /// Mints a Soroban total hold of 6 under `p` and consumes it into
        /// retained spend.
        fn retained_spend(l: &Ledger, p: &Policy) {
            let engine = hydrated(l, &l.store, p);
            let (request, minted) = admit_holds(l, &l.store, &engine, p, soroban(1), 6, T0);
            let minted = minted.unwrap();
            l.consume(&request, &minted, &consumption_of(&request.binding))
                .unwrap();
            let rows: Vec<_> = l
                .wire()
                .entries
                .iter()
                .filter(|bucket| bucket.bucket == "total:native")
                .flat_map(|bucket| bucket.records.clone())
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].status, RecordStatus::Confirmed);
            assert_eq!(rows[0].epoch, Some(p.digest));
        }

        #[test]
        #[serial]
        fn total_rows_survive_successful_pruning() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            retained_spend(&l, &p);
            l.clock.set(LATE);
            let late = WindowEntry::new(hold(1).key().clone(), LATE, 1, hold(1).limit().clone());
            l.store.record_and_persist(&l.profile, &[late]).unwrap();
            assert_eq!(sum(&l, p.digest, LATE), 6, "the total row remains");
            assert_denied(both(&l, &p, 2, 6, LATE), "after pruning");
        }

        #[test]
        #[serial]
        fn an_x402_consume_stays_counted() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            retained_spend(&l, &p);
            l.clock.set(LATE);
            let late = WindowEntry::new(hold(1).key().clone(), LATE, 1, hold(1).limit().clone());
            l.store.record_and_persist(&l.profile, &[late]).unwrap();
            assert_denied(both(&l, &p, 2, 6, LATE), "after a later write");
        }

        #[test]
        #[serial]
        fn assets_are_isolated_within_one_digest() {
            let l = Ledger::new();
            l.mint(&l.request(tx(1), vec![total(6, P7)])).unwrap();
            let other = format!("total:{DEST}");
            l.mint(&l.request(tx(2), vec![total_in(&other, 10, P7)]))
                .unwrap();
        }

        #[test]
        #[serial]
        fn open_holds_stay_in_their_epoch() {
            let l = Ledger::new();
            l.mint(&l.request(tx(1), vec![total(6, P7)])).unwrap();
            l.pin(8, [8; 32]);
            let mut request = l.request(tx(2), vec![total(10, [8; 32])]);
            request.policy_sequence = 8;
            request.policy_digest = [8; 32];
            l.mint(&request).unwrap();
        }

        #[test]
        #[serial]
        fn an_invalidated_hold_releases() {
            let l = Ledger::new();
            let minted = l.mint(&l.request(tx(1), vec![total(6, P7)])).unwrap();
            assert!(
                l.store
                    .invalidate_authorization(&l.profile, minted.id, "cancel")
                    .unwrap()
            );
            l.mint(&l.request(tx(2), vec![total(10, P7)])).unwrap();
        }

        #[test]
        #[serial]
        fn a_mint_binds_the_hold_epoch() {
            let l = Ledger::new();
            let before = l.store.path().exists();
            assert!(matches!(
                l.mint(&l.request(tx(1), vec![total(6, [8; 32])])),
                Err(WindowStoreError::TotalEpochStale)
            ));
            assert!(matches!(
                l.mint(&l.request(tx(2), vec![total(-1, P7)])),
                Err(WindowStoreError::Invalid { detail }) if detail == "a total-budget debit is negative"
            ));
            assert_eq!(l.store.path().exists(), before);
        }

        #[test]
        #[serial]
        fn equality_at_the_limit_passes() {
            let l = Ledger::new();
            let p = policy(7);
            l.pin(p.sequence, p.digest);
            assert_admitted(both(&l, &p, 1, 6, T0), "6 of 10");
            assert_admitted(both(&l, &p, 2, 4, T0 + 1), "10 of 10");
            assert_denied(both(&l, &p, 3, 1, T0 + 2), "11 of 10");
        }

        // ── reset ────────────────────────────────────────────────────────

        #[test]
        #[serial]
        fn reset_retains_a_claim_its_survivors_omit() {
            let l = Ledger::new();
            let request = l.request(tx(1), vec![total(6, P7)]);
            let minted = l.mint(&request).unwrap();
            l.clock.set(T0 + 7);
            l.claim(&request, &minted).unwrap();
            let after = T0 + APPROVAL_MS + 1;
            l.clock.set(after);
            l.reset(after).unwrap();
            let wire = l.wire();
            assert!(wire.authorizations.iter().all(|auth| auth.id != minted.id));
            let rows: Vec<_> = wire
                .entries
                .iter()
                .filter(|bucket| bucket.bucket == "total:native")
                .flat_map(|bucket| bucket.records.clone())
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                (rows[0].status, rows[0].amount, rows[0].epoch),
                (RecordStatus::Confirmed, 6, Some(P7))
            );
            assert_eq!(rows[0].authorization_id, Some(minted.id));
            assert_eq!(rows[0].ts_ms, T0 + 7);
        }

        #[test]
        #[serial]
        fn reset_converts_each_hold_once() {
            let l = Ledger::new();
            for (n, amount) in [(1_u8, 3), (2, 4)] {
                let request = l.request(tx(n), vec![total(amount, P7)]);
                let minted = l.mint(&request).unwrap();
                l.claim(&request, &minted).unwrap();
            }
            let after = T0 + TTL_MS + 1;
            l.clock.set(after);
            l.reset(after).unwrap();
            l.store
                .reset(
                    &l.profile,
                    &l.name(),
                    after + 1,
                    "repair",
                    "second-reset",
                    |row| Ok::<_, ()>(signed_by(11, row)),
                    |_, _| Ok(()),
                )
                .unwrap();
            assert_eq!(sum(&l, P7, after + 1), 7);
            assert!(l.wire().holds.is_empty());
        }

        // ── retirement and hydration on the mainnet route ────────────────

        /// Rewrites the committed file through `change`, sealing it unchecked.
        fn reseal(l: &Ledger, change: impl FnOnce(&mut WireFile)) {
            let mut wire = l.wire();
            change(&mut wire);
            l.store.seal_unchecked_for_test(&l.profile, &wire);
        }

        #[test]
        #[serial]
        fn earlier_build_content_is_not_relabelled() {
            let l = Ledger::new();
            l.mint(&l.request(tx(1), vec![total(6, P7)])).unwrap();
            let consumed = l.request(tx(2), vec![total(3, P7)]);
            let minted = l.mint(&consumed).unwrap();
            l.consume(&consumed, &minted, &consumption_of(&consumed.binding))
                .unwrap();
            reseal(&l, |wire| {
                wire.version = super::super::super::store::WIRE_VERSION_OPERATIONS;
                for record in wire.entries.iter_mut().flat_map(|b| &mut b.records) {
                    record.epoch = None;
                    record.authorization_id = None;
                }
                for hold in &mut wire.holds {
                    hold.epoch = None;
                }
            });
            l.pin(8, [8; 32]);
            let mut successor = l.wire();
            assert!(retire_earlier_build(&mut successor, Some([8; 32])).unwrap());
            assert_eq!(successor.retired_total_epoch, Some([8; 32]));
            assert_eq!(
                successor.version,
                super::super::super::store::WIRE_VERSION_TOTAL_EPOCH
            );
            assert!(successor.holds.iter().all(|hold| hold.epoch.is_none()));
            assert!(
                successor
                    .entries
                    .iter()
                    .flat_map(|bucket| &bucket.records)
                    .all(|record| record.epoch.is_none() && record.authorization_id.is_none())
            );
            l.store
                .load_into("ledger", &l.profile, &PolicyStateStore::new())
                .unwrap();
            let committed = l.wire();
            assert_eq!(committed.retired_total_epoch, Some([8; 32]));
            assert!(committed.holds.iter().all(|hold| hold.epoch.is_none()));
        }

        #[test]
        #[serial]
        fn retirement_refuses_a_total_mint() {
            let l = Ledger::new();
            l.mint(&l.request(tx(1), vec![hold(5)])).unwrap();
            reseal(&l, |wire| {
                wire.version = super::super::super::store::WIRE_VERSION_OPERATIONS;
            });
            l.store
                .load_into("ledger", &l.profile, &PolicyStateStore::new())
                .unwrap();
            assert_eq!(l.wire().retired_total_epoch, Some(P7));
            let error = l.mint(&l.request(tx(2), vec![total(1, P7)])).unwrap_err();
            assert!(matches!(error, WindowStoreError::TotalEpochRetired));
            assert_eq!(
                error.operation_error().unwrap().code(),
                "policy.total_epoch_retired"
            );
            #[cfg(feature = "mainnet-write")]
            assert_eq!(
                stellar_agent_core::error::WalletError::from(crate::mainnet::mint::store_error(
                    error
                ))
                .code(),
                "policy.total_epoch_retired",
                "the mainnet mint keeps the retired code"
            );
        }

        #[test]
        #[serial]
        fn hydration_and_admission_agree_on_the_sum() {
            let l = Ledger::new();
            let now = T0 + 1_000;
            // An open hold, a claimed hold, and two unclaimed holds that
            // expire at `now + 1`.
            l.mint(&l.request(tx(1), vec![total(1, P7)])).unwrap();
            let claimed = l.request(tx(2), vec![total(2, P7)]);
            let minted = l.mint(&claimed).unwrap();
            l.claim(&claimed, &minted).unwrap();
            for n in [3_u8, 4] {
                let mut request = l.request(tx(n), vec![total(1, P7)]);
                request.authorization_ttl_ms = now + 1 - T0;
                l.mint(&request).unwrap();
            }
            reseal(&l, |wire| {
                let key = StateKey::new("", 1, "total:native", 0);
                let bucket = find_or_insert_bucket(&mut wire.entries, &key);
                for (status, epoch) in [
                    (RecordStatus::Confirmed, P7),
                    (RecordStatus::Pending, P7),
                    (RecordStatus::Exposure, P7),
                    (RecordStatus::AccountingExpired, P7),
                    (RecordStatus::OperatorCleared, P7),
                    (RecordStatus::ProvedUnspent, P7),
                    (RecordStatus::Confirmed, [8; 32]),
                ] {
                    bucket.records.push(WireRecord {
                        chain_scope: wire.chain_scope,
                        ts_ms: T0,
                        amount: 1,
                        status,
                        epoch: Some(epoch),
                        id: "ef".repeat(32),
                        ..WireRecord::confirmed_defaults()
                    });
                }
            });
            for at in [now, now + 1] {
                l.clock.set(at);
                let memory = PolicyStateStore::new();
                l.store.load_into("ledger", &l.profile, &memory).unwrap();
                for epoch in [P7, [8; 32]] {
                    let key = StateKey::new("ledger", 1, "total:native", 0);
                    assert_eq!(
                        memory.query_epoch(&key, epoch).unwrap().0,
                        sum(&l, epoch, at),
                        "{at}"
                    );
                }
            }
            assert_eq!(sum(&l, P7, now), 2 + 1 + 1 + 1 + 5);
            assert_eq!(sum(&l, P7, now + 1), 2 + 1 + 5);
        }

        #[test]
        #[serial]
        fn hydration_samples_one_clock() {
            let l = Ledger::new();
            for n in [1_u8, 2] {
                l.mint(&l.request(tx(n), vec![total(1, P7)])).unwrap();
            }
            let expiry = T0 + TTL_MS;
            l.clock.set(expiry);
            super::super::super::store::CLOCK_READS.set(0);
            let memory = PolicyStateStore::new();
            l.store.load_into("ledger", &l.profile, &memory).unwrap();
            assert_eq!(super::super::super::store::CLOCK_READS.get(), 1);
            let key = StateKey::new("ledger", 1, "total:native", 0);
            assert_eq!(memory.query_epoch(&key, P7).unwrap().0, 0);
            assert_eq!(sum(&l, P7, expiry), 0);
        }

        // ── one asset under its classic and its asset-contract spelling ──

        /// A signed v2 policy: `stellar_pay` under a native total of 10 and
        /// `stellar_create_account` under a total of 10 in the native asset
        /// contract of the profile's network.
        fn two_spelling_policy(l: &Ledger) -> (Policy, String) {
            let native_sac = stellar_agent_core::asset_id::CanonicalAsset::Native
                .sac_contract_id(&l.profile.network_passphrase)
                .unwrap();
            let body = format!(
                "version = 2\nscope = \"profile:ledger\"\nsequence = 9\n\n\
                 [[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"*\" }}\n\
                 criteria = [{{ kind = \"total_budget\", asset = \"native\", max_stroops = 10 }}]\n\
                 decision = \"allow\"\n\n\
                 [[rules]]\nmatch = {{ tool = \"stellar_create_account\", chain = \"*\" }}\n\
                 criteria = [{{ kind = \"total_budget\", asset = \"{native_sac}\", max_stroops = 10 }}]\n\
                 decision = \"allow\"\n"
            );
            let d = digest(&canonical_bytes(&body).unwrap());
            let key = owner();
            let text = format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&key.sign(&d).to_bytes())
            );
            (
                Policy {
                    text,
                    digest: d,
                    sequence: 9,
                },
                native_sac,
            )
        }

        fn creation_tool() -> ToolDescriptor {
            ToolDescriptor::from_registration(&McpToolRegistration {
                name: "stellar_create_account",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: ToolValueKind::MovesValue,
            })
        }

        fn creation(amount: i128) -> ValueClass {
            ValueClass::single(ValueLeg {
                kind: ActionKind::AccountCreation,
                amount: Some(amount),
                asset: Some("native".to_owned()),
                destination: Some(DEST.to_owned()),
            })
        }

        /// Both layers for one call of `tool` with `value` at `now`, through
        /// a fresh hydration of `store`.
        fn spend(
            l: &Ledger,
            store: &PersistedWindowStore,
            p: &Policy,
            tool: &ToolDescriptor,
            value: &ValueClass,
            n: u8,
            now: u64,
        ) -> (Decision, Result<MintedRecord, WindowStoreError>) {
            let engine = hydrated(l, store, p);
            let _q = set_query_time_for_test(now);
            let decision = engine
                .evaluate_with_value_full(
                    tool,
                    &serde_json::Value::Null,
                    &l.profile,
                    value.clone(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                )
                .unwrap()
                .decision;
            let holds = engine
                .size_window_entries(tool, &l.profile, value, now)
                .unwrap();
            let mut request = l.request(tx(n), holds);
            request.policy_sequence = p.sequence;
            request.policy_digest = p.digest;
            (decision, store.mint_authorization(&l.profile, &request))
        }

        #[test]
        #[serial]
        fn equivalent_asset_spellings_share_one_total() {
            let l = Ledger::new();
            let (p, _) = two_spelling_policy(&l);
            l.pin(p.sequence, p.digest);
            let (decision, minted) = spend(&l, &l.store, &p, &pay_tool(), &payment(6), 1, T0);
            assert_eq!(decision, Decision::Allow);
            minted.unwrap();
            for reopen in [false, true] {
                let store = if reopen {
                    PersistedWindowStore::at_path(l.store.path().to_owned())
                } else {
                    l.store.clone()
                };
                let (decision, minted) =
                    spend(&l, &store, &p, &creation_tool(), &creation(6), 2, T0 + 1);
                assert!(
                    gate_denies(&decision),
                    "reopen {reopen}: one asset is allocated 6 + 6 at the gate"
                );
                assert!(
                    durable_denies(&minted),
                    "reopen {reopen}: one asset is allocated 6 + 6: {minted:?}"
                );
            }
        }

        /// A stored total row under either spelling of one asset, the bucket
        /// name taken from the policy text, counts in the one bucket that
        /// both spellings name.
        #[test]
        #[serial]
        fn stored_rows_of_either_spelling_count_together() {
            let (_, native_sac) = two_spelling_policy(&Ledger::new());
            for stored in ["native".to_owned(), native_sac] {
                let l = Ledger::new();
                let (p, _) = two_spelling_policy(&l);
                l.pin(p.sequence, p.digest);
                l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
                reseal(&l, |wire| {
                    let key = StateKey::new("", 1, &format!("total:{stored}"), 0);
                    find_or_insert_bucket(&mut wire.entries, &key)
                        .records
                        .push(WireRecord {
                            ts_ms: T0,
                            amount: 6,
                            epoch: Some(p.digest),
                            ..WireRecord::confirmed_defaults()
                        });
                });
                for reopen in [false, true] {
                    let store = if reopen {
                        PersistedWindowStore::at_path(l.store.path().to_owned())
                    } else {
                        l.store.clone()
                    };
                    for (n, tool, value) in [
                        (1, pay_tool(), payment(6)),
                        (2, creation_tool(), creation(6)),
                    ] {
                        let (decision, minted) = spend(&l, &store, &p, &tool, &value, n, T0 + 1);
                        assert!(
                            gate_denies(&decision),
                            "stored under {stored}, reopen {reopen}, {}: gate {decision:?}",
                            tool.name
                        );
                        assert!(
                            durable_denies(&minted),
                            "stored under {stored}, reopen {reopen}, {}: {minted:?}",
                            tool.name
                        );
                    }
                }
                let (decision, minted) =
                    spend(&l, &l.store, &p, &creation_tool(), &creation(4), 3, T0 + 2);
                assert_eq!(decision, Decision::Allow, "equality under {stored}");
                minted.unwrap();
            }
        }

        // ── the shape refusal precedes key creation ──────────────────────

        fn key_present(l: &Ledger) -> bool {
            let id = &l.profile.policy_window_state_key_id;
            keyring_core::Entry::new(&id.service, &id.account)
                .unwrap()
                .get_password()
                .is_ok()
        }

        /// Malformed entries, each beside another defect a later check
        /// refuses: the shape refusal wins, and no key, file, or counter is
        /// created.
        #[test]
        #[serial]
        fn a_malformed_mint_creates_no_key() {
            let windowed_total = WindowEntry::new(
                StateKey::new("ledger", 1, "native", 86_400),
                T0,
                6,
                WindowLimit::Total {
                    asset: "native".to_owned(),
                    max_stroops: 10,
                },
            )
            .with_epoch(Some(P7));
            let unepoched = WindowEntry::new(
                StateKey::new("ledger", 1, "total:native", 0),
                T0,
                6,
                WindowLimit::Total {
                    asset: "native".to_owned(),
                    max_stroops: 10,
                },
            );
            for (entry, expected) in [
                (
                    windowed_total,
                    "a total-budget entry's limit and key disagree",
                ),
                (unepoched, "a total-budget entry needs its epoch"),
            ] {
                for defect in ["none", "malformed pin", "future timestamp"] {
                    let l = Ledger::new();
                    let mut entry = entry.clone();
                    if defect == "malformed pin" {
                        let entry_ref =
                            PinScope::for_profile(l.store.path(), &l.profile).pin_entry_ref();
                        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                            .unwrap()
                            .set_password("unreadable")
                            .unwrap();
                    }
                    if defect == "future timestamp" {
                        entry = WindowEntry::new(
                            entry.key().clone(),
                            T0 + 3_600_000,
                            entry.amount(),
                            entry.limit().clone(),
                        )
                        .with_epoch(entry.epoch());
                    }
                    assert!(!key_present(&l));
                    let result = l.mint(&l.request(tx(1), vec![entry]));
                    assert!(
                        matches!(&result, Err(WindowStoreError::Invalid { detail }) if detail == expected),
                        "{defect}: {result:?}"
                    );
                    assert!(
                        !key_present(&l),
                        "{defect}: shape refusal mints the state key"
                    );
                    assert!(!l.store.path().exists(), "{defect}");
                    assert!(
                        get_raw_generation(&l).is_none(),
                        "{defect}: the counter is written"
                    );
                }
            }
        }

        fn get_raw_generation(l: &Ledger) -> Option<String> {
            let entry_ref = generation_entry_ref(&l.profile);
            keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                .unwrap()
                .get_password()
                .ok()
        }

        // ── shape checks of the mint ─────────────────────────────────────

        #[test]
        #[serial]
        fn a_mint_refuses_a_total_limit_on_a_windowed_key() {
            let l = Ledger::new();
            let entry = WindowEntry::new(
                StateKey::new("ledger", 1, "native", 86_400),
                T0,
                6,
                WindowLimit::Total {
                    asset: "native".to_owned(),
                    max_stroops: 10,
                },
            )
            .with_epoch(Some(P7));
            assert!(matches!(
                l.mint(&l.request(tx(1), vec![entry])),
                Err(WindowStoreError::Invalid { detail })
                    if detail == "a total-budget entry's limit and key disagree"
            ));
            assert!(!l.store.path().exists());
        }

        #[test]
        #[serial]
        fn a_mint_refuses_an_amount_limit_on_a_total_key() {
            let l = Ledger::new();
            let entry = WindowEntry::new(
                StateKey::new("ledger", 1, "total:native", 0),
                T0,
                6,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 10,
                },
            )
            .with_epoch(Some(P7));
            assert!(matches!(
                l.mint(&l.request(tx(1), vec![entry])),
                Err(WindowStoreError::Invalid { detail })
                    if detail == "a total-budget entry's limit and key disagree"
            ));
            assert!(!l.store.path().exists());
        }
    }
}
