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
//! authorization is consumed, invalidated, or expires.
//!
//! Every hold belongs to exactly one open authorization; a hold of a settled
//! or unknown authorization, a duplicate identity or ordinal, a reservation
//! other than the authorization's own, a hold kind other than the domain's,
//! or authorization history in a snapshot below version 4 refuses the read.
//!
//! # Freshness
//!
//! Every transition reads the mainnet clock, [`crate::mainnet::clock::now_ms`],
//! itself; no caller supplies the time a transition is checked against. Under
//! the lock, a transition first marks every open authorization whose expiry
//! has passed as expired, sets its settlement time, and drops only its holds.
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
use stellar_agent_core::policy::pin::{self, PinError, PinScope};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::policy::v1::criteria::state_store::{CLOCK_SKEW_TOLERANCE_MS, WindowEntry};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::Profile;

use super::WindowStoreError;
use super::store::{
    PersistedWindowStore, RecordStatus, WireFile, WireRecord, admit, file_holds_id,
    find_or_insert_bucket, generation_entry_ref, i128_decimal_str, now_ms, prune_stale,
    select_wire_version,
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

/// Serde adapter for an optional 32-byte value stored as lowercase hex.
mod opt_hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => super::hex32::serialize(bytes, s),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
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
    /// Consumed once.
    Used,
    /// Its expiry passed before it was used.
    Expired,
    /// Abandoned by its holder before use.
    Invalidated,
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
    pub(super) policy_sequence: i64,
    #[serde(with = "hex32")]
    pub(super) policy_digest: [u8; 32],
    pub(super) approval_nonce: String,
    pub(super) approval_expires_ms: u64,
    #[serde(with = "hex32")]
    pub(super) bindings_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub(super) entries_digest: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reservation: Option<AuthorizationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) parent: Option<AuthorizationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) consumption: Option<ConsumptionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) invalidation: Option<String>,
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
}

/// Validates the authorization history of one snapshot.
///
/// # Errors
///
/// [`WindowStoreError::Invalid`] naming the first broken invariant.
pub(super) fn validate(wire: &WireFile) -> Result<(), WindowStoreError> {
    let invalid = |detail: String| WindowStoreError::Invalid { detail };
    if wire.version < 4 && (!wire.authorizations.is_empty() || !wire.holds.is_empty()) {
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
        if auth.binding.domain() != auth.domain
            || auth.content_digest != auth.binding.content_digest()
        {
            return Err(invalid(
                "an authorization's content does not match its domain facts".to_owned(),
            ));
        }
        if (auth.state == AuthorizationState::Open) == auth.settled_ms.is_some() {
            return Err(invalid(
                "an authorization's settlement time disagrees with its state".to_owned(),
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
        if auth.parent.is_some() != (auth.domain == AuthorizationDomain::X402Submit) {
            return Err(invalid(
                "an authorization's parent disagrees with its domain".to_owned(),
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
        if owner.state != AuthorizationState::Open {
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
        if auth.state == AuthorizationState::Open
            && auth.reservation.is_some() != holding.contains(&auth.id)
        {
            return Err(invalid(
                "an open authorization's reservation disagrees with its holds".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Marks every open authorization whose expiry is at or before `now_ms`
/// expired, sets its settlement time, and drops only its holds. Returns
/// whether anything changed.
pub(super) fn sweep_expired(wire: &mut WireFile, now_ms: u64) -> bool {
    let mut swept = Vec::new();
    for auth in &mut wire.authorizations {
        if auth.state == AuthorizationState::Open && auth.expires_ms <= now_ms {
            auth.state = AuthorizationState::Expired;
            auth.settled_ms = Some(now_ms);
            swept.push(auth.id);
        }
    }
    wire.holds
        .retain(|hold| !swept.contains(&hold.authorization_id));
    !swept.is_empty()
}

/// Drops settled authorization history older than `cutoff`; open records
/// stay whatever their age.
pub(super) fn prune_history(wire: &mut WireFile, cutoff: u64) {
    wire.authorizations.retain(|auth| {
        auth.state == AuthorizationState::Open || auth.settled_ms.is_some_and(|t| t >= cutoff)
    });
}

/// Whether `auth` is effective at `now_ms`: open and inside its lifetime.
fn effective(auth: &WireAuthorization, now_ms: u64) -> bool {
    auth.state == AuthorizationState::Open && auth.minted_ms <= now_ms && now_ms < auth.expires_ms
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
    /// The approval nonce.
    pub approval_nonce: String,
    /// The approval's expiry, in Unix milliseconds.
    pub approval_expires_at_ms: u64,
    /// The authorization's lifetime, in milliseconds.
    pub authorization_ttl_ms: u64,
    /// Per-proof fact digests. The reservation must be absent; mint computes it.
    pub bindings: BindingFacts,
    /// The window entries the authorization holds: the value entries of a
    /// transaction, an inner fee bump, or a Soroban intent, and the fee
    /// entries of an outer fee bump. Empty for every other domain.
    pub holds: Vec<WindowEntry>,
    /// The used authorization an x402 submission continues; absent for every
    /// other domain.
    pub parent: Option<AuthorizationId>,
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
    /// When it expires: the earlier of the issue time plus the lifetime and
    /// the approval's expiry.
    pub expires_at_ms: u64,
    /// The window reservation of its holds; absent when it holds nothing.
    pub reservation: Option<WindowReservation>,
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
    approval_nonce: String,
    approval_expires_ms: u64,
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
        approval_nonce: String,
        approval_expires_ms: u64,
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
            approval_nonce,
            approval_expires_ms,
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
    /// When it expires, in Unix milliseconds.
    pub expires_at_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Transitions
// ─────────────────────────────────────────────────────────────────────────────

fn pin_refusal(error: PinError) -> WindowStoreError {
    match error {
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
    )?;
    check(
        auth.chain == profile.chain_id,
        MainnetPrecondition::ChainMismatch,
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
    check(
        auth.approval_nonce == expect.approval_nonce,
        P::ApprovalNonce,
    )?;
    check(
        auth.approval_expires_ms == expect.approval_expires_ms,
        P::ApprovalExpiry,
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
                operator_required: false,
            },
            // Retained authorized spend: confirmed at the moment the store
            // released it, as an authorized external settlement is.
            _ => WireRecord {
                ts_ms: now,
                amount: hold.amount,
                ..WireRecord::confirmed_defaults()
            },
        };
        let key = stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
            "",
            hold.scope_specificity,
            &hold.bucket,
            hold.window_secs,
        );
        find_or_insert_bucket(&mut wire.entries, &key)
            .records
            .push(record);
    }
    if let Some(auth) = wire.authorizations.iter_mut().find(|auth| auth.id == id) {
        auth.state = AuthorizationState::Used;
        auth.settled_ms = Some(now);
        auth.consumption = Some(binding.clone());
    }
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
    /// clock plus [`CLOCK_SKEW_TOLERANCE_MS`]; the lifetime is the
    /// earlier of the issue time plus `authorization_ttl_ms` and the
    /// approval's expiry, and a zero, an overflowing, or an already elapsed
    /// lifetime refuses; the policy pin must be present and equal to the
    /// request's policy. These checks precede the window key, so a refusal
    /// among them mints no key. Then expired authorizations are swept; no open
    /// authorization may name the same domain and content; an x402 submission
    /// must continue a used Soroban intent of the same profile, chain,
    /// consumer, policy, and approval that has no child yet, and every other
    /// request's approval nonce must appear on no record within retention;
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
        use MainnetPrecondition as P;
        let lock = self.ledger_lock(profile)?;
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
            HoldKind::of(domain).is_some() || request.holds.is_empty(),
            P::HoldsMismatch,
        )?;
        check(
            request.parent.is_some() == (domain == AuthorizationDomain::X402Submit),
            P::IntentRecordMismatch,
        )?;
        let now = now_ms()?;
        check(
            request
                .holds
                .iter()
                .all(|entry| entry.timestamp_ms() <= now.saturating_add(CLOCK_SKEW_TOLERANCE_MS)),
            P::HoldsMismatch,
        )?;
        check(request.authorization_ttl_ms > 0, P::LifetimeInvalid)?;
        let ttl_end = now
            .checked_add(request.authorization_ttl_ms)
            .ok_or_else(|| refused(P::LifetimeInvalid))?;
        let expires = ttl_end.min(request.approval_expires_at_ms);
        check(expires > now, P::LifetimeInvalid)?;

        pin::compare(
            &lock,
            &PinScope::for_profile(self.path(), profile),
            request.policy_sequence,
            &request.policy_digest,
        )
        .map_err(pin_refusal)?;

        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        let mut wire = original.clone();
        sweep_expired(&mut wire, now);

        let content = request.binding.content_digest();
        check(
            !wire.authorizations.iter().any(|auth| {
                auth.state == AuthorizationState::Open
                    && auth.domain == domain
                    && auth.content_digest == content
            }),
            P::DuplicateOpen,
        )?;
        match request.parent {
            Some(parent_id) => {
                let parent = wire.authorizations.iter().find(|auth| auth.id == parent_id);
                check(
                    parent.is_some_and(|parent| {
                        parent.state == AuthorizationState::Used
                            && parent.domain == AuthorizationDomain::Soroban
                            && parent.profile
                                == stellar_agent_core::profile::name::profile_name_for_approval(
                                    profile,
                                )
                            && parent.chain == request.chain
                            && parent.consumer == request.consumer
                            && parent.policy_sequence == request.policy_sequence
                            && parent.policy_digest == request.policy_digest
                            && parent.approval_nonce == request.approval_nonce
                            && parent.approval_expires_ms == request.approval_expires_at_ms
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
            None => check(
                !wire
                    .authorizations
                    .iter()
                    .any(|auth| auth.approval_nonce == request.approval_nonce),
                P::ApprovalNonceReused,
            )?,
        }
        check(
            wire.authorizations
                .iter()
                .filter(|auth| auth.state == AuthorizationState::Open)
                .count()
                < MAX_OPEN_AUTHORIZATIONS,
            P::TooManyOpen,
        )?;
        admit(&wire, &request.holds)?;

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
            policy_sequence: request.policy_sequence,
            policy_digest: request.policy_digest,
            approval_nonce: request.approval_nonce.clone(),
            approval_expires_ms: request.approval_expires_at_ms,
            bindings_digest,
            entries_digest: entries_digest(&request.holds),
            reservation,
            parent: request.parent,
            consumption: None,
            invalidation: None,
        });
        prune_stale(&mut wire, now);
        wire.version = select_wire_version(&wire);
        self.commit_generation(&key, &gen_entry, original, wire)?;
        drop(lock);
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

    /// Consumes every listed authorization in one transaction, all or
    /// nothing.
    ///
    /// Under one lock, on the store's clock, after sweeping expired
    /// authorizations: each record must exist, be open, and be inside its
    /// lifetime; the supplied profile's name and chain must be the record's;
    /// every expectation must equal the record; the policy pin,
    /// read under the same lock, must still equal the record's policy; the
    /// binding must be the one the domain is consumed by and match its
    /// facts. A transaction binding whose envelope the window already holds
    /// refuses as a duplicate. Then each consumption is applied: transaction
    /// holds become the submission's pending records, Soroban holds become
    /// retained authorized spend, and every record is marked used with its
    /// binding. One generation commit covers the batch; a second consumption
    /// of a record, in the same batch or later, refuses.
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::AuthorizationRefused`] naming the broken
    ///   precondition; the store file is not written.
    /// - [`WindowStoreError::DuplicateReservation`] for an envelope the window
    ///   already holds.
    /// - Every integrity, keyring, lock, and I/O error of the store.
    pub fn consume_authorizations(
        &self,
        profile: &Profile,
        batch: &[(AuthorizationId, ConsumeExpect, ConsumptionBinding)],
    ) -> Result<Vec<ConsumeReceipt>, WindowStoreError> {
        use MainnetPrecondition as P;
        let lock = self.ledger_lock(profile)?;
        let now = now_ms()?;
        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = self.read_verified(profile, &key, &gen_entry)?;
        let mut wire = original.clone();
        sweep_expired(&mut wire, now);
        let scope = PinScope::for_profile(self.path(), profile);
        let mut receipts = Vec::with_capacity(batch.len());
        let mut checked_envelopes = Vec::new();
        for (id, expect, binding) in batch {
            let auth = wire
                .authorizations
                .iter()
                .find(|auth| auth.id == *id)
                .ok_or_else(|| refused(P::UnknownAuthorization))?;
            check(auth.state == AuthorizationState::Open, P::NotOpen)?;
            check(auth.minted_ms <= now, P::NotYetValid)?;
            check_profile_handle(auth, profile)?;
            compare_expectation(auth, expect)?;
            pin::compare(&lock, &scope, auth.policy_sequence, &auth.policy_digest)
                .map_err(pin_refusal)?;
            check_consumption(&wire, auth, binding)?;
            if let ConsumptionBinding::Transaction(submission) = binding {
                let has_holds = wire.holds.iter().any(|hold| hold.authorization_id == *id);
                let envelope = stellar_agent_core::hex::encode(&submission.envelope_hash);
                if has_holds && !checked_envelopes.contains(&envelope) {
                    if file_holds_id(&original, &envelope) {
                        return Err(WindowStoreError::DuplicateReservation);
                    }
                    checked_envelopes.push(envelope);
                }
            }
            let domain = auth.domain;
            apply_consumption(&mut wire, *id, binding, now);
            receipts.push(ConsumeReceipt {
                authorization_id: *id,
                domain,
                consumed_at_ms: now,
            });
        }
        prune_stale(&mut wire, now);
        wire.version = select_wire_version(&wire);
        self.commit_generation(&key, &gen_entry, original, wire)?;
        drop(lock);
        Ok(receipts)
    }

    /// Abandons an open authorization before use: marks it invalidated with a
    /// bounded `reason`, sets its settlement time, and drops its holds.
    ///
    /// Returns `Ok(false)` for a settled record; this may still commit the
    /// expiry sweep. A used record is never reopened.
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::AuthorizationRefused`] with
    ///   [`MainnetPrecondition::UnknownAuthorization`] for an unknown identity,
    ///   and with [`MainnetPrecondition::ProfileMismatch`] or
    ///   [`MainnetPrecondition::ChainMismatch`] when the supplied profile's
    ///   name or chain is not the record's. On refusal the store file is not
    ///   written.
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
        let mut wire = original.clone();
        let swept = sweep_expired(&mut wire, now);
        let auth = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == id)
            .ok_or_else(|| refused(MainnetPrecondition::UnknownAuthorization))?;
        check_profile_handle(auth, profile)?;
        let invalidated = auth.state == AuthorizationState::Open;
        if invalidated {
            auth.state = AuthorizationState::Invalidated;
            auth.settled_ms = Some(now);
            auth.invalidation = Some(reason.chars().take(INVALIDATION_REASON_MAX).collect());
            wire.holds.retain(|hold| hold.authorization_id != id);
        }
        if invalidated || swept {
            prune_stale(&mut wire, now);
            wire.version = select_wire_version(&wire);
            self.commit_generation(&key, &gen_entry, original, wire)?;
        }
        drop(lock);
        Ok(invalidated)
    }

    /// Lists the authorizations effective at `now_ms`: open and inside their
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

    use super::super::store::{RETENTION_MS, SubmissionHold};
    use super::*;
    use crate::mainnet::clock::{TestClockGuard, set_now_ms_for_test};
    use crate::mainnet::types::RecomputedFacts;

    /// A change to a mint request that breaks one continuation requirement.
    type Mutation = fn(&mut MintRequest);

    /// A change to a valid snapshot that breaks one ledger invariant.
    type Breakage = fn(&mut WireFile);

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
            pin::write(
                &lock,
                &PinScope::for_profile(self.store.path(), &self.profile),
                &Pin::new(sequence, digest, [1; 32]).unwrap(),
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
                consumer: if matches!(
                    binding.domain(),
                    AuthorizationDomain::Soroban | AuthorizationDomain::X402Submit
                ) {
                    MainnetConsumer::X402Create
                } else {
                    MainnetConsumer::CliPay
                },
                binding,
                policy_sequence: 7,
                policy_digest: [7; 32],
                approval_nonce: format!("nonce-{n}"),
                approval_expires_at_ms: T0 + APPROVAL_MS,
                authorization_ttl_ms: TTL_MS,
                bindings: BindingFacts {
                    endpoint: None,
                    signer: [2; 32],
                    policy: [3; 32],
                    enablement: [4; 32],
                    witness: None,
                    reservation: None,
                    approval: [7; 32],
                    audit: [8; 32],
                },
                holds,
                parent: None,
            }
        }

        fn mint(&self, request: &MintRequest) -> Result<MintedRecord, WindowStoreError> {
            self.store.mint_authorization(&self.profile, request)
        }

        fn expect(&self, request: &MintRequest, minted: &MintedRecord) -> ConsumeExpect {
            ConsumeExpect::new(
                self.name(),
                request.chain,
                request.consumer,
                request.binding.clone(),
                request.policy_sequence,
                request.policy_digest,
                request.approval_nonce.clone(),
                request.approval_expires_at_ms,
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
    }

    fn refusal<T: std::fmt::Debug>(result: Result<T, WindowStoreError>) -> MainnetPrecondition {
        match result {
            Err(WindowStoreError::AuthorizationRefused { precondition }) => precondition,
            other => panic!("expected an authorization refusal, got {other:?}"),
        }
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

    fn submission(
        tx_hash: [u8; 32],
        source: &str,
        sequence: i64,
        fee_bump: Option<FeeBumpFacts>,
    ) -> ConsumptionBinding {
        ConsumptionBinding::Transaction(SubmissionBinding {
            fee_bump,
            envelope_hash: [0xee; 32],
            tx_hash,
            source: source.to_owned(),
            sequence,
            max_time: 1_800_000_300,
            pending_since_ms: T0 + 5,
            submission_ledger: 512,
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
        assert_eq!(wire.version, 4);
        let record = l.record(minted.id);
        assert_eq!(record.state, AuthorizationState::Open);
        assert_eq!(record.domain, AuthorizationDomain::Transaction);
        assert_eq!(record.content_digest, tx(1).content_digest());
        assert_eq!(record.entries_digest, entries_digest(&request.holds));
        assert_eq!(record.reservation, Some(minted.id));
        assert_eq!((record.minted_ms, record.expires_ms), (T0, T0 + TTL_MS));
        assert_eq!(record.approval_expires_ms, T0 + APPROVAL_MS);
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
    fn the_lifetime_is_the_earlier_of_the_ttl_and_the_approval_expiry() {
        let l = Ledger::new();
        let mut short_approval = l.request(message(1), vec![]);
        short_approval.approval_expires_at_ms = T0 + 30_000;
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
        elapsed.approval_expires_at_ms = T0;
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
        reuse.approval_nonce = first.approval_nonce.clone();
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
                    id: "a".repeat(64),
                    tx_hash: "b".repeat(64),
                    source: SOURCE.to_owned(),
                    sequence: 9,
                    max_time: 0,
                    pending_since_ms: T0,
                    submission_ledger: 1,
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
            assert_eq!(record.id, "ee".repeat(32));
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
        assert_eq!(pending[0].id, "ee".repeat(32));

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
                    approval_nonce: "other".to_owned(),
                    ..base.clone()
                },
                P::ApprovalNonce,
            ),
            (
                "approval expiry",
                ConsumeExpect {
                    approval_expires_ms: T0 + APPROVAL_MS + 1,
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
        child.approval_nonce = intent.approval_nonce.clone();
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
        second.approval_nonce = child.approval_nonce.clone();
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
            child.approval_nonce = intent.approval_nonce.clone();
            child.parent = Some(open.id);
            assert_eq!(refusal(l.mint(&child)), P::IntentRecordMismatch);
        }
        // The fields are equal.
        let mutations: [(&str, Mutation); 4] = [
            ("consumer", |c| {
                c.consumer = MainnetConsumer::X402Authenticated
            }),
            ("nonce", |c| c.approval_nonce = "other".to_owned()),
            ("approval expiry", |c| c.approval_expires_at_ms -= 1),
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
            child.approval_nonce = tx_request.approval_nonce.clone();
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
                ("fee".to_owned(), 2, "ee".repeat(32)),
                ("native".to_owned(), 100, "ee".repeat(32))
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
                    id: "ee".repeat(32),
                    tx_hash: "b".repeat(64),
                    source: SOURCE.to_owned(),
                    sequence: 9,
                    max_time: 0,
                    pending_since_ms: T0,
                    submission_ledger: 1,
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
        assert_eq!(l.wire().version, 4, "settled history keeps version 4");

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
        assert_eq!(wire.version, 3, "an empty history is written as version 3");
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
        prune_history(&mut wire, 100);
        assert_eq!(wire.authorizations, vec![open, recent_settled]);
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
            policy_sequence: 7,
            policy_digest: [7; 32],
            approval_nonce: format!("n{n}"),
            approval_expires_ms: 1_000,
            bindings_digest: [9; 32],
            entries_digest: entries_digest(&[]),
            reservation: None,
            parent: None,
            consumption: None,
            invalidation: None,
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
        assert_eq!(open[0].consumer, MainnetConsumer::CliPay);
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
            l.mint(&request).unwrap();
        }
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
        assert_eq!(
            refusal(l.store.consume_authorization(
                &other,
                minted.id,
                &l.expect(&request, &minted),
                &consumption_of(&request.binding)
            )),
            MainnetPrecondition::ChainMismatch
        );
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
        assert_eq!(
            refusal(l.store.invalidate_authorization(&other, minted.id, "test")),
            MainnetPrecondition::ChainMismatch
        );
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
            version: 4,
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
}
