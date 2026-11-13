//! The operation record a business id names.
//!
//! A mainnet value call has one authenticated operation record per retained
//! business id, kept in the window file beside the authorizations it links.
//! The record carries the call's identity, its intent slot, its state, its
//! attempts, their exposure and recovery evidence, its result and its
//! clocks. No separate file or lock exists: every step takes the window lock
//! once and commits one generation.
//!
//! # Identity and replay
//!
//! A business id holds 1 to 64 printable ASCII bytes and is unique within the
//! profile's retained set of records and tombstones. Opening an id compares
//! only the intent slot's kind and its `intent_digest`; the store never
//! computes a digest. A business id becomes reusable once its tombstone is
//! removed.
//!
//! # States and edges
//!
//! [`OperationState`] has twelve states. One edge check holds the whole
//! table; every other edge refuses with `internal.unexpected_state`. The
//! terminal states are `Succeeded`, `Failed`, `NotSent`, `PayloadReleased`,
//! `Expired` and `Cancelled`; `NotIncluded` stays resumable.
//!
//! # Release rows and floors
//!
//! Each linked authorization carries a release row once its native
//! reservation is released. A record, or an authorization it links, is
//! compacted or pruned only after every linked authorization has a release
//! row. Removing an authorization whose release row has a ledger or
//! close-time bound raises the window's admissible floors in the same
//! commit; an `Always` bound raises nothing. Floors never decrease; a window
//! reset clears both.
//!
//! # Retention
//!
//! A terminal record keeps its full form for seven days, and at most 256
//! such records stay; the oldest eligible records compact first into
//! tombstones. A tombstone stays 30 days, and at most 1,024 stay; the oldest
//! goes first. A protected record exceeds the terminal cap and never refuses
//! an `open`.
//!
//! # Audit
//!
//! Every creation, transition and exposure appends an `operation_transition`
//! row, and every commit that adds evidence rows or first records a sequence
//! release appends one `operation_evidence` row. The row is appended before
//! the window write; an append failure commits nothing. Each try draws a
//! fresh commit identifier from the operating system's random source.

use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::audit_log::schema::{EvidenceKind, OperationEvidenceRow};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::receipt::{AttemptRef, SequenceReleases};
use stellar_agent_core::profile::schema::Profile;

use super::WindowStoreError;
use super::ledger::{
    AuthorizationState, DomainBinding, MintAuthority, MintOptions, MintRequest, MintedRecord,
    WireAuthorization,
};
use super::recovery::{CheckedRecoveryDecision, DecidedTransition};
use super::store::{
    ChainTransition, PersistedWindowStore, WireFile, generation_entry_ref, now_ms, prune_stale,
};
use crate::mainnet::MainnetPrecondition;
use crate::mainnet::types::{AuthorizationId, hex32};

// ─────────────────────────────────────────────────────────────────────────────
// Limits
// ─────────────────────────────────────────────────────────────────────────────

/// The longest business id, in bytes. A longer id refuses with
/// `validation.business_id_invalid`.
pub const BUSINESS_ID_MAX: usize = 64;

/// The most operations one profile keeps in `Prepared` or `AwaitingApproval`.
/// A further new record refuses with `operation.capacity`, detail
/// `waiting_operations`.
pub const MAX_WAITING_OPERATIONS: usize = 16;

/// The longest envelope a record or an attempt stores, in base64 bytes. A
/// longer envelope refuses with `operation.capacity`, detail
/// `envelope_size`.
pub const ENVELOPE_XDR_MAX: usize = 8_192;

/// The largest serialized intent slot of a new record, in bytes, with its
/// digest and wrappers. A larger slot refuses with `operation.capacity`,
/// detail `intent_size`.
pub const INTENT_SLOT_MAX: usize = 1_377;

/// M: the largest serialized operation record, in bytes, with every optional
/// field present and every text at its bound. A larger new record refuses
/// with `operation.capacity`, detail `record_size`.
pub const RECORD_MAX: usize = 184_365;

/// T: the committed image size at which a new record refuses with
/// `operation.capacity`, detail `file_size`. It is 4 MiB less the headroom
/// of sixteen records of size M, rounded up to 64 KiB.
pub const FILE_THRESHOLD: usize = 1_179_648;

/// The most attempts one operation makes. A further `begin_attempt` refuses
/// with `operation.attempt_limit`.
pub const MAX_ATTEMPTS: usize = 8;

/// The most evidence rows one attempt keeps. A further row evicts the row
/// with the lowest observed ledger.
pub const MAX_EVIDENCE_ROWS: usize = 8;

/// The most history entries one record keeps: the initial transition and
/// the latest 31.
pub const HISTORY_MAX: usize = 32;

/// The most transition and exposure commit identifiers one record keeps. The
/// state machine admits no more; a further append refuses with
/// `internal.unexpected_state`.
pub const COMMIT_IDS_MAX: usize = 36;

/// How long a terminal record keeps its full form, in milliseconds.
pub const TERMINAL_RETENTION_MS: u64 = 7 * 86_400_000;

/// The most terminal records kept in full form; protected records may exceed
/// it.
pub const TERMINAL_RECORDS_MAX: usize = 256;

/// How long a tombstone stays after its record closed, in milliseconds.
pub const TOMBSTONE_RETENTION_MS: u64 = 30 * 86_400_000;

/// The most tombstones kept; the oldest goes first.
pub const TOMBSTONES_MAX: usize = 1_024;

/// The serialized bound of an endpoint `status` or `tx_hash` text.
const ENDPOINT_TEXT_MAX: usize = 256;

/// The serialized bound of a history entry's evidence text.
const HISTORY_EVIDENCE_MAX: usize = 128;

/// The serialized bound of a recovery diagnostic.
const DIAGNOSTIC_MAX: usize = 256;

/// The longest agreed result XDR kept as text, in base64 bytes.
const RESULT_XDR_MAX: usize = 2_048;

/// The serialized allowance of a prepared decision.
const PREPARED_DECISION_MAX: usize = 1_024;

/// The serialized allowance of a record's hold references.
const HOLDS_MAX: usize = 4_096;

/// The longest approval nonce an authority snapshot keeps, in bytes.
pub(super) const APPROVAL_NONCE_MAX: usize = 128;

/// The longest error code or profile name a record keeps, in bytes.
const NAME_MAX: usize = 64;

/// The longest receipt reference an exposure keeps, in bytes: a prefix and
/// 64 hex characters.
const RECEIPT_REFERENCE_MAX: usize = 78;

/// The longest request identifier an attempt keeps, in bytes.
const REQUEST_ID_MAX: usize = 64;

/// The longest recovery outcome class name, in bytes.
const RECOVERY_OUTCOME_MAX: usize = 32;

/// The most commit identifiers a waiting record holds: its creation and its
/// approval request. Adoption adds the third, so an expiry sweep adopts
/// without a refusal path.
const WAITING_COMMIT_IDS_MAX: usize = 2;

/// The `invalidation` text of an authorization retired for a remint.
const RETIRED_REASON: &str = "retired for a remint";

/// The `invalidation` text of an unused authorization released by its
/// operation's end.
const RELEASED_REASON: &str = "released by its operation's end";

// ─────────────────────────────────────────────────────────────────────────────
// Identifiers
// ─────────────────────────────────────────────────────────────────────────────

fn random_16() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn decode_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

macro_rules! hex16_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 16]);

        impl $name {
            /// A fresh identifier from the operating system's random source.
            #[must_use]
            pub fn random() -> Self {
                Self(random_16())
            }

            /// The identifier with these bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// The identifier's bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// The identifier as 32 lowercase hex characters, its stored form.
            #[must_use]
            pub fn to_hex(&self) -> String {
                stellar_agent_core::hex::encode(&self.0)
            }

            /// Parses the stored form: exactly 32 lowercase hex characters.
            #[must_use]
            pub fn from_hex(text: &str) -> Option<Self> {
                decode_hex16(text).map(Self)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                Self::from_hex(&text).ok_or_else(|| {
                    serde::de::Error::custom("expected 32 lowercase hex characters")
                })
            }
        }
    };
}

hex16_id!(
    /// The identity of one operation record: 16 random bytes.
    OperationId
);

hex16_id!(
    /// The identity of one commit that touched an operation record: 16 random
    /// bytes drawn for each try.
    CommitId
);

/// The caller's identity for one value call: 1 to 64 bytes, each a printable
/// ASCII byte from `!` to `~`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct BusinessId(String);

impl BusinessId {
    /// Parses a business id.
    ///
    /// # Errors
    ///
    /// `validation.business_id_required` for an empty value, and
    /// `validation.business_id_invalid` for a value longer than
    /// [`BUSINESS_ID_MAX`] bytes or holding a byte outside 0x21 to 0x7E.
    pub fn parse(value: &str) -> Result<Self, stellar_agent_core::error::WalletError> {
        use stellar_agent_core::error::ValidationError;
        if value.is_empty() {
            return Err(ValidationError::BusinessIdRequired.into());
        }
        if value.len() > BUSINESS_ID_MAX || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(ValidationError::BusinessIdInvalid.into());
        }
        Ok(Self(value.to_owned()))
    }

    /// The id's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BusinessId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(|_| serde::de::Error::custom("not a valid business id"))
    }
}

/// The link from an authorization to the operation attempt it was minted
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLink {
    /// The operation the authorization serves.
    pub operation_id: OperationId,
    /// The attempt the authorization serves, starting at 1.
    pub attempt_index: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Record vocabulary
// ─────────────────────────────────────────────────────────────────────────────

/// Where an operation is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Opened; no authority yet.
    Prepared,
    /// Waiting for an operator approval.
    AwaitingApproval,
    /// An authority stands; no attempt is in progress.
    Authorized,
    /// An attempt is open and may sign.
    Sending,
    /// The attempt provably never left.
    NotSent,
    /// The attempt left or may have left; its outcome is unknown.
    SentOutcomeUnknown,
    /// The signed x402 payload was returned to its caller.
    PayloadReleased,
    /// The transaction succeeded.
    Succeeded,
    /// The transaction failed on chain.
    Failed,
    /// Evidence shows the attempt was not included; a successor may follow.
    NotIncluded,
    /// The operation's window ended.
    Expired,
    /// An operator cleared the unknown outcome with evidence.
    Cancelled,
}

impl OperationState {
    /// The state's wire name.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Authorized => "authorized",
            Self::Sending => "sending",
            Self::NotSent => "not_sent",
            Self::SentOutcomeUnknown => "sent_outcome_unknown",
            Self::PayloadReleased => "payload_released",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::NotIncluded => "not_included",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the state ends the operation.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::NotSent
                | Self::PayloadReleased
                | Self::Expired
                | Self::Cancelled
        )
    }

    /// Whether the operation waits for its first authority.
    #[must_use]
    pub fn is_waiting(self) -> bool {
        matches!(self, Self::Prepared | Self::AwaitingApproval)
    }

    /// Whether a call under the operation's business id continues it: a
    /// waiting operation, and one whose authority stands with no attempt
    /// in progress. Every other state answers a retry with its stored
    /// state.
    #[must_use]
    pub fn resumes(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::AwaitingApproval | Self::Authorized | Self::NotIncluded
        )
    }

    /// Every state, in table order.
    pub const ALL: [Self; 12] = [
        Self::Prepared,
        Self::AwaitingApproval,
        Self::Authorized,
        Self::Sending,
        Self::NotSent,
        Self::SentOutcomeUnknown,
        Self::PayloadReleased,
        Self::Succeeded,
        Self::Failed,
        Self::NotIncluded,
        Self::Expired,
        Self::Cancelled,
    ];
}

/// Whether the state table admits the edge from `from` to `to`; `None` is
/// the record's creation.
#[must_use]
pub fn edge_allowed(from: Option<OperationState>, to: OperationState) -> bool {
    use OperationState as S;
    matches!(
        (from, to),
        (None, S::Prepared)
            | (Some(S::Prepared), S::AwaitingApproval)
            | (
                Some(S::Prepared | S::AwaitingApproval),
                S::Authorized | S::Expired
            )
            | (Some(S::Authorized | S::NotIncluded), S::Expired)
            | (Some(S::Authorized | S::NotIncluded), S::Sending)
            | (
                Some(S::Sending),
                S::NotSent | S::SentOutcomeUnknown | S::PayloadReleased
            )
            | (
                Some(S::SentOutcomeUnknown),
                S::Succeeded | S::Failed | S::NotIncluded | S::Expired | S::Cancelled
            )
    )
}

fn check_edge(from: Option<OperationState>, to: OperationState) -> Result<(), WindowStoreError> {
    if edge_allowed(from, to) {
        Ok(())
    } else {
        Err(unexpected(format!(
            "the operation state table has no edge from {} to {}",
            from.map_or("none", OperationState::wire_name),
            to.wire_name()
        )))
    }
}

fn unexpected(detail: impl Into<String>) -> WindowStoreError {
    WindowStoreError::UnexpectedState {
        detail: detail.into(),
    }
}

fn invalid(detail: impl Into<String>) -> WindowStoreError {
    WindowStoreError::Invalid {
        detail: detail.into(),
    }
}

fn capacity(detail: CapacityDetail) -> WindowStoreError {
    WindowStoreError::OperationCapacity { detail }
}

/// The value call an operation records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// A payment.
    Pay,
    /// An account creation.
    CreateAccount,
    /// A trustline change.
    Trustline,
    /// A claimable balance claim.
    Claim,
    /// An x402 payment.
    X402Payment,
    /// An authenticated x402 payment.
    X402AuthenticatedPayment,
}

impl OperationKind {
    /// Whether the kind signs authorization entries rather than a classic
    /// transaction; such an operation never retries.
    #[must_use]
    pub fn is_x402(self) -> bool {
        matches!(self, Self::X402Payment | Self::X402AuthenticatedPayment)
    }
}

/// The entry point that opened an operation: six MCP tools and four CLI
/// verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationTool {
    /// The MCP `stellar_pay` tool.
    StellarPay,
    /// The MCP `stellar_claim` tool.
    StellarClaim,
    /// The MCP `stellar_create_account` tool.
    StellarCreateAccount,
    /// The MCP `stellar_trustline` tool.
    StellarTrustline,
    /// The MCP `x402_create_payment` tool.
    X402CreatePayment,
    /// The MCP `x402_authenticated_payment` tool.
    X402AuthenticatedPayment,
    /// The CLI `pay` verb.
    CliPay,
    /// The CLI `claim` verb.
    CliClaim,
    /// The CLI `accounts create` verb.
    CliAccountsCreate,
    /// The CLI `trustline` verb.
    CliTrustline,
}

impl OperationTool {
    /// The tool's wire name.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::StellarPay => "stellar_pay",
            Self::StellarClaim => "stellar_claim",
            Self::StellarCreateAccount => "stellar_create_account",
            Self::StellarTrustline => "stellar_trustline",
            Self::X402CreatePayment => "x402_create_payment",
            Self::X402AuthenticatedPayment => "x402_authenticated_payment",
            Self::CliPay => "cli_pay",
            Self::CliClaim => "cli_claim",
            Self::CliAccountsCreate => "cli_accounts_create",
            Self::CliTrustline => "cli_trustline",
        }
    }
}

/// The digest inputs of an x402 payment intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402Intent {
    /// The payment network.
    pub network: String,
    /// The asset contract.
    pub asset: String,
    /// The paying account.
    pub payer: String,
    /// The receiving account.
    pub pay_to: String,
    /// The amount as the payment requirements' decimal string.
    pub amount: String,
}

/// What a business id is bound to. The store compares the slot's kind and
/// its `intent_digest` and never computes a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentSlot {
    /// A classic envelope prepared before the record opened.
    Envelope {
        /// The unsigned envelope's digest.
        #[serde(with = "hex32")]
        unsigned_envelope_sha256: [u8; 32],
        /// The intent digest of the request facts.
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
        /// The envelope's `max_time` in Unix seconds; zero for none. The
        /// record's waiting and execution expiry are each at most this time.
        max_time: u64,
    },
    /// A canonical classic intent.
    Canonical {
        /// The intent digest.
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
        /// The canonical intent.
        intent: serde_json::Value,
    },
    /// An x402 payment intent.
    X402 {
        /// The intent digest the x402 crate computed.
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
        /// The digest inputs.
        intent: X402Intent,
    },
}

impl IntentSlot {
    /// The digest a business id is compared by.
    #[must_use]
    pub fn intent_digest(&self) -> [u8; 32] {
        match self {
            Self::Envelope { intent_digest, .. }
            | Self::Canonical { intent_digest, .. }
            | Self::X402 { intent_digest, .. } => *intent_digest,
        }
    }

    /// The slot's kind.
    #[must_use]
    pub fn kind(&self) -> SlotKind {
        match self {
            Self::Envelope { .. } => SlotKind::Envelope,
            Self::Canonical { .. } => SlotKind::Canonical,
            Self::X402 { .. } => SlotKind::X402,
        }
    }

    /// The end of an envelope's validity in Unix milliseconds, when the slot
    /// binds an envelope with a `max_time`.
    fn envelope_end_ms(&self) -> Option<u64> {
        match self {
            Self::Envelope { max_time, .. } if *max_time > 0 => Some(max_time.saturating_mul(1000)),
            _ => None,
        }
    }
}

/// The kind of an intent slot, which a tombstone keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    /// [`IntentSlot::Envelope`].
    Envelope,
    /// [`IntentSlot::Canonical`].
    Canonical,
    /// [`IntentSlot::X402`].
    X402,
}

/// The authority an operation proceeds under, as recorded at its mint or
/// adoption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationAuthority {
    /// A policy decision.
    Policy {
        /// The verified policy's digest.
        #[serde(with = "hex32")]
        policy_digest: [u8; 32],
        /// The deciding rule's document position.
        rule_index: u32,
    },
    /// An operator approval.
    Approval {
        /// The linked durable approval record, when one is linked.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::ledger::opt_hex32"
        )]
        approval_record_id: Option<[u8; 32]>,
        /// The approval nonce.
        approval_nonce: String,
    },
}

/// One hold of the authorization an attempt runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HoldRef {
    pub(super) authorization_id: AuthorizationId,
    pub(super) ordinal: u32,
}

/// A free text kept within a serialized bound, or the SHA-256 hex of a text
/// above it with `truncated: true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedText {
    text: String,
    #[serde(default, skip_serializing_if = "is_false")]
    truncated: bool,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip predicate receives a reference to the field"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// The length of `text` as `serde_json` serializes it, escapes included and
/// quotes excluded.
fn serialized_text_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |quoted| quoted.len().saturating_sub(2))
}

fn sha256_hex(bytes: &[u8]) -> String {
    stellar_agent_core::hex::encode(&Sha256::digest(bytes))
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl BoundedText {
    /// `raw` when its serialized form fits `max` bytes, otherwise its
    /// SHA-256 hex marked truncated.
    fn bound(raw: &str, max: usize) -> Self {
        if serialized_text_len(raw) <= max {
            Self {
                text: raw.to_owned(),
                truncated: false,
            }
        } else {
            Self {
                text: sha256_hex(raw.as_bytes()),
                truncated: true,
            }
        }
    }

    /// The kept text: the original, or the SHA-256 hex of an overlong text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the text is the digest of an overlong original.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    fn fits(&self, max: usize) -> bool {
        if self.truncated {
            is_lower_hex(&self.text, 64)
        } else {
            serialized_text_len(&self.text) <= max
        }
    }
}

/// One state change of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistoryEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) from: Option<OperationState>,
    pub(super) to: OperationState,
    pub(super) at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) evidence: Option<BoundedText>,
}

/// What an attempt exposed: a classic transaction or x402 authorization
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExposureIdentity {
    /// A signed classic transaction.
    Classic {
        /// The signed envelope's hash.
        #[serde(with = "hex32")]
        envelope_sha256: [u8; 32],
        /// The network transaction hash.
        #[serde(with = "hex32")]
        tx_hash: [u8; 32],
        /// The sequence the transaction consumes.
        sequence: i64,
        /// The transaction's `max_time` in Unix seconds; zero for none.
        max_time: u64,
        /// The submission receipt's reference: lowercase printable ASCII, at
        /// most 78 bytes.
        receipt: String,
    },
    /// Signed x402 authorization entries.
    X402 {
        /// The authorization the entries were signed under.
        authorization_id: AuthorizationId,
        /// The digest of the signed authorization entries.
        #[serde(with = "hex32")]
        auth_entry_sha256: [u8; 32],
        /// The ledger after which the signatures expire.
        signature_expiration_ledger: u32,
    },
}

impl ExposureIdentity {
    fn well_formed(&self) -> bool {
        match self {
            Self::Classic { receipt, .. } => {
                !receipt.is_empty()
                    && receipt.len() <= RECEIPT_REFERENCE_MAX
                    && receipt
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase())
            }
            Self::X402 { .. } => true,
        }
    }
}

/// A committed exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireExposure {
    pub(super) identity: ExposureIdentity,
    pub(super) commit_id: CommitId,
    pub(super) exposed_at_ms: u64,
}

/// The first commit that proved an attempt's sequence released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SequenceReleased {
    pub(super) primary_ledger: u32,
    pub(super) witness_ledger: u32,
    pub(super) min_close_time_ms: u64,
    pub(super) commit_id: CommitId,
    pub(super) released_at_ms: u64,
}

/// One endpoint's ledger coverage for a non-inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCoverage {
    /// The first ledger the endpoint covered.
    pub first_ledger: u32,
    /// The last ledger the endpoint covered.
    pub last_ledger: u32,
    /// The endpoint's latest ledger.
    pub latest_ledger: u32,
    /// The endpoint's oldest retained ledger.
    pub oldest_ledger: u32,
}

/// The evidence that an attempt was not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NotIncludedProof {
    /// The account sequence passed the attempt's sequence without it.
    AccountSequence {
        /// The primary endpoint's coverage.
        primary: EndpointCoverage,
        /// The witness endpoint's coverage.
        witness: EndpointCoverage,
    },
    /// Complete history over the attempt's window holds no inclusion.
    CompleteHistory {
        /// The primary endpoint's coverage.
        primary: EndpointCoverage,
        /// The witness endpoint's coverage.
        witness: EndpointCoverage,
    },
}

/// The outcome both endpoints agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreedOutcome {
    /// The endpoint status text.
    pub status: String,
    /// The ledger that included the transaction.
    pub ledger: u32,
    /// The inclusion's close time in Unix seconds.
    pub created_at: u64,
    /// The result XDR in base64.
    pub result_xdr: String,
    /// The digest of the included envelope XDR.
    pub envelope_xdr_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAgreedOutcome {
    pub(super) status: BoundedText,
    pub(super) ledger: u32,
    pub(super) created_at: u64,
    pub(super) result_xdr: BoundedText,
    #[serde(with = "hex32")]
    pub(super) envelope_xdr_sha256: [u8; 32],
}

impl WireAgreedOutcome {
    fn from_input(input: &AgreedOutcome) -> Self {
        Self {
            status: BoundedText::bound(&input.status, ENDPOINT_TEXT_MAX),
            ledger: input.ledger,
            created_at: input.created_at,
            result_xdr: BoundedText::bound(&input.result_xdr, RESULT_XDR_MAX),
            envelope_xdr_sha256: input.envelope_xdr_sha256,
        }
    }
}

/// The endpoint an evidence row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEndpoint {
    /// The configured endpoint.
    Primary,
    /// The independent witness endpoint.
    Witness,
}

/// One endpoint answer, as the recovery pass read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceAnswer {
    /// A ledger read.
    Ledger {
        /// The ledger whose expiry the answer reports.
        expiry_ledger: u32,
        /// The ledger's close time in Unix seconds.
        close_time: u64,
        /// The endpoint's latest ledger.
        latest_ledger: u32,
    },
    /// An account read.
    Account {
        /// The account's sequence, when reported.
        sequence: Option<i64>,
        /// The endpoint's latest ledger, when reported.
        latest_ledger: Option<u32>,
    },
    /// A transaction outcome read. Every field the endpoint omits stays
    /// absent; none takes a zero or empty substitute.
    Outcome {
        /// The endpoint's status text, when reported.
        status: Option<String>,
        /// The including ledger, when reported.
        ledger: Option<u32>,
        /// The inclusion time in Unix seconds, when reported and valid.
        created_at: Option<u64>,
        /// The endpoint's transaction hash text, when reported.
        tx_hash: Option<String>,
        /// The digest of the reported envelope XDR, when reported.
        envelope_xdr: Option<[u8; 32]>,
        /// The digest of the reported result XDR, when reported.
        result_xdr: Option<[u8; 32]>,
        /// The endpoint's latest ledger, when reported.
        latest_ledger: Option<u32>,
        /// The endpoint's oldest retained ledger, when reported.
        oldest_ledger: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WireEvidenceAnswer {
    Ledger {
        expiry_ledger: u32,
        close_time: u64,
        latest_ledger: u32,
    },
    Account {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sequence: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        latest_ledger: Option<u32>,
    },
    Outcome {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<BoundedText>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ledger: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        created_at: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tx_hash: Option<BoundedText>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::ledger::opt_hex32"
        )]
        envelope_xdr: Option<[u8; 32]>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::ledger::opt_hex32"
        )]
        result_xdr: Option<[u8; 32]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        latest_ledger: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oldest_ledger: Option<u32>,
    },
}

impl WireEvidenceAnswer {
    fn from_input(answer: &EvidenceAnswer) -> Self {
        match answer {
            EvidenceAnswer::Ledger {
                expiry_ledger,
                close_time,
                latest_ledger,
            } => Self::Ledger {
                expiry_ledger: *expiry_ledger,
                close_time: *close_time,
                latest_ledger: *latest_ledger,
            },
            EvidenceAnswer::Account {
                sequence,
                latest_ledger,
            } => Self::Account {
                sequence: *sequence,
                latest_ledger: *latest_ledger,
            },
            EvidenceAnswer::Outcome {
                status,
                ledger,
                created_at,
                tx_hash,
                envelope_xdr,
                result_xdr,
                latest_ledger,
                oldest_ledger,
            } => Self::Outcome {
                status: status
                    .as_deref()
                    .map(|text| BoundedText::bound(text, ENDPOINT_TEXT_MAX)),
                ledger: *ledger,
                created_at: *created_at,
                tx_hash: tx_hash
                    .as_deref()
                    .map(|text| BoundedText::bound(text, ENDPOINT_TEXT_MAX)),
                envelope_xdr: *envelope_xdr,
                result_xdr: *result_xdr,
                latest_ledger: *latest_ledger,
                oldest_ledger: *oldest_ledger,
            },
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Ledger { .. } => 0,
            Self::Account { .. } => 1,
            Self::Outcome { .. } => 2,
        }
    }

    fn fits(&self) -> bool {
        match self {
            Self::Outcome {
                status, tx_hash, ..
            } => [status, tx_hash].into_iter().all(|text| {
                text.as_ref()
                    .is_none_or(|text| text.fits(ENDPOINT_TEXT_MAX))
            }),
            Self::Ledger { .. } | Self::Account { .. } => true,
        }
    }
}

/// One retained evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireEvidenceRow {
    pub(super) endpoint: EvidenceEndpoint,
    pub(super) observed_ledger: u32,
    pub(super) answer: WireEvidenceAnswer,
    #[serde(with = "hex32")]
    pub(super) digest: [u8; 32],
    pub(super) commit_id: CommitId,
    pub(super) evidence_seq: u64,
}

impl WireEvidenceRow {
    /// The duplicate key is the endpoint, answer kind and observed ledger.
    fn key(&self) -> (EvidenceEndpoint, u8, u32) {
        (self.endpoint, self.answer.kind(), self.observed_ledger)
    }

    fn audit_kind(&self) -> EvidenceKind {
        match (&self.answer, self.endpoint) {
            (WireEvidenceAnswer::Ledger { .. }, EvidenceEndpoint::Primary) => {
                EvidenceKind::PrimaryLedger
            }
            (WireEvidenceAnswer::Ledger { .. }, EvidenceEndpoint::Witness) => {
                EvidenceKind::OracleLedger
            }
            (WireEvidenceAnswer::Account { .. }, EvidenceEndpoint::Primary) => {
                EvidenceKind::PrimaryAccount
            }
            (WireEvidenceAnswer::Account { .. }, EvidenceEndpoint::Witness) => {
                EvidenceKind::OracleAccount
            }
            (WireEvidenceAnswer::Outcome { .. }, EvidenceEndpoint::Primary) => {
                EvidenceKind::PrimaryOutcome
            }
            (WireEvidenceAnswer::Outcome { .. }, EvidenceEndpoint::Witness) => {
                EvidenceKind::OracleOutcome
            }
        }
    }
}

/// The replaceable recovery state of an attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryUpdate {
    /// The primary endpoint's scan cursor.
    pub primary_cursor: Option<u32>,
    /// The witness endpoint's scan cursor.
    pub witness_cursor: Option<u32>,
    /// The primary endpoint's upper bound.
    pub primary_upper: Option<u32>,
    /// The witness endpoint's upper bound.
    pub witness_upper: Option<u32>,
    /// The count of endpoint disagreements; it saturates at 255.
    pub disagreements: u8,
    /// When the last pass ran, in Unix milliseconds.
    pub last_pass_at_ms: Option<u64>,
    /// The last pass's outcome class name.
    pub last_outcome: Option<String>,
    /// Whether history loss or a missing lower bound was recorded; once set,
    /// no update clears it.
    pub history_incomplete: bool,
    /// A replaceable diagnostic text.
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) primary_cursor: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) witness_cursor: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) primary_upper: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) witness_upper: Option<u32>,
    #[serde(default)]
    pub(super) disagreements: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_pass_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) history_incomplete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) diagnostic: Option<BoundedText>,
}

fn outcome_class_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= RECOVERY_OUTCOME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.')
}

impl WireRecovery {
    fn snapshot(&self) -> RecoveryUpdate {
        RecoveryUpdate {
            primary_cursor: self.primary_cursor,
            witness_cursor: self.witness_cursor,
            primary_upper: self.primary_upper,
            witness_upper: self.witness_upper,
            disagreements: self.disagreements,
            last_pass_at_ms: self.last_pass_at_ms,
            last_outcome: self.last_outcome.clone(),
            history_incomplete: self.history_incomplete,
            diagnostic: self.diagnostic.as_ref().map(|text| text.text.clone()),
        }
    }

    /// Applies `update`. `history_incomplete` only ever becomes set.
    fn apply(&mut self, update: &RecoveryUpdate) -> Result<(), WindowStoreError> {
        if let Some(name) = &update.last_outcome
            && !outcome_class_ok(name)
        {
            return Err(invalid("a recovery outcome class is not a class name"));
        }
        self.primary_cursor = update.primary_cursor;
        self.witness_cursor = update.witness_cursor;
        self.primary_upper = update.primary_upper;
        self.witness_upper = update.witness_upper;
        self.disagreements = update.disagreements;
        self.last_pass_at_ms = update.last_pass_at_ms;
        self.last_outcome.clone_from(&update.last_outcome);
        self.history_incomplete |= update.history_incomplete;
        self.diagnostic = update
            .diagnostic
            .as_deref()
            .map(|text| BoundedText::bound(text, DIAGNOSTIC_MAX));
        Ok(())
    }

    fn fits(&self) -> bool {
        self.diagnostic
            .as_ref()
            .is_none_or(|text| text.fits(DIAGNOSTIC_MAX))
            && self.last_outcome.as_deref().is_none_or(outcome_class_ok)
    }
}

/// The committed identity of an attempt's recovery decision: its commit,
/// its evidence digest, both deciding ledgers, a failure's charged fee and
/// the projection marker a successor needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireDecision {
    pub(super) commit_id: CommitId,
    #[serde(with = "hex32")]
    pub(super) evidence_digest: [u8; 32],
    pub(super) primary_ledger: u32,
    pub(super) witness_ledger: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) fee_charged: Option<i64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(super) projected: bool,
}

/// One attempt of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireAttempt {
    pub(super) index: u32,
    pub(super) authorization_id: AuthorizationId,
    pub(super) authority: OperationAuthority,
    pub(super) send_by_ms: u64,
    pub(super) request_id: String,
    pub(super) started_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) outcome: Option<OperationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pre_exposure_ledger: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exposure: Option<WireExposure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) sequence_released: Option<SequenceReleased>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) not_included: Option<NotIncludedProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) agreed_outcome: Option<WireAgreedOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) evidence: Vec<WireEvidenceRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recovery: Option<WireRecovery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) decision: Option<WireDecision>,
}

/// An operation's result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResult {
    /// The network transaction hash, when one exists.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::ledger::opt_hex32"
    )]
    pub tx_hash: Option<[u8; 32]>,
    /// The including ledger, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    /// The refusal or failure code, at most 64 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Whether a signed x402 payload was released.
    #[serde(default, skip_serializing_if = "is_false")]
    pub payload_released: bool,
}

impl OperationResult {
    fn well_formed(&self) -> bool {
        self.error_code.as_deref().is_none_or(|code| {
            !code.is_empty() && code.len() <= NAME_MAX && code.bytes().all(|b| b.is_ascii_graphic())
        })
    }
}

/// One operation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOperation {
    pub(super) id: OperationId,
    pub(super) business_id: BusinessId,
    pub(super) profile: String,
    pub(super) chain_id: Caip2,
    pub(super) state: OperationState,
    pub(super) tool: OperationTool,
    pub(super) kind: OperationKind,
    pub(super) intent: IntentSlot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) envelope_xdr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) prepared_decision: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) authority: Option<OperationAuthority>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::ledger::opt_hex32"
    )]
    pub(super) approval_record_id: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) holds: Vec<HoldRef>,
    pub(super) history: Vec<HistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_commit_id: Option<CommitId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) commit_ids: Vec<CommitId>,
    #[serde(default)]
    pub(super) evidence_committed_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) attempts: Vec<WireAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) result: Option<OperationResult>,
    pub(super) created_at_ms: u64,
    pub(super) updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) closed_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) execution_expires_at_ms: Option<u64>,
    pub(super) waiting_expires_at_ms: u64,
}

impl WireOperation {
    /// Records `commit` as a transition or exposure commit. A commit that
    /// already ends the list is not repeated.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::UnexpectedState`] when the record already holds
    /// [`COMMIT_IDS_MAX`] identifiers.
    fn note_commit(&mut self, commit: CommitId) -> Result<(), WindowStoreError> {
        if self.commit_ids.last() != Some(&commit) {
            if self.commit_ids.len() >= COMMIT_IDS_MAX {
                return Err(unexpected(format!(
                    "an operation record holds {COMMIT_IDS_MAX} commit identifiers and admits no \
                     further transition"
                )));
            }
            self.commit_ids.push(commit);
        }
        self.last_commit_id = Some(commit);
        Ok(())
    }

    /// Moves the record to `to` at `at_ms` under `commit`, keeping the initial
    /// history entry and the latest 31.
    fn step(
        &mut self,
        to: OperationState,
        at_ms: u64,
        evidence: Option<&str>,
        commit: CommitId,
    ) -> Result<(), WindowStoreError> {
        check_edge(Some(self.state), to)?;
        self.note_commit(commit)?;
        self.history.push(HistoryEntry {
            from: Some(self.state),
            to,
            at_ms,
            evidence: evidence.map(|text| BoundedText::bound(text, HISTORY_EVIDENCE_MAX)),
        });
        if self.history.len() > HISTORY_MAX {
            self.history.remove(1);
        }
        self.state = to;
        self.updated_at_ms = at_ms;
        if to.is_terminal() {
            self.closed_at_ms = Some(at_ms);
        }
        Ok(())
    }

    fn current_attempt(&self) -> Option<&WireAttempt> {
        self.attempts.last()
    }

    fn attempt_mut(&mut self, index: u32) -> Result<&mut WireAttempt, WindowStoreError> {
        self.attempts
            .iter_mut()
            .find(|attempt| attempt.index == index)
            .ok_or_else(|| unexpected(format!("the operation has no attempt {index}")))
    }

    fn history_incomplete(&self) -> bool {
        self.attempts.iter().any(|attempt| {
            attempt
                .recovery
                .as_ref()
                .is_some_and(|recovery| recovery.history_incomplete)
        })
    }

    fn tombstone(&self) -> WireTombstone {
        WireTombstone {
            id: self.id,
            business_id: self.business_id.clone(),
            state: self.state,
            result: self.result.clone(),
            intent_digest: self.intent.intent_digest(),
            slot_kind: self.intent.kind(),
            closed_at_ms: self.closed_at_ms.unwrap_or(self.updated_at_ms),
        }
    }
}

/// A compacted terminal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireTombstone {
    pub(super) id: OperationId,
    pub(super) business_id: BusinessId,
    pub(super) state: OperationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) result: Option<OperationResult>,
    #[serde(with = "hex32")]
    pub(super) intent_digest: [u8; 32],
    pub(super) slot_kind: SlotKind,
    pub(super) closed_at_ms: u64,
}

/// The operation records and tombstones of one window file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationsSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) records: Vec<WireOperation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) tombstones: Vec<WireTombstone>,
}

impl OperationsSection {
    fn is_empty(&self) -> bool {
        self.records.is_empty() && self.tombstones.is_empty()
    }
}

/// Whether the window file's operations section is absent or empty, so it
/// stays out of the serialized body.
#[allow(
    clippy::ref_option,
    reason = "serde's skip predicate receives a reference to the field"
)]
pub(super) fn section_absent(section: &Option<OperationsSection>) -> bool {
    section.as_ref().is_none_or(OperationsSection::is_empty)
}

/// The window's last stored chain observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowObservation {
    /// The observed ledger.
    pub ledger: u32,
    /// The lower bound of that ledger's close time, in Unix milliseconds.
    pub close_time_floor_ms: u64,
    /// When the observation was read, in Unix milliseconds.
    pub observed_at_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Authorization dispositions and release rows
// ─────────────────────────────────────────────────────────────────────────────

/// How a linked authorization ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Disposition {
    /// Consumed once.
    Used,
    /// Ended without a signature leaving.
    Unused,
}

/// Why a native reservation was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseClass {
    /// Nothing was spent.
    ProvedUnspent,
    /// The spend settled.
    Settled,
    /// An operator cleared an unknown outcome.
    Unknown,
    /// Retired unused for a remint.
    RetiredUnused,
}

/// From when a release row releases its reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseBound {
    /// From this ledger on.
    Ledger(u32),
    /// From this close time on, in Unix milliseconds.
    CloseTime(u64),
    /// Unconditionally.
    Always,
}

/// The release row of one native reservation; the reservation's identity is
/// its authorization's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRow {
    pub(super) class: ReleaseClass,
    pub(super) bound: ReleaseBound,
    #[serde(default)]
    pub(super) observed_ledger: Option<u32>,
    pub(super) commit_id: CommitId,
}

impl ReleaseRow {
    /// An unconditional row of `class` without an observation.
    pub(super) fn always(class: ReleaseClass, commit_id: CommitId) -> Self {
        Self {
            class,
            bound: ReleaseBound::Always,
            observed_ledger: None,
            commit_id,
        }
    }
}

/// The window's admissible floors: observations below either refuse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissibleFloors {
    /// The lowest admissible observed ledger.
    pub ledger: Option<u32>,
    /// The lowest admissible observed close time, in Unix milliseconds.
    pub close_time_ms: Option<u64>,
}

/// Removes every authorization `remove` selects. Each removed release row
/// with a ledger or close-time bound raises the matching admissible floor to
/// at least that bound; an `Always` bound raises nothing. Floors never
/// decrease here.
pub(super) fn remove_authorizations(
    wire: &mut WireFile,
    remove: impl Fn(&WireAuthorization) -> bool,
) {
    let mut floor_ledger = wire.admissible_floor_ledger;
    let mut floor_close = wire.admissible_floor_close_time_ms;
    wire.authorizations.retain(|auth| {
        if !remove(auth) {
            return true;
        }
        match auth.native_release.map(|row| row.bound) {
            Some(ReleaseBound::Ledger(bound)) => {
                floor_ledger = Some(floor_ledger.map_or(bound, |floor| floor.max(bound)));
            }
            Some(ReleaseBound::CloseTime(bound)) => {
                floor_close = Some(floor_close.map_or(bound, |floor| floor.max(bound)));
            }
            Some(ReleaseBound::Always) | None => {}
        }
        false
    });
    wire.admissible_floor_ledger = floor_ledger;
    wire.admissible_floor_close_time_ms = floor_close;
}

/// Whether `auth` serves an operation and has no release row, which protects
/// it and its record from pruning and compaction.
pub(super) fn unreleased_link(auth: &WireAuthorization) -> bool {
    auth.operation.is_some() && auth.native_release.is_none()
}

/// Whether `row` releases its reservation at `observation`. `Always`
/// releases without an observation; `Ledger(b)` releases once `b` is at or
/// below the observed ledger, and `CloseTime(b)` once `b` is at or below the
/// observed close-time floor. Without an observation a bounded row holds.
pub(super) fn row_releases(row: &ReleaseRow, observation: Option<&WindowObservation>) -> bool {
    match row.bound {
        ReleaseBound::Always => true,
        ReleaseBound::Ledger(bound) => observation.is_some_and(|seen| bound <= seen.ledger),
        ReleaseBound::CloseTime(bound) => {
            observation.is_some_and(|seen| bound <= seen.close_time_floor_ms)
        }
    }
}

/// The native stroops `wire` still reserves at `observation`. Each
/// authorization's amounts count once, whatever its buckets and epochs. A
/// reservation without a release row counts, a `used` disposition alone
/// releases nothing, and a row releases only as [`row_releases`] states.
pub(super) fn native_reserved(wire: &WireFile, observation: Option<&WindowObservation>) -> i128 {
    wire.authorizations
        .iter()
        .filter_map(|auth| {
            let amounts = auth.native_reservation?;
            let released = auth
                .native_release
                .is_some_and(|row| row_releases(&row, observation));
            (!released).then(|| amounts.total_stroops())
        })
        .sum()
}

/// Releases an unused authorization: it becomes invalidated with disposition
/// `unused`, its holds go, and it gets an `Always` row of `class`.
fn release_unused(
    wire: &mut WireFile,
    id: AuthorizationId,
    class: ReleaseClass,
    reason: &str,
    now_ms: u64,
    commit: CommitId,
) {
    if let Some(auth) = wire.authorizations.iter_mut().find(|auth| auth.id == id) {
        auth.state = AuthorizationState::Invalidated;
        auth.settled_ms = Some(now_ms);
        auth.invalidation = Some(reason.to_owned());
        auth.disposition = Some(Disposition::Unused);
        auth.native_release = Some(ReleaseRow::always(class, commit));
    }
    wire.holds.retain(|hold| hold.authorization_id != id);
}

/// Whether a committed exposure of any record names authorization `id`.
fn exposed(wire: &WireFile, id: AuthorizationId) -> bool {
    records(wire).iter().any(|record| {
        record
            .attempts
            .iter()
            .any(|attempt| attempt.authorization_id == id && attempt.exposure.is_some())
    })
}

/// Every authorization a committed exposure names.
pub(super) fn exposed_authorizations(wire: &WireFile) -> Vec<AuthorizationId> {
    records(wire)
        .iter()
        .flat_map(|record| &record.attempts)
        .filter(|attempt| attempt.exposure.is_some())
        .map(|attempt| attempt.authorization_id)
        .collect()
}

/// Every retained operation that has not ended. A writer without an
/// operation audit leaves the authorizations they link untouched.
pub(super) fn live_operations(wire: &WireFile) -> Vec<OperationId> {
    records(wire)
        .iter()
        .filter(|record| !record.state.is_terminal())
        .map(|record| record.id)
        .collect()
}

/// Releases every authorization linked to operation `id` that has no
/// release row, was never claimed, was not used and that no committed
/// exposure names. An open one is invalidated and its holds go; each gets
/// disposition `unused` and an `Always` row of class `proved_unspent` under
/// `commit`. Returns how many were released.
fn release_linked_unused(
    wire: &mut WireFile,
    id: OperationId,
    now_ms: u64,
    commit: CommitId,
) -> usize {
    let exposed = exposed_authorizations(wire);
    let unused: Vec<(AuthorizationId, AuthorizationState)> = wire
        .authorizations
        .iter()
        .filter(|auth| {
            auth.operation.is_some_and(|link| link.operation_id == id)
                && auth.native_release.is_none()
                && auth.claimed_ms.is_none()
                && auth.state != AuthorizationState::Used
                && !exposed.contains(&auth.id)
        })
        .map(|auth| (auth.id, auth.state))
        .collect();
    for (auth_id, state) in &unused {
        if *state == AuthorizationState::Open {
            release_unused(
                wire,
                *auth_id,
                ReleaseClass::ProvedUnspent,
                RELEASED_REASON,
                now_ms,
                commit,
            );
        } else if let Some(auth) = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == *auth_id)
        {
            auth.disposition = Some(Disposition::Unused);
            auth.native_release = Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit));
        }
    }
    unused.len()
}

/// Writes an unsent attempt's missing `proved_unspent` row. This requires no
/// committed exposure or proof that no send starts.
fn release_unsent_attempt(
    wire: &mut WireFile,
    auth_id: AuthorizationId,
    commit: CommitId,
    send_never_started: bool,
) {
    if exposed(wire, auth_id) && !send_never_started {
        return;
    }
    if let Some(auth) = wire
        .authorizations
        .iter_mut()
        .find(|auth| auth.id == auth_id)
        && auth.native_release.is_none()
    {
        auth.native_release = Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section access, adoption and expiry
// ─────────────────────────────────────────────────────────────────────────────

fn records(wire: &WireFile) -> &[WireOperation] {
    wire.operations
        .as_ref()
        .map_or(&[], |section| section.records.as_slice())
}

fn tombstones(wire: &WireFile) -> &[WireTombstone] {
    wire.operations
        .as_ref()
        .map_or(&[], |section| section.tombstones.as_slice())
}

fn section_mut(wire: &mut WireFile) -> &mut OperationsSection {
    wire.operations
        .get_or_insert_with(OperationsSection::default)
}

fn record_index(wire: &WireFile, id: OperationId) -> Result<usize, WindowStoreError> {
    records(wire)
        .iter()
        .position(|record| record.id == id)
        .ok_or_else(|| unexpected("the window holds no operation with this identity"))
}

/// Whether version-11 content is present: an operation section, a floor, a
/// stored observation, or an authorization's link, disposition or release
/// row.
pub(super) fn has_content(wire: &WireFile) -> bool {
    !section_absent(&wire.operations)
        || wire.admissible_floor_ledger.is_some()
        || wire.admissible_floor_close_time_ms.is_some()
        || wire.last_observation.is_some()
        || wire.authorizations.iter().any(|auth| {
            auth.operation.is_some() || auth.disposition.is_some() || auth.native_release.is_some()
        })
}

/// The authority snapshot of `auth` for `record`.
fn authority_of(
    record: &WireOperation,
    auth: &WireAuthorization,
) -> Result<OperationAuthority, WindowStoreError> {
    Ok(match auth.authority()? {
        MintAuthority::Policy(binding) => OperationAuthority::Policy {
            policy_digest: binding.policy_digest,
            rule_index: binding.rule_index,
        },
        MintAuthority::Approval { nonce, .. } => {
            if nonce.len() > APPROVAL_NONCE_MAX {
                return Err(invalid("an approval nonce exceeds its allowance"));
            }
            OperationAuthority::Approval {
                approval_record_id: record.approval_record_id,
                approval_nonce: nonce,
            }
        }
    })
}

/// Takes `auth`'s authority onto `record`: the authority on first adoption,
/// and an execution expiry no later than the authority's end, the envelope's
/// end and any earlier execution expiry.
fn take_authority(
    record: &mut WireOperation,
    auth: &WireAuthorization,
) -> Result<(), WindowStoreError> {
    if record.authority.is_none() {
        record.authority = Some(authority_of(record, auth)?);
    }
    let end = auth.authority_end_ms();
    let end = record
        .intent
        .envelope_end_ms()
        .map_or(end, |envelope| envelope.min(end));
    record.execution_expires_at_ms = Some(
        record
            .execution_expires_at_ms
            .map_or(end, |existing| existing.min(end)),
    );
    Ok(())
}

/// Moves the waiting `record` into `Authorized` under `auth`'s authority,
/// or leaves it unchanged on a refusal.
fn adopt(
    record: &mut WireOperation,
    auth: &WireAuthorization,
    now_ms: u64,
    commit: CommitId,
) -> Result<(), WindowStoreError> {
    let mut adopted = record.clone();
    take_authority(&mut adopted, auth)?;
    adopted.step(OperationState::Authorized, now_ms, None, commit)?;
    *record = adopted;
    Ok(())
}

/// The waiting record an open authorization links, when one is retained.
fn waiting_record<'w>(
    section: &'w mut Option<OperationsSection>,
    auth: &WireAuthorization,
) -> Option<&'w mut WireOperation> {
    let link = auth.operation?;
    if auth.state != AuthorizationState::Open {
        return None;
    }
    section
        .as_mut()?
        .records
        .iter_mut()
        .find(|record| record.id == link.operation_id && record.state.is_waiting())
}

/// Adopts the waiting operation `auth` links into `Authorized`, when `auth`
/// is still open. The sweep calls this before it marks `auth` expired.
/// Returns whether a record was adopted.
pub(super) fn adopt_on_expiry(
    section: &mut Option<OperationsSection>,
    auth: &WireAuthorization,
    now_ms: u64,
    commit: CommitId,
) -> bool {
    waiting_record(section, auth).is_some_and(|record| adopt(record, auth, now_ms, commit).is_ok())
}

/// Requires the operation a mint links to exist and be open, and the link to
/// name its next attempt.
pub(super) fn check_mint_link(
    wire: &WireFile,
    link: OperationLink,
) -> Result<(), WindowStoreError> {
    let record = records(wire)
        .iter()
        .find(|record| record.id == link.operation_id)
        .ok_or_else(|| {
            unexpected("an authorization links an operation the window does not hold")
        })?;
    if record.state.is_terminal() {
        return Err(unexpected("an authorization links an ended operation"));
    }
    let next = record.attempts.len() + 1;
    if usize::try_from(link.attempt_index).ok() != Some(next) || next > MAX_ATTEMPTS {
        return Err(unexpected(
            "an authorization links an attempt other than the operation's next one",
        ));
    }
    Ok(())
}

/// Collects the audit rows one commit appends, before the window write.
pub(super) struct AuditBatch<'a> {
    request_id: &'a str,
    chain_id: &'static str,
    commit: CommitId,
    entries: Vec<AuditEntry>,
}

impl AuditBatch<'_> {
    fn transition(
        &mut self,
        record: &WireOperation,
        attempt_index: Option<u32>,
        from: Option<OperationState>,
        step: &str,
    ) {
        self.entries.push(AuditEntry::new_operation_transition(
            record.tool.wire_name(),
            self.chain_id,
            record.id.to_hex(),
            attempt_index,
            from.map(|state| state.wire_name().to_owned()),
            step,
            self.commit.to_hex(),
            self.request_id,
        ));
    }
}

/// Adopts every waiting record whose linked authorization is open and
/// inside its lifetime.
fn adopt_live(
    wire: &mut WireFile,
    now_ms: u64,
    audit: &mut AuditBatch<'_>,
) -> Result<bool, WindowStoreError> {
    let mut changed = false;
    let live: Vec<WireAuthorization> = wire
        .authorizations
        .iter()
        .filter(|auth| auth.operation.is_some() && super::ledger::effective(auth, now_ms))
        .cloned()
        .collect();
    for auth in live {
        let Some(record) = waiting_record(&mut wire.operations, &auth) else {
            continue;
        };
        let from = record.state;
        adopt(record, &auth, now_ms, audit.commit)?;
        audit.transition(
            record,
            None,
            Some(from),
            OperationState::Authorized.wire_name(),
        );
        changed = true;
    }
    Ok(changed)
}

/// Applies the expiry edges at `now_ms` and releases the unused
/// authorizations of ended operations. Returns how many records expired or
/// had an authorization released.
fn expire_records(
    wire: &mut WireFile,
    now_ms: u64,
    audit: &mut AuditBatch<'_>,
) -> Result<usize, WindowStoreError> {
    use OperationState as S;
    let mut ended = 0;
    let count = records(wire).len();
    for index in 0..count {
        let record = &records(wire)[index];
        let id = record.id;
        let open_link = wire.authorizations.iter().any(|auth| {
            auth.operation.is_some_and(|link| link.operation_id == id)
                && auth.state == AuthorizationState::Open
        });
        let target = match record.state {
            S::Prepared | S::AwaitingApproval
                if !open_link && record.waiting_expires_at_ms <= now_ms =>
            {
                Some(S::Expired)
            }
            S::Authorized | S::NotIncluded
                if record
                    .execution_expires_at_ms
                    .is_some_and(|end| end <= now_ms) =>
            {
                Some(S::Expired)
            }
            S::Sending => sending_crash_edge(wire, record),
            _ => None,
        };
        let Some(to) = target else {
            if record.state.is_terminal()
                && release_linked_unused(wire, id, now_ms, audit.commit) > 0
            {
                ended += 1;
            }
            continue;
        };
        let record = &mut section_mut(wire).records[index];
        let from = record.state;
        let attempt = record.current_attempt().map(|attempt| attempt.index);
        if from == S::Sending
            && let Some(index) = attempt
        {
            record.attempt_mut(index)?.outcome = Some(to);
        }
        record.step(to, now_ms, None, audit.commit)?;
        audit.transition(record, attempt, Some(from), to.wire_name());
        let attempt_auth = record
            .current_attempt()
            .map(|attempt| attempt.authorization_id);
        release_linked_unused(wire, id, now_ms, audit.commit);
        if from == S::Sending
            && let Some(auth_id) = attempt_auth
        {
            release_unsent_attempt(wire, auth_id, audit.commit, false);
        }
        ended += 1;
    }
    Ok(ended)
}

/// The release row an operator clear of `record` writes, and the
/// authorization of the last exposed attempt it belongs to. `Untimed` needs
/// an exposure without `max_time` and writes `Always`; `Timed` needs one with
/// `max_time` and writes `CloseTime` at `max_time` in milliseconds. An x402
/// exposure has no clear: recovery bounds it by its ledger.
fn clear_release(
    wire: &WireFile,
    record: &WireOperation,
    clear: Option<ClearForm>,
    commit: CommitId,
) -> Result<(AuthorizationId, ReleaseRow), WindowStoreError> {
    let clear = clear.ok_or_else(|| unexpected("a cancellation needs the operator's clear"))?;
    let (auth_id, identity) = record
        .attempts
        .iter()
        .rev()
        .find_map(|attempt| {
            attempt
                .exposure
                .as_ref()
                .map(|exposure| (attempt.authorization_id, &exposure.identity))
        })
        .ok_or_else(|| unexpected("a clear needs an exposed attempt"))?;
    let ExposureIdentity::Classic { max_time, .. } = identity else {
        return Err(unexpected("an x402 exposure has no operator clear"));
    };
    let bound = match (clear, *max_time) {
        (ClearForm::Untimed, 0) => ReleaseBound::Always,
        (ClearForm::Timed, max_time) if max_time > 0 => ReleaseBound::CloseTime(
            max_time
                .checked_mul(1000)
                .ok_or_else(|| unexpected("an exposure's max_time exceeds its range"))?,
        ),
        (ClearForm::Untimed, _) => {
            return Err(unexpected("a bounded exposure needs the timed clear"));
        }
        (ClearForm::Timed, _) => {
            return Err(unexpected("an unbounded exposure needs the untimed clear"));
        }
    };
    if !wire.authorizations.iter().any(|auth| auth.id == auth_id) {
        return Err(unexpected("an exposed attempt's authorization is gone"));
    }
    Ok((
        auth_id,
        ReleaseRow {
            class: ReleaseClass::Unknown,
            bound,
            observed_ledger: None,
            commit_id: commit,
        },
    ))
}

/// The crash edge of a `Sending` record: `NotSent` when its attempt has no
/// committed exposure and its authorization has left `Open` without ever
/// being claimed. A claimed authorization keeps the record `Sending`.
fn sending_crash_edge(wire: &WireFile, record: &WireOperation) -> Option<OperationState> {
    let attempt = record.current_attempt()?;
    if attempt.exposure.is_some() {
        return None;
    }
    let auth = wire
        .authorizations
        .iter()
        .find(|auth| auth.id == attempt.authorization_id)?;
    let ended_unused = auth.state != AuthorizationState::Open
        && auth.claimed_ms.is_none()
        && (auth.disposition == Some(Disposition::Unused)
            || auth.state == AuthorizationState::Invalidated);
    ended_unused.then_some(OperationState::NotSent)
}

// ─────────────────────────────────────────────────────────────────────────────
// The section's registration points
// ─────────────────────────────────────────────────────────────────────────────

/// A window-file section's registration points: its checks on both prepared
/// sides, its survivors of a window reset, and its in-memory pruning.
pub(super) trait WindowSection {
    /// What a reset keeps of the section.
    type Survivors;

    /// Checks the section's invariants on one snapshot.
    fn validate(wire: &WireFile) -> Result<(), WindowStoreError>;

    /// The section's part of a reset successor at the store clock `now_ms`,
    /// or the refusal of the reset.
    fn on_reset(wire: Option<&WireFile>, now_ms: u64) -> Result<Self::Survivors, WindowStoreError>;

    /// Prunes the section at `now_ms`.
    fn prune(wire: &mut WireFile, now_ms: u64);
}

/// The operations section's registration.
pub(super) struct Operations;

impl WindowSection for Operations {
    type Survivors = Option<OperationsSection>;

    fn validate(wire: &WireFile) -> Result<(), WindowStoreError> {
        validate_section(wire)
    }

    /// Refuses while any record is not terminal once the sweep and the
    /// expiry edges apply at `now_ms`; those apply to a copy only, so the
    /// reset changes no record. Keeps the stored records and tombstones. A
    /// record the expiry edges end stays as stored until an operation step
    /// commits that expiry with its audit row.
    fn on_reset(wire: Option<&WireFile>, now_ms: u64) -> Result<Self::Survivors, WindowStoreError> {
        let Some(wire) = wire else {
            return Ok(None);
        };
        let mut expired = wire.clone();
        let mut audit = AuditBatch {
            request_id: "",
            chain_id: "",
            commit: CommitId::random(),
            entries: Vec::new(),
        };
        super::ledger::sweep_expired_with(&mut expired, now_ms, audit.commit);
        expire_records(&mut expired, now_ms, &mut audit)?;
        let open = records(&expired)
            .iter()
            .filter(|record| !record.state.is_terminal())
            .count();
        if open > 0 {
            return Err(WindowStoreError::OperationsOpen { open });
        }
        Ok(wire
            .operations
            .clone()
            .filter(|section| !section.is_empty()))
    }

    fn prune(wire: &mut WireFile, now_ms: u64) {
        prune_section(wire, now_ms);
    }
}

fn validate_section(wire: &WireFile) -> Result<(), WindowStoreError> {
    if wire.version < super::store::WIRE_VERSION_OPERATIONS && has_content(wire) {
        return Err(invalid(format!(
            "operation records, floors, observations and authorization links require wire \
             version {}",
            super::store::WIRE_VERSION_OPERATIONS
        )));
    }
    for auth in &wire.authorizations {
        let disposition_ok = match auth.disposition {
            None => true,
            Some(Disposition::Used) => auth.state == AuthorizationState::Used,
            Some(Disposition::Unused) => {
                matches!(
                    auth.state,
                    AuthorizationState::Expired | AuthorizationState::Invalidated
                ) && auth.claimed_ms.is_none()
            }
        };
        let release_ok = auth.native_release.is_none_or(|row| match row.class {
            ReleaseClass::ProvedUnspent | ReleaseClass::RetiredUnused => {
                row.bound == ReleaseBound::Always && row.observed_ledger.is_none()
            }
            ReleaseClass::Settled | ReleaseClass::Unknown => true,
        });
        let link_ok = auth.operation.is_none_or(|link| {
            link.attempt_index >= 1
                && usize::try_from(link.attempt_index).is_ok_and(|index| index <= MAX_ATTEMPTS)
        });
        if !disposition_ok || !release_ok || !link_ok {
            return Err(invalid(
                "an authorization's operation link, disposition or release row disagrees with \
                 its state",
            ));
        }
    }
    let Some(section) = &wire.operations else {
        return Ok(());
    };
    if section.tombstones.len() > TOMBSTONES_MAX {
        return Err(invalid("the window holds more tombstones than it keeps"));
    }
    let mut ids = std::collections::HashSet::new();
    let mut business_ids = std::collections::HashSet::new();
    let chain = wire.chain_scope.map(|scope| scope.chain());
    for record in &section.records {
        if !ids.insert(record.id) || !business_ids.insert(record.business_id.as_str()) {
            return Err(invalid("an operation identity or business id repeats"));
        }
        validate_record(record, chain)?;
    }
    for tombstone in &section.tombstones {
        if !ids.insert(tombstone.id)
            || !business_ids.insert(tombstone.business_id.as_str())
            || !tombstone.state.is_terminal()
            || !tombstone
                .result
                .as_ref()
                .is_none_or(OperationResult::well_formed)
        {
            return Err(invalid("an operation tombstone repeats or is not terminal"));
        }
    }
    Ok(())
}

fn serialized_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

#[allow(
    clippy::too_many_lines,
    reason = "one pass over every bound and invariant of a record"
)]
fn validate_record(record: &WireOperation, chain: Option<Caip2>) -> Result<(), WindowStoreError> {
    let bad = |detail: &str| Err(invalid(format!("an operation record {detail}")));
    if record.profile.is_empty() || record.profile.len() > NAME_MAX {
        return bad("names no valid profile");
    }
    if !record.chain_id.is_mainnet() || chain.is_some_and(|chain| chain != record.chain_id) {
        return bad("names a chain other than the window's mainnet scope");
    }
    if record.history.is_empty()
        || record.history.len() > HISTORY_MAX
        || record.history[0].from.is_some()
        || record.history[0].to != OperationState::Prepared
        || record.history.last().map(|entry| entry.to) != Some(record.state)
        || record.history.iter().any(|entry| {
            entry
                .evidence
                .as_ref()
                .is_some_and(|text| !text.fits(HISTORY_EVIDENCE_MAX))
        })
    {
        return bad("holds a history that disagrees with its state or bounds");
    }
    if record.commit_ids.len() > COMMIT_IDS_MAX
        || (record.state.is_waiting() && record.commit_ids.len() > WAITING_COMMIT_IDS_MAX)
    {
        return bad("holds more commit identifiers than its state admits");
    }
    if record.state.is_terminal() != record.closed_at_ms.is_some() {
        return bad("has a closing time that disagrees with its state");
    }
    if record
        .envelope_xdr
        .as_ref()
        .is_some_and(|xdr| xdr.len() > ENVELOPE_XDR_MAX)
        || serialized_len(&record.intent) > INTENT_SLOT_MAX
        || record
            .prepared_decision
            .as_ref()
            .is_some_and(|decision| serialized_len(decision) > PREPARED_DECISION_MAX)
        || serialized_len(&record.holds) > HOLDS_MAX
        || !record
            .result
            .as_ref()
            .is_none_or(OperationResult::well_formed)
    {
        return bad("exceeds an allowance");
    }
    if let Some(OperationAuthority::Approval { approval_nonce, .. }) = &record.authority
        && approval_nonce.len() > APPROVAL_NONCE_MAX
    {
        return bad("holds an approval nonce above its allowance");
    }
    if record.attempts.len() > MAX_ATTEMPTS {
        return bad("holds more attempts than it may make");
    }
    let mut seqs = std::collections::HashSet::new();
    for (position, attempt) in record.attempts.iter().enumerate() {
        if usize::try_from(attempt.index).ok() != Some(position + 1) {
            return bad("numbers its attempts out of order");
        }
        if attempt.request_id.is_empty()
            || attempt.request_id.len() > REQUEST_ID_MAX
            || attempt
                .exposure
                .as_ref()
                .is_some_and(|exposure| !exposure.identity.well_formed())
            || attempt.agreed_outcome.as_ref().is_some_and(|outcome| {
                !outcome.status.fits(ENDPOINT_TEXT_MAX) || !outcome.result_xdr.fits(RESULT_XDR_MAX)
            })
            || attempt.recovery.as_ref().is_some_and(|r| !r.fits())
        {
            return bad("holds an attempt outside its bounds");
        }
        if let Some(decision) = &attempt.decision {
            let proved = match attempt.outcome {
                Some(OperationState::Succeeded) => {
                    attempt.agreed_outcome.is_some() && decision.fee_charged.is_none()
                }
                Some(OperationState::Failed) => {
                    attempt.agreed_outcome.is_some()
                        && decision.fee_charged.is_some_and(|fee| fee >= 0)
                }
                Some(OperationState::NotIncluded) => {
                    attempt.not_included.is_some()
                        && attempt.sequence_released.is_some()
                        && decision.fee_charged.is_none()
                }
                _ => false,
            };
            if !proved || !record.commit_ids.contains(&decision.commit_id) {
                return bad("holds a recovery decision without its committed proof");
            }
        }
        if attempt.evidence.len() > MAX_EVIDENCE_ROWS
            || attempt.evidence.iter().any(|row| {
                !row.answer.fits()
                    || row.evidence_seq == 0
                    || row.evidence_seq > record.evidence_committed_seq
                    || !seqs.insert(row.evidence_seq)
            })
        {
            return bad("holds evidence rows outside its sequence or bounds");
        }
    }
    Ok(())
}

/// Prunes tombstones, then compacts terminal records past retention or above
/// the terminal cap. A record compacts only when every authorization it
/// links has a release row; the linked authorizations ordinary pruning would
/// drop are removed through [`remove_authorizations`].
fn prune_section(wire: &mut WireFile, now_ms: u64) {
    let Some(section) = wire.operations.as_mut() else {
        return;
    };
    section.tombstones.retain(|tombstone| {
        tombstone
            .closed_at_ms
            .saturating_add(TOMBSTONE_RETENTION_MS)
            > now_ms
    });

    let eligible = |wire: &WireFile, record: &WireOperation| {
        record.state.is_terminal()
            && !wire.authorizations.iter().any(|auth| {
                auth.operation
                    .is_some_and(|link| link.operation_id == record.id)
                    && auth.native_release.is_none()
            })
    };
    let mut compact: Vec<OperationId> = records(wire)
        .iter()
        .filter(|record| {
            eligible(wire, record)
                && record
                    .closed_at_ms
                    .is_some_and(|closed| closed.saturating_add(TERMINAL_RETENTION_MS) <= now_ms)
        })
        .map(|record| record.id)
        .collect();
    let terminal_kept = records(wire)
        .iter()
        .filter(|record| record.state.is_terminal() && !compact.contains(&record.id))
        .count();
    if terminal_kept > TERMINAL_RECORDS_MAX {
        let mut candidates: Vec<(u64, OperationId)> = records(wire)
            .iter()
            .filter(|record| eligible(wire, record) && !compact.contains(&record.id))
            .map(|record| {
                (
                    record.closed_at_ms.unwrap_or(record.updated_at_ms),
                    record.id,
                )
            })
            .collect();
        candidates.sort();
        compact.extend(
            candidates
                .into_iter()
                .take(terminal_kept - TERMINAL_RECORDS_MAX)
                .map(|(_, id)| id),
        );
    }
    if !compact.is_empty() {
        let cutoff = now_ms.saturating_sub(super::store::RETENTION_MS);
        remove_authorizations(wire, |auth| {
            auth.operation
                .is_some_and(|link| compact.contains(&link.operation_id))
                && super::ledger::prunable(auth, cutoff, now_ms)
        });
        let section = section_mut(wire);
        let mut kept = Vec::with_capacity(section.records.len());
        for record in std::mem::take(&mut section.records) {
            if compact.contains(&record.id) {
                section.tombstones.push(record.tombstone());
            } else {
                kept.push(record);
            }
        }
        section.records = kept;
    }
    let section = section_mut(wire);
    if section.tombstones.len() > TOMBSTONES_MAX {
        section
            .tombstones
            .sort_by_key(|tombstone| tombstone.closed_at_ms);
        let excess = section.tombstones.len() - TOMBSTONES_MAX;
        section.tombstones.drain(..excess);
    }
    if section.is_empty() {
        wire.operations = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Facade inputs and results
// ─────────────────────────────────────────────────────────────────────────────

/// The limit a new record or an attempt's envelope exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityDetail {
    /// The envelope exceeds [`ENVELOPE_XDR_MAX`] base64 bytes.
    EnvelopeSize,
    /// The committed image reached [`FILE_THRESHOLD`] bytes.
    FileSize,
    /// The serialized intent slot exceeds [`INTENT_SLOT_MAX`] bytes.
    IntentSize,
    /// The serialized record exceeds [`RECORD_MAX`] bytes.
    RecordSize,
    /// [`MAX_WAITING_OPERATIONS`] operations already wait.
    WaitingOperations,
}

impl CapacityDetail {
    /// The detail's wire label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::EnvelopeSize => "envelope_size",
            Self::FileSize => "file_size",
            Self::IntentSize => "intent_size",
            Self::RecordSize => "record_size",
            Self::WaitingOperations => "waiting_operations",
        }
    }
}

impl std::fmt::Display for CapacityDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// What [`OperationRecorder::open`] records for an unknown business id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// The caller's business id.
    pub business_id: BusinessId,
    /// The entry point.
    pub tool: OperationTool,
    /// The value call.
    pub kind: OperationKind,
    /// The intent the id is bound to.
    pub intent: IntentSlot,
    /// The prepared envelope of an `Envelope` record, or the envelope built
    /// for a `Canonical` record's first attempt; absent for x402.
    pub envelope_xdr: Option<String>,
    /// The prepared decision, for audit and status; at most 1,024 serialized
    /// bytes.
    pub prepared_decision: Option<serde_json::Value>,
    /// The deciding rule's lifetime in milliseconds; absent means the
    /// mainnet policy-authority lifetime.
    pub rule_ttl_ms: Option<u64>,
}

/// The result of [`OperationRecorder::open`].
#[derive(Debug)]
pub enum OpenOutcome {
    /// The id was unknown; a `Prepared` record was committed.
    New(OperationHandle),
    /// The id names a record or tombstone with the same intent in a state
    /// that does no further work; nothing was done for it.
    Replay(OperationView),
    /// The id names a waiting record inside its window, or an `Authorized`
    /// or `NotIncluded` record inside its execution window.
    Resumable(OperationHandle),
    /// The id names a record or tombstone with another intent digest or slot
    /// kind; the caller refuses with `operation.business_id_conflict`.
    Conflict,
}

/// The result of [`OperationRecorder::lookup`]: what a retained business id
/// names, before any comparison with a request's intent.
#[derive(Debug)]
pub enum LookupOutcome {
    /// A record or tombstone in a state that does no further work.
    Replay(OperationView),
    /// A waiting record inside its window, or an `Authorized` or
    /// `NotIncluded` record inside its execution window.
    Resumable(OperationHandle),
}

impl LookupOutcome {
    /// The slot kind and intent digest the business id is bound to.
    #[must_use]
    pub fn binding(&self) -> (SlotKind, [u8; 32]) {
        match self {
            Self::Replay(view) => (view.slot_kind, view.intent_digest),
            Self::Resumable(handle) => (handle.intent().kind(), handle.intent().intent_digest()),
        }
    }
}

/// The envelope an attempt signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEnvelope {
    /// The envelope in base64; at most [`ENVELOPE_XDR_MAX`] bytes.
    pub xdr: String,
    /// The unsigned envelope's digest.
    pub unsigned_envelope_sha256: [u8; 32],
}

/// The authorization an attempt runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptAuthorization {
    /// The open authorization already linked to the operation's next
    /// attempt.
    Linked,
    /// A mint under the window lock, linked to the next attempt. Open
    /// authorizations the operation links are retired in the same commit.
    Mint(Box<MintRequest>),
}

/// What [`OperationRecorder::begin_attempt`] opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRequest {
    /// The envelope of a classic attempt; absent for x402.
    pub envelope: Option<AttemptEnvelope>,
    /// The authorization source.
    pub authorization: AttemptAuthorization,
    /// The latest send time the caller allows, in Unix milliseconds; the
    /// attempt's send-by is at most the authorization's expiry.
    pub send_by_ms: u64,
}

/// The committed start of an attempt.
#[derive(Debug)]
pub struct AttemptStarted {
    /// The attempt's index, starting at 1.
    pub attempt_index: u32,
    /// The authorization the attempt runs under.
    pub authorization_id: AuthorizationId,
    /// The mint's record, when the attempt minted.
    pub minted: Option<MintedRecord>,
    /// The attempt's send-by time, in Unix milliseconds.
    pub send_by_ms: u64,
    /// The commit that opened the attempt.
    pub commit_id: CommitId,
}

/// What a transition records beside the state change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitionEvidence {
    /// The history entry's evidence text; at most 128 serialized bytes are
    /// kept, a longer text keeps its digest.
    pub note: Option<String>,
    /// The operation's result.
    pub result: Option<OperationResult>,
    /// The agreed outcome of the current attempt.
    pub agreed_outcome: Option<AgreedOutcome>,
    /// The non-inclusion proof `NotIncluded` requires.
    pub not_included: Option<NotIncludedProof>,
    /// The current attempt's recovery state.
    pub recovery: Option<RecoveryUpdate>,
    /// The acknowledged operator clear that `SentOutcomeUnknown` to
    /// `Cancelled` requires.
    pub clear: Option<ClearForm>,
    /// The submitter proved that no send of the attempt's payload started.
    /// A `Sending` to `NotSent` transition then writes the attempt's `Always`
    /// row of class `proved_unspent` also after a committed exposure; every
    /// other transition ignores it.
    pub send_never_started: bool,
}

/// How an operator clear of an unknown outcome releases the native
/// reservation of the last exposed attempt, in the clear's commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearForm {
    /// The operator acknowledged an exposure without a time bound: an
    /// `Always` row of class `unknown`.
    Untimed,
    /// The exposure carries a `max_time`: a `CloseTime` row of class
    /// `unknown` at that time in milliseconds.
    Timed,
}

/// One evidence row a recovery pass offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRowInput {
    /// The answering endpoint.
    pub endpoint: EvidenceEndpoint,
    /// The ledger the endpoint reported.
    pub observed_ledger: u32,
    /// The answer.
    pub answer: EvidenceAnswer,
    /// The answer's digest.
    pub digest: [u8; 32],
}

/// The first proof that an attempt's sequence was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceReleaseInput {
    /// The primary endpoint's release ledger.
    pub primary_ledger: u32,
    /// The witness endpoint's release ledger.
    pub witness_ledger: u32,
    /// The release's minimum close time, in Unix milliseconds.
    pub min_close_time_ms: u64,
}

/// What [`OperationRecorder::record_evidence`] commits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceInput {
    /// The attempt snapshot required before applying a network evaluation.
    pub expected_attempt: Option<RecoveryAttempt>,
    /// New rows, at most [`MAX_EVIDENCE_ROWS`]; a duplicate is a no-op.
    pub rows: Vec<EvidenceRowInput>,
    /// The first sequence release; a later one is ignored.
    pub sequence_released: Option<SequenceReleaseInput>,
    /// The attempt's replaceable recovery state.
    pub recovery: Option<RecoveryUpdate>,
    /// The pass's chain observation.
    pub observation: Option<WindowObservation>,
}

/// A capability to continue one operation, from [`OperationRecorder::open`].
#[derive(Debug, Clone)]
pub struct OperationHandle {
    id: OperationId,
    business_id: BusinessId,
    state: OperationState,
    kind: OperationKind,
    intent: IntentSlot,
    envelope_xdr: Option<String>,
    attempts: u32,
    waiting_expires_at_ms: u64,
    execution_expires_at_ms: Option<u64>,
}

impl OperationHandle {
    fn of(record: &WireOperation) -> Self {
        Self {
            id: record.id,
            business_id: record.business_id.clone(),
            state: record.state,
            kind: record.kind,
            intent: record.intent.clone(),
            envelope_xdr: record.envelope_xdr.clone(),
            attempts: u32::try_from(record.attempts.len()).unwrap_or(u32::MAX),
            waiting_expires_at_ms: record.waiting_expires_at_ms,
            execution_expires_at_ms: record.execution_expires_at_ms,
        }
    }

    /// The operation's identity.
    #[must_use]
    pub fn id(&self) -> OperationId {
        self.id
    }

    /// The business id the record is bound to.
    #[must_use]
    pub fn business_id(&self) -> &BusinessId {
        &self.business_id
    }

    /// Refuses a commit that presents another business id.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::BusinessIdMismatch`] when `presented` is not the
    /// record's business id.
    pub fn require_business_id(&self, presented: &BusinessId) -> Result<(), WindowStoreError> {
        if presented == &self.business_id {
            Ok(())
        } else {
            Err(WindowStoreError::BusinessIdMismatch)
        }
    }

    /// The state when the handle was issued.
    #[must_use]
    pub fn state(&self) -> OperationState {
        self.state
    }

    /// The value call.
    #[must_use]
    pub fn kind(&self) -> OperationKind {
        self.kind
    }

    /// The stored intent slot.
    #[must_use]
    pub fn intent(&self) -> &IntentSlot {
        &self.intent
    }

    /// The stored envelope text, which a resumed `Envelope` record reuses.
    #[must_use]
    pub fn envelope_xdr(&self) -> Option<&str> {
        self.envelope_xdr.as_deref()
    }

    /// The stored unsigned envelope digest of an `Envelope` record.
    #[must_use]
    pub fn unsigned_envelope_sha256(&self) -> Option<[u8; 32]> {
        match &self.intent {
            IntentSlot::Envelope {
                unsigned_envelope_sha256,
                ..
            } => Some(*unsigned_envelope_sha256),
            IntentSlot::Canonical { .. } | IntentSlot::X402 { .. } => None,
        }
    }

    /// The number of attempts made.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The end of the waiting window, in Unix milliseconds.
    #[must_use]
    pub fn waiting_expires_at_ms(&self) -> u64 {
        self.waiting_expires_at_ms
    }

    /// The end of the execution window, in Unix milliseconds, once an
    /// authority stands.
    #[must_use]
    pub fn execution_expires_at_ms(&self) -> Option<u64> {
        self.execution_expires_at_ms
    }
}

/// What a classic commit's business id names, read with the envelope's
/// owners in [`OperationStatus::commit_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitTarget {
    /// A retained record and the digest of the unsigned envelope it binds;
    /// `None` for an x402 record, which binds no envelope.
    Record {
        /// The record.
        view: OperationView,
        /// The digest of the unsigned envelope the record binds.
        envelope_sha256: Option<[u8; 32]>,
    },
    /// A tombstone, which keeps its slot kind and intent digest but no
    /// envelope binding.
    Tombstone(OperationView),
}

/// The facts of one window read a classic commit compares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitBinding {
    /// The record or tombstone under the commit's business id.
    pub target: Option<CommitTarget>,
    /// Every retained record that binds the commit's envelope. Two records
    /// under different ids bind the same bytes when two preparations of one
    /// intent build at the same sequence and second.
    pub owners: Vec<OperationView>,
}

/// A read-only view of one retained record or tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationView {
    /// The operation's identity.
    pub operation_id: OperationId,
    /// The business id.
    pub business_id: BusinessId,
    /// The state.
    pub state: OperationState,
    /// The entry point; absent for a tombstone.
    pub tool: Option<OperationTool>,
    /// The value call; absent for a tombstone.
    pub kind: Option<OperationKind>,
    /// The intent slot's kind.
    pub slot_kind: SlotKind,
    /// The intent digest.
    pub intent_digest: [u8; 32],
    /// The number of attempts made; zero for a tombstone.
    pub attempts: u32,
    /// The result.
    pub result: Option<OperationResult>,
    /// When the record opened; absent for a tombstone.
    pub created_at_ms: Option<u64>,
    /// When the record closed.
    pub closed_at_ms: Option<u64>,
    /// The end of the waiting window; absent for a tombstone.
    pub waiting_expires_at_ms: Option<u64>,
    /// The end of the execution window, once an authority stands.
    pub execution_expires_at_ms: Option<u64>,
    /// Whether the record was compacted to a tombstone.
    pub compacted: bool,
    /// Whether recovery recorded history loss for an attempt.
    pub history_incomplete: bool,
}

impl OperationView {
    fn of_record(record: &WireOperation) -> Self {
        Self {
            operation_id: record.id,
            business_id: record.business_id.clone(),
            state: record.state,
            tool: Some(record.tool),
            kind: Some(record.kind),
            slot_kind: record.intent.kind(),
            intent_digest: record.intent.intent_digest(),
            attempts: u32::try_from(record.attempts.len()).unwrap_or(u32::MAX),
            result: record.result.clone(),
            created_at_ms: Some(record.created_at_ms),
            closed_at_ms: record.closed_at_ms,
            waiting_expires_at_ms: Some(record.waiting_expires_at_ms),
            execution_expires_at_ms: record.execution_expires_at_ms,
            compacted: false,
            history_incomplete: record.history_incomplete(),
        }
    }

    fn of_tombstone(tombstone: &WireTombstone) -> Self {
        Self {
            operation_id: tombstone.id,
            business_id: tombstone.business_id.clone(),
            state: tombstone.state,
            tool: None,
            kind: None,
            slot_kind: tombstone.slot_kind,
            intent_digest: tombstone.intent_digest,
            attempts: 0,
            result: tombstone.result.clone(),
            created_at_ms: None,
            closed_at_ms: Some(tombstone.closed_at_ms),
            waiting_expires_at_ms: None,
            execution_expires_at_ms: None,
            compacted: true,
            history_incomplete: false,
        }
    }
}

/// Appends an operation step's audit row durably, before the window write.
pub trait OperationAudit {
    /// Appends `entry`.
    ///
    /// # Errors
    ///
    /// The writer's failure as text, without key material. The step is then
    /// not committed.
    fn append(&mut self, entry: AuditEntry) -> Result<(), String>;
}

impl OperationAudit for stellar_agent_core::audit_log::AuditWriter {
    fn append(&mut self, entry: AuditEntry) -> Result<(), String> {
        self.write_entry(entry).map_err(|error| error.to_string())?;
        self.require_anchor_current()
            .map_err(|error| error.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The recorder
// ─────────────────────────────────────────────────────────────────────────────

/// Records the steps of a profile's operations in its window file.
///
/// Each method takes the window lock once and commits at most one
/// generation. Audit rows are appended before the window write; an append
/// failure returns `audit.append_failed` and commits nothing. A caller that
/// holds an audit writer acquired it before calling, because the writer
/// lock precedes the window lock.
pub struct OperationRecorder<'a> {
    store: &'a PersistedWindowStore,
    profile: &'a Profile,
    audit: &'a mut dyn OperationAudit,
    request_id: String,
}

impl std::fmt::Debug for OperationRecorder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationRecorder")
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

/// One locked step: the store clock, the verified snapshot, its successor
/// and the step's audit rows.
pub(super) struct Session<'s> {
    pub(super) profile: &'s Profile,
    pub(super) now: u64,
    pub(super) original: &'s WireFile,
    pub(super) wire: WireFile,
    mint_expires: Option<u64>,
    audit: AuditBatch<'s>,
    pub(super) changed: bool,
}

impl Session<'_> {
    /// Links the approval and records its waiting edge in this session.
    pub(super) fn await_approval(
        &mut self,
        id: OperationId,
        approval_id: [u8; 32],
        intent_digest: [u8; 32],
    ) -> Result<(), WindowStoreError> {
        let index = record_index(&self.wire, id)?;
        let record = &mut section_mut(&mut self.wire).records[index];
        if record.state != OperationState::Prepared
            || record
                .approval_record_id
                .is_some_and(|linked| linked != approval_id)
            || record.intent.intent_digest() != intent_digest
        {
            return Err(unexpected(
                "the approval requires a matching prepared operation",
            ));
        }
        record.approval_record_id = Some(approval_id);
        record.step(
            OperationState::AwaitingApproval,
            self.now,
            None,
            self.audit.commit,
        )?;
        self.audit.transition(
            record,
            None,
            Some(OperationState::Prepared),
            OperationState::AwaitingApproval.wire_name(),
        );
        self.changed = true;
        Ok(())
    }

    /// Sweeps expired authorizations, adopting the waiting records they
    /// link, then adopts waiting records whose linked authorization is
    /// open.
    fn sweep_and_adopt(&mut self) -> Result<(), WindowStoreError> {
        let swept = super::ledger::sweep_expired_with(&mut self.wire, self.now, self.audit.commit);
        for id in swept.adopted {
            if let Some(record) = records(&self.wire).iter().find(|record| record.id == id) {
                let from = record.history.last().and_then(|entry| entry.from);
                self.audit
                    .transition(record, None, from, OperationState::Authorized.wire_name());
            }
        }
        self.changed |= swept.swept;
        self.changed |= adopt_live(&mut self.wire, self.now, &mut self.audit)?;
        Ok(())
    }

    fn expire(&mut self, at_ms: u64) -> Result<usize, WindowStoreError> {
        let ended = expire_records(&mut self.wire, at_ms, &mut self.audit)?;
        self.changed |= ended > 0;
        Ok(ended)
    }

    /// Sweeps and adopts, applies the expiry edges at the store clock and
    /// prunes, so a lookup reads the states a write would act on.
    fn settle(&mut self) -> Result<(), WindowStoreError> {
        self.sweep_and_adopt()?;
        self.expire(self.now)?;
        prune_stale(&mut self.wire, self.now);
        Ok(())
    }

    /// The record or tombstone `business_id` names, with its slot kind and
    /// intent digest.
    fn retained(&self, business_id: &BusinessId) -> Option<(SlotKind, [u8; 32], LookupOutcome)> {
        if let Some(record) = records(&self.wire)
            .iter()
            .find(|record| &record.business_id == business_id)
        {
            let found = if record.state.resumes() {
                LookupOutcome::Resumable(OperationHandle::of(record))
            } else {
                LookupOutcome::Replay(OperationView::of_record(record))
            };
            return Some((record.intent.kind(), record.intent.intent_digest(), found));
        }
        tombstones(&self.wire)
            .iter()
            .find(|tombstone| &tombstone.business_id == business_id)
            .map(|tombstone| {
                (
                    tombstone.slot_kind,
                    tombstone.intent_digest,
                    LookupOutcome::Replay(OperationView::of_tombstone(tombstone)),
                )
            })
    }

    fn open(&mut self, request: &OpenRequest) -> Result<OpenOutcome, WindowStoreError> {
        use OperationState as S;
        self.settle()?;
        if let Some((kind, digest, found)) = self.retained(&request.business_id) {
            if kind != request.intent.kind() || digest != request.intent.intent_digest() {
                return Ok(OpenOutcome::Conflict);
            }
            return Ok(match found {
                LookupOutcome::Resumable(handle) => OpenOutcome::Resumable(handle),
                LookupOutcome::Replay(view) => OpenOutcome::Replay(view),
            });
        }
        let record = self.new_record(request)?;
        let handle = OperationHandle::of(&record);
        self.audit
            .transition(&record, None, None, S::Prepared.wire_name());
        section_mut(&mut self.wire).records.push(record);
        self.changed = true;
        Ok(OpenOutcome::New(handle))
    }

    fn new_record(&self, request: &OpenRequest) -> Result<WireOperation, WindowStoreError> {
        if request
            .envelope_xdr
            .as_ref()
            .is_some_and(|xdr| xdr.len() > ENVELOPE_XDR_MAX)
        {
            return Err(capacity(CapacityDetail::EnvelopeSize));
        }
        if serialized_len(&request.intent) > INTENT_SLOT_MAX {
            return Err(capacity(CapacityDetail::IntentSize));
        }
        if request
            .prepared_decision
            .as_ref()
            .is_some_and(|decision| serialized_len(decision) > PREPARED_DECISION_MAX)
        {
            return Err(invalid("a prepared decision exceeds its allowance"));
        }
        let waiting = records(&self.wire)
            .iter()
            .filter(|record| record.state.is_waiting())
            .count();
        if waiting >= MAX_WAITING_OPERATIONS {
            return Err(capacity(CapacityDetail::WaitingOperations));
        }
        if serialized_len(self.original) >= FILE_THRESHOLD {
            return Err(capacity(CapacityDetail::FileSize));
        }
        let id = loop {
            let candidate = OperationId::random();
            if !records(&self.wire)
                .iter()
                .any(|record| record.id == candidate)
                && !tombstones(&self.wire)
                    .iter()
                    .any(|tombstone| tombstone.id == candidate)
            {
                break candidate;
            }
        };
        let ttl_ms = request.rule_ttl_ms.unwrap_or(
            stellar_agent_core::approval::MAINNET_POLICY_AUTHORITY_TTL_SECONDS.saturating_mul(1000),
        );
        let waiting_end = self.now.saturating_add(ttl_ms);
        let waiting_end = request
            .intent
            .envelope_end_ms()
            .map_or(waiting_end, |end| end.min(waiting_end));
        let profile = stellar_agent_core::profile::name::profile_name_for_approval(self.profile);
        if profile.is_empty() || profile.len() > NAME_MAX {
            return Err(invalid("the profile name exceeds its allowance"));
        }
        let record = WireOperation {
            id,
            business_id: request.business_id.clone(),
            profile,
            chain_id: self.profile.chain_id,
            state: OperationState::Prepared,
            tool: request.tool,
            kind: request.kind,
            intent: request.intent.clone(),
            envelope_xdr: match request.intent {
                IntentSlot::X402 { .. } => None,
                IntentSlot::Envelope { .. } | IntentSlot::Canonical { .. } => {
                    request.envelope_xdr.clone()
                }
            },
            prepared_decision: request.prepared_decision.clone(),
            authority: None,
            approval_record_id: None,
            holds: Vec::new(),
            history: vec![HistoryEntry {
                from: None,
                to: OperationState::Prepared,
                at_ms: self.now,
                evidence: None,
            }],
            last_commit_id: Some(self.audit.commit),
            commit_ids: vec![self.audit.commit],
            evidence_committed_seq: 0,
            attempts: Vec::new(),
            result: None,
            created_at_ms: self.now,
            updated_at_ms: self.now,
            closed_at_ms: None,
            execution_expires_at_ms: None,
            waiting_expires_at_ms: waiting_end,
        };
        if serialized_len(&record) > RECORD_MAX {
            return Err(capacity(CapacityDetail::RecordSize));
        }
        Ok(record)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one locked step: the checks in their order, the mint and the commit of the attempt"
    )]
    fn begin(
        &mut self,
        id: OperationId,
        request: &AttemptRequest,
        request_id: &str,
    ) -> Result<AttemptStarted, WindowStoreError> {
        use OperationState as S;
        self.sweep_and_adopt()?;
        let index = record_index(&self.wire, id)?;
        let record = &records(&self.wire)[index];
        if record.state.is_waiting() && record.waiting_expires_at_ms <= self.now {
            return Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::Expired,
            });
        }
        if let IntentSlot::Envelope {
            unsigned_envelope_sha256,
            ..
        } = &record.intent
            && let Some(envelope) = &request.envelope
            && envelope.unsigned_envelope_sha256 != *unsigned_envelope_sha256
        {
            return Err(WindowStoreError::BusinessIdConflict);
        }
        if matches!(record.state, S::Sending | S::SentOutcomeUnknown) {
            return Err(WindowStoreError::AttemptOpen);
        }
        if record.attempts.len() >= MAX_ATTEMPTS {
            return Err(WindowStoreError::AttemptLimit);
        }
        let from = record.state;
        if !from.is_waiting() {
            check_edge(Some(from), S::Sending)?;
        }
        if record
            .execution_expires_at_ms
            .is_some_and(|end| end <= self.now)
        {
            return Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::Expired,
            });
        }
        if request_id.is_empty() || request_id.len() > REQUEST_ID_MAX {
            return Err(invalid("a request identifier exceeds its allowance"));
        }
        let successor = from == S::NotIncluded;
        let previous_auth = record
            .current_attempt()
            .map(|attempt| attempt.authorization_id);
        if successor {
            if record.kind.is_x402() {
                return Err(unexpected("an x402 operation makes one attempt"));
            }
            if record
                .current_attempt()
                .is_none_or(|attempt| attempt.not_included.is_none())
            {
                return Err(unexpected(
                    "a successor attempt needs its predecessor's non-inclusion evidence",
                ));
            }
            // Only a checked non-inclusion permits a successor, and only
            // after the caller projected its decision onto the receipt.
            if record
                .current_attempt()
                .and_then(|attempt| attempt.decision.as_ref())
                .is_none_or(|decision| !decision.projected)
            {
                return Err(WindowStoreError::RetryRefused);
            }
        }
        let permission = successor
            .then(|| {
                record
                    .current_attempt()
                    .and_then(|attempt| attempt.decision.clone())
            })
            .flatten();
        let next = u32::try_from(record.attempts.len() + 1)
            .map_err(|_| unexpected("an attempt index exceeds its range"))?;
        let link = OperationLink {
            operation_id: id,
            attempt_index: next,
        };
        let commit = self.audit.commit;
        let now = self.now;
        let mut minted = None;
        let auth_id = match &request.authorization {
            AttemptAuthorization::Linked => {
                let linked = self
                    .wire
                    .authorizations
                    .iter()
                    .find(|auth| {
                        auth.operation == Some(link)
                            && auth.state == AuthorizationState::Open
                            && super::ledger::effective(auth, now)
                    })
                    .ok_or_else(|| {
                        unexpected("the operation has no open authorization for its next attempt")
                    })?;
                if successor {
                    same_policy_as_predecessor(
                        &self.wire,
                        previous_auth,
                        linked.policy_digest,
                        linked.policy_sequence,
                    )?;
                }
                linked.id
            }
            AttemptAuthorization::Mint(mint) => {
                if successor {
                    same_policy_as_predecessor(
                        &self.wire,
                        previous_auth,
                        mint.policy_digest,
                        mint.policy_sequence,
                    )?;
                }
                let linked_open: Vec<AuthorizationId> = self
                    .wire
                    .authorizations
                    .iter()
                    .filter(|auth| {
                        auth.operation.is_some_and(|link| link.operation_id == id)
                            && auth.state == AuthorizationState::Open
                    })
                    .map(|auth| auth.id)
                    .collect();
                for retired in linked_open {
                    if exposed(&self.wire, retired) {
                        return Err(unexpected("an exposed authorization cannot be retired"));
                    }
                    release_unused(
                        &mut self.wire,
                        retired,
                        ReleaseClass::RetiredUnused,
                        RETIRED_REASON,
                        now,
                        commit,
                    );
                }
                let mut mint = (**mint).clone();
                mint.operation = Some(link);
                let record = &records(&self.wire)[index];
                let mut expires = self
                    .mint_expires
                    .ok_or_else(|| unexpected("a mint ran without its checks"))?;
                if let Some(end) = record.execution_expires_at_ms {
                    expires = expires.min(end);
                }
                if let Some(end) = record.intent.envelope_end_ms() {
                    expires = expires.min(end);
                }
                if expires <= now {
                    return Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::LifetimeInvalid,
                    });
                }
                let record = super::ledger::mint_into(
                    &mut self.wire,
                    self.profile,
                    &mint,
                    now,
                    expires,
                    MintOptions {
                        exempt_cap: successor,
                        lineage: Some(id),
                    },
                )?;
                let auth_id = record.id;
                minted = Some(record);
                auth_id
            }
        };
        let auth = self
            .wire
            .authorizations
            .iter()
            .find(|auth| auth.id == auth_id)
            .cloned()
            .ok_or_else(|| unexpected("an attempt's authorization is gone"))?;
        let holds: Vec<HoldRef> = self
            .wire
            .holds
            .iter()
            .filter(|hold| hold.authorization_id == auth_id)
            .map(|hold| HoldRef {
                authorization_id: hold.authorization_id,
                ordinal: hold.ordinal,
            })
            .collect();
        if serialized_len(&holds) > HOLDS_MAX {
            return Err(invalid("an attempt's holds exceed their allowance"));
        }
        let mut record = records(&self.wire)[index].clone();
        if from.is_waiting() {
            take_authority(&mut record, &auth)?;
            record.step(S::Authorized, now, None, commit)?;
            self.audit
                .transition(&record, None, Some(from), S::Authorized.wire_name());
        } else if record.execution_expires_at_ms.is_none() {
            take_authority(&mut record, &auth)?;
        }
        let authority = authority_of(&record, &auth)?;
        match (&record.intent, &request.envelope) {
            (IntentSlot::Envelope { .. }, Some(envelope)) if record.envelope_xdr.is_none() => {
                record.envelope_xdr = Some(envelope.xdr.clone());
            }
            (IntentSlot::Canonical { .. }, envelope) => {
                record.envelope_xdr = envelope.as_ref().map(|envelope| envelope.xdr.clone());
            }
            (IntentSlot::X402 { .. }, _) => record.envelope_xdr = None,
            (IntentSlot::Envelope { .. }, _) => {}
        }
        let send_by_ms = request.send_by_ms.min(auth.expires_ms);
        record.holds = holds;
        record.attempts.push(WireAttempt {
            index: next,
            authorization_id: auth_id,
            authority,
            send_by_ms,
            request_id: request_id.to_owned(),
            started_at_ms: now,
            outcome: None,
            pre_exposure_ledger: None,
            exposure: None,
            sequence_released: None,
            not_included: None,
            agreed_outcome: None,
            evidence: Vec::new(),
            recovery: None,
            decision: None,
        });
        let before = record.state;
        record.step(S::Sending, now, None, commit)?;
        self.audit
            .transition(&record, Some(next), Some(before), S::Sending.wire_name());
        // The `not_included -> sending` row is the retry permission: it names
        // the checked decision that permits the successor.
        if let Some(decision) = permission
            && let Some(entry) = self.audit.entries.pop()
        {
            self.audit.entries.push(entry.with_recovery_decision(
                stellar_agent_core::hex::encode(&decision.evidence_digest),
                (decision.primary_ledger, decision.witness_ledger),
                None,
            ));
        }
        section_mut(&mut self.wire).records[index] = record;
        self.changed = true;
        Ok(AttemptStarted {
            attempt_index: next,
            authorization_id: auth_id,
            minted,
            send_by_ms,
            commit_id: commit,
        })
    }

    fn expose(
        &mut self,
        id: OperationId,
        attempt_index: u32,
        identity: &ExposureIdentity,
        pre_exposure_ledger: Option<u32>,
    ) -> Result<CommitId, WindowStoreError> {
        self.sweep_and_adopt()?;
        self.expose_swept(id, attempt_index, identity, pre_exposure_ledger)
    }

    /// The exposure step after the caller's own sweep.
    fn expose_swept(
        &mut self,
        id: OperationId,
        attempt_index: u32,
        identity: &ExposureIdentity,
        pre_exposure_ledger: Option<u32>,
    ) -> Result<CommitId, WindowStoreError> {
        if !identity.well_formed() {
            return Err(invalid(
                "an exposure's receipt reference is not a reference",
            ));
        }
        let index = record_index(&self.wire, id)?;
        let commit = self.audit.commit;
        let mut record = records(&self.wire)[index].clone();
        let open = record.state == OperationState::Sending
            && record.current_attempt().is_some_and(|attempt| {
                attempt.index == attempt_index && attempt.exposure.is_none()
            });
        if !open {
            return Err(unexpected(format!(
                "an exposure needs an open attempt {attempt_index} in sending, not {}",
                record.state.wire_name()
            )));
        }
        let auth_id = record
            .current_attempt()
            .map(|attempt| attempt.authorization_id);
        if let Some(auth) = self
            .wire
            .authorizations
            .iter()
            .find(|auth| Some(auth.id) == auth_id)
            && !matches!(
                auth.state,
                AuthorizationState::Claimed | AuthorizationState::Used
            )
        {
            return Err(unexpected(
                "an exposure needs its authorization claimed or used",
            ));
        }
        record.note_commit(commit)?;
        let attempt = record.attempt_mut(attempt_index)?;
        attempt.exposure = Some(WireExposure {
            identity: identity.clone(),
            commit_id: commit,
            exposed_at_ms: self.now,
        });
        attempt.pre_exposure_ledger = pre_exposure_ledger;
        record.updated_at_ms = self.now;
        self.audit.transition(
            &record,
            Some(attempt_index),
            Some(OperationState::Sending),
            "expose",
        );
        section_mut(&mut self.wire).records[index] = record;
        self.changed = true;
        Ok(commit)
    }

    fn transition(
        &mut self,
        id: OperationId,
        attempt_index: Option<u32>,
        to: OperationState,
        evidence: &TransitionEvidence,
    ) -> Result<CommitId, WindowStoreError> {
        use OperationState as S;
        self.sweep_and_adopt()?;
        let index = record_index(&self.wire, id)?;
        let commit = self.audit.commit;
        let now = self.now;
        let mut record = records(&self.wire)[index].clone();
        let current = record.current_attempt().map(|attempt| attempt.index);
        if record.state == to && current == attempt_index {
            return Ok(record.commit_ids.last().copied().unwrap_or(commit));
        }
        if matches!(to, S::Prepared | S::Authorized | S::Sending) {
            return Err(unexpected(format!(
                "the edge to {} belongs to open, adoption and begin_attempt",
                to.wire_name()
            )));
        }
        check_edge(Some(record.state), to)?;
        if attempt_index != current {
            return Err(unexpected(
                "a transition names an attempt other than the operation's current one",
            ));
        }
        let exposed_now = record
            .current_attempt()
            .is_some_and(|attempt| attempt.exposure.is_some());
        if record.state == S::Sending
            && matches!(to, S::SentOutcomeUnknown | S::PayloadReleased)
            && !exposed_now
        {
            return Err(unexpected(format!(
                "the edge to {} needs the attempt's committed exposure",
                to.wire_name()
            )));
        }
        // A non-inclusion permits a successor attempt, so only a checked,
        // committed recovery decision records one.
        if to == S::NotIncluded || evidence.not_included.is_some() {
            return Err(unexpected(
                "a non-inclusion commits only through a checked recovery decision",
            ));
        }
        if evidence.agreed_outcome.is_some() {
            return Err(unexpected(
                "an agreed outcome commits only through a checked recovery decision",
            ));
        }
        let clear = if to == S::Cancelled {
            Some(clear_release(&self.wire, &record, evidence.clear, commit)?)
        } else {
            None
        };
        if let Some(result) = &evidence.result
            && !result.well_formed()
        {
            return Err(invalid(
                "an operation result's error code exceeds its allowance",
            ));
        }
        let from = record.state;
        if let Some(index) = current
            && matches!(from, S::Sending | S::SentOutcomeUnknown)
        {
            let attempt = record.attempt_mut(index)?;
            attempt.outcome = Some(to);
            if let Some(update) = &evidence.recovery {
                attempt.recovery.get_or_insert_default().apply(update)?;
            }
        }
        if let Some(result) = &evidence.result {
            record.result = Some(result.clone());
        }
        if to == S::PayloadReleased {
            record.result.get_or_insert_default().payload_released = true;
        }
        record.step(to, now, evidence.note.as_deref(), commit)?;
        self.audit
            .transition(&record, current, Some(from), to.wire_name());
        let attempt_auth = record
            .current_attempt()
            .map(|attempt| attempt.authorization_id);
        section_mut(&mut self.wire).records[index] = record;
        if let Some((auth_id, row)) = clear
            && let Some(auth) = self
                .wire
                .authorizations
                .iter_mut()
                .find(|auth| auth.id == auth_id)
            && auth.native_release.is_none()
        {
            auth.native_release = Some(row);
        }
        if to.is_terminal() {
            release_linked_unused(&mut self.wire, id, now, commit);
        }
        if matches!(to, S::NotSent | S::Expired)
            && let Some(auth_id) = attempt_auth
        {
            let unsent = from == S::Sending && to == S::NotSent && evidence.send_never_started;
            release_unsent_attempt(&mut self.wire, auth_id, commit, unsent);
        }
        self.changed = true;
        Ok(commit)
    }

    fn record_evidence(
        &mut self,
        id: OperationId,
        attempt_index: u32,
        input: &EvidenceInput,
    ) -> Result<Option<CommitId>, WindowStoreError> {
        if input.rows.len() > MAX_EVIDENCE_ROWS {
            return Err(invalid(
                "an evidence commit offers more rows than an attempt keeps",
            ));
        }
        self.sweep_and_adopt()?;
        let index = record_index(&self.wire, id)?;
        if let Some(expected) = &input.expected_attempt {
            let record = &records(&self.wire)[index];
            let attempt = record
                .attempts
                .iter()
                .find(|attempt| attempt.index == attempt_index)
                .ok_or_else(|| invalid("recovery snapshot names an unknown attempt"))?;
            if expected.operation_id != id
                || expected.attempt_index != attempt_index
                || record.state != OperationState::SentOutcomeUnknown
                || attempt.outcome != Some(OperationState::SentOutcomeUnknown)
                || attempt.exposure.as_ref().map(|exposure| &exposure.identity)
                    != Some(&expected.exposure)
                || attempt.pre_exposure_ledger != expected.pre_exposure_ledger
                || attempt.sequence_released.is_some() != expected.sequence_released
                || attempt.recovery.clone().unwrap_or_default().snapshot() != expected.recovery
            {
                return Err(invalid("recovery snapshot is stale"));
            }
        }
        let commit = self.audit.commit;
        let now = self.now;
        let mut record = records(&self.wire)[index].clone();
        let mut seq = record.evidence_committed_seq;
        let mut added = Vec::new();
        let attempt = record.attempt_mut(attempt_index)?;
        let mut keys: std::collections::HashSet<_> =
            attempt.evidence.iter().map(WireEvidenceRow::key).collect();
        for row in &input.rows {
            let wire_row = WireEvidenceRow {
                endpoint: row.endpoint,
                observed_ledger: row.observed_ledger,
                answer: WireEvidenceAnswer::from_input(&row.answer),
                digest: row.digest,
                commit_id: commit,
                evidence_seq: seq + 1,
            };
            if !keys.insert(wire_row.key()) {
                continue;
            }
            seq += 1;
            added.push(OperationEvidenceRow {
                evidence_seq: seq,
                digest: stellar_agent_core::hex::encode(&row.digest),
                observed_ledger: row.observed_ledger,
                kind: Some(wire_row.audit_kind()),
            });
            attempt.evidence.push(wire_row);
        }
        while attempt.evidence.len() > MAX_EVIDENCE_ROWS {
            if let Some(lowest) = attempt
                .evidence
                .iter()
                .enumerate()
                .min_by_key(|(_, row)| (row.observed_ledger, row.evidence_seq))
                .map(|(position, _)| position)
            {
                attempt.evidence.remove(lowest);
            }
        }
        let mut release = None;
        if attempt.sequence_released.is_none()
            && let Some(proof) = input.sequence_released
        {
            attempt.sequence_released = Some(SequenceReleased {
                primary_ledger: proof.primary_ledger,
                witness_ledger: proof.witness_ledger,
                min_close_time_ms: proof.min_close_time_ms,
                commit_id: commit,
                released_at_ms: now,
            });
            release = Some((
                proof.primary_ledger,
                proof.witness_ledger,
                proof.min_close_time_ms,
            ));
        }
        let mut mutable = false;
        if let Some(update) = &input.recovery {
            let before = attempt.recovery.clone();
            attempt.recovery.get_or_insert_default().apply(update)?;
            mutable |= attempt.recovery != before;
        }
        // Each successfully read transaction answer whose retention starts
        // after the pre-exposure ledger proves history loss, with or without
        // the other endpoint's answer.
        let pre_exposure = attempt.pre_exposure_ledger;
        let pruned = input.rows.iter().any(|row| {
            matches!(
                row.answer,
                EvidenceAnswer::Outcome { oldest_ledger: Some(oldest), .. }
                    if pre_exposure.is_none_or(|ledger| oldest > ledger)
            )
        });
        if pruned {
            let recovery = attempt.recovery.get_or_insert_default();
            mutable |= !recovery.history_incomplete;
            recovery.history_incomplete = true;
        }
        let audited = !added.is_empty() || release.is_some();
        if audited {
            record.evidence_committed_seq = seq;
            record.last_commit_id = Some(commit);
            record.updated_at_ms = now;
            self.audit.entries.push(AuditEntry::new_operation_evidence(
                record.tool.wire_name(),
                self.audit.chain_id,
                record.id.to_hex(),
                attempt_index,
                added,
                release,
                commit.to_hex(),
                self.audit.request_id,
            ));
        }
        section_mut(&mut self.wire).records[index] = record;
        if let Some(observation) = input.observation {
            mutable |= store_observation(&mut self.wire, observation);
        }
        self.changed |= audited || mutable;
        Ok(audited.then_some(commit))
    }

    /// Commits a checked recovery decision with its accounting in this
    /// generation. A decision the attempt already holds returns that
    /// commit and writes nothing, so the first proof stands.
    #[allow(
        clippy::too_many_lines,
        reason = "one commit binds the state, proof, accounting, release row and audit row"
    )]
    fn commit_decision(
        &mut self,
        decision: &CheckedRecoveryDecision,
    ) -> Result<CommitId, WindowStoreError> {
        use OperationState as S;
        self.sweep_and_adopt()?;
        let id = decision.operation_id();
        let attempt_index = decision.attempt_index();
        let index = record_index(&self.wire, id)?;
        let mut record = records(&self.wire)[index].clone();
        let attempt = record
            .attempts
            .iter()
            .find(|attempt| attempt.index == attempt_index)
            .ok_or_else(|| invalid("a recovery decision names an unknown attempt"))?;
        if let Some(existing) = &attempt.decision {
            return Ok(existing.commit_id);
        }
        if self.original.generation != decision.generation() {
            return Err(invalid("recovery snapshot is stale"));
        }
        let Some(ExposureIdentity::Classic {
            envelope_sha256,
            tx_hash,
            ..
        }) = attempt.exposure.as_ref().map(|exposure| &exposure.identity)
        else {
            return Err(invalid("a recovery decision needs a classic exposure"));
        };
        let (envelope_sha256, tx_hash) = (*envelope_sha256, *tx_hash);
        if record.kind.is_x402()
            || envelope_sha256 != decision.envelope_sha256()
            || record.state != S::SentOutcomeUnknown
            || attempt.outcome != Some(S::SentOutcomeUnknown)
            || record.current_attempt().map(|current| current.index) != Some(attempt_index)
        {
            return Err(invalid("recovery snapshot is stale"));
        }
        let (to, outcome, chain, fee_charged) = match decision.transition() {
            DecidedTransition::Succeeded(outcome) => (
                S::Succeeded,
                Some(outcome),
                ChainTransition::Succeeded,
                None,
            ),
            DecidedTransition::Failed {
                outcome,
                fee_charged,
            } => (
                S::Failed,
                Some(outcome),
                ChainTransition::Failed {
                    fee_charged: *fee_charged,
                    close_time: outcome.created_at,
                },
                Some(*fee_charged),
            ),
            DecidedTransition::NotIncluded(_) => {
                (S::NotIncluded, None, ChainTransition::NotIncluded, None)
            }
        };
        if outcome.is_some_and(|outcome| outcome.envelope_xdr_sha256 != envelope_sha256) {
            return Err(invalid("an agreed outcome names another envelope"));
        }
        if fee_charged.is_some_and(|fee| fee < 0) {
            return Err(invalid("a failed outcome charges a negative fee"));
        }
        if to == S::NotIncluded && attempt.sequence_released.is_none() {
            return Err(invalid(
                "a non-inclusion needs the attempt's committed sequence release",
            ));
        }
        check_edge(Some(record.state), to)?;
        let commit = self.audit.commit;
        let now = self.now;
        let (primary_ledger, witness_ledger) = decision.ledgers();
        let attempt = record.attempt_mut(attempt_index)?;
        attempt.outcome = Some(to);
        match decision.transition() {
            DecidedTransition::Succeeded(outcome) | DecidedTransition::Failed { outcome, .. } => {
                attempt.agreed_outcome = Some(WireAgreedOutcome::from_input(outcome));
            }
            DecidedTransition::NotIncluded(proof) => attempt.not_included = Some(*proof),
        }
        let update = RecoveryUpdate {
            disagreements: 0,
            ..decision.recovery().clone()
        };
        attempt.recovery.get_or_insert_default().apply(&update)?;
        attempt.decision = Some(WireDecision {
            commit_id: commit,
            evidence_digest: decision.evidence_digest(),
            primary_ledger,
            witness_ledger,
            fee_charged,
            projected: false,
        });
        let auth_id = attempt.authorization_id;
        let result = record.result.get_or_insert_default();
        result.tx_hash = Some(tx_hash);
        result.ledger = outcome.map(|outcome| outcome.ledger);
        record.step(to, now, None, commit)?;
        self.audit.transition(
            &record,
            Some(attempt_index),
            Some(S::SentOutcomeUnknown),
            to.wire_name(),
        );
        if let Some(entry) = self.audit.entries.pop() {
            let code = (to == S::NotIncluded)
                .then_some(stellar_agent_core::profile::receipt::RELEASED_ON_EVIDENCE_CODE);
            self.audit.entries.push(entry.with_recovery_decision(
                stellar_agent_core::hex::encode(&decision.evidence_digest()),
                (primary_ledger, witness_ledger),
                code,
            ));
        }
        section_mut(&mut self.wire).records[index] = record;
        super::store::apply_chain_accounting(
            &mut self.wire,
            &stellar_agent_core::hex::encode(&envelope_sha256),
            chain,
            decision.evidence_digest(),
        )?;
        let row = match outcome {
            Some(outcome) => ReleaseRow {
                class: ReleaseClass::Settled,
                bound: ReleaseBound::Ledger(outcome.ledger),
                observed_ledger: Some(primary_ledger.max(witness_ledger)),
                commit_id: commit,
            },
            None => ReleaseRow::always(ReleaseClass::ProvedUnspent, commit),
        };
        // A consumed authorization's holds are already bucket records,
        // which the chain accounting above settles. A still-held one keeps
        // its holds, which its own lifetime bounds.
        if let Some(auth) = self
            .wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == auth_id)
            && auth.native_release.is_none()
        {
            auth.native_release = Some(row);
        }
        if to.is_terminal() {
            release_linked_unused(&mut self.wire, id, now, commit);
        }
        self.changed = true;
        Ok(commit)
    }

    /// Commits the release of one obligation the verified window holds at
    /// `observation`, with its proof, in one generation. A live x402 record
    /// also becomes `Expired` with its transition audit row; a terminal
    /// record keeps its state.
    fn release_obligation(
        &mut self,
        operation_id: OperationId,
        attempt_index: u32,
        observation: WindowObservation,
        acknowledged_clear: bool,
    ) -> Result<CommitId, WindowStoreError> {
        use OperationState as S;
        self.sweep_and_adopt()?;
        let index = record_index(&self.wire, operation_id)?;
        let mut record = records(&self.wire)[index].clone();
        let attempt = record
            .attempts
            .iter()
            .find(|attempt| attempt.index == attempt_index)
            .ok_or_else(|| invalid("a release obligation names an unknown attempt"))?;
        let obligation = obligation_of(&self.wire, &record, attempt, Some(&observation))
            .ok_or_else(|| invalid("the attempt owes no release its proof allows"))?;
        let auth_id = attempt.authorization_id;
        let commit = self.audit.commit;
        let bound = match obligation.kind {
            ObligationKind::X402Expired {
                signature_expiration_ledger,
            } => ReleaseBound::Ledger(signature_expiration_ledger),
            ObligationKind::TerminalTimed { release_after_ms } => {
                ReleaseBound::CloseTime(release_after_ms)
            }
            ObligationKind::TerminalUntimed if acknowledged_clear => ReleaseBound::Always,
            ObligationKind::TerminalUntimed => {
                return Err(invalid(
                    "an untimed release needs the operator's acknowledged clear",
                ));
            }
        };
        if matches!(obligation.kind, ObligationKind::X402Expired { .. })
            && !record.state.is_terminal()
        {
            let from = record.state;
            check_edge(Some(from), S::Expired)?;
            if record.current_attempt().map(|current| current.index) == Some(attempt_index) {
                record.attempt_mut(attempt_index)?.outcome = Some(S::Expired);
            }
            record.step(S::Expired, self.now, None, commit)?;
            self.audit.transition(
                &record,
                Some(attempt_index),
                Some(from),
                S::Expired.wire_name(),
            );
            section_mut(&mut self.wire).records[index] = record;
        }
        let auth = self
            .wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == auth_id)
            .ok_or_else(|| unexpected("an exposed attempt's authorization is gone"))?;
        auth.native_release = Some(ReleaseRow {
            class: ReleaseClass::Unknown,
            bound,
            observed_ledger: Some(observation.ledger),
            commit_id: commit,
        });
        store_observation(&mut self.wire, observation);
        self.changed = true;
        Ok(commit)
    }
}

/// Refuses a successor attempt whose authorization names another policy
/// digest or sequence than the predecessor attempt's authorization.
fn same_policy_as_predecessor(
    wire: &WireFile,
    previous_auth: Option<AuthorizationId>,
    policy_digest: [u8; 32],
    policy_sequence: i64,
) -> Result<(), WindowStoreError> {
    let previous = previous_auth
        .and_then(|previous| wire.authorizations.iter().find(|auth| auth.id == previous))
        .ok_or_else(|| unexpected("a successor attempt's predecessor authorization is gone"))?;
    if previous.policy_digest != policy_digest || previous.policy_sequence != policy_sequence {
        return Err(unexpected(
            "a successor attempt names another policy than its predecessor",
        ));
    }
    Ok(())
}

/// What one exposed authorization still owes its native release row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationKind {
    /// Signed x402 entries strictly past their expiration ledger.
    X402Expired {
        /// The ledger after which the signatures expire.
        signature_expiration_ledger: u32,
    },
    /// A terminal classic attempt whose `max_time` the close-time floor has
    /// strictly passed.
    TerminalTimed {
        /// The release bound: the attempt's `max_time` in milliseconds.
        release_after_ms: u64,
    },
    /// A terminal untimed classic attempt; its release needs the operator's
    /// acknowledged clear.
    TerminalUntimed,
}

/// An exposed authorization of a retained record without a release row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseObligation {
    /// The owning operation.
    pub operation_id: OperationId,
    /// The exposed attempt.
    pub attempt_index: u32,
    /// What the obligation needs.
    pub kind: ObligationKind,
}

/// The obligation of `attempt` in `record` at `observation`, when the
/// attempt is exposed, its authorization has no release row, and no checked
/// decision owns its release. An x402 obligation is due only strictly past
/// its expiration ledger, a timed classic one only on a terminal record
/// whose close-time floor is strictly past `max_time`.
fn obligation_of(
    wire: &WireFile,
    record: &WireOperation,
    attempt: &WireAttempt,
    observation: Option<&WindowObservation>,
) -> Option<ReleaseObligation> {
    let exposure = attempt.exposure.as_ref()?;
    let unreleased = wire
        .authorizations
        .iter()
        .any(|auth| auth.id == attempt.authorization_id && auth.native_release.is_none());
    if !unreleased || attempt.decision.is_some() {
        return None;
    }
    let kind = match exposure.identity {
        ExposureIdentity::X402 {
            signature_expiration_ledger,
            ..
        } => {
            let ledger = observation?.ledger;
            (ledger > signature_expiration_ledger).then_some(ObligationKind::X402Expired {
                signature_expiration_ledger,
            })?
        }
        ExposureIdentity::Classic { max_time, .. } if record.state.is_terminal() => {
            if max_time == 0 {
                ObligationKind::TerminalUntimed
            } else {
                let release_after_ms = max_time.checked_mul(1000)?;
                (observation?.close_time_floor_ms > release_after_ms)
                    .then_some(ObligationKind::TerminalTimed { release_after_ms })?
            }
        }
        ExposureIdentity::Classic { .. } => return None,
    };
    Some(ReleaseObligation {
        operation_id: record.id,
        attempt_index: attempt.index,
        kind,
    })
}

/// The account a classic attempt's authorization binds: the transaction
/// binding's source, never a receipt's.
fn attempt_account(wire: &WireFile, attempt: &WireAttempt) -> Option<String> {
    wire.authorizations
        .iter()
        .find(|auth| auth.id == attempt.authorization_id)
        .and_then(|auth| match &auth.binding {
            DomainBinding::Transaction { source, .. } => Some(source.clone()),
            _ => None,
        })
}

/// What a consumption commit exposes beside the consumption: one attempt's
/// signed identity, and the writer its row is appended to.
pub struct ConsumptionExposure<'a> {
    /// The operation the consumed authorization serves.
    pub operation_id: OperationId,
    /// The attempt the consumed authorization serves.
    pub attempt_index: u32,
    /// The signed identity the attempt is about to send.
    pub identity: ExposureIdentity,
    /// The independently observed lower bound before exposure.
    pub pre_exposure_ledger: Option<u32>,
    /// The writer the exposure row is appended to, before the window write.
    pub audit: &'a mut dyn OperationAudit,
    /// The caller's request identifier on the exposure row.
    pub request_id: &'a str,
}

impl std::fmt::Debug for ConsumptionExposure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumptionExposure")
            .field("operation_id", &self.operation_id)
            .field("attempt_index", &self.attempt_index)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

/// Commits `exposure` into `wire`, the successor of `original` that one
/// consumption commit writes after its own sweep, and returns the rows to
/// append before that commit. The exposure checks are those of
/// [`OperationRecorder::expose`]: the attempt is open and unexposed in
/// `Sending`, and its authorization is claimed or used.
pub(super) fn expose_in_consumption(
    wire: &mut WireFile,
    profile: &Profile,
    original: &WireFile,
    now_ms: u64,
    exposure: &ConsumptionExposure<'_>,
) -> Result<Vec<AuditEntry>, WindowStoreError> {
    let mut session = Session {
        profile,
        now: now_ms,
        original,
        wire: std::mem::take(wire),
        mint_expires: None,
        audit: AuditBatch {
            request_id: exposure.request_id,
            chain_id: profile.chain_id.caip2_str(),
            commit: CommitId::random(),
            entries: Vec::new(),
        },
        changed: false,
    };
    let exposed = session.expose_swept(
        exposure.operation_id,
        exposure.attempt_index,
        &exposure.identity,
        exposure.pre_exposure_ledger,
    );
    *wire = session.wire;
    exposed?;
    Ok(session.audit.entries)
}

/// Stores `observation` unless the window holds one of a later ledger.
/// Returns whether the stored observation changed.
fn store_observation(wire: &mut WireFile, observation: WindowObservation) -> bool {
    let newer = wire
        .last_observation
        .is_none_or(|stored| observation.ledger >= stored.ledger && observation != stored);
    if newer {
        wire.last_observation = Some(observation);
    }
    newer
}

impl<'a> OperationRecorder<'a> {
    /// A recorder for `profile`'s window in `store`. `request_id` names the
    /// caller's request on every audit row.
    #[must_use]
    pub fn new(
        store: &'a PersistedWindowStore,
        profile: &'a Profile,
        audit: &'a mut dyn OperationAudit,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            store,
            profile,
            audit,
            request_id: request_id.into(),
        }
    }

    /// Runs one locked step and commits it when it changed the window. A
    /// mint's checks that precede the window key run under the lock before
    /// the read.
    pub(super) fn run<T>(
        &mut self,
        mint: Option<&MintRequest>,
        step: impl FnOnce(&mut Session<'_>) -> Result<T, WindowStoreError>,
    ) -> Result<T, WindowStoreError> {
        let store = self.store;
        let profile = self.profile;
        if !profile.chain_id.is_mainnet() {
            return Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::ChainNotMainnet,
            });
        }
        store.ensure_parent_dir()?;
        let lock = WindowStoreLock::acquire_for_with_retry(
            store.path(),
            &profile.policy_window_state_key_id,
        )?;
        let now = now_ms()?;
        let mint_expires = match mint {
            Some(request) => Some(store.mint_prechecks(&lock, profile, request, now)?),
            None => None,
        };
        let (key, _minted) = store.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let original = store.read_verified(profile, &key, &gen_entry)?;
        let (value, next, entries) = {
            let mut session = Session {
                profile,
                now,
                original: &original,
                wire: original.clone(),
                mint_expires,
                audit: AuditBatch {
                    request_id: &self.request_id,
                    chain_id: profile.chain_id.caip2_str(),
                    commit: CommitId::random(),
                    entries: Vec::new(),
                },
                changed: false,
            };
            let value = step(&mut session)?;
            let next = session.changed.then_some(session.wire);
            (value, next, session.audit.entries)
        };
        if let Some(mut next) = next {
            for entry in entries {
                self.audit
                    .append(entry)
                    .map_err(|detail| WindowStoreError::AuditAppendFailed { detail })?;
            }
            prune_stale(&mut next, now);
            store.commit_generation(&key, &gen_entry, original, next)?;
        }
        drop(lock);
        Ok(value)
    }

    /// Opens or looks up the record `request.business_id` names.
    ///
    /// Under the lock it first sweeps expired authorizations, adopts every
    /// waiting record whose linked authorization is open, and applies the
    /// expiry edges; then it compares the stored slot kind and intent
    /// digest. An unknown id records a `Prepared` record whose waiting
    /// window is the rule lifetime, at most the envelope's `max_time`.
    ///
    /// # Errors
    ///
    /// - `operation.capacity` for a new record: detail `envelope_size`,
    ///   `intent_size`, `waiting_operations`, `file_size` or `record_size`.
    /// - `audit.append_failed` when an audit row cannot be appended; nothing
    ///   is committed.
    /// - Every integrity, keyring, lock and I/O error of the store.
    pub fn open(&mut self, request: &OpenRequest) -> Result<OpenOutcome, WindowStoreError> {
        self.run(None, |session| session.open(request))
    }

    /// Looks up the record or tombstone `business_id` names without opening
    /// one.
    ///
    /// Under the lock it runs the sweep, the adoption and the expiry edges
    /// [`Self::open`] runs. The state it reports is thus the state an open or
    /// an attempt would act on. It compares no intent: the caller compares
    /// [`LookupOutcome::binding`] with its own. `None` for an unknown id.
    ///
    /// # Errors
    ///
    /// - `audit.append_failed` when an adoption or expiry row cannot be
    ///   appended; nothing is committed.
    /// - Every integrity, keyring, lock and I/O error of the store.
    pub fn lookup(
        &mut self,
        business_id: &BusinessId,
    ) -> Result<Option<LookupOutcome>, WindowStoreError> {
        self.run(None, |session| {
            session.settle()?;
            Ok(session.retained(business_id).map(|(_, _, found)| found))
        })
    }

    /// Opens the next attempt of `handle`'s operation and commits it with
    /// `Sending` in one lock acquisition.
    ///
    /// The envelope's size is checked first, before any read or write. After
    /// the sweep and adoption, a waiting record past its waiting expiry and a
    /// record past its execution expiry refuse. Then an `Envelope` record
    /// refuses another envelope, an open attempt and a ninth attempt refuse,
    /// and the edge must exist. A mint retires the
    /// operation's open authorizations and mints in the same commit; a
    /// successor needs its predecessor's checked non-inclusion with its
    /// projection marker and an unchanged policy, and is exempt from the
    /// open-authorization cap.
    ///
    /// # Errors
    ///
    /// - `operation.capacity` with detail `envelope_size`.
    /// - `network.mainnet_authorization_refused` with precondition `expired`
    ///   for a waiting record past its waiting expiry or a record past its
    ///   execution expiry.
    /// - `operation.business_id_conflict` for another envelope under an
    ///   `Envelope` record.
    /// - `operation.attempt_open` and `operation.attempt_limit`.
    /// - `recovery.retry_refused` for a successor whose predecessor's checked
    ///   non-inclusion has no projection marker.
    /// - `internal.unexpected_state` for an edge outside the table or an
    ///   exposed authorization a remint would retire.
    /// - The mint's refusals and every store error. Nothing is written on a
    ///   refusal.
    pub fn begin_attempt(
        &mut self,
        handle: &OperationHandle,
        request: &AttemptRequest,
    ) -> Result<AttemptStarted, WindowStoreError> {
        if request
            .envelope
            .as_ref()
            .is_some_and(|envelope| envelope.xdr.len() > ENVELOPE_XDR_MAX)
        {
            return Err(capacity(CapacityDetail::EnvelopeSize));
        }
        let mint = match &request.authorization {
            AttemptAuthorization::Mint(mint) => Some(mint.as_ref()),
            AttemptAuthorization::Linked => None,
        };
        let request_id = self.request_id.clone();
        self.run(mint, |session| {
            session.begin(handle.id, request, &request_id)
        })
    }

    /// Commits the exposure of attempt `attempt_index` before its signed
    /// payload is transmitted.
    ///
    /// # Errors
    ///
    /// `internal.unexpected_state` unless the operation is `Sending` with
    /// that attempt open and unexposed and its authorization claimed or used,
    /// `audit.append_failed`, and every store error.
    pub fn expose(
        &mut self,
        operation_id: OperationId,
        attempt_index: u32,
        identity: &ExposureIdentity,
        pre_exposure_ledger: Option<u32>,
    ) -> Result<CommitId, WindowStoreError> {
        self.run(None, |session| {
            session.expose(operation_id, attempt_index, identity, pre_exposure_ledger)
        })
    }

    /// Moves an operation along one edge of the state table and commits the
    /// attempt's outcome, its evidence and the release rows of an unexposed
    /// end. `Sending` reaches `SentOutcomeUnknown` and `PayloadReleased` only
    /// with the attempt's committed exposure. `Cancelled` takes the
    /// operator's [`ClearForm`] in `evidence.clear` and writes the last
    /// exposed attempt's `unknown` release row in the same commit. A repeated
    /// transition to the current state of the same attempt returns the
    /// record's last commit and writes nothing. A non-inclusion or an agreed
    /// outcome commits only through [`Self::commit_decision`].
    ///
    /// # Errors
    ///
    /// `internal.unexpected_state` for an edge outside the table or owned by
    /// another step, a stale attempt index, a non-inclusion or agreed
    /// outcome, an exposure edge without a committed exposure, or a
    /// cancellation without the clear form its exposure needs;
    /// `audit.append_failed`; and every store error.
    pub fn transition(
        &mut self,
        operation_id: OperationId,
        attempt_index: Option<u32>,
        to: OperationState,
        evidence: &TransitionEvidence,
    ) -> Result<CommitId, WindowStoreError> {
        self.run(None, |session| {
            session.transition(operation_id, attempt_index, to, evidence)
        })
    }

    /// Commits new evidence rows, the first sequence release and the
    /// attempt's recovery state without changing the operation's state.
    ///
    /// New rows take contiguous sequence numbers from the record's committed
    /// sequence plus one. A commit that adds rows or first records a release
    /// appends one audit row and returns its commit identifier; a commit of
    /// mutable state alone appends none and returns `None`.
    ///
    /// # Errors
    ///
    /// `internal.unexpected_state` for an unknown attempt; a stale snapshot refuses before writing;
    /// `audit.append_failed`, and every store error.
    pub fn record_evidence(
        &mut self,
        operation_id: OperationId,
        attempt_index: u32,
        input: &EvidenceInput,
    ) -> Result<Option<CommitId>, WindowStoreError> {
        self.run(None, |session| {
            session.record_evidence(operation_id, attempt_index, input)
        })
    }

    /// Commits a checked recovery decision in one generation. The commit
    /// holds the state, the agreed outcome or non-inclusion proof, the
    /// disagreement reset, the bucket disposition and the native release
    /// row. One transition audit row names the evidence digest and both
    /// deciding ledgers.
    ///
    /// Success keeps its debit; a failure keeps its counts and debits the
    /// charged fee; a non-inclusion releases every hold under an `Always`
    /// row of class `proved_unspent`. A still-claimed authorization keeps
    /// its holds and its state. The ledger admits no invalidation of a
    /// claimed record, and the authorization's own lifetime bounds those
    /// holds. A decision the attempt already holds returns its first commit
    /// and writes nothing.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Invalid`] for a stale snapshot generation,
    /// another attempt or envelope, a non-inclusion without a committed
    /// sequence release, or an attempt that left recovery. Its submission
    /// code is `submission.record_unavailable`. `internal.unexpected_state`
    /// for an edge outside the table; `audit.append_failed`; and every store
    /// error. Nothing is written on a refusal.
    pub fn commit_decision(
        &mut self,
        decision: &CheckedRecoveryDecision,
    ) -> Result<CommitId, WindowStoreError> {
        self.run(None, |session| session.commit_decision(decision))
    }

    /// Commits the release row of one obligation in one generation, after
    /// rechecking it against the verified window at `observation`.
    ///
    /// x402 entries strictly past their expiration ledger get an `unknown`
    /// row bound at that ledger. A live x402 record also becomes `Expired`
    /// with its transition audit row. A terminal timed classic attempt
    /// needs a close-time floor strictly past its `max_time` and gets a row
    /// bound at `max_time` in milliseconds. A terminal untimed one needs
    /// `acknowledged_clear` and gets an `Always` row. Terminal states stay.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Invalid`] when the window holds no such
    /// obligation or its proof does not hold; `internal.unexpected_state`
    /// for an edge outside the table; `audit.append_failed`; and every store
    /// error. Nothing is written on a refusal.
    pub fn release_obligation(
        &mut self,
        operation_id: OperationId,
        attempt_index: u32,
        observation: WindowObservation,
        acknowledged_clear: bool,
    ) -> Result<CommitId, WindowStoreError> {
        self.run(None, |session| {
            session.release_obligation(operation_id, attempt_index, observation, acknowledged_clear)
        })
    }

    /// Writes the projection marker of the decision committed under
    /// `commit_id` on attempt `attempt_index`, after the caller wrote its
    /// receipt. A marker already written is kept. Appends no audit row.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Invalid`] unless the attempt holds a decision
    /// committed under `commit_id`, and every store error.
    pub fn acknowledge_projection(
        &mut self,
        operation_id: OperationId,
        attempt_index: u32,
        commit_id: CommitId,
    ) -> Result<(), WindowStoreError> {
        self.run(None, |session| {
            let index = record_index(&session.wire, operation_id)?;
            let record = &mut section_mut(&mut session.wire).records[index];
            let decision = record
                .attempt_mut(attempt_index)?
                .decision
                .as_mut()
                .filter(|decision| decision.commit_id == commit_id)
                .ok_or_else(|| invalid("the projection names no committed recovery decision"))?;
            if !decision.projected {
                decision.projected = true;
                session.changed = true;
            }
            Ok(())
        })
    }

    /// Stores the window's chain observation alone, unless a later ledger
    /// is stored. Appends no audit row.
    ///
    /// # Errors
    ///
    /// Every store error.
    pub fn record_observation(
        &mut self,
        observation: WindowObservation,
    ) -> Result<(), WindowStoreError> {
        self.run(None, |session| {
            session.changed |= store_observation(&mut session.wire, observation);
            Ok(())
        })
    }

    /// Links a waiting operation to its durable approval record.
    ///
    /// # Errors
    ///
    /// `internal.unexpected_state` unless the operation waits and links no
    /// other record, and every store error.
    pub fn link_approval(
        &mut self,
        operation_id: OperationId,
        approval_record_id: [u8; 32],
    ) -> Result<(), WindowStoreError> {
        self.run(None, |session| {
            let index = record_index(&session.wire, operation_id)?;
            let record = &mut section_mut(&mut session.wire).records[index];
            if !record.state.is_waiting() {
                return Err(unexpected("only a waiting operation links its approval"));
            }
            match record.approval_record_id {
                Some(linked) if linked == approval_record_id => Ok(()),
                Some(_) => Err(unexpected("the operation already links another approval")),
                None => {
                    record.approval_record_id = Some(approval_record_id);
                    record.updated_at_ms = session.now;
                    session.changed = true;
                    Ok(())
                }
            }
        })
    }

    /// Applies the expiry edges at the earlier of `now_ms` and the store
    /// clock, after the sweep and adoption, and releases the unused
    /// authorizations of ended operations. A `Sending` attempt without a
    /// committed exposure becomes `NotSent` once its authorization ended
    /// unused and was never claimed. Returns how many records ended.
    ///
    /// # Errors
    ///
    /// `audit.append_failed` and every store error.
    pub fn expire_due(&mut self, now_ms: u64) -> Result<usize, WindowStoreError> {
        self.run(None, |session| {
            session.sweep_and_adopt()?;
            session.expire(now_ms.min(session.now))
        })
    }

    /// Compacts the window at the store clock and stores `slot_kind` on the
    /// tombstone `business_id` names, keeping its intent digest. Returns
    /// whether such a tombstone exists.
    ///
    /// Test fixtures only: a compaction takes the slot kind from the record,
    /// so no production step stores a tombstone whose slot kind and digest
    /// come from different intents.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring, lock and I/O error of the store.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn set_tombstone_slot_kind_for_test(
        &mut self,
        business_id: &BusinessId,
        slot_kind: SlotKind,
    ) -> Result<bool, WindowStoreError> {
        self.run(None, |session| {
            prune_stale(&mut session.wire, session.now);
            let Some(tombstone) = session.wire.operations.as_mut().and_then(|section| {
                section
                    .tombstones
                    .iter_mut()
                    .find(|tombstone| &tombstone.business_id == business_id)
            }) else {
                return Ok(false);
            };
            tombstone.slot_kind = slot_kind;
            session.changed = true;
            Ok(true)
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Status reads and evidence classification
// ─────────────────────────────────────────────────────────────────────────────

/// Reads a profile's operation records without reconciliation or writes.
#[derive(Debug, Clone, Copy)]
pub struct OperationStatus<'a> {
    store: &'a PersistedWindowStore,
    profile: &'a Profile,
}

/// A committed recovery decision, read from the verified window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedDecision {
    /// The owning operation.
    pub operation_id: OperationId,
    /// The decided attempt.
    pub attempt_index: u32,
    /// The decided state: `Succeeded`, `Failed` or `NotIncluded`.
    pub state: OperationState,
    /// The decision's commit identifier.
    pub commit_id: CommitId,
    /// The digest of the ordered endpoint answers that decided it.
    pub evidence_digest: [u8; 32],
    /// The primary and oracle deciding ledgers.
    pub ledgers: (u32, u32),
    /// The exposed signed envelope's hash.
    pub envelope_sha256: [u8; 32],
    /// The exposed network transaction hash.
    pub tx_hash: [u8; 32],
    /// The agreed including ledger of a success or failure.
    pub ledger: Option<u32>,
    /// The fee a failure charged, in stroops.
    pub fee_charged: Option<i64>,
    /// The non-inclusion proof.
    pub not_included: Option<NotIncludedProof>,
    /// Whether the caller acknowledged the decision's receipt projection.
    pub projected: bool,
}

/// An authenticated classic attempt eligible for recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAttempt {
    /// The owning operation.
    pub operation_id: OperationId,
    /// The exposed attempt's index.
    pub attempt_index: u32,
    /// The signed identity committed before transmission.
    pub exposure: ExposureIdentity,
    /// The attempt's opening time in Unix milliseconds.
    pub started_at_ms: u64,
    /// The exclusive send deadline in Unix milliseconds.
    pub send_by_ms: u64,
    /// The independent lower bound observed before exposure.
    pub pre_exposure_ledger: Option<u32>,
    /// Both cursors, upper bounds and mutable recovery facts.
    pub recovery: RecoveryUpdate,
    /// Whether the immutable sequence release exists; a commit refuses when it changes.
    pub sequence_released: bool,
    /// Whether the attempt's authorization names a window reservation.
    pub reservation_present: bool,
    /// The generation of the verified snapshot that holds the attempt.
    pub generation: u64,
    /// The account whose sequence the attempt consumes, from its
    /// authenticated authorization's transaction binding.
    pub account: Option<String>,
    /// The committed facts of the attempt's first sequence release.
    pub sequence_release: Option<SequenceReleaseInput>,
}

impl<'a> OperationStatus<'a> {
    /// A status reader for `profile`'s window in `store`.
    #[must_use]
    pub fn new(store: &'a PersistedWindowStore, profile: &'a Profile) -> Self {
        Self { store, profile }
    }

    /// The verified window, pruned in memory on the store clock.
    fn read(&self) -> Result<Option<WireFile>, WindowStoreError> {
        let Some(mut wire) = self.store.read_for_inspection(self.profile)? else {
            return Ok(None);
        };
        prune_stale(&mut wire, now_ms()?);
        Ok(Some(wire))
    }

    /// Reads the four oldest exposed classic attempts with unknown outcomes
    /// and no sequence release. A transaction hash selects only its matching attempt.
    ///
    /// # Errors
    /// Returns every integrity, keyring and I/O error of the verified window read.
    pub fn recovery_snapshot(
        &self,
        tx_hash: Option<&[u8; 32]>,
    ) -> Result<Vec<RecoveryAttempt>, WindowStoreError> {
        self.unknown_attempts(tx_hash, false)
    }

    /// Reads the four oldest exposed classic attempts with unknown
    /// outcomes for the outcome stage, attempts with a recorded sequence
    /// release included. A transaction hash selects only its matching
    /// attempt, released or not.
    ///
    /// # Errors
    /// Returns every integrity, keyring and I/O error of the verified window read.
    pub fn outcome_snapshot(
        &self,
        tx_hash: Option<&[u8; 32]>,
    ) -> Result<Vec<RecoveryAttempt>, WindowStoreError> {
        self.unknown_attempts(tx_hash, true)
    }

    fn unknown_attempts(
        &self,
        tx_hash: Option<&[u8; 32]>,
        released: bool,
    ) -> Result<Vec<RecoveryAttempt>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(Vec::new());
        };
        let mut attempts = Vec::new();
        for record in records(&wire) {
            if record.state != OperationState::SentOutcomeUnknown || record.kind.is_x402() {
                continue;
            }
            for attempt in &record.attempts {
                let Some(exposure) = &attempt.exposure else {
                    continue;
                };
                let ExposureIdentity::Classic {
                    tx_hash: stored_hash,
                    ..
                } = &exposure.identity
                else {
                    continue;
                };
                // A released attempt never takes a sequence slot again; the
                // outcome stage still selects it.
                if attempt.outcome != Some(OperationState::SentOutcomeUnknown)
                    || (attempt.sequence_released.is_some() && !released)
                    || tx_hash.is_some_and(|hash| hash != stored_hash)
                {
                    continue;
                }
                let recovery = attempt.recovery.clone().unwrap_or_default();
                attempts.push(RecoveryAttempt {
                    operation_id: record.id,
                    attempt_index: attempt.index,
                    exposure: exposure.identity.clone(),
                    started_at_ms: attempt.started_at_ms,
                    send_by_ms: attempt.send_by_ms,
                    pre_exposure_ledger: attempt.pre_exposure_ledger,
                    recovery: recovery.snapshot(),
                    sequence_released: attempt.sequence_released.is_some(),
                    reservation_present: wire.authorizations.iter().any(|auth| {
                        auth.id == attempt.authorization_id && auth.reservation.is_some()
                    }),
                    generation: wire.generation,
                    account: attempt_account(&wire, attempt),
                    sequence_release: attempt.sequence_released.as_ref().map(|released| {
                        SequenceReleaseInput {
                            primary_ledger: released.primary_ledger,
                            witness_ledger: released.witness_ledger,
                            min_close_time_ms: released.min_close_time_ms,
                        }
                    }),
                });
            }
        }
        attempts.sort_by_key(|attempt| {
            (
                attempt.started_at_ms,
                attempt.operation_id.to_hex(),
                attempt.attempt_index,
            )
        });
        attempts.truncate(if tx_hash.is_some() { 1 } else { 4 });
        Ok(attempts)
    }

    /// Every committed recovery decision of a retained record: terminal
    /// outcomes and `NotIncluded`, read after the attempt left recovery
    /// selection. A transaction hash selects only its attempt's decision.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the verified window read.
    pub fn committed_decisions(
        &self,
        tx_hash: Option<&[u8; 32]>,
    ) -> Result<Vec<CommittedDecision>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(Vec::new());
        };
        let mut decisions = Vec::new();
        for record in records(&wire) {
            for attempt in &record.attempts {
                let (Some(decision), Some(state)) = (&attempt.decision, attempt.outcome) else {
                    continue;
                };
                let Some(ExposureIdentity::Classic {
                    envelope_sha256,
                    tx_hash: stored_hash,
                    ..
                }) = attempt.exposure.as_ref().map(|exposure| &exposure.identity)
                else {
                    continue;
                };
                if tx_hash.is_some_and(|hash| hash != stored_hash) {
                    continue;
                }
                decisions.push(CommittedDecision {
                    operation_id: record.id,
                    attempt_index: attempt.index,
                    state,
                    commit_id: decision.commit_id,
                    evidence_digest: decision.evidence_digest,
                    ledgers: (decision.primary_ledger, decision.witness_ledger),
                    envelope_sha256: *envelope_sha256,
                    tx_hash: *stored_hash,
                    ledger: attempt
                        .agreed_outcome
                        .as_ref()
                        .map(|outcome| outcome.ledger),
                    fee_charged: decision.fee_charged,
                    not_included: attempt.not_included,
                    projected: decision.projected,
                });
            }
        }
        Ok(decisions)
    }

    /// Every release obligation the verified window holds at `observation`,
    /// or at the stored observation when `None` is passed. Obligations are
    /// x402 entries strictly past their expiration ledger and terminal
    /// classic attempts whose exposed authorization has no release row.
    /// Obligations take no classic recovery slot.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the verified window read.
    pub fn release_obligations(
        &self,
        observation: Option<WindowObservation>,
    ) -> Result<Vec<ReleaseObligation>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(Vec::new());
        };
        let observation = observation.or(wire.last_observation);
        Ok(records(&wire)
            .iter()
            .flat_map(|record| {
                record
                    .attempts
                    .iter()
                    .filter_map(|attempt| {
                        obligation_of(&wire, record, attempt, observation.as_ref())
                    })
                    .collect::<Vec<_>>()
            })
            .collect())
    }

    /// The record or tombstone `business_id` names.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn view(
        &self,
        business_id: &BusinessId,
    ) -> Result<Option<OperationView>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(None);
        };
        Ok(records(&wire)
            .iter()
            .find(|record| &record.business_id == business_id)
            .map(OperationView::of_record)
            .or_else(|| {
                tombstones(&wire)
                    .iter()
                    .find(|tombstone| &tombstone.business_id == business_id)
                    .map(OperationView::of_tombstone)
            }))
    }

    /// The facts a classic commit of the unsigned envelope with digest
    /// `unsigned_envelope_sha256` under `business_id` compares, from one read
    /// of the window, so the target and the envelope's owners agree.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn commit_binding(
        &self,
        business_id: &BusinessId,
        unsigned_envelope_sha256: &[u8; 32],
    ) -> Result<CommitBinding, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(CommitBinding::default());
        };
        let records = records(&wire);
        let owners = records
            .iter()
            .filter(|record| bound_envelope(record) == Some(*unsigned_envelope_sha256))
            .map(OperationView::of_record)
            .collect();
        let target = match records
            .iter()
            .find(|record| &record.business_id == business_id)
        {
            Some(record) => Some(CommitTarget::Record {
                view: OperationView::of_record(record),
                envelope_sha256: bound_envelope(record),
            }),
            None => tombstones(&wire)
                .iter()
                .find(|tombstone| &tombstone.business_id == business_id)
                .map(|tombstone| CommitTarget::Tombstone(OperationView::of_tombstone(tombstone))),
        };
        Ok(CommitBinding { target, owners })
    }

    /// Whether the attempt `attempt` names carries a committed sequence
    /// release. The attempt is the one whose committed classic exposure
    /// names that signed envelope hash; an x402 attempt and an attempt
    /// before its exposure name none.
    ///
    /// The read takes no lock: the caller holds the window guard across it,
    /// so no writer advances the file between the read and the caller's use
    /// of the answer.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn sequence_released_unlocked(
        &self,
        attempt: &AttemptRef,
    ) -> Result<bool, WindowStoreError> {
        let AttemptRef::EnvelopeHash(signed) = attempt;
        let Some(wire) = self.store.read_for_inspection(self.profile)? else {
            return Ok(false);
        };
        Ok(records(&wire)
            .iter()
            .flat_map(|record| record.attempts.iter())
            .filter(|stored| {
                matches!(
                    stored.exposure.as_ref().map(|exposure| &exposure.identity),
                    Some(ExposureIdentity::Classic { envelope_sha256, .. }) if envelope_sha256 == signed
                )
            })
            .any(|stored| stored.sequence_released.is_some()))
    }

    /// Every open record, and every record or tombstone closed at or after
    /// `ts_ms`.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn list_since(&self, ts_ms: u64) -> Result<Vec<OperationView>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(Vec::new());
        };
        let mut views: Vec<OperationView> = records(&wire)
            .iter()
            .filter(|record| record.closed_at_ms.is_none_or(|closed| closed >= ts_ms))
            .map(OperationView::of_record)
            .collect();
        views.extend(
            tombstones(&wire)
                .iter()
                .filter(|tombstone| tombstone.closed_at_ms >= ts_ms)
                .map(OperationView::of_tombstone),
        );
        Ok(views)
    }

    /// The native stroops the verified window still reserves at
    /// `observation`, the stored observation when `None` is passed. Each
    /// authorization counts once; see the release rules of its row.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the verified window read.
    pub fn native_reserved_stroops(
        &self,
        observation: Option<WindowObservation>,
    ) -> Result<i128, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(0);
        };
        let observation = observation.or(wire.last_observation);
        Ok(native_reserved(&wire, observation.as_ref()))
    }

    /// The window's admissible floors.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn admissible_floors(&self) -> Result<AdmissibleFloors, WindowStoreError> {
        Ok(self
            .store
            .read_for_inspection(self.profile)?
            .map(|wire| AdmissibleFloors {
                ledger: wire.admissible_floor_ledger,
                close_time_ms: wire.admissible_floor_close_time_ms,
            })
            .unwrap_or_default())
    }

    /// Classifies `rows`, the `operation_evidence` audit rows naming one
    /// operation, against the retained record at `now_ms`.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring and I/O error of the store's reads.
    pub fn classify_evidence(
        &self,
        operation_id: OperationId,
        rows: &[EvidenceAuditFacts],
        now_ms: u64,
    ) -> Result<EvidenceClassification, WindowStoreError> {
        let wire = self.read()?.unwrap_or_default();
        let record = records(&wire)
            .iter()
            .find(|record| record.id == operation_id);
        let compacted = tombstones(&wire)
            .iter()
            .any(|tombstone| tombstone.id == operation_id);
        Ok(classify(record, compacted, rows, now_ms))
    }
}

impl SequenceReleases for OperationStatus<'_> {
    fn sequence_released(&self, attempt: &AttemptRef) -> bool {
        self.sequence_released_unlocked(attempt)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    code = error.submission_code(),
                    "operation store: a sequence release could not be read; the sequence stays held"
                );
                false
            })
    }
}

/// The digest of the unsigned envelope `record`'s intent binds: an
/// `Envelope` slot's digest, or the digest of a `Canonical` record's stored
/// envelope text. `None` for x402.
fn bound_envelope(record: &WireOperation) -> Option<[u8; 32]> {
    match &record.intent {
        IntentSlot::Envelope {
            unsigned_envelope_sha256,
            ..
        } => Some(*unsigned_envelope_sha256),
        IntentSlot::Canonical { .. } => record
            .envelope_xdr
            .as_ref()
            .map(|xdr| Sha256::digest(xdr.as_bytes()).into()),
        IntentSlot::X402 { .. } => None,
    }
}

/// The facts of one `operation_evidence` audit row the verifier compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAuditFacts {
    /// The attempt the row names.
    pub attempt_index: u32,
    /// The row's `evidence_seqs` range, first and last.
    pub evidence_seqs: Option<(u64, u64)>,
    /// Whether the row is release-flagged.
    pub sequence_released: bool,
    /// The row's commit identifier.
    pub commit_id: CommitId,
    /// When the row was appended, in Unix milliseconds.
    pub appended_at_ms: u64,
}

/// The class of one evidence sequence number of an audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSequenceClass {
    /// The record retains the sequence under the row's commit.
    Committed,
    /// The record retains the sequence under another commit that another
    /// row names with a range containing it.
    Superseded,
    /// The record does not retain the sequence, which is at most its
    /// committed sequence; neither commit nor failure is claimed.
    Evicted,
    /// The sequence is above the record's committed sequence: a commit that
    /// failed after its append.
    Uncommitted,
    /// The sequence contradicts the record.
    Tampered,
}

/// The verdict on one `operation_evidence` audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceVerdict {
    /// The record is retained; each sequence and the release flag carry
    /// their class.
    Retained {
        /// Each sequence of the row's range with its class.
        sequences: Vec<(u64, EvidenceSequenceClass)>,
        /// The class of the row's release flag, when it is set.
        release: Option<EvidenceSequenceClass>,
    },
    /// The record was compacted to a tombstone; the row is accepted.
    Compacted,
    /// Neither record nor tombstone remains and the row is older than the
    /// tombstone retention.
    BeyondRetention,
    /// Neither record nor tombstone remains inside the tombstone retention.
    Orphan,
}

impl EvidenceVerdict {
    /// Whether any sequence or the release flag is tampered; the verifier
    /// accepts every other row.
    #[must_use]
    pub fn tampered(&self) -> bool {
        match self {
            Self::Retained { sequences, release } => {
                sequences
                    .iter()
                    .any(|(_, class)| *class == EvidenceSequenceClass::Tampered)
                    || *release == Some(EvidenceSequenceClass::Tampered)
            }
            Self::Compacted | Self::BeyondRetention | Self::Orphan => false,
        }
    }
}

/// The verdicts on a record's audit rows, and the retained facts no row
/// names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceClassification {
    /// One verdict per audit row, in input order.
    pub verdicts: Vec<EvidenceVerdict>,
    /// Retained `(attempt, sequence)` rows no audit row names with their
    /// commit and a containing range; each is tampered.
    pub unnamed_rows: Vec<(u32, u64)>,
    /// Attempts whose sequence release no release-flagged row of the attempt
    /// names; each is tampered.
    pub unnamed_releases: Vec<u32>,
}

fn row_contains(row: &EvidenceAuditFacts, commit: CommitId, seq: u64) -> bool {
    row.commit_id == commit
        && row
            .evidence_seqs
            .is_some_and(|(first, last)| first <= seq && seq <= last)
}

/// Classifies `rows` against `record` under the verifier table.
fn classify(
    record: Option<&WireOperation>,
    compacted: bool,
    rows: &[EvidenceAuditFacts],
    now_ms: u64,
) -> EvidenceClassification {
    use EvidenceSequenceClass as C;
    let Some(record) = record else {
        let verdict = |row: &EvidenceAuditFacts| {
            if compacted {
                EvidenceVerdict::Compacted
            } else if now_ms.saturating_sub(row.appended_at_ms) > TOMBSTONE_RETENTION_MS {
                EvidenceVerdict::BeyondRetention
            } else {
                EvidenceVerdict::Orphan
            }
        };
        return EvidenceClassification {
            verdicts: rows.iter().map(verdict).collect(),
            ..EvidenceClassification::default()
        };
    };
    let committed = record.evidence_committed_seq;
    let retained = |seq: u64| {
        record.attempts.iter().find_map(|attempt| {
            attempt
                .evidence
                .iter()
                .find(|row| row.evidence_seq == seq)
                .map(|row| (attempt.index, row.commit_id))
        })
    };
    let mut verdicts = Vec::with_capacity(rows.len());
    for row in rows {
        let attempt = record
            .attempts
            .iter()
            .find(|attempt| attempt.index == row.attempt_index);
        let mut sequences = Vec::new();
        if let Some((first, last)) = row.evidence_seqs {
            let span_ok = first <= last
                && last - first < u64::try_from(MAX_EVIDENCE_ROWS).unwrap_or(u64::MAX)
                && first <= committed.saturating_add(1);
            if !span_ok || attempt.is_none() {
                sequences.push((first, C::Tampered));
            } else {
                for seq in first..=last {
                    let class = match retained(seq) {
                        Some((index, _)) if index != row.attempt_index => C::Tampered,
                        Some((_, commit)) if commit == row.commit_id => C::Committed,
                        Some((_, commit)) => {
                            if rows.iter().any(|other| row_contains(other, commit, seq)) {
                                C::Superseded
                            } else {
                                C::Tampered
                            }
                        }
                        None if seq <= committed => C::Evicted,
                        None => C::Uncommitted,
                    };
                    sequences.push((seq, class));
                }
            }
        }
        let release = row.sequence_released.then(|| {
            match attempt.and_then(|attempt| attempt.sequence_released.as_ref()) {
                Some(released) if released.commit_id == row.commit_id => C::Committed,
                Some(_) | None if attempt.is_some() => C::Uncommitted,
                _ => C::Tampered,
            }
        });
        verdicts.push(EvidenceVerdict::Retained { sequences, release });
    }
    let mut unnamed_rows = Vec::new();
    let mut unnamed_releases = Vec::new();
    for attempt in &record.attempts {
        for evidence in &attempt.evidence {
            if !rows.iter().any(|row| {
                row.attempt_index == attempt.index
                    && row_contains(row, evidence.commit_id, evidence.evidence_seq)
            }) {
                unnamed_rows.push((attempt.index, evidence.evidence_seq));
            }
        }
        if let Some(released) = &attempt.sequence_released
            && !rows.iter().any(|row| {
                row.attempt_index == attempt.index
                    && row.sequence_released
                    && row.commit_id == released.commit_id
            })
        {
            unnamed_releases.push(attempt.index);
        }
    }
    EvidenceClassification {
        verdicts,
        unnamed_rows,
        unnamed_releases,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::cell::Cell;
    use std::fs;

    use serial_test::serial;
    use stellar_agent_core::audit_log::schema::{EventKind, EvidenceSeqRange};
    use stellar_agent_core::mainnet::decision::AuthorityScope;
    use stellar_agent_core::policy::pin::{self, Pin, PinScope};
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    use super::super::reset_test::{owner_of, signed_by};
    use super::*;
    use crate::mainnet::clock::{TestClockGuard, set_now_ms_for_test};
    use crate::mainnet::digest::BindingFacts;
    use crate::mainnet::types::{AuthorizationDomain, MainnetConsumer};
    use crate::policy_state::ChainScope;
    use crate::policy_state::ledger::{ClaimExpect, DomainBinding, PolicyAuthorityBinding};
    use crate::policy_state::store::{RETENTION_MS, ResetConsent, ResetError};

    const T0: u64 = 1_800_000_000_000;
    const CAP: i128 = 1_000;
    const APPROVAL_MS: u64 = 600_000;
    const TTL_MS: u64 = 120_000;
    const SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM";
    const REQUEST_ID: &str = "6f9619ff-8b86-4d11-b42d-00c04fc964ff";

    /// An audit sink that keeps its rows, or refuses every append.
    #[derive(Default)]
    pub(crate) struct Sink {
        pub(crate) entries: Vec<AuditEntry>,
        pub(crate) fail: bool,
    }

    impl OperationAudit for Sink {
        fn append(&mut self, entry: AuditEntry) -> Result<(), String> {
            if self.fail {
                return Err("the audit log refused the row".to_owned());
            }
            self.entries.push(entry);
            Ok(())
        }
    }

    pub(crate) struct Fx {
        _dir: TempDir,
        pub(crate) profile: Profile,
        pub(crate) store: PersistedWindowStore,
        pub(crate) clock: TestClockGuard,
        pub(crate) sink: Sink,
        nonces: Cell<u32>,
    }

    impl Fx {
        /// A mainnet profile whose policy pin names sequence 7, digest `[7; 32]`.
        pub(crate) fn new() -> Self {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let mut profile = Profile::builder_mainnet_named(
                "ops",
                "https://rpc.example",
                "stellar-agent-signer-ops",
                "acct",
                "n-svc",
                "n-acct",
            )
            .build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            let store = PersistedWindowStore::at_path(dir.path().join("ops.window"));
            let fx = Self {
                _dir: dir,
                profile,
                store,
                clock: set_now_ms_for_test(T0),
                sink: Sink::default(),
                nonces: Cell::new(0),
            };
            let lock = WindowStoreLock::acquire_for(
                fx.store.path(),
                &fx.profile.policy_window_state_key_id,
            )
            .unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(fx.store.path(), &fx.profile),
                &Pin::new(7, [7; 32], owner_of(11)).unwrap(),
            )
            .unwrap();
            fx
        }

        pub(crate) fn recorder(&mut self) -> OperationRecorder<'_> {
            OperationRecorder::new(&self.store, &self.profile, &mut self.sink, REQUEST_ID)
        }

        fn now(&self) -> u64 {
            crate::mainnet::clock::now_ms().unwrap()
        }

        pub(in crate::policy_state) fn wire(&self) -> WireFile {
            self.store
                .read_for_inspection(&self.profile)
                .unwrap()
                .unwrap()
        }

        fn generation(&self) -> u64 {
            self.store
                .read_for_inspection(&self.profile)
                .unwrap()
                .map_or(0, |wire| wire.generation)
        }

        pub(in crate::policy_state) fn record(&self, id: OperationId) -> WireOperation {
            records(&self.wire())
                .iter()
                .find(|record| record.id == id)
                .cloned()
                .unwrap()
        }

        fn auth(&self, id: AuthorizationId) -> WireAuthorization {
            self.wire()
                .authorizations
                .into_iter()
                .find(|auth| auth.id == id)
                .unwrap()
        }

        fn open(&mut self, request: &OpenRequest) -> Result<OpenOutcome, WindowStoreError> {
            self.recorder().open(request)
        }

        fn open_new(&mut self, request: &OpenRequest) -> OperationHandle {
            match self.open(request).unwrap() {
                OpenOutcome::New(handle) => handle,
                other => panic!("expected a new record, got {other:?}"),
            }
        }

        /// Rewrites the committed window through the generation commit,
        /// without pruning.
        pub(in crate::policy_state) fn rewrite(&self, change: impl FnOnce(&mut WireFile)) {
            let lock = WindowStoreLock::acquire_for(
                self.store.path(),
                &self.profile.policy_window_state_key_id,
            )
            .unwrap();
            let (key, _) = self.store.load_or_mint_key(&self.profile).unwrap();
            let gen_entry = generation_entry_ref(&self.profile);
            let original = self
                .store
                .read_verified(&self.profile, &key, &gen_entry)
                .unwrap();
            let mut next = original.clone();
            change(&mut next);
            self.store
                .commit_generation(&key, &gen_entry, original, next)
                .unwrap();
            drop(lock);
        }

        /// Runs a pruning writer at the current clock.
        fn prune_now(&self) {
            self.store.record_and_persist(&self.profile, &[]).unwrap();
        }

        fn approval(&self) -> MintAuthority {
            let n = self.nonces.get() + 1;
            self.nonces.set(n);
            MintAuthority::Approval {
                nonce: format!("nonce-{n}"),
                expires_at_ms: self.now() + APPROVAL_MS,
            }
        }

        fn policy(&self) -> MintAuthority {
            MintAuthority::Policy(PolicyAuthorityBinding {
                policy_digest: [7; 32],
                policy_sequence: 7,
                rule_index: 0,
                evaluated_at_ms: self.now(),
                governing_until_ms: self.now() + APPROVAL_MS,
                scope: AuthorityScope::Classic,
            })
        }

        fn mint_request(
            &self,
            binding: DomainBinding,
            authority: MintAuthority,
            holds: Vec<WindowEntry>,
        ) -> MintRequest {
            MintRequest {
                chain: Caip2::Mainnet,
                consumer: match binding.domain() {
                    AuthorizationDomain::Soroban => MainnetConsumer::X402Create,
                    _ => MainnetConsumer::CliPay,
                },
                binding,
                policy_sequence: 7,
                policy_digest: [7; 32],
                authority,
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

        fn claim(&self, request: &MintRequest, minted: &MintedRecord) {
            self.store
                .claim_authorization(
                    &self.profile,
                    minted.id,
                    &ClaimExpect {
                        domain: request.binding.domain(),
                        consumer: request.consumer,
                        bindings_digest: minted.bindings_digest,
                        policy_sequence: request.policy_sequence,
                        policy_digest: request.policy_digest,
                        authority: request.authority.clone(),
                    },
                )
                .unwrap();
        }

        /// Opens the next attempt of `handle` under a fresh mint of `binding`.
        fn begin_mint(
            &mut self,
            handle: &OperationHandle,
            request: &MintRequest,
        ) -> Result<AttemptStarted, WindowStoreError> {
            let envelope = (!handle.kind().is_x402()).then(|| AttemptEnvelope {
                xdr: "AAAAENVELOPE".to_owned(),
                unsigned_envelope_sha256: handle.unsigned_envelope_sha256().unwrap_or([0xee; 32]),
            });
            self.recorder().begin_attempt(
                handle,
                &AttemptRequest {
                    envelope,
                    authorization: AttemptAuthorization::Mint(Box::new(request.clone())),
                    send_by_ms: u64::MAX,
                },
            )
        }

        /// Runs one attempt of `handle` to `NotIncluded` under a policy
        /// mint of `tx(n)`: begin, claim, expose, unknown outcome and a
        /// checked, projected non-inclusion.
        fn not_included_attempt(&mut self, handle: &OperationHandle, n: u8) -> u32 {
            let request = self.mint_request(tx(n), self.policy(), vec![]);
            let started = self.begin_mint(handle, &request).unwrap();
            self.claim(&request, started.minted.as_ref().unwrap());
            let index = started.attempt_index;
            self.recorder()
                .expose(handle.id(), index, &classic_exposure(n), Some(10))
                .unwrap();
            self.recorder()
                .transition(
                    handle.id(),
                    Some(index),
                    OperationState::SentOutcomeUnknown,
                    &TransitionEvidence::default(),
                )
                .unwrap();
            self.checked_non_inclusion(handle, index, n);
            index
        }

        /// Records attempt `index`'s sequence release, commits a checked
        /// non-inclusion of its exposure `classic_exposure(n)`, and writes
        /// the decision's projection marker.
        fn checked_non_inclusion(&mut self, handle: &OperationHandle, index: u32, n: u8) {
            self.recorder()
                .record_evidence(
                    handle.id(),
                    index,
                    &EvidenceInput {
                        sequence_released: Some(SequenceReleaseInput {
                            primary_ledger: 300,
                            witness_ledger: 300,
                            min_close_time_ms: T0,
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
            let attempt = OperationStatus::new(&self.store, &self.profile)
                .outcome_snapshot(Some(&[n ^ 0x80; 32]))
                .unwrap()
                .pop()
                .unwrap();
            let commit = self
                .recorder()
                .commit_decision(&decide(&attempt, DecidedTransition::NotIncluded(proof())))
                .unwrap();
            self.recorder()
                .acknowledge_projection(handle.id(), index, commit)
                .unwrap();
        }
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

    fn hold(amount: i128) -> WindowEntry {
        WindowEntry::new(
            StateKey::new("ops", 1, "native", 86_400),
            T0,
            amount,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: CAP,
            },
        )
    }

    fn canonical(n: u8) -> IntentSlot {
        IntentSlot::Canonical {
            intent_digest: [n; 32],
            intent: serde_json::json!({ "op": "pay", "n": n }),
        }
    }

    fn envelope(unsigned: u8, digest: u8, max_time: u64) -> IntentSlot {
        IntentSlot::Envelope {
            unsigned_envelope_sha256: [unsigned; 32],
            intent_digest: [digest; 32],
            max_time,
        }
    }

    fn x402_intent(amount: &str) -> X402Intent {
        X402Intent {
            network: "stellar:pubnet".to_owned(),
            asset: "CAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBA".to_owned(),
            payer: SOURCE.to_owned(),
            pay_to: SOURCE.to_owned(),
            amount: amount.to_owned(),
        }
    }

    fn x402(digest: [u8; 32]) -> IntentSlot {
        IntentSlot::X402 {
            intent_digest: digest,
            intent: x402_intent("100"),
        }
    }

    fn request(business_id: &str, intent: IntentSlot) -> OpenRequest {
        let kind = match intent {
            IntentSlot::X402 { .. } => OperationKind::X402Payment,
            IntentSlot::Envelope { .. } | IntentSlot::Canonical { .. } => OperationKind::Pay,
        };
        OpenRequest {
            business_id: BusinessId::parse(business_id).unwrap(),
            tool: match kind {
                OperationKind::X402Payment => OperationTool::X402CreatePayment,
                _ => OperationTool::CliPay,
            },
            kind,
            envelope_xdr: (kind == OperationKind::Pay).then(|| "AAAASTORED".to_owned()),
            intent,
            prepared_decision: Some(serde_json::json!({ "decision": "allow" })),
            rule_ttl_ms: None,
        }
    }

    fn classic_exposure(n: u8) -> ExposureIdentity {
        ExposureIdentity::Classic {
            envelope_sha256: [n ^ 0x5a; 32],
            tx_hash: [n ^ 0x80; 32],
            sequence: 100 + i64::from(n),
            max_time: 0,
            receipt: stellar_agent_core::hex::encode(&[n ^ 0x5a; 32]),
        }
    }

    fn proof() -> NotIncludedProof {
        let coverage = EndpointCoverage {
            first_ledger: 10,
            last_ledger: 300,
            latest_ledger: 310,
            oldest_ledger: 1,
        };
        NotIncludedProof::AccountSequence {
            primary: coverage,
            witness: coverage,
        }
    }

    fn code(error: &WindowStoreError) -> &'static str {
        error.operation_error().map_or("none", |error| error.code())
    }

    fn evidence_rows(fx: &Fx) -> Vec<(Option<EvidenceSeqRange>, Vec<u64>, bool, String)> {
        fx.sink
            .entries
            .iter()
            .filter_map(|entry| match &entry.event_kind {
                EventKind::OperationEvidence {
                    evidence_seqs,
                    rows,
                    sequence_released,
                    commit_id,
                    ..
                } => Some((
                    *evidence_seqs,
                    rows.iter().map(|row| row.evidence_seq).collect(),
                    *sequence_released,
                    commit_id.clone(),
                )),
                _ => None,
            })
            .collect()
    }

    fn outcome_row(n: u8, ledger: u32) -> EvidenceRowInput {
        EvidenceRowInput {
            endpoint: EvidenceEndpoint::Primary,
            observed_ledger: ledger,
            answer: EvidenceAnswer::Outcome {
                status: Some("NOT_FOUND".to_owned()),
                ledger: None,
                created_at: None,
                tx_hash: Some(stellar_agent_core::hex::encode(&[n; 32])),
                envelope_xdr: None,
                result_xdr: None,
                latest_ledger: Some(ledger),
                oldest_ledger: Some(1),
            },
            digest: [n; 32],
        }
    }

    fn ledger_row(endpoint: EvidenceEndpoint, ledger: u32) -> EvidenceRowInput {
        EvidenceRowInput {
            endpoint,
            observed_ledger: ledger,
            answer: EvidenceAnswer::Ledger {
                expiry_ledger: ledger,
                close_time: T0 / 1_000,
                latest_ledger: ledger,
            },
            digest: Sha256::digest(ledger.to_be_bytes()).into(),
        }
    }

    #[test]
    #[serial]
    fn recovery_emitted_kinds_survive_eviction() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        fx.sink.entries.clear();
        for ledger in 1..=9 {
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        rows: vec![
                            ledger_row(EvidenceEndpoint::Primary, ledger),
                            ledger_row(EvidenceEndpoint::Witness, ledger),
                        ],
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        assert!(
            fx.record(handle.id()).attempts[0]
                .evidence
                .iter()
                .all(|row| row.observed_ledger > 1)
        );
        assert_eq!(fx.sink.entries.len(), 9);
        for entry in &fx.sink.entries {
            let EventKind::OperationEvidence { rows, .. } = &entry.event_kind else {
                panic!("evidence row required")
            };
            assert_eq!(
                rows.iter().map(|row| row.kind).collect::<Vec<_>>(),
                vec![
                    Some(EvidenceKind::PrimaryLedger),
                    Some(EvidenceKind::OracleLedger)
                ]
            );
        }
    }

    #[test]
    #[serial]
    fn evidence_key_is_kind_and_observed_ledger() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let row = ledger_row(EvidenceEndpoint::Primary, 10);
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![row.clone()],
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let audit_count = fx.sink.entries.len();
        let mut duplicate = row.clone();
        duplicate.digest = [0x42; 32];
        assert_eq!(
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        rows: vec![duplicate],
                        recovery: Some(RecoveryUpdate {
                            primary_cursor: Some(11),
                            ..RecoveryUpdate::default()
                        }),
                        ..EvidenceInput::default()
                    }
                )
                .unwrap(),
            None
        );
        assert_eq!(fx.sink.entries.len(), audit_count);
        assert_eq!(
            fx.record(handle.id()).attempts[0]
                .recovery
                .as_ref()
                .unwrap()
                .primary_cursor,
            Some(11)
        );
        let mut later = row;
        later.observed_ledger = 11;
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![
                        later,
                        outcome_row(1, 10),
                        ledger_row(EvidenceEndpoint::Witness, 10),
                    ],
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        assert_eq!(fx.record(handle.id()).evidence_committed_seq, 4);
    }

    #[test]
    #[serial]
    fn recovery_evidence_eviction_tie_breaks_on_sequence() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let release = SequenceReleaseInput {
            primary_ledger: 1,
            witness_ledger: 2,
            min_close_time_ms: T0,
        };
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: (1..=4)
                        .flat_map(|ledger| {
                            [
                                ledger_row(EvidenceEndpoint::Primary, ledger),
                                ledger_row(EvidenceEndpoint::Witness, ledger),
                            ]
                        })
                        .collect(),
                    sequence_released: Some(release),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let proof = fx.record(handle.id()).attempts[0].sequence_released.clone();
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![ledger_row(EvidenceEndpoint::Primary, 5)],
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let record = fx.record(handle.id());
        assert_eq!(record.evidence_committed_seq, 9);
        assert_eq!(
            record.attempts[0]
                .evidence
                .iter()
                .map(|row| row.evidence_seq)
                .collect::<Vec<_>>(),
            (2..=9).collect::<Vec<_>>()
        );
        assert_eq!(record.attempts[0].sequence_released, proof);
    }

    /// An exposed classic attempt in `SentOutcomeUnknown`.
    fn unknown_outcome(fx: &mut Fx) -> OperationHandle {
        unknown_named(fx, 1)
    }

    pub(crate) fn unknown_named(fx: &mut Fx, n: u8) -> OperationHandle {
        unknown_with(fx, n, 0, vec![])
    }

    /// An exposed classic attempt in `SentOutcomeUnknown` with `max_time` and `holds`.
    pub(crate) fn unknown_with(
        fx: &mut Fx,
        n: u8,
        max_time: u64,
        holds: Vec<WindowEntry>,
    ) -> OperationHandle {
        let handle = fx.open_new(&request(&format!("order-{n}"), canonical(n)));
        let mint = fx.mint_request(tx(n), fx.policy(), holds);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        let mut exposure = classic_exposure(n);
        if let ExposureIdentity::Classic {
            max_time: bound, ..
        } = &mut exposure
        {
            *bound = max_time;
        }
        fx.recorder()
            .expose(handle.id(), started.attempt_index, &exposure, None)
            .unwrap();
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::SentOutcomeUnknown,
                &TransitionEvidence::default(),
            )
            .unwrap();
        handle
    }

    #[test]
    #[serial]
    fn recovery_snapshot_selects_oldest_eligible_and_targets_by_hash() {
        let mut fx = Fx::new();
        let mut ids = Vec::new();
        for n in 1..=5 {
            fx.clock.set(T0 + u64::from(n));
            let holds = if n == 3 { vec![hold(10)] } else { vec![] };
            ids.push(unknown_with(&mut fx, n, T0 / 1_000 - 10, holds).id());
        }
        let snapshot = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        assert_eq!(
            snapshot
                .iter()
                .map(|attempt| attempt.operation_id)
                .collect::<Vec<_>>(),
            ids[..4]
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|attempt| attempt.reservation_present)
                .collect::<Vec<_>>(),
            [false, false, true, false]
        );
        let ExposureIdentity::Classic { tx_hash, .. } = classic_exposure(5) else {
            unreachable!()
        };
        let targeted = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(Some(&tx_hash))
            .unwrap();
        assert_eq!(targeted.len(), 1);
        assert_eq!(targeted[0].operation_id, ids[4]);
        fx.rewrite(|wire| {
            let first = &mut section_mut(wire).records[0];
            first.kind = OperationKind::X402Payment;
        });
        let snapshot = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        assert_eq!(
            snapshot
                .iter()
                .map(|attempt| attempt.operation_id)
                .collect::<Vec<_>>(),
            ids[1..]
        );
        let targeted = |fx: &Fx, n: u8| {
            let ExposureIdentity::Classic { tx_hash, .. } = classic_exposure(n) else {
                unreachable!()
            };
            OperationStatus::new(&fx.store, &fx.profile)
                .recovery_snapshot(Some(&tx_hash))
                .unwrap()
                .len()
        };
        unknown_with(&mut fx, 6, T0 / 1_000 + 120, vec![]);
        unknown_with(&mut fx, 7, 0, vec![]);
        // A bound far ahead and a zero bound are both evaluated.
        assert_eq!((targeted(&fx, 6), targeted(&fx, 7)), (1, 1));
        let mut bytes = fs::read(fx.store.path()).unwrap();
        let at = bytes
            .windows(7)
            .rposition(|window| window == b"order-2")
            .unwrap();
        bytes[at + 6] = b'9';
        fs::write(fx.store.path(), bytes).unwrap();
        let error = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap_err();
        // Mainnet builds report the authentication mismatch as an unverifiable state.
        let expected = if cfg!(feature = "mainnet-write") {
            "MainnetStateUnverifiable { defect: HmacInvalid }"
        } else {
            "HmacMismatch"
        };
        assert_eq!(format!("{error:?}"), expected);
    }

    #[test]
    #[serial]
    fn open_returns_new_replay_resumable_and_conflict() {
        let mut fx = Fx::new();
        let a = fx.open_new(&request("order-1", canonical(1)));
        assert_eq!(a.state(), OperationState::Prepared);
        assert!(matches!(
            fx.open(&request("order-1", canonical(1))).unwrap(),
            OpenOutcome::Resumable(handle) if handle.id() == a.id()
        ));
        for other in [canonical(2), x402([1; 32])] {
            let before = fx.generation();
            assert!(matches!(
                fx.open(&request("order-1", other)).unwrap(),
                OpenOutcome::Conflict
            ));
            assert_eq!(fx.generation(), before);
        }

        fx.recorder()
            .transition(
                a.id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        assert!(matches!(
            fx.open(&request("order-1", canonical(1))).unwrap(),
            OpenOutcome::Replay(view)
                if view.operation_id == a.id()
                    && view.state == OperationState::Expired
                    && !view.compacted
        ));

        fx.clock.set(T0 + TERMINAL_RETENTION_MS);
        fx.open_new(&request("order-2", canonical(3)));
        assert!(
            tombstones(&fx.wire())
                .iter()
                .any(|tombstone| tombstone.id == a.id())
        );
        assert!(records(&fx.wire()).iter().all(|record| record.id != a.id()));
        assert!(matches!(
            fx.open(&request("order-1", canonical(1))).unwrap(),
            OpenOutcome::Replay(view) if view.operation_id == a.id() && view.compacted
        ));
        for other in [canonical(2), x402([1; 32])] {
            assert!(matches!(
                fx.open(&request("order-1", other)).unwrap(),
                OpenOutcome::Conflict
            ));
        }

        fx.clock.set(T0 + TOMBSTONE_RETENTION_MS);
        let reopened = fx.open_new(&request("order-1", canonical(2)));
        assert_ne!(reopened.id(), a.id());
    }

    #[test]
    #[serial]
    fn envelope_record_retry_with_the_same_intent_resumes_with_the_stored_envelope() {
        let mut fx = Fx::new();
        let first = fx.open_new(&request("order-1", envelope(5, 6, 0)));
        let mut retry = request("order-1", envelope(9, 6, 0));
        retry.envelope_xdr = Some("AAAAANOTHER".to_owned());
        match fx.open(&retry).unwrap() {
            OpenOutcome::Resumable(handle) => {
                assert_eq!(handle.id(), first.id());
                assert_eq!(handle.envelope_xdr(), Some("AAAASTORED"));
                assert_eq!(handle.unsigned_envelope_sha256(), Some([5; 32]));
            }
            other => panic!("expected a resumable record, got {other:?}"),
        }
    }

    #[test]
    #[serial]
    fn envelope_record_expiry_is_capped_at_max_time() {
        let mut fx = Fx::new();
        let max_time = T0 / 1000 + 100;
        let mut open = request("order-1", envelope(5, 6, max_time));
        open.rule_ttl_ms = Some(APPROVAL_MS);
        let handle = fx.open_new(&open);
        assert_eq!(handle.waiting_expires_at_ms(), T0 + 100_000);
        let mint = fx.mint_request(tx(5), fx.approval(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        assert_eq!(
            fx.record(handle.id()).execution_expires_at_ms,
            Some(T0 + 100_000)
        );
        assert!(fx.auth(started.authorization_id).expires_ms <= T0 + 100_000);
    }

    #[test]
    #[serial]
    fn begin_attempt_refuses_another_envelope_for_an_envelope_record() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", envelope(5, 6, 0)));
        let before = fx.generation();
        let mint = fx.mint_request(tx(5), fx.approval(), vec![]);
        let refused = fx.recorder().begin_attempt(
            &handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: "AAAAOTHER".to_owned(),
                    unsigned_envelope_sha256: [9; 32],
                }),
                authorization: AttemptAuthorization::Mint(Box::new(mint.clone())),
                send_by_ms: u64::MAX,
            },
        );
        let error = refused.unwrap_err();
        assert!(matches!(error, WindowStoreError::BusinessIdConflict));
        assert_eq!(code(&error), "operation.business_id_conflict");
        assert_eq!(fx.generation(), before);
        assert!(fx.wire().authorizations.is_empty());
        assert_eq!(fx.record(handle.id()).state, OperationState::Prepared);

        fx.begin_mint(&handle, &mint).unwrap();
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
    }

    #[test]
    fn business_id_grammar() {
        let code_of = |value: &str| BusinessId::parse(value).map(|_| ()).map_err(|e| e.code());
        assert_eq!(code_of(""), Err("validation.business_id_required"));
        assert_eq!(code_of("a"), Ok(()));
        assert_eq!(code_of(&"a".repeat(64)), Ok(()));
        assert_eq!(
            code_of(&"a".repeat(65)),
            Err("validation.business_id_invalid")
        );
        assert_eq!(code_of("a b"), Err("validation.business_id_invalid"));
        assert_eq!(code_of("\u{20}"), Err("validation.business_id_invalid"));
        assert_eq!(code_of("\u{21}"), Ok(()));
        assert_eq!(code_of("\u{7e}"), Ok(()));
        assert_eq!(code_of("\u{7f}"), Err("validation.business_id_invalid"));
        assert_eq!(code_of("caf\u{e9}"), Err("validation.business_id_invalid"));
        assert!(serde_json::from_str::<BusinessId>("\"\"").is_err());
        assert_eq!(
            serde_json::from_str::<BusinessId>("\"order-1\"").unwrap(),
            BusinessId::parse("order-1").unwrap()
        );
    }

    #[test]
    #[serial]
    fn waiting_operations_cap_refuses_the_seventeenth() {
        let mut fx = Fx::new();
        let mut handles = Vec::new();
        for n in 0..16_u8 {
            handles.push(fx.open_new(&request(&format!("order-{n}"), canonical(n))));
        }
        let before = fx.generation();
        let error = fx.open(&request("order-16", canonical(16))).unwrap_err();
        assert!(matches!(
            error,
            WindowStoreError::OperationCapacity {
                detail: CapacityDetail::WaitingOperations
            }
        ));
        assert_eq!(code(&error), "operation.capacity");
        assert_eq!(fx.generation(), before);
        assert_eq!(records(&fx.wire()).len(), 16);

        fx.recorder()
            .transition(
                handles[0].id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        fx.open_new(&request("order-16", canonical(16)));
    }

    #[test]
    #[serial]
    fn begin_attempt_refuses_an_open_attempt_and_a_ninth() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let first = fx.mint_request(tx(1), fx.policy(), vec![]);
        fx.begin_mint(&handle, &first).unwrap();
        let again = fx.mint_request(tx(2), fx.policy(), vec![]);
        let error = fx.begin_mint(&handle, &again).unwrap_err();
        assert!(matches!(error, WindowStoreError::AttemptOpen));
        assert_eq!(code(&error), "operation.attempt_open");

        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        for n in 1..=8_u8 {
            assert_eq!(fx.not_included_attempt(&handle, n), u32::from(n));
        }
        let before = fx.generation();
        let ninth = fx.mint_request(tx(9), fx.policy(), vec![]);
        let error = fx.begin_mint(&handle, &ninth).unwrap_err();
        assert!(matches!(error, WindowStoreError::AttemptLimit));
        assert_eq!(code(&error), "operation.attempt_limit");
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.record(handle.id()).attempts.len(), 8);
    }

    #[test]
    #[serial]
    fn longest_transition_path_fits_commit_ids() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        fx.recorder()
            .transition(
                handle.id(),
                None,
                OperationState::AwaitingApproval,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let mut linked = fx.mint_request(tx(1), fx.policy(), vec![]);
        linked.operation = Some(OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        });
        let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        let handle = match fx.open(&request("order-1", canonical(1))).unwrap() {
            OpenOutcome::Resumable(handle) => handle,
            other => panic!("expected the adopted record, got {other:?}"),
        };
        assert_eq!(handle.state(), OperationState::Authorized);
        let started = fx
            .recorder()
            .begin_attempt(
                &handle,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "AAAAENVELOPE".to_owned(),
                        unsigned_envelope_sha256: [1; 32],
                    }),
                    authorization: AttemptAuthorization::Linked,
                    send_by_ms: u64::MAX,
                },
            )
            .unwrap();
        assert_eq!(started.authorization_id, minted.id);
        fx.claim(&linked, &minted);
        fx.recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap();
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::SentOutcomeUnknown,
                &TransitionEvidence::default(),
            )
            .unwrap();
        fx.checked_non_inclusion(&handle, 1, 1);
        for n in 2..=8_u8 {
            fx.not_included_attempt(&handle, n);
        }
        fx.recorder()
            .transition(
                handle.id(),
                Some(8),
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let mut record = fx.record(handle.id());
        assert_eq!(record.commit_ids.len(), COMMIT_IDS_MAX);
        assert_eq!(record.state, OperationState::Expired);
        let error = record.note_commit(CommitId::random()).unwrap_err();
        assert_eq!(code(&error), "internal.unexpected_state");
        assert_eq!(record.commit_ids.len(), COMMIT_IDS_MAX);
    }

    #[test]
    #[serial]
    fn every_edge_outside_the_table_refuses() {
        use OperationState as S;
        let table = [
            (None, S::Prepared),
            (Some(S::Prepared), S::AwaitingApproval),
            (Some(S::Prepared), S::Authorized),
            (Some(S::AwaitingApproval), S::Authorized),
            (Some(S::Prepared), S::Expired),
            (Some(S::AwaitingApproval), S::Expired),
            (Some(S::Authorized), S::Expired),
            (Some(S::NotIncluded), S::Expired),
            (Some(S::Authorized), S::Sending),
            (Some(S::Sending), S::NotSent),
            (Some(S::Sending), S::SentOutcomeUnknown),
            (Some(S::Sending), S::PayloadReleased),
            (Some(S::SentOutcomeUnknown), S::Succeeded),
            (Some(S::SentOutcomeUnknown), S::Failed),
            (Some(S::SentOutcomeUnknown), S::NotIncluded),
            (Some(S::SentOutcomeUnknown), S::Expired),
            (Some(S::SentOutcomeUnknown), S::Cancelled),
            (Some(S::NotIncluded), S::Sending),
        ];
        let froms = std::iter::once(None).chain(S::ALL.into_iter().map(Some));
        let mut admitted = 0;
        for from in froms {
            for to in S::ALL {
                let expected = table.contains(&(from, to));
                assert_eq!(edge_allowed(from, to), expected, "{from:?} -> {to:?}");
                match check_edge(from, to) {
                    Ok(()) => admitted += 1,
                    Err(error) => {
                        assert!(!expected);
                        assert_eq!(code(&error), "internal.unexpected_state");
                    }
                }
            }
        }
        assert_eq!(admitted, table.len());

        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let before = fx.generation();
        for to in [S::Succeeded, S::Sending, S::NotIncluded, S::Cancelled] {
            let error = fx
                .recorder()
                .transition(handle.id(), None, to, &TransitionEvidence::default())
                .unwrap_err();
            assert_eq!(code(&error), "internal.unexpected_state", "{to:?}");
        }
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.record(handle.id()).state, S::Prepared);
    }

    #[test]
    #[serial]
    fn expose_after_not_sent_refuses() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        fx.begin_mint(&handle, &mint).unwrap();
        let error = fx
            .recorder()
            .expose(handle.id(), 2, &classic_exposure(1), None)
            .unwrap_err();
        assert_eq!(code(&error), "internal.unexpected_state");
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::NotSent,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let before = fx.generation();
        let error = fx
            .recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap_err();
        assert_eq!(code(&error), "internal.unexpected_state");
        assert_eq!(fx.generation(), before);
        assert!(fx.record(handle.id()).attempts[0].exposure.is_none());
    }

    #[test]
    #[serial]
    fn begin_attempt_refuses_oversized_envelope_before_mint() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let before = fx.generation();
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let mut unmintable = mint.clone();
        unmintable.authorization_ttl_ms = 0;
        for authorization in [mint.clone(), unmintable] {
            let error = fx
                .recorder()
                .begin_attempt(
                    &handle,
                    &AttemptRequest {
                        envelope: Some(AttemptEnvelope {
                            xdr: "A".repeat(ENVELOPE_XDR_MAX + 1),
                            unsigned_envelope_sha256: [1; 32],
                        }),
                        authorization: AttemptAuthorization::Mint(Box::new(authorization)),
                        send_by_ms: u64::MAX,
                    },
                )
                .unwrap_err();
            assert!(matches!(
                error,
                WindowStoreError::OperationCapacity {
                    detail: CapacityDetail::EnvelopeSize
                }
            ));
            assert_eq!(code(&error), "operation.capacity");
        }
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::Prepared);
        assert!(record.attempts.is_empty());
        assert!(fx.wire().authorizations.is_empty());
        assert_eq!(fx.generation(), before);

        let started = fx
            .recorder()
            .begin_attempt(
                &handle,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "A".repeat(ENVELOPE_XDR_MAX),
                        unsigned_envelope_sha256: [1; 32],
                    }),
                    authorization: AttemptAuthorization::Mint(Box::new(mint)),
                    send_by_ms: u64::MAX,
                },
            )
            .unwrap();
        assert_eq!(started.attempt_index, 1);
    }

    /// Text of exactly `max` serialized bytes: each `"` serializes as two.
    fn escaped(max: usize) -> String {
        "\"".repeat(max / 2)
    }

    /// A bounded text at its maximal serialized size, marked truncated.
    fn maximal_text(max: usize) -> BoundedText {
        BoundedText {
            text: escaped(max),
            truncated: true,
        }
    }

    /// A record of `intent` with every optional field present and every
    /// text at its bound.
    #[allow(
        clippy::too_many_lines,
        reason = "one literal holding every field of the largest record"
    )]
    fn maximal_record(intent: IntentSlot) -> WireOperation {
        let nonce = "\u{1}".repeat(APPROVAL_NONCE_MAX);
        let authority = OperationAuthority::Approval {
            approval_record_id: Some([0xff; 32]),
            approval_nonce: nonce,
        };
        let mut holds = Vec::new();
        loop {
            let mut next = holds.clone();
            next.push(HoldRef {
                authorization_id: AuthorizationId::from_bytes([0xff; 32]),
                ordinal: u32::MAX,
            });
            if serialized_len(&next) > HOLDS_MAX {
                break;
            }
            holds = next;
        }
        let decision = serde_json::json!({ "d": "x".repeat(PREPARED_DECISION_MAX - 8) });
        assert_eq!(serialized_len(&decision), PREPARED_DECISION_MAX);
        let coverage = EndpointCoverage {
            first_ledger: u32::MAX,
            last_ledger: u32::MAX,
            latest_ledger: u32::MAX,
            oldest_ledger: u32::MAX,
        };
        let evidence_row = WireEvidenceRow {
            endpoint: EvidenceEndpoint::Witness,
            observed_ledger: u32::MAX,
            answer: WireEvidenceAnswer::Outcome {
                status: Some(maximal_text(ENDPOINT_TEXT_MAX)),
                ledger: Some(u32::MAX),
                created_at: Some(u64::MAX),
                tx_hash: Some(maximal_text(ENDPOINT_TEXT_MAX)),
                envelope_xdr: Some([0xff; 32]),
                result_xdr: Some([0xff; 32]),
                latest_ledger: Some(u32::MAX),
                oldest_ledger: Some(u32::MAX),
            },
            digest: [0xff; 32],
            commit_id: CommitId::from_bytes([0xff; 16]),
            evidence_seq: u64::MAX,
        };
        let attempt = WireAttempt {
            index: u32::MAX,
            authorization_id: AuthorizationId::from_bytes([0xff; 32]),
            authority: authority.clone(),
            send_by_ms: u64::MAX,
            request_id: "-".repeat(REQUEST_ID_MAX),
            started_at_ms: u64::MAX,
            outcome: Some(OperationState::SentOutcomeUnknown),
            pre_exposure_ledger: Some(u32::MAX),
            exposure: Some(WireExposure {
                identity: ExposureIdentity::Classic {
                    envelope_sha256: [0xff; 32],
                    tx_hash: [0xff; 32],
                    sequence: i64::MIN,
                    max_time: u64::MAX,
                    receipt: "f".repeat(RECEIPT_REFERENCE_MAX),
                },
                commit_id: CommitId::from_bytes([0xff; 16]),
                exposed_at_ms: u64::MAX,
            }),
            sequence_released: Some(SequenceReleased {
                primary_ledger: u32::MAX,
                witness_ledger: u32::MAX,
                min_close_time_ms: u64::MAX,
                commit_id: CommitId::from_bytes([0xff; 16]),
                released_at_ms: u64::MAX,
            }),
            not_included: Some(NotIncludedProof::CompleteHistory {
                primary: coverage,
                witness: coverage,
            }),
            agreed_outcome: Some(WireAgreedOutcome {
                status: maximal_text(ENDPOINT_TEXT_MAX),
                ledger: u32::MAX,
                created_at: u64::MAX,
                result_xdr: BoundedText {
                    text: "A".repeat(RESULT_XDR_MAX),
                    truncated: true,
                },
                envelope_xdr_sha256: [0xff; 32],
            }),
            evidence: vec![evidence_row; MAX_EVIDENCE_ROWS],
            recovery: Some(WireRecovery {
                primary_cursor: Some(u32::MAX),
                witness_cursor: Some(u32::MAX),
                primary_upper: Some(u32::MAX),
                witness_upper: Some(u32::MAX),
                disagreements: u8::MAX,
                last_pass_at_ms: Some(u64::MAX),
                last_outcome: Some("r".repeat(RECOVERY_OUTCOME_MAX)),
                history_incomplete: true,
                diagnostic: Some(maximal_text(DIAGNOSTIC_MAX)),
            }),
            decision: Some(WireDecision {
                commit_id: CommitId::from_bytes([0xff; 16]),
                evidence_digest: [0xff; 32],
                primary_ledger: u32::MAX,
                witness_ledger: u32::MAX,
                fee_charged: Some(i64::MIN),
                projected: true,
            }),
        };
        WireOperation {
            id: OperationId::from_bytes([0xff; 16]),
            business_id: BusinessId::parse(&"\\".repeat(BUSINESS_ID_MAX)).unwrap(),
            profile: "\\".repeat(NAME_MAX),
            chain_id: Caip2::Mainnet,
            state: OperationState::SentOutcomeUnknown,
            tool: OperationTool::X402AuthenticatedPayment,
            kind: OperationKind::X402AuthenticatedPayment,
            intent,
            envelope_xdr: Some("A".repeat(ENVELOPE_XDR_MAX)),
            prepared_decision: Some(decision),
            authority: Some(authority),
            approval_record_id: Some([0xff; 32]),
            holds,
            history: vec![
                HistoryEntry {
                    from: Some(OperationState::SentOutcomeUnknown),
                    to: OperationState::SentOutcomeUnknown,
                    at_ms: u64::MAX,
                    evidence: Some(maximal_text(HISTORY_EVIDENCE_MAX)),
                };
                HISTORY_MAX
            ],
            last_commit_id: Some(CommitId::from_bytes([0xff; 16])),
            commit_ids: vec![CommitId::from_bytes([0xff; 16]); COMMIT_IDS_MAX],
            evidence_committed_seq: u64::MAX,
            attempts: vec![attempt; MAX_ATTEMPTS],
            result: Some(OperationResult {
                tx_hash: Some([0xff; 32]),
                ledger: Some(u32::MAX),
                error_code: Some("\\".repeat(NAME_MAX)),
                payload_released: true,
            }),
            created_at_ms: u64::MAX,
            updated_at_ms: u64::MAX,
            closed_at_ms: Some(u64::MAX),
            execution_expires_at_ms: Some(u64::MAX),
            waiting_expires_at_ms: u64::MAX,
        }
    }

    /// The x402 slot whose zero-padded amount brings the whole tagged value
    /// to `len` serialized bytes.
    fn x402_slot_of_len(len: usize) -> IntentSlot {
        let base = serialized_len(&IntentSlot::X402 {
            intent_digest: [0xff; 32],
            intent: x402_intent(""),
        });
        let slot = IntentSlot::X402 {
            intent_digest: [0xff; 32],
            intent: x402_intent(&format!("{:0>width$}", 1, width = len - base)),
        };
        assert_eq!(serialized_len(&slot), len);
        slot
    }

    #[test]
    #[serial]
    fn largest_record_fits_m() {
        let canonical_base = serialized_len(&IntentSlot::Canonical {
            intent_digest: [0xff; 32],
            intent: serde_json::json!({ "memo": "" }),
        });
        let canonical_max = IntentSlot::Canonical {
            intent_digest: [0xff; 32],
            intent: serde_json::json!({ "memo": "\"".repeat((INTENT_SLOT_MAX - canonical_base) / 2) }),
        };
        assert!(serialized_len(&canonical_max) >= INTENT_SLOT_MAX - 1);
        for intent in [
            envelope(0xff, 0xff, u64::MAX),
            canonical_max,
            x402_slot_of_len(INTENT_SLOT_MAX),
        ] {
            let record = maximal_record(intent);
            let len = serialized_len(&record);
            assert!(len <= RECORD_MAX, "{len} > {RECORD_MAX}");
        }

        let mut fx = Fx::new();
        let mut fits = request("order-1", x402_slot_of_len(INTENT_SLOT_MAX));
        fits.kind = OperationKind::X402Payment;
        fx.open_new(&fits);
        let before = fx.generation();
        let over = request("order-2", x402_slot_of_len(INTENT_SLOT_MAX + 1));
        let error = fx.open(&over).unwrap_err();
        assert!(matches!(
            error,
            WindowStoreError::OperationCapacity {
                detail: CapacityDetail::IntentSize
            }
        ));
        assert_eq!(code(&error), "operation.capacity");
        assert_eq!(fx.generation(), before);
    }

    /// Stored outcome and account rows keep their bytes, and a nullable
    /// answer omits each absent field without a zero or empty substitute.
    #[test]
    fn legacy_evidence_bytes_survive_the_additive_answer() {
        let hash = "ab".repeat(32);
        let legacy = [
            format!(
                r#"{{"outcome":{{"status":{{"text":"NOT_FOUND"}},"tx_hash":{{"text":"{hash}"}},"latest_ledger":50,"oldest_ledger":1}}}}"#
            ),
            format!(
                r#"{{"outcome":{{"status":{{"text":"SUCCESS"}},"ledger":40,"created_at":1700000000,"tx_hash":{{"text":"{hash}"}},"envelope_xdr":"{hash}","result_xdr":"{hash}","latest_ledger":50,"oldest_ledger":1}}}}"#
            ),
            r#"{"account":{"sequence":7,"latest_ledger":50}}"#.to_owned(),
            r#"{"ledger":{"expiry_ledger":9,"close_time":10,"latest_ledger":50}}"#.to_owned(),
        ];
        for bytes in &legacy {
            let answer: WireEvidenceAnswer = serde_json::from_str(bytes).unwrap();
            assert!(answer.fits(), "{bytes}");
            assert_eq!(&serde_json::to_string(&answer).unwrap(), bytes);
        }
        let absent = WireEvidenceAnswer::from_input(&EvidenceAnswer::Outcome {
            status: Some("NOT_FOUND".to_owned()),
            ledger: None,
            created_at: None,
            tx_hash: None,
            envelope_xdr: None,
            result_xdr: None,
            latest_ledger: None,
            oldest_ledger: None,
        });
        assert_eq!(
            serde_json::to_string(&absent).unwrap(),
            r#"{"outcome":{"status":{"text":"NOT_FOUND"}}}"#
        );
        assert_eq!(absent.kind(), 2);
        let account = WireEvidenceAnswer::from_input(&EvidenceAnswer::Account {
            sequence: None,
            latest_ledger: Some(0),
        });
        assert_eq!(
            serde_json::to_string(&account).unwrap(),
            r#"{"account":{"latest_ledger":0}}"#
        );
        assert_eq!(account.kind(), 1);
        for (answer, endpoint, kind) in [
            (
                absent.clone(),
                EvidenceEndpoint::Primary,
                EvidenceKind::PrimaryOutcome,
            ),
            (
                absent,
                EvidenceEndpoint::Witness,
                EvidenceKind::OracleOutcome,
            ),
            (
                account.clone(),
                EvidenceEndpoint::Primary,
                EvidenceKind::PrimaryAccount,
            ),
            (
                account,
                EvidenceEndpoint::Witness,
                EvidenceKind::OracleAccount,
            ),
        ] {
            let row = WireEvidenceRow {
                endpoint,
                observed_ledger: 50,
                answer,
                digest: [1; 32],
                commit_id: CommitId::from_bytes([2; 16]),
                evidence_seq: 1,
            };
            assert_eq!(row.audit_kind(), kind);
        }
        let overlong = WireEvidenceAnswer::Outcome {
            status: Some(BoundedText {
                text: "x".repeat(ENDPOINT_TEXT_MAX + 1),
                truncated: false,
            }),
            ledger: None,
            created_at: None,
            tx_hash: None,
            envelope_xdr: None,
            result_xdr: None,
            latest_ledger: None,
            oldest_ledger: None,
        };
        assert!(!overlong.fits());
    }

    #[test]
    #[serial]
    fn free_text_bounds_measure_serialized_bytes() {
        for max in [HISTORY_EVIDENCE_MAX, ENDPOINT_TEXT_MAX, DIAGNOSTIC_MAX] {
            let at = escaped(max);
            assert_eq!(serialized_text_len(&at), max);
            let kept = BoundedText::bound(&at, max);
            assert!(!kept.truncated());
            assert_eq!(kept.text(), at);
            let over = format!("{at}a");
            assert!(over.len() < max);
            let digest = BoundedText::bound(&over, max);
            assert!(digest.truncated());
            assert_eq!(digest.text(), sha256_hex(over.as_bytes()));
            assert!(digest.fits(max));
        }

        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let note = escaped(HISTORY_EVIDENCE_MAX);
        let mut row = outcome_row(3, 50);
        if let EvidenceAnswer::Outcome {
            status, tx_hash, ..
        } = &mut row.answer
        {
            *status = Some(escaped(ENDPOINT_TEXT_MAX));
            *tx_hash = Some(format!("{}a", escaped(ENDPOINT_TEXT_MAX)));
        }
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![row],
                    recovery: Some(RecoveryUpdate {
                        diagnostic: Some(format!("{}a", escaped(DIAGNOSTIC_MAX))),
                        ..RecoveryUpdate::default()
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::Cancelled,
                &TransitionEvidence {
                    note: Some(note.clone()),
                    clear: Some(ClearForm::Untimed),
                    ..TransitionEvidence::default()
                },
            )
            .unwrap();
        let record = fx.record(handle.id());
        let evidence = record.history.last().unwrap().evidence.clone().unwrap();
        assert!(!evidence.truncated());
        assert_eq!(evidence.text(), note);
        let attempt = &record.attempts[0];
        let WireEvidenceAnswer::Outcome {
            status, tx_hash, ..
        } = &attempt.evidence[0].answer
        else {
            panic!("expected an outcome answer");
        };
        let (status, tx_hash) = (status.as_ref().unwrap(), tx_hash.as_ref().unwrap());
        assert!(!status.truncated());
        assert!(tx_hash.truncated());
        assert_eq!(
            tx_hash.text(),
            sha256_hex(format!("{}a", escaped(ENDPOINT_TEXT_MAX)).as_bytes())
        );
        let diagnostic = attempt
            .recovery
            .as_ref()
            .unwrap()
            .diagnostic
            .clone()
            .unwrap();
        assert!(diagnostic.truncated());
    }

    #[test]
    #[serial]
    fn sweep_adopts_waiting_operation_before_restart() {
        #[derive(Debug, Clone, Copy)]
        enum Case {
            ApprovalClassic,
            PolicyClassic,
            X402,
        }
        for case in [Case::ApprovalClassic, Case::PolicyClassic, Case::X402] {
            for after_execution in [false, true] {
                let label = format!("{case:?}, after execution expiry: {after_execution}");
                let mut fx = Fx::new();
                let (slot, binding) = match case {
                    Case::X402 => (x402([1; 32]), soroban(1)),
                    Case::ApprovalClassic | Case::PolicyClassic => (canonical(1), tx(1)),
                };
                let mut open = request("order-1", slot);
                open.rule_ttl_ms = Some(300_000);
                let handle = fx.open_new(&open);

                fx.clock.set(T0 + 299_000);
                let authority = match case {
                    Case::PolicyClassic => fx.policy(),
                    Case::ApprovalClassic | Case::X402 => fx.approval(),
                };
                let mut linked = fx.mint_request(binding, authority.clone(), vec![]);
                linked.operation = Some(OperationLink {
                    operation_id: handle.id(),
                    attempt_index: 1,
                });
                let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
                assert_eq!(minted.expires_at_ms, T0 + 299_000 + TTL_MS, "{label}");

                fx.clock.set(T0 + 299_000 + TTL_MS + 1);
                let other = fx.mint_request(tx(0x40), fx.approval(), vec![]);
                fx.store.mint_authorization(&fx.profile, &other).unwrap();
                assert_eq!(
                    fx.record(handle.id()).state,
                    OperationState::Prepared,
                    "{label}"
                );
                let untouched = fx.auth(minted.id);
                assert_eq!(untouched.state, AuthorizationState::Open, "{label}");
                assert_eq!(untouched.native_release, None, "{label}");
                let now = fx.now();
                fx.recorder().expire_due(now).unwrap();
                let record = fx.record(handle.id());
                assert_eq!(record.state, OperationState::Authorized, "{label}");
                let execution_end = T0 + 299_000 + APPROVAL_MS;
                assert_eq!(
                    record.execution_expires_at_ms,
                    Some(execution_end),
                    "{label}"
                );
                let swept = fx.auth(minted.id);
                assert_eq!(swept.state, AuthorizationState::Expired, "{label}");
                assert_eq!(swept.disposition, Some(Disposition::Unused), "{label}");
                assert_eq!(
                    swept.native_release.map(|row| (row.class, row.bound)),
                    Some((ReleaseClass::ProvedUnspent, ReleaseBound::Always)),
                    "{label}"
                );

                fx.clock.set(if after_execution {
                    execution_end
                } else {
                    T0 + 500_000
                });
                match (fx.open(&open).unwrap(), after_execution) {
                    (OpenOutcome::Resumable(resumed), false) => {
                        assert_eq!(resumed.state(), OperationState::Authorized, "{label}");
                        let authority = match case {
                            Case::PolicyClassic => fx.policy(),
                            Case::ApprovalClassic | Case::X402 => authority.clone(),
                        };
                        let binding = match case {
                            Case::X402 => soroban(2),
                            Case::ApprovalClassic | Case::PolicyClassic => tx(2),
                        };
                        let remint = fx.mint_request(binding, authority, vec![]);
                        let started = fx.begin_mint(&resumed, &remint).unwrap();
                        assert_eq!(started.attempt_index, 1, "{label}");
                        assert_ne!(started.authorization_id, minted.id, "{label}");
                        assert_eq!(
                            fx.auth(started.authorization_id).operation,
                            Some(OperationLink {
                                operation_id: handle.id(),
                                attempt_index: 1
                            }),
                            "{label}"
                        );
                        assert_eq!(
                            fx.record(handle.id()).state,
                            OperationState::Sending,
                            "{label}"
                        );
                    }
                    (OpenOutcome::Replay(view), true) => {
                        assert_eq!(view.state, OperationState::Expired, "{label}");
                    }
                    (other, _) => panic!("{label}: unexpected {other:?}"),
                }
            }
        }
    }

    #[test]
    #[serial]
    fn sweep_marks_open_unused_with_an_always_row_and_keeps_claimed() {
        let fx = Fx::new();
        let open = fx.mint_request(tx(1), fx.approval(), vec![hold(70)]);
        let unused = fx.store.mint_authorization(&fx.profile, &open).unwrap();
        let claimed_request = fx.mint_request(tx(2), fx.approval(), vec![hold(30)]);
        let claimed = fx
            .store
            .mint_authorization(&fx.profile, &claimed_request)
            .unwrap();
        fx.claim(&claimed_request, &claimed);
        let claimed_at = fx.auth(claimed.id).claimed_ms.unwrap();

        fx.clock.set(T0 + TTL_MS);
        fx.prune_now();
        let wire = fx.wire();
        assert_eq!(wire.version, super::super::store::WIRE_VERSION_OPERATIONS);
        assert!(wire.holds.is_empty());
        let unused = fx.auth(unused.id);
        assert_eq!(unused.state, AuthorizationState::Expired);
        assert_eq!(unused.disposition, Some(Disposition::Unused));
        let row = unused.native_release.unwrap();
        assert_eq!(row.class, ReleaseClass::ProvedUnspent);
        assert_eq!(row.bound, ReleaseBound::Always);
        assert_eq!(row.observed_ledger, None);
        let claimed = fx.auth(claimed.id);
        assert_eq!(claimed.state, AuthorizationState::Expired);
        assert_eq!(claimed.disposition, None);
        assert_eq!(claimed.native_release, None);
        assert!(
            wire.entries
                .iter()
                .flat_map(|bucket| &bucket.records)
                .any(|record| record.ts_ms == claimed_at && record.amount == 30)
        );
    }

    #[test]
    #[serial]
    fn remint_retires_unused_reservation_atomically() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let authority = fx.approval();
        let mut linked = fx.mint_request(tx(1), authority.clone(), vec![hold(70)]);
        linked.operation = Some(OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        });
        let first = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        let handle = match fx.open(&request("order-1", canonical(1))).unwrap() {
            OpenOutcome::Resumable(handle) => handle,
            other => panic!("expected the adopted record, got {other:?}"),
        };
        assert_eq!(handle.state(), OperationState::Authorized);
        let before = fx.generation();

        let refused = fx.mint_request(tx(2), authority.clone(), vec![hold(CAP + 1)]);
        assert!(matches!(
            fx.begin_mint(&handle, &refused),
            Err(WindowStoreError::PolicyDenied { .. })
        ));
        assert_eq!(fx.generation(), before);
        let kept = fx.auth(first.id);
        assert_eq!(kept.state, AuthorizationState::Open);
        assert_eq!(kept.native_release, None);
        assert_eq!(kept.disposition, None);
        assert_eq!(fx.wire().holds.len(), 1);

        let remint = fx.mint_request(tx(2), authority, vec![hold(70)]);
        let started = fx.begin_mint(&handle, &remint).unwrap();
        assert_eq!(fx.generation(), before + 1);
        let retired = fx.auth(first.id);
        assert_eq!(retired.state, AuthorizationState::Invalidated);
        assert_eq!(retired.disposition, Some(Disposition::Unused));
        let row = retired.native_release.unwrap();
        assert_eq!(
            (row.class, row.bound, row.observed_ledger),
            (ReleaseClass::RetiredUnused, ReleaseBound::Always, None)
        );
        let wire = fx.wire();
        assert!(
            wire.holds
                .iter()
                .all(|hold| hold.authorization_id != first.id)
        );
        assert_eq!(wire.holds.len(), 1);
        let minted = fx.auth(started.authorization_id);
        assert_eq!(minted.state, AuthorizationState::Open);
        assert_eq!(
            minted.operation,
            Some(OperationLink {
                operation_id: handle.id(),
                attempt_index: 1
            })
        );
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::Sending);
        assert_eq!(
            record.attempts[0].authorization_id,
            started.authorization_id
        );
        assert_eq!(
            record.holds,
            vec![HoldRef {
                authorization_id: started.authorization_id,
                ordinal: 0
            }]
        );
        assert_eq!(row.commit_id, started.commit_id);
    }

    /// A remint never retires an exposed authorization: a claimed one keeps
    /// its holds and gets no row, and a file naming an open one under an
    /// exposure refuses the remint before any write.
    #[test]
    #[serial]
    fn retire_after_expose_refused() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap();
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::SentOutcomeUnknown,
                &TransitionEvidence::default(),
            )
            .unwrap();
        fx.checked_non_inclusion(&handle, 1, 1);
        let claimed = fx.auth(started.authorization_id);
        // The checked decision writes the `proved_unspent` row; a remint
        // writes none of its own and keeps this one.
        let decided = claimed.native_release;
        assert_eq!(
            decided.map(|row| (row.class, row.bound)),
            Some((ReleaseClass::ProvedUnspent, ReleaseBound::Always))
        );

        fx.rewrite(|wire| {
            let auth = wire
                .authorizations
                .iter_mut()
                .find(|auth| auth.id == started.authorization_id)
                .unwrap();
            auth.state = AuthorizationState::Open;
            auth.claimed_ms = None;
        });
        let before = fx.generation();
        let bytes = std::fs::read(fx.store.path()).unwrap();
        let successor = fx.mint_request(tx(2), fx.policy(), vec![]);
        let error = fx.begin_mint(&handle, &successor).unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("exposed authorization")),
            "{error:?}"
        );
        assert_eq!(code(&error), "internal.unexpected_state");
        assert_eq!(fx.generation(), before);
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), bytes);
        let exposed = fx.auth(started.authorization_id);
        assert_eq!(exposed.state, AuthorizationState::Open);
        assert_eq!(exposed.native_release, decided);

        fx.rewrite(|wire| {
            let auth = wire
                .authorizations
                .iter_mut()
                .find(|auth| auth.id == started.authorization_id)
                .unwrap();
            *auth = claimed.clone();
        });
        let successor = fx.mint_request(tx(3), fx.policy(), vec![]);
        let next = fx.begin_mint(&handle, &successor).unwrap();
        assert_eq!(next.attempt_index, 2);
        let kept = fx.auth(started.authorization_id);
        assert_eq!(kept.state, AuthorizationState::Claimed);
        assert_eq!(kept.disposition, None);
        assert_eq!(kept.native_release, decided);
    }

    #[test]
    #[serial]
    fn unexposed_sending_after_authorization_expiry_records_not_sent() {
        // An authorization that expired unused.
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.clock.set(T0 + TTL_MS);
        assert_eq!(fx.recorder().expire_due(u64::MAX).unwrap(), 1);
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::NotSent);
        assert_eq!(record.attempts[0].outcome, Some(OperationState::NotSent));
        let auth = fx.auth(started.authorization_id);
        assert_eq!(auth.disposition, Some(Disposition::Unused));
        assert_eq!(
            auth.native_release.map(|row| (row.class, row.bound)),
            Some((ReleaseClass::ProvedUnspent, ReleaseBound::Always))
        );

        // An authorization its holder invalidated before use.
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        assert!(
            fx.store
                .invalidate_authorization(&fx.profile, started.authorization_id, "abandoned")
                .unwrap()
        );
        assert_eq!(fx.recorder().expire_due(u64::MAX).unwrap(), 1);
        assert_eq!(fx.record(handle.id()).state, OperationState::NotSent);
        assert_eq!(
            fx.auth(started.authorization_id)
                .native_release
                .map(|row| row.class),
            Some(ReleaseClass::ProvedUnspent)
        );

        // An authorization that is still open keeps the attempt sending.
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        let before = fx.generation();
        assert_eq!(fx.recorder().expire_due(u64::MAX).unwrap(), 0);
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
        assert_eq!(fx.auth(started.authorization_id).native_release, None);
    }

    /// Commits a sequence release for attempt 1 of `handle`.
    fn release_sequence(fx: &mut Fx, handle: &OperationHandle) {
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 300,
                        witness_ledger: 301,
                        min_close_time_ms: T0 + 5,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap()
            .unwrap();
    }

    /// The sequence-release read finds an attempt by the signed envelope
    /// hash its committed exposure names, for a canonical and for an
    /// envelope record. It answers `true` only once that attempt's release
    /// commits, and `false` for the unsigned envelope digests the records
    /// bind and for a hash no exposure names.
    #[test]
    #[serial]
    fn sequence_releases_reads_by_envelope_hash() {
        let signed = |exposure: ExposureIdentity| match exposure {
            ExposureIdentity::Classic {
                envelope_sha256, ..
            } => AttemptRef::EnvelopeHash(envelope_sha256),
            ExposureIdentity::X402 { .. } => panic!("a classic exposure"),
        };
        let mut fx = Fx::new();
        let canonical_record = unknown_outcome(&mut fx);
        let stored_xdr = fx.record(canonical_record.id()).envelope_xdr.unwrap();
        let stored_text: [u8; 32] = Sha256::digest(stored_xdr.as_bytes()).into();
        let canonical_attempt = signed(classic_exposure(1));

        let envelope_record = fx.open_new(&request("order-2", envelope(9, 2, 0)));
        let mint = fx.mint_request(tx(2), fx.policy(), vec![]);
        let started = fx.begin_mint(&envelope_record, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(envelope_record.id(), 1, &classic_exposure(2), None)
            .unwrap();
        step(
            &mut fx,
            &envelope_record,
            Some(1),
            OperationState::SentOutcomeUnknown,
        );
        let envelope_attempt = signed(classic_exposure(2));
        let unsigned = [
            AttemptRef::EnvelopeHash(stored_text),
            AttemptRef::EnvelopeHash([9; 32]),
            AttemptRef::EnvelopeHash([0x77; 32]),
        ];

        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert!(!status.sequence_released(&canonical_attempt));
        assert!(!status.sequence_released(&envelope_attempt));

        release_sequence(&mut fx, &canonical_record);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert!(status.sequence_released(&canonical_attempt));
        assert!(
            !status.sequence_released(&envelope_attempt),
            "a release names its own attempt"
        );

        release_sequence(&mut fx, &envelope_record);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert!(status.sequence_released(&canonical_attempt));
        assert!(status.sequence_released(&envelope_attempt));
        for other in unsigned {
            assert!(!status.sequence_released(&other), "{other:?}");
        }
    }

    /// An exposed `Sending` attempt never ends as `NotSent` at the expiry
    /// edges, even when its authorization reads as ended unused and never
    /// claimed. The committed exposure means its bytes may have reached the
    /// network.
    #[test]
    #[serial]
    fn an_exposed_sending_attempt_never_recovers_as_not_sent() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let auth_id = exposed_attempt(&mut fx, &handle, 1, &classic_exposure(1));
        let now = fx.now();
        rewrite_auth(&fx, auth_id, |auth| {
            auth.state = AuthorizationState::Invalidated;
            auth.claimed_ms = None;
            auth.settled_ms = Some(now);
            auth.disposition = Some(Disposition::Unused);
        });
        fx.clock.set(T0 + TTL_MS);
        assert_eq!(fx.recorder().expire_due(u64::MAX).unwrap(), 0);
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::Sending);
        assert_eq!(record.attempts[0].outcome, None);
        assert!(record.attempts[0].exposure.is_some());
    }

    #[test]
    #[serial]
    fn claimed_unexposed_attempt_stays_sending() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![hold(40)]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.clock.set(T0 + TTL_MS);
        assert_eq!(fx.recorder().expire_due(u64::MAX).unwrap(), 0);
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::Sending);
        assert_eq!(record.attempts[0].outcome, None);
        let auth = fx.auth(started.authorization_id);
        assert_eq!(auth.state, AuthorizationState::Expired);
        assert_eq!(auth.disposition, None);
        assert_eq!(auth.native_release, None);
    }

    #[test]
    #[serial]
    fn unreleased_reservation_blocks_compaction() {
        let mut fx = Fx::new();
        let protected = fx.open_new(&request("order-1", x402([1; 32])));
        let mint = fx.mint_request(soroban(1), fx.approval(), vec![]);
        let started = fx.begin_mint(&protected, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(
                protected.id(),
                1,
                &ExposureIdentity::X402 {
                    authorization_id: started.authorization_id,
                    auth_entry_sha256: [3; 32],
                    signature_expiration_ledger: 500,
                },
                Some(400),
            )
            .unwrap();
        fx.recorder()
            .transition(
                protected.id(),
                Some(1),
                OperationState::PayloadReleased,
                &TransitionEvidence::default(),
            )
            .unwrap();

        let released = fx.open_new(&request("order-2", canonical(2)));
        let mint = fx.mint_request(tx(2), fx.approval(), vec![]);
        let released_attempt = fx.begin_mint(&released, &mint).unwrap();
        fx.recorder()
            .transition(
                released.id(),
                Some(1),
                OperationState::NotSent,
                &TransitionEvidence::default(),
            )
            .unwrap();
        assert!(
            fx.auth(released_attempt.authorization_id)
                .native_release
                .is_some()
        );

        fx.clock
            .set(T0 + TERMINAL_RETENTION_MS + RETENTION_MS + APPROVAL_MS + 1);
        fx.prune_now();
        let wire = fx.wire();
        assert!(
            records(&wire)
                .iter()
                .any(|record| record.id == protected.id())
        );
        assert!(
            tombstones(&wire)
                .iter()
                .all(|tombstone| tombstone.id != protected.id())
        );
        let kept = fx.auth(started.authorization_id);
        assert_eq!(kept.native_release, None);
        assert!(
            tombstones(&wire)
                .iter()
                .any(|tombstone| tombstone.id == released.id())
        );
        assert!(
            wire.authorizations
                .iter()
                .all(|auth| auth.id != released_attempt.authorization_id)
        );
    }

    /// Settles authorization `id` as a released reservation bounded by
    /// `bound`, settled at `T0`.
    fn release_with(wire: &mut WireFile, id: AuthorizationId, bound: ReleaseBound) {
        let auth = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == id)
            .unwrap();
        auth.state = AuthorizationState::Expired;
        auth.settled_ms = Some(T0);
        auth.native_release = Some(ReleaseRow {
            class: ReleaseClass::Settled,
            bound,
            observed_ledger: Some(4_000),
            commit_id: CommitId::random(),
        });
        wire.holds.retain(|hold| hold.authorization_id != id);
    }

    #[test]
    #[serial]
    fn late_release_ordinary_pruning_raises_floor() {
        let fx = Fx::new();
        let ledger_bound = fx
            .store
            .mint_authorization(
                &fx.profile,
                &fx.mint_request(soroban(1), fx.approval(), vec![]),
            )
            .unwrap();
        let close_bound = fx
            .store
            .mint_authorization(&fx.profile, &fx.mint_request(tx(2), fx.approval(), vec![]))
            .unwrap();
        let always = fx
            .store
            .mint_authorization(&fx.profile, &fx.mint_request(tx(3), fx.approval(), vec![]))
            .unwrap();
        fx.rewrite(|wire| {
            release_with(wire, ledger_bound.id, ReleaseBound::Ledger(5_000));
            release_with(wire, close_bound.id, ReleaseBound::CloseTime(T0 + 9));
            release_with(wire, always.id, ReleaseBound::Always);
        });
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(
            status.admissible_floors().unwrap(),
            AdmissibleFloors::default()
        );

        fx.clock.set(T0 + TERMINAL_RETENTION_MS + 1);
        fx.prune_now();
        let wire = fx.wire();
        assert!(wire.authorizations.is_empty());
        assert_eq!(
            status.admissible_floors().unwrap(),
            AdmissibleFloors {
                ledger: Some(5_000),
                close_time_ms: Some(T0 + 9),
            }
        );

        // A lower bound leaves the floor; a higher one raises it.
        for (bound, expected) in [(4_000, 5_000), (6_000, 6_000)] {
            let later = fx
                .store
                .mint_authorization(
                    &fx.profile,
                    &fx.mint_request(
                        soroban(u8::try_from(bound / 1000).unwrap()),
                        fx.approval(),
                        vec![],
                    ),
                )
                .unwrap();
            fx.rewrite(|wire| release_with(wire, later.id, ReleaseBound::Ledger(bound)));
            let now = fx.now();
            fx.clock.set(now + TERMINAL_RETENTION_MS + APPROVAL_MS);
            fx.prune_now();
            assert_eq!(status.admissible_floors().unwrap().ledger, Some(expected));
        }
    }

    #[test]
    #[serial]
    fn mainnet_reset_clears_the_floors() {
        let mut fx = Fx::new();
        let ended = fx.open_new(&request("order-1", canonical(1)));
        fx.recorder()
            .transition(
                ended.id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        fx.rewrite(|wire| {
            wire.admissible_floor_ledger = Some(9_000);
            wire.admissible_floor_close_time_ms = Some(T0 + 50);
        });
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&fx.profile);
        fx.store
            .reset(
                &fx.profile,
                &name,
                fx.now(),
                "repair",
                "reset-request",
                |row| Ok::<_, ()>(signed_by(11, row)),
                |_, _| Ok(()),
            )
            .unwrap();
        let wire = fx.wire();
        assert_eq!(wire.admissible_floor_ledger, None);
        assert_eq!(wire.admissible_floor_close_time_ms, None);
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .admissible_floors()
                .unwrap(),
            AdmissibleFloors::default()
        );
        assert_eq!(fx.record(ended.id()).state, OperationState::Expired);
    }

    /// A terminal record `n` closed at `closed_at_ms`.
    fn terminal_record(n: u16, closed_at_ms: u64) -> WireOperation {
        let mut record = maximal_record(canonical(1));
        record.id = OperationId::from_bytes({
            let mut bytes = [0u8; 16];
            bytes[..2].copy_from_slice(&n.to_be_bytes());
            bytes
        });
        record.business_id = BusinessId::parse(&format!("order-{n}")).unwrap();
        record.state = OperationState::Expired;
        record.attempts.clear();
        record.history.truncate(1);
        record.closed_at_ms = Some(closed_at_ms);
        record.updated_at_ms = closed_at_ms;
        record
    }

    fn tombstone(n: u16, closed_at_ms: u64) -> WireTombstone {
        terminal_record(n, closed_at_ms).tombstone()
    }

    /// An authorization linking operation `id` without a release row.
    fn unreleased(id: OperationId) -> WireAuthorization {
        let binding = tx(1);
        WireAuthorization {
            id: AuthorizationId::from_bytes([0x61; 32]),
            profile: "ops".to_owned(),
            chain: Caip2::Mainnet,
            domain: AuthorizationDomain::Transaction,
            consumer: MainnetConsumer::CliPay,
            content_digest: binding.content_digest(),
            binding,
            state: AuthorizationState::Expired,
            minted_ms: 0,
            expires_ms: 10,
            settled_ms: Some(5),
            claimed_ms: Some(1),
            policy_sequence: 7,
            policy_digest: [7; 32],
            approval_nonce: Some("n".to_owned()),
            approval_expires_ms: Some(10),
            policy_authority: None,
            bindings_digest: [9; 32],
            entries_digest: [9; 32],
            reservation: None,
            parent: None,
            consumption: None,
            invalidation: None,
            operation: Some(OperationLink {
                operation_id: id,
                attempt_index: 1,
            }),
            disposition: None,
            native_release: None,
            native_reservation: None,
        }
    }

    #[test]
    fn terminal_and_tombstone_retention_evict_oldest_unprotected() {
        let now = T0 + 1_000_000;
        let mut wire = WireFile {
            version: super::super::store::WIRE_VERSION_OPERATIONS,
            chain_scope: Some(ChainScope::for_chain(Caip2::Mainnet)),
            ..WireFile::default()
        };
        let mut section = OperationsSection::default();
        for n in 0..=u16::try_from(TERMINAL_RECORDS_MAX).unwrap() {
            section.records.push(terminal_record(n, T0 + u64::from(n)));
        }
        wire.operations = Some(section);
        let protected = records(&wire)[0].id;
        wire.authorizations.push(unreleased(protected));
        Operations::prune(&mut wire, now);
        let kept: Vec<OperationId> = records(&wire).iter().map(|record| record.id).collect();
        assert_eq!(kept.len(), TERMINAL_RECORDS_MAX);
        assert!(kept.contains(&protected));
        assert_eq!(
            tombstones(&wire)
                .iter()
                .map(|tombstone| tombstone.id)
                .collect::<Vec<_>>(),
            vec![terminal_record(1, 0).id]
        );
        assert_eq!(wire.authorizations.len(), 1);

        // Past the full retention every unprotected record compacts.
        Operations::prune(&mut wire, T0 + TERMINAL_RETENTION_MS + 1_000);
        assert_eq!(
            records(&wire)
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![protected]
        );

        let mut wire = WireFile {
            version: super::super::store::WIRE_VERSION_OPERATIONS,
            chain_scope: Some(ChainScope::for_chain(Caip2::Mainnet)),
            ..WireFile::default()
        };
        let mut section = OperationsSection::default();
        section.tombstones.push(tombstone(9_999, 0));
        for n in 0..=u16::try_from(TOMBSTONES_MAX).unwrap() {
            section.tombstones.push(tombstone(n, T0 + u64::from(n)));
        }
        wire.operations = Some(section);
        Operations::prune(&mut wire, T0 + 2_000);
        let kept = tombstones(&wire);
        assert_eq!(kept.len(), TOMBSTONES_MAX);
        assert!(kept.iter().all(|tombstone| tombstone.closed_at_ms > T0));
        assert_eq!(kept.iter().map(|t| t.closed_at_ms).min(), Some(T0 + 1));

        Operations::prune(
            &mut wire,
            T0 + TOMBSTONE_RETENTION_MS + u64::try_from(TOMBSTONES_MAX).unwrap(),
        );
        assert!(wire.operations.is_none());
    }

    #[test]
    fn history_keeps_the_initial_entry_and_the_latest_31() {
        use OperationState as S;
        let mut record = terminal_record(1, 0);
        record.state = S::Prepared;
        record.closed_at_ms = None;
        record.history = vec![HistoryEntry {
            from: None,
            to: S::Prepared,
            at_ms: 0,
            evidence: None,
        }];
        record.commit_ids.clear();
        let commit = CommitId::random();
        let mut full = record.history.clone();
        let cycle = [S::Sending, S::SentOutcomeUnknown, S::NotIncluded];
        let mut path = vec![S::AwaitingApproval, S::Authorized];
        while path.len() < 40 {
            path.extend(cycle);
        }
        for (at, to) in path.into_iter().enumerate() {
            let at = u64::try_from(at).unwrap() + 1;
            let from = record.state;
            record.step(to, at, Some("step"), commit).unwrap();
            full.push(HistoryEntry {
                from: Some(from),
                to,
                at_ms: at,
                evidence: Some(BoundedText::bound("step", HISTORY_EVIDENCE_MAX)),
            });
        }
        assert_eq!(record.history.len(), HISTORY_MAX);
        assert_eq!(record.history[0], full[0]);
        assert_eq!(record.history[1..], full[full.len() - (HISTORY_MAX - 1)..]);
        assert_eq!(record.commit_ids, vec![commit]);
    }

    #[test]
    #[serial]
    fn history_incomplete_survives_restart_and_eviction() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![outcome_row(1, 10)],
                    recovery: Some(RecoveryUpdate {
                        history_incomplete: true,
                        ..RecoveryUpdate::default()
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        for pass in 0..2_u8 {
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        rows: (0..8_u8)
                            .map(|n| outcome_row(0x20 + pass * 8 + n, 100 + u32::from(n)))
                            .collect(),
                        recovery: Some(RecoveryUpdate {
                            disagreements: pass,
                            ..RecoveryUpdate::default()
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        let record = fx.record(handle.id());
        assert!(
            record.attempts[0]
                .evidence
                .iter()
                .all(|row| row.digest != [1; 32])
        );
        assert!(
            record.attempts[0]
                .recovery
                .as_ref()
                .unwrap()
                .history_incomplete
        );
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let view = OperationStatus::new(&reopened, &fx.profile)
            .view(&BusinessId::parse("order-1").unwrap())
            .unwrap()
            .unwrap();
        assert!(view.history_incomplete);
    }

    #[test]
    #[serial]
    fn evidence_cap_evicts_lowest_ledger_and_keeps_the_watermark() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: (0..8_u8)
                        .map(|n| outcome_row(n, 10 + u32::from(n)))
                        .collect(),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![outcome_row(0x30, 20), outcome_row(0x31, 5)],
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let record = fx.record(handle.id());
        assert_eq!(record.evidence_committed_seq, 10);
        let mut kept: Vec<(u32, u64)> = record.attempts[0]
            .evidence
            .iter()
            .map(|row| (row.observed_ledger, row.evidence_seq))
            .collect();
        kept.sort_unstable();
        assert_eq!(
            kept,
            vec![
                (11, 2),
                (12, 3),
                (13, 4),
                (14, 5),
                (15, 6),
                (16, 7),
                (17, 8),
                (20, 9)
            ]
        );
    }

    #[test]
    #[serial]
    fn record_evidence_appends_one_audit_row_with_a_contiguous_range() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        fx.sink.entries.clear();
        let first = fx
            .recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![outcome_row(1, 10), outcome_row(2, 11)],
                    ..EvidenceInput::default()
                },
            )
            .unwrap()
            .unwrap();
        let second = fx
            .recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![outcome_row(2, 11), outcome_row(3, 12), outcome_row(4, 13)],
                    ..EvidenceInput::default()
                },
            )
            .unwrap()
            .unwrap();
        let before = fx.generation();
        assert_eq!(
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        rows: vec![outcome_row(1, 10)],
                        ..EvidenceInput::default()
                    },
                )
                .unwrap(),
            None
        );
        assert_eq!(fx.generation(), before);
        let release = SequenceReleaseInput {
            primary_ledger: 300,
            witness_ledger: 301,
            min_close_time_ms: T0 + 5,
        };
        let released = fx
            .recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    sequence_released: Some(release),
                    ..EvidenceInput::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        sequence_released: Some(release),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap(),
            None
        );
        assert_eq!(
            evidence_rows(&fx),
            vec![
                (
                    Some(EvidenceSeqRange { first: 1, last: 2 }),
                    vec![1, 2],
                    false,
                    first.to_hex()
                ),
                (
                    Some(EvidenceSeqRange { first: 3, last: 4 }),
                    vec![3, 4],
                    false,
                    second.to_hex()
                ),
                (None, vec![], true, released.to_hex()),
            ]
        );
        let record = fx.record(handle.id());
        assert_eq!(record.evidence_committed_seq, 4);
        let stored = record.attempts[0].sequence_released.clone().unwrap();
        assert_eq!(stored.commit_id, released);
        assert_eq!(
            (
                stored.primary_ledger,
                stored.witness_ledger,
                stored.min_close_time_ms
            ),
            (300, 301, T0 + 5)
        );
    }

    #[test]
    #[serial]
    fn audit_append_failure_commits_nothing() {
        let mut fx = Fx::new();
        fx.sink.fail = true;
        let error = fx.open(&request("order-1", canonical(1))).unwrap_err();
        assert!(matches!(error, WindowStoreError::AuditAppendFailed { .. }));
        assert_eq!(code(&error), "audit.append_failed");
        assert!(!fx.store.path().exists());

        fx.sink.fail = false;
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let before = fs::read(fx.store.path()).unwrap();
        fx.sink.fail = true;
        let error = fx
            .recorder()
            .transition(
                handle.id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap_err();
        assert_eq!(code(&error), "audit.append_failed");
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        assert!(matches!(
            fx.begin_mint(&handle, &mint),
            Err(WindowStoreError::AuditAppendFailed { .. })
        ));
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);
        assert_eq!(fx.record(handle.id()).state, OperationState::Prepared);
        assert!(fx.wire().authorizations.is_empty());
    }

    #[test]
    #[serial]
    fn record_observation_writes_no_audit_row() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        fx.sink.entries.clear();
        let observation = WindowObservation {
            ledger: 700,
            close_time_floor_ms: T0,
            observed_at_ms: T0 + 1,
        };
        fx.recorder().record_observation(observation).unwrap();
        assert_eq!(fx.wire().last_observation, Some(observation));
        let before = fx.generation();
        fx.recorder()
            .record_observation(WindowObservation {
                ledger: 699,
                ..observation
            })
            .unwrap();
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.wire().last_observation, Some(observation));
        assert_eq!(
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        recovery: Some(RecoveryUpdate {
                            disagreements: 2,
                            last_outcome: Some("recovery.evidence_pending".to_owned()),
                            ..RecoveryUpdate::default()
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap(),
            None
        );
        assert_eq!(fx.generation(), before + 1);
        assert!(fx.sink.entries.is_empty());
        assert_eq!(
            fx.record(handle.id()).attempts[0]
                .recovery
                .as_ref()
                .unwrap()
                .disagreements,
            2
        );
    }

    #[test]
    fn evidence_classification_covers_every_case() {
        use EvidenceSequenceClass as C;
        let c1 = CommitId::from_bytes([1; 16]);
        let c2 = CommitId::from_bytes([2; 16]);
        let other = CommitId::from_bytes([3; 16]);
        let release_commit = CommitId::from_bytes([4; 16]);
        let mut record = maximal_record(canonical(1));
        record.evidence_committed_seq = 5;
        record.attempts.truncate(1);
        let attempt = &mut record.attempts[0];
        attempt.index = 1;
        attempt.evidence.truncate(2);
        attempt.evidence[0].evidence_seq = 2;
        attempt.evidence[0].commit_id = c1;
        attempt.evidence[1].evidence_seq = 3;
        attempt.evidence[1].commit_id = c2;
        attempt.sequence_released.as_mut().unwrap().commit_id = release_commit;
        let row = |first: u64, last: u64, commit: CommitId| EvidenceAuditFacts {
            attempt_index: 1,
            evidence_seqs: Some((first, last)),
            sequence_released: false,
            commit_id: commit,
            appended_at_ms: T0,
        };
        let release = |commit: CommitId| EvidenceAuditFacts {
            attempt_index: 1,
            evidence_seqs: None,
            sequence_released: true,
            commit_id: commit,
            appended_at_ms: T0,
        };
        let rows = vec![
            row(2, 2, c1),
            row(3, 3, other),
            row(3, 3, c2),
            row(1, 1, other),
            row(6, 6, other),
            row(7, 8, other),
            release(release_commit),
            release(other),
            EvidenceAuditFacts {
                attempt_index: 2,
                ..row(4, 4, other)
            },
        ];
        let classified = classify(Some(&record), false, &rows, T0);
        let classes: Vec<_> = classified
            .verdicts
            .iter()
            .map(|verdict| match verdict {
                EvidenceVerdict::Retained { sequences, release } => (sequences.clone(), *release),
                other => panic!("expected a retained verdict, got {other:?}"),
            })
            .collect();
        assert_eq!(
            classes,
            vec![
                (vec![(2, C::Committed)], None),
                (vec![(3, C::Superseded)], None),
                (vec![(3, C::Committed)], None),
                (vec![(1, C::Evicted)], None),
                (vec![(6, C::Uncommitted)], None),
                (vec![(7, C::Tampered)], None),
                (vec![], Some(C::Committed)),
                (vec![], Some(C::Uncommitted)),
                (vec![(4, C::Tampered)], None),
            ]
        );
        assert_eq!(
            classified
                .verdicts
                .iter()
                .map(EvidenceVerdict::tampered)
                .collect::<Vec<_>>(),
            vec![false, false, false, false, false, true, false, false, true]
        );
        assert!(classified.unnamed_rows.is_empty());
        assert!(classified.unnamed_releases.is_empty());

        // Without the row that names the retained commit, the other commit's
        // claim and the retained row are tampered, and so is an unnamed
        // release.
        let partial = vec![row(2, 2, c1), row(3, 3, other)];
        let classified = classify(Some(&record), false, &partial, T0);
        assert_eq!(
            classified.verdicts[1],
            EvidenceVerdict::Retained {
                sequences: vec![(3, C::Tampered)],
                release: None
            }
        );
        assert_eq!(classified.unnamed_rows, vec![(1, 3)]);
        assert_eq!(classified.unnamed_releases, vec![1]);

        let old = EvidenceAuditFacts {
            appended_at_ms: T0,
            ..row(2, 2, c1)
        };
        assert_eq!(
            classify(None, true, &[old], T0).verdicts,
            vec![EvidenceVerdict::Compacted]
        );
        assert_eq!(
            classify(None, false, &[old], T0 + TOMBSTONE_RETENTION_MS + 1).verdicts,
            vec![EvidenceVerdict::BeyondRetention]
        );
        assert_eq!(
            classify(None, false, &[old], T0 + 1).verdicts,
            vec![EvidenceVerdict::Orphan]
        );
        assert!(!EvidenceVerdict::Orphan.tampered());
    }

    #[test]
    #[serial]
    fn list_since_returns_open_and_recently_closed() {
        let mut fx = Fx::new();
        let open = fx.open_new(&request("open", canonical(1)));
        let recent = fx.open_new(&request("recent", canonical(2)));
        let old = fx.open_new(&request("old", canonical(3)));
        for (handle, at) in [(&old, T0 + 5), (&recent, T0 + 10)] {
            fx.clock.set(at);
            fx.recorder()
                .transition(
                    handle.id(),
                    None,
                    OperationState::Expired,
                    &TransitionEvidence::default(),
                )
                .unwrap();
        }
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let ids = |views: Vec<OperationView>| {
            let mut ids: Vec<String> = views
                .into_iter()
                .map(|view| format!("{}:{}", view.business_id.as_str(), view.compacted))
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(
            ids(status.list_since(T0 + 10).unwrap()),
            vec!["open:false", "recent:false"]
        );
        assert_eq!(
            ids(status.list_since(T0).unwrap()),
            vec!["old:false", "open:false", "recent:false"]
        );
        assert_eq!(
            status
                .view(&BusinessId::parse("open").unwrap())
                .unwrap()
                .unwrap()
                .operation_id,
            open.id()
        );

        fx.clock.set(T0 + 10 + TERMINAL_RETENTION_MS);
        assert_eq!(
            ids(status.list_since(T0 + 10).unwrap()),
            vec!["open:false", "recent:true"]
        );
    }

    /// Rewrites authorization `id` in the committed window.
    fn rewrite_auth(fx: &Fx, id: AuthorizationId, change: impl FnOnce(&mut WireAuthorization)) {
        fx.rewrite(|wire| {
            change(
                wire.authorizations
                    .iter_mut()
                    .find(|auth| auth.id == id)
                    .unwrap(),
            );
        });
    }

    /// A mint of `binding` under `authority` linked to `handle`'s attempt
    /// `attempt_index`.
    fn linked_mint(
        fx: &Fx,
        handle: &OperationHandle,
        binding: DomainBinding,
        authority: MintAuthority,
        attempt_index: u32,
    ) -> MintRequest {
        let mut request = fx.mint_request(binding, authority, vec![]);
        request.operation = Some(OperationLink {
            operation_id: handle.id(),
            attempt_index,
        });
        request
    }

    /// The committed file's bytes.
    fn file_bytes(fx: &Fx) -> Vec<u8> {
        fs::read(fx.store.path()).unwrap()
    }

    /// Every commit identifier an audit row of either operation kind names.
    fn audited_commits(fx: &Fx) -> Vec<String> {
        fx.sink
            .entries
            .iter()
            .filter_map(|entry| match &entry.event_kind {
                EventKind::OperationTransition { commit_id, .. }
                | EventKind::OperationEvidence { commit_id, .. } => Some(commit_id.clone()),
                _ => None,
            })
            .collect()
    }

    /// Runs `handle`'s first attempt under a claimed policy mint of `tx(n)`
    /// to an exposure of `identity`, and returns the authorization.
    fn exposed_attempt(
        fx: &mut Fx,
        handle: &OperationHandle,
        n: u8,
        identity: &ExposureIdentity,
    ) -> AuthorizationId {
        let mint = fx.mint_request(tx(n), fx.policy(), vec![]);
        let started = fx.begin_mint(handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(handle.id(), started.attempt_index, identity, None)
            .unwrap();
        started.authorization_id
    }

    fn step(fx: &mut Fx, handle: &OperationHandle, attempt: Option<u32>, to: OperationState) {
        fx.recorder()
            .transition(handle.id(), attempt, to, &TransitionEvidence::default())
            .unwrap();
    }

    #[test]
    #[serial]
    fn expose_refuses_an_unclaimed_authorization() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        let before = fx.generation();
        let bytes = file_bytes(&fx);
        let rows = fx.sink.entries.len();
        let error = fx
            .recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("claimed or used")),
            "{error:?}"
        );
        assert_eq!(code(&error), "internal.unexpected_state");
        assert_eq!(fx.generation(), before);
        assert_eq!(file_bytes(&fx), bytes);
        assert_eq!(fx.sink.entries.len(), rows);
        assert_eq!(fx.record(handle.id()).attempts[0].exposure, None);

        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap();
        assert!(fx.record(handle.id()).attempts[0].exposure.is_some());
    }

    /// An authorization a committed exposure names gets no release row from
    /// the expiry sweep or a reset, even when it was never claimed; its record
    /// stays `Sending` or `SentOutcomeUnknown`.
    #[test]
    #[serial]
    fn an_exposed_authorization_expires_without_a_release_row() {
        for unknown in [false, true] {
            let mut fx = Fx::new();
            let handle = fx.open_new(&request("order-1", canonical(1)));
            let auth_id = exposed_attempt(&mut fx, &handle, 1, &classic_exposure(1));
            if unknown {
                step(
                    &mut fx,
                    &handle,
                    Some(1),
                    OperationState::SentOutcomeUnknown,
                );
            }
            let state = fx.record(handle.id()).state;
            rewrite_auth(&fx, auth_id, |auth| {
                auth.state = AuthorizationState::Open;
                auth.claimed_ms = None;
            });

            fx.clock.set(T0 + TTL_MS + 1);
            let now = fx.now();
            fx.recorder().expire_due(now).unwrap();
            assert_eq!(fx.record(handle.id()).state, state, "unknown: {unknown}");
            let expired = fx.auth(auth_id);
            assert_eq!(expired.state, AuthorizationState::Expired);
            assert_eq!(expired.disposition, None, "unknown: {unknown}");
            assert_eq!(expired.native_release, None, "unknown: {unknown}");

            let name = stellar_agent_core::profile::name::profile_name_for_approval(&fx.profile);
            let refused = fx.store.reset(
                &fx.profile,
                &name,
                now,
                "repair",
                "reset-request",
                |_| Ok::<_, ()>(ResetConsent::default()),
                |_, _| Ok(()),
            );
            assert!(
                matches!(
                    refused,
                    Err(ResetError::Store {
                        error: WindowStoreError::OperationsOpen { open: 1 },
                        ..
                    })
                ),
                "{refused:?}"
            );
            assert_eq!(fx.record(handle.id()).state, state, "unknown: {unknown}");
            assert_eq!(fx.auth(auth_id).native_release, None, "unknown: {unknown}");
        }
    }

    /// A reset of an ended operation keeps an exposed authorization that
    /// still holds capacity without a release row.
    #[test]
    #[serial]
    fn a_reset_writes_no_row_for_an_exposed_authorization() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let auth_id = exposed_attempt(&mut fx, &handle, 1, &classic_exposure(1));
        step(
            &mut fx,
            &handle,
            Some(1),
            OperationState::SentOutcomeUnknown,
        );
        step(&mut fx, &handle, Some(1), OperationState::Expired);
        let mut wire = fx.wire();
        let auth = wire
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == auth_id)
            .unwrap();
        auth.state = AuthorizationState::Open;
        auth.claimed_ms = None;
        let survivors = super::super::ledger::reset_survivors(&wire, fx.now());
        let kept = survivors.iter().find(|auth| auth.id == auth_id).unwrap();
        assert_eq!(kept.state, AuthorizationState::Expired);
        assert_eq!(kept.disposition, None);
        assert_eq!(kept.native_release, None);
    }

    /// An approval nonce whose earlier authorization was claimed carries no
    /// remint, even after that authorization expired.
    #[test]
    #[serial]
    fn remint_refuses_after_a_claimed_expired_carrier() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let authority = fx.approval();
        let carrier = linked_mint(&fx, &handle, tx(1), authority.clone(), 1);
        let minted = fx.store.mint_authorization(&fx.profile, &carrier).unwrap();
        fx.claim(&carrier, &minted);
        fx.clock.set(T0 + TTL_MS + 1);
        let before = fx.generation();
        let bytes = file_bytes(&fx);
        let remint = fx.mint_request(tx(2), authority, vec![]);
        let error = fx.begin_mint(&handle, &remint).unwrap_err();
        assert!(
            matches!(
                error,
                WindowStoreError::AuthorizationRefused {
                    precondition: MainnetPrecondition::ApprovalNonceReused
                }
            ),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(file_bytes(&fx), bytes);
        assert_eq!(fx.record(handle.id()).attempts.len(), 0);
    }

    #[test]
    #[serial]
    fn sent_outcome_unknown_needs_a_committed_exposure() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        let before = fx.generation();
        let error = fx
            .recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::SentOutcomeUnknown,
                &TransitionEvidence::default(),
            )
            .unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("committed exposure")),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
        fx.recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap();
        step(
            &mut fx,
            &handle,
            Some(1),
            OperationState::SentOutcomeUnknown,
        );
        assert_eq!(
            fx.record(handle.id()).state,
            OperationState::SentOutcomeUnknown
        );
    }

    #[test]
    #[serial]
    fn payload_released_needs_a_committed_exposure() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        let before = fx.generation();
        let error = fx
            .recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::PayloadReleased,
                &TransitionEvidence::default(),
            )
            .unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("committed exposure")),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
        fx.recorder()
            .expose(handle.id(), 1, &classic_exposure(1), None)
            .unwrap();
        step(&mut fx, &handle, Some(1), OperationState::PayloadReleased);
        assert_eq!(
            fx.record(handle.id()).state,
            OperationState::PayloadReleased
        );
    }

    /// A linked authorization its holder invalidated gets its release row in
    /// the commit that ends its operation; seven days and one retention later
    /// the record compacts and the authorization is pruned.
    #[test]
    #[serial]
    fn an_invalidated_linked_authorization_is_released_when_its_operation_ends() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let linked = linked_mint(&fx, &handle, tx(1), fx.approval(), 1);
        let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        assert!(
            fx.store
                .invalidate_authorization(&fx.profile, minted.id, "abandoned")
                .unwrap()
        );
        let invalidated = fx.auth(minted.id);
        assert_eq!(invalidated.state, AuthorizationState::Invalidated);
        assert_eq!(invalidated.native_release, None);

        fx.recorder()
            .transition(
                handle.id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let commit = *fx.record(handle.id()).commit_ids.last().unwrap();
        let released = fx.auth(minted.id);
        assert_eq!(released.state, AuthorizationState::Invalidated);
        assert_eq!(released.disposition, Some(Disposition::Unused));
        assert_eq!(
            released.native_release,
            Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit))
        );

        fx.clock
            .set(T0 + TERMINAL_RETENTION_MS + RETENTION_MS + APPROVAL_MS + 1);
        fx.prune_now();
        let wire = fx.wire();
        let section = wire.operations.as_ref().unwrap();
        assert!(section.records.is_empty());
        assert_eq!(
            section
                .tombstones
                .iter()
                .map(|tombstone| tombstone.id)
                .collect::<Vec<_>>(),
            vec![handle.id()]
        );
        assert!(wire.authorizations.iter().all(|auth| auth.id != minted.id));
    }

    /// A waiting record whose waiting expiry passed refuses a new attempt
    /// without a write; adoption through a linked open authorization still
    /// starts one.
    #[test]
    #[serial]
    fn begin_attempt_refuses_after_the_waiting_expiry() {
        let mut fx = Fx::new();
        let mut open = request("order-1", canonical(1));
        open.rule_ttl_ms = Some(300_000);
        let handle = fx.open_new(&open);
        fx.clock.set(T0 + 400_000);
        let before = fx.generation();
        let bytes = file_bytes(&fx);
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let error = fx.begin_mint(&handle, &mint).unwrap_err();
        assert!(
            matches!(
                error,
                WindowStoreError::AuthorizationRefused {
                    precondition: MainnetPrecondition::Expired
                }
            ),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(file_bytes(&fx), bytes);
        assert_eq!(fx.record(handle.id()).state, OperationState::Prepared);

        let mut open = request("order-2", canonical(2));
        open.rule_ttl_ms = Some(300_000);
        let adopted = fx.open_new(&open);
        fx.clock.set(T0 + 699_000);
        let linked = linked_mint(&fx, &adopted, tx(2), fx.approval(), 1);
        let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        fx.clock.set(T0 + 701_000);
        let started = fx
            .recorder()
            .begin_attempt(
                &adopted,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "AAAAENVELOPE".to_owned(),
                        unsigned_envelope_sha256: [2; 32],
                    }),
                    authorization: AttemptAuthorization::Linked,
                    send_by_ms: u64::MAX,
                },
            )
            .unwrap();
        assert_eq!(started.authorization_id, minted.id);
        assert_eq!(fx.record(adopted.id()).state, OperationState::Sending);
    }

    /// The operator clear writes the unknown release row in its own commit:
    /// `Always` for an exposure without `max_time`, `CloseTime` at `max_time`
    /// in milliseconds for one with it. Each form refuses the other exposure,
    /// and a cancellation without a clear refuses.
    #[test]
    #[serial]
    fn clear_writes_the_unknown_row_in_its_commit() {
        let bounded = ExposureIdentity::Classic {
            envelope_sha256: [0x5b; 32],
            tx_hash: [0x81; 32],
            sequence: 101,
            max_time: 1_800_000_900,
            receipt: stellar_agent_core::hex::encode(&[0x5b; 32]),
        };
        for (identity, form, wrong, bound) in [
            (
                classic_exposure(1),
                ClearForm::Untimed,
                ClearForm::Timed,
                ReleaseBound::Always,
            ),
            (
                bounded,
                ClearForm::Timed,
                ClearForm::Untimed,
                ReleaseBound::CloseTime(1_800_000_900_000),
            ),
        ] {
            let mut fx = Fx::new();
            let handle = fx.open_new(&request("order-1", canonical(1)));
            let auth_id = exposed_attempt(&mut fx, &handle, 1, &identity);
            step(
                &mut fx,
                &handle,
                Some(1),
                OperationState::SentOutcomeUnknown,
            );
            let before = fx.generation();
            for clear in [None, Some(wrong)] {
                let error = fx
                    .recorder()
                    .transition(
                        handle.id(),
                        Some(1),
                        OperationState::Cancelled,
                        &TransitionEvidence {
                            clear,
                            ..TransitionEvidence::default()
                        },
                    )
                    .unwrap_err();
                assert_eq!(code(&error), "internal.unexpected_state", "{clear:?}");
                assert_eq!(fx.generation(), before, "{clear:?}");
                assert_eq!(fx.auth(auth_id).native_release, None, "{clear:?}");
            }
            let commit = fx
                .recorder()
                .transition(
                    handle.id(),
                    Some(1),
                    OperationState::Cancelled,
                    &TransitionEvidence {
                        clear: Some(form),
                        ..TransitionEvidence::default()
                    },
                )
                .unwrap();
            assert_eq!(fx.record(handle.id()).state, OperationState::Cancelled);
            assert_eq!(fx.record(handle.id()).commit_ids.last(), Some(&commit));
            assert_eq!(
                fx.auth(auth_id).native_release,
                Some(ReleaseRow {
                    class: ReleaseClass::Unknown,
                    bound,
                    observed_ledger: None,
                    commit_id: commit,
                }),
                "{form:?}"
            );
        }
    }

    /// An unknown outcome keeps its reservation unreleased through expiry
    /// passes and every other step until the operator clear.
    #[test]
    #[serial]
    fn no_unknown_row_without_the_clear() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let auth_id = fx.record(handle.id()).attempts[0].authorization_id;
        fx.clock.set(T0 + TERMINAL_RETENTION_MS);
        let now = fx.now();
        fx.recorder().expire_due(now).unwrap();
        fx.prune_now();
        assert_eq!(
            fx.record(handle.id()).state,
            OperationState::SentOutcomeUnknown
        );
        assert_eq!(fx.auth(auth_id).native_release, None);
        let error = fx
            .recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::Cancelled,
                &TransitionEvidence::default(),
            )
            .unwrap_err();
        assert_eq!(code(&error), "internal.unexpected_state");
        assert_eq!(fx.auth(auth_id).native_release, None);
    }

    /// Writers that keep no operation audit leave the authorizations of a
    /// record that has not ended untouched, so every commit identifier a
    /// record holds has its audit row after another operation's mint, an
    /// expiry pass and a reset.
    #[test]
    #[serial]
    fn transition_rows_match_commit_ids() {
        let mut fx = Fx::new();
        let waiting = fx.open_new(&request("order-1", canonical(1)));
        let mut linked = linked_mint(&fx, &waiting, tx(1), fx.approval(), 1);
        linked.holds = vec![hold(10)];
        let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();

        fx.clock.set(T0 + TTL_MS + 1);
        let other = fx.mint_request(tx(0x40), fx.approval(), vec![]);
        fx.store.mint_authorization(&fx.profile, &other).unwrap();
        assert_eq!(fx.record(waiting.id()).state, OperationState::Prepared);
        let untouched = fx.auth(minted.id);
        assert_eq!(untouched.state, AuthorizationState::Open);
        assert_eq!(untouched.native_release, None);
        assert!(
            fx.wire()
                .holds
                .iter()
                .any(|hold| hold.authorization_id == minted.id)
        );

        let now = fx.now();
        fx.recorder().expire_due(now).unwrap();
        assert_eq!(fx.record(waiting.id()).state, OperationState::Authorized);
        fx.clock.set(T0 + APPROVAL_MS + 1);
        let now = fx.now();
        fx.recorder().expire_due(now).unwrap();
        assert_eq!(fx.record(waiting.id()).state, OperationState::Expired);
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&fx.profile);
        fx.store
            .reset(
                &fx.profile,
                &name,
                now,
                "repair",
                "reset-request",
                |row| Ok::<_, ()>(signed_by(11, row)),
                |_, _| Ok(()),
            )
            .unwrap();

        let audited = audited_commits(&fx);
        let wire = fx.wire();
        for record in records(&wire) {
            for commit in &record.commit_ids {
                assert!(
                    audited.contains(&commit.to_hex()),
                    "{} has no audit row for {commit:?}",
                    record.business_id.as_str()
                );
            }
        }
        assert_eq!(records(&wire).len(), 1);
    }

    /// A claimed authorization linked to an operation that has not ended
    /// stays through one more full retention after it expired.
    #[test]
    #[serial]
    fn a_claimed_expired_link_outlives_the_retention() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.clock.set(T0 + TTL_MS + 1);
        let now = fx.now();
        fx.recorder().expire_due(now).unwrap();
        let expired = fx.auth(started.authorization_id);
        assert_eq!(expired.state, AuthorizationState::Expired);
        assert_eq!(expired.native_release, None);

        fx.clock
            .set(T0 + TTL_MS + 1 + RETENTION_MS + APPROVAL_MS + 1);
        fx.prune_now();
        assert!(
            fx.wire()
                .authorizations
                .iter()
                .any(|auth| auth.id == started.authorization_id)
        );
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
    }

    /// A reset after a linked authorization's authority ended keeps it while
    /// it has no release row.
    #[test]
    #[serial]
    fn a_reset_keeps_a_link_whose_authority_ended() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let auth_id = exposed_attempt(&mut fx, &handle, 1, &classic_exposure(1));
        step(
            &mut fx,
            &handle,
            Some(1),
            OperationState::SentOutcomeUnknown,
        );
        step(&mut fx, &handle, Some(1), OperationState::Expired);
        fx.clock.set(T0 + APPROVAL_MS + 1);
        let now = fx.now();
        assert!(fx.auth(auth_id).authority_end_ms() <= now);
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&fx.profile);
        fx.store
            .reset(
                &fx.profile,
                &name,
                now,
                "repair",
                "reset-request",
                |row| Ok::<_, ()>(signed_by(11, row)),
                |_, _| Ok(()),
            )
            .unwrap();
        let wire = fx.wire();
        let kept = wire.authorizations.iter().find(|auth| auth.id == auth_id);
        assert!(kept.is_some(), "the reset dropped the linked authorization");
        assert_eq!(kept.and_then(|auth| auth.native_release), None);
        assert_eq!(fx.record(handle.id()).state, OperationState::Expired);
    }

    #[test]
    #[serial]
    fn an_exposed_unknown_outcome_expires_without_a_row() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let auth_id = fx.record(handle.id()).attempts[0].authorization_id;
        step(&mut fx, &handle, Some(1), OperationState::Expired);
        assert_eq!(fx.record(handle.id()).state, OperationState::Expired);
        let auth = fx.auth(auth_id);
        assert_eq!(auth.disposition, None);
        assert_eq!(auth.native_release, None);
    }

    /// An expiry pass over an ended record leaves an open authorization an
    /// exposure names without a release row.
    #[test]
    #[serial]
    fn expire_due_keeps_an_exposed_open_link_of_an_ended_record() {
        let mut fx = Fx::new();
        let handle = unknown_outcome(&mut fx);
        let auth_id = fx.record(handle.id()).attempts[0].authorization_id;
        step(&mut fx, &handle, Some(1), OperationState::Expired);
        rewrite_auth(&fx, auth_id, |auth| {
            auth.state = AuthorizationState::Open;
            auth.claimed_ms = None;
        });
        let now = fx.now();
        fx.recorder().expire_due(now).unwrap();
        let auth = fx.auth(auth_id);
        assert_eq!(auth.state, AuthorizationState::Open);
        assert_eq!(auth.disposition, None);
        assert_eq!(auth.native_release, None);
    }

    /// An exposed `Sending` attempt stays `Sending` once its authorization
    /// ended unused.
    #[test]
    #[serial]
    fn an_exposed_sending_attempt_stays_sending_after_its_authorization_ended() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        let auth_id = exposed_attempt(&mut fx, &handle, 1, &classic_exposure(1));
        let now = fx.now();
        rewrite_auth(&fx, auth_id, |auth| {
            auth.state = AuthorizationState::Expired;
            auth.claimed_ms = None;
            auth.settled_ms = Some(now);
            auth.disposition = Some(Disposition::Unused);
        });
        fx.recorder().expire_due(now).unwrap();
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
        assert_eq!(fx.auth(auth_id).native_release, None);
    }

    #[test]
    #[serial]
    fn a_mint_linking_an_ended_operation_refuses() {
        let mut fx = Fx::new();
        let handle = fx.open_new(&request("order-1", canonical(1)));
        step(&mut fx, &handle, None, OperationState::Expired);
        let before = fx.generation();
        let bytes = file_bytes(&fx);
        let linked = linked_mint(&fx, &handle, tx(1), fx.approval(), 1);
        let error = fx
            .store
            .mint_authorization(&fx.profile, &linked)
            .unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("ended operation")),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(file_bytes(&fx), bytes);
    }

    /// A mint link names the operation's next attempt and no other.
    #[test]
    #[serial]
    fn a_mint_link_names_the_next_attempt() {
        let mut fx = Fx::new();
        let fresh = fx.open_new(&request("order-1", canonical(1)));
        let before = fx.generation();
        let bytes = file_bytes(&fx);
        let ahead = linked_mint(&fx, &fresh, tx(1), fx.approval(), 2);
        let error = fx
            .store
            .mint_authorization(&fx.profile, &ahead)
            .unwrap_err();
        assert!(
            matches!(&error, WindowStoreError::UnexpectedState { detail } if detail.contains("next one")),
            "{error:?}"
        );
        assert_eq!(fx.generation(), before);
        assert_eq!(file_bytes(&fx), bytes);
        let next = linked_mint(&fx, &fresh, tx(1), fx.approval(), 1);
        fx.store.mint_authorization(&fx.profile, &next).unwrap();

        let retried = fx.open_new(&request("order-2", canonical(2)));
        fx.not_included_attempt(&retried, 2);
        let current = linked_mint(&fx, &retried, tx(3), fx.policy(), 1);
        let error = fx
            .store
            .mint_authorization(&fx.profile, &current)
            .unwrap_err();
        assert_eq!(code(&error), "internal.unexpected_state");
        let successor = linked_mint(&fx, &retried, tx(4), fx.policy(), 2);
        fx.store
            .mint_authorization(&fx.profile, &successor)
            .unwrap();
    }

    /// A reset counts a record the expiry edges end at its clock as ended,
    /// keeps it and the authorizations it links as stored, and the next
    /// operation step commits the expiry and the adoption with their audit
    /// rows.
    #[test]
    #[serial]
    fn reset_counts_a_record_its_expiry_edge_ends() {
        let mut fx = Fx::new();
        let mut open = request("order-1", canonical(1));
        open.rule_ttl_ms = Some(300_000);
        let waiting = fx.open_new(&open);
        let adopted = fx.open_new(&request("order-2", canonical(2)));
        let linked = linked_mint(&fx, &adopted, tx(2), fx.approval(), 1);
        let minted = fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        let stored = [fx.record(waiting.id()), fx.record(adopted.id())];
        let link = fx.auth(minted.id);
        fx.clock.set(T0 + APPROVAL_MS);
        let now = fx.now();
        let name = stellar_agent_core::profile::name::profile_name_for_approval(&fx.profile);
        fx.store
            .reset(
                &fx.profile,
                &name,
                now,
                "repair",
                "reset-request",
                |row| Ok::<_, ()>(signed_by(11, row)),
                |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!([fx.record(waiting.id()), fx.record(adopted.id())], stored);
        assert_eq!(fx.auth(minted.id), link);

        assert_eq!(fx.recorder().expire_due(now).unwrap(), 2);
        let audited = audited_commits(&fx);
        for id in [waiting.id(), adopted.id()] {
            let expired = fx.record(id);
            assert_eq!(expired.state, OperationState::Expired);
            for commit in &expired.commit_ids {
                assert!(audited.contains(&commit.to_hex()));
            }
        }
        assert_eq!(
            fx.record(adopted.id()).history[1].to,
            OperationState::Authorized
        );
        let released = fx.auth(minted.id);
        assert_eq!(released.disposition, Some(Disposition::Unused));
        assert!(released.native_release.is_some());
    }

    // ── Checked recovery decisions ───────────────────────────────────────

    /// The signed envelope text of attempt `n`; its SHA-256 is the
    /// exposure's envelope digest.
    pub(crate) fn envelope_text(n: u8) -> String {
        format!("AAAAENVELOPE{n:02}")
    }

    /// The window id of attempt `n`'s reservation records.
    pub(crate) fn envelope_id(n: u8) -> String {
        stellar_agent_core::hex::encode(&Sha256::digest(envelope_text(n)))
    }

    /// An unknown classic attempt of `order-{n}` with native amounts 25 and
    /// fee 100. Its envelope id names a native record of 25 and a `usdc`
    /// record of 40; it holds a native entry and a committed sequence
    /// release. Returns the handle and the attempt's outcome-stage snapshot.
    pub(crate) fn decided_attempt(fx: &mut Fx, n: u8) -> (OperationHandle, RecoveryAttempt) {
        let handle = fx.open_new(&request(&format!("order-{n}"), canonical(n)));
        let mut mint = fx.mint_request(tx(n), fx.policy(), vec![hold(5)]);
        mint.native_reservation = Some(super::super::ledger::NativeReservation {
            debit_stroops: 25,
            fee_stroops: 100,
        });
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        let exposure = ExposureIdentity::Classic {
            envelope_sha256: Sha256::digest(envelope_text(n)).into(),
            tx_hash: [n ^ 0x80; 32],
            sequence: 100 + i64::from(n),
            max_time: T0 / 1_000 + 60,
            receipt: envelope_id(n),
        };
        fx.recorder()
            .expose(handle.id(), started.attempt_index, &exposure, Some(10))
            .unwrap();
        fx.recorder()
            .transition(
                handle.id(),
                Some(started.attempt_index),
                OperationState::SentOutcomeUnknown,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let id = envelope_id(n);
        fx.rewrite(|wire| {
            let scope = wire.chain_scope;
            for (bucket, amount) in [("native", 25), ("usdc", 40)] {
                let key = StateKey::new("ops", 1, bucket, 86_400);
                super::super::store::find_or_insert_bucket(&mut wire.entries, &key)
                    .records
                    .push(super::super::store::WireRecord {
                        chain_scope: scope,
                        ts_ms: T0,
                        amount,
                        id: id.clone(),
                        status: super::super::store::RecordStatus::Pending,
                        tx_hash: stellar_agent_core::hex::encode(&[n ^ 0x80; 32]),
                        source: SOURCE.to_owned(),
                        sequence: 100 + i64::from(n),
                        pending_since_ms: T0,
                        ..super::super::store::WireRecord::confirmed_defaults()
                    });
            }
        });
        fx.recorder()
            .record_evidence(
                handle.id(),
                started.attempt_index,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 90,
                        witness_ledger: 91,
                        min_close_time_ms: T0,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let attempt = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[n ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        (handle, attempt)
    }

    /// The outcome both endpoints agree on for attempt `n`.
    pub(crate) fn agreed(n: u8, status: &str) -> AgreedOutcome {
        AgreedOutcome {
            status: status.to_owned(),
            ledger: 120,
            created_at: T0 / 1_000 - 30,
            result_xdr: "AAAB".to_owned(),
            envelope_xdr_sha256: Sha256::digest(envelope_text(n)).into(),
        }
    }

    /// A decision about `attempt` under evidence digest `[0xd1; 32]` and
    /// deciding ledgers 130 and 131, carrying three disagreements.
    pub(crate) fn decide(
        attempt: &RecoveryAttempt,
        transition: DecidedTransition,
    ) -> CheckedRecoveryDecision {
        CheckedRecoveryDecision::new(
            attempt,
            [0xd1; 32],
            (130, 131),
            transition,
            RecoveryUpdate {
                disagreements: 3,
                last_outcome: Some("concurring".to_owned()),
                ..attempt.recovery.clone()
            },
        )
        .unwrap()
    }

    /// The bucket, status, amount and timestamp of each record of
    /// attempt `n`'s reservation.
    pub(in crate::policy_state) fn bucket_rows(
        fx: &Fx,
        n: u8,
    ) -> Vec<(String, super::super::store::RecordStatus, i128, u64)> {
        let id = envelope_id(n);
        fx.wire()
            .entries
            .iter()
            .flat_map(|bucket| {
                bucket
                    .records
                    .iter()
                    .filter(|record| record.id == id)
                    .map(|record| {
                        (
                            bucket.bucket.clone(),
                            record.status,
                            record.amount,
                            record.ts_ms,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn transition_rows(fx: &Fx) -> Vec<EventKind> {
        fx.sink
            .entries
            .iter()
            .filter(|entry| matches!(entry.event_kind, EventKind::OperationTransition { .. }))
            .map(|entry| entry.event_kind.clone())
            .collect()
    }

    pub(crate) fn not_included_proof() -> NotIncludedProof {
        NotIncludedProof::AccountSequence {
            primary: EndpointCoverage {
                first_ledger: 10,
                last_ledger: 140,
                latest_ledger: 140,
                oldest_ledger: 1,
            },
            witness: EndpointCoverage {
                first_ledger: 10,
                last_ledger: 141,
                latest_ledger: 141,
                oldest_ledger: 1,
            },
        }
    }

    /// Counting follows each row's bound. Absent observations keep bounded
    /// rows, `Always` releases at once, and both equalities release. An
    /// older observation keeps the row, and the stored observation stands
    /// in for a caller that passes none.
    #[test]
    #[serial]
    fn recovery_release_counting_boundaries() {
        let mut fx = Fx::new();
        let (_handle, attempt) = decided_attempt(&mut fx, 1);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(status.native_reserved_stroops(None).unwrap(), 125);
        fx.recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::Succeeded(agreed(1, "SUCCESS")),
            ))
            .unwrap();
        let at = |ledger: u32, close: u64| WindowObservation {
            ledger,
            close_time_floor_ms: close,
            observed_at_ms: T0,
        };
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(status.native_reserved_stroops(None).unwrap(), 125);
        assert_eq!(
            status
                .native_reserved_stroops(Some(at(119, u64::MAX)))
                .unwrap(),
            125
        );
        assert_eq!(status.native_reserved_stroops(Some(at(120, 0))).unwrap(), 0);
        fx.recorder().record_observation(at(120, T0)).unwrap();
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            0
        );
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .native_reserved_stroops(Some(at(119, T0)))
                .unwrap(),
            125
        );
        fx.rewrite(|wire| {
            for auth in &mut wire.authorizations {
                if let Some(row) = &mut auth.native_release {
                    row.bound = ReleaseBound::CloseTime(T0 + 500);
                    row.observed_ledger = None;
                }
            }
        });
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(
            status
                .native_reserved_stroops(Some(at(u32::MAX, T0 + 499)))
                .unwrap(),
            125
        );
        assert_eq!(
            status
                .native_reserved_stroops(Some(at(0, T0 + 500)))
                .unwrap(),
            0
        );
        fx.rewrite(|wire| {
            for auth in &mut wire.authorizations {
                auth.native_release = Some(ReleaseRow::always(
                    ReleaseClass::ProvedUnspent,
                    CommitId::from_bytes([9; 16]),
                ));
            }
        });
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .native_reserved_stroops(Some(at(0, 0)))
                .unwrap(),
            0
        );
    }

    /// A commit that stops before its generation commit point leaves the
    /// complete old state; its appended row names a commit the record does
    /// not retain. An append failure persists nothing.
    #[test]
    #[serial]
    fn recovery_transition_before_commit_point_keeps_old_state() {
        use super::super::store::{COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault};
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let decision = decide(&attempt, DecidedTransition::Succeeded(agreed(1, "SUCCESS")));
        let before = fx.wire();
        fx.sink.fail = true;
        assert_eq!(
            code(&fx.recorder().commit_decision(&decision).unwrap_err()),
            "audit.append_failed"
        );
        fx.sink.fail = false;
        assert_eq!(
            serde_json::to_vec(&fx.wire()).unwrap(),
            serde_json::to_vec(&before).unwrap()
        );
        let rows_before = fx.sink.entries.len();
        let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
        assert!(fx.recorder().commit_decision(&decision).is_err());
        drop(armed);
        assert_eq!(fx.sink.entries.len(), rows_before + 1);
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let wire = reopened.read_for_inspection(&fx.profile).unwrap().unwrap();
        assert_eq!(wire.generation, before.generation);
        let record = records(&wire).iter().find(|r| r.id == handle.id()).unwrap();
        assert_eq!(record.state, OperationState::SentOutcomeUnknown);
        assert!(record.attempts[0].decision.is_none());
        assert!(record.attempts[0].agreed_outcome.is_none());
        assert!(
            wire.authorizations
                .iter()
                .all(|auth| auth.native_release.is_none())
        );
        assert_eq!(
            bucket_rows(&fx, 1)
                .iter()
                .map(|row| row.1)
                .collect::<Vec<_>>(),
            vec![super::super::store::RecordStatus::Pending; 2]
        );
        let EventKind::OperationTransition { commit_id, .. } =
            &fx.sink.entries.last().unwrap().event_kind
        else {
            panic!("a transition row");
        };
        assert!(!record.commit_ids.iter().any(|id| &id.to_hex() == commit_id));
        // The same decision commits once the seam is gone.
        fx.recorder().commit_decision(&decision).unwrap();
        assert_eq!(fx.record(handle.id()).state, OperationState::Succeeded);
    }

    /// A commit that stops after its counter moves reopens the complete new
    /// state: outcome, decision, accounting and release row together.
    #[test]
    #[serial]
    fn recovery_transition_after_commit_point_reopens_new_state() {
        use super::super::store::{COMMIT_FAULT_AFTER_COUNTER, arm_accounting_fault};
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let decision = decide(
            &attempt,
            DecidedTransition::NotIncluded(not_included_proof()),
        );
        let before = fx.wire().generation;
        let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
        let _ = fx.recorder().commit_decision(&decision);
        drop(armed);
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let wire = reopened.read_for_inspection(&fx.profile).unwrap().unwrap();
        assert_eq!(wire.generation, before + 1);
        let record = records(&wire).iter().find(|r| r.id == handle.id()).unwrap();
        assert_eq!(record.state, OperationState::NotIncluded);
        let decided = record.attempts[0].decision.as_ref().unwrap();
        assert_eq!(record.last_commit_id, Some(decided.commit_id));
        assert_eq!(record.attempts[0].not_included, Some(not_included_proof()));
        assert!(bucket_rows(&fx, 1).is_empty());
        let auth = &wire.authorizations[0];
        assert_eq!(
            auth.native_release,
            Some(ReleaseRow::always(
                ReleaseClass::ProvedUnspent,
                decided.commit_id
            ))
        );
    }

    /// A checked non-inclusion of an attempt whose authorization is still
    /// claimed releases the reservation records and writes the
    /// `proved_unspent` row. The claimed authorization keeps its state and
    /// its holds.
    #[test]
    #[serial]
    fn recovery_non_inclusion_keeps_a_claimed_authorizations_holds() {
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let auth_id = fx.record(handle.id()).attempts[0].authorization_id;
        let holds_before: Vec<_> = fx
            .wire()
            .holds
            .into_iter()
            .filter(|hold| hold.authorization_id == auth_id)
            .collect();
        assert!(!holds_before.is_empty());
        let commit = fx
            .recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::NotIncluded(not_included_proof()),
            ))
            .unwrap();
        let wire = fx.wire();
        let holds_after: Vec<_> = wire
            .holds
            .iter()
            .filter(|hold| hold.authorization_id == auth_id)
            .cloned()
            .collect();
        assert_eq!(holds_after, holds_before);
        let auth = fx.auth(auth_id);
        assert_eq!(auth.state, AuthorizationState::Claimed);
        assert_eq!(
            auth.native_release,
            Some(ReleaseRow::always(ReleaseClass::ProvedUnspent, commit))
        );
        assert!(bucket_rows(&fx, 1).is_empty());
    }

    /// Stale generations, substituted attempts or envelopes, a
    /// non-inclusion without its sequence release and direct proofs all
    /// refuse and write nothing.
    #[test]
    #[serial]
    fn recovery_checked_decision_refuses_stale_substituted_or_direct_proofs() {
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let success = DecidedTransition::Succeeded(agreed(1, "SUCCESS"));
        let refusals: Vec<(&str, CheckedRecoveryDecision)> = vec![
            ("stale", {
                let mut stale = attempt.clone();
                stale.generation -= 1;
                decide(&stale, success.clone())
            }),
            ("another attempt", {
                let mut other = attempt.clone();
                other.attempt_index = 2;
                decide(&other, success.clone())
            }),
            ("another envelope", {
                let mut other = attempt.clone();
                other.exposure = classic_exposure(1);
                decide(&other, success.clone())
            }),
            ("another operation", {
                let mut other = attempt.clone();
                other.operation_id = OperationId::from_bytes([0xee; 16]);
                decide(&other, success.clone())
            }),
            (
                "outcome of another envelope",
                decide(&attempt, DecidedTransition::Succeeded(agreed(2, "SUCCESS"))),
            ),
            (
                "negative fee",
                decide(
                    &attempt,
                    DecidedTransition::Failed {
                        outcome: agreed(1, "FAILED"),
                        fee_charged: -1,
                    },
                ),
            ),
        ];
        let before = fs::read(fx.store.path()).unwrap();
        for (label, decision) in &refusals {
            assert!(fx.recorder().commit_decision(decision).is_err(), "{label}");
            assert_eq!(fs::read(fx.store.path()).unwrap(), before, "{label}");
        }
        let direct = fx
            .recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::Succeeded,
                &TransitionEvidence {
                    agreed_outcome: Some(agreed(1, "SUCCESS")),
                    ..TransitionEvidence::default()
                },
            )
            .unwrap_err();
        assert_eq!(code(&direct), "internal.unexpected_state");
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);
        for (to, not_included) in [
            (OperationState::NotIncluded, Some(proof())),
            (OperationState::NotIncluded, None),
            (OperationState::Cancelled, Some(proof())),
        ] {
            let direct = fx
                .recorder()
                .transition(
                    handle.id(),
                    Some(1),
                    to,
                    &TransitionEvidence {
                        not_included,
                        clear: Some(ClearForm::Untimed),
                        ..TransitionEvidence::default()
                    },
                )
                .unwrap_err();
            assert_eq!(code(&direct), "internal.unexpected_state", "{to:?}");
            assert_eq!(fs::read(fx.store.path()).unwrap(), before);
        }

        let (_other, unreleased) = {
            let handle = unknown_named(&mut fx, 3);
            let attempt = OperationStatus::new(&fx.store, &fx.profile)
                .outcome_snapshot(Some(&[3 ^ 0x80; 32]))
                .unwrap()
                .pop()
                .unwrap();
            (handle, attempt)
        };
        assert!(unreleased.sequence_release.is_none());
        let before = fs::read(fx.store.path()).unwrap();
        assert!(
            fx.recorder()
                .commit_decision(&decide(
                    &unreleased,
                    DecidedTransition::NotIncluded(not_included_proof())
                ))
                .is_err()
        );
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);

        // A fresh snapshot after an unrelated commit decides; the consumed
        // generation then refuses a second, different decision's reuse.
        fx.recorder()
            .record_observation(WindowObservation {
                ledger: 200,
                close_time_floor_ms: T0,
                observed_at_ms: T0,
            })
            .unwrap();
        assert!(
            fx.recorder()
                .commit_decision(&decide(&attempt, success.clone()))
                .is_err()
        );
        let fresh = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        assert!(fresh.generation > attempt.generation);
        fx.recorder()
            .commit_decision(&decide(&fresh, success))
            .unwrap();
        assert_eq!(fx.record(handle.id()).state, OperationState::Succeeded);
    }

    /// A committed outcome keeps a 2,048-byte result, the digest of a
    /// 2,049-byte or escaped overlong result, and the exposed envelope's
    /// digest across restart and evidence eviction. Endpoint evidence keeps
    /// XDR digests only, and envelope bounds hold at 8,192 and 8,193.
    #[test]
    #[serial]
    fn recovery_persisted_outcome_keeps_bounded_result_and_original_envelope_digest() {
        for (result, kept) in [
            ("A".repeat(RESULT_XDR_MAX), true),
            ("A".repeat(RESULT_XDR_MAX + 1), false),
            (format!("{}\"", "A".repeat(RESULT_XDR_MAX - 1)), false),
        ] {
            let mut fx = Fx::new();
            let (handle, attempt) = decided_attempt(&mut fx, 1);
            let mut outcome = agreed(1, "FAILED");
            outcome.result_xdr.clone_from(&result);
            fx.recorder()
                .commit_decision(&decide(
                    &attempt,
                    DecidedTransition::Failed {
                        outcome,
                        fee_charged: 100,
                    },
                ))
                .unwrap();
            for ledger in 0..u32::try_from(MAX_EVIDENCE_ROWS + 2).unwrap() {
                fx.recorder()
                    .record_evidence(
                        handle.id(),
                        1,
                        &EvidenceInput {
                            rows: vec![ledger_row(EvidenceEndpoint::Primary, 500 + ledger)],
                            ..EvidenceInput::default()
                        },
                    )
                    .unwrap();
            }
            let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
            let wire = reopened.read_for_inspection(&fx.profile).unwrap().unwrap();
            let record = records(&wire).iter().find(|r| r.id == handle.id()).unwrap();
            let stored = record.attempts[0].agreed_outcome.as_ref().unwrap();
            assert_eq!(stored.result_xdr.truncated(), !kept, "{}", result.len());
            if kept {
                assert_eq!(stored.result_xdr.text(), result);
            } else {
                assert_eq!(stored.result_xdr.text(), sha256_hex(result.as_bytes()));
            }
            assert_eq!(
                stored.envelope_xdr_sha256,
                <[u8; 32]>::from(Sha256::digest(envelope_text(1)))
            );
            assert_eq!(record.attempts[0].evidence.len(), MAX_EVIDENCE_ROWS);
            assert_eq!(
                record.attempts[0].decision.as_ref().unwrap().fee_charged,
                Some(100)
            );
            assert!(serialized_len(record) <= RECORD_MAX);
        }

        let mut fx = Fx::new();
        let (handle, _attempt) = decided_attempt(&mut fx, 1);
        let answer = super::super::recovery::OutcomeAnswer {
            status: Some("SUCCESS".to_owned()),
            envelope_xdr: Some(envelope_text(1)),
            result_xdr: Some("RESULTXDRTEXT".to_owned()),
            latest_ledger: Some(150),
            ..super::super::recovery::OutcomeAnswer::default()
        };
        let row = answer
            .row(EvidenceEndpoint::Primary, [4; 32], None)
            .unwrap();
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows: vec![row],
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let bytes = String::from_utf8_lossy(&fs::read(fx.store.path()).unwrap()).into_owned();
        assert!(!bytes.contains("RESULTXDRTEXT"));
        assert!(bytes.contains(&sha256_hex(b"RESULTXDRTEXT")));

        for (len, fits) in [(ENVELOPE_XDR_MAX, true), (ENVELOPE_XDR_MAX + 1, false)] {
            let mut fx = Fx::new();
            let handle = fx.open_new(&request("order-9", canonical(9)));
            let mint = fx.mint_request(tx(9), fx.policy(), vec![]);
            let started = fx.recorder().begin_attempt(
                &handle,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "A".repeat(len),
                        unsigned_envelope_sha256: [0xee; 32],
                    }),
                    authorization: AttemptAuthorization::Mint(Box::new(mint)),
                    send_by_ms: u64::MAX,
                },
            );
            match started {
                Ok(_) => assert!(fits),
                Err(error) => {
                    assert!(!fits, "{error}");
                    assert_eq!(code(&error), "operation.capacity");
                }
            }
        }
    }

    /// Decisions stay readable after restart and attempt selection, a hash
    /// selects one, and only the decision's own commit writes its
    /// projection marker, once.
    #[test]
    #[serial]
    fn recovery_committed_decisions_survive_restart_and_gate_retry() {
        let mut fx = Fx::new();
        let (first, _) = decided_attempt(&mut fx, 1);
        let (second, two) = decided_attempt(&mut fx, 2);
        let one = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        let succeeded = fx
            .recorder()
            .commit_decision(&decide(
                &one,
                DecidedTransition::Succeeded(agreed(1, "SUCCESS")),
            ))
            .unwrap();
        let two = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[2 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap_or(two);
        let not_included = fx
            .recorder()
            .commit_decision(&decide(
                &two,
                DecidedTransition::NotIncluded(not_included_proof()),
            ))
            .unwrap();
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let status = OperationStatus::new(&reopened, &fx.profile);
        assert!(status.outcome_snapshot(None).unwrap().is_empty());
        let decisions = status.committed_decisions(None).unwrap();
        assert_eq!(decisions.len(), 2);
        let by_op = |id: OperationId| decisions.iter().find(|d| d.operation_id == id).unwrap();
        let ok = by_op(first.id());
        assert_eq!(
            (
                ok.state,
                ok.commit_id,
                ok.ledger,
                ok.ledgers,
                ok.evidence_digest,
                ok.projected
            ),
            (
                OperationState::Succeeded,
                succeeded,
                Some(120),
                (130, 131),
                [0xd1; 32],
                false
            )
        );
        let gone = by_op(second.id());
        assert_eq!(
            (gone.state, gone.commit_id, gone.not_included),
            (
                OperationState::NotIncluded,
                not_included,
                Some(not_included_proof())
            )
        );
        assert_eq!(gone.tx_hash, [2 ^ 0x80; 32]);
        assert_eq!(
            status
                .committed_decisions(Some(&[2 ^ 0x80; 32]))
                .unwrap()
                .len(),
            1
        );
        assert!(
            status
                .committed_decisions(Some(&[0x77; 32]))
                .unwrap()
                .is_empty()
        );

        let early = fx.mint_request(tx(41), fx.policy(), vec![]);
        assert_eq!(
            code(&fx.begin_mint(&second, &early).unwrap_err()),
            "recovery.retry_refused"
        );
        let rows = fx.sink.entries.len();
        let generation = fx.wire().generation;
        assert!(
            fx.recorder()
                .acknowledge_projection(second.id(), 1, succeeded)
                .is_err()
        );
        fx.recorder()
            .acknowledge_projection(second.id(), 1, not_included)
            .unwrap();
        assert_eq!(fx.wire().generation, generation + 1);
        fx.recorder()
            .acknowledge_projection(second.id(), 1, not_included)
            .unwrap();
        assert_eq!(fx.wire().generation, generation + 1);
        assert_eq!(fx.sink.entries.len(), rows);
        let projected = OperationStatus::new(&fx.store, &fx.profile)
            .committed_decisions(Some(&[2 ^ 0x80; 32]))
            .unwrap();
        assert!(projected[0].projected);
        let successor = fx.mint_request(tx(42), fx.policy(), vec![]);
        assert!(fx.begin_mint(&second, &successor).is_ok());
    }

    /// Without its projection marker a checked non-inclusion refuses the
    /// successor with `recovery.retry_refused`, and the marker alone admits
    /// it; a receipt claims nothing here.
    #[test]
    #[serial]
    fn recovery_committed_decisions_gate_the_successor_on_projection() {
        let mut fx = Fx::new();
        let (handle, commit) = checked_not_included(&mut fx, 4);
        let mint = fx.mint_request(tx(40), fx.policy(), vec![]);
        let refused = fx.begin_mint(&handle, &mint).unwrap_err();
        assert!(matches!(refused, WindowStoreError::RetryRefused));
        assert_eq!(code(&refused), "recovery.retry_refused");
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let mut sink = Sink::default();
        OperationRecorder::new(&reopened, &fx.profile, &mut sink, REQUEST_ID)
            .acknowledge_projection(handle.id(), 1, commit)
            .unwrap();
        assert!(fx.begin_mint(&handle, &mint).is_ok());
    }

    /// A repeated decision, the same or a different one, returns the first
    /// commit. The proof, accounting, release row and audit rows stay as
    /// the first commit writes them, before and after restart.
    #[test]
    #[serial]
    fn recovery_transition_replay_is_idempotent() {
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let first = decide(
            &attempt,
            DecidedTransition::Failed {
                outcome: agreed(1, "FAILED"),
                fee_charged: 100,
            },
        );
        let commit = fx.recorder().commit_decision(&first).unwrap();
        let bytes = fs::read(fx.store.path()).unwrap();
        let rows = fx.sink.entries.len();
        let mut other_outcome = agreed(1, "FAILED");
        other_outcome.ledger = 999;
        let replays = [
            first.clone(),
            decide(&attempt, DecidedTransition::Succeeded(agreed(1, "SUCCESS"))),
            decide(
                &attempt,
                DecidedTransition::NotIncluded(not_included_proof()),
            ),
            decide(
                &attempt,
                DecidedTransition::Failed {
                    outcome: other_outcome,
                    fee_charged: 7,
                },
            ),
        ];
        for replay in &replays {
            assert_eq!(fx.recorder().commit_decision(replay).unwrap(), commit);
            assert_eq!(fs::read(fx.store.path()).unwrap(), bytes);
            assert_eq!(fx.sink.entries.len(), rows);
        }
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let mut sink = Sink::default();
        for replay in &replays {
            assert_eq!(
                OperationRecorder::new(&reopened, &fx.profile, &mut sink, REQUEST_ID)
                    .commit_decision(replay)
                    .unwrap(),
                commit
            );
        }
        assert!(sink.entries.is_empty());
        assert_eq!(fs::read(fx.store.path()).unwrap(), bytes);
        let record = fx.record(handle.id());
        assert_eq!(
            record.attempts[0].agreed_outcome.as_ref().unwrap().ledger,
            120
        );
        assert_eq!(
            record.attempts[0].decision.as_ref().unwrap().fee_charged,
            Some(100)
        );
        assert_eq!(
            transition_rows(&fx)
                .iter()
                .filter(|row| matches!(row, EventKind::OperationTransition { step, .. } if step == "failed"))
                .count(),
            1
        );
    }

    /// The transition row names the evidence digest, both deciding ledgers,
    /// the retained commit and, for non-inclusion, the receipt code; the
    /// request id stays outer. All six evidence kinds audit, an uncovered
    /// answer falls back to the shared ledger, and no row names an endpoint.
    #[test]
    #[serial]
    fn recovery_transition_and_evidence_audit_rows_name_the_committed_proofs() {
        use super::super::recovery::{AccountAnswer, OutcomeAnswer};
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        let uncovered = OutcomeAnswer {
            status: Some("NOT_FOUND".to_owned()),
            ..OutcomeAnswer::default()
        };
        let account = AccountAnswer {
            sequence: Some(99),
            latest_ledger: Some(160),
        };
        let rows = vec![
            uncovered
                .row(EvidenceEndpoint::Primary, [1; 32], Some(150))
                .unwrap(),
            uncovered
                .row(EvidenceEndpoint::Witness, [1; 32], Some(151))
                .unwrap(),
            account
                .row(EvidenceEndpoint::Primary, [2; 32], Some(1))
                .unwrap(),
            account
                .row(EvidenceEndpoint::Witness, [2; 32], Some(1))
                .unwrap(),
            ledger_row(EvidenceEndpoint::Primary, 170),
            ledger_row(EvidenceEndpoint::Witness, 171),
        ];
        assert_eq!(rows[0].observed_ledger, 150);
        assert_eq!(rows[2].observed_ledger, 160);
        let before = fx.sink.entries.len();
        fx.recorder()
            .record_evidence(
                handle.id(),
                1,
                &EvidenceInput {
                    rows,
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let EventKind::OperationEvidence { rows, .. } = &fx.sink.entries[before].event_kind else {
            panic!("an evidence row");
        };
        let mut kinds: Vec<String> = rows
            .iter()
            .filter_map(|row| row.kind)
            .map(|kind| serde_json::to_string(&kind).unwrap())
            .collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), 6, "{kinds:?}");
        let attempt = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap_or(attempt);
        let commit = fx
            .recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::NotIncluded(not_included_proof()),
            ))
            .unwrap();
        let entry = fx.sink.entries.last().unwrap();
        assert_eq!(entry.request_id, REQUEST_ID);
        let EventKind::OperationTransition {
            step,
            from_state,
            commit_id,
            evidence_digest,
            primary_ledger,
            witness_ledger,
            release_code,
            ..
        } = &entry.event_kind
        else {
            panic!("a transition row");
        };
        assert_eq!(step, "not_included");
        assert_eq!(from_state.as_deref(), Some("sent_outcome_unknown"));
        assert_eq!(commit_id, &commit.to_hex());
        assert_eq!(evidence_digest.as_deref(), Some("d1".repeat(32).as_str()));
        assert_eq!((*primary_ledger, *witness_ledger), (Some(130), Some(131)));
        assert_eq!(
            release_code.as_deref(),
            Some("accounting.released_on_evidence")
        );
        assert!(fx.record(handle.id()).commit_ids.contains(&commit));
        let json = serde_json::to_string(&fx.sink.entries).unwrap();
        assert!(
            !json.contains("rpc.example") && !json.contains("http"),
            "{json}"
        );
        // A success names no receipt code.
        let (_other, two) = decided_attempt(&mut fx, 2);
        fx.recorder()
            .commit_decision(&decide(
                &two,
                DecidedTransition::Succeeded(agreed(2, "SUCCESS")),
            ))
            .unwrap();
        let EventKind::OperationTransition { release_code, .. } =
            &fx.sink.entries.last().unwrap().event_kind
        else {
            panic!("a transition row");
        };
        assert_eq!(release_code, &None);
    }

    /// Evidence and decisions keep contiguous ranges, the watermark, eviction
    /// and reverse linkage: every audit row classifies as committed or
    /// evicted, and a projection marker writes no audit row.
    #[test]
    #[serial]
    fn recovery_evidence_ranges_preserve_every_class() {
        let mut fx = Fx::new();
        let (handle, attempt) = decided_attempt(&mut fx, 1);
        for ledger in 0..12 {
            fx.recorder()
                .record_evidence(
                    handle.id(),
                    1,
                    &EvidenceInput {
                        rows: vec![
                            ledger_row(EvidenceEndpoint::Primary, 300 + ledger),
                            ledger_row(EvidenceEndpoint::Witness, 300 + ledger),
                        ],
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        let attempt = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap_or(attempt);
        let commit = fx
            .recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::NotIncluded(not_included_proof()),
            ))
            .unwrap();
        let rows_before = fx.sink.entries.len();
        fx.recorder()
            .acknowledge_projection(handle.id(), 1, commit)
            .unwrap();
        assert_eq!(fx.sink.entries.len(), rows_before);
        let ranges = evidence_rows(&fx);
        let mut next = 1;
        for (range, seqs, _, _) in &ranges {
            if let Some(range) = range {
                assert_eq!(range.first, next);
                assert_eq!(seqs, &(range.first..=range.last).collect::<Vec<_>>());
                next = range.last + 1;
            }
        }
        let record = fx.record(handle.id());
        assert_eq!(record.evidence_committed_seq, next - 1);
        assert_eq!(record.attempts[0].evidence.len(), MAX_EVIDENCE_ROWS);
        let facts: Vec<EvidenceAuditFacts> = fx
            .sink
            .entries
            .iter()
            .filter_map(|entry| match &entry.event_kind {
                EventKind::OperationEvidence {
                    attempt_index,
                    evidence_seqs,
                    sequence_released,
                    commit_id,
                    ..
                } => Some(EvidenceAuditFacts {
                    attempt_index: *attempt_index,
                    evidence_seqs: evidence_seqs.map(|range| (range.first, range.last)),
                    sequence_released: *sequence_released,
                    commit_id: CommitId::from_hex(commit_id).unwrap(),
                    appended_at_ms: T0,
                }),
                _ => None,
            })
            .collect();
        let classified = OperationStatus::new(&fx.store, &fx.profile)
            .classify_evidence(handle.id(), &facts, T0)
            .unwrap();
        assert!(classified.unnamed_rows.is_empty());
        assert!(classified.unnamed_releases.is_empty());
        let mut evicted = 0;
        for verdict in &classified.verdicts {
            assert!(!verdict.tampered(), "{verdict:?}");
            if let EvidenceVerdict::Retained { sequences, .. } = verdict {
                evicted += sequences
                    .iter()
                    .filter(|(_, class)| *class == EvidenceSequenceClass::Evicted)
                    .count();
            }
        }
        assert_eq!(evicted, 24 - MAX_EVIDENCE_ROWS);
    }

    /// Commits a checked non-inclusion of `order-{n}`'s first attempt and
    /// returns its handle and commit.
    fn checked_not_included(fx: &mut Fx, n: u8) -> (OperationHandle, CommitId) {
        let (handle, _) = decided_attempt(fx, n);
        let attempt = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[n ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        let commit = fx
            .recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::NotIncluded(not_included_proof()),
            ))
            .unwrap();
        (handle, commit)
    }

    /// A successor needs a checked non-inclusion with its projection
    /// marker, live authority and the predecessor's policy. A premature,
    /// unprojected, confirmed-failure or changed-policy successor refuses.
    /// The projected one starts the next attempt.
    #[test]
    #[serial]
    fn recovery_retry_permission_requires_evidenced_non_inclusion_and_live_authority() {
        let mut fx = Fx::new();
        let (premature, _) = decided_attempt(&mut fx, 1);
        let mint = fx.mint_request(tx(11), fx.policy(), vec![]);
        assert!(fx.begin_mint(&premature, &mint).is_err());

        let (failed, _) = decided_attempt(&mut fx, 2);
        let attempt = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[2 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        fx.recorder()
            .commit_decision(&decide(
                &attempt,
                DecidedTransition::Failed {
                    outcome: agreed(2, "FAILED"),
                    fee_charged: 100,
                },
            ))
            .unwrap();
        let mint = fx.mint_request(tx(12), fx.policy(), vec![]);
        assert!(fx.begin_mint(&failed, &mint).is_err());

        let (handle, commit) = checked_not_included(&mut fx, 3);
        let before = fs::read(fx.store.path()).unwrap();
        let mint = fx.mint_request(tx(13), fx.policy(), vec![]);
        let refused = fx.begin_mint(&handle, &mint).unwrap_err();
        assert_eq!(code(&refused), "recovery.retry_refused");
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);
        fx.recorder()
            .acknowledge_projection(handle.id(), 1, commit)
            .unwrap();
        // Each changed policy is pinned first, so the mint's own prechecks
        // pass and the successor's policy check alone refuses.
        let repin = |fx: &Fx, sequence: i64, digest: [u8; 32]| {
            let lock = WindowStoreLock::acquire_for(
                fx.store.path(),
                &fx.profile.policy_window_state_key_id,
            )
            .unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(fx.store.path(), &fx.profile),
                &Pin::new(sequence, digest, owner_of(11)).unwrap(),
            )
            .unwrap();
        };
        for (sequence, digest) in [(7, [8; 32]), (8, [7; 32])] {
            repin(&fx, sequence, digest);
            let mut changed = fx.mint_request(tx(13), fx.policy(), vec![]);
            changed.policy_sequence = sequence;
            changed.policy_digest = digest;
            if let MintAuthority::Policy(binding) = &mut changed.authority {
                binding.policy_sequence = sequence;
                binding.policy_digest = digest;
            }
            let error = fx.begin_mint(&handle, &changed).unwrap_err();
            assert!(
                matches!(&error, WindowStoreError::UnexpectedState { detail }
                    if detail.contains("another policy")),
                "{sequence}: {error:?}"
            );
        }
        repin(&fx, 7, [7; 32]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        assert_eq!(started.attempt_index, 2);
        assert_eq!(fx.record(handle.id()).state, OperationState::Sending);
        let open = fx.mint_request(tx(14), fx.policy(), vec![]);
        assert_eq!(
            code(&fx.begin_mint(&handle, &open).unwrap_err()),
            "operation.attempt_open"
        );
    }

    /// A linked successor authorization under another policy digest or
    /// sequence refuses as a minted one does; one under the predecessor's
    /// policy starts the next attempt.
    #[test]
    #[serial]
    fn recovery_linked_successor_requires_the_predecessor_policy() {
        let repin = |fx: &Fx, sequence: i64, digest: [u8; 32]| {
            let lock = WindowStoreLock::acquire_for(
                fx.store.path(),
                &fx.profile.policy_window_state_key_id,
            )
            .unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(fx.store.path(), &fx.profile),
                &Pin::new(sequence, digest, owner_of(11)).unwrap(),
            )
            .unwrap();
        };
        let linked_begin = |fx: &mut Fx, handle: &OperationHandle| {
            fx.recorder().begin_attempt(
                handle,
                &AttemptRequest {
                    envelope: Some(AttemptEnvelope {
                        xdr: "AAAAENVELOPE".to_owned(),
                        unsigned_envelope_sha256: handle
                            .unsigned_envelope_sha256()
                            .unwrap_or([0xee; 32]),
                    }),
                    authorization: AttemptAuthorization::Linked,
                    send_by_ms: u64::MAX,
                },
            )
        };
        for (n, sequence, digest) in [(1_u8, 7, [8; 32]), (2, 8, [7; 32])] {
            let mut fx = Fx::new();
            let (handle, commit) = checked_not_included(&mut fx, n);
            fx.recorder()
                .acknowledge_projection(handle.id(), 1, commit)
                .unwrap();
            repin(&fx, sequence, digest);
            let mut linked = fx.mint_request(tx(n + 20), fx.policy(), vec![]);
            linked.policy_sequence = sequence;
            linked.policy_digest = digest;
            if let MintAuthority::Policy(binding) = &mut linked.authority {
                binding.policy_sequence = sequence;
                binding.policy_digest = digest;
            }
            linked.operation = Some(OperationLink {
                operation_id: handle.id(),
                attempt_index: 2,
            });
            fx.store.mint_authorization(&fx.profile, &linked).unwrap();
            let before = fs::read(fx.store.path()).unwrap();
            let error = linked_begin(&mut fx, &handle).unwrap_err();
            assert!(
                matches!(&error, WindowStoreError::UnexpectedState { detail }
                    if detail.contains("another policy")),
                "{sequence}: {error:?}"
            );
            assert_eq!(fs::read(fx.store.path()).unwrap(), before);
        }

        let mut fx = Fx::new();
        let (handle, commit) = checked_not_included(&mut fx, 3);
        fx.recorder()
            .acknowledge_projection(handle.id(), 1, commit)
            .unwrap();
        let mut linked = fx.mint_request(tx(23), fx.policy(), vec![]);
        linked.operation = Some(OperationLink {
            operation_id: handle.id(),
            attempt_index: 2,
        });
        fx.store.mint_authorization(&fx.profile, &linked).unwrap();
        assert_eq!(linked_begin(&mut fx, &handle).unwrap().attempt_index, 2);
    }

    /// The successor's `not_included -> sending` row names the permitting
    /// decision's evidence and ledgers once; a racing second begin refuses
    /// and writes no second row.
    #[test]
    #[serial]
    fn recovery_retry_audit_row_from_begin_attempt() {
        let mut fx = Fx::new();
        let (handle, commit) = checked_not_included(&mut fx, 1);
        fx.recorder()
            .acknowledge_projection(handle.id(), 1, commit)
            .unwrap();
        let rows_before = fx.sink.entries.len();
        let mint = fx.mint_request(tx(21), fx.policy(), vec![]);
        fx.begin_mint(&handle, &mint).unwrap();
        let racing = fx.mint_request(tx(22), fx.policy(), vec![]);
        assert!(fx.begin_mint(&handle, &racing).is_err());
        let permissions: Vec<_> = fx.sink.entries[rows_before..]
            .iter()
            .filter_map(|entry| match &entry.event_kind {
                EventKind::OperationTransition {
                    from_state,
                    step,
                    evidence_digest,
                    primary_ledger,
                    witness_ledger,
                    ..
                } if from_state.as_deref() == Some("not_included") && step == "sending" => {
                    Some((evidence_digest.clone(), *primary_ledger, *witness_ledger))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            permissions,
            vec![(Some("d1".repeat(32)), Some(130), Some(131))]
        );
        assert_eq!(fx.record(handle.id()).attempts.len(), 2);
    }

    /// An x402 operation `order-x{n}` exposed with entries expiring after
    /// ledger 500 and moved to `to`, without window entries.
    fn x402_exposed(fx: &mut Fx, n: u8, to: OperationState) -> OperationHandle {
        let handle = fx.open_new(&request(&format!("order-x{n}"), x402([n; 32])));
        let mint = fx.mint_request(soroban(n), fx.approval(), vec![]);
        let started = fx.begin_mint(&handle, &mint).unwrap();
        fx.claim(&mint, started.minted.as_ref().unwrap());
        fx.recorder()
            .expose(
                handle.id(),
                1,
                &ExposureIdentity::X402 {
                    authorization_id: started.authorization_id,
                    auth_entry_sha256: [n; 32],
                    signature_expiration_ledger: 500,
                },
                Some(400),
            )
            .unwrap();
        fx.recorder()
            .transition(handle.id(), Some(1), to, &TransitionEvidence::default())
            .unwrap();
        handle
    }

    /// A classic operation exposed with `max_time` and moved from its
    /// unknown outcome to `Expired`.
    fn terminal_classic(fx: &mut Fx, n: u8, max_time: u64) -> OperationHandle {
        let handle = unknown_with(fx, n, max_time, vec![]);
        fx.recorder()
            .transition(
                handle.id(),
                Some(1),
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
        handle
    }

    /// The operation and kind of every obligation at `observation`, sorted.
    fn obligations_at(
        fx: &Fx,
        observation: WindowObservation,
    ) -> Vec<(OperationId, ObligationKind)> {
        let mut found: Vec<_> = OperationStatus::new(&fx.store, &fx.profile)
            .release_obligations(Some(observation))
            .unwrap()
            .into_iter()
            .map(|obligation| (obligation.operation_id, obligation.kind))
            .collect();
        found.sort_by_key(|(id, _)| id.to_hex());
        found
    }

    fn release_row(fx: &Fx, handle: &OperationHandle) -> Option<ReleaseRow> {
        let auth_id = fx.record(handle.id()).attempts[0].authorization_id;
        fx.auth(auth_id).native_release
    }

    /// Each obligation's release crosses the generation commit as one unit.
    /// A crash after the prepared file reopens the complete old state. A
    /// crash after the counter reopens the complete new state: the release
    /// row and, for live x402, the `Expired` state together.
    #[test]
    #[serial]
    fn recovery_obligation_release_crosses_the_commit_point_as_one_unit() {
        use super::super::store::{
            COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        };
        let observation = WindowObservation {
            ledger: 501,
            close_time_floor_ms: (T0 / 1_000 + 10) * 1_000 + 1,
            observed_at_ms: T0,
        };
        type Build = fn(&mut Fx) -> (OperationHandle, OperationState, bool);
        let proofs: [(&str, Build); 4] = [
            ("live x402", |fx| {
                (
                    x402_exposed(fx, 1, OperationState::SentOutcomeUnknown),
                    OperationState::Expired,
                    false,
                )
            }),
            ("terminal x402", |fx| {
                (
                    x402_exposed(fx, 2, OperationState::PayloadReleased),
                    OperationState::PayloadReleased,
                    false,
                )
            }),
            ("timed classic", |fx| {
                (
                    terminal_classic(fx, 3, T0 / 1_000 + 10),
                    OperationState::Expired,
                    false,
                )
            }),
            ("untimed classic", |fx| {
                (terminal_classic(fx, 4, 0), OperationState::Expired, true)
            }),
        ];
        for (label, build) in proofs {
            for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let mut fx = Fx::new();
                let (handle, released_state, ack) = build(&mut fx);
                let before = fx.record(handle.id()).state;
                let armed = arm_accounting_fault(seam);
                let result = fx
                    .recorder()
                    .release_obligation(handle.id(), 1, observation, ack);
                drop(armed);
                assert!(result.is_err(), "{label} at seam {seam}");
                let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
                let wire = reopened.read_for_inspection(&fx.profile).unwrap().unwrap();
                let record = records(&wire).iter().find(|r| r.id == handle.id()).unwrap();
                let auth_id = record.attempts[0].authorization_id;
                let row = wire
                    .authorizations
                    .iter()
                    .find(|auth| auth.id == auth_id)
                    .unwrap()
                    .native_release;
                if seam == COMMIT_FAULT_AFTER_PREPARED {
                    assert_eq!(
                        (record.state, row),
                        (before, None),
                        "{label}: the complete old state"
                    );
                } else {
                    assert_eq!(record.state, released_state, "{label}: the new state");
                    let row = row.unwrap_or_else(|| panic!("{label}: the release row"));
                    assert_eq!(row.class, ReleaseClass::Unknown, "{label}");
                    if released_state != before {
                        assert_eq!(record.last_commit_id, Some(row.commit_id), "{label}");
                    }
                }
            }
        }
    }

    /// Obligations are enumerated from the verified window only when their
    /// proof holds strictly. An x402 needs its expiration ledger passed, a
    /// timed classic its `max_time` passed, an untimed one its acknowledged
    /// clear. Each release commits its row atomically. A live x402 also
    /// becomes `Expired` with one transition row. Terminal states stay,
    /// obligations take no classic slot, and a repeated pass releases
    /// nothing again.
    #[test]
    #[serial]
    fn recovery_obligation_enumeration_and_release_rows_are_verified_and_atomic() {
        let mut fx = Fx::new();
        let live = x402_exposed(&mut fx, 1, OperationState::SentOutcomeUnknown);
        let released = x402_exposed(&mut fx, 2, OperationState::PayloadReleased);
        let timed = terminal_classic(&mut fx, 3, T0 / 1_000 + 10);
        let untimed = terminal_classic(&mut fx, 4, 0);
        let unknown = unknown_named(&mut fx, 5);
        let at = |ledger: u32, close_ms: u64| WindowObservation {
            ledger,
            close_time_floor_ms: close_ms,
            observed_at_ms: T0,
        };
        let deadline = (T0 / 1_000 + 10) * 1_000;
        let kinds = obligations_at;
        assert_eq!(
            kinds(&fx, at(500, deadline)),
            vec![(untimed.id(), ObligationKind::TerminalUntimed)]
        );
        let mut due = vec![
            (
                live.id(),
                ObligationKind::X402Expired {
                    signature_expiration_ledger: 500,
                },
            ),
            (
                released.id(),
                ObligationKind::X402Expired {
                    signature_expiration_ledger: 500,
                },
            ),
            (
                timed.id(),
                ObligationKind::TerminalTimed {
                    release_after_ms: deadline,
                },
            ),
            (untimed.id(), ObligationKind::TerminalUntimed),
        ];
        due.sort_by_key(|(id, _)| id.to_hex());
        assert_eq!(kinds(&fx, at(501, deadline + 1)), due);
        let classic: Vec<_> = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .into_iter()
            .map(|attempt| attempt.operation_id)
            .collect();
        assert_eq!(classic, vec![unknown.id()]);

        let bytes = fs::read(fx.store.path()).unwrap();
        for (handle, observation, ack) in [
            (&live, at(500, deadline + 1), false),
            (&timed, at(501, deadline), false),
            (&untimed, at(501, deadline + 1), false),
            (&unknown, at(501, deadline + 1), true),
        ] {
            assert!(
                fx.recorder()
                    .release_obligation(handle.id(), 1, observation, ack)
                    .is_err()
            );
            assert_eq!(fs::read(fx.store.path()).unwrap(), bytes);
        }
        fx.sink.fail = true;
        assert!(
            fx.recorder()
                .release_obligation(live.id(), 1, at(501, deadline + 1), false)
                .is_err()
        );
        fx.sink.fail = false;
        assert_eq!(fs::read(fx.store.path()).unwrap(), bytes);

        let rows = fx.sink.entries.len();
        let commit = fx
            .recorder()
            .release_obligation(live.id(), 1, at(501, deadline + 1), false)
            .unwrap();
        let record = fx.record(live.id());
        assert_eq!(record.state, OperationState::Expired);
        assert!(record.commit_ids.contains(&commit));
        assert_eq!(
            release_row(&fx, &live),
            Some(ReleaseRow {
                class: ReleaseClass::Unknown,
                bound: ReleaseBound::Ledger(500),
                observed_ledger: Some(501),
                commit_id: commit,
            })
        );
        let expired: Vec<_> = fx.sink.entries[rows..]
            .iter()
            .filter(|entry| {
                matches!(&entry.event_kind,
                    EventKind::OperationTransition { step, commit_id, .. }
                        if step == "expired" && commit_id == &commit.to_hex())
            })
            .collect();
        assert_eq!(expired.len(), 1);

        fx.recorder()
            .release_obligation(released.id(), 1, at(501, deadline + 1), false)
            .unwrap();
        assert_eq!(
            fx.record(released.id()).state,
            OperationState::PayloadReleased
        );
        assert_eq!(
            release_row(&fx, &released).map(|row| row.bound),
            Some(ReleaseBound::Ledger(500))
        );
        fx.recorder()
            .release_obligation(timed.id(), 1, at(501, deadline + 1), false)
            .unwrap();
        assert_eq!(fx.record(timed.id()).state, OperationState::Expired);
        assert_eq!(
            release_row(&fx, &timed).map(|row| (row.class, row.bound)),
            Some((ReleaseClass::Unknown, ReleaseBound::CloseTime(deadline)))
        );
        fx.recorder()
            .release_obligation(untimed.id(), 1, at(501, deadline + 1), true)
            .unwrap();
        assert_eq!(
            release_row(&fx, &untimed).map(|row| row.bound),
            Some(ReleaseBound::Always)
        );

        assert!(kinds(&fx, at(501, deadline + 1)).is_empty());
        let bytes = fs::read(fx.store.path()).unwrap();
        assert!(
            fx.recorder()
                .release_obligation(live.id(), 1, at(502, deadline + 2), true)
                .is_err()
        );
        assert_eq!(fs::read(fx.store.path()).unwrap(), bytes);
    }
}
