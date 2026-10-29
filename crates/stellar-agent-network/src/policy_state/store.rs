//! [`PersistedWindowStore`]: the HMAC-protected, single-writer, atomic-write
//! per-profile policy window-state file. See the module-level docs in
//! [`super`] for the wire format, integrity, and concurrency design.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::schema::{PreviousState, WipedAccrualRecord, WipedBucket};
use stellar_agent_core::policy::DenyReason;
use stellar_agent_core::policy::pin::{self, PinError, PinScope, PinState};
use stellar_agent_core::policy::v1::criteria::state_store::{
    CLOCK_SKEW_TOLERANCE_MS, PolicyStateStore, StateKey, StateStoreError, WindowEntry,
};
use stellar_agent_core::profile::owner_key::{self, OwnerKeyContext};
use stellar_agent_core::profile::receipt::{
    ReceiptStatus, ReceiptStore, ReceiptStoreError, ReleaseEvidence,
};
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, Profile, default_policy_window_state_path_for, generation_account,
};
use subtle::ConstantTimeEq as _;

use crate::endpoint_identity::MainnetOracle;
use crate::policy_state::WindowStoreError;
use crate::policy_state::ledger::{self, WireAuthorization, WireAuthorizationHold};
use crate::policy_state::lock::{WindowStoreLock, window_lock_path};
use crate::transaction_record::TransactionRecord;

type HmacSha256 = Hmac<Sha256>;

/// HMAC tag length in bytes.
const HMAC_TAG_LEN: usize = 32;

/// HMAC context-separation label for the window-state store's v1 wire
/// format. A tag computed under this label cannot verify under a different
/// context.
const HMAC_CONTEXT_LABEL: &[u8] = b"stellar-agent-policy-window/v1/body\x00";

/// Retention ceiling: the largest window a criterion supports (`"1w"`), in
/// milliseconds. Entries older than `now_ms - RETENTION_MS` are pruned on
/// every write, so the store never grows unbounded even if a criterion's
/// window shrinks or a rule is removed.
pub(super) const RETENTION_MS: u64 = 604_800 * 1_000;

/// Bounds the chain-time observation independently of the transport timeout.
const LEDGER_OBSERVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Bounds the oracle's single identity request independently of the
/// transport timeout.
const ORACLE_IDENTITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Chain observations and RPC allowance shared by one reconciliation pass.
///
/// The observations belong to one endpoint, the one the release rule asks:
/// the primary on testnet, the oracle on a mainnet profile. They are keyed to
/// that client, so values read from one endpoint are never applied to an
/// answer of another.
struct ReconcilePass<'o> {
    remaining: usize,
    spent: usize,
    /// Whether the pass established that the oracle serves mainnet. The
    /// check runs once per pass, on the first answer that needs the oracle,
    /// unless the caller hands the pass an oracle it already checked.
    oracle: OracleCheck<'o>,
    /// When every read of the oracle ends, its identity request included:
    /// the deadline of a caller that holds a resource across the pass. A
    /// read still open then is abandoned and counts as a failed read.
    oracle_deadline: Option<tokio::time::Instant>,
    /// The id of the client whose retention floor and chain time the pass
    /// holds.
    observed: Option<u64>,
    oldest_ledger: Option<u32>,
    chain: Option<(u32, u64)>,
    /// A ledger-time failure, promoted only when a sent, timed reservation needs it.
    ledger_failure: Option<ReconcileFailure>,
    /// The first endpoint failure the pass met. A later successful read does
    /// not clear it.
    failure: Option<ReconcileFailure>,
}

/// The oracle identity check of one reconciliation pass.
#[derive(Clone, Copy)]
enum OracleCheck<'o> {
    /// No answer of the pass has needed the oracle yet.
    Unchecked,
    /// The oracle reported mainnet.
    Verified(MainnetOracle<'o>),
    /// The oracle reported another network, or its identity could not be
    /// read; it settles nothing for the rest of the pass.
    Refused,
}

impl<'o> ReconcilePass<'o> {
    /// A pass over `budget` reservations. A mainnet profile's reservation can
    /// cost one read more than a testnet one, the oracle's transaction answer
    /// beside the primary's, and the pass shares one more read, the oracle's
    /// identity.
    fn new(budget: usize, mainnet: bool) -> Self {
        let (per_reservation, shared) = if mainnet { (4, 3) } else { (3, 2) };
        Self {
            remaining: budget
                .saturating_mul(per_reservation)
                .saturating_add(shared),
            spent: 0,
            oracle: OracleCheck::Unchecked,
            oracle_deadline: None,
            observed: None,
            oldest_ledger: None,
            chain: None,
            ledger_failure: None,
            failure: None,
        }
    }

    /// Records an endpoint failure, keeping the first one the pass met.
    fn fail(&mut self, client: &crate::client::StellarRpcClient, reason: String) {
        if self.failure.is_none() {
            self.failure = Some(ReconcileFailure {
                endpoint: client.url.authority().to_owned(),
                reason,
                kind: ReconcileFailureKind::Unreachable,
            });
        }
    }

    /// Records that a mainnet profile names no oracle, so a negative answer of
    /// the primary had no witness, keeping the first failure the pass met.
    fn fail_without_oracle(&mut self) {
        if self.failure.is_none() {
            self.failure = Some(ReconcileFailure {
                endpoint: String::new(),
                reason: stellar_agent_core::error::WitnessUnavailableReason::OracleNotConfigured
                    .to_string(),
                kind: ReconcileFailureKind::OracleNotConfigured,
            });
        }
    }

    /// A pass that takes `oracle` as checked and ends every read of it by
    /// `deadline`.
    fn with_checked_oracle(
        mut self,
        oracle: Option<MainnetOracle<'o>>,
        deadline: tokio::time::Instant,
    ) -> Self {
        if let Some(oracle) = oracle {
            self.oracle = OracleCheck::Verified(oracle);
        }
        self.oracle_deadline = Some(deadline);
        self
    }

    /// When a read of `client` must end: the caller's oracle deadline for a
    /// read of the checked oracle, no deadline for any other read.
    fn deadline_of(
        &self,
        client: &crate::client::StellarRpcClient,
    ) -> Option<tokio::time::Instant> {
        match self.oracle {
            OracleCheck::Verified(oracle) if oracle.client().id() == client.id() => {
                self.oracle_deadline
            }
            _ => None,
        }
    }

    /// Returns `oracle` once it has reported mainnet, checking its identity on
    /// the first call of the pass with one `getNetwork` request, charged to
    /// the allowance and never retried, so the pass's count holds every
    /// request it sent. An oracle that reports another network, or whose
    /// identity read fails or finds the allowance spent, yields `None`; the
    /// first two are recorded as the pass's failure and hold for the rest of
    /// the pass.
    async fn verified_oracle(
        &mut self,
        oracle: &'o crate::client::StellarRpcClient,
    ) -> Option<MainnetOracle<'o>> {
        match self.oracle {
            OracleCheck::Verified(verified) => return Some(verified),
            OracleCheck::Refused => return None,
            OracleCheck::Unchecked => {}
        }
        if !self.charge() {
            return None;
        }
        let own = tokio::time::Instant::now() + ORACLE_IDENTITY_TIMEOUT;
        let deadline = self.oracle_deadline.map_or(own, |caller| caller.min(own));
        match MainnetOracle::verify_once(oracle, deadline).await {
            Ok(verified) => {
                self.oracle = OracleCheck::Verified(verified);
                Some(verified)
            }
            Err(error) => {
                tracing::debug!(
                    %error,
                    "window reconcile: the oracle did not establish that it serves mainnet; \
                     its answers settle nothing"
                );
                self.oracle = OracleCheck::Refused;
                if self.failure.is_none() {
                    self.failure = Some(ReconcileFailure {
                        endpoint: oracle.url.authority().to_owned(),
                        reason: error.to_string(),
                        kind: ReconcileFailureKind::of_oracle_identity(&error),
                    });
                }
                None
            }
        }
    }

    fn charge(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        self.spent += 1;
        true
    }

    /// Reads `client`'s retention floor and latest ledger close time once per
    /// pass. Asked about another client, the pass drops what it holds and
    /// observes that client instead.
    async fn observe(&mut self, client: &crate::client::StellarRpcClient) {
        if self.observed == Some(client.id()) {
            return;
        }
        self.observed = Some(client.id());
        self.oldest_ledger = None;
        self.chain = None;
        self.ledger_failure = None;
        if !self.charge() {
            return;
        }
        let deadline = self.deadline_of(client);
        let health = match within(deadline, client.get_health()).await {
            Some(Ok(health)) => health,
            Some(Err(error)) => {
                tracing::debug!(%error, "window reconcile: retention observation unavailable; reservation stands");
                self.fail(client, network_failure_reason(error));
                return;
            }
            None => {
                tracing::debug!(
                    "window reconcile: retention observation not answered by the deadline; \
                     reservation stands"
                );
                self.fail(client, deadline_passed("getHealth"));
                return;
            }
        };
        self.oldest_ledger = Some(health.oldest_ledger);
        if !self.charge() {
            return;
        }
        let own = tokio::time::Instant::now() + LEDGER_OBSERVATION_TIMEOUT;
        let answer = tokio::time::timeout_at(
            deadline.map_or(own, |caller| caller.min(own)),
            client.inner.get_ledgers(
                stellar_rpc_client::LedgerStart::Ledger(health.latest_ledger),
                Some(1),
                None,
            ),
        )
        .await;
        let reason = match answer {
            Ok(Ok(answer))
                if answer.latest_ledger_close_time > 0
                    && answer.latest_ledger_close_time >= answer.oldest_ledger_close_time
                    && answer.latest_ledger >= health.latest_ledger
                    && answer.oldest_ledger <= answer.latest_ledger =>
            {
                self.oldest_ledger = Some(health.oldest_ledger.max(answer.oldest_ledger));
                self.chain = Some((answer.latest_ledger, answer.latest_ledger_close_time as u64));
                return;
            }
            Ok(Ok(_)) => "getLedgers answered without a valid ledger close time".to_owned(),
            Ok(Err(error)) => format!("getLedgers failed: {}", client.url.scrub_display(&error)),
            Err(_) if deadline.is_some_and(|caller| caller < own) => deadline_passed("getLedgers"),
            Err(_) => format!(
                "getLedgers did not answer within {}s",
                LEDGER_OBSERVATION_TIMEOUT.as_secs()
            ),
        };
        tracing::debug!(
            "window reconcile: valid ledger close time unavailable; time-bound release stays closed"
        );
        self.ledger_failure = Some(ReconcileFailure {
            endpoint: client.url.authority().to_owned(),
            reason,
            kind: ReconcileFailureKind::Unreachable,
        });
    }
}

/// Runs `read`, abandoning it at `deadline` when one is set. `None` means the
/// deadline passed before the read completed.
async fn within<F: std::future::Future>(
    deadline: Option<tokio::time::Instant>,
    read: F,
) -> Option<F::Output> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, read).await.ok(),
        None => Some(read.await),
    }
}

/// The failure reason of a read the caller's deadline ended.
fn deadline_passed(rpc_method: &str) -> String {
    format!("{rpc_method} did not answer before the caller's deadline")
}

/// The reason text of a failed endpoint read, without the endpoint's
/// authority, which [`ReconcileFailure::endpoint`] carries.
fn network_failure_reason(error: stellar_agent_core::error::NetworkError) -> String {
    match error {
        stellar_agent_core::error::NetworkError::RpcUnreachable { reason, .. } => reason,
        other => other.to_string(),
    }
}

/// Wire-format version of a snapshot whose authorization history is empty.
///
/// Every snapshot this build writes without authorization history uses it,
/// so a build that reads up to version 3 keeps reading the store until a
/// mainnet authorization is minted.
pub(super) const WIRE_VERSION_COMPACT: u32 = 3;

/// Wire-format version of a snapshot that carries authorization history,
/// settled records included, until pruning removes the last of it.
pub(super) const WIRE_VERSION_LEDGER: u32 = 4;

/// Highest wire-format version this build reads.
///
/// A file written by a newer build carries records this one cannot account
/// for, so it is refused rather than read with the fields it happens to
/// recognise.
const WIRE_VERSION_MAX: u32 = WIRE_VERSION_LEDGER;

/// The version a snapshot is written under, chosen from its content: version
/// 4 when it carries authorization history, version 3 otherwise.
pub(super) fn select_wire_version(wire: &WireFile) -> u32 {
    if wire.authorizations.is_empty() {
        WIRE_VERSION_COMPACT
    } else {
        WIRE_VERSION_LEDGER
    }
}

/// How many reservations one reconciliation pass settles.
///
/// A value verb runs a pass before its policy gate, so this bounds the extra
/// round trips it can spend: at most this many reservations, each costing at
/// most three transaction/account reads, plus one shared retention query and
/// one ledger observation. Every RPC consumes that pass's `3 * budget + 2`
/// allowance, including the ledger observation. On a mainnet profile a
/// reservation can also cost the oracle's transaction read, the pass shares
/// the oracle's identity read, and the allowance is `4 * budget + 3`.
pub const RECONCILE_BUDGET: usize = 5;

/// How long a reservation must stand before a reconciliation pass looks at it.
///
/// Below this age no release branch can fire: a transaction whose sequence is
/// not yet consumed and whose time bound has not passed is still applicable,
/// and asking about it only costs round trips.
pub const RECONCILE_MIN_AGE_MS: u64 = 300_000;

// ─────────────────────────────────────────────────────────────────────────────
// Wire format
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a record counts spend the chain has confirmed, or spend a
/// submission has reserved while its outcome is still open.
///
/// Both count against a window criterion: a submission that has been sent may
/// apply, so the operator's cap has to hold against it until the chain says
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecordStatus {
    /// The transaction reached a ledger. Version 1 records default to
    /// confirmed spend so their window accounting remains defined.
    #[default]
    Confirmed,
    /// A signed transaction was sent and its outcome is not known yet.
    Pending,
}

/// One `(timestamp_ms, amount)` record within a bucket, plus the identity of
/// the submission that reserved it.
///
/// The identity fields carry defaults so a v1 record deserialises as a
/// confirmed record with no reservation to reconcile.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct WireRecord {
    pub(super) ts_ms: u64,
    #[serde(with = "i128_decimal_str")]
    pub(super) amount: i128,
    /// Reservation identity: the envelope hash of the submission that wrote
    /// this record. Every record one submission writes shares it, so one
    /// reconciliation settles them together. Empty on a confirmed record
    /// written by a path that takes no reservation.
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) status: RecordStatus,
    /// Transaction hash to reconcile the reservation against.
    #[serde(default)]
    pub(super) tx_hash: String,
    /// The account whose sequence the transaction consumes.
    #[serde(default)]
    pub(super) source: String,
    /// The sequence number the transaction consumes.
    #[serde(default)]
    pub(super) sequence: i64,
    /// `TimeBounds.maxTime` in absolute unix seconds; `0` means no time bound.
    #[serde(default)]
    pub(super) max_time: u64,
    /// When the reservation was taken, in unix milliseconds.
    #[serde(default)]
    pub(super) pending_since_ms: u64,
    /// The endpoint's latest ledger when the reservation was taken, compared
    /// against the endpoint's retention floor to tell "the endpoint never saw
    /// it" apart from "the endpoint no longer remembers it".
    #[serde(default)]
    pub(super) submission_ledger: u32,
    /// An orphan beyond retention requires an operator decision.
    #[serde(default)]
    pub(super) operator_required: bool,
}

impl WireRecord {
    /// The identity fields of a record that carries no reservation.
    ///
    /// Used with struct-update syntax so a confirmed record names only its
    /// timestamp and amount at the call site.
    pub(super) fn confirmed_defaults() -> Self {
        Self {
            ts_ms: 0,
            amount: 0,
            id: String::new(),
            status: RecordStatus::Confirmed,
            tx_hash: String::new(),
            source: String::new(),
            sequence: 0,
            max_time: 0,
            pending_since_ms: 0,
            submission_ledger: 0,
            operator_required: false,
        }
    }
}

/// The identity of a submission whose pending records hold window headroom.
///
/// Every record one submission writes carries this identity, so a
/// reconciliation pass settles them together from one round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionHold {
    /// The submission's envelope hash, 64 lowercase hex characters.
    pub id: String,
    /// The transaction hash to reconcile against, 64 lowercase hex characters.
    pub tx_hash: String,
    /// The account whose sequence the transaction consumes, a `G...` strkey.
    pub source: String,
    /// The sequence number the transaction consumes.
    pub sequence: i64,
    /// `TimeBounds.maxTime` in absolute unix seconds; `0` means no time bound.
    pub max_time: u64,
    /// When the reservation was taken, in unix milliseconds.
    pub pending_since_ms: u64,
    /// The endpoint's latest ledger when the reservation was taken.
    pub submission_ledger: u32,
    /// The receipt is absent beyond retention; automatic reconciliation skips this hold.
    pub operator_required: bool,
}

/// What one reconciliation pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Reservations the pass asked the endpoint about.
    pub examined: usize,
    /// RPC calls charged to this pass, including its shared observations.
    pub rpc_calls: usize,
    /// Reservations confirmed by a `SUCCESS` answer.
    pub confirmed: usize,
    /// Reservations released, either by a `FAILED` answer or on chain
    /// evidence that the transaction can no longer apply.
    pub released: usize,
    /// Reservations left standing because the answers settled nothing, an
    /// endpoint failure included.
    pub kept_pending: usize,
    /// Receipt writes that failed; their reservations remain pending for a later pass.
    pub receipt_write_failed: usize,
    /// The first receipt-store error that prevented an outcome from being recorded.
    pub receipt_write_error: Option<String>,
    /// Reservations whose transaction the endpoint no longer remembers, so
    /// `NOT_FOUND` proves nothing. Their receipts are marked ambiguous without
    /// release evidence and the reservations stand until an operator resolves
    /// them.
    pub retention_expired: usize,
    /// The submissions the pass settled, in the order it settled them: one
    /// per definitive answer, and one per release on chain evidence.
    ///
    /// The pass holds no audit writer of its own, so it reports what it
    /// settled and the caller writes the value-action row each one is owed.
    pub settled: Vec<SettledSubmission>,
    /// The first unusable transaction, health or account read. An absent source
    /// account leaves its sequence unknown without setting this field. A ledger-time
    /// failure counts only when a sent, timed reservation needs that observation.
    /// A later successful read in the same pass does not clear the failure.
    ///
    /// A reservation such a failure left standing is reported in
    /// `kept_pending`. A caller that has to tell "the transaction can still
    /// apply" apart from "the endpoint could not say" reads this field.
    pub endpoint_failure: Option<ReconcileFailure>,
}

/// An endpoint read a reconciliation pass could not complete, the oracle a
/// mainnet profile does not name, or an oracle that did not establish that
/// it serves mainnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileFailure {
    /// The endpoint's scheme, host and port; empty for
    /// [`ReconcileFailureKind::OracleNotConfigured`].
    pub endpoint: String,
    /// What failed, scrubbed of credentials and credential-bearing URLs.
    pub reason: String,
    /// Which condition the failure is.
    pub kind: ReconcileFailureKind,
}

/// Which condition a [`ReconcileFailure`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconcileFailureKind {
    /// A read of the primary endpoint or the oracle did not complete.
    Unreachable,
    /// A mainnet profile names no oracle, so a `FAILED` or `NOT_FOUND`
    /// answer of the primary endpoint had no independent witness and settled
    /// nothing.
    OracleNotConfigured,
    /// The oracle reported a network other than mainnet, so its answers
    /// settled nothing.
    OracleNetworkMismatch,
    /// The oracle reported a protocol version the protocol rule refuses for
    /// mainnet, so its answers settled nothing.
    OracleProtocolUnsupported,
    /// The oracle's network identity could not be read, so its answers
    /// settled nothing.
    OracleIdentityUnavailable,
}

impl ReconcileFailureKind {
    /// The kind of a failed oracle identity check, from the error
    /// the identity check of a [`MainnetOracle`] returned.
    fn of_oracle_identity(error: &stellar_agent_core::error::WalletError) -> Self {
        use stellar_agent_core::error::{NetworkError, WalletError, WitnessUnavailableReason};
        match error {
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::IdentityNetworkMismatch { .. },
            }) => Self::OracleNetworkMismatch,
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::IdentityProtocolUnsupported { .. },
            }) => Self::OracleProtocolUnsupported,
            _ => Self::OracleIdentityUnavailable,
        }
    }
}

impl ReconcileFailure {
    /// The error the wallet reports for the failure:
    /// `network.rpc_unreachable` for an endpoint that could not be read, the
    /// code the status surfaces report when the endpoint cannot be asked
    /// about a transaction, and `network.witness_unavailable` for a mainnet
    /// profile without an oracle or with an oracle that did not establish
    /// that it serves mainnet, the code the cross-check reports for them.
    #[must_use]
    pub fn to_network_error(&self) -> stellar_agent_core::error::NetworkError {
        use stellar_agent_core::error::{NetworkError, WitnessUnavailableReason as Reason};
        let witness = |reason| NetworkError::WitnessUnavailable { reason };
        let authority = || self.endpoint.clone();
        match self.kind {
            ReconcileFailureKind::Unreachable => NetworkError::RpcUnreachable {
                url: self.endpoint.clone(),
                reason: self.reason.clone(),
            },
            ReconcileFailureKind::OracleNotConfigured => witness(Reason::OracleNotConfigured),
            ReconcileFailureKind::OracleNetworkMismatch => {
                witness(Reason::IdentityNetworkMismatch {
                    authority: authority(),
                })
            }
            ReconcileFailureKind::OracleProtocolUnsupported => {
                witness(Reason::IdentityProtocolUnsupported {
                    authority: authority(),
                })
            }
            ReconcileFailureKind::OracleIdentityUnavailable => {
                witness(Reason::IdentityUnavailable {
                    authority: authority(),
                })
            }
        }
    }
}

/// One submission a reconciliation pass settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledSubmission {
    /// The envelope hash naming the submission record.
    pub envelope_hash: String,
    /// The transaction the chain answered for, in full.
    pub tx_hash: String,
    /// The status the receipt now holds: `Success` or `Failed` for a
    /// definitive answer, `Ambiguous` for a release on chain evidence.
    pub status: ReceiptStatus,
    /// The chain evidence of a release whose outcome is unknown; `None` for a
    /// definitive answer.
    ///
    /// The caller writes the settled `value_action_failed` row under the
    /// evidence's wire code.
    pub release_code: Option<ReleaseEvidence>,
    /// The ledger the transaction confirmed in, when it did.
    pub ledger: Option<u32>,
}

/// One `StateKey` bucket (everything but the profile name, which is implied
/// by the file's identity) and its accumulated records.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct WireBucket {
    pub(super) scope_specificity: u8,
    pub(super) bucket: String,
    pub(super) window_secs: u64,
    pub(super) records: Vec<WireRecord>,
}

/// The canonical JSON body. `version` is the wire-format version, distinct
/// from any criterion or policy-document version — bumped only if this
/// store's own wire shape changes. `generation` is the anti-rollback counter
/// — see the module docs' "Anti-rollback" section; it MUST equal the
/// keyring-held generation counter for the file to be accepted.
///
/// Version 4 adds the mainnet authorization ledger: `authorizations`, the
/// record history, and `holds`, the window entries open authorizations own.
/// Both are omitted while empty, so a snapshot without authorization history
/// serializes exactly as version 3 does.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(super) struct WireFile {
    pub(super) version: u32,
    pub(super) generation: u64,
    pub(super) entries: Vec<WireBucket>,
    /// Mainnet authorization records, open and settled, until pruned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) authorizations: Vec<WireAuthorization>,
    /// The holds of open authorizations, keyed by `(authorization, ordinal)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) holds: Vec<WireAuthorizationHold>,
    /// Prepared next generation, authenticated with the current snapshot.
    /// The keyring counter selects exactly one side of the atomic commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) prepared: Option<Box<WireFile>>,
}

/// Decimal-string `i128` serde adapter, mirroring
/// `stellar_agent_core::wire_stroops::i128` / `audit_log::schema::i128_decimal_str` —
/// this crate cannot import those (private to their defining modules), and an
/// `i128` on the wire as a bare JSON number risks float round-tripping through
/// a permissive deserializer, so amounts are always decimal strings here too.
pub(super) mod i128_decimal_str {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &i128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<i128>()
            .map_err(|e| serde::de::Error::custom(format!("invalid i128 decimal string: {e}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PersistedWindowStore
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a store operation minted a fresh HMAC key (the keyring entry did
/// not previously exist).
///
/// Callers use this to decide whether to emit a `keyring_key_written` audit
/// row — the store itself has no audit-writer handle, so minting is reported
/// back rather than logged internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintOutcome {
    /// `true` when this call minted the HMAC key (it was absent beforehand).
    pub newly_minted: bool,
}

/// Successful recorded reset, including the snapshot written before mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetOutcome {
    /// Whether the reset minted a key.
    pub mint: MintOutcome,
    /// Accrual passed to the recorder.
    pub accrual: WipedAccrualRecord,
}

/// A defect that leaves a mainnet profile's window-state store unverifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateDefect {
    /// The file is missing while the keyring holds a committed generation.
    MissingFileWithGeneration,
    /// The file exists and its HMAC key does not.
    MissingKey,
    /// The file exists and its HMAC key is not 32 bytes of base64.
    BadKey,
    /// The file is truncated, is not the store's JSON, carries an invalid
    /// version, or breaks a ledger invariant.
    Malformed,
    /// The file's HMAC tag does not verify under its key.
    HmacInvalid,
    /// The file's generation, or its body, does not match the keyring's
    /// committed generation.
    GenerationMismatch,
}

impl StateDefect {
    /// The defect's stable snake-case label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::MissingFileWithGeneration => "missing_file_with_generation",
            Self::MissingKey => "missing_key",
            Self::BadKey => "bad_key",
            Self::Malformed => "malformed",
            Self::HmacInvalid => "hmac_invalid",
            Self::GenerationMismatch => "generation_mismatch",
        }
    }
}

impl std::fmt::Display for StateDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The reset's live accrual, store digest and any mainnet state defect.
/// The recorder can read the policy pin through [`Self::pin`] under the held
/// store lock. Only the store constructs this record and its scoped guard.
#[derive(Debug, Clone, Copy)]
pub struct ResetRecord<'a> {
    /// The live accrual of the store being replaced.
    pub accrual: &'a WipedAccrualRecord,
    /// The defect the reset recovers from; `None` for verifiable state, a
    /// genuine first run, a testnet profile, or a build without mainnet
    /// writes.
    pub defect: Option<StateDefect>,
    /// SHA-256 of the exact store bytes read, or `None` for a missing file.
    pub store_sha256: Option<[u8; 32]>,
    guard: &'a WindowStoreLock,
    scope: PinScope<'a>,
}

impl ResetRecord<'_> {
    /// Reads the policy pin under the reset's held store lock.
    ///
    /// # Errors
    /// Refuses a guard mismatch or an unreadable or malformed pin.
    pub fn pin(&self) -> Result<PinState, PinError> {
        pin::read(self.guard, &self.scope)
    }
}

/// Failure of the recorded reset ceremony.
#[derive(Debug, thiserror::Error)]
pub enum ResetError<E> {
    /// Store failure before or after the row was recorded.
    #[error("{error}")]
    Store {
        /// Underlying store failure.
        error: WindowStoreError,
        /// Whether this reset minted a key before failing.
        minted: bool,
    },
    /// The recorder refused; durable store state is unchanged.
    #[error("{0}")]
    Recorder(E),
}

/// The HMAC-protected, single-writer, atomically-written per-profile policy
/// window-state store. See the [`super`] module docs for the full design.
#[derive(Debug, Clone)]
pub struct PersistedWindowStore {
    path: PathBuf,
}

/// What the reset established before its recorder runs.
struct ResetSnapshot {
    store_sha256: Option<[u8; 32]>,
    key: Option<zeroize::Zeroizing<[u8; 32]>>,
    accrual: WipedAccrualRecord,
    defect: Option<StateDefect>,
}

/// Whether the mainnet rules apply to `profile`: a mainnet profile in a build
/// with mainnet writes.
fn mainnet_rules(profile: &Profile) -> bool {
    cfg!(feature = "mainnet-write") && profile.chain_id.is_mainnet()
}

/// The defect a loading error names, when it names one.
fn defect_of(error: &WindowStoreError, file_missing: bool) -> Option<StateDefect> {
    match error {
        WindowStoreError::GenerationMismatch if file_missing => {
            Some(StateDefect::MissingFileWithGeneration)
        }
        WindowStoreError::GenerationMismatch => Some(StateDefect::GenerationMismatch),
        WindowStoreError::HmacMismatch => Some(StateDefect::HmacInvalid),
        WindowStoreError::Invalid { .. } => Some(StateDefect::Malformed),
        _ => None,
    }
}

/// The defect a key load failure names, when it names one: an absent key or
/// a stored value that is not 32 bytes of base64.
fn key_defect_of(error: &stellar_agent_core::error::WalletError) -> Option<StateDefect> {
    use stellar_agent_core::error::{AuthError, InternalError, WalletError};
    match error {
        WalletError::Auth(AuthError::KeyringNotFound { .. }) => Some(StateDefect::MissingKey),
        WalletError::Internal(InternalError::UnexpectedState { detail })
            if detail.starts_with("audit.key_length_error:")
                || detail.starts_with("audit.key_decode_failed:") =>
        {
            Some(StateDefect::BadKey)
        }
        _ => None,
    }
}

/// Replaces a loading error of a mainnet profile with the unverifiable
/// refusal naming its defect; every other error, and every error under the
/// testnet and build-without-mainnet-writes rules, passes unchanged.
fn mainnet_loading_error(
    #[cfg_attr(
        not(feature = "mainnet-write"),
        expect(unused_variables, reason = "only the mainnet rules read the profile")
    )]
    profile: &Profile,
    error: WindowStoreError,
    #[cfg_attr(
        not(feature = "mainnet-write"),
        expect(unused_variables, reason = "only the mainnet rules name the defect")
    )]
    defect: Option<StateDefect>,
) -> WindowStoreError {
    #[cfg(feature = "mainnet-write")]
    if mainnet_rules(profile)
        && let Some(defect) = defect
    {
        return WindowStoreError::MainnetStateUnverifiable { defect };
    }
    error
}

/// The keyring error a key load failure becomes, or the unverifiable refusal
/// for a mainnet profile whose key is absent or unusable while its file
/// exists.
fn key_load_error(
    profile: &Profile,
    error: &stellar_agent_core::error::WalletError,
) -> WindowStoreError {
    mainnet_loading_error(
        profile,
        WindowStoreError::Keyring {
            detail: format!("{error}"),
        },
        key_defect_of(error),
    )
}

impl PersistedWindowStore {
    /// Constructs a store handle for the OS-conventional path for
    /// `profile_name` (`<state>/stellar-agent/policy/<profile_name>.window`).
    #[must_use]
    pub fn for_profile(profile_name: &str) -> Self {
        Self {
            path: default_policy_window_state_path_for(profile_name),
        }
    }

    /// Constructs a store handle at an explicit path — used by tests and by
    /// callers that override the OS-conventional state directory.
    #[must_use]
    pub fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns `true` if the store file exists on disk.
    ///
    /// Used before a pre-rotation integrity check: a file that exists but was
    /// signed by a key the keyring never minted (the keyring entry for
    /// `policy_window_state_key_id` is absent) cannot be verified against any
    /// legitimate prior key, and must be treated as suspicious rather than
    /// silently re-signed.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn lock_path(&self) -> PathBuf {
        window_lock_path(&self.path)
    }

    /// The store file's path.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Loads every persisted entry into `dest`, verifying the HMAC tag AND
    /// the anti-rollback generation under `profile.policy_window_state_key_id`.
    ///
    /// `profile_name` is the same profile-name string the caller passes to
    /// `PolicyEngineV1::new(_with_store)` / criterion evaluation — used to
    /// reconstruct each [`StateKey`] so a hydrated entry's key is identical to
    /// the key a criterion derives at `evaluate` time. Read from the profile
    /// struct itself, NOT re-derived from `policy_window_state_key_id`: an
    /// operator-overridden (non-name-derived) keyring coordinate must not
    /// change which profile a hydrated entry's `StateKey` belongs to.
    ///
    /// A missing store file with no keyring generation counter minted is
    /// treated as empty history (`Ok(())`, no entries appended) — a genuine
    /// first run for this profile. A missing file WITH a minted generation
    /// counter is deletion — see [`WindowStoreError::GenerationMismatch`].
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::HmacMismatch`] — tampering, corruption, or a
    ///   stale key.
    /// - [`WindowStoreError::GenerationMismatch`] — the file's generation does
    ///   not match the keyring's, or one of the two is present without the
    ///   other (deletion or rollback — see the module docs).
    /// - [`WindowStoreError::Invalid`] — the file is truncated or not valid
    ///   JSON in the expected shape.
    /// - [`WindowStoreError::Keyring`] — the HMAC key could not be loaded
    ///   (and the file exists, so a key SHOULD be present — a store file can
    ///   only have been written after the key was minted).
    /// - [`WindowStoreError::Io`] — the file could not be read for a reason
    ///   other than not existing.
    pub fn load_into(
        &self,
        profile_name: &str,
        profile: &Profile,
        dest: &PolicyStateStore,
    ) -> Result<(), WindowStoreError> {
        let entry_ref = &profile.policy_window_state_key_id;
        refuse_owner_coordinate(profile)?;
        let gen_entry = generation_entry_ref(profile);

        // Check file existence BEFORE loading the HMAC key: a genuinely
        // fresh profile (no file, no minted key) must not require a key
        // load at all — `load_hmac_key_32` would fail (`NoEntry`) for a
        // profile that has never recorded anything, and that failure must
        // not be conflated with a real integrity error. `read_verified`
        // (used by `record_and_persist`/`reset`) does not have this problem:
        // those callers always hold an already-minted key via
        // `load_or_mint_key`.
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return match load_generation(&gen_entry)? {
                    None => Ok(()), // genuine first run — no key, no file, no history.
                    // Deletion detected.
                    Some(_) => Err(mainnet_loading_error(
                        profile,
                        WindowStoreError::GenerationMismatch,
                        Some(StateDefect::MissingFileWithGeneration),
                    )),
                };
            }
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };

        let key =
            crate::keyring::load_hmac_key_32(entry_ref).map_err(|e| key_load_error(profile, &e))?;
        refuse_owner_public_key(
            key.as_ref(),
            &OwnerKeyContext::for_profile(profile_name, profile),
        )?;
        let counter = load_counter(&gen_entry)?;
        let wire = self
            .verify_with_key(&key, &bytes)
            .and_then(|wire| select_generation(wire, counter))
            .map_err(|e| {
                let defect = defect_of(&e, false);
                mainnet_loading_error(profile, e, defect)
            })?;

        for entry in wire.entries {
            let key = StateKey::new(
                profile_name,
                entry.scope_specificity,
                &entry.bucket,
                entry.window_secs,
            );
            for record in entry.records {
                let appended = if record.status == RecordStatus::Pending {
                    dest.append_pending(&key, record.ts_ms, record.amount)
                } else {
                    dest.append(&key, record.ts_ms, record.amount)
                };
                appended.map_err(|e| WindowStoreError::Invalid {
                    detail: format!("in-memory store append failed: {e}"),
                })?;
            }
        }
        Ok(())
    }

    /// Locks, re-reads and fully verifies the current on-disk state (HMAC +
    /// generation — the source of truth, correct even if another process
    /// wrote since this process last hydrated), appends `new_entries`, prunes
    /// entries older than the 1-week retention ceiling, bumps the generation
    /// counter, HMAC-signs under the NEW generation, and atomically writes.
    ///
    /// Lazily mints the HMAC key on the first write for a profile (the
    /// caller should emit a `keyring_key_written` audit row when
    /// [`MintOutcome::newly_minted`] is `true`).
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`]. A tampered, deleted, or rolled-back EXISTING
    /// file fails closed (`HmacMismatch` / `GenerationMismatch` / `Invalid`)
    /// rather than silently overwriting history with only the new entries —
    /// an operator must run `profile reset-window-state` to recover.
    pub fn record_and_persist(
        &self,
        profile: &Profile,
        new_entries: &[WindowEntry],
    ) -> Result<MintOutcome, WindowStoreError> {
        self.record_settled(profile, new_entries, false)
    }

    /// Admits authorized external-settlement spend before credential release.
    ///
    /// The exclusive lock covers the file read, the same whole-batch comparison
    /// used by reservations, and the write. Admitted spend is retained as window
    /// usage because a released credential can be redeemed outside this wallet.
    ///
    /// # Errors
    ///
    /// Returns [`WindowStoreError::PolicyDenied`] without recording any entry
    /// when the batch exceeds a window limit. Integrity and I/O errors also
    /// withhold authorization.
    pub fn record_authorized(
        &self,
        profile: &Profile,
        new_entries: &[WindowEntry],
    ) -> Result<MintOutcome, WindowStoreError> {
        self.record_settled(profile, new_entries, true)
    }

    fn record_settled(
        &self,
        profile: &Profile,
        new_entries: &[WindowEntry],
        require_admission: bool,
    ) -> Result<MintOutcome, WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire_with_retry(&self.lock_path())?;

        let (key, mint_outcome) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);

        let mut wire = self.read_verified(profile, &key, &gen_entry)?;
        let now_ms = now_ms()?;
        // Expired authorizations release their holds before the window is
        // counted; the holds that remain count against it.
        ledger::sweep_expired(&mut wire, now_ms);
        if require_admission {
            admit(&wire, new_entries)?;
        }

        for entry in new_entries {
            let bucket = find_or_insert_bucket(&mut wire.entries, entry.key());
            bucket.records.push(WireRecord {
                ts_ms: entry.timestamp_ms(),
                amount: entry.amount(),
                ..WireRecord::confirmed_defaults()
            });
        }

        prune_stale(&mut wire, now_ms);
        wire.version = select_wire_version(&wire);

        wire.generation = next_generation(&gen_entry)?;
        write_generation(&gen_entry, &wire)?;
        self.write_atomic(&key, &wire)?;
        Ok(mint_outcome)
    }

    /// Records `new_entries` as a reservation held by `reservation`, under the
    /// same lock, pruning and generation discipline as
    /// [`Self::record_and_persist`].
    ///
    /// A reservation counts toward every window criterion exactly as confirmed
    /// spend does: the transaction has been sent and may apply, so the
    /// operator's cap has to hold against it. It is settled by
    /// [`Self::confirm`], [`Self::release`], or a reconciliation pass.
    ///
    /// # Admission
    ///
    /// The policy gate evaluates a call against the window state it read
    /// before the transaction was built and signed. This write is where the
    /// spend is reserved, and it holds the store's exclusive lock, so it
    /// re-applies the governing criterion's comparison here: against the file
    /// it has just read and verified, at each entry's own timestamp, with the
    /// entries of this batch accumulating against each other on a shared key.
    /// A same-key pending record dated past the clock-skew tolerance fails the gate's
    /// query closed and is refused here the same way.
    /// A batch that would take any bucket past the limit its entry carries is
    /// refused as [`WindowStoreError::PolicyDenied`] before anything is
    /// written. Admission is whole-batch: every entry is written, or none is.
    ///
    /// # One reservation per envelope
    ///
    /// The reservation id is the envelope hash of the signed bytes. A file
    /// that already holds a record under that id, pending or confirmed, has
    /// already counted those bytes, so a second reservation is refused as
    /// [`WindowStoreError::DuplicateReservation`] before admission. The
    /// check runs under the lock; a caller asks
    /// [`Self::holds_reservation`] first so that the refusal precedes its
    /// own records.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`]. A batch a bucket can no longer admit is
    /// [`WindowStoreError::PolicyDenied`], carrying the denial the criterion
    /// itself produces for that condition.
    pub fn record_pending(
        &self,
        profile: &Profile,
        new_entries: &[WindowEntry],
        reservation: &SubmissionHold,
    ) -> Result<MintOutcome, WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire_with_retry(&self.lock_path())?;

        let (key, mint_outcome) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let mut wire = self.read_verified(profile, &key, &gen_entry)?;
        let now_ms = now_ms()?;

        if file_holds_id(&wire, &reservation.id) {
            return Err(WindowStoreError::DuplicateReservation);
        }
        // Expired authorizations release their holds before the window is
        // counted; the holds that remain count against it.
        ledger::sweep_expired(&mut wire, now_ms);
        admit(&wire, new_entries)?;

        for entry in new_entries {
            let bucket = find_or_insert_bucket(&mut wire.entries, entry.key());
            bucket.records.push(WireRecord {
                ts_ms: entry.timestamp_ms(),
                amount: entry.amount(),
                id: reservation.id.clone(),
                status: RecordStatus::Pending,
                tx_hash: reservation.tx_hash.clone(),
                source: reservation.source.clone(),
                sequence: reservation.sequence,
                max_time: reservation.max_time,
                pending_since_ms: reservation.pending_since_ms,
                submission_ledger: reservation.submission_ledger,
                operator_required: false,
            });
        }

        prune_stale(&mut wire, now_ms);
        wire.version = select_wire_version(&wire);
        wire.generation = next_generation(&gen_entry)?;
        write_generation(&gen_entry, &wire)?;
        self.write_atomic(&key, &wire)?;
        Ok(mint_outcome)
    }

    /// Marks every record held by reservation `id` confirmed.
    ///
    /// Confirmed spend ages from the applying ledger's close time, and never
    /// from a time before the record was taken: a transaction applies after
    /// it was sent, so a reported close time earlier than the record's own
    /// timestamp is not one the chain can produce, and taking it would date
    /// the spend out of its window at once. A close time later than the
    /// record's timestamp is kept as received. A missing or invalid close
    /// time leaves the hold pending because its age is unknown.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn confirm(
        &self,
        profile: &Profile,
        id: &str,
        created_at: Option<i64>,
    ) -> Result<(), WindowStoreError> {
        let close_ms = created_at
            .and_then(|time| u64::try_from(time).ok())
            .filter(|time| *time > 0)
            .and_then(|time| time.checked_mul(1_000));
        let Some(close_ms) = close_ms else {
            tracing::warn!(
                "window confirm: applying ledger close time unavailable; reservation stays pending"
            );
            return Ok(());
        };
        self.rewrite_records(profile, |wire| {
            let mut touched = false;
            for bucket in &mut wire.entries {
                for record in &mut bucket.records {
                    if record.id == id && record.status == RecordStatus::Pending {
                        record.status = RecordStatus::Confirmed;
                        record.ts_ms = close_ms.max(record.ts_ms);
                        touched = true;
                    }
                }
            }
            touched
        })
    }

    /// Removes every pending record held by reservation `id`.
    ///
    /// Called where the transaction can no longer apply: the network refused
    /// it, it failed on-chain, reconciliation established that it cannot
    /// land, or an operator acknowledged it. The reserved amount stops
    /// counting against the window.
    ///
    /// A confirmed record carrying `id` is kept: it is spend the chain
    /// applied, and it counts until it ages out of its window. A release for a
    /// reservation that holds no pending record changes nothing and writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn release(&self, profile: &Profile, id: &str) -> Result<(), WindowStoreError> {
        self.rewrite_records(profile, |wire| {
            let before: usize = wire.entries.iter().map(|b| b.records.len()).sum();
            for bucket in &mut wire.entries {
                bucket
                    .records
                    .retain(|r| r.id != id || r.status != RecordStatus::Pending);
            }
            wire.entries.retain(|b| !b.records.is_empty());
            let after: usize = wire.entries.iter().map(|b| b.records.len()).sum();
            after != before
        })
    }

    /// Keeps an orphan's authenticated identity and debit while excluding it
    /// from automatic reconciliation until an operator resolves its outcome.
    fn mark_operator_required(&self, profile: &Profile, id: &str) -> Result<(), WindowStoreError> {
        let result = self.rewrite_records(profile, |wire| {
            let mut touched = false;
            for bucket in &mut wire.entries {
                for record in &mut bucket.records {
                    if record.id == id
                        && record.status == RecordStatus::Pending
                        && !record.operator_required
                    {
                        record.operator_required = true;
                        touched = true;
                    }
                }
            }
            touched
        });
        if let Err(error) = &result {
            tracing::warn!(
                ?error,
                "window reconcile: operator marker write failed; reservation remains selectable"
            );
        }
        result
    }

    /// Whether any record in the file, pending or confirmed, carries
    /// reservation `id`.
    ///
    /// The reservation id is the envelope hash of the signed bytes, so a
    /// `true` answer means the window has already counted those bytes. An
    /// empty `id` matches nothing: confirmed spend recorded without a
    /// reservation carries an empty id.
    ///
    /// Verifies the file's HMAC tag and generation, like every other read,
    /// and takes no lock.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn holds_reservation(&self, profile: &Profile, id: &str) -> Result<bool, WindowStoreError> {
        Ok(self
            .read_for_inspection(profile)?
            .is_some_and(|wire| file_holds_id(&wire, id)))
    }

    /// Returns every reservation the file currently holds pending, oldest
    /// first.
    ///
    /// Verifies the file's HMAC tag and generation, like every other read.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub fn pending_reservations(
        &self,
        profile: &Profile,
    ) -> Result<Vec<SubmissionHold>, WindowStoreError> {
        let wire = match self.read_for_inspection(profile)? {
            Some(wire) => wire,
            None => return Ok(Vec::new()),
        };
        Ok(collect_pending(&wire))
    }

    /// Settles up to `budget` reservations that have stood at least
    /// [`RECONCILE_MIN_AGE_MS`], oldest first, on chain answers.
    ///
    /// Per reservation, `getTransaction` answers of `client`, the primary
    /// endpoint:
    ///
    /// - `SUCCESS` confirms the reservation and finalizes the receipt.
    /// - `FAILED` releases the reservation and finalizes the receipt failed.
    /// - `NOT_FOUND` is only evidence when the endpoint would still remember
    ///   the transaction. When the reservation's submission ledger predates
    ///   the endpoint's retention floor it proves nothing, so the reservation
    ///   stands and the receipt is marked ambiguous, without release evidence,
    ///   for an operator to resolve. A submission ledger of 0 cannot be
    ///   compared with the floor, so that reservation stands as well.
    ///   Otherwise the reservation is released when the source account's
    ///   sequence has reached the one the transaction needs, or an observed
    ///   ledger close time is strictly past its nonzero time bound. Both arms
    ///   require a fresh `NOT_FOUND`; a fresh definitive answer settles the
    ///   spend. Missing chain time closes only the time arm.
    /// - A release on that evidence marks the receipt ambiguous and records
    ///   the evidence on it ([`ReleaseEvidence::SequenceConsumed`] or
    ///   [`ReleaseEvidence::TimeBoundPassed`]). A missing receipt is restored
    ///   from the reservation's identity first, the way a definitive answer
    ///   restores one, and the release is reported in
    ///   [`ReconcileReport::settled`] so the caller writes its settled row.
    ///
    /// The receipt is never evidence. A receipt that already records release
    /// evidence, from a release whose window write did not complete, is
    /// settled by the rule above like any other: both release conditions
    /// stay true once they hold, so the evidence is found again while the
    /// endpoint holds the submission's ledger range, and the release then
    /// carries the evidence the receipt recorded.
    ///
    /// # Mainnet
    ///
    /// On a mainnet profile the primary endpoint's `FAILED` and `NOT_FOUND`
    /// settle nothing by themselves; `oracle`, the profile's oracle endpoint,
    /// is asked for the same hash. Before its first answer counts, the pass
    /// checks once that the oracle reports the mainnet passphrase, with one
    /// `getNetwork` request charged to the pass's allowance and not retried;
    /// an oracle that reports another
    /// network, or whose identity cannot be read, settles nothing in that
    /// pass. Its `SUCCESS` confirms and its `FAILED` releases, as above. Its
    /// `NOT_FOUND` runs the `NOT_FOUND` rule above against the oracle alone:
    /// the oracle's retention floor, its latest ledger close time, its
    /// account sequence and its fresh answer. With no oracle (`oracle` is
    /// `None`), an oracle that fails the identity check, or an oracle that
    /// cannot answer, the reservation stands and the failure is reported in
    /// [`ReconcileReport::endpoint_failure`], as
    /// [`ReconcileFailureKind::OracleNotConfigured`] when there is no oracle.
    /// The primary's `SUCCESS` confirms as on any chain. `oracle` is not read
    /// for any other profile.
    ///
    /// An endpoint that cannot answer leaves the reservation standing and is
    /// reported in [`ReconcileReport::endpoint_failure`]. Nothing here
    /// releases a reservation on a transport error.
    ///
    /// `now_ms` is the caller's clock, the same seam every other store
    /// operation takes it through.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`]. A per-reservation endpoint failure is not an
    /// error: it leaves that reservation standing and the pass continues.
    pub async fn reconcile_due(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        oracle: Option<&crate::client::StellarRpcClient>,
        receipts: Option<&ReceiptStore>,
        now_ms: u64,
        budget: usize,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let Some(wire) = self.read_for_inspection(profile)? else {
            return Ok(ReconcileReport::default());
        };

        // Oldest first, skipping ambiguous receipts without release evidence:
        // the budget goes only to reservations the endpoint can still answer
        // for. An ambiguous receipt with evidence is a release whose window
        // step did not complete; this pass settles it again from the chain.
        // Cleared receipts also need no endpoint answer.
        // One read of the receipt file for the whole pass. The filter below
        // consults it per candidate, and re-reading it each time would cost a
        // lock acquisition and a full parse for every reservation in the file.
        //
        // A read failure leaves the map empty, which makes the filter below
        // admit every reservation rather than exclude the ones the endpoint
        // cannot answer for. That is the safe direction — a pass that examines
        // too much settles nothing wrongly — but it is silent, so it is
        // logged: the same unreadable file is what the per-reservation read
        // below reports too.
        let known: HashMap<String, (ReceiptStatus, Option<ReleaseEvidence>)> =
            match receipts.map(ReceiptStore::all) {
                Some(Ok(all)) => all
                    .into_iter()
                    .map(|r| (r.envelope_hash, (r.status, r.release_code)))
                    .collect(),
                Some(Err(e)) => {
                    tracing::debug!(
                        error = %e,
                        "window reconcile: the receipt store could not be read; the starvation \
                         filter admits every reservation this pass"
                    );
                    HashMap::new()
                }
                None => HashMap::new(),
            };

        let due: Vec<SubmissionHold> = collect_pending(&wire)
            .into_iter()
            .filter(|r| now_ms.saturating_sub(r.pending_since_ms) >= RECONCILE_MIN_AGE_MS)
            .filter(|r| !r.operator_required && !outcome_already_unknown(&known, &r.id))
            .take(budget)
            .collect();

        let mut report = ReconcileReport::default();
        let mut pass = ReconcilePass::new(budget, profile.chain_id.is_mainnet());

        for reservation in due {
            report.examined += 1;
            let settlement = self
                .settle_reservation(profile, client, oracle, receipts, &reservation, &mut pass)
                .await?;
            record_settlement(&mut report, &reservation, settlement);
        }

        report.rpc_calls = pass.spent;
        report.endpoint_failure = pass.failure;
        Ok(report)
    }

    /// Settles one named submission, with no budget and no minimum age.
    ///
    /// The operator or the agent asked about this submission by name, so the
    /// bound a background pass needs does not apply: the work covers one
    /// requested submission. The release rule is the same one
    /// [`Self::reconcile_due`] applies.
    ///
    /// Works whether or not the submission holds a reservation. An action the
    /// policy engine sized no value for takes none, and its receipt is still
    /// the handle the agent reconciles with, so the identity is taken from the
    /// receipt when the window file holds no record for it. Settling the
    /// window is then a no-op.
    ///
    /// On a mainnet profile `oracle` witnesses the primary's negative
    /// answers, as [`Self::reconcile_due`] describes.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    pub async fn reconcile_one(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        oracle: Option<&crate::client::StellarRpcClient>,
        receipts: Option<&ReceiptStore>,
        id: &str,
        _now_ms: u64,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let pass = ReconcilePass::new(1, profile.chain_id.is_mainnet());
        self.reconcile_one_in(profile, client, oracle, receipts, id, pass)
            .await
    }

    /// Settles one named submission as [`Self::reconcile_one`] does, for a
    /// caller that already checked the oracle and holds a resource across the
    /// pass.
    ///
    /// `oracle` is taken as checked: its identity is not read again. Every
    /// read of it ends by `oracle_deadline`; a read still open then leaves
    /// the reservation standing and is reported in
    /// [`ReconcileReport::endpoint_failure`] as an unreachable endpoint, so
    /// the pass returns by that deadline whatever the oracle does. Reads of
    /// the primary endpoint keep their own bounds.
    ///
    /// # Errors
    ///
    /// See [`WindowStoreError`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the arguments of reconcile_one plus the checked oracle's deadline"
    )]
    pub async fn reconcile_one_within(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        oracle: Option<MainnetOracle<'_>>,
        receipts: Option<&ReceiptStore>,
        id: &str,
        _now_ms: u64,
        oracle_deadline: tokio::time::Instant,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let pass = ReconcilePass::new(1, profile.chain_id.is_mainnet())
            .with_checked_oracle(oracle, oracle_deadline);
        self.reconcile_one_in(
            profile,
            client,
            oracle.map(MainnetOracle::client),
            receipts,
            id,
            pass,
        )
        .await
    }

    /// The single-submission pass of [`Self::reconcile_one`] and
    /// [`Self::reconcile_one_within`], run with `pass`.
    async fn reconcile_one_in<'o>(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        oracle: Option<&'o crate::client::StellarRpcClient>,
        receipts: Option<&ReceiptStore>,
        id: &str,
        mut pass: ReconcilePass<'o>,
    ) -> Result<ReconcileReport, WindowStoreError> {
        let open = match self.read_for_inspection(profile)? {
            Some(wire) => collect_pending(&wire).into_iter().find(|r| r.id == id),
            None => None,
        };
        let reservation =
            match open.or_else(|| receipts.and_then(|s| reservation_from_receipt(s, id))) {
                Some(r) => r,
                None => return Ok(ReconcileReport::default()),
            };

        let mut report = ReconcileReport {
            examined: 1,
            ..ReconcileReport::default()
        };
        let settlement = self
            .settle_reservation(profile, client, oracle, receipts, &reservation, &mut pass)
            .await?;
        record_settlement(&mut report, &reservation, settlement);
        report.rpc_calls = pass.spent;
        report.endpoint_failure = pass.failure;
        Ok(report)
    }

    /// Records the live accrual under the window lock, then replaces the store
    /// with an authenticated empty body at the next generation.
    ///
    /// The recorder runs before minting a key or writing either durable state.
    /// An unverifiable file carries no totals; read and keyring errors refuse.
    ///
    /// For a mainnet profile in a build with mainnet writes, two rules apply.
    /// Verifiable state that still holds an effective open authorization
    /// refuses before the recorder, with nothing changed. Unverifiable state
    /// resets, and the recorder receives the defect it recovers from, so its
    /// audit row names it. Expired authorizations are released in memory only:
    /// nothing persists before the recorder succeeds. A missing file with no
    /// committed generation is a genuine first run and carries no defect.
    ///
    /// # Errors
    ///
    /// Returns a store failure or the recorder's refusal. A store failure reports
    /// whether this operation minted a key before it failed.
    pub fn reset<E>(
        &self,
        profile: &Profile,
        now_ms: u64,
        record: impl FnOnce(&ResetRecord<'_>) -> Result<(), E>,
    ) -> Result<ResetOutcome, ResetError<E>> {
        let before_mint = |error| ResetError::Store {
            error,
            minted: false,
        };
        self.ensure_parent_dir().map_err(before_mint)?;
        let lock = WindowStoreLock::acquire_for_with_retry(
            &self.path,
            &profile.policy_window_state_key_id,
        )
        .map_err(|e| before_mint(e.into()))?;
        let snapshot = self.reset_snapshot(profile, now_ms).map_err(before_mint)?;
        record(&ResetRecord {
            accrual: &snapshot.accrual,
            defect: snapshot.defect,
            store_sha256: snapshot.store_sha256,
            guard: &lock,
            scope: PinScope::for_profile(&self.path, profile),
        })
        .map_err(ResetError::Recorder)?;
        let accrual = snapshot.accrual;
        let mut minted = false;
        let mutation = (|| {
            let key = match snapshot.key {
                Some(key) => key,
                None => {
                    let entry = &profile.policy_window_state_key_id;
                    crate::keyring::rotate_keyring_secret_32(&entry.service, &entry.account)
                        .map_err(|e| WindowStoreError::Keyring {
                            detail: e.to_string(),
                        })?;
                    minted = true;
                    crate::keyring::load_hmac_key_32(entry).map_err(|e| {
                        WindowStoreError::Keyring {
                            detail: e.to_string(),
                        }
                    })?
                }
            };
            let empty = WireFile {
                version: WIRE_VERSION_COMPACT,
                generation: accrual.generation_after,
                ..WireFile::default()
            };
            write_generation(&generation_entry_ref(profile), &empty)?;
            self.write_atomic(&key, &empty)
        })();
        mutation.map_err(|error| ResetError::Store { error, minted })?;
        Ok(ResetOutcome {
            mint: MintOutcome {
                newly_minted: minted,
            },
            accrual,
        })
    }

    fn reset_snapshot(
        &self,
        profile: &Profile,
        now_ms: u64,
    ) -> Result<ResetSnapshot, WindowStoreError> {
        refuse_owner_coordinate(profile)?;
        let mut key_defect = None;
        let key = match crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id) {
            Ok(key) => {
                refuse_owner_public_key(
                    key.as_ref(),
                    &OwnerKeyContext::for_loaded_profile(profile),
                )?;
                Some(key)
            }
            // An absent key, or a stored value that is not base64 or not 32
            // bytes, is no usable key: the file is unverifiable and the key is
            // replaced after the row.
            Err(e) if key_defect_of(&e).is_some() => {
                key_defect = key_defect_of(&e);
                None
            }
            Err(e) => {
                return Err(WindowStoreError::Keyring {
                    detail: e.to_string(),
                });
            }
        };
        let counter = load_counter(&generation_entry_ref(profile))?;
        let generation_before = counter.as_ref().map(|state| state.generation);
        let generation_after = increment_generation(generation_before.unwrap_or(0))?;
        let mut accrual = WipedAccrualRecord {
            previous: PreviousState::Missing,
            entry_count: 0,
            buckets: Vec::new(),
            truncated: false,
            generation_before,
            generation_after,
        };
        let mainnet = mainnet_rules(profile);
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A committed generation without its file is a deletion; no
                // committed generation is a genuine first run.
                let defect = (mainnet && generation_before.is_some())
                    .then_some(StateDefect::MissingFileWithGeneration);
                return Ok(ResetSnapshot {
                    store_sha256: None,
                    key,
                    accrual,
                    defect,
                });
            }
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        accrual.previous = PreviousState::Unverifiable;
        let mut defect = key_defect;
        if let Some(key) = &key {
            match self
                .verify_with_key(key, &bytes)
                .and_then(|wire| select_generation(wire, counter))
            {
                Ok(mut wire) => {
                    accrual.previous = PreviousState::Verified;
                    // Authorization lifetimes are measured on the store's own
                    // clock, as every ledger transition measures them.
                    let clock = crate::policy_state::store::now_ms()?;
                    #[cfg(feature = "mainnet-write")]
                    if mainnet {
                        let open = ledger::effective_open_count(&wire, clock);
                        if open > 0 {
                            return Err(WindowStoreError::OpenAuthorizations { open });
                        }
                    }
                    ledger::sweep_expired(&mut wire, clock);
                    // The holds of authorizations still open count as the
                    // pending spend they hold.
                    for hold in std::mem::take(&mut wire.holds) {
                        let key = StateKey::new(
                            "",
                            hold.scope_specificity,
                            &hold.bucket,
                            hold.window_secs,
                        );
                        find_or_insert_bucket(&mut wire.entries, &key)
                            .records
                            .push(WireRecord {
                                ts_ms: hold.ts_ms,
                                amount: hold.amount,
                                status: RecordStatus::Pending,
                                ..WireRecord::confirmed_defaults()
                            });
                    }
                    snapshot_accrual(&wire, now_ms, &mut accrual);
                }
                Err(
                    e @ (WindowStoreError::HmacMismatch
                    | WindowStoreError::Invalid { .. }
                    | WindowStoreError::GenerationMismatch),
                ) => {
                    defect = defect_of(&e, false);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(ResetSnapshot {
            store_sha256: Some(Sha256::digest(&bytes).into()),
            key,
            accrual,
            defect: if mainnet { defect } else { None },
        })
    }

    /// Verifies the store file's HMAC tag under `key` WITHOUT checking the
    /// generation counter or parsing the body — a pure content-integrity
    /// check used before a key rotation destroys the OLD key, so a tampered
    /// file cannot be silently re-signed (and thereby laundered) under the
    /// new one. A missing file is `Ok(())` (nothing to verify).
    ///
    /// # Errors
    ///
    /// - [`WindowStoreError::HmacMismatch`] — the file's tag does not match
    ///   `key`.
    /// - [`WindowStoreError::Invalid`] — the file is shorter than the tag
    ///   prefix.
    /// - [`WindowStoreError::Io`] — the file could not be read for a reason
    ///   other than not existing.
    pub fn verify_tag(&self, key: &[u8; 32]) -> Result<(), WindowStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let (stored_tag, body) = bytes.split_at(HMAC_TAG_LEN);
        let recomputed = compute_tag(key, body)?;
        if !bool::from(stored_tag.ct_eq(&recomputed)) {
            return Err(WindowStoreError::HmacMismatch);
        }
        Ok(())
    }

    /// Re-signs the store file under `new_key`, WITHOUT requiring the old
    /// key: the body bytes (including the unchanged `generation` field) are
    /// read as-is (the same content any reader would see) and a fresh tag is
    /// computed over them with `new_key` — the same "recompute over the
    /// identical body" shape as [`stellar_agent_core::audit_log`]'s
    /// `resign_chain_root_sidecars`. Does NOT touch the generation counter:
    /// rotation is not a write in the anti-rollback sense, so it must not
    /// look like one.
    ///
    /// Callers MUST verify the file's tag under the OLD key via
    /// [`Self::verify_tag`] BEFORE rotating that key (see the `rotate-policy-state-key`
    /// CLI command) — this method itself performs no such check, so calling
    /// it directly on a tampered file would launder the tamper under the new
    /// key.
    ///
    /// A missing store file is a no-op (`Ok(())`) — nothing to re-sign.
    ///
    /// # Errors
    ///
    /// [`WindowStoreError::Io`] / [`WindowStoreError::Invalid`] if the
    /// existing file cannot be read or is shorter than the tag prefix.
    pub fn resign(&self, new_key: &[u8; 32]) -> Result<(), WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire_with_retry(&self.lock_path())?;

        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let body = &bytes[HMAC_TAG_LEN..];
        let tag = compute_tag(new_key, body)?;
        self.write_atomic_raw(&tag, body)
    }

    // ── internals ────────────────────────────────────────────────────────

    /// Applies `mutate` to the verified file under the write lock and writes
    /// the result, bumping the generation counter.
    ///
    /// `mutate` returns whether it changed anything; when it did not, the file
    /// is left exactly as it stands and the generation counter is not bumped,
    /// so a settle call for a reservation another process already settled
    /// costs nothing and cannot look like a write.
    fn rewrite_records(
        &self,
        profile: &Profile,
        mutate: impl FnOnce(&mut WireFile) -> bool,
    ) -> Result<(), WindowStoreError> {
        self.ensure_parent_dir()?;
        let _lock = WindowStoreLock::acquire_with_retry(&self.lock_path())?;

        let (key, _mint) = self.load_or_mint_key(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let mut wire = self.read_verified(profile, &key, &gen_entry)?;
        let original = wire.clone();

        if !mutate(&mut wire) {
            return Ok(());
        }

        prune_stale(&mut wire, now_ms()?);
        self.commit_generation(&key, &gen_entry, original, wire)
    }

    /// Persists both sides before advancing the keyring commit point. A crash
    /// at any write leaves a snapshot matching the counter, while replay of an
    /// older file cannot supply a matching committed generation.
    pub(super) fn commit_generation(
        &self,
        key: &[u8; 32],
        gen_entry: &KeyringEntryRef,
        mut original: WireFile,
        mut next: WireFile,
    ) -> Result<(), WindowStoreError> {
        next.generation =
            original
                .generation
                .checked_add(1)
                .ok_or_else(|| WindowStoreError::Invalid {
                    detail: "policy window-state generation counter overflow".to_owned(),
                })?;
        next.prepared = None;
        // The successor's version follows from its own content, before its
        // commitment is hashed. The current snapshot keeps the version it was
        // committed under, so its committed digest stays the same with the
        // successor beside it.
        next.version = select_wire_version(&next);
        if original.generation == 0 {
            // Initialisation has no prior debit to retain. A missing trusted
            // counter on an existing file must remain a deletion error.
            write_generation(gen_entry, &next)?;
            return self.write_atomic(key, &next);
        }
        original.prepared = Some(Box::new(next.clone()));
        self.write_atomic(key, &original)?;
        write_generation(gen_entry, &next)?;
        // The committed candidate is already durable. Compaction is optional:
        // readers use it directly if replacing the prepared image fails.
        if let Err(error) = self.write_atomic(key, &next) {
            tracing::warn!(
                ?error,
                "window store: committed prepared generation retained; compaction failed"
            );
        }
        Ok(())
    }

    /// Settles one reservation on chain answers. See [`Self::reconcile_due`]
    /// for the rule this implements.
    async fn settle_reservation<'o>(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        oracle: Option<&'o crate::client::StellarRpcClient>,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        pass: &mut ReconcilePass<'o>,
    ) -> Result<Settlement, WindowStoreError> {
        // The receipt is unauthenticated, so nothing it records releases a
        // reservation: release evidence it carries is found again on the chain
        // below. A missing receipt leaves the authenticated reservation as the
        // submission identity. An unreadable receipt store keeps the hold.
        if let Some(store) = receipts
            && let Err(e) = store.get(&reservation.id)
        {
            tracing::debug!(
                error = %e,
                "window reconcile: the receipt store could not be read; the reservation stands"
            );
            return Ok(Settlement::KeptPending);
        }

        let Ok(hash_bytes) = stellar_agent_core::hex::decode_hex32(&reservation.tx_hash) else {
            // A reservation with no usable transaction hash cannot be asked
            // about. It stands until an operator resolves it.
            return Ok(Settlement::KeptPending);
        };
        let tx_hash = stellar_xdr::Hash(hash_bytes);

        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let record = match client.get_transaction_record(&tx_hash).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    tx_hash = %crate::submit::redact_tx_hash(&reservation.tx_hash),
                    error = %client.url.scrub_display(&e),
                    "window reconcile: getTransaction failed; reservation stands"
                );
                pass.fail(
                    client,
                    format!("getTransaction failed: {}", client.url.scrub_display(&e)),
                );
                return Ok(Settlement::KeptPending);
            }
        };

        // On a mainnet profile the primary's negative answers are claims the
        // oracle has to confirm, and only an oracle that reports mainnet can
        // confirm them; the primary's SUCCESS confirms as on any chain, which
        // keeps the debit.
        if profile.chain_id.is_mainnet() && matches!(record.status(), "FAILED" | "NOT_FOUND") {
            let Some(oracle) = oracle else {
                tracing::debug!(
                    "window reconcile: the primary endpoint's negative answer has no oracle to \
                     confirm it; reservation stands"
                );
                pass.fail_without_oracle();
                return Ok(Settlement::KeptPending);
            };
            let Some(oracle) = pass.verified_oracle(oracle).await else {
                return Ok(Settlement::KeptPending);
            };
            return self
                .settle_on_oracle(profile, oracle, receipts, reservation, &tx_hash, pass)
                .await;
        }
        if record.status() == "NOT_FOUND" {
            return self
                .settle_not_found(profile, client, receipts, reservation, pass)
                .await;
        }
        self.settle_chain_answer(profile, receipts, reservation, &record)
    }

    /// Settles a mainnet reservation whose primary endpoint answered `FAILED`
    /// or `NOT_FOUND`, on the oracle's answers alone.
    ///
    /// The oracle's `SUCCESS` and `FAILED` settle as a definitive answer
    /// does. Its `NOT_FOUND` runs the `NOT_FOUND` rule with the oracle as the
    /// endpoint, so the retention floor, the chain time, the account sequence
    /// and the fresh answer are all the oracle's. An oracle read that fails
    /// keeps the reservation and reports the failure.
    async fn settle_on_oracle(
        &self,
        profile: &Profile,
        oracle: MainnetOracle<'_>,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        tx_hash: &stellar_xdr::Hash,
        pass: &mut ReconcilePass<'_>,
    ) -> Result<Settlement, WindowStoreError> {
        let oracle = oracle.client();
        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let deadline = pass.deadline_of(oracle);
        let record = match within(deadline, oracle.get_transaction_record(tx_hash)).await {
            Some(Ok(r)) => r,
            None => {
                tracing::debug!(
                    tx_hash = %crate::submit::redact_tx_hash(&reservation.tx_hash),
                    "window reconcile: the oracle's getTransaction did not answer by the \
                     deadline; reservation stands"
                );
                pass.fail(oracle, deadline_passed("getTransaction"));
                return Ok(Settlement::KeptPending);
            }
            Some(Err(e)) => {
                tracing::debug!(
                    tx_hash = %crate::submit::redact_tx_hash(&reservation.tx_hash),
                    error = %oracle.url.scrub_display(&e),
                    "window reconcile: the oracle's getTransaction failed; reservation stands"
                );
                pass.fail(
                    oracle,
                    format!("getTransaction failed: {}", oracle.url.scrub_display(&e)),
                );
                return Ok(Settlement::KeptPending);
            }
        };
        if record.status() == "NOT_FOUND" {
            return self
                .settle_not_found(profile, oracle, receipts, reservation, pass)
                .await;
        }
        self.settle_chain_answer(profile, receipts, reservation, &record)
    }

    /// Applies a definitive transaction answer to the reservation and receipt.
    ///
    /// A `SUCCESS` answer confirms from its status, ledger and created-at as
    /// received; only a `FAILED` answer's result XDR is decoded, for its
    /// failure code.
    fn settle_chain_answer(
        &self,
        profile: &Profile,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        record: &TransactionRecord,
    ) -> Result<Settlement, WindowStoreError> {
        match record.status() {
            "SUCCESS" => {
                if let Err(error) = finalize_receipt(
                    receipts,
                    reservation,
                    ReceiptStatus::Success,
                    record.ledger(),
                ) {
                    return Ok(Settlement::ReceiptWriteFailed {
                        error: error.to_string(),
                    });
                }
                self.confirm(profile, &reservation.id, record.created_at())?;
                Ok(Settlement::Confirmed {
                    ledger: record.ledger(),
                })
            }
            "FAILED" => {
                let code = crate::submit::map_failed_record(record).code().to_owned();
                if let Err(error) = finalize_receipt(
                    receipts,
                    reservation,
                    ReceiptStatus::Failed { code: code.clone() },
                    None,
                ) {
                    return Ok(Settlement::ReceiptWriteFailed {
                        error: error.to_string(),
                    });
                }
                self.release(profile, &reservation.id)?;
                Ok(Settlement::Failed { code })
            }
            _ => Ok(Settlement::KeptPending),
        }
    }

    /// The `NOT_FOUND` half of the release rule.
    ///
    /// A consumed sequence requires one extra bounded transaction query: the
    /// reserved transaction can land between the first query and the account
    /// read. Settling that answer preserves its debit when it consumed its own
    /// sequence. Only a second `NOT_FOUND` permits sequence-based release.
    async fn settle_not_found(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        pass: &mut ReconcilePass<'_>,
    ) -> Result<Settlement, WindowStoreError> {
        // A submission ledger of 0 records no view of the chain, so the
        // retention boundary below cannot be checked against it and a
        // NOT_FOUND carries no information. The reservation stands for the
        // operator.
        if reservation.submission_ledger == 0 {
            return Ok(Settlement::KeptPending);
        }
        // The retention boundary first: an endpoint that no longer holds the
        // ledger range the submission was made in cannot report the
        // transaction whatever happened to it, so its NOT_FOUND carries no
        // information.
        pass.observe(client).await;
        let Some(floor) = pass.oldest_ledger else {
            return Ok(Settlement::KeptPending);
        };
        if reservation.submission_ledger < floor {
            if let Some(receipts) = receipts {
                match receipts.get(&reservation.id) {
                    Ok(None) => self.mark_operator_required(profile, &reservation.id)?,
                    Ok(Some(_)) => {
                        if let Err(error) = finalize_receipt(
                            Some(receipts),
                            reservation,
                            ReceiptStatus::Ambiguous,
                            None,
                        ) {
                            return Ok(Settlement::ReceiptWriteFailed {
                                error: error.to_string(),
                            });
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "window reconcile: receipt read failed; orphan status unknown");
                        return Ok(Settlement::KeptPending);
                    }
                }
            }
            return Ok(Settlement::RetentionExpired);
        }

        // Only a timed, sent reservation needs the failed ledger observation.
        // An unsent receipt clears without a ledger time.
        if reservation.max_time > 0 && pass.chain.is_none() && pass.failure.is_none() {
            let never_sent = receipts
                .and_then(|store| store.get(&reservation.id).ok().flatten())
                .is_some_and(|receipt| !receipt.submitted);
            if !never_sent {
                pass.failure = pass.ledger_failure.clone();
            }
        }
        let time_expired = reservation.max_time > 0
            && reservation.submission_ledger >= floor
            && reservation.submission_ledger > 0
            && pass.chain.is_some_and(|(ledger, close_time)| {
                reservation.submission_ledger <= ledger && close_time > reservation.max_time
            });
        if time_expired {
            return self
                .fresh_answer_or_release(
                    profile,
                    client,
                    receipts,
                    reservation,
                    pass,
                    ReleaseEvidence::TimeBoundPassed,
                )
                .await;
        }

        // A consumed sequence needs a fresh transaction answer to distinguish
        // this submission landing from another submission using the sequence.
        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let deadline = pass.deadline_of(client);
        let account = match within(
            deadline,
            crate::account::fetch_account(client, &reservation.source, &[]),
        )
        .await
        {
            Some(Ok(a)) => a,
            Some(Err(stellar_agent_core::error::WalletError::Network(
                stellar_agent_core::error::NetworkError::AccountNotFound { .. },
            ))) => return Ok(Settlement::KeptPending),
            None => {
                tracing::debug!(
                    "window reconcile: source account not read by the deadline; reservation stands"
                );
                pass.fail(client, deadline_passed("getLedgerEntries"));
                return Ok(Settlement::KeptPending);
            }
            Some(Err(e)) => {
                tracing::debug!(
                    error = %e,
                    "window reconcile: source account fetch failed; reservation stands"
                );
                pass.fail(
                    client,
                    match e {
                        stellar_agent_core::error::WalletError::Network(error) => {
                            network_failure_reason(error)
                        }
                        other => format!("the source account could not be read: {other}"),
                    },
                );
                return Ok(Settlement::KeptPending);
            }
        };
        if account.sequence_number >= reservation.sequence {
            return self
                .fresh_answer_or_release(
                    profile,
                    client,
                    receipts,
                    reservation,
                    pass,
                    ReleaseEvidence::SequenceConsumed,
                )
                .await;
        }

        Ok(Settlement::KeptPending)
    }

    /// Rechecks the transaction after observing `evidence` that it cannot
    /// apply.
    async fn fresh_answer_or_release(
        &self,
        profile: &Profile,
        client: &crate::client::StellarRpcClient,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        pass: &mut ReconcilePass<'_>,
        evidence: ReleaseEvidence,
    ) -> Result<Settlement, WindowStoreError> {
        let Ok(hash) = stellar_agent_core::hex::decode_hex32(&reservation.tx_hash) else {
            return Ok(Settlement::KeptPending);
        };
        if !pass.charge() {
            return Ok(Settlement::KeptPending);
        }
        let deadline = pass.deadline_of(client);
        let record = match within(
            deadline,
            client.get_transaction_record(&stellar_xdr::Hash(hash)),
        )
        .await
        {
            Some(Ok(record)) => record,
            None => {
                tracing::debug!(
                    "window reconcile: confirmation query not answered by the deadline; \
                     reservation stands"
                );
                pass.fail(client, deadline_passed("getTransaction"));
                return Ok(Settlement::KeptPending);
            }
            Some(Err(e)) => {
                tracing::debug!(error = %client.url.scrub_display(&e),
                    "window reconcile: confirmation query failed; reservation stands");
                pass.fail(
                    client,
                    format!("getTransaction failed: {}", client.url.scrub_display(&e)),
                );
                return Ok(Settlement::KeptPending);
            }
        };
        if record.status() == "NOT_FOUND" {
            return self.release_on_evidence(profile, receipts, reservation, evidence);
        }
        self.settle_chain_answer(profile, receipts, reservation, &record)
    }

    /// Releases a reservation whose transaction can no longer apply, recording
    /// the receipt as ambiguous with the evidence that released it.
    ///
    /// The outcome is ambiguous rather than failed because no
    /// `TransactionResult` exists for it: what is established is that the
    /// transaction cannot reach a ledger, which rests on the endpoint's
    /// answers being honest. The evidence is what the settled audit row
    /// names, and what lets a later status run write that row when this pass
    /// could not.
    fn release_on_evidence(
        &self,
        profile: &Profile,
        receipts: Option<&ReceiptStore>,
        reservation: &SubmissionHold,
        evidence: ReleaseEvidence,
    ) -> Result<Settlement, WindowStoreError> {
        let evidence = match release_receipt(receipts, reservation, evidence) {
            Ok(evidence) => evidence,
            Err(error) => {
                return Ok(Settlement::ReceiptWriteFailed {
                    error: error.to_string(),
                });
            }
        };
        self.release(profile, &reservation.id)?;
        Ok(Settlement::ReleasedOnEvidence { evidence })
    }

    /// Reads and fully verifies the file for inspection, taking no lock.
    ///
    /// `Ok(None)` means there is nothing recorded yet for this profile.
    pub(super) fn read_for_inspection(
        &self,
        profile: &Profile,
    ) -> Result<Option<WireFile>, WindowStoreError> {
        refuse_owner_coordinate(profile)?;
        let gen_entry = generation_entry_ref(profile);
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return match load_generation(&gen_entry)? {
                    None => Ok(None),
                    Some(_) => Err(mainnet_loading_error(
                        profile,
                        WindowStoreError::GenerationMismatch,
                        Some(StateDefect::MissingFileWithGeneration),
                    )),
                };
            }
            Err(e) => return Err(WindowStoreError::Io { kind: e.kind() }),
        };
        let key = crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id)
            .map_err(|e| key_load_error(profile, &e))?;
        refuse_owner_public_key(key.as_ref(), &OwnerKeyContext::for_loaded_profile(profile))?;
        let counter = load_counter(&gen_entry)?;
        self.verify_with_key(&key, &bytes)
            .and_then(|wire| select_generation(wire, counter))
            .map(Some)
            .map_err(|e| {
                let defect = defect_of(&e, false);
                mainnet_loading_error(profile, e, defect)
            })
    }

    pub(super) fn ensure_parent_dir(&self) -> Result<(), WindowStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        Ok(())
    }

    pub(super) fn load_or_mint_key(
        &self,
        profile: &Profile,
    ) -> Result<(zeroize::Zeroizing<[u8; 32]>, MintOutcome), WindowStoreError> {
        let entry_ref = &profile.policy_window_state_key_id;
        // An owner-namespace coordinate refuses here, so it never reaches the
        // mint arm below.
        refuse_owner_coordinate(profile)?;
        let loaded = crate::keyring::load_hmac_key_32(entry_ref);
        // Under the mainnet rules a key is minted only for a store with no
        // committed history: a file without its key, and a committed
        // generation without its file, are defects a write must not paper
        // over with a fresh key.
        if mainnet_rules(profile)
            && let Err(error) = &loaded
        {
            if self.path.exists() {
                return Err(key_load_error(profile, error));
            }
            if load_generation(&generation_entry_ref(profile))?.is_some() {
                return Err(mainnet_loading_error(
                    profile,
                    WindowStoreError::GenerationMismatch,
                    Some(StateDefect::MissingFileWithGeneration),
                ));
            }
        }
        match loaded {
            Ok(key) => {
                refuse_owner_public_key(
                    key.as_ref(),
                    &OwnerKeyContext::for_loaded_profile(profile),
                )?;
                Ok((
                    key,
                    MintOutcome {
                        newly_minted: false,
                    },
                ))
            }
            Err(_) => {
                // Load failure is treated as "not yet minted" — mint a fresh
                // key. A genuinely different failure (backend unavailable)
                // surfaces again on the mint attempt below and is reported.
                crate::keyring::rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account)
                    .map_err(|e| WindowStoreError::Keyring {
                        detail: format!("mint failed: {e}"),
                    })?;
                let key = crate::keyring::load_hmac_key_32(entry_ref).map_err(|e| {
                    WindowStoreError::Keyring {
                        detail: format!("load-after-mint failed: {e}"),
                    }
                })?;
                Ok((key, MintOutcome { newly_minted: true }))
            }
        }
    }

    /// Reads and fully verifies (HMAC, then anti-rollback generation) the
    /// current file, or establishes the genuine-first-run empty state.
    /// Requires an already-available `key` — used by
    /// [`Self::record_and_persist`], which holds one
    /// via [`Self::load_or_mint_key`] (which mints on first use) before
    /// calling this. NOT used by [`Self::load_into`]: that method must not
    /// force a key load (and thus a `Keyring` error) for a profile that has
    /// never recorded anything — file existence is checked first there,
    /// inline, so the key is only touched when a file is actually present to
    /// verify.
    ///
    /// Reads the FILE before the KEYRING generation (narrows, in the
    /// fail-closed direction, a benign lock-free-read-races-a-write window:
    /// this method takes no lock, by design, so a concurrent writer could
    /// complete between the two reads; the ordering here means a read that
    /// loses that race sees an old file generation against the new keyring
    /// value and reports [`WindowStoreError::GenerationMismatch`] rather than
    /// silently accepting stale data — the caller retries and the very next
    /// read is consistent).
    pub(super) fn read_verified(
        &self,
        profile: &Profile,
        key: &[u8; 32],
        gen_entry: &KeyringEntryRef,
    ) -> Result<WireFile, WindowStoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let counter = load_counter(gen_entry)?;
                self.verify_with_key(key, &bytes)
                    .and_then(|wire| select_generation(wire, counter))
                    .map_err(|e| {
                        let defect = defect_of(&e, false);
                        mainnet_loading_error(profile, e, defect)
                    })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match load_generation(gen_entry)?
            {
                None => Ok(WireFile {
                    version: WIRE_VERSION_COMPACT,
                    ..WireFile::default()
                }),
                Some(_) => Err(mainnet_loading_error(
                    profile,
                    WindowStoreError::GenerationMismatch,
                    Some(StateDefect::MissingFileWithGeneration),
                )),
            },
            Err(e) => Err(WindowStoreError::Io { kind: e.kind() }),
        }
    }

    fn verify_with_key(&self, key: &[u8; 32], bytes: &[u8]) -> Result<WireFile, WindowStoreError> {
        if bytes.len() < HMAC_TAG_LEN {
            return Err(WindowStoreError::Invalid {
                detail: "store file is shorter than the HMAC tag prefix".to_owned(),
            });
        }
        let (stored_tag, body) = bytes.split_at(HMAC_TAG_LEN);
        let recomputed = compute_tag(key, body)?;
        if !bool::from(stored_tag.ct_eq(&recomputed)) {
            return Err(WindowStoreError::HmacMismatch);
        }
        #[derive(serde::Deserialize)]
        struct Version {
            version: u32,
        }
        let version: Version =
            serde_json::from_slice(body).map_err(|error| WindowStoreError::Invalid {
                detail: format!("store body has no readable version: {error}"),
            })?;
        if version.version > WIRE_VERSION_MAX {
            return Err(WindowStoreError::UnsupportedVersion {
                version: version.version,
                max: WIRE_VERSION_MAX,
            });
        }
        let wire: WireFile =
            serde_json::from_slice(body).map_err(|e| WindowStoreError::Invalid {
                detail: format!("store body is not valid JSON: {e}"),
            })?;
        check_snapshot(&wire)?;
        if let Some(prepared) = &wire.prepared {
            check_snapshot(prepared)?;
        }
        Ok(wire)
    }

    fn write_atomic(&self, key: &[u8; 32], wire: &WireFile) -> Result<(), WindowStoreError> {
        let body = serde_json::to_vec(wire).map_err(|e| WindowStoreError::Invalid {
            detail: format!("failed to serialise store body: {e}"),
        })?;
        let tag = compute_tag(key, &body)?;
        self.write_atomic_raw(&tag, &body)
    }

    /// Writes `tag || body` to the store path via temp-file +
    /// `sync_data` + rename + parent-directory fsync — the
    /// `write_sidecar_atomic` precedent
    /// ([`stellar_agent_core::audit_log`] rotation.rs).
    fn write_atomic_raw(
        &self,
        tag: &[u8; HMAC_TAG_LEN],
        body: &[u8],
    ) -> Result<(), WindowStoreError> {
        let mut tmp = self.path.clone();
        let name = tmp
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("policy.window")
            .to_owned();
        tmp.set_file_name(format!("{name}.tmp"));
        {
            #[cfg(unix)]
            let mut f = {
                use std::os::unix::fs::OpenOptionsExt as _;
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| WindowStoreError::Io { kind: e.kind() })?
            };
            #[cfg(not(unix))]
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.write_all(tag)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.write_all(body)
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
            f.sync_data()
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| WindowStoreError::Io { kind: e.kind() })?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-rollback generation counter
// ─────────────────────────────────────────────────────────────────────────────

/// Derives the generation-counter keyring coordinate from the profile's
/// `policy_window_state_key_id`: same `service`, `account` suffixed
/// `-generation`. Derived from the coordinate ITSELF (not re-derived from the
/// profile name) so an operator-overridden HMAC-key coordinate still gets a
/// correctly-associated generation entry.
pub(super) fn generation_entry_ref(profile: &Profile) -> KeyringEntryRef {
    let base = &profile.policy_window_state_key_id;
    KeyringEntryRef::new(base.service.clone(), generation_account(&base.account))
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner key refusals
// ─────────────────────────────────────────────────────────────────────────────

/// The profile field a window-state key owner refusal names.
pub const POLICY_STATE_KEY_FIELD: &str = "policy_window_state_key_id";

/// Refuses a window-state key coordinate in the owner key namespace, before
/// any keyring read.
fn refuse_owner_coordinate(profile: &Profile) -> Result<(), WindowStoreError> {
    owner_key::refuse_owner_key_coordinate(
        &profile.policy_window_state_key_id,
        POLICY_STATE_KEY_FIELD,
    )
    .map_err(|_| WindowStoreError::KeyMatchesOwnerPublicKey)
}

/// Refuses a loaded window-state key equal to the profile's owner public key.
/// An owner entry that cannot be read refuses with its keyring error.
fn refuse_owner_public_key(key: &[u8], owner: &OwnerKeyContext) -> Result<(), WindowStoreError> {
    owner_key::refuse_owner_public_key(key, owner, POLICY_STATE_KEY_FIELD).map_err(|e| match e {
        stellar_agent_core::error::WalletError::Validation(
            stellar_agent_core::error::ValidationError::KeyMatchesOwnerPublicKey { .. },
        ) => WindowStoreError::KeyMatchesOwnerPublicKey,
        other => WindowStoreError::Keyring {
            detail: format!("owner key read failed: {other}"),
        },
    })
}

/// The trusted commit binds one generation to exactly one canonical body.
/// An abandoned candidate can reuse a generation number, but cannot replace
/// another body's commitment when that generation is later committed.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationCommitment {
    generation: u64,
    body_sha256: String,
}

struct GenerationState {
    generation: u64,
    body_sha256: Option<String>,
}

/// Numeric entries retain compatibility with files written under versions 1 and 2.
fn load_counter(entry_ref: &KeyringEntryRef) -> Result<Option<GenerationState>, WindowStoreError> {
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    match entry.get_password() {
        Ok(value) => {
            if let Ok(generation) = value.trim().parse::<u64>() {
                return Ok(Some(GenerationState {
                    generation,
                    body_sha256: None,
                }));
            }
            let committed: GenerationCommitment =
                serde_json::from_str(&value).map_err(|e| WindowStoreError::Keyring {
                    detail: format!("generation entry value is not a valid commitment: {e}"),
                })?;
            if committed.body_sha256.len() != 64
                || !committed
                    .body_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(WindowStoreError::Keyring {
                    detail: "generation commitment digest is invalid".to_owned(),
                });
            }
            Ok(Some(GenerationState {
                generation: committed.generation,
                body_sha256: Some(committed.body_sha256),
            }))
        }
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(WindowStoreError::Keyring {
            detail: format!("generation entry read failed: {e}"),
        }),
    }
}

fn load_generation(entry_ref: &KeyringEntryRef) -> Result<Option<u64>, WindowStoreError> {
    Ok(load_counter(entry_ref)?.map(|state| state.generation))
}

fn next_generation(entry_ref: &KeyringEntryRef) -> Result<u64, WindowStoreError> {
    increment_generation(load_generation(entry_ref)?.unwrap_or(0))
}

fn increment_generation(generation: u64) -> Result<u64, WindowStoreError> {
    generation
        .checked_add(1)
        .ok_or_else(|| WindowStoreError::Invalid {
            detail: "policy window-state generation counter overflow".to_owned(),
        })
}

/// Hashes the selected snapshot, whose prepared field is absent. The digest
/// stays identical across the prepared and compacted representations.
fn body_digest(wire: &WireFile) -> Result<String, WindowStoreError> {
    let body = serde_json::to_vec(wire).map_err(|e| WindowStoreError::Invalid {
        detail: format!("failed to serialise committed store body: {e}"),
    })?;
    Ok(stellar_agent_core::hex::encode(
        &<Sha256 as sha2::Digest>::digest(&body),
    ))
}

/// The window lock serialises callers; one keyring write commits both fields.
fn write_generation(entry_ref: &KeyringEntryRef, wire: &WireFile) -> Result<(), WindowStoreError> {
    let committed = GenerationCommitment {
        generation: wire.generation,
        body_sha256: body_digest(wire)?,
    };
    let value = serde_json::to_string(&committed).map_err(|e| WindowStoreError::Invalid {
        detail: format!("failed to serialise generation commitment: {e}"),
    })?;
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        WindowStoreError::Keyring {
            detail: format!("generation entry open failed: {e}"),
        }
    })?;
    entry
        .set_password(&value)
        .map_err(|e| WindowStoreError::Keyring {
            detail: format!("generation entry write failed: {e}"),
        })
}

#[cfg(test)]
fn bump_generation(entry_ref: &KeyringEntryRef) -> Result<u64, WindowStoreError> {
    let next = next_generation(entry_ref)?;
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .and_then(|entry| entry.set_password(&next.to_string()))
        .map_err(|e| WindowStoreError::Keyring {
            detail: format!("generation entry write failed: {e}"),
        })?;
    Ok(next)
}

fn compute_tag(key: &[u8], body: &[u8]) -> Result<[u8; HMAC_TAG_LEN], WindowStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| WindowStoreError::Invalid {
        detail: format!("HMAC key construction failed: {e}"),
    })?;
    mac.update(HMAC_CONTEXT_LABEL);
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// The store's clock: the mainnet clock every authorization transition reads,
/// which also dates pruning and the window's own writes.
pub(super) fn now_ms() -> Result<u64, WindowStoreError> {
    crate::mainnet::clock::now_ms().map_err(|e| WindowStoreError::Invalid {
        detail: format!("the store clock cannot be read: {e}"),
    })
}

/// Checks one snapshot's version and its authorization history.
///
/// Versions 1 to 4 are read; a snapshot below version 4 carries no
/// authorization history, and a version 4 snapshot may carry none.
fn check_snapshot(wire: &WireFile) -> Result<(), WindowStoreError> {
    if wire.version > WIRE_VERSION_MAX {
        return Err(WindowStoreError::UnsupportedVersion {
            version: wire.version,
            max: WIRE_VERSION_MAX,
        });
    }
    if wire.version == 0 {
        return Err(WindowStoreError::Invalid {
            detail: format!(
                "store file wire version 0 is not a version this build reads (max \
                 {WIRE_VERSION_MAX})"
            ),
        });
    }
    ledger::validate(wire)
}

/// Drops records and settled authorization history that have aged out of the
/// retention window.
///
/// A pending reservation is kept whatever its age. It holds the operator's cap
/// for a submission whose outcome is still unknown, and dropping it would stop
/// that spend counting and take the record out of reconciliation's reach while
/// its receipt still reports pending. A reservation that old is resolved by
/// `tx status` or by `tx receipt clear`, not by the clock.
pub(super) fn prune_stale(wire: &mut WireFile, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(RETENTION_MS);
    for bucket in &mut wire.entries {
        bucket
            .records
            .retain(|r| r.ts_ms >= cutoff || r.status == RecordStatus::Pending);
    }
    wire.entries.retain(|b| !b.records.is_empty());
    // Settled authorization history ages out on the same retention; an open
    // authorization stays whatever its age, until a transaction's sweep
    // settles it.
    ledger::prune_history(wire, cutoff);
}

/// Whether the receipt for `envelope_hash` already records an outcome the
/// endpoint cannot resolve.
fn outcome_already_unknown(
    known: &HashMap<String, (ReceiptStatus, Option<ReleaseEvidence>)>,
    envelope_hash: &str,
) -> bool {
    matches!(
        known.get(envelope_hash),
        Some((ReceiptStatus::Ambiguous, None) | (ReceiptStatus::ClearedByOperator, _))
    )
}

/// What one reservation's reconciliation established.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settlement {
    /// The transaction reached a ledger; the reservation became real spend.
    Confirmed {
        /// The ledger the endpoint reported it in.
        ledger: Option<u32>,
    },
    /// The chain reported the transaction failed; the reservation was
    /// removed.
    Failed {
        /// The wire code of the on-chain failure.
        code: String,
    },
    /// The transaction can no longer apply on chain evidence, and the
    /// endpoint never reported it; the reservation was removed and the
    /// outcome is unknown.
    ReleasedOnEvidence {
        /// What established that the transaction cannot apply.
        evidence: ReleaseEvidence,
    },
    /// The receipt could not record the outcome; the reservation stands.
    ReceiptWriteFailed {
        /// The receipt-store error as displayed to the caller.
        error: String,
    },
    /// Nothing was established; the reservation stands.
    KeptPending,
    /// The endpoint no longer holds the ledger range the submission was made
    /// in, so it cannot answer; the reservation stands for an operator.
    RetentionExpired,
}

/// Builds the settlement identity of a submission from its receipt, for a
/// submission that holds no window reservation.
///
/// Only a receipt still awaiting an answer is settled this way: one the chain
/// has already answered for needs no round trip.
fn reservation_from_receipt(receipts: &ReceiptStore, id: &str) -> Option<SubmissionHold> {
    let receipt = receipts.get(id).ok().flatten()?;
    if receipt.status.is_terminal() || receipt.tx_hash.is_empty() {
        return None;
    }
    Some(SubmissionHold {
        id: receipt.envelope_hash,
        tx_hash: receipt.tx_hash,
        source: receipt.source,
        sequence: receipt.sequence,
        max_time: receipt.max_time,
        pending_since_ms: 0,
        submission_ledger: receipt.recorded_at_ledger,
        operator_required: false,
    })
}

/// Records a terminal status on the receipt a reservation belongs to.
///
/// A missing receipt is restored from the reservation's identity only for a
/// definitive answer; an ambiguous status without evidence is not recorded on
/// a receipt that does not exist.
///
/// The receipt is the crash checkpoint and is written before the window is
/// settled. A failed write leaves the reservation standing for the next pass.
fn finalize_receipt(
    receipts: Option<&ReceiptStore>,
    reservation: &SubmissionHold,
    status: ReceiptStatus,
    ledger: Option<u32>,
) -> Result<(), ReceiptStoreError> {
    let restore = status.is_definitive_outcome();
    persist_receipt(receipts, reservation, restore, |store| {
        store.finalize(&reservation.id, status, ledger)
    })
}

/// Records on the receipt a reservation belongs to that the reservation was
/// released on `evidence`.
///
/// A missing receipt is restored from the reservation's identity first, as
/// for a definitive answer, so the release and its evidence stay visible to
/// the status surfaces and the settled row stays writable after this pass.
/// The reservation is released only after this write succeeds.
fn release_receipt(
    receipts: Option<&ReceiptStore>,
    reservation: &SubmissionHold,
    evidence: ReleaseEvidence,
) -> Result<ReleaseEvidence, ReceiptStoreError> {
    if let Some(store) = receipts
        && let Some(recorded) = store
            .get(&reservation.id)?
            .filter(|receipt| receipt.status == ReceiptStatus::Ambiguous)
            .and_then(|receipt| receipt.release_code)
    {
        return Ok(recorded);
    }
    persist_receipt(receipts, reservation, true, |store| {
        store.finalize_released(&reservation.id, evidence)
    })?;
    // A concurrent release can record its evidence first; the receipt owns the code.
    Ok(receipts
        .map(|store| store.get(&reservation.id))
        .transpose()?
        .flatten()
        .and_then(|receipt| receipt.release_code)
        .unwrap_or(evidence))
}

/// Applies `write` to the receipt store, restoring a missing receipt from the
/// reservation's identity first when `restore` is set and skipping the write
/// otherwise. A failed write leaves the reservation standing; the receipt
/// must be durable before the window settles.
fn persist_receipt(
    receipts: Option<&ReceiptStore>,
    reservation: &SubmissionHold,
    restore: bool,
    write: impl FnOnce(&ReceiptStore) -> Result<(), ReceiptStoreError>,
) -> Result<(), ReceiptStoreError> {
    let Some(store) = receipts else {
        return Ok(());
    };
    let persist = || {
        if store.get(&reservation.id)?.is_none() {
            if !restore {
                return Ok(());
            }
            store.try_begin(
                &reservation.id,
                &reservation.tx_hash,
                &reservation.source,
                reservation.sequence,
                reservation.max_time,
                reservation.submission_ledger,
            )?;
            store.mark_submitted(&reservation.id)?;
        }
        write(store)
    };
    let result = persist();
    if let Err(error) = &result {
        tracing::warn!(
            %error,
            "window reconcile: receipt write failed; the reservation stands"
        );
    }
    result
}

/// Counts one settlement into `report`, and records what the caller owes an
/// audit row for.
///
/// A definitive answer from the chain settles a submission's value action,
/// and so does a release on chain evidence: the settled row of an evidence
/// release is a `value_action_failed` row under the evidence's wire code.
/// A reservation left standing owes nothing yet, and neither does one whose
/// retention window closed: its outcome stays unknown, which is what the
/// pending row already records.
fn record_settlement(
    report: &mut ReconcileReport,
    reservation: &SubmissionHold,
    settlement: Settlement,
) {
    let settled = |status, release_code, ledger| SettledSubmission {
        envelope_hash: reservation.id.clone(),
        tx_hash: reservation.tx_hash.clone(),
        status,
        release_code,
        ledger,
    };
    match settlement {
        Settlement::Confirmed { ledger } => {
            report.confirmed += 1;
            report
                .settled
                .push(settled(ReceiptStatus::Success, None, ledger));
        }
        Settlement::Failed { code } => {
            report.released += 1;
            report
                .settled
                .push(settled(ReceiptStatus::Failed { code }, None, None));
        }
        Settlement::ReleasedOnEvidence { evidence } => {
            report.released += 1;
            report
                .settled
                .push(settled(ReceiptStatus::Ambiguous, Some(evidence), None));
        }
        Settlement::ReceiptWriteFailed { error } => {
            report.receipt_write_failed += 1;
            report.receipt_write_error.get_or_insert(error);
        }
        Settlement::KeptPending => report.kept_pending += 1,
        Settlement::RetentionExpired => report.retention_expired += 1,
    }
}

/// Resolves a verified prepared image against the trusted keyring counter.
///
/// A candidate is adopted only against a commitment that carries a digest.
/// Every commit of a candidate writes one, so a numeric counter has never
/// committed a candidate and a numeric counter equal to a candidate's
/// generation is refused.
fn select_generation(
    mut wire: WireFile,
    counter: Option<GenerationState>,
) -> Result<WireFile, WindowStoreError> {
    // The current snapshot may carry any version this build reads, a legacy
    // one included; a successor is always written by a build that writes
    // version 3 or 4.
    if let Some(next) = &wire.prepared
        && (!(WIRE_VERSION_COMPACT..=WIRE_VERSION_LEDGER).contains(&next.version)
            || next.prepared.is_some()
            || wire.generation.checked_add(1) != Some(next.generation))
    {
        return Err(WindowStoreError::GenerationMismatch);
    }
    let counter = counter.ok_or(WindowStoreError::GenerationMismatch)?;
    if counter.generation == wire.generation {
        wire.prepared = None;
    } else if counter.body_sha256.is_some()
        && let Some(next) = wire.prepared
        && counter.generation == next.generation
    {
        wire = *next;
    } else {
        return Err(WindowStoreError::GenerationMismatch);
    }
    if let Some(expected) = counter.body_sha256
        && expected != body_digest(&wire)?
    {
        return Err(WindowStoreError::GenerationMismatch);
    }
    Ok(wire)
}

/// Whether any record in `wire`, pending or confirmed, carries the non-empty
/// reservation `id`.
pub(super) fn file_holds_id(wire: &WireFile, id: &str) -> bool {
    !id.is_empty()
        && wire
            .entries
            .iter()
            .any(|bucket| bucket.records.iter().any(|record| record.id == id))
}

/// Collects one [`SubmissionHold`] per distinct pending reservation id,
/// oldest first by the time the reservation was taken.
fn collect_pending(wire: &WireFile) -> Vec<SubmissionHold> {
    let mut seen: Vec<SubmissionHold> = Vec::new();
    for bucket in &wire.entries {
        for record in &bucket.records {
            if record.status != RecordStatus::Pending || record.id.is_empty() {
                continue;
            }
            if seen.iter().any(|r| r.id == record.id) {
                continue;
            }
            seen.push(SubmissionHold {
                id: record.id.clone(),
                tx_hash: record.tx_hash.clone(),
                source: record.source.clone(),
                sequence: record.sequence,
                max_time: record.max_time,
                pending_since_ms: record.pending_since_ms,
                submission_ledger: record.submission_ledger,
                operator_required: record.operator_required,
            });
        }
    }
    seen.sort_by(|a, b| {
        a.pending_since_ms
            .cmp(&b.pending_since_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    seen
}

/// The window `key` holds in `wire` at `now_ms`, as
/// [`PolicyStateStore::query_window`] computes it from the same records.
///
/// A confirmed record ages out at `now_ms - window_secs * 1000`. A pending
/// record counts whatever its age: it holds the operator's cap for a
/// submission whose outcome is still open. Only host-dated pending records
/// are subject to [`CLOCK_SKEW_TOLERANCE_MS`]. Confirmed records, whether
/// dated by a ledger close time or by the host at authorization, count even
/// when they are ahead of the host clock. Every hold of an open mainnet
/// authorization counts too, whatever its age, until the authorization is
/// consumed, invalidated, or swept as expired.
fn window_in_file(wire: &WireFile, key: &StateKey, now_ms: u64) -> Result<(i128, u32), DenyReason> {
    let future_limit = now_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS);
    let mut sum: i128 = 0;
    let mut count: u32 = 0;
    for bucket in &wire.entries {
        if bucket.scope_specificity != key.scope_specificity()
            || bucket.bucket != key.bucket()
            || bucket.window_secs != key.window_secs()
        {
            continue;
        }
        for record in &bucket.records {
            if record.status == RecordStatus::Pending && record.ts_ms > future_limit {
                return Err(DenyReason::EvaluationError {
                    detail: StateStoreError::ClockSkewExceeded {
                        entry_ts_ms: record.ts_ms,
                        now_ms,
                    }
                    .to_string(),
                });
            }
            if !record_is_live(record, now_ms, key.window_secs()) {
                continue;
            }
            sum = sum.saturating_add(record.amount);
            count = count.saturating_add(1);
        }
    }
    for hold in &wire.holds {
        if hold.scope_specificity == key.scope_specificity()
            && hold.bucket == key.bucket()
            && hold.window_secs == key.window_secs()
        {
            sum = sum.saturating_add(hold.amount);
            count = count.saturating_add(1);
        }
    }
    Ok((sum, count))
}

/// Pending holds remain live until their outcome is settled.
fn record_is_live(record: &WireRecord, now_ms: u64, window_secs: u64) -> bool {
    record.status == RecordStatus::Pending
        || record.ts_ms >= now_ms.saturating_sub(window_secs.saturating_mul(1_000))
}

// Bound serialized bytes as well as characters: JSON escapes expand control text.
fn bounded_reset_bucket(bucket: &str) -> String {
    bucket
        .chars()
        .take(64)
        .scan(0, |bytes, ch| {
            let encoded_len = match ch {
                '"' | '\\' => 2,
                ch if ch.is_control() => 6,
                ch => ch.len_utf8(),
            };
            *bytes += encoded_len;
            (*bytes <= 64).then_some(ch)
        })
        .collect()
}

fn snapshot_accrual(wire: &WireFile, now_ms: u64, accrual: &mut WipedAccrualRecord) {
    for bucket in &wire.entries {
        let mut snapshot = WipedBucket {
            scope_specificity: bucket.scope_specificity,
            bucket: bounded_reset_bucket(&bucket.bucket),
            window_secs: bucket.window_secs,
            confirmed_count: 0,
            confirmed_total: 0,
            pending_count: 0,
            pending_total: 0,
        };
        for record in &bucket.records {
            if !record_is_live(record, now_ms, bucket.window_secs) {
                continue;
            }
            accrual.entry_count = accrual.entry_count.saturating_add(1);
            match record.status {
                RecordStatus::Confirmed => {
                    snapshot.confirmed_count = snapshot.confirmed_count.saturating_add(1);
                    snapshot.confirmed_total =
                        snapshot.confirmed_total.saturating_add(record.amount);
                }
                RecordStatus::Pending => {
                    snapshot.pending_count = snapshot.pending_count.saturating_add(1);
                    snapshot.pending_total = snapshot.pending_total.saturating_add(record.amount);
                }
            }
        }
        if snapshot.confirmed_count == 0 && snapshot.pending_count == 0 {
            continue;
        }
        if accrual.buckets.len() < 8 {
            accrual.buckets.push(snapshot);
        } else {
            accrual.truncated = true;
        }
    }
}

/// Refuses `entries` when any of them would take its bucket past the limit it
/// carries, measured against `wire` plus the entries ahead of it in the batch.
///
/// The batch is one submission's reservation, so entries that share a key are
/// accumulated against each other: a batch whose own entries jointly exceed a
/// bucket is refused, at the first entry that tips it.
pub(super) fn admit(wire: &WireFile, entries: &[WindowEntry]) -> Result<(), WindowStoreError> {
    let mut batch: HashMap<&StateKey, (i128, u32)> = HashMap::new();
    for entry in entries {
        let (file_sum, file_count) = window_in_file(wire, entry.key(), entry.timestamp_ms())
            .map_err(|reason| WindowStoreError::PolicyDenied {
                reason: Box::new(reason),
            })?;
        let (batch_sum, batch_count) = batch.get(entry.key()).copied().unwrap_or((0, 0));
        let used = file_sum.saturating_add(batch_sum);
        let calls = file_count.saturating_add(batch_count);
        if let Some(reason) = entry.refusal(used, calls) {
            return Err(WindowStoreError::PolicyDenied {
                reason: Box::new(reason),
            });
        }
        let accrued = batch.entry(entry.key()).or_insert((0, 0));
        accrued.0 = accrued.0.saturating_add(entry.amount());
        accrued.1 = accrued.1.saturating_add(1);
    }
    Ok(())
}

pub(super) fn find_or_insert_bucket<'a>(
    entries: &'a mut Vec<WireBucket>,
    key: &StateKey,
) -> &'a mut WireBucket {
    let idx = entries.iter().position(|b| {
        b.scope_specificity == key.scope_specificity()
            && b.bucket == key.bucket()
            && b.window_secs == key.window_secs()
    });
    let idx = idx.unwrap_or_else(|| {
        entries.push(WireBucket {
            scope_specificity: key.scope_specificity(),
            bucket: key.bucket().to_owned(),
            window_secs: key.window_secs(),
            records: Vec::new(),
        });
        entries.len() - 1
    });
    &mut entries[idx]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::path::Path;

    use serial_test::serial;

    use super::*;
    use stellar_agent_core::policy::v1::criteria::state_store::WindowLimit;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    fn test_profile(dir: &Path, name: &str) -> Profile {
        let mut p = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        p.policy_window_state_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key(
                name,
            );
        p.audit_log_path = dir.join("audit.jsonl");
        p
    }

    /// One entry under a cap far above every amount these tests record.
    ///
    /// These tests pin the file's integrity, retention and settlement
    /// behaviour, not admission, so no write they make is refused by the
    /// limit its entries carry.
    fn entry(key: StateKey, ts_ms: u64, amount: i128) -> WindowEntry {
        WindowEntry::new(
            key,
            ts_ms,
            amount,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: i128::from(u32::MAX),
            },
        )
    }

    fn key(profile_name: &str, bucket: &str, window_secs: u64) -> StateKey {
        StateKey::new(profile_name, 1, bucket, window_secs)
    }

    // ── round-trip matrix ────────────────────────────────────────────────

    #[test]
    #[serial]
    fn fresh_store_load_into_appends_nothing() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "fresh");
        let store = PersistedWindowStore::at_path(dir.path().join("fresh.window"));
        let dest = PolicyStateStore::new();
        store.load_into("fresh", &profile, &dest).unwrap();
        let (sum, count) = dest
            .query_window(&key("fresh", "native", 86_400), now_ms().unwrap())
            .unwrap();
        assert_eq!((sum, count), (0, 0));
    }

    #[test]
    #[serial]
    fn record_then_load_into_round_trips_accumulated_entries() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "acc");
        let store = PersistedWindowStore::at_path(dir.path().join("acc.window"));
        let k = key("acc", "native", 86_400);
        let now = now_ms().unwrap();
        let outcome = store
            .record_and_persist(&profile, &[entry(k.clone(), now, 500_000_000)])
            .unwrap();
        assert!(outcome.newly_minted, "first write mints the key");

        let dest = PolicyStateStore::new();
        store.load_into("acc", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 500_000_000);
        assert_eq!(count, 1);
    }

    #[test]
    #[serial]
    fn second_record_does_not_re_mint_and_accumulates() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "acc2");
        let store = PersistedWindowStore::at_path(dir.path().join("acc2.window"));
        let k = key("acc2", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 100)])
            .unwrap();
        let outcome2 = store
            .record_and_persist(&profile, &[entry(k.clone(), now, 200)])
            .unwrap();
        assert!(!outcome2.newly_minted, "second write reuses the minted key");

        let dest = PolicyStateStore::new();
        store.load_into("acc2", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 300);
        assert_eq!(count, 2);
    }

    /// Above-`i64::MAX` amounts round-trip exactly (`i128` decimal-string
    /// wire form, not a bare JSON number).
    #[test]
    #[serial]
    fn round_trip_amount_above_i64_max_is_exact() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "big");
        let store = PersistedWindowStore::at_path(dir.path().join("big.window"));
        let k = key("big", "native", 86_400);
        let now = now_ms().unwrap();
        let beyond = i128::from(i64::MAX) + 1_000;
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, beyond)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("big", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, beyond);
    }

    /// Entries older than the 1-week retention ceiling are pruned on write.
    #[test]
    #[serial]
    fn post_prune_old_entries_are_dropped() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "prune");
        let store = PersistedWindowStore::at_path(dir.path().join("prune.window"));
        let k = key("prune", "native", 86_400);
        let now = now_ms().unwrap();
        let ancient = now.saturating_sub(RETENTION_MS + 1_000);
        store
            .record_and_persist(&profile, &[entry(k.clone(), ancient, 999)])
            .unwrap();
        // A second write triggers pruning against the ancient entry.
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 1)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("prune", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 1, "the ancient entry must be pruned");
        assert_eq!(count, 1);
    }

    // ── HMAC tamper ──────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn tampered_file_fails_closed_on_load() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "tamper");
        let path = dir.path().join("tamper.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("tamper", "native", 86_400);
        store
            .record_and_persist(&profile, &[entry(k, now_ms().unwrap(), 500)])
            .unwrap();

        // Flip a byte in the body (past the 32-byte tag prefix).
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("tamper", &profile, &dest);
        assert!(matches!(result, Err(WindowStoreError::HmacMismatch)));
    }

    #[test]
    #[serial]
    fn tampered_file_fails_closed_on_record() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "tamper2");
        let path = dir.path().join("tamper2.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("tamper2", "native", 86_400);
        store
            .record_and_persist(&profile, &[entry(k.clone(), now_ms().unwrap(), 500)])
            .unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let result = store.record_and_persist(&profile, &[entry(k, now_ms().unwrap(), 1)]);
        assert!(matches!(result, Err(WindowStoreError::HmacMismatch)));
    }

    // ── lock contention ──────────────────────────────────────────────────

    #[test]
    #[serial]
    fn concurrent_record_calls_are_serialised_not_lost() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "lockt");
        let path = dir.path().join("lockt.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("lockt", "native", 86_400);
        let now = now_ms().unwrap();

        // Two sequential handles (simulating two dispatches) both succeed and
        // their entries are both present — the lock serialises rather than
        // drops either writer.
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 10)])
            .unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 20)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("lockt", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 30);
        assert_eq!(count, 2);
    }

    #[test]
    fn held_lock_blocks_a_second_writer() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("held.window.lock");
        let _held = WindowStoreLock::acquire(&lock_path).unwrap();
        let result = WindowStoreLock::acquire(&lock_path).map_err(WindowStoreError::from);
        assert!(matches!(result, Err(WindowStoreError::WriterLocked)));
    }

    // ── atomic-write crash-surface ───────────────────────────────────────

    /// A leftover `.tmp` file from a crashed prior write does not block the
    /// next successful write (the next write creates+truncates its own temp
    /// file and renames over the leftover).
    #[test]
    #[serial]
    fn leftover_temp_file_does_not_block_next_write() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "crash");
        let path = dir.path().join("crash.window");
        fs::write(path.with_file_name("crash.window.tmp"), b"leftover-garbage").unwrap();

        let store = PersistedWindowStore::at_path(path);
        let k = key("crash", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 42)])
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("crash", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 42);
    }

    // ── reset ────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn reset_clears_accumulated_history() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "reset");
        let path = dir.path().join("reset.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("reset", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 999)])
            .unwrap();

        let outcome = store.reset(&profile, now, |_| Ok::<(), ()>(())).unwrap();
        assert!(
            !outcome.mint.newly_minted,
            "the key was already minted by record_and_persist"
        );

        let dest = PolicyStateStore::new();
        store.load_into("reset", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!((sum, count), (0, 0), "reset must clear all history");
    }

    // ── resign ───────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn resign_then_load_with_new_key_reads_green() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut profile = test_profile(dir.path(), "resign");
        let path = dir.path().join("resign.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("resign", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 777)])
            .unwrap();

        // Rotate: mint a NEW key at the same keyring coordinate, then re-sign.
        let entry_ref = &profile.policy_window_state_key_id;
        crate::keyring::rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account).unwrap();
        let new_key = crate::keyring::load_hmac_key_32(entry_ref).unwrap();
        store.resign(&new_key).unwrap();

        // load_into re-reads the (now-current) keyring key internally.
        let dest = PolicyStateStore::new();
        store.load_into("resign", &profile, &dest).unwrap();
        let (sum, _) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            sum, 777,
            "re-signed store must read green under the new key"
        );

        // Silence an unused-mut warning if the profile is never mutated
        // beyond construction in this test.
        let _ = &mut profile;
    }

    // ── anti-rollback generation counter ────────────────────────────────

    /// No file, no keyring generation entry: `load_into` initializes cleanly
    /// (empty history, no error), and the subsequent first write mints both
    /// the HMAC key and generation=1.
    #[test]
    #[serial]
    fn first_run_initializes_cleanly_with_no_prior_state() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "firstrun");
        let store = PersistedWindowStore::at_path(dir.path().join("firstrun.window"));

        let dest = PolicyStateStore::new();
        store.load_into("firstrun", &profile, &dest).unwrap();
        let (sum, count) = dest
            .query_window(&key("firstrun", "native", 86_400), now_ms().unwrap())
            .unwrap();
        assert_eq!((sum, count), (0, 0));

        let k = key("firstrun", "native", 86_400);
        let now = now_ms().unwrap();
        let outcome = store
            .record_and_persist(&profile, &[entry(k.clone(), now, 111)])
            .unwrap();
        assert!(outcome.newly_minted);

        let dest2 = PolicyStateStore::new();
        store.load_into("firstrun", &profile, &dest2).unwrap();
        let (sum, _) = dest2.query_window(&k, now + 1_000).unwrap();
        assert_eq!(sum, 111);
    }

    /// Deleting the store file after it has been used (the keyring
    /// generation is minted and non-zero) is detected as a deletion:
    /// `load_into` fails closed instead of silently treating the missing
    /// file as a fresh first run.
    #[test]
    #[serial]
    fn deletion_after_use_fails_closed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "deleted");
        let path = dir.path().join("deleted.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("deleted", "native", 86_400);
        store
            .record_and_persist(&profile, &[entry(k, now_ms().unwrap(), 500)])
            .unwrap();

        fs::remove_file(&path).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("deleted", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "a missing file with a minted keyring generation must fail closed, got {result:?}"
        );
    }

    /// Restoring an OLDER, validly-HMAC-signed snapshot of the store file
    /// (e.g. from a stale backup) after the generation has moved on is a
    /// rollback attempt. The HMAC alone would verify — it was genuinely
    /// signed under the same key when written — so only the generation
    /// check catches this.
    #[test]
    #[serial]
    fn rollback_to_older_valid_file_fails_closed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "rollback");
        let path = dir.path().join("rollback.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("rollback", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 100)])
            .unwrap();
        // Snapshot the validly-signed generation=1 file bytes before the
        // second write bumps the generation to 2.
        let old_bytes = fs::read(&path).unwrap();

        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 200)])
            .unwrap();

        // Restore the older (generation=1) snapshot: still a valid HMAC tag
        // under the current key, but behind the keyring's generation=2.
        fs::write(&path, &old_bytes).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("rollback", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "a validly-signed but stale-generation file must fail closed, got {result:?}"
        );
    }

    /// Simulates a crash between the keyring generation bump and the
    /// following file write completing (the keyring-first ordering
    /// `record_and_persist` documents): the keyring is ahead of the file.
    /// `load_into` fails closed, and `reset` recovers by re-baselining both
    /// to a new, consistent generation.
    #[test]
    #[serial]
    fn crash_ordering_keyring_ahead_of_file_fails_closed_and_reset_recovers() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "crashgen");
        let path = dir.path().join("crashgen.window");
        let store = PersistedWindowStore::at_path(path);
        let k = key("crashgen", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 50)])
            .unwrap();

        // Simulate the crash: bump the keyring generation as
        // `record_and_persist` would at its keyring-first step, WITHOUT the
        // file write that should follow it.
        let gen_entry = generation_entry_ref(&profile);
        bump_generation(&gen_entry).unwrap();

        let dest = PolicyStateStore::new();
        let result = store.load_into("crashgen", &profile, &dest);
        assert!(
            matches!(result, Err(WindowStoreError::GenerationMismatch)),
            "keyring ahead of the file must fail closed, got {result:?}"
        );

        // reset re-baselines both — recovery succeeds and the store reads
        // empty (the pre-crash history is unrecoverable, by design: the
        // store cannot know whether the un-persisted write was legitimate).
        store.reset(&profile, now, |_| Ok::<(), ()>(())).unwrap();
        let dest2 = PolicyStateStore::new();
        store.load_into("crashgen", &profile, &dest2).unwrap();
        let (sum, count) = dest2.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (0, 0),
            "reset must recover to an empty, consistent state"
        );
    }

    // ── end-to-end persist seam ─────────────────────────────────────────

    /// The full persist → fresh-load → fresh-engine round trip: a first
    /// "process" (fresh in-memory store hydrated from an empty file, fresh
    /// `PolicyEngineV1`) evaluates and confirms a payment, persisting the
    /// derived window-state entries to disk. A second, entirely independent
    /// "process" (a NEW `PolicyStateStore` hydrated from that file, a NEW
    /// `PolicyEngineV1` over it) evaluates the identical payment again and
    /// is DENIED — proving the persisted state, not merely in-memory
    /// accumulation within one engine instance, drives the second decision.
    /// (`record_confirmed_per_period_cap_accumulates_then_second_call_denies`
    /// in `stellar-agent-core` covers the in-memory-only case; this test is
    /// the seam that case cannot reach, since `stellar-agent-core` cannot
    /// depend on `stellar-agent-network`.)
    #[test]
    #[serial]
    fn end_to_end_persist_seam_second_process_denies() {
        use stellar_agent_core::policy::ToolValueKind;
        use stellar_agent_core::policy::v1::criteria::per_period_cap::{
            PerPeriodCapCriterion, Window,
        };
        use stellar_agent_core::policy::v1::value::{
            ActionKind, ValueClass, ValueEffects, ValueLeg,
        };
        use stellar_agent_core::{
            Decision, DenyReason, McpToolRegistration, PolicyDocument, PolicyEngine,
            PolicyEngineV1, PolicyRule, RuleMatch, ScopeId, ToolDescriptor,
        };

        fn allow_all_with_per_period_cap() -> PolicyDocument {
            // Cap: 100 XLM. Each call attempts 60 XLM.
            let window = Window::parse("1d").unwrap();
            let criterion = PerPeriodCapCriterion::new("native".into(), window, 1_000_000_000);
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: vec![Box::new(criterion)],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
                signature: None,
            }
        }

        fn pay_tool() -> ToolDescriptor {
            let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: false,
                read_only_hint: false,
                chain_id_required: false,
                value_kind: ToolValueKind::MovesValue,
            });
            td.chain_id = "stellar:testnet".to_owned();
            td
        }

        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "seam");
        let store = PersistedWindowStore::at_path(dir.path().join("seam.window"));
        let td = pay_tool();
        let value = ValueClass::Value(ValueEffects::single(ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        }));

        // "Process" 1: fresh store hydrated from disk (empty — genuine first
        // run), evaluate → Allow, record_confirmed → derive entries, persist.
        let fresh1 = PolicyStateStore::new();
        store.load_into("seam", &profile, &fresh1).unwrap();
        let engine1 =
            PolicyEngineV1::new_with_store(allow_all_with_per_period_cap(), "seam".into(), fresh1);
        let d1 = engine1
            .evaluate_with_value(
                &td,
                &serde_json::Value::Null,
                &profile,
                value.clone(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(d1, Decision::Allow, "first call must be allowed");
        let recorded = engine1.record_confirmed(&td, &profile, &value).unwrap();
        assert_eq!(recorded.len(), 1, "exactly one debit entry recorded");
        store.record_and_persist(&profile, &recorded).unwrap();

        // "Process" 2: an entirely fresh PolicyStateStore hydrated from the
        // file `store` just wrote, and a fresh PolicyEngineV1 over it. The
        // identical call now DENIES: 60 + 60 = 120 XLM exceeds the 100 XLM
        // cap, and the 60 XLM from "process" 1 is visible ONLY because it
        // was persisted to disk and re-hydrated — this engine instance never
        // saw the first call.
        let fresh2 = PolicyStateStore::new();
        store.load_into("seam", &profile, &fresh2).unwrap();
        let engine2 =
            PolicyEngineV1::new_with_store(allow_all_with_per_period_cap(), "seam".into(), fresh2);
        let d2 = engine2
            .evaluate_with_value(
                &td,
                &serde_json::Value::Null,
                &profile,
                value,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(
            matches!(d2, Decision::Deny(DenyReason::PerPeriodCapExceeded { .. })),
            "second process's identical call must be denied by persisted state, got {d2:?}"
        );
    }

    // ── reservations ────────────────────────────────────────────────────

    fn reservation(id: &str, source: &str, sequence: i64, pending_since_ms: u64) -> SubmissionHold {
        SubmissionHold {
            id: id.to_owned(),
            tx_hash: "ab".repeat(32),
            source: source.to_owned(),
            sequence,
            max_time: 0,
            pending_since_ms,
            submission_ledger: 1_000,
            operator_required: false,
        }
    }

    /// A reservation counts against a window criterion exactly as confirmed
    /// spend does: the transaction has been sent and may apply.
    #[test]
    #[serial]
    fn a_pending_reservation_counts_toward_the_window_total() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-count");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-count.window"));
        let k = key("resv-count", "native", 86_400);
        let now = now_ms().unwrap();

        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 600_000_000)],
                &reservation("a".repeat(64).as_str(), "GSOURCE", 7, now),
            )
            .unwrap();

        let dest = PolicyStateStore::new();
        store.load_into("resv-count", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (600_000_000, 1),
            "a pending reservation must count against the window like confirmed spend"
        );
    }

    /// Confirming a reservation keeps its records and stops them being
    /// reported as open.
    #[test]
    #[serial]
    fn confirm_keeps_the_records_and_closes_the_reservation() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-confirm");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-confirm.window"));
        let k = key("resv-confirm", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "b".repeat(64);

        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 250)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        assert_eq!(store.pending_reservations(&profile).unwrap().len(), 1);

        store
            .confirm(&profile, &id, Some((now / 1_000) as i64))
            .unwrap();

        assert!(
            store.pending_reservations(&profile).unwrap().is_empty(),
            "a confirmed reservation is no longer open"
        );
        let dest = PolicyStateStore::new();
        store.load_into("resv-confirm", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (250, 1),
            "confirming keeps the spend: the transaction reached a ledger"
        );
    }

    /// Releasing a reservation removes its records, so the reserved amount
    /// stops counting against the window.
    #[test]
    #[serial]
    fn release_removes_the_records() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-release");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-release.window"));
        let k = key("resv-release", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "c".repeat(64);

        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 900)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        store.release(&profile, &id).unwrap();

        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let dest = PolicyStateStore::new();
        store.load_into("resv-release", &profile, &dest).unwrap();
        let (sum, count) = dest.query_window(&k, now + 1_000).unwrap();
        assert_eq!(
            (sum, count),
            (0, 0),
            "a released reservation stops counting against the window"
        );
    }

    /// A release drops pending records only: spend the chain confirmed under
    /// the same reservation id keeps counting, and a release that finds
    /// nothing pending leaves the file as it stands.
    #[test]
    #[serial]
    fn release_keeps_confirmed_records() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-keep-confirmed");
        let path = dir.path().join("resv-keep-confirmed.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("resv-keep-confirmed", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "c1".repeat(32);

        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 900)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        store
            .confirm(&profile, &id, Some((now / 1_000) as i64))
            .unwrap();
        let confirmed_bytes = std::fs::read(&path).unwrap();

        store.release(&profile, &id).unwrap();

        assert_eq!(
            std::fs::read(&path).unwrap(),
            confirmed_bytes,
            "a release with nothing pending writes nothing"
        );
        let dest = PolicyStateStore::new();
        store
            .load_into("resv-keep-confirmed", &profile, &dest)
            .unwrap();
        assert_eq!(
            dest.query_window(&k, now + 1_000).unwrap(),
            (900, 1),
            "confirmed spend keeps counting after a release of its reservation id"
        );
    }

    /// The file refuses a second reservation for bytes it already holds,
    /// pending or confirmed, and writes nothing.
    #[test]
    #[serial]
    fn a_reservation_for_bytes_the_file_holds_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-duplicate");
        let path = dir.path().join("resv-duplicate.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("resv-duplicate", "native", 86_400);
        let now = now_ms().unwrap();
        let id = "d1".repeat(32);

        assert!(!store.holds_reservation(&profile, &id).unwrap());
        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 400)],
                &reservation(&id, "GSOURCE", 7, now),
            )
            .unwrap();
        assert!(store.holds_reservation(&profile, &id).unwrap());
        assert!(!store.holds_reservation(&profile, &"d2".repeat(32)).unwrap());
        assert!(
            !store.holds_reservation(&profile, "").unwrap(),
            "an empty id matches no record"
        );

        for settled in [false, true] {
            if settled {
                store
                    .confirm(&profile, &id, Some((now / 1_000) as i64))
                    .unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let refused = store.record_pending(
                &profile,
                &[entry(k.clone(), now, 400)],
                &reservation(&id, "GSOURCE", 7, now),
            );
            assert!(
                matches!(refused, Err(WindowStoreError::DuplicateReservation)),
                "confirmed={settled}: {refused:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), before, "nothing is written");
        }

        // Spend recorded without a reservation carries an empty id and never
        // stands in for one.
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 5)])
            .unwrap();
        store
            .record_pending(
                &profile,
                &[entry(k.clone(), now, 5)],
                &reservation(&"d3".repeat(32), "GSOURCE", 8, now),
            )
            .unwrap();
        let dest = PolicyStateStore::new();
        store.load_into("resv-duplicate", &profile, &dest).unwrap();
        assert_eq!(dest.query_window(&k, now + 1_000).unwrap(), (410, 3));
    }

    /// Reservations are reported oldest first, so a bounded reconciliation
    /// pass settles the ones that have stood longest.
    #[test]
    #[serial]
    fn pending_reservations_are_reported_oldest_first() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "resv-order");
        let store = PersistedWindowStore::at_path(dir.path().join("resv-order.window"));
        let k = key("resv-order", "native", 86_400);
        let now = now_ms().unwrap();

        for (index, offset) in [(0_u8, 30_000_u64), (1, 10_000), (2, 20_000)] {
            let id = format!("{index:064}");
            store
                .record_pending(
                    &profile,
                    &[entry(k.clone(), now, 1)],
                    &reservation(&id, "GSOURCE", i64::from(index), now - offset),
                )
                .unwrap();
        }

        let open = store.pending_reservations(&profile).unwrap();
        let ages: Vec<u64> = open.iter().map(|r| r.pending_since_ms).collect();
        assert_eq!(
            ages,
            vec![now - 30_000, now - 20_000, now - 10_000],
            "reservations must be reported oldest first"
        );
    }

    // ── wire version ────────────────────────────────────────────────────

    /// Rewrites the store file's body with `mutate` applied, re-signing under
    /// the profile's key so the tag stays valid.
    fn rewrite_body_version(store: &PersistedWindowStore, profile: &Profile, version: u32) {
        let key = crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let bytes = fs::read(&store.path).unwrap();
        let mut wire: serde_json::Value = serde_json::from_slice(&bytes[HMAC_TAG_LEN..]).unwrap();
        wire["version"] = serde_json::json!(version);
        let gen_entry = generation_entry_ref(profile);
        keyring_core::Entry::new(&gen_entry.service, &gen_entry.account)
            .unwrap()
            .set_password(&wire["generation"].as_u64().unwrap().to_string())
            .unwrap();
        if version == 1 {
            for bucket in wire["entries"].as_array_mut().unwrap() {
                for record in bucket["records"].as_array_mut().unwrap() {
                    record
                        .as_object_mut()
                        .unwrap()
                        .retain(|name, _| name == "ts_ms" || name == "amount");
                }
            }
        }
        if version == 2 {
            for bucket in wire["entries"].as_array_mut().unwrap() {
                for record in bucket["records"].as_array_mut().unwrap() {
                    record.as_object_mut().unwrap().remove("operator_required");
                }
            }
        }
        let body = serde_json::to_vec(&wire).unwrap();
        let tag = compute_tag(key.as_slice(), &body).unwrap();
        store.write_atomic_raw(&tag, &body).unwrap();
    }

    /// A v1 file contains confirmed spend and no open reservation identity.
    #[test]
    #[serial]
    fn a_v1_file_reads_as_confirmed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v1-read");
        let store = PersistedWindowStore::at_path(dir.path().join("v1-read.window"));
        let k = key("v1-read", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 4_200)])
            .unwrap();
        rewrite_body_version(&store, &profile, 1);

        let original = fs::read(&store.path).unwrap();
        let dest = PolicyStateStore::new();
        store.load_into("v1-read", &profile, &dest).unwrap();
        assert_eq!(
            fs::read(&store.path).unwrap(),
            original,
            "hydration leaves v1 bytes unchanged"
        );
        assert_eq!(dest.query_window(&k, now + 1_000).unwrap(), (4_200, 1));
        assert_eq!(dest.query_window(&k, now + 86_400_001).unwrap(), (0, 0));
        assert!(
            store.pending_reservations(&profile).unwrap().is_empty(),
            "a v1 record carries no reservation to reconcile"
        );
    }

    /// A prepared settlement is selected only by its trusted generation;
    /// both crash checkpoints remain readable and a replayed old file is refused.
    #[test]
    #[serial]
    fn prepared_settlement_recovers_both_sides_of_the_commit_point() {
        for release in [false, true] {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let profile = test_profile(dir.path(), "prepared-hold");
            let store = PersistedWindowStore::at_path(dir.path().join("prepared-hold.window"));
            let k = key("prepared-hold", "native", 86_400);
            let now = now_ms().unwrap();
            let res = reservation(&"c".repeat(64), "GSOURCE", 7, now);
            store
                .record_pending(&profile, &[entry(k.clone(), now, 43)], &res)
                .unwrap();
            let old_bytes = fs::read(&store.path).unwrap();
            let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
            let mut next = original.clone();
            next.generation += 1;
            if release {
                next.entries.clear();
            } else {
                next.entries[0].records[0].operator_required = true;
            }
            original.prepared = Some(Box::new(next.clone()));
            let hmac_key =
                crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
            store.write_atomic(&hmac_key, &original).unwrap();
            let prepared_bytes = fs::read(&store.path).unwrap();
            let reopened = PersistedWindowStore::at_path(store.path.clone());
            assert_eq!(
                reopened.pending_reservations(&profile).unwrap(),
                vec![res.clone()]
            );
            let memory = PolicyStateStore::new();
            reopened
                .load_into("prepared-hold", &profile, &memory)
                .unwrap();
            assert_eq!(memory.query_window(&k, now).unwrap(), (43, 1));
            write_generation(&generation_entry_ref(&profile), &next).unwrap();
            let held = reopened.pending_reservations(&profile).unwrap();
            assert_eq!(held.len(), usize::from(!release));
            if !release {
                assert!(held[0].operator_required);
            }
            let memory = PolicyStateStore::new();
            reopened
                .load_into("prepared-hold", &profile, &memory)
                .unwrap();
            assert_eq!(
                memory.query_window(&k, now).unwrap(),
                if release { (0, 0) } else { (43, 1) }
            );
            fs::write(&store.path, &old_bytes).unwrap();
            assert!(matches!(
                reopened.pending_reservations(&profile),
                Err(WindowStoreError::GenerationMismatch)
            ));
            fs::write(&store.path, &prepared_bytes).unwrap();
            reopened.release(&profile, &res.id).unwrap();
            assert!(reopened.pending_reservations(&profile).unwrap().is_empty());
        }
    }

    /// An abandoned candidate cannot replace a different committed body that
    /// receives the same generation number after retrying the write.
    #[test]
    #[serial]
    fn abandoned_candidate_cannot_replay_at_a_reused_generation() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "abandoned-candidate");
        let store = PersistedWindowStore::at_path(dir.path().join("abandoned-candidate.window"));
        let k = key("abandoned-candidate", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"e".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[entry(k.clone(), now, 45)], &res)
            .unwrap();
        let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut abandoned = original.clone();
        abandoned.generation += 1;
        abandoned.entries.clear();
        original.prepared = Some(Box::new(abandoned));
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        store.write_atomic(&hmac_key, &original).unwrap();
        let abandoned_bytes = fs::read(&store.path).unwrap();

        // A new debit commits while the abandoned release remains uncommitted.
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 5)])
            .unwrap();
        let committed_bytes = fs::read(&store.path).unwrap();
        assert_eq!(
            load_generation(&generation_entry_ref(&profile)).unwrap(),
            Some(original.generation + 1)
        );
        fs::write(&store.path, abandoned_bytes).unwrap();
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.load_into("abandoned-candidate", &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.release(&profile, &res.id),
            Err(WindowStoreError::GenerationMismatch)
        ));
        fs::write(&store.path, committed_bytes).unwrap();
        let memory = PolicyStateStore::new();
        store
            .load_into("abandoned-candidate", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (50, 2));
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
    }

    /// A failed prepare write cannot advance the trusted generation or hide a hold.
    #[test]
    #[serial]
    fn failed_prepare_write_keeps_the_authenticated_hold_readable() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "prepare-write-failure");
        let store = PersistedWindowStore::at_path(dir.path().join("prepare-write-failure.window"));
        let k = key("prepare-write-failure", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"d".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[entry(k.clone(), now, 44)], &res)
            .unwrap();
        let blocker = dir.path().join("prepare-write-failure.window.tmp");
        fs::create_dir(&blocker).unwrap();
        assert!(store.mark_operator_required(&profile, &res.id).is_err());
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        let memory = PolicyStateStore::new();
        store
            .load_into("prepare-write-failure", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (44, 1));
    }

    /// A candidate is committed only by a digest-bearing keyring write, so a
    /// numeric counter equal to a candidate's generation is not a commitment
    /// of it and the file is refused. A numeric counter at the outer
    /// generation still reads the outer, which is the state a crash before
    /// the commit point leaves under a legacy counter.
    #[test]
    #[serial]
    fn a_numeric_counter_never_selects_a_candidate() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "numeric-candidate");
        let store = PersistedWindowStore::at_path(dir.path().join("numeric-candidate.window"));
        let k = key("numeric-candidate", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"f".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[entry(k.clone(), now, 46)], &res)
            .unwrap();
        let gen_entry = generation_entry_ref(&profile);
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut candidate = original.clone();
        candidate.generation += 1;
        candidate.entries.clear();
        original.prepared = Some(Box::new(candidate.clone()));
        store.write_atomic(&hmac_key, &original).unwrap();
        let counter = keyring_core::Entry::new(&gen_entry.service, &gen_entry.account).unwrap();

        counter
            .set_password(&candidate.generation.to_string())
            .unwrap();
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.load_into("numeric-candidate", &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::GenerationMismatch)
        ));
        assert!(matches!(
            store.release(&profile, &res.id),
            Err(WindowStoreError::GenerationMismatch)
        ));

        counter
            .set_password(&original.generation.to_string())
            .unwrap();
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        let memory = PolicyStateStore::new();
        store
            .load_into("numeric-candidate", &profile, &memory)
            .unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (46, 1));
    }

    /// A keyring failure at the commit point, through the production commit:
    /// the prepared image is on disk, the counter is unchanged, the hold is
    /// still reported and counted, and a retry completes and compacts.
    ///
    /// The injected error is single-shot and lands on the commit write
    /// because the commit does not read the counter again after the
    /// verified read.
    #[test]
    #[serial]
    fn a_keyring_failure_at_the_commit_point_keeps_the_hold_and_the_retry_completes() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "commit-point");
        let store = PersistedWindowStore::at_path(dir.path().join("commit-point.window"));
        let k = key("commit-point", "native", 86_400);
        let now = now_ms().unwrap();
        let res = reservation(&"a".repeat(64), "GSOURCE", 7, now);
        store
            .record_pending(&profile, &[entry(k.clone(), now, 47)], &res)
            .unwrap();
        let gen_entry = generation_entry_ref(&profile);
        let counter = keyring_core::Entry::new(&gen_entry.service, &gen_entry.account).unwrap();
        let committed = counter.get_password().unwrap();
        let hmac_key =
            crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
        let original = store.read_for_inspection(&profile).unwrap().unwrap();
        let mut next = original.clone();
        next.entries.clear();
        keyring_mock::inject_error(
            &gen_entry.service,
            &gen_entry.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(
                "keyring unavailable at the commit point",
            ))),
        )
        .unwrap();

        let result = store.commit_generation(&hmac_key, &gen_entry, original.clone(), next);
        assert!(
            matches!(result, Err(WindowStoreError::Keyring { .. })),
            "the commit must report the keyring failure, got {result:?}"
        );
        assert_eq!(counter.get_password().unwrap(), committed);
        let body: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()[HMAC_TAG_LEN..]).unwrap();
        assert_eq!(body["generation"], original.generation);
        assert_eq!(body["prepared"]["generation"], original.generation + 1);
        assert_eq!(
            store.pending_reservations(&profile).unwrap(),
            vec![res.clone()]
        );
        let memory = PolicyStateStore::new();
        store.load_into("commit-point", &profile, &memory).unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (47, 1));

        store.release(&profile, &res.id).unwrap();
        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let body: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).unwrap()[HMAC_TAG_LEN..]).unwrap();
        assert!(
            body.get("prepared").is_none(),
            "a completed commit is compacted"
        );
        assert_eq!(body["generation"], original.generation + 1);
        assert_eq!(
            load_generation(&gen_entry).unwrap(),
            Some(original.generation + 1)
        );
    }

    /// Version 2 preserves pending identity and headroom without an operator marker.
    #[test]
    #[serial]
    fn a_v2_pending_file_keeps_its_hold() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v2-hold");
        let store = PersistedWindowStore::at_path(dir.path().join("v2-hold.window"));
        let k = key("v2-hold", "native", 86_400);
        let now = now_ms().unwrap();
        let old = now - 14 * 86_400_000;
        let res = reservation(&"a".repeat(64), "GSOURCE", 7, old);
        store
            .record_pending(&profile, &[entry(k.clone(), old, 42)], &res)
            .unwrap();
        rewrite_body_version(&store, &profile, 2);
        let original = fs::read(&store.path).unwrap();
        let dest = PolicyStateStore::new();
        store.load_into("v2-hold", &profile, &dest).unwrap();
        assert_eq!(dest.query_window(&k, now).unwrap(), (42, 1));
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
        assert_eq!(fs::read(&store.path).unwrap(), original);
    }

    /// A file written by a newer build carries records this one cannot
    /// account for, so it is refused rather than read with the fields it
    /// happens to recognise.
    #[test]
    #[serial]
    fn a_newer_wire_version_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v3-read");
        let store = PersistedWindowStore::at_path(dir.path().join("v3-read.window"));
        let k = key("v3-read", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k, now, 1)])
            .unwrap();
        rewrite_body_version(&store, &profile, WIRE_VERSION_MAX + 1);

        let dest = PolicyStateStore::new();
        let err = store
            .load_into("v3-read", &profile, &dest)
            .expect_err("a newer wire version must be refused");
        assert!(
            matches!(err, WindowStoreError::UnsupportedVersion { version, max } if version == max + 1),
            "the refusal must name the version condition; got {err:?}"
        );
    }

    /// The reconciliation budget and minimum age are the bound a value verb
    /// spends on reconciliation before its policy gate.
    #[test]
    fn reconcile_bounds_are_the_documented_values() {
        assert_eq!(RECONCILE_BUDGET, 5);
        assert_eq!(RECONCILE_MIN_AGE_MS, 300_000);
    }

    /// The window file is owner-read-write only on Unix.
    ///
    /// It holds account identifiers, sequence numbers and spend history, and
    /// the HMAC tag proves integrity, not confidentiality.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn the_window_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;

        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "mode-guard");
        let path = dir.path().join("mode-guard.window");
        let store = PersistedWindowStore::at_path(path.clone());
        let k = key("mode-guard", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k, now, 1)])
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the window file must be readable and writable by its owner alone; got {mode:o}"
        );
    }

    // ── owner key refusals ───────────────────────────────────────────────

    const OWNER_KEY: [u8; 32] = [0x6a; 32];

    fn owner_profile(dir: &Path, name: &str) -> Profile {
        let mut p = Profile::builder_testnet_named(name, "s", "acct", "n-svc", "n-acct").build();
        p.audit_log_path = dir.join("audit.jsonl");
        p
    }

    fn put_raw(entry_ref: &KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    }

    fn get_raw(entry_ref: &KeyringEntryRef) -> Option<String> {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .unwrap()
            .get_password()
            .ok()
    }

    /// A window file sealed under a key equal to the owner public key loads
    /// while no owner entry exists. Once the owner entry holds that key in the
    /// older form, `load_into`, the inspection read, and the load branch of
    /// the lazy-mint path each refuse, and nothing is minted over the key.
    #[test]
    #[serial]
    fn every_window_key_loader_refuses_the_owner_key() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "owner-window";
        let profile = owner_profile(dir.path(), name);
        let older_form = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(OWNER_KEY);
        put_raw(&profile.policy_window_state_key_id, &older_form);
        let store = PersistedWindowStore::at_path(dir.path().join("owner.window"));
        let k = key(name, "native", 86_400);
        let now = now_ms().unwrap();
        let outcome = store
            .record_and_persist(&profile, &[entry(k.clone(), now, 100)])
            .unwrap();
        assert!(
            !outcome.newly_minted,
            "the planted key is loaded, not minted"
        );
        store
            .load_into(name, &profile, &PolicyStateStore::new())
            .unwrap();
        assert_eq!(store.pending_reservations(&profile).unwrap().len(), 0);

        put_raw(&KeyringEntryRef::default_owner_key(name), &older_form);
        assert!(matches!(
            store.load_into(name, &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(matches!(
            store.record_and_persist(&profile, &[entry(k, now, 100)]),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(
            get_raw(&profile.policy_window_state_key_id).as_deref() == Some(older_form.as_str()),
            "the refusal mints nothing over the key"
        );
    }

    /// A G-strkey owner value at the window-key coordinate decodes to 42
    /// bytes, so the readers refuse it as a key.
    #[test]
    #[serial]
    fn a_g_strkey_owner_value_is_refused_by_the_window_readers() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let name = "owner-window-strkey";
        let profile = owner_profile(dir.path(), name);
        let store = PersistedWindowStore::at_path(dir.path().join("strkey.window"));
        store
            .record_and_persist(
                &profile,
                &[entry(key(name, "native", 86_400), now_ms().unwrap(), 1)],
            )
            .unwrap();
        put_raw(
            &profile.policy_window_state_key_id,
            &stellar_agent_core::profile::owner_key::encode_owner_public_key(&OWNER_KEY),
        );
        for result in [
            store.load_into(name, &profile, &PolicyStateStore::new()),
            store.pending_reservations(&profile).map(|_| ()),
        ] {
            let err = result.expect_err("a G-strkey is not a 32-byte key");
            assert!(err.to_string().contains("got 42"), "{err}");
        }
    }

    /// An owner-namespace window-key coordinate refuses before any keyring
    /// read, on every loader, and mints nothing there.
    #[test]
    #[serial]
    fn an_owner_namespace_window_key_coordinate_is_refused() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let mut profile = owner_profile(dir.path(), "owner-window-coord");
        profile.policy_window_state_key_id =
            KeyringEntryRef::new("stellar-agent-owner-B", "default");
        let store = PersistedWindowStore::at_path(dir.path().join("coord.window"));
        assert!(matches!(
            store.record_and_persist(
                &profile,
                &[entry(
                    key("owner-window-coord", "native", 86_400),
                    now_ms().unwrap(),
                    1
                )]
            ),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(matches!(
            store.pending_reservations(&profile),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(matches!(
            store.load_into("owner-window-coord", &profile, &PolicyStateStore::new()),
            Err(WindowStoreError::KeyMatchesOwnerPublicKey)
        ));
        assert!(
            get_raw(&profile.policy_window_state_key_id).is_none(),
            "nothing is minted at the owner coordinate"
        );
    }

    /// The helper names the `policy_window_state_key_id` label and the shared
    /// code.
    #[test]
    #[serial]
    fn the_owner_refusal_names_the_window_label() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        put_raw(
            &KeyringEntryRef::default_owner_key("owner-window-label"),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(OWNER_KEY),
        );
        let owner = OwnerKeyContext::for_profile_name("owner-window-label");
        let err = refuse_owner_public_key(&OWNER_KEY, &owner).unwrap_err();
        let message = err.to_string();
        assert!(message.contains(POLICY_STATE_KEY_FIELD), "{message}");
        assert!(
            message.contains("validation.key_matches_owner_public_key"),
            "{message}"
        );
        assert!(refuse_owner_public_key(&[0x11; 32], &owner).is_ok());
    }
    struct ResetFixture {
        _dir: TempDir,
        profile: Profile,
        store: PersistedWindowStore,
    }

    impl ResetFixture {
        fn new() -> Self {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let profile = owner_profile(dir.path(), "reset-snapshot");
            let store = PersistedWindowStore::at_path(dir.path().join("state.window"));
            Self {
                _dir: dir,
                profile,
                store,
            }
        }

        fn seal(&self, wire: &WireFile) {
            let (key, _) = self.store.load_or_mint_key(&self.profile).unwrap();
            self.store.write_atomic(&key, wire).unwrap();
            write_generation(&generation_entry_ref(&self.profile), wire).unwrap();
        }

        fn reset(&self) -> ResetOutcome {
            self.store
                .reset(&self.profile, 100_000, |_| Ok::<_, ()>(()))
                .unwrap()
        }
    }

    fn reset_wire() -> WireFile {
        WireFile {
            version: WIRE_VERSION_COMPACT,
            generation: 1,
            prepared: None,
            entries: vec![WireBucket {
                scope_specificity: 2,
                bucket: "native".to_owned(),
                window_secs: 10,
                records: vec![WireRecord {
                    ts_ms: 90_000,
                    amount: 7,
                    ..WireRecord::confirmed_defaults()
                }],
            }],
            ..WireFile::default()
        }
    }

    #[test]
    #[serial]
    fn reset_snapshot_keeps_inclusive_boundary_and_pending_records() {
        let f = ResetFixture::new();
        let mut wire = reset_wire();
        wire.entries[0].records.extend([
            WireRecord {
                ts_ms: 89_999,
                amount: 100,
                ..WireRecord::confirmed_defaults()
            },
            WireRecord {
                ts_ms: 95_000,
                amount: 11,
                ..WireRecord::confirmed_defaults()
            },
            WireRecord {
                ts_ms: 0,
                amount: 13,
                status: RecordStatus::Pending,
                ..WireRecord::confirmed_defaults()
            },
            WireRecord {
                ts_ms: u64::MAX,
                amount: 17,
                status: RecordStatus::Pending,
                ..WireRecord::confirmed_defaults()
            },
        ]);
        let mut other = wire.entries[0].clone();
        other.scope_specificity = 3;
        other.records.truncate(1);
        wire.entries.push(other);
        f.seal(&wire);
        let outcome = f.reset();
        let row = outcome.accrual;
        assert_eq!(row.previous, PreviousState::Verified);
        assert_eq!(row.entry_count, 5);
        assert_eq!((row.generation_before, row.generation_after), (Some(1), 2));
        assert_eq!(row.buckets.len(), 2);
        assert_eq!(row.buckets[0].scope_specificity, 2);
        assert_eq!(row.buckets[1].scope_specificity, 3);
        assert_eq!(
            (
                row.buckets[0].confirmed_count,
                row.buckets[0].confirmed_total
            ),
            (2, 18)
        );
        assert_eq!(
            (row.buckets[0].pending_count, row.buckets[0].pending_total),
            (2, 30)
        );
        assert!(!row.truncated);
        assert_eq!(
            load_generation(&generation_entry_ref(&f.profile)).unwrap(),
            Some(2)
        );
        let empty = f.store.read_for_inspection(&f.profile).unwrap().unwrap();
        assert_eq!(empty.generation, 2);
        assert!(empty.entries.is_empty());
    }

    #[test]
    #[serial]
    fn reset_totals_saturate() {
        let f = ResetFixture::new();
        let mut wire = reset_wire();
        wire.entries[0].records = [RecordStatus::Confirmed, RecordStatus::Pending]
            .into_iter()
            .flat_map(|status| {
                [i128::MAX, 1].map(|amount| WireRecord {
                    ts_ms: 100_000,
                    status,
                    amount,
                    ..WireRecord::confirmed_defaults()
                })
            })
            .collect();
        f.seal(&wire);
        let row = f.reset().accrual;
        assert_eq!(row.buckets[0].confirmed_total, i128::MAX);
        assert_eq!(row.buckets[0].pending_total, i128::MAX);
    }

    #[test]
    #[serial]
    fn reset_omits_empty_buckets_and_caps_live_buckets_in_file_order() {
        let f = ResetFixture::new();
        let mut wire = reset_wire();
        let live = wire.entries[0].clone();
        wire.entries[0].records[0].ts_ms = 1;
        for i in 0..9 {
            let mut bucket = live.clone();
            bucket.bucket = format!("bucket-{i}");
            wire.entries.push(bucket);
        }
        f.seal(&wire);
        let row = f.reset().accrual;
        assert_eq!(row.entry_count, 9);
        assert!(row.truncated);
        assert_eq!(
            row.buckets
                .iter()
                .map(|b| b.bucket.as_str())
                .collect::<Vec<_>>(),
            (0..8).map(|i| format!("bucket-{i}")).collect::<Vec<_>>()
        );
    }

    fn largest_reset_authorization()
    -> stellar_agent_core::audit_log::schema::WindowResetAuthorization {
        stellar_agent_core::audit_log::schema::WindowResetAuthorization {
            owner_redacted: stellar_agent_core::observability::RedactedStrkey::from_full(
                &stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x51; 32]),
            ),
            store_sha256: Some("f".repeat(64)),
            signature: "f".repeat(128),
        }
    }

    #[test]
    #[serial]
    fn reset_largest_row_fits_without_writer_truncation() {
        use stellar_agent_core::audit_log::AuditEntry;
        use stellar_agent_core::audit_log::entry::MAX_ENTRY_BYTES;
        let f = ResetFixture::new();
        let mut wire = reset_wire();
        wire.entries[0].bucket = "b".repeat(300);
        wire.entries = vec![wire.entries[0].clone(); 8];
        f.seal(&wire);
        let mut row = f.reset().accrual;
        for bucket in &mut row.buckets {
            assert_eq!(bucket.bucket.chars().count(), 64);
            bucket.confirmed_count = usize::MAX;
            bucket.pending_count = usize::MAX;
            bucket.confirmed_total = i128::MIN;
            bucket.pending_total = i128::MAX;
            bucket.window_secs = u64::MAX;
            bucket.scope_specificity = u8::MAX;
        }
        row.entry_count = usize::MAX;
        row.generation_before = Some(u64::MAX - 1);
        row.generation_after = u64::MAX;
        let mut entry = AuditEntry::new_policy_window_state_reset(
            "profile_reset_window_state",
            "p".repeat(64),
            "r".repeat(128),
            "00000000-0000-4000-8000-000000000000",
            "stellar:mainnet",
            row,
            Some(largest_reset_authorization()),
        );
        assert_eq!(entry.chain_id.as_deref(), Some("stellar:mainnet"));
        entry.previous_entry_hash = format!("sha256:{}", "f".repeat(64));
        // The writer runs this bound at append.
        let size = serde_json::to_vec(&entry).unwrap().len();
        assert!(size < MAX_ENTRY_BYTES, "row is {size} bytes");
        entry.truncate_arg_keys_if_needed().unwrap();
        assert!(!entry.truncated);
        let json = serde_json::to_vec(&entry).unwrap();
        assert!(json.len() < MAX_ENTRY_BYTES, "row is {} bytes", json.len());
    }

    #[test]
    #[serial]
    fn reset_escaped_and_multibyte_ids_fit_without_writer_truncation() {
        use stellar_agent_core::audit_log::AuditEntry;
        use stellar_agent_core::audit_log::entry::MAX_ENTRY_BYTES;
        for (id, count) in [("\0", 10), ("\u{10348}", 16)] {
            let f = ResetFixture::new();
            let mut wire = reset_wire();
            wire.entries[0].bucket = id.repeat(300);
            wire.entries = vec![wire.entries[0].clone(); 8];
            f.seal(&wire);
            let mut row = f.reset().accrual;
            for bucket in &mut row.buckets {
                assert_eq!(bucket.bucket.chars().count(), count);
                bucket.confirmed_count = usize::MAX;
                bucket.pending_count = usize::MAX;
                bucket.confirmed_total = i128::MIN;
                bucket.pending_total = i128::MAX;
                bucket.window_secs = u64::MAX;
                bucket.scope_specificity = u8::MAX;
            }
            row.entry_count = usize::MAX;
            row.generation_before = Some(u64::MAX - 1);
            row.generation_after = u64::MAX;
            let mut entry = AuditEntry::new_policy_window_state_reset(
                "profile_reset_window_state",
                "\\".repeat(64),
                "\0".repeat(128),
                "00000000-0000-4000-8000-000000000000",
                "stellar:mainnet",
                row,
                Some(largest_reset_authorization()),
            );
            assert_eq!(entry.chain_id.as_deref(), Some("stellar:mainnet"));
            entry.previous_entry_hash = format!("sha256:{}", "f".repeat(64));
            // The writer runs this bound at append.
            let size = serde_json::to_vec(&entry).unwrap().len();
            assert!(size < MAX_ENTRY_BYTES, "row is {size} bytes");
            entry.truncate_arg_keys_if_needed().unwrap();
            assert!(!entry.truncated);
            let json = serde_json::to_vec(&entry).unwrap();
            assert!(json.len() < MAX_ENTRY_BYTES, "row is {} bytes", json.len());
        }
    }

    #[test]
    #[serial]
    fn reset_snapshots_the_committed_prepared_successor() {
        let f = ResetFixture::new();
        let mut original = reset_wire();
        let mut next = original.clone();
        next.generation = 2;
        next.entries[0].records[0].amount = 101;
        original.prepared = Some(Box::new(next.clone()));
        f.seal(&original);
        write_generation(&generation_entry_ref(&f.profile), &next).unwrap();
        let row = f.reset().accrual;
        assert_eq!(row.previous, PreviousState::Verified);
        assert_eq!(row.buckets[0].confirmed_total, 101);
        assert_eq!(row.generation_before, Some(2));
    }

    #[test]
    #[serial]
    fn reset_tampered_file_is_unverifiable_without_totals() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        let mut bytes = fs::read(&f.store.path).unwrap();
        bytes[0] ^= 1;
        fs::write(&f.store.path, bytes).unwrap();
        let row = f.reset().accrual;
        assert_eq!(row.previous, PreviousState::Unverifiable);
        assert_eq!(row.entry_count, 0);
        assert!(row.buckets.is_empty());
    }

    #[test]
    #[serial]
    fn reset_authentic_rollback_is_unverifiable() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        put_raw(&generation_entry_ref(&f.profile), "2");
        assert_eq!(f.reset().accrual.previous, PreviousState::Unverifiable);
    }

    #[test]
    #[serial]
    fn reset_malformed_files_are_unverifiable() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        let key = crate::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id).unwrap();
        let body = b"invalid JSON";
        f.store
            .write_atomic_raw(&compute_tag(key.as_ref(), body).unwrap(), body)
            .unwrap();
        assert_eq!(f.reset().accrual.previous, PreviousState::Unverifiable);
    }

    #[test]
    #[serial]
    fn reset_file_without_key_is_unverifiable_and_mints_after_recording() {
        let f = ResetFixture::new();
        fs::write(&f.store.path, b"unverifiable").unwrap();
        let row = f
            .store
            .reset(&f.profile, 100_000, |row| {
                assert!(get_raw(&f.profile.policy_window_state_key_id).is_none());
                assert_eq!(row.accrual.previous, PreviousState::Unverifiable);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(row.mint.newly_minted);
    }

    #[test]
    #[serial]
    fn reset_short_key_is_replaced_after_the_row() {
        let f = ResetFixture::new();
        put_raw(&f.profile.policy_window_state_key_id, "AA");
        fs::write(&f.store.path, b"unverifiable").unwrap();
        let outcome = f
            .store
            .reset(&f.profile, 100_000, |row| {
                assert_eq!(
                    get_raw(&f.profile.policy_window_state_key_id).as_deref(),
                    Some("AA")
                );
                assert_eq!(row.accrual.previous, PreviousState::Unverifiable);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(outcome.mint.newly_minted);
        assert!(crate::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id).is_ok());
    }

    #[test]
    #[serial]
    fn reset_undecodable_key_is_replaced_after_the_row() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        put_raw(&f.profile.policy_window_state_key_id, "not*base64");
        let outcome = f
            .store
            .reset(&f.profile, 100_000, |row| {
                assert_eq!(
                    get_raw(&f.profile.policy_window_state_key_id).as_deref(),
                    Some("not*base64")
                );
                assert_eq!(row.accrual.previous, PreviousState::Unverifiable);
                assert!(row.accrual.buckets.is_empty());
                assert_eq!(row.accrual.generation_before, Some(1));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(outcome.mint.newly_minted);
        assert!(crate::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id).is_ok());
    }

    #[test]
    #[serial]
    fn reset_key_read_error_refuses_before_recorder() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        let old = get_raw(&f.profile.policy_window_state_key_id);
        keyring_mock::inject_error(
            &f.profile.policy_window_state_key_id.service,
            &f.profile.policy_window_state_key_id.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("locked"))),
        )
        .unwrap();
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::Keyring { .. },
                minted: false,
            })
        ));
        assert!(!called);
        assert_eq!(get_raw(&f.profile.policy_window_state_key_id), old);
    }

    #[test]
    #[serial]
    fn reset_invalid_counter_refuses_before_recorder() {
        let f = ResetFixture::new();
        put_raw(&generation_entry_ref(&f.profile), "invalid commitment");
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::Keyring { .. },
                minted: false,
            })
        ));
        assert!(!called);
        assert!(get_raw(&f.profile.policy_window_state_key_id).is_none());
    }

    #[test]
    #[serial]
    fn reset_read_error_refuses_before_recorder() {
        let f = ResetFixture::new();
        fs::create_dir(&f.store.path).unwrap();
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::Io { .. },
                minted: false,
            })
        ));
        assert!(!called);
        assert!(get_raw(&f.profile.policy_window_state_key_id).is_none());
    }

    #[test]
    #[serial]
    fn reset_missing_with_counter_and_first_run_are_distinct() {
        let f = ResetFixture::new();
        let first = f.reset().accrual;
        assert_eq!(first.previous, PreviousState::Missing);
        assert_eq!(first.generation_before, None);
        assert_eq!(first.generation_after, 1);
        fs::remove_file(&f.store.path).unwrap();
        let next = f.reset().accrual;
        assert_eq!(next.previous, PreviousState::Missing);
        assert_eq!(next.generation_before, Some(1));
        assert_eq!(next.generation_after, 2);
    }

    #[test]
    #[serial]
    fn reset_generation_overflow_refuses_before_recorder() {
        let f = ResetFixture::new();
        put_raw(&generation_entry_ref(&f.profile), &u64::MAX.to_string());
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::Invalid { .. },
                minted: false,
            })
        ));
        assert!(!called);
        assert!(get_raw(&f.profile.policy_window_state_key_id).is_none());
    }

    #[test]
    #[serial]
    fn reset_owner_namespace_refuses_before_recorder() {
        let mut f = ResetFixture::new();
        f.profile.policy_window_state_key_id = KeyringEntryRef::default_owner_key("another");
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::KeyMatchesOwnerPublicKey,
                minted: false,
            })
        ));
        assert!(!called);
        assert!(get_raw(&f.profile.policy_window_state_key_id).is_none());
    }

    #[test]
    #[serial]
    fn reset_owner_equal_key_refuses_before_recorder() {
        use base64::Engine as _;
        let f = ResetFixture::new();
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(OWNER_KEY);
        put_raw(&f.profile.policy_window_state_key_id, &value);
        put_raw(&f.profile.policy_owner_key_id, &value);
        let mut called = false;
        let result = f.store.reset(&f.profile, 100_000, |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::KeyMatchesOwnerPublicKey,
                minted: false,
            })
        ));
        assert!(!called);
        assert_eq!(get_raw(&f.profile.policy_window_state_key_id), Some(value));
    }

    #[test]
    #[serial]
    fn reset_recorder_observes_unchanged_state_and_refusal_changes_nothing() {
        let f = ResetFixture::new();
        for present in [false, true] {
            if present {
                f.seal(&reset_wire());
            }
            let before = fs::read(&f.store.path).ok();
            let key = get_raw(&f.profile.policy_window_state_key_id);
            let counter = get_raw(&generation_entry_ref(&f.profile));
            let result = f.store.reset(&f.profile, 100_000, |row| {
                assert_eq!(fs::read(&f.store.path).ok(), before);
                assert_eq!(get_raw(&f.profile.policy_window_state_key_id), key);
                assert_eq!(get_raw(&generation_entry_ref(&f.profile)), counter);
                assert_eq!(
                    row.accrual.generation_before,
                    load_generation(&generation_entry_ref(&f.profile)).unwrap()
                );
                Err("recorder refused")
            });
            assert!(matches!(
                result,
                Err(ResetError::Recorder("recorder refused"))
            ));
            assert_eq!(fs::read(&f.store.path).ok(), before);
            assert_eq!(get_raw(&f.profile.policy_window_state_key_id), key);
            assert_eq!(get_raw(&generation_entry_ref(&f.profile)), counter);
        }
    }

    #[test]
    #[serial]
    fn reset_holds_window_lock_during_recorder() {
        let f = ResetFixture::new();
        let other = f.store.clone();
        let mut observed = None;
        f.store
            .reset(&f.profile, 100_000, |_| {
                observed = Some(other.reset(&f.profile, 100_000, |_| Ok::<_, ()>(())));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(
            observed,
            Some(Err(ResetError::Store {
                error: WindowStoreError::WriterLocked,
                minted: false,
            }))
        ));
    }

    #[test]
    #[serial]
    fn reset_write_failure_after_mint_reports_minted() {
        let f = ResetFixture::new();
        fs::create_dir(f.store.path.with_file_name("state.window.tmp")).unwrap();
        let result = f.store.reset(&f.profile, 100_000, |_| Ok::<_, ()>(()));
        assert!(matches!(
            result,
            Err(ResetError::Store {
                error: WindowStoreError::Io { .. },
                minted: true,
            })
        ));
        assert!(get_raw(&f.profile.policy_window_state_key_id).is_some());
    }

    /// A failed receipt checkpoint keeps the window pending until a retry succeeds.
    fn assert_settlement_waits_for_receipt(status: Option<&str>, missing: bool) {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "checkpoint");
        let store = PersistedWindowStore::at_path(dir.path().join("checkpoint.window"));
        let receipts = ReceiptStore::open_at(dir.path(), "checkpoint").unwrap();
        let now = now_ms().unwrap();
        let res = reservation(&"7a".repeat(32), "GSOURCE", 7, now);
        store
            .record_pending(
                &profile,
                &[entry(key("checkpoint", "native", 86_400), now, 900)],
                &res,
            )
            .unwrap();
        if !missing {
            receipts
                .try_begin(&res.id, &res.tx_hash, &res.source, 7, 0, 100)
                .unwrap();
            receipts.mark_submitted(&res.id).unwrap();
        }
        let before = receipts.get(&res.id).unwrap();
        let held = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(receipts.lock_file_path().unwrap())
            .unwrap();
        held.try_lock().unwrap();
        let settle = || {
            if let Some(status) = status {
                let answer = TransactionRecord::from_raw(
                    serde_json::from_value(serde_json::json!({
                        "status": status, "latestLedger": 200, "oldestLedger": 1,
                        "ledger": 150, "createdAt": (now / 1_000).to_string(),
                        "resultXdr": "AAAAAAAAAGT////wAAAAAA==",
                    }))
                    .unwrap(),
                );
                store.settle_chain_answer(&profile, Some(&receipts), &res, &answer)
            } else {
                store.release_on_evidence(
                    &profile,
                    Some(&receipts),
                    &res,
                    ReleaseEvidence::SequenceConsumed,
                )
            }
        };
        let failed = settle().unwrap();
        let mut report = ReconcileReport::default();
        record_settlement(&mut report, &res, failed);
        assert_eq!(report.receipt_write_failed, 1);
        assert_eq!(
            report.receipt_write_error.as_deref(),
            Some(ReceiptStoreError::WriterLocked.to_string().as_str())
        );
        assert_eq!(report.released, 0);
        assert_eq!(report.confirmed, 0);
        assert_eq!(
            store.pending_reservations(&profile).unwrap(),
            *std::slice::from_ref(&res)
        );
        assert_eq!(receipts.get(&res.id).unwrap(), before);
        drop(held);
        assert!(!matches!(
            settle().unwrap(),
            Settlement::ReceiptWriteFailed { .. }
        ));
        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let receipt = receipts.get(&res.id).unwrap().unwrap();
        match status {
            Some("SUCCESS") => assert_eq!(receipt.status, ReceiptStatus::Success),
            Some(_) => assert!(matches!(receipt.status, ReceiptStatus::Failed { .. })),
            None => assert_eq!(
                receipt.release_code,
                Some(ReleaseEvidence::SequenceConsumed)
            ),
        }
    }

    /// An evidence release persists its receipt before releasing the reservation.
    #[test]
    #[serial]
    fn evidence_waits_for_receipt_persistence() {
        assert_settlement_waits_for_receipt(None, false);
    }

    /// Both definitive answers persist their receipts before settling the window.
    #[test]
    #[serial]
    fn chain_answers_wait_for_receipt_persistence() {
        assert_settlement_waits_for_receipt(Some("SUCCESS"), false);
        assert_settlement_waits_for_receipt(Some("FAILED"), false);
    }

    /// A missing receipt is restored durably before its reservation is released.
    #[test]
    #[serial]
    fn evidence_waits_for_a_missing_receipt_restore() {
        assert_settlement_waits_for_receipt(None, true);
    }

    /// Clearing a receipt preserves evidence but refuses another evidence release.
    #[test]
    #[serial]
    fn a_cleared_receipt_with_evidence_keeps_its_pending_reservation() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "release-cleared");
        let store = PersistedWindowStore::at_path(dir.path().join("release.window"));
        let receipts = ReceiptStore::open_at(dir.path(), "release-cleared").unwrap();
        let now = now_ms().unwrap();
        let res = reservation(&"7d".repeat(32), "GSOURCE", 7, now);
        store
            .record_pending(
                &profile,
                &[entry(key("release-cleared", "native", 86_400), now, 500)],
                &res,
            )
            .unwrap();
        receipts
            .try_begin(&res.id, &res.tx_hash, &res.source, 7, 0, 100)
            .unwrap();
        receipts
            .finalize_released(&res.id, ReleaseEvidence::TimeBoundPassed)
            .unwrap();
        let cleared = receipts.clear_by_operator(&res.id).unwrap();
        assert_eq!(cleared.release_code, Some(ReleaseEvidence::TimeBoundPassed));
        assert_eq!(
            store
                .release_on_evidence(
                    &profile,
                    Some(&receipts),
                    &res,
                    ReleaseEvidence::SequenceConsumed,
                )
                .unwrap(),
            Settlement::ReceiptWriteFailed {
                error: ReceiptStoreError::InvalidTransition {
                    from: "cleared_by_operator",
                    to: "ambiguous",
                }
                .to_string(),
            }
        );
        assert_eq!(receipts.get(&res.id).unwrap().unwrap(), cleared);
        assert_eq!(store.pending_reservations(&profile).unwrap(), vec![res]);
    }

    /// A durable evidence checkpoint needs no receipt write when its window retries.
    #[test]
    #[serial]
    fn a_checkpointed_release_keeps_its_evidence_without_rewriting() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "release-retry");
        let store = PersistedWindowStore::at_path(dir.path().join("release.window"));
        let receipts = ReceiptStore::open_at(dir.path(), "release-retry").unwrap();
        let now = now_ms().unwrap();
        let res = reservation(&"7c".repeat(32), "GSOURCE", 7, now);
        store
            .record_pending(
                &profile,
                &[entry(key("release-retry", "native", 86_400), now, 500)],
                &res,
            )
            .unwrap();
        receipts
            .try_begin(&res.id, &res.tx_hash, &res.source, 7, 0, 100)
            .unwrap();
        let held = WindowStoreLock::acquire(&store.lock_path()).unwrap();
        assert!(matches!(
            store.release_on_evidence(
                &profile,
                Some(&receipts),
                &res,
                ReleaseEvidence::TimeBoundPassed
            ),
            Err(WindowStoreError::WriterLocked)
        ));
        drop(held);
        let checkpoint = receipts.get(&res.id).unwrap().unwrap();
        let known = HashMap::from([(
            res.id.clone(),
            (checkpoint.status.clone(), checkpoint.release_code),
        )]);
        assert!(!outcome_already_unknown(&known, &res.id));
        let held_receipt = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(receipts.lock_file_path().unwrap())
            .unwrap();
        held_receipt.try_lock().unwrap();
        assert_eq!(
            store
                .release_on_evidence(
                    &profile,
                    Some(&receipts),
                    &res,
                    ReleaseEvidence::SequenceConsumed
                )
                .unwrap(),
            Settlement::ReleasedOnEvidence {
                evidence: ReleaseEvidence::TimeBoundPassed
            }
        );
        assert_eq!(receipts.get(&res.id).unwrap().unwrap(), checkpoint);
        assert!(store.pending_reservations(&profile).unwrap().is_empty());
    }

    // ── wire versions ───────────────────────────────────────────────────

    /// The HMAC key the version 3 fixtures are signed under.
    const FIXTURE_KEY: [u8; 32] = [0x11; 32];

    /// A compact version 3 file: a current snapshot at generation 7 with a
    /// confirmed record at the largest amount, a pending reservation marked
    /// operator-required, and a rate-limit bucket. The tag was computed
    /// independently of this code.
    const V3_CURRENT_TAG: &str = "8645b5289a347ee41607c7cf139e9be8d3f174d4e5783db4ce4e6ab298f54ad4";
    const V3_CURRENT_BODY: &str = r#"{"version":3,"generation":7,"entries":[{"scope_specificity":1,"bucket":"native","window_secs":86400,"records":[{"ts_ms":1700000000000,"amount":"170141183460469231731687303715884105727","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false},{"ts_ms":1700000001000,"amount":"25","id":"abababababababababababababababababababababababababababababababab","status":"pending","tx_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":42,"max_time":1700000300,"pending_since_ms":1700000001000,"submission_ledger":512,"operator_required":true}]},{"scope_specificity":3,"bucket":"rate_limit","window_secs":60,"records":[{"ts_ms":1700000002000,"amount":"1","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false}]}]}"#;

    /// The same snapshot with a prepared successor at generation 8 that
    /// released the pending reservation.
    const V3_PREPARED_TAG: &str =
        "9692cca26f07f67d3f61be6ccf8981b40bbd6d4d471c3e0bce1582dfa65d7642";
    const V3_PREPARED_BODY: &str = r#"{"version":3,"generation":7,"entries":[{"scope_specificity":1,"bucket":"native","window_secs":86400,"records":[{"ts_ms":1700000000000,"amount":"170141183460469231731687303715884105727","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false},{"ts_ms":1700000001000,"amount":"25","id":"abababababababababababababababababababababababababababababababab","status":"pending","tx_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","source":"GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM","sequence":42,"max_time":1700000300,"pending_since_ms":1700000001000,"submission_ledger":512,"operator_required":true}]},{"scope_specificity":3,"bucket":"rate_limit","window_secs":60,"records":[{"ts_ms":1700000002000,"amount":"1","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false}]}],"prepared":{"version":3,"generation":8,"entries":[{"scope_specificity":1,"bucket":"native","window_secs":86400,"records":[{"ts_ms":1700000000000,"amount":"170141183460469231731687303715884105727","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false}]},{"scope_specificity":3,"bucket":"rate_limit","window_secs":60,"records":[{"ts_ms":1700000002000,"amount":"1","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false}]}]}}"#;

    fn fixture_bytes(tag: &str, body: &str) -> Vec<u8> {
        let mut bytes = stellar_agent_core::hex::decode_hex32(tag).unwrap().to_vec();
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    /// The compact version 3 files read, select version 3, and serialise back
    /// to the same bytes, the current and the prepared container alike.
    #[test]
    fn a_compact_version_3_file_round_trips_byte_for_byte() {
        let dir = TempDir::new().unwrap();
        let store = PersistedWindowStore::at_path(dir.path().join("fixture.window"));
        for (tag, body) in [
            (V3_CURRENT_TAG, V3_CURRENT_BODY),
            (V3_PREPARED_TAG, V3_PREPARED_BODY),
        ] {
            let bytes = fixture_bytes(tag, body);
            let wire = store.verify_with_key(&FIXTURE_KEY, &bytes).unwrap();
            assert_eq!((wire.version, wire.generation), (3, 7));
            assert_eq!(select_wire_version(&wire), WIRE_VERSION_COMPACT);
            if let Some(prepared) = &wire.prepared {
                assert_eq!((prepared.version, prepared.generation), (3, 8));
                assert_eq!(select_wire_version(prepared), WIRE_VERSION_COMPACT);
            }
            store.write_atomic(&FIXTURE_KEY, &wire).unwrap();
            assert_eq!(fs::read(&store.path).unwrap(), bytes);
        }
        let current = store
            .verify_with_key(
                &FIXTURE_KEY,
                &fixture_bytes(V3_CURRENT_TAG, V3_CURRENT_BODY),
            )
            .unwrap();
        let mut container = store
            .verify_with_key(
                &FIXTURE_KEY,
                &fixture_bytes(V3_PREPARED_TAG, V3_PREPARED_BODY),
            )
            .unwrap();
        container.prepared = None;
        assert_eq!(
            body_digest(&current).unwrap(),
            body_digest(&container).unwrap(),
            "a prepared successor leaves the current commitment unchanged"
        );
    }

    /// A version 4 file whose history is empty is read; the writer selects
    /// version 3 for it.
    #[test]
    #[serial]
    fn a_version_4_file_with_an_empty_history_is_read() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = test_profile(dir.path(), "v4-empty");
        let store = PersistedWindowStore::at_path(dir.path().join("v4-empty.window"));
        let k = key("v4-empty", "native", 86_400);
        let now = now_ms().unwrap();
        store
            .record_and_persist(&profile, &[entry(k.clone(), now, 3)])
            .unwrap();
        rewrite_body_version(&store, &profile, 4);
        let memory = PolicyStateStore::new();
        store.load_into("v4-empty", &profile, &memory).unwrap();
        assert_eq!(memory.query_window(&k, now).unwrap(), (3, 1));
        store
            .record_and_persist(&profile, &[entry(k, now, 1)])
            .unwrap();
        assert_eq!(
            store
                .read_for_inspection(&profile)
                .unwrap()
                .unwrap()
                .version,
            3
        );
    }

    /// A settled authorization record, so a snapshot carries history.
    fn settled_authorization(n: u8) -> ledger::WireAuthorization {
        let binding = ledger::DomainBinding::Soroban {
            intent_digest: [n; 32],
        };
        ledger::WireAuthorization {
            id: crate::mainnet::AuthorizationId::from_bytes([n; 32]),
            profile: "versions".to_owned(),
            chain: stellar_agent_core::profile::caip2::Caip2::Mainnet,
            domain: crate::mainnet::AuthorizationDomain::Soroban,
            consumer: crate::mainnet::MainnetConsumer::X402Create,
            content_digest: binding.content_digest(),
            binding,
            state: ledger::AuthorizationState::Expired,
            minted_ms: 1,
            expires_ms: 2,
            settled_ms: Some(now_ms().unwrap()),
            policy_sequence: 1,
            policy_digest: [1; 32],
            approval_nonce: format!("versions-{n}"),
            approval_expires_ms: 2,
            bindings_digest: [2; 32],
            entries_digest: [3; 32],
            reservation: None,
            parent: None,
            consumption: None,
            invalidation: None,
        }
    }

    /// Every supported pair of a current and a prepared snapshot version is
    /// read on both sides of the commit point: before the counter commits the
    /// successor, the current snapshot wins; after, the successor does, also
    /// when its compaction never happened. A commitment naming another body
    /// refuses, and the next write selects its version from its content.
    #[test]
    #[serial]
    fn every_prepared_version_pair_survives_both_sides_of_the_commit_point() {
        for (current_version, prepared_version) in [
            (1, 3),
            (2, 3),
            (1, 4),
            (2, 4),
            (3, 3),
            (3, 4),
            (4, 4),
            (4, 3),
        ] {
            let pair = format!("{current_version}->{prepared_version}");
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let profile = test_profile(dir.path(), "versions");
            let store = PersistedWindowStore::at_path(dir.path().join("versions.window"));
            let k = key("versions", "native", 86_400);
            let now = now_ms().unwrap();
            store
                .record_and_persist(&profile, &[entry(k.clone(), now, 10)])
                .unwrap();
            let hmac_key =
                crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
            let gen_entry = generation_entry_ref(&profile);
            match current_version {
                1 | 2 => rewrite_body_version(&store, &profile, current_version),
                _ => {
                    let mut wire = store.read_for_inspection(&profile).unwrap().unwrap();
                    wire.version = current_version;
                    if current_version == 4 {
                        wire.authorizations.push(settled_authorization(1));
                    }
                    store.write_atomic(&hmac_key, &wire).unwrap();
                    write_generation(&gen_entry, &wire).unwrap();
                }
            }
            let current = store.read_for_inspection(&profile).unwrap().unwrap();
            assert_eq!(current.version, current_version, "{pair}");

            let mut next = current.clone();
            next.generation += 1;
            next.version = prepared_version;
            next.entries[0].records.push(WireRecord {
                ts_ms: now,
                amount: 5,
                ..WireRecord::confirmed_defaults()
            });
            if prepared_version == 4 {
                next.authorizations.push(settled_authorization(2));
            } else {
                next.authorizations.clear();
            }
            let mut container = current.clone();
            container.prepared = Some(Box::new(next.clone()));
            store.write_atomic(&hmac_key, &container).unwrap();

            let before_commit = store.read_for_inspection(&profile).unwrap().unwrap();
            assert_eq!(
                (before_commit.version, before_commit.generation),
                (current_version, current.generation),
                "{pair}: the current snapshot wins before the commit"
            );
            let memory = PolicyStateStore::new();
            store.load_into("versions", &profile, &memory).unwrap();
            assert_eq!(memory.query_window(&k, now).unwrap(), (10, 1), "{pair}");

            let mut other = next.clone();
            other.entries[0].records[0].amount = 11;
            write_generation(&gen_entry, &other).unwrap();
            assert!(
                matches!(
                    store.read_for_inspection(&profile),
                    Err(WindowStoreError::GenerationMismatch)
                ),
                "{pair}: a commitment of another body refuses"
            );

            write_generation(&gen_entry, &next).unwrap();
            let after_commit = store.read_for_inspection(&profile).unwrap().unwrap();
            assert_eq!(
                (after_commit.version, after_commit.generation),
                (prepared_version, next.generation),
                "{pair}: the successor wins after the commit"
            );
            assert_eq!(after_commit.authorizations, next.authorizations, "{pair}");
            let memory = PolicyStateStore::new();
            store.load_into("versions", &profile, &memory).unwrap();
            assert_eq!(memory.query_window(&k, now).unwrap(), (15, 2), "{pair}");

            store
                .record_and_persist(&profile, &[entry(k.clone(), now, 1)])
                .unwrap();
            let written = store.read_for_inspection(&profile).unwrap().unwrap();
            assert_eq!(
                written.version,
                if prepared_version == 4 { 4 } else { 3 },
                "{pair}: the next write selects its version from its content"
            );
        }
    }

    /// A successor above the versions this build writes, or a nested
    /// candidate, refuses selection.
    #[test]
    fn a_successor_outside_the_written_versions_refuses_selection() {
        let current = WireFile {
            version: 3,
            generation: 4,
            ..WireFile::default()
        };
        let counter = || {
            Some(GenerationState {
                generation: 4,
                body_sha256: None,
            })
        };
        for version in [1, 2, 5] {
            let mut container = current.clone();
            container.prepared = Some(Box::new(WireFile {
                version,
                generation: 5,
                ..WireFile::default()
            }));
            assert!(
                matches!(
                    select_generation(container, counter()),
                    Err(WindowStoreError::GenerationMismatch)
                ),
                "prepared version {version}"
            );
        }
        let mut nested = current.clone();
        nested.prepared = Some(Box::new(WireFile {
            version: 4,
            generation: 5,
            prepared: Some(Box::new(WireFile {
                version: 3,
                generation: 6,
                ..WireFile::default()
            })),
            ..WireFile::default()
        }));
        assert!(matches!(
            select_generation(nested, counter()),
            Err(WindowStoreError::GenerationMismatch)
        ));
        let mut accepted = current;
        accepted.prepared = Some(Box::new(WireFile {
            version: 4,
            generation: 5,
            ..WireFile::default()
        }));
        assert_eq!(
            select_generation(accepted, counter()).unwrap().generation,
            4
        );
    }

    // ── mainnet rules ───────────────────────────────────────────────────

    fn mainnet_test_profile(dir: &Path, name: &str) -> Profile {
        let mut p = Profile::builder_mainnet_named(
            name,
            "https://rpc.example",
            "stellar-agent-signer-rules",
            "acct",
            "n-svc",
            "n-acct",
        )
        .build();
        p.policy_window_state_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key(
                name,
            );
        p.audit_log_path = dir.join("audit.jsonl");
        p
    }

    /// Leaves the committed store of `profile` in the state `defect` names.
    fn break_store(store: &PersistedWindowStore, profile: &Profile, defect: StateDefect) {
        let window_key = &profile.policy_window_state_key_id;
        match defect {
            StateDefect::MissingFileWithGeneration => fs::remove_file(&store.path).unwrap(),
            StateDefect::MissingKey => {
                keyring_core::Entry::new(&window_key.service, &window_key.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            StateDefect::BadKey => put_raw(window_key, "AA"),
            StateDefect::Malformed => {
                let key = crate::keyring::load_hmac_key_32(window_key).unwrap();
                let body = b"{\"version\":3,\"generation\":1,\"entries\":7}";
                let tag = compute_tag(key.as_slice(), body).unwrap();
                store.write_atomic_raw(&tag, body).unwrap();
            }
            StateDefect::HmacInvalid => {
                let mut bytes = fs::read(&store.path).unwrap();
                let last = bytes.len() - 2;
                bytes[last] ^= 0x01;
                fs::write(&store.path, bytes).unwrap();
            }
            StateDefect::GenerationMismatch => {
                let gen_entry = generation_entry_ref(profile);
                keyring_core::Entry::new(&gen_entry.service, &gen_entry.account)
                    .unwrap()
                    .set_password("9")
                    .unwrap();
            }
        }
    }

    const DEFECTS: [StateDefect; 6] = [
        StateDefect::MissingFileWithGeneration,
        StateDefect::MissingKey,
        StateDefect::BadKey,
        StateDefect::Malformed,
        StateDefect::HmacInvalid,
        StateDefect::GenerationMismatch,
    ];

    /// A committed store of `profile` in the state `defect` names.
    fn broken(
        name: &str,
        mainnet: bool,
        defect: StateDefect,
    ) -> (TempDir, Profile, PersistedWindowStore) {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = if mainnet {
            mainnet_test_profile(dir.path(), name)
        } else {
            test_profile(dir.path(), name)
        };
        let store = PersistedWindowStore::at_path(dir.path().join(format!("{name}.window")));
        store
            .record_and_persist(
                &profile,
                &[entry(key(name, "native", 86_400), now_ms().unwrap(), 2)],
            )
            .unwrap();
        break_store(&store, &profile, defect);
        (dir, profile, store)
    }

    /// Under the mainnet rules every unverifiable state refuses with the
    /// defect it names, on every read and every write; no write replaces a
    /// missing key or a missing file.
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial]
    fn each_unverifiable_mainnet_state_refuses_naming_its_defect() {
        for defect in DEFECTS {
            let (_dir, profile, store) = broken("rules", true, defect);
            let unverifiable = |result: Result<(), WindowStoreError>, what: &str| {
                assert!(
                    matches!(
                        &result,
                        Err(WindowStoreError::MainnetStateUnverifiable { defect: found })
                            if *found == defect
                    ),
                    "{what} under {defect}: {result:?}"
                );
            };
            unverifiable(
                store.load_into("rules", &profile, &PolicyStateStore::new()),
                "load_into",
            );
            unverifiable(
                store.pending_reservations(&profile).map(|_| ()),
                "pending_reservations",
            );
            let key_before = get_raw(&profile.policy_window_state_key_id);
            unverifiable(
                store
                    .record_and_persist(
                        &profile,
                        &[entry(key("rules", "native", 86_400), now_ms().unwrap(), 1)],
                    )
                    .map(|_| ()),
                "record_and_persist",
            );
            assert_eq!(
                get_raw(&profile.policy_window_state_key_id),
                key_before,
                "{defect}: a refused write mints no key"
            );
            if defect == StateDefect::MissingFileWithGeneration {
                assert!(!store.path.exists(), "a refused write creates no file");
            }
        }
    }

    /// Without the mainnet rules the same states keep their generic errors.
    #[test]
    #[serial]
    fn without_the_mainnet_rules_the_generic_errors_stand() {
        let networks: &[bool] = if cfg!(feature = "mainnet-write") {
            &[false]
        } else {
            &[false, true]
        };
        for &mainnet in networks {
            for defect in DEFECTS {
                let (_dir, profile, store) = broken("generic", mainnet, defect);
                let result = store.load_into("generic", &profile, &PolicyStateStore::new());
                let generic = match defect {
                    StateDefect::MissingFileWithGeneration | StateDefect::GenerationMismatch => {
                        matches!(result, Err(WindowStoreError::GenerationMismatch))
                    }
                    StateDefect::MissingKey | StateDefect::BadKey => {
                        matches!(result, Err(WindowStoreError::Keyring { .. }))
                    }
                    StateDefect::Malformed => {
                        matches!(result, Err(WindowStoreError::Invalid { .. }))
                    }
                    StateDefect::HmacInvalid => {
                        matches!(result, Err(WindowStoreError::HmacMismatch))
                    }
                };
                assert!(generic, "mainnet={mainnet} {defect}: {result:?}");
            }
        }
    }

    /// A mainnet store with no file and no committed generation is a genuine
    /// first run under every rule set.
    #[test]
    #[serial]
    fn a_genuine_mainnet_first_run_reads_empty_and_writes() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = mainnet_test_profile(dir.path(), "first");
        let store = PersistedWindowStore::at_path(dir.path().join("first.window"));
        store
            .load_into("first", &profile, &PolicyStateStore::new())
            .unwrap();
        assert!(store.pending_reservations(&profile).unwrap().is_empty());
        let outcome = store
            .record_and_persist(
                &profile,
                &[entry(key("first", "native", 86_400), now_ms().unwrap(), 1)],
            )
            .unwrap();
        assert!(outcome.newly_minted);
    }

    /// The reset of an unverifiable mainnet store hands the recorder the
    /// defect, before anything changes, and then recovers; under the other
    /// rules the recorder sees no defect.
    #[test]
    #[serial]
    fn an_unverifiable_reset_passes_its_defect_to_the_recorder() {
        for mainnet in [true, false] {
            for defect in DEFECTS {
                let (_dir, profile, store) = broken("unverifiable", mainnet, defect);
                let before = fs::read(&store.path).ok();
                let mut seen = None;
                store
                    .reset(&profile, now_ms().unwrap(), |record| {
                        assert_eq!(fs::read(&store.path).ok(), before);
                        seen = Some(record.defect);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                let expected = (mainnet && cfg!(feature = "mainnet-write")).then_some(defect);
                assert_eq!(seen, Some(expected), "mainnet={mainnet} {defect}");
                store
                    .load_into("unverifiable", &profile, &PolicyStateStore::new())
                    .unwrap();
            }
        }
    }

    /// A verifiable mainnet store with an effective open authorization
    /// refuses the reset with nothing changed; once it expires, the reset
    /// proceeds. Without the mainnet rules the open record does not block.
    #[test]
    #[serial]
    fn a_reset_refuses_while_a_mainnet_authorization_is_open() {
        for mainnet in [true, false] {
            keyring_mock::install().unwrap();
            let dir = TempDir::new().unwrap();
            let profile = if mainnet {
                mainnet_test_profile(dir.path(), "open-reset")
            } else {
                test_profile(dir.path(), "open-reset")
            };
            let store = PersistedWindowStore::at_path(dir.path().join("open-reset.window"));
            let now = now_ms().unwrap();
            store
                .record_and_persist(
                    &profile,
                    &[entry(key("open-reset", "native", 86_400), now, 1)],
                )
                .unwrap();
            let hmac_key =
                crate::keyring::load_hmac_key_32(&profile.policy_window_state_key_id).unwrap();
            let gen_entry = generation_entry_ref(&profile);
            let mut wire = store.read_for_inspection(&profile).unwrap().unwrap();
            let mut open = settled_authorization(1);
            open.state = ledger::AuthorizationState::Open;
            open.settled_ms = None;
            open.minted_ms = now;
            open.expires_ms = now + 60_000;
            wire.authorizations.push(open);
            wire.version = 4;
            store.write_atomic(&hmac_key, &wire).unwrap();
            write_generation(&gen_entry, &wire).unwrap();
            let bytes = fs::read(&store.path).unwrap();
            let counter = get_raw(&gen_entry);

            let _clock = crate::mainnet::clock::set_now_ms_for_test(now);
            let result = store.reset(&profile, now, |_| Ok::<_, ()>(()));
            if mainnet && cfg!(feature = "mainnet-write") {
                #[cfg(feature = "mainnet-write")]
                assert!(matches!(
                    result,
                    Err(ResetError::Store {
                        error: WindowStoreError::OpenAuthorizations { open: 1 },
                        minted: false,
                    })
                ));
                assert_eq!(fs::read(&store.path).unwrap(), bytes);
                assert_eq!(get_raw(&gen_entry), counter);
                _clock.set(now + 60_000);
                store
                    .reset(&profile, now + 60_000, |_| Ok::<_, ()>(()))
                    .unwrap();
            } else {
                result.unwrap();
            }
            assert!(
                store
                    .read_for_inspection(&profile)
                    .unwrap()
                    .unwrap()
                    .authorizations
                    .is_empty()
            );
        }
    }

    /// An authenticated file of a newer version is refused, never reset, on
    /// every chain.
    #[test]
    #[serial]
    fn newer_files_with_unknown_fields_cannot_be_reset() {
        use stellar_agent_core::profile::caip2::Caip2;
        for chain in [Caip2::Testnet, Caip2::Mainnet] {
            let mut f = ResetFixture::new();
            f.profile.chain_id = chain;
            f.seal(&reset_wire());
            let key =
                crate::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id).unwrap();
            let body = br#"{"version":5,"future_authorities":[{"open":true}],"prepared":"future representation"}"#;
            f.store
                .write_atomic_raw(&compute_tag(key.as_ref(), body).unwrap(), body)
                .unwrap();
            let before = fs::read(f.store.path()).unwrap();
            assert!(
                matches!(
                    f.store.verify_with_key(&key, &before),
                    Err(WindowStoreError::UnsupportedVersion { version: 5, max: 4 })
                ),
                "{chain:?}"
            );
            assert_eq!(
                defect_of(
                    &WindowStoreError::UnsupportedVersion { version: 5, max: 4 },
                    false
                ),
                None
            );
            let called = std::cell::Cell::new(false);
            let result = f.store.reset(&f.profile, 100_000, |_| -> Result<(), ()> {
                called.set(true);
                Ok(())
            });
            assert!(
                matches!(
                    result,
                    Err(ResetError::Store {
                        error: WindowStoreError::UnsupportedVersion { version: 5, max: 4 },
                        minted: false,
                    })
                ),
                "{chain:?}: {result:?}"
            );
            assert!(!called.get(), "{chain:?}");
            assert_eq!(fs::read(f.store.path()).unwrap(), before, "{chain:?}");
        }
    }

    #[test]
    #[serial]
    fn a_supported_version_with_broken_invariants_is_malformed() {
        let f = ResetFixture::new();
        f.seal(&reset_wire());
        let key = crate::keyring::load_hmac_key_32(&f.profile.policy_window_state_key_id).unwrap();
        let mut invalid = reset_wire();
        invalid.version = 4;
        let mut auth = settled_authorization(1);
        auth.settled_ms = None;
        invalid.authorizations.push(auth);
        let body = serde_json::to_vec(&invalid).unwrap();
        f.store
            .write_atomic_raw(&compute_tag(key.as_ref(), &body).unwrap(), &body)
            .unwrap();
        let error = f
            .store
            .verify_with_key(&key, &fs::read(f.store.path()).unwrap())
            .unwrap_err();
        assert_eq!(defect_of(&error, false), Some(StateDefect::Malformed));
    }
}
