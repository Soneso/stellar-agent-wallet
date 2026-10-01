//! Audit-log payload value types for signer-set state tracking.
//!
//! Defines [`SignerPubkey`], [`ObservedSignerSet`], [`SignerSetStatePayload`],
//! and [`BaselineReason`] — the value types shared between the audit-log
//! substrate (this module) and the `SignersManager` smart-account wrappers.
//!
//! The version-2 snapshot types [`SignerIdentityV2`], [`SignerEntryV2`],
//! [`ThresholdObservation`] and [`SignerSetSnapshotV2`] record every signer's
//! full identity and a threshold observation that may be absent. The reader
//! returns either version as a [`SignerSetView`] inside a
//! [`SignerSetViewPayload`].
//!
//! # Type-placement rationale
//!
//! These value types live in `stellar-agent-core::audit_log::signer_set` so
//! that the audit-log substrate is self-contained.  Placing them in the
//! smart-account crate would invert the dependency direction:
//! `stellar-agent-core` must not depend on `stellar-agent-smart-account`.
//! Smart-account-specific wrappers (`FrozenChainStateTuple`, `SaError`
//! variants, etc.) remain in the smart-account crate.
//!
//! # Digest domain separator
//!
//! [`DOMAIN_SA_SIGNER_SET_V1`] is the first 16 bytes of
//! `SHA-256("sa.signer_set.v1.divergence")`. It is used as a domain
//! separator when computing the `(signer_ids, signer_pubkeys, threshold)`
//! digest fields carried by the `EventKind` signer-set variants.
//!
//! [`DOMAIN_SA_SIGNER_SET_V2`] is the first 16 bytes of
//! `SHA-256("sa.signer_set.v2.divergence")` and separates the version-2
//! snapshot digest computed by [`compute_signer_set_digest_v2`].
//! [`DOMAIN_SA_ACCOUNT_ID_V1`] is the first 16 bytes of
//! `SHA-256("sa.account_id.v1")` and separates the account digest computed
//! by [`account_digest`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Canonical-body error ──────────────────────────────────────────────────────

/// Error type for [`signer_pubkey_canonical_body`], [`canonical_scaddress`],
/// [`compute_signer_set_digest`], [`SignerSetSnapshotV2::validate`] and
/// [`compute_signer_set_digest_v2`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerSetCanonicalBodyError {
    /// The `External` variant carries an invalid C-strkey in `verifier_contract`.
    ///
    /// This indicates a data-integrity problem in the stored [`SignerPubkey::External`]
    /// value. Callers that surface this error should propagate it as an audit-log
    /// integrity error.
    #[error("invalid External verifier_contract C-strkey '{strkey}': {source}")]
    InvalidVerifierContract {
        /// The C-strkey that failed to decode.
        strkey: String,
        /// The underlying strkey decode error.
        #[source]
        source: stellar_strkey::DecodeError,
    },

    /// The [`ObservedSignerSet`] fields have mismatched lengths or an inconsistent
    /// `signer_count`.
    ///
    /// Indicates a data-integrity problem in the stored signer-set state: the
    /// `signer_ids`, `signer_pubkeys`, and `signer_count` fields must be mutually
    /// consistent. Callers that surface this error should propagate it as an
    /// audit-log integrity error.
    #[error("malformed ObservedSignerSet: {reason}")]
    MalformedObservedSignerSet {
        /// Human-readable description of the inconsistency.
        reason: &'static str,
    },

    /// A [`SignerSetSnapshotV2`] breaks one of its structural rules: signer
    /// ids strictly ascending, an `External` identity with non-empty key
    /// data, and at most `u32::MAX` entries.
    ///
    /// Raised by [`SignerSetSnapshotV2::validate`] and by
    /// [`compute_signer_set_digest_v2`], which validates before hashing so a
    /// digest always describes a well-formed snapshot. A snapshot read from the
    /// audit log that fails this check is an audit-log integrity problem.
    #[error("malformed SignerSetSnapshotV2: {reason}")]
    MalformedSnapshotV2 {
        /// Human-readable description of the broken rule.
        reason: &'static str,
    },
}

// ── Domain separator ──────────────────────────────────────────────────────────

/// Domain separator for `(signer_ids, signer_pubkeys, threshold)` digests.
///
/// The first 16 bytes of `SHA-256("sa.signer_set.v1.divergence")`.
/// Used by the `expected_signer_set_digest` / `observed_signer_set_digest`
/// fields of the [`super::schema::EventKind`] signer-set variants.
///
/// Including a domain separator prevents cross-context preimage collisions: a
/// digest computed for signer-set comparison cannot be reused in any other
/// protocol context.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::DOMAIN_SA_SIGNER_SET_V1;
///
/// // Verify at test time that the constant equals the first 16 bytes of
/// // SHA-256("sa.signer_set.v1.divergence").
/// use sha2::{Digest, Sha256};
/// let full = Sha256::digest(b"sa.signer_set.v1.divergence");
/// assert_eq!(DOMAIN_SA_SIGNER_SET_V1, full[..16]);
/// assert_eq!(DOMAIN_SA_SIGNER_SET_V1.len(), 16);
/// ```
pub const DOMAIN_SA_SIGNER_SET_V1: [u8; 16] = {
    // SHA-256("sa.signer_set.v1.divergence") pre-computed bytes (first 16).
    // Verified by the doc-test above and the unit test below.
    //
    // Full digest: `echo -n "sa.signer_set.v1.divergence" | sha256sum`
    //   => 66c33500e30500ccf5d292eea83b94893776f1a54bfa78cf5a1d743394a3e315
    [
        0x66, 0xc3, 0x35, 0x00, 0xe3, 0x05, 0x00, 0xcc, 0xf5, 0xd2, 0x92, 0xee, 0xa8, 0x3b, 0x94,
        0x89,
    ]
};

// ── SignerPubkey ──────────────────────────────────────────────────────────────

/// Public-key envelope for audit-log signer-set payloads.
///
/// Mirrors the OZ `Signer` storage enum with truncation for `External` and
/// `WebAuthn` variants for forensic correlation.  Lossy first-16 comparison is
/// acceptable for divergence detection because `signer_id: u32` is also part
/// of the comparison tuple — the combination `(signer_id, pubkey_first16)` is
/// sufficient to detect a signer-set replacement without leaking full credential
/// data to the audit log.
///
/// # Debug discipline
///
/// `Debug` is manually implemented to emit only first-8-byte hex projections
/// of any key material — never the full 32-byte Ed25519 pubkey, the full 16-byte
/// `key_data_first16`, or the full 16-byte `credential_id_first16`.  This
/// prevents key material from appearing in debug traces or log output.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::SignerPubkey;
///
/// let pk = SignerPubkey::Ed25519 { pubkey: [0u8; 32] };
/// let json = serde_json::to_string(&pk).unwrap();
/// assert!(json.contains("ed25519"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignerPubkey {
    /// Ed25519 signer — carries the full 32-byte public key.
    Ed25519 {
        /// The full 32-byte Ed25519 public key.
        pubkey: [u8; 32],
    },

    /// External (custom verifier contract) signer.
    ///
    /// `key_data` is truncated to the first 16 bytes for audit-log storage
    /// (lossy comparison rationale above).
    External {
        /// The verifier contract C-strkey address.
        verifier_contract: String,
        /// First 16 bytes of the signer's `key_data` blob.
        ///
        /// Truncated to bound audit-log size and avoid storing unbounded
        /// external verifier payloads. Sufficient for forensic correlation
        /// when combined with `signer_id`.
        key_data_first16: [u8; 16],
    },

    /// WebAuthn passkey signer.
    ///
    /// Corresponds to OZ `Signer::External` with the WebAuthn verifier
    /// contract address and a `key_data` blob whose first 16 bytes are the
    /// credential_id prefix. Stored separately from `External` for semantic
    /// clarity in audit trail rendering.
    WebAuthn {
        /// First 16 bytes of the WebAuthn credential ID.
        ///
        /// Sufficient for forensic correlation with `signer_id`; full
        /// credential_id is in the passkeys registry (not the audit log).
        credential_id_first16: [u8; 16],
    },
}

// ── SignerPubkey fmt::Debug ───────────────────────────────────────────────────

// Debug must never emit full pubkey/credential bytes — see Debug discipline above.
impl std::fmt::Debug for SignerPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerPubkey::Ed25519 { pubkey } => f
                .debug_struct("SignerPubkey::Ed25519")
                .field("pubkey_first8", &crate::hex::encode(&pubkey[..8]))
                .finish(),
            SignerPubkey::External {
                verifier_contract,
                key_data_first16,
            } => f
                .debug_struct("SignerPubkey::External")
                .field(
                    "verifier_contract_redacted",
                    &crate::observability::redact_strkey_first5_last5(verifier_contract),
                )
                .field(
                    "key_data_first8",
                    &crate::hex::encode(&key_data_first16[..8]),
                )
                .finish(),
            SignerPubkey::WebAuthn {
                credential_id_first16,
            } => f
                .debug_struct("SignerPubkey::WebAuthn")
                .field(
                    "credential_id_first8",
                    &crate::hex::encode(&credential_id_first16[..8]),
                )
                .finish(),
        }
    }
}

// ── signer_pubkey_canonical_body ──────────────────────────────────────────────

/// Produces the 36-byte canonical XDR encoding of a Soroban contract address.
///
/// Layout:
/// ```text
/// [0x00, 0x00, 0x00, 0x01]      ← 4-byte big-endian XDR discriminant for
///                                   SC_ADDRESS_TYPE_CONTRACT = 1
///                                   (Stellar XDR SCAddressType, CONTRACT = 1)
/// [<32 bytes of contract hash>]  ← raw 32-byte hash decoded from the C-strkey
///                                   (same as XDR `Hash` / `ContractId`)
/// ```
///
/// Total: 36 bytes. Used by [`signer_pubkey_canonical_body`] for the `External`
/// variant.
///
/// # Errors
///
/// Returns [`SignerSetCanonicalBodyError::InvalidVerifierContract`] when
/// `c_strkey` is not a valid C-strkey.
pub fn canonical_scaddress(c_strkey: &str) -> Result<Vec<u8>, SignerSetCanonicalBodyError> {
    let contract = stellar_strkey::Contract::from_string(c_strkey).map_err(|e| {
        // Distinguish a G-strkey (Ed25519 account, wrong type) from a malformed
        // C-strkey so callers can surface a more actionable error message.
        // Redact the strkey to first-5-last-5 — the full strkey must not appear
        // in rendered error messages.
        let redacted = crate::observability::redact_strkey_first5_last5(c_strkey);
        let strkey = if c_strkey.starts_with('G') {
            format!("{redacted} (account G-strkey not accepted; expected contract C-strkey)")
        } else {
            redacted
        };
        SignerSetCanonicalBodyError::InvalidVerifierContract { strkey, source: e }
    })?;
    let mut body = Vec::with_capacity(36);
    // 4-byte big-endian XDR discriminant for SC_ADDRESS_TYPE_CONTRACT = 1.
    // Stellar XDR SCAddressType, CONTRACT = 1; big-endian: [0x00, 0x00, 0x00, 0x01].
    body.extend_from_slice(&[0x00u8, 0x00, 0x00, 0x01]);
    // 32-byte contract hash from the decoded strkey (same as XDR `Hash`).
    body.extend_from_slice(&contract.0);
    Ok(body)
}

/// Produces the per-variant canonical byte sequence for signer-set digest inputs.
///
/// | Variant    | Layout                                                           | Bytes |
/// |------------|------------------------------------------------------------------|-------|
/// | `Ed25519`  | `0x01 ‖ pubkey_32`                                              | 33    |
/// | `External` | `0x02 ‖ canonical_scaddress(verifier_contract) ‖ key_data_first16` | 53 |
/// | `WebAuthn` | `0x03 ‖ credential_id_first16`                                   | 17    |
///
/// `canonical_scaddress` for the `External` variant is the 36-byte XDR
/// encoding of `ScAddress::Contract(Hash([u8; 32]))`. See [`canonical_scaddress`]
/// for the byte layout.
///
/// The `External` output is 53 bytes: 1 tag + 36 (`canonical_scaddress`) +
/// 16 (`key_data_first16`). There is no variable-length component.
///
/// # Errors
///
/// Returns [`SignerSetCanonicalBodyError`] when `verifier_contract` is not a
/// valid C-strkey. This signals a data integrity problem in the stored
/// `SignerPubkey::External` value — the verifier_contract field MUST be a
/// well-formed C-strkey when the value is constructed; callers that surface the
/// error should propagate it as an audit-log integrity error.
///
/// `External` `verifier_contract` C-strkey validity is NOT validated at
/// deserialization time (only structural JSON field shapes are checked).
/// The validation happens here, downstream, when the canonical body is computed.
/// Consumers calling this on `ObservedSignerSet` values read from the audit log
/// must handle the `Err` path. See `extract_observed_signer_set` in
/// `reader.rs` for the downstream validation contract.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::{SignerPubkey, signer_pubkey_canonical_body};
///
/// let pk = SignerPubkey::Ed25519 { pubkey: [0u8; 32] };
/// let body = signer_pubkey_canonical_body(&pk).unwrap();
/// assert_eq!(body.len(), 33);
/// assert_eq!(body[0], 0x01);
/// assert_eq!(&body[1..], &[0u8; 32]);
/// ```
pub fn signer_pubkey_canonical_body(
    pubkey: &SignerPubkey,
) -> Result<Vec<u8>, SignerSetCanonicalBodyError> {
    match pubkey {
        SignerPubkey::Ed25519 { pubkey } => {
            let mut body = Vec::with_capacity(33);
            body.push(0x01);
            body.extend_from_slice(pubkey);
            Ok(body)
        }
        SignerPubkey::External {
            verifier_contract,
            key_data_first16,
        } => {
            let sc_addr = canonical_scaddress(verifier_contract)?;
            let mut body = Vec::with_capacity(53);
            body.push(0x02);
            body.extend_from_slice(&sc_addr);
            body.extend_from_slice(key_data_first16);
            Ok(body)
        }
        SignerPubkey::WebAuthn {
            credential_id_first16,
        } => {
            let mut body = Vec::with_capacity(17);
            body.push(0x03);
            body.extend_from_slice(credential_id_first16);
            Ok(body)
        }
    }
}

// ── ObservedSignerSet ─────────────────────────────────────────────────────────

/// The observed state of a smart-account context-rule's signer set.
///
/// Constructed from the most-recent `SaSignerAdded`, `SaSignerRemoved`,
/// `SaThresholdChanged`, or `SaSignerSetBaselined` audit row for a given
/// `(rule_id, smart_account)` pair. Used both as the audit-log payload for
/// reconstruction and as the comparison target in divergence detection.
///
/// The four fields together uniquely identify the signer-set state at a point in
/// time. `signer_ids` and `signer_pubkeys` are parallel slices (index N of
/// `signer_ids` corresponds to index N of `signer_pubkeys`).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::{ObservedSignerSet, SignerPubkey};
///
/// let s = ObservedSignerSet {
///     signer_count: 2,
///     threshold: 2,
///     signer_ids: vec![0, 1],
///     signer_pubkeys: vec![
///         SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
///         SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
///     ],
/// };
/// assert_eq!(s.signer_count, 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSignerSet {
    /// Number of signers in the rule at observation time.
    ///
    /// Must equal `signer_pubkeys.len()` and `signer_ids.len()`.
    pub signer_count: u32,

    /// Threshold for the rule at observation time.
    ///
    /// Invariant: `1 <= threshold <= signer_count`.
    pub threshold: u32,

    /// Signer IDs in declaration order (parallel to `signer_pubkeys`).
    ///
    /// IDs are assigned by the smart-account contract monotonically from 0.
    pub signer_ids: Vec<u32>,

    /// Public-key envelopes in declaration order (parallel to `signer_ids`).
    pub signer_pubkeys: Vec<SignerPubkey>,
}

impl std::fmt::Display for ObservedSignerSet {
    /// Formats the signer-set summary as `count=N threshold=M`.
    ///
    /// Deliberately omits `signer_ids` and `signer_pubkeys` to prevent
    /// Ed25519 key material from appearing in log output or error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "count={} threshold={}",
            self.signer_count, self.threshold
        )
    }
}

// ── SignerSetStatePayload ─────────────────────────────────────────────────────

/// The version-1 state payload; [`SignerSetViewPayload::into_v1`] produces it
/// from a [`super::reader::AuditReader::find_latest_signer_set_view`] result.
///
/// Carries the reconstructed signer-set state AND the SHA-256 of the canonical-
/// encoded audit row it was reconstructed from. The `row_hash` is bound into
/// `FrozenChainStateTuple` by the smart-account layer so the signing call commits
/// to the exact baseline row that was validated — the TOCTOU anchor.
///
/// `row_hash` is the raw 32-byte SHA-256 of the audit row's canonical JSON body
/// (the same body used for the hash-chain computation). It is NOT the chain-link
/// hash (which includes the previous entry hash); it is the body-only digest
/// suitable for out-of-band cross-checking without requiring the full chain.
///
/// # Sealed-field discipline
///
/// Fields are `pub(crate)` to prevent consumers from cloning `row_hash` bytes
/// and forging a binding on a later signing call. Public accessor methods return
/// borrowed references. The only constructor is `SignerSetStatePayload::new`
/// (also `pub(crate)`), keeping construction authority exclusively within the
/// audit-log reader path.
///
/// # Note on `PartialEq`
///
/// Two `SignerSetStatePayload` values are equal if and only if both their
/// `state` and `row_hash` match. This is used in tests to assert that the
/// reader returns the expected payload without consulting the full audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSetStatePayload {
    /// The reconstructed signer-set state from the most-recent audit row.
    pub(crate) state: ObservedSignerSet,

    /// SHA-256 of the canonical JSON body of the source audit row.
    ///
    /// TOCTOU anchor: bound into `FrozenChainStateTuple` by the smart-account
    /// layer so the signing call is committed to the same on-chain view the
    /// reader validated.
    pub(crate) row_hash: [u8; 32],
}

impl SignerSetStatePayload {
    /// Constructs a new `SignerSetStatePayload`.
    ///
    /// `pub(crate)` — only the audit-log reader path constructs these.
    /// Callers receive payloads through the `AuditReader` return value only.
    #[must_use]
    pub(crate) fn new(state: ObservedSignerSet, row_hash: [u8; 32]) -> Self {
        Self { state, row_hash }
    }

    /// Returns a reference to the reconstructed signer-set state.
    #[must_use]
    pub fn state(&self) -> &ObservedSignerSet {
        &self.state
    }

    /// Returns a reference to the SHA-256 row-hash TOCTOU anchor.
    ///
    /// Returns `&[u8; 32]` (borrowed) so a caller cannot persist the hash
    /// beyond the payload's lifetime and forge an anchor binding on a later
    /// signing call.
    #[must_use]
    pub fn row_hash(&self) -> &[u8; 32] {
        &self.row_hash
    }
}

// ── BaselineReason ────────────────────────────────────────────────────────────

/// Reason recorded on a signer-set baseline row.
///
/// Carried by [`super::schema::EventKind::SaSignerSetBaselined`] and
/// [`super::schema::EventKind::SaSignerSetBaselinedV2`]. A baseline row is
/// written only through `SignersManager::emit_baseline` in
/// `stellar-agent-smart-account`; the repository gate
/// `check-no-direct-sasignersetbaselined-emit.sh` enforces that invariant and
/// confines the construction of every reason to the manager's baseline paths.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::BaselineReason;
///
/// let json = serde_json::to_string(&BaselineReason::FirstObservation).unwrap();
/// assert_eq!(json, r#""first_observation""#);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BaselineReason {
    /// The first recorded observation of a rule's signer set.
    ///
    /// Written only through `SignersManager::emit_baseline`, enforced by the
    /// repository gate.
    FirstObservation,

    /// A deliberate re-anchor of a rule's baseline to the observed signer set.
    ///
    /// Written only through `SignersManager::emit_baseline`, enforced by the
    /// repository gate.
    ExplicitRefresh,

    /// The created rule's signer set as read after an install confirmed.
    ///
    /// Written only through `SignersManager::emit_baseline`, enforced by the
    /// repository gate.
    ConfirmedInstall,
}

impl BaselineReason {
    /// Constructs a `FirstObservation` baseline reason.
    ///
    /// `pub` because the construction sites live in
    /// `stellar-agent-smart-account`, a separate compilation unit; the
    /// repository gate `check-no-direct-sasignersetbaselined-emit.sh`, not
    /// Rust visibility, confines it to `SignersManager::list_signers`.
    #[must_use]
    pub fn first_observation() -> Self {
        Self::FirstObservation
    }

    /// Constructs an `ExplicitRefresh` baseline reason.
    ///
    /// `pub` because the construction sites live in
    /// `stellar-agent-smart-account`, a separate compilation unit; the
    /// repository gate `check-no-direct-sasignersetbaselined-emit.sh`, not
    /// Rust visibility, confines it to
    /// `SignersManager::refresh_signer_baseline`.
    #[must_use]
    pub fn explicit_refresh() -> Self {
        Self::ExplicitRefresh
    }

    /// Constructs a `ConfirmedInstall` baseline reason.
    ///
    /// `pub` because the construction sites live in
    /// `stellar-agent-smart-account`, a separate compilation unit; the
    /// repository gate `check-no-direct-sasignersetbaselined-emit.sh`, not
    /// Rust visibility, confines it to
    /// `SignersManager::baseline_confirmed_install`.
    #[must_use]
    pub fn confirmed_install() -> Self {
        Self::ConfirmedInstall
    }
}

// ── compute_signer_set_digest ─────────────────────────────────────────────────

/// Computes the domain-tagged SHA-256 digest over `(signer_ids, signer_pubkeys, threshold)`.
///
/// Digest preimage:
///
/// ```text
/// DOMAIN_SA_SIGNER_SET_V1 (16 bytes)
/// ‖ u32_be(signer_count)
/// ‖ sorted_signer_ids_concat_be         // each id as 4-byte big-endian
/// ‖ u32_be(signer_count)
/// ‖ signer_pubkeys_concat               // each via signer_pubkey_canonical_body
/// ‖ u32_be(threshold)
/// ```
///
/// The canonical length prefix is `u32_be(signer_count)`. After the length-parity
/// guard, `signer_count == sorted_signer_ids.len() == signer_pubkeys.len()`, so
/// all three are equivalent — the implementation uses `signer_count.to_be_bytes()`
/// directly to avoid an `as u32` cast.
///
/// `sorted_signer_ids` is `signer_ids` sorted ascending before serialisation.
/// All integers are big-endian (u32_be). The signer_pubkeys are serialised in the
/// **same index order as the sorted_signer_ids** (not in input order).
///
/// The result is a 32-byte raw SHA-256 digest suitable for display as a
/// first-8-last-8 hex string in audit-log `expected_signer_set_digest` /
/// `observed_signer_set_digest` fields.
///
/// # Errors
///
/// - [`SignerSetCanonicalBodyError::MalformedObservedSignerSet`] — when the
///   `signer_ids`, `signer_pubkeys`, or `signer_count` fields are mutually
///   inconsistent (either `signer_ids.len() != signer_pubkeys.len()` or either
///   length disagrees with `signer_count`). Indicates a data-integrity problem
///   in the stored `ObservedSignerSet` and fires before any pubkey encoding.
/// - [`SignerSetCanonicalBodyError::InvalidVerifierContract`] — when any
///   `SignerPubkey::External` variant carries an invalid `verifier_contract`
///   C-strkey (propagated from [`signer_pubkey_canonical_body`]).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::{
///     ObservedSignerSet, SignerPubkey, compute_signer_set_digest,
/// };
///
/// let s = ObservedSignerSet {
///     signer_count: 1,
///     threshold: 1,
///     signer_ids: vec![0],
///     signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0u8; 32] }],
/// };
/// let digest = compute_signer_set_digest(&s).unwrap();
/// assert_eq!(digest.len(), 32);
/// // Deterministic: same input → same digest.
/// let digest2 = compute_signer_set_digest(&s).unwrap();
/// assert_eq!(digest, digest2);
/// ```
pub fn compute_signer_set_digest(
    s: &ObservedSignerSet,
) -> Result<[u8; 32], SignerSetCanonicalBodyError> {
    // Validate length parity before any indexing.
    // `signer_ids` and `signer_pubkeys` are parallel slices; both must equal
    // `signer_count`. A mismatch indicates a data-integrity problem in the stored
    // `ObservedSignerSet` (truncated read, schema drift, or attacker-controlled
    // deserialization anomaly). Return a typed error rather than panicking (OOB
    // index) or silently producing a digest with a mismatched length-prefix.
    if s.signer_ids.len() != s.signer_pubkeys.len() {
        return Err(SignerSetCanonicalBodyError::MalformedObservedSignerSet {
            reason: "signer_ids.len() != signer_pubkeys.len()",
        });
    }
    if s.signer_pubkeys.len() != s.signer_count as usize {
        return Err(SignerSetCanonicalBodyError::MalformedObservedSignerSet {
            reason: "signer_pubkeys.len() != signer_count",
        });
    }
    // By this point all three lengths are equal to `signer_count`, so
    // `signer_count.to_be_bytes()` is the authoritative u32_be length prefix for
    // both the id-concat and pubkey-concat sections (avoids `len() as u32`
    // truncating casts; `signer_count: u32` is the stored trusted value).

    // Sort signer IDs ascending before serialisation. Derive a sorted index
    // mapping so the corresponding pubkeys are serialised in the same sorted order.
    let mut sorted_indices: Vec<usize> = (0..s.signer_ids.len()).collect();
    sorted_indices.sort_unstable_by_key(|&i| s.signer_ids[i]);

    let mut preimage: Vec<u8> = Vec::new();

    // DOMAIN_SA_SIGNER_SET_V1 (16 bytes)
    preimage.extend_from_slice(&DOMAIN_SA_SIGNER_SET_V1);

    // u32_be(signer_count) ‖ sorted_signer_ids_concat_be
    // Both length prefixes use `signer_count.to_be_bytes()` — the three lengths
    // are equal (verified above) so `signer_count` is the canonical source.
    preimage.extend_from_slice(&s.signer_count.to_be_bytes());
    for &i in &sorted_indices {
        preimage.extend_from_slice(&s.signer_ids[i].to_be_bytes());
    }

    // u32_be(signer_count) ‖ signer_pubkeys_concat (in sorted-ID order)
    preimage.extend_from_slice(&s.signer_count.to_be_bytes());
    for &i in &sorted_indices {
        let body = signer_pubkey_canonical_body(&s.signer_pubkeys[i])?;
        preimage.extend_from_slice(&body);
    }

    // u32_be(threshold)
    preimage.extend_from_slice(&s.threshold.to_be_bytes());

    Ok(Sha256::digest(&preimage).into())
}

/// Formats a 32-byte digest as a first-8-last-8 hex string for audit-log fields.
///
/// Produces a string of the form `"<16 hex chars>...<16 hex chars>"` (35 chars
/// total including the `...` separator). Applied to signer-set digests to
/// keep the audit-log field width bounded while retaining forensic usefulness.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::format_digest_first8_last8;
///
/// let digest = [0xabu8; 32];
/// let s = format_digest_first8_last8(&digest);
/// assert_eq!(s, "abababababababab...abababababababab");
/// assert_eq!(s.len(), 35);
/// ```
#[must_use]
pub fn format_digest_first8_last8(digest: &[u8; 32]) -> String {
    // Byte offset for the last 8 bytes of a 32-byte digest.
    // Avoids the magic number `48` in the original hex-string slice index.
    const LAST_8_OFFSET: usize = 24; // 32 - 8

    let first8 = crate::hex::encode(&digest[..8]);
    let last8 = crate::hex::encode(&digest[LAST_8_OFFSET..]);
    format!("{first8}...{last8}")
}

// ── Version-2 domain separators ───────────────────────────────────────────────

/// Domain separator for the version-2 signer-set snapshot digest.
///
/// The first 16 bytes of `SHA-256("sa.signer_set.v2.divergence")`. Used by
/// [`compute_signer_set_digest_v2`]; a version-2 digest can never equal a
/// version-1 digest or a digest from any other protocol context because the
/// preimages start with different separators.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::DOMAIN_SA_SIGNER_SET_V2;
/// use sha2::{Digest, Sha256};
///
/// let full = Sha256::digest(b"sa.signer_set.v2.divergence");
/// assert_eq!(DOMAIN_SA_SIGNER_SET_V2, full[..16]);
/// ```
pub const DOMAIN_SA_SIGNER_SET_V2: [u8; 16] = {
    // Full digest: `echo -n "sa.signer_set.v2.divergence" | sha256sum`
    //   => d541fbb2709265c4d90475f81c65c1200e962439babad74904e791a9ddf460b7
    [
        0xd5, 0x41, 0xfb, 0xb2, 0x70, 0x92, 0x65, 0xc4, 0xd9, 0x04, 0x75, 0xf8, 0x1c, 0x65, 0xc1,
        0x20,
    ]
};

/// Domain separator for the account digest.
///
/// The first 16 bytes of `SHA-256("sa.account_id.v1")`. Used by
/// [`account_digest`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::DOMAIN_SA_ACCOUNT_ID_V1;
/// use sha2::{Digest, Sha256};
///
/// let full = Sha256::digest(b"sa.account_id.v1");
/// assert_eq!(DOMAIN_SA_ACCOUNT_ID_V1, full[..16]);
/// ```
pub const DOMAIN_SA_ACCOUNT_ID_V1: [u8; 16] = {
    // Full digest: `echo -n "sa.account_id.v1" | sha256sum`
    //   => 85f7b5cc9f880870a0b397110322874108e054b6df674f069d843c59bbdff482
    [
        0x85, 0xf7, 0xb5, 0xcc, 0x9f, 0x88, 0x08, 0x70, 0xa0, 0xb3, 0x97, 0x11, 0x03, 0x22, 0x87,
        0x41,
    ]
};

// ── hex32 serde ───────────────────────────────────────────────────────────────

/// Serde helpers for the 32-byte fields of the version-2 signer-set rows.
///
/// A 32-byte field serializes as a 64-character lowercase hex string. The
/// deserializer refuses an uppercase hex digit so every value has exactly
/// one accepted spelling, and a row re-serializes to the text it was read
/// from; the audit chain hashes that text.
pub(crate) mod hex32 {
    use super::ThresholdObservation;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes 32 bytes as 64 lowercase hex characters.
    pub(crate) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::hex::encode(bytes))
    }

    /// Deserializes 64 lowercase hex characters into 32 bytes.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        parse(&text).map_err(serde::de::Error::custom)
    }

    /// Parses the canonical lowercase spelling of a 32-byte value.
    fn parse(text: &str) -> Result<[u8; 32], String> {
        if let Some(offset) = text.bytes().position(|b| matches!(b, b'A'..=b'F')) {
            return Err(format!(
                "uppercase hex digit at offset {offset}; 32-byte fields are lowercase hex"
            ));
        }
        crate::hex::decode_hex32(text).map_err(|e| e.to_string())
    }

    /// Deserializes a required `Option<ThresholdObservation>` field.
    ///
    /// Accepts `null` as `None` and an object as `Some`. Because the field
    /// carries `deserialize_with`, serde refuses a row that omits it: the
    /// absence of a threshold observation is spelled `null`, never by a
    /// missing key.
    pub(crate) fn required_threshold<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<ThresholdObservation>, D::Error> {
        Option::<ThresholdObservation>::deserialize(d)
    }
}

// ── SignerIdentityV2 ──────────────────────────────────────────────────────────

/// Full identity of one signer in a version-2 signer-set snapshot.
///
/// Every variant is fixed width and keeps the whole identity: two signers
/// that differ in any byte have different identities, and so different
/// snapshot digests. A passkey signer is an `External` identity whose
/// verifier is the WebAuthn verifier contract.
///
/// # Serialization
///
/// Internally tagged by `kind` (`ed25519`, `external`, `delegated_contract`).
/// Every 32-byte field is a 64-character lowercase hex string.
///
/// # Debug discipline
///
/// `Debug` prints the variant and the first 8 bytes of each 32-byte field as
/// hex, never a whole key, verifier or key-data hash. [`Self::summary`] uses
/// the same first-8 projection for display.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::SignerIdentityV2;
///
/// let id = SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] };
/// assert_eq!(id.summary(), "ed25519:1111111111111111");
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignerIdentityV2 {
    /// An Ed25519 signer.
    Ed25519 {
        /// The 32-byte Ed25519 public key.
        #[serde(with = "hex32")]
        pubkey: [u8; 32],
    },

    /// A signer checked by a verifier contract over opaque key data.
    ///
    /// The key data is recorded as its SHA-256 and its length, which keeps
    /// the row fixed width while still distinguishing any two key-data
    /// values. The length is carried beside the hash so the digest binds it
    /// directly.
    External {
        /// The verifier contract id.
        #[serde(with = "hex32")]
        verifier: [u8; 32],
        /// SHA-256 of the signer's key data.
        #[serde(with = "hex32")]
        key_data_sha256: [u8; 32],
        /// Length of the signer's key data in bytes; never zero.
        key_data_len: u32,
    },

    /// A signer delegated to a contract address.
    DelegatedContract {
        /// The delegate contract id.
        #[serde(with = "hex32")]
        contract: [u8; 32],
    },
}

impl SignerIdentityV2 {
    /// Renders a display summary built from first-8-byte hex projections.
    ///
    /// `ed25519:<pubkey first8>`, `external:<verifier first8>:<key_data_sha256
    /// first8>` or `delegated_contract:<contract first8>`. The rows carry no
    /// first-8 twin fields; display derives them here.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Ed25519 { pubkey } => format!("ed25519:{}", crate::hex::encode(&pubkey[..8])),
            Self::External {
                verifier,
                key_data_sha256,
                ..
            } => format!(
                "external:{}:{}",
                crate::hex::encode(&verifier[..8]),
                crate::hex::encode(&key_data_sha256[..8])
            ),
            Self::DelegatedContract { contract } => {
                format!("delegated_contract:{}", crate::hex::encode(&contract[..8]))
            }
        }
    }

    /// Appends this identity's canonical digest body to `preimage`.
    ///
    /// `0x01 ‖ pubkey` (33 bytes), `0x02 ‖ verifier ‖ key_data_sha256 ‖
    /// u32_be(key_data_len)` (69 bytes) or `0x03 ‖ contract` (33 bytes).
    fn append_canonical_body(&self, preimage: &mut Vec<u8>) {
        match self {
            Self::Ed25519 { pubkey } => {
                preimage.push(0x01);
                preimage.extend_from_slice(pubkey);
            }
            Self::External {
                verifier,
                key_data_sha256,
                key_data_len,
            } => {
                preimage.push(0x02);
                preimage.extend_from_slice(verifier);
                preimage.extend_from_slice(key_data_sha256);
                preimage.extend_from_slice(&key_data_len.to_be_bytes());
            }
            Self::DelegatedContract { contract } => {
                preimage.push(0x03);
                preimage.extend_from_slice(contract);
            }
        }
    }
}

// Debug must never emit a whole 32-byte field; see the Debug discipline above.
impl std::fmt::Debug for SignerIdentityV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 { pubkey } => f
                .debug_struct("SignerIdentityV2::Ed25519")
                .field("pubkey_first8", &crate::hex::encode(&pubkey[..8]))
                .finish(),
            Self::External {
                verifier,
                key_data_sha256,
                key_data_len,
            } => f
                .debug_struct("SignerIdentityV2::External")
                .field("verifier_first8", &crate::hex::encode(&verifier[..8]))
                .field(
                    "key_data_sha256_first8",
                    &crate::hex::encode(&key_data_sha256[..8]),
                )
                .field("key_data_len", key_data_len)
                .finish(),
            Self::DelegatedContract { contract } => f
                .debug_struct("SignerIdentityV2::DelegatedContract")
                .field("contract_first8", &crate::hex::encode(&contract[..8]))
                .finish(),
        }
    }
}

// ── SignerEntryV2 / ThresholdObservation / SignerSetSnapshotV2 ────────────────

/// One signer of a version-2 snapshot: the rule-local signer id and the
/// signer's full identity.
///
/// Fields are `pub`; structural validity is checked where a snapshot is
/// consumed ([`SignerSetSnapshotV2::validate`], the digest and the reader).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEntryV2 {
    /// The signer id the smart-account contract assigned within the rule.
    pub id: u32,
    /// The signer's full identity.
    pub identity: SignerIdentityV2,
}

/// The rule's simple-threshold policy and its threshold, as observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdObservation {
    /// The policy contract id.
    #[serde(with = "hex32")]
    pub policy: [u8; 32],
    /// The threshold the policy enforces.
    pub threshold: u32,
}

/// A version-2 snapshot of a context rule's signer set.
///
/// Records every signer's full identity in ascending id order and the
/// rule's simple-threshold observation, which is absent when the rule has
/// no simple-threshold policy. Fields are `pub`; [`Self::validate`] checks
/// the structural rules wherever a snapshot is consumed.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::{
///     SignerEntryV2, SignerIdentityV2, SignerSetSnapshotV2,
/// };
///
/// let snapshot = SignerSetSnapshotV2 {
///     signers: vec![SignerEntryV2 {
///         id: 0,
///         identity: SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] },
///     }],
///     threshold: None,
/// };
/// let json = serde_json::to_string(&snapshot).unwrap();
/// assert!(json.ends_with(r#""threshold":null}"#));
/// assert!(snapshot.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSetSnapshotV2 {
    /// The signers, ordered by strictly ascending id.
    pub signers: Vec<SignerEntryV2>,

    /// The simple-threshold observation.
    ///
    /// The field is required on the wire: `null` records that no
    /// simple-threshold policy was observed, and a row without the key is
    /// refused.
    #[serde(deserialize_with = "hex32::required_threshold")]
    pub threshold: Option<ThresholdObservation>,
}

impl SignerSetSnapshotV2 {
    /// Checks the snapshot's structural rules.
    ///
    /// Signer ids are strictly ascending (a duplicate or an out-of-order id
    /// is refused), an `External` identity has non-empty key data, and the
    /// snapshot holds at most `u32::MAX` entries so the count fits the
    /// digest's length prefix.
    ///
    /// # Errors
    ///
    /// [`SignerSetCanonicalBodyError::MalformedSnapshotV2`] naming the first
    /// broken rule.
    pub fn validate(&self) -> Result<(), SignerSetCanonicalBodyError> {
        if u32::try_from(self.signers.len()).is_err() {
            return Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 {
                reason: "more than u32::MAX signer entries",
            });
        }
        for pair in self.signers.windows(2) {
            if let [previous, next] = pair {
                if previous.id == next.id {
                    return Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 {
                        reason: "duplicate signer id",
                    });
                }
                if previous.id > next.id {
                    return Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 {
                        reason: "signer ids are not in ascending order",
                    });
                }
            }
        }
        if self.signers.iter().any(|entry| {
            matches!(
                entry.identity,
                SignerIdentityV2::External {
                    key_data_len: 0,
                    ..
                }
            )
        }) {
            return Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 {
                reason: "External signer with empty key data",
            });
        }
        Ok(())
    }

    /// Number of signers in the snapshot.
    ///
    /// Saturates at `u32::MAX`; [`Self::validate`] refuses a snapshot whose
    /// entry count does not fit a `u32`.
    #[must_use]
    pub fn signer_count(&self) -> u32 {
        u32::try_from(self.signers.len()).unwrap_or(u32::MAX)
    }
}

// ── compute_signer_set_digest_v2 ──────────────────────────────────────────────

/// Computes the domain-tagged SHA-256 digest of a version-2 snapshot.
///
/// Validates the snapshot first ([`SignerSetSnapshotV2::validate`]), then
/// hashes this preimage (all integers big-endian):
///
/// ```text
/// DOMAIN_SA_SIGNER_SET_V2                       16 bytes
/// ‖ u32_be(count)                                4 bytes
/// ‖ for each entry, in ascending id order:
///     u32_be(id)                                 4 bytes
///     ‖ body
/// ‖ threshold_tail
/// ```
///
/// | Part                | Layout                                                        | Bytes |
/// |---------------------|---------------------------------------------------------------|-------|
/// | `Ed25519` body      | `0x01 ‖ pubkey`                                               | 33    |
/// | `External` body     | `0x02 ‖ verifier ‖ key_data_sha256 ‖ u32_be(key_data_len)`    | 69    |
/// | `DelegatedContract` | `0x03 ‖ contract`                                             | 33    |
/// | tail, `None`        | `0x00`                                                        | 1     |
/// | tail, `Some`        | `0x01 ‖ policy ‖ u32_be(threshold)`                           | 37    |
///
/// Every body is fixed width per tag and the count prefixes the entries, so
/// the encoding is prefix-free: two different valid snapshots never share a
/// preimage.
///
/// # Errors
///
/// [`SignerSetCanonicalBodyError::MalformedSnapshotV2`] when the snapshot
/// fails [`SignerSetSnapshotV2::validate`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::{
///     SignerEntryV2, SignerIdentityV2, SignerSetSnapshotV2, compute_signer_set_digest_v2,
/// };
///
/// let snapshot = SignerSetSnapshotV2 {
///     signers: vec![
///         SignerEntryV2 { id: 0, identity: SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] } },
///         SignerEntryV2 { id: 1, identity: SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] } },
///     ],
///     threshold: None,
/// };
/// let digest = compute_signer_set_digest_v2(&snapshot).unwrap();
/// assert_eq!(
///     stellar_agent_core::hex::encode(&digest),
///     "c1d338dfb630f4af8559d3f63a44e498a94d552d03f8a994d29f14d51ac76f17"
/// );
/// ```
pub fn compute_signer_set_digest_v2(
    snapshot: &SignerSetSnapshotV2,
) -> Result<[u8; 32], SignerSetCanonicalBodyError> {
    snapshot.validate()?;
    let preimage = signer_set_preimage_v2(snapshot);
    Ok(Sha256::digest(&preimage).into())
}

/// Builds the version-2 digest preimage laid out in
/// [`compute_signer_set_digest_v2`].
///
/// The caller validates first, so the entry count fits the `u32` prefix
/// and [`SignerSetSnapshotV2::signer_count`] is exact.
fn signer_set_preimage_v2(snapshot: &SignerSetSnapshotV2) -> Vec<u8> {
    let count = snapshot.signer_count();
    let mut preimage = Vec::with_capacity(16 + 4 + snapshot.signers.len() * (4 + 69) + 37);
    preimage.extend_from_slice(&DOMAIN_SA_SIGNER_SET_V2);
    preimage.extend_from_slice(&count.to_be_bytes());
    for entry in &snapshot.signers {
        preimage.extend_from_slice(&entry.id.to_be_bytes());
        entry.identity.append_canonical_body(&mut preimage);
    }
    match &snapshot.threshold {
        None => preimage.push(0x00),
        Some(observation) => {
            preimage.push(0x01);
            preimage.extend_from_slice(&observation.policy);
            preimage.extend_from_slice(&observation.threshold.to_be_bytes());
        }
    }
    preimage
}

// ── account_digest ────────────────────────────────────────────────────────────

/// Computes the digest that binds a smart account to its network.
///
/// SHA-256 over `DOMAIN_SA_ACCOUNT_ID_V1 ‖ u32_be(passphrase byte length) ‖
/// passphrase bytes ‖ smart_account bytes`. The length prefix makes the
/// split between passphrase and account unambiguous, so the digest names
/// exactly one `(network, account)` pair. Version-2 state rows carry it as
/// the account key: a redacted strkey names many accounts and no network,
/// the digest names one account on one network.
///
/// `smart_account` is the full C-strkey. A passphrase longer than
/// `u32::MAX` bytes saturates the length prefix; network passphrases are a
/// few dozen bytes.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::audit_log::signer_set::account_digest;
///
/// let digest = account_digest(
///     "Test SDF Network ; September 2015",
///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
/// );
/// assert_eq!(
///     stellar_agent_core::hex::encode(&digest),
///     "bd188dc1cf49dca11c897fd86800c78d77c30d72d212bffa8031fa950cc49407"
/// );
/// ```
#[must_use]
pub fn account_digest(network_passphrase: &str, smart_account: &str) -> [u8; 32] {
    Sha256::digest(account_digest_preimage(network_passphrase, smart_account)).into()
}

/// Builds the preimage hashed by [`account_digest`].
fn account_digest_preimage(network_passphrase: &str, smart_account: &str) -> Vec<u8> {
    let passphrase_len = u32::try_from(network_passphrase.len()).unwrap_or(u32::MAX);
    let mut preimage = Vec::with_capacity(16 + 4 + network_passphrase.len() + smart_account.len());
    preimage.extend_from_slice(&DOMAIN_SA_ACCOUNT_ID_V1);
    preimage.extend_from_slice(&passphrase_len.to_be_bytes());
    preimage.extend_from_slice(network_passphrase.as_bytes());
    preimage.extend_from_slice(smart_account.as_bytes());
    preimage
}

// ── SignerSetView / SignerSetViewPayload ──────────────────────────────────────

/// A signer-set state read from the audit log, tagged with its row version.
///
/// A version-1 state keeps the first 16 bytes of an `External` signer's key
/// data; a version-2 state keeps every identity in full and a threshold
/// observation that may be absent. A comparison runs only between states of
/// the same version. The enum is exhaustive so every consumer handles each
/// version explicitly.
///
/// # Serialization
///
/// Internally tagged by `version` (`v1`, `v2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "snake_case")]
pub enum SignerSetView {
    /// State reconstructed from a version-1 state row.
    V1(ObservedSignerSet),
    /// State read from a version-2 state row.
    V2(SignerSetSnapshotV2),
}

impl SignerSetView {
    /// The row version: `1` or `2`.
    #[must_use]
    pub fn version(&self) -> u8 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    /// Number of signers in the state.
    #[must_use]
    pub fn signer_count(&self) -> u32 {
        match self {
            Self::V1(state) => state.signer_count,
            Self::V2(snapshot) => snapshot.signer_count(),
        }
    }
}

impl std::fmt::Display for SignerSetView {
    /// Formats the view as `v{version} count={n} threshold={t}`, with
    /// `threshold=none` for a version-2 snapshot that observed no
    /// simple-threshold policy.
    ///
    /// Omits signer ids and identities so no key material reaches log
    /// output or error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "v{} count={} threshold=",
            self.version(),
            self.signer_count()
        )?;
        match self {
            Self::V1(state) => write!(f, "{}", state.threshold),
            Self::V2(snapshot) => match &snapshot.threshold {
                Some(observation) => write!(f, "{}", observation.threshold),
                None => f.write_str("none"),
            },
        }
    }
}

/// Return value of [`super::reader::AuditReader::find_latest_signer_set_view`].
///
/// Carries the versioned state, the SHA-256 of the canonical JSON body of
/// the row it was read from, and where that row is: the basename of the log
/// file and the 1-based line number, so a refusal can name the row.
///
/// # Sealed-field discipline
///
/// Fields are `pub(crate)` and the constructor is `pub(crate)`, as on
/// [`SignerSetStatePayload`]: only the audit-log reader constructs a
/// payload, and accessors return borrowed references so a caller cannot
/// forge a `row_hash` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSetViewPayload {
    /// The versioned signer-set state.
    pub(crate) view: SignerSetView,
    /// SHA-256 of the canonical JSON body of the source audit row.
    pub(crate) row_hash: [u8; 32],
    /// 1-based line number of the source row within its file.
    pub(crate) line: usize,
    /// Basename of the log file holding the source row.
    pub(crate) file: String,
}

impl SignerSetViewPayload {
    /// Constructs a payload; only the audit-log reader calls this.
    #[must_use]
    pub(crate) fn new(view: SignerSetView, row_hash: [u8; 32], line: usize, file: String) -> Self {
        Self {
            view,
            row_hash,
            line,
            file,
        }
    }

    /// The versioned signer-set state.
    #[must_use]
    pub fn view(&self) -> &SignerSetView {
        &self.view
    }

    /// SHA-256 of the canonical JSON body of the source audit row.
    #[must_use]
    pub fn row_hash(&self) -> &[u8; 32] {
        &self.row_hash
    }

    /// 1-based line number of the source row within its file.
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }

    /// Basename of the log file holding the source row.
    #[must_use]
    pub fn file(&self) -> &str {
        &self.file
    }

    /// Converts a version-1 payload into the [`SignerSetStatePayload`] with
    /// the same state and row hash.
    ///
    /// Returns `None` for a version-2 view. A caller that needs the row's
    /// location reads [`Self::line`] and [`Self::file`] before consuming the
    /// payload.
    #[must_use]
    pub fn into_v1(self) -> Option<SignerSetStatePayload> {
        match self.view {
            SignerSetView::V1(state) => Some(SignerSetStatePayload::new(state, self.row_hash)),
            SignerSetView::V2(_) => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // clippy::panic covers `panic!(...)` calls in structural match arms
    // (e.g. `other => panic!("expected X, got: {other:?}")`) and
    // `assert!(tamper_applied, ...)` in the tamper-detection test.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use super::*;

    // ── DOMAIN_SA_SIGNER_SET_V1 correctness ───────────────────────────────────

    #[test]
    fn domain_separator_matches_sha256_prefix() {
        // Independently compute SHA-256("sa.signer_set.v1.divergence") and verify
        // that DOMAIN_SA_SIGNER_SET_V1 equals the first 16 bytes.
        let full = Sha256::digest(b"sa.signer_set.v1.divergence");
        assert_eq!(
            DOMAIN_SA_SIGNER_SET_V1,
            full[..16],
            "DOMAIN_SA_SIGNER_SET_V1 must equal first 16 bytes of SHA-256(\"sa.signer_set.v1.divergence\")"
        );
    }

    // ── SignerPubkey round-trips ───────────────────────────────────────────────

    #[test]
    fn signer_pubkey_ed25519_round_trip() {
        let pk = SignerPubkey::Ed25519 {
            pubkey: [0xabu8; 32],
        };
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains("ed25519"), "kind discriminant: {json}");
        let back: SignerPubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn signer_pubkey_external_round_trip() {
        let pk = SignerPubkey::External {
            // A syntactically valid C-strkey fixture (32 zero bytes → strkey).
            verifier_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            key_data_first16: [0xbbu8; 16],
        };
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains("external"), "kind discriminant: {json}");
        let back: SignerPubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn signer_pubkey_webauthn_round_trip() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [0xccu8; 16],
        };
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains("web_authn"), "kind discriminant: {json}");
        let back: SignerPubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, back);
    }

    // ── signer_pubkey_canonical_body byte-equality ────────────────────────────

    #[test]
    fn canonical_body_ed25519_is_33_bytes_starting_with_0x01() {
        let pk = SignerPubkey::Ed25519 {
            pubkey: [0x42u8; 32],
        };
        let body = signer_pubkey_canonical_body(&pk).unwrap();
        assert_eq!(body.len(), 33, "Ed25519 body must be 33 bytes");
        assert_eq!(body[0], 0x01, "Ed25519 tag must be 0x01");
        assert_eq!(&body[1..], &[0x42u8; 32]);
    }

    #[test]
    fn canonical_body_external_is_53_bytes_starting_with_0x02() {
        // C-strkey for a contract. The exact decoded hash is not all-zeros — the
        // checksum and base32 encoding determine the hash bytes. We verify the
        // structural layout (tag, XDR discriminant, contract hash, key_data).
        let strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let pk = SignerPubkey::External {
            verifier_contract: strkey.to_owned(),
            key_data_first16: [0xbbu8; 16],
        };
        let body = signer_pubkey_canonical_body(&pk).unwrap();
        assert_eq!(body.len(), 53, "External body must be 53 bytes");
        assert_eq!(body[0], 0x02, "External tag must be 0x02");
        // bytes 1..5 are the 4-byte XDR discriminant for SC_ADDRESS_TYPE_CONTRACT = 1.
        assert_eq!(
            &body[1..5],
            &[0x00u8, 0x00, 0x00, 0x01],
            "XDR discriminant must be 0x00000001"
        );
        // bytes 5..37 are the 32-byte contract hash decoded from the C-strkey.
        // Verify these match what stellar_strkey::Contract::from_string decodes.
        let expected_hash = stellar_strkey::Contract::from_string(strkey).unwrap().0;
        assert_eq!(
            &body[5..37],
            &expected_hash,
            "contract hash must match decoded strkey"
        );
        // bytes 37..53 are key_data_first16.
        assert_eq!(&body[37..53], &[0xbbu8; 16], "key_data_first16 must match");
    }

    #[test]
    fn canonical_body_webauthn_is_17_bytes_starting_with_0x03() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [0xccu8; 16],
        };
        let body = signer_pubkey_canonical_body(&pk).unwrap();
        assert_eq!(body.len(), 17, "WebAuthn body must be 17 bytes");
        assert_eq!(body[0], 0x03, "WebAuthn tag must be 0x03");
        assert_eq!(&body[1..], &[0xccu8; 16]);
    }

    #[test]
    fn canonical_body_external_invalid_strkey_returns_err() {
        let pk = SignerPubkey::External {
            verifier_contract: "not_a_valid_cstrkey".to_owned(),
            key_data_first16: [0u8; 16],
        };
        assert!(signer_pubkey_canonical_body(&pk).is_err());
    }

    // ── BaselineReason round-trips ────────────────────────────────────────────

    #[test]
    fn baseline_reason_first_observation_serialises_to_snake_case() {
        let r = BaselineReason::FirstObservation;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#""first_observation""#);
        let back: BaselineReason = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn baseline_reason_explicit_refresh_serialises_to_snake_case() {
        let r = BaselineReason::ExplicitRefresh;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#""explicit_refresh""#);
        let back: BaselineReason = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    // ── compute_signer_set_digest ─────────────────────────────────────────────

    #[test]
    fn compute_signer_set_digest_deterministic() {
        let s = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
        };
        let d1 = compute_signer_set_digest(&s).unwrap();
        let d2 = compute_signer_set_digest(&s).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_signer_set_digest_changes_on_threshold_change() {
        let base = ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            ],
        };
        let modified = ObservedSignerSet {
            threshold: 2,
            ..base.clone()
        };
        assert_ne!(
            compute_signer_set_digest(&base).unwrap(),
            compute_signer_set_digest(&modified).unwrap()
        );
    }

    #[test]
    fn compute_signer_set_digest_changes_on_signer_change() {
        let s1 = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
        };
        let s2 = ObservedSignerSet {
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [2u8; 32] }],
            ..s1.clone()
        };
        assert_ne!(
            compute_signer_set_digest(&s1).unwrap(),
            compute_signer_set_digest(&s2).unwrap()
        );
    }

    #[test]
    fn compute_signer_set_digest_sorted_ids_invariant() {
        // Two ObservedSignerSets that differ only in the order of signer_ids
        // (with pubkeys re-ordered correspondingly) must produce the SAME digest,
        // because signer_ids are sorted ascending before serialisation.
        let pk0 = SignerPubkey::Ed25519 { pubkey: [1u8; 32] };
        let pk1 = SignerPubkey::Ed25519 { pubkey: [2u8; 32] };
        let s_forward = ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![pk0.clone(), pk1.clone()],
        };
        let s_reversed = ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![1, 0],                         // reversed
            signer_pubkeys: vec![pk1.clone(), pk0.clone()], // pubkeys follow IDs
        };
        assert_eq!(
            compute_signer_set_digest(&s_forward).unwrap(),
            compute_signer_set_digest(&s_reversed).unwrap(),
            "digest must be ID-order-independent (sorted before serialisation)"
        );
    }

    #[test]
    fn compute_signer_set_digest_big_endian_encoding() {
        // Verify that the digest changes when threshold byte-order is big-endian
        // (the spec mandates u32_be). We construct two digests: one with the
        // correct BE implementation, one with a manually LE-encoded preimage,
        // and verify they differ for a threshold != 0 that differs in byte order.
        //
        // Since threshold = 1 has the same value in LE and BE (0x01000000 vs
        // 0x00000001), use threshold = 256 (0x00000100 in BE, 0x00010000 in LE).
        let s = ObservedSignerSet {
            signer_count: 1,
            threshold: 256,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0u8; 32] }],
        };
        let d = compute_signer_set_digest(&s).unwrap();
        assert_ne!(d, [0u8; 32], "digest must be non-zero");

        // Build a LE-encoded preimage manually and check it differs.
        let mut le_preimage: Vec<u8> = Vec::new();
        le_preimage.extend_from_slice(&DOMAIN_SA_SIGNER_SET_V1);
        le_preimage.extend_from_slice(&1u32.to_le_bytes()); // len(ids) LE
        le_preimage.extend_from_slice(&0u32.to_le_bytes()); // id[0] LE
        le_preimage.extend_from_slice(&1u32.to_le_bytes()); // len(pubkeys) LE
        le_preimage.push(0x01);
        le_preimage.extend_from_slice(&[0u8; 32]); // pubkey body
        le_preimage.extend_from_slice(&256u32.to_le_bytes()); // threshold LE
        let le_digest: [u8; 32] = Sha256::digest(&le_preimage).into();
        assert_ne!(
            d, le_digest,
            "BE digest must differ from LE digest for threshold = 256"
        );
    }

    #[test]
    fn canonical_scaddress_produces_36_bytes() {
        let strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let body = canonical_scaddress(strkey).unwrap();
        assert_eq!(body.len(), 36, "canonical_scaddress must be 36 bytes");
        assert_eq!(
            &body[..4],
            &[0x00u8, 0x00, 0x00, 0x01],
            "first 4 bytes must be the XDR discriminant for SC_ADDRESS_TYPE_CONTRACT = 1"
        );
        let expected_hash = stellar_strkey::Contract::from_string(strkey).unwrap().0;
        assert_eq!(
            &body[4..],
            &expected_hash,
            "remaining 32 bytes must be the contract hash"
        );
    }

    #[test]
    fn canonical_scaddress_rejects_invalid_strkey() {
        let err = canonical_scaddress("not_a_cstrkey");
        assert!(err.is_err(), "invalid C-strkey must return Err");
        let e = err.unwrap_err();
        assert!(
            matches!(
                e,
                SignerSetCanonicalBodyError::InvalidVerifierContract { .. }
            ),
            "must be InvalidVerifierContract variant: {e}"
        );
    }

    // ── format_digest_first8_last8 ────────────────────────────────────────────

    #[test]
    fn format_digest_first8_last8_length_and_separator() {
        let digest = [0xabu8; 32];
        let s = format_digest_first8_last8(&digest);
        assert_eq!(s.len(), 35); // 16 + 3 ("...") + 16
        assert!(s.contains("..."));
        // First 8 bytes → 16 hex chars.
        assert!(s.starts_with("abababababababab"));
        // Last 8 bytes → 16 hex chars.
        assert!(s.ends_with("abababababababab"));
    }

    #[test]
    fn format_digest_first8_last8_differs_on_different_digest() {
        let d1 = [0u8; 32];
        let mut d2 = [0u8; 32];
        d2[0] = 1;
        assert_ne!(
            format_digest_first8_last8(&d1),
            format_digest_first8_last8(&d2)
        );
    }

    // ── SignerPubkey Debug redaction ──────────────────────────────────────────

    #[test]
    fn debug_ed25519_emits_only_first8_hex() {
        let pk = SignerPubkey::Ed25519 {
            pubkey: [0xabu8; 32],
        };
        let s = format!("{pk:?}");
        // Must contain the first-8-byte hex projection.
        assert!(
            s.contains("abababababababab"),
            "Debug must contain first-8 hex projection: {s}"
        );
        // Must NOT contain the remaining bytes (would be 64 hex chars for full 32 bytes).
        // The full 32-byte hex is "abababab...abababab" (64 chars); we verify the
        // output does not contain 32 consecutive 'ab' pairs beyond the first-8 projection.
        let full_hex = "abababababababababababababababababababababababababababababababababab";
        assert!(
            !s.contains(full_hex),
            "Debug must NOT emit full 32-byte pubkey hex: {s}"
        );
    }

    #[test]
    fn debug_external_emits_only_first8_hex() {
        let pk = SignerPubkey::External {
            verifier_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            key_data_first16: [0xbbu8; 16],
        };
        let s = format!("{pk:?}");
        // Must contain the first-8-byte hex projection of key_data_first16.
        assert!(
            s.contains("bbbbbbbbbbbbbbbb"),
            "Debug must contain first-8 hex projection of key_data: {s}"
        );
        // Must NOT contain the full 16-byte hex of key_data_first16 (32 chars).
        let full_key_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(
            !s.contains(full_key_hex),
            "Debug must NOT emit full 16-byte key_data hex: {s}"
        );
        // Must NOT emit the full verifier_contract C-strkey.
        assert!(
            !s.contains("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"),
            "Debug must NOT emit full verifier_contract C-strkey: {s}"
        );
    }

    #[test]
    fn debug_webauthn_emits_only_first8_hex() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [0xccu8; 16],
        };
        let s = format!("{pk:?}");
        // Must contain the first-8-byte hex projection.
        assert!(
            s.contains("cccccccccccccccc"),
            "Debug must contain first-8 hex projection of credential_id: {s}"
        );
        // Must NOT contain the full 16-byte hex of credential_id_first16 (32 chars).
        let full_cred_hex = "cccccccccccccccccccccccccccccccc";
        assert!(
            !s.contains(full_cred_hex),
            "Debug must NOT emit full 16-byte credential_id hex: {s}"
        );
    }

    // ── ObservedSignerSet serde round-trip ────────────────────────────────────

    #[test]
    fn observed_signer_set_round_trip() {
        let s = ObservedSignerSet {
            signer_count: 2,
            threshold: 2,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::WebAuthn {
                    credential_id_first16: [2u8; 16],
                },
            ],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: ObservedSignerSet = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ── compute_signer_set_digest length parity ───────────────────────────────

    #[test]
    fn compute_signer_set_digest_rejects_length_mismatch() {
        // Case 1: signer_ids.len() > signer_pubkeys.len() (extra ID).
        let s_extra_id = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0, 1], // 2 ids but signer_count says 1
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
        };
        let err = compute_signer_set_digest(&s_extra_id);
        assert!(
            matches!(
                err,
                Err(SignerSetCanonicalBodyError::MalformedObservedSignerSet { .. })
            ),
            "extra signer_id must return MalformedObservedSignerSet: {err:?}"
        );

        // Case 2: signer_pubkeys.len() > signer_ids.len() (extra pubkey).
        let s_extra_pk = ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            ],
        };
        let err = compute_signer_set_digest(&s_extra_pk);
        assert!(
            matches!(
                err,
                Err(SignerSetCanonicalBodyError::MalformedObservedSignerSet { .. })
            ),
            "extra signer_pubkey must return MalformedObservedSignerSet: {err:?}"
        );

        // Case 3: signer_ids.len() == signer_pubkeys.len() but signer_count disagrees.
        let s_count_mismatch = ObservedSignerSet {
            signer_count: 3, // claims 3, but only 1 id and 1 pubkey
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
        };
        let err = compute_signer_set_digest(&s_count_mismatch);
        assert!(
            matches!(
                err,
                Err(SignerSetCanonicalBodyError::MalformedObservedSignerSet { .. })
            ),
            "signer_count mismatch must return MalformedObservedSignerSet: {err:?}"
        );
    }

    // ── canonical_scaddress G-vs-C error message ──────────────────────────────

    #[test]
    fn canonical_scaddress_rejects_g_strkey_with_descriptive_error() {
        // A well-formed G-strkey (Ed25519 account) must be rejected with an
        // error message indicating it is an account key, not a contract address.
        let g_strkey = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
        let err = canonical_scaddress(g_strkey);
        assert!(err.is_err(), "G-strkey must return Err");
        match err.unwrap_err() {
            SignerSetCanonicalBodyError::InvalidVerifierContract { strkey, .. } => {
                assert!(
                    strkey.contains("account G-strkey not accepted"),
                    "error must note G-strkey type: {strkey}"
                );
            }
            other => panic!("expected InvalidVerifierContract, got: {other:?}"),
        }
    }

    // ── Version-2 snapshot ────────────────────────────────────────────────────

    /// The 40 key-data bytes `00 01 .. 27` of the published Vector B.
    fn vector_b_key_data() -> Vec<u8> {
        (0u8..40).collect()
    }

    fn ed25519_entry(id: u32, byte: u8) -> SignerEntryV2 {
        SignerEntryV2 {
            id,
            identity: SignerIdentityV2::Ed25519 { pubkey: [byte; 32] },
        }
    }

    /// Published Vector A: a policyless two-signer rule.
    fn vector_a() -> SignerSetSnapshotV2 {
        SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x11), ed25519_entry(1, 0x22)],
            threshold: None,
        }
    }

    /// Published Vector B: one External and one DelegatedContract signer with
    /// a threshold.
    fn vector_b() -> SignerSetSnapshotV2 {
        SignerSetSnapshotV2 {
            signers: vec![
                SignerEntryV2 {
                    id: 3,
                    identity: SignerIdentityV2::External {
                        verifier: [0x33; 32],
                        key_data_sha256: Sha256::digest(vector_b_key_data()).into(),
                        key_data_len: 40,
                    },
                },
                SignerEntryV2 {
                    id: 7,
                    identity: SignerIdentityV2::DelegatedContract {
                        contract: [0x44; 32],
                    },
                },
            ],
            threshold: Some(ThresholdObservation {
                policy: [0x55; 32],
                threshold: 2,
            }),
        }
    }

    fn digest_hex(snapshot: &SignerSetSnapshotV2) -> String {
        crate::hex::encode(&compute_signer_set_digest_v2(snapshot).unwrap())
    }

    #[test]
    fn domain_separator_v2_matches_sha256_prefix() {
        let full = Sha256::digest(b"sa.signer_set.v2.divergence");
        assert_eq!(DOMAIN_SA_SIGNER_SET_V2, full[..16]);
        assert_eq!(
            crate::hex::encode(&DOMAIN_SA_SIGNER_SET_V2),
            "d541fbb2709265c4d90475f81c65c120"
        );
    }

    #[test]
    fn domain_separator_account_id_matches_sha256_prefix() {
        let full = Sha256::digest(b"sa.account_id.v1");
        assert_eq!(DOMAIN_SA_ACCOUNT_ID_V1, full[..16]);
        assert_eq!(
            crate::hex::encode(&DOMAIN_SA_ACCOUNT_ID_V1),
            "85f7b5cc9f880870a0b3971103228741"
        );
    }

    #[test]
    fn vector_a_preimage_and_digest_match_the_published_values() {
        let snapshot = vector_a();
        let expected_preimage = format!(
            "d541fbb2709265c4d90475f81c65c120\
             00000002\
             00000000\
             01{}\
             00000001\
             01{}\
             00",
            "11".repeat(32),
            "22".repeat(32)
        );
        let preimage = signer_set_preimage_v2(&snapshot);
        assert_eq!(preimage.len(), 95);
        assert_eq!(crate::hex::encode(&preimage), expected_preimage);
        assert_eq!(
            digest_hex(&snapshot),
            "c1d338dfb630f4af8559d3f63a44e498a94d552d03f8a994d29f14d51ac76f17"
        );
    }

    #[test]
    fn vector_b_preimage_and_digest_match_the_published_values() {
        assert_eq!(
            crate::hex::encode(&vector_b_key_data()),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
        );
        assert_eq!(
            crate::hex::encode(&Sha256::digest(vector_b_key_data())),
            "5faa4eec3611556812c2d74b437c8c49add3f910f10063d801441f7d75cd5e3b"
        );
        let snapshot = vector_b();
        let expected_preimage = format!(
            "d541fbb2709265c4d90475f81c65c120\
             00000002\
             00000003\
             02{}\
             5faa4eec3611556812c2d74b437c8c49add3f910f10063d801441f7d75cd5e3b\
             00000028\
             00000007\
             03{}\
             01{}\
             00000002",
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32)
        );
        let preimage = signer_set_preimage_v2(&snapshot);
        assert_eq!(preimage.len(), 167);
        assert_eq!(crate::hex::encode(&preimage), expected_preimage);
        assert_eq!(
            digest_hex(&snapshot),
            "8b0c7e46a6bddd17098d72d89d0e15729fb3fa68863e53935488f627ef3cee0f"
        );
    }

    #[test]
    fn account_digest_matches_the_published_vector() {
        let passphrase = "Test SDF Network ; September 2015";
        let account = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let preimage = account_digest_preimage(passphrase, account);
        assert_eq!(preimage.len(), 109);
        let mut expected = DOMAIN_SA_ACCOUNT_ID_V1.to_vec();
        expected.extend_from_slice(&33u32.to_be_bytes());
        expected.extend_from_slice(passphrase.as_bytes());
        expected.extend_from_slice(account.as_bytes());
        assert_eq!(preimage, expected);
        assert_eq!(
            crate::hex::encode(&account_digest(passphrase, account)),
            "bd188dc1cf49dca11c897fd86800c78d77c30d72d212bffa8031fa950cc49407"
        );
    }

    #[test]
    fn account_digest_separates_network_and_account() {
        let account = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        assert_ne!(
            account_digest("Test SDF Network ; September 2015", account),
            account_digest("Public Global Stellar Network ; September 2015", account)
        );
        // Moving a byte across the passphrase/account boundary changes the
        // digest through the length prefix.
        assert_ne!(account_digest("ab", "c"), account_digest("a", "bc"));
    }

    // ── Version-2 serde ───────────────────────────────────────────────────────

    #[test]
    fn v2_types_round_trip_through_json() {
        for snapshot in [vector_a(), vector_b()] {
            let json = serde_json::to_string(&snapshot).unwrap();
            let back: SignerSetSnapshotV2 = serde_json::from_str(&json).unwrap();
            assert_eq!(back, snapshot);
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
        let vector_a_json = serde_json::to_string(&vector_a()).unwrap();
        assert!(
            vector_a_json.contains(r#""threshold":null"#),
            "an absent observation is spelled null: {vector_a_json}"
        );
        let identities = [
            SignerIdentityV2::Ed25519 { pubkey: [1; 32] },
            SignerIdentityV2::External {
                verifier: [2; 32],
                key_data_sha256: [3; 32],
                key_data_len: 65,
            },
            SignerIdentityV2::DelegatedContract { contract: [4; 32] },
        ];
        for identity in identities {
            let json = serde_json::to_string(&identity).unwrap();
            let back: SignerIdentityV2 = serde_json::from_str(&json).unwrap();
            assert_eq!(back, identity);
        }
        let entry = ed25519_entry(9, 0xab);
        let back: SignerEntryV2 =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(back, entry);
        let observation = ThresholdObservation {
            policy: [0x55; 32],
            threshold: 2,
        };
        let back: ThresholdObservation =
            serde_json::from_str(&serde_json::to_string(&observation).unwrap()).unwrap();
        assert_eq!(back, observation);
        for view in [
            SignerSetView::V2(vector_b()),
            SignerSetView::V1(ObservedSignerSet {
                signer_count: 1,
                threshold: 1,
                signer_ids: vec![0],
                signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [7; 32] }],
            }),
        ] {
            let back: SignerSetView =
                serde_json::from_str(&serde_json::to_string(&view).unwrap()).unwrap();
            assert_eq!(back, view);
        }
    }

    #[test]
    fn v2_identity_wire_shape_is_lowercase_hex() {
        let json = serde_json::to_string(&SignerIdentityV2::External {
            verifier: [0xab; 32],
            key_data_sha256: [0xcd; 32],
            key_data_len: 40,
        })
        .unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"kind":"external","verifier":"{}","key_data_sha256":"{}","key_data_len":40}}"#,
                "ab".repeat(32),
                "cd".repeat(32)
            )
        );
        let json = serde_json::to_string(&SignerIdentityV2::DelegatedContract {
            contract: [0x01; 32],
        })
        .unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"kind":"delegated_contract","contract":"{}"}}"#,
                "01".repeat(32)
            )
        );
    }

    #[test]
    fn snapshot_without_threshold_key_is_refused_and_null_is_none() {
        let signers = format!(
            r#"[{{"id":0,"identity":{{"kind":"ed25519","pubkey":"{}"}}}}]"#,
            "11".repeat(32)
        );
        let missing = format!(r#"{{"signers":{signers}}}"#);
        let err = serde_json::from_str::<SignerSetSnapshotV2>(&missing).unwrap_err();
        assert!(
            err.to_string().contains("missing field `threshold`"),
            "unexpected error: {err}"
        );
        let null = format!(r#"{{"signers":{signers},"threshold":null}}"#);
        let snapshot: SignerSetSnapshotV2 = serde_json::from_str(&null).unwrap();
        assert_eq!(snapshot.threshold, None);
        assert_eq!(snapshot.signers.len(), 1);
    }

    #[test]
    fn uppercase_or_short_hex_is_refused() {
        let uppercase = format!(r#"{{"kind":"ed25519","pubkey":"{}"}}"#, "AB".repeat(32));
        let err = serde_json::from_str::<SignerIdentityV2>(&uppercase).unwrap_err();
        assert!(err.to_string().contains("uppercase"), "{err}");
        let short = format!(r#"{{"kind":"ed25519","pubkey":"{}"}}"#, "a".repeat(63));
        let err = serde_json::from_str::<SignerIdentityV2>(&short).unwrap_err();
        assert!(err.to_string().contains("wrong length"), "{err}");
        let policy = format!(r#"{{"policy":"{}","threshold":1}}"#, "5".repeat(63));
        assert!(serde_json::from_str::<ThresholdObservation>(&policy).is_err());
    }

    #[test]
    fn confirmed_install_reason_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&BaselineReason::confirmed_install()).unwrap(),
            r#""confirmed_install""#
        );
        let back: BaselineReason = serde_json::from_str(r#""confirmed_install""#).unwrap();
        assert_eq!(back, BaselineReason::ConfirmedInstall);
    }

    // ── Version-2 validation ──────────────────────────────────────────────────

    fn assert_malformed_v2(snapshot: &SignerSetSnapshotV2, expected_reason: &str) {
        match compute_signer_set_digest_v2(snapshot) {
            Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 { reason }) => {
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected MalformedSnapshotV2, got {other:?}"),
        }
        match snapshot.validate() {
            Err(SignerSetCanonicalBodyError::MalformedSnapshotV2 { reason }) => {
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected MalformedSnapshotV2, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_signer_ids_are_malformed() {
        let snapshot = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(1, 0x11), ed25519_entry(1, 0x22)],
            threshold: None,
        };
        assert_malformed_v2(&snapshot, "duplicate signer id");
    }

    #[test]
    fn unsorted_signer_ids_are_malformed() {
        let snapshot = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(2, 0x11), ed25519_entry(1, 0x22)],
            threshold: None,
        };
        assert_malformed_v2(&snapshot, "signer ids are not in ascending order");
    }

    #[test]
    fn external_signer_with_empty_key_data_is_malformed() {
        let snapshot = SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::External {
                    verifier: [0x33; 32],
                    key_data_sha256: Sha256::digest([]).into(),
                    key_data_len: 0,
                },
            }],
            threshold: None,
        };
        assert_malformed_v2(&snapshot, "External signer with empty key data");
    }

    #[test]
    fn well_formed_vectors_validate() {
        assert!(vector_a().validate().is_ok());
        assert!(vector_b().validate().is_ok());
        let empty = SignerSetSnapshotV2 {
            signers: vec![],
            threshold: None,
        };
        assert!(empty.validate().is_ok());
        assert_eq!(empty.signer_count(), 0);
    }

    // ── Version-2 digest sensitivity ──────────────────────────────────────────

    fn external_of(snapshot: &mut SignerSetSnapshotV2) -> (&mut [u8; 32], &mut u32) {
        match &mut snapshot.signers[0].identity {
            SignerIdentityV2::External {
                key_data_sha256,
                key_data_len,
                ..
            } => (key_data_sha256, key_data_len),
            other => panic!("vector B's first signer is External, got {other:?}"),
        }
    }

    #[test]
    fn digest_changes_with_any_key_data_byte() {
        let base = digest_hex(&vector_b());
        for index in [0usize, 16, 39] {
            let mut key_data = vector_b_key_data();
            key_data[index] ^= 0x01;
            let mut snapshot = vector_b();
            *external_of(&mut snapshot).0 = Sha256::digest(&key_data).into();
            assert_ne!(digest_hex(&snapshot), base, "key-data byte {index}");
        }
    }

    #[test]
    fn digest_changes_with_key_data_len_alone() {
        let mut snapshot = vector_b();
        *external_of(&mut snapshot).1 = 41;
        assert_ne!(digest_hex(&snapshot), digest_hex(&vector_b()));
    }

    #[test]
    fn digest_changes_when_two_entries_swap_ids() {
        let base = vector_a();
        let swapped = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x22), ed25519_entry(1, 0x11)],
            threshold: None,
        };
        assert_ne!(digest_hex(&swapped), digest_hex(&base));
    }

    #[test]
    fn digest_changes_when_threshold_flips_between_none_and_some() {
        let mut with_threshold = vector_a();
        with_threshold.threshold = Some(ThresholdObservation {
            policy: [0x55; 32],
            threshold: 1,
        });
        assert_ne!(digest_hex(&with_threshold), digest_hex(&vector_a()));
        let mut without_threshold = vector_b();
        without_threshold.threshold = None;
        assert_ne!(digest_hex(&without_threshold), digest_hex(&vector_b()));
    }

    #[test]
    fn digest_changes_when_policy_changes_alone() {
        let mut snapshot = vector_b();
        if let Some(observation) = snapshot.threshold.as_mut() {
            observation.policy[31] ^= 0x01;
        }
        assert_ne!(digest_hex(&snapshot), digest_hex(&vector_b()));
    }

    // ── Version-2 display ─────────────────────────────────────────────────────

    #[test]
    fn external_debug_and_summary_never_print_whole_fields() {
        let verifier = [0x9au8; 32];
        let key_data_sha256: [u8; 32] = Sha256::digest(vector_b_key_data()).into();
        let identity = SignerIdentityV2::External {
            verifier,
            key_data_sha256,
            key_data_len: 40,
        };
        let full_verifier = crate::hex::encode(&verifier);
        let full_key_hash = crate::hex::encode(&key_data_sha256);
        for rendered in [format!("{identity:?}"), identity.summary()] {
            assert!(!rendered.contains(&full_verifier), "{rendered}");
            assert!(!rendered.contains(&full_key_hash), "{rendered}");
            assert!(rendered.contains(&full_verifier[..16]), "{rendered}");
            assert!(rendered.contains(&full_key_hash[..16]), "{rendered}");
        }
        assert_eq!(
            identity.summary(),
            format!("external:{}:{}", &full_verifier[..16], &full_key_hash[..16])
        );
        assert_eq!(
            SignerIdentityV2::DelegatedContract {
                contract: [0x44; 32]
            }
            .summary(),
            "delegated_contract:4444444444444444"
        );
    }

    // ── SignerSetView / SignerSetViewPayload ──────────────────────────────────

    #[test]
    fn view_reports_version_and_count() {
        let v2 = SignerSetView::V2(vector_b());
        assert_eq!(v2.version(), 2);
        assert_eq!(v2.signer_count(), 2);
        let v1 = SignerSetView::V1(ObservedSignerSet {
            signer_count: 3,
            threshold: 2,
            signer_ids: vec![0, 1, 2],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1; 32] },
                SignerPubkey::Ed25519 { pubkey: [2; 32] },
                SignerPubkey::Ed25519 { pubkey: [3; 32] },
            ],
        });
        assert_eq!(v1.version(), 1);
        assert_eq!(v1.signer_count(), 3);
        let json = serde_json::to_string(&v2).unwrap();
        assert!(json.starts_with(r#"{"version":"v2","#), "{json}");
    }

    #[test]
    fn into_v1_keeps_state_and_row_hash_and_refuses_v2() {
        let state = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [7; 32] }],
        };
        let payload = SignerSetViewPayload::new(
            SignerSetView::V1(state.clone()),
            [0xee; 32],
            4,
            "audit.jsonl".to_owned(),
        );
        assert_eq!(payload.line(), 4);
        assert_eq!(payload.file(), "audit.jsonl");
        let v1 = payload.into_v1().expect("a v1 view converts");
        assert_eq!(v1, SignerSetStatePayload::new(state, [0xee; 32]));

        let payload =
            SignerSetViewPayload::new(SignerSetView::V2(vector_a()), [0xee; 32], 2, "x".to_owned());
        assert!(payload.into_v1().is_none());
    }

    #[test]
    fn signer_set_view_display_v1_names_version_count_and_threshold() {
        let view = SignerSetView::V1(ObservedSignerSet {
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            ],
        });
        assert_eq!(view.to_string(), "v1 count=2 threshold=1");
    }

    #[test]
    fn signer_set_view_display_v2_renders_an_absent_threshold_as_none() {
        let mut snapshot = vector_a();
        snapshot.threshold = None;
        let count = snapshot.signer_count();
        assert_eq!(
            SignerSetView::V2(snapshot.clone()).to_string(),
            format!("v2 count={count} threshold=none")
        );
        snapshot.threshold = Some(ThresholdObservation {
            policy: [0x44; 32],
            threshold: 3,
        });
        let rendered = SignerSetView::V2(snapshot).to_string();
        assert_eq!(rendered, format!("v2 count={count} threshold=3"));
        assert!(
            !rendered.contains("4444"),
            "the policy id stays out of the display: {rendered}"
        );
    }
}
