//! Audit-log payload value types for signer-set state tracking.
//!
//! Defines [`SignerPubkey`], [`ObservedSignerSet`], [`SignerSetStatePayload`],
//! and [`BaselineReason`] — the value types shared between the audit-log
//! substrate (this module) and the `SignersManager` smart-account wrappers.
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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Canonical-body error ──────────────────────────────────────────────────────

/// Error type for [`signer_pubkey_canonical_body`] and [`canonical_scaddress`].
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

/// Return value of [`super::reader::AuditReader::find_latest_signer_set_state`].
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

/// Reason class for [`super::schema::EventKind::SaSignerSetBaselined`] emissions.
///
/// Only two call sites may construct values:
/// - `SignersManager::refresh_signer_baseline` — programmatic re-baseline.
/// - `SignersManager::list_signers` — human-path first-observation bootstrap.
///
/// No other call site may construct this type, preserving the single-source
/// baseline invariant.
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
    /// The audit log had no prior signer-set row for this `(rule_id,
    /// smart_account)` pair; this baseline is the first recorded observation.
    ///
    /// Emitted by `SignersManager::list_signers` when the audit log is empty
    /// for this rule (human-path bootstrap).
    FirstObservation,

    /// An explicit re-baseline was requested.
    ///
    /// Emitted by `SignersManager::refresh_signer_baseline` on every call,
    /// regardless of whether a prior baseline exists. Used by automation paths
    /// after intentional out-of-band signer changes.
    ExplicitRefresh,
}

impl BaselineReason {
    /// Constructs a `FirstObservation` baseline reason.
    ///
    /// `pub` because the single-caller invariant is enforced by the repo-gate
    /// `check-no-direct-sasignersetbaselined-emit.sh`, not by Rust visibility.
    /// Only `SignersManager::list_signers` in `stellar-agent-smart-account` may
    /// produce this variant in production code; that crate is a separate
    /// compilation unit from `stellar-agent-core`, so `pub(crate)` would not
    /// compile.
    pub fn first_observation() -> Self {
        Self::FirstObservation
    }

    /// Constructs an `ExplicitRefresh` baseline reason.
    ///
    /// `pub` because the single-caller invariant is enforced by the repo-gate
    /// `check-no-direct-sasignersetbaselined-emit.sh`, not by Rust visibility.
    /// Only `SignersManager::refresh_signer_baseline` in
    /// `stellar-agent-smart-account` may produce this variant in production
    /// code; that crate is a separate compilation unit from `stellar-agent-core`,
    /// so `pub(crate)` would not compile.
    pub fn explicit_refresh() -> Self {
        Self::ExplicitRefresh
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // clippy::panic covers `panic!(...)` calls in structural match arms
    // (e.g. `other => panic!("expected X, got: {other:?}")`) and
    // `assert!(tamper_applied, ...)` in the tamper-detection test.
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
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
}
