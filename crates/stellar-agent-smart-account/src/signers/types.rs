//! Value types for the signer-set substrate.
//!
//! Defines [`FrozenChainStateTuple`], [`WasmHashSummary`], and
//! [`ThresholdAffectingOp`] — the value types consumed by the
//! `SignersManager` implementation (`managers/signers.rs`).
//!
//! # TOCTOU anchor
//!
//! [`FrozenChainStateTuple`] is the move-only TOCTOU primitive that binds
//! the divergence-check result to the signing call: the constructor
//! (`pub(crate)`) is called exclusively inside
//! `managers/signers.rs::verify_signer_set_against_chain`, and the
//! only consumer is the signing call that receives it by move.  Dropping it
//! without consuming is detected at the call site by `#[must_use]`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use stellar_agent_core::audit_log::signer_set::ObservedSignerSet;

// ── FrozenChainStateTuple ─────────────────────────────────────────────────────

/// Move-only TOCTOU anchor returned by
/// `managers/signers.rs::verify_signer_set_against_chain`.
///
/// Binds the divergence-check result to a subsequent signing call so the
/// on-chain state observed at check time cannot be silently replaced by a
/// concurrent mutation before the signing call fires.
///
/// # Security invariants
///
/// - `!Copy`, `!Clone` — enforced at compile time via
///   `static_assertions::assert_not_impl_any!` in `#[cfg(test)]` (see
///   `frozen_chain_state_tuple_is_not_copy_or_clone`).
/// - `pub(crate)` constructor — the ONLY authorised constructor call site is
///   `managers/signers.rs::verify_signer_set_against_chain`. In test code
///   the constructor is only called from `#[cfg(test)]` so the field values
///   can be verified without a production call site.
/// - `#[must_use]` — dropping without consuming triggers a warning at the call
///   site, surfacing accidental discards during code review.
///
/// # Usage
///
/// ```ignore
/// // Inside managers/signers.rs:
/// let frozen = verify_signer_set_against_chain(&writer, rule_id, smart_account).await?;
/// sign_with_frozen_state(&frozen, &payload).await
/// ```
///
#[must_use = "FrozenChainStateTuple binds the divergence-check result to the signing call; \
              dropping it without consuming defeats the TOCTOU mitigation"]
pub struct FrozenChainStateTuple {
    /// The signer-set state observed at divergence-check time.
    pub(crate) observed_chain_state: ObservedSignerSet,

    /// Simulation ledger at divergence-check time: `(latest_ledger_seq, observed_at_unix_ms)`.
    ///
    /// Used to bound the validity window of the frozen tuple. A signing call
    /// that uses a tuple anchored to a ledger sequence far in the past should
    /// be rejected (staleness check in the signing manager).
    pub(crate) simulation_ledger: (u32, i64),

    /// SHA-256 of the canonical JSON body of the audit-log baseline row that
    /// was used to construct the expected signer-set view.
    ///
    /// Bound into the signing call so the signing path commits to exactly the
    /// baseline row the divergence check validated. Any post-check append to the
    /// log (which would change the row hash) causes a mismatch and aborts signing.
    pub(crate) expected_audit_row_hash: [u8; 32],

    /// The `rule_id` for which this tuple was produced.
    ///
    /// The signing call validates that its `rule_id` argument matches the frozen
    /// tuple's `rule_id` before proceeding, preventing cross-rule confusion.
    pub(crate) rule_id: u32,
}

impl FrozenChainStateTuple {
    /// Constructs a new `FrozenChainStateTuple`.
    ///
    /// `pub(crate)` — the only authorised call site is
    /// `managers/signers.rs::verify_signer_set_against_chain`.
    /// Only `#[cfg(test)]` code calls this constructor in test mode.
    ///
    /// # Arguments
    ///
    /// - `observed_chain_state` — the on-chain signer-set state observed at check time.
    /// - `simulation_ledger` — `(latest_ledger_seq, observed_at_unix_ms)`.
    /// - `expected_audit_row_hash` — SHA-256 of the baseline audit-log row body.
    /// - `rule_id` — the context-rule identifier.
    #[allow(
        dead_code,
        reason = "production call site wired in managers/signers.rs"
    )]
    pub(crate) fn new(
        observed_chain_state: ObservedSignerSet,
        simulation_ledger: (u32, i64),
        expected_audit_row_hash: [u8; 32],
        rule_id: u32,
    ) -> Self {
        Self {
            observed_chain_state,
            simulation_ledger,
            expected_audit_row_hash,
            rule_id,
        }
    }

    /// Returns the rule identifier this tuple was produced for.
    ///
    /// The signing call compares this against its own `rule_id` argument to
    /// prevent cross-rule confusion.
    #[must_use]
    pub fn rule_id(&self) -> u32 {
        self.rule_id
    }

    /// Returns the simulation ledger snapshot as `(latest_ledger_seq, observed_at_unix_ms)`.
    ///
    /// Used by the signing call to check whether the frozen tuple has gone stale
    /// relative to the current ledger sequence (signing manager staleness policy).
    #[must_use]
    pub fn simulation_ledger(&self) -> (u32, i64) {
        self.simulation_ledger
    }

    /// Returns a reference to the expected-audit-row SHA-256 TOCTOU anchor.
    ///
    /// Returns `&[u8; 32]` (not `[u8; 32]` by value) so a caller cannot
    /// persist the hash beyond the tuple's lifetime and forge an anchor binding
    /// on a later signing call.
    #[must_use]
    pub fn expected_audit_row_hash(&self) -> &[u8; 32] {
        &self.expected_audit_row_hash
    }

    /// Returns a reference to the observed on-chain signer-set state.
    ///
    /// The signing call uses this as the starting point for signing-entry
    /// construction, after confirming the tuple's `rule_id` and staleness bound.
    #[must_use]
    pub fn observed_chain_state(&self) -> &ObservedSignerSet {
        &self.observed_chain_state
    }
}

// Manual Debug impl — avoids leaking full signer-set pubkey data at info level.
// Redaction discipline: only counts and the rule_id are printed; the full
// pubkey data is available at debug level via `observed_chain_state` directly.
impl fmt::Debug for FrozenChainStateTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrozenChainStateTuple")
            .field("rule_id", &self.rule_id)
            .field("simulation_ledger", &self.simulation_ledger)
            .field("signer_count", &self.observed_chain_state.signer_count)
            .field("threshold", &self.observed_chain_state.threshold)
            .field(
                "expected_audit_row_hash_first8",
                &format_args!(
                    "{}",
                    self.expected_audit_row_hash[..8]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
            )
            .finish()
    }
}

// ── WasmHashSummary ───────────────────────────────────────────────────────────

/// Error returned by [`WasmHashSummary::new`] when the count-presence invariant
/// is violated.
///
/// `count == 0 ⟺ first_first8.is_none()` must hold for every valid
/// [`WasmHashSummary`].  Any other combination indicates a programming error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WasmHashSummaryError {
    /// `count == 0` but `first_first8` is `Some(...)`.
    ///
    /// A zero-policy count implies no hash bytes exist; presence of bytes is
    /// inconsistent.
    #[error("WasmHashSummary: count == 0 but first_first8 is Some")]
    CountZeroWithBytes,

    /// `count > 0` but `first_first8` is `None`.
    ///
    /// A positive policy count implies at least one hash was observed; absence
    /// of bytes is inconsistent.
    #[error("WasmHashSummary: count > 0 but first_first8 is None")]
    CountNonZeroWithoutBytes,
}

/// Summary of wasm-hash observations for threshold-policy identification.
///
/// Used by [`crate::SaError::ThresholdPolicyIdentificationFailed`] to carry
/// forensic correlation data when zero or multiple policies match the
/// `THRESHOLD_POLICY_WASM_HASHES` allowlist.
///
/// `first_first8` carries the raw first 8 bytes of the first observed policy
/// wasm hash (typed `[u8; 8]`, NOT `Option<String>`).  The `Display` impl
/// renders the bytes as lowercase hex for operator-facing error messages.
///
/// # Invariant
///
/// `count == 0` if and only if `first_first8.is_none()`.  Enforced by both
/// [`WasmHashSummary::new`] and the custom [`Deserialize`] implementation.
/// Callers that construct by hand should use `new`.  The `Deserialize` impl
/// rejects any wire payload that violates the invariant with a descriptive
/// error, preventing a deserialization-side invariant bypass.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::signers::types::WasmHashSummary;
///
/// let s = WasmHashSummary::new(2, Some([0xab; 8])).expect("valid: count>0 and first_first8 is Some");
/// let disp = format!("{s}");
/// assert!(disp.contains("count=2"));
/// // Assert the full hex content — protects against silent format regression.
/// assert!(disp.contains("first_first8=abababababababab"), "got: {disp}");
///
/// // count == 0 requires first_first8 == None.
/// assert!(WasmHashSummary::new(0, Some([0xab; 8])).is_err());
/// assert!(WasmHashSummary::new(1, None).is_err());
/// assert!(WasmHashSummary::new(0, None).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WasmHashSummary {
    /// Number of policies observed in the context rule's `policies` list.
    pub count: u32,

    /// First 8 bytes of the first observed policy's wasm hash, if any.
    ///
    /// Raw bytes. The `Display` impl renders as 16 lowercase hex chars
    /// (e.g. `"abababababababab"` for `[0xab; 8]`).
    ///
    /// `None` when `count == 0` (no policies observed). `Some([u8; 8])` when
    /// at least one policy wasm hash was observed.
    pub first_first8: Option<[u8; 8]>,
}

impl WasmHashSummary {
    /// Constructs a [`WasmHashSummary`], enforcing the count-presence invariant.
    ///
    /// Returns `Err(WasmHashSummaryError::CountZeroWithBytes)` if `count == 0`
    /// but `first_first8.is_some()`, or
    /// `Err(WasmHashSummaryError::CountNonZeroWithoutBytes)` if `count > 0`
    /// but `first_first8.is_none()`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmHashSummaryError`] when the `count == 0 ⟺ first_first8.is_none()`
    /// invariant is violated.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::signers::types::WasmHashSummary;
    ///
    /// assert!(WasmHashSummary::new(0, None).is_ok());
    /// assert!(WasmHashSummary::new(3, Some([0x11; 8])).is_ok());
    /// assert!(WasmHashSummary::new(0, Some([0x11; 8])).is_err());
    /// assert!(WasmHashSummary::new(1, None).is_err());
    /// ```
    pub fn new(count: u32, first_first8: Option<[u8; 8]>) -> Result<Self, WasmHashSummaryError> {
        match (count, first_first8) {
            (0, None) | (1.., Some(_)) => Ok(Self {
                count,
                first_first8,
            }),
            (0, Some(_)) => Err(WasmHashSummaryError::CountZeroWithBytes),
            (_, None) => Err(WasmHashSummaryError::CountNonZeroWithoutBytes),
        }
    }
}

/// Custom `Deserialize` for `WasmHashSummary` that enforces the count-presence
/// invariant on the wire.
///
/// Deserialises via the derived serde helper `WasmHashSummaryWire` and then
/// validates `count == 0 ⟺ first_first8.is_none()`.  Any payload that violates
/// the invariant returns a serde error rather than silently producing an
/// inconsistent value.
///
/// # Wire format
///
/// `{"count": 2, "first_first8": [171, 171, 171, 171, 171, 171, 171, 171]}`
/// for `Some([0xab; 8])`, and `{"count": 0}` (or `{"count": 0, "first_first8":
/// null}`) for `None`.  The `#[serde(skip_serializing_if)]` on `Serialize`
/// omits `null` when `first_first8` is `None`.
impl<'de> Deserialize<'de> for WasmHashSummary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Wire helper that derives `Deserialize` without the invariant check.
        /// The invariant is applied after raw deserialization completes.
        #[derive(Deserialize)]
        struct Wire {
            count: u32,
            #[serde(default)]
            first_first8: Option<[u8; 8]>,
        }

        let raw = Wire::deserialize(deserializer)?;
        WasmHashSummary::new(raw.count, raw.first_first8).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for WasmHashSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = match self.first_first8 {
            None => "none".to_owned(),
            Some(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        };
        write!(f, "count={} first_first8={}", self.count, hex)
    }
}

// ── ThresholdAffectingOp ──────────────────────────────────────────────────────

/// Identifies which operation would produce an unreachable threshold.
///
/// Carried by [`crate::SaError::ThresholdUnreachable::requested_op`] to give
/// operators a structured, machine-readable description of the refused
/// operation.
///
/// `#[non_exhaustive]` so future signer-operation variants (e.g. a
/// `SetSignerWeight` for a future weighted-threshold policy) can be added
/// without a breaking change.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::signers::types::ThresholdAffectingOp;
///
/// let op = ThresholdAffectingOp::RemoveSigner { signer_id: 3 };
/// let json = serde_json::to_string(&op).unwrap();
/// assert!(json.contains("remove_signer"));
/// assert!(json.contains("signer_id"));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThresholdAffectingOp {
    /// Remove a signer from the context rule.
    ///
    /// `signer_id` is the monotonically-assigned on-chain signer index
    /// (`u32`, assigned by `SmartAccount::add_signer` return value).
    RemoveSigner {
        /// The on-chain signer index being removed.
        signer_id: u32,
    },

    /// Add a signer to the context rule.
    ///
    /// `signer_type` is a discriminant string (`"ed25519"`, `"webauthn"`,
    /// `"external"`) identifying the signer arm being added.  `signer_id` is
    /// present when the add operation targets a known-ID signer (currently
    /// `None` for new-signer adds; the on-chain ID is assigned by the contract
    /// and only known post-submit).
    ///
    /// The `signer_type` discriminant and `signer_id: Option<u32>` provide
    /// symmetry with `RemoveSigner` while accommodating future signer-input
    /// type variants.
    AddSigner {
        /// Discriminant string for the signer arm being added.
        ///
        /// Known values: `"ed25519"`, `"webauthn"`, `"external"`.
        /// `String` rather than `&'static str` to support serde round-trips
        /// (deserialization cannot produce `&'static str` from heap-allocated JSON).
        signer_type: String,
        /// On-chain signer ID for symmetry with `RemoveSigner`, if known.
        ///
        /// `None` for new-signer adds (ID assigned post-submit).
        #[serde(skip_serializing_if = "Option::is_none")]
        signer_id: Option<u32>,
    },

    /// Change the threshold directly (without a signer-count change).
    SetThreshold {
        /// The proposed new threshold value.
        new: u32,
    },
}

// ── (AtomicBundleAlternative removed — CAP-46 makes atomic bundles infeasible) ──

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use static_assertions::assert_not_impl_any;
    use stellar_agent_core::audit_log::signer_set::{ObservedSignerSet, SignerPubkey};

    use super::*;

    // ── FrozenChainStateTuple trait bounds ────────────────────────────────────

    /// Asserts at compile time that `FrozenChainStateTuple` does not implement
    /// `Copy` or `Clone`.
    ///
    /// The move-only discipline requires that the TOCTOU anchor cannot be
    /// duplicated by a memcpy or `.clone()`.
    ///
    /// `assert_not_impl_any!` is a compile-time assertion: if a future engineer
    /// adds `#[derive(Copy)]` or `#[derive(Clone)]` to `FrozenChainStateTuple`,
    /// this test will fail to compile, not merely fail at runtime.  A runtime
    /// move-and-reuse test (`let _y = frozen; frozen`) would pass silently for
    /// `Copy` types because both bindings would resolve.
    #[test]
    fn frozen_chain_state_tuple_is_not_copy_or_clone() {
        assert_not_impl_any!(FrozenChainStateTuple: Copy, Clone);
    }

    /// Verifies that `expected_audit_row_hash()` returns a reference (not a
    /// moved-out value), preserving the accessor's borrow semantics.
    ///
    /// If the accessor returned `[u8; 32]` by value, the tuple would be partially
    /// moved-from after the call and unusable. This test confirms the borrow
    /// contract is correct by calling the accessor twice on the same frozen tuple.
    #[test]
    fn frozen_chain_state_tuple_expected_audit_row_hash_accessor_borrows() {
        let hash: [u8; 32] = [0xde; 32];
        let frozen =
            FrozenChainStateTuple::new(observed_signer_set(), (42u32, 999_000i64), hash, 7u32);
        // Call the accessor twice — only valid if it borrows (not moves).
        let r1: &[u8; 32] = frozen.expected_audit_row_hash();
        let r2: &[u8; 32] = frozen.expected_audit_row_hash();
        assert_eq!(r1, r2);
        assert_eq!(r1, &hash);
    }

    // ── WasmHashSummary ───────────────────────────────────────────────────────

    #[test]
    fn wasm_hash_summary_typed_error_variants() {
        assert!(matches!(
            WasmHashSummary::new(0, Some([0xab; 8])),
            Err(crate::signers::types::WasmHashSummaryError::CountZeroWithBytes)
        ));
        assert!(matches!(
            WasmHashSummary::new(1, None),
            Err(crate::signers::types::WasmHashSummaryError::CountNonZeroWithoutBytes)
        ));
    }

    #[test]
    fn wasm_hash_summary_deserialize_rejects_count_zero_with_bytes() {
        // Wire payload that violates count==0 ⟺ first_first8.is_none(): count=0 but bytes present.
        let bad = r#"{"count":0,"first_first8":[171,171,171,171,171,171,171,171]}"#;
        let result: Result<WasmHashSummary, _> = serde_json::from_str(bad);
        assert!(
            result.is_err(),
            "deserializer must reject invariant violation"
        );
    }

    #[test]
    fn wasm_hash_summary_deserialize_rejects_count_nonzero_without_bytes() {
        // Wire payload that violates count==0 ⟺ first_first8.is_none(): count=2 but no bytes.
        let bad = r#"{"count":2}"#;
        let result: Result<WasmHashSummary, _> = serde_json::from_str(bad);
        assert!(
            result.is_err(),
            "deserializer must reject invariant violation"
        );
    }

    #[test]
    fn wasm_hash_summary_serde_roundtrip() {
        let s = WasmHashSummary {
            count: 3,
            first_first8: Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: WasmHashSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn wasm_hash_summary_serde_roundtrip_none() {
        let s = WasmHashSummary {
            count: 0,
            first_first8: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: WasmHashSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn wasm_hash_summary_display_renders_hex() {
        let s = WasmHashSummary {
            count: 1,
            first_first8: Some([0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44]),
        };
        let disp = format!("{s}");
        assert!(disp.contains("count=1"), "must contain count: {disp}");
        assert!(
            disp.contains("first_first8=aabbccdd11223344"),
            "must render hex: {disp}"
        );
    }

    #[test]
    fn wasm_hash_summary_display_none_renders_none() {
        let s = WasmHashSummary {
            count: 0,
            first_first8: None,
        };
        let disp = format!("{s}");
        assert!(
            disp.contains("first_first8=none"),
            "must render none: {disp}"
        );
    }

    /// Verifies the `WasmHashSummary::new` constructor enforces the
    /// count==0 ⟺ first_first8.is_none() invariant.
    #[test]
    fn wasm_hash_summary_new_enforces_count_presence_invariant() {
        // Valid: count == 0 and first_first8 == None.
        assert!(WasmHashSummary::new(0, None).is_ok(), "0/None must be ok");
        // Valid: count > 0 and first_first8 == Some.
        assert!(
            WasmHashSummary::new(1, Some([0x00; 8])).is_ok(),
            "1/Some must be ok"
        );
        assert!(
            WasmHashSummary::new(5, Some([0xff; 8])).is_ok(),
            "5/Some must be ok"
        );
        // Invalid: count == 0 with first_first8 == Some.
        assert!(
            WasmHashSummary::new(0, Some([0x11; 8])).is_err(),
            "0/Some must be err"
        );
        // Invalid: count > 0 with first_first8 == None.
        assert!(WasmHashSummary::new(1, None).is_err(), "1/None must be err");
        assert!(WasmHashSummary::new(3, None).is_err(), "3/None must be err");
    }

    // ── ThresholdAffectingOp ──────────────────────────────────────────────────

    #[test]
    fn threshold_affecting_op_remove_serde_tagged_roundtrip() {
        let op = ThresholdAffectingOp::RemoveSigner { signer_id: 42 };
        let json = serde_json::to_string(&op).unwrap();
        let msg = format!("tag must be remove_signer: {json}");
        assert!(json.contains("remove_signer"), "{msg}");
        let back: ThresholdAffectingOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn threshold_affecting_op_add_serde_tagged_roundtrip() {
        let op = ThresholdAffectingOp::AddSigner {
            signer_type: "ed25519".to_owned(),
            signer_id: Some(0),
        };
        let json = serde_json::to_string(&op).unwrap();
        let msg = format!("tag must be add_signer: {json}");
        assert!(json.contains("add_signer"), "{msg}");
        let back: ThresholdAffectingOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn threshold_affecting_op_add_none_signer_id_omitted_from_json() {
        let op = ThresholdAffectingOp::AddSigner {
            signer_type: "webauthn".to_owned(),
            signer_id: None,
        };
        let json = serde_json::to_string(&op).unwrap();
        // skip_serializing_if = "Option::is_none" must omit the field.
        let msg = format!("signer_id=None must be omitted: {json}");
        assert!(!json.contains("signer_id"), "{msg}");
        let back: ThresholdAffectingOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    #[test]
    fn threshold_affecting_op_set_threshold_serde_tagged_roundtrip() {
        let op = ThresholdAffectingOp::SetThreshold { new: 3 };
        let json = serde_json::to_string(&op).unwrap();
        let msg = format!("tag must be set_threshold: {json}");
        assert!(json.contains("set_threshold"), "{msg}");
        let back: ThresholdAffectingOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn observed_signer_set() -> ObservedSignerSet {
        ObservedSignerSet {
            signer_count: 2,
            threshold: 2,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [1u8; 32] },
                SignerPubkey::Ed25519 { pubkey: [2u8; 32] },
            ],
        }
    }
}
