//! Value types for the signer-set substrate.
//!
//! Defines [`FrozenChainStateTuple`] and [`ThresholdAffectingOp`], the
//! value types consumed by the
//! `SignersManager` implementation (`managers/signers.rs`).
//!
//! # Comparison record
//!
//! [`FrozenChainStateTuple`] is the move-only record of one standalone
//! signer-set comparison: the constructor (`pub(crate)`) is called only
//! inside `managers/signers.rs::verify_signer_set_against_chain`, the public
//! entry tests and live suites call. The submit path runs the same
//! comparison under the rule's lock for every rule a submission is signed
//! under and builds no tuple. Dropping one without reading it is detected at
//! the call site by `#[must_use]`.

use std::fmt;

use serde::{Deserialize, Serialize};

use stellar_agent_core::audit_log::signer_set::SignerSetView;

// ── FrozenChainStateTuple ─────────────────────────────────────────────────────

/// Move-only record of one standalone signer-set comparison, returned by
/// `managers/signers.rs::verify_signer_set_against_chain`.
///
/// It carries what the comparison matched: the observed view, the ledger
/// and wall-clock instant of the reads, the matched state row's hash and
/// the compared rule. It holds no lock.
///
/// # Security invariants
///
/// - `!Copy`, `!Clone`: enforced at compile time via
///   `static_assertions::assert_not_impl_any!` in `#[cfg(test)]` (see
///   `frozen_chain_state_tuple_is_not_copy_or_clone`).
/// - `pub(crate)` constructor: the only constructor call site is
///   `managers/signers.rs::verify_signer_set_against_chain`, the standalone
///   form of the submit path's comparison, which tests and live suites call
///   to inspect a comparison's result.
/// - `#[must_use]`: discarding the result of a comparison unread triggers a
///   warning at the call site.
///
/// # Usage
///
/// ```ignore
/// let frozen = signers_manager
///     .verify_signer_set_against_chain(smart_account, rule_id, None, request_id)
///     .await?;
/// assert_eq!(frozen.rule_id(), rule_id);
/// ```
///
#[must_use = "FrozenChainStateTuple is the result of a standalone comparison; read it or drop \
              it explicitly"]
pub struct FrozenChainStateTuple {
    /// The observed signer-set view, in the version of the state row it
    /// matched.
    pub(crate) observed_chain_state: SignerSetView,

    /// `(latest_ledger_seq, observed_at_unix_ms)`: the smallest
    /// `latestLedger` of the comparison's reads and the wall-clock instant
    /// the comparison completed.
    pub(crate) simulation_ledger: (u32, i64),

    /// SHA-256 of the canonical JSON body of the state row the observation
    /// matched.
    pub(crate) expected_audit_row_hash: [u8; 32],

    /// The compared rule.
    pub(crate) rule_id: u32,
}

impl FrozenChainStateTuple {
    /// Constructs a new `FrozenChainStateTuple`.
    ///
    /// `pub(crate)`: the only call site is
    /// `managers/signers.rs::verify_signer_set_against_chain`, the public
    /// entry tests and live suites call; in-crate tests construct one
    /// directly to check the accessors.
    ///
    /// # Arguments
    ///
    /// - `observed_chain_state`: the on-chain signer-set state observed at
    ///   check time, in the baseline's snapshot version.
    /// - `simulation_ledger` — `(latest_ledger_seq, observed_at_unix_ms)`.
    /// - `expected_audit_row_hash` — SHA-256 of the baseline audit-log row body.
    /// - `rule_id` — the context-rule identifier.
    pub(crate) fn new(
        observed_chain_state: SignerSetView,
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

    /// Returns the compared rule.
    #[must_use]
    pub fn rule_id(&self) -> u32 {
        self.rule_id
    }

    /// Returns `(latest_ledger_seq, observed_at_unix_ms)`: the smallest
    /// `latestLedger` of the comparison's reads and the wall-clock instant the
    /// comparison completed.
    #[must_use]
    pub fn simulation_ledger(&self) -> (u32, i64) {
        self.simulation_ledger
    }

    /// Returns the SHA-256 of the canonical JSON body of the state row the
    /// observation matched.
    #[must_use]
    pub fn expected_audit_row_hash(&self) -> &[u8; 32] {
        &self.expected_audit_row_hash
    }

    /// Returns the observed signer-set view, in the version of the state row
    /// it matched.
    #[must_use]
    pub fn observed_chain_state(&self) -> &SignerSetView {
        &self.observed_chain_state
    }
}

// Manual Debug impl: avoids leaking signer identities at info level.
// Redaction discipline: only the snapshot version, the signer count, the
// threshold and the rule_id are printed; the full identities are available
// through `observed_chain_state` directly.
impl fmt::Debug for FrozenChainStateTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let threshold = match &self.observed_chain_state {
            SignerSetView::V1(state) => Some(state.threshold),
            SignerSetView::V2(snapshot) => snapshot.threshold.as_ref().map(|t| t.threshold),
        };
        f.debug_struct("FrozenChainStateTuple")
            .field("rule_id", &self.rule_id)
            .field("simulation_ledger", &self.simulation_ledger)
            .field("snapshot_version", &self.observed_chain_state.version())
            .field("signer_count", &self.observed_chain_state.signer_count())
            .field("threshold", &threshold)
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

// ── ThresholdAffectingOp ──────────────────────────────────────────────────────

/// Identifies which operation would produce an unreachable threshold.
///
/// The post-operation invariant check selects the recovery hint of
/// [`crate::SaError::ThresholdUnreachable`] from it.
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
    /// `signer_type` is a discriminant string (`"ed25519"`, `"external"`,
    /// `"delegated_contract"`) identifying the kind of the signer being
    /// added, decoded from the signer itself; a passkey signer is
    /// `"external"`.  `signer_id` is
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
        /// Known values: `"ed25519"`, `"external"`, `"delegated_contract"`,
        /// and `"unknown"` for a kind this build does not name.
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

// ── PolicyIdentifiedKind ──────────────────────────────────────────────────────

/// Closed-set per-policy classification returned by
/// `SignersManager::classify_rule_policies`.
///
/// Unlike the signer-set observation's threshold-policy identification and
/// `identify_spending_limit_policy` (which fail closed when a rule's policies
/// do not resolve to the allowlisted contracts they require), this
/// classification is for
/// read-only observability: each policy address attached to a rule is
/// independently classified by its own on-chain wasm-hash, and an
/// unrecognised or unreachable hash degrades to `Unknown` rather than
/// failing the whole read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyIdentifiedKind {
    /// Wasm-hash matches an entry in `THRESHOLD_POLICY_WASM_HASHES`.
    Threshold,
    /// Wasm-hash matches the spending-limit-policy allowlist entry
    /// (`SPENDING_LIMIT_POLICY_WASM_SHA256`).
    SpendingLimit,
    /// Wasm-hash did not match any recognised policy allowlist, or could
    /// not be observed (RPC gap, non-wasm entry).
    Unknown,
}

impl fmt::Display for PolicyIdentifiedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Threshold => f.write_str("threshold"),
            Self::SpendingLimit => f.write_str("spending-limit"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use static_assertions::assert_not_impl_any;
    use stellar_agent_core::audit_log::signer_set::{
        ObservedSignerSet, SignerEntryV2, SignerIdentityV2, SignerPubkey, SignerSetSnapshotV2,
    };

    use super::*;

    // ── FrozenChainStateTuple trait bounds ────────────────────────────────────

    /// Asserts at compile time that `FrozenChainStateTuple` does not implement
    /// `Copy` or `Clone`.
    ///
    /// The move-only discipline requires that the comparison record cannot be
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
        let frozen = FrozenChainStateTuple::new(
            SignerSetView::V1(observed_signer_set()),
            (42u32, 999_000i64),
            hash,
            7u32,
        );
        // Call the accessor twice — only valid if it borrows (not moves).
        let r1: &[u8; 32] = frozen.expected_audit_row_hash();
        let r2: &[u8; 32] = frozen.expected_audit_row_hash();
        assert_eq!(r1, r2);
        assert_eq!(r1, &hash);
    }

    /// `Debug` prints the snapshot version, the signer count and the
    /// threshold of each version and never a signer identity.
    #[test]
    fn frozen_chain_state_tuple_debug_prints_version_count_and_threshold() {
        let v1 = FrozenChainStateTuple::new(
            SignerSetView::V1(observed_signer_set()),
            (42, 1),
            [0xde; 32],
            7,
        );
        let rendered = format!("{v1:?}");
        assert!(rendered.contains("snapshot_version: 1"), "{rendered}");
        assert!(rendered.contains("signer_count: 2"), "{rendered}");
        assert!(rendered.contains("threshold: Some(2)"), "{rendered}");

        let v2 = FrozenChainStateTuple::new(
            SignerSetView::V2(SignerSetSnapshotV2 {
                signers: vec![SignerEntryV2 {
                    id: 3,
                    identity: SignerIdentityV2::Ed25519 { pubkey: [0x5a; 32] },
                }],
                threshold: None,
            }),
            (43, 2),
            [0xde; 32],
            8,
        );
        let rendered = format!("{v2:?}");
        assert!(rendered.contains("snapshot_version: 2"), "{rendered}");
        assert!(rendered.contains("signer_count: 1"), "{rendered}");
        assert!(rendered.contains("threshold: None"), "{rendered}");
        assert!(!rendered.contains("5a5a"), "no identity bytes: {rendered}");
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

    #[test]
    fn policy_identified_kind_display_renders_wire_labels() {
        assert_eq!(PolicyIdentifiedKind::Threshold.to_string(), "threshold");
        assert_eq!(
            PolicyIdentifiedKind::SpendingLimit.to_string(),
            "spending-limit"
        );
        assert_eq!(PolicyIdentifiedKind::Unknown.to_string(), "unknown");
    }
}
