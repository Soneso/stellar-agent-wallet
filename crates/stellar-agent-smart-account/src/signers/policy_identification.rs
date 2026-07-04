//! Threshold-policy wasm-hash allowlist and vendored WASM bytes.
//!
//! Provides [`THRESHOLD_POLICY_WASM_HASHES`] — the compile-time allowlist of
//! audited threshold-policy wasm SHA-256 hashes — and `THRESHOLD_POLICY_WASM`
//! — the vendored WASM bytes embedded at compile time.
//!
//! The allowlist currently contains a single entry: the OZ
//! `multisig-threshold-policy-example` v0.7.1 canonical hash built from
//! OpenZeppelin `stellar-contracts` at SHA
//! `3f81125bed3114cc93f5fca6d13240082050269a` (tag `v0.7.1`).
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::vendored_wasm_hash_matches_allowlist_entry` below.  This test
//! fires on every `cargo test` invocation, providing the supply-chain integrity
//! gate.  The SHA-256
//! value is pinned in TWO places (this file + `vendor/oz-threshold-policy/
//! v0.7.1/PROVENANCE.md`).  A substitution attack must update both the WASM
//! bytes and the PROVENANCE.md to defeat the gate; the secondary defence is
//! the compile-time hash const here and the per-PR CI vendored-wasm-provenance gate.
//!
//! # Policy identification
//!
//! `SignersManager::identify_threshold_policy` fetches the wasm-hash
//! of each `Address` in the rule's `policies: Vec<Address>` via batched
//! `getLedgerEntries` and matches against this allowlist.  Single-match is
//! required; zero or multi-match returns a typed error (fail-closed).
//!
//! # Per-rule wasm-hash drift
//!
//! Advisory: the current implementation accepts any hash in
//! `THRESHOLD_POLICY_WASM_HASHES` at identification time and logs every
//! observed hash at `debug!`.  Per-rule hash drift is promoted to a typed
//! error by the verifier-wasm-hash-pinning enforcement layer.
//!
/// SHA-256 allowlist for audited threshold-policy WASM deployments.
///
/// Each entry is a 32-byte raw SHA-256 digest (the same value extracted from
/// `PROVENANCE.md` by the CI provenance gate and the same value
/// `sha2::Sha256::digest(THRESHOLD_POLICY_WASM)` must produce).
///
/// # Allowlist (single entry)
///
/// - Index 0: OZ `multisig-threshold-policy-example` v0.7.1.
///   Built from OpenZeppelin `stellar-contracts` at SHA
///   `3f81125bed3114cc93f5fca6d13240082050269a` (tag `v0.7.1`) via
///   `stellar contract build --package multisig-threshold-policy-example`
///   (stellar-cli 25.2.0, rustc 1.94.0 stable, wasm32v1-none target).
///   PROVENANCE.md: `vendor/oz-threshold-policy/v0.7.1/PROVENANCE.md`.
///   Build script: `vendor/oz-threshold-policy/v0.7.1/build.sh`.
///   OZ source: `examples/multisig-smart-account/threshold-policy/src/contract.rs`
///   at SHA `3f81125`.
///
/// # Extension
///
/// Append a new entry here when a new audited policy deployment is created.
/// Each addition requires an operator-authorised PR with an updated
/// `PROVENANCE.md` and a corresponding `vendor/` artefact.
///
pub const THRESHOLD_POLICY_WASM_HASHES: &[[u8; 32]] = &[
    // OZ multisig-threshold-policy-example v0.7.1.
    // SHA-256: 43c48790b83fbe283e139f881aa091198c4df554022aa10c12d9ca484edf0702
    // OZ SHA: 3f81125bed3114cc93f5fca6d13240082050269a (tag v0.7.1)
    // Build: stellar contract build --package multisig-threshold-policy-example
    //        stellar-cli 25.2.0, rustc 1.94.0 stable, wasm32v1-none
    // PROVENANCE: vendor/oz-threshold-policy/v0.7.1/PROVENANCE.md
    [
        0x43, 0xc4, 0x87, 0x90, 0xb8, 0x3f, 0xbe, 0x28, 0x3e, 0x13, 0x9f, 0x88, 0x1a, 0xa0, 0x91,
        0x19, 0x8c, 0x4d, 0xf5, 0x54, 0x02, 0x2a, 0xa1, 0x0c, 0x12, 0xd9, 0xca, 0x48, 0x4e, 0xdf,
        0x07, 0x02,
    ],
];

/// The vendored `multisig_threshold_policy_example.wasm` binary, embedded at
/// compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-threshold-policy`) can upload
/// the WASM via `UploadContractWasm` without re-fetching from disk at runtime.
/// Also ensures the SHA-256 check in
/// `tests::vendored_wasm_hash_matches_allowlist_entry` can verify the
/// artefact at `cargo test` time.
///
/// # Provenance
///
/// Built from OpenZeppelin `stellar-contracts` at SHA
/// `3f81125bed3114cc93f5fca6d13240082050269a` (tag `v0.7.1`) via
/// `stellar contract build --package multisig-threshold-policy-example`
/// (stellar-cli 25.2.0, rustc 1.94.0 stable, wasm32v1-none target).
///
/// Supply-chain integrity: `sha2::Sha256::digest(THRESHOLD_POLICY_WASM)`
/// must equal `THRESHOLD_POLICY_WASM_HASHES[0]` — verified by
/// `tests::vendored_wasm_hash_matches_allowlist_entry`.
///
// Path is relative to THIS FILE (`src/signers/policy_identification.rs`),
// per Rust `include_bytes!` semantics — NOT the crate root or workspace root.
// Resolves to `<repo-root>/vendor/oz-threshold-policy/
// v0.7.1/multisig_threshold_policy_example.wasm`.
#[cfg(any(test, feature = "deploy-cli", feature = "testnet-integration"))]
pub const THRESHOLD_POLICY_WASM: &[u8] = include_bytes!(
    "../../../../vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm"
);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Asserts that `SHA256(THRESHOLD_POLICY_WASM)` matches
    /// `THRESHOLD_POLICY_WASM_HASHES[0]`.
    ///
    /// This is the supply-chain integrity gate.  The check fires on every
    /// `cargo test` invocation.
    ///
    /// A WASM blob substitution will fail this test AND fail
    /// `vendor/oz-threshold-policy/v0.7.1/PROVENANCE.md` cross-reference (the
    /// sha256 is pinned in both places, verified at CI time by the
    /// vendored-wasm-provenance CI gate).
    #[test]
    fn vendored_wasm_hash_matches_allowlist_entry() {
        let digest: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();
        assert_eq!(
            digest, THRESHOLD_POLICY_WASM_HASHES[0],
            "vendored multisig_threshold_policy_example.wasm sha256 mismatch: \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-threshold-policy/v0.7.1/build.sh and update both \
             THRESHOLD_POLICY_WASM_HASHES[0] and PROVENANCE.md."
        );
    }

    /// Asserts that the allowlist has at least one entry.
    ///
    /// An empty allowlist would cause `identify_threshold_policy`
    /// to always fail with `ThresholdPolicyIdentificationFailed`, silently
    /// disabling the threshold-policy enforcement path.
    #[test]
    fn allowlist_is_non_empty() {
        assert!(
            !THRESHOLD_POLICY_WASM_HASHES.is_empty(),
            "THRESHOLD_POLICY_WASM_HASHES must contain at least one entry"
        );
    }
}
