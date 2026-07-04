//! Verifier wasm-hash identification substrate.
//!
//! Provides `VERIFIER_WASM_FIXTURE` — the vendored WASM bytes embedded at
//! compile time for supply-chain integrity verification and deploy-CLI upload.
//!
//! The compile-time allowlist of audited verifier wasm SHA-256 hashes is
//! `crate::VERIFIER_ALLOWLIST` (`crates/stellar-agent-smart-account/src/verifier_allowlist.rs`),
//! populated with audit-status taxonomy
//! (`VerifierAuditStatus`: `Audited` / `Unaudited` / `Revoked` / `Retired`).
//! This is the canonical allowlist source.
//! Use `VERIFIER_ALLOWLIST[i].wasm_hash` to access the raw hash bytes.
//!
//! The allowlist's canonical entry (index 0) is the OZ
//! `multisig-webauthn-verifier-example` v0.7.2 hash built from
//! OpenZeppelin `stellar-contracts` at SHA
//! `a9c42169000638da937577f592ebf61a7a3c94ca` (tag `v0.7.2`) — the hash new
//! verifier deployments upload. Index 1 is the v0.7.1 hash, still recognised for
//! verifier contracts already deployed on-chain (the ABI is unchanged).
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::vendored_wasm_hash_matches_allowlist_entry` below.  This test
//! fires on every `cargo test` invocation, providing a supply-chain integrity
//! gate.  The SHA-256 value is pinned
//! in TWO places (the `VERIFIER_ALLOWLIST` const in `verifier_allowlist.rs` +
//! `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md`).  A substitution attack
//! must update both the WASM bytes and the PROVENANCE.md to defeat the gate;
//! the secondary defence is the per-PR CI vendored-wasm-provenance gate.
//!
//! Note the pinned PROVENANCE path below is the v0.7.2 artefact.
//!
//! # Verifier identification
//!
//! `SignersManager::identify_verifier` fetches the wasm-hash of a deployed
//! verifier contract via batched `getLedgerEntries` on BOTH RPCs in parallel
//! (two-RPC consultation) and matches against [`crate::VERIFIER_ALLOWLIST`].
//! Single-match is required; zero-match returns
//! [`crate::SaError::VerifierWasmNotInAllowlist`] (fail-closed).
//!
//! # Per-rule wasm-hash drift
//!
//! Per-rule hash drift is promoted to a typed error
//! [`crate::SaError::VerifierHashDrift`] on every signing operation that
//! references a pinned verifier.
//!
/// The vendored `multisig_webauthn_verifier_example.wasm` binary, embedded at
/// compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-webauthn-verifier`) can upload
/// the WASM via `UploadContractWasm` without re-fetching from disk at runtime,
/// and so the SHA-256 check in
/// `tests::vendored_wasm_hash_matches_allowlist_entry` can verify the
/// artefact at `cargo test` time.
///
/// # Provenance
///
/// Built from OpenZeppelin `stellar-contracts` at SHA
/// `a9c42169000638da937577f592ebf61a7a3c94ca` (tag `v0.7.2`) via
/// `stellar contract build --package multisig-webauthn-verifier-example`
/// (stellar-cli 25.2.0, rustc 1.96.0 stable, wasm32v1-none target).
///
/// Supply-chain integrity: `sha2::Sha256::digest(VERIFIER_WASM_FIXTURE)`
/// must equal `crate::VERIFIER_ALLOWLIST[0].wasm_hash` — verified by
/// `tests::vendored_wasm_hash_matches_allowlist_entry`.
///
// Path is relative to THIS FILE (`src/signers/verifier_identification.rs`),
// per Rust `include_bytes!` semantics — NOT the crate root or workspace root.
// Resolves to `<repo-root>/vendor/oz-webauthn-verifier/
// v0.7.2/multisig_webauthn_verifier_example.wasm`.
#[cfg(any(test, feature = "deploy-cli"))]
pub const VERIFIER_WASM_FIXTURE: &[u8] = include_bytes!(
    "../../../../vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm"
);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::VERIFIER_ALLOWLIST;

    /// Asserts that `SHA256(VERIFIER_WASM_FIXTURE)` matches
    /// `VERIFIER_ALLOWLIST[0].wasm_hash`.
    ///
    /// This is the supply-chain integrity gate.  The check fires on every
    /// `cargo test` invocation.
    ///
    /// A WASM blob substitution will fail this test AND fail the
    /// `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md` cross-reference (the
    /// SHA-256 is pinned in both places, verified at CI time by the
    /// vendored-wasm-provenance CI gate).
    ///
    /// # Hard-coded OZ canonical hash
    ///
    /// The expected digest is the OZ multisig-webauthn-verifier-example v0.7.2
    /// wasm hash verbatim from `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md`:
    /// `9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7`
    /// (OZ source SHA `a9c42169000638da937577f592ebf61a7a3c94ca`, tag v0.7.2).
    /// Asserted against BOTH the computed digest AND `VERIFIER_ALLOWLIST[0].wasm_hash`
    /// so a mismatch in either direction is caught.
    #[test]
    fn vendored_wasm_hash_matches_allowlist_entry() {
        // Hard-coded canonical hash per vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md.
        // OZ source SHA: a9c42169000638da937577f592ebf61a7a3c94ca (tag v0.7.2).
        let canonical: [u8; 32] = [
            0x94, 0x27, 0xe3, 0xdd, 0x71, 0xfb, 0x29, 0x11, 0x5c, 0x6f, 0x0e, 0xfd, 0xf2, 0xf7,
            0x03, 0xb3, 0x2f, 0xec, 0x56, 0x6b, 0x15, 0x14, 0x21, 0xf9, 0x91, 0xc3, 0xb4, 0xe2,
            0x48, 0xeb, 0xb1, 0xf7,
        ];
        let digest: [u8; 32] = Sha256::digest(VERIFIER_WASM_FIXTURE).into();
        assert_eq!(
            digest, canonical,
            "vendored multisig_webauthn_verifier_example.wasm sha256 mismatch against \
             PROVENANCE.md canonical: if the WASM was intentionally updated, regenerate via \
             vendor/oz-webauthn-verifier/v0.7.2/build.sh and update VERIFIER_ALLOWLIST[0].wasm_hash \
             and PROVENANCE.md."
        );
        // Cross-check: VERIFIER_ALLOWLIST[0].wasm_hash must equal the canonical v0.7.2 hash.
        assert_eq!(
            VERIFIER_ALLOWLIST[0].wasm_hash, canonical,
            "VERIFIER_ALLOWLIST[0].wasm_hash does not match the canonical OZ v0.7.2 hash; \
             update verifier_allowlist.rs to match PROVENANCE.md."
        );
    }

    /// Asserts that the allowlist has at least one entry.
    ///
    /// An empty allowlist would cause `identify_verifier` to always fail with
    /// `SaError::VerifierWasmNotInAllowlist`, silently disabling the
    /// verifier-identification enforcement path.
    #[test]
    fn allowlist_is_non_empty() {
        assert!(
            !VERIFIER_ALLOWLIST.is_empty(),
            "VERIFIER_ALLOWLIST must contain at least one entry"
        );
    }

    /// Asserts that the allowlist contains no duplicate entries.
    ///
    /// Duplicate entries are benign for correctness but indicate a build-time
    /// mistake (the same hash pasted twice, or a mis-merged conflict).  A
    /// closed-set gate prevents silent drift.
    #[test]
    fn allowlist_has_no_duplicates() {
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for entry in VERIFIER_ALLOWLIST {
            assert!(
                !seen.contains(&entry.wasm_hash),
                "VERIFIER_ALLOWLIST contains duplicate entry: {:?}",
                entry
                    .wasm_hash
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            seen.push(entry.wasm_hash);
        }
    }
}
