//! OZ `multisig-ed25519-verifier-example` v0.7.2 vendored WASM.
//!
//! Built from OZ `stellar-contracts` at SHA `a9c4216` (tag `v0.7.2`) via
//! `stellar contract build --package multisig-ed25519-verifier-example`
//! (stellar-cli 25.2.0). The resulting cdylib is the `release` profile output
//! (`target/wasm32v1-none/release/multisig_ed25519_verifier_example.wasm`)
//! — the deployable production contract, not a `contractimport!` artefact.
//!
//! # What this WASM does
//!
//! Soroban contract implementing the OZ `Verifier` trait (per
//! OZ `examples/multisig-smart-account/ed25519-verifier/src/contract.rs:14-70`
//! at SHA `a9c4216`) with three exported functions:
//!
//! - `verify(signature_payload: Bytes, key_data: BytesN<32>, sig_data: BytesN<64>)
//!     -> bool` — the Ed25519 signature-verification entry point. Unlike the
//!   WebAuthn verifier, `key_data` is exactly the raw 32-byte Ed25519 public
//!   key (no credential-id suffix), and `sig_data` is exactly the raw 64-byte
//!   Ed25519 signature (no XDR ceremony blob). `signature_payload` is verified
//!   as-is. The body delegates to `stellar_accounts::verifiers::ed25519::verify`
//!   (`packages/accounts/src/verifiers/ed25519.rs:31-40`, SHA `a9c4216`), which
//!   calls `e.crypto().ed25519_verify(public_key, signature_payload, signature)`
//!   — a standard Ed25519 verification with no additional hashing or wrapping.
//! - `canonicalize_key(key_data: BytesN<32>) -> Bytes` — returns the 32-byte
//!   key verbatim as `Bytes`; the Ed25519 public-key encoding is already
//!   canonical.
//! - `batch_canonicalize_key(keys_data: Vec<BytesN<32>>) -> Vec<Bytes>` — batch
//!   variant of `canonicalize_key`.
//!
//! # How the wallet uses it
//!
//! An Ed25519-backed `Signer::External(verifier, key_data)` in an installed
//! context rule names this verifier address; the 32-byte `key_data` is the
//! agent's raw Ed25519 public key. At signing time the smart-account's
//! `__check_auth` invokes `verify(signature_payload, key_data, sig_data)` where
//! `signature_payload` is the raw 32-byte `auth_digest`
//! (`packages/accounts/src/smart_account/storage.rs:346`, SHA `a9c4216`:
//! `sig_payload = auth_digest.to_bytes()`), and `sig_data` is the raw 64-byte
//! Ed25519 signature the agent produced over that digest. There is NO nested
//! host-level auth entry for an External signer (a Delegated signer instead
//! requires a separate `SorobanAuthorizationEntry` for its G-key at
//! `storage.rs:352-354`); possession is proven entirely inside the WASM-to-WASM
//! call to this verifier (`storage.rs:341-355`, SHA `a9c4216`).
//!
//! # Deployment model
//!
//! The verifier is deployed once per network via
//! `smart-account deploy-ed25519-verifier` and the contract-id is recorded in
//! wallet-local config (`~/.config/stellar-agent/networks.toml`). Subsequent
//! `smart-account signers add --signer-ed25519` invocations resolve the
//! verifier address from this config when `--verifier` is omitted.
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::ed25519_verifier_wasm_sha256_matches_provenance` below, on every
//! `cargo test`. The SHA-256 value is pinned in three places (this file,
//! `build.rs`, and `vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md`) plus the
//! `verifier_allowlist.rs` entry, and the CI vendored-wasm gate re-hashes the
//! in-repo WASM against PROVENANCE.md on every run.

/// SHA-256 of the vendored `multisig_ed25519_verifier_example.wasm` artefact.
///
/// Pinned here, in `build.rs`, in `verifier_allowlist.rs`, and in
/// `vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md` (same value in all places).
/// The compile-time integrity gate is `build.rs`; the runtime
/// `tests::ed25519_verifier_wasm_sha256_matches_provenance` test remains as
/// defense in depth.
///
/// Built from OZ `stellar-contracts` at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
/// (tag `v0.7.2`) via `stellar contract build --package multisig-ed25519-verifier-example`
/// (stellar-cli 25.2.0), then copying the release cdylib from
/// `target/wasm32v1-none/release/multisig_ed25519_verifier_example.wasm`.
pub const ED25519_VERIFIER_WASM_SHA256: &str =
    "ea13b07083a8275e7bade954e4ccc1827495f253c18dc06edcc49104c11fb725";

/// The vendored `multisig_ed25519_verifier_example.wasm` binary, embedded at
/// compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-ed25519-verifier`) can
/// upload the WASM via `UploadContractWasm` without re-fetching from disk at
/// runtime; the bytes are passed by reference to the deployment substrate.
pub const ED25519_VERIFIER_WASM: &[u8] = include_bytes!(
    "../../../vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm"
);

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Asserts that `SHA256(ED25519_VERIFIER_WASM)` matches the pinned
    /// `ED25519_VERIFIER_WASM_SHA256` const. Supply-chain integrity gate; fires
    /// on every `cargo test`.
    #[test]
    fn ed25519_verifier_wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(ED25519_VERIFIER_WASM);
        let digest: [u8; 32] = hasher.finalize().into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, ED25519_VERIFIER_WASM_SHA256,
            "vendored multisig_ed25519_verifier_example.wasm sha256 mismatch: \
             expected {ED25519_VERIFIER_WASM_SHA256}, got {actual}. \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-ed25519-verifier/v0.7.2/build.sh and update both \
             ED25519_VERIFIER_WASM_SHA256 and PROVENANCE.md."
        );
    }

    /// Asserts the embedded WASM starts with the WASM binary magic bytes
    /// `\0asm`.
    #[test]
    fn ed25519_verifier_wasm_has_correct_magic_bytes() {
        assert_eq!(
            &ED25519_VERIFIER_WASM[..4],
            b"\0asm",
            "ED25519_VERIFIER_WASM must start with WASM magic bytes"
        );
    }

    /// Asserts the embedded WASM byte length matches the value recorded in
    /// PROVENANCE.md.
    #[test]
    fn ed25519_verifier_wasm_size_matches_provenance() {
        assert_eq!(
            ED25519_VERIFIER_WASM.len(),
            1_972,
            "vendored WASM byte count must match the value recorded in \
             vendor/oz-ed25519-verifier/v0.7.2/PROVENANCE.md"
        );
    }
}
