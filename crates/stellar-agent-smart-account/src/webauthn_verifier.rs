//! OZ `multisig-webauthn-verifier-example` v0.7.2 vendored WASM.
//!
//! Built from OZ `stellar-contracts` at SHA `a9c4216` (tag `v0.7.2`) via
//! `stellar contract build --package multisig-webauthn-verifier-example`
//! (stellar-cli 25.2.0).  The resulting cdylib is the `release` profile output
//! (`target/wasm32v1-none/release/multisig_webauthn_verifier_example.wasm`)
//! — the deployable production contract, not a `contractimport!` artefact.
//! New verifier deployments use these v0.7.2 bytes; the ABI is unchanged from
//! v0.7.1, and verifier contracts already deployed on-chain from the v0.7.1 bytes
//! remain recognised via `VERIFIER_ALLOWLIST`.
//!
//! # What this WASM does
//!
//! Soroban contract implementing the OZ `Verifier` trait (per
//! OZ `examples/multisig-smart-account/webauthn-verifier/src/contract.rs:51-90`
//! at SHA `a9c4216`) with three exported functions:
//!
//! - `verify(signature_payload: Bytes, key_data: Bytes, sig_data: Bytes)
//!     -> bool` — the WebAuthn-2 P-256 assertion verification entry point.
//!   `key_data` is the concatenation of a 65-byte uncompressed-SEC1 P-256
//!   pubkey (`0x04 ‖ X ‖ Y`) and the variable-length credential_id (the
//!   suffix is unused inside `verify` and is stripped by `canonicalize_key`).
//!   `sig_data` is an XDR-encoded `WebAuthnSigData { authenticator_data,
//!   client_data_json, signature }` blob.  Implementation extracts the
//!   65-byte pubkey from `key_data`, decodes `sig_data` via `WebAuthnSigData::
//!   from_xdr`, then delegates to `stellar_accounts::verifiers::webauthn::
//!   verify` which validates `client_data.type == "webauthn.get"`, validates
//!   `client_data.challenge == base64url(signature_payload)`, validates the
//!   `UP` (and `UV` if required) flag bits in `authenticator_data`, and
//!   verifies the ECDSA-P-256 signature over
//!   `authenticator_data ‖ sha256(client_data_json)`.
//! - `canonicalize_key(key_data: Bytes) -> Bytes` — returns the 65-byte
//!   uncompressed-SEC1 P-256 pubkey prefix of `key_data`, stripping the
//!   credential_id suffix which is not part of the cryptographic identity.
//! - `batch_canonicalize_key(keys_data: Vec<Bytes>) -> Vec<Bytes>` — batch
//!   variant of `canonicalize_key`.
//!
//! The wallet uses the `verify` entry point indirectly: a passkey-backed
//! `Signer::External` in an installed context rule names the verifier address;
//! the smart-account's `__check_auth` invokes `verify(...)` against the
//! submitted assertion bytes.  The wallet does NOT call `verify` directly from
//! off-chain Rust — off-chain pre-verification uses `webauthn-rs`
//! (see `webauthn/pre_verifier.rs`).
//!
//! # Deployment model
//!
//! The verifier is deployed once per network and the contract-id is recorded
//! in wallet-local config.  Subsequent `smart-account rules create --signer-webauthn`
//! invocations populate `ContextRuleSignerInput::External::verifier` from this
//! config via `smart-account deploy-webauthn-verifier`.
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `tests::webauthn_verifier_wasm_sha256_matches_provenance` below.  This
//! test fires on every `cargo test` invocation, providing the supply-chain
//! integrity gate.  The SHA-256 value is pinned in TWO places (this file +
//! `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md`).  A substitution attack
//! must update both the WASM bytes AND the [`WEBAUTHN_VERIFIER_WASM_SHA256`]
//! const in a single commit, detectable by reviewer attention to either the
//! binary diff (large diff stat for the `.wasm` file) or the const update (a
//! one-line text change adjacent to the `include_bytes!`).
//!
//! A CI vendored-wasm-provenance gate adds a deterministic re-build
//! cross-check. Rust → WASM compilation is not always bit-identical across
//! `rustc` / `stellar-cli` patch-version drifts.
//!
//! # Reference cross-check
//!
//! - OZ `examples/multisig-smart-account/webauthn-verifier/src/contract.rs:51-90`
//!   (SHA `a9c4216`) — the contract whose WASM this constant embeds; defines
//!   the `Verifier` trait impl with `verify` / `canonicalize_key` /
//!   `batch_canonicalize_key`.
//! - OZ `packages/accounts/src/verifiers/webauthn.rs:151-163` (SHA `a9c4216`) —
//!   `validate_challenge`: the canonical binding from
//!   `client_data_json.challenge` (base64url-encoded) back to the 32-byte
//!   `signature_payload`.  Step 12 of the WebAuthn-2 verification procedure.
//! - OZ `packages/accounts/src/verifiers/webauthn.rs:302-355` (SHA `a9c4216`) —
//!   `verify`: the full verification body that the contract's `verify`
//!   delegates to; covers `validate_expected_type`, `validate_challenge`,
//!   flag-bit checks, the `authenticator_data ‖ sha256(client_data_json)`
//!   message-digest construction, and the ECDSA-P-256 signature check.
//!   The RP-ID-hash bytes at `authenticator_data[0..32]` are NOT explicitly
//!   re-validated by the verifier (no registered-RP-ID input); binding is
//!   implicit via the signature: a different RP-ID would yield a different
//!   `authenticator_data` and the signature would fail to verify against the
//!   registered pubkey.

/// SHA-256 of the vendored `multisig_webauthn_verifier_example.wasm` artefact.
///
/// Pinned here, in `build.rs`, and in
/// `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md` (same value in all
/// places). The compile-time integrity gate is `build.rs`; the runtime
/// `tests::webauthn_verifier_wasm_sha256_matches_provenance` test remains as
/// defense in depth.
///
/// Built from OZ `stellar-contracts` at SHA `a9c42169000638da937577f592ebf61a7a3c94ca`
/// (tag `v0.7.2`) via `stellar contract build --package multisig-webauthn-verifier-example`
/// (stellar-cli 25.2.0), then copying the release cdylib from
/// `target/wasm32v1-none/release/multisig_webauthn_verifier_example.wasm`.
pub const WEBAUTHN_VERIFIER_WASM_SHA256: &str =
    "9427e3dd71fb29115c6f0efdf2f703b32fec566b151421f991c3b4e248ebb1f7";

/// The vendored `multisig_webauthn_verifier_example.wasm` binary, embedded at
/// compile time.
///
/// Embedded so the deploy CLI (`smart-account deploy-webauthn-verifier`) can
/// upload the WASM via `UploadContractWasm` without re-fetching from disk at
/// runtime; the bytes are passed by reference to the deployment substrate.
/// Also ensures the SHA-256 check in
/// `tests::webauthn_verifier_wasm_sha256_matches_provenance` can verify the
/// artefact at `cargo test` time.
pub const WEBAUTHN_VERIFIER_WASM: &[u8] =
    include_bytes!("../vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm");

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Asserts that `SHA256(WEBAUTHN_VERIFIER_WASM)` matches the pinned
    /// `WEBAUTHN_VERIFIER_WASM_SHA256` const.
    ///
    /// This is the supply-chain integrity gate. The check fires on every
    /// `cargo test` invocation.
    ///
    /// A WASM blob substitution will fail this test AND fail
    /// `vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md` cross-reference (the
    /// sha256 is pinned in both places).
    #[test]
    fn webauthn_verifier_wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(WEBAUTHN_VERIFIER_WASM);
        let digest: [u8; 32] = hasher.finalize().into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, WEBAUTHN_VERIFIER_WASM_SHA256,
            "vendored multisig_webauthn_verifier_example.wasm sha256 mismatch: \
             expected {WEBAUTHN_VERIFIER_WASM_SHA256}, got {actual}. \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-webauthn-verifier/v0.7.2/build.sh and update both \
             WEBAUTHN_VERIFIER_WASM_SHA256 and PROVENANCE.md."
        );
    }

    /// Asserts the embedded WASM starts with the WASM binary magic bytes
    /// `\0asm`.
    #[test]
    fn webauthn_verifier_wasm_has_correct_magic_bytes() {
        assert_eq!(
            &WEBAUTHN_VERIFIER_WASM[..4],
            b"\0asm",
            "WEBAUTHN_VERIFIER_WASM must start with WASM magic bytes"
        );
    }

    /// Asserts the embedded WASM byte length matches the value recorded in
    /// the audit / provenance doc.  Adds an independent witness on top of the
    /// SHA pin: a deliberate truncation would fail this test even if the
    /// resulting bytes coincidentally hashed to the pin (cryptographically
    /// infeasible but the size check is a fast, obvious failure mode for an
    /// accidental truncation during re-vendor).
    #[test]
    fn webauthn_verifier_wasm_size_matches_provenance() {
        assert_eq!(
            WEBAUTHN_VERIFIER_WASM.len(),
            14_097,
            "vendored WASM byte count must match the value recorded in \
             vendor/oz-webauthn-verifier/v0.7.2/PROVENANCE.md"
        );
    }
}
