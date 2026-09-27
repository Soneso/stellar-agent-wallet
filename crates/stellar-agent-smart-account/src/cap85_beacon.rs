//! Vendored CAP-85 executable-reference beacon Wasm (test infrastructure).
//!
//! The beacon owns executable-reference entries, deploys contracts whose
//! executable is an external reference to itself, and repoints those entries.
//! The CAP-85 testnet acceptance suites upload it to prove the wallet's
//! handling of owner-managed executables; no production path deploys or
//! invokes it, so the module compiles only under `test-helpers` and in this
//! crate's own unit-test build, where the digest test runs.
//!
//! Source: `contracts/cap85-beacon/` at the repository root. Build record and
//! rebuild steps: `vendor/cap85-beacon/v0.1.0/REFERENCE.md`.

/// SHA-256 of [`CAP85_BEACON_WASM`], as 64-char lowercase hex.
///
/// Equal to the `cap85_beacon.wasm` row of `WASM_PINS` in `build.rs`, which
/// fails the build on a mismatch, and to the digest in
/// `vendor/cap85-beacon/v0.1.0/REFERENCE.md`.
pub const CAP85_BEACON_WASM_SHA256: &str =
    "b3495f664a6c6a3bf52daf0089f3790670b2033d78e02a53f0fa765521e51813";

/// The vendored `cap85_beacon.wasm` binary, embedded at compile time so an
/// acceptance suite can upload it without reading the vendor directory.
pub const CAP85_BEACON_WASM: &[u8] =
    include_bytes!("../vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm");

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    /// The embedded bytes hash to the pinned digest.
    #[test]
    fn cap85_beacon_wasm_sha256_matches_reference() {
        let digest: [u8; 32] = Sha256::digest(CAP85_BEACON_WASM).into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, CAP85_BEACON_WASM_SHA256,
            "vendored cap85_beacon.wasm sha256 mismatch; rebuild with \
             vendor/cap85-beacon/v0.1.0/build.sh and update the pins it names"
        );
    }

    /// The embedded bytes are a Wasm module (magic `\0asm`, version 1).
    #[test]
    fn cap85_beacon_wasm_has_wasm_header() {
        assert_eq!(&CAP85_BEACON_WASM[..8], b"\0asm\x01\0\0\0");
    }
}
