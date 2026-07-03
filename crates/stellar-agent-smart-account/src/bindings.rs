//! OZ `stellar-accounts` v0.7.1 host-side typed bindings.
//!
//! Built from OZ `stellar-contracts` at SHA `3f81125` (tag `v0.7.1`).
//! The `vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm` artefact is
//! the unoptimised cdylib (17179 bytes — the WASM is small because
//! `stellar-accounts` is a contracts library with mostly events and UDT field
//! names, not a standalone deployable with executable function bodies)
//! retaining the full `contractspecv0` section (16 KB).
//!
//! # Type-binding strategy
//!
//! `soroban_sdk::contractimport!` fails to compile against the OZ
//! stellar-accounts WASM in a host `std` environment (rustc E0425 — `Context`
//! not in scope in `std` builds). The error is fundamental to any WASM whose
//! `contractspecv0` section includes a `__check_auth` signature.
//!
//! Exact rustc error:
//! ```text
//! error[E0425]: cannot find type `Context` in this scope
//!  --> src/lib.rs:2:1
//!   |
//! 2 | / soroban_sdk::contractimport!(
//! 3 | |     file = "...stellar_accounts.wasm"
//! 4 | | );
//!   | |_^ not found in this scope
//!   |
//! help: consider importing one of these items
//!   |
//! 2 + use soroban_sdk::auth::Context;
//! ```
//!
//! The macro generates a client struct that references `Context` unqualified
//! (from the `__check_auth` function signature in the WASM contractspec). In
//! a host `std` environment, `Context` is in scope only in WASM guest builds
//! where `soroban_sdk` re-exports it from the ambient prelude. In a host
//! build, the macro expansion fails because the generated type name has no
//! `use` import. This is a fundamental constraint of the macro when applied
//! to custom-account-contract WASMs that include `__check_auth` signatures,
//! regardless of whether `soroban-sdk/testutils` is enabled.
//!
//! The stellar-accounts crate IS the canonical source of these types in its
//! `lib` form (the `cdylib` form is the deployed contract). Re-exporting from
//! the Rust crate is semantically identical to what `contractimport!` would
//! generate — both produce types backed by the same XDR serialisation.
//!
//! # Supply-chain integrity
//!
//! The SHA-256 of the vendored WASM is verified in the unit test
//! `wasm_sha256_matches_provenance` below. This test fires on every
//! `cargo test` invocation, providing the supply-chain integrity gate.
//! The SHA-256 value is
//! pinned in TWO places (this file + `vendor/oz-stellar-accounts/v0.7.1/PROVENANCE.md`).
//! The integrity gate is reviewer attention plus the runtime test: a
//! substitution attack must update both the WASM bytes AND the `WASM_SHA256`
//! const in a single commit, which is detectable by reviewer attention to
//! either the binary diff (large diff stat for the `.wasm` file) or the const
//! update (a one-line text change adjacent to the `include_bytes!`).
//!
//! # Reference cross-check
//!
//! Type shapes MUST match:
//! - `packages/accounts/src/smart_account/storage.rs` `AuthPayload` at lines
//!   131-138 (SHA `3f81125`): `context_rule_ids: Vec<u32>`.
//! - `packages/accounts/src/smart_account/storage.rs` `Signer`, `ContextRule`
//!   at lines 152-174 (SHA `3f81125`).

/// SHA-256 of the vendored `stellar_accounts.wasm` artefact.
///
/// Pinned here, in `build.rs`, and in
/// `vendor/oz-stellar-accounts/v0.7.1/PROVENANCE.md` (same value in all
/// places). The compile-time integrity gate is `build.rs`; the runtime
/// `wasm_sha256_matches_provenance` test remains as defense in depth.
///
/// Built from OZ `stellar-contracts` at SHA `3f81125bed3114cc93f5fca6d13240082050269a`
/// (tag `v0.7.1`) via `stellar contract build --package stellar-accounts`
/// (stellar-cli 25.2.0), then copying the unoptimised cdylib from
/// `target/wasm32v1-none/release/deps/stellar_accounts.wasm`.
pub const WASM_SHA256: &str = "5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322";

/// The vendored `stellar_accounts.wasm` binary, embedded at compile time.
///
/// Embedded to ensure the sha256 check in `wasm_sha256_matches_provenance`
/// can verify the artefact on disk at `cargo test` time.
pub const WASM: &[u8] =
    include_bytes!("../../../vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm");

// Re-export the OZ stellar-accounts types that the off-chain orchestration
// layer uses for auth-entry construction. These types are re-exported
// from `stellar-accounts::smart_account` (which re-exports from its private
// `storage` module). The types are the SAME as what `contractimport!` would
// generate from the WASM spec — both are backed by the same XDR-encoded
// `#[contracttype]` layout.
//
// The `stellar-accounts` crate is the on-chain canonical source; the deployed
// WASM IS this crate compiled to `wasm32v1-none`. Off-chain code importing
// the types from the Rust crate gets byte-layout identity with the on-chain
// XDR encoding by construction (same `#[contracttype]` proc-macro, same
// stellar-xdr 25.x dependency chain).
pub use stellar_accounts::smart_account::{
    AuthPayload, ContextRule, ContextRuleEntry, ContextRuleType, Signer, SmartAccountError,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use sha2::{Digest as _, Sha256};

    use super::*;

    /// Verifies the sha256 of the vendored WASM matches the pinned constant.
    ///
    /// This is the supply-chain integrity gate. The check fires on every
    /// `cargo test` invocation.
    ///
    /// A WASM blob substitution will fail this test AND fail
    /// `vendor/oz-stellar-accounts/v0.7.1/PROVENANCE.md` cross-reference
    /// (the sha256 is pinned in both places).
    #[test]
    fn wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(WASM);
        let digest: [u8; 32] = hasher.finalize().into();
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, WASM_SHA256,
            "vendored stellar_accounts.wasm sha256 mismatch: \
             expected {WASM_SHA256}, got {actual}. \
             If the WASM was intentionally updated, regenerate via \
             vendor/oz-stellar-accounts/v0.7.1/build.sh and update both \
             WASM_SHA256 and PROVENANCE.md."
        );
    }

    /// Asserts the WASM magic bytes are present (sanity check for the artefact).
    #[test]
    fn wasm_has_correct_magic_bytes() {
        assert_eq!(
            &WASM[..4],
            b"\0asm",
            "vendored stellar_accounts.wasm does not start with WASM magic bytes"
        );
    }
}
