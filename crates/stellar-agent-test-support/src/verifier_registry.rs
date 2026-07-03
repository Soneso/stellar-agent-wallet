//! Shared `VerifierRegistry`-isolation helpers for testnet acceptance tests.
//!
//! # Problem
//!
//! `VerifierRegistry::open()` (the default-path variant) stores entries keyed
//! by network passphrase in a single file. When two verifier deploys target
//! the same network inside one `cargo test` process, a per-network idempotency
//! shortcut fires on the second call and returns the first deploy's address
//! with `status="already_deployed"`, ignoring the new deployer keypair.
//!
//! # Solution
//!
//! Each call site that must produce a **distinct** deployed address passes
//! `registry_path_override: Some(<path>)` pointing at an isolated `TempDir`.
//! `fresh_verifier_registry_tempdir` creates that `(TempDir, PathBuf)` pair.
//!
//! # `verifier-registry` cargo feature
//!
//! This module is gated behind `#[cfg(feature = "verifier-registry")]` in
//! the crate `lib.rs`.  Consumer crates opt in via their `[dev-dependencies]`:
//!
//! ```toml
//! stellar-agent-test-support = { workspace = true, features = ["verifier-registry"] }
//! ```

#![allow(
    clippy::panic,
    reason = "test-helper constructors panic on tempdir-creation failure; acceptable in test-only code"
)]

use std::path::PathBuf;

/// Returns an isolated `(TempDir, PathBuf)` pair for use as a
/// `VerifierRegistry` override in a single `deploy_webauthn_verifier` call.
///
/// The `PathBuf` is `<tempdir>/networks.toml`; pass it as
/// `WebAuthnVerifierDeployArgs::registry_path_override: Some(<path>)`.
///
/// # Isolation contract
///
/// Each call site that deploys a **distinct** verifier contract on the same
/// network must receive its own `(TempDir, PathBuf)` pair from this function.
/// The per-network idempotency shortcut fires only within a single registry
/// file, so separate files eliminate cross-call collisions.
///
/// # Lifetime
///
/// The returned `TempDir` MUST be bound to a **named** (non-`_`) variable at
/// the call site.  Binding it to `_` drops it immediately (Rust drops
/// temporaries at the end of the statement), deleting the underlying directory
/// and every file in it before `deploy_webauthn_verifier` completes.
///
/// Correct (TempDir lives until end of function scope):
///
/// ```ignore
/// let (_reg_dir, reg_path) = fresh_verifier_registry_tempdir("my-label");
/// deploy_webauthn_verifier(WebAuthnVerifierDeployArgs {
///     registry_path_override: Some(reg_path),
///     // other fields elided
/// }).await?;
/// ```
///
/// Wrong (TempDir dropped immediately; deletes networks.toml before the
/// awaited `deploy_webauthn_verifier` completes):
///
/// ```ignore
/// let (_, reg_path) = fresh_verifier_registry_tempdir("my-label"); // BUG: bare `_` drops TempDir at end of let-statement
/// ```
///
/// # Panics
///
/// Panics if [`tempfile::tempdir`] fails.  In a testnet acceptance test,
/// tempdir-creation failure is a non-recoverable environment problem; a panic
/// with a descriptive message is the appropriate signal.
pub fn fresh_verifier_registry_tempdir(label: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("{label}: verifier-registry tempdir must succeed: {e}"));
    let path = dir.path().join("networks.toml");
    (dir, path)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn fresh_tempdir_returns_isolated_networks_toml_path() {
        let (dir, path) = fresh_verifier_registry_tempdir("unit");
        assert!(dir.path().is_dir(), "tempdir must exist");
        assert_eq!(path.file_name().unwrap(), "networks.toml");
        assert!(
            path.starts_with(dir.path()),
            "path must be inside the tempdir"
        );
    }

    #[test]
    fn two_calls_yield_distinct_directories() {
        let (d1, p1) = fresh_verifier_registry_tempdir("a");
        let (d2, p2) = fresh_verifier_registry_tempdir("b");
        assert_ne!(d1.path(), d2.path());
        assert_ne!(p1, p2);
    }
}
