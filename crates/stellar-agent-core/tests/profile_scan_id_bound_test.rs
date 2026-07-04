//! Unit tests for `smart_account_max_context_rule_scan_id` profile-field bounds enforcement.
//!
//! # Purpose
//!
//! `ProfileLoadError::InvalidScanIdBound` is emitted by `Profile::load_from_path`
//! (and `load_with_overlay_from_dir`) when the TOML field
//! `smart_account_max_context_rule_scan_id` exceeds `UPPER_BOUND_MAX_SCAN_ID = 10_000`.
//!
//! This is a DoS-defence cap: an attacker who can edit the profile TOML cannot
//! force up to ~4.3B simulate calls by setting the field to `u32::MAX`.
//!
//! # Tests
//!
//! T-10a: Value `u32::MAX` (4,294,967,295) → `InvalidScanIdBound`.
//! T-10b: Value `10_001` (just above the bound) → `InvalidScanIdBound`.
//! T-10c: Value `10_000` (exactly the bound) → accepted.
//! T-10d: Value `1` (well within bounds) → accepted.
//! T-10e: Field absent → accepted (defaults to `None`).
//!
//! # Gating
//!
//! No feature flags required. Runs under default `cargo test`.
//!
//! ```text
//! cargo test -p stellar-agent-core --test profile_scan_id_bound_test
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::io::Write as _;
use stellar_agent_core::profile::loader::{ProfileLoadError, load_from_path};

// ── Helper ────────────────────────────────────────────────────────────────────

/// Minimal profile TOML boilerplate (all required fields).
///
/// Based on the `minimal_toml()` fixture in `src/profile/loader.rs` tests.
const MINIMAL_TOML_BASE: &str = r#"version = 2
chain_id = "stellar:testnet"

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test-profile"
account = "default"

[policy]
engine = "v1"
"#;

/// Returns a minimal valid profile TOML with the `smart_account_max_context_rule_scan_id`
/// field set to `scan_id_value`.
///
/// Uses u64 to allow writing u32::MAX (4,294,967,295) without overflow.
/// The field is placed before any `[section]` headers to ensure it is parsed as
/// a top-level field (TOML: key-value pairs after a section header belong to that section).
fn toml_with_scan_id(scan_id_value: u64) -> String {
    format!(
        r#"version = 2
chain_id = "stellar:testnet"
smart_account_max_context_rule_scan_id = {scan_id_value}

[mcp_signer_default]
service = "stellar-agent-signer"
account = "test"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce"
account = "test"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-test-profile"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-test-profile"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-test-profile"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-test-profile"
account = "default"

[policy]
engine = "v1"
"#
    )
}

/// Returns a minimal valid profile TOML WITHOUT the `smart_account_max_context_rule_scan_id` field.
fn toml_without_scan_id() -> &'static str {
    MINIMAL_TOML_BASE
}

/// Writes `content` to a temp file and returns `(file, path, tempdir)`.
///
/// Caller must hold `tempdir` for the duration of the test (drop = delete).
fn write_temp_toml(content: &str) -> (tempfile::NamedTempFile, std::path::PathBuf) {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile::NamedTempFile must succeed");
    file.write_all(content.as_bytes())
        .expect("write_all must succeed");
    let path = file.path().to_owned();
    (file, path)
}

// ── T-10a: u32::MAX → InvalidScanIdBound ─────────────────────────────────────

/// T-10a: `smart_account_max_context_rule_scan_id = 4294967295` (u32::MAX) is
/// rejected at profile-load time with `ProfileLoadError::InvalidScanIdBound`.
///
/// u32::MAX would cause ~4.3B simulate calls per `smart-account list-rules` invocation.
/// The bounds check prevents this at profile-load, never reaching the manager layer.
#[test]
fn t10a_u32_max_scan_id_rejected() {
    let toml = toml_with_scan_id(u32::MAX as u64);
    let (_file, path) = write_temp_toml(&toml);

    let result = load_from_path("test-profile", &path, None);

    let err = result.expect_err("T-10a: u32::MAX scan_id must be rejected");
    assert!(
        matches!(err, ProfileLoadError::InvalidScanIdBound { .. }),
        "T-10a: error must be InvalidScanIdBound; got: {err:?}"
    );

    if let ProfileLoadError::InvalidScanIdBound {
        ref name,
        value,
        upper_bound,
    } = err
    {
        assert_eq!(name, "test-profile", "T-10a: name must match");
        assert_eq!(value, u32::MAX, "T-10a: value must be u32::MAX");
        assert_eq!(upper_bound, 10_000, "T-10a: upper_bound must be 10,000");
    }

    let msg = err.to_string();
    assert!(
        msg.contains("10000") || msg.contains("10,000"),
        "T-10a: error message must reference upper_bound 10_000; got: {msg}"
    );
}

// ── T-10b: 10_001 → InvalidScanIdBound ───────────────────────────────────────

/// T-10b: `smart_account_max_context_rule_scan_id = 10001` (just above the bound)
/// is rejected with `ProfileLoadError::InvalidScanIdBound`.
#[test]
fn t10b_just_above_bound_rejected() {
    let toml = toml_with_scan_id(10_001);
    let (_file, path) = write_temp_toml(&toml);

    let result = load_from_path("test-profile", &path, None);

    let err = result.expect_err("T-10b: value 10_001 must be rejected");
    assert!(
        matches!(err, ProfileLoadError::InvalidScanIdBound { .. }),
        "T-10b: error must be InvalidScanIdBound; got: {err:?}"
    );
}

// ── T-10c: 10_000 → accepted (at the bound) ──────────────────────────────────

/// T-10c: `smart_account_max_context_rule_scan_id = 10000` (exactly the bound)
/// is accepted.
#[test]
fn t10c_exactly_at_bound_accepted() {
    let toml = toml_with_scan_id(10_000);
    let (_file, path) = write_temp_toml(&toml);

    let profile = load_from_path("test-profile", &path, None)
        .expect("T-10c: value 10_000 must be accepted (exactly at bound)");

    assert_eq!(
        profile.smart_account_max_context_rule_scan_id,
        Some(10_000),
        "T-10c: profile.smart_account_max_context_rule_scan_id must be Some(10_000)"
    );
}

// ── T-10d: value 1 → accepted ────────────────────────────────────────────────

/// T-10d: `smart_account_max_context_rule_scan_id = 1` (well within bounds)
/// is accepted.
#[test]
fn t10d_small_value_accepted() {
    let toml = toml_with_scan_id(1);
    let (_file, path) = write_temp_toml(&toml);

    let profile =
        load_from_path("test-profile", &path, None).expect("T-10d: value 1 must be accepted");

    assert_eq!(
        profile.smart_account_max_context_rule_scan_id,
        Some(1),
        "T-10d: profile.smart_account_max_context_rule_scan_id must be Some(1)"
    );
}

// ── T-10e: field absent → accepted (None) ────────────────────────────────────

/// T-10e: A profile TOML without `smart_account_max_context_rule_scan_id` is
/// accepted; the field defaults to `None`.
#[test]
fn t10e_field_absent_defaults_to_none() {
    let toml = toml_without_scan_id();
    let (_file, path) = write_temp_toml(toml);

    let profile = load_from_path("test-profile", &path, None)
        .expect("T-10e: profile without scan_id field must be accepted");

    assert_eq!(
        profile.smart_account_max_context_rule_scan_id, None,
        "T-10e: profile.smart_account_max_context_rule_scan_id must be None when absent"
    );
}
