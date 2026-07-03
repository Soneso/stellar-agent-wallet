//! Unit tests for `session_rule_max_horizon_ledgers` profile-field bounds enforcement.
//!
//! # Purpose
//!
//! `ProfileLoadError::InvalidHorizonBound` is emitted by `Profile::load_from_path`
//! (and `load_with_overlay_from_dir`) when the TOML field
//! `session_rule_max_horizon_ledgers` exceeds `UPPER_BOUND_HORIZON_LEDGERS = 10_000`.
//!
//! This is a DoS-defence cap: an attacker who can edit the profile TOML cannot
//! force a ~4.3B-ledger horizon window by setting the field to `u32::MAX`.
//!
//! # Tests
//!
//! T-7a: Value `u32::MAX` (4,294,967,295) → `InvalidHorizonBound`.
//! T-7b: Value `10_001` (just above the bound) → `InvalidHorizonBound`.
//! T-7c: Value `10_000` (exactly the bound) → accepted.
//! T-7d: Value `1` (well within bounds) → accepted.
//! T-7e: Field absent → accepted (defaults to `None`).
//!
//! # Gating
//!
//! No feature flags required. Runs under default `cargo test`.
//!
//! ```text
//! cargo test -p stellar-agent-core --test profile_horizon_bound_test
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

/// Returns a minimal valid profile TOML with the `session_rule_max_horizon_ledgers`
/// field set to `horizon_value`.
///
/// Uses u64 to allow writing u32::MAX (4,294,967,295) without overflow.
fn toml_with_horizon(horizon_value: u64) -> String {
    format!(
        r#"version = 2
chain_id = "stellar:testnet"
session_rule_max_horizon_ledgers = {horizon_value}

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

/// Returns a minimal valid profile TOML WITHOUT the `session_rule_max_horizon_ledgers` field.
const TOML_WITHOUT_HORIZON: &str = r#"version = 2
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

/// Writes `content` to a temp file and returns `(file, path)`.
///
/// Caller must hold `_file` for the duration of the test (drop = delete).
fn write_temp_toml(content: &str) -> (tempfile::NamedTempFile, std::path::PathBuf) {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile::NamedTempFile must succeed");
    file.write_all(content.as_bytes())
        .expect("write_all must succeed");
    let path = file.path().to_owned();
    (file, path)
}

// ── T-7a: u32::MAX → InvalidHorizonBound ─────────────────────────────────────

/// T-7a: `session_rule_max_horizon_ledgers = 4294967295` (u32::MAX) is rejected
/// at profile-load time with `ProfileLoadError::InvalidHorizonBound`.
///
/// u32::MAX would permit a ~4.3B-ledger lookahead window, enabling a trivially
/// revocable session key that can sign for millennia. The bounds check prevents
/// this at profile-load, never reaching the manager layer.
#[test]
fn t7a_u32_max_horizon_rejected() {
    let toml = toml_with_horizon(u32::MAX as u64);
    let (_file, path) = write_temp_toml(&toml);

    let result = load_from_path("test-profile", &path, None);

    let err = result.expect_err("T-7a: u32::MAX horizon must be rejected");
    assert!(
        matches!(err, ProfileLoadError::InvalidHorizonBound { .. }),
        "T-7a: error must be InvalidHorizonBound; got: {err:?}"
    );

    if let ProfileLoadError::InvalidHorizonBound {
        ref name,
        value,
        upper_bound,
    } = err
    {
        assert_eq!(name, "test-profile", "T-7a: name must match");
        assert_eq!(value, u32::MAX, "T-7a: value must be u32::MAX");
        assert_eq!(upper_bound, 10_000, "T-7a: upper_bound must be 10,000");
    }

    let msg = err.to_string();
    assert!(
        msg.contains("10000") || msg.contains("10,000"),
        "T-7a: error message must reference upper_bound 10_000; got: {msg}"
    );
}

// ── T-7b: 10_001 → InvalidHorizonBound ───────────────────────────────────────

/// T-7b: `session_rule_max_horizon_ledgers = 10001` (just above the bound) is
/// rejected with `ProfileLoadError::InvalidHorizonBound`.
#[test]
fn t7b_just_above_bound_rejected() {
    let toml = toml_with_horizon(10_001);
    let (_file, path) = write_temp_toml(&toml);

    let result = load_from_path("test-profile", &path, None);

    let err = result.expect_err("T-7b: value 10_001 must be rejected");
    assert!(
        matches!(err, ProfileLoadError::InvalidHorizonBound { .. }),
        "T-7b: error must be InvalidHorizonBound; got: {err:?}"
    );
}

// ── T-7c: 10_000 → accepted (at the bound) ───────────────────────────────────

/// T-7c: `session_rule_max_horizon_ledgers = 10000` (exactly the bound) is accepted.
#[test]
fn t7c_exactly_at_bound_accepted() {
    let toml = toml_with_horizon(10_000);
    let (_file, path) = write_temp_toml(&toml);

    let profile = load_from_path("test-profile", &path, None)
        .expect("T-7c: value 10_000 must be accepted (exactly at bound)");

    assert_eq!(
        profile.session_rule_max_horizon_ledgers,
        Some(10_000),
        "T-7c: profile.session_rule_max_horizon_ledgers must be Some(10_000)"
    );
}

// ── T-7d: value 500 → accepted ───────────────────────────────────────────────

/// T-7d: `session_rule_max_horizon_ledgers = 500` (well within bounds) is accepted.
#[test]
fn t7d_small_value_accepted() {
    let toml = toml_with_horizon(500);
    let (_file, path) = write_temp_toml(&toml);

    let profile =
        load_from_path("test-profile", &path, None).expect("T-7d: value 500 must be accepted");

    assert_eq!(
        profile.session_rule_max_horizon_ledgers,
        Some(500),
        "T-7d: profile.session_rule_max_horizon_ledgers must be Some(500)"
    );
}

// ── T-7e: field absent → accepted (None) ─────────────────────────────────────

/// T-7e: A profile TOML without `session_rule_max_horizon_ledgers` is accepted;
/// the field defaults to `None` (callers use `DEFAULT_SESSION_RULE_HORIZON_LEDGERS`).
#[test]
fn t7e_field_absent_defaults_to_none() {
    let (_file, path) = write_temp_toml(TOML_WITHOUT_HORIZON);

    let profile = load_from_path("test-profile", &path, None)
        .expect("T-7e: profile without horizon field must be accepted");

    assert_eq!(
        profile.session_rule_max_horizon_ledgers, None,
        "T-7e: profile.session_rule_max_horizon_ledgers must be None when absent"
    );
}
