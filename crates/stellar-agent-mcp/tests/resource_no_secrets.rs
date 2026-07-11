//! Runtime resource-content secret-scan gate.
//!
//! Calls every registered MCP-resource generator function and asserts that the
//! output contains no secret-shaped bytes.  Runs the same detection patterns as
//! `.github/scripts/check-mcp-resources-no-secrets.sh` so that even dynamically
//! generated resource content is covered.
//!
//! Coverage policy: both static `mcp-resources/` files (CI script) and runtime
//! generator output (this test) must pass the scan.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only; static regex and fixture construction; panics acceptable"
)]

use stellar_agent_mcp::server::usage_md_content;
use stellar_agent_test_support::assert_no_secret_bytes;

#[test]
fn usage_md_no_secret_bytes() {
    let content = usage_md_content();
    assert_no_secret_bytes(content.as_bytes());
}

#[test]
fn usage_md_no_keyring_service_names() {
    let content = usage_md_content();
    // Keyring service-name patterns.
    assert!(
        !content.contains("stellar-agent-signer-"),
        "usage.md must not contain keyring signer service names"
    );
    assert!(
        !content.contains("stellar-agent-nonce-"),
        "usage.md must not contain keyring nonce service names"
    );
    assert!(
        !content.contains("stellar-agent-profile-"),
        "usage.md must not contain keyring profile service names"
    );
}

#[test]
fn usage_md_no_profile_paths() {
    let content = usage_md_content();
    // Profile-file path patterns, matching the canonical data-root shapes
    // the wallet actually derives per platform.
    assert!(
        !content.contains(".local/share/stellar-agent"),
        "usage.md must not contain Linux profile state directory paths"
    );
    assert!(
        !content.contains("Application Support/Soneso.stellar-agent"),
        "usage.md must not contain macOS profile state directory paths"
    );
    assert!(
        !content.contains("stellar-agent\\"),
        "usage.md must not contain Windows profile state directory paths"
    );
}

#[test]
fn usage_md_no_hmac_key_shapes() {
    use regex_lite::Regex;

    let content = usage_md_content();
    // HMAC-key detection: base64-encoded string ≥32 chars adjacent to key-shape
    // word.
    let re = Regex::new(
        r"(?i)(secret|key|seed|mnemonic|password|nonce_key|hmac).{0,80}[A-Za-z0-9+/]{32,}={0,2}",
    )
    .expect("static regex is valid");
    assert!(
        !re.is_match(&content),
        "usage.md must not contain HMAC-key-adjacent base64 patterns"
    );
}
