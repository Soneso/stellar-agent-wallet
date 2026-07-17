pub mod policy_mock;
pub mod v1_engine_mock;

use std::sync::OnceLock;

use rmcp::model::CallToolResult;

/// Fixed non-secret 32-byte value used as the audit chain-root HMAC key by
/// every test in a binary that calls [`install_test_audit_key`].
///
/// MUST be identical across every call within one test binary — see that
/// function's doc comment for why a per-call random key (the naive seeding
/// choice) breaks `AuditWriterRegistry`'s process-lifetime cache.
const TEST_AUDIT_KEY_BYTES: [u8; 32] = [0x37_u8; 32];

/// Per-process temp directory backing every `install_test_audit_key` call in
/// a test binary — created once, reused by every test. As a `static`, this
/// value is never dropped at process exit (Rust does not run destructors on
/// statics), so the directory is NOT deleted by this binding; it is left for
/// the OS temp-directory cleanup policy, same as any other leaked tempdir.
static TEST_AUDIT_LOG_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

/// Redirects `profile.audit_log_path` to a per-process temp directory and
/// seeds a fixed 32-byte audit chain-root HMAC key at the profile's
/// `audit_log_hash_chain_key_id` keyring coordinate, under the process-global
/// mock keyring store (`stellar_agent_test_support::keyring_mock::install`
/// must already be installed by the caller).
///
/// Every full commit/submit round-trip test needs this: `require_value_audit_writer`
/// refuses BEFORE the signer is loaded or the transaction is submitted unless
/// the profile's audit chain-root key is acquirable — mirrors
/// `install_test_nonce_key`'s per-test seeding pattern for the nonce mint's
/// HMAC key.
///
/// # Why a FIXED path and a FIXED key, not a fresh tempdir/random key per test
///
/// `AuditWriterRegistry` is a process-global cache keyed by profile name
/// (`stellar-agent-core::audit_log::writer`): the FIRST call for a given
/// profile name in this test binary's process pins the `(log_path, hmac_key)`
/// pair for every later call with that same profile name — a later call
/// presenting a different path or key fails closed
/// (`WriterError::PathMismatch` / `HmacKeyMismatch`), which this crate's
/// `require_value_audit_writer` maps to the SAME `audit.chain_key_unavailable`
/// refusal as a genuinely-missing key. Since every test built on
/// `testnet_profile_with_rpc`-style helpers shares the same signer account
/// (hence the same profile name), every test in one binary that reaches the
/// audit pre-flight MUST present the identical path and key regardless of
/// which test happens to run first under `#[serial]` — a per-test tempdir or
/// random key reproduces the exact registry collision this function exists to
/// avoid. Redirecting to a temp directory (rather than the real
/// `canonical_data_root()` default, which `default_audit_log_path_for` does
/// NOT gate behind `STELLAR_AGENT_HOME`) also keeps these tests from writing a
/// real file under the developer's or CI runner's actual home directory.
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn install_test_audit_key(profile: &mut stellar_agent_core::profile::schema::Profile) {
    use base64::Engine as _;

    let dir =
        TEST_AUDIT_LOG_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir for audit log"));
    profile.audit_log_path = dir
        .path()
        .join(format!("{}.jsonl", profile.mcp_signer_default.account));

    let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(TEST_AUDIT_KEY_BYTES);
    let coord = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coord.service, &coord.account)
        .expect("Entry::new for audit key")
        .set_password(&key_b64)
        .expect("set_password for audit key");
}

/// Asserts the shared business-error envelope invariants on a tool result and
/// returns `(code, message, full_text)` for further per-test assertions.
///
/// The normalised business-error wire contract is:
///
/// ```json
/// { "ok": false, "error": { "code": "...", "message": "..." }, "request_id": "..." }
/// ```
///
/// This checks `is_error == Some(true)`, `ok == false`, and a non-empty
/// `request_id`, then extracts `error.code` and `error.message`.
///
/// `request_id` is freshly minted per call and therefore intentionally excluded
/// from the returned tuple: indistinguishability comparisons across two refusals
/// must compare `(code, message)`, never the full JSON.
#[must_use]
#[allow(
    dead_code,
    reason = "shared across integration-test binaries; unused in some"
)]
pub fn assert_business_envelope(result: &CallToolResult) -> (String, String, String) {
    assert_eq!(
        result.is_error,
        Some(true),
        "business-error result must set is_error = true"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("business-error result must carry a text content block");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("business-error content must be JSON");
    assert_eq!(
        value["ok"],
        serde_json::json!(false),
        "business-error envelope must have ok:false: {value}"
    );
    assert!(
        value["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "business-error envelope must carry a non-empty request_id: {value}"
    );
    let code = value["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let message = value["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (code, message, text)
}
