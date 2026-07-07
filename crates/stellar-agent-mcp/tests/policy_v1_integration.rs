//! End-to-end integration test for PolicyEngineV1.
//!
//! Exercises the integration of:
//!
//! - [`stellar_agent_core::policy::v1::loader::load_signed_policy`]
//!   canonical-TOML + blake3 + ed25519 signature verification.
//! - [`stellar_agent_core::policy::v1::PolicyEngineV1`] construction
//!   from a verified document and the [`PolicyEngine::evaluate`] dispatch over
//!   first-match scope-resolved rules.
//! - [`WalletServer`] construction via `WalletServer::new` in
//!   production-shaped paths and `WalletServer::new_with_policy_dir_for_test`
//!   in policy-dir-isolated tests. Both internally call `build_policy_engine`
//!   to load the signed policy file and fetch the owner public key from the
//!   keyring.  Also covers the feature-gated
//!   [`WalletServer::set_policy_engine_for_test`] path for dispatch-gate testing.
//!
//! ## `build_policy_engine` tests
//!
//! `build_policy_engine` accepts a policy-directory override, so tests that
//! exercise this path use a per-test [`TempDir`] instead of the OS-conventional
//! `default_policy_dir()`.
//!
//! The mock-keyring install is process-global, so these tests are marked
//! `#[serial]` to prevent them from racing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::policy::v1::{
    PolicyEngineV1, canonical::canonical_bytes, loader::load_signed_policy, signature::digest,
};
use stellar_agent_core::policy::{
    Decision, DenyReason, McpToolRegistration, PolicyEngine, ToolDescriptor,
};
use stellar_agent_core::profile::schema::{PolicyConfig, PolicyEngineKind, Profile};
use stellar_agent_mcp::server::{StellarBalancesArgs, WalletServer};
use tempfile::TempDir;

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair, returning `(SigningKey, public_key_bytes)`.
fn fresh_keypair() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Computes the canonical bytes of `policy_body`, signs the BLAKE3 digest with
/// `sk`, and emits a complete signed TOML string with the `[signature]` table
/// appended.  `owner_id` is the operator-supplied G-strkey label echoed in
/// `[signature].owner_id`.
fn sign_policy_toml(policy_body: &str, sk: &SigningKey, owner_id: &str) -> String {
    let canon = canonical_bytes(policy_body).expect("canonical_bytes must succeed");
    let d = digest(&canon);
    let sig: [u8; 64] = sk.sign(&d).to_bytes();
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    format!("{policy_body}\n[signature]\nowner_id = \"{owner_id}\"\nsig = \"{sig_hex}\"\n")
}

/// Writes `content` to `<dir>/<name>` and returns the path.
fn write_policy_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write must succeed");
    path
}

/// Builds a `ToolDescriptor` for `stellar_balances` matching the registration
/// emitted by the `#[mcp_tool_item]` attribute (read-only, chain-id required).
fn balances_descriptor() -> ToolDescriptor {
    let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_balances",
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: true,
        value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    });
    td.chain_id = "stellar:testnet".to_owned();
    td
}

/// Builds the canonical args used for engine evaluation in every test.
fn balances_args_value() -> serde_json::Value {
    serde_json::json!({
        "chain_id": "stellar:testnet",
        "account_id": "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        "assets_count": 0,
    })
}

/// Builds a testnet `WalletServer` with its policy engine swapped for the
/// supplied [`PolicyEngineV1`].  Substitution uses the feature-gated
/// `set_policy_engine_for_test` helper.
fn make_server_with_v1_engine(engine: PolicyEngineV1) -> WalletServer {
    stellar_agent_test_support::keyring_mock::install().ok();
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1); the real V1 engine is
    // injected below via set_policy_engine_for_test.
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).expect("WalletServer::new must not fail");
    server.set_policy_engine_for_test(Arc::new(engine));
    server
}

/// Builds the canonical `stellar_balances` args used by every dispatch test.
fn balances_args() -> StellarBalancesArgs {
    StellarBalancesArgs {
        account_id: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
        chain_id: "stellar:testnet".to_owned(),
        assets: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-track tests: loader + engine + decision
// ─────────────────────────────────────────────────────────────────────────────

/// End-to-end: a signed `decision = "allow"` rule loads, verifies, and returns
/// `Decision::Allow` from the engine.
#[test]
#[serial]
fn signed_allow_rule_evaluates_to_allow() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "allow"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    assert!(
        document.signature.is_some(),
        "verified doc must carry signature"
    );

    let engine = PolicyEngineV1::new(document, "default".into());
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();
    let decision = engine
        .evaluate(
            &balances_descriptor(),
            &balances_args_value(),
            &profile,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("engine evaluation must not error");

    assert!(
        matches!(decision, Decision::Allow),
        "allow rule must produce Decision::Allow; got: {decision:?}"
    );
}

/// End-to-end: a signed `decision = "deny"` rule evaluates to
/// `Decision::Deny(DenyReason::ExplicitRuleDeny)`.
///
/// The TOML `decision = "deny"` parses as
/// `Decision::Deny(DenyReason::ExplicitRuleDeny)` (loader.rs `parse_decision`
/// distinguishes explicit rule denials from the default-deny fallback
/// `NoMatchingRule`).
#[test]
#[serial]
fn signed_deny_rule_evaluates_to_explicit_rule_deny() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "deny"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    let engine = PolicyEngineV1::new(document, "default".into());
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();

    let decision = engine
        .evaluate(
            &balances_descriptor(),
            &balances_args_value(),
            &profile,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("engine evaluation must not error");

    assert!(
        matches!(decision, Decision::Deny(DenyReason::ExplicitRuleDeny)),
        "deny rule must produce Decision::Deny(ExplicitRuleDeny); got: {decision:?}"
    );
}

/// End-to-end: a signed `decision = "require_approval"` rule produces
/// `Decision::RequireApproval(_)` with the loader's default 300-second TTL.
#[test]
#[serial]
fn signed_require_approval_rule_evaluates_to_require_approval() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "require_approval"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    let engine = PolicyEngineV1::new(document, "default".into());
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();

    let decision = engine
        .evaluate(
            &balances_descriptor(),
            &balances_args_value(),
            &profile,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("engine evaluation must not error");

    let req = match decision {
        Decision::RequireApproval(req) => req,
        other => panic!("require_approval rule must produce RequireApproval; got: {other:?}"),
    };
    // Loader's parse_decision injects a 300s default TTL when promoting the
    // `require_approval` keyword; nonce is empty until populated by the
    // dispatch site.
    assert_eq!(req.ttl_seconds, 300, "loader default TTL is 300");
}

/// End-to-end: an empty `[[rules]]` array hits the engine's default-deny
/// fallback (`DenyReason::NoMatchingRule`).
#[test]
#[serial]
fn empty_rules_default_deny_evaluates_to_no_matching_rule() {
    const BODY: &str = r#"version = 1
scope = "profile:default"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    let engine = PolicyEngineV1::new(document, "default".into());
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct").build();

    let decision = engine
        .evaluate(
            &balances_descriptor(),
            &balances_args_value(),
            &profile,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("engine evaluation must not error");

    assert!(
        matches!(decision, Decision::Deny(DenyReason::NoMatchingRule)),
        "default-deny path must produce Deny(NoMatchingRule); got: {decision:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader rejection paths
// ─────────────────────────────────────────────────────────────────────────────

/// Loader rejects a policy signed by one key when verified against another.
#[test]
#[serial]
fn wrong_owner_pubkey_rejects_signature() {
    const BODY: &str = r#"version = 1
scope = "profile:default"
"#;

    let (sk, _pk) = fresh_keypair();
    let (_sk2, pk_other) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let err = load_signed_policy(&path, "default", &pk_other)
        .expect_err("verification with wrong key must fail");
    use stellar_agent_core::policy::PolicyError;
    assert!(
        matches!(err, PolicyError::OwnerSignatureInvalid { ref profile } if profile == "default"),
        "wrong-key verification must produce OwnerSignatureInvalid; got: {err:?}"
    );
}

/// Loader rejects a policy whose body is mutated after signing.
#[test]
#[serial]
fn tampered_policy_body_rejects_signature() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "allow"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    // Flip "allow" → "deny" after signing — content + canonical bytes change,
    // but the signature was computed against the original.
    let tampered = signed.replace("decision = \"allow\"", "decision = \"deny\"");
    let path = write_policy_file(&dir, "default.toml", &tampered);

    let err = load_signed_policy(&path, "default", &pk)
        .expect_err("tampered body must fail signature verification");
    use stellar_agent_core::policy::PolicyError;
    assert!(
        matches!(err, PolicyError::OwnerSignatureInvalid { ref profile } if profile == "default"),
        "tampered body must produce OwnerSignatureInvalid; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch-gate wiring: gate routes engine decisions to wire codes
// ─────────────────────────────────────────────────────────────────────────────

/// End-to-end: a signed `decision = "deny"` rule produces the
/// `policy.deny.explicit_rule_deny` wire code when routed through the
/// `WalletServer` dispatch gate.
///
/// This test wires the V1 engine through to the actual MCP-handler entry
/// point (`call_stellar_balances`), so it validates the full engine → loader →
/// dispatch-gate → wire-format chain — not just a mocked dispatch arm.
#[tokio::test]
#[serial]
async fn dispatch_gate_routes_v1_deny_to_wire_code() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "deny"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    // Engine carries profile_name "default" — but PolicyEngineV1::evaluate
    // resolves scope against `self.profile_name`.  The loader's scope was
    // `profile:default`, so we must construct the engine with the same name
    // for the rule to match.
    let engine = PolicyEngineV1::new(document, "default".into());
    let server = make_server_with_v1_engine(engine);

    let result = server
        .call_stellar_balances(balances_args())
        .await
        .expect("Decision::Deny must return Ok(is_error) envelope");

    let (code, _message, _text) = common::assert_business_envelope(&result);
    let expected_wire_code = format!("policy.deny.{}", DenyReason::ExplicitRuleDeny.code());
    assert_eq!(
        code, expected_wire_code,
        "wire code must be {expected_wire_code}; got: {code}"
    );
}

/// End-to-end: a signed `decision = "require_approval"` rule is dispatched
/// correctly through the policy-engine gate.
///
/// `RequireApproval` on a simulate/read-only tool (such as `stellar_balances`)
/// is not an immediate error at the policy gate.  Instead, `dispatch_gate`
/// returns `Ok(DispatchOutcome::RequireApproval)` and the tool handler proceeds.
/// The `policy.approval_required` wire code only surfaces at the commit
/// step attestation gate (see `approval_spine_integration.rs` for commit-gate tests).
///
/// This test verifies that a `stellar_balances` call with a `require_approval`
/// policy rule does NOT produce `policy.approval_required` at the policy gate
/// — i.e. the call passes through `dispatch_gate` and reaches the RPC layer.
/// The RPC layer will fail because the test server uses the live Stellar testnet
/// endpoint and the test account `GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY`
/// may or may not exist; any error must come from the network/account level, not
/// from the policy gate.
#[tokio::test]
#[serial]
async fn dispatch_gate_routes_v1_require_approval_to_wire_code() {
    const BODY: &str = r#"version = 1
scope = "profile:default"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "require_approval"
"#;

    let (sk, pk) = fresh_keypair();
    let dir = TempDir::new().unwrap();
    let signed = sign_policy_toml(BODY, &sk, "GABCDE");
    let path = write_policy_file(&dir, "default.toml", &signed);

    let document = load_signed_policy(&path, "default", &pk).expect("policy must load");
    let engine = PolicyEngineV1::new(document, "default".into());
    let server = make_server_with_v1_engine(engine);

    // RequireApproval on a read-only simulate tool passes through dispatch_gate
    // (returns Ok(DispatchOutcome::RequireApproval)) rather than returning
    // policy.approval_required.  The call proceeds to the RPC layer.
    //
    // Accept any result: the test verifies only that the response does NOT carry
    // the policy.approval_required code (which would indicate the dispatch gate
    // is incorrectly denying at the policy gate).
    let result = server.call_stellar_balances(balances_args()).await;
    match result {
        Err(err) => {
            assert!(
                !err.message.contains("policy.approval_required"),
                "RequireApproval must NOT produce policy.approval_required at the \
                 dispatch gate for read-only tools; \
                 policy.approval_required is only emitted at commit-step \
                 attestation gates; got: {}",
                err.message
            );
        }
        Ok(tool_result) => {
            // Tool succeeded or produced a tool-level error (is_error=Some(true))
            // at the RPC layer (account not found, network error, etc.).
            // In either case, no policy.approval_required should be present.
            let json_text = tool_result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.as_str())
                .unwrap_or("");
            assert!(
                !json_text.contains("policy.approval_required"),
                "RequireApproval must NOT produce policy.approval_required at the \
                 dispatch gate for read-only tools; got: {json_text}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `build_policy_engine` path: WalletServer::new with PolicyEngineKind::V1
//
// The mock-keyring install is process-global, so all tests here are `#[serial]`.
// ─────────────────────────────────────────────────────────────────────────────

/// Collision-resistant profile-name prefix for the `build_policy_engine`
/// integration tests.
///
/// Each test appends a per-test suffix (e.g. `_happy_path`, `_missing_keyring`,
/// `_missing_policy`) so policy file paths and mock-keyring entries remain
/// disjoint.
const TEST_PROFILE_PREFIX: &str = "__stellar_agent_v1_integration_test";

/// Builds a `Profile` with `engine = PolicyEngineKind::V1` for the integration
/// tests.  `name` is the per-test suffix appended to [`TEST_PROFILE_PREFIX`];
/// the resulting profile-name (after `OWNER_KEY_SERVICE_PREFIX` strip in
/// `build_policy_engine`) is `<TEST_PROFILE_PREFIX>_<name>`.
///
/// Distinct names produce disjoint policy file paths and disjoint keyring
/// entries.
fn build_v1_profile(name: &str) -> Profile {
    let profile_account = format!("{TEST_PROFILE_PREFIX}_{name}");
    let mut policy = PolicyConfig::default();
    policy.engine = PolicyEngineKind::V1;
    Profile::builder_testnet(
        "stellar-agent-signer",
        &profile_account,
        "stellar-agent-nonce",
        &profile_account,
    )
    .policy(policy)
    .build()
}

/// Returns the test-local profile-name for the given suffix — same value
/// `build_policy_engine` will derive after stripping `OWNER_KEY_SERVICE_PREFIX`.
fn test_profile_name(suffix: &str) -> String {
    format!("{TEST_PROFILE_PREFIX}_{suffix}")
}

/// Returns the URL-safe base64-encoded (no padding) form of a 32-byte public key.
///
/// This matches the format stored by `stellar-agent policy sign` and expected
/// by `fetch_owner_pubkey_from_keyring` in `server.rs`.
fn encode_owner_pubkey(pk_bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk_bytes)
}

/// Installs the in-memory mock keyring and populates the
/// `stellar-agent-owner-<TEST_PROFILE_PREFIX>_<suffix>` / `"default"` entry
/// with `pk_bytes`.
///
/// `build_policy_engine` derives the profile name by stripping the
/// `"stellar-agent-owner-"` prefix from `policy_owner_key_id.service`.
fn install_owner_key_in_mock_keyring(suffix: &str, pk_bytes: &[u8; 32]) {
    stellar_agent_test_support::keyring_mock::install().expect("mock keyring install");
    use keyring_core::Entry;
    let service = format!("stellar-agent-owner-{}", test_profile_name(suffix));
    let entry = Entry::new(&service, "default").expect("keyring entry creation");
    entry
        .set_password(&encode_owner_pubkey(pk_bytes))
        .expect("keyring set_password");
}

/// End-to-end: server construction succeeds when a valid signed policy file is
/// present in the injected policy directory and the owner public key is in the
/// keyring.
///
/// This test exercises the full `build_policy_engine` → keyring read →
/// policy-file load → signature verify → `PolicyEngineV1::new` path inside the
/// test-only policy-dir constructor.
///
/// Uses suffix `"happy_path"` so the policy file path and keyring service are
/// disjoint from any operator-named profile and from the other two tests.
///
#[test]
#[serial]
fn build_policy_engine_v1_loads_signed_file_from_injected_policy_dir() {
    let suffix = "happy_path";
    let profile_name = test_profile_name(suffix);
    let (sk, pk) = fresh_keypair();

    let body = format!(
        r#"version = 1
scope = "profile:{profile_name}"

[[rules]]
match = {{ tool = "stellar_balances", chain = "*" }}
criteria = []
decision = "allow"
"#
    );
    let signed = sign_policy_toml(&body, &sk, "GABCDE");

    let policy_dir = TempDir::new().unwrap();
    let policy_filename = format!("{profile_name}.toml");
    write_policy_file(&policy_dir, &policy_filename, &signed);
    install_owner_key_in_mock_keyring(suffix, &pk);

    let profile = build_v1_profile(suffix);

    match WalletServer::new_with_policy_dir_for_test(profile, policy_dir.path()) {
        Ok(_) => {
            // Success — the full `build_policy_engine` path was exercised.
        }
        Err(e) => {
            panic!("WalletServer::new must succeed with valid policy + owner key; got: {e}");
        }
    }
}

/// Negative path: `WalletServer::new` returns `Err(BuildRegistryError::OwnerKeyAbsent)`
/// when the keyring entry for the owner public key is absent.
///
/// Uses suffix `"missing_keyring"` so the policy file written by this test is
/// disjoint from any operator-named profile and from the other two tests.
///
/// With the mock keyring holding no entries, `Entry::get_password` fails and
/// `build_policy_engine` returns `BuildRegistryError::OwnerKeyAbsent`.  The
/// test asserts on the error display string so it is resilient to minor
/// wording changes.
#[test]
#[serial]
fn build_policy_engine_v1_fails_when_owner_key_absent_from_keyring() {
    let suffix = "missing_keyring";
    let profile_name = test_profile_name(suffix);

    // Fresh mock keyring — no entries populated.
    stellar_agent_test_support::keyring_mock::install().expect("mock keyring install");

    // Write a valid policy file so we reach the keyring-absent branch (not a
    // missing-file branch).
    let (sk, _pk) = fresh_keypair();
    let body = format!(
        r#"version = 1
scope = "profile:{profile_name}"
"#
    );
    let signed = sign_policy_toml(&body, &sk, "GABCDE");
    let policy_dir = TempDir::new().unwrap();
    let policy_filename = format!("{profile_name}.toml");
    write_policy_file(&policy_dir, &policy_filename, &signed);

    let profile = build_v1_profile(suffix);

    match WalletServer::new_with_policy_dir_for_test(profile, policy_dir.path()) {
        Ok(_) => {
            panic!("WalletServer::new must fail when the owner key is absent from the keyring");
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("owner") || msg.contains("keyring") || msg.contains("key"),
                "error must mention owner key or keyring; got: {msg}"
            );
        }
    }
}

/// Negative path: `WalletServer::new` returns `Err(BuildRegistryError::PolicyFileLoadFailed)`
/// when the policy file is absent from the injected policy directory.
///
/// Uses suffix `"missing_policy"` so the file path checked by this test is
/// disjoint from the other tests.
#[test]
#[serial]
fn build_policy_engine_v1_fails_when_policy_file_absent() {
    let suffix = "missing_policy";
    let (_sk, pk) = fresh_keypair();
    install_owner_key_in_mock_keyring(suffix, &pk);

    let policy_dir = TempDir::new().unwrap();

    let profile = build_v1_profile(suffix);

    match WalletServer::new_with_policy_dir_for_test(profile, policy_dir.path()) {
        Ok(_) => {
            panic!("WalletServer::new must fail when the policy file is absent");
        }
        Err(e) => {
            let msg = e.to_string();
            // The error message from the load path mentions "policy" or "file".
            assert!(
                msg.contains("policy") || msg.contains("file") || msg.contains("load"),
                "error must mention policy or file; got: {msg}"
            );
        }
    }
}
