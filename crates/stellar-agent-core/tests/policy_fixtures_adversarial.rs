//! Integration test driver for the adversarial policy fixture suite.
//!
//! # Fixture provenance
//!
//! Fixtures live at `<repo-root>/tests/policy-fixtures/adversarial/` and are
//! pairs of production-format policy TOML files plus JSON case-metadata files.
//!
//! - `<name>.toml` — plain policy document without a `[signature]` table.
//!   The driver signs it at runtime with a freshly generated ed25519 keypair
//!   so the TOML content itself never embeds key material.
//!
//! - `<name>.case.json` — case metadata describing the tool call, expected
//!   outcome, and any per-category driver hints (state_seed, mock_home_domain,
//!   load_signing_strategy).
//!
//! # Coverage
//!
//! Six adversarial categories:
//! 1. `per_tx_cap_boundary/` — per-transaction cap boundary values
//! 2. `per_period_rollover/` — rolling-window cap with pre-seeded state store
//! 3. `combinator_and_or/` — multi-criterion first-fail ordering
//! 4. `counterparty_lookalike/` — homoglyph + IDN + case-insensitive HOME_DOMAIN
//! 5. `null_source_account/` — null G-account vs G-allowlist
//! 6. `mutation_stale_key/` — load-time owner-signature verification
//!
//! # Scope
//!
//! Oracle-staleness and SEP-10 replay are not covered by this fixture suite.
//!
//! # Redaction discipline
//!
//! No secret key material is logged.  The ed25519 signing seeds generated during
//! test setup are ephemeral, wrapped in `Zeroizing` so their bytes are wiped on
//! drop, and discarded; only the public key bytes are passed to `load_signed_policy`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer;
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use zeroize::Zeroizing;

use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, load_signed_policy};
use stellar_agent_core::policy::v1::signature::digest;
use stellar_agent_core::policy::{Decision, PolicyEngine, ToolDescriptor};
use stellar_agent_core::profile::schema::Profile;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structs
// ─────────────────────────────────────────────────────────────────────────────

/// Root case metadata structure parsed from `<name>.case.json`.
#[derive(Debug, Deserialize)]
struct CaseMeta {
    test_kind: String,
    name: String,
    category: String,
    #[allow(dead_code)]
    description: String,

    // evaluate fields
    tool: Option<ToolMeta>,
    args: Option<Value>,
    profile_name: Option<String>,
    expected: Option<ExpectedMeta>,

    // per_period_rollover: prior state-store entries to seed before evaluation.
    // Each entry has an `offset_secs_ago` (how many seconds before now the
    // entry was recorded) and `amount_stroops`.
    state_seed: Option<Vec<StateSeedEntry>>,

    // counterparty_lookalike: mock HOME_DOMAIN value supplied to the engine.
    mock_home_domain: Option<String>,

    // home_domain_resolved: set of resolved home_domain strings to inject into
    // the engine as a MockCounterpartyCacheView.  When absent (None) the cache
    // is not wired (counterparty_cache = None), exercising the fail-closed path.
    mock_resolved_domains: Option<Vec<String>>,

    // load_failure fields
    load_signing_strategy: Option<String>,
    expected_load_ok: Option<bool>,
    expected_load_error: Option<String>,
    expected_load_wire_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolMeta {
    name: String,
    destructive_hint: bool,
    read_only_hint: bool,
    chain_id_required: bool,
    chain_id: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedMeta {
    /// "Allow", "Deny", or "Error" (for fail-closed criterion errors).
    kind: String,
    deny_reason: Option<String>,
    wire_code: Option<String>,
    /// For kind = "Error": expected substring of the `PolicyError` Debug string.
    error_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StateSeedEntry {
    /// Seconds before the current wall-clock time that this entry was recorded.
    offset_secs_ago: u64,
    /// Stroop amount recorded.
    amount_stroops: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto helpers (mirrors loader.rs test helpers)
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair via `OsRng`.
fn make_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (Zeroizing::new(sk.to_bytes()), pk)
}

/// Builds a signed policy TOML string for the given policy body (which MUST NOT
/// contain a `[signature]` table).  The signature is computed over the canonical
/// bytes of the full document (signature table excluded) using the same
/// `canonical_bytes → digest → ed25519_sign` chain as `load_signed_policy`.
///
/// Uses the public API:
/// - `stellar_agent_core::policy::v1::canonical::canonical_bytes`
/// - `stellar_agent_core::policy::v1::signature::digest`
fn make_signed_toml(policy_body: &str, seed: &[u8; 32], owner_id: &str) -> String {
    let canon = canonical_bytes(policy_body)
        .expect("canonical_bytes must succeed for well-formed policy body");
    let d = digest(&canon);
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let sig: [u8; 64] = sk.sign(&d).to_bytes();
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    format!("{policy_body}\n[signature]\nowner_id = \"{owner_id}\"\nsig = \"{sig_hex}\"\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test infrastructure helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the path to the adversarial fixture root.
fn adversarial_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/stellar-agent-core
    // ../../tests/policy-fixtures/adversarial
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("../..")
        .join("tests/policy-fixtures/adversarial")
}

/// Walks all `*.case.json` files under `root` and returns them sorted by path.
///
/// Uses `std::fs::read_dir` recursively to keep the dev-dep surface minimal;
/// the fixture tree depth is bounded (`adversarial/<category>/<name>.case.json`).
fn collect_case_files(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    walk_dir(root, &mut paths);
    paths.sort();
    paths
}

/// Recursively appends `*.case.json` paths under `dir` to `out`.
fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            walk_dir(&path, out);
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".case.json"))
        {
            out.push(path);
        }
    }
}

/// Constructs a `ToolDescriptor` from case metadata.
///
/// `ToolDescriptor` is `#[non_exhaustive]` and must be constructed via
/// `from_registration`.  `McpToolRegistration::name` is `&'static str`;
/// fixture tool names are matched against the known set and resolved to their
/// static equivalents.  Unknown tool names fall back to a leaked allocation
/// (acceptable in test code where the test process exits shortly after).
fn tool_descriptor_from_meta(meta: &ToolMeta) -> ToolDescriptor {
    use stellar_agent_core::policy::McpToolRegistration;

    // All tool names used by adversarial fixtures.
    static STELLAR_PAY: &str = "stellar_pay";
    static STELLAR_PAY_COMMIT: &str = "stellar_pay_commit";
    static STELLAR_CREATE_ACCOUNT: &str = "stellar_create_account";
    static STELLAR_CREATE_ACCOUNT_COMMIT: &str = "stellar_create_account_commit";
    static STELLAR_BALANCES: &str = "stellar_balances";
    static STELLAR_FRIENDBOT: &str = "stellar_friendbot";
    static STELLAR_FEE_STATS: &str = "stellar_fee_stats";

    let static_name: &'static str = match meta.name.as_str() {
        "stellar_pay" => STELLAR_PAY,
        "stellar_pay_commit" => STELLAR_PAY_COMMIT,
        "stellar_create_account" => STELLAR_CREATE_ACCOUNT,
        "stellar_create_account_commit" => STELLAR_CREATE_ACCOUNT_COMMIT,
        "stellar_balances" => STELLAR_BALANCES,
        "stellar_friendbot" => STELLAR_FRIENDBOT,
        "stellar_fee_stats" => STELLAR_FEE_STATS,
        // Safety: this leak is intentional and bounded — integration test
        // processes are short-lived and each fixture name is unique.
        // SAFETY: test-only; no secret material; process exits after tests.
        other => Box::leak(other.to_owned().into_boxed_str()),
    };

    let reg = McpToolRegistration {
        name: static_name,
        destructive_hint: meta.destructive_hint,
        read_only_hint: meta.read_only_hint,
        chain_id_required: meta.chain_id_required,
    };
    let mut td = ToolDescriptor::from_registration(&reg);
    td.chain_id = meta.chain_id.clone();
    td
}

/// Constructs a `Profile` from the case `profile_name` and `chain_id`.
fn profile_from_case(profile_name: &str, chain_id: &str) -> Profile {
    if chain_id.contains("mainnet") {
        Profile::builder_mainnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name(profile_name)
            .build()
    } else {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name(profile_name)
            .build()
    }
}

/// Reads the TOML policy body (no [signature] table) corresponding to a case file.
fn load_policy_body(case_path: &Path) -> String {
    // <name>.case.json → <name>.toml
    let stem = case_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_suffix(".case.json")
        .unwrap();
    let toml_path = case_path.with_file_name(format!("{stem}.toml"));
    std::fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("Could not read TOML at {}: {e}", toml_path.display()))
}

/// Writes a signed policy to a temp file and loads it via `load_signed_policy`.
fn load_doc_signed(
    toml_body: &str,
    seed: &[u8; 32],
    pk: &[u8; 32],
    profile_name: &str,
    dir: &TempDir,
) -> PolicyDocument {
    let signed_toml = make_signed_toml(toml_body, seed, "TEST_OWNER_ID");
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, &signed_toml).expect("write policy");
    load_signed_policy(&path, profile_name, pk).expect("load_signed_policy must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock AccountIdentityView for HOME_DOMAIN tests
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal `AccountIdentityView` for counterparty_lookalike HOME_DOMAIN tests.
///
/// `home_domain` lives on `AccountIdentityView`.  The adversarial fixture
/// driver injects this view via the `identity_view` parameter of
/// `PolicyEngineV1::evaluate`.
struct MockIdentityView {
    home_domain: Option<String>,
}

impl stellar_agent_core::policy::v1::AccountIdentityView for MockIdentityView {
    fn home_domain(&self) -> Option<String> {
        // An empty string encodes "identity present, no home_domain" to allow
        // fixture JSON to distinguish "no identity view" (null) from "identity
        // view present but home_domain absent" (empty string).
        self.home_domain
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    fn account_id(&self) -> &str {
        // Fixture account ID; not consumed by the HOME_DOMAIN criterion.
        "GABC123456789012345678901234567890123456789012345678901234"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock CounterpartyCacheView for home_domain_resolved tests
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal `CounterpartyCacheView` for `home_domain_resolved` criterion tests.
///
/// The fixture driver injects this view via the `counterparty_cache` parameter
/// of `PolicyEngineV1::evaluate`.
struct MockCounterpartyCacheView {
    resolved: std::collections::HashSet<String>,
}

impl stellar_agent_core::policy::v1::CounterpartyCacheView for MockCounterpartyCacheView {
    fn has_resolved(&self, home_domain: &str) -> bool {
        self.resolved.contains(home_domain)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-period cap state seeding
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-populates a `PolicyStateStore` from the `state_seed` array in the case
/// metadata.  Each seed entry specifies how many seconds ago the entry was
/// recorded and the amount.
///
/// The key matches what `PerPeriodCapCriterion` uses at evaluation time:
/// - profile_name from the case
/// - scope_specificity = 1 (AllProfiles default)
/// - bucket = "native" (all per_period_rollover and combinator fixtures use native)
/// - window_secs = 86_400 (1d, matching the fixture TOML)
fn seed_state_store(store: &PolicyStateStore, profile_name: &str, seeds: &[StateSeedEntry]) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_millis() as u64;

    let key = StateKey::new(profile_name, 1, "native", 86_400);

    for seed in seeds {
        let ts_ms = now_ms.saturating_sub(seed.offset_secs_ago.saturating_mul(1_000));
        store
            .append(&key, ts_ms, seed.amount_stroops)
            .expect("state store append must succeed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Case runner
// ─────────────────────────────────────────────────────────────────────────────

/// Runs a single adversarial case.  Returns `Ok(())` on pass, `Err(String)` with
/// a description of the failure.
fn run_case(case_path: &Path) -> Result<(), String> {
    let raw_json = std::fs::read_to_string(case_path)
        .map_err(|e| format!("{}: cannot read case file: {e}", case_path.display()))?;

    let meta: CaseMeta = serde_json::from_str(&raw_json)
        .map_err(|e| format!("{}: invalid case JSON: {e}", case_path.display()))?;

    let policy_body = load_policy_body(case_path);

    match meta.test_kind.as_str() {
        "evaluate" => run_evaluate_case(case_path, &meta, &policy_body),
        "load_failure" => run_load_failure_case(case_path, &meta, &policy_body),
        other => Err(format!(
            "{}: unknown test_kind '{other}'",
            case_path.display()
        )),
    }
}

/// Runs an `evaluate` case end-to-end through `PolicyEngineV1::evaluate`.
fn run_evaluate_case(case_path: &Path, meta: &CaseMeta, policy_body: &str) -> Result<(), String> {
    let tool_meta = meta
        .tool
        .as_ref()
        .ok_or_else(|| format!("{}: evaluate case missing 'tool'", case_path.display()))?;
    let args = meta
        .args
        .as_ref()
        .ok_or_else(|| format!("{}: evaluate case missing 'args'", case_path.display()))?;
    let profile_name = meta.profile_name.as_deref().ok_or_else(|| {
        format!(
            "{}: evaluate case missing 'profile_name'",
            case_path.display()
        )
    })?;
    let expected = meta
        .expected
        .as_ref()
        .ok_or_else(|| format!("{}: evaluate case missing 'expected'", case_path.display()))?;

    // Generate a fresh keypair for signing.
    let (sk, pk) = make_keypair();
    let dir = TempDir::new().map_err(|e| format!("tempdir creation failed: {e}"))?;

    // Sign the TOML body and load it.
    let doc = load_doc_signed(policy_body, &sk, &pk, profile_name, &dir);

    // Build state store and optionally seed it.
    let store = PolicyStateStore::new();
    if let Some(seeds) = &meta.state_seed
        && !seeds.is_empty()
    {
        seed_state_store(&store, profile_name, seeds);
    }

    // Build the engine.
    let engine = PolicyEngineV1::new_with_store(doc, profile_name.to_owned(), store);

    // Build the ToolDescriptor.
    let tool = tool_descriptor_from_meta(tool_meta);

    // Build the Profile.
    let profile = profile_from_case(profile_name, &tool_meta.chain_id);

    // Build the optional identity_view for HOME_DOMAIN tests.  home_domain
    // lives on AccountIdentityView; engine.evaluate accepts an identity_view
    // parameter directly.
    let mock_identity = meta.mock_home_domain.as_ref().map(|d| MockIdentityView {
        home_domain: Some(d.clone()),
    });

    // Build the optional counterparty_cache for home_domain_resolved tests.
    // When mock_resolved_domains is absent, the cache is not wired (None),
    // exercising the fail-closed path.
    let mock_cache = meta
        .mock_resolved_domains
        .as_ref()
        .map(|domains| MockCounterpartyCacheView {
            resolved: domains.iter().cloned().collect(),
        });

    // Evaluate via the engine's injection point.  Pass identity_view when a
    // mock_home_domain is configured (HOME_DOMAIN criterion cases); pass None
    // for all other cases.  account_view is None in both paths because none of
    // the adversarial fixtures currently exercise the minimum-reserve criterion
    // with a real account view.
    let identity_view_ref: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView> =
        mock_identity
            .as_ref()
            .map(|v| v as &dyn stellar_agent_core::policy::v1::AccountIdentityView);

    let cache_ref: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView> = mock_cache
        .as_ref()
        .map(|v| v as &dyn stellar_agent_core::policy::v1::CounterpartyCacheView);

    let eval_result = engine.evaluate(
        &tool,
        args,
        &profile,
        None,
        identity_view_ref,
        cache_ref,
        None,
        None,
    );

    // If expected.kind == "Error", assert the evaluation errored.
    if expected.kind == "Error" {
        return match eval_result {
            Err(e) => {
                if let Some(contains) = &expected.error_contains {
                    let debug_str = format!("{e:?}");
                    if debug_str.contains(contains.as_str()) {
                        Ok(())
                    } else {
                        Err(format!(
                            "{} [{}::{}]: expected error containing '{}', got: {debug_str}",
                            case_path.display(),
                            meta.category,
                            meta.name,
                            contains
                        ))
                    }
                } else {
                    Ok(())
                }
            }
            Ok(decision) => Err(format!(
                "{} [{}::{}]: expected Error, got Decision: {decision:?}",
                case_path.display(),
                meta.category,
                meta.name
            )),
        };
    }

    let decision = eval_result.map_err(|e| {
        format!(
            "{} [{}::{}]: evaluate returned error: {e:?}",
            case_path.display(),
            meta.category,
            meta.name
        )
    })?;

    // Assert the outcome.
    assert_decision(case_path, meta, expected, &decision)
}

/// Asserts the `Decision` matches `expected`.
fn assert_decision(
    case_path: &Path,
    meta: &CaseMeta,
    expected: &ExpectedMeta,
    decision: &Decision,
) -> Result<(), String> {
    match expected.kind.as_str() {
        "Allow" => {
            if !matches!(decision, Decision::Allow) {
                return Err(format!(
                    "{} [{}::{}]: expected Allow, got: {decision:?}",
                    case_path.display(),
                    meta.category,
                    meta.name
                ));
            }
        }
        "Deny" => {
            let reason = match decision {
                Decision::Deny(r) => r,
                other => {
                    return Err(format!(
                        "{} [{}::{}]: expected Deny, got: {other:?}",
                        case_path.display(),
                        meta.category,
                        meta.name
                    ));
                }
            };

            if let Some(expected_code) = &expected.deny_reason {
                let actual_code = reason.code();
                if actual_code != expected_code.as_str() {
                    return Err(format!(
                        "{} [{}::{}]: expected deny_reason '{}', got '{}'",
                        case_path.display(),
                        meta.category,
                        meta.name,
                        expected_code,
                        actual_code
                    ));
                }

                // Also verify the wire_code if supplied.
                if let Some(expected_wire) = &expected.wire_code {
                    let actual_wire = format!("policy.deny.{actual_code}");
                    if actual_wire != *expected_wire {
                        return Err(format!(
                            "{} [{}::{}]: expected wire_code '{}', got '{}'",
                            case_path.display(),
                            meta.category,
                            meta.name,
                            expected_wire,
                            actual_wire
                        ));
                    }
                }
            }
        }
        other => {
            return Err(format!(
                "{} [{}::{}]: unknown expected.kind '{other}'",
                case_path.display(),
                meta.category,
                meta.name
            ));
        }
    }

    Ok(())
}

/// Runs a `load_failure` case.
fn run_load_failure_case(
    case_path: &Path,
    meta: &CaseMeta,
    policy_body: &str,
) -> Result<(), String> {
    let strategy = meta.load_signing_strategy.as_deref().ok_or_else(|| {
        format!(
            "{}: load_failure case missing 'load_signing_strategy'",
            case_path.display()
        )
    })?;

    let expect_ok = meta.expected_load_ok.unwrap_or(false);
    if expect_ok && (meta.expected_load_error.is_some() || meta.expected_load_wire_code.is_some()) {
        return Err(format!(
            "{} [{}::{}]: expected_load_ok=true must not also set expected load-error metadata",
            case_path.display(),
            meta.category,
            meta.name
        ));
    }

    let (sk_correct, pk_correct) = make_keypair();
    let (sk_rotated, pk_rotated) = make_keypair();
    let (_, pk_stale) = make_keypair();

    let dir = TempDir::new().map_err(|e| format!("tempdir creation failed: {e}"))?;

    match strategy {
        "correct_key" => {
            // Sign with correct key; verify with correct key → must succeed.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct);
            if expect_ok {
                result.map(|_| ()).map_err(|e| {
                    format!(
                        "{} [{}::{}]: expected Ok from load_signed_policy, got: {e:?}",
                        case_path.display(),
                        meta.category,
                        meta.name
                    )
                })
            } else {
                match result {
                    Err(_) => Ok(()),
                    Ok(_) => Err(format!(
                        "{} [{}::{}]: expected Err from load_signed_policy, got Ok",
                        case_path.display(),
                        meta.category,
                        meta.name
                    )),
                }
            }
        }

        "post_rotation_correct_key" => {
            // Sign and verify with the rotated key; the stale key is not consulted.
            let signed_toml = make_signed_toml(policy_body, &sk_rotated, "TEST_OWNER_ROTATED");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_rotated);
            if expect_ok {
                result.map(|_| ()).map_err(|e| {
                    format!(
                        "{} [{}::{}]: expected Ok from post-rotation load, got: {e:?}",
                        case_path.display(),
                        meta.category,
                        meta.name
                    )
                })
            } else {
                match result {
                    Err(_) => Ok(()),
                    Ok(_) => Err(format!(
                        "{} [{}::{}]: expected Err from post-rotation load, got Ok",
                        case_path.display(),
                        meta.category,
                        meta.name
                    )),
                }
            }
        }

        "stale_key" => {
            // Sign with key A; verify with key B → must fail.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_stale);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "tampered_byte" => {
            // Sign correctly, then flip one hex nibble of the signature.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let tampered = tamper_sig_byte(&signed_toml)?;
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &tampered).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "truncated" => {
            // Sign correctly, then truncate the hex signature by 4 chars.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let truncated = truncate_sig(&signed_toml)?;
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &truncated).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "cross_profile_replay" => {
            // Signature is valid under the owner key, but scope must still reject.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct);
            check_load_error(case_path, meta, result, "policy_file_parse_failed")
        }

        other => Err(format!(
            "{} [{}::{}]: unknown load_signing_strategy '{other}'",
            case_path.display(),
            meta.category,
            meta.name
        )),
    }
}

/// Asserts a `load_signed_policy` result is an error matching the expected
/// error discriminant.
fn check_load_error(
    case_path: &Path,
    meta: &CaseMeta,
    result: Result<PolicyDocument, stellar_agent_core::policy::PolicyError>,
    expected_variant: &str,
) -> Result<(), String> {
    use stellar_agent_core::policy::PolicyError;

    let expected_from_fixture = meta.expected_load_error.as_deref().ok_or_else(|| {
        format!(
            "{} [{}::{}]: load-failure case missing expected_load_error metadata",
            case_path.display(),
            meta.category,
            meta.name
        )
    })?;
    if expected_from_fixture != expected_variant {
        return Err(format!(
            "{} [{}::{}]: load_signing_strategy expects '{expected_variant}', but fixture metadata says '{expected_from_fixture}'",
            case_path.display(),
            meta.category,
            meta.name
        ));
    }
    let expected_wire_code = meta.expected_load_wire_code.as_deref().ok_or_else(|| {
        format!(
            "{} [{}::{}]: load-failure case missing expected_load_wire_code metadata",
            case_path.display(),
            meta.category,
            meta.name
        )
    })?;

    match result {
        Ok(_) => Err(format!(
            "{} [{}::{}]: expected Err({expected_variant}), got Ok",
            case_path.display(),
            meta.category,
            meta.name
        )),
        Err(e) => {
            let matches = match expected_variant {
                "owner_signature_invalid" => matches!(e, PolicyError::OwnerSignatureInvalid { .. }),
                "policy_file_parse_failed" => {
                    matches!(e, PolicyError::PolicyFileParseFailed { .. })
                }
                other => {
                    return Err(format!(
                        "{} [{}::{}]: unknown expected_load_error '{other}'",
                        case_path.display(),
                        meta.category,
                        meta.name
                    ));
                }
            };

            if matches {
                let actual_wire_code = e.wire_code();
                if actual_wire_code == expected_wire_code {
                    Ok(())
                } else {
                    Err(format!(
                        "{} [{}::{}]: expected wire code '{expected_wire_code}', got '{actual_wire_code}'",
                        case_path.display(),
                        meta.category,
                        meta.name
                    ))
                }
            } else {
                Err(format!(
                    "{} [{}::{}]: expected error variant '{}', got: {e:?}",
                    case_path.display(),
                    meta.category,
                    meta.name,
                    expected_variant
                ))
            }
        }
    }
}

/// Flips one nibble in the hex-encoded `sig = "..."` line of the signed TOML.
fn tamper_sig_byte(toml: &str) -> Result<String, String> {
    // Find the `sig = "...hex..."` line and flip the second character of the hex.
    let sig_prefix = "sig = \"";
    let line_idx = toml
        .lines()
        .position(|l| l.starts_with(sig_prefix))
        .ok_or("tamper_sig_byte: no 'sig = ' line found in TOML")?;

    let lines: Vec<&str> = toml.lines().collect();
    let orig_line = lines[line_idx];

    // Extract hex: sig = "....hex...."
    let hex_start = orig_line
        .find('"')
        .map(|i| i + 1)
        .ok_or("tamper_sig_byte: no opening quote on sig line")?;
    let hex_end = orig_line[hex_start..]
        .find('"')
        .map(|i| i + hex_start)
        .ok_or("tamper_sig_byte: no closing quote on sig line")?;

    let hex = &orig_line[hex_start..hex_end];
    if hex.len() < 4 {
        return Err("tamper_sig_byte: hex too short to tamper".into());
    }

    // Flip the second character of the hex string.
    let mut chars: Vec<char> = hex.chars().collect();
    chars[1] = match chars[1] {
        '0' => 'f',
        _ => '0',
    };
    let new_hex: String = chars.iter().collect();
    let new_line = format!("sig = \"{new_hex}\"");

    let mut owned_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    owned_lines[line_idx] = new_line;
    Ok(owned_lines.join("\n"))
}

/// Truncates the hex-encoded signature in the signed TOML by 4 characters.
fn truncate_sig(toml: &str) -> Result<String, String> {
    let sig_prefix = "sig = \"";
    let line_idx = toml
        .lines()
        .position(|l| l.starts_with(sig_prefix))
        .ok_or("truncate_sig: no 'sig = ' line found in TOML")?;

    let mut owned_lines: Vec<String> = toml.lines().map(|l| l.to_string()).collect();
    let orig_line = owned_lines[line_idx].clone();

    let hex_start = orig_line
        .find('"')
        .map(|i| i + 1)
        .ok_or("truncate_sig: no opening quote on sig line")?;
    let hex_end = orig_line[hex_start..]
        .find('"')
        .map(|i| i + hex_start)
        .ok_or("truncate_sig: no closing quote on sig line")?;

    let hex = &orig_line[hex_start..hex_end];
    if hex.len() < 4 {
        return Err("truncate_sig: hex too short to truncate".into());
    }

    let truncated_hex = &hex[..hex.len() - 4];
    owned_lines[line_idx] = format!("sig = \"{truncated_hex}\"");
    Ok(owned_lines.join("\n"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Subdirectory presence guard
// ─────────────────────────────────────────────────────────────────────────────

const REQUIRED_SUBDIRS: &[&str] = &[
    "per_tx_cap_boundary",
    "per_period_rollover",
    "combinator_and_or",
    "counterparty_lookalike",
    "null_source_account",
    "mutation_stale_key",
];

/// Defence-in-depth structural guard that fails fast when a required adversarial
/// subdirectory or its case files are missing.
fn assert_required_subdirs(root: &Path) {
    for subdir in REQUIRED_SUBDIRS {
        let path = root.join(subdir);
        assert!(
            path.is_dir(),
            "required adversarial subdirectory '{subdir}' is missing at {path:?}; \
             each declared adversarial axis must have its own fixture subdirectory"
        );
        let has_case = std::fs::read_dir(&path)
            .expect("read_dir")
            .flatten()
            .any(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".case.json"))
            });
        assert!(
            has_case,
            "adversarial subdirectory '{subdir}' exists but contains no *.case.json files; \
             each adversarial axis must provide at least one *.case.json fixture"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main test entry point
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "test-only; per-case PASS/FAIL output aids CI failure triage"
)]
fn run_all_adversarial_fixtures() {
    let root = adversarial_root();
    assert_required_subdirs(&root);

    let cases = collect_case_files(&root);
    assert!(
        !cases.is_empty(),
        "no *.case.json files found under {root:?}"
    );

    let total = cases.len();
    let mut failures: Vec<String> = Vec::new();

    for case_path in &cases {
        match run_case(case_path) {
            Ok(()) => {
                // Report passing case for visibility in verbose output.
                let rel = case_path.strip_prefix(&root).unwrap_or(case_path);
                println!("PASS  {}", rel.display());
            }
            Err(msg) => {
                eprintln!("FAIL  {msg}");
                failures.push(msg);
            }
        }
    }

    if !failures.is_empty() {
        let count = failures.len();
        panic!(
            "{count}/{total} adversarial fixture(s) failed:\n{}",
            failures.join("\n")
        );
    }

    println!("run_all_adversarial_fixtures: {total} fixtures passed");
}
