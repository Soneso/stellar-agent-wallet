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
//! Seven legacy categories:
//! 1. `per_tx_cap_boundary/`: per-transaction cap boundary values
//! 2. `per_period_rollover/`: rolling-window cap with pre-seeded state store
//! 3. `combinator_and_or/`: multi-criterion first-fail ordering
//! 4. `counterparty_lookalike/`: homoglyph + IDN + case-insensitive HOME_DOMAIN
//! 5. `null_source_account/`: null G-account vs G-allowlist
//! 6. `home_domain_resolved/`: home-domain resolution and the missing cache
//! 7. `mutation_stale_key/`: load-time owner-signature verification
//!
//! Each of the 28 legacy pairs has a `<name>_v2` companion: the same policy
//! as a version 2 document with `sequence = 1`, and the same case metadata
//! under the companion name. Both must reach the same outcome.
//!
//! `extended_grammar/` holds the version 2 additions: unlisted recipient
//! modes, total budgets, the balance floor, and memo bindings. Its cases run
//! in the named `extended_corpus_*` tests. A `sequence` case evaluates its
//! steps against one usage history. Except for the deliberate zero-digest
//! refusal case, each step loads its policy through the verified loader, so
//! `total_budget` counts against the signed digest. The history is replayed
//! into each step's in-memory store; it is not a durable
//! restart. Account views in these cases are core test inputs, not evidence
//! that a caller supplies them.
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
use std::sync::Arc;

use ed25519_dalek::Signer;
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use zeroize::Zeroizing;

use stellar_agent_core::asset_id::CanonicalAsset;
use stellar_agent_core::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::criteria::state_store::{
    PolicyStateStore, StateKey, WindowEntry, set_query_time_for_test,
};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, load_signed_policy};
use stellar_agent_core::policy::v1::signature::digest;
use stellar_agent_core::policy::v1::value::{ValueClass, derive_value_class};
use stellar_agent_core::policy::v1::verified::{
    OwnerKeySource, PinMode, PolicyLoad, load_verified_policy,
};
use stellar_agent_core::policy::v1::{
    AccountReserveLookupError, AccountReservesView, FloorInput, ObservedAccount, PolicyEngineV1,
};
use stellar_agent_core::policy::{Decision, PolicyEngine, PolicyError, ToolDescriptor};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::schema::Profile;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture structs
// ─────────────────────────────────────────────────────────────────────────────

/// Root case metadata structure parsed from `<name>.case.json`.
///
/// Unknown fields refuse, so a misspelled expectation cannot be skipped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseMeta {
    test_kind: String,
    name: String,
    category: String,
    #[allow(dead_code)]
    description: String,

    // evaluate fields
    tool: Option<ToolMeta>,
    args: Option<Value>,
    sac_payment_context: Option<stellar_agent_core::sac_payment::SacPaymentContext>,
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
    // grammar_refused: the exact loader refusal detail.
    expected_load_detail: Option<String>,

    // sequence fields: the steps evaluated in order against one history.
    steps: Option<Vec<StepMeta>>,
    // sequence: build each engine without the verified loader, so its policy
    // digest is all zeros. Only a case that tests the zero digest sets it.
    unverified_engine: Option<bool>,
}

/// One evaluation of a `sequence` case.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepMeta {
    /// Overrides the case tool's name.
    tool: Option<String>,
    /// A sibling policy stem to load instead of the case's own policy.
    policy: Option<String>,
    args: Value,
    /// Evaluates a bundle of token transfers instead of `args` alone.
    bundle: Option<Vec<InnerMeta>>,
    /// The account view the evaluation receives.
    account: Option<AccountMeta>,
    /// Evaluates provisionally instead of strictly.
    #[serde(default)]
    provisional: bool,
    /// Milliseconds after [`EVALUATION_INSTANT_MS`] at which the step runs.
    #[serde(default)]
    after_ms: u64,
    /// Records the permitted step into the history.
    #[serde(default)]
    record: bool,
    expected: ExpectedMeta,
}

/// A token transfer inside a bundle, in the asset's Stellar Asset Contract.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InnerMeta {
    to: String,
    asset: String,
    amount_stroops: i128,
}

/// A native account view. Without `observed_age_ms` it is a plain view with
/// no observation; with it, the observation is that old at the step's
/// instant, and `reservations_stroops` adds the floor's reservation sum.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountMeta {
    balance_stroops: i64,
    observed_age_ms: Option<u64>,
    reservations_stroops: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolMeta {
    name: String,
    destructive_hint: bool,
    read_only_hint: bool,
    chain_id_required: bool,
    chain_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedMeta {
    /// "Allow", "Deny", "RequireApproval", or "Error" (for fail-closed
    /// criterion errors).
    kind: String,
    /// For kind = "Deny": the expected `DenyReason::code()`.
    deny_reason: Option<String>,
    /// For kind = "Deny": the expected `DenyReason::wire_code()`, compared
    /// whether or not `deny_reason` is present.
    wire_code: Option<String>,
    /// For kind = "Deny": the expected serialized `DenyReason`.
    reason: Option<Value>,
    /// For kind = "RequireApproval": the exact approval reason and lifetime,
    /// both required.
    approval_reason: Option<String>,
    approval_ttl_secs: Option<u32>,
    /// For kind = "Error": expected substring of the `PolicyError` Debug string.
    error_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateSeedEntry {
    /// Seconds before the current wall-clock time that this entry was recorded.
    offset_secs_ago: u64,
    /// Stroop amount recorded.
    amount_stroops: i64,
    /// The state-store bucket; `native` when absent.
    bucket: Option<String>,
    /// The bucket's window in seconds; 86,400 when absent.
    window_secs: Option<u64>,
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
        value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
    };
    let mut td = ToolDescriptor::from_registration(&reg);
    td.chain_id = meta.chain_id.clone();
    td
}

/// Constructs a `Profile` from the case `profile_name` and `chain_id`.
fn profile_from_case(profile_name: &str, chain_id: &str) -> Profile {
    if chain_id.contains("mainnet") {
        Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "nonce-svc",
            "nonce-acct",
        )
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

/// Writes a signed policy to a temp file and loads it via `load_signed_policy`
/// for `profile`, the profile the case evaluates under.
fn load_doc_signed(
    toml_body: &str,
    seed: &[u8; 32],
    pk: &[u8; 32],
    profile_name: &str,
    profile: &Profile,
    dir: &TempDir,
) -> PolicyDocument {
    let signed_toml = make_signed_toml(toml_body, seed, "TEST_OWNER_ID");
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, &signed_toml).expect("write policy");
    load_signed_policy(&path, profile_name, pk, &profile.network_passphrase)
        .expect("load_signed_policy must succeed")
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

/// Minimal `CounterpartyCacheView` for `home_domain_resolved` AND `HOME_DOMAIN`
/// (counterparty_allowlist) criterion tests.
///
/// The fixture driver injects this view via the `counterparty_cache` parameter
/// of `PolicyEngineV1::evaluate`. Every fixture in this suite uses the SAME
/// fixed `MockIdentityView::account_id()`, so `is_account_listed` mirrors
/// `has_resolved` rather than tracking a separate per-domain accounts list —
/// this suite covers domain-resolution/homoglyph edge cases, not the
/// account-listing dimension (unit-tested directly in
/// `counterparty_allowlist.rs`).
struct MockCounterpartyCacheView {
    resolved: std::collections::HashSet<String>,
}

impl stellar_agent_core::policy::v1::CounterpartyCacheView for MockCounterpartyCacheView {
    fn has_resolved(&self, home_domain: &str) -> bool {
        self.resolved.contains(home_domain)
    }

    fn is_account_listed(&self, home_domain: &str, _account_id: &str) -> bool {
        self.resolved.contains(home_domain)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-period cap state seeding
// ─────────────────────────────────────────────────────────────────────────────

/// The evaluation instant of every case, in Unix milliseconds.
const EVALUATION_INSTANT_MS: u64 = 1_700_000_000_000;

/// Pre-populates a `PolicyStateStore` from the `state_seed` array in the case
/// metadata.  Each seed entry specifies how many seconds ago the entry was
/// recorded and the amount.
///
/// The key matches what the windowed criteria use at evaluation time:
/// - profile_name from the case
/// - scope_specificity = 1 (AllProfiles default)
/// - bucket = the entry's `bucket`, or "native" as `per_period_cap` uses for
///   the native asset; an unlisted budget reads `unlisted:<asset>`
/// - window_secs = the entry's `window_secs`, or 86_400 (1d)
///
/// Entries sit relative to [`EVALUATION_INSTANT_MS`], the instant the case
/// evaluates at.
fn seed_state_store(store: &PolicyStateStore, profile_name: &str, seeds: &[StateSeedEntry]) {
    let now_ms = EVALUATION_INSTANT_MS;

    for seed in seeds {
        let key = StateKey::new(
            profile_name,
            1,
            seed.bucket.as_deref().unwrap_or("native"),
            seed.window_secs.unwrap_or(86_400),
        );
        let ts_ms = now_ms.saturating_sub(seed.offset_secs_ago.saturating_mul(1_000));
        store
            .append(&key, ts_ms, i128::from(seed.amount_stroops))
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

    let mut meta: CaseMeta = serde_json::from_str(&raw_json)
        .map_err(|e| format!("{}: invalid case JSON: {e}", case_path.display()))?;

    if let Some(context) = &meta.sac_payment_context {
        use stellar_xdr::{Limits, TransactionEnvelope, WriteXdr as _};
        let envelope = stellar_agent_core::approval::fixtures::sac_transfer(context);
        let xdr = TransactionEnvelope::Tx(envelope)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let args =
            stellar_agent_core::envelope_decode::decode_pay_args_with_context(&xdr, Some(context))
                .map_err(|error| error.code().to_owned())?;
        assert!(
            matches!(
                derive_value_class("stellar_pay_commit", &args),
                ValueClass::Value(_)
            ),
            "contract transfer stays a value action"
        );
        meta.args = Some(args);
    }

    let policy_body = load_policy_body(case_path);

    match meta.test_kind.as_str() {
        "evaluate" => run_evaluate_case(case_path, &meta, &policy_body),
        "load_failure" => run_load_failure_case(case_path, &meta, &policy_body),
        "sequence" => run_sequence_case(case_path, &meta, &policy_body),
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

    // Build the Profile.
    let profile = profile_from_case(profile_name, &tool_meta.chain_id);

    // Sign the TOML body and load it for that profile.
    let doc = load_doc_signed(policy_body, &sk, &pk, profile_name, &profile, &dir);

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
    // for all other cases.  account_view is None for every evaluate case;
    // sequence cases supply their account views.
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
        EVALUATION_INSTANT_MS,
    );

    check_outcome(&case_label(case_path, meta), expected, eval_result)
}

/// Names a case in failure messages.
fn case_label(case_path: &Path, meta: &CaseMeta) -> String {
    format!("{} [{}::{}]", case_path.display(), meta.category, meta.name)
}

/// Asserts an evaluation result matches `expected`: an error for kind
/// "Error", otherwise the decision.
fn check_outcome(
    label: &str,
    expected: &ExpectedMeta,
    eval_result: Result<Decision, PolicyError>,
) -> Result<(), String> {
    if expected.kind == "Error" {
        return match eval_result {
            Err(e) => {
                if let Some(contains) = &expected.error_contains {
                    let debug_str = format!("{e:?}");
                    if debug_str.contains(contains.as_str()) {
                        Ok(())
                    } else {
                        Err(format!(
                            "{label}: expected error containing '{contains}', got: {debug_str}"
                        ))
                    }
                } else {
                    Ok(())
                }
            }
            Ok(decision) => Err(format!(
                "{label}: expected Error, got Decision: {decision:?}"
            )),
        };
    }

    let decision = eval_result.map_err(|e| format!("{label}: evaluate returned error: {e:?}"))?;
    assert_decision(label, expected, &decision)
}

/// Asserts the `Decision` matches `expected`.
fn assert_decision(
    label: &str,
    expected: &ExpectedMeta,
    decision: &Decision,
) -> Result<(), String> {
    match expected.kind.as_str() {
        "Allow" => {
            if !matches!(decision, Decision::Allow) {
                return Err(format!("{label}: expected Allow, got: {decision:?}"));
            }
        }
        "RequireApproval" => {
            let Decision::RequireApproval(request) = decision else {
                return Err(format!(
                    "{label}: expected RequireApproval, got: {decision:?}"
                ));
            };
            let (Some(reason), Some(ttl_secs)) =
                (&expected.approval_reason, expected.approval_ttl_secs)
            else {
                return Err(format!(
                    "{label}: a RequireApproval expectation needs approval_reason and \
                     approval_ttl_secs"
                ));
            };
            if request.reason.as_deref() != Some(reason.as_str()) || request.ttl_seconds != ttl_secs
            {
                return Err(format!(
                    "{label}: expected approval reason '{reason}' for {ttl_secs} s, got \
                     {:?} for {} s",
                    request.reason, request.ttl_seconds
                ));
            }
        }
        "Deny" => {
            let reason = match decision {
                Decision::Deny(r) => r,
                other => {
                    return Err(format!("{label}: expected Deny, got: {other:?}"));
                }
            };

            if let Some(expected_code) = &expected.deny_reason {
                let actual_code = reason.code();
                if actual_code != expected_code.as_str() {
                    return Err(format!(
                        "{label}: expected deny_reason '{expected_code}', got '{actual_code}'"
                    ));
                }
            }
            if let Some(expected_wire) = &expected.wire_code {
                let actual_wire = reason.wire_code();
                if actual_wire != expected_wire.as_str() {
                    return Err(format!(
                        "{label}: expected wire_code '{expected_wire}', got '{actual_wire}'"
                    ));
                }
            }
            if let Some(expected_reason) = &expected.reason {
                let actual_reason = serde_json::to_value(reason)
                    .map_err(|e| format!("{label}: cannot serialize the denial: {e}"))?;
                if actual_reason != *expected_reason {
                    return Err(format!(
                        "{label}: expected reason {expected_reason}, got {actual_reason}"
                    ));
                }
            }
        }
        other => {
            return Err(format!("{label}: unknown expected.kind '{other}'"));
        }
    }

    Ok(())
}

/// A native-balance account view with the reserve of an account without
/// subentries.
struct Balance(i64);

impl AccountReservesView for Balance {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        2 * base_reserve_stroops
    }

    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        Ok(self.0)
    }
}

/// Signs `body` and loads it through the verified loader for `profile`,
/// with `store` as the engine's window state.
///
/// The load compares against no pin, so a step may return to an earlier
/// sequence; the engine carries the digest of the signed canonical bytes.
fn verified_engine(
    body: &str,
    (seed, pk): (&[u8; 32], &[u8; 32]),
    profile: &Profile,
    profile_name: &str,
    dir: &TempDir,
    store: PolicyStateStore,
) -> Result<Arc<PolicyEngineV1>, PolicyError> {
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, make_signed_toml(body, seed, "TEST_OWNER_ID")).expect("write policy");
    let policy = load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile,
            profile_name,
            owner_pubkey: pk,
            owner_source: OwnerKeySource::TestFile,
            window_path: &dir.path().join("state.window"),
        },
        store,
        PinMode::CompareOnly,
    )?;
    Ok(policy.engine())
}

/// Replays recorded entries into `store`, each in its own epoch.
fn replay(store: &PolicyStateStore, history: &[WindowEntry]) {
    for entry in history {
        match entry.epoch() {
            Some(epoch) => {
                store.append_epoch(entry.key(), entry.timestamp_ms(), entry.amount(), epoch)
            }
            None => store.append(entry.key(), entry.timestamp_ms(), entry.amount()),
        }
        .expect("state store append must succeed");
    }
}

/// Builds the bundle inners of a step; each asset is its Stellar Asset
/// Contract on the test network.
fn bundle_inners(inners: &[InnerMeta]) -> Result<Vec<InnerOpDescriptor>, String> {
    inners
        .iter()
        .map(|inner| {
            let asset = if inner.asset == "native" {
                CanonicalAsset::Native
            } else {
                CanonicalAsset::parse_threshold_key(&inner.asset)
                    .map_err(|e| format!("bundle asset '{}': {e}", inner.asset))?
            };
            Ok(InnerOpDescriptor::TokenTransfer {
                asset: asset
                    .sac_contract_id(TESTNET_PASSPHRASE)
                    .ok_or_else(|| format!("bundle asset '{}' has no contract", inner.asset))?,
                from: BUNDLE_SOURCE.to_owned(),
                to: inner.to.clone(),
                amount: inner.amount_stroops,
            })
        })
        .collect()
}

/// The account a bundle's transfers debit.
const BUNDLE_SOURCE: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Runs a `sequence` case: each step evaluates at its instant against the
/// seeds and every entry earlier steps recorded.
fn run_sequence_case(case_path: &Path, meta: &CaseMeta, policy_body: &str) -> Result<(), String> {
    let label = case_label(case_path, meta);
    let (Some(tool_meta), Some(profile_name), Some(steps)) =
        (&meta.tool, meta.profile_name.as_deref(), &meta.steps)
    else {
        return Err(format!(
            "{label}: a sequence case needs 'tool', 'profile_name' and 'steps'"
        ));
    };
    if steps.is_empty() {
        return Err(format!("{label}: a sequence case needs at least one step"));
    }
    // The verified loader reads the profile's mainnet enablement from the
    // keyring; the mock keyring holds none.
    stellar_agent_test_support::keyring_mock::install()
        .map_err(|e| format!("{label}: mock keyring: {e:?}"))?;
    let (sk, pk) = make_keypair();
    let dir = TempDir::new().map_err(|e| format!("tempdir creation failed: {e}"))?;
    let profile = profile_from_case(profile_name, &tool_meta.chain_id);
    let mut history: Vec<WindowEntry> = Vec::new();

    for (index, step) in steps.iter().enumerate() {
        let label = format!("{label} step {index}");
        let now_ms = EVALUATION_INSTANT_MS + step.after_ms;
        let _clock = set_query_time_for_test(now_ms);

        let body = match &step.policy {
            Some(stem) => {
                let path = case_path.with_file_name(format!("{stem}.toml"));
                std::fs::read_to_string(&path)
                    .map_err(|e| format!("{label}: cannot read {}: {e}", path.display()))?
            }
            None => policy_body.to_owned(),
        };
        let store = PolicyStateStore::new();
        if let Some(seeds) = &meta.state_seed {
            seed_state_store(&store, profile_name, seeds);
        }
        replay(&store, &history);
        let engine = if meta.unverified_engine == Some(true) {
            let doc = load_doc_signed(&body, &sk, &pk, profile_name, &profile, &dir);
            Arc::new(PolicyEngineV1::new_with_store(
                doc,
                profile_name.to_owned(),
                store,
            ))
        } else {
            verified_engine(&body, (&sk, &pk), &profile, profile_name, &dir, store)
                .map_err(|e| format!("{label}: verified load failed: {e:?}"))?
        };

        let mut step_tool = tool_meta.clone();
        if let Some(name) = &step.tool {
            step_tool.name.clone_from(name);
        }
        let tool = tool_descriptor_from_meta(&step_tool);

        if let Some(inners) = &step.bundle {
            if step.account.is_some() || step.provisional {
                return Err(format!(
                    "{label}: a bundle step takes no account view and is never provisional"
                ));
            }
            let inners = bundle_inners(inners).map_err(|e| format!("{label}: {e}"))?;
            let overlay = BundleStateOverlay::default();
            let view = BundleView {
                inners: &inners,
                overlay: &overlay,
            };
            let result = engine.evaluate_bundle(&tool, &step.args, &profile, &view);
            check_outcome(&label, &step.expected, result)?;
            if step.record {
                let recorded = engine
                    .record_confirmed_bundle(&tool, &profile, &view)
                    .map_err(|e| format!("{label}: recording the bundle failed: {e:?}"))?;
                history.extend(recorded);
            }
            continue;
        }

        let plain;
        let observed;
        let input;
        let account_view: Option<&dyn AccountReservesView> = match &step.account {
            None => None,
            Some(AccountMeta {
                balance_stroops,
                observed_age_ms: None,
                reservations_stroops: None,
            }) => {
                plain = Balance(*balance_stroops);
                Some(&plain)
            }
            Some(AccountMeta {
                balance_stroops,
                observed_age_ms: Some(age_ms),
                reservations_stroops,
            }) => {
                let observed_at_ms = now_ms - age_ms;
                observed = ObservedAccount::new(
                    Balance(*balance_stroops),
                    1,
                    observed_at_ms,
                    observed_at_ms,
                );
                match reservations_stroops {
                    None => Some(&observed),
                    Some(reservations) => {
                        input = FloorInput {
                            observed: &observed,
                            effective_reservations_stroops: *reservations,
                        };
                        Some(&input)
                    }
                }
            }
            Some(AccountMeta {
                observed_age_ms: None,
                reservations_stroops: Some(_),
                ..
            }) => {
                return Err(format!(
                    "{label}: reservations_stroops needs observed_age_ms"
                ));
            }
        };

        let value = derive_value_class(&tool.name, &step.args);
        let evaluation = if step.provisional {
            engine.evaluate_provisional(
                &tool,
                &step.args,
                &profile,
                value,
                account_view,
                None,
                None,
                None,
                None,
                now_ms,
            )
        } else {
            engine.evaluate_with_value_full(
                &tool,
                &step.args,
                &profile,
                value,
                account_view,
                None,
                None,
                None,
                None,
                now_ms,
            )
        };
        let effects = evaluation
            .as_ref()
            .ok()
            .and_then(|evaluation| evaluation.value_effects.clone());
        check_outcome(
            &label,
            &step.expected,
            evaluation.map(|evaluation| evaluation.decision),
        )?;
        if step.record {
            let effects =
                effects.ok_or_else(|| format!("{label}: a recorded step carries no effects"))?;
            let recorded = engine
                .record_confirmed(&tool, &profile, &ValueClass::Value(effects))
                .map_err(|e| format!("{label}: recording failed: {e:?}"))?;
            history.extend(recorded);
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
            let result = load_signed_policy(&path, "default", &pk_correct, TESTNET_PASSPHRASE);
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
            let result = load_signed_policy(&path, "default", &pk_rotated, TESTNET_PASSPHRASE);
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
            let result = load_signed_policy(&path, "default", &pk_stale, TESTNET_PASSPHRASE);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "tampered_byte" => {
            // Sign correctly, then flip one hex nibble of the signature.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let tampered = tamper_sig_byte(&signed_toml)?;
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &tampered).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct, TESTNET_PASSPHRASE);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "truncated" => {
            // Sign correctly, then truncate the hex signature by 4 chars.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let truncated = truncate_sig(&signed_toml)?;
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &truncated).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct, TESTNET_PASSPHRASE);
            check_load_error(case_path, meta, result, "owner_signature_invalid")
        }

        "cross_profile_replay" => {
            // Signature is valid under the owner key, but scope must still reject.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct, TESTNET_PASSPHRASE);
            check_load_error(case_path, meta, result, "policy_file_parse_failed")
        }

        "grammar_refused" => {
            // Correctly signed; the body itself must refuse with the exact detail.
            let signed_toml = make_signed_toml(policy_body, &sk_correct, "TEST_OWNER");
            let path = dir.path().join("policy.toml");
            std::fs::write(&path, &signed_toml).expect("write");
            let result = load_signed_policy(&path, "default", &pk_correct, TESTNET_PASSPHRASE);
            let expected_detail = meta.expected_load_detail.as_deref().ok_or_else(|| {
                format!(
                    "{}: grammar_refused case missing expected_load_detail",
                    case_label(case_path, meta)
                )
            })?;
            if let Err(PolicyError::PolicyFileParseFailed { detail }) = &result
                && detail != expected_detail
            {
                return Err(format!(
                    "{}: expected refusal '{expected_detail}', got '{detail}'",
                    case_label(case_path, meta)
                ));
            }
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
    result: Result<PolicyDocument, PolicyError>,
    expected_variant: &str,
) -> Result<(), String> {
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
    "home_domain_resolved",
    "mutation_stale_key",
    EXTENDED_DIR,
];

/// The directory of the version 2 addition cases, run by the named
/// `extended_corpus_*` tests instead of [`run_all_adversarial_fixtures`].
const EXTENDED_DIR: &str = "extended_grammar";

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
#[serial_test::serial]
fn run_all_adversarial_fixtures() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let root = adversarial_root();
    assert_required_subdirs(&root);

    let extended = root.join(EXTENDED_DIR);
    let (extended_cases, cases): (Vec<PathBuf>, Vec<PathBuf>) = collect_case_files(&root)
        .into_iter()
        .partition(|path| path.starts_with(&extended));
    assert!(
        !cases.is_empty(),
        "no *.case.json files found under {root:?}"
    );
    let claimed: std::collections::BTreeSet<&str> = EXTENDED_GROUPS
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    for path in &extended_cases {
        let stem = case_stem(path);
        assert!(
            claimed.contains(stem.as_str()),
            "{EXTENDED_DIR}/{stem} belongs to no extended_corpus_* test"
        );
    }

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

/// Returns the `<name>` of a `<name>.case.json` path.
fn case_stem(case_path: &Path) -> String {
    case_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".case.json"))
        .unwrap_or_else(|| panic!("not a case file: {}", case_path.display()))
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 2 companions of the legacy corpus
// ─────────────────────────────────────────────────────────────────────────────

/// The 28 legacy pairs, each with a `_v2` companion.
const LEGACY_CASES: [&str; 28] = [
    "per_tx_cap_boundary/999_xlm_allow",
    "per_tx_cap_boundary/1000_xlm_allow_inclusive",
    "per_tx_cap_boundary/1000_0000001_xlm_deny",
    "per_tx_cap_boundary/1001_xlm_deny",
    "per_period_rollover/in_window_under_cap_allow",
    "per_period_rollover/in_window_over_cap_deny",
    "per_period_rollover/boundary_23h59m_deny",
    "per_period_rollover/past_window_rollover_allow",
    "combinator_and_or/both_pass_allow",
    "combinator_and_or/per_tx_fails_first",
    "combinator_and_or/per_period_fails_first",
    "combinator_and_or/ordering_inversion_different_deny",
    "counterparty_lookalike/legitimate_circle_allow",
    "counterparty_lookalike/case_insensitive_match_allow",
    "counterparty_lookalike/cyrillic_s_circle_deny",
    "counterparty_lookalike/homoglyph_digit1_circ1e_deny",
    "null_source_account/legitimate_g_allow",
    "null_source_account/null_g_account_deny",
    "home_domain_resolved/no_home_domain_allow",
    "home_domain_resolved/resolved_domain_allow",
    "home_domain_resolved/unresolved_domain_deny",
    "home_domain_resolved/missing_cache_fail_closed",
    "mutation_stale_key/signed_with_correct_key_loads",
    "mutation_stale_key/post_rotation_correct_key_loads",
    "mutation_stale_key/signed_with_stale_key_rejected",
    "mutation_stale_key/tampered_signature_byte_rejected",
    "mutation_stale_key/truncated_signature_rejected",
    "mutation_stale_key/cross_profile_replay_rejected",
];

/// Every legacy pair has a `_v2` companion whose policy differs only in
/// `version = 2` and `sequence = 1`, whose case differs only in its name,
/// and which reaches the same outcome. The legacy and companion pairs are
/// the whole legacy corpus; contract cases extend the directory inventory.
#[test]
#[serial_test::serial]
fn legacy_corpus_v2_companions_preserve_outcomes() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let root = adversarial_root();
    let mut expected_files: Vec<PathBuf> = Vec::new();
    for case in LEGACY_CASES {
        let original = root.join(format!("{case}.case.json"));
        let companion = root.join(format!("{case}_v2.case.json"));
        expected_files.extend([original.clone(), companion.clone()]);

        let original_policy = load_policy_body(&original);
        let companion_policy = load_policy_body(&companion);
        assert!(
            original_policy.starts_with("version = 1\n"),
            "{case}: the original is a version 1 document"
        );
        let mut lines: Vec<&str> = companion_policy.lines().collect();
        assert_eq!(lines.first(), Some(&"version = 2"), "{case}_v2");
        assert_eq!(
            lines.iter().filter(|line| **line == "sequence = 1").count(),
            1,
            "{case}_v2 carries one `sequence = 1`"
        );
        lines.retain(|line| *line != "sequence = 1");
        lines[0] = "version = 1";
        assert_eq!(
            lines,
            original_policy.lines().collect::<Vec<_>>(),
            "{case}_v2 differs from {case} only in version and sequence"
        );

        let read_json = |path: &Path| -> Value {
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
        };
        let mut original_case = read_json(&original);
        let companion_case = read_json(&companion);
        assert_eq!(
            companion_case["name"],
            format!("{}_v2", original_case["name"].as_str().unwrap()),
            "{case}_v2"
        );
        original_case["name"] = companion_case["name"].clone();
        assert_eq!(
            companion_case, original_case,
            "{case}_v2 keeps every expectation of {case}"
        );

        for path in [&original, &companion] {
            run_case(path).unwrap_or_else(|failure| panic!("{failure}"));
        }
    }

    for name in [
        "native",
        "issued",
        "mixed_accounts",
        "home_domain",
        "opaque_payment",
    ] {
        let path = root.join(format!("k3_contract/{name}.case.json"));
        assert!(run_case(&path).is_ok(), "contract corpus case {name}");
        expected_files.push(path);
    }

    let extended = root.join(EXTENDED_DIR);
    let mut corpus_files: Vec<PathBuf> = collect_case_files(&root)
        .into_iter()
        .filter(|path| !path.starts_with(&extended))
        .collect();
    corpus_files.sort();
    expected_files.sort();
    assert_eq!(
        corpus_files, expected_files,
        "the corpus is the 28 legacy pairs, their companions and five contract cases"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Version 2 additions
// ─────────────────────────────────────────────────────────────────────────────

/// The four additions are closed, signed version 2 syntax; version 1 refuses
/// each of them.
const CLOSED_GRAMMAR: &[&str] = &[
    "v2_extended_fields",
    "v1_unlisted_rejected",
    "v1_total_rejected",
    "v1_floor_rejected",
    "v1_memo_rejected",
    "unlisted_unknown_key_rejected",
    "binding_unknown_key_rejected",
    "unlisted_unequal_rules_rejected",
    "unlisted_wrong_decision_rejected",
    "unlisted_bound_not_below_cap_rejected",
    "binding_duplicate_destination_rejected",
    "budget_window_30d_rejected",
];

/// Unlisted recipients deny by default; approval escalates only a
/// classifiable unlisted debit, and hard refusals still win.
const RECIPIENT_MODES: &[&str] = &[
    "unlisted_default_deny",
    "unlisted_explicit_deny",
    "unlisted_approval",
    "unverifiable_never_approved",
    "approval_then_hard_cap_deny",
    "hard_cap_then_approval_deny",
    "equal_tables_shared_counter",
];

/// Both unlisted bounds are inclusive and refuse the excess on the test
/// network.
const TESTNET_BUDGET_BOUNDARIES: &[&str] = &[
    "testnet_unlisted_per_tx_boundary",
    "testnet_unlisted_period_boundary",
    "unlisted_bundle_overlay",
    "listed_not_charged",
];

/// Mainnet requests approval beyond either allowance bound; hard caps and
/// the testnet refusals still apply.
const BUDGET_NETWORK_MATRIX: &[&str] = &[
    "mainnet_unlisted_per_tx_approval",
    "mainnet_unlisted_period_approval",
    "mainnet_approved_hard_cap_refused",
    "testnet_unlisted_per_tx_boundary",
    "testnet_unlisted_period_boundary",
];

/// A total allocation never renews with time and is bound to the signed
/// digest.
const TOTAL_EPOCH: &[&str] = &[
    "total_epoch_nonrenewing",
    "total_digest_change",
    "total_zero_digest_refused",
];

/// The floor is a strict check that needs fresh, complete account facts.
const FLOOR_FACTS: &[&str] = &[
    "floor_missing_facts_refused",
    "floor_fresh_boundary",
    "floor_stale_refused",
    "floor_provisional_then_strict",
];

/// A bound payment needs the exact memo kind and value.
const MEMO_BINDINGS: &[&str] = &[
    "memo_kind_value_matrix",
    "memo_id_boundaries",
    "memo_none_refused",
    "memo_muxed_base_binding",
    "memo_unbound_contract",
    "memo_malformed_fact_refused",
];

/// Refusals carry the production wire code and structured fields.
/// `account_wire_code_only` sets only `wire_code`, so that expectation is
/// compared on its own.
const REFUSAL_CODES: &[&str] = &[
    "account_wire_code_only",
    "floor_stale_refused",
    "memo_kind_value_matrix",
    "testnet_unlisted_per_tx_boundary",
];

const EXTENDED_GROUPS: [&[&str]; 8] = [
    CLOSED_GRAMMAR,
    RECIPIENT_MODES,
    TESTNET_BUDGET_BOUNDARIES,
    BUDGET_NETWORK_MATRIX,
    TOTAL_EPOCH,
    FLOOR_FACTS,
    MEMO_BINDINGS,
    REFUSAL_CODES,
];

/// Runs every named `extended_grammar` case and fails on a missing one.
fn run_extended(stems: &[&str]) {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let dir = adversarial_root().join(EXTENDED_DIR);
    let failures: Vec<String> = stems
        .iter()
        .filter_map(|stem| {
            let path = dir.join(format!("{stem}.case.json"));
            if !path.is_file() {
                return Some(format!("{EXTENDED_DIR}/{stem}.case.json is missing"));
            }
            run_case(&path).err()
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[serial_test::serial]
fn extended_corpus_closed_grammar() {
    run_extended(CLOSED_GRAMMAR);
}

#[test]
#[serial_test::serial]
fn extended_corpus_recipient_modes() {
    run_extended(RECIPIENT_MODES);
}

#[test]
#[serial_test::serial]
fn extended_corpus_testnet_budget_boundaries() {
    run_extended(TESTNET_BUDGET_BOUNDARIES);
}

#[test]
#[serial_test::serial]
fn extended_corpus_budget_network_matrix() {
    use stellar_agent_core::policy::v1::presets::{AuthorityStatus, summarize};
    use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;

    run_extended(BUDGET_NETWORK_MATRIX);
    let body = load_policy_body(
        &adversarial_root()
            .join(EXTENDED_DIR)
            .join("mainnet_unlisted_per_tx_approval.case.json"),
    );
    let body = body.parse().unwrap();
    for (passphrase, exhaustion, largest) in [
        (MAINNET_PASSPHRASE, "approval", "0.0001"),
        (TESTNET_PASSPHRASE, "deny", "0.00001"),
    ] {
        let summary = summarize(&body, passphrase, AuthorityStatus::Draft);
        let pay = summary
            .limits
            .iter()
            .flat_map(|limit| &limit.tools)
            .find(|tool| tool.tool == "stellar_pay")
            .unwrap();
        assert_eq!(pay.unlisted_exhaustion, exhaustion);
        assert_eq!(pay.unlisted_largest_payment.as_deref(), Some(largest));
    }
}

#[test]
#[serial_test::serial]
fn extended_corpus_total_epoch() {
    run_extended(TOTAL_EPOCH);
}

#[test]
#[serial_test::serial]
fn extended_corpus_floor_facts() {
    run_extended(FLOOR_FACTS);
}

#[test]
#[serial_test::serial]
fn extended_corpus_memo_bindings() {
    run_extended(MEMO_BINDINGS);
}

#[test]
#[serial_test::serial]
fn extended_corpus_refusal_codes() {
    run_extended(REFUSAL_CODES);
}
