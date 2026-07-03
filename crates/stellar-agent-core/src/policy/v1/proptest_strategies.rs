//! Proptest strategy generators for `PolicyEngineV1` property tests.
//!
//! # Scope
//!
//! These generators cover the **four state-independent criteria**:
//!
//! | Criterion           | Strategy function               |
//! |---------------------|---------------------------------|
//! | `per_tx_cap`        | `arb_per_tx_cap_rule`         |
//! | `counterparty_allowlist` | `arb_counterparty_allowlist_rule` |
//! | `minimum_reserve`   | `arb_minimum_reserve_rule`    |
//! | `soroban_resource_fee_cap` | `arb_soroban_resource_fee_rule` |
//!
//! # Why `per_period_cap` and `rate_limit` are excluded
//!
//! Both criteria depend on `SystemTime::now()` and mutate
//! `PolicyStateStore`.  Including them in proptest
//! would make all four properties wall-clock-sensitive and create
//! flaky tests whose outcome depends on scheduler timing.
//!
//! # Coverage
//!
//! The four generators cover every criterion the engine can evaluate without
//! external clock state.  `minimum_reserve` requires an `account_view`; the
//! property tests inject a synthetic view that always returns a fixed balance
//! so the criterion's result is deterministic.
//!
//! # Runtime budget (PROPTEST_CASES override)
//!
//! The property tests in `proptest_properties.rs` configure each `proptest!`
//! block with `#![proptest_config(ProptestConfig::with_cases(10_000))]`.
//! The `PROPTEST_CASES` environment variable overrides the per-block setting and
//! can be used to lower the case count for fast local iteration:
//!
//! ```bash
//! PROPTEST_CASES=200 cargo test -p stellar-agent-core --lib
//! ```

#![cfg(any(test, feature = "test-helpers"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "proptest strategy code runs only in test context; panics are acceptable"
)]

use std::sync::LazyLock;

use proptest::prelude::*;

use stellar_agent_test_support::testnet_strkeys::{VERSION_PUBLIC_KEY, strkey_from_seed};

use crate::policy::v1::criteria::{
    CounterpartyAllowlistCriterion, MinimumReserveCriterion, PerTxCapCriterion,
    SorobanResourceFeeCriterion, counterparty_allowlist::CounterpartyKind,
};
use crate::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use crate::policy::{Decision, McpToolRegistration, ToolDescriptor};
use crate::profile::schema::Profile;

// ─────────────────────────────────────────────────────────────────────────────
// Fixed G-strkey test fixtures
//
// Generated from deterministic seed bytes via
// `stellar_agent_test_support::testnet_strkeys::strkey_from_seed`.
// These are synthetic ed25519 public keys carrying no funds on any network.
// ─────────────────────────────────────────────────────────────────────────────

/// Four deterministic testnet G-strkeys used by the allowlist strategies.
///
/// Indices 0..=2 are used as "allowed" destinations; the generator picks one
/// or more at random.  Index 3 is reserved as a "not-on-allowlist" destination
/// for future monotonicity / counterparty-miss tests.
///
/// Cached in a [`LazyLock`] so the ed25519 public-key derivation runs once per
/// process rather than per strategy invocation.  At 10 000 cases per property
/// and multiple per-property strategy invocations, this matters.
static TESTNET_G_STRKEYS: LazyLock<[String; 4]> = LazyLock::new(|| {
    const SEEDS: [[u8; 32]; 4] = [
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ],
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
            0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
            0x3D, 0x3E, 0x3F, 0x40,
        ],
        [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
            0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
            0x5D, 0x5E, 0x5F, 0x60,
        ],
        [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
            0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
            0x7D, 0x7E, 0x7F, 0x80,
        ],
    ];
    std::array::from_fn(|i| strkey_from_seed(VERSION_PUBLIC_KEY, &SEEDS[i]))
});

/// Returns a reference to the cached testnet G-strkey fixture set.
fn testnet_g_strkeys() -> &'static [String; 4] {
    &TESTNET_G_STRKEYS
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_per_tx_cap_rule
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`PolicyRule`] whose single criterion is a random `per_tx_cap`.
///
/// - `tool` name is drawn from `{"stellar_pay", "stellar_create_account", "*"}`.
/// - `max_stroops` is drawn from `1..=100_000_000_000_i64` (1 stroop to 10 000 XLM).
/// - `chain` is always `"*"` (wildcard) so the rule matches any chain ID.
/// - `decision` is always `Decision::Allow` so the criterion governs the outcome.
/// - `asset` is always `"native"` to keep the criterion applicable to the
///   payment-args generator ([`arb_payment_args`]).
pub fn arb_per_tx_cap_rule() -> impl Strategy<Value = PolicyRule> {
    let tool_names = prop_oneof![
        Just("stellar_pay".to_owned()),
        Just("stellar_create_account".to_owned()),
        Just("*".to_owned()),
    ];
    let max_stroops_strategy = 1_i64..=100_000_000_000_i64;

    (tool_names, max_stroops_strategy).prop_map(|(tool_name, max_stroops)| {
        let criterion: Box<dyn crate::policy::v1::criteria::Criterion> =
            Box::new(PerTxCapCriterion::new("native".to_owned(), max_stroops));
        PolicyRule {
            r#match: RuleMatch {
                tool: tool_name,
                chain: "*".to_owned(),
            },
            criteria: vec![criterion],
            decision: Decision::Allow,
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_counterparty_allowlist_rule
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`PolicyRule`] whose single criterion is a random
/// `counterparty_allowlist` with `G_ACCOUNT` kind.
///
/// - `kinds` is always `[G_ACCOUNT]` — the only kind that can be tested
///   without `account_view` injection.
/// - `allowlist` contains 1–3 synthetic testnet G-strkeys.
/// - `tool` name is `"stellar_pay"` (fixed — G-account checks read
///   `args["destination"]` which is produced by [`arb_payment_args`]).
/// - `chain` is `"*"`.
/// - `decision` is `Decision::Allow`.
///
/// `HOME_DOMAIN` kind is excluded because it requires `account_view` injection.
pub fn arb_counterparty_allowlist_rule() -> impl Strategy<Value = PolicyRule> {
    let strkeys = testnet_g_strkeys();
    let allowlist_count = 1_usize..=3_usize;

    allowlist_count.prop_map(move |count| {
        // Take the first `count` entries from the fixed set.
        let allowlist: Vec<String> = strkeys[..count].to_vec();
        let criterion: Box<dyn crate::policy::v1::criteria::Criterion> = Box::new(
            CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::GAccount], allowlist),
        );
        PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_pay".to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![criterion],
            decision: Decision::Allow,
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_minimum_reserve_rule
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`PolicyRule`] whose single criterion is a random
/// `minimum_reserve`.
///
/// - `margin_stroops` is drawn from `0..=1_000_000_000_i64` (0 to 100 XLM).
/// - `tool` is `"*"` (wildcard).
/// - `chain` is `"*"`.
/// - `decision` is `Decision::Allow`.
///
/// Note: the minimum-reserve criterion requires `ctx.account_view` to be set;
/// property tests inject a fixed `MockAccountView` so the result is
/// deterministic.  Without `account_view`, the criterion returns
/// `Err(CriterionEvaluationFailed)` (fail-closed).
pub fn arb_minimum_reserve_rule() -> impl Strategy<Value = PolicyRule> {
    let margin_strategy = 0_i64..=1_000_000_000_i64;

    margin_strategy.prop_map(|margin_stroops| {
        let criterion: Box<dyn crate::policy::v1::criteria::Criterion> =
            Box::new(MinimumReserveCriterion::new(margin_stroops));
        PolicyRule {
            r#match: RuleMatch {
                tool: "*".to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![criterion],
            decision: Decision::Allow,
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_soroban_resource_fee_rule
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`PolicyRule`] whose single criterion is a random
/// `soroban_resource_fee_cap`.
///
/// - `max_resource_fee_stroops` is drawn from `1..=1_000_000_000_i64`.
/// - `max_footprint_entries` is drawn from `1_u32..=1000_u32`.
/// - `tool` is `"*"` (wildcard).
/// - `chain` is `"*"`.
/// - `decision` is `Decision::Allow`.
///
/// Note: non-Soroban tools cause this criterion to return `Ok(None)` (does not
/// apply).  The property test for this rule verifies determinism by confirming
/// two evaluations of the same non-Soroban tool produce identical
/// `Ok(Decision::Allow)` results.
pub fn arb_soroban_resource_fee_rule() -> impl Strategy<Value = PolicyRule> {
    let max_fee_strategy = 1_i64..=1_000_000_000_i64;
    let max_footprint_strategy = 1_u32..=1000_u32;

    (max_fee_strategy, max_footprint_strategy).prop_map(
        |(max_resource_fee_stroops, max_footprint_entries)| {
            let criterion: Box<dyn crate::policy::v1::criteria::Criterion> = Box::new(
                SorobanResourceFeeCriterion::new(max_resource_fee_stroops, max_footprint_entries),
            );
            PolicyRule {
                r#match: RuleMatch {
                    tool: "*".to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![criterion],
                decision: Decision::Allow,
            }
        },
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_strict_deny_per_tx_rule
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`PolicyRule`] whose embedded `per_tx_cap` criterion denies
/// any payment of more than 1 stroop.
///
/// **Naming note.** The rule's own `decision` field is `Decision::Allow` (the
/// permissive fallback when the criterion does not fire); the deny outcome
/// comes from the criterion failing.  The "strict-deny" qualifier in the
/// function name reflects the **observable behaviour** of the rule when paired
/// with payment amounts ≥ 2 stroops, not the value of the `decision` field.
/// This matters for the monotonicity property: placing this rule first in the
/// document and exercising it with a >1-stroop payment forces the engine into
/// the criterion-deny short-circuit path.
///
/// Used by Property 2 (monotonicity).  The caller is responsible for choosing
/// a tool name that `per_tx_cap` actually evaluates (`stellar_pay`,
/// `stellar_create_account`, or their `_commit` variants).
///
/// Note: `PolicyRule` cannot implement `Clone` because it holds
/// `Box<dyn Criterion>`.  This strategy uses `prop_map` over `Just(())` so
/// proptest constructs a fresh instance per shrink step rather than requiring
/// `Clone`.
pub fn arb_strict_deny_per_tx_rule() -> impl Strategy<Value = PolicyRule> {
    // max_stroops = 1 stroop — catches any payment ≥ 2 stroops.
    // Use prop_map over Just(()) to construct a non-Clone value.
    Just(()).prop_map(|()| PolicyRule {
        r#match: RuleMatch {
            tool: "*".to_owned(),
            chain: "*".to_owned(),
        },
        criteria: vec![Box::new(PerTxCapCriterion::new(
            "native".to_owned(),
            1_i64, // 1 stroop cap — denies payments > 1 stroop via criterion failure
        ))],
        decision: Decision::Allow,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_tool_descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`ToolDescriptor`] for one of the standard tools.
///
/// Varies `chain_id` between `"stellar:testnet"` and `"stellar:mainnet"` to
/// exercise the chain-id filter path.  The `name` is drawn from the set of
/// tools the criterion strategies above produce rules for.
pub fn arb_tool_descriptor() -> impl Strategy<Value = ToolDescriptor> {
    let tool_names = prop_oneof![
        Just("stellar_pay"),
        Just("stellar_create_account"),
        Just("stellar_balances"),
    ];
    let chain_ids = prop_oneof![
        Just("stellar:testnet".to_owned()),
        Just("stellar:mainnet".to_owned()),
    ];

    (tool_names, chain_ids).prop_map(|(name, chain_id)| {
        let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        });
        td.chain_id = chain_id;
        td
    })
}

/// Generates a [`ToolDescriptor`] restricted to payment-like write tools.
///
/// Used by monotonicity properties that need the `per_tx_cap` criterion to be
/// active; read-only or unrelated tools would correctly return `Ok(None)`.
pub fn arb_tool_descriptor_for_payment_tools() -> impl Strategy<Value = ToolDescriptor> {
    let tool_names = prop_oneof![Just("stellar_pay"), Just("stellar_create_account")];

    tool_names.prop_map(|name| {
        let mut td = ToolDescriptor::from_registration(&McpToolRegistration {
            name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
        });
        td.chain_id = "stellar:testnet".to_owned();
        td
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_payment_args
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a `serde_json::Value` representing payment arguments for
/// `stellar_pay` or `stellar_create_account`.
///
/// The `amount` field is a decimal XLM string (e.g. `"10.0000000 XLM"`)
/// with a random stroop value in `2..=90_000_000_000_i64` (up to 9 000 XLM,
/// always >1 stroop so the strict-deny rule triggers it).
///
/// The `asset` field is partitioned across `"native"` and non-native
/// credit assets so property tests exercise both the matching and
/// asset-mismatch branches of amount criteria.
///
/// The `destination` field is a randomly chosen synthetic testnet G-strkey
/// from the first three fixture keys (those that appear on the allowlist
/// generated by [`arb_counterparty_allowlist_rule`]).
///
/// The `starting_balance` field mirrors `amount` so this value works for
/// both `stellar_pay` and `stellar_create_account`.
pub fn arb_payment_args() -> impl Strategy<Value = serde_json::Value> {
    let strkeys = testnet_g_strkeys();
    // Amount in stroops: 2 to 9 000 XLM (always above the 1-stroop strict-deny cap).
    let amount_stroops = 2_i64..=90_000_000_000_i64;
    // Pick one of the first three allowed destinations.
    let dest_idx = 0_usize..=2_usize;
    let assets = prop_oneof![
        Just("native".to_owned()),
        Just(format!("USDC:{}", strkeys[3])),
        Just(format!("EURC:{}", strkeys[2])),
    ];

    (amount_stroops, dest_idx, assets).prop_map(move |(stroops, idx, asset)| {
        // Convert stroops to 7-decimal XLM string as expected by the criteria.
        let xlm_whole = stroops / 10_000_000;
        let xlm_frac = stroops % 10_000_000;
        let amount_str = format!("{xlm_whole}.{xlm_frac:07} XLM");
        let destination = strkeys[idx].clone();
        serde_json::json!({
            "amount": amount_str,
            "starting_balance": amount_str,
            "asset": asset,
            "destination": destination,
        })
    })
}

/// Generates native-XLM payment arguments without rejection filtering.
///
/// Used by monotonicity properties whose strict-deny rule is intentionally
/// native-only. Keeping native selection in the generator avoids `prop_filter`
/// rejection churn in high-case-count runs.
pub fn arb_native_payment_args() -> impl Strategy<Value = serde_json::Value> {
    let strkeys = testnet_g_strkeys();
    let amount_stroops = 2_i64..=90_000_000_000_i64;
    let dest_idx = 0_usize..=2_usize;

    (amount_stroops, dest_idx).prop_map(move |(stroops, idx)| {
        let xlm_whole = stroops / 10_000_000;
        let xlm_frac = stroops % 10_000_000;
        let amount_str = format!("{xlm_whole}.{xlm_frac:07} XLM");
        let destination = strkeys[idx].clone();
        serde_json::json!({
            "amount": amount_str,
            "starting_balance": amount_str,
            "asset": "native",
            "destination": destination,
        })
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy: arb_profile
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a [`Profile`] for either testnet or mainnet, paired with the
/// explicit profile name used to construct it.
///
/// The profile name is drawn from a small fixed set:
/// `{"alice", "bob", "carol", "dave"}`.  Both testnet and mainnet profiles are
/// generated with equal probability.
pub fn arb_profile() -> impl Strategy<Value = (Profile, String)> {
    let profile_names = prop_oneof![Just("alice"), Just("bob"), Just("carol"), Just("dave"),];
    let is_mainnet = prop::bool::ANY;

    (profile_names, is_mainnet).prop_map(|(name, mainnet)| {
        let profile_name = name.to_owned();
        if mainnet {
            (
                Profile::builder_mainnet_named(&profile_name, "svc", "acct", "n-svc", "n-acct")
                    .build(),
                profile_name,
            )
        } else {
            (
                Profile::builder_testnet_named(&profile_name, "svc", "acct", "n-svc", "n-acct")
                    .build(),
                profile_name,
            )
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Document assembly helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a single [`PolicyRule`] into an [`AllProfiles`]-scoped
/// [`PolicyDocument`] with no signature (test-constructed).
///
/// [`AllProfiles`]: ScopeId::AllProfiles
pub fn single_rule_document(rule: PolicyRule) -> PolicyDocument {
    PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: vec![rule],
        signature: None,
    }
}

/// Builds a two-rule [`PolicyDocument`] with `first` before `second`.
///
/// First-match-stop semantics: if `first` matches the tool, it wins; `second`
/// is evaluated only if `first` does not match.
pub fn two_rule_document(first: PolicyRule, second: PolicyRule) -> PolicyDocument {
    PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: vec![first, second],
        signature: None,
    }
}

#[cfg(test)]
mod tests {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    use super::*;

    /// Build a deterministic-RNG `TestRunner` so cargo-mutants results are
    /// reproducible across invocations.  Strategy fixture tests must surface the
    /// same mutant-kill verdict on every run.
    /// `TestRng::deterministic_rng(RngAlgorithm::ChaCha)` is proptest 1.11's
    /// canonical fixed-seed RNG;
    /// combined with the 16-case cap below it gives a reproducible distribution.
    fn seeded_runner() -> TestRunner {
        TestRunner::new_with_rng(
            Config {
                cases: 16,
                ..Config::default()
            },
            TestRng::deterministic_rng(RngAlgorithm::ChaCha),
        )
    }

    #[test]
    fn arb_payment_args_amount_matches_stroop_decimal_format() {
        let mut runner = seeded_runner();

        for _ in 0..16 {
            let value = arb_payment_args()
                .new_tree(&mut runner)
                .expect("strategy must produce payment args")
                .current();
            let amount = value
                .get("amount")
                .and_then(serde_json::Value::as_str)
                .expect("amount must be a string");
            let starting_balance = value
                .get("starting_balance")
                .and_then(serde_json::Value::as_str)
                .expect("starting_balance must be a string");
            assert_eq!(
                amount, starting_balance,
                "starting_balance mirrors amount for shared pay/create-account args"
            );

            let numeric = amount
                .strip_suffix(" XLM")
                .expect("amount must carry XLM suffix");
            let (whole, frac) = numeric.split_once('.').expect("amount must be decimal XLM");
            assert_eq!(
                frac.len(),
                7,
                "fractional stroops must be zero-padded to seven places"
            );
            assert!(
                whole.chars().all(|c| c.is_ascii_digit())
                    && frac.chars().all(|c| c.is_ascii_digit()),
                "amount must contain only decimal digits and one dot: {amount}"
            );

            let whole_stroops: i64 = whole.parse::<i64>().expect("whole part parses") * 10_000_000;
            let frac_stroops: i64 = frac.parse().expect("fractional part parses");
            let reconstructed = whole_stroops + frac_stroops;
            assert!(
                (2..=90_000_000_000_i64).contains(&reconstructed),
                "reconstructed stroops must remain in generator range: {reconstructed}"
            );
        }
    }

    #[test]
    fn arb_payment_args_samples_non_native_asset_partition() {
        let mut runner = TestRunner::new_with_rng(
            Config {
                cases: 64,
                ..Config::default()
            },
            TestRng::deterministic_rng(RngAlgorithm::ChaCha),
        );
        let mut non_native = 0usize;

        for _ in 0..64 {
            let value = arb_payment_args()
                .new_tree(&mut runner)
                .expect("strategy must produce payment args")
                .current();
            let asset = value
                .get("asset")
                .and_then(serde_json::Value::as_str)
                .expect("asset must be a string");
            if asset != "native" {
                non_native += 1;
            }
        }

        assert!(
            non_native >= 7,
            "at least 10% of 64 samples must be non-native, got {non_native}"
        );
    }

    #[test]
    fn arb_native_payment_args_always_samples_native_asset() {
        let mut runner = TestRunner::new_with_rng(
            Config {
                cases: 64,
                ..Config::default()
            },
            TestRng::deterministic_rng(RngAlgorithm::ChaCha),
        );

        for _ in 0..64 {
            let value = arb_native_payment_args()
                .new_tree(&mut runner)
                .expect("strategy must produce native payment args")
                .current();
            assert_eq!(
                value.get("asset").and_then(serde_json::Value::as_str),
                Some("native")
            );
        }
    }

    #[test]
    fn profile_strategy_outputs_expected_non_empty_names() {
        let mut runner = seeded_runner();

        for _ in 0..16 {
            let (_profile, name) = arb_profile()
                .new_tree(&mut runner)
                .expect("strategy must produce profile")
                .current();
            assert!(!name.is_empty(), "profile_name must not be empty");
            assert_ne!(name, "xyzzy", "profile_name must not be mutant sentinel");
            assert!(
                matches!(name.as_str(), "alice" | "bob" | "carol" | "dave"),
                "profile_name must come from the strategy fixture set: {name}"
            );
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase()),
                "profile_name must be lowercase ASCII: {name}"
            );
        }
    }
}
