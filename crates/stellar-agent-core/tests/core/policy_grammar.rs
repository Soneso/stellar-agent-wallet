//! Policy grammar and evaluation of unlisted recipients, total budgets, the
//! observed balance floor, memo bindings, provisional evaluation, and the
//! mainnet minimum for claims and trustlines.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures fail loudly"
)]

use std::any::Any;

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use stellar_agent_core::{
    approval::store::DEFAULT_TTL_MS,
    asset_id::CanonicalAsset,
    envelope_decode::ClassicMemo,
    policy::{
        Decision, DenyReason, Evaluation, McpToolRegistration, PolicyEngine, PolicyError,
        ToolDescriptor, ToolValueKind, UnlistedBound,
        v1::{
            AccountIdentityView, AccountReserveLookupError, AccountReservesView,
            CounterpartyCacheView, EvalContext, FloorInput, ObservedAccount, PolicyEngineV1,
            PolicyStateStore, Sep10SessionView, Sep45SessionView,
            bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor},
            canonical::canonical_bytes,
            criteria::{
                Criterion,
                balance_floor::{BalanceFloorCriterion, MAX_OBSERVATION_AGE_MS},
                counterparty_allowlist::{
                    CounterpartyAllowlistCriterion, CounterpartyKind, RecipientClass, UnlistedMode,
                },
                memo_binding::{MemoBinding, MemoBindingCriterion, MemoRequirement},
                state_store::{StateKey, WindowLimit, set_query_time_for_test},
            },
            loader::{PolicyDocument, load_signed_policy_text},
            mainnet_minimum, validate_unsigned_policy,
            value::{ActionKind, ValueClass, ValueEffects, ValueLeg},
        },
    },
    profile::{caip2::TESTNET_PASSPHRASE, schema::Profile},
};
use toml_edit::DocumentMut;

use crate::policy_compat_guards::{FIXTURE, FIXTURE_CANONICAL, FIXTURE_DIGEST_HEX};

/// An account on the test lists.
const LISTED: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// A well-formed account outside the test lists.
const UNLISTED: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// A fixed policy clock for tests that read time.
const NOW_MS: u64 = 1_800_000_000_000;

/// The instant an evaluation reads: the policy clock, which a test that reads
/// time fixes at [`NOW_MS`].
fn instant() -> u64 {
    stellar_agent_core::policy::policy_now_ms().expect("policy clock")
}
/// One week in milliseconds.
const WEEK_MS: u64 = 7 * 86_400_000;

#[test]
fn unselected_kind_destination_consumes_unlisted_budget() {
    let _clock = set_query_time_for_test(NOW_MS);
    let engine = engine_from_criteria(&budget(10, 20));
    let destination = contract(3);
    let evaluated = strict(&engine, payment(6, &destination), None).unwrap();
    assert_eq!(evaluated.decision, Decision::Allow);
    assert_eq!(
        evaluated.value_effects.as_ref().unwrap().recipient_class(),
        Some(RecipientClass::Unlisted)
    );
    let entries = engine
        .record_confirmed(
            &pay(),
            &profile(),
            &ValueClass::Value(evaluated.value_effects.unwrap()),
        )
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key(), &unlisted_key());
    assert_eq!(entries[0].amount(), 6);
    assert_eq!(
        engine
            .state_store()
            .query_window(&unlisted_key(), NOW_MS)
            .unwrap(),
        (6, 1)
    );
    assert!(matches!(
        decide(&engine, payment(15, &destination)),
        Decision::Deny(DenyReason::UnlistedBudgetExceeded { .. })
    ));
}

fn g_c_budget_criterion() -> String {
    "{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [], unlisted = { mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", window = \"1d\" } }".into()
}

#[test]
fn unverified_domain_never_reaches_unlisted_mode() {
    let identity = Identity(Some("example.com"));
    let cache = Cache {
        resolved: false,
        listed: false,
    };
    for mode in [
        "{ mode = \"approval\" }",
        "{ mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, window = \"1d\" }",
    ] {
        let criteria = format!(
            "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\", \"HOME_DOMAIN\"], allowlist = [\"example.com\"], unlisted = {mode} }}"
        );
        let engine = engine_from_criteria(&criteria);
        let decision = engine
            .evaluate_with_value(
                &pay(),
                &Value::Null,
                &profile(),
                payment(1, LISTED),
                None,
                Some(&identity),
                Some(&cache),
                None,
                None,
                NOW_MS,
            )
            .unwrap();
        // The address check precedes HOME_DOMAIN in `kinds`, so its denial is
        // the first; the unverified domain keeps it final in every mode.
        assert_eq!(
            decision,
            Decision::Deny(DenyReason::CounterpartyDenied {
                kind: "G_ACCOUNT".into(),
                value: LISTED.into(),
            })
        );
        let criterion = loaded_criterion::<CounterpartyAllowlistCriterion>(
            &load(&v2(&rule(&criteria, "allow"))),
            0,
            0,
        )
        .clone();
        assert_eq!(
            classify(
                &criterion,
                payment(1, LISTED),
                Some(&identity),
                Some(&cache)
            )
            .unwrap(),
            Some(RecipientClass::Unverifiable)
        );
        let domain_only = allowlist(CounterpartyKind::HomeDomain, &["example.com"]);
        let tool = pay();
        let profile = profile();
        let store = PolicyStateStore::new();
        let args = Value::Null;
        let ctx = EvalContext::new(&tool, &args, "operator", &profile, &store, NOW_MS)
            .with_value(ValueClass::single(leg(
                ActionKind::Claim,
                1,
                "native",
                Some(LISTED),
            )))
            .with_identity_view(&identity)
            .with_counterparty_cache(&cache);
        assert_eq!(
            domain_only.recipient_class(&ctx).unwrap(),
            Some(RecipientClass::Listed)
        );
        assert!(
            matches!(domain_only.evaluate_decision(&ctx).unwrap(), Decision::Deny(DenyReason::CounterpartyDenied { kind, .. }) if kind == "HOME_DOMAIN")
        );
    }
}

#[test]
fn mixed_g_c_bundle_overlay_and_confirmation() {
    let _clock = set_query_time_for_test(NOW_MS);
    let text = g_c_budget_criterion();
    let document = load(&v2(&rule(&text, "allow")));
    let criterion = loaded_criterion::<CounterpartyAllowlistCriterion>(&document, 0, 0);
    let inners = [transfer(LISTED, 6), transfer(&contract(3), 6)];
    let mut overlay = BundleStateOverlay::default();
    let tool = pay();
    let profile = profile();
    let store = PolicyStateStore::new();
    let ctx = EvalContext::new(&tool, &Value::Null, "operator", &profile, &store, NOW_MS);
    for inner in &inners {
        criterion.accumulate_overlay(&ctx, inner, &mut overlay);
    }
    let next = [transfer(LISTED, 9)];
    let bundle = BundleView {
        inners: &next,
        overlay: &overlay,
    };
    let ctx = ctx.with_value(payment(9, LISTED)).with_bundle(&bundle);
    assert!(matches!(
        criterion.evaluate_decision(&ctx).unwrap(),
        Decision::Deny(DenyReason::UnlistedBudgetExceeded {
            bound: UnlistedBound::PerPeriod,
            ..
        })
    ));
    let engine = engine_from_criteria(&text);
    assert_eq!(evaluate_bundle(&engine, &inners), Decision::Allow);
    assert!(matches!(
        evaluate_bundle(
            &engine,
            &[inners[0].clone(), inners[1].clone(), transfer(LISTED, 9)]
        ),
        Decision::Deny(DenyReason::BundleDenied { inner_index: 2, .. })
    ));
    let evaluated = strict(&engine, payment(6, &contract(3)), None).unwrap();
    assert_eq!(
        evaluated.value_effects.unwrap().recipient_class(),
        Some(RecipientClass::Unlisted)
    );
    let entries = confirm_bundle(&engine, &inners).unwrap();
    assert_eq!(entries.iter().map(|entry| entry.amount()).sum::<i128>(), 12);
    assert_eq!(
        engine
            .state_store()
            .query_window(&unlisted_key(), NOW_MS)
            .unwrap(),
        (12, 2)
    );
}

#[test]
fn loaded_g_c_budget_sizes_and_records() {
    let _clock = set_query_time_for_test(NOW_MS);
    let engine = engine_from_criteria(&g_c_budget_criterion());
    let evaluated = strict(&engine, payment(6, LISTED), None).unwrap();
    assert_eq!(evaluated.decision, Decision::Allow);
    let value = ValueClass::Value(evaluated.value_effects.unwrap());
    let entries = engine
        .size_window_entries(&pay(), &profile(), &value, NOW_MS)
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].amount(), 6);
    engine.record_confirmed(&pay(), &profile(), &value).unwrap();
    assert_eq!(
        engine
            .state_store()
            .query_window(&unlisted_key(), NOW_MS)
            .unwrap(),
        (6, 1)
    );
}

#[test]
fn unlisted_call_charges_every_debit_leg() {
    let criterion =
        g_c_budget_criterion().replace("allowlist = []", &format!("allowlist = [\"{LISTED}\"]"));
    let engine = engine_from_criteria(&criterion);
    let value = ValueClass::Value(ValueEffects::new(vec![
        leg(ActionKind::Payment, 3, "native", Some(LISTED)),
        leg(ActionKind::Payment, 4, "native", Some(&contract(3))),
    ]));
    let evaluated = strict(&engine, value, None).unwrap();
    assert_eq!(evaluated.decision, Decision::Allow);
    let entries = engine
        .size_window_entries(
            &pay(),
            &profile(),
            &ValueClass::Value(evaluated.value_effects.unwrap()),
            NOW_MS,
        )
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].amount(), 7);
}

#[test]
fn opaque_signing_and_generic_inners_refuse_under_address_kinds() {
    for mode in [
        "{ mode = \"deny\" }",
        "{ mode = \"approval\" }",
        "{ mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, window = \"1d\" }",
    ] {
        let raw = v2(&format!(
            "{}allow_opaque_signing = true\n",
            rule_for("*", &cp(mode), "allow")
        ));
        let engine = engine(&raw);
        for name in [
            "stellar_sep43_sign_transaction",
            "stellar_sep43_sign_and_submit_transaction",
            "stellar_sep43_sign_auth_entry",
            "stellar_pay_commit",
            "stellar_claim_commit",
        ] {
            let tool = ToolDescriptor::from_registration(&McpToolRegistration {
                name,
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: ToolValueKind::OpaqueSign,
            });
            let value = ValueClass::Opaque(
                stellar_agent_core::policy::v1::value::OpaqueReason::RawTransactionSignature,
            );
            let result = engine.evaluate_with_value(
                &tool,
                &json!({}),
                &profile(),
                value,
                None,
                None,
                None,
                None,
                None,
                NOW_MS,
            );
            let Err(PolicyError::CriterionEvaluationFailed { detail }) = result else {
                panic!("{name}: {result:?}");
            };
            assert_eq!(detail, missing_destination(name), "{name}");
        }
        let inners = [generic()];
        let overlay = BundleStateOverlay::default();
        let result = engine.evaluate_bundle(
            &pay(),
            &json!({"smart_account": contract(3), "rule_id": 1}),
            &profile(),
            &BundleView {
                inners: &inners,
                overlay: &overlay,
            },
        );
        if mode.contains("budget") {
            assert!(matches!(
                result.unwrap(),
                Decision::Deny(DenyReason::BundleContainsGenericKind { inner_index: 0 })
            ));
        } else {
            let Err(PolicyError::CriterionEvaluationFailed { detail }) = result else {
                panic!("{mode}: {result:?}");
            };
            assert_eq!(detail, missing_destination("stellar_pay"), "{mode}");
        }
    }
}

/// The raw-path refusal of a call that carries no `destination`.
fn missing_destination(tool: &str) -> String {
    format!(
        "counterparty_allowlist: missing or non-string field 'destination' in args for tool '{tool}'"
    )
}

#[test]
fn window_grammar_keeps_five_values_and_rejects_30d() {
    use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    for (name, seconds) in [
        ("1m", 60),
        ("5m", 300),
        ("1h", 3600),
        ("1d", 86400),
        ("1w", 604800),
    ] {
        assert_eq!(Window::parse(name).unwrap().as_secs(), seconds);
    }
    assert!(Window::parse("30d").is_err());
    for zero in ["0", "0s", "0m", "0h", "0d", "0w"] {
        assert!(Window::parse(zero).is_err());
    }
    let total = StateKey::new("operator", 1, "total:native", 0);
    assert_eq!(total.window_secs(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Documents
// ─────────────────────────────────────────────────────────────────────────────

fn owner_key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

/// Signs `raw` with the owner key over the BLAKE3 digest of its canonical
/// bytes.
fn signed(raw: &str) -> String {
    let key = owner_key();
    let canonical = canonical_bytes(raw).unwrap();
    let signature = key.sign(blake3::hash(&canonical).as_bytes());
    format!(
        "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&signature.to_bytes())
    )
}

/// Loads a signed policy file on the test network.
fn load_text(text: &str) -> Result<PolicyDocument, PolicyError> {
    load_signed_policy_text(
        text,
        "operator",
        &owner_key().verifying_key().to_bytes(),
        TESTNET_PASSPHRASE,
    )
}

/// Signs and loads `raw` on the test network.
fn load(raw: &str) -> PolicyDocument {
    load_text(&signed(raw)).unwrap()
}

fn v2(rules: &str) -> String {
    format!("version = 2\nscope = \"profile:operator\"\nsequence = 1\n\n{rules}")
}

fn v1(rules: &str) -> String {
    format!("version = 1\nscope = \"profile:operator\"\n\n{rules}")
}

/// A rule for `tool` with `criteria` and `decision`. A `require_approval` rule
/// carries a reason and no lifetime.
fn rule_for(tool: &str, criteria: &str, decision: &str) -> String {
    let approval = if decision == "require_approval" {
        "reason = \"review\"\n"
    } else {
        ""
    };
    format!(
        "[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"*\" }}\ncriteria = [{criteria}]\n\
         decision = \"{decision}\"\n{approval}"
    )
}

fn rule(criteria: &str, decision: &str) -> String {
    rule_for("stellar_pay", criteria, decision)
}

/// Validates an unsigned body on the test network.
fn check(raw: &str) -> Result<(), PolicyError> {
    validate_unsigned_policy(raw, "operator", TESTNET_PASSPHRASE)
}

/// Asserts that the loader refuses `raw` with exactly `detail`.
fn refused(raw: &str, detail: &str) {
    match check(raw) {
        Err(PolicyError::PolicyFileParseFailed { detail: actual }) => {
            assert_eq!(actual, detail, "{raw}");
        }
        other => panic!("expected the refusal {detail:?}, got {other:?} for {raw}"),
    }
}

/// A `counterparty_allowlist` criterion listing [`LISTED`] with an
/// `unlisted` table.
fn cp(unlisted: &str) -> String {
    format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{LISTED}\"], \
         unlisted = {unlisted} }}"
    )
}

fn budget(per_tx: i64, per_period: i64) -> String {
    cp(&format!(
        "{{ mode = \"budget\", per_tx_stroops = {per_tx}, per_period_stroops = {per_period}, \
         window = \"1d\" }}"
    ))
}

fn loaded_criterion<T: 'static>(document: &PolicyDocument, rule: usize, index: usize) -> &T {
    let criterion: &dyn Criterion = document.rules[rule].criteria[index].as_ref();
    (criterion as &dyn Any).downcast_ref::<T>().unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluation fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn profile() -> Profile {
    Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
}

fn tool(name: &'static str) -> ToolDescriptor {
    ToolDescriptor::from_registration(&McpToolRegistration {
        name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    })
}

fn pay() -> ToolDescriptor {
    tool("stellar_pay")
}

fn leg(kind: ActionKind, amount: i128, asset: &str, destination: Option<&str>) -> ValueLeg {
    ValueLeg {
        kind,
        amount: Some(amount),
        asset: Some(asset.to_owned()),
        destination: destination.map(ToOwned::to_owned),
    }
}

fn payment(amount: i128, destination: &str) -> ValueClass {
    ValueClass::single(leg(
        ActionKind::Payment,
        amount,
        "native",
        Some(destination),
    ))
}

fn engine(raw: &str) -> PolicyEngineV1 {
    PolicyEngineV1::new_with_store(load(raw), "operator".to_owned(), PolicyStateStore::new())
        .with_policy_digest_for_test([5; 32])
}

/// Evaluates `value` strictly with `account_view`.
fn strict(
    engine: &dyn PolicyEngine,
    value: ValueClass,
    account_view: Option<&dyn AccountReservesView>,
) -> Result<Evaluation, PolicyError> {
    engine.evaluate_with_value_full(
        &pay(),
        &Value::Null,
        &profile(),
        value,
        account_view,
        None,
        None,
        None,
        None,
        instant(),
    )
}

/// Evaluates `value` provisionally without views.
fn provisional(engine: &dyn PolicyEngine, value: ValueClass) -> Result<Evaluation, PolicyError> {
    engine.evaluate_provisional(
        &pay(),
        &Value::Null,
        &profile(),
        value,
        None,
        None,
        None,
        None,
        None,
        instant(),
    )
}

fn decide(engine: &PolicyEngineV1, value: ValueClass) -> Decision {
    strict(engine, value, None).unwrap().decision
}

fn muxed(base: &str, id: u64) -> String {
    let base = stellar_strkey::ed25519::PublicKey::from_string(base).unwrap();
    format!(
        "{}",
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: base.0,
            id
        }
    )
}

fn contract(byte: u8) -> String {
    format!("{}", stellar_strkey::Contract([byte; 32]))
}

/// The classic asset the tests pin, issued by [`LISTED`].
fn usd() -> String {
    format!("USD:{LISTED}")
}

/// The Stellar Asset Contract of `asset` on the test network.
fn sac(asset: &str) -> String {
    let asset = if asset == "native" {
        CanonicalAsset::Native
    } else {
        CanonicalAsset::parse_threshold_key(asset).unwrap()
    };
    asset.sac_contract_id(TESTNET_PASSPHRASE).unwrap()
}

/// An account view with a native balance and the reserve of an account
/// without subentries.
struct Balance(i64);

impl AccountReservesView for Balance {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        2 * base_reserve_stroops
    }

    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        Ok(self.0)
    }
}

/// An account view whose balance cannot be read.
struct Unreadable;

impl AccountReservesView for Unreadable {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        2 * base_reserve_stroops
    }

    fn balance_stroops(&self) -> Result<i64, AccountReserveLookupError> {
        Err(AccountReserveLookupError {
            detail: "no native balance".to_owned(),
        })
    }
}

/// The account a `HOME_DOMAIN` check reads.
struct Identity(Option<&'static str>);

impl AccountIdentityView for Identity {
    fn home_domain(&self) -> Option<String> {
        self.0.map(ToOwned::to_owned)
    }

    fn account_id(&self) -> &str {
        UNLISTED
    }
}

/// A counterparty cache with a resolution and a listing answer.
struct Cache {
    resolved: bool,
    listed: bool,
}

impl CounterpartyCacheView for Cache {
    fn has_resolved(&self, _home_domain: &str) -> bool {
        self.resolved
    }

    fn is_account_listed(&self, _home_domain: &str, _account_id: &str) -> bool {
        self.listed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical form and signature
// ─────────────────────────────────────────────────────────────────────────────

/// Every new field and nested key is covered by the owner signature, and the
/// order of nested keys does not change the canonical bytes.
#[test]
fn new_policy_fields_are_signed() {
    let binding_a = format!("{{ destination = \"{UNLISTED}\", kind = \"id\", value = \"7\" }}");
    let approval = v2(&rule(
        &format!(
            "{}, {{ kind = \"total_budget\", asset = \"native\", max_stroops = 1000 }}, \
             {{ kind = \"balance_floor\", min_stroops = 50 }}, \
             {{ kind = \"memo_binding\", bindings = [{binding_a}] }}",
            cp("{ mode = \"approval\" }")
        ),
        "allow",
    ));
    let budget = v2(&rule(
        &cp(
            "{ mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, \
             asset = \"native\", window = \"1d\" }",
        ),
        "allow",
    ));
    let other = format!("{}", stellar_strkey::ed25519::PublicKey([9; 32]));
    let edits: [(&str, &str, &str); 11] = [
        (&approval, "mode = \"approval\"", "mode = \"deny\""),
        (&approval, "max_stroops = 1000", "max_stroops = 1001"),
        (
            &approval,
            "asset = \"native\", max_stroops",
            "asset = \"XLM\", max_stroops",
        ),
        (&approval, "min_stroops = 50", "min_stroops = 51"),
        (&approval, "value = \"7\"", "value = \"8\""),
        (
            &approval,
            "kind = \"id\", value = \"7\"",
            "kind = \"text\", value = \"7\"",
        ),
        (&approval, UNLISTED, &other),
        (&budget, "per_tx_stroops = 10", "per_tx_stroops = 11"),
        (
            &budget,
            "per_period_stroops = 20",
            "per_period_stroops = 21",
        ),
        (
            &budget,
            "asset = \"native\", window",
            "asset = \"XLM\", window",
        ),
        (&budget, "window = \"1d\"", "window = \"1h\""),
    ];
    for (raw, from, to) in edits {
        let original = signed(raw);
        load_text(&original).unwrap();
        let edited = original.replacen(from, to, 1);
        assert_ne!(edited, original, "the edit {from} must apply");
        check(edited.split("\n[signature]").next().unwrap())
            .unwrap_or_else(|error| panic!("the edit {from} -> {to} must stay valid: {error:?}"));
        assert!(
            matches!(
                load_text(&edited),
                Err(PolicyError::OwnerSignatureInvalid { .. })
            ),
            "the edit {from} -> {to} must break the signature"
        );
    }

    let reordered = budget.replace(
        "{ mode = \"budget\", per_tx_stroops = 10, per_period_stroops = 20, asset = \"native\", \
         window = \"1d\" }",
        "{ window = \"1d\", asset = \"native\", per_period_stroops = 20, per_tx_stroops = 10, \
         mode = \"budget\" }",
    );
    assert_ne!(reordered, budget);
    assert_eq!(
        canonical_bytes(&reordered).unwrap(),
        canonical_bytes(&budget).unwrap()
    );
    let reordered_binding = approval.replace(
        &binding_a,
        &format!("{{ value = \"7\", kind = \"id\", destination = \"{UNLISTED}\" }}"),
    );
    assert_ne!(reordered_binding, approval);
    assert_eq!(
        canonical_bytes(&reordered_binding).unwrap(),
        canonical_bytes(&approval).unwrap()
    );
    load_text(&signed(&approval).replace(
        &binding_a,
        &format!("{{ value = \"7\", kind = \"id\", destination = \"{UNLISTED}\" }}"),
    ))
    .unwrap();
}

/// Adds `addition` as the last criterion of the fixture's rule.
fn fixture_with_criterion(addition: &str) -> String {
    FIXTURE.replacen(
        "    { kind = \"rate_limit\", window = \"1d\", max_calls = 10 },\n",
        &format!(
            "    {{ kind = \"rate_limit\", window = \"1d\", max_calls = 10 }},\n    {addition},\n"
        ),
        1,
    )
}

/// The fixture with `addition` changes canonical bytes and digest; the same
/// document without it matches the guard literals.
fn assert_absent_addition_keeps_bytes_and_digest(with: &str) {
    assert_ne!(with, FIXTURE, "the addition must apply");
    let canonical = canonical_bytes(with).unwrap();
    assert_ne!(
        String::from_utf8(canonical.clone()).unwrap(),
        FIXTURE_CANONICAL
    );
    assert_ne!(
        stellar_agent_core::hex::encode(blake3::hash(&canonical).as_bytes()),
        FIXTURE_DIGEST_HEX
    );

    let mut doc = with.parse::<DocumentMut>().unwrap();
    let criteria = doc["rules"][0]["criteria"].as_array_mut().unwrap();
    for index in (0..criteria.len()).rev() {
        let table = criteria
            .get_mut(index)
            .unwrap()
            .as_inline_table_mut()
            .unwrap();
        table.remove("unlisted");
        let kind = table["kind"].as_str().unwrap();
        if matches!(kind, "total_budget" | "balance_floor" | "memo_binding") {
            criteria.remove(index);
        }
    }
    let without = canonical_bytes(&doc.to_string()).unwrap();
    assert_eq!(
        String::from_utf8(without.clone()).unwrap(),
        FIXTURE_CANONICAL
    );
    assert_eq!(
        stellar_agent_core::hex::encode(blake3::hash(&without).as_bytes()),
        FIXTURE_DIGEST_HEX
    );
}

#[test]
fn document_without_unlisted_keeps_bytes_and_digest() {
    let with = FIXTURE.replacen(
        "allowlist = [\"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\"] }",
        "allowlist = [\"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\"], \
         unlisted = { mode = \"approval\" } }",
        1,
    );
    assert_absent_addition_keeps_bytes_and_digest(&with);
}

#[test]
fn document_without_total_budget_keeps_bytes_and_digest() {
    assert_absent_addition_keeps_bytes_and_digest(&fixture_with_criterion(
        "{ kind = \"total_budget\", asset = \"native\", max_stroops = \"500\" }",
    ));
}

#[test]
fn document_without_balance_floor_keeps_bytes_and_digest() {
    assert_absent_addition_keeps_bytes_and_digest(&fixture_with_criterion(
        "{ kind = \"balance_floor\", min_stroops = \"20000000\" }",
    ));
}

#[test]
fn document_without_memo_binding_keeps_bytes_and_digest() {
    assert_absent_addition_keeps_bytes_and_digest(&fixture_with_criterion(&format!(
        "{{ kind = \"memo_binding\", bindings = [{{ destination = \"{UNLISTED}\", kind = \"any\" }}] }}"
    )));
}

// ─────────────────────────────────────────────────────────────────────────────
// Unlisted grammar
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unlisted_modes_validate_closed_grammar() {
    let loc = "rule[0].criteria[0].unlisted";
    let mode_of = |unlisted: &str| -> UnlistedMode {
        let document = load(&v2(&rule(&cp(unlisted), "allow")));
        loaded_criterion::<CounterpartyAllowlistCriterion>(&document, 0, 0)
            .unlisted()
            .unwrap()
            .clone()
    };

    // Defaults: an empty table and an omitted mode deny; the budget asset is
    // native.
    assert_eq!(mode_of("{}"), UnlistedMode::Deny);
    assert_eq!(mode_of("{ mode = \"deny\" }"), UnlistedMode::Deny);
    assert_eq!(mode_of("{ mode = \"approval\" }"), UnlistedMode::Approval);
    let UnlistedMode::Budget(parsed) = mode_of(
        "{ mode = \"budget\", per_tx_stroops = 10, per_period_stroops = \"20\", window = \"1h\" }",
    ) else {
        panic!("budget mode");
    };
    assert_eq!(parsed.asset(), "native");
    assert_eq!(parsed.per_tx_stroops(), 10);
    assert_eq!(parsed.per_period_stroops(), 20);
    assert_eq!(parsed.window().label(), "1h");
    let document = load(&v2(&rule(
        &format!(
            "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{LISTED}\"] }}"
        ),
        "allow",
    )));
    assert!(
        loaded_criterion::<CounterpartyAllowlistCriterion>(&document, 0, 0)
            .unlisted()
            .is_none()
    );

    // Keys per mode.
    for (mode, extra) in [
        ("deny", "window = \"1d\""),
        ("approval", "per_tx_stroops = 1"),
        ("approval", "asset = \"native\""),
    ] {
        refused(
            &v2(&rule(
                &cp(&format!("{{ mode = \"{mode}\", {extra} }}")),
                "allow",
            )),
            &format!("{loc}: mode `{mode}` accepts no key other than `mode`"),
        );
    }
    for (missing, body) in [
        ("per_tx_stroops", "per_period_stroops = 2, window = \"1d\""),
        ("per_period_stroops", "per_tx_stroops = 1, window = \"1d\""),
    ] {
        refused(
            &v2(&rule(
                &cp(&format!("{{ mode = \"budget\", {body} }}")),
                "allow",
            )),
            &format!("{loc}: missing or non-integer required field `{missing}`"),
        );
    }
    let missing_window = check(&v2(&rule(
        &cp("{ mode = \"budget\", per_tx_stroops = 1, per_period_stroops = 2 }"),
        "allow",
    )));
    assert!(
        matches!(
            &missing_window,
            Err(PolicyError::PolicyFileParseFailed { detail })
                if detail.starts_with(&format!("{loc}: ")) && detail.contains("`window`")
        ),
        "{missing_window:?}"
    );
    refused(
        &v2(&rule(&cp("{ mode = \"allow\" }"), "allow")),
        &format!("{loc}: `mode` must be deny, approval, or budget"),
    );
    refused(
        &v2(&rule(&cp("\"approval\""), "allow")),
        &format!("{loc}: must be an inline table"),
    );

    // `approval` and `budget` require an allow rule; `deny` takes any decision.
    for decision in ["deny", "require_approval"] {
        for unlisted in [
            "{ mode = \"approval\" }",
            "{ mode = \"budget\", per_tx_stroops = 1, per_period_stroops = 2, window = \"1d\" }",
        ] {
            refused(
                &v2(&rule(&cp(unlisted), decision)),
                &format!("{loc}: this mode requires decision = \"allow\""),
            );
        }
        check(&v2(&rule(&cp("{ mode = \"deny\" }"), decision))).unwrap();
    }

    // Unknown nested keys.
    refused(
        &v2(&rule(
            &cp(
                "{ mode = \"budget\", per_tx_stroops = 1, per_period_stroops = 2, window = \"1d\", \
                 cap = 3 }",
            ),
            "allow",
        )),
        &format!(
            "{loc}: unknown key; an `unlisted` table accepts mode, per_tx_stroops, \
             per_period_stroops, asset, window"
        ),
    );

    // Negative amounts refuse; zero and decimal strings load.
    refused(
        &v2(&rule(&budget(-1, 2), "allow")),
        &format!("{loc}: `per_tx_stroops` must be non-negative"),
    );
    refused(
        &v2(&rule(&budget(1, -2), "allow")),
        &format!("{loc}: `per_period_stroops` must be non-negative"),
    );
    check(&v2(&rule(&budget(0, 0), "allow"))).unwrap();
    check(&v2(&rule(
        &cp(
            "{ mode = \"budget\", per_tx_stroops = \"170141183460469231731687303715884105727\", \
             per_period_stroops = \"0\", window = \"1d\" }",
        ),
        "allow",
    )))
    .unwrap();

    // Each window loads; any other refuses.
    for window in ["1m", "5m", "1h", "1d", "1w"] {
        let UnlistedMode::Budget(parsed) = mode_of(&format!(
            "{{ mode = \"budget\", per_tx_stroops = 1, per_period_stroops = 2, window = \"{window}\" }}"
        )) else {
            panic!("budget mode");
        };
        assert_eq!(parsed.window().label(), window);
    }
    refused(
        &v2(&rule(
            &cp(
                "{ mode = \"budget\", per_tx_stroops = 1, per_period_stroops = 2, window = \"30d\" }",
            ),
            "allow",
        )),
        &format!("{loc}: `window` is not accepted; valid values: 1m, 5m, 1h, 1d, 1w"),
    );

    // A version 1 document refuses the table, in every mode.
    for unlisted in ["{}", "{ mode = \"deny\" }", "{ mode = \"approval\" }"] {
        refused(
            &v1(&rule(&cp(unlisted), "allow")),
            "rule[0].criteria[0]: counterparty_allowlist.unlisted requires policy version 2",
        );
    }
}

#[test]
fn second_unlisted_criterion_refuses_policy() {
    let plain = format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{LISTED}\"] }}"
    );
    let approval = cp("{ mode = \"approval\" }");
    let deny = cp("{ mode = \"deny\" }");

    refused(
        &v2(&rule(&format!("{approval}, {deny}"), "allow")),
        "rule[0].criteria[1]: a policy carries at most one `unlisted` table; \
         rule[0].criteria[0] carries the first",
    );
    refused(
        &v2(&format!(
            "{}{}",
            rule_for("stellar_pay", &format!("{plain}, {approval}"), "allow"),
            rule_for("stellar_create_account", &deny, "allow"),
        )),
        "rule[1].criteria[0]: every `unlisted` table of a policy must equal the first; \
         rule[0].criteria[1] carries the first",
    );
    check(&v2(&format!(
        "{}{}",
        rule_for("stellar_pay", &format!("{plain}, {approval}"), "allow"),
        rule_for("stellar_create_account", &plain, "allow"),
    )))
    .unwrap();

    // Two equal tables in one rule refuse with the same text.
    refused(
        &v2(&rule(&format!("{approval}, {approval}"), "allow")),
        "rule[0].criteria[1]: a policy carries at most one `unlisted` table; \
         rule[0].criteria[0] carries the first",
    );
    // The second table of a later rule names the first table of that rule.
    let shared = budget(10, 20);
    refused(
        &v2(&format!(
            "{}{}",
            rule_for("stellar_pay", &shared, "allow"),
            rule_for(
                "stellar_x402_create_payment",
                &format!("{shared}, {shared}"),
                "allow"
            ),
        )),
        "rule[1].criteria[1]: a policy carries at most one `unlisted` table; \
         rule[1].criteria[0] carries the first",
    );
}

/// An `unlisted` budget table with each field spelled out.
fn budget_table(asset: &str, per_tx: &str, per_period: &str, window: &str) -> String {
    cp(&format!(
        "{{ mode = \"budget\"{asset}, per_tx_stroops = {per_tx}, \
         per_period_stroops = {per_period}, window = \"{window}\" }}"
    ))
}

/// The tools of the rules [`rules_with`] builds, in rule order.
const RULE_TOOLS: [&str; 5] = [
    "stellar_pay",
    "stellar_x402_create_payment",
    "stellar_x402_commit",
    "stellar_create_account",
    "stellar_claim",
];

/// A policy whose rules carry `criteria` in order, one rule per tool of
/// [`RULE_TOOLS`]. More inputs than tools panic.
fn rules_with(criteria: &[&str]) -> String {
    assert!(
        criteria.len() <= RULE_TOOLS.len(),
        "rules_with takes at most {} rules, got {}",
        RULE_TOOLS.len(),
        criteria.len()
    );
    v2(&criteria
        .iter()
        .zip(RULE_TOOLS)
        .map(|(criteria, tool)| rule_for(tool, criteria, "allow"))
        .collect::<String>())
}

#[test]
#[should_panic(expected = "rules_with takes at most 5 rules, got 6")]
fn rules_with_refuses_more_rules_than_tools() {
    let _ = rules_with(&[""; 6]);
}

/// Evaluates `value` strictly as a call of the tool `name`.
fn decide_on(engine: &PolicyEngineV1, name: &'static str, value: ValueClass) -> Decision {
    engine
        .evaluate_with_value_full(
            &tool(name),
            &Value::Null,
            &profile(),
            value,
            None,
            None,
            None,
            None,
            None,
            instant(),
        )
        .unwrap()
        .decision
}

/// Records a strictly evaluated call of the tool `name` as confirmed.
fn confirm_on(engine: &PolicyEngineV1, name: &'static str, value: ValueClass) {
    let evaluation = engine
        .evaluate_with_value_full(
            &tool(name),
            &Value::Null,
            &profile(),
            value,
            None,
            None,
            None,
            None,
            None,
            instant(),
        )
        .unwrap();
    assert!(
        !matches!(evaluation.decision, Decision::Deny(_)),
        "{name}: {evaluation:?}"
    );
    engine
        .record_confirmed(
            &tool(name),
            &profile(),
            &ValueClass::Value(evaluation.value_effects.unwrap()),
        )
        .unwrap();
}

/// The usage the shared native budget counter holds.
fn shared_usage(engine: &PolicyEngineV1) -> (i128, u32) {
    engine
        .state_store()
        .query_window(&unlisted_key(), NOW_MS)
        .unwrap()
}

fn native_exceeded(bound: UnlistedBound, max_stroops: i128, attempted_stroops: i128) -> Decision {
    Decision::Deny(DenyReason::UnlistedBudgetExceeded {
        asset: "native".to_owned(),
        bound,
        max_stroops,
        attempted_stroops,
    })
}

/// Integer forms, key order, an escaped asset, and the omitted `native`
/// asset parse to one table, and every rule carrying it draws on one counter.
#[test]
fn unlisted_representations_load_and_share_counter() {
    let _clock = set_query_time_for_test(NOW_MS);
    let forms = [
        budget_table("", "10", "20", "1d"),
        cp(
            "{ window = \"1d\", per_period_stroops = 0x14, asset = \"native\", \
            per_tx_stroops = 1_0, mode = \"budget\" }",
        ),
        cp(
            "{ mode = \"budget\", per_tx_stroops = 0o12, per_period_stroops = 0b10100, \
            window = \"1d\" }",
        ),
        cp(
            "{ mode = \"budget\", per_tx_stroops = +10, per_period_stroops = \"020\", \
            window = \"1d\" }",
        ),
        cp(
            "{ mode = \"budget\", asset = \"nat\\u0069ve\", per_tx_stroops = \"+10\", \
            per_period_stroops = \"20\", window = \"1d\" }",
        ),
    ];
    let engine = engine(&rules_with(&forms.each_ref().map(String::as_str)));
    for name in RULE_TOOLS {
        assert_eq!(
            decide_on(&engine, name, payment(10, UNLISTED)),
            Decision::Allow,
            "{name}"
        );
        assert_eq!(
            decide_on(&engine, name, payment(11, UNLISTED)),
            native_exceeded(UnlistedBound::PerTx, 10, 11),
            "{name}"
        );
    }
    confirm_on(&engine, RULE_TOOLS[0], payment(10, UNLISTED));
    confirm_on(&engine, RULE_TOOLS[1], payment(10, UNLISTED));
    assert_eq!(shared_usage(&engine), (20, 2));
    for name in RULE_TOOLS {
        assert_eq!(
            decide_on(&engine, name, payment(1, UNLISTED)),
            native_exceeded(UnlistedBound::PerPeriod, 20, 1),
            "{name}"
        );
    }

    // An omitted mode equals an explicit `deny`.
    let deny = self::engine(&rules_with(&[&cp("{}"), &cp("{ mode = \"deny\" }")]));
    for name in &RULE_TOOLS[..2] {
        assert_eq!(decide_on(&deny, name, payment(1, LISTED)), Decision::Allow);
        assert_eq!(
            decide_on(&deny, name, payment(1, UNLISTED)),
            Decision::Deny(DenyReason::CounterpartyDenied {
                kind: "G_ACCOUNT".to_owned(),
                value: UNLISTED.to_owned(),
            }),
            "{name}"
        );
    }
}

/// Asset aliases that parse to different strings are unequal tables; the
/// same alias on every rule loads and shares one counter.
#[test]
fn unlisted_asset_aliases_compare_as_parsed() {
    let _clock = set_query_time_for_test(NOW_MS);
    let native = budget_table(", asset = \"native\"", "10", "20", "1d");
    let native_sac = sac("native");
    for alias in ["XLM", "NATIVE", "xlm", native_sac.as_str()] {
        refused(
            &rules_with(&[
                &native,
                &budget_table(&format!(", asset = \"{alias}\""), "10", "20", "1d"),
            ]),
            "rule[1].criteria[0]: every `unlisted` table of a policy must equal the first; \
             rule[0].criteria[0] carries the first",
        );
    }
    let xlm = budget_table(", asset = \"XLM\"", "10", "20", "1d");
    let engine = engine(&rules_with(&[&xlm, &xlm]));
    confirm_on(&engine, RULE_TOOLS[0], payment(10, UNLISTED));
    confirm_on(&engine, RULE_TOOLS[1], payment(10, UNLISTED));
    for name in &RULE_TOOLS[..2] {
        assert!(
            matches!(
                decide_on(&engine, name, payment(1, UNLISTED)),
                Decision::Deny(DenyReason::UnlistedBudgetExceeded {
                    bound: UnlistedBound::PerPeriod,
                    max_stroops: 20,
                    attempted_stroops: 1,
                    ..
                })
            ),
            "{name}"
        );
    }
}

/// Three and four equal rules load around a rule without a table; the rules
/// with the table share one counter and the rule without it is unaffected.
#[test]
fn many_equal_unlisted_rules_share_counter_around_a_plain_rule() {
    let _clock = set_query_time_for_test(NOW_MS);
    let shared = budget(10, 20);
    check(&rules_with(&[&shared, &shared, "", &shared])).unwrap();
    let engine = engine(&rules_with(&[&shared, "", &shared, &shared, &shared]));
    confirm_on(&engine, RULE_TOOLS[0], payment(10, UNLISTED));
    confirm_on(&engine, RULE_TOOLS[4], payment(10, UNLISTED));
    for name in [RULE_TOOLS[0], RULE_TOOLS[2], RULE_TOOLS[3], RULE_TOOLS[4]] {
        assert_eq!(
            decide_on(&engine, name, payment(1, UNLISTED)),
            native_exceeded(UnlistedBound::PerPeriod, 20, 1),
            "{name}"
        );
    }
    assert_eq!(
        decide_on(&engine, RULE_TOOLS[1], payment(1000, UNLISTED)),
        Decision::Allow
    );
    confirm_on(&engine, RULE_TOOLS[1], payment(1000, UNLISTED));
    assert_eq!(shared_usage(&engine), (20, 2));
}

/// The first table may sit at a later rule and criterion; a third table
/// that differs is refused naming that first position.
#[test]
fn first_unlisted_table_at_a_later_position() {
    let _clock = set_query_time_for_test(NOW_MS);
    let shared = budget(10, 20);
    let capped =
        format!("{{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = 1000 }}, {shared}");
    let engine = engine(&rules_with(&["", &capped, &shared]));
    confirm_on(&engine, RULE_TOOLS[1], payment(10, UNLISTED));
    confirm_on(&engine, RULE_TOOLS[2], payment(10, UNLISTED));
    for name in &RULE_TOOLS[1..3] {
        assert_eq!(
            decide_on(&engine, name, payment(1, UNLISTED)),
            native_exceeded(UnlistedBound::PerPeriod, 20, 1),
            "{name}"
        );
    }
    assert_eq!(
        decide_on(&engine, RULE_TOOLS[0], payment(1, UNLISTED)),
        Decision::Allow
    );
    refused(
        &rules_with(&["", &capped, &shared, &budget(10, 21)]),
        "rule[3].criteria[0]: every `unlisted` table of a policy must equal the first; \
         rule[1].criteria[1] carries the first",
    );
}

fn bundle_on(
    engine: &PolicyEngineV1,
    name: &'static str,
    inners: &[InnerOpDescriptor],
) -> Decision {
    let overlay = BundleStateOverlay::default();
    engine
        .evaluate_bundle(
            &tool(name),
            &Value::Null,
            &profile(),
            &BundleView {
                inners,
                overlay: &overlay,
            },
        )
        .unwrap()
}

fn confirm_bundle_on(engine: &PolicyEngineV1, name: &'static str, inners: &[InnerOpDescriptor]) {
    let overlay = BundleStateOverlay::default();
    engine
        .record_confirmed_bundle(
            &tool(name),
            &profile(),
            &BundleView {
                inners,
                overlay: &overlay,
            },
        )
        .unwrap();
}

/// A bundle under one of two sharing rules counts against the shared
/// counter, writes nothing when refused, and records on confirmation.
#[test]
fn bundles_across_sharing_rules_use_one_counter() {
    let _clock = set_query_time_for_test(NOW_MS);
    let shared = budget(10, 20);
    let engine = engine(&rules_with(&[&shared, &shared]));
    let [pay_tool, x402] = [RULE_TOOLS[0], RULE_TOOLS[1]];
    let exceeded = |attempted_stroops| {
        bundle_denied(
            2,
            DenyReason::UnlistedBudgetExceeded {
                asset: "native".to_owned(),
                bound: UnlistedBound::PerPeriod,
                max_stroops: 20,
                attempted_stroops,
            },
        )
    };
    let three = [
        transfer(UNLISTED, 10),
        transfer(UNLISTED, 10),
        transfer(UNLISTED, 1),
    ];
    for name in [pay_tool, x402] {
        assert_eq!(bundle_on(&engine, name, &three), exceeded(1), "{name}");
    }
    assert_eq!(shared_usage(&engine), (0, 0));

    let two = [transfer(UNLISTED, 10), transfer(UNLISTED, 10)];
    assert_eq!(bundle_on(&engine, x402, &two), Decision::Allow);
    confirm_bundle_on(&engine, x402, &two);
    assert_eq!(shared_usage(&engine), (20, 2));
    assert_eq!(
        decide_on(&engine, pay_tool, payment(1, UNLISTED)),
        native_exceeded(UnlistedBound::PerPeriod, 20, 1)
    );
}

/// Equal tables on rules with different allow lists: each rule charges only
/// recipients outside its own list, and all charges share one counter.
#[test]
fn equal_unlisted_tables_with_different_allow_lists() {
    let _clock = set_query_time_for_test(NOW_MS);
    let listing = |account: &str| {
        format!(
            "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], \
             allowlist = [\"{account}\"], unlisted = {{ mode = \"budget\", \
             per_tx_stroops = 10, per_period_stroops = 20, window = \"1d\" }} }}"
        )
    };
    let engine = engine(&rules_with(&[&listing(LISTED), &listing(UNLISTED)]));
    let [pay_tool, x402] = [RULE_TOOLS[0], RULE_TOOLS[1]];
    confirm_on(&engine, pay_tool, payment(1000, LISTED));
    confirm_on(&engine, x402, payment(1000, UNLISTED));
    assert_eq!(shared_usage(&engine), (0, 0));
    confirm_on(&engine, pay_tool, payment(10, UNLISTED));
    confirm_on(&engine, x402, payment(10, LISTED));
    assert_eq!(shared_usage(&engine), (20, 2));
    assert_eq!(
        decide_on(&engine, pay_tool, payment(1, UNLISTED)),
        native_exceeded(UnlistedBound::PerPeriod, 20, 1)
    );
    assert_eq!(
        decide_on(&engine, x402, payment(1, LISTED)),
        native_exceeded(UnlistedBound::PerPeriod, 20, 1)
    );
    assert_eq!(
        decide_on(&engine, pay_tool, payment(1000, LISTED)),
        Decision::Allow
    );
    assert_eq!(
        decide_on(&engine, x402, payment(1000, UNLISTED)),
        Decision::Allow
    );
}

#[test]
fn equal_unlisted_tables_load_across_rules() {
    let shared = budget(10, 20);
    check(&rules_with(&[&shared, &shared])).unwrap();

    // A rule without a table between two equal tables.
    check(&rules_with(&[&shared, "", &shared])).unwrap();

    // Equality is on the parsed table: the `native` default and a decimal
    // string bound equal their spelled-out forms.
    check(&rules_with(&[
        &budget_table("", "10", "20", "1d"),
        &budget_table(", asset = \"native\"", "\"10\"", "20", "1d"),
    ]))
    .unwrap();

    // A list entry gains no validation from a second table.
    let odd_list = "{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], \
                    allowlist = [\"not-a-strkey\"], unlisted = { mode = \"approval\" } }";
    check(&rules_with(&[odd_list])).unwrap();
    check(&rules_with(&[odd_list, odd_list])).unwrap();

    // Each table is checked against the hard caps of its own rule.
    refused(
        &rules_with(&[
            &shared,
            &format!("{shared}, {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = 10 }}"),
        ]),
        "rule[1].criteria[0].unlisted: `per_tx_stroops` must be less than the `per_tx_cap` bound",
    );
}

#[test]
fn unequal_unlisted_tables_refuse_policy() {
    let first = budget_table(", asset = \"native\"", "10", "20", "1d");
    let unequal = "rule[1].criteria[0]: every `unlisted` table of a policy must equal the \
                   first; rule[0].criteria[0] carries the first";
    let usd = format!(", asset = \"{}\"", usd());
    for (field, second) in [
        ("asset", budget_table(&usd, "10", "20", "1d")),
        (
            "window",
            budget_table(", asset = \"native\"", "10", "20", "1h"),
        ),
        (
            "per_tx",
            budget_table(", asset = \"native\"", "11", "20", "1d"),
        ),
        (
            "per_period",
            budget_table(", asset = \"native\"", "10", "21", "1d"),
        ),
    ] {
        check(&rules_with(&[&second])).unwrap_or_else(|e| panic!("{field}: {e:?}"));
        refused(&rules_with(&[&first, &second]), unequal);
    }
    refused(
        &rules_with(&[&cp("{ mode = \"approval\" }"), &first]),
        unequal,
    );
}

#[test]
fn unlisted_bounds_are_strictly_below_hard_caps() {
    let loc = "rule[0].criteria[0].unlisted";
    let per_tx = format!("{loc}: `per_tx_stroops` must be less than the `per_tx_cap` bound");
    let per_period = format!(
        "{loc}: `per_period_stroops` must be less than the `per_period_cap` bound of the same window"
    );
    let total = format!(
        "{loc}: `per_tx_stroops` and `per_period_stroops` must be less than the `total_budget` bound"
    );
    let usd = usd();
    let usd_sac = sac(&usd);
    let unlisted_in = |asset: &str, per_tx: i64, per_period: i64| {
        cp(&format!(
            "{{ mode = \"budget\", asset = \"{asset}\", per_tx_stroops = {per_tx}, \
             per_period_stroops = {per_period}, window = \"1d\" }}"
        ))
    };
    for (budget_asset, cap_asset) in [
        ("native", "native".to_owned()),
        (usd.as_str(), usd.clone()),
        (usd.as_str(), usd_sac.clone()),
        (usd_sac.as_str(), usd.clone()),
    ] {
        let tx_cap =
            format!("{{ kind = \"per_tx_cap\", asset = \"{cap_asset}\", max_stroops = 100 }}");
        let period_cap = |window: &str| {
            format!(
                "{{ kind = \"per_period_cap\", asset = \"{cap_asset}\", window = \"{window}\", \
                 max_stroops = 1000 }}"
            )
        };
        let total_cap =
            format!("{{ kind = \"total_budget\", asset = \"{cap_asset}\", max_stroops = 5000 }}");

        for value in [100, 101] {
            refused(
                &v2(&rule(
                    &format!("{}, {tx_cap}", unlisted_in(budget_asset, value, 10)),
                    "allow",
                )),
                &per_tx,
            );
        }
        check(&v2(&rule(
            &format!("{}, {tx_cap}", unlisted_in(budget_asset, 99, 10)),
            "allow",
        )))
        .unwrap();

        for value in [1000, 1001] {
            refused(
                &v2(&rule(
                    &format!(
                        "{}, {}",
                        unlisted_in(budget_asset, 10, value),
                        period_cap("1d")
                    ),
                    "allow",
                )),
                &per_period,
            );
        }
        check(&v2(&rule(
            &format!(
                "{}, {}",
                unlisted_in(budget_asset, 10, 999),
                period_cap("1d")
            ),
            "allow",
        )))
        .unwrap();
        check(&v2(&rule(
            &format!(
                "{}, {}",
                unlisted_in(budget_asset, 10, 1000),
                period_cap("1h")
            ),
            "allow",
        )))
        .unwrap();

        for (tx, period) in [(5000, 10), (5001, 10), (10, 5000), (10, 5001)] {
            refused(
                &v2(&rule(
                    &format!("{}, {total_cap}", unlisted_in(budget_asset, tx, period)),
                    "allow",
                )),
                &total,
            );
        }
        check(&v2(&rule(
            &format!("{}, {total_cap}", unlisted_in(budget_asset, 4999, 4999)),
            "allow",
        )))
        .unwrap();
    }

    // A cap in another asset does not bound the budget.
    check(&v2(&rule(
        &format!(
            "{}, {{ kind = \"per_tx_cap\", asset = \"{usd}\", max_stroops = 100 }}",
            unlisted_in("native", 500, 600)
        ),
        "allow",
    )))
    .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// Recipient classes
// ─────────────────────────────────────────────────────────────────────────────

fn classify(
    criterion: &CounterpartyAllowlistCriterion,
    value: ValueClass,
    identity: Option<&dyn AccountIdentityView>,
    cache: Option<&dyn CounterpartyCacheView>,
) -> Result<Option<RecipientClass>, PolicyError> {
    let tool = pay();
    let profile = profile();
    let store = PolicyStateStore::new();
    let args = Value::Null;
    let mut ctx =
        EvalContext::new(&tool, &args, "operator", &profile, &store, instant()).with_value(value);
    if let Some(identity) = identity {
        ctx = ctx.with_identity_view(identity);
    }
    if let Some(cache) = cache {
        ctx = ctx.with_counterparty_cache(cache);
    }
    criterion.recipient_class(&ctx)
}

fn allowlist(kind: CounterpartyKind, entries: &[&str]) -> CounterpartyAllowlistCriterion {
    CounterpartyAllowlistCriterion::new(
        vec![kind],
        entries.iter().map(|entry| (*entry).to_owned()).collect(),
    )
    .with_unlisted(UnlistedMode::Approval)
}

#[test]
fn recipient_classes_are_rule_local_and_debit_only() {
    use RecipientClass::{Listed, Unlisted, Unverifiable};

    // G accounts, with a muxed destination reduced to its base account.
    let g = allowlist(CounterpartyKind::GAccount, &[LISTED]);
    let class = |criterion: &CounterpartyAllowlistCriterion, value| {
        classify(criterion, value, None, None).unwrap()
    };
    assert_eq!(class(&g, payment(1, LISTED)), Some(Listed));
    assert_eq!(class(&g, payment(1, UNLISTED)), Some(Unlisted));
    assert_eq!(class(&g, payment(1, &muxed(LISTED, 9))), Some(Listed));
    assert_eq!(class(&g, payment(1, &muxed(UNLISTED, 9))), Some(Unlisted));
    assert_eq!(class(&g, ValueClass::ReadOnly), None);

    // C accounts.
    let listed_contract = contract(1);
    let c = allowlist(CounterpartyKind::CAccount, &[&listed_contract]);
    assert_eq!(class(&c, payment(1, &listed_contract)), Some(Listed));
    assert_eq!(class(&c, payment(1, &contract(2))), Some(Unlisted));

    // Debit-leg issuers.
    let usd = usd();
    let issuer = allowlist(CounterpartyKind::KnownIssuer, &[&usd]);
    let issued =
        |asset: &str| ValueClass::single(leg(ActionKind::Payment, 1, asset, Some(UNLISTED)));
    assert_eq!(class(&issuer, issued(&usd)), Some(Listed));
    assert_eq!(
        class(&issuer, issued(&format!("EUR:{UNLISTED}"))),
        Some(Unlisted)
    );
    assert_eq!(class(&issuer, issued("native")), Some(Listed));

    // A verified home domain.
    let domain = allowlist(CounterpartyKind::HomeDomain, &["example.com"]);
    let other_domain = allowlist(CounterpartyKind::HomeDomain, &["other.example"]);
    let identity = Identity(Some("example.com"));
    let verified = Cache {
        resolved: true,
        listed: true,
    };
    assert_eq!(
        classify(
            &domain,
            payment(1, UNLISTED),
            Some(&identity),
            Some(&verified)
        )
        .unwrap(),
        Some(Listed)
    );
    assert_eq!(
        classify(
            &other_domain,
            payment(1, UNLISTED),
            Some(&identity),
            Some(&verified)
        )
        .unwrap(),
        Some(Unlisted)
    );

    // Inflow legs carry no class; the strictest debit leg governs.
    let inflow_only = ValueClass::Value(ValueEffects::new(vec![leg(
        ActionKind::Claim,
        5,
        "native",
        Some(UNLISTED),
    )]));
    assert_eq!(class(&g, inflow_only), Some(Listed));
    let mixed = |legs: Vec<ValueLeg>| ValueClass::Value(ValueEffects::new(legs));
    assert_eq!(
        class(
            &g,
            mixed(vec![
                leg(ActionKind::Payment, 1, "native", Some(LISTED)),
                leg(ActionKind::Claim, 1, "native", Some(UNLISTED)),
            ])
        ),
        Some(Listed)
    );
    assert_eq!(
        class(
            &g,
            mixed(vec![
                leg(ActionKind::Payment, 1, "native", Some(LISTED)),
                leg(ActionKind::Payment, 1, "native", Some(UNLISTED)),
            ])
        ),
        Some(Unlisted)
    );
    assert_eq!(
        class(
            &g,
            mixed(vec![
                leg(ActionKind::Payment, 1, "native", Some(UNLISTED)),
                leg(ActionKind::Payment, 1, "native", None),
                leg(ActionKind::Payment, 1, "native", Some(LISTED)),
            ])
        ),
        Some(Unverifiable)
    );

    // The class is local to the matched rule: a recipient on another rule's
    // list stays unlisted, and the evaluation carries the class.
    let engine = engine(&v2(&format!(
        "{}{}",
        rule(&cp("{ mode = \"approval\" }"), "allow"),
        rule_for(
            "stellar_create_account",
            &format!(
                "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], \
                 allowlist = [\"{UNLISTED}\"] }}"
            ),
            "allow"
        ),
    )));
    let evaluation = strict(&engine, payment(5, UNLISTED), None).unwrap();
    assert!(matches!(evaluation.decision, Decision::RequireApproval(_)));
    assert_eq!(
        evaluation.value_effects.unwrap().recipient_class(),
        Some(Unlisted)
    );
    let evaluation = strict(&engine, payment(5, LISTED), None).unwrap();
    assert_eq!(evaluation.decision, Decision::Allow);
    assert_eq!(
        evaluation.value_effects.unwrap().recipient_class(),
        Some(Listed)
    );
}

#[test]
fn unverifiable_recipients_never_escalate() {
    let approval = UnlistedMode::Approval;
    let document = load(&v2(&rule(&budget(100, 200), "allow")));
    let budget = loaded_criterion::<CounterpartyAllowlistCriterion>(&document, 0, 0)
        .unlisted()
        .unwrap()
        .clone();
    for mode in [approval, budget] {
        let decide_with = |kind: CounterpartyKind,
                           entries: &[&str],
                           value: ValueClass,
                           identity: Option<&dyn AccountIdentityView>,
                           cache: Option<&dyn CounterpartyCacheView>| {
            let criterion = CounterpartyAllowlistCriterion::new(
                vec![kind],
                entries.iter().map(|entry| (*entry).to_owned()).collect(),
            )
            .with_unlisted(mode.clone());
            let tool = pay();
            let profile = profile();
            let store = PolicyStateStore::new();
            let args = Value::Null;
            let mut ctx = EvalContext::new(&tool, &args, "operator", &profile, &store, instant())
                .with_value(value);
            if let Some(identity) = identity {
                ctx = ctx.with_identity_view(identity);
            }
            if let Some(cache) = cache {
                ctx = ctx.with_counterparty_cache(cache);
            }
            let class = criterion.recipient_class(&ctx);
            (criterion.evaluate_decision(&ctx), class)
        };
        let denied = |kind: &str, value: &str| {
            Decision::Deny(DenyReason::CounterpartyDenied {
                kind: kind.to_owned(),
                value: value.to_owned(),
            })
        };

        // A malformed key errors in every mode.
        let (decision, class) = decide_with(
            CounterpartyKind::GAccount,
            &[LISTED],
            payment(1, "GBAD"),
            None,
            None,
        );
        assert!(matches!(
            decision,
            Err(PolicyError::CriterionEvaluationFailed { .. })
        ));
        assert!(matches!(
            class,
            Err(PolicyError::CriterionEvaluationFailed { .. })
        ));
        let (decision, _) = decide_with(
            CounterpartyKind::CAccount,
            &[LISTED],
            payment(1, "CBAD"),
            None,
            None,
        );
        assert!(matches!(
            decision,
            Err(PolicyError::CriterionEvaluationFailed { .. })
        ));

        // A missing destination refuses.
        let no_destination = ValueClass::single(leg(ActionKind::Payment, 1, "native", None));
        let (decision, class) = decide_with(
            CounterpartyKind::GAccount,
            &[LISTED],
            no_destination.clone(),
            None,
            None,
        );
        assert_eq!(decision.unwrap(), denied("G_ACCOUNT", ""));
        assert_eq!(class.unwrap(), Some(RecipientClass::Unverifiable));
        let (decision, _) = decide_with(
            CounterpartyKind::CAccount,
            &[LISTED],
            no_destination,
            None,
            None,
        );
        assert_eq!(decision.unwrap(), denied("C_ACCOUNT", ""));

        // A missing issuer asset refuses.
        let no_asset = ValueClass::single(ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(1),
            asset: None,
            destination: Some(UNLISTED.to_owned()),
        });
        let (decision, _) = decide_with(
            CounterpartyKind::KnownIssuer,
            &[&usd()],
            no_asset,
            None,
            None,
        );
        assert_eq!(decision.unwrap(), denied("KNOWN_ISSUER", ""));

        // A missing identity, home domain, cache, cache entry, or listing
        // refuses.
        let identity = Identity(Some("example.com"));
        let no_domain = Identity(None);
        let unresolved = Cache {
            resolved: false,
            listed: true,
        };
        let unlisted_account = Cache {
            resolved: true,
            listed: false,
        };
        let home = |identity: Option<&dyn AccountIdentityView>,
                    cache: Option<&dyn CounterpartyCacheView>| {
            decide_with(
                CounterpartyKind::HomeDomain,
                &["other.example"],
                payment(1, UNLISTED),
                identity,
                cache,
            )
        };
        let verified = Cache {
            resolved: true,
            listed: true,
        };
        for (identity, cache) in [
            (None, Some(&verified as &dyn CounterpartyCacheView)),
            (
                Some(&no_domain as &dyn AccountIdentityView),
                Some(&verified),
            ),
            (Some(&identity), None),
            (Some(&identity), Some(&unresolved)),
            (Some(&identity), Some(&unlisted_account)),
        ] {
            let (decision, class) = home(identity, cache);
            assert!(
                matches!(
                    decision.unwrap(),
                    Decision::Deny(DenyReason::CounterpartyDenied { ref kind, .. })
                        if kind == "HOME_DOMAIN"
                ),
                "an unverified home domain must refuse"
            );
            assert_eq!(class.unwrap(), Some(RecipientClass::Unverifiable));
        }

        // An unsupported kind refuses.
        let (decision, class) = decide_with(
            CounterpartyKind::parse("SEP10_IDENTITY").unwrap(),
            &[LISTED],
            payment(1, UNLISTED),
            None,
            None,
        );
        assert_eq!(
            decision.unwrap(),
            Decision::Deny(DenyReason::CounterpartyKindUnsupported {
                kind: "SEP10_IDENTITY".to_owned()
            })
        );
        assert_eq!(class.unwrap(), Some(RecipientClass::Unverifiable));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unlisted approval
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unlisted_approval_preserves_first_match_and_hard_caps() {
    let _clock = set_query_time_for_test(NOW_MS);
    let caps = "{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = 1000 }, \
                { kind = \"per_period_cap\", asset = \"native\", window = \"1d\", max_stroops = 1500 }, \
                { kind = \"rate_limit\", window = \"1d\", max_calls = 3 }";
    let engine = engine(&v2(&format!(
        "{}{}",
        rule(
            &format!("{}, {caps}", cp("{ mode = \"approval\" }")),
            "allow"
        ),
        rule("", "allow"),
    )));
    let escalates = |decision: &Decision| matches!(decision, Decision::RequireApproval(_));

    // Escalation at any amount up to the hard cap; a listed recipient passes.
    for amount in [0, 1, 999, 1000] {
        assert!(
            escalates(&decide(&engine, payment(amount, UNLISTED))),
            "{amount}"
        );
    }
    assert_eq!(decide(&engine, payment(1000, LISTED)), Decision::Allow);

    // A later criterion's denial wins over the escalation.
    assert_eq!(
        decide(&engine, payment(1001, UNLISTED)),
        Decision::Deny(DenyReason::PerTxCapExceeded {
            asset: "native".to_owned(),
            max_stroops: 1000,
            attempted_stroops: 1001,
        })
    );

    // The period cap and the rate limit still apply to an unlisted payment.
    let recorded = strict(&engine, payment(1000, LISTED), None).unwrap();
    engine
        .record_confirmed(
            &pay(),
            &profile(),
            &ValueClass::Value(recorded.value_effects.unwrap()),
        )
        .unwrap();
    assert!(escalates(&decide(&engine, payment(500, UNLISTED))));
    assert!(matches!(
        decide(&engine, payment(501, UNLISTED)),
        Decision::Deny(DenyReason::PerPeriodCapExceeded { .. })
    ));
    for _ in 0..2 {
        let evaluation = strict(&engine, payment(1, LISTED), None).unwrap();
        engine
            .record_confirmed(
                &pay(),
                &profile(),
                &ValueClass::Value(evaluation.value_effects.unwrap()),
            )
            .unwrap();
    }
    assert!(matches!(
        decide(&engine, payment(1, UNLISTED)),
        Decision::Deny(DenyReason::RateLimitExceeded { .. })
    ));

    // First match: the second, permissive rule never decides a payment.
    let first_only = engine_with_second_rule(&format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{LISTED}\"] }}"
    ));
    assert_eq!(
        decide(&first_only, payment(1, UNLISTED)),
        Decision::Deny(DenyReason::CounterpartyDenied {
            kind: "G_ACCOUNT".to_owned(),
            value: UNLISTED.to_owned(),
        })
    );
    let approval_first = engine_with_second_rule(&cp("{ mode = \"approval\" }"));
    assert!(escalates(&decide(&approval_first, payment(1, UNLISTED))));

    // `approval_above` escalates by amount whatever the recipient.
    let above = engine_from_criteria(&format!(
        "{}, {{ kind = \"approval_above\", asset = \"native\", max_stroops = 50 }}",
        cp("{ mode = \"approval\" }")
    ));
    assert_eq!(decide(&above, payment(50, LISTED)), Decision::Allow);
    assert!(escalates(&decide(&above, payment(51, LISTED))));
    assert!(escalates(&decide(&above, payment(50, UNLISTED))));
    assert!(escalates(&decide(&above, payment(51, UNLISTED))));
}

fn engine_from_criteria(criteria: &str) -> PolicyEngineV1 {
    engine(&v2(&rule(criteria, "allow")))
}

fn engine_with_second_rule(first: &str) -> PolicyEngineV1 {
    engine(&v2(&format!(
        "{}{}",
        rule(first, "allow"),
        rule("", "allow")
    )))
}

#[test]
fn unlisted_approval_escalates_with_default_ttl() {
    let approval = engine_from_criteria(&cp("{ mode = \"approval\" }"));
    let Decision::RequireApproval(request) = decide(&approval, payment(10, UNLISTED)) else {
        panic!("an unlisted recipient must escalate");
    };
    assert_eq!(u64::from(request.ttl_seconds) * 1_000, DEFAULT_TTL_MS);
    let plain = engine(&v2(&rule("", "require_approval")));
    let Decision::RequireApproval(rule_request) = decide(&plain, payment(10, UNLISTED)) else {
        panic!("a require_approval rule must escalate");
    };
    assert_eq!(request.ttl_seconds, rule_request.ttl_seconds);
    assert_eq!(
        request.reason.as_deref(),
        Some("counterparty_allowlist: an unlisted recipient requires approval")
    );
    let wire = serde_json::to_string(&request).unwrap();
    assert!(!wire.contains(UNLISTED), "{wire}");
    assert!(!wire.contains(&UNLISTED[..12]), "{wire}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Unlisted budget
// ─────────────────────────────────────────────────────────────────────────────

/// Records a strictly evaluated payment as confirmed.
fn confirm(engine: &PolicyEngineV1, value: ValueClass) {
    let evaluation = strict(engine, value, None).unwrap();
    assert!(
        !matches!(evaluation.decision, Decision::Deny(_)),
        "{evaluation:?}"
    );
    engine
        .record_confirmed(
            &pay(),
            &profile(),
            &ValueClass::Value(evaluation.value_effects.unwrap()),
        )
        .unwrap();
}

fn unlisted_key() -> StateKey {
    StateKey::new("operator", 1, "unlisted:native", 86_400)
}

#[test]
fn unlisted_budget_checks_both_bounds_and_bundle_overlay() {
    let _clock = set_query_time_for_test(NOW_MS);
    let caps = "{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = 1000 }";
    let engine = engine_from_criteria(&format!("{}, {caps}", budget(100, 250)));
    let exceeded = |bound, max_stroops, attempted_stroops| {
        Decision::Deny(DenyReason::UnlistedBudgetExceeded {
            asset: "native".to_owned(),
            bound,
            max_stroops,
            attempted_stroops,
        })
    };

    // The per-transaction bound: equality passes, one stroop over refuses.
    assert_eq!(decide(&engine, payment(100, UNLISTED)), Decision::Allow);
    assert_eq!(
        decide(&engine, payment(101, UNLISTED)),
        exceeded(UnlistedBound::PerTx, 100, 101)
    );
    assert_eq!(decide(&engine, payment(1000, LISTED)), Decision::Allow);

    // The period bound counts confirmed unlisted payments only.
    confirm(&engine, payment(100, UNLISTED));
    confirm(&engine, payment(100, UNLISTED));
    confirm(&engine, payment(1000, LISTED));
    assert_eq!(
        engine
            .state_store()
            .query_window(&unlisted_key(), NOW_MS)
            .unwrap(),
        (200, 2)
    );
    assert_eq!(decide(&engine, payment(50, UNLISTED)), Decision::Allow);
    assert_eq!(
        decide(&engine, payment(51, UNLISTED)),
        exceeded(UnlistedBound::PerPeriod, 250, 51)
    );
    assert_eq!(decide(&engine, payment(1000, LISTED)), Decision::Allow);

    // A debit in another asset keeps the counterparty denial.
    assert_eq!(
        decide(
            &engine,
            ValueClass::single(leg(ActionKind::Payment, 1, &usd(), Some(UNLISTED)))
        ),
        Decision::Deny(DenyReason::CounterpartyDenied {
            kind: "G_ACCOUNT".to_owned(),
            value: UNLISTED.to_owned(),
        })
    );

    // Sizing without the evaluated class fails.
    for result in [
        engine.size_window_entries(&pay(), &profile(), &payment(10, UNLISTED), NOW_MS),
        engine.record_confirmed(&pay(), &profile(), &payment(10, UNLISTED)),
    ] {
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "{result:?}"
        );
    }

    // Every rule's budget shares one key: a policy that moves the budget to
    // another rule reads the same window.
    let moved = PolicyEngineV1::new_with_store(
        load(&v2(&format!(
            "{}{}",
            rule_for("stellar_create_account", "", "allow"),
            rule(&budget(100, 250), "allow"),
        ))),
        "operator".to_owned(),
        PolicyStateStore::new(),
    );
    let entries = engine
        .size_window_entries(
            &pay(),
            &profile(),
            &ValueClass::Value(
                strict(&engine, payment(40, UNLISTED), None)
                    .unwrap()
                    .value_effects
                    .unwrap(),
            ),
            NOW_MS,
        )
        .unwrap();
    let unlisted_entry = entries
        .iter()
        .find(|entry| matches!(entry.limit(), WindowLimit::Unlisted { .. }))
        .unwrap();
    assert_eq!(unlisted_entry.key(), &unlisted_key());
    assert_eq!(
        unlisted_entry.limit(),
        &WindowLimit::Unlisted {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: 250,
        }
    );
    moved
        .state_store()
        .append(&unlisted_key(), NOW_MS - 1, 200)
        .unwrap();
    assert_eq!(decide(&moved, payment(50, UNLISTED)), Decision::Allow);
    assert_eq!(
        decide(&moved, payment(51, UNLISTED)),
        exceeded(UnlistedBound::PerPeriod, 250, 51)
    );

    // A bundle accumulates its unlisted transfers only.
    let bundle_engine = engine_from_criteria(&budget(100, 100));
    let native = sac("native");
    let transfer = |to: &str, amount: i128| InnerOpDescriptor::TokenTransfer {
        asset: native.clone(),
        from: LISTED.to_owned(),
        to: to.to_owned(),
        amount,
    };
    let bundle = |inners: &[InnerOpDescriptor]| {
        let overlay = BundleStateOverlay::default();
        bundle_engine
            .evaluate_bundle(
                &pay(),
                &Value::Null,
                &profile(),
                &BundleView {
                    inners,
                    overlay: &overlay,
                },
            )
            .unwrap()
    };
    assert_eq!(
        bundle(&[
            transfer(LISTED, 500),
            transfer(UNLISTED, 60),
            transfer(UNLISTED, 40)
        ]),
        Decision::Allow
    );
    assert_eq!(
        bundle(&[
            transfer(UNLISTED, 60),
            transfer(LISTED, 500),
            transfer(UNLISTED, 41)
        ]),
        Decision::Deny(DenyReason::BundleDenied {
            inner_index: 2,
            deny_reason: Box::new(DenyReason::UnlistedBudgetExceeded {
                asset: "native".to_owned(),
                bound: UnlistedBound::PerPeriod,
                max_stroops: 100,
                attempted_stroops: 41,
            }),
        })
    );
}

/// The strictest class of the rule's counterparty criteria is carried, in
/// either order, so a recipient listed by one criterion and unlisted by the
/// budget criterion still uses the budget.
#[test]
fn strictest_recipient_class_is_carried_in_any_criterion_order() {
    let _clock = set_query_time_for_test(NOW_MS);
    let listed_by_other = format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{UNLISTED}\"] }}"
    );
    for criteria in [
        format!("{}, {listed_by_other}", budget(100, 250)),
        format!("{listed_by_other}, {}", budget(100, 250)),
    ] {
        let engine = engine_from_criteria(&criteria);
        let effects = strict(&engine, payment(40, UNLISTED), None)
            .unwrap()
            .value_effects
            .unwrap();
        assert_eq!(
            effects.recipient_class(),
            Some(RecipientClass::Unlisted),
            "{criteria}"
        );
        let entries = engine
            .record_confirmed(&pay(), &profile(), &ValueClass::Value(effects))
            .unwrap();
        assert_eq!(entries.len(), 1, "{criteria}");
        assert_eq!(entries[0].key(), &unlisted_key(), "{criteria}");
        assert_eq!(entries[0].amount(), 40, "{criteria}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Total budget
// ─────────────────────────────────────────────────────────────────────────────

fn total_key() -> StateKey {
    StateKey::new("operator", 1, "total:native", 0)
}

/// Evaluates a native `total_budget` of `max` over `store` for a payment of
/// `amount`, under epoch `[5; 32]`, with `overlay` as the bundle's state.
fn total_evaluation(
    max: i128,
    store: &PolicyStateStore,
    amount: i128,
    overlay: Option<&BundleStateOverlay>,
) -> Result<Option<DenyReason>, PolicyError> {
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    let criterion = TotalBudgetCriterion::new("native".to_owned(), max);
    let tool = pay();
    let profile = profile();
    let args = Value::Null;
    let none = BundleStateOverlay::default();
    let inners = [transfer(UNLISTED, 0)];
    let bundle = BundleView {
        inners: &inners,
        overlay: overlay.unwrap_or(&none),
    };
    let ctx = EvalContext::new(&tool, &args, "operator", &profile, store, NOW_MS)
        .with_policy_digest([5; 32])
        .with_value(payment(amount, UNLISTED));
    let ctx = if overlay.is_some() {
        ctx.with_bundle(&bundle)
    } else {
        ctx
    };
    criterion.evaluate(&ctx)
}

#[test]
fn total_budget_attempt_overflow_denies() {
    let store = PolicyStateStore::new();
    store
        .append_epoch(&total_key(), NOW_MS, i128::MAX, [5; 32])
        .unwrap();
    let result = total_evaluation(i128::MAX, &store, 1, None);
    assert!(
        !matches!(result, Ok(None)),
        "an overflowing attempt is allowed: {result:?}"
    );
}

/// Two native debit legs of `i128::MAX` and 1 in one call.
fn overflowing_legs() -> ValueClass {
    ValueClass::Value(ValueEffects::new(vec![
        leg(ActionKind::Payment, i128::MAX, "native", Some(UNLISTED)),
        leg(ActionKind::Payment, 1, "native", Some(UNLISTED)),
    ]))
}

/// The key a native `total_budget` configured as `asset` sizes `value` under.
fn total_key_for(asset: &str, value: ValueClass) -> StateKey {
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    let store = PolicyStateStore::new();
    let tool = pay();
    let profile = profile();
    let ctx = EvalContext::new(&tool, &Value::Null, "operator", &profile, &store, NOW_MS)
        .with_policy_digest([5; 32])
        .with_value(value);
    TotalBudgetCriterion::new(asset.to_owned(), 10)
        .size(&ctx, NOW_MS)
        .unwrap()
        .expect("the leg matches the criterion")
        .key()
        .clone()
}

#[test]
fn total_budget_spellings_of_one_asset_share_one_key() {
    let native_sac = CanonicalAsset::Native
        .sac_contract_id(TESTNET_PASSPHRASE)
        .unwrap();
    let issued = format!("USDC:{LISTED}");
    let issued_sac = CanonicalAsset::parse_threshold_key(&issued)
        .unwrap()
        .sac_contract_id(TESTNET_PASSPHRASE)
        .unwrap();
    let native_leg = || payment(1, UNLISTED);
    let issued_leg = || ValueClass::single(leg(ActionKind::Payment, 1, &issued, Some(UNLISTED)));
    assert_eq!(
        total_key_for("native", native_leg()),
        total_key_for(&native_sac, native_leg()),
        "native and its asset contract fill two buckets"
    );
    assert_eq!(
        total_key_for(&issued, issued_leg()),
        total_key_for(&issued_sac, issued_leg()),
        "an issued asset and its asset contract fill two buckets"
    );
    assert_ne!(
        total_key_for("native", native_leg()),
        total_key_for(&issued, issued_leg())
    );
}

#[test]
fn total_budget_multileg_overflow_denies() {
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    let store = PolicyStateStore::new();
    let tool = pay();
    let profile = profile();
    let ctx = EvalContext::new(&tool, &Value::Null, "operator", &profile, &store, NOW_MS)
        .with_policy_digest([5; 32])
        .with_value(overflowing_legs());
    let result = TotalBudgetCriterion::new("native".to_owned(), i128::MAX).evaluate(&ctx);
    assert!(
        matches!(&result, Err(PolicyError::CriterionEvaluationFailed { detail }) if detail == "total_budget: sum overflows"),
        "an overflowing multileg debit is allowed: {result:?}"
    );
}

#[test]
fn total_budget_multileg_sizing_refuses_overflow() {
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    let store = PolicyStateStore::new();
    let tool = pay();
    let profile = profile();
    let ctx = EvalContext::new(&tool, &Value::Null, "operator", &profile, &store, NOW_MS)
        .with_policy_digest([5; 32])
        .with_value(overflowing_legs());
    let result = TotalBudgetCriterion::new("native".to_owned(), i128::MAX).size(&ctx, NOW_MS);
    assert!(
        matches!(&result, Err(PolicyError::CriterionEvaluationFailed { detail }) if detail == "total_budget: sum overflows"),
        "an overflowing multileg debit is sized: {result:?}"
    );
}

#[test]
fn query_epoch_overflow_errors() {
    use stellar_agent_core::policy::v1::criteria::state_store::StateStoreError;
    let store = PolicyStateStore::new();
    store
        .append_epoch(&total_key(), NOW_MS, i128::MAX, [5; 32])
        .unwrap();
    store
        .append_epoch(&total_key(), NOW_MS, 1, [5; 32])
        .unwrap();
    assert_eq!(
        store.query_epoch(&total_key(), [5; 32]),
        Err(StateStoreError::SumOverflow)
    );
}

#[test]
fn total_budget_overlay_overflow_denies() {
    use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
    let store = PolicyStateStore::new();
    store
        .append_epoch(&total_key(), NOW_MS, i128::MAX, [5; 32])
        .unwrap();
    let mut overlay = BundleStateOverlay::default();
    let tool = pay();
    let profile = profile();
    let ctx = EvalContext::new(&tool, &Value::Null, "operator", &profile, &store, NOW_MS);
    TotalBudgetCriterion::new("native".to_owned(), i128::MAX).accumulate_overlay(
        &ctx,
        &transfer(UNLISTED, 1),
        &mut overlay,
    );
    let result = total_evaluation(i128::MAX, &store, 0, Some(&overlay));
    assert!(
        matches!(&result, Err(PolicyError::CriterionEvaluationFailed { detail }) if detail == "total_budget: sum overflows"),
        "{result:?}"
    );
}

#[test]
fn total_budget_requires_v2_allow_without_window() {
    let total = "{ kind = \"total_budget\", asset = \"native\", max_stroops = 100 }";
    refused(
        &v1(&rule(total, "allow")),
        "rule[0].criteria[0]: total_budget requires policy version 2",
    );
    for decision in ["deny", "require_approval"] {
        refused(
            &v2(&rule(total, decision)),
            "rule[0].criteria[0]: `total_budget` requires decision = \"allow\"",
        );
    }
    refused(
        &v2(&rule(
            "{ kind = \"total_budget\", asset = \"native\", max_stroops = 100, window = \"1w\" }",
            "allow",
        )),
        "rule[0].criteria[0]: unknown key; a `total_budget` criterion accepts kind, asset, \
         max_stroops",
    );
    refused(
        &v2(&rule(
            "{ kind = \"total_budget\", asset = \"native\", max_stroops = -1 }",
            "allow",
        )),
        "rule[0].criteria[0]: `max_stroops` must be non-negative",
    );
    let missing_asset = check(&v2(&rule(
        "{ kind = \"total_budget\", max_stroops = 1 }",
        "allow",
    )));
    assert!(
        matches!(
            &missing_asset,
            Err(PolicyError::PolicyFileParseFailed { detail })
                if detail.starts_with("rule[0].criteria[0]: ") && detail.contains("`asset`")
        ),
        "{missing_asset:?}"
    );
    let document = load(&v2(&rule(
        "{ kind = \"total_budget\", asset = \"native\", max_stroops = \"0\" }",
        "allow",
    )));
    let criterion = document.rules[0].criteria[0].as_ref();
    assert_eq!(criterion.kind(), "total_budget");
    assert!(criterion.windowed());
}

#[test]
fn total_epochs_ignore_time_and_isolate_resigning() {
    let clock = set_query_time_for_test(NOW_MS);
    let raw = v2(&rule(
        "{ kind = \"total_budget\", asset = \"native\", max_stroops = 100 }",
        "allow",
    ));
    let first = engine(&raw);
    assert_eq!(first.policy_digest(), [5; 32]);
    let exhausted = |remaining_stroops| {
        Decision::Deny(DenyReason::TotalBudgetExhausted {
            asset: "native".to_owned(),
            max_stroops: 100,
            remaining_stroops,
        })
    };

    // An entry older than a week counts, also after ordinary-window
    // retention has pruned the store.
    first
        .state_store()
        .append_epoch(&total_key(), NOW_MS - 2 * WEEK_MS, 60, [5; 32])
        .unwrap();
    let prune = |now_ms| {
        first
            .state_store()
            .query_window(&StateKey::new("operator", 1, "native", 86_400), now_ms)
            .unwrap()
    };
    prune(NOW_MS);
    assert_eq!(
        first
            .state_store()
            .query_epoch(&total_key(), [5; 32])
            .unwrap(),
        (60, 1)
    );
    assert_eq!(decide(&first, payment(40, UNLISTED)), Decision::Allow);
    assert_eq!(decide(&first, payment(41, UNLISTED)), exhausted(40));

    // A confirmed payment records against the epoch, and time never
    // releases it.
    let entries = first
        .record_confirmed(&pay(), &profile(), &payment(30, UNLISTED))
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].epoch(), Some([5; 32]));
    assert_eq!(
        entries[0].limit(),
        &WindowLimit::Total {
            asset: "native".to_owned(),
            max_stroops: 100,
        }
    );
    clock.set(NOW_MS + 52 * WEEK_MS);
    prune(NOW_MS + 52 * WEEK_MS);
    assert_eq!(decide(&first, payment(10, UNLISTED)), Decision::Allow);
    assert_eq!(decide(&first, payment(11, UNLISTED)), exhausted(10));
    assert_eq!(
        first
            .state_store()
            .query_epoch(&total_key(), [5; 32])
            .unwrap(),
        (90, 2)
    );

    // A re-signed policy starts another allocation at zero.
    let resigned =
        PolicyEngineV1::new_with_store(load(&raw), "operator".to_owned(), PolicyStateStore::new())
            .with_policy_digest_for_test([6; 32]);
    resigned
        .state_store()
        .append_epoch(&total_key(), NOW_MS, 90, [5; 32])
        .unwrap();
    assert_eq!(decide(&resigned, payment(100, UNLISTED)), Decision::Allow);
    assert_eq!(decide(&resigned, payment(101, UNLISTED)), exhausted(100));
    assert_eq!(
        resigned
            .state_store()
            .query_epoch(&total_key(), [6; 32])
            .unwrap(),
        (0, 0)
    );

    // A used amount above the allocation reports zero remaining.
    resigned
        .state_store()
        .append_epoch(&total_key(), NOW_MS, 150, [6; 32])
        .unwrap();
    assert_eq!(decide(&resigned, payment(1, UNLISTED)), exhausted(0));
}

#[test]
fn total_budget_refuses_without_policy_digest() {
    let _clock = set_query_time_for_test(NOW_MS);
    let engine = PolicyEngineV1::new_with_store(
        load(&v2(&rule(
            "{ kind = \"total_budget\", asset = \"native\", max_stroops = 100 }",
            "allow",
        ))),
        "operator".to_owned(),
        PolicyStateStore::new(),
    );
    assert_eq!(engine.policy_digest(), [0; 32]);
    let refuses = |error: PolicyError| {
        assert!(
            matches!(
                &error,
                PolicyError::CriterionEvaluationFailed { detail }
                    if detail == "total_budget requires a verified policy digest"
            ),
            "{error:?}"
        );
    };
    // A read-only call, a debit in another asset, and a matching debit all
    // fail, in evaluation, sizing, and recording alike.
    let read_only = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: false,
        read_only_hint: true,
        chain_id_required: true,
        value_kind: ToolValueKind::ReadOnly,
    });
    let other_asset = ValueClass::single(leg(ActionKind::Payment, 1, &usd(), Some(UNLISTED)));
    for (tool, value) in [
        (&read_only, ValueClass::ReadOnly),
        (&pay(), other_asset),
        (&pay(), payment(1, UNLISTED)),
    ] {
        refuses(
            engine
                .evaluate_with_value_full(
                    tool,
                    &Value::Null,
                    &profile(),
                    value.clone(),
                    None,
                    None,
                    None,
                    None,
                    None,
                    instant(),
                )
                .unwrap_err(),
        );
        refuses(
            engine
                .size_window_entries(tool, &profile(), &value, NOW_MS)
                .unwrap_err(),
        );
        refuses(
            engine
                .record_confirmed(tool, &profile(), &value)
                .unwrap_err(),
        );
    }
    assert_eq!(
        engine
            .state_store()
            .query_epoch(&total_key(), [0; 32])
            .unwrap(),
        (0, 0)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Bundle accounting
// ─────────────────────────────────────────────────────────────────────────────

/// A native transfer from the wallet to `to`, as a multicall inner.
fn transfer(to: &str, amount: i128) -> InnerOpDescriptor {
    InnerOpDescriptor::TokenTransfer {
        asset: sac("native"),
        from: LISTED.to_owned(),
        to: to.to_owned(),
        amount,
    }
}

/// An inner the wallet does not recognize as a transfer.
fn generic() -> InnerOpDescriptor {
    InnerOpDescriptor::Generic {
        target: contract(9),
        fn_name: "swap".to_owned(),
    }
}

fn evaluate_bundle(engine: &PolicyEngineV1, inners: &[InnerOpDescriptor]) -> Decision {
    let overlay = BundleStateOverlay::default();
    engine
        .evaluate_bundle(
            &pay(),
            &Value::Null,
            &profile(),
            &BundleView {
                inners,
                overlay: &overlay,
            },
        )
        .unwrap()
}

fn confirm_bundle(
    engine: &PolicyEngineV1,
    inners: &[InnerOpDescriptor],
) -> Result<Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>, PolicyError> {
    let overlay = BundleStateOverlay::default();
    engine.record_confirmed_bundle(
        &pay(),
        &profile(),
        &BundleView {
            inners,
            overlay: &overlay,
        },
    )
}

fn bundle_denied(inner_index: u32, reason: DenyReason) -> Decision {
    Decision::Deny(DenyReason::BundleDenied {
        inner_index,
        deny_reason: Box::new(reason),
    })
}

/// A confirmed bundle uses the total allocation as the same payments made
/// one by one would, and its inners accumulate within the bundle.
#[test]
fn confirmed_bundles_record_total_budget_usage() {
    let _clock = set_query_time_for_test(NOW_MS);
    let engine =
        engine_from_criteria("{ kind = \"total_budget\", asset = \"native\", max_stroops = 100 }");
    let exhausted = |remaining_stroops| DenyReason::TotalBudgetExhausted {
        asset: "native".to_owned(),
        max_stroops: 100,
        remaining_stroops,
    };

    // Two inners accumulate: 60 and 40 fit, 60 and 41 do not.
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60), transfer(LISTED, 40)]),
        Decision::Allow
    );
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60), transfer(LISTED, 41)]),
        bundle_denied(1, exhausted(40))
    );

    // A confirmed 60 leaves 40 for the next bundle.
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60)]),
        Decision::Allow
    );
    let entries = confirm_bundle(&engine, &[transfer(UNLISTED, 60)]).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key(), &total_key());
    assert_eq!(entries[0].amount(), 60);
    assert_eq!(entries[0].epoch(), Some([5; 32]));
    assert_eq!(
        engine
            .state_store()
            .query_epoch(&total_key(), [5; 32])
            .unwrap(),
        (60, 1)
    );
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60)]),
        bundle_denied(0, exhausted(40))
    );
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 40)]),
        Decision::Allow
    );
}

/// A confirmed bundle uses the unlisted window for its unlisted inners only.
#[test]
fn confirmed_bundles_record_unlisted_budget_usage() {
    let _clock = set_query_time_for_test(NOW_MS);
    let engine = engine_from_criteria(&budget(100, 100));

    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60), transfer(LISTED, 500)]),
        Decision::Allow
    );
    let entries =
        confirm_bundle(&engine, &[transfer(UNLISTED, 60), transfer(LISTED, 500)]).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key(), &unlisted_key());
    assert_eq!(entries[0].amount(), 60);
    assert_eq!(
        engine
            .state_store()
            .query_window(&unlisted_key(), NOW_MS)
            .unwrap(),
        (60, 1)
    );
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 60)]),
        bundle_denied(
            0,
            DenyReason::UnlistedBudgetExceeded {
                asset: "native".to_owned(),
                bound: UnlistedBound::PerPeriod,
                max_stroops: 100,
                attempted_stroops: 60,
            }
        )
    );
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 40), transfer(LISTED, 500)]),
        Decision::Allow
    );
}

/// A bundle whose inner cannot be sized refuses under a rule that records
/// each inner, and recording such a bundle fails.
#[test]
fn bundles_with_unsizable_inners_refuse_under_recorded_budgets() {
    let _clock = set_query_time_for_test(NOW_MS);
    for criteria in [
        "{ kind = \"total_budget\", asset = \"native\", max_stroops = 100 }".to_owned(),
        budget(100, 100),
    ] {
        let mut document = load(&v2(&rule(&criteria, "allow")));
        document.rules[0].allow_opaque_signing = true;
        let engine = PolicyEngineV1::new_with_store(
            document,
            "operator".to_owned(),
            PolicyStateStore::new(),
        )
        .with_policy_digest_for_test([5; 32]);
        assert_eq!(
            evaluate_bundle(&engine, &[transfer(UNLISTED, 10), generic()]),
            Decision::Deny(DenyReason::BundleContainsGenericKind { inner_index: 1 }),
            "{criteria}"
        );
        let recorded = confirm_bundle(&engine, &[transfer(UNLISTED, 10), generic()]);
        assert!(
            matches!(
                &recorded,
                Err(PolicyError::CriterionEvaluationFailed { detail })
                    if detail.contains("not a recognized transfer")
            ),
            "{criteria}: {recorded:?}"
        );
    }

    // A rule without either criterion keeps admitting the inner under
    // `allow_opaque_signing`.
    let mut document = load(&v2(&rule("", "allow")));
    document.rules[0].allow_opaque_signing = true;
    let engine =
        PolicyEngineV1::new_with_store(document, "operator".to_owned(), PolicyStateStore::new());
    assert_eq!(
        evaluate_bundle(&engine, &[transfer(UNLISTED, 10), generic()]),
        Decision::Allow
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Provisional evaluation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn evaluate_provisional_defers_only_reserve_and_floor() {
    let engine = engine_from_criteria(&format!(
        "{{ kind = \"minimum_reserve\", margin_stroops = 0 }}, \
         {{ kind = \"balance_floor\", min_stroops = 0 }}, \
         {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{LISTED}\"] }}, \
         {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = 100 }}, \
         {{ kind = \"approval_above\", asset = \"native\", max_stroops = 50 }}"
    ));

    // Strictly, both deferred criteria need the account.
    assert!(matches!(
        strict(&engine, payment(40, LISTED), None),
        Err(PolicyError::CriterionEvaluationFailed { .. })
    ));

    let allowed = provisional(&engine, payment(40, LISTED)).unwrap();
    assert_eq!(allowed.decision, Decision::Allow);
    assert!(allowed.provisional);
    assert!(allowed.value_effects.is_some());

    let escalated = provisional(&engine, payment(60, LISTED)).unwrap();
    assert!(matches!(escalated.decision, Decision::RequireApproval(_)));
    assert!(escalated.provisional);

    let capped = provisional(&engine, payment(101, LISTED)).unwrap();
    assert_eq!(
        capped.decision,
        Decision::Deny(DenyReason::PerTxCapExceeded {
            asset: "native".to_owned(),
            max_stroops: 100,
            attempted_stroops: 101,
        })
    );
    assert!(capped.provisional);

    let unlisted = provisional(&engine, payment(10, UNLISTED)).unwrap();
    assert_eq!(
        unlisted.decision,
        Decision::Deny(DenyReason::CounterpartyDenied {
            kind: "G_ACCOUNT".to_owned(),
            value: UNLISTED.to_owned(),
        })
    );

    // The floor alone: strict refuses unread, provisional passes.
    let floor = engine_from_criteria("{ kind = \"balance_floor\", min_stroops = 0 }");
    assert_eq!(
        strict(&floor, payment(1, LISTED), None).unwrap().decision,
        Decision::Deny(DenyReason::AccountUnread)
    );
    assert_eq!(
        provisional(&floor, payment(1, LISTED)).unwrap().decision,
        Decision::Allow
    );
}

#[test]
fn final_evaluation_runs_deferred_checks() {
    let _clock = set_query_time_for_test(NOW_MS);
    let above = "{ kind = \"approval_above\", asset = \"native\", max_stroops = 50 }";

    let reserve = engine_from_criteria(&format!(
        "{{ kind = \"minimum_reserve\", margin_stroops = 0 }}, {above}"
    ));
    let first = provisional(&reserve, payment(60, LISTED)).unwrap();
    assert!(matches!(first.decision, Decision::RequireApproval(_)));
    assert!(first.provisional);
    let low = Balance(10_000_000);
    let last = strict(&reserve, payment(60, LISTED), Some(&low)).unwrap();
    assert!(!last.provisional);
    assert_eq!(
        last.decision,
        Decision::Deny(DenyReason::MinimumReserveBreached {
            reserve_required_stroops: 10_000_000,
            balance_stroops: 10_000_000,
        })
    );

    let floor = engine_from_criteria(&format!(
        "{{ kind = \"balance_floor\", min_stroops = 1000 }}, {above}"
    ));
    let first = provisional(&floor, payment(60, LISTED)).unwrap();
    assert!(matches!(first.decision, Decision::RequireApproval(_)));
    assert!(first.provisional);
    let observed = ObservedAccount::new(Balance(1050), 10, NOW_MS, NOW_MS - 5_000);
    let input = FloorInput {
        observed: &observed,
        effective_reservations_stroops: 0,
    };
    let last = strict(&floor, payment(60, LISTED), Some(&input)).unwrap();
    assert!(!last.provisional);
    assert_eq!(
        last.decision,
        Decision::Deny(DenyReason::AccountFloorRefused {
            min_stroops: 1000,
            balance_after_stroops: 990,
        })
    );
    let passing = strict(&floor, payment(50, LISTED), Some(&input)).unwrap();
    assert_eq!(passing.decision, Decision::Allow);
    assert!(!passing.provisional);
}

/// An engine that implements only the strict methods.
struct StrictOnly(PolicyEngineV1);

impl PolicyEngine for StrictOnly {
    fn evaluate(
        &self,
        tool: &ToolDescriptor,
        args: &Value,
        profile: &Profile,
        account_view: Option<&dyn AccountReservesView>,
        identity_view: Option<&dyn AccountIdentityView>,
        counterparty_cache: Option<&dyn CounterpartyCacheView>,
        sep10_sessions: Option<&dyn Sep10SessionView>,
        sep45_sessions: Option<&dyn Sep45SessionView>,
        now_ms: u64,
    ) -> Result<Decision, PolicyError> {
        self.0.evaluate(
            tool,
            args,
            profile,
            account_view,
            identity_view,
            counterparty_cache,
            sep10_sessions,
            sep45_sessions,
            now_ms,
        )
    }

    fn evaluate_with_value_full(
        &self,
        tool: &ToolDescriptor,
        args: &Value,
        profile: &Profile,
        value: ValueClass,
        account_view: Option<&dyn AccountReservesView>,
        identity_view: Option<&dyn AccountIdentityView>,
        counterparty_cache: Option<&dyn CounterpartyCacheView>,
        sep10_sessions: Option<&dyn Sep10SessionView>,
        sep45_sessions: Option<&dyn Sep45SessionView>,
        now_ms: u64,
    ) -> Result<Evaluation, PolicyError> {
        self.0.evaluate_with_value_full(
            tool,
            args,
            profile,
            value,
            account_view,
            identity_view,
            counterparty_cache,
            sep10_sessions,
            sep45_sessions,
            now_ms,
        )
    }
}

#[test]
fn evaluate_provisional_default_is_strict() {
    let wrapper = StrictOnly(engine_from_criteria(
        "{ kind = \"balance_floor\", min_stroops = 0 }, \
         { kind = \"approval_above\", asset = \"native\", max_stroops = 50 }",
    ));
    let evaluation = provisional(&wrapper, payment(10, LISTED)).unwrap();
    assert_eq!(
        evaluation.decision,
        Decision::Deny(DenyReason::AccountUnread)
    );
    assert!(!evaluation.provisional);
    let expected = strict(&wrapper.0, payment(10, LISTED), None).unwrap();
    assert_eq!(evaluation.decision, expected.decision);
    assert_eq!(evaluation.provisional, expected.provisional);
}

// ─────────────────────────────────────────────────────────────────────────────
// Observed floor
// ─────────────────────────────────────────────────────────────────────────────

fn floor_decision(
    min_stroops: i128,
    account_view: Option<&dyn AccountReservesView>,
    value: ValueClass,
    args: &Value,
) -> Option<DenyReason> {
    let criterion = BalanceFloorCriterion::new(min_stroops);
    let tool = pay();
    let profile = profile();
    let store = PolicyStateStore::new();
    let mut ctx =
        EvalContext::new(&tool, args, "operator", &profile, &store, instant()).with_value(value);
    if let Some(view) = account_view {
        ctx = ctx.with_account_view(view);
    }
    criterion.evaluate(&ctx).unwrap()
}

#[test]
fn observed_floor_checks_age_and_exact_balance() {
    let _clock = set_query_time_for_test(NOW_MS);
    let null = Value::Null;
    let observed = |balance: i64, age_ms: u64| {
        ObservedAccount::new(
            Balance(balance),
            7,
            NOW_MS - age_ms,
            NOW_MS - age_ms - 5_000,
        )
    };

    // A missing view, observation, reservation sum, or balance is unread.
    assert_eq!(
        floor_decision(0, None, payment(1, LISTED), &null),
        Some(DenyReason::AccountUnread)
    );
    let plain = Balance(1_000);
    assert_eq!(
        floor_decision(0, Some(&plain), payment(1, LISTED), &null),
        Some(DenyReason::AccountUnread)
    );
    let without_reservations = observed(1_000, 0);
    assert_eq!(
        floor_decision(0, Some(&without_reservations), payment(1, LISTED), &null),
        Some(DenyReason::AccountUnread)
    );
    let unreadable = ObservedAccount::new(Unreadable, 7, NOW_MS, NOW_MS);
    let unreadable_input = FloorInput {
        observed: &unreadable,
        effective_reservations_stroops: 0,
    };
    assert_eq!(
        floor_decision(0, Some(&unreadable_input), payment(1, LISTED), &null),
        Some(DenyReason::AccountUnread)
    );

    // Ages up to 120,000 ms pass; older observations are stale.
    assert_eq!(MAX_OBSERVATION_AGE_MS, 120_000);
    for (age, expected) in [
        (119_999, None),
        (120_000, None),
        (120_001, Some(DenyReason::AccountStale { age_ms: 120_001 })),
    ] {
        let account = observed(1_000, age);
        let input = FloorInput {
            observed: &account,
            effective_reservations_stroops: 0,
        };
        assert_eq!(
            floor_decision(0, Some(&input), payment(1, LISTED), &null),
            expected,
            "{age}"
        );
    }

    // balance - reservations - (debit + fee) against the floor; equality
    // passes.
    let account = observed(10_000, 0);
    let input = FloorInput {
        observed: &account,
        effective_reservations_stroops: 3_000,
    };
    let fee = json!({ "total_fee_stroops": 500 });
    assert_eq!(
        floor_decision(4_500, Some(&input), payment(2_000, LISTED), &fee),
        None
    );
    assert_eq!(
        floor_decision(4_501, Some(&input), payment(2_000, LISTED), &fee),
        Some(DenyReason::AccountFloorRefused {
            min_stroops: 4_501,
            balance_after_stroops: 4_500,
        })
    );
    assert_eq!(
        floor_decision(4_500, Some(&input), payment(2_001, LISTED), &fee),
        Some(DenyReason::AccountFloorRefused {
            min_stroops: 4_500,
            balance_after_stroops: 4_499,
        })
    );
    assert_eq!(
        floor_decision(
            4_500,
            Some(&input),
            payment(2_000, LISTED),
            &json!({ "total_fee_stroops": 501 })
        ),
        Some(DenyReason::AccountFloorRefused {
            min_stroops: 4_500,
            balance_after_stroops: 4_499,
        })
    );
    // A debit in another asset does not reduce the native balance.
    assert_eq!(
        floor_decision(
            6_500,
            Some(&input),
            ValueClass::single(leg(ActionKind::Payment, 2_000, &usd(), Some(LISTED))),
            &fee
        ),
        None
    );
}

/// The unlisted budget, the total budget and the balance floor of one rule
/// decide and record at the supplied instant, which lies years before the
/// host clock: the floor's observation is fresh only at that instant, the
/// recorded debits carry it, and the unlisted window counts them only from
/// it.
#[test]
fn grammar_criteria_read_the_evaluation_instant() {
    const SAMPLE_MS: u64 = 1_000_000_000_000;
    let _clock = set_query_time_for_test(SAMPLE_MS);
    let engine = engine_from_criteria(&format!(
        "{}, {{ kind = \"total_budget\", asset = \"native\", max_stroops = 1000 }}, \
         {{ kind = \"balance_floor\", min_stroops = 0 }}",
        budget(100, 150)
    ));
    let account = ObservedAccount::new(Balance(1_000_000), 7, SAMPLE_MS - 1_000, SAMPLE_MS - 6_000);
    let input = FloorInput {
        observed: &account,
        effective_reservations_stroops: 0,
    };
    let evaluate = |value: ValueClass| {
        engine
            .evaluate_with_value_full(
                &pay(),
                &Value::Null,
                &profile(),
                value,
                Some(&input),
                None,
                None,
                None,
                None,
                SAMPLE_MS,
            )
            .unwrap()
    };

    let allowed = evaluate(payment(100, UNLISTED));
    assert_eq!(allowed.decision, Decision::Allow);
    let recorded = engine
        .record_confirmed(
            &pay(),
            &profile(),
            &ValueClass::Value(allowed.value_effects.unwrap()),
        )
        .unwrap();
    let stamps: std::collections::HashMap<StateKey, u64> = recorded
        .iter()
        .map(|entry| (entry.key().clone(), entry.timestamp_ms()))
        .collect();
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert_eq!(
        stamps,
        std::collections::HashMap::from([(total_key(), SAMPLE_MS), (unlisted_key(), SAMPLE_MS)])
    );
    assert_eq!(
        evaluate(payment(51, UNLISTED)).decision,
        Decision::Deny(DenyReason::UnlistedBudgetExceeded {
            asset: "native".to_owned(),
            bound: UnlistedBound::PerPeriod,
            max_stroops: 150,
            attempted_stroops: 51,
        })
    );
}

#[test]
fn balance_floor_requires_v2_and_admits_every_decision() {
    let floor = "{ kind = \"balance_floor\", min_stroops = 20000000 }";
    refused(
        &v1(&rule(floor, "allow")),
        "rule[0].criteria[0]: balance_floor requires policy version 2",
    );
    for decision in ["allow", "deny", "require_approval"] {
        check(&v2(&rule(floor, decision))).unwrap();
    }
    refused(
        &v2(&rule(
            "{ kind = \"balance_floor\", min_stroops = -1 }",
            "allow",
        )),
        "rule[0].criteria[0]: `min_stroops` must be non-negative",
    );
    let document = load(&v2(&rule(
        "{ kind = \"balance_floor\", min_stroops = \"0\" }",
        "allow",
    )));
    assert_eq!(
        loaded_criterion::<BalanceFloorCriterion>(&document, 0, 0).min_stroops(),
        0
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Memo binding
// ─────────────────────────────────────────────────────────────────────────────

fn memo_criterion(bindings: &str) -> String {
    format!("{{ kind = \"memo_binding\", bindings = [{bindings}] }}")
}

fn memo_decision(
    criterion: &MemoBindingCriterion,
    legs: Vec<ValueLeg>,
    memo: Option<ClassicMemo>,
) -> Result<Option<DenyReason>, PolicyError> {
    let tool = pay();
    let profile = profile();
    let store = PolicyStateStore::new();
    let args = Value::Null;
    let ctx = EvalContext::new(&tool, &args, "operator", &profile, &store, instant())
        .with_value(ValueClass::Value(ValueEffects::new(legs).with_memo(memo)));
    criterion.evaluate(&ctx)
}

fn mismatch(kind: &str) -> Option<DenyReason> {
    Some(DenyReason::MemoBindingMismatch {
        kind: kind.to_owned(),
    })
}

#[test]
fn memo_binding_grammar_and_matching() {
    let loc = "rule[0].criteria[0]";
    let id_binding = |destination: &str| {
        format!("{{ destination = \"{destination}\", kind = \"id\", value = \"7\" }}")
    };
    let accounts: Vec<String> = (0..65_u8)
        .map(|i| format!("{}", stellar_strkey::ed25519::PublicKey([i; 32])))
        .collect();
    let bindings = |count: usize| {
        accounts[..count]
            .iter()
            .map(|account| id_binding(account))
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Closed keys, counts, and distinct destinations.
    refused(
        &v2(&rule(
            &memo_criterion(&format!(
                "{{ destination = \"{LISTED}\", kind = \"id\", value = \"7\", note = \"x\" }}"
            )),
            "allow",
        )),
        &format!("{loc}.bindings[0]: unknown key; a binding accepts destination, kind, value"),
    );
    let document = load(&v2(&rule(&memo_criterion(&bindings(64)), "allow")));
    assert_eq!(
        loaded_criterion::<MemoBindingCriterion>(&document, 0, 0)
            .bindings()
            .len(),
        64
    );
    for count in [0, 65] {
        refused(
            &v2(&rule(&memo_criterion(&bindings(count)), "allow")),
            &format!("{loc}: `bindings` holds 1 to 64 bindings"),
        );
    }
    refused(
        &v2(&rule(
            &memo_criterion(&format!(
                "{}, {{ destination = \"{LISTED}\", kind = \"any\" }}",
                id_binding(LISTED)
            )),
            "allow",
        )),
        &format!("{loc}.bindings[1]: `destination` repeats an earlier binding"),
    );
    for destination in [muxed(LISTED, 1), contract(4), "GBAD".to_owned()] {
        refused(
            &v2(&rule(&memo_criterion(&id_binding(&destination)), "allow")),
            &format!(
                "{loc}.bindings[0]: `destination` must be a G-strkey; M and C addresses are refused"
            ),
        );
    }
    refused(
        &v1(&rule(&memo_criterion(&id_binding(LISTED)), "allow")),
        &format!("{loc}: memo_binding requires policy version 2"),
    );
    for decision in ["deny", "require_approval"] {
        check(&v2(&rule(&memo_criterion(&id_binding(LISTED)), decision))).unwrap();
    }

    // Value forms per kind.
    let hash = "ab".repeat(32);
    let accepted = [
        format!("kind = \"text\", value = \"{}\"", "t".repeat(28)),
        "kind = \"text\", value = \"\"".to_owned(),
        "kind = \"id\", value = \"0\"".to_owned(),
        "kind = \"id\", value = \"18446744073709551615\"".to_owned(),
        format!("kind = \"hash\", value = \"{hash}\""),
        format!("kind = \"return\", value = \"{hash}\""),
        "kind = \"any\"".to_owned(),
    ];
    for form in &accepted {
        check(&v2(&rule(
            &memo_criterion(&format!("{{ destination = \"{LISTED}\", {form} }}")),
            "allow",
        )))
        .unwrap_or_else(|error| panic!("{form}: {error:?}"));
    }
    let rejected = [
        (
            format!("kind = \"text\", value = \"{}\"", "t".repeat(29)),
            "a text `value` holds at most 28 bytes of UTF-8",
        ),
        (
            "kind = \"id\", value = \"042\"".to_owned(),
            "an id `value` is a decimal without sign or leading zero",
        ),
        (
            "kind = \"id\", value = \"-1\"".to_owned(),
            "an id `value` is a decimal without sign or leading zero",
        ),
        (
            "kind = \"id\", value = \"+1\"".to_owned(),
            "an id `value` is a decimal without sign or leading zero",
        ),
        (
            "kind = \"id\", value = \"18446744073709551616\"".to_owned(),
            "an id `value` must fit in an unsigned 64-bit integer",
        ),
        (
            format!("kind = \"hash\", value = \"{}\"", "AB".repeat(32)),
            "a hash or return `value` is 64 lowercase hex digits",
        ),
        (
            format!("kind = \"return\", value = \"{}\"", "a".repeat(63)),
            "a hash or return `value` is 64 lowercase hex digits",
        ),
        (
            "kind = \"any\", value = \"x\"".to_owned(),
            "`value` is not accepted with kind `any`",
        ),
        (
            "kind = \"text\"".to_owned(),
            "`value` is required for this kind",
        ),
        (
            "kind = \"hash\"".to_owned(),
            "`value` is required for this kind",
        ),
        (
            "kind = \"none\", value = \"x\"".to_owned(),
            "`kind` must be text, id, hash, return, or any",
        ),
    ];
    for (form, detail) in &rejected {
        refused(
            &v2(&rule(
                &memo_criterion(&format!("{{ destination = \"{LISTED}\", {form} }}")),
                "allow",
            )),
            &format!("{loc}.bindings[0]: {detail}"),
        );
    }

    // Matching: a bound destination needs its memo, through a muxed address's
    // base account too; unbound, contract, and inflow legs pass.
    let criterion = MemoBindingCriterion::new(vec![
        MemoBinding::new(LISTED, MemoRequirement::Id(7)).unwrap(),
    ]);
    let pay_to = |destination: &str| leg(ActionKind::Payment, 5, "native", Some(destination));
    let id7 = Some(ClassicMemo::Id(7));
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(LISTED)], id7.clone()).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(LISTED)], None).unwrap(),
        mismatch("id")
    );
    let bound_muxed = muxed(LISTED, 42);
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(&bound_muxed)], id7.clone()).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(&bound_muxed)], None).unwrap(),
        mismatch("id")
    );
    assert_eq!(
        memo_decision(
            &criterion,
            vec![pay_to(&bound_muxed)],
            Some(ClassicMemo::Id(8))
        )
        .unwrap(),
        mismatch("id")
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(UNLISTED)], None).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(&muxed(UNLISTED, 42))], None).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(&contract(3))], None).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(
            &criterion,
            vec![leg(ActionKind::Claim, 5, "native", Some(LISTED))],
            None
        )
        .unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, vec![pay_to(UNLISTED), pay_to(LISTED)], None).unwrap(),
        mismatch("id")
    );
    for destination in [None, Some("GBAD")] {
        assert!(matches!(
            memo_decision(
                &criterion,
                vec![leg(ActionKind::Payment, 5, "native", destination)],
                id7.clone()
            ),
            Err(PolicyError::CriterionEvaluationFailed { .. })
        ));
    }

    // The loaded criterion matches as the constructed one does.
    let document = load(&v2(&rule(&memo_criterion(&id_binding(LISTED)), "allow")));
    let loaded = loaded_criterion::<MemoBindingCriterion>(&document, 0, 0);
    assert_eq!(loaded.bindings(), criterion.bindings());
}

#[test]
fn memo_requirements_preserve_destination_kind_and_value() {
    let hash = [0xab; 32];
    let other = [0xcd; 32];
    let memos = [
        ClassicMemo::None,
        ClassicMemo::Text("42".to_owned()),
        ClassicMemo::Text("43".to_owned()),
        ClassicMemo::Id(42),
        ClassicMemo::Id(43),
        ClassicMemo::Hash(hash),
        ClassicMemo::Hash(other),
        ClassicMemo::Return(hash),
        ClassicMemo::Return(other),
    ];
    let cases = [
        (MemoRequirement::Text("42".to_owned()), 1),
        (MemoRequirement::Id(42), 3),
        (MemoRequirement::Hash(hash), 5),
        (MemoRequirement::Return(hash), 7),
    ];
    for (requirement, met_index) in &cases {
        for (index, memo) in memos.iter().enumerate() {
            assert_eq!(
                requirement.is_met_by(memo),
                index == *met_index,
                "{requirement:?} against {memo:?}"
            );
        }
    }
    for (index, memo) in memos.iter().enumerate() {
        assert_eq!(MemoRequirement::Any.is_met_by(memo), index != 0, "{memo:?}");
    }
    assert_eq!(
        MemoRequirement::parse("text", Some("42")).unwrap(),
        MemoRequirement::Text("42".to_owned())
    );
    assert_eq!(
        MemoRequirement::parse("id", Some("42")).unwrap(),
        MemoRequirement::Id(42)
    );
    assert_eq!(
        MemoRequirement::parse("hash", Some(&"ab".repeat(32))).unwrap(),
        MemoRequirement::Hash(hash)
    );
    assert_eq!(
        MemoRequirement::parse("return", Some(&"ab".repeat(32))).unwrap(),
        MemoRequirement::Return(hash)
    );

    // Each binding applies to its own destination with its own kind.
    let criterion = MemoBindingCriterion::new(vec![
        MemoBinding::new(LISTED, MemoRequirement::Text("42".to_owned())).unwrap(),
        MemoBinding::new(UNLISTED, MemoRequirement::Id(42)).unwrap(),
    ]);
    let pay_to = |destination: &str| vec![leg(ActionKind::Payment, 5, "native", Some(destination))];
    let text = Some(ClassicMemo::Text("42".to_owned()));
    let id = Some(ClassicMemo::Id(42));
    assert_eq!(
        memo_decision(&criterion, pay_to(LISTED), text.clone()).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, pay_to(LISTED), id.clone()).unwrap(),
        mismatch("text")
    );
    assert_eq!(
        memo_decision(&criterion, pay_to(UNLISTED), id).unwrap(),
        None
    );
    assert_eq!(
        memo_decision(&criterion, pay_to(UNLISTED), text).unwrap(),
        mismatch("id")
    );
    assert_eq!(
        memo_decision(&criterion, pay_to(UNLISTED), Some(ClassicMemo::None)).unwrap(),
        mismatch("id")
    );
    assert_eq!(
        memo_decision(&criterion, pay_to(UNLISTED), None).unwrap(),
        mismatch("id")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mainnet minimum
// ─────────────────────────────────────────────────────────────────────────────

fn mainnet_profile() -> Profile {
    Profile::builder_mainnet_named(
        "operator",
        "https://rpc.example.invalid",
        "s",
        "a",
        "n",
        "a",
    )
    .build()
}

fn first_rule(doc: &mut DocumentMut) -> &mut toml_edit::Table {
    doc["rules"]
        .as_array_of_tables_mut()
        .unwrap()
        .get_mut(0)
        .unwrap()
}

/// The rule indexes failing `requirement` for `doc`.
fn failing(doc: &DocumentMut, requirement: &str) -> Vec<Option<usize>> {
    mainnet_minimum::failures(doc, &mainnet_profile(), "operator")
        .into_iter()
        .filter_map(|error| match error {
            PolicyError::MainnetMinimumUnmet {
                requirement: name,
                rule,
            } if name == requirement => Some(rule),
            _ => None,
        })
        .collect()
}

#[test]
fn mainnet_claim_and_trustline_require_rate_limits() {
    for tool in [
        "stellar_claim",
        "stellar_claim_commit",
        "stellar_trustline",
        "stellar_trustline_commit",
    ] {
        let trustline = tool.starts_with("stellar_trustline");
        let mut doc = FIXTURE.parse::<DocumentMut>().unwrap();
        first_rule(&mut doc)["match"]["tool"] = toml_edit::value(tool);
        let criteria = first_rule(&mut doc)["criteria"].as_array_mut().unwrap();
        criteria.retain(|c| {
            let kind = c.as_inline_table().unwrap()["kind"].as_str().unwrap();
            kind == "rate_limit" || (trustline && kind == "asset_allowlist")
        });
        assert!(
            mainnet_minimum::failures(&doc, &mainnet_profile(), "operator").is_empty(),
            "{tool}"
        );
        let criteria = first_rule(&mut doc)["criteria"].as_array_mut().unwrap();
        criteria.retain(|c| c.as_inline_table().unwrap()["kind"].as_str() != Some("rate_limit"));
        assert_eq!(failing(&doc, "rate_limit"), [Some(0)], "{tool}");
        assert!(
            matches!(
                mainnet_minimum::validate(&doc, &mainnet_profile(), "operator"),
                Err(PolicyError::MainnetMinimumUnmet {
                    requirement: "rate_limit",
                    rule: Some(0)
                })
            ),
            "{tool}"
        );

        // A deny rule needs no rate limit.
        first_rule(&mut doc)["decision"] = toml_edit::value("deny");
        first_rule(&mut doc).remove("reason");
        first_rule(&mut doc).remove("ttl_secs");
        first_rule(&mut doc)["criteria"] = toml_edit::value(toml_edit::Array::new());
        assert!(failing(&doc, "rate_limit").is_empty(), "{tool}");
        mainnet_minimum::validate(&doc, &mainnet_profile(), "operator").unwrap();
    }
}

#[test]
fn mainnet_approval_ttl_accepts_one_day_only_with_explicit_value() {
    let with_ttl = |ttl: Option<i64>| {
        let mut doc = FIXTURE.parse::<DocumentMut>().unwrap();
        match ttl {
            Some(ttl) => first_rule(&mut doc)["ttl_secs"] = toml_edit::value(ttl),
            None => {
                first_rule(&mut doc).remove("ttl_secs");
            }
        }
        doc
    };
    for (ttl, met) in [
        (None, false),
        (Some(0), false),
        (Some(1), true),
        (Some(3_601), true),
        (Some(86_400), true),
        (Some(86_401), false),
    ] {
        let doc = with_ttl(ttl);
        assert_eq!(
            failing(&doc, "rule_ttl"),
            if met { vec![] } else { vec![Some(0)] },
            "{ttl:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Refusal codes
// ─────────────────────────────────────────────────────────────────────────────

/// The window comparison the durable reservation write re-applies refuses
/// exactly as the gate does, for unlisted and total entries.
#[test]
fn window_entry_refusals_for_unlisted_and_total_limits() {
    let unlisted = |amount| {
        stellar_agent_core::policy::v1::criteria::state_store::WindowEntry::new(
            unlisted_key(),
            NOW_MS,
            amount,
            WindowLimit::Unlisted {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: 100,
            },
        )
    };
    let total = |amount| {
        stellar_agent_core::policy::v1::criteria::state_store::WindowEntry::new(
            total_key(),
            NOW_MS,
            amount,
            WindowLimit::Total {
                asset: "native".to_owned(),
                max_stroops: 100,
            },
        )
        .with_epoch(Some([5; 32]))
    };
    let over = |attempted_stroops| {
        Some(DenyReason::UnlistedBudgetExceeded {
            asset: "native".to_owned(),
            bound: UnlistedBound::PerPeriod,
            max_stroops: 100,
            attempted_stroops,
        })
    };
    let exhausted = |remaining_stroops| {
        Some(DenyReason::TotalBudgetExhausted {
            asset: "native".to_owned(),
            max_stroops: 100,
            remaining_stroops,
        })
    };
    let cases = [
        (unlisted(40), 60, None),
        (unlisted(41), 60, over(41)),
        (unlisted(1), i128::MAX, over(1)),
        (unlisted(i128::MAX), 1, over(i128::MAX)),
        (total(40), 60, None),
        (total(41), 60, exhausted(40)),
        (total(1), 150, exhausted(0)),
        (total(1), i128::MAX, exhausted(0)),
        (total(i128::MAX), 1, exhausted(99)),
    ];
    for (entry, used_stroops, expected) in cases {
        assert_eq!(
            entry.refusal(used_stroops, 1),
            expected,
            "{entry:?} over {used_stroops}"
        );
    }
}

/// Each new refusal serializes its amounts as decimal strings and names no
/// recipient and no memo value.
#[test]
fn new_denials_serialize_exact_json() {
    let max = i128::MAX.to_string();
    let cases = [
        (
            DenyReason::TotalBudgetExhausted {
                asset: "native".to_owned(),
                max_stroops: i128::MAX,
                remaining_stroops: -5,
            },
            format!(
                r#"{{"TotalBudgetExhausted":{{"asset":"native","max_stroops":"{max}","remaining_stroops":"-5"}}}}"#
            ),
        ),
        (
            DenyReason::UnlistedBudgetExceeded {
                asset: "native".to_owned(),
                bound: UnlistedBound::PerTx,
                max_stroops: -1,
                attempted_stroops: i128::MAX,
            },
            format!(
                r#"{{"UnlistedBudgetExceeded":{{"asset":"native","bound":"per_tx","max_stroops":"-1","attempted_stroops":"{max}"}}}}"#
            ),
        ),
        (
            DenyReason::MemoBindingMismatch {
                kind: "text".to_owned(),
            },
            r#"{"MemoBindingMismatch":{"kind":"text"}}"#.to_owned(),
        ),
        (
            DenyReason::AccountFloorRefused {
                min_stroops: i128::MAX,
                balance_after_stroops: -20_000_000,
            },
            format!(
                r#"{{"AccountFloorRefused":{{"min_stroops":"{max}","balance_after_stroops":"-20000000"}}}}"#
            ),
        ),
        (DenyReason::AccountUnread, r#""AccountUnread""#.to_owned()),
        (
            DenyReason::AccountStale { age_ms: 120_001 },
            r#"{"AccountStale":{"age_ms":120001}}"#.to_owned(),
        ),
    ];
    for (reason, json) in cases {
        assert_eq!(serde_json::to_string(&reason).unwrap(), json);
    }

    // Denials from evaluation carry neither the recipient nor the memo.
    let unlisted = engine_from_criteria(&budget(100, 250));
    let Decision::Deny(over) = decide(&unlisted, payment(101, UNLISTED)) else {
        panic!("a payment over the unlisted bound must refuse");
    };
    let binding =
        MemoBinding::new(UNLISTED, MemoRequirement::Text("invoice-7".to_owned())).unwrap();
    let mismatch = memo_decision(
        &MemoBindingCriterion::new(vec![binding]),
        vec![leg(ActionKind::Payment, 1, "native", Some(UNLISTED))],
        Some(ClassicMemo::Text("invoice-8".to_owned())),
    )
    .unwrap()
    .unwrap();
    for reason in [over, mismatch] {
        let json = serde_json::to_string(&reason).unwrap();
        for secret in [UNLISTED, &UNLISTED[..12], "invoice"] {
            assert!(!json.contains(secret), "{json}");
        }
    }
}
