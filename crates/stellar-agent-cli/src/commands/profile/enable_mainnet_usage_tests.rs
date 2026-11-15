thread_local! {
    static BEFORE_USAGE_READ: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

/// Runs the action a test installed between the inspection and the usage read.
pub(super) fn before_usage_read() {
    if let Some(action) = BEFORE_USAGE_READ.with_borrow_mut(Option::take) {
        action();
    }
}

use stellar_agent_network::policy_state::store::total_intent_test_helpers::{
    EARLIER_BUILD_VERSION, TOTAL_INTENTS_VERSION, seal_total_rows,
};

/// The mainnet contract of the native asset.
fn native_contract() -> String {
    stellar_agent_core::asset_id::CanonicalAsset::Native
        .sac_contract_id(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
        .unwrap()
}

/// Two total bounds on rules 1 and 2: native at 10, and native through its
/// contract spelling at 20.
fn total_rules() -> String {
    let rule = |tool: &str, asset: &str, max: &str| {
        format!(
            "\n[[rules]]\nmatch = {{ tool = \"{tool}\", chain = \"stellar:mainnet\" }}\n\
             criteria = [{{ kind = \"total_budget\", asset = \"{asset}\", max_stroops = {max} }}]\n\
             decision = \"allow\"\n"
        )
    };
    format!(
        "{}{}",
        rule("stellar_balances", "native", "\"10\""),
        rule("stellar_fee_stats", &native_contract(), "20")
    )
}

/// An enabled fixture whose signed body at sequence 2 holds the two total
/// bounds, pinned by an advancing load, in check mode. Returns the pinned
/// digest.
fn pinned_total_fixture() -> (Fixture, [u8; 32]) {
    let mut fixture = Fixture::new();
    fixture.run().unwrap();
    fixture.sign(&format!("{}{}", fixture.rewritten_body(2, 1), total_rules()));
    let owner = fixture.owner.verifying_key().to_bytes();
    load_verified_policy(
        &PolicyLoad {
            path: &fixture.path(),
            profile: &fixture.profile,
            profile_name: "operator",
            owner_pubkey: &owner,
            owner_source: OwnerKeySource::Keyring,
            window_path: &fixture.window,
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .unwrap();
    fixture.args.check = true;
    let PinState::Present(pin) = fixture.pin() else {
        panic!("the advancing load pins the body");
    };
    assert_eq!(pin.sequence(), 2);
    (fixture, pin.digest())
}

/// The expected rows of the two bounds.
fn usage_of(used: [&str; 2], remaining: [&str; 2]) -> serde_json::Value {
    serde_json::json!([
        {"asset": "native", "scope_specificity": 1, "rule_indexes": [1],
         "max_stroops": "10", "used_stroops": used[0], "remaining_stroops": remaining[0]},
        {"asset": "native", "scope_specificity": 1, "rule_indexes": [2],
         "max_stroops": "20", "used_stroops": used[1], "remaining_stroops": remaining[1]},
    ])
}

/// The status and code of the usage check.
fn usage_check(output: &serde_json::Value) -> (String, Option<String>) {
    let check = output["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["item"] == "total_budget_usage")
        .unwrap_or_else(|| panic!("no usage check: {output}"));
    (
        check["status"].as_str().unwrap().to_owned(),
        check["code"].as_str().map(str::to_owned),
    )
}

/// Every file under the fixture with its bytes, and the window key, the
/// commit counter, the pin, and the nonce.
#[allow(clippy::type_complexity, reason = "a comparable snapshot tuple")]
fn wallet_state(
    fixture: &Fixture,
) -> (
    Vec<(std::path::PathBuf, Vec<u8>)>,
    Vec<std::path::PathBuf>,
    Option<String>,
    Option<String>,
    PinState,
    Option<String>,
) {
    let window = &fixture.profile.policy_window_state_key_id;
    let counter = KeyringEntryRef::new(
        window.service.clone(),
        stellar_agent_core::profile::schema::generation_account(&window.account),
    );
    (
        persisted(fixture),
        fixture.listing(),
        get(window),
        get(&counter),
        fixture.pin(),
        get(&fixture.nonce_ref()),
    )
}

/// Each bound joins the use of its own scope and canonical bucket; remaining
/// is the checked difference, floored at zero, in exact decimal stroops.
#[test]
fn usage_rows_join_scope_and_floor() {
    let bound = |max_stroops: i128, rule_indexes: Vec<usize>| TotalBound {
        scope_specificity: 1,
        asset: "native".to_owned(),
        max_stroops,
        rule_indexes,
    };
    let used = |scope_specificity: u8, used_stroops: i128| TotalUsage {
        scope_specificity,
        bucket: "total:native".to_owned(),
        used_stroops,
    };
    let row = |max: &str, used: &str, remaining: &str, rules: serde_json::Value| {
        serde_json::json!({"asset": "native", "scope_specificity": 1, "rule_indexes": rules,
            "max_stroops": max, "used_stroops": used, "remaining_stroops": remaining})
    };
    let rule_zero = || serde_json::json!([0]);
    assert_eq!(
        usage_rows(
            &[bound(10, vec![0, 2]), bound(20, vec![1])],
            &[used(1, 6), used(9, 9)]
        ),
        Some(serde_json::json!([
            row("10", "6", "4", serde_json::json!([0, 2])),
            row("20", "6", "14", serde_json::json!([1])),
        ]))
    );
    for (use_stroops, remaining) in [(8, "2"), (10, "0"), (12, "0")] {
        assert_eq!(
            usage_rows(&[bound(10, vec![0])], &[used(1, use_stroops)]),
            Some(serde_json::json!([row(
                "10",
                &use_stroops.to_string(),
                remaining,
                rule_zero()
            )])),
            "use {use_stroops}"
        );
    }
    assert_eq!(
        usage_rows(&[bound(i128::MAX, vec![0])], &[used(1, 1)]),
        Some(serde_json::json!([row(
            "170141183460469231731687303715884105727",
            "1",
            "170141183460469231731687303715884105726",
            rule_zero()
        )]))
    );
    assert_eq!(
        usage_rows(&[bound(10, vec![0])], &[used(9, 9)]),
        Some(serde_json::json!([row("10", "0", "10", rule_zero())]))
    );
    assert_eq!(usage_rows(&[], &[used(1, 6)]), Some(serde_json::json!([])));
}

/// `--check` reports committed use only for trusted current state. A pin
/// with no store reports zero; committed rows report their use, and an
/// issued asset keeps its own bucket; an earlier build's history, a retired
/// digest, and a missing pin report `null` with a code; corrupt bytes fail the
/// check. A pinned body without a bound reports `[]` on healthy state and
/// fails the check with `null` on corrupt bytes. No case creates or changes a
/// file, a keyring value, or the counter, and the exit code follows `valid`.
#[test]
#[serial]
fn check_reports_usage_only_for_trusted_current_state() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (fixture, digest) = pinned_total_fixture();
    let store = PersistedWindowStore::at_path(fixture.window.clone());
    let checked = |label: &str| {
        let before = wallet_state(&fixture);
        let result = fixture.run();
        assert_eq!(wallet_state(&fixture), before, "{label}: the check writes nothing");
        let status = exit_code(&result);
        let output = result.unwrap();
        assert_eq!(status, i32::from(output["valid"] != true), "{label}");
        output
    };

    assert!(!fixture.window.exists());
    let output = checked("first use");
    assert_eq!(output["valid"], true, "{output}");
    assert_eq!(output["total_budget_usage"], usage_of(["0", "0"], ["10", "20"]));
    assert_eq!(usage_check(&output), ("passed".to_owned(), None));

    let contract = format!("total:{}", native_contract());
    let issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let classic = format!("total:USDC:{issuer}");
    let issued_contract = stellar_agent_core::asset_id::CanonicalAsset::Classic {
        code: "USDC".to_owned(),
        issuer: issuer.to_owned(),
    }
    .sac_contract_id(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
    .unwrap();
    let issued = format!("total:{issued_contract}");
    let rows = [
        (1, "total:native", 4, Some(digest)),
        (1, contract.as_str(), 2, Some(digest)),
        (9, "total:native", 9, Some(digest)),
        (1, "total:native", 5, Some([7; 32])),
        (1, classic.as_str(), 3, Some(digest)),
    ];
    seal_total_rows(&store, &fixture.profile, TOTAL_INTENTS_VERSION, None, &rows);
    let usage = |scope_specificity: u8, bucket: &str, used_stroops: i128| TotalUsage {
        scope_specificity,
        bucket: bucket.to_owned(),
        used_stroops,
    };
    assert_eq!(
        store.total_usage(&fixture.profile, digest).unwrap(),
        [
            usage(1, &issued, 3),
            usage(1, "total:native", 6),
            usage(9, "total:native", 9),
        ]
    );
    let output = checked("committed rows");
    assert_eq!(output["valid"], true, "{output}");
    assert_eq!(output["total_budget_usage"], usage_of(["6", "6"], ["4", "14"]));

    for (label, version, retired, epoch) in [
        ("earlier build", EARLIER_BUILD_VERSION, None, None),
        ("retired digest", TOTAL_INTENTS_VERSION, Some(digest), Some(digest)),
    ] {
        seal_total_rows(
            &store,
            &fixture.profile,
            version,
            retired,
            &[(1, "total:native", 6, epoch)],
        );
        let output = checked(label);
        assert_eq!(output["valid"], true, "{label}: {output}");
        assert!(output["total_budget_usage"].is_null(), "{label}: {output}");
        assert_eq!(
            usage_check(&output),
            (
                "not_evaluated".to_owned(),
                Some("policy.total_epoch_retired".to_owned())
            ),
            "{label}"
        );
    }

    let sealed = std::fs::read(&fixture.window).unwrap();
    std::fs::write(&fixture.window, b"{").unwrap();
    let output = checked("corrupt state");
    assert_eq!(output["valid"], false, "{output}");
    assert_eq!(check_of(&output, "verified_policy").0, "passed");
    assert!(output["total_budget_usage"].is_null(), "{output}");
    assert_eq!(
        usage_check(&output),
        (
            "failed".to_owned(),
            Some("policy.window_state_unverifiable".to_owned())
        )
    );

    std::fs::write(&fixture.window, &sealed).unwrap();
    let raw = std::fs::read_to_string(fixture.path()).unwrap();
    let mut document = raw.parse::<toml_edit::DocumentMut>().unwrap();
    let rules = document["rules"].as_array_of_tables_mut().unwrap();
    assert_eq!(rules.len(), 3, "rule 0 and the two total rules");
    rules.remove(2);
    rules.remove(1);
    std::fs::write(fixture.path(), document.to_string()).unwrap();
    fixture.sign_rewritten_and_verify(3);
    let output = checked("no bound");
    assert_eq!(output["valid"], true, "{output}");
    assert_eq!(output["total_budget_usage"], serde_json::json!([]));
    assert_eq!(usage_check(&output), ("passed".to_owned(), None));

    std::fs::write(&fixture.window, b"{").unwrap();
    let output = checked("no bound, corrupt state");
    assert_eq!(output["valid"], false, "{output}");
    assert_eq!(check_of(&output, "verified_policy").0, "passed");
    assert!(output["total_budget_usage"].is_null(), "{output}");
    assert_eq!(
        usage_check(&output),
        (
            "failed".to_owned(),
            Some("policy.window_state_unverifiable".to_owned())
        )
    );

    std::fs::write(&fixture.window, sealed).unwrap();
    let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
        &fixture.profile.policy_window_state_key_id,
    );
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    let output = checked("no pin");
    assert!(output["total_budget_usage"].is_null(), "{output}");
    assert_eq!(
        usage_check(&output),
        (
            "not_evaluated".to_owned(),
            Some("policy.pin_absent".to_owned())
        )
    );
}

/// Runs `--check` on `fixture` with committed rows while another writer
/// repins to `repinned` after the inspection and before either pin
/// comparison. Asserts that the repin ran and stands, that `valid` and the
/// exit code are unchanged, and that the use is `null` with the stale code.
fn assert_repin_race(fixture: &Fixture, digest: [u8; 32], repinned: Pin) {
    let store = PersistedWindowStore::at_path(fixture.window.clone());
    seal_total_rows(
        &store,
        &fixture.profile,
        TOTAL_INTENTS_VERSION,
        None,
        &[(1, "total:native", 6, Some(digest))],
    );
    let window = fixture.window.clone();
    let profile = fixture.profile.clone();
    let written = repinned.clone();
    BEFORE_USAGE_READ.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move || {
            let lock =
                WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id)
                    .unwrap();
            pin::write_for_test(&lock, &PinScope::for_profile(&window, &profile), &written)
                .unwrap();
        }));
    });
    let result = fixture.run();
    let ran = BEFORE_USAGE_READ.with_borrow(Option::is_none);
    BEFORE_USAGE_READ.with_borrow_mut(|hook| *hook = None);
    assert!(ran, "the repin ran between the inspection and the usage read");
    assert_eq!(fixture.pin(), PinState::Present(repinned));
    assert_eq!(exit_code(&result), 0);
    let output = result.unwrap();
    assert_eq!(output["valid"], true, "{output}");
    assert_eq!(check_of(&output, "verified_policy").0, "passed");
    assert!(output["total_budget_usage"].is_null(), "{output}");
    assert_eq!(
        usage_check(&output),
        (
            "not_evaluated".to_owned(),
            Some("policy.total_epoch_stale".to_owned())
        )
    );
}

/// The inspection reads the pin of the verified body; a repin to another
/// digest before the usage read reports `null`, because the locked pin no
/// longer names the body.
#[test]
#[serial]
fn a_repin_away_from_the_body_during_the_check_reports_no_usage() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (fixture, digest) = pinned_total_fixture();
    let owner = fixture.owner.verifying_key().to_bytes();
    assert_repin_race(&fixture, digest, Pin::new(3, [3; 32], owner).unwrap());
}

/// The inspection reads another pin; a repin to the body's own digest before
/// the usage read still reports `null`, because the inspected and the locked
/// pins differ and the two snapshots are never joined.
#[test]
#[serial]
fn a_repin_to_the_body_during_the_check_reports_no_usage() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (fixture, digest) = pinned_total_fixture();
    fixture.put_pin(1);
    let owner = fixture.owner.verifying_key().to_bytes();
    assert_repin_race(&fixture, digest, Pin::new(2, digest, owner).unwrap());
}
