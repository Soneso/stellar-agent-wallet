//! Signed policy, minimum restrictions, and installation binding regressions.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::{Signer as _, SigningKey};
use serial_test::serial;
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use stellar_agent_core::{
    mainnet::{
        enablement::{normalize_endpoint_host, verify_enablement},
        verified_policy::VerifiedPolicy,
    },
    policy::{
        PolicyError,
        pin::{self, Pin, PinScope, PinState},
        state_lock::{StateLockError, WindowStoreLock},
        v1::{
            PolicyStateStore,
            canonical::canonical_bytes,
            mainnet_minimum::{self, RequirementStatus},
            verified::{
                OwnerKeySource, PinMode, PolicyLoad, acquire_state_lock, inspect_verified_policy,
                load_verified_policy, with_pin_without_creating,
            },
        },
    },
    profile::{
        loader,
        name::ProfileNameSource,
        schema::{Profile, policy_pin_entry_ref},
    },
};
use stellar_agent_test_support::keyring_mock::{self, ReadHook};
use toml_edit::{DocumentMut, value};
const FULL: &str = include_str!("../fixtures/policy-v2.toml");
const V1: &str = "version = 1\nscope = \"profile:operator\"\n[[rules]]\n\
    match = {tool = \"stellar_balances\", chain = \"*\"}\ncriteria = []\ndecision = \"allow\"\n";

fn profile(mainnet: bool) -> Profile {
    if mainnet {
        Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .build()
    } else {
        Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
    }
}
fn signed(raw: &str, key: &SigningKey) -> String {
    let mut doc = raw.parse::<DocumentMut>().unwrap();
    doc.remove("signature");
    let canonical = canonical_bytes(&doc.to_string()).unwrap();
    let signature = key.sign(blake3::hash(&canonical).as_bytes());
    format!(
        "{doc}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
        stellar_agent_core::hex::encode(&signature.to_bytes())
    )
}
fn load(
    dir: &Path,
    raw: &str,
    profile: &Profile,
    key: &SigningKey,
    mode: PinMode,
) -> Result<VerifiedPolicy, PolicyError> {
    std::fs::write(dir.join("policy.toml"), signed(raw, key)).unwrap();
    load_file(dir, profile, key, OwnerKeySource::Keyring, mode)
}
/// Loads the policy file already in `dir` with the given owner-key source.
fn load_file(
    dir: &Path,
    profile: &Profile,
    key: &SigningKey,
    owner_source: OwnerKeySource,
    mode: PinMode,
) -> Result<VerifiedPolicy, PolicyError> {
    load_verified_policy(
        &PolicyLoad {
            path: &dir.join("policy.toml"),
            profile,
            profile_name: "operator",
            owner_pubkey: &key.verifying_key().to_bytes(),
            owner_source,
            window_path: &dir.join("state.window"),
        },
        PolicyStateStore::new(),
        mode,
    )
}
fn pinned(dir: &Path, profile: &Profile) -> PinState {
    let path = dir.join("state.window");
    let lock = WindowStoreLock::acquire_for(&path, &profile.policy_window_state_key_id).unwrap();
    pin::read(&lock, &PinScope::for_profile(&path, profile)).unwrap()
}
fn put_pin(dir: &Path, profile: &Profile, sequence: i64, digest: [u8; 32], owner: [u8; 32]) {
    let path = dir.join("state.window");
    let lock = WindowStoreLock::acquire_for(&path, &profile.policy_window_state_key_id).unwrap();
    pin::write(
        &lock,
        &PinScope::for_profile(&path, profile),
        &Pin::new(sequence, digest, owner).unwrap(),
    )
    .unwrap();
}
fn fixture() -> (tempfile::TempDir, Profile, SigningKey) {
    keyring_mock::install().unwrap();
    (
        tempfile::tempdir().unwrap(),
        profile(true),
        SigningKey::from_bytes(&[11; 32]),
    )
}
fn without_mainnet() -> String {
    let mut doc = FULL.parse::<DocumentMut>().unwrap();
    doc.remove("mainnet");
    doc.to_string()
}

#[test]
fn v2_canonical_full_literal() {
    const EXPECTED: &str = r#"version = 2
scope = "profile:operator"
sequence = 7

[mainnet]
profile = "operator"
endpoint_host = "rpc.example.invalid"
installation_nonce_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
classic_max_fee_per_op_stroops = 500
authorization_ttl_seconds = 60
approval_credentials = [{ credential_id_b64url = "WlpaWlpaWlpaWlpaWlpaWg", public_key_sec1_b64url = "BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE" }]

[mainnet.cross_check_thresholds]
"USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" = "100"
native = "10000000000"

[[rules]]
match = { chain = "stellar:mainnet", tool = "stellar_pay" }
criteria = [{ assets = ["native"], kind = "asset_allowlist" }, { allowlist = ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"], kind = "counterparty_allowlist", kinds = ["G_ACCOUNT"] }, { asset = "native", kind = "per_tx_cap", max_stroops = "100" }, { asset = "native", kind = "per_period_cap", max_stroops = "200", window = "1d" }, { kind = "rate_limit", max_calls = 10, window = "1d" }]
decision = "require_approval"
reason = "review"
ttl_secs = 3600
allow_opaque_signing = false
"#;
    assert_eq!(
        String::from_utf8(canonical_bytes(FULL).unwrap()).unwrap(),
        EXPECTED
    );
}

macro_rules! minimum {
    ($name:ident, $requirement:literal, $edit:expr) => {
        #[test]
        fn $name() {
            let profile = profile(true);
            let mut doc = FULL.parse::<DocumentMut>().unwrap();
            assert!(mainnet_minimum::failures(&doc, &profile, "operator").is_empty());
            ($edit)(&mut doc);
            let failures = mainnet_minimum::failures(&doc, &profile, "operator");
            assert!(
                failures.iter().any(|error| matches!(
                    error,
                    PolicyError::MainnetMinimumUnmet {
                        requirement: $requirement,
                        ..
                    }
                )),
                "{failures:?}"
            );
        }
    };
}
/// The mainnet minimum requires one to sixteen well-formed, distinct
/// approval credentials; an absent, empty, malformed or duplicated list is
/// unmet with its own detail.
#[test]
fn mainnet_minimum_requires_approval_credentials() {
    let profile = profile(true);
    let entry = |id: &str| {
        format!(
            "{{ credential_id_b64url = \"{id}\", public_key_sec1_b64url = \"BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE\" }}"
        )
    };
    let fixture = entry("WlpaWlpaWlpaWlpaWlpaWg");
    let seventeen = (0..17_u8)
        .map(|i| {
            entry(&format!(
                "WlpaWlpaWlpaWlpaWlpa{}",
                [
                    "AA", "AQ", "Ag", "Aw", "BA", "BQ", "Bg", "Bw", "CA", "CQ", "Cg", "Cw", "DA",
                    "DQ", "Dg", "Dw", "EA"
                ][usize::from(i)]
            ))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cases = [
        ("absent", None),
        ("empty", Some("[]".to_owned())),
        (
            "malformed id",
            Some(format!("[{}]", entry("WlpaWlpaWlpaWlpaWlpaWg=="))),
        ),
        ("duplicate", Some(format!("[{fixture}, {fixture}]"))),
        ("seventeen", Some(format!("[{seventeen}]"))),
    ];
    for (label, array) in cases {
        let mut doc = FULL.parse::<DocumentMut>().unwrap();
        let mainnet = doc["mainnet"].as_table_like_mut().unwrap();
        mainnet.remove("approval_credentials");
        if let Some(array) = array {
            let parsed = format!("v = {array}").parse::<DocumentMut>().unwrap();
            mainnet.insert("approval_credentials", parsed["v"].clone());
        }
        let failures = mainnet_minimum::failures(&doc, &profile, "operator");
        assert!(
            failures.iter().any(|error| matches!(
                error,
                PolicyError::MainnetMinimumUnmet {
                    requirement: "approval_credentials",
                    rule: None,
                }
            )),
            "{label}: {failures:?}"
        );
        let outcome = mainnet_minimum::evaluate(&doc, &profile, "operator")
            .into_iter()
            .find(|outcome| outcome.requirement == "approval_credentials")
            .unwrap();
        assert!(
            matches!(outcome.status, RequirementStatus::Failed { .. }),
            "{label}: {outcome:?}"
        );
    }
    let doc = FULL.parse::<DocumentMut>().unwrap();
    assert!(mainnet_minimum::failures(&doc, &profile, "operator").is_empty());
}

fn rule(doc: &mut DocumentMut) -> &mut toml_edit::Table {
    doc["rules"]
        .as_array_of_tables_mut()
        .unwrap()
        .get_mut(0)
        .unwrap()
}
minimum!(
    minimum_body_version,
    "body_version",
    |d: &mut DocumentMut| {
        d["version"] = value(1);
    }
);
minimum!(minimum_sequence, "body_version", |d: &mut DocumentMut| {
    d["sequence"] = value(0);
});
minimum!(
    minimum_mainnet_table,
    "mainnet_table",
    |d: &mut DocumentMut| {
        d.remove("mainnet");
    }
);
minimum!(minimum_rules_empty, "rules_empty", |d: &mut DocumentMut| {
    d.remove("rules");
});
minimum!(minimum_scope, "scope", |d: &mut DocumentMut| {
    d["scope"] = value("profile:*");
});
minimum!(minimum_chain, "chain", |d: &mut DocumentMut| {
    rule(d)["match"]["chain"] = value("*");
});
minimum!(minimum_tool, "tool", |d: &mut DocumentMut| {
    rule(d)["match"]["tool"] = value("*");
});
minimum!(minimum_opaque, "opaque", |d: &mut DocumentMut| {
    rule(d)["allow_opaque_signing"] = value(true);
});
minimum!(minimum_ttl_absent, "rule_ttl", |d: &mut DocumentMut| {
    rule(d).remove("ttl_secs");
});
minimum!(minimum_ttl_above_hour, "rule_ttl", |d: &mut DocumentMut| {
    rule(d)["ttl_secs"] = value(3601);
});
minimum!(
    minimum_asset_allowlist,
    "asset_allowlist",
    |d: &mut DocumentMut| {
        rule(d)["criteria"].as_array_mut().unwrap().remove(0);
    }
);
minimum!(minimum_destination, "destination", |d: &mut DocumentMut| {
    rule(d)["criteria"].as_array_mut().unwrap().remove(1);
});
minimum!(
    minimum_known_issuer_only,
    "destination",
    |d: &mut DocumentMut| {
        criterion(d, 1).insert(
            "kinds",
            toml_edit::Value::Array(["KNOWN_ISSUER"].into_iter().collect()),
        );
    }
);
minimum!(minimum_per_tx_cap, "per_tx_cap", |d: &mut DocumentMut| {
    rule(d)["criteria"].as_array_mut().unwrap().remove(2);
});
minimum!(
    minimum_per_period_cap,
    "per_period_cap",
    |d: &mut DocumentMut| {
        rule(d)["criteria"].as_array_mut().unwrap().remove(3);
    }
);
minimum!(minimum_rate_limit, "rate_limit", |d: &mut DocumentMut| {
    rule(d)["criteria"].as_array_mut().unwrap().remove(4);
});
minimum!(minimum_fee_cap, "fee_cap", |d: &mut DocumentMut| {
    d["mainnet"]
        .as_table_like_mut()
        .unwrap()
        .remove("classic_max_fee_per_op_stroops");
});
minimum!(minimum_native_floor, "thresholds", |d: &mut DocumentMut| {
    d["mainnet"]["cross_check_thresholds"]["native"] = value("9999999999");
});
minimum!(
    minimum_positive_threshold,
    "thresholds",
    |d: &mut DocumentMut| {
        d["mainnet"]["cross_check_thresholds"]["native"] = value("0");
    }
);
minimum!(minimum_authorization_ttl, "ttl", |d: &mut DocumentMut| {
    d["mainnet"]["authorization_ttl_seconds"] = value(121);
});
minimum!(
    minimum_claim_has_no_assets,
    "asset_allowlist",
    |d: &mut DocumentMut| {
        rule(d)["match"]["tool"] = value("stellar_claim");
    }
);

minimum!(
    minimum_duplicate_asset_allowlist,
    "asset_allowlist",
    |d: &mut DocumentMut| {
        let extra = rule(d)["criteria"]
            .as_array()
            .unwrap()
            .get(0)
            .unwrap()
            .clone();
        rule(d)["criteria"].as_array_mut().unwrap().push(extra);
    }
);
minimum!(
    minimum_unpinned_asset,
    "asset_allowlist",
    |d: &mut DocumentMut| {
        criterion(d, 0).insert(
            "assets",
            toml_edit::Value::Array(["USD"].into_iter().collect()),
        );
    }
);
minimum!(
    minimum_authorization_ttl_zero,
    "ttl",
    |d: &mut DocumentMut| {
        d["mainnet"]["authorization_ttl_seconds"] = value(0);
    }
);
minimum!(
    minimum_threshold_key,
    "thresholds",
    |d: &mut DocumentMut| {
        d["mainnet"]["cross_check_thresholds"]["USD"] = value("1");
    }
);
#[test]
fn minimum_deny_rules_need_no_value_restrictions() {
    let profile = profile(true);
    for tool in ["stellar_pay", "stellar_trustline"] {
        let mut doc = FULL.parse::<DocumentMut>().unwrap();
        rule(&mut doc)["match"]["tool"] = value(tool);
        rule(&mut doc)["decision"] = value("deny");
        rule(&mut doc).remove("reason");
        rule(&mut doc).remove("ttl_secs");
        rule(&mut doc)["criteria"] = value(toml_edit::Array::new());
        stellar_agent_core::policy::v1::validate_unsigned_policy(
            &doc.to_string(),
            "operator",
            &profile.network_passphrase,
        )
        .unwrap();
        mainnet_minimum::validate(&doc, &profile, "operator").unwrap();
    }
}

#[test]
fn minimum_authorization_ttl_endpoints_pass() {
    let profile = profile(true);
    for ttl in [1, 120] {
        let mut doc = FULL.parse::<DocumentMut>().unwrap();
        doc["mainnet"]["authorization_ttl_seconds"] = value(ttl);
        mainnet_minimum::validate(&doc, &profile, "operator").unwrap();
    }
}

#[test]
fn minimum_read_only_and_trustline_requirements() {
    let profile = profile(true);
    for tool in mainnet_minimum::MAINNET_READ_ONLY_TOOLS {
        let mut doc = FULL.parse::<DocumentMut>().unwrap();
        rule(&mut doc)["match"]["tool"] = value(*tool);
        rule(&mut doc)["criteria"] = value(toml_edit::Array::new());
        assert!(mainnet_minimum::validate(&doc, &profile, "operator").is_ok());
    }
    for tool in ["stellar_trustline", "stellar_claim"] {
        let mut doc = FULL.parse::<DocumentMut>().unwrap();
        rule(&mut doc)["match"]["tool"] = value(tool);
        let criteria = rule(&mut doc)["criteria"].as_array_mut().unwrap();
        while criteria.len() > usize::from(tool == "stellar_trustline") {
            criteria.remove(criteria.len() - 1);
        }
        assert!(mainnet_minimum::validate(&doc, &profile, "operator").is_ok());
    }
}

#[test]
fn minimum_cap_coverage_uses_network_identity() {
    let profile = profile(true);
    let classic = "USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let sac = stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(classic)
        .unwrap()
        .sac_contract_id(&profile.network_passphrase)
        .unwrap();
    let mut doc = FULL
        .replace(
            "assets = [\"native\"]",
            &format!("assets = [\"{classic}\"]"),
        )
        .replace("asset = \"native\"", &format!("asset = \"{sac}\""))
        .parse::<DocumentMut>()
        .unwrap();
    assert!(mainnet_minimum::validate(&doc, &profile, "operator").is_ok());
    criterion(&mut doc, 2).insert(
        "asset",
        stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(&format!(
            "USD:{}",
            stellar_strkey::ed25519::PublicKey([8; 32])
        ))
        .unwrap()
        .sac_contract_id(&profile.network_passphrase)
        .unwrap()
        .into(),
    );
    assert!(
        mainnet_minimum::failures(&doc, &profile, "operator")
            .iter()
            .any(|e| matches!(
                e,
                PolicyError::MainnetMinimumUnmet {
                    requirement: "per_tx_cap",
                    rule: Some(0)
                }
            ))
    );
}

#[test]
#[serial]
fn absent_v2_advances_and_equal_does_not_write() {
    let (dir, profile, key) = fixture();
    let first = load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    assert_eq!(first.sequence(), 7);
    let before = pinned(dir.path(), &profile);
    let coordinate = policy_pin_entry_ref(&profile.policy_window_state_key_id);
    let raw = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .get_password()
        .unwrap();
    keyring_mock::install_with_write_error(
        &coordinate.service,
        &coordinate.account,
        Some(&raw),
        keyring_core::Error::NoEntry,
    )
    .unwrap();
    let second = load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(pinned(dir.path(), &profile), before);
}
#[test]
#[serial]
fn honest_advance_accepts_and_rollback_refuses() {
    let (dir, profile, key) = fixture();
    load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    let newer = FULL.replace("sequence = 7", "sequence = 8");
    assert_eq!(
        load(dir.path(), &newer, &profile, &key, PinMode::Advance)
            .unwrap()
            .sequence(),
        8
    );
    assert!(matches!(
        load(dir.path(), FULL, &profile, &key, PinMode::Advance),
        Err(PolicyError::SequenceRollback)
    ));
    assert!(matches!(pinned(dir.path(), &profile), PinState::Present(pin) if pin.sequence() == 8));
}
#[test]
#[serial]
fn equal_sequence_digest_fork_refuses() {
    let (dir, profile, key) = fixture();
    load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    assert!(matches!(
        load(
            dir.path(),
            &FULL.replace("review", "changed"),
            &profile,
            &key,
            PinMode::Advance
        ),
        Err(PolicyError::SequenceFork)
    ));
}
#[test]
#[serial]
fn equal_sequence_owner_fork_refuses() {
    let (dir, profile, key) = fixture();
    let canonical = canonical_bytes(FULL).unwrap();
    put_pin(
        dir.path(),
        &profile,
        7,
        *blake3::hash(&canonical).as_bytes(),
        [0; 32],
    );
    assert!(matches!(
        load(dir.path(), FULL, &profile, &key, PinMode::Advance),
        Err(PolicyError::SequenceFork)
    ));
}
#[test]
#[serial]
fn v1_absent_accepts_but_present_refuses_on_testnet() {
    let (dir, _, key) = fixture();
    let profile = profile(false);
    assert_eq!(
        load(dir.path(), V1, &profile, &key, PinMode::Advance)
            .unwrap()
            .sequence(),
        0
    );
    assert_eq!(pinned(dir.path(), &profile), PinState::Absent);
    put_pin(
        dir.path(),
        &profile,
        7,
        [0; 32],
        key.verifying_key().to_bytes(),
    );
    assert!(matches!(
        load(dir.path(), V1, &profile, &key, PinMode::Advance),
        Err(PolicyError::SequenceRollback)
    ));
}
#[test]
#[serial]
fn invalid_body_never_advances() {
    let (dir, profile, key) = fixture();
    load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    let before = pinned(dir.path(), &profile);
    let invalid = FULL
        .replace("sequence = 7", "sequence = 8")
        .replace("max_calls = 10", "max_calls = -1");
    assert!(load(dir.path(), &invalid, &profile, &key, PinMode::Advance).is_err());
    assert_eq!(pinned(dir.path(), &profile), before);
}
#[test]
#[serial]
fn compare_only_never_writes_absent_or_advancing() {
    let (dir, profile, key) = fixture();
    load(dir.path(), FULL, &profile, &key, PinMode::CompareOnly).unwrap();
    assert_eq!(pinned(dir.path(), &profile), PinState::Absent);
    put_pin(
        dir.path(),
        &profile,
        1,
        [0; 32],
        key.verifying_key().to_bytes(),
    );
    let before = pinned(dir.path(), &profile);
    load(dir.path(), FULL, &profile, &key, PinMode::CompareOnly).unwrap();
    assert_eq!(pinned(dir.path(), &profile), before);
}
#[test]
#[serial]
fn failed_pin_write_returns_no_proof() {
    let (dir, profile, key) = fixture();
    let coordinate = policy_pin_entry_ref(&profile.policy_window_state_key_id);
    keyring_mock::install_with_write_error(
        &coordinate.service,
        &coordinate.account,
        None,
        keyring_core::Error::NoEntry,
    )
    .unwrap();
    let err = load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap_err();
    assert!(
        matches!(
            &err,
            PolicyError::PinUnusable { detail }
                if detail.starts_with("the policy pin keyring entry could not be used: ")
        ),
        "{err:?}"
    );
    assert_eq!(err.wire_code(), "policy.pin_unusable");
    assert_eq!(pinned(dir.path(), &profile), PinState::Absent);
}
#[test]
#[serial]
fn held_lock_refuses_with_busy_and_no_proof() {
    let (dir, profile, key) = fixture();
    let _lock = WindowStoreLock::acquire_for(
        &dir.path().join("state.window"),
        &profile.policy_window_state_key_id,
    )
    .unwrap();
    let start = std::time::Instant::now();
    assert!(matches!(
        load(dir.path(), FULL, &profile, &key, PinMode::Advance),
        Err(PolicyError::StateLockBusy)
    ));
    assert!(start.elapsed() >= std::time::Duration::from_millis(100));
}
#[test]
#[serial]
fn pin_read_is_guarded_against_interleaving() {
    let (dir, profile, key) = fixture();
    let coordinate = policy_pin_entry_ref(&profile.policy_window_state_key_id);
    let path = dir.path().join("state.window");
    let hook_profile = profile.clone();
    let wrote = Arc::new(AtomicBool::new(false));
    let observed = wrote.clone();
    keyring_mock::install_with_read_hooks(vec![ReadHook::new(
        &coordinate.service,
        &coordinate.account,
        Arc::new(move || {
            if let Ok(lock) =
                WindowStoreLock::acquire_for(&path, &hook_profile.policy_window_state_key_id)
            {
                pin::write(
                    &lock,
                    &PinScope::for_profile(&path, &hook_profile),
                    &Pin::new(9, [9; 32], [9; 32]).unwrap(),
                )
                .unwrap();
                observed.store(true, Ordering::SeqCst);
            }
        }),
    )])
    .unwrap();
    put_pin(
        dir.path(),
        &profile,
        6,
        [6; 32],
        key.verifying_key().to_bytes(),
    );
    let result = load(dir.path(), FULL, &profile, &key, PinMode::Advance);
    if wrote.load(Ordering::SeqCst) {
        assert!(matches!(result, Err(PolicyError::SequenceRollback)));
        assert!(
            matches!(pinned(dir.path(), &profile), PinState::Present(pin) if pin.sequence() == 9)
        );
    } else {
        assert_eq!(result.unwrap().sequence(), 7);
    }
    assert!(
        !wrote.load(Ordering::SeqCst),
        "pin reads must hold the state lock"
    );
}
#[test]
#[serial]
fn compare_runs_under_the_lock_the_pin_was_read_with() {
    let (dir, profile, key) = fixture();
    let path = dir.path().join("state.window");
    let window_key = &profile.policy_window_state_key_id;
    put_pin(
        dir.path(),
        &profile,
        6,
        [6; 32],
        key.verifying_key().to_bytes(),
    );
    let (state, writer) = with_pin_without_creating(&path, &profile, |state| {
        (
            state,
            WindowStoreLock::acquire_for(&path, window_key).map(drop),
        )
    })
    .unwrap();
    assert!(matches!(state, PinState::Present(ref pin) if pin.sequence() == 6));
    assert_eq!(writer, Err(StateLockError::WriterLocked));
    assert!(WindowStoreLock::acquire_for(&path, window_key).is_ok());

    let fresh = dir.path().join("absent").join("state.window");
    let state = with_pin_without_creating(&fresh, &profile, |state| state).unwrap();
    assert_eq!(state, PinState::Absent);
    assert!(!dir.path().join("absent").exists());
}
#[test]
#[serial]
fn compare_only_loads_hold_the_lock_against_a_writer() {
    let (dir, profile, key) = fixture();
    let coordinate = policy_pin_entry_ref(&profile.policy_window_state_key_id);
    let path = dir.path().join("state.window");
    let owner = key.verifying_key().to_bytes();
    std::fs::write(dir.path().join("policy.toml"), signed(FULL, &key)).unwrap();
    let hook_profile = profile.clone();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let recorded = attempts.clone();
    keyring_mock::install_with_read_hooks(vec![ReadHook::new(
        &coordinate.service,
        &coordinate.account,
        Arc::new(move || {
            let attempt = acquire_state_lock(&path, &hook_profile).and_then(|lock| {
                pin::write(
                    &lock,
                    &PinScope::for_profile(&path, &hook_profile),
                    &Pin::new(9, [9; 32], [9; 32]).unwrap(),
                )
                .map_err(PolicyError::from)
            });
            recorded
                .lock()
                .unwrap()
                .push(attempt.map_err(|e| e.wire_code()));
        }),
    )])
    .unwrap();
    put_pin(dir.path(), &profile, 6, [6; 32], owner);

    let loaded = load_file(
        dir.path(),
        &profile,
        &key,
        OwnerKeySource::Keyring,
        PinMode::CompareOnly,
    );
    assert_eq!(loaded.unwrap().sequence(), 7);
    let inspection = inspect_verified_policy(
        &PolicyLoad {
            path: &dir.path().join("policy.toml"),
            profile: &profile,
            profile_name: "operator",
            owner_pubkey: &owner,
            owner_source: OwnerKeySource::Keyring,
            window_path: &dir.path().join("state.window"),
        },
        PolicyStateStore::new(),
    );
    assert!(matches!(inspection.pin, Some(PinState::Present(ref pin)) if pin.sequence() == 6));
    assert_eq!(inspection.verified.unwrap().sequence(), 7);
    assert_eq!(
        *attempts.lock().unwrap(),
        vec![Err("policy.state_lock_busy"), Err("policy.state_lock_busy")]
    );
    assert!(matches!(pinned(dir.path(), &profile), PinState::Present(pin) if pin.sequence() == 6));
}
#[test]
#[serial]
fn testnet_refuses_mainnet_table() {
    let (dir, _, key) = fixture();
    assert!(matches!(
        load(
            dir.path(),
            FULL,
            &profile(false),
            &key,
            PinMode::CompareOnly
        ),
        Err(PolicyError::MainnetTableOnTestnet)
    ));
}

#[test]
#[serial]
fn unknown_v2_keys_precede_signature_verification() {
    let (dir, profile, key) = fixture();
    for place in [
        "root",
        "mainnet",
        "thresholds",
        "rule",
        "match",
        "criterion",
        "signature",
    ] {
        for valid in [true, false] {
            let mut doc = signed(FULL, &key).parse::<DocumentMut>().unwrap();
            match place {
                "root" => {
                    doc["unknown"] = value(1);
                }
                "mainnet" => {
                    doc["mainnet"]["unknown"] = value(1);
                }
                "thresholds" => {
                    doc["mainnet"]["cross_check_thresholds"]["unknown"] = value("1");
                }
                "rule" => {
                    rule(&mut doc)["unknown"] = value(1);
                }
                "match" => {
                    rule(&mut doc)["match"]["unknown"] = value(1);
                }
                "criterion" => {
                    rule(&mut doc)["criteria"]
                        .as_array_mut()
                        .unwrap()
                        .get_mut(0)
                        .unwrap()
                        .as_inline_table_mut()
                        .unwrap()
                        .insert("unknown", 1.into());
                }
                _ => {
                    doc["signature"]["unknown"] = value(1);
                }
            }
            let canon = canonical_bytes(&doc.to_string()).unwrap();
            doc["signature"]["sig"] = value(stellar_agent_core::hex::encode(
                &key.sign(blake3::hash(&canon).as_bytes()).to_bytes(),
            ));
            if !valid {
                doc["signature"]["sig"] = value("00");
            }
            std::fs::write(dir.path().join("policy.toml"), doc.to_string()).unwrap();
            let result = load_file(
                dir.path(),
                &profile,
                &key,
                OwnerKeySource::Keyring,
                PinMode::Advance,
            );
            assert!(
                matches!(
                    &result,
                    Err(PolicyError::PolicyFileParseFailed { detail })
                        if detail.contains("unknown key `unknown`")
                ),
                "{place}: {result:?}"
            );
        }
    }
}
#[test]
#[serial]
fn mainnet_configuration_condition() {
    let (dir, profile, key) = fixture();
    assert!(load(dir.path(), V1, &profile, &key, PinMode::CompareOnly).is_ok());
    assert!(
        load(
            dir.path(),
            &without_mainnet(),
            &profile,
            &key,
            PinMode::CompareOnly
        )
        .is_ok()
    );
    let invalid = FULL.replace("ttl_secs = 3600", "ttl_secs = 3601");
    assert_eq!(
        load(dir.path(), &invalid, &profile, &key, PinMode::CompareOnly).is_err(),
        cfg!(feature = "mainnet-write")
    );
}
fn criterion(doc: &mut DocumentMut, index: usize) -> &mut toml_edit::InlineTable {
    rule(doc)["criteria"]
        .as_array_mut()
        .unwrap()
        .get_mut(index)
        .unwrap()
        .as_inline_table_mut()
        .unwrap()
}

#[test]
fn asset_equivalence_covers_classic_native_and_networks() {
    use stellar_agent_core::{
        asset_id::CanonicalAsset, policy::v1::asset_equivalence::assets_equivalent,
    };
    let mainnet = profile(true);
    let testnet = profile(false);
    let classic = "USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let asset = CanonicalAsset::parse_threshold_key(classic).unwrap();
    let sac = asset.sac_contract_id(&mainnet.network_passphrase).unwrap();
    assert!(assets_equivalent(
        classic,
        &sac,
        &mainnet.network_passphrase
    ));
    assert!(assets_equivalent(
        &sac,
        classic,
        &mainnet.network_passphrase
    ));
    assert!(!assets_equivalent(
        classic,
        &sac,
        &testnet.network_passphrase
    ));
    assert!(!assets_equivalent(
        &sac,
        &stellar_strkey::Contract([8; 32]).to_string(),
        &mainnet.network_passphrase
    ));
    assert!(assets_equivalent(
        "native",
        "XLM",
        &mainnet.network_passphrase
    ));
    assert!(assets_equivalent(
        "native",
        &CanonicalAsset::Native
            .sac_contract_id(&mainnet.network_passphrase)
            .unwrap(),
        &mainnet.network_passphrase
    ));
}

fn tool() -> stellar_agent_core::policy::ToolDescriptor {
    use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
    ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_pay",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    })
}
fn ctx<'a>(
    tool: &'a stellar_agent_core::policy::ToolDescriptor,
    profile: &'a Profile,
    args: &'a serde_json::Value,
    state: &'a PolicyStateStore,
) -> stellar_agent_core::policy::v1::EvalContext<'a> {
    stellar_agent_core::policy::v1::EvalContext::new(tool, args, "operator", profile, state)
        .with_value(stellar_agent_core::policy::v1::value::derive_value_class(
            "stellar_pay",
            args,
        ))
}
fn classic_and_sac(profile: &Profile) -> (String, String) {
    let classic = "USD:GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned();
    let sac = stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(&classic)
        .unwrap()
        .sac_contract_id(&profile.network_passphrase)
        .unwrap();
    (classic, sac)
}
#[test]
fn asset_allowlist_testnet_equivalence_and_deny_code() {
    use stellar_agent_core::policy::{
        DenyReason,
        v1::criteria::{Criterion, asset_allowlist::AssetAllowlistCriterion},
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let (classic, sac) = classic_and_sac(&profile);
    let allowlist = AssetAllowlistCriterion::new(vec![classic]).unwrap();
    let allowed = serde_json::json!({"asset": sac, "amount_stroops": "60"});
    assert!(
        allowlist
            .evaluate(&ctx(&tool, &profile, &allowed, &state))
            .unwrap()
            .is_none()
    );
    let denied = serde_json::json!({"asset": "native", "amount_stroops": "60"});
    let denial = allowlist
        .evaluate(&ctx(&tool, &profile, &denied, &state))
        .unwrap()
        .unwrap();
    assert_eq!(denial, DenyReason::AssetNotAllowlisted);
    assert_eq!(denial.wire_code(), "policy.deny.asset_not_allowlisted");
}
#[test]
fn per_transaction_cap_counts_equivalent_sac() {
    use stellar_agent_core::policy::{
        DenyReason,
        v1::criteria::{Criterion, per_tx_cap::PerTxCapCriterion},
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let (classic, sac) = classic_and_sac(&profile);
    let cap = PerTxCapCriterion::new(classic, 100);
    let args = serde_json::json!({"asset": sac, "amount_stroops": "101"});
    assert!(matches!(
        cap.evaluate(&ctx(&tool, &profile, &args, &state)).unwrap(),
        Some(DenyReason::PerTxCapExceeded {
            attempted_stroops: 101,
            ..
        })
    ));
}
#[test]
fn period_accounting_sums_classic_and_sac() {
    use stellar_agent_core::policy::{
        DenyReason,
        v1::criteria::{
            Criterion,
            per_period_cap::{PerPeriodCapCriterion, Window},
        },
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let (classic, sac) = classic_and_sac(&profile);
    let cap = PerPeriodCapCriterion::new(classic.clone(), Window::parse("1d").unwrap(), 100);
    for asset in [&classic, &sac] {
        let args = serde_json::json!({"asset": asset, "amount_stroops": "40"});
        let context = ctx(&tool, &profile, &args, &state);
        assert!(cap.evaluate(&context).unwrap().is_none());
        assert_eq!(cap.record_confirmed(&context).unwrap().len(), 1);
    }
    let args = serde_json::json!({"asset": sac, "amount_stroops": "21"});
    assert!(matches!(
        cap.evaluate(&ctx(&tool, &profile, &args, &state)).unwrap(),
        Some(DenyReason::PerPeriodCapExceeded {
            period_used_stroops: 80,
            ..
        })
    ));
}
#[test]
fn bundle_period_overlay_counts_two_sac_inners() {
    use stellar_agent_core::policy::{
        DenyReason,
        v1::{
            bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor},
            criteria::{
                Criterion,
                per_period_cap::{PerPeriodCapCriterion, Window},
            },
        },
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let (classic, sac) = classic_and_sac(&profile);
    let cap = PerPeriodCapCriterion::new(classic, Window::parse("1d").unwrap(), 100);
    let args = serde_json::json!({"asset": sac, "amount_stroops": "60"});
    let inner = InnerOpDescriptor::TokenTransfer {
        asset: sac,
        from: "sender".into(),
        to: "recipient".into(),
        amount: 60,
    };
    let inners = [inner.clone(), inner.clone()];
    let mut overlay = BundleStateOverlay::default();
    assert!(
        cap.evaluate(&ctx(&tool, &profile, &args, &state))
            .unwrap()
            .is_none()
    );
    cap.accumulate_overlay(&ctx(&tool, &profile, &args, &state), &inner, &mut overlay);
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };
    assert!(matches!(
        cap.evaluate(&ctx(&tool, &profile, &args, &state).with_bundle(&view))
            .unwrap(),
        Some(DenyReason::PerPeriodCapExceeded { .. })
    ));
}
#[test]
fn bundle_caps_and_accounting_use_classic_sac_identity() {
    use stellar_agent_core::policy::v1::{
        bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor},
        criteria::{
            Criterion, bundle_aggregate_cap::BundleAggregateCapCriterion,
            bundle_per_period_cap::BundlePerPeriodCapCriterion,
            bundle_per_tx_cap::BundlePerTxCapCriterion, per_period_cap::Window,
        },
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let (classic, sac) = classic_and_sac(&profile);
    let inners = [InnerOpDescriptor::TokenTransfer {
        asset: sac,
        from: "sender".into(),
        to: "recipient".into(),
        amount: 60,
    }];
    let overlay = BundleStateOverlay::default();
    let view = BundleView {
        inners: &inners,
        overlay: &overlay,
    };
    let args = serde_json::Value::Null;
    let context = ctx(&tool, &profile, &args, &state).with_bundle(&view);
    assert!(
        BundlePerTxCapCriterion::new(classic.clone(), 50)
            .evaluate(&context)
            .unwrap()
            .is_some()
    );
    assert!(
        (BundleAggregateCapCriterion {
            asset: Some(classic.clone()),
            max_amount: 50
        })
        .evaluate(&context)
        .unwrap()
        .is_some()
    );
    let period = BundlePerPeriodCapCriterion::new(classic, Window::parse("1d").unwrap(), 100);
    assert!(period.evaluate(&context).unwrap().is_none());
    assert_eq!(period.record_confirmed(&context).unwrap().len(), 1);
    assert!(period.evaluate(&context).unwrap().is_some());
}

fn enabled_fixture() -> (tempfile::TempDir, Profile, VerifiedPolicy) {
    use sha2::Digest as _;
    let (dir, profile, key) = fixture();
    loader::save_to_dir("operator", &profile, dir.path()).unwrap();
    let digest = stellar_agent_core::hex::encode(&sha2::Sha256::digest(b"installation-nonce"));
    let body = FULL.replace(&"0".repeat(64), &digest);
    let verified = load(dir.path(), &body, &profile, &key, PinMode::CompareOnly).unwrap();
    (dir, profile, verified)
}
fn nonce(
    _: &stellar_agent_core::profile::schema::KeyringEntryRef,
) -> Result<String, stellar_agent_core::error::ValidationError> {
    Ok("installation-nonce".into())
}
#[test]
#[serial]
fn enablement_verifies_all_bindings() {
    let (dir, profile, verified) = enabled_fixture();
    let record = verify_enablement(
        &verified,
        "operator",
        ProfileNameSource::Flag,
        &profile,
        dir.path(),
        &nonce,
    )
    .unwrap();
    assert_eq!(record.policy_sequence(), 7);
    assert_eq!(record.profile(), "operator");
    assert_eq!(record.endpoint_host(), "rpc.example.invalid");
    assert_eq!(record.fee_cap(), 500);
    assert_eq!(record.authorization_ttl(), Some(60));
}
#[test]
#[serial]
fn enablement_name_source_and_default_refuse() {
    let (dir, profile, verified) = enabled_fixture();
    for (name, source, binding) in [
        ("other", ProfileNameSource::Flag, "profile"),
        ("operator", ProfileNameSource::Env, "source"),
        ("operator", ProfileNameSource::Default, "source"),
    ] {
        let err =
            verify_enablement(&verified, name, source, &profile, dir.path(), &nonce).unwrap_err();
        assert_eq!(err.code(), "profile.mainnet_enablement_invalid");
        assert!(
            matches!(
                err,
                stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                    binding: found
                } if found == binding
            ),
            "{err:?}"
        );
    }
    let key = SigningKey::from_bytes(&[11; 32]);
    let raw = FULL.replace("operator", "default");
    let path = dir.path().join("policy.toml");
    std::fs::write(&path, signed(&raw, &key)).unwrap();
    let verified = load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile: &profile,
            profile_name: "default",
            owner_pubkey: &key.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: &dir.path().join("state.window"),
        },
        PolicyStateStore::new(),
        PinMode::CompareOnly,
    )
    .unwrap();
    assert!(
        verify_enablement(
            &verified,
            "default",
            ProfileNameSource::Flag,
            &profile,
            dir.path(),
            &nonce
        )
        .unwrap_err()
        .to_string()
        .contains("default")
    );
}
#[test]
#[serial]
fn enablement_disk_and_merged_hosts_are_both_checked() {
    let (dir, mut profile, verified) = enabled_fixture();
    profile.rpc_url = "https://another.example.invalid".into();
    assert!(
        verify_enablement(
            &verified,
            "operator",
            ProfileNameSource::Flag,
            &profile,
            dir.path(),
            &nonce
        )
        .unwrap_err()
        .to_string()
        .contains("merged_host")
    );
    loader::save_to_dir("operator", &profile, dir.path()).unwrap();
    profile.rpc_url = "https://rpc.example.invalid".into();
    assert!(
        verify_enablement(
            &verified,
            "operator",
            ProfileNameSource::Flag,
            &profile,
            dir.path(),
            &nonce
        )
        .unwrap_err()
        .to_string()
        .contains("on_disk_host")
    );
}
#[test]
fn endpoint_host_normalization() {
    assert_eq!(
        normalize_endpoint_host("https://ignored:credential@RPC.Example.Invalid:443/path?q=yes")
            .unwrap(),
        "rpc.example.invalid"
    );
    assert_eq!(
        normalize_endpoint_host("https://RPC.Example.Invalid:8443/path").unwrap(),
        "rpc.example.invalid:8443"
    );
    assert!(normalize_endpoint_host("missing-host").is_err());
}
#[test]
#[serial]
fn enablement_nonce_digest_and_absence_refuse() {
    let (dir, profile, verified) = enabled_fixture();
    let digest = verify_enablement(
        &verified,
        "operator",
        ProfileNameSource::Flag,
        &profile,
        dir.path(),
        &|_| Ok("different".into()),
    )
    .unwrap_err();
    assert!(
        matches!(
            digest,
            stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                binding: "nonce_digest"
            }
        ),
        "{digest:?}"
    );
    let absent = verify_enablement(
        &verified,
        "operator",
        ProfileNameSource::Flag,
        &profile,
        dir.path(),
        &stellar_agent_core::mainnet::enablement::read_enablement_nonce,
    )
    .unwrap_err();
    assert!(
        matches!(
            absent,
            stellar_agent_core::error::ValidationError::MainnetEnablementInvalid {
                binding: "nonce"
            }
        ),
        "{absent:?}"
    );
}
#[test]
#[serial]
fn malformed_nonce_digest_refuses_at_load() {
    let (dir, profile, key) = fixture();
    for malformed in ["A".repeat(64), "0".repeat(63), "g".repeat(64)] {
        assert!(matches!(
            load(
                dir.path(),
                &FULL.replace(&"0".repeat(64), &malformed),
                &profile,
                &key,
                PinMode::Advance
            ),
            Err(PolicyError::PolicyFileParseFailed { .. })
        ));
        assert_eq!(pinned(dir.path(), &profile), PinState::Absent);
    }
}
#[test]
fn state_lock_retries_then_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let profile = profile(false);
    let path = dir.path().join("state.window");
    let held = WindowStoreLock::acquire_for(&path, &profile.policy_window_state_key_id).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            drop(held);
        });
        assert!(
            WindowStoreLock::acquire_for_with_retry(&path, &profile.policy_window_state_key_id)
                .is_ok()
        );
    });
}
#[test]
fn state_lock_io_preserves_error_kind() {
    let dir = tempfile::tempdir().unwrap();
    let profile = profile(false);
    let err = stellar_agent_core::policy::v1::verified::acquire_state_lock(
        &dir.path().join("absent/state.window"),
        &profile,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        PolicyError::StateLockIo {
            kind: std::io::ErrorKind::NotFound
        }
    ));
    assert_eq!(err.wire_code(), "policy.state_lock_io");
}
#[test]
fn signed_threshold_precedence_and_wide_values() {
    use std::collections::BTreeMap;
    use stellar_agent_core::{
        asset_id::CanonicalAsset,
        cross_check::{
            CrossCheckThresholds, CrossCheckValue, ThresholdSet, cross_check_requirement,
        },
        profile::schema::MINIMUM_FLOOR,
    };
    let mut profile = profile(true);
    let (classic, sac) = classic_and_sac(&profile);
    let asset = CanonicalAsset::parse_threshold_key(&classic).unwrap();
    let sac = CanonicalAsset::contract(&sac).unwrap();
    for (configured, signed, expected) in [
        (None, Some(25), Some(25)),
        (Some(25), None, Some(25)),
        (Some(50), Some(25), Some(25)),
        (Some(25), Some(50), Some(25)),
        (Some(25), Some(25), Some(25)),
        (None, None, None),
        (None, Some(i128::MAX), Some(i128::MAX)),
    ] {
        profile.cross_check_thresholds =
            CrossCheckThresholds::new(configured.map(|v| (asset.clone(), v)).into_iter().collect())
                .unwrap();
        let table: BTreeMap<_, _> = signed.map(|v| (classic.clone(), v)).into_iter().collect();
        let thresholds = ThresholdSet::from_profile_and_signed(&profile, Some(&table));
        assert_eq!(thresholds.threshold_for(&asset), expected);
        assert_eq!(thresholds.threshold_for(&sac), expected);
        if expected.is_none() {
            assert!(
                cross_check_requirement(
                    profile.chain_id,
                    CrossCheckValue::Amount {
                        asset: &asset,
                        base_units: 1
                    },
                    &thresholds,
                    true,
                    false
                )
                .is_err()
            );
        }
    }
    profile.cross_check_threshold_stroops = 0;
    assert_eq!(
        ThresholdSet::from_profile_and_signed(&profile, None)
            .threshold_for(&CanonicalAsset::Native),
        Some(i128::from(MINIMUM_FLOOR))
    );
}
#[test]
fn signed_threshold_warns_when_profile_is_higher() {
    use std::collections::BTreeMap;
    use stellar_agent_core::{
        asset_id::CanonicalAsset,
        cross_check::{CrossCheckThresholds, ThresholdSet},
    };
    let mut profile = profile(true);
    let (classic, _) = classic_and_sac(&profile);
    let asset = CanonicalAsset::parse_threshold_key(&classic).unwrap();
    profile.cross_check_thresholds =
        CrossCheckThresholds::new(BTreeMap::from([(asset.clone(), 50)])).unwrap();
    let table = BTreeMap::from([(classic, 25)]);
    let capture = stellar_agent_test_support::CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    assert_eq!(
        ThresholdSet::from_profile_and_signed(&profile, Some(&table)).threshold_for(&asset),
        Some(25)
    );
    let output = capture.captured_str();
    assert!(
        output.contains("WARN")
            && output.contains("profile cross-check threshold exceeds signed threshold"),
        "{output}"
    );
}
#[test]
fn threshold_aliases_and_duplicate_identities_refuse() {
    let profile = profile(true);
    let (classic, sac) = classic_and_sac(&profile);
    let refusal = |doc: &DocumentMut| {
        stellar_agent_core::policy::v1::verified::validate_profile_body(doc, &profile)
            .unwrap_err()
            .to_string()
    };
    let mut doc = FULL.parse::<DocumentMut>().unwrap();
    doc["mainnet"]["cross_check_thresholds"][&sac] = value("100");
    assert_eq!(
        refusal(&doc),
        format!(
            "policy file parse failed: mainnet.cross_check_thresholds: key `{sac}` names the \
             same asset as key `{classic}`"
        )
    );
    // Beside a `native` key the native contract also names the same asset, so
    // the native-contract refusal is checked without one.
    let thresholds = doc["mainnet"]["cross_check_thresholds"]
        .as_table_like_mut()
        .unwrap();
    for key in [sac.as_str(), classic.as_str(), "native"] {
        thresholds.remove(key);
    }
    let native_sac = stellar_agent_core::asset_id::CanonicalAsset::Native
        .sac_contract_id(&profile.network_passphrase)
        .unwrap();
    doc["mainnet"]["cross_check_thresholds"][&native_sac] = value("10000000000");
    assert_eq!(
        refusal(&doc),
        format!(
            "policy file parse failed: mainnet.cross_check_thresholds: key `{native_sac}` \
             names the native asset's contract; set the `native` key instead"
        )
    );
}
#[test]
fn verified_sequence_is_a_positive_toml_integer() {
    use stellar_agent_core::policy::v1::validate_unsigned_policy;
    use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
    for value in ["0", "-1", "\"1\"", "1.0"] {
        assert!(
            validate_unsigned_policy(
                &without_mainnet().replace("sequence = 7", &format!("sequence = {value}")),
                "operator",
                MAINNET_PASSPHRASE,
            )
            .is_err()
        );
    }
    assert!(
        validate_unsigned_policy(
            &without_mainnet().replace("sequence = 7", "sequence = 9223372036854775807"),
            "operator",
            MAINNET_PASSPHRASE,
        )
        .is_ok()
    );
}
#[test]
fn asset_allowlist_leaves_assetless_claims_unrestricted() {
    use stellar_agent_core::policy::v1::criteria::{
        Criterion, asset_allowlist::AssetAllowlistCriterion,
    };
    let profile = profile(false);
    let tool = tool();
    let state = PolicyStateStore::new();
    let args = serde_json::json!({});
    let context = ctx(&tool, &profile, &args, &state).with_value(
        stellar_agent_core::policy::v1::value::derive_value_class("stellar_claim", &args),
    );
    assert!(
        AssetAllowlistCriterion::new(vec!["native".into()])
            .unwrap()
            .evaluate(&context)
            .unwrap()
            .is_none()
    );
}
/// `FULL` with one more criterion on its first rule.
fn with_criterion(criterion: &str) -> String {
    let mut doc = FULL.parse::<DocumentMut>().unwrap();
    rule(&mut doc)["criteria"]
        .as_array_mut()
        .unwrap()
        .push(criterion.parse::<toml_edit::Value>().unwrap());
    doc.to_string()
}
fn pin_value(profile: &Profile) -> Option<String> {
    let coordinate = policy_pin_entry_ref(&profile.policy_window_state_key_id);
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .get_password()
        .ok()
}
/// Every path under `dir`, relative and sorted.
fn listing(dir: &Path) -> Vec<std::path::PathBuf> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.strip_prefix(root).unwrap().to_path_buf());
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
#[serial]
fn home_domain_criteria_are_valid_but_fail_the_minimum() {
    for criterion in [
        r#"{ kind = "home_domain_resolved" }"#,
        r#"{ kind = "counterparty_allowlist", kinds = ["HOME_DOMAIN"], allowlist = ["example.org"] }"#,
    ] {
        let (dir, profile, key) = fixture();
        let body = with_criterion(criterion);
        stellar_agent_core::policy::v1::validate_unsigned_policy(
            &body,
            "operator",
            &profile.network_passphrase,
        )
        .unwrap();
        let failures =
            mainnet_minimum::failures(&body.parse::<DocumentMut>().unwrap(), &profile, "operator");
        assert!(
            matches!(
                failures.as_slice(),
                [PolicyError::MainnetMinimumUnmet {
                    requirement: "home_domain",
                    rule: Some(0)
                }]
            ),
            "{criterion}: {failures:?}"
        );
        let result = load(dir.path(), &body, &profile, &key, PinMode::Advance);
        if cfg!(feature = "mainnet-write") {
            assert!(
                matches!(
                    result,
                    Err(PolicyError::MainnetMinimumUnmet {
                        requirement: "home_domain",
                        rule: Some(0)
                    })
                ),
                "{criterion}: {result:?}"
            );
        } else {
            assert_eq!(result.unwrap().sequence(), 7, "{criterion}");
        }
    }
}

#[test]
#[serial]
fn test_owner_source_refuses_an_enabled_mainnet_body_and_keeps_the_pin() {
    let (dir, profile, key) = fixture();
    std::fs::write(dir.path().join("policy.toml"), signed(FULL, &key)).unwrap();
    let refused = |dir: &Path| {
        load_file(
            dir,
            &profile,
            &key,
            OwnerKeySource::TestFile,
            PinMode::Advance,
        )
    };
    if cfg!(feature = "mainnet-write") {
        let err = refused(dir.path()).unwrap_err();
        assert!(matches!(err, PolicyError::TestOwnerKeyRefused), "{err:?}");
        assert_eq!(err.to_string(), "policy.engine_unavailable: test_owner_key");
        assert_eq!(err.wire_code(), "policy.engine_unavailable");
        assert_eq!(pin_value(&profile), None);
        put_pin(
            dir.path(),
            &profile,
            6,
            [6; 32],
            key.verifying_key().to_bytes(),
        );
        let before = pin_value(&profile);
        assert!(matches!(
            refused(dir.path()),
            Err(PolicyError::TestOwnerKeyRefused)
        ));
        assert_eq!(pin_value(&profile), before);
    } else {
        assert_eq!(refused(dir.path()).unwrap().sequence(), 7);
    }
    let accepted = load_file(
        dir.path(),
        &profile,
        &key,
        OwnerKeySource::Keyring,
        PinMode::Advance,
    )
    .unwrap();
    assert_eq!(accepted.sequence(), 7);
    assert!(matches!(pinned(dir.path(), &profile), PinState::Present(pin) if pin.sequence() == 7));
}

#[test]
#[serial]
fn test_owner_source_loads_outside_the_mainnet_condition() {
    let (dir, _, key) = fixture();
    let testnet = profile(false);
    std::fs::write(dir.path().join("policy.toml"), signed(V1, &key)).unwrap();
    assert_eq!(
        load_file(
            dir.path(),
            &testnet,
            &key,
            OwnerKeySource::TestFile,
            PinMode::Advance
        )
        .unwrap()
        .sequence(),
        0
    );
    let mainnet = profile(true);
    std::fs::write(
        dir.path().join("policy.toml"),
        signed(&without_mainnet(), &key),
    )
    .unwrap();
    assert_eq!(
        load_file(
            dir.path(),
            &mainnet,
            &key,
            OwnerKeySource::TestFile,
            PinMode::Advance
        )
        .unwrap()
        .sequence(),
        7
    );
}

#[test]
#[serial]
fn compare_only_creates_neither_the_window_directory_nor_the_lock_file() {
    let (dir, profile, key) = fixture();
    std::fs::write(dir.path().join("policy.toml"), signed(FULL, &key)).unwrap();
    let owner = key.verifying_key().to_bytes();
    for window in [
        dir.path().join("absent").join("state.window"),
        dir.path().join("state.window"),
    ] {
        let before = listing(dir.path());
        let load = PolicyLoad {
            path: &dir.path().join("policy.toml"),
            profile: &profile,
            profile_name: "operator",
            owner_pubkey: &owner,
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        };
        let inspection = inspect_verified_policy(&load, PolicyStateStore::new());
        assert_eq!(
            inspection.pin,
            Some(PinState::Absent),
            "{}",
            window.display()
        );
        assert_eq!(inspection.verified.unwrap().sequence(), 7);
        assert!(inspection.document.is_some());
        assert_eq!(
            load_verified_policy(&load, PolicyStateStore::new(), PinMode::CompareOnly)
                .unwrap()
                .sequence(),
            7
        );
        assert_eq!(listing(dir.path()), before, "{}", window.display());
    }
}

#[test]
#[serial]
fn inspection_reports_the_pin_it_compared_and_the_verified_document() {
    let (dir, profile, key) = fixture();
    std::fs::write(dir.path().join("policy.toml"), signed(FULL, &key)).unwrap();
    put_pin(
        dir.path(),
        &profile,
        9,
        [9; 32],
        key.verifying_key().to_bytes(),
    );
    let owner = key.verifying_key().to_bytes();
    let load = PolicyLoad {
        path: &dir.path().join("policy.toml"),
        profile: &profile,
        profile_name: "operator",
        owner_pubkey: &owner,
        owner_source: OwnerKeySource::Keyring,
        window_path: &dir.path().join("state.window"),
    };
    let inspection = inspect_verified_policy(&load, PolicyStateStore::new());
    assert!(matches!(inspection.pin, Some(PinState::Present(ref pin)) if pin.sequence() == 9));
    assert!(matches!(
        inspection.verified,
        Err(PolicyError::SequenceRollback)
    ));
    assert_eq!(
        inspection.document.unwrap()["sequence"].as_integer(),
        Some(7)
    );
    let other = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
    let unverified = inspect_verified_policy(
        &PolicyLoad {
            owner_pubkey: &other,
            ..load
        },
        PolicyStateStore::new(),
    );
    assert!(unverified.document.is_none());
    assert!(unverified.pin.is_none());
    assert!(matches!(
        unverified.verified,
        Err(PolicyError::OwnerSignatureInvalid { .. })
    ));
}

#[test]
fn minimum_report_lists_every_requirement_with_its_status() {
    let profile = profile(true);
    let evaluate = |doc: &DocumentMut| mainnet_minimum::evaluate(doc, &profile, "operator");
    let full = evaluate(&FULL.parse::<DocumentMut>().unwrap());
    assert_eq!(
        full.iter().map(|o| o.requirement).collect::<Vec<_>>(),
        mainnet_minimum::REQUIREMENTS
    );
    assert!(
        full.iter().all(|o| o.status == RequirementStatus::Passed),
        "{full:?}"
    );

    for outcome in evaluate(&without_mainnet().parse::<DocumentMut>().unwrap()) {
        let expected = if [
            "mainnet_table",
            "fee_cap",
            "thresholds",
            "ttl",
            "approval_credentials",
        ]
        .contains(&outcome.requirement)
        {
            RequirementStatus::Failed {
                rules: vec![],
                detail: "the [mainnet] table is missing".into(),
            }
        } else {
            RequirementStatus::Passed
        };
        assert_eq!(outcome.status, expected, "{}", outcome.requirement);
    }

    let value_requirements = [
        "asset_allowlist",
        "destination",
        "per_tx_cap",
        "per_period_cap",
        "rate_limit",
    ];
    let mut read_only = FULL.parse::<DocumentMut>().unwrap();
    rule(&mut read_only)["match"]["tool"] = value("stellar_balances");
    rule(&mut read_only)["criteria"] = value(toml_edit::Array::new());
    for outcome in evaluate(&read_only) {
        let expected = if value_requirements.contains(&outcome.requirement) {
            RequirementStatus::NotEvaluated {
                detail: "no rule this requirement applies to",
            }
        } else {
            RequirementStatus::Passed
        };
        assert_eq!(outcome.status, expected, "{}", outcome.requirement);
    }

    let mut ruleless = FULL.parse::<DocumentMut>().unwrap();
    ruleless.remove("rules");
    for outcome in evaluate(&ruleless) {
        let expected = match outcome.requirement {
            "rules_empty" => RequirementStatus::Failed {
                rules: vec![],
                detail: "the policy has no rules".into(),
            },
            "chain" | "tool" | "opaque" | "rule_ttl" | "home_domain" => {
                RequirementStatus::NotEvaluated {
                    detail: "the policy has no rules",
                }
            }
            requirement if value_requirements.contains(&requirement) => {
                RequirementStatus::NotEvaluated {
                    detail: "the policy has no rules",
                }
            }
            _ => RequirementStatus::Passed,
        };
        assert_eq!(outcome.status, expected, "{}", outcome.requirement);
    }

    let mut two_rules = FULL.parse::<DocumentMut>().unwrap();
    rule(&mut two_rules)["match"]["chain"] = value("*");
    let copy = two_rules["rules"]
        .as_array_of_tables()
        .unwrap()
        .get(0)
        .unwrap()
        .clone();
    two_rules["rules"]
        .as_array_of_tables_mut()
        .unwrap()
        .push(copy);
    let chain = evaluate(&two_rules)
        .into_iter()
        .find(|o| o.requirement == "chain")
        .unwrap();
    assert_eq!(
        chain.status,
        RequirementStatus::Failed {
            rules: vec![0, 1],
            detail: "rules 0, 1".into()
        }
    );
}

#[test]
#[serial]
fn higher_sequence_owner_rotation_is_accepted() {
    let (dir, profile, key) = fixture();
    load(dir.path(), FULL, &profile, &key, PinMode::Advance).unwrap();
    let rotated = SigningKey::from_bytes(&[12; 32]);
    let newer = FULL.replace("sequence = 7", "sequence = 8");
    let mut doc = newer.parse::<DocumentMut>().unwrap();
    doc["owner_rotation"] = toml_edit::Item::Table(
        stellar_agent_core::policy::v1::signature::build_owner_rotation(
            &newer,
            &key,
            &rotated.verifying_key().to_bytes(),
        )
        .unwrap(),
    );
    let verified = load(
        dir.path(),
        &doc.to_string(),
        &profile,
        &rotated,
        PinMode::Advance,
    )
    .unwrap();
    assert_eq!(verified.sequence(), 8);
    assert_eq!(verified.owner(), rotated.verifying_key().to_bytes());
    assert!(matches!(
        pinned(dir.path(), &profile),
        PinState::Present(pin)
            if pin.sequence() == 8 && pin.owner() == rotated.verifying_key().to_bytes()
    ));
}

#[test]
#[serial]
fn integer_threshold_is_accepted() {
    let (dir, profile, key) = fixture();
    let body = FULL.replace("native = \"10000000000\"", "native = 10000000000");
    assert_ne!(body, FULL, "the threshold edit must apply");
    let doc = body.parse::<DocumentMut>().unwrap();
    assert!(mainnet_minimum::failures(&doc, &profile, "operator").is_empty());
    stellar_agent_core::policy::v1::verified::validate_profile_body(&doc, &profile).unwrap();
    let verified = load(dir.path(), &body, &profile, &key, PinMode::Advance).unwrap();
    let thresholds = verified
        .mainnet()
        .unwrap()
        .cross_check_thresholds
        .clone()
        .unwrap();
    assert_eq!(thresholds.get("native"), Some(&10_000_000_000));
}

#[test]
fn period_cap_coverage_is_checked_independently_of_the_transaction_cap() {
    let profile = profile(true);
    let mut doc = FULL.parse::<DocumentMut>().unwrap();
    criterion(&mut doc, 3).insert(
        "asset",
        stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(&format!(
            "USD:{}",
            stellar_strkey::ed25519::PublicKey([8; 32])
        ))
        .unwrap()
        .sac_contract_id(&profile.network_passphrase)
        .unwrap()
        .into(),
    );
    let failures = mainnet_minimum::failures(&doc, &profile, "operator");
    assert!(
        matches!(
            failures.as_slice(),
            [PolicyError::MainnetMinimumUnmet {
                requirement: "per_period_cap",
                rule: Some(0)
            }]
        ),
        "{failures:?}"
    );
}
