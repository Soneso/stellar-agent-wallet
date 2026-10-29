//! A stored mainnet profile without a usable oracle refuses mainnet writes
//! with `profile.mainnet_oracle_required` through the release binary, before
//! any endpoint contact.
//!
//! Two setups reach the refusal. An enabled installation carries every file
//! and keyring entry the enablement ceremony leaves: the enrolled keys, the
//! signer pin, the signed version 2 policy bound to the installation nonce,
//! the policy pin, and the nonce. Its operator then removes the oracle URL and
//! its record from the profile file, and `pay` refuses. A fresh profile, with
//! no enablement, keyring entry, or policy, shows that every write verb takes
//! the refusal at its first step. With the oracle in place, each setup passes
//! that step and stops at the endpoint identity probe, which the loopback
//! counter accepts and cannot answer, so the refusal belongs to the oracle.
//!
//! `STELLAR_AGENT_HOME` is set on the child only, and the headless keyring
//! backend is forced so no run reaches the login keychain. The enabled
//! installation also opens its headless store in-process to store the nonce
//! and to verify the enablement, so that test is `#[serial]`.

#![cfg(feature = "mainnet-write")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; assertions fail loudly"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::Value;
use serial_test::serial;
use sha2::Digest as _;
use stellar_agent_core::error::MainnetOracleGap;
use stellar_agent_core::mainnet::enablement::{
    normalize_endpoint_host, read_enablement_nonce, verify_enablement,
};
use stellar_agent_core::policy::v1::PolicyStateStore;
use stellar_agent_core::policy::v1::verified::{
    OwnerKeySource, PinMode, PolicyLoad, load_verified_policy,
};
use stellar_agent_core::profile::loader::{load_from_path, save_to_dir};
use stellar_agent_core::profile::name::ProfileNameSource;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PolicyEngineKind, PrimaryProviderRecord, Profile, ProviderRecord,
    default_policy_window_state_path_for, mainnet_enablement_entry_ref,
};
use stellar_agent_core::profile::signer_identity::enrolled_signer_pin;
use stellar_agent_network::keyring::{EnrolledRole, enrolled_signer};
use stellar_agent_test_support::{ConnectionCounter, StellarAgentHomeGuard};

use crate::v1_ceremony::{IsolatedHome, Keypair};

/// The profile every run selects with `--profile`.
const PROFILE: &str = "oracle-removed";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The source account of every verb; no run reaches a read of it.
const SOURCE_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The oracle endpoint of the complete profile. No run reaches it.
const ORACLE_URL: &str = "https://oracle.example.invalid";

/// The mainnet write verbs, with arguments that pass the parser.
const WRITE_VERBS: &[(&str, &[&str])] = &[
    ("pay", &["pay", SOURCE_G, "1 XLM", "--source", SOURCE_G]),
    (
        "claim",
        &[
            "claim",
            "000000000000000000000000000000000000000000000000000000000000000000000000",
            "--source",
            SOURCE_G,
        ],
    ),
    (
        "accounts create",
        &[
            "accounts",
            "create",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "--sponsor",
            SOURCE_G,
            "--starting-balance",
            "1 XLM",
        ],
    ),
    (
        "trustline",
        &["trustline", "--from", SOURCE_G, "--asset", "USDC"],
    ),
];

/// Saves the V1 mainnet profile [`PROFILE`] whose primary endpoint is
/// `rpc_url`, with its oracle when `oracle` is set.
fn write_profile(home: &Path, rpc_url: &str, oracle: bool) {
    let signer = KeyringEntryRef::default_signer(PROFILE);
    let nonce = KeyringEntryRef::default_nonce(PROFILE);
    let host = url::Url::parse(rpc_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_owned();
    let mut builder = Profile::builder_mainnet_named(
        PROFILE,
        rpc_url,
        &signer.service,
        &signer.account,
        &nonce.service,
        &nonce.account,
    )
    .primary_provider(PrimaryProviderRecord::new("Primary operator", host))
    .audit_log_path(home.join("audit").join(format!("{PROFILE}.jsonl")))
    .classic_max_fee_per_op_stroops(Some(1000))
    .policy_engine(PolicyEngineKind::V1);
    if oracle {
        builder = builder
            .oracle_provider_url(url::Url::parse(ORACLE_URL).unwrap())
            .oracle_provider(ProviderRecord::new(
                "Oracle operator",
                "oracle.example.invalid",
                true,
            ));
    }
    save_to_dir(PROFILE, &builder.build(), &home.join("profiles")).unwrap();
}

/// Runs the binary in `home` with `args` and `--profile PROFILE`, and
/// returns its exit code and the JSON envelope it printed.
fn run(home: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .args(["--profile", PROFILE])
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
        .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
        .output()
        .expect("stellar-agent binary must run");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let envelope = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout must be one JSON envelope ({e}); stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().expect("exit code"), envelope)
}

/// Every mainnet write verb refuses a fresh profile, with no enablement,
/// that sets no oracle with `profile.mainnet_oracle_required` and the
/// missing-URL detail, before any endpoint contact; the same fresh profile
/// with its oracle passes the oracle step and refuses at the endpoint probe.
#[test]
fn mainnet_oracle_required_refuses_every_write_verb_of_a_fresh_profile_without_an_oracle() {
    for (verb, args) in WRITE_VERBS {
        let home = tempfile::tempdir().unwrap();
        let endpoint = ConnectionCounter::start().expect("loopback connection counter");
        write_profile(home.path(), &endpoint.https_uri(), true);
        let (code, complete) = run(home.path(), args);
        assert_eq!(code, 1, "`{verb}` with its oracle: {complete}");
        assert_eq!(
            complete["error"]["code"], "network.endpoint_identity_unavailable",
            "`{verb}` with its oracle: {complete}"
        );
        assert!(
            endpoint.accepted().expect("connection count") > 0,
            "`{verb}` with its oracle probes the primary endpoint"
        );

        let home = tempfile::tempdir().unwrap();
        let endpoint = ConnectionCounter::start().expect("loopback connection counter");
        write_profile(home.path(), &endpoint.https_uri(), false);
        let (code, removed) = run(home.path(), args);
        assert_eq!(code, 1, "`{verb}` without its oracle: {removed}");
        assert_eq!(
            removed["error"]["code"], "profile.mainnet_oracle_required",
            "`{verb}` without its oracle: {removed}"
        );
        assert_eq!(
            removed["error"]["message"],
            MainnetOracleGap::UrlMissing.text(),
            "`{verb}`"
        );
        assert_eq!(
            endpoint.accepted().expect("connection count"),
            0,
            "`{verb}`: no connection reaches the primary endpoint"
        );
    }
}

/// The installation nonce the enabled installation stores.
const NONCE: &str = "oracle-removed-installation-nonce";

/// The allowlisted payment destination of the enabled installation's policy.
const DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The signed version 2 policy the enablement ceremony leaves for
/// [`PROFILE`]: bound to `endpoint_host` and the digest of [`NONCE`], with the
/// mainnet restrictions and one allowing native payment rule.
fn bound_policy(endpoint_host: &str) -> String {
    let digest = stellar_agent_core::hex::encode(&sha2::Sha256::digest(NONCE.as_bytes()));
    format!(
        "version = 2\nscope = \"profile:{PROFILE}\"\n\n[mainnet]\nprofile = \"{PROFILE}\"\n\
         endpoint_host = \"{endpoint_host}\"\ninstallation_nonce_sha256 = \"{digest}\"\n\
         classic_max_fee_per_op_stroops = 500\nauthorization_ttl_seconds = 60\n\
         [mainnet.cross_check_thresholds]\nnative = \"10000000000\"\n\n\
         [[rules]]\nmatch = {{ tool = \"stellar_pay\", chain = \"stellar:mainnet\" }}\n\
         criteria = [\n\
         {{ kind = \"asset_allowlist\", assets = [\"native\"] }},\n\
         {{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{DESTINATION}\"] }},\n\
         {{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1000000000\" }},\n\
         {{ kind = \"per_period_cap\", window = \"1d\", asset = \"native\", max_stroops = \"10000000000\" }},\n\
         {{ kind = \"rate_limit\", window = \"1d\", max_calls = 100 }},\n\
         ]\ndecision = \"allow\"\n"
    )
}

/// Every file under `root` with its bytes, keyed by its path below `root`.
fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// An enabled mainnet installation whose operator removes the oracle URL
/// and its record from the profile file refuses a payment through the
/// binary with `profile.mainnet_oracle_required` and the missing-URL detail:
/// no connection reaches the primary endpoint, and no file changes, so no
/// audit row, pin, policy, or keyring entry is written. With the oracle in
/// place the same installation passes the oracle step and probes the
/// endpoint.
#[test]
#[serial]
fn mainnet_oracle_required_refuses_a_payment_of_an_enabled_installation_without_its_oracle() {
    let home = IsolatedHome::new();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_core::set_default_store(Arc::new(
        stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.keyring_path(),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(home.headless_key()),
            )),
        ),
    ));
    let endpoint = ConnectionCounter::start().expect("loopback connection counter");
    let signer = Keypair::from_seed([0x51; 32]);
    let owner = Keypair::from_seed([0x52; 32]);

    // The ceremony: the profile with its oracle, every key, the policy
    // bound to the nonce and signed by the owner, its pin, and the nonce.
    write_profile(home.path(), &endpoint.https_uri(), true);
    home.enroll_keys(PROFILE, &signer, &owner);
    let profile = home.load_profile(PROFILE);
    home.write_policy(
        PROFILE,
        &bound_policy(&normalize_endpoint_host(&profile.rpc_url).unwrap()),
    );
    home.sign_policy(PROFILE, &owner);
    let owner_key = stellar_strkey::ed25519::PublicKey::from_string(owner.public())
        .unwrap()
        .0;
    let window = default_policy_window_state_path_for(PROFILE);
    std::fs::create_dir_all(window.parent().unwrap()).unwrap();
    let verified = load_verified_policy(
        &PolicyLoad {
            path: &home.policy_path(PROFILE),
            profile: &profile,
            profile_name: PROFILE,
            owner_pubkey: &owner_key,
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .expect("the signed policy loads and pins");
    keyring_core::Entry::new(
        &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id).service,
        &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id).account,
    )
    .unwrap()
    .set_password(NONCE)
    .unwrap();

    // The installation is enabled as a mainnet write verifies it.
    let profiles_dir = home.path().join("profiles");
    verify_enablement(
        &verified,
        PROFILE,
        ProfileNameSource::Flag,
        &profile,
        &profiles_dir,
        &read_enablement_nonce,
    )
    .expect("the installation is enabled");
    assert_eq!(
        enrolled_signer_pin(PROFILE, &profile).unwrap().as_deref(),
        Some(signer.public())
    );
    let signer_key = stellar_strkey::ed25519::PublicKey::from_string(signer.public())
        .unwrap()
        .0;
    enrolled_signer(
        PROFILE,
        &profiles_dir,
        &profile,
        EnrolledRole::Agent,
        &signer_key,
    )
    .expect("the signer is enrolled");

    let pay = [
        "pay",
        DESTINATION,
        "1 XLM",
        "--source",
        signer.public(),
        "--profile",
        PROFILE,
    ];
    let complete = home.run(&pay, &[]);
    assert_eq!(complete.code, 1, "with its oracle: {}", complete.envelope);
    assert_eq!(
        complete.error_code(),
        "network.endpoint_identity_unavailable",
        "with its oracle: {}",
        complete.envelope
    );
    let probed = endpoint.accepted().expect("connection count");
    assert!(
        probed > 0,
        "with its oracle the payment probes the endpoint"
    );

    // The operator removes the oracle URL and its record; nothing else
    // changes.
    let mut removed = load_from_path(PROFILE, &home.profile_path(PROFILE), None).unwrap();
    removed.oracle_provider_url = None;
    removed.providers.as_mut().unwrap().oracle = None;
    save_to_dir(PROFILE, &removed, &profiles_dir).unwrap();
    let before = tree(home.path());

    let refused = home.run(&pay, &[]);
    assert_eq!(refused.code, 1, "without its oracle: {}", refused.envelope);
    assert_eq!(
        refused.error_code(),
        "profile.mainnet_oracle_required",
        "without its oracle: {}",
        refused.envelope
    );
    assert_eq!(refused.error_message(), MainnetOracleGap::UrlMissing.text());
    assert_eq!(
        endpoint.accepted().expect("connection count"),
        probed,
        "no connection reaches the primary endpoint"
    );
    assert_eq!(
        tree(home.path()),
        before,
        "the refused payment writes no file: no audit row, pin, policy, or keyring entry"
    );
}
