//! Mainnet stdin input cannot authorize consent: with the owner-signed
//! policy in place, a mainnet approval reaches the browser boundary, and
//! without a browser it refuses whatever stdin carries.
//!
//! The binary runs with [`NO_BROWSER_ENV`], which a `test-helpers` build
//! reads as an unavailable local browser, so no run launches one.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use stellar_agent_core::{
    approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore,
        mainnet_fixtures::{ENABLEMENT_NONCE, policy_body_for, signed_policy_text},
        process_uid_for_attestation,
    },
    policy::v1::{
        PolicyStateStore,
        verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
    },
    profile::{
        loader::save_new_to_dir,
        schema::{
            KeyringEntryRef, Profile, default_policy_window_state_path_for,
            mainnet_enablement_entry_ref,
        },
    },
};
use stellar_xdr::{
    Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
    SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, VecM, WriteXdr,
};

const NAME: &str = "presence-mainnet";
const SIGNER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const PROTECTION_KEY: [u8; 32] = [9; 32];

/// The seed of the owner who signs the presence policy.
const OWNER_SEED: [u8; 32] = [11; 32];

/// The variable a `test-helpers` build reads as an unavailable local
/// browser.
pub(crate) const NO_BROWSER_ENV: &str = "STELLAR_AGENT_TEST_PRESENCE_NO_BROWSER";

/// Enables the saved mainnet profile `profile` named `name` under `home` as
/// the enablement ceremony leaves it, in the keyring store the caller
/// installed: the owner key, the window-state key, the policy the presence
/// listener tests sign, admitting the test-support fixture approval
/// credential and signed by [`OWNER_SEED`], its pin, and the installation
/// nonce.
pub(crate) fn sign_presence_policy(home: &Path, name: &str, profile: &Profile) {
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home);
    let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
    let put = |entry: &KeyringEntryRef, value: &str| {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    };
    put(
        &profile.policy_owner_key_id,
        &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
    );
    stellar_agent_network::keyring::rotate_keyring_secret_32(
        &profile.policy_window_state_key_id.service,
        &profile.policy_window_state_key_id.account,
    )
    .unwrap();
    let host =
        stellar_agent_core::mainnet::enablement::normalize_endpoint_host(&profile.rpc_url).unwrap();
    let body = policy_body_for(
        name,
        &host,
        1,
        &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
    );
    let path = home.join("policies").join(format!("{name}.toml"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, signed_policy_text(&body, &owner)).unwrap();
    let window = default_policy_window_state_path_for(name);
    std::fs::create_dir_all(window.parent().unwrap()).unwrap();
    load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile,
            profile_name: name,
            owner_pubkey: &owner.verifying_key().to_bytes(),
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        },
        PolicyStateStore::new(),
        PinMode::Advance,
    )
    .expect("the signed presence policy loads and pins");
    put(
        &mainnet_enablement_entry_ref(&profile.policy_window_state_key_id),
        ENABLEMENT_NONCE,
    );
}

/// A mainnet profile with its attestation and audit keys in a headless
/// keyring under `home`, its owner-signed presence policy, and one pending
/// payment in its store. Returns the profile and the entry's nonce.
fn mainnet_home(home: &std::path::Path) -> (Profile, String) {
    let signer = KeyringEntryRef::default_signer(NAME);
    let nonce_ref = KeyringEntryRef::default_nonce(NAME);
    let mut profile = Profile::builder_mainnet_named(
        NAME,
        "https://presence-rpc.example:8443",
        &signer.service,
        SIGNER,
        &nonce_ref.service,
        &nonce_ref.account,
    )
    .audit_log_path(home.join("audit").join("presence.jsonl"))
    .build();
    profile.attestation_key_id = KeyringEntryRef::default_attestation_key(NAME);
    save_new_to_dir(NAME, &profile, &home.join("profiles")).unwrap();
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(PROTECTION_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
    for (entry, key) in [
        (&profile.attestation_key_id, [0x42_u8; 32]),
        (&profile.audit_log_hash_chain_key_id, [0x24_u8; 32]),
    ] {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
    }
    sign_presence_policy(home, NAME, &profile);
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([2; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256([4; 32])),
                    asset: Asset::Native,
                    amount: 1_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let entry = PendingApproval::new_payment_pending(
        envelope.clone(),
        envelope.as_bytes(),
        stellar_strkey::ed25519::PublicKey([4; 32])
            .to_string()
            .to_string(),
        1_000_000,
        "XLM".to_owned(),
        None,
        100,
        1,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    let mut approvals =
        PendingApprovalStore::open(home.join("approvals").join(format!("{NAME}.toml"))).unwrap();
    approvals
        .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .unwrap();
    (profile, nonce)
}

/// Runs `approve --id <nonce> --profile <NAME>` with `extra` arguments and
/// `typed` on stdin, and returns the exit code, the envelope and stderr.
fn approve(
    home: &std::path::Path,
    nonce: &str,
    extra: &[&str],
    typed: &str,
) -> (i32, serde_json::Value, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "--id", nonce, "--profile", NAME])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(PROTECTION_KEY),
        )
        .env(NO_BROWSER_ENV, "1")
        .env_remove("STELLAR_AGENT_PROFILE")
        .spawn()
        .expect("approve binary runs");
    // The binary may exit before it reads stdin; a closed pipe is not a
    // failure of this test.
    let _ = child.stdin.take().unwrap().write_all(typed.as_bytes());
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let json = serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    (output.status.code().unwrap(), json, stderr)
}

/// Stdin supplies no mainnet consent: with the owner-signed policy, a
/// genuine attestation key and a live pending entry, typed `y`, `yes` and
/// the profile name reach the browser boundary and refuse there with the
/// browser-required code, and `--yes` with `y` is refused outright. The
/// pending file stays byte-identical and no audit row is written.
#[cfg(feature = "test-helpers")]
#[test]
#[serial]
fn mainnet_presence_stdin_cannot_supply_signed_authority() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (profile, nonce) = mainnet_home(home);
    let pending = home.join("approvals").join(format!("{NAME}.toml"));
    let before = std::fs::read(&pending).unwrap();

    for typed in ["y\n", "yes\n", &format!("{NAME}\n")] {
        let (code, json, stderr) = approve(home, &nonce, &[], typed);
        assert_eq!(code, 1, "{json} {stderr}");
        assert_eq!(json["ok"], false);
        assert_eq!(
            json["error"]["code"], "approval.presence_browser_required",
            "{json} {stderr}"
        );
        assert_eq!(
            json["error"]["message"],
            "Mainnet consent requires a local browser with WebAuthn user verification; no approval is recorded."
        );
        assert!(
            stderr.contains(
                "Review this transaction in the local browser and approve with a pinned passkey."
            ),
            "{stderr}"
        );
        assert!(!stderr.contains("[y/N]"), "no prompt reads stdin: {stderr}");
        assert!(
            stderr.contains(&format!("  Profile:           {NAME}")),
            "{stderr}"
        );
    }

    let (code, json, _stderr) = approve(home, &nonce, &["--yes"], "y\n");
    assert_eq!(code, 1, "{json}");
    assert_eq!(json["error"]["code"], "approve.yes_refused_on_mainnet");
    assert_eq!(
        json["error"]["message"],
        "approve --yes is refused on a mainnet profile; approve with a pinned passkey in the local browser."
    );

    assert_eq!(std::fs::read(&pending).unwrap(), before);
    let store = PendingApprovalStore::open(pending).unwrap();
    let entry = store.get(&nonce).expect("the entry stays pending");
    assert!(entry.attestation_blob_b64.is_none());
    assert!(entry.mainnet_presence.is_none());
    assert!(
        !profile.audit_log_path.exists(),
        "no consent row is written"
    );
}

/// Mainnet startup refusals precede TLS, keyring, and listener setup.
#[test]
#[serial]
fn mainnet_presence_inbox_refuses_remote_and_no_open() {
    let dir = tempfile::tempdir().unwrap();
    mainnet_home(dir.path());
    for (flag, code) in [
        ("--remote", "approval.mainnet_remote_unsupported"),
        ("--no-open", "approval.presence_browser_required"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args(["approve", "serve", "--profile", NAME, flag])
            .env("STELLAR_AGENT_HOME", dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["error"]["code"], code);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("/bootstrap/"));
    }
}
