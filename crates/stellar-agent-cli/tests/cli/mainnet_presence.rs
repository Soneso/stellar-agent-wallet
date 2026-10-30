//! Mainnet consent through the shipped binary: no passkey ceremony is
//! connected, so `approve` on a mainnet profile refuses with
//! `approval.presence_required` whatever the operator types, with a genuine
//! attestation key and a pending mainnet entry in place, and records
//! nothing. `--yes` is refused before the store opens.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;
use stellar_agent_core::{
    approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
    },
    profile::{
        loader::save_new_to_dir,
        schema::{KeyringEntryRef, Profile},
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

/// A mainnet profile with its attestation and audit keys in a headless
/// keyring under `home`, and one pending payment in its store. Returns the
/// profile and the entry's nonce.
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
    .with_noop_engine()
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

/// The release adapter refuses every mainnet consent: typed `y`, a typed
/// profile name and `--yes` with `y` all record nothing, with a genuine
/// attestation key and a live pending entry. The pending file stays
/// byte-identical and no audit row is written.
#[test]
#[serial]
fn pr1_production_mainnet_consent_is_closed() {
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
            json["error"]["code"], "approval.presence_required",
            "{json}"
        );
        assert_eq!(
            json["error"]["message"],
            "Mainnet consent requires a verified assertion from an approval credential in the \
             owner-signed policy."
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
        "approve --yes is refused on a mainnet profile; mainnet consent requires a verified \
         passkey assertion from an approval credential in the owner-signed policy."
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
