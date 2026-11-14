//! On Linux another process of the same user cannot read the environment of
//! a running CLI.
//!
//! The binary marks itself non-dumpable before its async runtime starts, so
//! `/proc/<pid>/environ` belongs to root while the command runs. The test
//! holds a testnet `approve --id` at its terminal prompt, with a marker
//! variable in the binary's environment, and reads that file from the test
//! process, which runs as the same user. The test needs a user without
//! `CAP_SYS_PTRACE`: root reads every environment.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use stellar_agent_core::approval::{
    DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
};
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_xdr::{
    Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
    SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, VecM, WriteXdr,
};

/// The profile's enrolled signer coordinate account.
const SIGNER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
/// The variable whose value the reader looks for.
const PROBE_VAR: &str = "STELLAR_AGENT_ENVIRON_PROBE";
/// The prompt `approve --id` blocks on.
const PROMPT: &[u8] = b"Approve? [y/N]: ";
/// How long the binary may take to reach its prompt.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Saves a testnet profile named `name` under `home` with its attestation
/// and audit keys in a headless keyring, inserts one pending payment, and
/// returns the payment's approval nonce and the keyring's protection key.
fn testnet_pending_payment(home: &std::path::Path, name: &str) -> (String, [u8; 32]) {
    let signer = KeyringEntryRef::default_signer(name);
    let nonce_ref = KeyringEntryRef::default_nonce(name);
    let mut profile = Profile::builder_testnet_named(
        name,
        &signer.service,
        SIGNER,
        &nonce_ref.service,
        &nonce_ref.account,
    )
    .rpc_url("https://approval-rpc.example:8443/private")
    .audit_log_path(home.join("audit").join("approval.jsonl"))
    .with_noop_engine()
    .build();
    profile.attestation_key_id = KeyringEntryRef::default_attestation_key(name);
    save_new_to_dir(name, &profile, &home.join("profiles")).unwrap();

    let protection_key = [7_u8; 32];
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(protection_key),
            )),
        ));
    keyring_core::set_default_store(store);
    for (coordinate, key) in [
        (&profile.attestation_key_id, [0x42_u8; 32]),
        (&profile.audit_log_hash_chain_key_id, [0x24_u8; 32]),
    ] {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
    }

    let destination_strkey = stellar_strkey::ed25519::PublicKey([4; 32]).to_string();
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([2; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: Some(MuxedAccount::Ed25519(Uint256([3; 32]))),
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
        destination_strkey.to_string(),
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
        PendingApprovalStore::open(home.join("approvals").join(format!("{name}.toml"))).unwrap();
    approvals
        .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .unwrap();
    (nonce, protection_key)
}

#[test]
#[serial]
fn a_same_user_process_cannot_read_the_cli_environment() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let name = "environ-probe";
    let (nonce, protection_key) = testnet_pending_payment(home, name);
    let marker = uuid::Uuid::new_v4().simple().to_string();
    assert_ne!(
        process_uid_for_attestation().unwrap(),
        "0",
        "the test runs as root, which reads every environment; run the test as a user \
         without CAP_SYS_PTRACE"
    );

    stellar_agent_test_support::sandbox::mark_sandbox(home).expect("mark fixture directory");
    let mut child = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "--id", &nonce, "--profile", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(protection_key),
        )
        .env(crate::mainnet_presence::NO_BROWSER_ENV, "1")
        .env(PROBE_VAR, &marker)
        .env_remove("STELLAR_AGENT_PROFILE")
        .spawn()
        .expect("the binary starts");
    let pid = child.id();

    // The reader thread signals once the prompt is on stderr and returns
    // everything the binary wrote there.
    let mut stderr = child.stderr.take().unwrap();
    let (prompted, at_prompt) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut byte = [0_u8; 1];
        let mut signalled = false;
        while stderr.read(&mut byte).unwrap_or(0) == 1 {
            seen.push(byte[0]);
            if !signalled && seen.ends_with(PROMPT) {
                signalled = true;
                let _ = prompted.send(());
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    });
    if at_prompt.recv_timeout(PROMPT_TIMEOUT).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "the binary did not reach its prompt: {}",
            reader.join().unwrap()
        );
    }

    let read = std::fs::read(format!("/proc/{pid}/environ"));

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"n\n").unwrap();
    drop(stdin);
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let status = child.wait().unwrap();
    let stderr = reader.join().unwrap();

    match read {
        Ok(bytes) => {
            let marker_present = bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes());
            panic!(
                "a same-user process read {} bytes of the running CLI's environment \
                 (marker present: {marker_present})",
                bytes.len()
            );
        }
        Err(error) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{error}"
        ),
    }
    assert_eq!(status.code(), Some(1), "stdout={stdout}; stderr={stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    assert_eq!(json["error"]["code"], "approval.denied", "{stdout}");
}
