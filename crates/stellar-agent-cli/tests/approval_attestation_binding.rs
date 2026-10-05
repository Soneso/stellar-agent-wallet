//! The approve binary renders and attests the selected profile and network.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use std::{process::Command, sync::Arc};
use stellar_agent_core::{
    approval::{
        AttestationBinding, DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, envelope_sha256,
        process_uid_for_attestation, verify_attestation,
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

const SIGNER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

fn approve_binary_case(mainnet: bool) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let name = if mainnet {
        "treasury-mainnet"
    } else {
        "testnet-operator"
    };
    let signer = KeyringEntryRef::default_signer(name);
    let nonce_ref = KeyringEntryRef::default_nonce(name);
    let rpc_url = "https://approval-rpc.example:8443/private";
    let builder = if mainnet {
        Profile::builder_mainnet_named(
            name,
            rpc_url,
            &signer.service,
            SIGNER,
            &nonce_ref.service,
            &nonce_ref.account,
        )
    } else {
        Profile::builder_testnet_named(
            name,
            &signer.service,
            SIGNER,
            &nonce_ref.service,
            &nonce_ref.account,
        )
        .rpc_url(rpc_url)
    };
    let mut profile = builder
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
    let key = [0x42; 32];
    keyring_core::Entry::new(
        &profile.attestation_key_id.service,
        &profile.attestation_key_id.account,
    )
    .unwrap()
    .set_password(&URL_SAFE_NO_PAD.encode(key))
    .unwrap();
    // `approve --id` writes its consent row before it persists the approval,
    // so the profile's audit key must be present.
    keyring_core::Entry::new(
        &profile.audit_log_hash_chain_key_id.service,
        &profile.audit_log_hash_chain_key_id.account,
    )
    .unwrap()
    .set_password(&URL_SAFE_NO_PAD.encode([0x24_u8; 32]))
    .unwrap();
    let transaction_source = MuxedAccount::Ed25519(Uint256([2; 32]));
    let operation_source = MuxedAccount::Ed25519(Uint256([3; 32]));
    let operation_source_strkey = stellar_strkey::ed25519::PublicKey([3; 32]).to_string();
    let destination = MuxedAccount::Ed25519(Uint256([4; 32]));
    let destination_strkey = stellar_strkey::ed25519::PublicKey([4; 32]).to_string();
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: transaction_source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: Some(operation_source),
                body: OperationBody::Payment(PaymentOp {
                    destination,
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
    let uid = process_uid_for_attestation().unwrap();
    let mut entry = PendingApproval::new_payment_pending(
        envelope.clone(),
        envelope.as_bytes(),
        destination_strkey.to_string(),
        1_000_000,
        "XLM".to_owned(),
        None,
        100,
        1,
        uid.clone(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    entry.approval_nonce = format!("-{}", &entry.approval_nonce[1..]);
    let nonce = entry.approval_nonce.clone();
    let mut approvals =
        PendingApprovalStore::open(home.join("approvals").join(format!("{name}.toml"))).unwrap();
    approvals
        .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .unwrap();
    drop(approvals);
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "--id", &nonce, "--profile", name, "--yes"])
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(protection_key),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "stdout={stdout}; stderr={stderr}");
    for row in [
        format!("  Profile:           {name}"),
        format!("  Network:           {}", profile.chain_id.caip2_str()),
        "  Endpoint:          https://approval-rpc.example:8443".to_owned(),
        format!("  Signer:            {SIGNER}"),
        format!("  Source:            {operation_source_strkey}"),
    ] {
        assert!(stderr.contains(&row), "missing {row:?}: {stderr}");
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(json["data"]["approval_attestation"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(verify_attestation(
        &key,
        &AttestationBinding::new(name, profile.chain_id.caip2_str()),
        &nonce,
        &envelope_sha256(envelope.as_bytes()),
        &uid,
        &blob
    ));
    assert_eq!(json["data"]["audit"], "written", "{stdout}");
    let log = std::fs::read_to_string(&profile.audit_log_path).unwrap();
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &serde_json::Value| row["kind"] == "approval_attested")
        .collect();
    assert_eq!(rows.len(), 1, "one consent row: {log}");
    assert_eq!(rows[0]["nonce_prefix"], nonce[..8]);
    assert_eq!(rows[0]["origin"], "cli");
    assert_eq!(rows[0]["approval_kind"], "PaymentSimulated");
}

#[test]
#[serial]
fn approve_binary_testnet_binding_and_summary() {
    approve_binary_case(false);
}

#[test]
#[serial]
fn approve_binary_mainnet_binding_and_summary() {
    approve_binary_case(true);
}
