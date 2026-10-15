//! The operator approves a split-policy MCP payment through the real CLI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use std::{process::Command, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::{
    approval::PendingApprovalStore,
    policy::v1::{canonical::canonical_bytes, signature::digest},
    profile::{loader::save_new_to_dir, schema::Profile},
};
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::{
    StellarAgentHomeGuard,
    signed_envelope::{get_network_result, send_transaction_hash_hex},
    xdr_fixtures::{account_entry_xdr_with_seq, account_ledger_key_xdr},
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn split_pay_approval_through_operator_cli() {
    const NAME: &str = "split-cli-approval";
    const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const NETWORK: &str = "Test SDF Network ; September 2015";
    let home = tempfile::tempdir().unwrap();
    let _home_guard = StellarAgentHomeGuard::new(home.path());
    let protection_key = [7; 32];
    let keyring: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.path().join("headless-keyring/store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(protection_key),
            )),
        ));
    keyring_core::set_default_store(keyring);
    let signer = SigningKey::from_bytes(&[0x61; 32]);
    let source = stellar_strkey::ed25519::PublicKey(signer.verifying_key().to_bytes())
        .to_string()
        .to_string();
    let rpc = MockServer::start().await;
    let mut profile =
        Profile::builder_testnet_named(NAME, "split-signer", &source, "split-nonce", NAME)
            .rpc_url(rpc.uri())
            .audit_log_path(home.path().join("audit/approval.jsonl"))
            .build();
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::V1;
    profile.submit_timeout_seconds = Some(2);
    save_new_to_dir(NAME, &profile, &home.path().join("profiles")).unwrap();
    keyring_core::Entry::new("split-signer", &source)
        .unwrap()
        .set_password(
            stellar_strkey::ed25519::PrivateKey(signer.to_bytes())
                .as_unredacted()
                .to_string()
                .as_ref(),
        )
        .unwrap();
    for (coordinate, bytes) in [
        (&profile.mcp_nonce_key_alias, [9; 32]),
        (&profile.attestation_key_id, [0x42; 32]),
        (&profile.audit_log_hash_chain_key_id, [0x24; 32]),
        (
            &profile.policy_owner_key_id,
            signer.verifying_key().to_bytes(),
        ),
    ] {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(bytes))
            .unwrap();
    }
    let body = format!(
        r#"version = 1
scope = "profile:{NAME}"
[[rules]]
match = {{ tool = "stellar_pay", chain = "stellar:testnet" }}
criteria = [{{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 100000000 }}]
decision = "allow"
[[rules]]
match = {{ tool = "*", chain = "*" }}
criteria = []
decision = "require_approval"
ttl_secs = 617
reason = "Operator review"
"#
    );
    let signature = hex::encode(
        signer
            .sign(&digest(&canonical_bytes(&body).unwrap()))
            .to_bytes(),
    );
    let policy_dir = home.path().join("policies");
    std::fs::create_dir_all(&policy_dir).unwrap();
    std::fs::write(
        policy_dir.join(format!("{NAME}.toml")),
        format!("{body}\n[signature]\nowner_id = \"{source}\"\nsig = \"{signature}\"\n"),
    )
    .unwrap();
    let accounts = [
        (
            account_ledger_key_xdr(&source),
            account_entry_xdr_with_seq(&source, 500_000_000_000, 0, 42),
        ),
        (
            account_ledger_key_xdr(DEST),
            account_entry_xdr_with_seq(DEST, 500_000_000_000, 0, 42),
        ),
    ];
    Mock::given(method("POST")).respond_with(move |request: &wiremock::Request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fee = json!({"max":"100", "min":"100", "mode":"100", "p10":"100", "p20":"100", "p30":"100", "p40":"100", "p50":"100", "p60":"100", "p70":"100", "p80":"100", "p90":"100", "p95":"100", "p99":"100", "transactionCount":"10", "ledgerCount":5});
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(NETWORK),
            "getFeeStats" => json!({"sorobanInclusionFee":fee, "inclusionFee":fee, "latestLedger":1001}),
            "getLedgerEntries" => {
                let keys = body["params"]["keys"].as_array().unwrap();
                let entries: Vec<Value> = accounts.iter().filter(|(key, _)| keys.contains(&json!(key))).map(|(key, xdr)| json!({"key":key, "xdr":xdr, "lastModifiedLedgerSeq":1000})).collect();
                json!({"entries":entries, "latestLedger":1001})
            },
            "sendTransaction" => json!({"hash":send_transaction_hash_hex(&body, NETWORK), "status":"PENDING", "latestLedger":1001, "latestLedgerCloseTime":"1234567890"}),
            "getTransaction" => json!({"status":"SUCCESS", "ledger":1001, "latestLedger":1002, "oldestLedger":1, "createdAt":(stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000).to_string()}),
            other => panic!("unexpected RPC method: {other}"),
        };
        ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
    }).mount(&rpc).await;
    let mut server = WalletServer::new_with_policy_dir_for_test(profile, &policy_dir).unwrap();
    server.set_approval_dir_for_test(home.path().join("approvals"));
    let mut args = json!({"chain_id":"stellar:testnet", "source":source, "destination":DEST, "asset":"native", "amount_in_stroops":"10000000"});
    let result = server
        .call_stellar_pay(serde_json::from_value(args.clone()).unwrap())
        .await
        .unwrap();
    let sim: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(sim["ok"], true, "{sim}");
    let nonce = sim["data"]["approval"]["approval_nonce"]
        .as_str()
        .expect("paired commit creates an operator request");
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "--id", nonce, "--profile", NAME, "--yes"])
        .env("STELLAR_AGENT_HOME", home.path())
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(protection_key),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let approved: Value = serde_json::from_slice(&output.stdout).unwrap();
    let attestation = approved["data"]["approval_attestation"].as_str().unwrap();
    {
        let store =
            PendingApprovalStore::open(home.path().join(format!("approvals/{NAME}.toml"))).unwrap();
        assert_eq!(
            store.get(nonce).unwrap().attestation_blob_b64.as_deref(),
            Some(attestation)
        );
    }
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(attestation);
    let result = server
        .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
        .await
        .unwrap();
    let committed: Value =
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(committed["ok"], true, "{committed}");
    assert!(
        rpc.received_requests().await.unwrap().iter().any(
            |request| serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                == "sendTransaction"
        )
    );
}
