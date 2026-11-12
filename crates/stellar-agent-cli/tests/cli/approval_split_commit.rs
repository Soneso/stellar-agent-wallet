//! The operator approves a split-policy MCP payment through the real CLI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use std::{path::PathBuf, process::Command, sync::Arc};

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

const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const NETWORK: &str = "Test SDF Network ; September 2015";

/// A split-policy payment the operator approved through the real CLI. It
/// holds the home, the mock RPC and the server that prepared it. It also
/// holds the prepare result, the commit arguments, the nonce and the
/// attestation.
struct SplitPayment {
    server: WalletServer,
    rpc: MockServer,
    profile: Profile,
    policy_dir: PathBuf,
    protection_key: [u8; 32],
    sim: Value,
    args: Value,
    nonce: String,
    attestation: String,
    _home_guard: StellarAgentHomeGuard,
    home: tempfile::TempDir,
}

impl SplitPayment {
    /// Runs the real binary with `args` under the fixture home and keyring.
    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args(args)
            .env("STELLAR_AGENT_HOME", self.home.path())
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                URL_SAFE_NO_PAD.encode(self.protection_key),
            )
            .env_remove("STELLAR_AGENT_PROFILE")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    /// The commit arguments of `sim` with the approval nonce and attestation.
    fn commit_args(&self, sim: &Value, nonce: &str, attestation: &str) -> Value {
        let mut args = self.args.clone();
        for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
            args[field] = sim["data"][field].clone();
        }
        args["approval_nonce"] = json!(nonce);
        args["approval_attestation"] = json!(attestation);
        args
    }

    /// How many `sendTransaction` calls the mock RPC received.
    async fn sends(&self) -> usize {
        self.rpc
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                    == "sendTransaction"
            })
            .count()
    }
}

/// Prepares a payment that a `require_approval` rule of 617 s gates, and
/// approves it through `approve --id <nonce> --profile <name> --yes`.
async fn approved_split_payment(name: &'static str) -> SplitPayment {
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
        Profile::builder_testnet_named(name, "split-signer", &source, "split-nonce", name)
            .rpc_url(rpc.uri())
            .audit_log_path(home.path().join("audit/approval.jsonl"))
            .build();
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::V1;
    profile.submit_timeout_seconds = Some(2);
    save_new_to_dir(name, &profile, &home.path().join("profiles")).unwrap();
    keyring_core::Entry::new("split-signer", &source)
        .unwrap()
        .set_password(
            stellar_strkey::ed25519::PrivateKey(signer.to_bytes())
                .as_unredacted()
                .to_string()
                .as_ref(),
        )
        .unwrap();
    stellar_agent_network::keyring::write_keyring_string(
        &stellar_agent_core::profile::schema::signer_identity_entry_ref(
            &profile.mcp_signer_default,
        ),
        &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
            signer.verifying_key().to_bytes(),
            name,
            profile.chain_id,
        )
        .render()
        .unwrap(),
    )
    .unwrap();
    for (coordinate, bytes) in [
        (&profile.mcp_nonce_key_alias, [9; 32]),
        (&profile.attestation_key_id, [0x42; 32]),
        (&profile.audit_log_hash_chain_key_id, [0x24; 32]),
    ] {
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(bytes))
            .unwrap();
    }
    keyring_core::Entry::new(
        &profile.policy_owner_key_id.service,
        &profile.policy_owner_key_id.account,
    )
    .unwrap()
    .set_password(
        &stellar_agent_core::profile::owner_key::encode_owner_public_key(
            &signer.verifying_key().to_bytes(),
        ),
    )
    .unwrap();
    let body = format!(
        r#"version = 1
scope = "profile:{name}"
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
        policy_dir.join(format!("{name}.toml")),
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
            other => crate::classic_ledger::readiness_result(other)
                .unwrap_or_else(|| panic!("unexpected RPC method: {other}")),
        };
        ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
    }).mount(&rpc).await;
    let mut server =
        WalletServer::new_with_policy_dir_for_test(profile.clone(), &policy_dir).unwrap();
    server.set_approval_dir_for_test(home.path().join("approvals"));
    let args = json!({"chain_id":"stellar:testnet", "source":source, "destination":DEST, "asset":"native", "amount_in_stroops":"10000000"});
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
        .args(["approve", "--id", nonce, "--profile", name, "--yes"])
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
            PendingApprovalStore::open(home.path().join(format!("approvals/{name}.toml"))).unwrap();
        assert_eq!(
            store.get(nonce).unwrap().attestation_blob_b64.as_deref(),
            Some(attestation)
        );
    }
    SplitPayment {
        server,
        rpc,
        profile,
        policy_dir,
        protection_key,
        nonce: nonce.to_owned(),
        attestation: attestation.to_owned(),
        sim,
        args,
        _home_guard,
        home,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn split_pay_approval_through_operator_cli() {
    let payment = approved_split_payment("split-cli-approval").await;
    let args = payment.commit_args(&payment.sim, &payment.nonce, &payment.attestation);
    let result = payment
        .server
        .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
        .await
        .unwrap();
    let committed: Value =
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(committed["ok"], true, "{committed}");
    assert!(
        payment
            .rpc
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(
                |request| serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                    == "sendTransaction"
            )
    );
}

/// `approve gc --include-consumed` removes a spent approval's row, and the
/// receipt still refuses the spent nonce. A restarted server prepares the
/// payment afresh and commits with the spent nonce and attestation. The
/// commit refuses with `policy.approval_consumed`, and nothing is sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn gc_include_consumed_keeps_receipt_replay_protection() {
    const NAME: &str = "split-gc-replay";
    let payment = approved_split_payment(NAME).await;
    let args = payment.commit_args(&payment.sim, &payment.nonce, &payment.attestation);
    let result = payment
        .server
        .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
        .await
        .unwrap();
    let committed: Value =
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(committed["ok"], true, "{committed}");
    assert_eq!(payment.sends().await, 1);

    let json_of = |output: std::process::Output| -> Value {
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let consumed_rows = |listed: &Value| {
        listed["data"]["pending"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["approval_nonce"] == payment.nonce.as_str())
            .map(|row| row["kind_name"].clone())
            .collect::<Vec<_>>()
    };
    let list = ["approve", "list", "--profile", NAME];
    assert_eq!(
        consumed_rows(&json_of(payment.cli(&list))),
        [json!("Consumed")],
        "the completed payment leaves a consumed row"
    );
    let default = json_of(payment.cli(&["approve", "gc", "--profile", NAME]));
    assert_eq!(
        default["data"],
        json!({"profile": NAME, "evicted_count": 0}),
        "{default}"
    );
    assert_eq!(
        consumed_rows(&json_of(payment.cli(&list))),
        [json!("Consumed")],
        "default gc keeps the consumed row"
    );
    let flagged = json_of(payment.cli(&["approve", "gc", "--profile", NAME, "--include-consumed"]));
    assert_eq!(
        flagged["data"],
        json!({"profile": NAME, "evicted_count": 1}),
        "{flagged}"
    );
    assert!(
        consumed_rows(&json_of(payment.cli(&list))).is_empty(),
        "flagged gc removes the consumed row"
    );

    let mut restarted =
        WalletServer::new_with_policy_dir_for_test(payment.profile.clone(), &payment.policy_dir)
            .unwrap();
    restarted.set_approval_dir_for_test(payment.home.path().join("approvals"));
    let result = restarted
        .call_stellar_pay(serde_json::from_value(payment.args.clone()).unwrap())
        .await
        .unwrap();
    let fresh: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(fresh["ok"], true, "{fresh}");
    let replay = payment.commit_args(&fresh, &payment.nonce, &payment.attestation);
    let result = restarted
        .call_stellar_pay_commit(serde_json::from_value(replay).unwrap())
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let refused: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(
        refused["error"]["code"], "policy.approval_consumed",
        "{refused}"
    );
    assert_eq!(payment.sends().await, 1, "nothing is sent again");
}

/// `approve gc` without a flag removes expired rows only: a consumed row
/// stays, and the JSON data names the profile and the evicted count alone.
#[test]
#[serial]
fn approve_gc_default_keeps_consumed_rows_and_its_json() {
    const NAME: &str = "gc-default";
    let home = tempfile::tempdir().unwrap();
    let _home_guard = StellarAgentHomeGuard::new(home.path());
    let account = stellar_strkey::ed25519::PublicKey([0x31; 32])
        .to_string()
        .to_string();
    let profile = Profile::builder_testnet_named(NAME, "gc-signer", &account, "gc-nonce", NAME)
        .audit_log_path(home.path().join("audit/approval.jsonl"))
        .build();
    save_new_to_dir(NAME, &profile, &home.path().join("profiles")).unwrap();
    let entry = |ttl_ms: u64| {
        stellar_agent_core::approval::PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"gc-envelope-bytes",
            account.clone(),
            1_000_000,
            "XLM".to_owned(),
            None,
            100,
            12_345,
            "1000".to_owned(),
            ttl_ms,
        )
        .unwrap()
    };
    let path = home.path().join(format!("approvals/{NAME}.toml"));
    let (live, consumed, expired) = (entry(600_000), entry(600_000), entry(1));
    let nonces = [
        live.approval_nonce.clone(),
        consumed.approval_nonce.clone(),
        expired.approval_nonce.clone(),
    ];
    {
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        for row in [live, consumed, expired] {
            store.insert(row, now).unwrap();
        }
        assert!(
            store
                .consume(
                    &nonces[1],
                    &"ab".repeat(32),
                    stellar_agent_core::approval::store::ConsumedOutcome::Confirmed,
                )
                .unwrap()
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["approve", "gc", "--profile", NAME])
        .env("STELLAR_AGENT_HOME", home.path())
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
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert_eq!(
        envelope["data"],
        json!({"profile": NAME, "evicted_count": 1}),
        "{envelope}"
    );
    let store = PendingApprovalStore::open(path).unwrap();
    assert!(store.get(&nonces[0]).is_some(), "the live row stays");
    assert!(
        matches!(
            store.get(&nonces[1]).map(|row| &row.kind),
            Some(stellar_agent_core::approval::store::ApprovalKind::Consumed { .. })
        ),
        "the consumed row stays"
    );
    assert!(store.get(&nonces[2]).is_none(), "the expired row goes");
}
