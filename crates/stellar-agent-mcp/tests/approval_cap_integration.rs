//! Approved submissions keep their policy-sized audit legs and cap reservations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
};
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rmcp::model::CallToolResult;
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::approval::{
    PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrantStore,
    attestation::{compute_attestation, envelope_sha256},
    build_attested_grant, process_uid_for_attestation,
};
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::v1::{canonical::canonical_bytes, signature::digest};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_mcp::server::{
    StellarPayCommitArgs, StellarToolsetInvokeArgs, StellarTransactionStatusArgs, WalletServer,
};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_test_support::{
    keyring_mock,
    xdr_fixtures::{account_entry_xdr_with_seq, account_ledger_key_xdr},
};
use tempfile::TempDir;
use wiremock::{Mock, MockServer, Respond, ResponseTemplate, matchers::method};

mod common;

const AMOUNT: i128 = 60_000_000;
const ATTESTATION_KEY: [u8; 32] = [0xD2; 32];
const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

fn claim_entry(source: &str) -> (String, String) {
    use stellar_xdr::{
        AccountId, Asset, ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt,
        ClaimableBalanceId, Claimant, ClaimantV0, Hash, LedgerEntryData, LedgerKey,
        LedgerKeyClaimableBalance, Limits, PublicKey, Uint256, WriteXdr,
    };
    let id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
    let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
        balance_id: id.clone(),
    });
    let entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
        balance_id: id,
        claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(source)
                    .unwrap()
                    .0,
            ))),
            predicate: ClaimPredicate::Unconditional,
        })]
        .try_into()
        .unwrap(),
        asset: Asset::Native,
        amount: 5_000_000,
        ext: ClaimableBalanceEntryExt::V0,
    });
    (
        key.to_xdr_base64(Limits::none()).unwrap(),
        entry.to_xdr_base64(Limits::none()).unwrap(),
    )
}

fn result_json(result: &CallToolResult) -> Value {
    serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
}

fn pay_json(args: &StellarPayCommitArgs) -> Value {
    json!({
        "chain_id": args.chain_id, "source": args.source, "destination": args.destination,
        "asset": args.asset, "amount_in_stroops": args.amount_in_stroops,
        "nonce": args.nonce, "expires_at_unix_ms": args.expires_at_unix_ms,
        "envelope_xdr": args.envelope_xdr, "approval_nonce": args.approval_nonce,
        "approval_attestation": args.approval_attestation
    })
}

fn seed_key(service: &str, account: &str, bytes: &[u8]) {
    keyring_core::Entry::new(service, account)
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        .unwrap();
}

#[derive(Clone, Copy)]
enum Outcome {
    Success,
    Timeout,
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
struct WindowSnapshot {
    amount: i128,
    entries: u32,
    pending: usize,
}

fn snapshot(profile: &Profile, name: &str) -> WindowSnapshot {
    let disk = PersistedWindowStore::for_profile(name);
    let state = PolicyStateStore::new();
    disk.load_into(name, profile, &state).unwrap();
    let (amount, entries) = state
        .query_window(
            &StateKey::new(name, 1, "native", 86_400),
            now_unix_ms().unwrap(),
        )
        .unwrap();
    WindowSnapshot {
        amount,
        entries,
        pending: disk.pending_reservations(profile).unwrap().len(),
    }
}

struct Harness {
    server: WalletServer,
    profile: Profile,
    name: String,
    source: String,
    outcomes: Arc<Mutex<Outcome>>,
    sends: Arc<Mutex<Vec<WindowSnapshot>>>,
    policy_dir: TempDir,
    approval_dir: TempDir,
    _rpc: MockServer,
    _root: common::IsolatedDataRoot,
}

impl Harness {
    async fn new(name: &str, decision: &str, outcome: Outcome) -> Self {
        let root = common::isolated_data_root();
        keyring_mock::install().unwrap();
        let signer = SigningKey::from_bytes(&[0x61; 32]);
        let source = stellar_strkey::ed25519::PublicKey(signer.verifying_key().to_bytes())
            .to_string()
            .to_string();
        keyring_core::Entry::new("svc", name)
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey(signer.to_bytes())
                    .as_unredacted()
                    .to_string()
                    .as_ref(),
            )
            .unwrap();
        seed_key("n-svc", "n-acct", &[7; 32]);
        let rpc = MockServer::start().await;
        let mut profile = common::timeout_profile(&rpc.uri(), name);
        profile.policy.engine = PolicyEngineKind::V1;
        seed_key(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
            &ATTESTATION_KEY,
        );
        seed_key(
            &profile.policy_owner_key_id.service,
            &profile.policy_owner_key_id.account,
            &signer.verifying_key().to_bytes(),
        );

        let body = format!(
            r#"version = 1
scope = "profile:{name}"
[[rules]]
match = {{ tool = "stellar_transaction_status", chain = "*" }}
criteria = []
decision = "allow"
[[rules]]
match = {{ tool = "*", chain = "*" }}
criteria = [{{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 100000000 }}]
decision = "{decision}"
"#
        );
        let signature = hex::encode(
            signer
                .sign(&digest(&canonical_bytes(&body).unwrap()))
                .to_bytes(),
        );
        let policy_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            policy_dir.path().join(format!("{name}.toml")),
            format!("{body}\n[signature]\nowner_id = \"{source}\"\nsig = \"{signature}\"\n"),
        )
        .unwrap();
        let approval_dir = tempfile::tempdir().unwrap();
        let mut server =
            WalletServer::new_with_policy_dir_for_test(profile.clone(), policy_dir.path()).unwrap();
        server.set_approval_dir_for_test(approval_dir.path().to_owned());
        assert_eq!(server.profile_name_for_approval(), name);

        let outcomes = Arc::new(Mutex::new(outcome));
        let sends = Arc::new(Mutex::new(Vec::new()));
        let response_outcome = outcomes.clone();
        let observations = sends.clone();
        let response_profile = profile.clone();
        let response_name = name.to_owned();
        let response_source = source.clone();
        let sequence = AtomicI64::new(42);
        Mock::given(method("POST")).respond_with(move |request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            if body["method"] == "sendTransaction" {
                observations.lock().unwrap().push(snapshot(&response_profile, &response_name));
            }
            if body["method"] == "getTransaction" {
                let status = match *response_outcome.lock().unwrap() {
                    Outcome::Success => { sequence.store(43, Ordering::SeqCst); "SUCCESS" }, Outcome::Timeout => "NOT_FOUND", Outcome::Failed => { sequence.store(43, Ordering::SeqCst); "FAILED" },
                };
                return ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": body["id"],
                    "result": { "status": status, "ledger": 1001, "latestLedger": 1002, "oldestLedger": 1,
                        "createdAt": (stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000).to_string() }
                }));
            }
        let responder = common::TimeoutRpc::new(vec![
            claim_entry(&response_source),
            (
                account_ledger_key_xdr(USDC_ISSUER),
                account_entry_xdr_with_seq(USDC_ISSUER, 500_000_000_000, 0, 1),
            ),
            (
                account_ledger_key_xdr(&response_source),
                account_entry_xdr_with_seq(&response_source, 500_000_000_000, 0, sequence.load(Ordering::SeqCst)),
            ),
            (
                account_ledger_key_xdr(DEST),
                account_entry_xdr_with_seq(DEST, 500_000_000_000, 0, 42),
            ),
        ]);
            responder.respond(request)
        }).mount(&rpc).await;
        Self {
            server,
            profile,
            name: name.to_owned(),
            source,
            outcomes,
            sends,
            policy_dir,
            approval_dir,
            _rpc: rpc,
            _root: root,
        }
    }

    async fn simulate_pay(&self, amount: i128) -> Value {
        let result = self
            .server
            .call_stellar_pay(
                serde_json::from_value(json!({
                    "chain_id": "stellar:testnet", "source": self.source, "destination": DEST,
                    "asset": "native", "amount_in_stroops": amount.to_string()
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        result_json(&result)
    }

    fn attest(&self, data: &Value) -> (String, String) {
        let nonce = data["approval"]["approval_nonce"]
            .as_str()
            .expect("simulation requests approval");
        let envelope = data["envelope_xdr"].as_str().unwrap();
        self.attest_nonce(nonce, envelope)
    }

    fn attest_nonce(&self, nonce: &str, envelope: &str) -> (String, String) {
        let blob = compute_attestation(
            &ATTESTATION_KEY,
            nonce,
            &envelope_sha256(envelope.as_bytes()),
            &process_uid_for_attestation().unwrap(),
        );
        let mut store = PendingApprovalStore::open(
            self.approval_dir.path().join(format!("{}.toml", self.name)),
        )
        .unwrap();
        store.record_attestation(nonce, blob).unwrap();
        (
            nonce.to_owned(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob),
        )
    }

    fn pay_args(
        &self,
        data: &Value,
        amount: i128,
        approval: Option<(String, String)>,
    ) -> StellarPayCommitArgs {
        let (nonce, attestation) = approval
            .map(|(n, a)| (Some(n), Some(a)))
            .unwrap_or_default();
        serde_json::from_value(json!({
            "chain_id": "stellar:testnet", "source": self.source, "destination": DEST,
            "asset": "native", "amount_in_stroops": amount.to_string(),
            "nonce": data["nonce"], "expires_at_unix_ms": data["expires_at_unix_ms"], "envelope_xdr": data["envelope_xdr"],
            "approval_nonce": nonce, "approval_attestation": attestation
        })).unwrap()
    }

    async fn commit_pay(&self, args: StellarPayCommitArgs) -> Value {
        result_json(
            &tokio::time::timeout(
                Duration::from_secs(5),
                self.server.call_stellar_pay_commit(args),
            )
            .await
            .expect("commit is bounded around its one-second poll deadline")
            .unwrap(),
        )
    }

    fn window(&self) -> WindowSnapshot {
        snapshot(&self.profile, &self.name)
    }

    fn assert_send_reserved(&self) {
        assert_eq!(
            *self.sends.lock().unwrap(),
            vec![WindowSnapshot {
                amount: AMOUNT,
                entries: 1,
                pending: 1
            }],
            "the complete amount must be reserved when bytes reach RPC"
        );
    }

    fn assert_legs(&self, kind: &str, action: &str, amount: Option<i128>) {
        let rows = common::audit_rows(&self.profile);
        let selected = common::rows_of_kind(&rows, kind);
        assert_eq!(selected.len(), 1, "one row per submission: {rows:?}");
        let legs = selected[0]["legs"].as_array().expect("audit legs");
        assert_eq!(
            legs.len(),
            1,
            "the gate-sized leg must survive approval: {rows:?}"
        );
        assert_eq!(legs[0]["action"], action);
        assert_eq!(
            legs[0]["amount"],
            amount
                .map(|n| Value::String(n.to_string()))
                .unwrap_or(Value::Null)
        );
    }
}

#[tokio::test]
#[serial]
async fn approved_payment_reserves_before_send_and_settles_with_sized_audit_legs() {
    let h = Harness::new("cap-approved-confirm", "require_approval", Outcome::Success).await;
    let sim = h.simulate_pay(AMOUNT).await;
    assert_eq!(sim["ok"], true, "{sim}");
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: 0,
            entries: 0,
            pending: 0
        },
        "requesting approval takes no reservation"
    );
    assert!(h.sends.lock().unwrap().is_empty());
    let args = h.pay_args(&sim["data"], AMOUNT, Some(h.attest(&sim["data"])));
    let result = h.commit_pay(args).await;
    assert_eq!(result["ok"], true, "{result}");
    h.assert_send_reserved();
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 0
        }
    );
    h.assert_legs("value_action_pending", "payment", Some(AMOUNT));
    h.assert_legs("value_action_submitted", "payment", Some(AMOUNT));
}

#[tokio::test]
#[serial]
async fn approval_does_not_waive_commit_time_cap_denial() {
    let h = Harness::new("cap-approved-second", "require_approval", Outcome::Success).await;
    let first = h.simulate_pay(AMOUNT).await;
    let second = h.simulate_pay(50_000_000).await;
    let first = h.pay_args(&first["data"], AMOUNT, Some(h.attest(&first["data"])));
    let second = h.pay_args(&second["data"], 50_000_000, Some(h.attest(&second["data"])));
    assert_eq!(h.commit_pay(first).await["ok"], true);
    let refusal = h.commit_pay(second).await;
    assert_eq!(
        refusal["error"]["code"], "policy.deny.per_period_cap_exceeded",
        "{refusal}"
    );
    h.assert_send_reserved();
    assert_eq!(h.window().amount, AMOUNT);
}

#[tokio::test]
#[serial]
async fn approved_timeout_keeps_cap_until_transaction_status_settles() {
    let h = Harness::new("cap-approved-timeout", "require_approval", Outcome::Timeout).await;
    let sim = h.simulate_pay(AMOUNT).await;
    let result = h
        .commit_pay(h.pay_args(&sim["data"], AMOUNT, Some(h.attest(&sim["data"]))))
        .await;
    assert_eq!(result["error"]["code"], "submission.tx_timeout", "{result}");
    h.assert_send_reserved();
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 1
        }
    );
    assert!(
        common::rows_of_kind(&common::audit_rows(&h.profile), "value_action_submitted").is_empty()
    );
    let details = &result["error"]["details"];
    *h.outcomes.lock().unwrap() = Outcome::Success;
    let status = result_json(
        &h.server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:testnet".to_owned(),
                tx_hash: details["tx_hash"].as_str().unwrap().to_owned(),
            })
            .await
            .unwrap(),
    );
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 0
        }
    );
    let receipt = ReceiptStore::open(&h.name)
        .unwrap()
        .get(details["envelope_hash"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    h.assert_legs("value_action_submitted", "payment", Some(AMOUNT));
}

#[tokio::test]
#[serial]
async fn approved_definitive_failure_releases_cap() {
    let h = Harness::new("cap-approved-failed", "require_approval", Outcome::Failed).await;
    let sim = h.simulate_pay(AMOUNT).await;
    let result = h
        .commit_pay(h.pay_args(&sim["data"], AMOUNT, Some(h.attest(&sim["data"]))))
        .await;
    assert_eq!(result["ok"], false, "{result}");
    h.assert_send_reserved();
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: 0,
            entries: 0,
            pending: 0
        }
    );
    h.assert_legs("value_action_failed", "payment", Some(AMOUNT));
    assert_eq!(h.simulate_pay(AMOUNT).await["ok"], true);
}

#[tokio::test]
#[serial]
async fn missing_or_invalid_attestation_never_reserves_or_sends() {
    let h = Harness::new(
        "cap-approved-bad-attestation",
        "require_approval",
        Outcome::Success,
    )
    .await;
    let sim = h.simulate_pay(AMOUNT).await;
    let valid = h.attest(&sim["data"]);
    for approval in [
        None,
        Some((
            valid.0.clone(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0; 32]),
        )),
    ] {
        let result = h
            .commit_pay(h.pay_args(&sim["data"], AMOUNT, approval))
            .await;
        assert_eq!(
            result["error"]["code"], "policy.approval_required",
            "{result}"
        );
        assert_eq!(
            h.window(),
            WindowSnapshot {
                amount: 0,
                entries: 0,
                pending: 0
            }
        );
        assert!(h.sends.lock().unwrap().is_empty());
        assert!(
            common::rows_of_kind(&common::audit_rows(&h.profile), "value_action_pending")
                .is_empty()
        );
    }
    assert_eq!(
        h.commit_pay(h.pay_args(&sim["data"], AMOUNT, Some(valid)))
            .await["ok"],
        true
    );
    h.assert_send_reserved();
}

#[tokio::test]
#[serial]
async fn approved_pending_cap_survives_server_restart_and_store_hydration() {
    let mut h = Harness::new("cap-approved-restart", "require_approval", Outcome::Timeout).await;
    let sim = h.simulate_pay(AMOUNT).await;
    assert_eq!(
        h.commit_pay(h.pay_args(&sim["data"], AMOUNT, Some(h.attest(&sim["data"]))))
            .await["error"]["code"],
        "submission.tx_timeout"
    );
    h.assert_send_reserved();
    let restarted =
        WalletServer::new_with_policy_dir_for_test(h.profile.clone(), h.policy_dir.path()).unwrap();
    drop(std::mem::replace(&mut h.server, restarted));
    h.server
        .set_approval_dir_for_test(h.approval_dir.path().to_owned());
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 1
        }
    );
    let refused = h.simulate_pay(50_000_000).await;
    assert_eq!(
        refused["error"]["code"], "policy.deny.per_period_cap_exceeded",
        "{refused}"
    );
    assert_eq!(h.sends.lock().unwrap().len(), 1);
}

#[tokio::test]
#[serial]
async fn approved_sponsored_account_creation_reserves_and_settles() {
    let h = Harness::new("cap-approved-create", "require_approval", Outcome::Success).await;
    let destination = stellar_strkey::ed25519::PublicKey(
        SigningKey::from_bytes(&[0x62; 32])
            .verifying_key()
            .to_bytes(),
    )
    .to_string()
    .to_string();
    let sim_args = json!({"chain_id": "stellar:testnet", "source": h.source, "destination": destination, "starting_balance": "6 XLM"});
    let sim = result_json(
        &h.server
            .call_stellar_create_account(serde_json::from_value(sim_args.clone()).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(sim["ok"], true, "{sim}");
    assert_eq!(h.window().amount, 0);
    let (nonce, attestation) = h.attest(&sim["data"]);
    let mut args = sim_args;
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(attestation);
    let result = result_json(
        &h.server
            .call_stellar_create_account_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(result["ok"], true, "{result}");
    h.assert_send_reserved();
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 0
        }
    );
    h.assert_legs("value_action_pending", "account_creation", Some(AMOUNT));
    h.assert_legs("value_action_submitted", "account_creation", Some(AMOUNT));
}

#[tokio::test]
#[serial]
async fn toolset_forced_approval_keeps_allow_effects_and_reservation() {
    let mut h = Harness::new("cap-toolset-forced", "allow", Outcome::Success).await;
    let tools = tempfile::tempdir().unwrap();
    let tool_dir = tools.path().join("payment-toolset");
    std::fs::create_dir(&tool_dir).unwrap();
    std::fs::write(tool_dir.join(".stellar-agent-toolset-pin.json"), json!({
        "package": "payment-toolset", "version": "1.0.0", "shasum": "a".repeat(64),
        "publisher": h.source, "installed_at": "2026-06-02T00:00:00Z", "capabilities": ["sign-payment"], "allowed_tools": []
    }).to_string()).unwrap();
    let grant_path = tools.path().join("grants.toml");
    let now = now_unix_ms().unwrap();
    let grant = build_attested_grant(
        "payment-toolset".to_owned(),
        "sign-payment".to_owned(),
        DEST.to_owned(),
        "XLM".to_owned(),
        1,
        100_000_000,
        process_uid_for_attestation().unwrap(),
        now,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &ATTESTATION_KEY,
    )
    .unwrap();
    ToolsetGrantStore::open(grant_path.clone(), now)
        .unwrap()
        .insert(grant)
        .unwrap();
    h.server.set_toolsets_root_for_test(tools.path().to_owned());
    h.server.set_grant_store_path_for_test(grant_path);
    let sim = h.simulate_pay(AMOUNT).await;
    assert!(sim["data"]["approval"].is_null());
    let args = h.pay_args(&sim["data"], AMOUNT, None);
    let invoke = |params| StellarToolsetInvokeArgs {
        toolset: "payment-toolset".to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: params,
    };
    let prompt = result_json(
        &h.server
            .call_stellar_toolset_invoke(invoke(pay_json(&args)))
            .await
            .unwrap(),
    );
    assert_eq!(
        prompt["error"]["code"], "policy.approval_required",
        "{prompt}"
    );
    let nonce = {
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let entries = store.snapshot(now_unix_ms().unwrap());
        assert_eq!(entries.len(), 1, "toolset queues per-action approval");
        entries[0].approval_nonce.clone()
    };
    let approval = h.attest_nonce(&nonce, &args.envelope_xdr);
    let result = result_json(
        &h.server
            .call_stellar_toolset_invoke(invoke(pay_json(&h.pay_args(
                &sim["data"],
                AMOUNT,
                Some(approval),
            ))))
            .await
            .unwrap(),
    );
    assert_eq!(result["ok"], true, "{result}");
    h.assert_send_reserved();
    assert_eq!(
        h.window(),
        WindowSnapshot {
            amount: AMOUNT,
            entries: 1,
            pending: 0
        }
    );
    h.assert_legs("value_action_submitted", "payment", Some(AMOUNT));
}

#[tokio::test]
#[serial]
async fn approved_claim_preserves_non_debit_audit_leg() {
    let h = Harness::new("cap-approved-claim", "require_approval", Outcome::Success).await;
    let mut args = json!({"chain_id": "stellar:testnet", "balance_id": "ab".repeat(32), "source_account": h.source});
    let sim = result_json(
        &h.server
            .call_stellar_claim(serde_json::from_value(args.clone()).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(sim["ok"], true, "{sim}");
    let (nonce, attestation) = h.attest(&sim["data"]);
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(attestation);
    let result = result_json(
        &h.server
            .call_stellar_claim_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        *h.sends.lock().unwrap(),
        vec![WindowSnapshot {
            amount: 0,
            entries: 0,
            pending: 0
        }]
    );
    h.assert_legs("value_action_pending", "claim", None);
    h.assert_legs("value_action_submitted", "claim", None);
}

#[tokio::test]
#[serial]
async fn approved_trustline_preserves_non_debit_audit_leg() {
    let h = Harness::new(
        "cap-approved-trustline",
        "require_approval",
        Outcome::Success,
    )
    .await;
    let mut args = json!({"chain_id": "stellar:testnet", "from": h.source, "asset": "USDC", "limit_stroops": "1000000000"});
    let sim = result_json(
        &h.server
            .call_stellar_trustline(serde_json::from_value(args.clone()).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(sim["ok"], true, "{sim}");
    let (nonce, attestation) = h.attest(&sim["data"]);
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(attestation);
    let result = result_json(
        &h.server
            .call_stellar_trustline_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        *h.sends.lock().unwrap(),
        vec![WindowSnapshot {
            amount: 0,
            entries: 0,
            pending: 0
        }]
    );
    h.assert_legs("value_action_pending", "trustline", None);
    h.assert_legs("value_action_submitted", "trustline", None);
}
