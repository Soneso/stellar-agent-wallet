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
    attestation::{compute_attestation_v4, envelope_sha256},
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

const AMOUNT: i128 = 60_000_000;
const ATTESTATION_KEY: [u8; 32] = [0xD2; 32];
const DEST: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
/// A destination whose on-chain home domain no cached `stellar.toml` resolves.
const DOMAIN_DEST: &str = "GBRWGY3DMNRWGY3DMNRWGY3DMNRWGY3DMNRWGY3DMNRWGY3DMNRWHOI2";
const UNRESOLVED_HOME_DOMAIN: &str = "unresolved.example";

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

/// An account entry for `account` whose on-chain `home_domain` is `domain`.
fn home_domain_account_entry(account: &str, domain: &str) -> String {
    use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, String32, WriteXdr};
    let LedgerEntryData::Account(mut entry) = LedgerEntryData::from_xdr_base64(
        account_entry_xdr_with_seq(account, 500_000_000_000, 0, 42),
        Limits::none(),
    )
    .unwrap() else {
        panic!("the account fixture decodes to an account entry");
    };
    entry.home_domain = String32::try_from(domain.as_bytes().to_vec()).unwrap();
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .unwrap()
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
    signer_reads: Arc<AtomicI64>,
    policy_dir: TempDir,
    approval_dir: TempDir,
    rpc: MockServer,
    _root: crate::common::IsolatedDataRoot,
}

impl Harness {
    async fn new(name: &str, decision: &str, outcome: Outcome) -> Self {
        Self::with_approval_fields(name, decision, outcome, "").await
    }

    async fn with_approval_fields(
        name: &str,
        decision: &str,
        outcome: Outcome,
        approval_fields: &str,
    ) -> Self {
        Self::with_policy_chain(name, decision, outcome, approval_fields, "*").await
    }

    async fn with_policy_chain(
        name: &str,
        decision: &str,
        outcome: Outcome,
        approval_fields: &str,
        chain: &str,
    ) -> Self {
        let rules = format!(
            r#"[[rules]]
match = {{ tool = "stellar_transaction_status", chain = "*" }}
criteria = []
decision = "allow"
[[rules]]
match = {{ tool = "*", chain = "{chain}" }}
criteria = [{{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 100000000 }}]
decision = "{decision}"
{approval_fields}
[[rules]]
match = {{ tool = "*", chain = "*" }}
criteria = []
decision = "allow"
"#
        );
        Self::with_rules(name, outcome, &rules).await
    }

    async fn with_rules(name: &str, outcome: Outcome, rules: &str) -> Self {
        let root = crate::common::isolated_data_root();
        let signer_reads = Arc::new(AtomicI64::new(0));
        let observed_reads = Arc::clone(&signer_reads);
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            "svc",
            name,
            Arc::new(move || {
                observed_reads.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .expect("hooked mock keyring");
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
        let mut profile = crate::common::timeout_profile(&rpc.uri(), name);
        profile.policy.engine = PolicyEngineKind::V1;
        seed_key(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
            &ATTESTATION_KEY,
        );
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

        let body = format!("version = 1\nscope = \"profile:{name}\"\n{rules}");
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
        let responder = crate::common::TimeoutRpc::new(vec![
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
            (
                account_ledger_key_xdr(DOMAIN_DEST),
                home_domain_account_entry(DOMAIN_DEST, UNRESOLVED_HOME_DOMAIN),
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
            signer_reads,
            policy_dir,
            approval_dir,
            rpc,
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
        let mut store = PendingApprovalStore::open(
            self.approval_dir.path().join(format!("{}.toml", self.name)),
        )
        .unwrap();
        let stored = store.get(nonce).unwrap().clone();
        let blob = compute_attestation_v4(
            &ATTESTATION_KEY,
            &stellar_agent_core::approval::AttestationBinding::new(
                &self.name,
                self.profile.chain_id.caip2_str(),
            ),
            nonce,
            &envelope_sha256(envelope.as_bytes()),
            &process_uid_for_attestation().unwrap(),
            &stored.attested_lifetime(),
            &stellar_agent_core::approval::AttestedApprover::Local,
        );
        store
            .record_attestation(
                nonce,
                blob,
                stellar_agent_core::approval::AttestedApprover::Local,
            )
            .unwrap();
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
        let rows = crate::common::audit_rows(&self.profile);
        let selected = crate::common::rows_of_kind(&rows, kind);
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
async fn approval_above_payment_gate_pending_reason_and_approval_round_trip() {
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    let rules = ["stellar_pay", "stellar_pay_commit"]
        .map(|tool| {
            format!(
                r#"
[[rules]]
match = {{ tool = "{tool}", chain = "*" }}
criteria = [
    {{ kind = "approval_above", asset = "native", max_stroops = 100 }},
    {{ kind = "per_tx_cap", asset = "native", max_stroops = 500 }},
]
decision = "allow"
"#
            )
        })
        .join("\n");
    let h = Harness::with_rules("approval-above", Outcome::Success, &rules).await;

    let small = h.simulate_pay(25).await;
    assert_eq!(small["ok"], true, "{small}");
    assert!(small["data"].get("approval").is_none(), "{small}");

    let large = h.simulate_pay(600).await;
    assert_eq!(
        large["error"]["code"], "policy.deny.per_tx_cap_exceeded",
        "{large}"
    );
    assert!(h.sends.lock().unwrap().is_empty());

    let sim = h.simulate_pay(150).await;
    assert_eq!(sim["ok"], true, "{sim}");
    assert_eq!(h.signer_reads.load(Ordering::SeqCst), 0);
    let envelope = TransactionEnvelope::from_xdr_base64(
        sim["data"]["envelope_xdr"].as_str().unwrap(),
        Limits::none(),
    )
    .unwrap();
    let TransactionEnvelope::Tx(unsigned) = envelope else {
        panic!("payment simulation returns a v1 envelope");
    };
    assert!(unsigned.signatures.is_empty());
    let nonce = sim["data"]["approval"]["approval_nonce"].as_str().unwrap();
    let reason = "approval_above: 150 stroops of native exceeds threshold 100 stroops";
    assert_eq!(sim["data"]["approval"]["reason"], reason);
    {
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let pending = store
            .get(nonce)
            .expect("escalation persists a pending approval");
        assert_eq!(pending.reason.as_deref(), Some(reason));
    }
    let unapproved = h.commit_pay(h.pay_args(&sim["data"], 150, None)).await;
    assert_eq!(
        unapproved["error"]["code"], "policy.approval_required",
        "{unapproved}"
    );
    assert!(h.sends.lock().unwrap().is_empty());

    assert_eq!(h.signer_reads.load(Ordering::SeqCst), 0);

    let approved = h.attest(&sim["data"]);
    let result = h
        .commit_pay(h.pay_args(&sim["data"], 150, Some(approved)))
        .await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(h.sends.lock().unwrap().len(), 1);
    assert!(h.signer_reads.load(Ordering::SeqCst) > 0);
    let requests = h.rpc.received_requests().await.unwrap();
    let submissions: Vec<Value> = requests
        .iter()
        .map(|request| serde_json::from_slice::<Value>(&request.body).unwrap())
        .filter(|body| body["method"] == "sendTransaction")
        .collect();
    assert_eq!(submissions.len(), 1);
    let envelope = TransactionEnvelope::from_xdr_base64(
        submissions[0]["params"]["transaction"].as_str().unwrap(),
        Limits::none(),
    )
    .unwrap();
    let TransactionEnvelope::Tx(signed) = envelope else {
        panic!("payment submission carries a v1 envelope");
    };
    assert_eq!(signed.tx, unsigned.tx);
    assert_eq!(signed.signatures.len(), 1);
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
        crate::common::rows_of_kind(
            &crate::common::audit_rows(&h.profile),
            "value_action_submitted"
        )
        .is_empty()
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
    let rows = crate::common::audit_rows(&h.profile);
    let submitted = crate::common::rows_of_kind(&rows, "value_action_submitted");
    assert_eq!(submitted[0]["policy_decision"], "require_approval");
    assert_eq!(
        submitted[0]["approval_nonce"],
        sim["data"]["approval"]["approval_nonce"]
    );
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
            crate::common::rows_of_kind(
                &crate::common::audit_rows(&h.profile),
                "value_action_pending"
            )
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
    let mut h = Harness::with_policy_chain(
        "cap-toolset-forced",
        "allow",
        Outcome::Success,
        "",
        "stellar:testnet",
    )
    .await;
    let tools = tempfile::tempdir().unwrap();
    stellar_agent_toolsets_install::write_toolset_for_test(
        tools.path(),
        "payment-toolset",
        &["sign-payment"],
        &[],
        "2026-06-02T00:00:00Z",
        &crate::common::toolset_pin_key(),
    )
    .unwrap();
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
        &stellar_agent_core::approval::AttestationBinding::new(&h.name, "stellar:testnet"),
    )
    .unwrap();
    ToolsetGrantStore::open(grant_path.clone(), now)
        .unwrap()
        .insert(grant)
        .unwrap();
    h.server.set_toolsets_root_for_test(tools.path().to_owned());
    h.server
        .set_toolset_pin_key_for_test(crate::common::toolset_pin_key());
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
    for candidate in [nonce.clone(), "A".repeat(22)] {
        let invalid = h.pay_args(
            &sim["data"],
            AMOUNT,
            Some((candidate, "invalid".to_owned())),
        );
        let refusal = result_json(
            &h.server
                .call_stellar_toolset_invoke(invoke(pay_json(&invalid)))
                .await
                .unwrap(),
        );
        assert_eq!(refusal["error"], prompt["error"], "{refusal}");
    }
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
    {
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let nonce = sim["data"]["approval"]["approval_nonce"].as_str().unwrap();
        assert!(matches!(
            store.get(nonce).unwrap().kind,
            stellar_agent_core::approval::ApprovalKind::TrustlineSimulated {
                summary_limit_stroops: Some(1_000_000_000),
                ..
            }
        ));
    }
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
    let rows = crate::common::audit_rows(&h.profile);
    for kind in ["value_action_pending", "value_action_submitted"] {
        let row = crate::common::rows_of_kind(&rows, kind)[0];
        assert_eq!(
            row["legs"][0]["asset"],
            format!("USDC:{USDC_ISSUER}"),
            "{kind}: {row}"
        );
    }
}

/// Submission rows retain the decision and approval binding of the gate.
#[tokio::test]
#[serial]
async fn submission_rows_preserve_allowed_and_approved_decisions() {
    for decision in ["allow", "require_approval"] {
        for (suffix, outcome, final_kind) in [
            ("success", Outcome::Success, "value_action_submitted"),
            ("failed", Outcome::Failed, "value_action_failed"),
        ] {
            let name = format!("audit-decision-{decision}-{suffix}");
            let h = Harness::new(&name, decision, outcome).await;
            let simulation = h.simulate_pay(AMOUNT).await;
            let approval = if decision == "require_approval" {
                Some(h.attest(&simulation["data"]))
            } else {
                None
            };
            let expected_nonce = approval.as_ref().map(|(nonce, _)| nonce.clone());
            let result = h
                .commit_pay(h.pay_args(&simulation["data"], AMOUNT, approval))
                .await;
            assert_eq!(result["ok"], suffix == "success", "{result}");
            let rows = crate::common::audit_rows(&h.profile);
            for kind in ["value_action_pending", final_kind] {
                let matching = crate::common::rows_of_kind(&rows, kind);
                assert_eq!(matching.len(), 1, "{kind}: {rows:?}");
                let row = &matching[0];
                assert_eq!(row["policy_decision"], decision, "{row}");
                assert_eq!(
                    row["approval_nonce"],
                    serde_json::to_value(&expected_nonce).unwrap(),
                    "{row}"
                );
                if expected_nonce.is_none() {
                    assert!(row.get("approval_nonce").is_none(), "{row}");
                }
                assert!(
                    row.get("event_kind").is_none(),
                    "event fields are flattened: {row}"
                );
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn rule_approval_shape_reaches_pending_and_response() {
    for (fields, ttl) in [
        ("ttl_secs = 617\nreason = \"Treasury review\"", 617_000),
        ("reason = \"Treasury review\"", 86_400_000),
    ] {
        let h = Harness::with_approval_fields(
            "rule-shape",
            "require_approval",
            Outcome::Success,
            fields,
        )
        .await;
        let destination = stellar_strkey::ed25519::PublicKey(
            SigningKey::from_bytes(&[0x62; 32])
                .verifying_key()
                .to_bytes(),
        )
        .to_string()
        .to_string();
        let responses = [
            h.simulate_pay(AMOUNT).await,
            result_json(&h.server.call_stellar_create_account(serde_json::from_value(json!({"chain_id":"stellar:testnet", "source":h.source,"destination":destination,"starting_balance":"6 XLM"})).unwrap()).await.unwrap()),
            result_json(&h.server.call_stellar_claim(serde_json::from_value(json!({"chain_id":"stellar:testnet","balance_id":"ab".repeat(32),"source_account":h.source})).unwrap()).await.unwrap()),
            result_json(&h.server.call_stellar_trustline(serde_json::from_value(json!({"chain_id":"stellar:testnet","from":h.source,"asset":"USDC","limit_stroops":"1000000000"})).unwrap()).await.unwrap()),
        ];
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        for response in responses {
            assert_eq!(response["ok"], true, "{response}");
            let approval = &response["data"]["approval"];
            let nonce = approval["approval_nonce"].as_str().unwrap();
            let pending = store.get(nonce).unwrap();
            assert_eq!(pending.expires_at_unix_ms - pending.created_at_unix_ms, ttl);
            assert_eq!(approval["expires_at_unix_ms"], pending.expires_at_unix_ms);
            assert_eq!(pending.reason.as_deref(), Some("Treasury review"));
            assert_eq!(approval["reason"], "Treasury review");
            assert_eq!(approval["profile"], h.name);
            assert_eq!(approval["chain_id"], h.profile.chain_id.caip2_str());
            let request = pending.approval_request();
            assert_eq!(request.nonce, nonce);
            assert_eq!(u64::from(request.ttl_seconds) * 1_000, ttl);
            assert_eq!(request.reason, pending.reason);
        }
    }
}

/// An allowed submission records and spends no approval the gate did not verify.
#[tokio::test]
#[serial]
async fn allowed_submission_ignores_an_unverified_approval_nonce() {
    let h = Harness::new(
        "audit-decision-allow-stray-nonce",
        "allow",
        Outcome::Success,
    )
    .await;
    let simulation = h.simulate_pay(AMOUNT).await;
    let stray = Some(("A".repeat(22), "unverified".to_owned()));
    let result = h
        .commit_pay(h.pay_args(&simulation["data"], AMOUNT, stray))
        .await;
    assert_eq!(result["ok"], true, "{result}");
    let rows = crate::common::audit_rows(&h.profile);
    for kind in ["value_action_pending", "value_action_submitted"] {
        let matching = crate::common::rows_of_kind(&rows, kind);
        assert_eq!(matching.len(), 1, "{kind}: {rows:?}");
        assert_eq!(matching[0]["policy_decision"], "allow", "{}", matching[0]);
        assert!(
            matching[0].get("approval_nonce").is_none(),
            "{}",
            matching[0]
        );
    }
}

/// A requiring rule's lifetime bounds a toolset-queued approval at commit.
#[tokio::test]
#[serial]
async fn rule_ttl_bounds_toolset_queued_approval_at_commit() {
    let mut h = Harness::with_approval_fields(
        "cap-toolset-rule-ttl",
        "require_approval",
        Outcome::Success,
        "ttl_secs = 1",
    )
    .await;
    let tools = tempfile::tempdir().unwrap();
    stellar_agent_toolsets_install::write_toolset_for_test(
        tools.path(),
        "payment-toolset",
        &["sign-payment"],
        &[],
        "2026-06-02T00:00:00Z",
        &crate::common::toolset_pin_key(),
    )
    .unwrap();
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
        &stellar_agent_core::approval::AttestationBinding::new(&h.name, "stellar:testnet"),
    )
    .unwrap();
    ToolsetGrantStore::open(grant_path.clone(), now)
        .unwrap()
        .insert(grant)
        .unwrap();
    h.server.set_toolsets_root_for_test(tools.path().to_owned());
    h.server
        .set_toolset_pin_key_for_test(crate::common::toolset_pin_key());
    h.server.set_grant_store_path_for_test(grant_path);
    let sim = h.simulate_pay(AMOUNT).await;
    let rule_nonce = sim["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
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
        let mut store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let queued: Vec<_> = store
            .snapshot(now_unix_ms().unwrap())
            .into_iter()
            .filter(|entry| entry.approval_nonce != rule_nonce)
            .collect();
        assert_eq!(queued.len(), 1, "toolset queues per-action approval");
        assert!(
            !queued[0].expired,
            "the toolset entry carries its own expiry"
        );
        let nonce = queued[0].approval_nonce.clone();
        let now = now_unix_ms().unwrap();
        let mut entry = store.get(&nonce).unwrap().clone();
        entry.created_at_unix_ms = now - 2_000;
        assert!(!entry.is_expired(now), "the stored expiry remains live");
        assert!(store.remove(&nonce).unwrap());
        store.insert(entry, now).unwrap();
        nonce
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
    assert_eq!(result["error"], prompt["error"], "{result}");
    let rows = crate::common::audit_rows(&h.profile);
    assert!(
        crate::common::rows_of_kind(&rows, "value_action_pending").is_empty(),
        "{rows:?}"
    );
}

#[tokio::test]
#[serial]
async fn profile_chain_approval_preserves_nonce_and_consumes_attestation() {
    let h = Harness::with_policy_chain(
        "chain-approval",
        "require_approval",
        Outcome::Success,
        "",
        "stellar:testnet",
    )
    .await;
    let amount = 20_000_000;
    let sim = h.simulate_pay(amount).await;
    assert_eq!(sim["ok"], true, "{sim}");
    let data = &sim["data"];
    let approval_nonce = data["approval"]["approval_nonce"]
        .as_str()
        .expect("pending approval");
    let store_path = h.approval_dir.path().join(format!("{}.toml", h.name));
    let pending = PendingApprovalStore::open(store_path.clone()).expect("pending store");
    assert_eq!(pending.snapshot(now_unix_ms().expect("clock")).len(), 1);
    drop(pending);

    let args = h.pay_args(data, amount, None);
    let commit_nonce = args.nonce.clone();
    let reads_before_commit = h.signer_reads.load(Ordering::SeqCst);
    let refusal = h.commit_pay(args).await;
    assert_eq!(
        refusal["error"]["code"], "policy.approval_required",
        "{refusal}"
    );
    assert!(h.sends.lock().expect("sends").is_empty());
    assert_eq!(h.window().entries, 0);
    assert_eq!(h.signer_reads.load(Ordering::SeqCst), reads_before_commit);
    assert!(
        crate::common::rows_of_kind(
            &crate::common::audit_rows(&h.profile),
            "value_action_submitted"
        )
        .is_empty()
    );

    let approval = h.attest(data);
    let retry = h.pay_args(data, amount, Some(approval.clone()));
    assert_eq!(retry.nonce, commit_nonce);
    let result = h.commit_pay(retry).await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(h.window().amount, amount);
    assert!(h.signer_reads.load(Ordering::SeqCst) > reads_before_commit);
    h.assert_legs("value_action_submitted", "payment", Some(amount));
    let rows = crate::common::audit_rows(&h.profile);
    let submitted = crate::common::rows_of_kind(&rows, "value_action_submitted");
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0]["chain_id"], h.profile.chain_id.caip2_str());
    assert_eq!(submitted[0]["policy_decision"], "require_approval");
    assert_eq!(submitted[0]["approval_nonce"], approval_nonce);
    assert_eq!(submitted[0]["legs"][0]["asset"], "native");
    assert_eq!(
        submitted[0]["legs"][0]["destination_redacted"],
        stellar_agent_core::observability::redact_strkey_first5_last5(DEST)
    );
    let consumed = PendingApprovalStore::open(store_path).expect("consumed approval store");
    assert!(matches!(
        consumed
            .get(approval_nonce)
            .expect("approval tombstone")
            .kind,
        stellar_agent_core::approval::ApprovalKind::Consumed { .. }
    ));

    drop(consumed);
    let second = h.simulate_pay(amount).await;
    assert_eq!(second["ok"], true, "cap headroom: {second}");
    let second_args = h.pay_args(&second["data"], amount, Some(approval));
    assert_ne!(second_args.nonce, commit_nonce);
    let refused = h.commit_pay(second_args).await;
    assert_eq!(
        refused["error"]["code"], "policy.approval_consumed",
        "{refused}"
    );
    assert_eq!(h.sends.lock().expect("sends").len(), 1);
}

#[tokio::test]
#[serial]
async fn profile_chain_payment_accounting_persists_cap() {
    let h = Harness::with_policy_chain(
        "chain-payment",
        "allow",
        Outcome::Success,
        "",
        "stellar:testnet",
    )
    .await;
    let sim = h.simulate_pay(AMOUNT).await;
    assert_eq!(sim["ok"], true, "{sim}");
    let result = h.commit_pay(h.pay_args(&sim["data"], AMOUNT, None)).await;
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
    let second = h.simulate_pay(AMOUNT).await;
    assert_eq!(
        second["error"]["code"], "policy.deny.per_period_cap_exceeded",
        "{second}"
    );
    assert_eq!(h.sends.lock().expect("sends").len(), 1);
}

#[tokio::test]
#[serial]
async fn trustline_simulate_persists_each_limit() {
    use stellar_agent_core::approval::ApprovalKind;
    for (limit, expected_limit) in [
        (None, None),
        (Some(0), Some(0)),
        (Some(1_000_000_000_i64), Some(1_000_000_000)),
        (Some(i64::MAX), None),
    ] {
        let h = Harness::new(
            "trustline-limit-record",
            "require_approval",
            Outcome::Success,
        )
        .await;
        let mut args = json!({"chain_id":"stellar:testnet", "from":h.source, "asset":"USDC"});
        if let Some(limit) = limit {
            args["limit_stroops"] = json!(limit.to_string());
        }
        let sim = result_json(
            &h.server
                .call_stellar_trustline(serde_json::from_value(args).unwrap())
                .await
                .unwrap(),
        );
        assert_eq!(sim["ok"], true, "{sim}");
        let nonce = sim["data"]["approval"]["approval_nonce"].as_str().unwrap();
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let ApprovalKind::TrustlineSimulated {
            summary_holder,
            summary_asset_code,
            summary_asset_issuer,
            summary_limit_stroops,
            envelope_sha256_hex,
            ..
        } = &store.get(nonce).unwrap().kind
        else {
            panic!("trustline record")
        };
        assert_eq!(summary_holder, &h.source);
        assert_eq!(summary_asset_code, "USDC");
        assert_eq!(summary_asset_issuer, USDC_ISSUER);
        assert_eq!(*summary_limit_stroops, expected_limit);
        assert_eq!(
            envelope_sha256_hex,
            &hex::encode(envelope_sha256(
                sim["data"]["envelope_xdr"].as_str().unwrap().as_bytes()
            ))
        );
    }
}

#[tokio::test]
#[serial]
async fn trustline_commit_refuses_payment_approval_for_same_envelope() {
    use stellar_agent_core::approval::{DEFAULT_TTL_MS, PendingApproval};
    let h = Harness::new(
        "trustline-payment-refusal",
        "require_approval",
        Outcome::Success,
    )
    .await;
    let mut args = json!({"chain_id":"stellar:testnet", "from":h.source, "asset":"USDC", "limit_stroops":"1000000000"});
    let sim = result_json(
        &h.server
            .call_stellar_trustline(serde_json::from_value(args.clone()).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(sim["ok"], true, "{sim}");
    let envelope = sim["data"]["envelope_xdr"].as_str().unwrap();
    let entry = PendingApproval::new_payment_pending(
        envelope.to_owned(),
        envelope.as_bytes(),
        h.source.clone(),
        1_000_000_000,
        format!("USDC:{USDC_ISSUER}"),
        None,
        100,
        1,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    {
        let mut store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        store.insert(entry, now_unix_ms().unwrap()).unwrap();
    }
    let (nonce, blob) = h.attest_nonce(&nonce, envelope);
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    args["approval_nonce"] = json!(nonce);
    args["approval_attestation"] = json!(blob);
    let result = result_json(
        &h.server
            .call_stellar_trustline_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(
        result["error"]["code"], "policy.approval_required",
        "{result}"
    );
    assert!(h.sends.lock().unwrap().is_empty());
}

#[derive(Clone, Copy, Debug)]
enum ClassicPair {
    Pay,
    CreateAccount,
    Trustline,
    Claim,
}

impl ClassicPair {
    fn tool(self) -> &'static str {
        match self {
            Self::Pay => "stellar_pay",
            Self::CreateAccount => "stellar_create_account",
            Self::Trustline => "stellar_trustline",
            Self::Claim => "stellar_claim",
        }
    }

    fn args(self, h: &Harness) -> Value {
        match self {
            Self::Pay => json!({"chain_id":"stellar:testnet", "source":h.source,
                "destination":DEST, "asset":"native", "amount_in_stroops":AMOUNT.to_string()}),
            Self::CreateAccount => json!({"chain_id":"stellar:testnet", "source":h.source,
                "destination":stellar_strkey::ed25519::PublicKey([0x62; 32]).to_string().to_string(),
                "starting_balance":"6 XLM"}),
            Self::Trustline => json!({"chain_id":"stellar:testnet", "from":h.source,
                "asset":"USDC", "limit_stroops":"1000000000"}),
            Self::Claim => json!({"chain_id":"stellar:testnet", "source_account":h.source,
                "balance_id":"ab".repeat(32)}),
        }
    }

    async fn simulate(self, h: &Harness) -> Value {
        let args = self.args(h);
        let result = match self {
            Self::Pay => {
                h.server
                    .call_stellar_pay(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::CreateAccount => {
                h.server
                    .call_stellar_create_account(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Trustline => {
                h.server
                    .call_stellar_trustline(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Claim => {
                h.server
                    .call_stellar_claim(serde_json::from_value(args).unwrap())
                    .await
            }
        }
        .unwrap();
        result_json(&result)
    }

    async fn commit(self, h: &Harness, data: &Value, approval: Option<(String, String)>) -> Value {
        let mut args = self.args(h);
        for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
            args[field] = data[field].clone();
        }
        if let Some((nonce, attestation)) = approval {
            args["approval_nonce"] = json!(nonce);
            args["approval_attestation"] = json!(attestation);
        }
        let result = match self {
            Self::Pay => {
                h.server
                    .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::CreateAccount => {
                h.server
                    .call_stellar_create_account_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Trustline => {
                h.server
                    .call_stellar_trustline_commit(serde_json::from_value(args).unwrap())
                    .await
            }
            Self::Claim => {
                h.server
                    .call_stellar_claim_commit(serde_json::from_value(args).unwrap())
                    .await
            }
        }
        .unwrap();
        result_json(&result)
    }

    fn assert_pending(self, h: &Harness, data: &Value, ttl: u64, reason: &str) {
        use stellar_agent_core::approval::ApprovalKind;
        let store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let approval = &data["approval"];
        let nonce = approval["approval_nonce"]
            .as_str()
            .expect("paired commit requests approval");
        let entry = store.get(nonce).expect("pending approval is durable");
        let digest = match (self, &entry.kind) {
            (
                Self::Pay | Self::CreateAccount,
                ApprovalKind::PaymentSimulated {
                    envelope_sha256_hex,
                    ..
                },
            )
            | (
                Self::Trustline,
                ApprovalKind::TrustlineSimulated {
                    envelope_sha256_hex,
                    ..
                },
            )
            | (
                Self::Claim,
                ApprovalKind::ClaimSimulated {
                    envelope_sha256_hex,
                    ..
                },
            ) => envelope_sha256_hex,
            _ => panic!("wrong approval kind for {self:?}: {:?}", entry.kind),
        };
        assert_eq!(
            digest,
            &hex::encode(envelope_sha256(
                data["envelope_xdr"].as_str().unwrap().as_bytes()
            ))
        );
        assert_eq!(entry.expires_at_unix_ms - entry.created_at_unix_ms, ttl);
        assert_eq!(entry.reason.as_deref(), Some(reason));
        assert_eq!(approval["reason"], reason);
        assert_eq!(approval["expires_at_unix_ms"], entry.expires_at_unix_ms);
        assert_eq!(approval["profile"], h.name);
        assert_eq!(approval["chain_id"], "stellar:testnet");
        assert!(approval["summary"].is_object());
    }
}

const CLASSIC_PAIRS: [ClassicPair; 4] = [
    ClassicPair::Pay,
    ClassicPair::CreateAccount,
    ClassicPair::Trustline,
    ClassicPair::Claim,
];
const CAP: &str =
    r#"{ kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 100000000 }"#;

fn split_rules(pair: ClassicPair, simulate: &str, commit: &str, commit_criteria: &str) -> String {
    let tool = pair.tool();
    let simulate_criteria = if matches!(pair, ClassicPair::Pay) {
        CAP
    } else {
        ""
    };
    let simulate_fields = if simulate == "require_approval" {
        "ttl_secs = 419\nreason = \"Simulate review\""
    } else {
        ""
    };
    let commit_fields = if commit == "require_approval" {
        "ttl_secs = 617\nreason = \"Commit review\""
    } else {
        ""
    };
    format!(
        r#"[[rules]]
match = {{ tool = "{tool}", chain = "stellar:testnet" }}
criteria = [{simulate_criteria}]
decision = "{simulate}"
{simulate_fields}
[[rules]]
match = {{ tool = "*", chain = "*" }}
criteria = [{commit_criteria}]
decision = "{commit}"
{commit_fields}
"#
    )
}

async fn split_approval_round_trip(pair: ClassicPair) {
    let h = Harness::with_rules(
        pair.tool(),
        Outcome::Success,
        &split_rules(pair, "allow", "require_approval", ""),
    )
    .await;
    let sim = pair.simulate(&h).await;
    assert_eq!(sim["ok"], true, "{sim}");
    pair.assert_pending(&h, &sim["data"], 617_000, "Commit review");
    assert_eq!(h.window().pending, 0);
    let data = &sim["data"];
    let nonce = data["approval"]["approval_nonce"].as_str().unwrap();
    let expired = {
        let mut store =
            PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name)))
                .unwrap();
        let mut entry = store.get(nonce).unwrap().clone();
        entry.approval_nonce = "E".repeat(22);
        entry.expires_at_unix_ms = entry.created_at_unix_ms;
        let blob = compute_attestation_v4(
            &ATTESTATION_KEY,
            &stellar_agent_core::approval::AttestationBinding::new(&h.name, "stellar:testnet"),
            &entry.approval_nonce,
            &envelope_sha256(data["envelope_xdr"].as_str().unwrap().as_bytes()),
            &process_uid_for_attestation().unwrap(),
            &entry.attested_lifetime(),
            &stellar_agent_core::approval::AttestedApprover::Local,
        );
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob);
        entry.attestation_blob_b64 = Some(encoded.clone());
        entry.attested_approver = Some(stellar_agent_core::approval::AttestedApprover::Local);
        let approval = (entry.approval_nonce.clone(), encoded);
        store.insert(entry, now_unix_ms().unwrap()).unwrap();
        approval
    };
    let mut errors = Vec::new();
    for approval in [
        None,
        Some((
            nonce.to_owned(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0; 32]),
        )),
        Some(expired),
    ] {
        let result = pair.commit(&h, data, approval).await;
        assert_eq!(
            result["error"]["code"], "policy.approval_required",
            "{result}"
        );
        assert_eq!(
            result["error"]["message"],
            format!(
                "approval attestation absent, invalid, or expired; run `{}` then re-submit with attestation",
                stellar_agent_core::approval::approve_hint("<nonce>", &h.name)
            )
        );
        assert!(result["error"].get("details").is_none(), "{result}");
        errors.push(result["error"].clone());
    }
    assert!(errors.windows(2).all(|adjacent| adjacent[0] == adjacent[1]));
    assert!(h.sends.lock().unwrap().is_empty());
    let approved = h.attest_nonce(nonce, data["envelope_xdr"].as_str().unwrap());
    let result = pair.commit(&h, data, Some(approved)).await;
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        *h.sends.lock().unwrap(),
        vec![WindowSnapshot {
            amount: 0,
            entries: 0,
            pending: 0
        }]
    );
    assert_eq!(h.window().pending, 0);
    let (action, amount) = match pair {
        ClassicPair::Pay => ("payment", Some(AMOUNT)),
        ClassicPair::CreateAccount => ("account_creation", Some(AMOUNT)),
        ClassicPair::Trustline => ("trustline", None),
        ClassicPair::Claim => ("claim", None),
    };
    h.assert_legs("value_action_submitted", action, amount);
}

#[tokio::test]
#[serial]
async fn split_pay_approval_round_trip() {
    split_approval_round_trip(ClassicPair::Pay).await;
}

#[tokio::test]
#[serial]
async fn split_create_account_approval_round_trip() {
    split_approval_round_trip(ClassicPair::CreateAccount).await;
}

#[tokio::test]
#[serial]
async fn split_trustline_approval_round_trip() {
    split_approval_round_trip(ClassicPair::Trustline).await;
}

#[tokio::test]
#[serial]
async fn split_claim_approval_round_trip() {
    split_approval_round_trip(ClassicPair::Claim).await;
}

#[tokio::test]
#[serial]
async fn split_pay_approval_commit_cap_reserves_and_settles() {
    let h = Harness::with_rules(
        "split-cap",
        Outcome::Success,
        &split_rules(ClassicPair::Pay, "allow", "require_approval", CAP),
    )
    .await;
    let sim = h.simulate_pay(AMOUNT).await;
    ClassicPair::Pay.assert_pending(&h, &sim["data"], 617_000, "Commit review");
    let result = h
        .commit_pay(h.pay_args(&sim["data"], AMOUNT, Some(h.attest(&sim["data"]))))
        .await;
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
}

#[tokio::test]
#[serial]
async fn split_approval_verdict_matrix_preserves_simulate_precedence() {
    for pair in CLASSIC_PAIRS {
        for (simulate, commit) in [
            ("allow", "allow"),
            ("allow", "deny"),
            ("require_approval", "allow"),
            ("require_approval", "require_approval"),
            ("deny", "require_approval"),
        ] {
            let h = Harness::with_rules(
                "split-matrix",
                Outcome::Success,
                &split_rules(pair, simulate, commit, ""),
            )
            .await;
            let result = pair.simulate(&h).await;
            assert_eq!(
                result["ok"],
                simulate != "deny",
                "{pair:?} {simulate}/{commit}: {result}"
            );
            if simulate == "require_approval" {
                pair.assert_pending(&h, &result["data"], 419_000, "Simulate review");
            } else {
                assert!(result["data"].get("approval").is_none(), "{result}");
                let store = PendingApprovalStore::open(
                    h.approval_dir.path().join(format!("{}.toml", h.name)),
                )
                .unwrap();
                assert!(store.snapshot(now_unix_ms().unwrap()).is_empty());
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn split_pay_approval_uses_destination_identity_view() {
    let h = Harness::with_rules(
        "split-identity",
        Outcome::Success,
        &split_rules(
            ClassicPair::Pay,
            "allow",
            "require_approval",
            r#"{ kind = "home_domain_resolved" }"#,
        ),
    )
    .await;
    let sim = h.simulate_pay(AMOUNT).await;
    assert_eq!(sim["ok"], true, "{sim}");
    ClassicPair::Pay.assert_pending(&h, &sim["data"], 617_000, "Commit review");

    // The source has no home domain and this destination has an unresolved one,
    // so only the destination's identity view makes the commit refuse.
    let mut args = ClassicPair::Pay.args(&h);
    args["destination"] = json!(DOMAIN_DEST);
    let sim = result_json(
        &h.server
            .call_stellar_pay(serde_json::from_value(args.clone()).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(sim["ok"], true, "{sim}");
    assert!(sim["data"].get("approval").is_none(), "{sim}");
    let store =
        PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name))).unwrap();
    assert_eq!(store.snapshot(now_unix_ms().unwrap()).len(), 1);
    drop(store);
    for field in ["nonce", "expires_at_unix_ms", "envelope_xdr"] {
        args[field] = sim["data"][field].clone();
    }
    let result = result_json(
        &h.server
            .call_stellar_pay_commit(serde_json::from_value(args).unwrap())
            .await
            .unwrap(),
    );
    assert_eq!(
        result["error"]["code"], "policy.deny.home_domain_not_resolved",
        "{result}"
    );
    assert!(h.sends.lock().unwrap().is_empty());
}

#[tokio::test]
#[serial]
async fn split_trustline_approval_uses_decoded_issuer() {
    let criteria = format!(
        r#"{{ kind = "counterparty_allowlist", kinds = ["KNOWN_ISSUER"], allowlist = ["{USDC_ISSUER}"], gate_inflows = true }}"#
    );
    let h = Harness::with_rules(
        "split-issuer",
        Outcome::Success,
        &split_rules(
            ClassicPair::Trustline,
            "allow",
            "require_approval",
            &criteria,
        ),
    )
    .await;
    for issuer in [USDC_ISSUER, DEST] {
        let mut args = ClassicPair::Trustline.args(&h);
        args["asset"] = json!(format!("TEST:{issuer}"));
        let sim = result_json(
            &h.server
                .call_stellar_trustline(serde_json::from_value(args).unwrap())
                .await
                .unwrap(),
        );
        assert_eq!(sim["ok"], true, "{sim}");
        if issuer == USDC_ISSUER {
            ClassicPair::Trustline.assert_pending(&h, &sim["data"], 617_000, "Commit review");
        } else {
            assert!(sim["data"].get("approval").is_none(), "{sim}");
        }
    }
    let store =
        PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name))).unwrap();
    assert_eq!(store.snapshot(now_unix_ms().unwrap()).len(), 1);
}

#[tokio::test]
#[serial]
async fn split_approval_reconciles_only_one_bounded_pass() {
    use stellar_agent_core::policy::v1::criteria::state_store::{WindowEntry, WindowLimit};
    use stellar_agent_network::policy_state::{RECONCILE_MIN_AGE_MS, SubmissionHold};
    let h = Harness::with_rules(
        "split-reconcile",
        Outcome::Success,
        &split_rules(ClassicPair::Pay, "allow", "require_approval", ""),
    )
    .await;
    let disk = PersistedWindowStore::for_profile(&h.name);
    let old = now_unix_ms().unwrap() - RECONCILE_MIN_AGE_MS - 1_000;
    let receipts = ReceiptStore::open(&h.name).unwrap();
    for index in 0..6 {
        let id = format!("{index:064x}");
        let reservation = SubmissionHold {
            id: id.clone(),
            tx_hash: id.clone(),
            source: h.source.clone(),
            sequence: 30 + index,
            max_time: 0,
            pending_since_ms: old,
            submission_ledger: 1000,
            operator_required: false,
        };
        let entry = WindowEntry::new(
            StateKey::new(&h.name, 0, "native", 86_400),
            old,
            1,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: 100_000_000,
            },
        );
        disk.record_pending(&h.profile, &[entry], &reservation)
            .unwrap();
        receipts
            .try_begin(&id, &id, &h.source, reservation.sequence, 0, 1000)
            .unwrap();
    }
    let sim = h.simulate_pay(AMOUNT).await;
    assert_eq!(sim["ok"], true, "{sim}");
    ClassicPair::Pay.assert_pending(&h, &sim["data"], 617_000, "Commit review");
    let requests = h.rpc.received_requests().await.unwrap();
    let statuses = requests
        .iter()
        .filter(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["method"] == "getTransaction"
        })
        .count();
    assert_eq!(
        statuses, 5,
        "one simulate dispatch reconciles at most five reservations"
    );
    assert_eq!(disk.pending_reservations(&h.profile).unwrap().len(), 1);
}

#[tokio::test]
#[serial]
async fn split_approval_commit_evaluation_error_leaves_simulate_allowed() {
    let pair = ClassicPair::CreateAccount;
    let h = Harness::with_rules(
        "split-eval-error",
        Outcome::Success,
        &split_rules(
            pair,
            "allow",
            "require_approval",
            r#"{ kind = "home_domain_resolved" }"#,
        ),
    )
    .await;
    let sim = pair.simulate(&h).await;
    assert_eq!(sim["ok"], true, "{sim}");
    assert!(sim["data"].get("approval").is_none(), "{sim}");
    let store =
        PendingApprovalStore::open(h.approval_dir.path().join(format!("{}.toml", h.name))).unwrap();
    assert!(store.snapshot(now_unix_ms().unwrap()).is_empty());
    drop(store);
    let result = pair.commit(&h, &sim["data"], None).await;
    assert_eq!(
        result["error"]["code"], "policy.engine_required",
        "{result}"
    );
}
