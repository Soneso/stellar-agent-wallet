//! Owner tests for muxed payment destinations at the MCP surface.
//!
//! Every owner test uses its own fixed destination key. The mocked endpoint
//! answers only for G accounts, so a read that names an M address finds
//! nothing and a decision that skips the base account read shows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use std::sync::Arc;

use serial_test::serial;
use stellar_agent_core::approval::store::ApprovalKind;
use stellar_agent_core::approval::{
    PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrantStore, build_attested_grant,
    process_uid_for_attestation,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    StellarPayArgs, StellarPayCommitArgs, StellarToolsetInvokeArgs, WalletServer,
};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_balance, account_ledger_key_xdr,
};
use stellar_xdr::{
    Limits, Memo, MuxedAccount, MuxedAccountMed25519, OperationBody, PaymentOp, ReadXdr,
    TransactionEnvelope, Uint256,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The signing seed of the source account every test pays from.
const SOURCE_SEED: [u8; 32] = [0x61; 32];

fn g(key: [u8; 32]) -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey(key))
}

fn m(key: [u8; 32], id: u64) -> String {
    format!(
        "{}",
        stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
    )
}

fn muxed(key: [u8; 32], id: u64) -> MuxedAccount {
    MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id,
        ed25519: Uint256(key),
    })
}

/// G, M0 and M17 of `key`, with the XDR each must emit.
fn forms(key: [u8; 32]) -> [(String, MuxedAccount); 3] {
    [
        (g(key), MuxedAccount::Ed25519(Uint256(key))),
        (m(key, 0), muxed(key, 0)),
        (m(key, 17), muxed(key, 17)),
    ]
}

fn source_g() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&SOURCE_SEED);
    g(key.verifying_key().to_bytes())
}

/// A mocked testnet endpoint that answers for G accounts, refuses reads that
/// name a `failing` key, confirms every send, and records every request.
struct MuxRpc {
    entries: Vec<(String, String)>,
    failing: Vec<String>,
    /// Keys whose reads the endpoint answers with HTTP 401.
    unauthorized: Vec<String>,
}

impl Respond for MuxRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
        let id = body["id"].clone();
        let raw = String::from_utf8_lossy(&request.body);
        let result = match body["method"].as_str().unwrap_or("") {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
            "getLedgerEntries"
                if self
                    .unauthorized
                    .iter()
                    .any(|key| raw.contains(key.as_str())) =>
            {
                return ResponseTemplate::new(401);
            }
            "getLedgerEntries" if self.failing.iter().any(|key| raw.contains(key.as_str())) => {
                return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": "backend unavailable" }
                }));
            }
            "getLedgerEntries" => {
                let entries: Vec<serde_json::Value> = self
                    .entries
                    .iter()
                    .filter(|(key, _)| raw.contains(key.as_str()))
                    .map(|(key, entry)| {
                        serde_json::json!({ "key": key, "xdr": entry, "lastModifiedLedgerSeq": 1000 })
                    })
                    .collect();
                serde_json::json!({ "entries": entries, "latestLedger": 1001 })
            }
            "sendTransaction" => serde_json::json!({
                "hash": crate::common::submitted_tx_hash(request),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "SUCCESS",
                "ledger": 1005,
                "txHash": crate::common::polled_tx_hash(request),
            }),
            other => {
                crate::common::operational_result(other).unwrap_or_else(|| serde_json::json!({}))
            }
        };
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            .insert_header("content-type", "application/json")
    }
}

/// An endpoint answering for the source and for each account in `existing`.
async fn endpoint(
    existing: &[String],
    extra: Vec<(String, String)>,
    failing: &[String],
) -> MockServer {
    endpoint_refusing(existing, extra, failing, &[]).await
}

/// [`endpoint`] that also answers reads of each `unauthorized` account
/// with HTTP 401.
async fn endpoint_refusing(
    existing: &[String],
    extra: Vec<(String, String)>,
    failing: &[String],
    unauthorized: &[String],
) -> MockServer {
    let mut entries = vec![(
        account_ledger_key_xdr(&source_g()),
        account_entry_xdr_with_balance(&source_g(), 100_000_000_000_000),
    )];
    for account in existing {
        entries.push((
            account_ledger_key_xdr(account),
            account_entry_xdr_with_balance(account, 100_000_000_000),
        ));
    }
    entries.extend(extra);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(MuxRpc {
            entries,
            failing: failing
                .iter()
                .map(|account| account_ledger_key_xdr(account))
                .collect(),
            unauthorized: unauthorized
                .iter()
                .map(|account| account_ledger_key_xdr(account))
                .collect(),
        })
        .mount(&server)
        .await;
    server
}

/// A fresh mock keyring store as the process default for one test.
///
/// The store replaces the current default in one step. Dropping the guard
/// restores what it found: the previous store, or no store when none was
/// registered, so no test relies on a store another test left behind.
struct StoreGuard {
    previous: Option<Arc<keyring_core::CredentialStore>>,
}

impl StoreGuard {
    fn install() -> Self {
        let previous = keyring_core::get_default_store();
        let store: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().expect("mock keyring store");
        keyring_core::set_default_store(store);
        Self { previous }
    }
}

impl Drop for StoreGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => keyring_core::set_default_store(previous),
            None => {
                keyring_core::unset_default_store();
            }
        }
    }
}

/// Dropping the guard restores an absent store: with no store registered
/// before, none is registered after, and a production keyring call then
/// refuses with its platform error instead of using a left-over mock.
#[test]
#[serial]
fn store_guard_restores_an_absent_store() {
    /// Puts back the store the test found, also when an assertion fails.
    struct Outer(Option<Arc<keyring_core::CredentialStore>>);
    impl Drop for Outer {
        fn drop(&mut self) {
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }
    let _outer = Outer(keyring_core::unset_default_store());
    assert!(keyring_core::get_default_store().is_none());
    drop(StoreGuard::install());
    assert!(
        keyring_core::get_default_store().is_none(),
        "the guard leaves no store registered"
    );
    let coordinate = stellar_agent_core::profile::schema::KeyringEntryRef::new(
        "mux-guard-absence",
        crate::common::own_signer_account("absent"),
    );
    let error = stellar_agent_network::keyring::load_or_mint_secret_32(&coordinate)
        .expect_err("no store is registered, so the call refuses");
    assert_eq!(error.code(), "auth.keyring_platform_error");
    // A store the guard found is restored as found.
    let found: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
    keyring_core::set_default_store(Arc::clone(&found));
    drop(StoreGuard::install());
    assert!(
        keyring_core::get_default_store().is_some_and(|store| Arc::ptr_eq(&store, &found)),
        "the guard restores the store it found"
    );
    keyring_core::unset_default_store();
}

/// The state one test runs under: a guarded mock keyring store, a data root,
/// and one identity with its keys and audit log.
///
/// The store is installed once, before the first await, and every server of
/// the test reuses it. The profile name, the signer account and the nonce
/// coordinate are unique to the test, so no other test in this binary shares
/// its keys, its audit writer or its stores. Dropping the fixture restores the
/// previous default store.
struct Fixture {
    _store: StoreGuard,
    _root: crate::common::IsolatedDataRoot,
    name: String,
    profile: Profile,
}

impl Fixture {
    fn new() -> Self {
        use base64::Engine as _;
        let root = crate::common::isolated_data_root();
        let store = StoreGuard::install();
        let name = crate::common::own_signer_account("mux");
        let nonce_account = format!("{name}-nonce");
        keyring_core::Entry::new("n-svc", &nonce_account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x62; 32]))
            .unwrap();
        keyring_core::Entry::new("svc", &name)
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey(SOURCE_SEED)
                    .as_unredacted()
                    .to_string()
                    .as_str(),
            )
            .unwrap();
        crate::common::store_signer_identity("svc", &name, SOURCE_SEED);
        let mut profile = Profile::builder_testnet("svc", &name, "n-svc", &nonce_account)
            .with_noop_engine()
            .build();
        // The one audit initialization of the test.
        crate::common::install_test_audit_key(&mut profile);
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(GRANT_KEY))
        .unwrap();
        Self {
            _store: store,
            _root: root,
            name,
            profile,
        }
    }

    /// A server for `rpc` signing with [`SOURCE_SEED`], with approvals in
    /// `approval_dir`.
    fn server(&self, rpc: &MockServer, approval_dir: &std::path::Path) -> WalletServer {
        self.server_with(rpc, approval_dir, |_| {})
    }

    /// [`Self::server`] with `adjust` applied to the profile.
    fn server_with(
        &self,
        rpc: &MockServer,
        approval_dir: &std::path::Path,
        adjust: impl FnOnce(&mut Profile),
    ) -> WalletServer {
        let mut profile = self.profile.clone();
        profile.rpc_url = rpc.uri();
        adjust(&mut profile);
        let mut server = WalletServer::new(profile).expect("WalletServer::new");
        server.set_approval_dir_for_test(approval_dir.to_path_buf());
        server
    }
}

fn pay_args(destination: &str) -> StellarPayArgs {
    StellarPayArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: source_g(),
        destination: destination.to_owned(),
        amount: Some(serde_json::from_str(r#""10 XLM""#).unwrap()),
        amount_in_stroops: None,
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        classic_base: None,
        business_id: None,
    }
}

fn json_of(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or("{}");
    serde_json::from_str(text).unwrap()
}

/// The prepared call's data, which must succeed.
async fn prepare(server: &WalletServer, args: &StellarPayArgs) -> serde_json::Value {
    let result = server
        .call_stellar_pay(args.clone())
        .await
        .expect("prepare");
    let json = json_of(&result);
    assert_ne!(result.is_error, Some(true), "prepare: {json}");
    json["data"].clone()
}

/// The commit arguments of a prepared call.
fn commit_args(args: &StellarPayArgs, data: &serde_json::Value) -> StellarPayCommitArgs {
    StellarPayCommitArgs {
        chain_id: args.chain_id.clone(),
        source: args.source.clone(),
        destination: args.destination.clone(),
        amount: args.amount.clone(),
        amount_in_stroops: args.amount_in_stroops.clone(),
        asset: args.asset.clone(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        nonce: data["nonce"].as_str().unwrap().to_owned(),
        expires_at_unix_ms: data["expires_at_unix_ms"].as_u64().unwrap(),
        envelope_xdr: data["envelope_xdr"].as_str().unwrap().to_owned(),
        approval_nonce: None,
        approval_attestation: None,
        business_id: None,
    }
}

/// The payment of a base64 envelope.
fn payment_of(envelope: &str) -> PaymentOp {
    let TransactionEnvelope::Tx(envelope) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("a v1 envelope");
    };
    let OperationBody::Payment(payment) = envelope.tx.operations[0].body.clone() else {
        panic!("a payment");
    };
    payment
}

/// `envelope` with `change` applied to its first operation body.
fn with_body(envelope: &str, change: impl FnOnce(&mut OperationBody)) -> String {
    let TransactionEnvelope::Tx(mut tx) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("a v1 envelope");
    };
    let mut operations = tx.tx.operations.to_vec();
    change(&mut operations[0].body);
    tx.tx.operations = operations.try_into().unwrap();
    stellar_xdr::WriteXdr::to_xdr_base64(&TransactionEnvelope::Tx(tx), Limits::none()).unwrap()
}

/// The bodies of the requests `server` received for `rpc_method`.
async fn bodies(server: &MockServer, rpc_method: &str) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|request| serde_json::from_slice::<serde_json::Value>(&request.body).ok())
        .filter(|body| body["method"] == rpc_method)
        .collect()
}

/// The payments the endpoint was asked to send.
async fn sent_payments(server: &MockServer) -> Vec<PaymentOp> {
    bodies(server, "sendTransaction")
        .await
        .iter()
        .map(|body| payment_of(body["params"]["transaction"].as_str().unwrap()))
        .collect()
}

/// Every ledger key the endpoint was asked to read.
async fn read_keys(server: &MockServer) -> Vec<String> {
    bodies(server, "getLedgerEntries")
        .await
        .iter()
        .flat_map(|body| {
            body["params"]["keys"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|key| key.as_str().map(str::to_owned))
        .collect()
}

/// MCP and toolsets work. `stellar_pay` and `stellar_pay_commit` send
/// G, M0 and M17 with the key and ID in the decoded sent XDR; a changed ID
/// in the caller's arguments, a tampered envelope and a tampered nonce
/// refuse before signing; the gated toolset route queues an approval for
/// the full M17 and honors an M17 grant or a grant for its G base for M17,
/// and an M18 grant not.
#[tokio::test]
#[serial]
async fn mcp_muxed_payment_pipeline() {
    let fx = Fixture::new();
    let key = [0xA6; 32];
    for (destination, emitted) in forms(key) {
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&rpc, approvals.path());
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        assert_eq!(data["simulation"]["operation"]["destination"], destination);
        assert_eq!(
            payment_of(data["envelope_xdr"].as_str().unwrap()).destination,
            emitted
        );

        // A changed ID in the caller's arguments refuses before signing.
        let mut moved = commit_args(&args, &data);
        moved.destination = m(key, 18);
        let refused = server.call_stellar_pay_commit(moved).await.unwrap();
        assert_eq!(refused.is_error, Some(true));
        assert_eq!(
            json_of(&refused)["error"]["code"],
            "simulation.divergence",
            "{destination}"
        );
        // A tampered envelope or nonce refuses before signing.
        let mut tampered = commit_args(&args, &data);
        tampered.envelope_xdr = with_body(&tampered.envelope_xdr, |body| {
            if let OperationBody::Payment(payment) = body {
                payment.destination = muxed(key, 18);
            }
        });
        let mut bad_nonce = commit_args(&args, &data);
        bad_nonce.nonce = "A".repeat(bad_nonce.nonce.len());
        for refused in [tampered, bad_nonce] {
            let outcome = server.call_stellar_pay_commit(refused).await;
            let rejected = match outcome {
                Ok(result) => result.is_error == Some(true),
                Err(_) => true,
            };
            assert!(rejected, "{destination}: tampering refuses");
        }
        assert!(sent_payments(&rpc).await.is_empty(), "nothing is sent");

        let committed = server
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await
            .unwrap();
        assert_ne!(committed.is_error, Some(true), "{}", json_of(&committed));
        let sent = sent_payments(&rpc).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].destination, emitted, "{destination}: sent XDR");
        assert_eq!(sent[0].amount, 100_000_000);
    }

    // The gated toolset route takes an M17 envelope.
    gated_route_keeps_the_full_id(&fx, key).await;
}

/// The toolset grant's attestation key.
const GRANT_KEY: [u8; 32] = [0x42; 32];
const TOOLSET: &str = "mux-payment-toolset";

/// A payment envelope from the source to `destination`.
fn envelope_to(destination: MuxedAccount) -> String {
    use stellar_xdr::{
        Asset, Memo, Operation, Preconditions, SequenceNumber, Transaction, TransactionExt,
        TransactionV1Envelope, VecM, WriteXdr,
    };
    let source = ed25519_dalek::SigningKey::from_bytes(&SOURCE_SEED)
        .verifying_key()
        .to_bytes();
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 100,
            seq_num: SequenceNumber(101),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination,
                    asset: Asset::Native,
                    amount: 10_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// A gated invocation of `stellar_pay_commit` for `envelope`.
fn gated(envelope: &str, destination: &str) -> StellarToolsetInvokeArgs {
    StellarToolsetInvokeArgs {
        toolset: TOOLSET.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope,
            "source": source_g(),
            "destination": destination,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    }
}

/// A server of `fixture` for the gated route with isolated toolset and
/// approval stores.
fn gated_server(
    fixture: &Fixture,
    rpc: &MockServer,
    approvals: &std::path::Path,
    grants: &std::path::Path,
    toolsets: &std::path::Path,
) -> WalletServer {
    let mut profile = fixture.profile.clone();
    profile.rpc_url = rpc.uri();
    stellar_agent_toolsets_install::write_toolset_for_test(
        toolsets,
        TOOLSET,
        &["sign-payment"],
        &[],
        "2026-06-02T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &crate::common::toolset_pin_key(),
    )
    .unwrap();
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(
        crate::common::policy_mock::MockPolicyEngine::allow(),
    ));
    server.set_payment_recovery_policy_for_test(crate::common::payment_recovery_policy(&server));
    server.set_approval_dir_for_test(approvals.to_path_buf());
    server.set_grant_store_path_for_test(grants.to_path_buf());
    server.set_toolsets_root_for_test(toolsets.to_path_buf());
    server.set_toolset_pin_key_for_test(crate::common::toolset_pin_key());
    server
}

fn insert_grant(fixture: &Fixture, grants: &std::path::Path, destination: &str) {
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let grant = build_attested_grant(
        TOOLSET.to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "1.0.0".to_owned(),
        "0".repeat(64),
        "sign-payment".to_owned(),
        destination.to_owned(),
        "XLM".to_owned(),
        0,
        10_000_000,
        process_uid_for_attestation().unwrap(),
        now,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &GRANT_KEY,
        &stellar_agent_core::approval::AttestationBinding::new(&fixture.name, "stellar:testnet"),
    )
    .unwrap();
    ToolsetGrantStore::open(grants.to_path_buf(), now)
        .unwrap()
        .insert(grant)
        .unwrap();
}

/// The single pending approval of profile `profile` in `approvals`.
fn only_pending(approvals: &std::path::Path, profile: &str) -> ApprovalKind {
    let store = PendingApprovalStore::open(approvals.join(format!("{profile}.toml"))).unwrap();
    let views = store.snapshot(stellar_agent_core::timefmt::now_unix_ms().unwrap());
    assert_eq!(views.len(), 1);
    store.get(&views[0].approval_nonce).unwrap().kind.clone()
}

async fn gated_route_keeps_the_full_id(fx: &Fixture, key: [u8; 32]) {
    let m17 = m(key, 17);
    let envelope = envelope_to(muxed(key, 17));

    // Without a grant, the first-invoke gate queues the full M17.
    let toolsets = tempfile::TempDir::new().unwrap();
    let approvals = tempfile::TempDir::new().unwrap();
    let grants = approvals.path().join("grants.toml");
    let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
    let server = gated_server(fx, &rpc, approvals.path(), &grants, toolsets.path());
    let error = server
        .call_stellar_toolset_invoke(gated(&envelope, &m17))
        .await
        .unwrap_err();
    assert!(
        error.message.contains("first_invoke_approval_required"),
        "{}",
        error.message
    );
    let ApprovalKind::ToolsetFirstInvokeGate { destination, .. } =
        only_pending(approvals.path(), &fx.name)
    else {
        panic!("a first-invoke gate");
    };
    assert_eq!(destination, m17);

    // M17 and G-base grants permit a real Allow send; another ID prompts.
    for (index, (granted, first_invoke)) in
        [(m17.clone(), false), (g(key), false), (m(key, 18), true)]
            .into_iter()
            .enumerate()
    {
        let toolsets = tempfile::TempDir::new().unwrap();
        let approvals = tempfile::TempDir::new().unwrap();
        let grants = approvals.path().join("grants.toml");
        insert_grant(fx, &grants, &granted);
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let server = gated_server(fx, &rpc, approvals.path(), &grants, toolsets.path());
        let mut args = pay_args(&m17);
        args.amount = Some(serde_json::from_str(r#""1 XLM""#).unwrap());
        args.memo_id = Some(index as u64);
        let data = prepare(&server, &args).await;
        let mut invoke = gated(data["envelope_xdr"].as_str().unwrap(), &m17);
        invoke.args["nonce"] = data["nonce"].clone();
        invoke.args["expires_at_unix_ms"] = data["expires_at_unix_ms"].clone();
        invoke.args["memo_id"] = serde_json::json!(index);
        let outcome = server.call_stellar_toolset_invoke(invoke).await;
        match (first_invoke, outcome) {
            (false, Ok(result)) => {
                assert_eq!(
                    json_of(&result)["ok"],
                    true,
                    "the grant for {granted} covers M17: {}",
                    json_of(&result)
                );
                assert_eq!(json_of(&result)["data"]["destination"], m17);
                let sent = sent_payments(&rpc).await;
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].destination, muxed(key, 17));
                assert_eq!(sent[0].amount, 10_000_000);
                assert!(!approvals.path().join(format!("{}.toml", fx.name)).exists());
            }
            (true, Err(error)) => assert!(
                error.message.contains("first_invoke_approval_required"),
                "a grant for {granted} does not cover M17: {}",
                error.message
            ),
            (expected, other) => panic!("grant {granted}, first invoke {expected}: {other:?}"),
        }
    }
}

/// The base64 testnet transfer of one stroop of `asset` from the G account
/// of key `[1; 32]` to the C contract of key `[2; 32]`, with `memo`.
fn contract_transfer(asset: stellar_agent_core::approval::IntentAsset, memo: Memo) -> String {
    let context = stellar_agent_core::sac_payment::SacPaymentContext::new(
        stellar_agent_core::profile::caip2::Caip2::Testnet,
        asset,
    )
    .unwrap();
    let mut envelope = stellar_agent_core::approval::fixtures::sac_transfer(&context);
    envelope.tx.memo = memo;
    stellar_xdr::WriteXdr::to_xdr_base64(&TransactionEnvelope::Tx(envelope), Limits::none())
        .unwrap()
}

/// The four memo arguments of the payment tools.
const MEMO_FORMS: [&str; 4] = ["text", "id", "hash", "return"];

/// Sets exactly the memo argument `form` names.
fn with_memo(
    form: &str,
    text: &mut Option<stellar_agent_core::amount::McpMemoTextArgument>,
    id: &mut Option<u64>,
    hash: &mut Option<String>,
    ret: &mut Option<String>,
) {
    match form {
        "text" => *text = Some(serde_json::from_str(r#""note""#).unwrap()),
        "id" => *id = Some(3),
        "hash" => *hash = Some("ab".repeat(32)),
        _ => *ret = Some("cd".repeat(32)),
    }
}

/// The JSON memo argument of `form`, for toolset arguments.
fn memo_json(form: &str) -> (&'static str, serde_json::Value) {
    match form {
        "text" => ("memo_text", "note".into()),
        "id" => ("memo_id", 3.into()),
        "hash" => ("memo_hash_hex", "ab".repeat(32).into()),
        _ => ("memo_return_hex", "cd".repeat(32).into()),
    }
}

/// The wire code of a business refusal, `ok` for a success, or the message
/// of a protocol error.
fn refusal_code(result: Result<rmcp::model::CallToolResult, rmcp::ErrorData>) -> String {
    match result {
        Ok(result) if result.is_error == Some(true) => json_of(&result)["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("protocol error: {}", error.message),
    }
}

/// Every MCP payment route refuses a C recipient with its fixed code before
/// any request, approval, grant, nonce, or send: direct preparation and
/// commit, and both toolset payment actions. Invalid assets and non-C
/// destinations keep their own refusals; a G preparation still succeeds.
#[tokio::test]
#[serial]
async fn contract_recipients_refuse_on_every_mcp_payment_route() {
    use stellar_agent_core::approval::IntentAsset;
    const UNAVAILABLE: &str = "validation.contract_payment_unavailable";
    const MEMO: &str = "validation.contract_payment_memo_unsupported";
    const INVALID: &str = "validation.contract_payment_invalid";
    let fx = Fixture::new();
    let contract = format!("{}", stellar_strkey::Contract([2; 32]));
    let issuer = g([0x77; 32]);
    let usd = IntentAsset::Issued {
        code: "USD".to_owned(),
        issuer: issuer.clone(),
    };
    let toolsets = tempfile::TempDir::new().unwrap();
    let approvals = tempfile::TempDir::new().unwrap();
    let grants = approvals.path().join("grants.toml");
    let rpc = endpoint(&[], Vec::new(), &[]).await;
    let server = gated_server(&fx, &rpc, approvals.path(), &grants, toolsets.path());

    let mut usd_args = pay_args(&contract);
    usd_args.asset = format!("USD:{issuer}");
    usd_args.amount = Some(serde_json::from_str(r#""1 USD""#).unwrap());
    for (args, code) in [(pay_args(&contract), UNAVAILABLE), (usd_args, UNAVAILABLE)] {
        let result = server.call_stellar_pay(args).await;
        assert_eq!(refusal_code(result), code, "direct preparation");
    }
    for form in MEMO_FORMS {
        let mut args = pay_args(&contract);
        with_memo(
            form,
            &mut args.memo_text,
            &mut args.memo_id,
            &mut args.memo_hash_hex,
            &mut args.memo_return_hex,
        );
        let result = server.call_stellar_pay(args).await;
        assert_eq!(
            refusal_code(result),
            MEMO,
            "direct preparation, {form} memo"
        );
    }
    let mut bad_asset = pay_args(&contract);
    bad_asset.asset = "USD:NOTANISSUER".to_owned();
    assert!(
        server.call_stellar_pay(bad_asset).await.is_err(),
        "asset first"
    );
    for other in [contract.to_lowercase(), format!("{contract}A")] {
        assert!(
            server.call_stellar_pay(pay_args(&other)).await.is_err(),
            "{other} keeps the address refusal"
        );
    }

    let commit = |envelope: String, asset: &str| {
        let mut args = commit_args(
            &pay_args(&contract),
            &serde_json::json!({
                "nonce": "A".repeat(64), "expires_at_unix_ms": 9_999_999_999_u64,
                "envelope_xdr": envelope,
            }),
        );
        args.asset = asset.to_owned();
        args.amount = None;
        args.amount_in_stroops = Some("1".to_owned());
        args
    };
    for (envelope, asset, code) in [
        (
            contract_transfer(IntentAsset::Native, Memo::None),
            "native",
            UNAVAILABLE,
        ),
        (
            contract_transfer(usd.clone(), Memo::None),
            &format!("USD:{issuer}") as &str,
            UNAVAILABLE,
        ),
        (
            contract_transfer(usd.clone(), Memo::None),
            "native",
            INVALID,
        ),
        (
            contract_transfer(IntentAsset::Native, Memo::Id(7)),
            "native",
            MEMO,
        ),
    ] {
        let result = server
            .call_stellar_pay_commit(commit(envelope, asset))
            .await;
        assert_eq!(refusal_code(result), code, "direct commit {asset}");
    }
    // A classic envelope does not refuse first, so the memo argument decides.
    let classic = envelope_to(MuxedAccount::Ed25519(Uint256([3; 32])));
    for form in MEMO_FORMS {
        let mut args = commit(classic.clone(), "native");
        with_memo(
            form,
            &mut args.memo_text,
            &mut args.memo_id,
            &mut args.memo_hash_hex,
            &mut args.memo_return_hex,
        );
        let result = server.call_stellar_pay_commit(args).await;
        assert_eq!(refusal_code(result), MEMO, "direct commit, {form} memo");

        let (key, value) = memo_json(form);
        let mut proposal = gated("", &contract);
        proposal.action = "stellar_pay".to_owned();
        proposal.args = serde_json::json!({
            "source": source_g(), "destination": contract, "asset": "native",
            "amount": "1 XLM",
        });
        proposal.args[key] = value.clone();
        let result = server.call_stellar_toolset_invoke(proposal).await;
        assert_eq!(refusal_code(result), MEMO, "toolset proposal, {form} memo");

        let mut sign = gated(&classic, &contract);
        sign.args[key] = value;
        let result = server.call_stellar_toolset_invoke(sign).await;
        assert_eq!(
            refusal_code(result),
            MEMO,
            "toolset sign-payment, {form} memo"
        );
    }
    for (envelope, code) in [
        (
            contract_transfer(IntentAsset::Native, Memo::None),
            UNAVAILABLE,
        ),
        (contract_transfer(usd, Memo::None), INVALID),
    ] {
        let result = server
            .call_stellar_toolset_invoke(gated(&envelope, &contract))
            .await;
        assert_eq!(refusal_code(result), code, "toolset sign-payment");
    }

    assert!(
        rpc.received_requests().await.unwrap().is_empty(),
        "no request precedes a contract refusal"
    );
    assert!(
        !approvals.path().join(format!("{}.toml", fx.name)).exists(),
        "no approval or first-invoke gate is queued"
    );
    assert!(!grants.exists(), "no grant is read or written");

    let key = [0xA8; 32];
    let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
    let server = gated_server(&fx, &rpc, approvals.path(), &grants, toolsets.path());
    prepare(&server, &pay_args(&g(key))).await;
}

/// Destination reads use the base. Prepare and commit read
/// the G base of M0 and M17, an absent base counts as absent, and any other
/// failed base read stays an error at commit.
#[tokio::test]
#[serial]
async fn muxed_destination_reads() {
    let fx = Fixture::new();
    let key = [0xA7; 32];
    let base_key = account_ledger_key_xdr(&g(key));
    for destination in [m(key, 0), m(key, 17)] {
        for exists in [true, false] {
            let existing = if exists { vec![g(key)] } else { Vec::new() };
            let rpc = endpoint(&existing, Vec::new(), &[]).await;
            let approvals = tempfile::TempDir::new().unwrap();
            let server = fx.server(&rpc, approvals.path());
            let mut args = pay_args(&destination);
            // Each submission needs its own envelope in the shared receipt store.
            args.amount = Some(
                serde_json::from_str(if exists { r#""11 XLM""# } else { r#""12 XLM""# }).unwrap(),
            );
            let data = prepare(&server, &args).await;
            let committed = server
                .call_stellar_pay_commit(commit_args(&args, &data))
                .await
                .unwrap();
            assert_ne!(
                committed.is_error,
                Some(true),
                "{destination} exists={exists}: {}",
                json_of(&committed)
            );
            let reads = read_keys(&rpc).await;
            assert!(
                reads.iter().filter(|read| **read == base_key).count() >= 2,
                "{destination}: prepare and commit read the base"
            );
            assert_eq!(
                sent_payments(&rpc).await[0].destination.clone(),
                stellar_agent_core::payment_accounts::PaymentAccount::parse(&destination)
                    .unwrap()
                    .to_muxed_account()
            );
        }

        // A failed base read is an error at commit, not an absent account.
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&rpc, approvals.path());
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        let failing = endpoint(&[], Vec::new(), &[g(key)]).await;
        let refused = fx
            .server(&failing, approvals.path())
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await
            .unwrap();
        assert_eq!(refused.is_error, Some(true), "{destination}");
        assert!(sent_payments(&failing).await.is_empty());
    }
}

/// The `config.memo_required` data entry of `account` set to `1`.
fn memo_required_entry(account: &str) -> (String, String) {
    use stellar_xdr::{
        AccountId, DataEntry, DataEntryExt, LedgerEntryData, LedgerKey, LedgerKeyData, PublicKey,
        String64, StringM, WriteXdr,
    };
    let pk = stellar_strkey::ed25519::PublicKey::from_string(account).unwrap();
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
    let name: String64 = StringM::<64>::try_from(b"config.memo_required".to_vec())
        .unwrap()
        .into();
    let key = LedgerKey::Data(LedgerKeyData {
        account_id: account_id.clone(),
        data_name: name.clone(),
    });
    let entry = LedgerEntryData::Data(DataEntry {
        account_id,
        data_name: name,
        data_value: b"1".to_vec().try_into().unwrap(),
        ext: DataEntryExt::V0,
    });
    (
        key.to_xdr_base64(Limits::none()).unwrap(),
        entry.to_xdr_base64(Limits::none()).unwrap(),
    )
}

/// M0 and M17 without a memo skip the SEP-29 lookup at
/// prepare and commit, though their base sets the flag; the G base without
/// a memo refuses with `validation.memo_required`, and with a memo passes.
#[tokio::test]
#[serial]
async fn muxed_sep29_exception() {
    let fx = Fixture::new();
    let key = [0xA8; 32];
    let (data_key, data_entry) = memo_required_entry(&g(key));
    for destination in [m(key, 0), m(key, 17)] {
        let rpc = endpoint(&[g(key)], vec![(data_key.clone(), data_entry.clone())], &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&rpc, approvals.path());
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        let committed = server
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await
            .unwrap();
        assert_ne!(committed.is_error, Some(true), "{}", json_of(&committed));
        assert!(
            !read_keys(&rpc).await.contains(&data_key),
            "{destination}: no data entry is read"
        );
    }
    let rpc = endpoint(&[g(key)], vec![(data_key.clone(), data_entry)], &[]).await;
    let approvals = tempfile::TempDir::new().unwrap();
    let server = fx.server(&rpc, approvals.path());
    let refused = server.call_stellar_pay(pay_args(&g(key))).await.unwrap();
    assert_eq!(
        json_of(&refused)["error"]["code"],
        "validation.memo_required",
        "{}",
        json_of(&refused)
    );
    assert!(read_keys(&rpc).await.contains(&data_key));
    let mut with_memo = pay_args(&g(key));
    with_memo.memo_id = Some(7);
    prepare(&server, &with_memo).await;
}

/// The prepare preview and the pending approval carry the
/// full M0 and M17, and the approval envelope keeps the ID.
#[tokio::test]
#[serial]
async fn muxed_original_address_records() {
    let fx = Fixture::new();
    let key = [0xAD; 32];
    for id in [0, 17] {
        let destination = m(key, id);
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let mut server = fx.server(&rpc, approvals.path());
        server.set_policy_engine_for_test(Arc::new(
            crate::common::policy_mock::MockPolicyEngine::require_approval(),
        ));
        server
            .set_payment_recovery_policy_for_test(crate::common::payment_recovery_policy(&server));
        let data = prepare(&server, &pay_args(&destination)).await;
        assert_eq!(data["simulation"]["operation"]["destination"], destination);
        assert_eq!(data["approval"]["summary"]["to"], destination);
        let ApprovalKind::PaymentSimulated {
            summary_to,
            envelope_xdr_b64,
            ..
        } = only_pending(approvals.path(), &fx.name)
        else {
            panic!("a payment approval");
        };
        assert_eq!(summary_to, destination);
        assert_eq!(payment_of(&envelope_xdr_b64).destination, muxed(key, id));
    }
}

/// Plain destinations refuse M. Create-account prepare and
/// commit, Friendbot, the builder's create-account destination, payment
/// issuers and URI issuers refuse M0 and M17 before any RPC request, name
/// the field with the `AccountId` reason, and never echo the input.
#[tokio::test]
#[serial]
async fn destination_plain_field_reason() {
    use stellar_agent_mcp::server::{StellarCreateAccountArgs, StellarCreateAccountCommitArgs};
    let fx = Fixture::new();
    let key = [0xA4; 32];
    let rpc = MockServer::start().await;
    let approvals = tempfile::TempDir::new().unwrap();
    let server = fx.server(&rpc, approvals.path());
    let reason = "destination requires AccountId; a muxed ID cannot be encoded";
    let mut builder = stellar_agent_network::builder::ClassicOpBuilder::new(
        source_g(),
        1,
        stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
        100,
    );
    builder
        .create_account(&g(key), stellar_agent_core::StellarAmount::from_stroops(1))
        .map(|_| ())
        .unwrap();
    let create_envelope = builder.build().unwrap();
    for id in [0, 17] {
        let destination = m(key, id);
        let prepare = server
            .call_stellar_create_account(StellarCreateAccountArgs {
                chain_id: "stellar:testnet".to_owned(),
                source: source_g(),
                destination: destination.clone(),
                starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
                classic_base: None,
                business_id: None,
            })
            .await
            .unwrap_err();
        let commit = server
            .call_stellar_create_account_commit(
                serde_json::from_value::<StellarCreateAccountCommitArgs>(serde_json::json!({
                    "chain_id": "stellar:testnet",
                    "source": source_g(),
                    "destination": destination,
                    "starting_balance": "1 XLM",
                    "nonce": "A".repeat(64),
                    "expires_at_unix_ms": 9_999_999_999_u64,
                    "envelope_xdr": create_envelope,
                }))
                .unwrap(),
            )
            .await
            .unwrap_err();
        for error in [prepare, commit] {
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(error.message, reason, "M{id}");
        }
        let friendbot = server
            .call_stellar_friendbot(stellar_agent_mcp::server::StellarFriendbotArgs {
                chain_id: "stellar:testnet".to_owned(),
                account_id: destination.clone(),
                friendbot_url: None,
            })
            .await
            .unwrap_err();
        assert_eq!(
            friendbot.message,
            "account_id requires AccountId; a muxed ID cannot be encoded"
        );

        let mut builder = stellar_agent_network::builder::ClassicOpBuilder::new(
            source_g(),
            1,
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            100,
        );
        let built = builder
            .create_account(
                &destination,
                stellar_agent_core::StellarAmount::from_stroops(1),
            )
            .map(|_| ())
            .unwrap_err();
        assert_eq!(built.code(), "validation.address_invalid");
        assert_eq!(built.message(), reason);

        for issuer in [
            stellar_agent_network::builder::Asset::parse(&format!("USDC:{destination}"))
                .unwrap_err(),
            stellar_agent_network::builder::Asset::from_code_and_issuer("USDC", &destination)
                .unwrap_err(),
        ] {
            assert_eq!(issuer.code(), "validation.asset_invalid");
            assert!(
                issuer
                    .message()
                    .contains("issuer requires AccountId; a muxed ID cannot be encoded"),
                "{}",
                issuer.message()
            );
            assert!(!issuer.message().contains(&destination));
        }
        let uri = stellar_agent_sep7::parse_sep7_uri(&format!(
            "web+stellar:pay?destination={destination}&asset_code=USDC&asset_issuer={destination}"
        ))
        .unwrap_err();
        assert!(
            uri.to_string()
                .contains("issuer requires AccountId; a muxed ID cannot be encoded")
        );
    }
    // A malformed or secret-key-shaped destination is refused unechoed.
    let secret = stellar_strkey::ed25519::PrivateKey(key)
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned();
    for refused in [secret, "MNOTAVALIDADDRESS".to_owned()] {
        let error = server
            .call_stellar_create_account(StellarCreateAccountArgs {
                chain_id: "stellar:testnet".to_owned(),
                source: source_g(),
                destination: refused.clone(),
                starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
                classic_base: None,
                business_id: None,
            })
            .await
            .unwrap_err();
        assert!(!error.message.contains(&refused));
        assert!(!error.message.contains("muxed ID"));
    }
    assert!(
        rpc.received_requests().await.unwrap().is_empty(),
        "no RPC request precedes the refusals"
    );
}

/// Safety gates stay. A wrong endpoint network, a policy
/// denial, an insufficient balance, a fee above the cap, an expired nonce
/// and an unsupported operation refuse M0 and M17 with the code G gets,
/// and nothing is sent.
#[tokio::test]
#[serial]
async fn muxed_destination_safety_parity() {
    let fx = Fixture::new();
    let key = [0xB0; 32];
    let mut codes: Vec<Vec<String>> = Vec::new();
    for (destination, _) in forms(key) {
        let mut seen = Vec::new();
        let code_of = |outcome: Result<rmcp::model::CallToolResult, rmcp::ErrorData>| match outcome
        {
            Ok(result) => {
                assert_eq!(result.is_error, Some(true), "{}", json_of(&result));
                json_of(&result)["error"]["code"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned()
            }
            Err(error) => error.message.split(':').next().unwrap_or("").to_owned(),
        };

        // Wrong endpoint network.
        let wrong = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(crate::common::TimeoutRpc::new(Vec::new()).with_network(
                crate::common::EndpointNetwork::reporting(
                    "Public Global Stellar Network ; September 2015",
                ),
            ))
            .mount(&wrong)
            .await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&wrong, approvals.path());
        seen.push(code_of(
            server.call_stellar_pay(pay_args(&destination)).await,
        ));

        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        // Policy denial.
        let mut denied = fx.server(&rpc, approvals.path());
        denied.set_policy_engine_for_test(Arc::new(
            crate::common::policy_mock::MockPolicyEngine::deny_explicit_rule(),
        ));
        denied
            .set_payment_recovery_policy_for_test(crate::common::payment_recovery_policy(&denied));
        seen.push(code_of(
            denied.call_stellar_pay(pay_args(&destination)).await,
        ));

        // Fee above the profile cap.
        let capped = fx.server_with(&rpc, approvals.path(), |profile| {
            profile.classic_max_fee_per_op_stroops = Some(100);
        });
        let mut expensive = pay_args(&destination);
        expensive.classic_base = Some("5000".to_owned());
        seen.push(code_of(capped.call_stellar_pay(expensive).await));
        let server = fx.server(&rpc, approvals.path());

        // Insufficient balance.
        let mut huge = pay_args(&destination);
        huge.amount = Some(serde_json::from_str(r#""90000000000 XLM""#).unwrap());
        seen.push(code_of(server.call_stellar_pay(huge).await));

        // An expired nonce at commit.
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        let mut expired = commit_args(&args, &data);
        expired.expires_at_unix_ms = 1;
        seen.push(code_of(server.call_stellar_pay_commit(expired).await));

        // An unsupported operation at commit: an account merge to the same
        // destination.
        let mut merge = commit_args(&args, &data);
        let merged =
            stellar_agent_core::payment_accounts::PaymentAccount::parse(&destination).unwrap();
        merge.envelope_xdr = with_body(&merge.envelope_xdr, |body| {
            *body = OperationBody::AccountMerge(merged.to_muxed_account());
        });
        seen.push(code_of(server.call_stellar_pay_commit(merge).await));

        assert!(sent_payments(&rpc).await.is_empty(), "{destination}");
        assert!(sent_payments(&wrong).await.is_empty(), "{destination}");
        codes.push(seen);
    }
    assert_eq!(
        codes[0],
        [
            "network.mainnet_write_forbidden",
            "policy.deny.explicit_rule_deny",
            "fees.percentile_exceeds_cap",
            "ledger.insufficient_balance",
            "nonce.expired",
            "simulation.divergence",
        ],
        "the G refusals"
    );
    assert_eq!(codes[0], codes[1], "M0 refuses as G does");
    assert_eq!(codes[0], codes[2], "M17 refuses as G does");
}

/// The stored receipt of a successful payment carries the full M destination
/// decoded from the sent envelope, under a policy that produces no audit
/// legs. The repeated commit refuses with exactly one send, and the receipt
/// reads back after the store is reopened. A G payment stores no destination.
#[tokio::test]
#[serial]
async fn mcp_muxed_submission_receipt_keeps_original_address() {
    let fx = Fixture::new();
    let key = [0xD4; 32];
    for (destination, emitted) in forms(key) {
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&rpc, approvals.path());
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        let committed = server
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await
            .unwrap();
        assert_ne!(committed.is_error, Some(true), "{}", json_of(&committed));
        let tx_hash = json_of(&committed)["data"]["tx_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let repeated = server
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await;
        assert!(
            repeated.map_or(true, |result| result.is_error == Some(true)),
            "{destination}: the repeated commit refuses"
        );
        let sent = sent_payments(&rpc).await;
        assert_eq!(sent.len(), 1, "{destination}: exactly one send");
        assert_eq!(sent[0].destination, emitted);
        drop(server);

        let receipts = stellar_agent_core::profile::receipt::ReceiptStore::open(&fx.name).unwrap();
        let receipt = receipts
            .all()
            .unwrap()
            .into_iter()
            .find(|receipt| receipt.tx_hash == tx_hash)
            .expect("the receipt of the send");
        let expected =
            matches!(emitted, MuxedAccount::MuxedEd25519(_)).then(|| destination.clone());
        assert_eq!(
            receipt.destinations,
            expected
                .map(stellar_agent_core::profile::receipt::PaymentDestinations::Single)
                .unwrap_or_default(),
            "{destination}"
        );
    }
}

/// An allowed `stellar_pay_commit` to M0 and M17 under a sizing engine
/// writes an audit payment leg whose `destination_sha256` is the SHA-256 of
/// the complete M address. No audit row holds the complete address.
#[tokio::test]
#[serial]
async fn mcp_payment_audit_leg_hashes_the_complete_destination() {
    use stellar_agent_test_support::xdr_fixtures::{trustline_entry_xdr, trustline_ledger_key_xdr};
    let trustline = (
        trustline_ledger_key_xdr(&source_g(), "USDC", RESULT_ISSUER),
        trustline_entry_xdr(&source_g(), "USDC", RESULT_ISSUER, 10_000_000_000),
    );
    for issued in [false, true] {
        for (destination, expected, redacted) in [
            (
                RESULT_G,
                "07c771942ac09608159b09c3073d4349690182de7c46322af475bb7a698ef992",
                "GCTKN...KNG7S",
            ),
            (
                RESULT_M0,
                "87478b29542363dbd4b73c7638df3b56e554252fe53d66dce81e9aa905a8cf55",
                "MCTKN...ABA5O",
            ),
            (
                RESULT_MMAX,
                "9ad4d124b64bfd959c317416ff7fe0937544a14c00b52d29012246b6ce209f53",
                "MCTKN...76QHC",
            ),
        ] {
            let fx = Fixture::new();
            let rpc = endpoint(
                &[RESULT_G.to_owned(), RESULT_ISSUER.to_owned()],
                vec![trustline.clone()],
                &[],
            )
            .await;
            let approvals = tempfile::TempDir::new().unwrap();
            let mut server = fx.server(&rpc, approvals.path());
            server.set_policy_engine_for_test(Arc::new(
                crate::common::v1_engine_mock::minimum_reserve_engine(
                    &["stellar_pay", "stellar_pay_commit"],
                    0,
                ),
            ));
            server.set_payment_recovery_policy_for_test(crate::common::payment_recovery_policy(
                &server,
            ));
            let mut args = pay_args(destination);
            if issued {
                args.asset = format!("USDC:{RESULT_ISSUER}");
                args.amount = Some(serde_json::from_str(r#""10 USDC""#).unwrap());
            }
            let data = prepare(&server, &args).await;
            let committed = server
                .call_stellar_pay_commit(commit_args(&args, &data))
                .await
                .unwrap();
            assert_ne!(committed.is_error, Some(true), "{}", json_of(&committed));
            assert_eq!(sent_payments(&rpc).await.len(), 1, "{destination}");
            drop(server);
            let rows = crate::common::audit_rows(&fx.profile);
            let legs: Vec<&serde_json::Value> = rows
                .iter()
                .filter_map(|row| row["legs"].as_array())
                .flatten()
                .filter(|leg| leg["destination_redacted"] == redacted)
                .collect();
            assert!(!legs.is_empty(), "{destination}: a payment leg: {rows:?}");
            for leg in legs {
                assert_eq!(leg["amount"], "100000000");
                assert_eq!(leg["asset"], args.asset);
                assert_eq!(leg["action"], "payment", "{destination}");
                assert_eq!(
                    leg["destination_sha256"], expected,
                    "{destination}: complete destination hash"
                );
                assert_eq!(leg["destination_redacted"], redacted);
            }
            let log = std::fs::read_to_string(&fx.profile.audit_log_path).unwrap();
            assert!(
                !log.contains(destination),
                "{destination}: no audit row holds the complete destination"
            );
        }
    }
}

/// The text of an MCP refusal of a muxed asset issuer.
fn muxed_issuer_text(prefix: &str) -> String {
    format!(
        "{prefix}: validation.asset_invalid: {}",
        stellar_agent_core::classic_address::MUXED_ISSUER_REASON
    )
}

/// A muxed asset issuer with mux ID `id` refuses at MCP pay prepare and commit,
/// at the balances trustline field, in the builder and in a payment URI, with
/// the existing code, the field and the base-account reason, before any RPC
/// request and without echoing the address.
async fn issuer_refuses_as_a_base_account(id: u64) {
    use stellar_agent_mcp::server::{StellarBalancesArgs, TrustlineAssetArg};
    let fx = Fixture::new();
    let key = [0xD2; 32];
    let issuer = m(key, id);
    let rpc = MockServer::start().await;
    let approvals = tempfile::TempDir::new().unwrap();
    let server = fx.server(&rpc, approvals.path());
    let mut args = pay_args(&g([0xD3; 32]));
    args.asset = format!("USDC:{issuer}");
    args.amount = Some(serde_json::from_str(r#""1 USDC""#).unwrap());
    let prepare = server.call_stellar_pay(args.clone()).await.unwrap_err();
    let commit = server
        .call_stellar_pay_commit(commit_args(
            &args,
            &serde_json::json!({
                "nonce": "A".repeat(64),
                "expires_at_unix_ms": 9_999_999_999_u64,
                "envelope_xdr": envelope_to(MuxedAccount::Ed25519(Uint256([0xD3; 32]))),
            }),
        ))
        .await
        .unwrap_err();
    for error in [&prepare, &commit] {
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(error.message, muxed_issuer_text("invalid asset"), "M{id}");
        assert!(!error.message.contains(&issuer));
    }
    let balances = server
        .call_stellar_balances(StellarBalancesArgs {
            chain_id: "stellar:testnet".to_owned(),
            account_id: g([0xD3; 32]),
            assets: vec![TrustlineAssetArg {
                code: "USDC".to_owned(),
                issuer: issuer.clone(),
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(balances.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    assert_eq!(
        balances.message,
        muxed_issuer_text("invalid trustline asset")
    );
    assert!(!balances.message.contains(&issuer));

    let built =
        stellar_agent_network::builder::Asset::parse(&format!("USDC:{issuer}")).unwrap_err();
    assert_eq!(built.code(), "validation.asset_invalid");
    assert_eq!(
        built.message(),
        format!(
            "asset ({}) is not a valid asset descriptor",
            stellar_agent_core::classic_address::MUXED_ISSUER_REASON
        )
    );
    let uri = stellar_agent_sep7::parse_sep7_uri(&format!(
        "web+stellar:pay?destination={}&asset_code=USDC&asset_issuer={issuer}",
        g([0xD3; 32])
    ))
    .unwrap_err();
    assert_eq!(
        uri.to_string(),
        format!(
            "SEP-7 invalid parameter value for 'asset_issuer': {}",
            stellar_agent_core::classic_address::MUXED_ISSUER_REASON
        )
    );
    // A malformed issuer keeps its pinned text.
    let mut malformed = args.clone();
    malformed.asset = "USDC:NOTAKEY".to_owned();
    assert_eq!(
        server
            .call_stellar_pay(malformed)
            .await
            .unwrap_err()
            .message,
        "invalid asset: validation.asset_invalid"
    );
    assert!(
        rpc.received_requests().await.unwrap().is_empty(),
        "no RPC request precedes the refusals"
    );
}

/// A muxed issuer with ID zero refuses as a base account.
#[tokio::test]
#[serial]
async fn issuer_m0_refuses_as_a_base_account() {
    issuer_refuses_as_a_base_account(0).await;
}

/// A muxed issuer with the largest ID refuses as a base account.
#[tokio::test]
#[serial]
async fn issuer_m_max_refuses_as_a_base_account() {
    issuer_refuses_as_a_base_account(u64::MAX).await;
}

/// The G account of `[0xA6; 32]`, its M0, and its maximum-ID M address.
const RESULT_G: &str = "GCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNG7S";
const RESULT_M0: &str = "MCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKMAAAAAAAAAAAABA5O";
const RESULT_MMAX: &str = "MCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKN7777777777776QHC";
/// The issuer of the issued cases, the G account of `[0xD6; 32]`.
const RESULT_ISSUER: &str = "GDLNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNMSZB";
/// Another G account, the G account of `[0xA7; 32]`.
const OTHER_G: &str = "GCT2PJ5HU6T2PJ5HU6T2PJ5HU6T2PJ5HU6T2PJ5HU6T2PJ5HU6T2OJHQ";

/// The pending approvals of `profile` in `approvals`.
fn pending_count(approvals: &std::path::Path, profile: &str) -> usize {
    let path = approvals.join(format!("{profile}.toml"));
    if !path.exists() {
        return 0;
    }
    PendingApprovalStore::open(path)
        .unwrap()
        .snapshot(stellar_agent_core::timefmt::now_unix_ms().unwrap())
        .len()
}

/// A destination read failing with a backend error refuses the preparation
/// with `network.rpc_unreachable`, and an HTTP 401 with
/// `network.rpc_credential_refused`, before any nonce, approval, or send. A
/// repeated preparation refuses with the same code. An absent account
/// prepares. G and the maximum-ID M read the same G key.
#[tokio::test]
#[serial]
async fn pay_prepare_destination_read_error_refuses_with_its_code() {
    let fx = Fixture::new();
    let base_key = account_ledger_key_xdr(RESULT_G);
    for destination in [RESULT_G, RESULT_MMAX] {
        for (failing, unauthorized, code, detail) in [
            (
                vec![RESULT_G.to_owned()],
                vec![],
                "network.rpc_unreachable",
                "backend unavailable",
            ),
            (
                vec![],
                vec![RESULT_G.to_owned()],
                "network.rpc_credential_refused",
                "answered a request with HTTP 401",
            ),
        ] {
            let rpc = endpoint_refusing(&[], Vec::new(), &failing, &unauthorized).await;
            let approvals = tempfile::TempDir::new().unwrap();
            let server = fx.server(&rpc, approvals.path());
            for attempt in 0..2 {
                let result = server
                    .call_stellar_pay(pay_args(destination))
                    .await
                    .expect("a business refusal");
                let json = json_of(&result);
                assert_eq!(result.is_error, Some(true), "{destination}: {json}");
                assert_eq!(
                    json["error"]["code"], code,
                    "{destination} #{attempt}: {json}"
                );
                assert!(
                    json["error"]["message"]
                        .as_str()
                        .is_some_and(|message| message.contains(detail)),
                    "{destination}: {json}"
                );
                assert!(json.get("data").is_none(), "no nonce: {json}");
            }
            assert_eq!(pending_count(approvals.path(), &fx.name), 0, "no approval");
            assert!(bodies(&rpc, "sendTransaction").await.is_empty(), "no send");
            let reads = read_keys(&rpc).await;
            assert!(reads.contains(&base_key), "{destination} reads the G key");
            assert!(
                !reads.contains(&account_ledger_key_xdr(OTHER_G)),
                "{destination}"
            );
        }

        // An absent account prepares with no identity view.
        let rpc = endpoint(&[], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let server = fx.server(&rpc, approvals.path());
        let data = prepare(&server, &pay_args(destination)).await;
        assert!(data["nonce"].is_string(), "{data}");
        assert!(read_keys(&rpc).await.contains(&base_key), "{destination}");
    }
}

/// `envelope` with a second native payment to `to` appended.
fn with_second_payment(envelope: &str, to: MuxedAccount) -> String {
    let TransactionEnvelope::Tx(mut tx) =
        TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
    else {
        panic!("a v1 envelope");
    };
    let mut operations = tx.tx.operations.to_vec();
    operations.push(stellar_xdr::Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: to,
            asset: stellar_xdr::Asset::Native,
            amount: 1,
        }),
    });
    tx.tx.operations = operations.try_into().unwrap();
    tx.tx.fee *= 2;
    stellar_xdr::WriteXdr::to_xdr_base64(&TransactionEnvelope::Tx(tx), Limits::none()).unwrap()
}

/// A successful commit carries the complete G, M0, and maximum-ID
/// destination, native and issued, and no `destinations` member. A
/// presented envelope with a second payment to another account refuses
/// `simulation.divergence` and sends nothing.
#[tokio::test]
#[serial]
async fn pay_commit_success_carries_the_complete_destination() {
    use stellar_agent_test_support::xdr_fixtures::{trustline_entry_xdr, trustline_ledger_key_xdr};
    let fx = Fixture::new();
    let trustline = (
        trustline_ledger_key_xdr(&source_g(), "USDC", RESULT_ISSUER),
        trustline_entry_xdr(&source_g(), "USDC", RESULT_ISSUER, 10_000_000_000),
    );
    for issued in [false, true] {
        for destination in [RESULT_G, RESULT_M0, RESULT_MMAX] {
            let rpc = endpoint(
                &[RESULT_G.to_owned(), RESULT_ISSUER.to_owned()],
                vec![trustline.clone()],
                &[],
            )
            .await;
            let approvals = tempfile::TempDir::new().unwrap();
            let server = fx.server(&rpc, approvals.path());
            let mut args = pay_args(destination);
            if issued {
                args.asset = format!("USDC:{RESULT_ISSUER}");
                args.amount = Some(serde_json::from_str(r#""10 USDC""#).unwrap());
            }
            let data = prepare(&server, &args).await;

            let mut diverged = commit_args(&args, &data);
            diverged.envelope_xdr = with_second_payment(
                &diverged.envelope_xdr,
                MuxedAccount::Ed25519(Uint256(
                    stellar_strkey::ed25519::PublicKey::from_string(OTHER_G)
                        .unwrap()
                        .0,
                )),
            );
            let refused = server.call_stellar_pay_commit(diverged).await.unwrap();
            assert_eq!(
                json_of(&refused)["error"]["code"],
                "simulation.divergence",
                "{destination}"
            );
            assert!(sent_payments(&rpc).await.is_empty(), "nothing is sent");

            let committed = server
                .call_stellar_pay_commit(commit_args(&args, &data))
                .await
                .unwrap();
            let json = json_of(&committed);
            assert_ne!(committed.is_error, Some(true), "{json}");
            assert_eq!(json["data"]["destination"], destination, "{json}");
            assert!(json["data"].get("destinations").is_none(), "{json}");
            assert_eq!(sent_payments(&rpc).await.len(), 1, "{destination}");
        }
    }
}

fn public_payment_server(
    fx: &Fixture,
    rpc: &MockServer,
    approvals: &std::path::Path,
    grants: &std::path::Path,
    toolsets: &std::path::Path,
    asset: &str,
) -> WalletServer {
    let server = gated_server(fx, rpc, approvals, grants, toolsets);
    stellar_agent_toolsets_install::write_toolset_for_test(
        toolsets,
        TOOLSET,
        &["propose-transaction", "sign-payment"],
        &[],
        "2026-06-02T00:00:00Z",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &crate::common::toolset_pin_key(),
    )
    .unwrap();
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let grant = build_attested_grant(
        TOOLSET.into(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        "1.0.0".into(),
        "0".repeat(64),
        "sign-payment".into(),
        RESULT_G.into(),
        asset.into(),
        1,
        100_000_000,
        process_uid_for_attestation().unwrap(),
        now,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &GRANT_KEY,
        &stellar_agent_core::approval::AttestationBinding::new(&fx.name, "stellar:testnet"),
    )
    .unwrap();
    ToolsetGrantStore::open(grants.to_owned(), now)
        .unwrap()
        .insert(grant)
        .unwrap();
    server
}

async fn public_payment_call(
    server: &WalletServer,
    action: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    json_of(
        &server
            .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                toolset: TOOLSET.into(),
                action: action.into(),
                chain_id: Some("stellar:testnet".into()),
                args,
            })
            .await
            .expect("public payment returns a business envelope"),
    )
}

fn matrix_asset(issued: bool) -> (String, Vec<(String, String)>) {
    use stellar_agent_test_support::xdr_fixtures::{trustline_entry_xdr, trustline_ledger_key_xdr};
    if issued {
        (
            format!("USDC:{RESULT_ISSUER}"),
            vec![(
                trustline_ledger_key_xdr(&source_g(), "USDC", RESULT_ISSUER),
                trustline_entry_xdr(&source_g(), "USDC", RESULT_ISSUER, 10_000_000_000),
            )],
        )
    } else {
        ("XLM".into(), Vec::new())
    }
}

fn matrix_args(destination: &str, issued: bool) -> StellarPayArgs {
    let mut args = pay_args(destination);
    if issued {
        args.asset = format!("USDC:{RESULT_ISSUER}");
        args.amount = Some(serde_json::from_str(r#""10 USDC""#).unwrap());
    }
    args
}

fn matrix_pay_wire(args: &StellarPayArgs) -> serde_json::Value {
    serde_json::json!({
        "chain_id": args.chain_id, "source": args.source, "destination": args.destination,
        "asset": args.asset, "amount": args.amount, "memo_id": args.memo_id,
    })
}

fn matrix_commit_wire(args: &StellarPayCommitArgs) -> serde_json::Value {
    serde_json::json!({
        "chain_id": args.chain_id, "source": args.source, "destination": args.destination,
        "asset": args.asset, "amount": args.amount, "memo_id": args.memo_id,
        "envelope_xdr": args.envelope_xdr, "nonce": args.nonce,
        "expires_at_unix_ms": args.expires_at_unix_ms,
    })
}

#[tokio::test]
#[serial]
async fn public_toolset_destination_read_failures_keep_their_codes_at_both_boundaries() {
    let fx = Fixture::new();
    let base_key = account_ledger_key_xdr(RESULT_G);
    for issued in [false, true] {
        for destination in [RESULT_G, RESULT_M0, RESULT_MMAX] {
            for (index, code) in ["network.rpc_unreachable", "network.rpc_credential_refused"]
                .into_iter()
                .enumerate()
            {
                let (asset, entries) = matrix_asset(issued);
                let rpc = endpoint(
                    &[RESULT_G.into(), RESULT_ISSUER.into()],
                    entries.clone(),
                    &[],
                )
                .await;
                let failing = endpoint_refusing(
                    &[RESULT_G.into(), RESULT_ISSUER.into()],
                    entries,
                    &if index == 0 {
                        vec![RESULT_G.into()]
                    } else {
                        Vec::new()
                    },
                    &if index == 1 {
                        vec![RESULT_G.into()]
                    } else {
                        Vec::new()
                    },
                )
                .await;
                let approvals = tempfile::tempdir().unwrap();
                let root = tempfile::tempdir().unwrap();
                let grants = root.path().join("grants.toml");
                let server = public_payment_server(
                    &fx,
                    &rpc,
                    approvals.path(),
                    &grants,
                    root.path(),
                    &asset,
                );
                let bad = public_payment_server(
                    &fx,
                    &failing,
                    approvals.path(),
                    &grants,
                    root.path(),
                    &asset,
                );
                let mut args = matrix_args(destination, issued);
                args.memo_id = Some(index as u64);
                for _ in 0..2 {
                    let refused =
                        public_payment_call(&bad, "stellar_pay", matrix_pay_wire(&args)).await;
                    assert_eq!(
                        refused["error"]["code"], code,
                        "public toolset preparation preserves read refusal: {refused}"
                    );
                    assert!(refused.get("data").is_none(), "no returned nonce");
                }
                let prepared =
                    public_payment_call(&server, "stellar_pay", matrix_pay_wire(&args)).await;
                assert_eq!(prepared["ok"], true, "{prepared}");
                let mut commit = commit_args(&args, &prepared["data"]);
                commit.memo_id = args.memo_id;
                let refused =
                    public_payment_call(&bad, "stellar_pay_commit", matrix_commit_wire(&commit))
                        .await;
                assert_eq!(
                    refused["error"]["code"], code,
                    "public toolset commit preserves read refusal: {refused}"
                );
                assert!(sent_payments(&failing).await.is_empty());
                assert_eq!(pending_count(approvals.path(), &fx.name), 0);
                assert!(
                    read_keys(&failing)
                        .await
                        .iter()
                        .filter(|key| **key == base_key)
                        .count()
                        >= 3
                );
                let result =
                    public_payment_call(&server, "stellar_pay_commit", matrix_commit_wire(&commit))
                        .await;
                assert_eq!(
                    result["ok"], true,
                    "the same nonce works after the read recovers: {result}"
                );
                let sent = sent_payments(&rpc).await;
                assert_eq!(sent.len(), 1);
                assert_eq!(
                    sent[0].destination,
                    stellar_agent_core::payment_accounts::PaymentAccount::parse(destination)
                        .unwrap()
                        .to_muxed_account()
                );
                assert_eq!(sent[0].amount, 100_000_000);
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn public_toolset_sep29_uses_the_full_destination_for_native_and_issued() {
    let fx = Fixture::new();
    let base_key = account_ledger_key_xdr(RESULT_G);
    for issued in [false, true] {
        for destination in [RESULT_G, RESULT_M0, RESULT_MMAX] {
            let (asset, mut entries) = matrix_asset(issued);
            let (data_key, data_entry) = memo_required_entry(RESULT_G);
            let unflagged = endpoint(
                &[RESULT_G.into(), RESULT_ISSUER.into()],
                entries.clone(),
                &[],
            )
            .await;
            entries.push((data_key.clone(), data_entry));
            let rpc = endpoint(&[RESULT_G.into(), RESULT_ISSUER.into()], entries, &[]).await;
            let approvals = tempfile::tempdir().unwrap();
            let root = tempfile::tempdir().unwrap();
            let grants = root.path().join("grants.toml");
            let server =
                public_payment_server(&fx, &rpc, approvals.path(), &grants, root.path(), &asset);
            let before_flag = public_payment_server(
                &fx,
                &unflagged,
                approvals.path(),
                &grants,
                root.path(),
                &asset,
            );
            let mut args = matrix_args(destination, issued);
            if destination == RESULT_G {
                let prepared =
                    public_payment_call(&before_flag, "stellar_pay", matrix_pay_wire(&args)).await;
                assert_eq!(prepared["ok"], true, "{prepared}");
                let commit = commit_args(&args, &prepared["data"]);
                let refused =
                    public_payment_call(&server, "stellar_pay_commit", matrix_commit_wire(&commit))
                        .await;
                assert_eq!(
                    refused["error"]["code"], "validation.memo_required",
                    "the G account's new flag is enforced at commit: {refused}"
                );
                let refused =
                    public_payment_call(&server, "stellar_pay", matrix_pay_wire(&args)).await;
                assert_eq!(
                    refused["error"]["code"], "validation.memo_required",
                    "the G account requires a memo at preparation: {refused}"
                );
                assert!(sent_payments(&rpc).await.is_empty());
                args.memo_id = Some(7);
            }
            let prepared =
                public_payment_call(&server, "stellar_pay", matrix_pay_wire(&args)).await;
            assert_eq!(
                prepared["ok"], true,
                "full payment destination governs SEP-29 at preparation: {prepared}"
            );
            let mut commit = commit_args(&args, &prepared["data"]);
            commit.memo_id = args.memo_id;
            let result =
                public_payment_call(&server, "stellar_pay_commit", matrix_commit_wire(&commit))
                    .await;
            assert_eq!(
                result["ok"], true,
                "full payment destination governs SEP-29 at commit: {result}"
            );
            let reads = read_keys(&rpc).await;
            assert!(
                reads.iter().filter(|key| **key == base_key).count() >= 2,
                "both boundaries read the G base"
            );
            assert_eq!(
                reads.contains(&data_key),
                destination == RESULT_G,
                "M destinations never read the memo data entry"
            );
            assert_eq!(sent_payments(&rpc).await.len(), 1);
            assert_eq!(result["data"]["destination"], destination);
            assert_eq!(pending_count(approvals.path(), &fx.name), 0);
        }
    }
}
