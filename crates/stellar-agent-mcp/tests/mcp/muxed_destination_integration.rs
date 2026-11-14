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
    Limits, MuxedAccount, MuxedAccountMed25519, OperationBody, PaymentOp, ReadXdr,
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
}

impl Respond for MuxRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
        let id = body["id"].clone();
        let raw = String::from_utf8_lossy(&request.body);
        let result = match body["method"].as_str().unwrap_or("") {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
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
    approvals: &std::path::Path,
    grants: &std::path::Path,
    toolsets: &std::path::Path,
) -> WalletServer {
    let profile = fixture.profile.clone();
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
    let server = gated_server(fx, approvals.path(), &grants, toolsets.path());
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

    // A grant for M17 or for its G base reaches the per-action approval for
    // M17; a grant for another ID does not.
    for (granted, first_invoke) in [(m17.clone(), false), (g(key), false), (m(key, 18), true)] {
        let toolsets = tempfile::TempDir::new().unwrap();
        let approvals = tempfile::TempDir::new().unwrap();
        let grants = approvals.path().join("grants.toml");
        insert_grant(fx, &grants, &granted);
        let server = gated_server(fx, approvals.path(), &grants, toolsets.path());
        let outcome = server
            .call_stellar_toolset_invoke(gated(&envelope, &m17))
            .await;
        match (first_invoke, outcome) {
            (false, Ok(result)) => {
                assert_eq!(
                    json_of(&result)["error"]["code"],
                    "policy.approval_required",
                    "the grant for {granted} covers M17"
                );
                let ApprovalKind::PaymentSimulated {
                    summary_to,
                    envelope_xdr_b64,
                    ..
                } = only_pending(approvals.path(), &fx.name)
                else {
                    panic!("a per-action payment approval");
                };
                assert_eq!(summary_to, m17);
                assert_eq!(payment_of(&envelope_xdr_b64).destination, muxed(key, 17));
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
        assert_eq!(receipt.destination, expected, "{destination}");
    }
}

/// An allowed `stellar_pay_commit` to M0 and M17 under a sizing engine
/// writes an audit payment leg whose `destination_sha256` is the SHA-256 of
/// the complete M address. No audit row holds the complete address.
#[tokio::test]
#[serial]
async fn mcp_payment_audit_leg_hashes_the_complete_destination() {
    use sha2::Digest as _;
    let fx = Fixture::new();
    let key = [0xD7; 32];
    for id in [0, 17] {
        let destination = m(key, id);
        let rpc = endpoint(&[g(key)], Vec::new(), &[]).await;
        let approvals = tempfile::TempDir::new().unwrap();
        let mut server = fx.server(&rpc, approvals.path());
        server.set_policy_engine_for_test(Arc::new(
            crate::common::v1_engine_mock::minimum_reserve_engine(
                &["stellar_pay", "stellar_pay_commit"],
                0,
            ),
        ));
        let args = pay_args(&destination);
        let data = prepare(&server, &args).await;
        let committed = server
            .call_stellar_pay_commit(commit_args(&args, &data))
            .await
            .unwrap();
        assert_ne!(committed.is_error, Some(true), "{}", json_of(&committed));
        assert_eq!(sent_payments(&rpc).await.len(), 1, "{destination}");
        drop(server);

        let redacted = stellar_agent_core::observability::redact_strkey_first5_last5(&destination);
        let expected =
            stellar_agent_core::hex::encode(&sha2::Sha256::digest(destination.as_bytes()));
        let rows = crate::common::audit_rows(&fx.profile);
        let legs: Vec<&serde_json::Value> = rows
            .iter()
            .filter_map(|row| row["legs"].as_array())
            .flatten()
            .filter(|leg| leg["destination_redacted"] == redacted.as_str())
            .collect();
        assert!(!legs.is_empty(), "{destination}: a payment leg: {rows:?}");
        for leg in legs {
            assert_eq!(leg["action"], "payment", "{destination}");
            assert_eq!(
                leg["destination_sha256"],
                expected.as_str(),
                "{destination}: the leg carries the complete destination's SHA-256"
            );
        }
        let log = std::fs::read_to_string(&fx.profile.audit_log_path).unwrap();
        assert!(
            !log.contains(&destination),
            "{destination}: no audit row holds the complete destination"
        );
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
