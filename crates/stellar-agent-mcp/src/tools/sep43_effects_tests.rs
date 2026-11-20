//! The effects decision through both SEP-43 transaction tools.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rmcp::model::CallToolResult;
use serde_json::{Value, json};
use stellar_agent_core::asset_id::CanonicalAsset;
use stellar_agent_core::policy::v1::criteria::Criterion;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::policy::v1::{AccountReservesView, PolicyEngineV1};
use stellar_agent_core::policy::{Decision, PolicyEngine};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, Asset, ContractId, Hash, HostFunction,
    InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData, LedgerKey, Limits, Memo,
    MuxedAccount, MuxedAccountMed25519, Operation, OperationBody, PaymentOp, PublicKey, ReadXdr,
    ScAddress, ScSymbol, ScVal, SequenceNumber, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, String32,
    Thresholds, Transaction, TransactionEnvelope, TransactionV1Envelope, Uint256, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

use crate::server::{Sep43SignAndSubmitTransactionArgs, WalletServer};
use crate::tools::common::assert_business_envelope;
use crate::tools::sep43_sign_transaction::Sep43SignTransactionArgs;

pub(crate) const SIGN: &str = "stellar_sep43_sign_transaction";
pub(crate) const SUBMIT: &str = "stellar_sep43_sign_and_submit_transaction";
pub(crate) const PAY: &str = "stellar_pay_commit";
pub(crate) const XLM: i64 = 10_000_000;
/// Each fixture enrolls a fresh wallet: the audit writer registry of the
/// test process keys writers by profile name, which is the wallet address.
static NEXT_SEED: AtomicUsize = AtomicUsize::new(0);
pub(crate) const A: [u8; 32] = [0xA1; 32];
pub(crate) const B: [u8; 32] = [0xB2; 32];
pub(crate) const OTHER: [u8; 32] = [0xC3; 32];
const WALLET_BALANCE: i64 = 100_000 * XLM;

// ─── Envelopes ───────────────────────────────────────────────────────────────

pub(crate) fn g(key: [u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(key)
        .to_string()
        .as_str()
        .to_owned()
}

fn public_key(seed: [u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

pub(crate) fn op(body: OperationBody) -> Operation {
    Operation {
        source_account: None,
        body,
    }
}

pub(crate) fn tx(
    source: [u8; 32],
    fee: u32,
    memo: Memo,
    operations: Vec<Operation>,
) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source)),
        fee,
        seq_num: SequenceNumber(1),
        memo,
        operations: operations.try_into().unwrap(),
        ..Default::default()
    }
}

pub(crate) fn encode(tx: Transaction) -> String {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// A wallet-sourced `BumpSequence`: a transaction without a value effect.
pub(crate) fn bump_sequence(source: [u8; 32]) -> String {
    encode(tx(
        source,
        100,
        Memo::None,
        vec![op(OperationBody::BumpSequence(
            stellar_xdr::BumpSequenceOp {
                bump_to: SequenceNumber(0),
            },
        ))],
    ))
}

/// The testnet native asset contract transfer of one stroop from the G
/// account of key `[1; 32]` to the C contract of key `[2; 32]`, the
/// envelope the payment tools refuse.
pub(crate) fn contract_transfer() -> String {
    use stellar_xdr::WriteXdr as _;
    let context = stellar_agent_core::sac_payment::SacPaymentContext::new(
        stellar_agent_core::profile::caip2::Caip2::Testnet,
        stellar_agent_core::approval::IntentAsset::Native,
    )
    .unwrap();
    stellar_xdr::TransactionEnvelope::Tx(stellar_agent_core::approval::fixtures::sac_transfer(
        &context,
    ))
    .to_xdr_base64(stellar_xdr::Limits::none())
    .unwrap()
}

/// An approval proof: the nonce and the attestation.
pub(crate) type Proof = (Option<String>, Option<String>);

pub(crate) fn muxed(key: [u8; 32], id: Option<u64>) -> MuxedAccount {
    match id {
        None => MuxedAccount::Ed25519(Uint256(key)),
        Some(id) => MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id,
            ed25519: Uint256(key),
        }),
    }
}

pub(crate) fn payment(destination: MuxedAccount, amount: i64) -> OperationBody {
    OperationBody::Payment(PaymentOp {
        destination,
        asset: Asset::Native,
        amount,
    })
}

fn native_contract() -> [u8; 32] {
    let id = CanonicalAsset::Native
        .sac_contract_id(TESTNET_PASSPHRASE)
        .unwrap();
    stellar_strkey::Contract::from_string(&id).unwrap().0
}

fn account_address(key: [u8; 32]) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))))
}

fn call(contract: [u8; 32], name: &str, args: Vec<ScVal>) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash(contract))),
            function_name: ScSymbol(name.try_into().unwrap()),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: Default::default(),
    }
}

/// A native asset contract transfer `from` authorizes.
fn transfer(from: [u8; 32], to: [u8; 32], amount: i128) -> SorobanAuthorizedInvocation {
    call(
        native_contract(),
        "transfer",
        vec![
            ScVal::Address(account_address(from)),
            ScVal::Address(account_address(to)),
            ScVal::from(amount),
        ],
    )
}

fn invoke(roots: Vec<SorobanAuthorizedInvocation>) -> OperationBody {
    OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function: HostFunction::InvokeContract(InvokeContractArgs::default()),
        auth: roots
            .into_iter()
            .map(|root_invocation| SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    })
}

/// A transaction of `bodies` from `source` with 100 stroops per operation.
fn source_tx(source: [u8; 32], memo: Memo, bodies: Vec<OperationBody>) -> String {
    let fee = 100 * u32::try_from(bodies.len()).unwrap();
    encode(tx(source, fee, memo, bodies.into_iter().map(op).collect()))
}

// ─── Policy ──────────────────────────────────────────────────────────────────

pub(crate) fn rule(tool: &str, criteria: Vec<Box<dyn Criterion>>, opt_in: bool) -> PolicyRule {
    PolicyRule {
        r#match: RuleMatch {
            tool: tool.into(),
            chain: "*".into(),
        },
        criteria,
        decision: Decision::Allow,
        allow_opaque_signing: opt_in,
    }
}

/// Allowing rules for both transaction tools.
fn tools(opt_in: bool) -> Vec<PolicyRule> {
    vec![rule(SIGN, vec![], opt_in), rule(SUBMIT, vec![], opt_in)]
}

fn per_tx(cap: i128) -> Box<dyn Criterion> {
    Box::new(stellar_agent_core::policy::v1::criteria::PerTxCapCriterion::new("native".into(), cap))
}

fn per_day(cap: i128) -> Box<dyn Criterion> {
    Box::new(
        stellar_agent_core::policy::v1::criteria::PerPeriodCapCriterion::new(
            "native".into(),
            stellar_agent_core::policy::v1::criteria::per_period_cap::Window::parse("1d").unwrap(),
            cap,
        ),
    )
}

fn rate(calls: u32) -> Box<dyn Criterion> {
    Box::new(
        stellar_agent_core::policy::v1::criteria::rate_limit::RateLimitCriterion::new(
            stellar_agent_core::policy::v1::criteria::per_period_cap::Window::parse("1m").unwrap(),
            calls,
        ),
    )
}

// ─── RPC ─────────────────────────────────────────────────────────────────────

/// One ledger account the fixture endpoint serves.
#[derive(Clone, Default)]
pub(crate) struct Account {
    pub balance: i64,
    pub home_domain: Option<&'static str>,
    pub fails: bool,
    /// Plain ed25519 signers at weight 1, besides the master key.
    pub signers: Vec<[u8; 32]>,
    /// A read answers HTTP 401.
    pub rejects: bool,
    /// A read answers an entry that is not account XDR.
    pub bad_xdr: bool,
    /// The codes of the trustlines it holds on assets issued by `OTHER`.
    pub trustlines: Vec<[u8; 4]>,
}

/// The trustline entry of a trustline key `key` the fixture account holds.
fn held_trustline(ledger: &Ledger, key: &stellar_xdr::LedgerKeyTrustLine) -> Option<String> {
    let PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) = key.account_id.0;
    let stellar_xdr::TrustLineAsset::CreditAlphanum4(asset) = &key.asset else {
        return None;
    };
    let account = ledger.accounts.lock().unwrap().get(&g(bytes)).cloned()?;
    let held = account.trustlines.contains(&asset.asset_code.0)
        && asset.issuer == AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER)));
    held.then(|| {
        LedgerEntryData::Trustline(stellar_xdr::TrustLineEntry {
            account_id: key.account_id.clone(),
            asset: key.asset.clone(),
            balance: 0,
            limit: i64::MAX,
            flags: 1,
            ext: stellar_xdr::TrustLineEntryExt::V0,
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    })
}

#[derive(Default)]
pub(crate) struct Ledger {
    accounts: Mutex<HashMap<String, Account>>,
    reads: Mutex<Vec<String>>,
    sends: AtomicUsize,
    /// Entry reads answer `latestLedger` 0.
    bad_latest: std::sync::atomic::AtomicBool,
    /// Runs once when an entry read next asks for this account.
    on_read: Mutex<Option<ReadHook>>,
}

/// An account and the action its next read runs.
type ReadHook = (String, Box<dyn FnOnce() + Send>);

struct LedgerRpc(Arc<Ledger>);

impl Respond for LedgerRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let request: Value = serde_json::from_slice(&request.body).unwrap();
        let answer = |body: Value| {
            let mut envelope = json!({"jsonrpc": "2.0", "id": request["id"]});
            envelope
                .as_object_mut()
                .unwrap()
                .extend(body.as_object().unwrap().clone());
            ResponseTemplate::new(200).set_body_json(envelope)
        };
        match request["method"].as_str().unwrap() {
            "getNetwork" => answer(json!({"result":
                stellar_agent_test_support::signed_envelope::get_network_result(TESTNET_PASSPHRASE)
            })),
            "getLatestLedger" => answer(json!({"result":
                {"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 23}
            })),
            "getLedgerEntries" => {
                let mut entries = Vec::new();
                for key in request["params"]["keys"].as_array().unwrap() {
                    let key = key.as_str().unwrap();
                    let account = match LedgerKey::from_xdr_base64(key, Limits::none()).unwrap() {
                        LedgerKey::Account(account) => account,
                        LedgerKey::Trustline(trustline) => {
                            if let Some(xdr) = held_trustline(&self.0, &trustline) {
                                entries.push(json!({
                                    "key": key, "xdr": xdr, "lastModifiedLedgerSeq": 100,
                                }));
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    let PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) = account.account_id.0;
                    let id = g(bytes);
                    self.0.reads.lock().unwrap().push(id.clone());
                    let hook = self
                        .0
                        .on_read
                        .lock()
                        .unwrap()
                        .take_if(|(account, _)| *account == id);
                    if let Some((_, action)) = hook {
                        action();
                    }
                    let Some(fixture) = self.0.accounts.lock().unwrap().get(&id).cloned() else {
                        continue;
                    };
                    if fixture.fails {
                        return answer(
                            json!({"error": {"code": -32603, "message": "fixture failure"}}),
                        );
                    }
                    if fixture.rejects {
                        return ResponseTemplate::new(401);
                    }
                    entries.push(json!({
                        "key": key,
                        "xdr": match fixture.bad_xdr {
                            true => "AAAA".to_owned(),
                            false => account_entry(bytes, &fixture),
                        },
                        "lastModifiedLedgerSeq": 100,
                    }));
                }
                let latest = match self.0.bad_latest.load(Ordering::SeqCst) {
                    true => 0,
                    false => 1000,
                };
                answer(json!({"result": {"entries": entries, "latestLedger": latest}}))
            }
            "sendTransaction" => {
                self.0.sends.fetch_add(1, Ordering::SeqCst);
                answer(json!({"error": {"code": -32603, "message": "fixture send failure"}}))
            }
            _ => answer(json!({"error": {"code": -32601, "message": "method not found"}})),
        }
    }
}

/// A fixture endpoint that serves `accounts` with their balances.
pub(crate) async fn ledger_server(accounts: &[([u8; 32], i64)]) -> MockServer {
    let ledger = Arc::new(Ledger::default());
    for (key, balance) in accounts {
        ledger.accounts.lock().unwrap().insert(
            g(*key),
            Account {
                balance: *balance,
                ..Default::default()
            },
        );
    }
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(LedgerRpc(ledger))
        .mount(&rpc)
        .await;
    rpc
}

fn account_entry(key: [u8; 32], fixture: &Account) -> String {
    LedgerEntryData::Account(AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))),
        balance: fixture.balance,
        seq_num: SequenceNumber(100),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::from(
            stellar_xdr::StringM::<32>::try_from(fixture.home_domain.unwrap_or_default()).unwrap(),
        ),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: fixture
            .signers
            .iter()
            .map(|key| stellar_xdr::Signer {
                key: stellar_xdr::SignerKey::Ed25519(Uint256(*key)),
                weight: 1,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        ext: AccountEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

// ─── Fixture ─────────────────────────────────────────────────────────────────

pub(crate) struct Fixture {
    /// The wallet account key.
    pub key: [u8; 32],
    pub server: WalletServer,
    pub profile: Profile,
    pub ledger: Arc<Ledger>,
    pub rpc: MockServer,
    seed_reads: Arc<AtomicUsize>,
    /// The count of the seed read that fails; 0 fails none.
    failing_seed_read: Arc<AtomicUsize>,
    pub audit: std::path::PathBuf,
    pub dir: tempfile::TempDir,
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _sandbox: stellar_agent_test_support::sandbox::StateSandbox,
}

impl Fixture {
    pub(crate) async fn new(rules: Vec<PolicyRule>) -> Self {
        Self::with(rules, |_| {}).await
    }

    /// A testnet wallet whose signer, audit key and identity are enrolled,
    /// served by a fixture endpoint that holds the wallet account.
    pub(crate) async fn with(rules: Vec<PolicyRule>, edit: impl FnOnce(&mut Profile)) -> Self {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut seed = [0x5C; 32];
        seed[..8].copy_from_slice(&NEXT_SEED.fetch_add(1, Ordering::SeqCst).to_be_bytes());
        let key = public_key(seed);
        let wallet = g(key);
        let seed_reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seed_reads);
        let failing_seed_read = Arc::new(AtomicUsize::new(0));
        let failing = Arc::clone(&failing_seed_read);
        let seed_account = wallet.clone();
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                "svc-s43fx",
                &wallet,
                Arc::new(move || {
                    let read = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if read == failing.load(Ordering::SeqCst) {
                        stellar_agent_test_support::keyring_mock::inject_error(
                            "svc-s43fx",
                            &seed_account,
                            keyring_core::Error::NoStorageAccess(
                                std::io::Error::other("locked").into(),
                            ),
                        )
                        .unwrap();
                    }
                }),
            ),
        ])
        .unwrap();
        let ledger = Arc::new(Ledger::default());
        ledger.accounts.lock().unwrap().insert(
            wallet.clone(),
            Account {
                balance: WALLET_BALANCE,
                ..Default::default()
            },
        );
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(LedgerRpc(Arc::clone(&ledger)))
            .mount(&rpc)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        let mut profile = Profile::builder_testnet("svc-s43fx", &wallet, "n-svc", "n-acct")
            .with_noop_engine()
            .rpc_url(rpc.uri())
            .audit_log_path(&audit)
            .build();
        edit(&mut profile);
        keyring_core::Entry::new("svc-s43fx", &wallet)
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey(seed)
                    .as_unredacted()
                    .to_string()
                    .as_str(),
            )
            .unwrap();
        let coord = profile.audit_log_hash_chain_key_id.clone();
        keyring_core::Entry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x41u8; 32]))
            .unwrap();
        keyring_core::Entry::new("n-svc", "n-acct")
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]))
            .unwrap();
        crate::tools::identity_fixture::store_signer_identity(&profile, seed);
        let mut server = WalletServer::new(profile.clone()).unwrap();
        let name = server.profile_name_for_approval();
        server.set_policy_engine_for_test(Arc::new(engine(&name, rules)));
        Self {
            key,
            server,
            profile,
            ledger,
            rpc,
            seed_reads,
            failing_seed_read,
            audit,
            dir,
            _home: home,
            _sandbox: sandbox,
        }
    }

    /// Serves `key` with `balance` and an optional home domain.
    pub(crate) fn account(&self, key: [u8; 32], balance: i64, home_domain: Option<&'static str>) {
        self.ledger.accounts.lock().unwrap().insert(
            g(key),
            Account {
                balance,
                home_domain,
                ..Default::default()
            },
        );
    }

    /// Makes every read of `key` fail at the endpoint.
    pub(crate) fn failing(&self, key: [u8; 32]) {
        self.ledger.accounts.lock().unwrap().insert(
            g(key),
            Account {
                fails: true,
                ..Default::default()
            },
        );
    }

    /// Serves `key` as an account whose signer set lists the wallet key
    /// exactly when `member`.
    pub(crate) fn source(&self, key: [u8; 32], member: bool) {
        self.ledger.accounts.lock().unwrap().insert(
            g(key),
            Account {
                balance: WALLET_BALANCE,
                signers: member.then_some(self.key).into_iter().collect(),
                ..Default::default()
            },
        );
    }

    /// Replaces the served account of `key`.
    pub(crate) fn serve(&self, key: [u8; 32], account: Account) {
        self.ledger.accounts.lock().unwrap().insert(g(key), account);
    }

    /// Runs `action` once, when the endpoint next reads the account of `key`.
    pub(crate) fn on_read(&self, key: [u8; 32], action: impl FnOnce() + Send + 'static) {
        *self.ledger.on_read.lock().unwrap() = Some((g(key), Box::new(action)));
    }

    /// A wallet transaction of `bodies` without a memo.
    pub(crate) fn tx(&self, bodies: Vec<OperationBody>) -> String {
        source_tx(self.key, Memo::None, bodies)
    }

    /// A native asset contract transfer the wallet authorizes.
    pub(crate) fn transfer(&self, to: [u8; 32], amount: i128) -> SorobanAuthorizedInvocation {
        transfer(self.key, to, amount)
    }

    /// Replaces the server, as a restart does, keeping state and policy.
    pub(crate) fn restart(&mut self, rules: Vec<PolicyRule>) {
        let mut server = WalletServer::new(self.profile.clone()).unwrap();
        let name = server.profile_name_for_approval();
        server.set_policy_engine_for_test(Arc::new(engine(&name, rules)));
        self.server = server;
    }

    pub(crate) async fn sign(&self, transaction_xdr: String) -> CallToolResult {
        self.sign_with(transaction_xdr, Proof::default()).await
    }

    pub(crate) async fn submit(&self, transaction_xdr: String) -> CallToolResult {
        self.submit_with(transaction_xdr, Proof::default()).await
    }

    /// The sign-only call with an approval proof.
    pub(crate) async fn sign_with(&self, transaction_xdr: String, proof: Proof) -> CallToolResult {
        self.server
            .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
                chain_id: "stellar:testnet".into(),
                transaction_xdr,
                network_passphrase: None,
                address: None,
                approval_nonce: proof.0,
                approval_attestation: proof.1,
            })
            .await
            .expect("a business result")
    }

    /// The submitting call with an approval proof.
    pub(crate) async fn submit_with(
        &self,
        transaction_xdr: String,
        proof: Proof,
    ) -> CallToolResult {
        self.server
            .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
                chain_id: "stellar:testnet".into(),
                transaction_xdr,
                network_passphrase: None,
                address: None,
                approval_nonce: proof.0,
                approval_attestation: proof.1,
            })
            .await
            .expect("a business result")
    }

    /// Account reads of `key` so far.
    pub(crate) fn reads(&self, key: [u8; 32]) -> usize {
        let id = g(key);
        self.ledger
            .reads
            .lock()
            .unwrap()
            .iter()
            .filter(|read| **read == id)
            .count()
    }

    pub(crate) async fn requests(&self) -> usize {
        self.rpc.received_requests().await.unwrap().len()
    }

    pub(crate) fn seed_reads(&self) -> usize {
        self.seed_reads.load(Ordering::SeqCst)
    }

    /// Fails the seed read that follows the next `skipped` seed reads.
    pub(crate) fn fail_seed_read_after(&self, skipped: usize) {
        self.failing_seed_read
            .store(self.seed_reads() + skipped + 1, Ordering::SeqCst);
    }

    /// Durable usage of the daily window of `bucket`.
    pub(crate) fn usage(&self, bucket: &str) -> (i128, u32) {
        let name = self.server.profile_name_for_approval();
        let state = PolicyStateStore::new();
        PersistedWindowStore::for_profile(&name)
            .load_into(&name, &self.profile, &state)
            .unwrap();
        let window = if bucket == "rate_limit" { 60 } else { 86_400 };
        state
            .query_window(
                &StateKey::new(&name, 1, bucket, window),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap()
    }

    /// Every audit row of `kind`.
    pub(crate) fn rows(&self, kind: &str) -> Vec<Value> {
        std::fs::read_to_string(&self.audit)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["kind"] == kind)
            .collect()
    }
}

pub(crate) fn engine(name: &str, rules: Vec<PolicyRule>) -> PolicyEngineV1 {
    PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            signature: None,
            rules,
        },
        name.into(),
    )
}

/// The refusal code; asserts that no signature was returned.
pub(crate) fn refused(result: &CallToolResult) -> (String, String) {
    let (code, message, text) = assert_business_envelope(result);
    assert!(!text.contains("signedTxXdr"), "{text}");
    (code, message)
}

/// Asserts a returned signature.
pub(crate) fn signed(result: &CallToolResult) {
    let text = result.content[0].as_text().unwrap().text.clone();
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(text.contains("signedTxXdr"), "{text}");
}

fn pay_rule(criteria: Vec<Box<dyn Criterion>>) -> Vec<PolicyRule> {
    let mut rules = tools(false);
    rules.push(rule(PAY, criteria, false));
    rules
}

// ─── Decisions ───────────────────────────────────────────────────────────────

/// A payment over the pay rule's cap refuses through both tools with that
/// rule's code before the seed is read; a payment within the cap signs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_payment_over_the_pay_cap_denies_through_both_tools() {
    let fx = Fixture::new(pay_rule(vec![per_tx(10 * i128::from(XLM))])).await;
    let over = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    for result in [fx.sign(over.clone()).await, fx.submit(over).await] {
        assert_eq!(refused(&result).0, "policy.deny.per_tx_cap_exceeded");
    }
    assert_eq!(fx.seed_reads(), 0, "no seed read before a denial");
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 5 * XLM)])).await);
}

/// Each operation is decided by the rule of its own payment tool: an
/// allowing pay rule does not admit a create-account, trustline or claim.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn each_route_is_decided_by_its_own_tool_rule() {
    let routes = [
        (
            "stellar_create_account_commit",
            OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
                destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(B))),
                starting_balance: 2 * XLM,
            }),
        ),
        (
            "stellar_trustline_commit",
            OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
                line: stellar_xdr::ChangeTrustAsset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                    asset_code: stellar_xdr::AssetCode4(*b"USDC"),
                    issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER))),
                }),
                limit: 100 * XLM,
            }),
        ),
        (
            "stellar_claim_commit",
            OperationBody::ClaimClaimableBalance(stellar_xdr::ClaimClaimableBalanceOp {
                balance_id: stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                    [0xAB; 32],
                )),
            }),
        ),
        (PAY, payment(muxed(A, None), XLM)),
    ];
    for (tool, body) in routes {
        let fx = Fixture::new(pay_rule(vec![])).await;
        let result = fx.sign(fx.tx(vec![body.clone()])).await;
        if tool == PAY {
            signed(&result);
            continue;
        }
        assert_eq!(refused(&result).0, "policy.deny.no_matching_rule", "{tool}");
        drop(fx);
        let mut rules = pay_rule(vec![]);
        rules.push(rule(tool, vec![], false));
        let fx = Fixture::new(rules).await;
        signed(&fx.sign(fx.tx(vec![body])).await);
    }
}

/// A transaction without a value effect keeps the tool rule's decision: it
/// signs without a payment rule, sends no request and records no legs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_transaction_without_a_value_effect_keeps_the_tool_rule_decision() {
    let fx = Fixture::new(tools(false)).await;
    signed(&fx.sign(bump_sequence(fx.key)).await);
    assert_eq!(fx.requests().await, 0, "no account read");
    let rows = fx.rows("opaque_payload_signed");
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].to_string().contains("\"legs\""), "{}", rows[0]);
}

/// Allowed legs are admitted with the classification the evaluation
/// returned: an unlisted recipient charges the unlisted budget.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_unlisted_recipient_is_admitted_with_its_classification() {
    use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind, UnlistedBudget, UnlistedMode,
    };
    let budget = UnlistedBudget::new(
        "native".into(),
        10 * i128::from(XLM),
        15 * i128::from(XLM),
        stellar_agent_core::policy::v1::criteria::per_period_cap::Window::parse("1d").unwrap(),
    );
    let fx = Fixture::new(pay_rule(vec![Box::new(
        CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::GAccount], vec![g(A)])
            .with_unlisted(UnlistedMode::Budget(budget)),
    )]))
    .await;
    let unlisted = || fx.tx(vec![payment(muxed(B, None), 6 * XLM)]);
    signed(&fx.sign(unlisted()).await);
    signed(&fx.sign(unlisted()).await);
    assert_eq!(
        refused(&fx.sign(unlisted()).await).0,
        "policy.deny.unlisted_budget_exceeded"
    );
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 6 * XLM)])).await);
}

/// An `approval_above` escalation of a transaction no approval surface shows
/// refuses: a payment beside a second operation has no approval
/// continuation.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_operation_that_needs_approval_refuses() {
    let fx = Fixture::new(pay_rule(vec![Box::new(
        stellar_agent_core::policy::v1::criteria::approval_above::ApprovalAboveCriterion::new(
            "native".into(),
            10 * i128::from(XLM),
        ),
    )]))
    .await;
    assert_eq!(
        refused(
            &fx.sign(fx.tx(vec![
                payment(muxed(A, None), 11 * XLM),
                payment(muxed(B, None), XLM),
            ]))
            .await
        )
        .0,
        "policy.approval_required_unsupported"
    );
    signed(
        &fx.sign(fx.tx(vec![payment(muxed(A, None), 10 * XLM)]))
            .await,
    );
}

// ─── Decoder outcomes ────────────────────────────────────────────────────────

/// One operation per signed amount field the decoder validates, with that
/// field negative.
fn negative_fields() -> Vec<(OperationBody, &'static str)> {
    use stellar_xdr::{
        ChangeTrustOp, ClawbackOp, CreateAccountOp, CreateClaimableBalanceOp,
        CreatePassiveSellOfferOp, LiquidityPoolDepositOp, LiquidityPoolWithdrawOp,
        ManageBuyOfferOp, ManageSellOfferOp, PathPaymentStrictReceiveOp, PathPaymentStrictSendOp,
    };
    let receive = PathPaymentStrictReceiveOp::default();
    let send = PathPaymentStrictSendOp::default();
    let deposit = LiquidityPoolDepositOp::default();
    let withdraw = LiquidityPoolWithdrawOp::default();
    vec![
        (payment(muxed(A, None), -1), "Payment.amount"),
        (
            OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                send_max: -1,
                ..receive.clone()
            }),
            "PathPaymentStrictReceive.send_max",
        ),
        (
            OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                dest_amount: -1,
                ..receive
            }),
            "PathPaymentStrictReceive.dest_amount",
        ),
        (
            OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_amount: -1,
                ..send.clone()
            }),
            "PathPaymentStrictSend.send_amount",
        ),
        (
            OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                dest_min: -1,
                ..send
            }),
            "PathPaymentStrictSend.dest_min",
        ),
        (
            OperationBody::CreateAccount(CreateAccountOp {
                starting_balance: -1,
                ..Default::default()
            }),
            "CreateAccount.starting_balance",
        ),
        (
            OperationBody::CreateClaimableBalance(CreateClaimableBalanceOp {
                amount: -1,
                ..Default::default()
            }),
            "CreateClaimableBalance.amount",
        ),
        (
            OperationBody::Clawback(ClawbackOp {
                amount: -1,
                ..Default::default()
            }),
            "Clawback.amount",
        ),
        (
            OperationBody::ManageSellOffer(ManageSellOfferOp {
                amount: -1,
                ..Default::default()
            }),
            "ManageSellOffer.amount",
        ),
        (
            OperationBody::ManageBuyOffer(ManageBuyOfferOp {
                buy_amount: -1,
                ..Default::default()
            }),
            "ManageBuyOffer.buy_amount",
        ),
        (
            OperationBody::CreatePassiveSellOffer(CreatePassiveSellOfferOp {
                amount: -1,
                ..Default::default()
            }),
            "CreatePassiveSellOffer.amount",
        ),
        (
            OperationBody::ChangeTrust(ChangeTrustOp {
                limit: -1,
                ..Default::default()
            }),
            "ChangeTrust.limit",
        ),
        (
            OperationBody::LiquidityPoolDeposit(LiquidityPoolDepositOp {
                max_amount_a: -1,
                ..deposit.clone()
            }),
            "LiquidityPoolDeposit.max_amount_a",
        ),
        (
            OperationBody::LiquidityPoolDeposit(LiquidityPoolDepositOp {
                max_amount_b: -1,
                ..deposit
            }),
            "LiquidityPoolDeposit.max_amount_b",
        ),
        (
            OperationBody::LiquidityPoolWithdraw(LiquidityPoolWithdrawOp {
                amount: -1,
                ..withdraw.clone()
            }),
            "LiquidityPoolWithdraw.amount",
        ),
        (
            OperationBody::LiquidityPoolWithdraw(LiquidityPoolWithdrawOp {
                min_amount_a: -1,
                ..withdraw.clone()
            }),
            "LiquidityPoolWithdraw.min_amount_a",
        ),
        (
            OperationBody::LiquidityPoolWithdraw(LiquidityPoolWithdrawOp {
                min_amount_b: -1,
                ..withdraw
            }),
            "LiquidityPoolWithdraw.min_amount_b",
        ),
    ]
}

fn fee_bump(payer: [u8; 32], fee: i64, inner: Transaction) -> String {
    use stellar_xdr::{
        FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx,
    };
    TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: muxed(payer, None),
            fee,
            inner_tx: FeeBumpTransactionInnerTx::Tx(TransactionV1Envelope {
                tx: inner,
                signatures: Default::default(),
            }),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// Every negative operation field refuses with `sep43.invalid_xdr` naming
/// its index, kind and field, through both tools, inside a fee bump and
/// under another source, before any account read or seed read. Malformed and
/// legacy envelopes refuse the same way.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn negative_operation_fields_map_to_invalid_xdr_before_external_work() {
    let fx = Fixture::new(tools(true)).await;
    for (body, field) in negative_fields() {
        let bump = bump_sequence(fx.key);
        let TransactionEnvelope::Tx(bump) =
            TransactionEnvelope::from_xdr_base64(&bump, Limits::none()).unwrap()
        else {
            panic!("a v1 envelope")
        };
        let mut foreign = op(body.clone());
        foreign.source_account = Some(muxed(OTHER, None));
        let envelopes = [
            (fx.tx(vec![body.clone()]), 0),
            (
                fx.tx(vec![bump.tx.operations[0].body.clone(), body.clone()]),
                1,
            ),
            (
                fee_bump(fx.key, 1_000, tx(fx.key, 100, Memo::None, vec![op(body)])),
                0,
            ),
            (encode(tx(fx.key, 100, Memo::None, vec![foreign])), 0),
        ];
        for (envelope, index) in envelopes {
            for result in [fx.sign(envelope.clone()).await, fx.submit(envelope).await] {
                let (code, message) = refused(&result);
                assert_eq!(code, "sep43.invalid_xdr", "{field}: {message}");
                assert!(
                    message.ends_with(&format!("operation {index} has a negative {field}")),
                    "{message}"
                );
            }
        }
    }
    let legacy = TransactionEnvelope::TxV0(stellar_xdr::TransactionV0Envelope::default())
        .to_xdr_base64(Limits::none())
        .unwrap();
    for (envelope, detail) in [
        (legacy, "legacy V0 transaction envelopes are not supported"),
        ("AAAA".to_owned(), ""),
    ] {
        let (code, message) = refused(&fx.sign(envelope).await);
        assert_eq!(code, "sep43.invalid_xdr", "{message}");
        assert!(message.ends_with(detail), "{message}");
    }
    assert_eq!(fx.requests().await, 0, "no account read");
    assert_eq!(fx.seed_reads(), 0, "no seed read");
}

/// A text memo that is not UTF-8 refuses a valued transaction, classic or
/// contract, mixed or not, with `sep43.invalid_xdr` and no account read.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_unreadable_text_memo_refuses_a_valued_transaction() {
    let fx = Fixture::new(pay_rule(vec![])).await;
    let memo = Memo::Text(vec![0xff].try_into().unwrap());
    let swap = call([9; 32], "swap", vec![]);
    for body in [
        payment(muxed(A, None), XLM),
        invoke(vec![fx.transfer(A, 1)]),
        invoke(vec![swap, fx.transfer(A, 1)]),
    ] {
        let envelope = source_tx(fx.key, memo.clone(), vec![body]);
        for result in [fx.sign(envelope.clone()).await, fx.submit(envelope).await] {
            let (code, message) = refused(&result);
            assert_eq!(code, "sep43.invalid_xdr");
            assert!(
                message.ends_with("the text memo of a valued transaction is not valid UTF-8"),
                "{message}"
            );
        }
    }
    assert_eq!(fx.requests().await, 0);
    assert_eq!(fx.seed_reads(), 0);
}

/// A text memo that is not UTF-8 refuses a transaction whose only effect is
/// a pool share `ChangeTrust` with `sep43.invalid_xdr`, as it refuses a
/// credit `ChangeTrust`, with no account read.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_unreadable_text_memo_refuses_a_pool_share_trustline() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let memo = Memo::Text(vec![0xff].try_into().unwrap());
    for body in [trustline_on(*b"USDC", 100 * XLM), pool_share_trustline()] {
        let envelope = source_tx(fx.key, memo.clone(), vec![body]);
        for result in [fx.sign(envelope.clone()).await, fx.submit(envelope).await] {
            let (code, message) = refused(&result);
            assert_eq!(code, "sep43.invalid_xdr");
            assert!(
                message.ends_with("the text memo of a valued transaction is not valid UTF-8"),
                "{message}"
            );
        }
    }
    assert_eq!(fx.requests().await, 0);
    assert_eq!(fx.seed_reads(), 0);
}

/// A merge and an authority change refuse with their fixed texts even under
/// a rule that opts into unvalued effects.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_merge_and_an_authority_change_refuse_under_the_opt_in() {
    let fx = Fixture::new(tools(true)).await;
    for (body, text) in [
        (
            OperationBody::AccountMerge(muxed(A, None)),
            "the transaction merges an account; a merge moves the balance the account holds \
             when it applies, which no signed limit bounds",
        ),
        (
            OperationBody::SetOptions(stellar_xdr::SetOptionsOp {
                master_weight: Some(0),
                ..Default::default()
            }),
            "the transaction changes a signer, the master weight or a threshold; the change \
             gives another key authority outside every signed limit",
        ),
    ] {
        let envelope = fx.tx(vec![body]);
        for result in [fx.sign(envelope.clone()).await, fx.submit(envelope).await] {
            let (code, message) = refused(&result);
            assert_eq!(code, "policy.deny.unsizable_value_effect");
            assert!(message.contains(text), "{message}");
        }
    }
    assert_eq!(fx.seed_reads(), 0);
}

/// An unvalued effect needs the tool rule's opt-in: a nonzero offer and a
/// negative token argument refuse without it and sign with it. A zero offer
/// deletion has no effect and signs without it.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_unvalued_effect_needs_the_rules_opt_in() {
    let offer = |amount| {
        OperationBody::ManageSellOffer(stellar_xdr::ManageSellOfferOp {
            amount,
            price: stellar_xdr::Price { n: 1, d: 1 },
            ..Default::default()
        })
    };
    for opt_in in [false, true] {
        let mut rules = tools(opt_in);
        rules.push(rule(PAY, vec![per_tx(1)], false));
        let fx = Fixture::new(rules).await;
        signed(&fx.sign(fx.tx(vec![offer(0)])).await);
        for (body, label) in [
            (offer(5), "offer"),
            (invoke(vec![fx.transfer(A, -1)]), "contract_invocation"),
        ] {
            let result = fx.sign(fx.tx(vec![body])).await;
            if opt_in {
                signed(&result);
            } else {
                let (code, message) = refused(&result);
                assert_eq!(code, "policy.deny.unsizable_value_effect");
                assert!(
                    message.contains(&format!(
                        "the transaction holds an effect the wallet cannot value ({label}); \
                         the rule for this tool does not set allow_opaque_signing"
                    )),
                    "{message}"
                );
            }
        }
        if opt_in {
            let rows = fx.rows("opaque_payload_signed");
            assert!(rows.iter().all(|row| !row.to_string().contains("\"legs\"")));
        }
    }
}

/// A mixed invocation needs the opt-in, and each retained token leg is
/// decided by the pay rule: over the cap refuses, within it signs and charges
/// the period window with the audit leg naming the contract.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_mixed_invocation_evaluates_its_legs_and_needs_the_opt_in() {
    let swap = || call([9; 32], "swap", vec![]);
    let cap = || {
        vec![
            per_tx(10 * i128::from(XLM)),
            per_day(1_000 * i128::from(XLM)),
        ]
    };
    let fx = Fixture::new(pay_rule(cap())).await;
    let mixed = |amount| fx.tx(vec![invoke(vec![swap(), fx.transfer(A, amount)])]);
    let (code, message) = refused(&fx.sign(mixed(XLM.into())).await);
    assert_eq!(code, "policy.deny.unsizable_value_effect");
    assert!(message.contains("(contract_invocation)"), "{message}");
    drop(fx);

    let mut rules = tools(true);
    rules.push(rule(PAY, cap(), false));
    let fx = Fixture::new(rules).await;
    let mixed = |amount| fx.tx(vec![invoke(vec![swap(), fx.transfer(A, amount)])]);
    assert_eq!(
        refused(&fx.sign(mixed((11 * XLM).into())).await).0,
        "policy.deny.per_tx_cap_exceeded"
    );
    signed(&fx.sign(mixed((5 * XLM).into())).await);
    assert_eq!(fx.usage("native"), (5 * i128::from(XLM), 1));
    let rows = fx.rows("opaque_payload_signed");
    let legs = &rows[0]["legs"];
    assert_eq!(legs.as_array().map(Vec::len), Some(1), "{rows:?}");
    let contract = stellar_strkey::Contract(native_contract()).to_string();
    assert_eq!(legs[0]["asset"], contract.as_str(), "{legs}");
}

/// Every retained leg of a mixed invocation is decided: a second transfer to
/// an unlisted recipient refuses, and two listed transfers record two legs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_mixed_invocation_evaluates_every_retained_leg() {
    use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind,
    };
    let mut rules = tools(true);
    rules.push(rule(
        PAY,
        vec![Box::new(CounterpartyAllowlistCriterion::new(
            vec![CounterpartyKind::GAccount],
            vec![g(A)],
        ))],
        false,
    ));
    let fx = Fixture::new(rules).await;
    let swap = || call([9; 32], "swap", vec![]);
    let mixed = |second| {
        fx.tx(vec![invoke(vec![
            swap(),
            fx.transfer(A, 1),
            fx.transfer(second, 2),
        ])])
    };
    assert_eq!(
        refused(&fx.sign(mixed(B)).await).0,
        "policy.deny.counterparty_denied"
    );
    signed(&fx.sign(mixed(A)).await);
    let rows = fx.rows("opaque_payload_signed");
    assert_eq!(
        rows[0]["legs"].as_array().map(Vec::len),
        Some(2),
        "{rows:?}"
    );
}

/// The own rule's denial precedes envelope decoding, and an undecodable
/// envelope refuses before the audit pre-flight.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_undecodable_envelope_refuses_between_the_tool_rule_and_the_audit_preflight() {
    let fx = Fixture::new(vec![rule(PAY, vec![], false)]).await;
    assert_eq!(
        refused(&fx.sign("AAAA".into()).await).0,
        "policy.deny.no_matching_rule"
    );
    drop(fx);
    let fx = Fixture::new(tools(false)).await;
    let coord = fx.profile.audit_log_hash_chain_key_id.clone();
    keyring_core::Entry::new(&coord.service, &coord.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    assert_eq!(
        refused(&fx.sign("AAAA".into()).await).0,
        "sep43.invalid_xdr"
    );
    assert_eq!(
        refused(&fx.sign(bump_sequence(fx.key)).await).0,
        "audit.chain_key_unavailable"
    );
}

/// A refused audit pre-flight precedes admission in both tools: under
/// chargeable payment and count rules, an allowed payment leaves durable
/// usage unchanged and reads no seed; with the audit key restored it charges.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_refused_audit_preflight_admits_nothing_in_either_tool() {
    let fx = Fixture::new(vec![
        rule(SIGN, vec![rate(5)], false),
        rule(SUBMIT, vec![rate(5)], false),
        rule(PAY, vec![per_day(100 * i128::from(XLM))], false),
    ])
    .await;
    let coord = fx.profile.audit_log_hash_chain_key_id.clone();
    let entry = keyring_core::Entry::new(&coord.service, &coord.account).unwrap();
    let key = entry.get_password().unwrap();
    entry.delete_credential().unwrap();
    let xdr = fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    for result in [fx.sign(xdr.clone()).await, fx.submit(xdr.clone()).await] {
        assert_eq!(refused(&result).0, "audit.chain_key_unavailable");
    }
    assert_eq!(fx.usage("native"), (0, 0));
    assert_eq!(fx.usage("rate_limit"), (0, 0));
    assert_eq!(fx.seed_reads(), 0);
    entry.set_password(&key).unwrap();
    signed(&fx.sign(xdr).await);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
}

// ─── Fees ────────────────────────────────────────────────────────────────────

fn bump_op(source: Option<[u8; 32]>) -> Operation {
    Operation {
        source_account: source.map(|key| muxed(key, None)),
        body: OperationBody::BumpSequence(stellar_xdr::BumpSequenceOp {
            bump_to: SequenceNumber(0),
        }),
    }
}

fn with_fee_cap(cap: Option<u32>) -> impl FnOnce(&mut Profile) {
    move |profile| profile.classic_max_fee_per_op_stroops = cap
}

/// The classic per-operation cap bounds the fee the wallet pays; the same
/// fee paid by another account signs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_fee_cap_bounds_the_fee_the_wallet_pays() {
    let fx = Fixture::with(tools(false), with_fee_cap(Some(1_000))).await;
    let wallet = |fee| encode(tx(fx.key, fee, Memo::None, vec![bump_op(None)]));
    signed(&fx.sign(wallet(1_000)).await);
    assert_eq!(
        refused(&fx.sign(wallet(XLM as u32)).await).0,
        "fees.percentile_exceeds_cap"
    );
    let foreign = encode(tx(
        OTHER,
        XLM as u32,
        Memo::None,
        vec![bump_op(Some(fx.key))],
    ));
    signed(&fx.sign(foreign).await);
}

/// The per-operation fee rounds up, and a fee-bump quotient above `u32`
/// refuses under a cap with its full value and signs without a cap.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn fee_arithmetic_preserves_remainders_and_width() {
    let wide = |key| {
        fee_bump(
            key,
            2 * i64::from(u32::MAX) + 4,
            tx(key, 100, Memo::None, vec![bump_op(None)]),
        )
    };
    let fx = Fixture::with(tools(false), with_fee_cap(Some(1_000))).await;
    let two = |fee| {
        encode(tx(
            fx.key,
            fee,
            Memo::None,
            vec![bump_op(None), bump_op(None)],
        ))
    };
    signed(&fx.sign(two(2_000)).await);
    assert_eq!(
        refused(&fx.sign(two(2_001)).await).0,
        "fees.percentile_exceeds_cap"
    );
    let (code, message) = refused(&fx.sign(wide(fx.key)).await);
    assert_eq!(code, "fees.percentile_exceeds_cap");
    assert!(message.contains("4294967297 stroops"), "{message}");
    drop(fx);
    let fx = Fixture::with(tools(false), with_fee_cap(None)).await;
    signed(&fx.sign(wide(fx.key)).await);
}

fn soroban(source: [u8; 32], fee: u32, resource_fee: i64, operation: Operation) -> Transaction {
    Transaction {
        ext: stellar_xdr::TransactionExt::V1(stellar_xdr::SorobanTransactionData {
            resource_fee,
            ..Default::default()
        }),
        ..tx(source, fee, Memo::None, vec![operation])
    }
}

/// A verified policy whose signed contract transfer fee cap is zero.
fn zero_cap_policy(fx: &Fixture) -> stellar_agent_core::mainnet::verified_policy::VerifiedPolicy {
    signed_policy(
        fx,
        "version = 1\nscope = \"profile:*\"\ncontract_transfer_max_fee_stroops = 0\n",
    )
}

/// The owner-signed V1 policy `body`, loaded and verified for `fx`.
fn signed_policy(
    fx: &Fixture,
    body: &str,
) -> stellar_agent_core::mainnet::verified_policy::VerifiedPolicy {
    use stellar_agent_core::policy::v1::canonical::canonical_bytes;
    use stellar_agent_core::policy::v1::signature::{digest, sign};
    use stellar_agent_core::policy::v1::verified::{
        OwnerKeySource, PinMode, PolicyLoad, load_verified_policy,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let public = key.verifying_key().to_bytes();
    let path = fx.dir.path().join("policy.toml");
    std::fs::write(
        &path,
        format!(
            "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            g(public),
            stellar_agent_core::hex::encode(&sign(&digest(&canonical_bytes(body).unwrap()), &key))
        ),
    )
    .unwrap();
    let mut profile = fx.profile.clone();
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::V1;
    load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile: &profile,
            profile_name: &fx.server.profile_name_for_approval(),
            owner_pubkey: &public,
            owner_source: OwnerKeySource::Keyring,
            window_path: &fx.dir.path().join("state.window"),
        },
        PolicyStateStore::new(),
        PinMode::CompareOnly,
    )
    .unwrap()
}

/// A wallet-paid resource transaction passes its full total through the
/// contract transfer fee cap: equality signs, one more stroop refuses, a
/// total above `u32` refuses intact, a resource fee above the total is
/// invalid, another payer is exempt, and a signed zero cap replaces the
/// default.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_contract_transfer_fee_cap_bounds_a_soroban_fee() {
    let mut fx = Fixture::new(tools(false)).await;
    let call = || op(invoke(vec![]));
    let wallet = |fee, resource| encode(soroban(fx.key, fee, resource, call()));
    signed(&fx.sign(wallet(1_000_000, 999_900)).await);
    signed(&fx.sign(wallet(100, 50)).await);
    assert_eq!(
        refused(&fx.sign(wallet(1_000_001, 999_901)).await).0,
        "validation.contract_transfer_fee_exceeded"
    );
    let (code, message) = refused(&fx.sign(wallet(100, 101)).await);
    assert_eq!(code, "sep43.invalid_xdr");
    assert!(
        message.ends_with("the resource fee exceeds the transaction fee"),
        "{message}"
    );
    let mut foreign_call = call();
    foreign_call.source_account = Some(muxed(fx.key, None));
    signed(
        &fx.sign(encode(soroban(OTHER, 5_000_000, 4_999_900, foreign_call)))
            .await,
    );
    let wide = fee_bump(
        fx.key,
        i64::from(u32::MAX) + 1,
        soroban(fx.key, 100, 4_294_967_000, call()),
    );
    assert_eq!(
        refused(&fx.sign(wide).await).0,
        "validation.contract_transfer_fee_exceeded"
    );
    fx.server.verified_policy = Some(Arc::new(zero_cap_policy(&fx)));
    assert_eq!(
        refused(&fx.sign(wallet(100, 50)).await).0,
        "validation.contract_transfer_fee_exceeded"
    );
}

/// A fee bump is decided by its outer fee alone: an inner token transfer over
/// the pay cap adds no leg, while the outer fee still passes the classic cap.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_fee_bump_gates_only_the_outer_fee() {
    let fx = Fixture::with(pay_rule(vec![per_tx(1)]), with_fee_cap(Some(1_000))).await;
    let inner = || {
        tx(
            fx.key,
            100,
            Memo::None,
            vec![op(invoke(vec![fx.transfer(A, (10 * XLM).into())]))],
        )
    };
    signed(&fx.sign(fee_bump(fx.key, 2_000, inner())).await);
    assert!(
        fx.rows("opaque_payload_signed")
            .iter()
            .all(|row| !row.to_string().contains("\"legs\""))
    );
    assert_eq!(
        refused(&fx.sign(fee_bump(fx.key, 2_002, inner())).await).0,
        "fees.percentile_exceeds_cap"
    );
}

// ─── Accounts ────────────────────────────────────────────────────────────────

fn home_domain_rules() -> Vec<PolicyRule> {
    pay_rule(vec![Box::new(
        stellar_agent_core::policy::v1::criteria::home_domain_resolved::HomeDomainResolvedCriterion::new(),
    )])
}

/// Each payment reads its own recipient: a recipient without a home domain
/// passes `home_domain_resolved`, an unresolved one refuses alone and inside
/// a combined transaction.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_recipient_view_is_read_per_operation() {
    let fx = Fixture::new(home_domain_rules()).await;
    fx.account(A, 100 * XLM, None);
    fx.account(B, 100 * XLM, Some("unresolved.example"));
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), XLM)])).await);
    for envelope in [
        fx.tx(vec![payment(muxed(B, None), XLM)]),
        fx.tx(vec![
            payment(muxed(A, None), XLM),
            payment(muxed(B, None), XLM),
        ]),
    ] {
        assert_eq!(
            refused(&fx.sign(envelope).await).0,
            "policy.deny.home_domain_not_resolved"
        );
    }
}

/// Muxed recipients with one base account share one read per call and keep
/// their own destinations in the audit row.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn recipient_reads_share_a_base_account() {
    let fx = Fixture::new(pay_rule(vec![])).await;
    fx.account(A, 100 * XLM, None);
    signed(
        &fx.sign(fx.tx(vec![
            payment(muxed(A, Some(1)), XLM),
            payment(muxed(A, Some(2)), XLM),
        ]))
        .await,
    );
    assert_eq!(fx.reads(A), 1, "one read of the shared base account");
    let rows = fx.rows("opaque_payload_signed");
    let legs = rows[0]["legs"].as_array().unwrap();
    assert_eq!(legs.len(), 2);
    assert_ne!(
        legs[0]["destination_redacted"],
        legs[1]["destination_redacted"]
    );
    let log = std::fs::read_to_string(&fx.audit).unwrap();
    assert!(!log.contains(&g(A)), "no full address in the audit log");
}

/// A muxed recipient is read at its base account, and that account's facts
/// decide the payment.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_muxed_recipient_is_read_at_its_base_account() {
    let fx = Fixture::new(home_domain_rules()).await;
    fx.account(A, 100 * XLM, None);
    fx.account(B, 100 * XLM, Some("unresolved.example"));
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, Some(7)), XLM)])).await);
    assert_eq!(fx.reads(A), 1);
    assert_eq!(
        refused(&fx.sign(fx.tx(vec![payment(muxed(B, Some(7)), XLM)])).await).0,
        "policy.deny.home_domain_not_resolved"
    );
}

/// An absent recipient is no fact and signs; a failed recipient read refuses
/// with its ledger code. A missing route registration is a protocol error,
/// a failed wallet read refuses before the seed, and a wallet key that does
/// not parse counts every fee as the wallet's.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn missing_registry_and_account_facts_refuse() {
    let mut fx = Fixture::new(pay_rule(vec![])).await;
    signed(
        &fx.sign(fx.tx(vec![payment(muxed([0xD4; 32], None), XLM)]))
            .await,
    );
    let seed_reads = fx.seed_reads();
    fx.failing(B);
    assert_eq!(
        refused(&fx.sign(fx.tx(vec![payment(muxed(B, None), XLM)])).await).0,
        "network.rpc_unreachable"
    );
    fx.failing(fx.key);
    assert_eq!(
        refused(&fx.sign(fx.tx(vec![payment(muxed(A, None), XLM)])).await).0,
        "network.rpc_unreachable"
    );
    assert_eq!(
        fx.seed_reads(),
        seed_reads,
        "no seed read after a failed read"
    );
    fx.account(fx.key, WALLET_BALANCE, None);
    Arc::make_mut(&mut fx.server.tool_registry).remove(PAY);
    let error = fx
        .server
        .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".into(),
            transaction_xdr: fx.tx(vec![payment(muxed(A, None), XLM)]),
            network_passphrase: None,
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .unwrap_err();
    assert!(
        error.message.starts_with("tool.registry_missing"),
        "{error:?}"
    );
    drop(fx);

    let fx = Fixture::with(tools(false), |profile| {
        profile.mcp_signer_default.account = "unparsed-signer".into();
        profile.classic_max_fee_per_op_stroops = Some(1_000);
    })
    .await;
    let foreign = encode(tx(OTHER, XLM as u32, Memo::None, vec![bump_op(None)]));
    assert_eq!(
        refused(&fx.sign(foreign).await).0,
        "fees.percentile_exceeds_cap"
    );
}

// ─── Reserve ─────────────────────────────────────────────────────────────────

const RESERVE: i64 = 2 * stellar_agent_core::BASE_RESERVE_STROOPS;

fn reserve_rules() -> Vec<PolicyRule> {
    pay_rule(vec![Box::new(
        stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion::new(0),
    )])
}

/// Each payment sees the balance the fee and earlier native debits leave:
/// two payments that each pass alone refuse together one stroop short.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_minimum_reserve_sees_earlier_operations_and_the_fee() {
    let fx = Fixture::new(reserve_rules()).await;
    let exact = RESERVE + 200 + 20 * XLM;
    let two = || {
        fx.tx(vec![
            payment(muxed(A, None), 10 * XLM),
            payment(muxed(A, None), 10 * XLM),
        ])
    };
    fx.account(fx.key, exact, None);
    signed(&fx.sign(two()).await);
    fx.account(fx.key, exact - 1, None);
    signed(
        &fx.sign(fx.tx(vec![payment(muxed(A, None), 10 * XLM)]))
            .await,
    );
    assert_eq!(
        refused(&fx.sign(two()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// Allowing rules for both transaction tools, and a trustline rule with a
/// zero-margin reserve.
fn trustline_reserve_rules() -> Vec<PolicyRule> {
    let mut rules = reserve_rules();
    rules.push(rule(
        "stellar_trustline_commit",
        vec![Box::new(
            stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion::new(
                0,
            ),
        )],
        false,
    ));
    rules
}

/// A trustline on `code` issued by `OTHER`.
fn trustline_on(code: [u8; 4], limit: i64) -> OperationBody {
    OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
        line: stellar_xdr::ChangeTrustAsset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(code),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER))),
        }),
        limit,
    })
}

/// The reserve earlier operations open accumulates: two new trustlines
/// with a balance enough for one refuse, and a balance enough for both signs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn two_new_trustlines_need_the_reserve_of_both() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    let two = || {
        fx.tx(vec![
            trustline_on(*b"USDC", 100 * XLM),
            trustline_on(*b"EURC", 100 * XLM),
        ])
    };
    fx.account(fx.key, RESERVE + 2 * base + 200, None);
    signed(&fx.sign(two()).await);
    fx.account(fx.key, RESERVE + 2 * base + 199, None);
    assert_eq!(
        refused(&fx.sign(two()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
    fx.account(fx.key, RESERVE + base + 200, None);
    signed(
        &fx.sign(fx.tx(vec![trustline_on(*b"USDC", 100 * XLM)]))
            .await,
    );
    assert_eq!(
        refused(&fx.sign(two()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// The wallet read requests the trustline a `ChangeTrust` names: removing
/// or changing a held trustline needs only the pre-call reserve and fee.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_held_trustline_adds_no_reserve() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let held = |balance| {
        fx.serve(
            fx.key,
            Account {
                balance,
                trustlines: vec![*b"USDC"],
                ..Default::default()
            },
        );
    };
    for limit in [0, 100 * XLM] {
        let change = || fx.tx(vec![trustline_on(*b"USDC", limit)]);
        held(RESERVE + 100);
        signed(&fx.sign(change()).await);
        held(RESERVE + 99);
        assert_eq!(
            refused(&fx.sign(change()).await).0,
            "policy.deny.minimum_reserve_breached",
            "limit {limit}"
        );
    }
}

/// A trustline an earlier operation opens counts as held for a later one:
/// opening USDC and then changing its limit needs the reserve of one
/// trustline, to the stroop.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_trustline_opened_earlier_counts_as_held() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    let open_then_change = || {
        fx.tx(vec![
            trustline_on(*b"USDC", 100 * XLM),
            trustline_on(*b"USDC", 200 * XLM),
        ])
    };
    fx.account(fx.key, RESERVE + base + 200, None);
    signed(&fx.sign(open_then_change()).await);
    fx.account(fx.key, RESERVE + base + 199, None);
    assert_eq!(
        refused(&fx.sign(open_then_change()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// A `ChangeTrust` whose operation source is another account opens no
/// subentry on the wallet: the wallet's pre-call reserve and fee suffice.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn another_sources_trustline_adds_no_reserve() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    fx.source(B, true);
    let foreign = || fx.ops(vec![from(B, None, trustline_on(*b"USDC", 100 * XLM))]);
    fx.account(fx.key, RESERVE + 100, None);
    signed(&fx.sign(foreign()).await);
    fx.account(fx.key, RESERVE + 99, None);
    assert_eq!(
        refused(&fx.sign(foreign()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// A pool share trustline the wallet opens counts two base reserves toward
/// every leg: a later payment needs the reserve of both subentries. The
/// trustline rule judges the pool share operation itself.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_pool_share_trustline_adds_two_base_reserves() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    let pool = OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
        line: stellar_xdr::ChangeTrustAsset::PoolShare(
            stellar_xdr::LiquidityPoolParameters::default(),
        ),
        limit: 100 * XLM,
    });
    let pooled = || fx.tx(vec![pool.clone(), payment(muxed(A, None), XLM)]);
    fx.account(fx.key, RESERVE + 2 * base + 200 + XLM, None);
    signed(&fx.sign(pooled()).await);
    fx.account(fx.key, RESERVE + 2 * base + 199 + XLM, None);
    assert_eq!(
        refused(&fx.sign(pooled()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// After a dust payment the trustline rule still judges a pool share
/// `ChangeTrust`, at its own position after the payment: the audit record
/// lists the payment leg first. Its `minimum_reserve` refuses one stroop
/// under the reserve of the two subentries after the dust debit, and
/// without a trustline rule the transaction refuses
/// `policy.deny.no_matching_rule`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_pool_share_trustline_after_a_payment_is_judged_by_the_trustline_rule() {
    let mut rules = pay_rule(vec![]);
    rules.push(rule(
        "stellar_trustline_commit",
        vec![Box::new(
            stellar_agent_core::policy::v1::criteria::minimum_reserve::MinimumReserveCriterion::new(
                0,
            ),
        )],
        false,
    ));
    let fx = Fixture::new(rules).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    let dust_then_pool = || fx.tx(vec![payment(muxed(A, None), 1), pool_share_trustline()]);
    fx.account(fx.key, RESERVE + 2 * base + 200 + 1, None);
    signed(&fx.sign(dust_then_pool()).await);
    // The gate records each leg in the order it decides them.
    let rows = fx.rows("opaque_payload_signed");
    let legs = rows[0]["legs"].as_array().unwrap();
    let kinds: Vec<&str> = legs
        .iter()
        .map(|leg| leg["action"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["payment", "trustline"], "{legs:?}");
    fx.account(fx.key, RESERVE + 2 * base + 200, None);
    assert_eq!(
        refused(&fx.sign(dust_then_pool()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
    drop(fx);

    let fx = Fixture::new(pay_rule(vec![])).await;
    let dust_then_pool = fx.tx(vec![payment(muxed(A, None), 1), pool_share_trustline()]);
    assert_eq!(
        refused(&fx.sign(dust_then_pool).await).0,
        "policy.deny.no_matching_rule"
    );
}

/// Each pool share `ChangeTrust` is its own trustline call: two in one
/// transaction charge two calls to the rule's `rate_limit`, so a third
/// call refuses at a limit of two.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn each_pool_share_trustline_charges_one_call() {
    let mut rules = tools(false);
    rules.push(rule("stellar_trustline_commit", vec![rate(2)], false));
    let fx = Fixture::new(rules).await;
    signed(
        &fx.sign(fx.tx(vec![pool_share_trustline(), pool_share_trustline()]))
            .await,
    );
    assert_eq!(fx.usage("rate_limit").1, 2);
    assert_eq!(
        refused(&fx.sign(fx.tx(vec![pool_share_trustline()])).await).0,
        "policy.deny.rate_limit_exceeded"
    );
}

/// The audit record names each pool share operation in transaction order
/// as a trustline leg without an asset, beside the payment between them.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_audit_record_names_each_pool_share_operation() {
    let mut rules = pay_rule(vec![]);
    rules.push(rule("stellar_trustline_commit", vec![], false));
    let fx = Fixture::new(rules).await;
    signed(
        &fx.sign(fx.tx(vec![
            pool_share_trustline(),
            payment(muxed(A, None), XLM),
            pool_share_trustline(),
        ]))
        .await,
    );
    let rows = fx.rows("opaque_payload_signed");
    let legs = rows[0]["legs"].as_array().unwrap();
    let kinds: Vec<&str> = legs
        .iter()
        .map(|leg| leg["action"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["trustline", "payment", "trustline"], "{legs:?}");
    for index in [0, 2] {
        assert!(legs[index].get("asset").is_none(), "{legs:?}");
    }
    assert_eq!(legs[1]["asset"], "native", "{legs:?}");
}

/// An `asset_allowlist` on the trustline rule refuses a pool share
/// `ChangeTrust`, alone and after a payment: no entry can name a pool.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_asset_allowlist_refuses_a_pool_share_trustline() {
    let mut rules = pay_rule(vec![]);
    rules.push(rule(
        "stellar_trustline_commit",
        vec![Box::new(
            stellar_agent_core::policy::v1::criteria::asset_allowlist::AssetAllowlistCriterion::new(
                vec!["native".into()],
            )
            .unwrap(),
        )],
        false,
    ));
    let fx = Fixture::new(rules).await;
    for bodies in [
        vec![pool_share_trustline()],
        vec![payment(muxed(A, None), XLM), pool_share_trustline()],
    ] {
        assert_eq!(
            refused(&fx.sign(fx.tx(bodies)).await).0,
            "policy.deny.asset_not_allowlisted"
        );
    }
}

/// A pool share `ChangeTrust` with a nonzero limit.
fn pool_share_trustline() -> OperationBody {
    OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
        line: stellar_xdr::ChangeTrustAsset::PoolShare(
            stellar_xdr::LiquidityPoolParameters::default(),
        ),
        limit: 100 * XLM,
    })
}

/// Checks a transaction whose only operation is `body` through both tools:
/// at `boundary` the sign tool signs and the submit tool reaches the send;
/// one stroop under, both refuse with the reserve breach and sign nothing.
async fn assert_only_operation_boundary(fx: &Fixture, body: OperationBody, boundary: i64) {
    let only = fx.tx(vec![body]);
    fx.account(fx.key, boundary, None);
    let before = fx.sends();
    let [sign, submit] = both(fx, &only).await;
    signed(&sign);
    sent(fx, before, &submit);
    let sends = fx.ledger.sends.load(Ordering::SeqCst);
    fx.account(fx.key, boundary - 1, None);
    for result in both(fx, &only).await {
        assert_eq!(refused(&result).0, "policy.deny.minimum_reserve_breached");
    }
    assert_eq!(
        fx.ledger.sends.load(Ordering::SeqCst),
        sends,
        "nothing sent"
    );
}

/// A transaction whose only operation opens a credit trustline needs one
/// base reserve more than the account's reserve and fee, to the stroop.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_credit_trustline_alone_is_checked_at_the_reserve() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    let credit = trustline_on(*b"USDC", 100 * XLM);
    assert_only_operation_boundary(&fx, credit, RESERVE + base + 100).await;
}

/// A transaction whose only operation opens a pool share trustline is
/// decided by the trustline rule and needs two base reserves more, to the
/// stroop.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_pool_share_trustline_alone_is_checked_at_the_reserve() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let base = stellar_agent_core::BASE_RESERVE_STROOPS;
    assert_only_operation_boundary(&fx, pool_share_trustline(), RESERVE + 2 * base + 100).await;
}

/// A transaction whose only operation is a pool share `ChangeTrust` with a
/// limit of 0 opens nothing: the account's reserve and fee alone sign it,
/// to the stroop.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_pool_share_line_with_a_zero_limit_opens_nothing() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    let removal = OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
        line: stellar_xdr::ChangeTrustAsset::PoolShare(
            stellar_xdr::LiquidityPoolParameters::default(),
        ),
        limit: 0,
    });
    assert_only_operation_boundary(&fx, removal, RESERVE + 100).await;
}

/// A pool share `ChangeTrust` whose source is another account opens nothing
/// on the wallet: the wallet's reserve and fee alone sign it.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn another_sources_pool_share_trustline_adds_no_reserve() {
    let fx = Fixture::new(trustline_reserve_rules()).await;
    fx.source(B, true);
    fx.account(fx.key, RESERVE + 100, None);
    let foreign = fx.ops(vec![from(B, None, pool_share_trustline())]);
    let before = fx.sends();
    let [sign, submit] = both(&fx, &foreign).await;
    signed(&sign);
    sent(&fx, before, &submit);
}

/// The wallet fee reduces the reserve balance exactly once.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_fee_is_subtracted_once() {
    let fx = Fixture::new(reserve_rules()).await;
    let exact = RESERVE + 100 + 10 * XLM;
    let one = || fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    fx.account(fx.key, exact, None);
    signed(&fx.sign(one()).await);
    fx.account(fx.key, exact - 1, None);
    assert_eq!(
        refused(&fx.sign(one()).await).0,
        "policy.deny.minimum_reserve_breached"
    );
}

/// A native asset contract transfer keeps its contract address and adds no
/// reserve debit before a later classic payment.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_native_contract_transfer_does_not_count_against_the_reserve() {
    let fx = Fixture::new(reserve_rules()).await;
    fx.account(fx.key, RESERVE + 200 + 10 * XLM, None);
    signed(
        &fx.sign(fx.tx(vec![
            invoke(vec![fx.transfer(A, (10 * XLM).into())]),
            payment(muxed(A, None), 10 * XLM),
        ]))
        .await,
    );
}

struct InnerView;

impl AccountReservesView for InnerView {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        3 * base_reserve_stroops
    }

    fn balance_stroops(
        &self,
    ) -> Result<i64, stellar_agent_core::policy::v1::AccountReserveLookupError> {
        Ok(100)
    }

    fn observation(&self) -> Option<stellar_agent_core::policy::v1::AccountObservation> {
        Some(stellar_agent_core::policy::v1::AccountObservation {
            ledger_sequence: 9,
            close_time_floor_ms: 8,
            observed_at_ms: 7,
        })
    }

    fn effective_native_reservations_stroops(&self) -> Option<u64> {
        Some(6)
    }

    fn holds_trustline(&self, _asset: &str, _network_passphrase: &str) -> Option<bool> {
        Some(false)
    }
}

struct BrokenView;

impl AccountReservesView for BrokenView {
    fn reserves_stroops(&self, _: i64) -> i64 {
        0
    }

    fn balance_stroops(
        &self,
    ) -> Result<i64, stellar_agent_core::policy::v1::AccountReserveLookupError> {
        Err(stellar_agent_core::policy::v1::AccountReserveLookupError {
            detail: "no native balance".into(),
        })
    }
}

/// The spent view subtracts exactly, floors at zero, propagates a balance
/// error and delegates reserves, observation, reservations and trustlines.
/// The subentries earlier operations open raise its reserve, and their
/// trustlines and another source's trustline answer held.
#[test]
fn spent_view_delegates_and_propagates_errors() {
    use super::SpentAccountView;
    let opened = vec!["EURC:G".to_owned()];
    let view = |spent_stroops| SpentAccountView {
        inner: &InnerView,
        spent_stroops,
        opened_subentries: 0,
        opened_trustlines: &[],
        other_source: false,
    };
    assert_eq!(view(30).balance_stroops().unwrap(), 70);
    assert_eq!(view(101).balance_stroops().unwrap(), 0);
    assert_eq!(view(-1).balance_stroops().unwrap(), 101);
    assert!(view(i128::MIN).balance_stroops().is_err());
    assert_eq!(view(0).reserves_stroops(5), 15);
    assert_eq!(view(0).observation(), InnerView.observation());
    assert_eq!(view(0).effective_native_reservations_stroops(), Some(6));
    assert_eq!(
        view(0).holds_trustline("USDC:G", TESTNET_PASSPHRASE),
        Some(false)
    );
    let after = |other_source| SpentAccountView {
        inner: &InnerView,
        spent_stroops: 0,
        opened_subentries: 2,
        opened_trustlines: &opened,
        other_source,
    };
    assert_eq!(after(false).reserves_stroops(5), 25);
    assert_eq!(
        after(false).holds_trustline("EURC:G", TESTNET_PASSPHRASE),
        Some(true)
    );
    assert_eq!(
        after(false).holds_trustline("USDC:G", TESTNET_PASSPHRASE),
        Some(false)
    );
    assert_eq!(
        after(true).holds_trustline("USDC:G", TESTNET_PASSPHRASE),
        Some(true)
    );
    let broken = SpentAccountView {
        inner: &BrokenView,
        spent_stroops: 0,
        opened_subentries: 0,
        opened_trustlines: &[],
        other_source: false,
    };
    assert_eq!(
        broken.balance_stroops().unwrap_err().detail,
        "no native balance"
    );
}

// ─── Values and memos ────────────────────────────────────────────────────────

/// A contract transfer above `i64::MAX` keeps its exact amount in the
/// decision and the audit leg.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn large_contract_quantities_remain_exact() {
    let amount = i128::from(i64::MAX) + 1;
    for (cap, allowed) in [(amount, true), (amount - 1, false)] {
        let fx = Fixture::new(pay_rule(vec![per_tx(cap)])).await;
        let result = fx
            .sign(fx.tx(vec![invoke(vec![fx.transfer(A, amount)])]))
            .await;
        if allowed {
            signed(&result);
            let rows = fx.rows("opaque_payload_signed");
            assert_eq!(rows[0]["legs"][0]["amount"], amount.to_string());
        } else {
            assert_eq!(refused(&result).0, "policy.deny.per_tx_cap_exceeded");
        }
    }
}

/// The signed memo of every kind reaches classic and contract evaluations:
/// a `memo_binding` rule admits the bound memo and refuses its absence.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_signed_memo_reaches_every_valued_evaluation() {
    use stellar_agent_core::policy::v1::criteria::memo_binding::{
        MemoBinding, MemoBindingCriterion, MemoRequirement,
    };
    for (memo, requirement) in [
        (
            Memo::Text("inv-7".try_into().unwrap()),
            MemoRequirement::Text("inv-7".into()),
        ),
        (Memo::Id(u64::MAX), MemoRequirement::Id(u64::MAX)),
        (Memo::Hash(Hash([3; 32])), MemoRequirement::Hash([3; 32])),
        (
            Memo::Return(Hash([4; 32])),
            MemoRequirement::Return([4; 32]),
        ),
    ] {
        let fx = Fixture::new(pay_rule(vec![Box::new(MemoBindingCriterion::new(vec![
            MemoBinding::new(&g(A), requirement).unwrap(),
        ]))]))
        .await;
        let bodies = || {
            [
                payment(muxed(A, None), XLM),
                invoke(vec![fx.transfer(A, XLM.into())]),
            ]
        };
        for body in bodies() {
            signed(&fx.sign(source_tx(fx.key, memo.clone(), vec![body])).await);
        }
        for body in bodies() {
            assert_eq!(
                refused(&fx.sign(fx.tx(vec![body])).await).0,
                "policy.deny.memo_binding_mismatch"
            );
        }
    }
}

// ─── Admission ───────────────────────────────────────────────────────────────

/// Classic and equivalent contract legs share one window limit: 10 and 10
/// under 15 refuse in one batch with no usage and no seed read; 5 and 5
/// persist both.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn classic_and_contract_payments_share_window_limits() {
    let fx = Fixture::new(pay_rule(vec![per_day(15 * i128::from(XLM))])).await;
    let both = |amount: i64| {
        fx.tx(vec![
            payment(muxed(A, None), amount),
            invoke(vec![fx.transfer(A, amount.into())]),
        ])
    };
    assert_eq!(
        refused(&fx.sign(both(10 * XLM)).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (0, 0));
    assert_eq!(fx.seed_reads(), 0);
    signed(&fx.sign(both(5 * XLM)).await);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 2));
}

struct UnrecordableEngine;

impl PolicyEngine for UnrecordableEngine {
    fn evaluate(
        &self,
        _: &stellar_agent_core::policy::ToolDescriptor,
        _: &Value,
        _: &Profile,
        _: Option<&dyn AccountReservesView>,
        _: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        _: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
        _: u64,
    ) -> Result<Decision, stellar_agent_core::policy::PolicyError> {
        Ok(Decision::Allow)
    }

    fn record_confirmed(
        &self,
        _: &stellar_agent_core::policy::ToolDescriptor,
        _: &Profile,
        _: &stellar_agent_core::policy::v1::ValueClass,
    ) -> Result<
        Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
        stellar_agent_core::policy::PolicyError,
    > {
        Err(
            stellar_agent_core::policy::PolicyError::CriterionEvaluationFailed {
                detail: "fixture accounting failure".into(),
            },
        )
    }
}

/// An accounting failure that is not a limit denial refuses with
/// `policy.engine_required` and the unavailable-accounting text.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn sep43_admission_errors_keep_their_channel() {
    let mut fx = Fixture::new(tools(false)).await;
    fx.server
        .set_policy_engine_for_test(Arc::new(UnrecordableEngine));
    let effects = super::Sep43Effects {
        legs: Vec::new(),
        admissions: vec![(
            fx.server.policy_descriptor(SIGN).unwrap(),
            stellar_agent_core::policy::v1::ValueClass::ReadOnly,
        )],
        approval_nonce: None,
        decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
    };
    let refusal = fx.server.sep43_admit(&effects).unwrap_err();
    let (code, message, _) = assert_business_envelope(&refusal);
    assert_eq!(code, "policy.engine_required");
    assert_eq!(message, "authorized payment accounting is unavailable");
}

// ─── Signing-time usage ──────────────────────────────────────────────────────

/// Sign-only admits the spend when it signs: a second 10 under a 15 period
/// cap refuses.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn sign_only_admits_the_spend_at_signing() {
    let fx = Fixture::new(pay_rule(vec![per_day(15 * i128::from(XLM))])).await;
    let ten = || fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    signed(&fx.sign(ten()).await);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    assert_eq!(
        refused(&fx.sign(ten()).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
}

/// Each sign-only call charges its own rule's count, identical bytes
/// included: the third call refuses at a limit of two.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn sign_only_repeated_bytes_charge_each_call() {
    let fx = Fixture::new(vec![rule(SIGN, vec![rate(2)], false)]).await;
    let bytes = bump_sequence(fx.key);
    signed(&fx.sign(bytes.clone()).await);
    signed(&fx.sign(bytes.clone()).await);
    assert_eq!(fx.usage("rate_limit").1, 2);
    assert_eq!(
        refused(&fx.sign(bytes).await).0,
        "policy.deny.rate_limit_exceeded"
    );
}

/// A valued signature records its legs with amount, asset and a redacted
/// destination.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_valued_signature_records_its_legs() {
    let fx = Fixture::new(pay_rule(vec![])).await;
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 5 * XLM)])).await);
    let rows = fx.rows("opaque_payload_signed");
    let leg = &rows[0]["legs"][0];
    assert_eq!(leg["action"], "payment", "{leg}");
    assert_eq!(leg["amount"], (5 * XLM).to_string(), "{leg}");
    assert_eq!(leg["asset"], "native", "{leg}");
    assert_eq!(
        leg["destination_redacted"],
        stellar_agent_core::observability::redact_strkey_first5_last5(&g(A)),
        "{leg}"
    );
    let log = std::fs::read_to_string(&fx.audit).unwrap();
    assert!(!log.contains(&g(A)), "no full address in the audit log");
}

/// A signer failure and a signing failure after admission keep the admitted
/// usage, which still counts after a restart.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn signer_and_signing_failures_keep_admission() {
    let rules = || pay_rule(vec![per_day(15 * i128::from(XLM))]);
    let mut fx = Fixture::new(rules()).await;
    let ten = fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    let refusal = fx
        .server
        .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".into(),
            transaction_xdr: ten.clone(),
            network_passphrase: Some("Public Global Stellar Network ; September 2015".into()),
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
        .await
        .unwrap();
    assert_eq!(refused(&refusal).0, "sep43.invalid_network_passphrase");
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    fx.restart(rules());
    assert_eq!(
        refused(&fx.sign(ten).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    drop(fx);

    let mut fx = Fixture::new(rules()).await;
    keyring_core::Entry::new("svc-s43fx", &g(fx.key))
        .unwrap()
        .delete_credential()
        .unwrap();
    let ten = fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    let (code, _) = refused(&fx.sign(ten.clone()).await);
    assert_eq!(code, "sep43.wallet_unlock_failed");
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    fx.restart(rules());
    assert_eq!(
        refused(&fx.sign(ten).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
}

/// A failed send keeps the spend admitted before signing.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_failed_send_keeps_the_admitted_spend() {
    let fx = Fixture::new(pay_rule(vec![per_day(15 * i128::from(XLM))])).await;
    let ten = || fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    let first = fx.submit(ten()).await;
    let text = &first.content[0].as_text().unwrap().text;
    assert!(
        !text.contains("\"success\""),
        "the send does not succeed: {text}"
    );
    assert_eq!(fx.ledger.sends.load(Ordering::SeqCst), 1);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    assert_eq!(
        refused(&fx.submit(ten()).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.ledger.sends.load(Ordering::SeqCst), 1);
}

/// A valued submission records its legs in the pending row; the value is
/// charged once at admission and the recorder charges only the tool's count.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_valued_submission_records_its_legs() {
    let mut rules = vec![
        rule(SIGN, vec![], false),
        rule(SUBMIT, vec![rate(5)], false),
    ];
    rules.push(rule(PAY, vec![per_day(100 * i128::from(XLM))], false));
    let fx = Fixture::new(rules).await;
    let _ = fx
        .submit(fx.tx(vec![payment(muxed(A, None), 10 * XLM)]))
        .await;
    let pending = fx.rows("value_action_pending");
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["legs"][0]["amount"], (10 * XLM).to_string());
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    assert_eq!(fx.usage("rate_limit").1, 1);
}

// ─── Frame ───────────────────────────────────────────────────────────────────

/// Records the instant of every evaluation and moves the policy clock after
/// the decision of the `outer` tool.
struct FrameEngine {
    seen: Mutex<Vec<(String, u64)>>,
    later: u64,
    outer: &'static str,
}

impl PolicyEngine for FrameEngine {
    fn evaluate(
        &self,
        tool: &stellar_agent_core::policy::ToolDescriptor,
        _: &Value,
        _: &Profile,
        _: Option<&dyn AccountReservesView>,
        _: Option<&dyn stellar_agent_core::policy::v1::AccountIdentityView>,
        _: Option<&dyn stellar_agent_core::policy::v1::CounterpartyCacheView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep10SessionView>,
        _: Option<&dyn stellar_agent_core::policy::v1::Sep45SessionView>,
        now_ms: u64,
    ) -> Result<Decision, stellar_agent_core::policy::PolicyError> {
        self.seen.lock().unwrap().push((tool.name.clone(), now_ms));
        if tool.name == self.outer {
            // The caller's guard restores the clock when the test ends.
            std::mem::forget(
                stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
                    self.later,
                ),
            );
        }
        Ok(Decision::Allow)
    }
}

/// Every payment evaluation reads the outer allowed dispatch's frame, even
/// after the policy clock moves.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn effects_share_the_tool_gate_snapshot() {
    let mut fx = Fixture::new(tools(false)).await;
    let now = stellar_agent_core::policy::policy_now_ms().unwrap();
    let _clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
    let engine = Arc::new(FrameEngine {
        seen: Mutex::new(Vec::new()),
        later: now + 60_000,
        outer: SIGN,
    });
    fx.server.set_policy_engine_for_test(engine.clone());
    signed(
        &fx.sign(fx.tx(vec![
            payment(muxed(A, None), XLM),
            payment(muxed(B, None), XLM),
        ]))
        .await,
    );
    assert_eq!(
        *engine.seen.lock().unwrap(),
        vec![
            (SIGN.to_owned(), now),
            (PAY.to_owned(), now),
            (PAY.to_owned(), now)
        ]
    );
}

/// A failed policy clock refuses with `wallet.clock_error` before any
/// account read.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn effects_clock_failure_refuses() {
    let fx = Fixture::new(pay_rule(vec![])).await;
    let _broken =
        stellar_agent_core::policy::v1::criteria::state_store::set_policy_clock_error_for_test();
    assert_eq!(
        refused(&fx.sign(fx.tx(vec![payment(muxed(A, None), XLM)])).await).0,
        "wallet.clock_error"
    );
    assert_eq!(fx.reads(fx.key), 0);
    assert_eq!(fx.reads(A), 0);
}

// ─── Approval ────────────────────────────────────────────────────────────────

use stellar_agent_core::approval::{
    ApprovalKind, AttestationBinding, AttestedApprover, ConsumedOutcome, PendingApproval,
    PendingApprovalStore,
    attestation::{compute_attestation_v4, envelope_sha256},
    process_uid_for_attestation,
};
use stellar_agent_core::policy::ApprovalRequest;

const ATTESTATION_KEY: [u8; 32] = [0xD2; 32];

/// A pay rule that escalates a native payment above 10 XLM and caps the day
/// at 100 XLM, so an admitted spend leaves a window entry.
fn escalating_rules() -> Vec<PolicyRule> {
    pay_rule(vec![
        Box::new(
            stellar_agent_core::policy::v1::criteria::approval_above::ApprovalAboveCriterion::new(
                "native".into(),
                10 * i128::from(XLM),
            ),
        ),
        per_day(100 * i128::from(XLM)),
    ])
}

/// A rule for `tool` whose decision requires approval for `ttl_seconds`.
fn approval_rule(tool: &str, ttl_seconds: u32) -> PolicyRule {
    let mut rule = rule(tool, vec![], false);
    rule.decision = Decision::RequireApproval(ApprovalRequest::new("rule".into(), ttl_seconds));
    rule
}

/// A trustline on `USDC` issued by `OTHER`.
fn usdc_trustline(limit: i64) -> OperationBody {
    OperationBody::ChangeTrust(stellar_xdr::ChangeTrustOp {
        line: stellar_xdr::ChangeTrustAsset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER))),
        }),
        limit,
    })
}

impl Fixture {
    /// A fixture whose approvals live in its own directory, whose attestation
    /// key is enrolled, and whose verified policy binds each payment approval
    /// for recovery as a V1 profile does.
    async fn approving(rules: Vec<PolicyRule>) -> Self {
        let mut fx = Self::new(rules).await;
        fx.server.verified_policy = Some(Arc::new(signed_policy(
            &fx,
            "version = 1\nscope = \"profile:*\"\n",
        )));
        fx.server
            .set_approval_dir_for_test(fx.dir.path().join("approvals"));
        let key = &fx.profile.attestation_key_id;
        keyring_core::Entry::new(&key.service, &key.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ATTESTATION_KEY))
            .unwrap();
        fx
    }

    fn store(&self) -> PendingApprovalStore {
        let name = self.server.profile_name_for_approval();
        PendingApprovalStore::open(
            self.dir
                .path()
                .join("approvals")
                .join(format!("{name}.toml")),
        )
        .unwrap()
    }

    fn entry(&self, nonce: &str) -> PendingApproval {
        self.store().get(nonce).cloned().expect("a stored approval")
    }

    /// Attests the pending approval `nonce` over `envelope` as the operator
    /// does and returns the proof the agent presents.
    fn attest(&self, nonce: &str, envelope: &str) -> Proof {
        let entry = self.entry(nonce);
        let name = self.server.profile_name_for_approval();
        let blob = compute_attestation_v4(
            &ATTESTATION_KEY,
            &AttestationBinding::new(&name, "stellar:testnet"),
            nonce,
            &envelope_sha256(envelope.as_bytes()),
            &process_uid_for_attestation().unwrap(),
            &entry.attested_lifetime(),
            &AttestedApprover::Local,
        );
        self.store()
            .record_attestation(nonce, blob, AttestedApprover::Local)
            .unwrap();
        (
            Some(nonce.to_owned()),
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob)),
        )
    }

    fn sends(&self) -> usize {
        self.ledger.sends.load(Ordering::SeqCst)
    }
}

/// The `approval` block of a pending response, which holds no signature.
fn pending(result: &CallToolResult) -> Value {
    let text = &result.content[0].as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    assert!(!text.contains("signedTxXdr"), "{text}");
    let approval = serde_json::from_str::<Value>(text).unwrap()["data"]["approval"].clone();
    assert!(approval["approval_nonce"].is_string(), "{text}");
    approval
}

fn nonce_of(approval: &Value) -> String {
    approval["approval_nonce"].as_str().unwrap().to_owned()
}

/// The first call of an escalated payment stores a pending approval over the
/// caller's envelope text and returns its block; it signs nothing, reads no
/// seed and admits no spend.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_escalated_payment_returns_a_pending_approval_and_signs_nothing() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let approval = pending(&fx.submit(xdr.clone()).await);
    assert_eq!(approval["chain_id"], "stellar:testnet");
    assert_eq!(approval["profile"], fx.server.profile_name_for_approval());
    let instructions = approval["instructions"].as_str().unwrap();
    assert!(
        instructions.contains("approval_attestation"),
        "{instructions}"
    );
    let entry = fx.entry(&nonce_of(&approval));
    assert_eq!(approval["expires_at_unix_ms"], entry.expires_at_unix_ms);
    let ApprovalKind::PaymentSimulated {
        envelope_sha256_hex,
        summary_to,
        summary_amount_stroops,
        ..
    } = &entry.kind
    else {
        panic!("a payment approval: {:?}", entry.kind);
    };
    assert_eq!(
        *envelope_sha256_hex,
        stellar_agent_core::hex::encode(&envelope_sha256(xdr.as_bytes()))
    );
    assert_eq!(
        (summary_to.as_str(), *summary_amount_stroops),
        (g(A).as_str(), 11 * XLM)
    );
    assert_eq!(fx.seed_reads(), 0, "no seed read");
    assert_eq!(fx.sends(), 0);
    assert_eq!(fx.usage("native"), (0, 0), "no window entry");
}

/// The attested repeat submits and spends the approval; the same proof then
/// refuses as consumed and sends nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_attested_second_call_signs_and_spends_the_approval() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    let second = fx.submit_with(xdr.clone(), proof.clone()).await;
    let text = &second.content[0].as_text().unwrap().text;
    assert_eq!(fx.sends(), 1, "the attested repeat sends: {text}");
    assert_eq!(fx.usage("native"), (11 * i128::from(XLM), 1));
    assert!(
        matches!(fx.entry(&nonce).kind, ApprovalKind::Consumed { .. }),
        "the send spends the approval"
    );
    assert_eq!(
        refused(&fx.submit_with(xdr, proof).await).0,
        "policy.approval_consumed"
    );
    assert_eq!(fx.sends(), 1);
}

/// Under a verified policy the payment approval is bound for recovery: a
/// repeated first call returns the same nonce, and a first call after the
/// spend refuses as consumed and sends nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_policy_bound_first_call_returns_its_approval_until_spent() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    assert_eq!(
        nonce_of(&pending(&fx.submit(xdr.clone()).await)),
        nonce,
        "a repeated first call returns the bound approval"
    );
    let proof = fx.attest(&nonce, &xdr);
    let second = fx.submit_with(xdr.clone(), proof).await;
    let text = &second.content[0].as_text().unwrap().text;
    assert_eq!(fx.sends(), 1, "the attested repeat sends: {text}");
    assert!(
        matches!(fx.entry(&nonce).kind, ApprovalKind::Consumed { .. }),
        "the send spends the approval"
    );
    assert_eq!(refused(&fx.submit(xdr).await).0, "policy.approval_consumed");
    assert_eq!(fx.sends(), 1);
}

/// The sign-only tool spends the approval with an unknown outcome before it
/// returns the signature; a repeat refuses.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn sign_only_consumes_the_approval_before_it_returns_the_signature() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    signed(&fx.sign_with(xdr.clone(), proof.clone()).await);
    let ApprovalKind::Consumed { outcome, .. } = fx.entry(&nonce).kind else {
        panic!("the signature spends the approval");
    };
    assert_eq!(outcome, ConsumedOutcome::Unknown);
    assert_eq!(
        refused(&fx.sign_with(xdr, proof).await).0,
        "policy.approval_consumed"
    );
}

/// The spend refuses an approval that is no longer pending, so a second
/// process that verified the same proof returns no signature.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_spent_approval_releases_no_second_signature() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    signed(&fx.sign_with(xdr.clone(), proof).await);
    let refusal = fx.server.sep43_spend_approval(&nonce, &xdr).unwrap_err();
    assert_eq!(
        assert_business_envelope(&refusal).0,
        "submission.record_unavailable"
    );
    let missing = fx.server.sep43_spend_approval("absent", &xdr).unwrap_err();
    assert_eq!(
        assert_business_envelope(&missing).0,
        "submission.record_unavailable"
    );
}

/// A proof for one envelope does not admit another: a different amount or
/// the same recipient spelled as an M address refuses.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_approval_binds_the_exact_envelope() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    for other in [
        fx.tx(vec![payment(muxed(A, None), 12 * XLM)]),
        fx.tx(vec![payment(muxed(A, Some(0)), 11 * XLM)]),
    ] {
        assert_eq!(
            refused(&fx.submit_with(other, proof.clone()).await).0,
            "policy.approval_required"
        );
    }
    assert_eq!(fx.sends(), 0);
    assert_eq!(fx.seed_reads(), 0);
}

/// A tool rule that requires approval, under an allowing pay rule, pends
/// on the first call and submits on the attested repeat.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_tool_rule_requirement_follows_the_same_flow() {
    let fx = Fixture::approving(vec![
        rule(SIGN, vec![], false),
        approval_rule(SUBMIT, 600),
        rule(PAY, vec![], false),
    ])
    .await;
    let xdr = fx.tx(vec![payment(muxed(A, None), XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    let _ = fx.submit_with(xdr, proof).await;
    assert_eq!(fx.sends(), 1);
    let reads = fx.reads(A);
    assert_eq!(
        refused(
            &fx.submit(fx.tx(vec![
                payment(muxed(A, None), XLM),
                payment(muxed(B, None), XLM),
            ]))
            .await
        )
        .0,
        "policy.approval_required_unsupported"
    );
    assert_eq!(
        fx.reads(A),
        reads,
        "the shape refuses before any account read"
    );
    assert_eq!(
        refused(&fx.submit("AAAA".into()).await).0,
        "sep43.invalid_xdr"
    );
    assert_eq!(
        fx.store().len(),
        1,
        "no pending approval for an undecodable envelope"
    );
}

/// Under a tool rule and an operation rule of 3600 s and 120 s, in either
/// order, the pending approval lives 120 s.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn the_shorter_lifetime_governs() {
    for (own, operation) in [(3600, 120), (120, 3600)] {
        let fx = Fixture::approving(vec![
            rule(SIGN, vec![], false),
            approval_rule(SUBMIT, own),
            approval_rule(PAY, operation),
        ])
        .await;
        let approval = pending(&fx.submit(fx.tx(vec![payment(muxed(A, None), XLM)])).await);
        let entry = fx.entry(&nonce_of(&approval));
        assert_eq!(
            entry.expires_at_unix_ms - entry.created_at_unix_ms,
            120_000,
            "tool {own} s, operation {operation} s"
        );
    }
}

/// Shapes `classic_summary` cannot show keep the unsupported refusal under
/// an escalation: two payments, a contract transfer and a claim.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_shape_the_summary_cannot_show_keeps_the_refusal() {
    let mut rules = escalating_rules();
    rules.push(approval_rule("stellar_claim_commit", 600));
    let fx = Fixture::approving(rules).await;
    fx.source(STRANGER, false);
    let claim = OperationBody::ClaimClaimableBalance(stellar_xdr::ClaimClaimableBalanceOp {
        balance_id: stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xAB; 32])),
    });
    for xdr in [
        fx.tx(vec![
            payment(muxed(A, None), 11 * XLM),
            payment(muxed(B, None), 11 * XLM),
        ]),
        // One included payment in two raw operations.
        fx.ops(vec![
            op(payment(muxed(A, None), 11 * XLM)),
            from(STRANGER, None, payment(muxed(B, None), XLM)),
        ]),
        fx.tx(vec![invoke(vec![fx.transfer(A, (11 * XLM).into())])]),
        fx.tx(vec![claim]),
    ] {
        assert_eq!(
            refused(&fx.submit(xdr).await).0,
            "policy.approval_required_unsupported"
        );
    }
    assert!(
        !fx.dir.path().join("approvals").exists(),
        "no pending approval"
    );
}

/// A path payment with a credit send asset, an account creation and a
/// trustline change each store their own approval kind with the summary of
/// their envelope, and each attested repeat sends and spends its approval.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn each_approvable_kind_persists_its_own_summary() {
    use stellar_agent_core::envelope_decode::{
        ClassicOperation, ClassicTransactionKind, classic_summary,
    };
    let fx = Fixture::approving(vec![
        rule(SIGN, vec![], false),
        rule(SUBMIT, vec![], false),
        approval_rule(PAY, 600),
        approval_rule("stellar_create_account_commit", 600),
        approval_rule("stellar_trustline_commit", 600),
    ])
    .await;
    let repeat = |xdr: String, nonce: String| {
        let fx = &fx;
        async move {
            let sends = fx.sends();
            let proof = fx.attest(&nonce, &xdr);
            let result = fx.submit_with(xdr, proof).await;
            let text = &result.content[0].as_text().unwrap().text;
            assert_eq!(fx.sends(), sends + 1, "the attested repeat sends: {text}");
            assert!(
                matches!(fx.entry(&nonce).kind, ApprovalKind::Consumed { .. }),
                "the send spends the approval"
            );
        }
    };
    let usdc = Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
        asset_code: stellar_xdr::AssetCode4(*b"USDC"),
        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER))),
    });
    let path = OperationBody::PathPaymentStrictSend(stellar_xdr::PathPaymentStrictSendOp {
        send_asset: usdc,
        send_amount: 11 * XLM,
        destination: muxed(A, Some(7)),
        dest_asset: Asset::Native,
        dest_min: 11 * XLM,
        path: Default::default(),
    });
    let create = OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(B))),
        starting_balance: 2 * XLM,
    });
    // Each send needs its own sequence number.
    let at = |seq, body| {
        let mut tx = tx(fx.key, 100, Memo::None, vec![op(body)]);
        tx.seq_num = SequenceNumber(seq);
        encode(tx)
    };
    for (seq, body) in [(1, path), (2, create)] {
        let xdr = at(seq, body);
        let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
        let entry = fx.entry(&nonce);
        let summary = classic_summary(&xdr, ClassicTransactionKind::Payment).unwrap();
        let (to, amount, asset) = match summary.operation {
            ClassicOperation::PathPayment {
                destination,
                send_amount_stroops,
                send_asset,
                ..
            } => (destination, send_amount_stroops, send_asset),
            ClassicOperation::CreateAccount {
                destination,
                starting_balance_stroops,
            } => (destination, starting_balance_stroops, "XLM".to_owned()),
            other => panic!("{other:?}"),
        };
        let ApprovalKind::PaymentSimulated {
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            ..
        } = entry.kind
        else {
            panic!("a payment approval: {:?}", entry.kind);
        };
        assert_eq!(
            (summary_to, summary_amount_stroops, summary_asset),
            (to, amount, asset)
        );
        assert_eq!(
            (summary_simulated_fee_stroops, summary_simulated_seq_num),
            (summary.fee_stroops, summary.seq_num)
        );
        repeat(xdr, nonce).await;
    }
    let xdr = at(3, usdc_trustline(100 * XLM));
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let entry = fx.entry(&nonce);
    let summary = classic_summary(&xdr, ClassicTransactionKind::Trustline).unwrap();
    let ClassicOperation::ChangeTrust {
        asset_code,
        asset_issuer,
        limit_stroops,
    } = summary.operation
    else {
        panic!("a trustline summary");
    };
    let ApprovalKind::TrustlineSimulated {
        summary_holder,
        summary_asset_code,
        summary_asset_issuer,
        summary_limit_stroops,
        summary_simulated_fee_stroops,
        summary_simulated_seq_num,
        ..
    } = entry.kind
    else {
        panic!("a trustline approval: {:?}", entry.kind);
    };
    assert_eq!(
        (
            summary_holder,
            summary_asset_code,
            summary_asset_issuer,
            summary_limit_stroops
        ),
        (summary.source, asset_code, asset_issuer, limit_stroops)
    );
    assert_eq!(
        (summary_simulated_fee_stroops, summary_simulated_seq_num),
        (summary.fee_stroops, summary.seq_num)
    );
    repeat(xdr, nonce).await;
}

/// A nonce without an attestation, and the reverse, return the refusal of
/// an absent proof and store nothing new.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn half_a_proof_refuses_uniformly() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let (_, attestation) = fx.attest(&nonce, &xdr);
    let absent = crate::tools::common::approval_required_indistinguishable(
        &fx.server.profile_name_for_approval(),
    );
    let absent = assert_business_envelope(&absent);
    for half in [(Some(nonce.clone()), None), (None, attestation)] {
        let (code, message) = refused(&fx.submit_with(xdr.clone(), half).await);
        assert_eq!((code, message), (absent.0.clone(), absent.1.clone()));
    }
    assert_eq!(fx.store().len(), 1, "no second approval");
    assert_eq!(fx.sends(), 0);
}

/// `Debug` of both argument structs shows only whether an attestation is
/// set.
#[test]
fn the_arguments_hide_the_attestation() {
    let sign = format!(
        "{:?}",
        Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".into(),
            transaction_xdr: String::new(),
            network_passphrase: None,
            address: None,
            approval_nonce: Some("nonce".into()),
            approval_attestation: Some("credential-value".into()),
        }
    );
    let submit = format!(
        "{:?}",
        Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".into(),
            transaction_xdr: String::new(),
            network_passphrase: None,
            address: None,
            approval_nonce: Some("nonce".into()),
            approval_attestation: Some("credential-value".into()),
        }
    );
    for text in [sign, submit] {
        assert!(text.contains("Some(<set>)"), "{text}");
        assert!(!text.contains("credential-value"), "{text}");
    }
}

/// The integration cases of the S43c review: an issuer-pinned classic asset
/// passes while a contract call on an unlisted contract refuses;
/// `balance_floor` without an observed account view refuses; a zero payment
/// is a payment; a zero pool deposit needs the opt-in; a zero allowance has
/// no effect.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn integration_value_cases_keep_their_outcomes() {
    use stellar_agent_core::policy::v1::criteria::asset_allowlist::AssetAllowlistCriterion;
    let usdc = Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
        asset_code: stellar_xdr::AssetCode4(*b"USDC"),
        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(OTHER))),
    });
    let allowlist =
        AssetAllowlistCriterion::new(vec![format!("USDC:{}", g(OTHER)), "native".into()]).unwrap();
    let fx = Fixture::new(pay_rule(vec![Box::new(allowlist)])).await;
    signed(
        &fx.sign(fx.tx(vec![OperationBody::Payment(PaymentOp {
            destination: muxed(A, None),
            asset: usdc,
            amount: XLM,
        })]))
        .await,
    );
    let unlisted = call(
        [0x99; 32],
        "transfer",
        vec![
            ScVal::Address(account_address(fx.key)),
            ScVal::Address(account_address(A)),
            ScVal::from(i128::from(XLM)),
        ],
    );
    let (code, _) = refused(&fx.sign(fx.tx(vec![invoke(vec![unlisted])])).await);
    assert_eq!(code, "policy.deny.asset_not_allowlisted");
    drop(fx);

    let floor =
        stellar_agent_core::policy::v1::criteria::balance_floor::BalanceFloorCriterion::new(1);
    let fx = Fixture::new(pay_rule(vec![Box::new(floor)])).await;
    let (code, _) = refused(&fx.sign(fx.tx(vec![payment(muxed(A, None), XLM)])).await);
    assert_eq!(code, "account.unread");
    drop(fx);

    let fx = Fixture::new(pay_rule(vec![per_day(10 * i128::from(XLM))])).await;
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 0)])).await);
    assert_eq!(fx.usage("native"), (0, 1));
    let deposit =
        OperationBody::LiquidityPoolDeposit(stellar_xdr::LiquidityPoolDepositOp::default());
    let (code, _) = refused(&fx.sign(fx.tx(vec![deposit])).await);
    assert_eq!(code, "policy.deny.unsizable_value_effect");
    let zero_allowance = call(
        native_contract(),
        "approve",
        vec![
            ScVal::Address(account_address(fx.key)),
            ScVal::Address(account_address(A)),
            ScVal::from(0i128),
            ScVal::U32(100),
        ],
    );
    signed(&fx.sign(fx.tx(vec![invoke(vec![zero_allowance])])).await);
    assert_eq!(
        fx.usage("native"),
        (0, 1),
        "a zero allowance charges nothing"
    );
}

/// Holds the window writer lock of `fx` until the guard drops.
fn hold_window_lock(fx: &Fixture) -> stellar_agent_core::policy::state_lock::WindowStoreLock {
    stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
        fx.server.window_store.path(),
        &fx.profile.policy_window_state_key_id,
    )
    .unwrap()
}

/// A held window writer lock refuses admission before the signer and
/// records nothing; after a reopen the same call signs and charges once.
/// A failed admission of an attested repeat leaves the approval pending.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn admission_failures_record_nothing_and_recover() {
    let rules = || pay_rule(vec![per_day(15 * i128::from(XLM))]);
    let mut fx = Fixture::new(rules()).await;
    let ten = fx.tx(vec![payment(muxed(A, None), 10 * XLM)]);
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 0)])).await);
    let seed_reads = fx.seed_reads();
    let held = hold_window_lock(&fx);
    let (code, _) = refused(&fx.sign(ten.clone()).await);
    assert_eq!(code, "policy.engine_required");
    drop(held);
    assert_eq!(fx.seed_reads(), seed_reads, "no seed read");
    fx.restart(rules());
    assert_eq!(fx.usage("native"), (0, 1));
    signed(&fx.sign(ten).await);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 2));
    drop(fx);

    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    let held = hold_window_lock(&fx);
    let (code, _) = refused(&fx.sign_with(xdr.clone(), proof.clone()).await);
    drop(held);
    assert_eq!(code, "policy.engine_required");
    assert_eq!(fx.seed_reads(), 0);
    assert!(
        !matches!(
            fx.entry(&nonce).kind,
            ApprovalKind::Consumed { .. } | ApprovalKind::Rejected { .. }
        ),
        "the approval stays pending"
    );
    signed(&fx.sign_with(xdr, proof).await);
}

/// An approval directory that cannot be created returns
/// `approval.store_error` on the protocol channel for the stored shapes and
/// signs nothing.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_unwritable_approval_store_is_a_protocol_error() {
    let mut fx = Fixture::approving(vec![
        rule(SIGN, vec![], false),
        rule(SUBMIT, vec![], false),
        approval_rule("stellar_create_account_commit", 600),
        approval_rule("stellar_trustline_commit", 600),
    ])
    .await;
    let blocker = fx.dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"file").unwrap();
    fx.server
        .set_approval_dir_for_test(blocker.join("approvals"));
    let create = OperationBody::CreateAccount(stellar_xdr::CreateAccountOp {
        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(B))),
        starting_balance: 2 * XLM,
    });
    for xdr in [fx.tx(vec![create]), fx.tx(vec![usdc_trustline(XLM)])] {
        let error = fx
            .server
            .call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
                chain_id: "stellar:testnet".into(),
                transaction_xdr: xdr,
                network_passphrase: None,
                address: None,
                approval_nonce: None,
                approval_attestation: None,
            })
            .await
            .unwrap_err();
        assert!(
            error.message.starts_with("approval.store_error: "),
            "{}",
            error.message
        );
    }
    assert_eq!(fx.seed_reads(), 0);
    assert!(fx.rows("opaque_payload_signed").is_empty());
}

/// Makes the next approval spends fail before the tombstone is written.
pub(crate) static SPEND_FAULT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// A failed spend withholds the signature and leaves the approval pending,
/// so the signing retry signs; a rejected approval is never spent.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn a_failed_spend_withholds_the_signature() {
    let fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    SPEND_FAULT.store(true, Ordering::SeqCst);
    let failed = fx.sign_with(xdr.clone(), proof.clone()).await;
    SPEND_FAULT.store(false, Ordering::SeqCst);
    assert_eq!(refused(&failed).0, "submission.record_unavailable");
    assert!(
        !matches!(
            fx.entry(&nonce).kind,
            ApprovalKind::Consumed { .. } | ApprovalKind::Rejected { .. }
        ),
        "the approval stays pending"
    );
    signed(&fx.sign_with(xdr.clone(), proof).await);
    assert!(matches!(
        fx.entry(&nonce).kind,
        ApprovalKind::Consumed { .. }
    ));

    let rejected = fx.tx(vec![payment(muxed(A, None), 12 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(rejected.clone()).await));
    fx.store()
        .reject(
            &nonce,
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            600_000,
        )
        .unwrap();
    let refusal = fx
        .server
        .sep43_spend_approval(&nonce, &rejected)
        .unwrap_err();
    assert_eq!(
        assert_business_envelope(&refusal).0,
        "submission.record_unavailable"
    );
}

/// The signature row of an approved sign-only call records
/// `require_approval`; an allowed signature keeps `allow`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_approved_signature_row_records_the_decision() {
    let fx = Fixture::approving(escalating_rules()).await;
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 5 * XLM)])).await);
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.sign(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    signed(&fx.sign_with(xdr, proof).await);
    let decisions: Vec<_> = fx
        .rows("opaque_payload_signed")
        .iter()
        .map(|row| row["policy_decision"].clone())
        .collect();
    assert_eq!(decisions, vec![json!("allow"), json!("require_approval")]);
}

/// An approval read under a clock past its lifetime refuses; one read
/// under a clock before its creation refuses too.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_approval_outside_its_interval_refuses() {
    struct FixedClock(u64);
    impl stellar_agent_core::timefmt::Clock for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, stellar_agent_core::WalletLifecycleError> {
            Ok(self.0)
        }
    }
    let mut fx = Fixture::approving(escalating_rules()).await;
    let xdr = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    let nonce = nonce_of(&pending(&fx.submit(xdr.clone()).await));
    let proof = fx.attest(&nonce, &xdr);
    let entry = fx.entry(&nonce);
    for now in [entry.created_at_unix_ms - 1, entry.expires_at_unix_ms + 1] {
        fx.server.set_clock_for_test(Arc::new(FixedClock(now)));
        assert_eq!(
            refused(&fx.submit_with(xdr.clone(), proof.clone()).await).0,
            "policy.approval_required"
        );
    }
    assert_eq!(fx.sends(), 0);
    assert!(matches!(
        fx.entry(&nonce).kind,
        ApprovalKind::PaymentSimulated { .. }
    ));
}

// ─── Authorization entries ───────────────────────────────────────────────────

const AUTH: &str = "stellar_sep43_sign_auth_entry";

fn network_id() -> Hash {
    use sha2::Digest as _;
    Hash(sha2::Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into())
}

/// A base64 preimage of `version` over `root` on the network `network_id`,
/// with nonce 7 and expiration ledger 100. A type 9 preimage omits `address`.
fn preimage_xdr(
    version: stellar_agent_soroban_auth::AuthCredentialsVersion,
    network_id: [u8; 32],
    address: &ScAddress,
    root: SorobanAuthorizedInvocation,
) -> String {
    stellar_agent_soroban_auth::build_auth_preimage(version, network_id, 7, 100, address, root)
        .to_xdr_base64(Limits::none())
        .unwrap()
}

/// A type 9 preimage of `root` on the test network.
fn auth_preimage(root: SorobanAuthorizedInvocation) -> String {
    preimage_xdr(
        stellar_agent_soroban_auth::AuthCredentialsVersion::V1,
        network_id().0,
        &account_address(A),
        root,
    )
}

/// A type 10 preimage of `root` bound to `address`.
fn bound_preimage(address: &ScAddress, root: SorobanAuthorizedInvocation) -> String {
    preimage_xdr(
        stellar_agent_soroban_auth::AuthCredentialsVersion::V2,
        network_id().0,
        address,
        root,
    )
}

fn with_children(
    mut root: SorobanAuthorizedInvocation,
    children: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    root.sub_invocations = children.try_into().unwrap();
    root
}

/// A call the wallet cannot value: a function without a token shape.
fn unknown_call() -> SorobanAuthorizedInvocation {
    call([0xE5; 32], "swap", vec![])
}

/// A tree without a call: a contract creation.
fn create_contract() -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::CreateContractHostFn(Default::default()),
        sub_invocations: Default::default(),
    }
}

/// A muxed account address of `key` with `id`.
fn muxed_address(key: [u8; 32], id: u64) -> ScAddress {
    ScAddress::MuxedAccount(stellar_xdr::MuxedEd25519Account {
        id,
        ed25519: Uint256(key),
    })
}

/// A native asset contract transfer the wallet authorizes to `to`.
fn transfer_to(fx: &Fixture, to: ScAddress, amount: i128) -> SorobanAuthorizedInvocation {
    call(
        native_contract(),
        "transfer",
        vec![
            ScVal::Address(account_address(fx.key)),
            ScVal::Address(to),
            ScVal::from(amount),
        ],
    )
}

/// The auth tool's own rule and a pay rule with `criteria`.
fn auth_rules(opt_in: bool, criteria: Vec<Box<dyn Criterion>>) -> Vec<PolicyRule> {
    vec![rule(AUTH, vec![], opt_in), rule(PAY, criteria, false)]
}

async fn auth_call(
    server: &WalletServer,
    auth_entry_xdr: String,
    address: Option<String>,
) -> CallToolResult {
    server
        .call_stellar_sep43_sign_auth_entry(
            crate::tools::sep43_sign_auth_entry::Sep43SignAuthEntryArgs {
                chain_id: "stellar:testnet".into(),
                auth_entry_xdr,
                network_passphrase: None,
                address,
            },
        )
        .await
        .expect("a business result")
}

impl Fixture {
    async fn auth(&self, preimage: String) -> CallToolResult {
        auth_call(&self.server, preimage, None).await
    }
}

/// The refusal code; asserts that no signature was returned.
fn auth_refused(result: &CallToolResult) -> String {
    let (code, _, text) = assert_business_envelope(result);
    assert!(!text.contains("signedAuthEntry"), "{text}");
    code
}

/// Asserts a returned signature and returns it.
fn auth_signed(result: &CallToolResult) -> String {
    let text = &result.content[0].as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str::<Value>(text).unwrap()["data"]["signedAuthEntry"]
        .as_str()
        .unwrap_or_else(|| panic!("a signature: {text}"))
        .to_owned()
}

/// Every invalid preimage refuses with its SEP-43 code before any account
/// read, admission or seed read; a valid type 9 and type 10 preimage sign.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_preimage_validation_precedes_external_work() {
    let fx = Fixture::new(vec![rule(AUTH, vec![rate(10)], false)]).await;
    let paying = transfer_to(&fx, account_address(A), XLM.into());
    let operation_id = stellar_xdr::HashIdPreimage::OpId(stellar_xdr::HashIdPreimageOperationId {
        source_account: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(fx.key))),
        seq_num: SequenceNumber(1),
        op_num: 0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let foreign = preimage_xdr(
        stellar_agent_soroban_auth::AuthCredentialsVersion::V1,
        [9; 32],
        &account_address(fx.key),
        paying.clone(),
    );
    let mut deep = paying.clone();
    for _ in 0..600 {
        deep = with_children(unknown_call(), vec![deep]);
    }
    let cases = [
        ("not base64!".to_owned(), "sep43.invalid_xdr"),
        (
            base64::engine::general_purpose::STANDARD.encode([0xFF; 12]),
            "sep43.invalid_xdr",
        ),
        (operation_id, "sep43.malformed_auth_entry"),
        (foreign, "sep43.invalid_network_passphrase"),
        (
            bound_preimage(&account_address(A), paying.clone()),
            "sep43.invalid_address",
        ),
        (
            bound_preimage(
                &ScAddress::Contract(ContractId(Hash(fx.key))),
                paying.clone(),
            ),
            "sep43.invalid_address",
        ),
        (
            bound_preimage(&muxed_address(fx.key, 1), paying.clone()),
            "sep43.invalid_address",
        ),
        (auth_preimage(deep), "sep43.invalid_xdr"),
    ];
    for (preimage, expected) in cases {
        assert_eq!(auth_refused(&fx.auth(preimage).await), expected);
    }
    assert_eq!(fx.requests().await, 0, "no account read");
    assert_eq!(fx.seed_reads(), 0, "no seed read");
    assert_eq!(fx.usage("rate_limit").1, 0, "no admission");
    auth_signed(&fx.auth(auth_preimage(create_contract())).await);
    auth_signed(
        &fx.auth(bound_preimage(&account_address(fx.key), create_contract()))
            .await,
    );
    assert_eq!(fx.usage("rate_limit").1, 2);
}

/// A profile signer that is not a G-strkey refuses with
/// `policy.engine_required` before any read, even for a valued tree.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_missing_authorizer_fails_before_seed() {
    let fx = Fixture::with(auth_rules(true, vec![]), |profile| {
        profile.mcp_signer_default.account = "acct-not-a-key".into();
    })
    .await;
    let result = fx.auth(auth_preimage(transfer(OTHER, A, XLM.into()))).await;
    let (code, message, _) = assert_business_envelope(&result);
    assert_eq!(code, "policy.engine_required");
    assert!(message.contains("not a G-strkey"), "{message}");
    assert_eq!(fx.requests().await, 0);
    assert_eq!(fx.seed_reads(), 0);
}

/// An unknown root does not hide its token children: without the opt-in
/// it refuses; with it the second, over-cap leg refuses; both legs within
/// the cap sign. A fully known tree needs no opt-in.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_mixed_tree_keeps_every_leg_and_needs_consent() {
    let cap = || vec![per_tx(10 * i128::from(XLM))];
    let mixed = |fx: &Fixture, second: i64| {
        auth_preimage(with_children(
            unknown_call(),
            vec![
                fx.transfer(A, (5 * XLM).into()),
                fx.transfer(B, second.into()),
            ],
        ))
    };
    let fx = Fixture::new(auth_rules(false, cap())).await;
    assert_eq!(
        auth_refused(&fx.auth(mixed(&fx, 5 * XLM)).await),
        "policy.deny.unsizable_value_effect"
    );
    assert_eq!(fx.requests().await, 0);
    let known = with_children(
        fx.transfer(A, (5 * XLM).into()),
        vec![fx.transfer(B, (5 * XLM).into())],
    );
    auth_signed(&fx.auth(auth_preimage(known)).await);
    drop(fx);

    let fx = Fixture::new(auth_rules(true, cap())).await;
    assert_eq!(
        auth_refused(&fx.auth(mixed(&fx, 11 * XLM)).await),
        "policy.deny.per_tx_cap_exceeded"
    );
    assert_eq!(fx.seed_reads(), 0);
    auth_signed(&fx.auth(mixed(&fx, 5 * XLM)).await);
    let rows = fx.rows("opaque_payload_signed");
    let legs = rows[0]["legs"].as_array().unwrap();
    let redacted = |key| stellar_agent_core::observability::redact_strkey_first5_last5(&g(key));
    assert_eq!(legs.len(), 2, "{legs:?}");
    assert_eq!(legs[0]["destination_redacted"], redacted(A));
    assert_eq!(legs[1]["destination_redacted"], redacted(B));
}

/// Each leg is decided by the pay rule, not the tool rule, in the outer
/// frame: the cap admits its equal and refuses one unit more, a memo
/// binding refuses the memo-less entry, and two muxed recipients of one
/// account share one read.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_legs_obey_the_pay_rule_in_the_outer_frame() {
    use stellar_agent_core::policy::v1::criteria::memo_binding::{
        MemoBinding, MemoBindingCriterion, MemoRequirement,
    };
    let cap = 10 * i128::from(XLM);
    let fx = Fixture::new(auth_rules(false, vec![per_tx(cap)])).await;
    auth_signed(&fx.auth(auth_preimage(fx.transfer(A, cap))).await);
    let seed_reads = fx.seed_reads();
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(fx.transfer(A, cap + 1))).await),
        "policy.deny.per_tx_cap_exceeded"
    );
    assert_eq!(fx.seed_reads(), seed_reads);
    let two = with_children(
        transfer_to(&fx, muxed_address(B, 1), XLM.into()),
        vec![transfer_to(&fx, muxed_address(B, 2), XLM.into())],
    );
    auth_signed(&fx.auth(auth_preimage(two)).await);
    assert_eq!(fx.reads(B), 1, "one read of the shared base account");
    drop(fx);

    let fx = Fixture::new(auth_rules(
        false,
        vec![Box::new(MemoBindingCriterion::new(vec![
            MemoBinding::new(&g(A), MemoRequirement::Id(7)).unwrap(),
        ]))],
    ))
    .await;
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(fx.transfer(A, XLM.into()))).await),
        "policy.deny.memo_binding_mismatch"
    );
    auth_signed(&fx.auth(auth_preimage(fx.transfer(B, XLM.into()))).await);
    drop(fx);

    let mut fx = Fixture::new(auth_rules(false, vec![])).await;
    let now = stellar_agent_core::policy::policy_now_ms().unwrap();
    let _clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(now);
    let engine = Arc::new(FrameEngine {
        seen: Mutex::new(Vec::new()),
        later: now + 60_000,
        outer: AUTH,
    });
    fx.server.set_policy_engine_for_test(engine.clone());
    let two = with_children(fx.transfer(A, XLM.into()), vec![fx.transfer(B, XLM.into())]);
    auth_signed(&fx.auth(auth_preimage(two)).await);
    assert_eq!(
        *engine.seen.lock().unwrap(),
        vec![
            (AUTH.to_owned(), now),
            (PAY.to_owned(), now),
            (PAY.to_owned(), now)
        ]
    );
}

/// Quantities stay exact through decision, admission and audit: `i128::MAX`
/// fits a `MAX` period cap, while `MAX` and one more refuse in one batch.
/// A zero transfer reaches the pay rule; a zero allowance has no leg; a
/// negative amount is unvalued.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_exact_quantities_and_overflow_refuse() {
    let rules = || auth_rules(false, vec![per_day(i128::MAX)]);
    let fx = Fixture::new(rules()).await;
    let above_i64 = i128::from(i64::MAX) + 1;
    auth_signed(&fx.auth(auth_preimage(fx.transfer(A, above_i64))).await);
    assert_eq!(
        fx.rows("opaque_payload_signed")[0]["legs"][0]["amount"],
        above_i64.to_string()
    );
    drop(fx);
    let fx = Fixture::new(rules()).await;
    auth_signed(&fx.auth(auth_preimage(fx.transfer(A, i128::MAX))).await);
    assert_eq!(fx.usage("native"), (i128::MAX, 1));
    drop(fx);
    let fx = Fixture::new(rules()).await;
    let over = with_children(fx.transfer(A, i128::MAX), vec![fx.transfer(B, 1)]);
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(over)).await),
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (0, 0));
    assert_eq!(fx.seed_reads(), 0);
    drop(fx);

    let fx = Fixture::new(vec![rule(AUTH, vec![], false)]).await;
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(fx.transfer(A, 0))).await),
        "policy.deny.no_matching_rule"
    );
    let approve = |amount: i128| {
        call(
            native_contract(),
            "approve",
            vec![
                ScVal::Address(account_address(fx.key)),
                ScVal::Address(account_address(A)),
                ScVal::from(amount),
                ScVal::U32(100),
            ],
        )
    };
    let requests = fx.requests().await;
    auth_signed(&fx.auth(auth_preimage(approve(0))).await);
    assert_eq!(
        fx.requests().await,
        requests,
        "a zero allowance reads nothing"
    );
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(fx.transfer(A, -1))).await),
        "policy.deny.unsizable_value_effect"
    );
}

/// One durable batch admits every leg and the tool's own count: 10 and 10
/// under 15 add nothing; 5 and 5 add both legs and one count; a stale
/// second server cannot add another 10; a tree without a leg reaches the
/// tool's count limit without a read.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_admission_is_atomic_and_charges_its_own_rule() {
    let rules = || {
        vec![
            rule(AUTH, vec![rate(5)], false),
            rule(PAY, vec![per_day(15 * i128::from(XLM))], false),
        ]
    };
    let mut fx = Fixture::new(rules()).await;
    let pair = |fx: &Fixture, amount: i64| {
        auth_preimage(with_children(
            fx.transfer(A, amount.into()),
            vec![fx.transfer(B, amount.into())],
        ))
    };
    let stale = WalletServer::new(fx.profile.clone()).unwrap();
    assert_eq!(
        auth_refused(&fx.auth(pair(&fx, 10 * XLM)).await),
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (0, 0));
    assert_eq!(fx.usage("rate_limit").1, 0);
    auth_signed(&fx.auth(pair(&fx, 5 * XLM)).await);
    fx.restart(rules());
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 2));
    assert_eq!(fx.usage("rate_limit").1, 1);
    let mut stale = stale;
    let name = stale.profile_name_for_approval();
    stale.set_policy_engine_for_test(Arc::new(engine(&name, rules())));
    assert_eq!(
        auth_refused(&auth_call(&stale, pair(&fx, 5 * XLM), None).await),
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 2));
    drop(fx);

    let fx = Fixture::new(vec![rule(AUTH, vec![rate(1)], false)]).await;
    auth_signed(&fx.auth(auth_preimage(create_contract())).await);
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(create_contract())).await),
        "policy.deny.rate_limit_exceeded"
    );
    assert_eq!(fx.requests().await, 0, "no payment read");
}

/// Admitted usage stays after a signing or signer failure and a restart;
/// identical bytes charge each call; a refused call adds nothing, also when
/// the caller's address is not the signer.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_failures_and_repeats_keep_authorized_spend() {
    let rules = || auth_rules(false, vec![per_day(15 * i128::from(XLM))]);
    let mut fx = Fixture::new(rules()).await;
    let ten = auth_preimage(fx.transfer(A, (10 * XLM).into()));
    assert_eq!(
        auth_refused(&auth_call(&fx.server, ten.clone(), Some(g(A))).await),
        "sep43.invalid_address"
    );
    assert_eq!(
        fx.usage("native"),
        (0, 0),
        "a foreign address charges nothing"
    );
    assert_eq!(fx.requests().await, 0);
    assert_eq!(fx.seed_reads(), 0);
    // The signer load reads the seed once; the read at signing fails.
    fx.fail_seed_read_after(1);
    assert_eq!(
        auth_refused(&fx.auth(ten.clone()).await),
        "sep43.user_rejected"
    );
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    fx.restart(rules());
    assert_eq!(
        auth_refused(&fx.auth(ten).await),
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    drop(fx);

    let mut fx = Fixture::new(rules()).await;
    keyring_core::Entry::new("svc-s43fx", &g(fx.key))
        .unwrap()
        .delete_credential()
        .unwrap();
    let ten = auth_preimage(fx.transfer(A, (10 * XLM).into()));
    assert_eq!(
        auth_refused(&fx.auth(ten.clone()).await),
        "sep43.wallet_unlock_failed"
    );
    fx.restart(rules());
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    drop(fx);

    let fx = Fixture::new(vec![rule(AUTH, vec![rate(2)], false)]).await;
    let bytes = auth_preimage(create_contract());
    auth_signed(&fx.auth(bytes.clone()).await);
    auth_signed(&fx.auth(bytes.clone()).await);
    assert_eq!(fx.usage("rate_limit").1, 2);
    assert_eq!(
        auth_refused(&fx.auth(bytes.clone()).await),
        "policy.deny.rate_limit_exceeded"
    );
    assert_eq!(
        auth_refused(&fx.auth(bytes).await),
        "policy.deny.rate_limit_exceeded"
    );
    assert_eq!(fx.usage("rate_limit").1, 2, "a refusal adds no count");
}

/// The signature covers SHA-256 of the supplied bytes, and the row records
/// the admitted legs in order with the contract asset and redacted
/// recipients, never a full address, the preimage or the signature.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_signature_audits_the_admitted_legs() {
    use sha2::Digest as _;
    let fx = Fixture::new(auth_rules(false, vec![])).await;
    let muxed =
        stellar_strkey::Strkey::MuxedAccountEd25519(stellar_strkey::ed25519::MuxedAccount {
            ed25519: B,
            id: 9,
        })
        .to_string()
        .as_str()
        .to_owned();
    let preimage = auth_preimage(with_children(
        fx.transfer(A, (5 * XLM).into()),
        vec![transfer_to(&fx, muxed_address(B, 9), (3 * XLM).into())],
    ));
    let signature = auth_signed(&auth_call(&fx.server, preimage.clone(), Some(g(fx.key))).await);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&preimage)
        .unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let raw: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(&signature)
        .unwrap()
        .try_into()
        .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&fx.key)
        .unwrap()
        .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&raw))
        .expect("the signature covers the supplied preimage");
    let rows = fx.rows("opaque_payload_signed");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["tool"], AUTH);
    let redacted = stellar_agent_core::observability::redact_strkey_first5_last5;
    let contract = stellar_strkey::Contract(native_contract()).to_string();
    let expected = json!([
        {"action": "payment", "amount": (5 * XLM).to_string(), "asset": contract.as_str(),
         "destination_redacted": redacted(&g(A))},
        {"action": "payment", "amount": (3 * XLM).to_string(), "asset": contract.as_str(),
         "destination_redacted": redacted(&muxed)},
    ]);
    assert_eq!(rows[0]["legs"], expected);
    let log = std::fs::read_to_string(&fx.audit).unwrap();
    for secret in [g(A), muxed, g(fx.key), preimage, signature] {
        assert!(!log.contains(&secret), "the row holds no {secret}");
    }
    auth_signed(&fx.auth(auth_preimage(create_contract())).await);
    let empty = &fx.rows("opaque_payload_signed")[1];
    assert!(empty.get("legs").is_none(), "{empty}");
}

/// An approval requirement of the tool rule or of a pay rule refuses as
/// unsupported without a pending approval, a seed read or a signature.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_escalation_never_enters_transaction_approval() {
    let pending_store = |fx: &Fixture| {
        fx.dir
            .path()
            .join("approvals")
            .join(format!("{}.toml", fx.server.profile_name_for_approval()))
    };
    let fx = Fixture::approving(auth_rules(
        false,
        vec![Box::new(
            stellar_agent_core::policy::v1::criteria::approval_above::ApprovalAboveCriterion::new(
                "native".into(),
                10 * i128::from(XLM),
            ),
        )],
    ))
    .await;
    assert_eq!(
        auth_refused(
            &fx.auth(auth_preimage(fx.transfer(A, (11 * XLM).into())))
                .await
        ),
        "policy.approval_required_unsupported"
    );
    assert_eq!(fx.seed_reads(), 0);
    assert!(!pending_store(&fx).exists(), "no pending approval");
    auth_signed(
        &fx.auth(auth_preimage(fx.transfer(A, (10 * XLM).into())))
            .await,
    );
    drop(fx);

    let fx = Fixture::approving(vec![approval_rule(AUTH, 120), rule(PAY, vec![], false)]).await;
    assert_eq!(
        auth_refused(&fx.auth(auth_preimage(fx.transfer(A, XLM.into()))).await),
        "policy.approval_required_unsupported"
    );
    assert_eq!(fx.seed_reads(), 0);
    assert!(!pending_store(&fx).exists(), "no pending approval");
}

/// Auth legs and classic payments share one asset limit: a contract 10
/// then a classic 10 refuse under 15, and a classic 5 fits.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_and_classic_payments_share_one_asset_limit() {
    let mut rules = auth_rules(false, vec![per_day(15 * i128::from(XLM))]);
    rules.push(rule(SIGN, vec![], false));
    let fx = Fixture::new(rules).await;
    auth_signed(
        &fx.auth(auth_preimage(fx.transfer(A, (10 * XLM).into())))
            .await,
    );
    assert_eq!(
        refused(
            &fx.sign(fx.tx(vec![payment(muxed(A, None), 10 * XLM)]))
                .await
        )
        .0,
        "policy.deny.per_period_cap_exceeded"
    );
    signed(&fx.sign(fx.tx(vec![payment(muxed(A, None), 5 * XLM)])).await);
    assert_eq!(fx.usage("native"), (15 * i128::from(XLM), 2));
}

/// A failed wallet read and unavailable accounting refuse before the seed;
/// the next call after recovery signs without a person.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn auth_retry_after_transient_failure_works() {
    let mut fx = Fixture::new(auth_rules(false, vec![])).await;
    let one = || auth_preimage(fx.transfer(A, XLM.into()));
    fx.failing(fx.key);
    let code = auth_refused(&fx.auth(one()).await);
    assert!(code.starts_with("network."), "{code}");
    assert_eq!(fx.seed_reads(), 0);
    fx.account(fx.key, WALLET_BALANCE, None);
    auth_signed(&fx.auth(one()).await);
    let seed_reads = fx.seed_reads();

    fx.server
        .set_policy_engine_for_test(Arc::new(UnrecordableEngine));
    let result = fx.auth(auth_preimage(create_contract())).await;
    let (code, message, _) = assert_business_envelope(&result);
    assert_eq!(code, "policy.engine_required");
    assert_eq!(message, "authorized payment accounting is unavailable");
    assert_eq!(fx.seed_reads(), seed_reads);
    fx.restart(auth_rules(false, vec![]));
    auth_signed(&fx.auth(auth_preimage(create_contract())).await);
}

// ─── Source membership ───────────────────────────────────────────────────────

/// An operation source whose signer set the fixture decides.
const SOURCE: [u8; 32] = [0xD4; 32];
/// An operation source whose signer set never lists the wallet.
const STRANGER: [u8; 32] = [0xE5; 32];

/// `body` with `key` as its explicit source.
fn from(key: [u8; 32], id: Option<u64>, body: OperationBody) -> Operation {
    Operation {
        source_account: Some(muxed(key, id)),
        body,
    }
}

impl Fixture {
    /// A wallet transaction of `operations` without a memo.
    fn ops(&self, operations: Vec<Operation>) -> String {
        let fee = 100 * u32::try_from(operations.len()).unwrap();
        encode(tx(self.key, fee, Memo::None, operations))
    }
}

/// Both refusal codes, or both signatures, of the two tools for `xdr`.
async fn both(fx: &Fixture, xdr: &str) -> [CallToolResult; 2] {
    [
        fx.sign(xdr.to_owned()).await,
        fx.submit(xdr.to_owned()).await,
    ]
}

/// The submit result reached the send: the fixture endpoint refuses it.
fn sent(fx: &Fixture, before: usize, result: &CallToolResult) {
    let text = &result.content[0].as_text().unwrap().text;
    assert!(!text.contains("policy."), "{text}");
    assert!(!text.contains("network.account_not_found"), "{text}");
    assert_eq!(fx.sends(), before + 1, "one send: {text}");
}

#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn both_tools_use_attributed_effects_and_original_approval_shape() {
    let fx = Fixture::approving(tools(false)).await;
    fx.source(SOURCE, false);
    let foreign = fx.ops(vec![from(SOURCE, None, payment(muxed(B, None), 5 * XLM))]);
    let before = fx.sends();
    let [sign, submit] = both(&fx, &foreign).await;
    signed(&sign);
    sent(&fx, before, &submit);
    assert_eq!(fx.sends(), 1);
    // One membership read per call; submit's network binding reads once more.
    assert_eq!(fx.reads(SOURCE), 3);
    assert_eq!(fx.reads(B), 0, "an excluded payment reads no recipient");
    fx.source(SOURCE, true);
    for result in both(&fx, &foreign).await {
        assert_eq!(refused(&result).0, "policy.deny.no_matching_rule");
    }
    drop(fx);
    // One included payment in two raw operations keeps the raw shape.
    let fx = Fixture::approving(escalating_rules()).await;
    fx.source(SOURCE, false);
    let two = fx.ops(vec![
        op(payment(muxed(A, None), 11 * XLM)),
        from(SOURCE, None, payment(muxed(B, None), XLM)),
    ]);
    for result in both(&fx, &two).await {
        assert_eq!(refused(&result).0, "policy.approval_required_unsupported");
    }
    assert!(
        !fx.dir.path().join("approvals").exists(),
        "no pending approval"
    );
    let one = fx.tx(vec![payment(muxed(A, None), 11 * XLM)]);
    pending(&fx.sign(one).await);
}

#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn signer_read_failure_is_not_nonmembership() {
    let fx = Fixture::new(tools(false)).await;
    let xdr = fx.ops(vec![from(SOURCE, Some(3), payment(muxed(B, None), XLM))]);
    type Fault = Box<dyn Fn(&Fixture)>;
    let faults: [(&str, Fault); 5] = [
        ("network.account_not_found", Box::new(|_| {})),
        (
            "network.rpc_credential_refused",
            Box::new(|fx| {
                fx.serve(
                    SOURCE,
                    Account {
                        rejects: true,
                        ..Default::default()
                    },
                )
            }),
        ),
        ("network.rpc_unreachable", Box::new(|fx| fx.failing(SOURCE))),
        (
            "protocol.xdr_codec_failed",
            Box::new(|fx| {
                fx.serve(
                    SOURCE,
                    Account {
                        bad_xdr: true,
                        ..Default::default()
                    },
                )
            }),
        ),
        (
            "network.rpc_response_malformed",
            Box::new(|fx| {
                fx.source(SOURCE, false);
                fx.ledger.bad_latest.store(true, Ordering::SeqCst);
            }),
        ),
    ];
    for (code, fault) in faults {
        fault(&fx);
        for result in both(&fx, &xdr).await {
            assert_eq!(refused(&result).0, code);
        }
        fx.ledger.bad_latest.store(false, Ordering::SeqCst);
        fx.ledger.accounts.lock().unwrap().remove(&g(SOURCE));
    }
    assert_eq!(fx.seed_reads(), 0, "no seed read");
    assert!(fx.rows("opaque_payload_signed").is_empty(), "no audit row");
    assert_eq!(fx.sends(), 0);
    assert_eq!(fx.usage("native"), (0, 0));
    fx.source(SOURCE, false);
    signed(&fx.sign(xdr).await);
}

#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn membership_is_refreshed_on_each_call() {
    let fx = Fixture::new(tools(false)).await;
    let xdr = fx.ops(vec![from(SOURCE, None, payment(muxed(B, None), XLM))]);
    fx.source(SOURCE, false);
    signed(&fx.sign(xdr.clone()).await);
    fx.source(SOURCE, true);
    assert_eq!(
        refused(&fx.sign(xdr.clone()).await).0,
        "policy.deny.no_matching_rule"
    );
    fx.source(SOURCE, false);
    signed(&fx.sign(xdr).await);
    assert_eq!(fx.reads(SOURCE), 3);
}

/// Wallet 5, member 5 and stranger 100 under a 10 cap: exactly the two
/// selected legs reach admission and the audit row.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn selected_sources_alone_reach_windows_and_audit() {
    let rules = |counted| {
        let own = |tool| match tool == counted {
            true => rule(tool, vec![rate(5)], false),
            false => rule(tool, vec![], false),
        };
        vec![
            own(SIGN),
            own(SUBMIT),
            rule(PAY, vec![per_day(10 * i128::from(XLM))], false),
        ]
    };
    let ten = |fx: &Fixture| {
        fx.source(SOURCE, true);
        fx.source(STRANGER, false);
        fx.ops(vec![
            op(payment(muxed(A, None), 5 * XLM)),
            from(STRANGER, None, payment(muxed(B, Some(7)), 100 * XLM)),
            from(SOURCE, Some(2), payment(muxed(B, Some(8)), 5 * XLM)),
        ])
    };
    let fx = Fixture::new(rules(SIGN)).await;
    let xdr = ten(&fx);
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 2));
    assert_eq!(fx.usage("rate_limit").1, 1, "one own count");
    let rows = fx.rows("opaque_payload_signed");
    let legs = rows[0]["legs"].as_array().unwrap();
    let redact = stellar_agent_core::observability::redact_strkey_first5_last5;
    let muxed_b = |id| {
        stellar_strkey::ed25519::MuxedAccount { ed25519: B, id }
            .to_string()
            .as_str()
            .to_owned()
    };
    let seen: Vec<_> = legs
        .iter()
        .map(|leg| (leg["amount"].clone(), leg["destination_redacted"].clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (json!((5 * XLM).to_string()), json!(redact(&g(A)))),
            (json!((5 * XLM).to_string()), json!(redact(&muxed_b(8)))),
        ]
    );
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(
        fx.usage("native"),
        (10 * i128::from(XLM), 2),
        "atomic refusal"
    );
    drop(fx);
    let fx = Fixture::new(rules(SUBMIT)).await;
    let before = fx.sends();
    sent(&fx, before, &fx.submit(ten(&fx)).await);
    assert_eq!(
        fx.usage("native"),
        (10 * i128::from(XLM), 2),
        "a failed send keeps it"
    );
    assert_eq!(fx.usage("rate_limit").1, 1, "the recorder's own count");
    assert_eq!(
        fx.rows("value_action_pending")[0]["legs"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// Sequence 4: identical calls charge again; a refusal adds nothing; every
/// call reads the signer set.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn source_selection_repeats_keep_signing_charges() {
    let mut rules = pay_rule(vec![per_day(10 * i128::from(XLM))]);
    rules[0] = rule(SIGN, vec![rate(5)], false);
    let fx = Fixture::new(rules).await;
    fx.source(SOURCE, true);
    let xdr = fx.ops(vec![from(SOURCE, None, payment(muxed(B, None), 4 * XLM))]);
    signed(&fx.sign(xdr.clone()).await);
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(fx.usage("native"), (8 * i128::from(XLM), 2));
    assert_eq!(fx.usage("rate_limit").1, 2);
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (8 * i128::from(XLM), 2));
    assert_eq!(fx.reads(SOURCE), 3);
}

/// Sequence 5: a selected leg at the cap signs and one stroop more refuses;
/// a stranger's maximal leg is excluded; a negative field refuses for any
/// source.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn source_selection_does_not_mask_invalid_amounts() {
    let fx = Fixture::new(pay_rule(vec![per_tx(10 * i128::from(XLM))])).await;
    fx.source(SOURCE, true);
    fx.source(STRANGER, false);
    let pair = |amount| {
        fx.ops(vec![
            from(SOURCE, None, payment(muxed(B, None), amount)),
            from(STRANGER, None, payment(muxed(B, None), i64::MAX)),
        ])
    };
    assert_eq!(
        refused(&fx.sign(pair(10 * XLM + 1)).await).0,
        "policy.deny.per_tx_cap_exceeded"
    );
    signed(&fx.sign(pair(10 * XLM)).await);
    signed(&fx.sign(pair(0)).await);
    let negative = fx.ops(vec![from(STRANGER, None, payment(muxed(B, None), -1))]);
    for result in both(&fx, &negative).await {
        assert_eq!(refused(&result).0, "sep43.invalid_xdr");
    }
    assert_eq!(
        fx.reads(STRANGER),
        3,
        "a negative field refuses before any read"
    );
}

/// Sequence 6: G and M spellings of a source share one request and one
/// membership; muxed recipients keep their own identities.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn source_aliases_share_one_membership_query() {
    let fx = Fixture::new(pay_rule(vec![per_day(10 * i128::from(XLM))])).await;
    fx.source(SOURCE, true);
    let xdr = fx.ops(vec![
        from(SOURCE, None, payment(muxed(B, Some(1)), XLM)),
        from(SOURCE, Some(0), payment(muxed(B, Some(2)), XLM)),
        from(SOURCE, Some(u64::MAX), payment(muxed(B, None), XLM)),
    ]);
    signed(&fx.sign(xdr).await);
    assert_eq!(fx.reads(SOURCE), 1);
    assert_eq!(fx.usage("native"), (3 * i128::from(XLM), 3));
    let legs = fx.rows("opaque_payload_signed")[0]["legs"].clone();
    let distinct: std::collections::BTreeSet<_> = legs
        .as_array()
        .unwrap()
        .iter()
        .map(|leg| leg["destination_redacted"].to_string())
        .collect();
    assert_eq!(distinct.len(), 3, "{legs}");
}

/// Sequence 9: a stranger's 100 beside a selected 5 fits a cap of 5 and
/// records exactly 5; the next selected 5 refuses at the cap.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn excluded_sources_do_not_consume_capacity() {
    let fx = Fixture::new(pay_rule(vec![per_day(5 * i128::from(XLM))])).await;
    fx.source(STRANGER, false);
    let xdr = fx.ops(vec![
        from(STRANGER, None, payment(muxed(B, None), 100 * XLM)),
        op(payment(muxed(A, None), 5 * XLM)),
    ]);
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(fx.usage("native"), (5 * i128::from(XLM), 1));
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
}

/// A member's 6 beside a stranger's 100, under a daily cap of 10 for the
/// pay rule.
fn selected_six(fx: &Fixture) -> String {
    fx.source(SOURCE, true);
    fx.source(STRANGER, false);
    fx.ops(vec![
        from(SOURCE, None, payment(muxed(B, None), 6 * XLM)),
        from(STRANGER, None, payment(muxed(B, None), 100 * XLM)),
    ])
}

/// A crash before admission records nothing. A crash after admission and
/// before the signer keeps the selected 6 across a restart, without the
/// excluded 100, so the repeat refuses at the cap.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn source_selection_survives_admission_crash() {
    let rules = || pay_rule(vec![per_day(10 * i128::from(XLM))]);
    let mut fx = Fixture::new(rules()).await;
    let xdr = selected_six(&fx);
    std::fs::create_dir_all(fx.server.window_store.path().parent().unwrap()).unwrap();
    let held = hold_window_lock(&fx);
    assert_eq!(
        refused(&fx.sign(xdr.clone()).await).0,
        "policy.engine_required"
    );
    drop(held);
    fx.restart(rules());
    assert_eq!(fx.usage("native"), (0, 0), "nothing before admission");
    fx.fail_seed_read_after(0);
    assert_eq!(
        refused(&fx.sign(xdr.clone()).await).0,
        "sep43.wallet_unlock_failed"
    );
    fx.restart(rules());
    assert_eq!(
        fx.usage("native"),
        (6 * i128::from(XLM), 1),
        "the selected leg alone survives the restart"
    );
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.deny.per_period_cap_exceeded"
    );
    assert_eq!(fx.usage("native"), (6 * i128::from(XLM), 1));
    assert!(fx.rows("opaque_payload_signed").is_empty());
    assert_eq!(fx.reads(STRANGER), 3, "every call reads the signer set");
}

/// After a restart under an earlier clock the selected 6 still counts. Under
/// a clock two days later it has expired and does not return, and the
/// signer sets are read again: a newly listed stranger's 100 counts.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn selected_usage_keeps_existing_expiry() {
    let rules = || pay_rule(vec![per_day(10 * i128::from(XLM))]);
    let start = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let policy_clock =
        stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(start);
    let store_clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(start);
    let set_clock = |now| {
        policy_clock.set(now);
        store_clock.set(now);
    };
    let mut fx = Fixture::new(rules()).await;
    let xdr = selected_six(&fx);
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(fx.usage("native"), (6 * i128::from(XLM), 1));

    set_clock(start - 3_600_000);
    fx.restart(rules());
    assert_eq!(
        refused(&fx.sign(xdr.clone()).await).0,
        "policy.deny.per_period_cap_exceeded",
        "an earlier clock releases nothing"
    );

    set_clock(start + 2 * 86_400_000);
    fx.restart(rules());
    fx.source(STRANGER, true);
    assert_eq!(
        refused(&fx.sign(xdr.clone()).await).0,
        "policy.deny.per_period_cap_exceeded",
        "a newly listed source counts"
    );
    fx.source(STRANGER, false);
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.deny.per_period_cap_exceeded",
        "the new 6 counts once and the expired 6 stays out"
    );
    assert_eq!(fx.reads(STRANGER), 5, "every call reads the signer set");
    assert_eq!(fx.rows("opaque_payload_signed").len(), 2);
}

/// Two servers on one store read the signer sets and evaluate before either
/// admits. Admission rereads the window file under `WindowStoreLock`, so one
/// selected 10 fits a cap of 15 and the other refuses. A held audit writer
/// lock refuses before admission and the signer. The signer-set read takes
/// no lock; the order stays audit sidecar, window lock, signer.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn source_reads_do_not_bypass_locked_admission() {
    let rules = || pay_rule(vec![per_day(15 * i128::from(XLM))]);
    let fx = Fixture::new(rules()).await;
    fx.source(SOURCE, true);
    fx.source(STRANGER, false);
    let xdr = fx.ops(vec![
        from(SOURCE, None, payment(muxed(B, None), 10 * XLM)),
        from(STRANGER, None, payment(muxed(B, None), 100 * XLM)),
    ]);
    let mut sidecar = fx.audit.clone().into_os_string();
    sidecar.push(".lock");
    let holder = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&sidecar)
        .unwrap();
    holder.try_lock().unwrap();
    let (code, message) = refused(&fx.sign(xdr.clone()).await);
    assert_eq!(code, "audit.chain_key_unavailable");
    assert!(message.contains("audit.writer_locked"), "{message}");
    drop(holder);
    assert_eq!(fx.usage("native"), (0, 0));
    assert_eq!(fx.seed_reads(), 0);

    let mut other = WalletServer::new(fx.profile.clone()).unwrap();
    let name = other.profile_name_for_approval();
    other.set_policy_engine_for_test(Arc::new(engine(&name, rules())));
    let (first, second) = tokio::join!(
        fx.sign(xdr.clone()),
        other.call_stellar_sep43_sign_transaction(Sep43SignTransactionArgs {
            chain_id: "stellar:testnet".into(),
            transaction_xdr: xdr,
            network_passphrase: None,
            address: None,
            approval_nonce: None,
            approval_attestation: None,
        })
    );
    let second = second.expect("a business result");
    let signatures = [&first, &second]
        .iter()
        .filter(|result| {
            result.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("signedTxXdr")
        })
        .count();
    assert_eq!(signatures, 1, "one batch fits");
    let refusal = match first.is_error {
        Some(true) => &first,
        _ => &second,
    };
    assert_eq!(refused(refusal).0, "policy.deny.per_period_cap_exceeded");
    assert_eq!(fx.usage("native"), (10 * i128::from(XLM), 1));
    assert_eq!(fx.reads(SOURCE), 3, "every call reads the signer set");
}

/// A window file an older build wrote keeps counting and admits a selected
/// leg. A file rolled back after the gate's read refuses that use before
/// the signer and keeps its bytes; another profile still signs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn selected_admission_preserves_legacy_state() {
    let rules = || pay_rule(vec![per_day(20 * i128::from(XLM))]);
    let mut fx = Fixture::new(rules()).await;
    let xdr = selected_six(&fx);
    signed(&fx.sign(xdr.clone()).await);
    let path = fx.server.window_store.path().to_owned();
    let rolled_back = std::fs::read(&path).unwrap();
    fx.server
        .window_store
        .write_earlier_build_for_test(&fx.profile)
        .unwrap();
    fx.restart(rules());
    signed(&fx.sign(xdr.clone()).await);
    assert_eq!(
        fx.usage("native"),
        (12 * i128::from(XLM), 2),
        "the older build's record keeps counting"
    );

    let seed_reads = fx.seed_reads();
    let (target, bytes) = (path.clone(), rolled_back.clone());
    fx.on_read(SOURCE, move || std::fs::write(target, bytes).unwrap());
    assert_eq!(refused(&fx.sign(xdr).await).0, "policy.engine_required");
    assert_eq!(fx.seed_reads(), seed_reads, "no seed read");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        rolled_back,
        "the store keeps its bytes"
    );
    assert_eq!(fx.rows("opaque_payload_signed").len(), 2);
    drop(fx);

    let fx = Fixture::new(rules()).await;
    signed(&fx.sign(selected_six(&fx)).await);
    assert_eq!(fx.usage("native"), (6 * i128::from(XLM), 1));
}

/// A crash after the window counter moves and before the window file is
/// written refuses the signature and admits nothing: the file keeps its
/// bytes, no seed is read, no row is written, and the generation gap stops
/// the next call.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn an_interrupted_admission_write_admits_nothing() {
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_SETTLED_AFTER_COUNTER, arm_accounting_fault,
    };
    let fx = Fixture::new(pay_rule(vec![per_day(15 * i128::from(XLM))])).await;
    let xdr = selected_six(&fx);
    signed(&fx.sign(xdr.clone()).await);
    let path = fx.server.window_store.path().to_owned();
    let before = std::fs::read(&path).unwrap();
    let seed_reads = fx.seed_reads();
    let fault = arm_accounting_fault(COMMIT_FAULT_SETTLED_AFTER_COUNTER);
    let result = fx.sign(xdr.clone()).await;
    drop(fault);
    assert_eq!(refused(&result).0, "policy.engine_required");
    assert_eq!(fx.seed_reads(), seed_reads, "no seed read");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the batch never reaches the file"
    );
    assert_eq!(fx.rows("opaque_payload_signed").len(), 1);
    assert_eq!(
        refused(&fx.sign(xdr).await).0,
        "policy.engine_required",
        "the generation gap stops the next call"
    );
    assert_eq!(fx.seed_reads(), seed_reads);
}
