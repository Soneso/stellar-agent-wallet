//! A mocked Stellar RPC endpoint for the command tests, answering by JSON-RPC
//! method, the observations the endpoint tests make, and the zero-config setup
//! those tests run under.
//!
//! The endpoint reports one network passphrase, which a test can change
//! between calls. It answers `getLedgerEntries` for the accounts and the
//! extra ledger entries it was given, quotes fixed fee statistics, accepts
//! every send with the hash of the transaction it was handed, and confirms
//! every transaction. `getHealth` and `getLedgers` describe a ledger range
//! that covers every submission the tests make.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture; a malformed request panics the calling test"
)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::loader::ProfileLoadError;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_test_support::signed_envelope::{get_network_result, send_transaction_hash_hex};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The native balance every account the endpoint reports holds: 10 000 XLM.
const ACCOUNT_BALANCE_STROOPS: i64 = 100_000_000_000;

/// The sequence number of every account [`ClassicRpc::testnet`] reports. An
/// oracle fixture that agrees with such a primary builds its account entry
/// with [`account_xdr`] at this sequence.
pub(crate) const ACCOUNT_SEQUENCE: i64 = 100;

/// A mocked endpoint for the classic value verbs.
#[derive(Clone)]
pub(crate) struct ClassicRpc {
    network: Arc<Mutex<String>>,
    /// `(ledger key XDR, entry XDR)` per answerable ledger entry.
    entries: Arc<Vec<(String, String)>>,
}

impl ClassicRpc {
    /// An endpoint reporting testnet and answering for each of `accounts`,
    /// funded and signed by its own master key.
    pub(crate) fn testnet(accounts: &[&str]) -> Self {
        Self {
            network: Arc::new(Mutex::new(TESTNET_PASSPHRASE.to_owned())),
            entries: Arc::new(
                accounts
                    .iter()
                    .map(|account| {
                        (
                            account_ledger_key_xdr(account),
                            account_entry_xdr_with_seq(
                                account,
                                ACCOUNT_BALANCE_STROOPS,
                                0,
                                ACCOUNT_SEQUENCE,
                            ),
                        )
                    })
                    .collect(),
            ),
        }
    }

    /// Answers `getLedgerEntries` for `key` with `entry` as well.
    pub(crate) fn with_entry(mut self, key: String, entry: String) -> Self {
        Arc::make_mut(&mut self.entries).push((key, entry));
        self
    }

    /// Reports `passphrase` from every later `getNetwork`.
    pub(crate) fn report(&self, passphrase: &str) {
        *self.network.lock().unwrap() = passphrase.to_owned();
    }

    /// Starts a server answering every `POST` with this endpoint.
    pub(crate) async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }

    fn ledger_entries(&self, body: &Value) -> Value {
        let requested: Vec<&str> = body["params"]["keys"]
            .as_array()
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let entries: Vec<Value> = self
            .entries
            .iter()
            .filter(|(key, _)| requested.contains(&key.as_str()))
            .map(|(key, entry)| json!({ "key": key, "xdr": entry, "lastModifiedLedgerSeq": 1000 }))
            .collect();
        json!({ "entries": entries, "latestLedger": 1001 })
    }
}

impl Respond for ClassicRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fees = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        let result = match body["method"].as_str().unwrap_or_default() {
            "getNetwork" => get_network_result(&self.network.lock().unwrap()),
            "getLedgerEntries" => self.ledger_entries(&body),
            "getFeeStats" => json!({
                "sorobanInclusionFee": fees, "inclusionFee": fees, "latestLedger": 1001
            }),
            "sendTransaction" => json!({
                "hash": send_transaction_hash_hex(&body, TESTNET_PASSPHRASE),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1700000000"
            }),
            "getTransaction" => json!({
                "status": "SUCCESS",
                "txHash": body["params"]["hash"],
                "ledger": 1005,
                "createdAt": "1700000005",
                "latestLedger": 1006,
                "oldestLedger": 1
            }),
            "getHealth" => json!({
                "status": "healthy",
                "latestLedger": 2000,
                "oldestLedger": 1,
                "ledgerRetentionWindow": 1999
            }),
            "getLedgers" => json!({
                "latestLedger": 2000,
                "oldestLedger": 1,
                "latestLedgerCloseTime": "1700000100",
                "oldestLedgerCloseTime": "1",
                "cursor": "2000",
                "ledgers": []
            }),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({ "jsonrpc": "2.0", "id": body["id"], "result": result }))
    }
}

/// The JSON-RPC methods `server` received, in order.
pub(crate) async fn methods(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// How many `getNetwork` requests `methods` holds.
pub(crate) fn network_checks(methods: &[String]) -> usize {
    methods
        .iter()
        .filter(|m| m.as_str() == "getNetwork")
        .count()
}

/// Runs `call` and returns its output with the number of `StellarRpcClient`
/// values it built.
///
/// The command tests run on a current-thread runtime, so every client the
/// call builds is built on the test's thread and counted here.
pub(crate) async fn clients_built_by<F: Future>(call: F) -> (F::Output, usize) {
    let before = stellar_agent_network::client::constructions_on_this_thread();
    let output = call.await;
    let built = stellar_agent_network::client::constructions_on_this_thread() - before;
    (output, built)
}

/// Isolation every zero-config run needs, as one value.
///
/// The synthesized profile is named by the resolved name, which with no flag
/// and no variable is the literal `default`. Its audit log path and its audit
/// chain-root keyring coordinate are therefore the real `default` profile's.
/// Without this value a test would read and write the operator's own audit
/// log. On a host where `stellar-agent-audit-default` exists, it would also
/// acquire a writer instead of exercising the fail-open branch.
///
/// Bundles the redirected data root, the in-memory keyring store, and a
/// cleared `STELLAR_AGENT_PROFILE`. The resolver reads the ambient
/// environment, so an exported value would make the name explicit and the run
/// refuse. Callers are `#[serial]`: all three are process-global.
pub(crate) struct ZeroConfig {
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _profile_var: stellar_agent_test_support::ProfileEnvVarGuard,
    _dir: tempfile::TempDir,
}

/// Sets up the isolation of [`ZeroConfig`] for the lifetime of the value.
pub(crate) fn zero_config() -> ZeroConfig {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
    let profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
    stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
    ZeroConfig {
        _home: home,
        _profile_var: profile_var,
        _dir: dir,
    }
}

/// An injected loader reporting that the profile file does not exist.
///
/// Whether that becomes a synthesized profile or a refusal is decided by the
/// caller of the injected closure, keyed on the resolved name's provenance.
pub(crate) fn absent_profile_file(name: &str) -> Result<Profile, ProfileLoadError> {
    Err(ProfileLoadError::NotFound {
        name: name.to_owned(),
        path: std::path::PathBuf::from("/nonexistent"),
    })
}

/// The signer of a zero-config run: the account of `seed`, whose secret sits
/// in the environment variable `var` for the lifetime of the value.
pub(crate) struct EnvSigner {
    /// The signer's G-strkey.
    pub(crate) g: String,
    /// The environment variable that holds the signer's S-strkey.
    pub(crate) var: &'static str,
}

impl EnvSigner {
    /// Puts the secret of `seed` into `var`. The variable name is unique to
    /// its test, and the caller is `#[serial]`.
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; serialised by #[serial]"
    )]
    pub(crate) fn new(seed: [u8; 32], var: &'static str) -> Self {
        let secret = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        // SAFETY: serialised by #[serial]; the variable name is unique to its
        // test.
        unsafe {
            std::env::set_var(var, secret);
        }
        Self {
            g: stellar_agent_test_support::signed_envelope::account_id_for_seed(seed),
            var,
        }
    }
}

impl Drop for EnvSigner {
    #[allow(unsafe_code, reason = "test-only env cleanup")]
    fn drop(&mut self) {
        // SAFETY: same as `new`.
        unsafe {
            std::env::remove_var(self.var);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-check witness fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// A testnet profile named `name`, reading through `primary` and witnessing
/// through `oracle`.
///
/// The audit log lives in `audit_dir`, and the profile's audit chain-root key
/// is minted in the mock keyring [`zero_config`] installed, so a stage
/// acquires its audit writer and records its pending and submitted rows. The
/// audit writer registry is process-wide and keyed by profile name, so each
/// test names its own profile.
pub(crate) fn witness_profile(
    name: &str,
    primary: &str,
    oracle: Option<&str>,
    audit_dir: &std::path::Path,
) -> Profile {
    let profile = Profile::builder_testnet_named(
        name,
        "stellar-agent-signer",
        name,
        "stellar-agent-nonce",
        name,
    )
    .policy_engine(stellar_agent_core::profile::schema::PolicyEngineKind::Noop)
    .wallet({
        let mut wallet = stellar_agent_core::profile::schema::WalletConfig::default();
        wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
        wallet.unlock_ttl_seconds = stellar_agent_core::wallet::DEFAULT_TTL_SECONDS;
        wallet
    })
    .rpc_url(primary)
    .oracle_provider_url(oracle.map(|url| url::Url::parse(url).unwrap()))
    .audit_log_path(audit_dir.join("audit.jsonl"))
    .build();
    stellar_agent_network::keyring::rotate_keyring_secret_32(
        &profile.audit_log_hash_chain_key_id.service,
        &profile.audit_log_hash_chain_key_id.account,
    )
    .unwrap();
    profile
}

/// The audit rows of `kind` in `profile`'s audit log.
pub(crate) fn audit_rows(profile: &Profile, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(&profile.audit_log_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["kind"] == kind)
        .collect()
}

/// Asserts that the pending and submitted rows each carry the witness of
/// `oracle` at the fixture ledger.
pub(crate) fn assert_rows_carry_witness(profile: &Profile, oracle: &str) {
    let pending = audit_rows(profile, "value_action_pending");
    let submitted = audit_rows(profile, "value_action_submitted");
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(submitted.len(), 1, "{submitted:?}");
    for row in [&pending[0], &submitted[0]] {
        assert_eq!(row["witness"]["provider"], oracle, "{row}");
        assert_eq!(row["witness"]["ledger"], 1001, "{row}");
        assert_eq!(row["witness"]["inputs_digest"].as_str().unwrap().len(), 64);
    }
    assert_eq!(pending[0]["witness"], submitted[0]["witness"]);
}

/// The envelope a command printed last on this thread.
pub(crate) fn last_rendered() -> Value {
    crate::common::render::take_rendered_for_test()
        .pop()
        .expect("the command printed an envelope")
}

/// Account entry XDR with the fields a witness compares set explicitly.
pub(crate) fn account_xdr(account: &str, seq: i64, flags: u32, home_domain: &str) -> String {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, Thresholds, Uint256, WriteXdr,
    };
    let pk = stellar_strkey::ed25519::PublicKey::from_string(account).unwrap();
    LedgerEntryData::Account(AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))),
        balance: ACCOUNT_BALANCE_STROOPS,
        seq_num: SequenceNumber(seq),
        num_sub_entries: 0,
        inflation_dest: None,
        flags,
        home_domain: home_domain.as_bytes().to_vec().try_into().unwrap(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![].try_into().unwrap(),
        ext: AccountEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// The ledger key of `account`'s account entry.
pub(crate) fn account_key(account: &str) -> String {
    account_ledger_key_xdr(account)
}

/// Trustline `(key, entry)` XDR of `account` for `code:issuer`.
pub(crate) fn trustline_xdr(
    account: &str,
    code: &str,
    issuer: &str,
    balance: i64,
    limit: i64,
    flags: u32,
) -> (String, String) {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerEntryData, LedgerKey, LedgerKeyTrustLine, Limits,
        PublicKey, TrustLineAsset, TrustLineEntry, TrustLineEntryExt, Uint256, WriteXdr,
    };
    let id = |g: &str| {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            stellar_strkey::ed25519::PublicKey::from_string(g)
                .unwrap()
                .0,
        )))
    };
    let mut bytes = [0u8; 4];
    bytes[..code.len()].copy_from_slice(code.as_bytes());
    let asset = TrustLineAsset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(bytes),
        issuer: id(issuer),
    });
    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: id(account),
        asset: asset.clone(),
    });
    let entry = LedgerEntryData::Trustline(TrustLineEntry {
        account_id: id(account),
        asset,
        balance,
        limit,
        flags,
        ext: TrustLineEntryExt::V0,
    });
    (
        key.to_xdr_base64(Limits::none()).unwrap(),
        entry.to_xdr_base64(Limits::none()).unwrap(),
    )
}

/// The `config.memo_required = "1"` data entry `(key, entry)` of `account`.
pub(crate) fn memo_required_xdr(account: &str) -> (String, String) {
    use stellar_xdr::{
        AccountId, DataEntry, DataEntryExt, LedgerEntryData, LedgerKey, LedgerKeyData, Limits,
        PublicKey, String64, StringM, Uint256, WriteXdr,
    };
    let id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        stellar_strkey::ed25519::PublicKey::from_string(account)
            .unwrap()
            .0,
    )));
    let name: String64 = StringM::<64>::try_from(b"config.memo_required".to_vec())
        .unwrap()
        .into();
    let key = LedgerKey::Data(LedgerKeyData {
        account_id: id.clone(),
        data_name: name.clone(),
    });
    let entry = LedgerEntryData::Data(DataEntry {
        account_id: id,
        data_name: name,
        data_value: b"1".to_vec().try_into().unwrap(),
        ext: DataEntryExt::V0,
    });
    (
        key.to_xdr_base64(Limits::none()).unwrap(),
        entry.to_xdr_base64(Limits::none()).unwrap(),
    )
}

/// A threshold table holding `threshold` base units for `asset`.
pub(crate) fn thresholds(
    asset: &str,
    threshold: i128,
) -> stellar_agent_core::cross_check::CrossCheckThresholds {
    stellar_agent_core::cross_check::CrossCheckThresholds::new(
        [(
            stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(asset).unwrap(),
            threshold,
        )]
        .into_iter()
        .collect(),
    )
    .unwrap()
}

/// Mounts, ahead of `server`'s other answers, an HTTP 503 for a
/// `getLedgerEntries` request whose only key is `key`.
pub(crate) async fn fail_read_of(server: &MockServer, key: &str) {
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getLedgerEntries", "params": {"keys": [key]}
        })))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(1)
        .mount(server)
        .await;
}

/// The credential [`credential_primary`] configures for the primary endpoint.
pub(crate) const PRIMARY_CREDENTIAL: &str = "Bearer cli-rpc-credential-0123456789";

/// The part of [`PRIMARY_CREDENTIAL`] that names the secret.
pub(crate) const PRIMARY_CREDENTIAL_TOKEN: &str = "cli-rpc-credential-0123456789";

/// Names a keyring credential with a header placement for `profile`'s primary
/// endpoint and stores [`PRIMARY_CREDENTIAL`] there in the installed mock
/// keyring store.
pub(crate) fn credential_primary(profile: &mut Profile) {
    use stellar_agent_core::profile::schema::{
        KeyringEntryRef, PrimaryProviderRecord, Providers, RpcCredentialPlacement,
    };
    let entry = KeyringEntryRef::new("stellar-agent-rpc-cli-test", "primary");
    profile
        .providers
        .get_or_insert_with(Providers::default)
        .primary = Some(
        PrimaryProviderRecord::new("Primary RPC", "127.0.0.1").with_credential(
            entry.clone(),
            RpcCredentialPlacement::Header {
                name: "X-API-Key".to_owned(),
            },
        ),
    );
    keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .set_password(PRIMARY_CREDENTIAL)
        .unwrap();
}

/// Answers with a JSON-RPC error object whose `message` is the given server
/// text, under the request's own id.
struct RpcErrorText(String);

impl Respond for RpcErrorText {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let id = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|body| body.get("id").cloned())
            .unwrap_or_else(|| json!(1));
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32000, "message": self.0},
        }))
    }
}

/// Mounts, ahead of `server`'s other answers, a JSON-RPC error object whose
/// `message` is `text` for a `getLedgerEntries` request whose only key is
/// `key`.
pub(crate) async fn fail_read_of_with_text(server: &MockServer, key: &str, text: String) {
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getLedgerEntries", "params": {"keys": [key]}
        })))
        .respond_with(RpcErrorText(text))
        .with_priority(1)
        .mount(server)
        .await;
}

/// The profile name a witness test derives from its signer's variable.
pub(crate) fn profile_name_for(signer: &EnvSigner) -> String {
    signer.var.to_ascii_lowercase().replace('_', "-")
}

/// How many signing keys a call resolved, with its output.
pub(crate) async fn signers_resolved_by<F: Future>(call: F) -> (F::Output, usize) {
    let before = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
    let output = call.await;
    let resolved = crate::common::signer_ceremony::signer_resolutions_on_this_thread() - before;
    (output, resolved)
}

/// Whether `server` received a `sendTransaction`.
pub(crate) async fn sent(server: &MockServer) -> bool {
    methods(server).await.iter().any(|m| m == "sendTransaction")
}
