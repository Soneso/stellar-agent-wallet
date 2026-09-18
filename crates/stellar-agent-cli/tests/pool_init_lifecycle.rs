//! Sponsored-pool recovery against loopback RPC and an isolated encrypted keyring.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration assertions"
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use serial_test::serial;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use stellar_agent_core::profile::{
    loader,
    receipt::{ReceiptStatus, ReceiptStore},
    schema::Profile,
};
use stellar_agent_headless_keyring::{crypto::ProtectionMode, store::HeadlessStore};
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, ledger_entries_result_for, send_transaction_hash_hex,
};
use stellar_xdr::{LedgerKey, Limits, ReadXdr, WriteXdr};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

const NAME: &str = "pool-lifecycle";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FUNDER_SEED: [u8; 32] = [17; 32];
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

struct State {
    home: PathBuf,
    fail_funder: bool,
    /// Refuses the transport on `sendTransaction`, so the endpoint accepts no
    /// submission and `send_count` does not move.
    refuse_send: bool,
    block_completion: bool,
    channels_exist: bool,
    /// Oldest ledger the endpoint still holds. Raising it past a submission's
    /// recorded ledger is what makes reconciliation record that submission's
    /// outcome as unknown.
    oldest_ledger: u32,
    next_status: &'static str,
    send_count: usize,
    sent: HashMap<String, &'static str>,
}

#[derive(Clone)]
struct Rpc(Arc<Mutex<State>>);
impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut state = self.0.lock().unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(PASSPHRASE),
            "getHealth" => {
                let oldest = state.oldest_ledger;
                json!({"status":"healthy","latestLedger":2000,"oldestLedger":oldest,
                    "ledgerRetentionWindow":2000 - oldest})
            }
            "getLedgers" => {
                let oldest = state.oldest_ledger;
                json!({"latestLedger":2000,"oldestLedger":oldest,"latestLedgerCloseTime":"100",
                    "oldestLedgerCloseTime":1,"cursor":"2000","ledgers":[]})
            }
            "getLedgerEntries" => {
                let mut accounts = Vec::new();
                for encoded in body["params"]["keys"].as_array().unwrap() {
                    if let LedgerKey::Account(key) =
                        LedgerKey::from_xdr_base64(encoded.as_str().unwrap(), Limits::none())
                            .unwrap()
                    {
                        let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = key.account_id.0;
                        let key = stellar_strkey::ed25519::PublicKey(key.0)
                            .to_string()
                            .as_str()
                            .to_owned();
                        if key == account_id_for_seed(FUNDER_SEED) {
                            if state.fail_funder {
                                return ResponseTemplate::new(503);
                            }
                            accounts.push(key);
                        } else if state.channels_exist {
                            accounts.push(key);
                        }
                    }
                }
                ledger_entries_result_for(&accounts.iter().map(String::as_str).collect::<Vec<_>>())
            }
            "sendTransaction" => {
                let hash = send_transaction_hash_hex(&body, PASSPHRASE);
                let checkpoint = profile(&state.home).pool_initialization.unwrap();
                assert!(
                    checkpoint.seed_ready,
                    "the seed must be durable before send"
                );
                let submission = checkpoint.submission.as_ref().unwrap();
                assert!(submission.send_started);
                assert_eq!(submission.tx_hash, hash);
                let persisted =
                    seed(&state.home).expect("the sent channels must have a persisted seed");
                let wallet = stellar_agent_sep5::Sep5Wallet::from_bip39_seed_zeroizing(
                    Zeroizing::new(persisted.try_into().unwrap()),
                );
                for channel in &checkpoint.channels {
                    assert_eq!(
                        wallet
                            .derive_account(channel.index)
                            .unwrap()
                            .public_key_strkey(),
                        channel.public_key
                    );
                }
                if state.refuse_send {
                    return ResponseTemplate::new(503);
                }
                let status = state.next_status;
                state.send_count += 1;
                state.sent.insert(hash.clone(), status);
                json!({"hash":hash,"status":"PENDING","latestLedger":1000,"latestLedgerCloseTime":"1700000000"})
            }
            "getTransaction" => {
                let hash = body["params"]["hash"].as_str().unwrap();
                let status = state.sent.get(hash).copied().unwrap_or("NOT_FOUND");
                if status == "SUCCESS" {
                    state.channels_exist = true;
                    if state.block_completion {
                        state.block_completion = false;
                        let path = state.home.join(format!("profiles/{NAME}.toml"));
                        std::fs::rename(&path, state.home.join("checkpoint.toml")).unwrap();
                        std::fs::create_dir(&path).unwrap();
                    }
                }
                let result = if status == "FAILED" {
                    Some(
                        stellar_xdr::TransactionResult {
                            fee_charged: 100,
                            result: stellar_xdr::TransactionResultResult::TxFailed(
                                vec![].try_into().unwrap(),
                            ),
                            ext: stellar_xdr::TransactionResultExt::V0,
                        }
                        .to_xdr_base64(Limits::none())
                        .unwrap(),
                    )
                } else {
                    None
                };
                json!({"status":status,"txHash":hash,"ledger":1001,"createdAt":"1700000001","resultXdr":result})
            }
            other => panic!("unexpected RPC {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc":"2.0","id":body["id"],"result":result}))
    }
}

fn cli(home: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value = serde_json::from_str(
        stdout
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&output.stderr))),
    )
    .unwrap();
    (output.status.code().unwrap(), value)
}

fn profile(home: &Path) -> Profile {
    loader::load_from_path(NAME, &home.join(format!("profiles/{NAME}.toml")), None).unwrap()
}

fn seed(home: &Path) -> Option<Vec<u8>> {
    keyring_core::set_default_store(Arc::new(HeadlessStore::new(
        home.join("headless-keyring/store.keyring"),
        ProtectionMode::EnvKey(Arc::new(Zeroizing::new(std::array::from_fn(|index| {
            index as u8
        })))),
    )));
    let p = profile(home);
    let key = p.pool_master_key_id.as_ref()?;
    let value = keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .get_password()
        .ok()?;
    Some(URL_SAFE_NO_PAD.decode(value).unwrap())
}

fn profile_path(home: &Path) -> PathBuf {
    home.join(format!("profiles/{NAME}.toml"))
}

fn receipts(home: &Path) -> ReceiptStore {
    ReceiptStore::open_at(&home.join("receipts"), NAME).unwrap()
}

fn receipt_status(home: &Path, envelope_hash: &str) -> ReceiptStatus {
    receipts(home)
        .get(envelope_hash)
        .unwrap()
        .expect("the submission must have a receipt")
        .status
}

/// Rewrites the durable send barrier to false, leaving the checkpoint a crash
/// between the receipt write and the barrier write produces: the submission
/// identity is on disk, its receipt exists, and nothing records that bytes may
/// have left.
fn clear_send_barrier(home: &Path) {
    let path = profile_path(home);
    let mut document: toml::Value =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).expect("the profile must parse");
    document["pool_initialization"]["submission"]["send_started"] = toml::Value::Boolean(false);
    std::fs::write(&path, toml::to_string_pretty(&document).unwrap()).unwrap();
}

fn event_count(home: &Path, kind: &str) -> usize {
    std::fs::read_to_string(profile(home).audit_log_path)
        .unwrap()
        .lines()
        .filter(|line| serde_json::from_str::<Value>(line).unwrap()["kind"] == kind)
        .count()
}

async fn fixture() -> (tempfile::TempDir, MockServer, Rpc) {
    let home = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let state = Rpc(Arc::new(Mutex::new(State {
        home: home.path().to_owned(),
        fail_funder: false,
        refuse_send: false,
        block_completion: false,
        channels_exist: false,
        oldest_ledger: 1,
        next_status: "SUCCESS",
        send_count: 0,
        sent: HashMap::new(),
    })));
    Mock::given(method("POST"))
        .respond_with(state.clone())
        .mount(&server)
        .await;
    let p = Profile::builder_testnet(
        "pool-test-signer",
        account_id_for_seed(FUNDER_SEED),
        "pool-test-nonce",
        "default",
    )
    .with_profile_name(NAME)
    .rpc_url(server.uri())
    .audit_log_path(home.path().join(format!("audit/{NAME}.jsonl")))
    .build();
    loader::save_to_dir(NAME, &p, &home.path().join("profiles")).unwrap();
    keyring_core::set_default_store(Arc::new(HeadlessStore::new(
        home.path().join("headless-keyring/store.keyring"),
        ProtectionMode::EnvKey(Arc::new(Zeroizing::new(std::array::from_fn(|index| {
            index as u8
        })))),
    )));
    keyring_core::Entry::new(&p.mcp_signer_default.service, &p.mcp_signer_default.account)
        .unwrap()
        .set_password(
            stellar_strkey::ed25519::PrivateKey(FUNDER_SEED)
                .as_unredacted()
                .to_string()
                .as_str(),
        )
        .unwrap();
    let (code, output) = cli(home.path(), &["profile", "rotate-audit-key", NAME]);
    assert_eq!(code, 0, "{output}");
    (home, server, state)
}

fn start(home: &Path) -> (i32, Value) {
    cli(
        home,
        &[
            "pool",
            "init",
            "--size",
            "2",
            "--timeout-seconds",
            "2",
            "--profile",
            NAME,
        ],
    )
}
fn resume(home: &Path) -> (i32, Value) {
    cli(
        home,
        &[
            "pool",
            "init",
            "--resume",
            "--timeout-seconds",
            "2",
            "--profile",
            NAME,
        ],
    )
}

/// A seed persisted ahead of a pre-send failure remains the source of every
/// channel key when a fresh process resumes and submits the sponsored creation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn interrupted_after_seed_write_resumes_with_the_persisted_seed() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().fail_funder = true;
    assert_eq!(start(home.path()).0, 1);
    let pending = profile(home.path()).pool_initialization.unwrap();
    assert!(pending.seed_ready);
    assert!(pending.submission.is_none());
    let before = seed(home.path());
    assert_eq!(rpc.0.lock().unwrap().send_count, 0);
    rpc.0.lock().unwrap().fail_funder = false;
    let (code, output) = resume(home.path());
    assert_eq!(
        code, 0,
        "completion must derive from the persisted seed: {output}"
    );
    let after = seed(home.path()).unwrap();
    assert_eq!(before.as_ref(), Some(&after));
    let wallet = stellar_agent_sep5::Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(
        after.try_into().unwrap(),
    ));
    for channel in &pending.channels {
        assert_eq!(
            wallet
                .derive_account(channel.index)
                .unwrap()
                .public_key_strkey(),
            channel.public_key
        );
    }
    assert_eq!(
        profile(home.path()).pool_config.unwrap().channels,
        pending.channels
    );
    assert!(profile(home.path()).pool_initialization.is_none());
    assert_eq!(rpc.0.lock().unwrap().send_count, 1);
    assert_eq!(event_count(home.path(), "channel_pool_initialised"), 1);
    assert_eq!(event_count(home.path(), "value_action_pending"), 1);
    assert_eq!(event_count(home.path(), "value_action_submitted"), 1);
}

/// An acknowledged chain success survives interrupted profile persistence;
/// completing it writes config and one event without transmitting again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn confirmed_initialization_finishes_without_a_second_send() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().block_completion = true;
    assert_eq!(start(home.path()).0, 1);
    let path = home.path().join(format!("profiles/{NAME}.toml"));
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(home.path().join("checkpoint.toml"), &path).unwrap();
    let checkpoint = profile(home.path()).pool_initialization.unwrap();
    let hash = checkpoint
        .submission
        .as_ref()
        .unwrap()
        .envelope_hash
        .clone();
    assert_eq!(
        ReceiptStore::open_at(&home.path().join("receipts"), NAME)
            .unwrap()
            .get(&hash)
            .unwrap()
            .unwrap()
            .status,
        ReceiptStatus::Success
    );
    assert!(profile(home.path()).pool_config.is_none());
    let before = seed(home.path());
    let (code, output) = resume(home.path());
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        profile(home.path()).pool_config.unwrap().channels,
        checkpoint.channels
    );
    assert_eq!(seed(home.path()), before);
    assert_eq!(rpc.0.lock().unwrap().send_count, 1);
    assert_eq!(event_count(home.path(), "channel_pool_initialised"), 1);
    assert_eq!(resume(home.path()).0, 0);
    assert_eq!(rpc.0.lock().unwrap().send_count, 1);
}

/// A pending seed cannot be replaced, even under an explicit force request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn force_refuses_a_pending_initialization() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().fail_funder = true;
    assert_eq!(start(home.path()).0, 1);
    let before = seed(home.path());
    let bytes = std::fs::read(home.path().join(format!("profiles/{NAME}.toml"))).unwrap();
    rpc.0.lock().unwrap().fail_funder = false;
    let (code, output) = cli(
        home.path(),
        &["pool", "init", "--size", "2", "--force", "--profile", NAME],
    );
    assert_eq!(code, 1, "{output}");
    assert!(
        output["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--resume")
    );
    assert_eq!(seed(home.path()), before);
    assert_eq!(
        std::fs::read(home.path().join(format!("profiles/{NAME}.toml"))).unwrap(),
        bytes
    );
    assert_eq!(rpc.0.lock().unwrap().send_count, 0);
}

/// A definitive failure with no channel accounts permits a fresh envelope for
/// the same sponsored creations and preserves the failed attempt's receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn failed_creation_retries_with_the_same_keys_and_a_distinct_receipt() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().next_status = "FAILED";
    assert_eq!(start(home.path()).0, 1);
    let checkpoint = profile(home.path()).pool_initialization.unwrap();
    let before = seed(home.path());
    rpc.0.lock().unwrap().next_status = "SUCCESS";
    let (code, output) = resume(home.path());
    assert_eq!(code, 0, "{output}");
    assert_eq!(rpc.0.lock().unwrap().send_count, 2);
    assert_eq!(seed(home.path()), before);
    assert_eq!(
        profile(home.path()).pool_config.unwrap().channels,
        checkpoint.channels
    );
    let records = ReceiptStore::open_at(&home.path().join("receipts"), NAME)
        .unwrap()
        .all()
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .any(|record| matches!(record.status, ReceiptStatus::Failed { .. }))
    );
    assert!(
        records
            .iter()
            .any(|record| record.status == ReceiptStatus::Success)
    );
}

/// A durable completion row closes the audit obligation exactly once, including
/// the checkpoint after config and audit persistence but before marker removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn completion_audit_is_not_duplicated_after_restart() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().block_completion = true;
    assert_eq!(start(home.path()).0, 1);
    let path = home.path().join(format!("profiles/{NAME}.toml"));
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(home.path().join("checkpoint.toml"), &path).unwrap();
    let mut checkpoint = profile(home.path()).pool_initialization.unwrap();
    assert_eq!(resume(home.path()).0, 0);
    checkpoint.completion_ledger = Some(2000);
    let mut doc: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc.as_table_mut().unwrap().insert(
        "pool_initialization".to_owned(),
        toml::Value::try_from(checkpoint).unwrap(),
    );
    std::fs::write(&path, toml::to_string_pretty(&doc).unwrap()).unwrap();
    let (code, output) = resume(home.path());
    assert_eq!(code, 0, "{output}");
    assert_eq!(event_count(home.path(), "channel_pool_initialised"), 1);
    assert_eq!(rpc.0.lock().unwrap().send_count, 1);
    assert!(profile(home.path()).pool_initialization.is_none());
}

/// A two-second confirmation deadline leaves a discoverable hash and an
/// unchanged unknown checkpoint. Transaction status and pool completion settle
/// it once the endpoint reports the channel accounts. The 360-second bound is
/// the test's own: it fails a run that stops making progress, which a
/// subprocess request carrying no deadline of its own would otherwise hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn timeout_status_is_pending_until_the_chain_reports_the_channels() {
    tokio::time::timeout(std::time::Duration::from_secs(360), async {
        let (home, _server, rpc) = fixture().await;
        rpc.0.lock().unwrap().next_status = "NOT_FOUND";
        let task_home = home.path().to_owned();
        let (code, output) = tokio::task::spawn_blocking(move || start(&task_home))
            .await
            .unwrap();
        assert_eq!(code, 1, "{output}");
        assert!(
            output["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not confirmed within 2s")
        );
        let pending = profile(home.path()).pool_initialization.unwrap();
        let submission = pending.submission.unwrap();
        let (code, status) = cli(home.path(), &["pool", "status", "--profile", NAME]);
        assert_eq!(code, 0, "{status}");
        assert_eq!(status["data"]["initialised"], false);
        assert_eq!(status["data"]["pending"]["tx_hash"], submission.tx_hash);
        assert!(
            status["data"]["pending"]["resume_with"]
                .as_str()
                .unwrap()
                .contains("--resume")
        );
        let bytes = std::fs::read(home.path().join(format!("profiles/{NAME}.toml"))).unwrap();
        let (code, status) = resume(home.path());
        assert_eq!(code, 0, "{status}");
        assert_eq!(status["data"]["pending"], true);
        assert_eq!(
            std::fs::read(home.path().join(format!("profiles/{NAME}.toml"))).unwrap(),
            bytes
        );
        assert_eq!(rpc.0.lock().unwrap().send_count, 1);
        rpc.0
            .lock()
            .unwrap()
            .sent
            .insert(submission.tx_hash.clone(), "SUCCESS");
        let (code, status) = cli(
            home.path(),
            &["tx", "status", &submission.tx_hash, "--profile", NAME],
        );
        assert_eq!(code, 0, "{status}");
        assert_eq!(status["data"]["record"]["status"], "success");
        let (code, result) = resume(home.path());
        assert_eq!(code, 0, "{result}");
        assert!(profile(home.path()).pool_initialization.is_none());
        assert_eq!(profile(home.path()).pool_config.unwrap().pool_size, 2);
        assert_eq!(rpc.0.lock().unwrap().send_count, 1);
    })
    .await
    .expect("pool timeout recovery must remain bounded");
}

/// A submission identity that is durable while its barrier is not proves that
/// the attempt never left. Resume retires that attempt's receipt, keeps the
/// channel keys, and sends the next attempt exactly once.
///
/// The endpoint refuses the transport for the first attempt, so it accepts no
/// submission; the barrier is then cleared on disk, which is the checkpoint a
/// crash between the receipt write and the barrier write leaves behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn unsent_attempt_is_retired_and_retried_with_one_send() {
    let (home, _server, rpc) = fixture().await;
    rpc.0.lock().unwrap().refuse_send = true;
    assert_eq!(start(home.path()).0, 1);
    assert_eq!(rpc.0.lock().unwrap().send_count, 0);

    let checkpoint = profile(home.path()).pool_initialization.unwrap();
    let unsent = checkpoint.submission.clone().unwrap();
    assert_eq!(checkpoint.attempt, 0);
    assert_eq!(
        receipt_status(home.path(), &unsent.envelope_hash),
        ReceiptStatus::Pending
    );
    assert_eq!(event_count(home.path(), "value_action_pending"), 1);

    clear_send_barrier(home.path());
    rpc.0.lock().unwrap().refuse_send = false;
    let (code, output) = resume(home.path());
    assert_eq!(code, 0, "{output}");

    assert_eq!(rpc.0.lock().unwrap().send_count, 1);
    assert_eq!(
        receipt_status(home.path(), &unsent.envelope_hash),
        ReceiptStatus::Failed {
            code: "submission.not_transmitted".to_owned()
        }
    );
    assert_eq!(event_count(home.path(), "value_action_failed"), 1);

    let records = receipts(home.path()).all().unwrap();
    assert_eq!(records.len(), 2);
    let sent = records
        .iter()
        .find(|record| record.envelope_hash != unsent.envelope_hash)
        .expect("the retry must carry its own receipt");
    assert_eq!(sent.status, ReceiptStatus::Success);

    assert_eq!(
        profile(home.path()).pool_config.unwrap().channels,
        checkpoint.channels
    );
    assert!(profile(home.path()).pool_initialization.is_none());
    assert_eq!(event_count(home.path(), "channel_pool_initialised"), 1);
}

/// An attempt the endpoint can no longer account for settles as ambiguous, and
/// resume holds there: that is the state where a second envelope could create
/// the channels twice. `pool status` names the acknowledgement that releases
/// it, and only after `tx receipt clear --acknowledge` does resume retry, with
/// the same channel keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn ambiguous_attempt_is_retried_only_after_an_operator_clears_it() {
    tokio::time::timeout(std::time::Duration::from_secs(360), async {
        let (home, _server, rpc) = fixture().await;
        rpc.0.lock().unwrap().next_status = "NOT_FOUND";
        let task_home = home.path().to_owned();
        let (code, output) = tokio::task::spawn_blocking(move || start(&task_home))
            .await
            .unwrap();
        assert_eq!(code, 1, "{output}");
        let checkpoint = profile(home.path()).pool_initialization.unwrap();
        let submission = checkpoint.submission.clone().unwrap();
        assert_eq!(rpc.0.lock().unwrap().send_count, 1);

        // Retention moves past the submission's ledger, so the endpoint's
        // NOT_FOUND carries no information and reconciliation can only record
        // the outcome as unknown.
        rpc.0.lock().unwrap().oldest_ledger = 500;
        let (code, status) = cli(
            home.path(),
            &["tx", "status", &submission.tx_hash, "--profile", NAME],
        );
        assert_eq!(code, 0, "{status}");
        assert_eq!(
            receipt_status(home.path(), &submission.envelope_hash),
            ReceiptStatus::Ambiguous
        );

        let (code, status) = cli(home.path(), &["pool", "status", "--profile", NAME]);
        assert_eq!(code, 0, "{status}");
        let clear_with = status["data"]["pending"]["clear_with"]
            .as_str()
            .expect("an ambiguous receipt must name its acknowledgement command");
        assert!(clear_with.contains("tx receipt clear"), "{clear_with}");
        assert!(
            clear_with.contains(&submission.envelope_hash),
            "{clear_with}"
        );
        assert!(clear_with.contains("--acknowledge"), "{clear_with}");

        // An ambiguous receipt on its own is not the operator's statement: it
        // changes nothing and sends nothing.
        let before = std::fs::read(profile_path(home.path())).unwrap();
        let (code, held) = resume(home.path());
        assert_eq!(code, 0, "{held}");
        assert_eq!(held["data"]["pending"], true);
        assert_eq!(std::fs::read(profile_path(home.path())).unwrap(), before);
        assert_eq!(rpc.0.lock().unwrap().send_count, 1);
        assert_eq!(
            receipt_status(home.path(), &submission.envelope_hash),
            ReceiptStatus::Ambiguous
        );

        let (code, cleared) = cli(
            home.path(),
            &[
                "tx",
                "receipt",
                "clear",
                &submission.envelope_hash,
                "--acknowledge",
                "--profile",
                NAME,
            ],
        );
        assert_eq!(code, 0, "{cleared}");
        assert_eq!(
            receipt_status(home.path(), &submission.envelope_hash),
            ReceiptStatus::ClearedByOperator
        );

        rpc.0.lock().unwrap().next_status = "SUCCESS";
        let (code, output) = resume(home.path());
        assert_eq!(code, 0, "{output}");
        assert_eq!(rpc.0.lock().unwrap().send_count, 2);
        assert_eq!(
            profile(home.path()).pool_config.unwrap().channels,
            checkpoint.channels
        );
        assert!(profile(home.path()).pool_initialization.is_none());
        assert_eq!(event_count(home.path(), "channel_pool_initialised"), 1);
    })
    .await
    .expect("operator-acknowledged recovery must remain bounded");
}
