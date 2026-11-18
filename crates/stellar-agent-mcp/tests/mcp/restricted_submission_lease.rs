//! A restricted authorization's toolset lease through authorized submission.
//!
//! The authorization holds a real runtime lease. Grant insertion, grant
//! revocation, and an install's exclusive root lock each meet their busy
//! refusal, with the grant store and installation bytes unchanged, after the
//! recorder consumes the authorization, during the send, and while the outcome
//! is reported. Each succeeds once submission returns.

#![cfg(feature = "mainnet-write")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test assertions"
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::approval::{ApprovalError, AttestationBinding, ToolsetGrantStore};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_agent_network::mainnet::consumed::AuthorizationConsumed;
use stellar_agent_network::mainnet::restriction::ToolsetRestriction;
use stellar_agent_network::mainnet::test_support::{AuthorizedSubmissionFixture, FixtureEnvelope};
use stellar_agent_network::{
    MainnetSubmitGrant, StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, submit_authorized_transaction_and_wait,
};
use stellar_agent_test_support::SubmissionEchoResponder;
use stellar_agent_test_support::signed_envelope::get_network_result;
use stellar_agent_toolsets_install::{ToolsetInstallError, lock_toolsets};
use stellar_agent_toolsets_runtime::{
    GatedInvokeParams, GatedResolveOutcome, GrantRecheckParams, ToolsetRuntimeError,
    acquire_toolset_grant_lease, record_first_invoke_grant, resolve_toolset_sign_payment_gated,
};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const NOW: u64 = 1_800_000_000_000;
const TIMEOUT: Duration = Duration::from_secs(10);
const PROFILE: &str = "operator";
const CHAIN: &str = "stellar:pubnet";
const TOOLSET: &str = "pay-toolset";
const ACTION: &str = "stellar_pay_commit";
const INSTALL_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: [u8; 32] = [0x42; 32];
const UID: &str = "1000";
const DESTINATION: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const OTHER_DESTINATION: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Busy refusals of grant insertion, revocation, and install, then whether the
/// grant store and installation bytes are unchanged.
type Observed = [bool; 4];

/// The toolset writers, tried at each stage of the submission.
struct Writers {
    root: PathBuf,
    grants: PathBuf,
    before: Vec<Vec<u8>>,
    seen: Mutex<Vec<(&'static str, Observed)>>,
}

impl Writers {
    fn bytes(&self) -> Vec<Vec<u8>> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.root.join(TOOLSET))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        files.sort();
        files.push(self.grants.clone());
        files
            .iter()
            .map(|file| std::fs::read(file).unwrap())
            .collect()
    }

    fn record_grant(&self, destination: &str) -> Result<(), ToolsetRuntimeError> {
        record_first_invoke_grant(
            PROFILE,
            TOOLSET,
            INSTALL_ID,
            "1.0.0",
            &"0".repeat(64),
            "sign-payment",
            destination,
            "XLM",
            0,
            10,
            UID,
            now_ms(),
            &KEY,
            &AttestationBinding::new(PROFILE, CHAIN),
            Some(self.grants.clone()),
        )
        .map(drop)
    }

    fn revoke(&self) -> Result<usize, ApprovalError> {
        ToolsetGrantStore::open(self.grants.clone(), now_ms())
            .and_then(|mut store| store.revoke_toolset(TOOLSET))
    }

    /// Tries each writer once and records what it met at `stage`.
    fn attempt(&self, stage: &'static str) {
        let insert = matches!(
            self.record_grant(OTHER_DESTINATION),
            Err(ToolsetRuntimeError::CoordinationBusy)
        );
        let revoke = matches!(self.revoke(), Err(ApprovalError::WriterLocked));
        let install = matches!(lock_toolsets(&self.root), Err(ToolsetInstallError::Busy));
        let unchanged = self.bytes() == self.before;
        self.seen
            .lock()
            .unwrap()
            .push((stage, [insert, revoke, install, unchanged]));
    }
}

fn now_ms() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap()
}

/// The wallet recorder, trying the writers after a successful consumption and
/// while the outcome is reported.
struct ProbingRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    writers: Arc<Writers>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for ProbingRecorder<'_> {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        let consumed = self.inner.pre_send_authorized(intent, grant).await?;
        self.writers.attempt("consumed");
        Ok(consumed)
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.writers.attempt("outcome");
        self.inner.outcome(intent, outcome).await;
    }
}

/// Answers as [`SubmissionEchoResponder`], trying the writers on the send.
struct ProbingSend {
    inner: SubmissionEchoResponder,
    writers: Arc<Writers>,
}

impl Respond for ProbingSend {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.writers.attempt("send");
        self.inner.respond(request)
    }
}

/// A mock mainnet endpoint for `envelope` that accepts the send and reports
/// success, trying the writers on the send, and a client of it.
async fn endpoint(
    envelope: &FixtureEnvelope,
    writers: &Arc<Writers>,
) -> (MockServer, StellarRpcClient) {
    let server = MockServer::start().await;
    let send = json!({
        "hash": envelope.signed.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 1000,
        "latestLedgerCloseTime": "1699999999"
    });
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "sendTransaction" })))
        .respond_with(ProbingSend {
            inner: SubmissionEchoResponder::new(send, MAINNET_PASSPHRASE),
            writers: Arc::clone(writers),
        })
        .mount(&server)
        .await;
    for (rpc_method, result) in [
        ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
        ("getLedgerEntries", envelope.signed.ledger_entries_result()),
        (
            "getTransaction",
            json!({
                "status": "SUCCESS",
                "txHash": envelope.signed.tx_hash_hex(),
                "ledger": 4567,
                "createdAt": "1700000000",
                "envelopeXdr": null,
                "resultXdr": null,
                "resultMetaXdr": null
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({ "method": rpc_method })))
            .respond_with(SubmissionEchoResponder::new(result, MAINNET_PASSPHRASE))
            .mount(&server)
            .await;
    }
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    (server, client)
}

/// Installs the toolset, records its grant, and takes a real lease on it.
fn leased_restriction(root: &Path, grants: &Path) -> ToolsetRestriction {
    let pin_key = crate::common::toolset_pin_key();
    drop(lock_toolsets(root).unwrap());
    stellar_agent_toolsets_install::write_toolset_for_test(
        root,
        TOOLSET,
        &["sign-payment"],
        &[],
        "2026-06-02T00:00:00Z",
        INSTALL_ID,
        &pin_key,
    )
    .unwrap();
    let binding = AttestationBinding::new(PROFILE, CHAIN);
    record_first_invoke_grant(
        PROFILE,
        TOOLSET,
        INSTALL_ID,
        "1.0.0",
        &"0".repeat(64),
        "sign-payment",
        DESTINATION,
        "XLM",
        0,
        10,
        UID,
        now_ms(),
        &KEY,
        &binding,
        Some(grants.to_path_buf()),
    )
    .unwrap();
    let params = GatedInvokeParams {
        toolset_name: TOOLSET,
        action: ACTION,
        toolsets_root: root,
        profile_name: PROFILE,
        attestation_key: &KEY,
        attestation_binding: &binding,
        authoritative_destination: DESTINATION,
        authoritative_asset: "XLM",
        authoritative_amount_stroops: 10,
        now_unix_ms: now_ms(),
        process_uid: UID,
        pin_key: Some(&pin_key),
        approval_dir_override: Some(root.join("approvals")),
        grant_store_path_override: Some(grants.to_path_buf()),
    };
    let GatedResolveOutcome::Resolved { grant, .. } =
        resolve_toolset_sign_payment_gated(&params).unwrap()
    else {
        panic!("the recorded grant covers the invocation")
    };
    let recheck = GrantRecheckParams {
        toolset_name: TOOLSET,
        action: ACTION,
        toolsets_root: root,
        profile_name: PROFILE,
        attestation_key: &KEY,
        attestation_binding: &binding,
        authoritative_destination: DESTINATION,
        authoritative_asset: "XLM",
        authoritative_amount_stroops: 10,
        pin_key: Some(&pin_key),
        grant_store_path_override: Some(grants.to_path_buf()),
    };
    let lease = acquire_toolset_grant_lease(&grant, &recheck).unwrap();
    ToolsetRestriction::new(Box::new(lease))
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn restricted_submission_holds_the_lease_until_it_returns() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let toolsets = tempfile::TempDir::new().unwrap();
    let root = toolsets.path().join("toolsets");
    let grants = toolsets.path().join("grants.toml");
    let restriction = leased_restriction(&root, &grants);
    let mut writers = Writers {
        root,
        grants,
        before: Vec::new(),
        seen: Mutex::new(Vec::new()),
    };
    writers.before = writers.bytes();
    let writers = Arc::new(writers);

    let fx = AuthorizedSubmissionFixture::new("restricted-lease", NOW);
    let envelope = fx.envelope(10, NOW / 1000 + 30 * 86_400);
    let (server, client) = endpoint(&envelope, &writers).await;
    let (id, grant) = fx.restricted_grant(&envelope, &client, "approval-restricted", restriction);
    writers.attempt("minted");
    let recorder = ProbingRecorder {
        inner: fx.recorder(None, fx.writer()),
        writers: Arc::clone(&writers),
    };

    let result = submit_authorized_transaction_and_wait(
        &client,
        None,
        envelope.signed.envelope_xdr(),
        TIMEOUT,
        MAINNET_PASSPHRASE,
        None,
        &recorder,
        stellar_agent_network::mainnet::MainnetConsumer::CliPay,
        grant,
    )
    .await;

    result.expect("the restricted submission succeeds");
    assert!(!fx.is_open(id), "the authorization is used");
    let sends = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                == "sendTransaction"
        })
        .count();
    assert_eq!(sends, 1, "one send");
    let held = [true; 4];
    assert_eq!(
        *writers.seen.lock().unwrap(),
        [
            ("minted", held),
            ("consumed", held),
            ("send", held),
            ("outcome", held)
        ],
        "the lease holds off every writer, with unchanged bytes, until submission returns"
    );

    writers
        .record_grant(OTHER_DESTINATION)
        .expect("grant insertion succeeds after submission returns");
    assert_eq!(
        writers
            .revoke()
            .expect("revocation succeeds after submission returns"),
        2,
        "both grants are revoked"
    );
    drop(lock_toolsets(&writers.root).expect("an install locks the root after submission returns"));
}

/// Queues an unattested payment approval in `approvals` and returns its nonce.
fn queued_approval(approvals: &Path) -> String {
    let entry = stellar_agent_core::approval::PendingApproval::new_payment_pending(
        "b64xdr".to_owned(),
        b"restricted-envelope",
        DESTINATION.to_owned(),
        10,
        "XLM".to_owned(),
        None,
        100,
        7,
        UID.to_owned(),
        600_000,
    )
    .unwrap();
    let nonce = entry.approval_nonce.clone();
    let created = entry.created_at_unix_ms;
    stellar_agent_core::approval::PendingApprovalStore::open(
        approvals.join(format!("{PROFILE}.toml")),
    )
    .unwrap()
    .insert(entry, created)
    .unwrap();
    nonce
}

/// Whether the approval `nonce` in `approvals` is consumed on disk.
fn consumed(approvals: &Path, nonce: &str) -> bool {
    stellar_agent_core::approval::PendingApprovalStore::open(
        approvals.join(format!("{PROFILE}.toml")),
    )
    .unwrap()
    .get(nonce)
    .is_some_and(|entry| {
        matches!(
            entry.kind,
            stellar_agent_core::approval::ApprovalKind::Consumed { .. }
        )
    })
}

/// The wallet recorder of an approved restricted submission, reading the
/// approval on disk after the outcome is reported, while the lease holds.
struct ApprovalRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    approvals: PathBuf,
    nonce: String,
    at_outcome: Mutex<Vec<bool>>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for ApprovalRecorder<'_> {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.inner.pre_send_authorized(intent, grant).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.inner.outcome(intent, outcome).await;
        self.at_outcome
            .lock()
            .unwrap()
            .push(consumed(&self.approvals, &self.nonce));
    }
}

/// Submits a restricted payment under a real lease on the grant in `root`
/// and `grants`, spending the approval `nonce` in `approvals` as the MCP
/// commit's deferring recorder does, and returns the recorder.
async fn restricted_approved_submission<'a>(
    fx: &'a AuthorizedSubmissionFixture,
    root: &Path,
    grants: &Path,
    approvals: &Path,
    nonce: &str,
) -> ApprovalRecorder<'a> {
    let restriction = leased_restriction(root, grants);
    let mut writers = Writers {
        root: root.to_path_buf(),
        grants: grants.to_path_buf(),
        before: Vec::new(),
        seen: Mutex::new(Vec::new()),
    };
    writers.before = writers.bytes();
    let writers = Arc::new(writers);
    let envelope = fx.envelope(10, NOW / 1000 + 30 * 86_400);
    let (_server, client) = endpoint(&envelope, &writers).await;
    let (_, grant) = fx.restricted_grant(&envelope, &client, "approval-spent", restriction);
    let recorder = ApprovalRecorder {
        inner: fx
            .recorder(None, fx.writer())
            .with_approval(Some(stellar_agent_network::ApprovalTombstone {
                store_dir: approvals.to_path_buf(),
                profile_name: PROFILE.to_owned(),
                approval_nonce: nonce.to_owned(),
            }))
            .with_deferred_approval(true),
        approvals: approvals.to_path_buf(),
        nonce: nonce.to_owned(),
        at_outcome: Mutex::new(Vec::new()),
    };
    submit_authorized_transaction_and_wait(
        &client,
        None,
        envelope.signed.envelope_xdr(),
        TIMEOUT,
        MAINNET_PASSPHRASE,
        None,
        &recorder,
        stellar_agent_network::mainnet::MainnetConsumer::CliPay,
        grant,
    )
    .await
    .expect("the restricted submission succeeds");
    recorder
}

/// A restricted submission leaves its approval unconsumed on disk while the
/// restriction holds the grant lease, and consumes it once the lease drops.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn restricted_submission_consumes_its_approval_after_the_lease_drops() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let toolsets = tempfile::TempDir::new().unwrap();
    let root = toolsets.path().join("toolsets");
    let grants = toolsets.path().join("grants.toml");
    let approvals = toolsets.path().join("approval-store");
    let nonce = queued_approval(&approvals);
    let fx = AuthorizedSubmissionFixture::new("restricted-approval", NOW);

    let recorder = restricted_approved_submission(&fx, &root, &grants, &approvals, &nonce).await;

    assert_eq!(
        *recorder.at_outcome.lock().unwrap(),
        [false],
        "the approval is unconsumed while the restriction holds its lease"
    );
    drop(lock_toolsets(&root).expect("the lease drops when submission returns"));
    recorder.inner.complete_owed_approval();
    assert!(
        consumed(&approvals, &nonce),
        "the approval is consumed after the lease drops"
    );
}

/// A restricted submission that stops before completing its approval
/// consumption leaves it owed in the receipt, and the receipt repair the
/// status call runs completes it.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn owed_approval_consumption_is_completed_by_the_receipt_repair() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let toolsets = tempfile::TempDir::new().unwrap();
    let root = toolsets.path().join("toolsets");
    let grants = toolsets.path().join("grants.toml");
    let approvals = toolsets.path().join("approval-store");
    let nonce = queued_approval(&approvals);
    let fx = AuthorizedSubmissionFixture::new("restricted-owed", NOW);

    drop(restricted_approved_submission(&fx, &root, &grants, &approvals, &nonce).await);

    let file = fx.receipts_file().unwrap();
    let receipts = stellar_agent_core::profile::receipt::ReceiptStore::open_at(
        file.parent().unwrap(),
        file.file_stem().unwrap().to_str().unwrap(),
    )
    .unwrap();
    let owed = receipts
        .find_by_approval_nonce(&nonce)
        .unwrap()
        .expect("the receipt holds the approval");
    assert!(
        owed.submitted && !owed.approval_consumed && !consumed(&approvals, &nonce),
        "the receipt records the consumption as owed"
    );
    stellar_agent_network::submission_record::repair_approval_consumption(
        &receipts,
        &owed.envelope_hash,
        &approvals,
        PROFILE,
    )
    .unwrap();
    assert!(
        receipts
            .get(&owed.envelope_hash)
            .unwrap()
            .unwrap()
            .approval_consumed,
        "the repair acknowledges the consumption"
    );
    assert!(
        consumed(&approvals, &nonce),
        "the repair consumes the owed approval"
    );
}
