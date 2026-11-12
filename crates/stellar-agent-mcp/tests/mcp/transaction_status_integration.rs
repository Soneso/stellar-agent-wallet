//! `stellar_transaction_status` and the dispatch gate's reconciliation pass
//! against a mocked endpoint, on records seeded in the isolated data root.
//!
//! The status tool observes a submission by its receipt or authenticated
//! reservation. Endpoint reports retain exposure without creating definitive
//! outcome rows. No path sends, which the responder counts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarPayArgs, StellarTransactionStatusArgs, WalletServer};
use stellar_agent_network::policy_state::{PersistedWindowStore, SubmissionHold};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub(super) const ENVELOPE_HASH: &str =
    "77777777777777777777777777777777777777777777777777777777777777aa";
pub(super) const TX_HASH: &str = "88888888888888888888888888888888888888888888888888888888888888bb";
pub(super) const SOURCE: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DESTINATION: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// The sequence the source account reports.
const ACCOUNT_SEQUENCE: i64 = 41;
/// The ledger every seeded submission was recorded at.
const SUBMISSION_LEDGER: u32 = 1_000;

fn now_ms() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap()
}

/// Answers every read the status tool and the gate pass make, and counts
/// `sendTransaction`.
#[derive(Clone)]
struct StatusRpc {
    status: Arc<Mutex<&'static str>>,
    floor: u32,
    sends: Arc<AtomicUsize>,
}

impl StatusRpc {
    fn new(status: &'static str, floor: u32) -> Self {
        Self {
            status: Arc::new(Mutex::new(status)),
            floor,
            sends: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    async fn endpoint(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }
}

impl Respond for StatusRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let result = match body["method"].as_str().unwrap_or_default() {
            "getNetwork" => crate::common::EndpointNetwork::testnet().result(),
            "getHealth" => json!({
                "status": "healthy",
                "latestLedger": 2_000,
                "oldestLedger": self.floor,
                "ledgerRetentionWindow": 2_000 - self.floor,
            }),
            "getLedgers" => json!({
                "latestLedger": 2_000,
                "oldestLedger": 1,
                "latestLedgerCloseTime": (now_ms() / 1_000).to_string(),
                "oldestLedgerCloseTime": 1,
                "cursor": "2000",
                "ledgers": [],
            }),
            "getLedgerEntries" => json!({
                "entries": [{
                    "key": account_ledger_key_xdr(SOURCE),
                    "xdr": account_entry_xdr_with_seq(SOURCE, 100_000_000_000, 0, ACCOUNT_SEQUENCE),
                    "lastModifiedLedgerSeq": 1_000,
                }],
                "latestLedger": 2_000,
            }),
            "sendTransaction" => {
                self.sends.fetch_add(1, Ordering::SeqCst);
                return ResponseTemplate::new(500);
            }
            _ => match *self.status.lock().unwrap() {
                "SUCCESS" => json!({
                    "status": "SUCCESS",
                    "ledger": 1_500,
                    "latestLedger": 2_000,
                    "oldestLedger": self.floor,
                    "createdAt": (now_ms() / 1_000).to_string(),
                    "txHash": TX_HASH,
                }),
                other => json!({
                    "status": other,
                    "latestLedger": 2_000,
                    "oldestLedger": self.floor,
                }),
            },
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
            .insert_header("content-type", "application/json")
    }
}

/// A profile under its own signer account, so its audit log is not shared
/// with another test in this binary.
pub(super) fn status_profile(rpc_url: &str, account: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", account, "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p.submit_timeout_seconds = Some(1);
    crate::common::install_test_audit_key(&mut p);
    p
}

/// Seeds a sent, unanswered receipt for `ENVELOPE_HASH`.
pub(super) fn seed_receipt(profile_name: &str, sequence: i64, max_time: u64) {
    let receipts = ReceiptStore::open(profile_name).unwrap();
    receipts
        .begin_submission(
            ENVELOPE_HASH,
            TX_HASH,
            SOURCE,
            sequence,
            max_time,
            SUBMISSION_LEDGER,
        )
        .unwrap();
    receipts.mark_submitted(ENVELOPE_HASH).unwrap();
}

/// Takes a reservation for `ENVELOPE_HASH` that a gate pass treats as due.
pub(super) fn seed_reservation(
    profile: &Profile,
    profile_name: &str,
    sequence: i64,
) -> PersistedWindowStore {
    let now = now_ms();
    let window = PersistedWindowStore::for_profile(profile_name);
    window
        .record_pending(
            profile,
            &[WindowEntry::new(
                StateKey::new(profile_name, 1, "native", 86_400),
                now,
                75,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000_000_000,
                },
            )],
            &SubmissionHold {
                chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                    profile.chain_id,
                ),
                id: ENVELOPE_HASH.to_owned(),
                tx_hash: TX_HASH.to_owned(),
                source: SOURCE.to_owned(),
                sequence,
                max_time: 0,
                pending_since_ms: now - 400_000,
                submission_ledger: SUBMISSION_LEDGER,
                submission_anchor: None,
                operator_required: false,
            },
        )
        .unwrap();
    window
}

async fn status(server: &WalletServer) -> Value {
    let result = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash: TX_HASH.to_owned(),
        })
        .await
        .expect("the status tool must not error");
    let text = result.content[0].as_text().unwrap().text.clone();
    let json: Value = serde_json::from_str(&text).unwrap();
    assert_ne!(result.is_error, Some(true), "{json}");
    json
}

/// The rows of `kind` naming `ENVELOPE_HASH` in the profile's audit log.
fn rows_naming(profile: &Profile, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(&profile.audit_log_path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| row["kind"] == kind && row["envelope_hash"] == ENVELOPE_HASH)
        .collect()
}

/// A V1 engine with a per-period cap on the simulate tool, which is what
/// makes the dispatch gate run its reconciliation pass.
fn capped_engine(profile_name: &str) -> stellar_agent_core::policy::v1::PolicyEngineV1 {
    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};

    let document = PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: ["stellar_pay", "stellar_transaction_status"]
            .into_iter()
            .map(|tool| PolicyRule {
                r#match: RuleMatch {
                    tool: tool.to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![Box::new(PerPeriodCapCriterion::new(
                    "native".to_owned(),
                    Window::parse("1d").unwrap(),
                    1_000_000_000_000,
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            })
            .collect(),
        signature: None,
    };
    stellar_agent_core::policy::v1::PolicyEngineV1::new(document, profile_name.to_owned())
}

fn simulate_args() -> StellarPayArgs {
    StellarPayArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE.to_owned(),
        destination: DESTINATION.to_owned(),
        amount: None,
        amount_in_stroops: Some("10000000".to_owned()),
        asset: "native".to_owned(),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        classic_base: None,
        business_id: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool descriptions
// ─────────────────────────────────────────────────────────────────────────────

/// Each commit tool tells the agent how to recover from a timeout, and the
/// status tool documents the fields that report a release and a hold.
#[test]
fn the_tool_descriptions_carry_the_timeout_recovery() {
    let sentence = "On submission.tx_timeout the outcome is unknown: pass error.details.tx_hash \
                    to stellar_transaction_status, and never resubmit.";
    let description = |name: &str| {
        WalletServer::all_registered_tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("{name} is registered"))
            .description
            .map(|d| d.into_owned())
            .unwrap_or_default()
    };
    for name in [
        "stellar_pay_commit",
        "stellar_claim_commit",
        "stellar_trustline_commit",
        "stellar_create_account_commit",
    ] {
        let text = description(name);
        assert!(text.contains(sentence), "{name}: {text}");
    }
    let text = description("stellar_transaction_status");
    assert!(text.contains("record.release_code"), "{text}");
    assert!(
        text.contains("reservation {envelope_hash, operator_required}"),
        "{text}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Release evidence
// ─────────────────────────────────────────────────────────────────────────────

/// A passed time bound alone does not prove the possible spend is safe to forget.
#[tokio::test]
#[serial]
async fn transaction_status_retains_a_time_bound_observation() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-status-time-bound");
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    // The time bound passed before the latest ledger closed; the sequence is
    // one the account has not reached.
    seed_receipt(&profile_name, ACCOUNT_SEQUENCE + 1, now_ms() / 1_000 - 100);

    let json = status(&server).await;

    assert_eq!(json["data"]["record"]["status"], "pending", "{json}");
    assert!(json["data"]["record"]["release_code"].is_null(), "{json}");
    let failed = rows_naming(&profile, "value_action_failed");
    assert!(failed.is_empty(), "{failed:?}");

    status(&server).await;
    assert_eq!(
        rows_naming(&profile, "value_action_failed").len(),
        0,
        "a rerun writes no outcome row"
    );
    assert_eq!(rpc.sends(), 0, "the status tool never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// Receipts are display data
// ─────────────────────────────────────────────────────────────────────────────

/// The spending the window counts for the seeded bucket.
fn counted(window: &PersistedWindowStore, profile: &Profile, profile_name: &str) -> (i128, u32) {
    let state = stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new();
    window.load_into(profile_name, profile, &state).unwrap();
    state
        .query_window(
            &StateKey::new(profile_name, 1, "native", 86_400),
            now_ms() + 1_000,
        )
        .unwrap()
}

/// Forged receipts create no settlement rows. Two status calls preserve
/// authentic holds and counted amounts. The forged cases are a receipt edited
/// to `Failed` over an authentic untimed hold and a fabricated `Failed`
/// receipt with no hold. An ambiguous receipt with a release code and a
/// success report are the controls.
#[tokio::test]
#[serial]
async fn forged_receipt_cannot_create_settled_row() {
    for (label, endpoint, held) in [
        ("edited-failed", "FAILED", true),
        ("fabricated-failed", "FAILED", false),
        ("ambiguous-released", "NOT_FOUND", true),
        ("success", "SUCCESS", true),
    ] {
        let _data_root = crate::common::isolated_data_root();
        keyring_mock::install().expect("mock keyring store init");
        let rpc = StatusRpc::new(endpoint, 1);
        let mock_server = rpc.endpoint().await;
        let profile = status_profile(&mock_server.uri(), &format!("acct-forged-{label}"));
        let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
        let profile_name = server.profile_name_for_approval();
        seed_receipt(&profile_name, ACCOUNT_SEQUENCE + 1, 0);
        let window = if held {
            seed_reservation(&profile, &profile_name, ACCOUNT_SEQUENCE + 1)
        } else {
            PersistedWindowStore::for_profile(&profile_name)
        };
        let receipts = ReceiptStore::open(&profile_name).unwrap();
        match label {
            "edited-failed" | "fabricated-failed" => receipts
                .finalize(
                    ENVELOPE_HASH,
                    ReceiptStatus::Failed {
                        code: "ledger.op_failed".to_owned(),
                    },
                    Some(SUBMISSION_LEDGER + 1),
                )
                .unwrap(),
            "ambiguous-released" => receipts
                .finalize_released(
                    ENVELOPE_HASH,
                    stellar_agent_core::profile::receipt::ReleaseEvidence::SequenceConsumed,
                )
                .unwrap(),
            _ => {}
        }
        let holds_before = window.pending_reservations(&profile).unwrap();
        let counted_before = if held {
            counted(&window, &profile, &profile_name)
        } else {
            (0, 0)
        };

        for _ in 0..2 {
            let json = status(&server).await;
            assert_eq!(
                json["data"]["record"]["settlement_evidence"], "unavailable",
                "{label}: {json}"
            );
        }

        for kind in [
            "value_action_failed",
            "value_action_submitted",
            "submission_accounting_expired",
        ] {
            let rows = rows_naming(&profile, kind);
            assert!(rows.is_empty(), "{label}: {kind}: {rows:?}");
        }
        assert_eq!(
            window.pending_reservations(&profile).unwrap(),
            holds_before,
            "{label}: the hold stands"
        );
        if held {
            assert_eq!(
                counted(&window, &profile, &profile_name),
                counted_before,
                "{label}: the counted amount stands"
            );
            assert_eq!(counted_before, (75, 1), "{label}");
        } else {
            assert!(holds_before.is_empty(), "{label}");
            assert!(
                !window.exists(),
                "{label}: no reservation or decision is created"
            );
        }
        assert!(
            window
                .owed_accounting_expiries(&profile)
                .unwrap()
                .is_empty(),
            "{label}: no accounting decision"
        );
        assert_eq!(rpc.sends(), 0, "{label}: the status tool never sends");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Orphan recovery
// ─────────────────────────────────────────────────────────────────────────────

/// A success report restores a missing receipt while retaining exposure and
/// leaving authenticated outcome audit rows absent.
#[tokio::test]
#[serial]
async fn transaction_status_restores_an_orphan_on_a_success_report() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("SUCCESS", 1_200);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-status-orphan-success");
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    let window = seed_reservation(&profile, &profile_name, 7);

    let json = status(&server).await;

    assert_eq!(json["data"]["chain_status"], "SUCCESS");
    assert_eq!(json["data"]["record"]["status"], "success", "{json}");
    assert_eq!(json["data"]["record"]["reservation_open"], true);
    assert_eq!(json["data"]["reservation"]["envelope_hash"], ENVELOPE_HASH);
    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    let restored = ReceiptStore::open(&profile_name)
        .unwrap()
        .get(ENVELOPE_HASH)
        .unwrap()
        .expect("the definitive answer restores the receipt");
    assert_eq!(restored.status, ReceiptStatus::Success);
    assert_eq!(rows_naming(&profile, "value_action_submitted").len(), 0);

    status(&server).await;
    assert_eq!(
        rows_naming(&profile, "value_action_submitted").len(),
        0,
        "a rerun writes no outcome row"
    );
    assert_eq!(rpc.sends(), 0, "the status tool never sends");
}

/// A reservation whose receipt is missing and whose submission ledger is
/// below the endpoint's retention floor stays held, marked for the operator,
/// and the status tool reports the hold.
#[tokio::test]
#[serial]
async fn transaction_status_reports_an_orphan_beyond_retention() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1_200);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-status-orphan-retention");
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    let window = seed_reservation(&profile, &profile_name, 7);

    let json = status(&server).await;

    assert_eq!(json["data"]["chain_status"], "NOT_FOUND");
    assert!(json["data"]["record"].is_null(), "{json}");
    assert_eq!(
        json["data"]["reservation"]["envelope_hash"], ENVELOPE_HASH,
        "{json}"
    );
    assert_eq!(json["data"]["reservation"]["operator_required"], true);
    let held = window.pending_reservations(&profile).unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].operator_required);
    assert!(rows_naming(&profile, "value_action_failed").is_empty());
    assert_eq!(rpc.sends(), 0, "the status tool never sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// The dispatch gate's reconciliation pass
// ─────────────────────────────────────────────────────────────────────────────

/// The dispatch gate retains exposure on negative observations and never sends.
#[tokio::test]
#[serial]
async fn the_gate_pass_retains_negative_exposure_and_never_sends() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-gate-evidence");
    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    server.set_policy_engine_for_test(Arc::new(capped_engine(&profile_name)));
    seed_receipt(&profile_name, ACCOUNT_SEQUENCE, 0);
    let window = seed_reservation(&profile, &profile_name, ACCOUNT_SEQUENCE);

    // The simulate's outcome is not under test: the gate pass runs before it.
    let _ = server.call_stellar_pay(simulate_args()).await;

    assert!(
        window.pending_reservations(&profile).unwrap().len() == 1,
        "the pass retains the reservation"
    );
    assert_eq!(
        ReceiptStore::open(&profile_name)
            .unwrap()
            .get(ENVELOPE_HASH)
            .unwrap()
            .unwrap()
            .release_code,
        None
    );
    let failed = rows_naming(&profile, "value_action_failed");
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(rpc.sends(), 0, "the gate pass never sends");
}

/// An unavailable audit writer does not turn absence into an owed failure row.
#[tokio::test]
#[serial]
async fn a_negative_gate_observation_does_not_owe_an_audit_failure() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let mut profile = status_profile(&mock_server.uri(), "acct-gate-no-audit");
    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    server.set_policy_engine_for_test(Arc::new(capped_engine(&profile_name)));
    seed_receipt(&profile_name, ACCOUNT_SEQUENCE, 0);
    let window = seed_reservation(&profile, &profile_name, ACCOUNT_SEQUENCE);

    // The audit chain key is absent while the gate pass runs.
    let coordinate = profile.audit_log_hash_chain_key_id.clone();
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    let _ = server.call_stellar_pay(simulate_args()).await;

    assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
    assert_eq!(
        ReceiptStore::open(&profile_name)
            .unwrap()
            .get(ENVELOPE_HASH)
            .unwrap()
            .unwrap()
            .release_code,
        None,
        "the receipt has no definitive failure evidence"
    );
    assert!(rows_naming(&profile, "value_action_failed").is_empty());

    crate::common::install_test_audit_key(&mut profile);
    let json = status(&server).await;

    assert!(json["data"]["record"]["release_code"].is_null(), "{json}");
    let failed = rows_naming(&profile, "value_action_failed");
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!(rpc.sends(), 0, "neither call sends");
}

// ─────────────────────────────────────────────────────────────────────────────
// Accounting delivery
// ─────────────────────────────────────────────────────────────────────────────

/// An envelope hash and a transaction hash for a second seeded submission.
const OLD_ENVELOPE_HASH: &str = "66666666666666666666666666666666666666666666666666666666666666cc";
const OLD_TX_HASH: &str = "55555555555555555555555555555555555555555555555555555555555555dd";

/// Records a sent submission under a bounded hold whose accounting horizon
/// has passed, with its receipt, so a pass commits its accounting expiry.
fn seed_expired_hold(
    profile: &Profile,
    profile_name: &str,
    envelope_hash: &str,
    tx_hash: &str,
    sequence: i64,
) -> PersistedWindowStore {
    let now = now_ms();
    let max_time = now / 1_000 - 86_401;
    let window = PersistedWindowStore::for_profile(profile_name);
    window
        .record_pending(
            profile,
            &[WindowEntry::new(
                StateKey::new(profile_name, 1, "native", 86_400),
                now,
                75,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000_000_000,
                },
            )],
            &SubmissionHold {
                chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                    profile.chain_id,
                ),
                id: envelope_hash.to_owned(),
                tx_hash: tx_hash.to_owned(),
                source: SOURCE.to_owned(),
                sequence,
                max_time,
                pending_since_ms: now - 400_000,
                submission_ledger: SUBMISSION_LEDGER,
                submission_anchor: None,
                operator_required: false,
            },
        )
        .unwrap();
    let receipts = ReceiptStore::open(profile_name).unwrap();
    receipts
        .begin_submission(
            envelope_hash,
            tx_hash,
            SOURCE,
            sequence,
            max_time,
            SUBMISSION_LEDGER,
        )
        .unwrap();
    receipts.mark_submitted(envelope_hash).unwrap();
    window
}

/// Commits the accounting expiry of every due hold through an ordinary pass
/// and returns the one committed decision identifier. Delivery is left to
/// the caller, so the audit event stays owed.
async fn commit_expiry(
    window: &PersistedWindowStore,
    profile: &Profile,
    receipts: Option<&ReceiptStore>,
) -> String {
    let client = stellar_agent_network::StellarRpcClient::new(&profile.rpc_url).unwrap();
    let report = window
        .reconcile_due(
            profile,
            &client,
            None,
            receipts,
            now_ms(),
            stellar_agent_network::policy_state::RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    let [settled] = report.settled.as_slice() else {
        panic!("one committed expiry: {report:?}");
    };
    settled.decision_id.clone()
}

/// The `submission_accounting_expired` rows naming `decision_id`.
fn expiry_rows(profile: &Profile, decision_id: &str) -> usize {
    crate::common::audit_rows(profile)
        .iter()
        .filter(|row| {
            row["kind"] == "submission_accounting_expired" && row["decision_id"] == decision_id
        })
        .count()
}

/// Holds the window state's writer lock, so every window commit refuses
/// while reads still succeed.
fn hold_window_lock(
    window: &PersistedWindowStore,
    profile: &Profile,
) -> stellar_agent_core::policy::state_lock::WindowStoreLock {
    stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
        window.path(),
        &profile.policy_window_state_key_id,
    )
    .unwrap()
}

/// A delivered event whose receipt projection is still owed completes on a
/// status run whose audit writer is unavailable: the run renders the
/// projected record and appends no row.
#[tokio::test]
#[serial]
async fn a_projection_only_retry_runs_without_the_audit_writer() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-projection-only");
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    let window = seed_expired_hold(
        &profile,
        &profile_name,
        ENVELOPE_HASH,
        TX_HASH,
        ACCOUNT_SEQUENCE + 1,
    );
    let decision_id = commit_expiry(&window, &profile, None).await;

    // The event is delivered and acknowledged without the receipt store, so
    // only the projection stays owed.
    let access = stellar_agent_network::keyring::keyed_audit_access(
        &profile,
        &profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    )
    .unwrap();
    let writer = stellar_agent_core::audit_log::AuditWriterRegistry::get_or_open_keyed(
        &profile_name,
        &profile.audit_log_path,
        access,
    )
    .unwrap();
    let delivered = stellar_agent_network::policy_state::deliver_accounting_expiries(
        &mut writer.lock().unwrap(),
        &window,
        &profile,
        &profile_name,
        None,
    )
    .unwrap();
    assert_eq!(
        (
            delivered.appended,
            delivered.acknowledged,
            delivered.projected
        ),
        (1, 1, 0),
        "{delivered:?}"
    );
    let owed = window.owed_accounting_expiries(&profile).unwrap();
    assert!(owed.unacknowledged.is_empty(), "{owed:?}");
    assert_eq!(owed.unprojected, vec![decision_id.clone()]);

    // The audit chain key is absent, so no audit writer can be acquired.
    let coordinate = profile.audit_log_hash_chain_key_id.clone();
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    let rows_before = crate::common::audit_rows(&profile).len();

    let json = status(&server).await;

    let record = &json["data"]["record"];
    assert_eq!(
        record["settlement_decision_id"],
        decision_id.as_str(),
        "{json}"
    );
    assert_eq!(
        record["release_code"], "submission.accounting_expired",
        "{json}"
    );
    assert_eq!(record["status"], "ambiguous", "{json}");
    assert_eq!(record["settlement_evidence"], "unavailable", "{json}");
    assert!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .is_empty(),
        "the projection completes"
    );
    assert_eq!(
        crate::common::audit_rows(&profile).len(),
        rows_before,
        "the run appends no row"
    );
    assert_eq!(expiry_rows(&profile, &decision_id), 1);
    assert_eq!(rpc.sends(), 0, "the status tool never sends");
}

/// The dispatch gate delivers old obligations even when its pass refuses. A
/// held window lock prevents the due expiry commit while the old event is
/// appended. Once the lock is released, the next pass acknowledges it without
/// a second row.
#[tokio::test]
#[serial]
async fn the_gate_delivers_an_old_obligation_after_a_refused_pass() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-gate-refused-drain");
    let mut server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    server.set_policy_engine_for_test(Arc::new(capped_engine(&profile_name)));
    let receipts = ReceiptStore::open(&profile_name).unwrap();
    let window = seed_expired_hold(
        &profile,
        &profile_name,
        OLD_ENVELOPE_HASH,
        OLD_TX_HASH,
        ACCOUNT_SEQUENCE + 1,
    );
    let old = commit_expiry(&window, &profile, Some(&receipts)).await;
    seed_expired_hold(
        &profile,
        &profile_name,
        ENVELOPE_HASH,
        TX_HASH,
        ACCOUNT_SEQUENCE + 2,
    );

    let lock = hold_window_lock(&window, &profile);
    // The simulate's outcome is not under test: the gate pass runs before it.
    let _ = server.call_stellar_pay(simulate_args()).await;
    assert_eq!(
        window.pending_reservations(&profile).unwrap().len(),
        1,
        "the refused pass commits nothing"
    );
    assert_eq!(
        expiry_rows(&profile, &old),
        1,
        "the old event is appended after the refused pass"
    );
    assert_eq!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .unacknowledged,
        vec![old.clone()],
        "the held lock refuses the acknowledgement"
    );
    drop(lock);

    let _ = server.call_stellar_pay(simulate_args()).await;
    assert_eq!(expiry_rows(&profile, &old), 1, "no second row");
    assert!(window.pending_reservations(&profile).unwrap().is_empty());
    let owed = window.owed_accounting_expiries(&profile).unwrap();
    assert!(owed.unacknowledged.is_empty(), "{owed:?}");
    let rows = crate::common::audit_rows(&profile);
    assert_eq!(
        crate::common::rows_of_kind(&rows, "submission_accounting_expired").len(),
        2,
        "each decision has one row"
    );
    assert_eq!(rpc.sends(), 0, "the gate pass never sends");
}

/// A status run whose own reconciliation refuses still delivers the
/// obligations of earlier runs before it returns the refusal.
#[tokio::test]
#[serial]
async fn a_refused_status_run_delivers_old_obligations() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().expect("mock keyring store init");
    let rpc = StatusRpc::new("NOT_FOUND", 1);
    let mock_server = rpc.endpoint().await;
    let profile = status_profile(&mock_server.uri(), "acct-status-refused-drain");
    let server = WalletServer::new(profile.clone()).expect("WalletServer::new");
    let profile_name = server.profile_name_for_approval();
    let receipts = ReceiptStore::open(&profile_name).unwrap();
    let window = seed_expired_hold(
        &profile,
        &profile_name,
        OLD_ENVELOPE_HASH,
        OLD_TX_HASH,
        ACCOUNT_SEQUENCE + 1,
    );
    let old = commit_expiry(&window, &profile, Some(&receipts)).await;
    seed_expired_hold(
        &profile,
        &profile_name,
        ENVELOPE_HASH,
        TX_HASH,
        ACCOUNT_SEQUENCE + 2,
    );

    let lock = hold_window_lock(&window, &profile);
    let refused = server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash: TX_HASH.to_owned(),
        })
        .await
        .unwrap();
    let (code, _, text) = crate::common::assert_business_envelope(&refused);
    assert_eq!(code, "submission.record_unavailable", "{text}");
    assert_eq!(
        expiry_rows(&profile, &old),
        1,
        "the old event is appended before the refusal returns"
    );
    drop(lock);

    let json = status(&server).await;
    assert_eq!(
        json["data"]["record"]["release_code"],
        "submission.accounting_expired"
    );
    assert_eq!(expiry_rows(&profile, &old), 1, "no second row");
    let rows = crate::common::audit_rows(&profile);
    assert_eq!(
        crate::common::rows_of_kind(&rows, "submission_accounting_expired").len(),
        2,
        "each decision has one row"
    );
    assert!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .unacknowledged
            .is_empty()
    );
    assert_eq!(rpc.sends(), 0, "the status tool never sends");
}

/// Both the status read and the V1 refresh preserve a foreign network's history.
#[tokio::test]
#[serial]
async fn chain_flip_refuses_status_without_rpc_or_state_changes() {
    let _data_root = crate::common::isolated_data_root();
    keyring_mock::install().unwrap();
    let rpc = StatusRpc::new("FAILED", 1);
    let primary = rpc.endpoint().await;
    let edited = status_profile(&primary.uri(), "acct-status-chain-scope");
    let mut server = WalletServer::new(edited.clone()).unwrap();
    let name = server.profile_name_for_approval();
    let mut original = edited.clone();
    original.chain_id = stellar_agent_core::profile::caip2::Caip2::Mainnet;
    original.rpc_url = "https://primary.example".to_owned();
    let window = seed_reservation(&original, &name, ACCOUNT_SEQUENCE + 1);
    seed_receipt(&name, ACCOUNT_SEQUENCE + 1, 0);
    let receipts = ReceiptStore::open(&name).unwrap();
    let before = std::fs::read(
        stellar_agent_core::profile::schema::default_policy_window_state_path_for(&name),
    )
    .unwrap();
    let receipt_before = std::fs::read(receipts.file_path().unwrap()).unwrap();
    let audit_before = std::fs::read(&edited.audit_log_path).ok();
    let entry = &edited.policy_window_state_key_id;
    let key_before = keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .get_password()
        .unwrap();
    let generation =
        keyring_core::Entry::new(&entry.service, &format!("{}-generation", entry.account)).unwrap();
    let generation_before = generation.get_password().unwrap();
    for v1 in [false, true] {
        if v1 {
            server.set_policy_engine_for_test(Arc::new(capped_engine(&name)));
        }
        for bytes in [receipt_before.as_slice(), b"unreadable receipt"] {
            std::fs::write(receipts.file_path().unwrap(), bytes).unwrap();
            let result = server
                .call_stellar_transaction_status(StellarTransactionStatusArgs {
                    chain_id: "stellar:testnet".to_owned(),
                    tx_hash: TX_HASH.to_owned(),
                })
                .await
                .unwrap();
            assert_eq!(result.is_error, Some(true));
            let json: Value =
                serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
            assert_eq!(
                json["error"]["code"], "policy.window_chain_mismatch",
                "{json}"
            );
            assert!(!json.to_string().contains("reset-window-state"));
            assert_eq!(
                std::fs::read(
                    stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                        &name
                    )
                )
                .unwrap(),
                before
            );
            assert_eq!(std::fs::read(receipts.file_path().unwrap()).unwrap(), bytes);
            assert_eq!(std::fs::read(&edited.audit_log_path).ok(), audit_before);
            assert_eq!(
                keyring_core::Entry::new(&entry.service, &entry.account)
                    .unwrap()
                    .get_password()
                    .unwrap(),
                key_before
            );
            assert_eq!(generation.get_password().unwrap(), generation_before);
        }
    }
    assert!(primary.received_requests().await.unwrap().is_empty());
    assert_eq!(window.pending_reservations(&original).unwrap().len(), 1);
}
