//! Accounting delivery finds an expiry event across audit rotation by its
//! decision identifier, and acknowledges nothing when the retained history
//! cannot be verified.
//!
//! The shared test audit log is named after the signer-account alias, and each
//! test here uses its payer account as that alias, so each fixture's identity,
//! and with it its audit log path, is its own: a second profile name on the
//! same log path would open a second writer and find the first one's lock
//! held.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use serial_test::serial;
use stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold;
use stellar_agent_core::audit_log::test_helpers::{
    break_newest_archive_link, rotated_archives_newest_first,
};
use stellar_agent_core::audit_log::{AuditEntry, AuditWriterRegistry, BindingCheck};
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarTransactionStatusArgs, WalletServer};
use stellar_agent_network::policy_state::{
    ChainScope, PersistedWindowStore, RECONCILE_BUDGET, RECONCILE_MIN_AGE_MS, SubmissionHold,
};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_agent_test_support::{keyring_mock, signed_envelope::SignedTestEnvelope};
use wiremock::{Mock, MockServer, matchers::method};

/// An authentic accounting expiry whose audit event one filler append rotated
/// into an archive, with the obligation still unacknowledged.
struct RotatedSettlement {
    _home: crate::common::IsolatedDataRoot,
    _rpc: MockServer,
    server: WalletServer,
    profile: Profile,
    window: PersistedWindowStore,
    tx_hash: String,
    decision_id: String,
}

/// Records a sent submission by the payer `seed` names under a bounded hold
/// whose accounting horizon has passed, commits its expiry through an
/// ordinary reconciliation pass, appends the owed event through the writer
/// without acknowledging it, then rotates the log so the event sits in an
/// archive and the active file holds only a filler row.
async fn settle_then_rotate(seed: [u8; 32]) -> RotatedSettlement {
    let home = crate::common::isolated_data_root();
    keyring_mock::install().unwrap();
    let envelope = SignedTestEnvelope::builder(seed).sequence(43).build();
    let source = envelope.source();
    keyring_core::Entry::new("svc", source)
        .unwrap()
        .set_password(
            &stellar_strkey::ed25519::PrivateKey(seed)
                .as_unredacted()
                .to_string(),
        )
        .unwrap();
    crate::common::store_signer_identity("svc", source, seed);
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(crate::common::TimeoutRpc::new(vec![(
            account_ledger_key_xdr(source),
            account_entry_xdr_with_seq(source, 500_000_000_000, 0, 42),
        )]))
        .mount(&rpc)
        .await;
    let profile = crate::common::timeout_profile(&rpc.uri(), source);
    let server = WalletServer::new(profile.clone()).unwrap();
    let name = server.profile_name_for_approval();
    let envelope_hash = stellar_agent_network::envelope_hash_hex(envelope.envelope_xdr());
    let tx_hash = envelope.tx_hash_hex().to_owned();
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let since = now - RECONCILE_MIN_AGE_MS;
    let max_time = now / 1_000 - 86_401;
    let window = PersistedWindowStore::for_profile(&name);
    window
        .record_pending(
            &profile,
            &[WindowEntry::new(
                StateKey::new(&name, 1, "native", 86_400),
                since,
                75,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000_000_000,
                },
            )],
            &SubmissionHold {
                chain_scope: ChainScope::for_chain(profile.chain_id),
                id: envelope_hash.clone(),
                tx_hash: tx_hash.clone(),
                source: source.to_owned(),
                sequence: 43,
                max_time,
                pending_since_ms: since,
                submission_ledger: 1_000,
                submission_anchor: None,
                operator_required: false,
            },
        )
        .unwrap();
    let receipts = ReceiptStore::open(&name).unwrap();
    receipts
        .begin_submission(&envelope_hash, &tx_hash, source, 43, max_time, 1_000)
        .unwrap();
    receipts.mark_submitted(&envelope_hash).unwrap();
    let client = stellar_agent_network::StellarRpcClient::new(&rpc.uri()).unwrap();
    let report = window
        .reconcile_due(
            &profile,
            &client,
            None,
            Some(&receipts),
            now,
            RECONCILE_BUDGET,
        )
        .await
        .unwrap();
    let [settled] = report.settled.as_slice() else {
        panic!("one committed expiry: {report:?}");
    };
    let decision_id = settled.decision_id.clone();

    let access =
        stellar_agent_network::keyring::keyed_audit_access(&profile, &name, BindingCheck::Enforce)
            .unwrap();
    let writer =
        AuditWriterRegistry::get_or_open_keyed(&name, &profile.audit_log_path, access).unwrap();
    writer
        .lock()
        .unwrap()
        .write_entry(
            window
                .accounting_expiry_event(&profile, &decision_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        window
            .owed_accounting_expiries(&profile)
            .unwrap()
            .unacknowledged,
        vec![decision_id.clone()],
        "the appended event is not yet acknowledged"
    );
    let size = std::fs::metadata(&profile.audit_log_path).unwrap().len();
    let threshold = set_rotation_threshold(&profile.audit_log_path, size);
    writer
        .lock()
        .unwrap()
        .write_entry(AuditEntry::new_submission_receipt_cleared(
            "filler",
            Some("stellar:testnet".to_owned()),
            "other",
            "pending",
            false,
            false,
            None,
            Some("other".to_owned()),
            "filler",
        ))
        .unwrap();
    drop(threshold);
    assert_eq!(
        expiry_rows(&archive_rows(&profile), &decision_id),
        1,
        "the expiry event sits in an archive"
    );
    RotatedSettlement {
        _home: home,
        _rpc: rpc,
        server,
        profile,
        window,
        tx_hash,
        decision_id,
    }
}

/// The `submission_accounting_expired` rows among `rows` naming `decision_id`.
fn expiry_rows(rows: &[serde_json::Value], decision_id: &str) -> usize {
    crate::common::rows_of_kind(rows, "submission_accounting_expired")
        .into_iter()
        .filter(|row| row["decision_id"] == decision_id)
        .count()
}

/// Every row of every archive of the profile's log, newest archive first.
fn archive_rows(profile: &Profile) -> Vec<serde_json::Value> {
    rotated_archives_newest_first(&profile.audit_log_path)
        .into_iter()
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The expiry events naming the fixture's decision across the archives and
/// the active file.
fn expiry_rows_everywhere(settled: &RotatedSettlement) -> usize {
    let mut rows = archive_rows(&settled.profile);
    rows.extend(crate::common::audit_rows(&settled.profile));
    expiry_rows(&rows, &settled.decision_id)
}

/// Runs the status tool for the settled submission; it must not refuse.
async fn status(settled: &RotatedSettlement) {
    let status = settled
        .server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash: settled.tx_hash.clone(),
        })
        .await
        .unwrap();
    assert_ne!(status.is_error, Some(true), "{status:?}");
}

/// A status run finds the decision identifier in the archive, appends
/// nothing, and acknowledges the obligation.
#[tokio::test]
#[serial]
async fn a_status_rerun_after_rotation_writes_no_duplicate_settled_row() {
    let settled = settle_then_rotate([0x8a; 32]).await;
    status(&settled).await;
    assert_eq!(expiry_rows_everywhere(&settled), 1);
    assert!(
        settled
            .window
            .owed_accounting_expiries(&settled.profile)
            .unwrap()
            .unacknowledged
            .is_empty(),
        "the retained event is acknowledged"
    );
    status(&settled).await;
    assert_eq!(expiry_rows_everywhere(&settled), 1);
}

/// A status run over a broken retained history still renders its answer. The
/// writer acquisition refuses, so the run appends no row and the obligation
/// stays unacknowledged for a later delivery.
#[tokio::test]
#[serial]
async fn a_status_run_over_a_broken_archive_renders_and_keeps_the_expiry_owed() {
    let settled = settle_then_rotate([0x9d; 32]).await;
    break_newest_archive_link(&settled.profile.audit_log_path);
    let active_before = crate::common::audit_rows(&settled.profile).len();
    let result = settled
        .server
        .call_stellar_transaction_status(StellarTransactionStatusArgs {
            chain_id: "stellar:testnet".to_owned(),
            tx_hash: settled.tx_hash.clone(),
        })
        .await
        .unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    assert_ne!(result.is_error, Some(true), "{text}");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["data"]["tx_hash"], settled.tx_hash, "{json}");
    assert_eq!(
        json["data"]["record"]["settlement_evidence"], "unavailable",
        "{json}"
    );
    assert_eq!(
        crate::common::audit_rows(&settled.profile).len(),
        active_before,
        "the run appends no row to the active file"
    );
    assert_eq!(expiry_rows_everywhere(&settled), 1);
    assert_eq!(
        settled
            .window
            .owed_accounting_expiries(&settled.profile)
            .unwrap()
            .unacknowledged,
        vec![settled.decision_id.clone()],
        "the obligation stays unacknowledged"
    );
}
