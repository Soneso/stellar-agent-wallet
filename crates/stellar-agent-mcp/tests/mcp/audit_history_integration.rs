//! Reconciliation keeps its duplicate suppression across audit rotation, and
//! writes no settled row when the retained history cannot be read.
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
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{
    Sep43SignAndSubmitTransactionArgs, StellarTransactionStatusArgs, WalletServer,
};
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, account_ledger_key_xdr,
};
use stellar_agent_test_support::{keyring_mock, signed_envelope::SignedTestEnvelope};
use wiremock::{Mock, MockServer, matchers::method};

/// A confirmed submission whose settled row one filler append rotated into an
/// archive.
struct RotatedSettlement {
    _home: crate::common::IsolatedDataRoot,
    _rpc: MockServer,
    server: WalletServer,
    profile: Profile,
    tx_hash: String,
}

/// Submits a SEP-43 transaction by the payer `seed` names, which the endpoint
/// confirms, then rotates the log so the settled row sits in an archive and
/// the active file holds only a filler row for another submission.
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
    let rpc = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            crate::common::TimeoutRpc::new(vec![(
                account_ledger_key_xdr(source),
                account_entry_xdr_with_seq(source, 500_000_000_000, 0, 42),
            )])
            .confirming_in(1_001),
        )
        .mount(&rpc)
        .await;
    let profile = crate::common::timeout_profile(&rpc.uri(), source);
    let server = WalletServer::new(profile.clone()).unwrap();
    let result = server
        .call_stellar_sep43_sign_and_submit_transaction(Sep43SignAndSubmitTransactionArgs {
            chain_id: "stellar:testnet".to_owned(),
            transaction_xdr: envelope.envelope_xdr().to_owned(),
            network_passphrase: None,
            address: None,
        })
        .await
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(json["data"]["status"], "success", "{json}");
    let name = server.profile_name_for_approval();
    let access =
        stellar_agent_network::keyring::keyed_audit_access(&profile, &name, BindingCheck::Enforce)
            .unwrap();
    let writer =
        AuditWriterRegistry::get_or_open_keyed(&name, &profile.audit_log_path, access).unwrap();
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
            None,
            Some("other".to_owned()),
            "filler",
        ))
        .unwrap();
    drop(threshold);
    assert_eq!(
        crate::common::rows_of_kind(&archive_rows(&profile), "value_action_submitted").len(),
        1,
        "the settled row sits in an archive"
    );
    RotatedSettlement {
        _home: home,
        _rpc: rpc,
        server,
        profile,
        tx_hash: json["data"]["txHash"].as_str().unwrap().to_owned(),
    }
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

/// The settled rows across the archives and the active file.
fn submitted_rows_everywhere(profile: &Profile) -> usize {
    let mut rows = archive_rows(profile);
    rows.extend(crate::common::audit_rows(profile));
    crate::common::rows_of_kind(&rows, "value_action_submitted").len()
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

#[tokio::test]
#[serial]
async fn a_status_rerun_after_rotation_writes_no_duplicate_settled_row() {
    let settled = settle_then_rotate([0x8a; 32]).await;
    status(&settled).await;
    assert_eq!(submitted_rows_everywhere(&settled.profile), 1);
}

/// A settlement lookup that cannot read the retained history writes no
/// settled row. The active file holds no row for the submission, so the
/// lookup visits the archive, whose interior link is broken: whether a row
/// is owed is unknown, and status writes none rather than guess.
#[tokio::test]
#[serial]
async fn a_status_run_over_a_broken_archive_writes_no_settled_row() {
    let settled = settle_then_rotate([0x9d; 32]).await;
    break_newest_archive_link(&settled.profile.audit_log_path);
    status(&settled).await;
    assert!(
        crate::common::rows_of_kind(
            &crate::common::audit_rows(&settled.profile),
            "value_action_submitted"
        )
        .is_empty(),
        "no settled row is appended to the active file"
    );
    assert_eq!(submitted_rows_everywhere(&settled.profile), 1);
}
