//! The settlement lookup at the edge of the retained audit history.
//!
//! The authorized path refuses resent bytes while the lookup answers
//! [`ValueActionSettlement::Owed`] for their original. The lookup cases place
//! the original at the oldest retained archive, under normal retention, and
//! check the answers the precheck acts on, through a keyed writer whose
//! verification walk feeds the lookup's index. With `mainnet-write`, the
//! authorized cases resend the bytes through
//! `submit_authorized_transaction_and_wait` against a mock endpoint.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test assertions"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use stellar_agent_core::audit_log::reader::{
    SettledValueAction, ValueActionSettlement, try_value_action_settled_row,
    try_value_action_settlement,
};
use stellar_agent_core::audit_log::rotation::MAX_ROTATED_FILES;
use stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold;
use stellar_agent_core::audit_log::schema::PolicyDecision;
use stellar_agent_core::audit_log::test_helpers::rotated_archives_newest_first;
use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::audit_log::{
    AuditEntry, KeyedAuditAccess, NewToolInvocation, TipAnchorStore,
};

const KEY: [u8; 32] = [0x3d; 32];
const ORIGINAL: &str = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a";
const FRESH: &str = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";

fn open(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
    AuditWriter::open(
        path.to_path_buf(),
        Some(KeyedAuditAccess::new(
            zeroize::Zeroizing::new(KEY),
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
        )),
    )
    .unwrap()
}

fn pending(envelope_hash: &str) -> AuditEntry {
    AuditEntry::new_value_action_pending(
        "stellar_pay_commit",
        Some("stellar:pubnet".to_owned()),
        vec![],
        "6ba7aaac...69060003",
        "GAOTC...PZ6X4",
        7,
        PolicyDecision::Allow,
        Some(envelope_hash.to_owned()),
        None,
        None,
        "req-original",
        None,
    )
}

fn filler() -> AuditEntry {
    AuditEntry::new_tool_invocation(NewToolInvocation::new(
        "stellar_pay_commit",
        "stellar:pubnet",
        vec![],
        PolicyDecision::Allow,
        "req-filler",
    ))
}

/// Rotates the log once: the next row lands in a new active file.
fn rotate(writer: &mut AuditWriter, path: &Path) {
    let _threshold = set_rotation_threshold(path, 1);
    writer.write_entry(filler()).unwrap();
}

fn log_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("audit.jsonl")
}

fn answer(writer: &AuditWriter, hash: &str) -> ValueActionSettlement {
    try_value_action_settlement(writer, hash).unwrap()
}

/// An owed original in the oldest retained archive still reads as owed, on
/// the open writer and after a reopen, and fresh bytes read as never written.
/// One more rotation prunes that archive and the original stops answering.
#[test]
fn owed_original_at_lookup_bound_refuses_resend() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = log_path(&dir);
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = open(&path, &store);
    writer.write_entry(pending(ORIGINAL)).unwrap();
    for _ in 0..MAX_ROTATED_FILES {
        rotate(&mut writer, &path);
    }
    let archives = rotated_archives_newest_first(&path);
    assert_eq!(archives.len(), MAX_ROTATED_FILES);
    assert!(
        std::fs::read_to_string(archives.last().unwrap())
            .unwrap()
            .contains(ORIGINAL),
        "the original sits in the oldest retained archive"
    );
    assert!(matches!(
        answer(&writer, ORIGINAL),
        ValueActionSettlement::Owed(_)
    ));
    assert_eq!(
        answer(&writer, FRESH),
        ValueActionSettlement::OwedWithoutLegs
    );
    drop(writer);

    let mut writer = open(&path, &store);
    assert!(
        matches!(answer(&writer, ORIGINAL), ValueActionSettlement::Owed(_)),
        "the reopened writer keeps the oldest obligation"
    );
    assert_eq!(
        answer(&writer, FRESH),
        ValueActionSettlement::OwedWithoutLegs
    );

    rotate(&mut writer, &path);
    assert_eq!(
        rotated_archives_newest_first(&path).len(),
        MAX_ROTATED_FILES
    );
    assert_eq!(
        answer(&writer, ORIGINAL),
        ValueActionSettlement::OwedWithoutLegs,
        "a pruned archive answers nothing"
    );
}

/// Submitted and failed settlement rows in an archive keep their answers: the
/// lookup reports the original as settled, and the settled-row lookup tells
/// the two apart.
#[test]
fn settled_original_with_lost_receipt_keeps_settlement_semantics() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = log_path(&dir);
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let submitted = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let failed = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
    let mut writer = open(&path, &store);
    writer.write_entry(pending(submitted)).unwrap();
    writer
        .write_entry(AuditEntry::new_value_action_submitted(
            "stellar_pay_commit",
            Some("stellar:pubnet".to_owned()),
            vec![],
            "6ba7aaac...69060003",
            9,
            PolicyDecision::Allow,
            Some(submitted.to_owned()),
            None,
            None,
            "req-submitted",
            None,
        ))
        .unwrap();
    writer.write_entry(pending(failed)).unwrap();
    writer
        .write_entry(AuditEntry::new_value_action_failed(
            "stellar_pay_commit",
            Some("stellar:pubnet".to_owned()),
            vec![],
            "6ba7aaac...69060003",
            "submission.failed",
            PolicyDecision::Allow,
            Some(failed.to_owned()),
            None,
            None,
            "req-failed",
        ))
        .unwrap();
    rotate(&mut writer, &path);
    rotate(&mut writer, &path);
    drop(writer);

    let writer = open(&path, &store);
    for _repeat in 0..2 {
        assert_eq!(answer(&writer, submitted), ValueActionSettlement::Settled);
        assert_eq!(answer(&writer, failed), ValueActionSettlement::Settled);
        assert_eq!(
            answer(&writer, FRESH),
            ValueActionSettlement::OwedWithoutLegs
        );
    }
    assert_eq!(
        try_value_action_settled_row(&writer, submitted).unwrap(),
        Some(SettledValueAction::Submitted)
    );
    assert_eq!(
        try_value_action_settled_row(&writer, failed).unwrap(),
        Some(SettledValueAction::Failed {
            code: "submission.failed".to_owned()
        })
    );
}

/// Resends through the authorized path, against a mock mainnet endpoint.
#[cfg(feature = "mainnet-write")]
mod authorized {
    use std::sync::Mutex;
    use std::time::Duration;

    use serde_json::json;
    use serial_test::serial;
    use stellar_agent_core::audit_log::test_helpers::append_forged_entry;
    use stellar_agent_core::error::WalletError;
    use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
    use stellar_agent_network::mainnet::test_support::{
        AuthorizedSubmissionFixture, FixtureEnvelope,
    };
    use stellar_agent_network::{
        AuditWriterHandle, StellarRpcClient, SubmissionResult, envelope_hash_hex,
        submit_authorized_transaction_and_wait,
    };
    use stellar_agent_test_support::SubmissionEchoResponder;
    use stellar_agent_test_support::signed_envelope::get_network_result;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};

    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 86_400_000;
    /// Past the seven days a used authorization stays recorded once its
    /// authority ends.
    const AFTER_LEDGER_RETENTION_MS: u64 = 8 * DAY_MS;
    const TIMEOUT: Duration = Duration::from_secs(10);
    const ALREADY_SUBMITTED: &str = "submission.tx_already_submitted";

    /// A mock mainnet endpoint for `envelope` that accepts every send and
    /// reports the transaction's success, and a client of it.
    async fn endpoint(envelope: &FixtureEnvelope) -> (MockServer, StellarRpcClient) {
        let server = MockServer::start().await;
        for (rpc_method, result) in [
            ("getNetwork", get_network_result(MAINNET_PASSPHRASE)),
            ("getLedgerEntries", envelope.signed.ledger_entries_result()),
            (
                "sendTransaction",
                json!({
                    "hash": envelope.signed.tx_hash_hex(),
                    "status": "PENDING",
                    "latestLedger": 1000,
                    "latestLedgerCloseTime": "1699999999"
                }),
            ),
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

    /// The number of `sendTransaction` requests `server` received.
    async fn sends(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    == "sendTransaction"
            })
            .count()
    }

    /// Submits `envelope` under `grant` through the authorized entry point.
    async fn submit(
        client: &StellarRpcClient,
        envelope: &FixtureEnvelope,
        recorder: &stellar_agent_network::WalletSubmissionRecorder<'_>,
        grant: stellar_agent_network::MainnetSubmitGrant,
    ) -> Result<SubmissionResult, WalletError> {
        submit_authorized_transaction_and_wait(
            client,
            None,
            envelope.signed.envelope_xdr(),
            TIMEOUT,
            MAINNET_PASSPHRASE,
            None,
            recorder,
            stellar_agent_network::mainnet::MainnetConsumer::CliPay,
            grant,
        )
        .await
    }

    /// Every log file's bytes, the active file first.
    fn audit_bytes(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        std::iter::once(path.to_path_buf())
            .chain(rotated_archives_newest_first(path))
            .map(|file| {
                let bytes = std::fs::read(&file).unwrap();
                (file, bytes)
            })
            .collect()
    }

    /// Rotates `writer`'s log until the active file's rows sit in the oldest
    /// of [`MAX_ROTATED_FILES`] archives.
    fn push_to_oldest_archive(writer: &AuditWriterHandle, path: &Path) {
        let mut writer = writer.lock().unwrap();
        for _ in 0..MAX_ROTATED_FILES {
            rotate(&mut writer, path);
        }
        assert_eq!(rotated_archives_newest_first(path).len(), MAX_ROTATED_FILES);
    }

    fn settlement(writer: &AuditWriterHandle, hash: &str) -> ValueActionSettlement {
        try_value_action_settlement(&writer.lock().unwrap(), hash).unwrap()
    }

    /// An audit timestamp `age_ms` before the wall clock.
    fn audit_ts_before_now(age_ms: u64) -> String {
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let then_ms = now_ms - age_ms;
        let (year, month, day, hour, min, sec) =
            stellar_agent_core::timefmt::epoch_to_datetime(then_ms / 1000);
        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{:03}Z",
            then_ms % 1000
        )
    }

    /// The refusal a resend meets: the duplicate code, nothing sent, the
    /// audit bytes unchanged, and the fresh grant still open.
    async fn assert_resend_refused(
        fx: &AuthorizedSubmissionFixture,
        server: &MockServer,
        result: Result<SubmissionResult, WalletError>,
        fresh: stellar_agent_network::mainnet::AuthorizationId,
        sends_before: usize,
        bytes_before: &[(PathBuf, Vec<u8>)],
    ) {
        let error = result.expect_err("the resend is refused");
        assert_eq!(error.code(), ALREADY_SUBMITTED, "{error}");
        assert_eq!(
            sends(server).await,
            sends_before,
            "the resend sends nothing"
        );
        assert_eq!(
            audit_bytes(fx.audit_log_path()),
            bytes_before,
            "no pending or closing row is appended"
        );
        assert!(fx.is_open(fresh), "the fresh grant stays unused");
        assert_eq!(fx.holds_recorded(), 0, "no grant holds anything");
    }

    /// An original sent through the authorized path, with no holds, whose
    /// receipt is lost and whose authorization record the ledger has dropped,
    /// sits in the oldest retained archive. Its resend under a fresh grant
    /// is refused before any send or row.
    #[tokio::test]
    #[serial]
    async fn an_authorized_original_past_ledger_retention_refuses_its_resend() {
        let mut fx = AuthorizedSubmissionFixture::new("bound-authorized-original", NOW);
        let envelope = fx.envelope(100, NOW / 1000 + 30 * 86_400);
        let (server, client) = endpoint(&envelope).await;
        let hash = envelope_hash_hex(envelope.signed.envelope_xdr());
        let (original, grant) = fx.grant(&envelope, &client, None, "approval-original");
        let recorder = fx.recorder(None, fx.writer());
        submit(&client, &envelope, &recorder, grant)
            .await
            .expect("the original submits");
        assert_eq!(sends(&server).await, 1);
        assert!(!fx.is_open(original), "the original grant is used");
        assert!(matches!(
            settlement(&fx.writer(), &hash),
            ValueActionSettlement::Owed(_)
        ));

        push_to_oldest_archive(&fx.writer(), fx.audit_log_path());
        if let Some(receipts) = fx.receipts_file() {
            std::fs::remove_file(receipts).unwrap();
        }
        fx.set_now(NOW + AFTER_LEDGER_RETENTION_MS);
        let (fresh, grant) = fx.grant(&envelope, &client, None, "approval-resend");
        assert!(
            !fx.is_recorded(original),
            "the ledger keeps no record of the original authorization"
        );
        let bytes_before = audit_bytes(fx.audit_log_path());

        let recorder = fx.recorder(None, fx.writer());
        let result = submit(&client, &envelope, &recorder, grant).await;

        assert_resend_refused(&fx, &server, result, fresh, 1, &bytes_before).await;
        assert!(matches!(
            settlement(&fx.writer(), &hash),
            ValueActionSettlement::Owed(_)
        ));
    }

    /// An original pending row thirty days old, as the authorized path
    /// writes it, sits in the oldest retained archive. No receipt, hold, or
    /// ledger record protects it. Its resend under a fresh grant is refused
    /// before any send or row.
    #[tokio::test]
    #[serial]
    async fn an_aged_original_in_the_oldest_archive_refuses_an_authorized_resend() {
        aged_original_refuses_its_resend("bound-aged-original", 0).await;
    }

    /// The aged original sits in the oldest of the archives a stopped prune
    /// keeps past [`MAX_ROTATED_FILES`], and its resend is refused the same
    /// way.
    #[tokio::test]
    #[serial]
    async fn an_aged_original_past_stopped_pruning_refuses_an_authorized_resend() {
        aged_original_refuses_its_resend("bound-aged-excess", 2).await;
    }

    /// Writes a thirty-day-old original, pushes it to the oldest archive,
    /// keeps `excess` more archives through stopped prunes, and resends.
    async fn aged_original_refuses_its_resend(label: &str, excess: usize) {
        let fx = AuthorizedSubmissionFixture::new(label, NOW);
        let envelope = fx.envelope(100, NOW / 1000 + 30 * 86_400);
        let (server, client) = endpoint(&envelope).await;
        let hash = envelope_hash_hex(envelope.signed.envelope_xdr());
        let mut aged = pending(&hash);
        aged.tool = "stellar_pay_commit".to_owned();
        aged.ts = audit_ts_before_now(30 * DAY_MS);
        fx.writer().lock().unwrap().write_entry(aged).unwrap();
        push_to_oldest_archive(&fx.writer(), fx.audit_log_path());
        {
            let writer = fx.writer();
            let mut writer = writer.lock().unwrap();
            writer.stop_prune_removal_for_test(true);
            for _ in 0..excess {
                rotate(&mut writer, fx.audit_log_path());
            }
            writer.stop_prune_removal_for_test(false);
        }
        let archives = rotated_archives_newest_first(fx.audit_log_path());
        assert_eq!(archives.len(), MAX_ROTATED_FILES + excess);
        assert!(
            std::fs::read_to_string(archives.last().unwrap())
                .unwrap()
                .contains(&hash),
            "the original sits in the oldest retained archive"
        );
        assert!(fx.receipts_file().is_none_or(|file| !file.exists()));

        let (fresh, grant) = fx.grant(&envelope, &client, None, "approval-resend");
        let bytes_before = audit_bytes(fx.audit_log_path());
        let recorder = fx.recorder(None, fx.writer());
        let result = submit(&client, &envelope, &recorder, grant).await;

        assert_resend_refused(&fx, &server, result, fresh, 0, &bytes_before).await;
    }

    /// Submitted and failed settlement rows keep the caller's behavior with
    /// a lost receipt: the lookup reports the original settled, so the
    /// precheck lets the resend through and it is sent once.
    #[tokio::test]
    #[serial]
    async fn a_settled_original_with_a_lost_receipt_lets_the_resend_through() {
        for (label, amount) in [("submitted", 100), ("failed", 200)] {
            let fx = AuthorizedSubmissionFixture::new(&format!("bound-settled-{label}"), NOW);
            let envelope = fx.envelope(amount, NOW / 1000 + 30 * 86_400);
            let (server, client) = endpoint(&envelope).await;
            let hash = envelope_hash_hex(envelope.signed.envelope_xdr());
            {
                let writer = fx.writer();
                let mut writer = writer.lock().unwrap();
                writer.write_entry(pending(&hash)).unwrap();
                writer.write_entry(closing(label, &hash)).unwrap();
                rotate(&mut writer, fx.audit_log_path());
            }
            assert_eq!(
                settlement(&fx.writer(), &hash),
                ValueActionSettlement::Settled
            );

            let (fresh, grant) = fx.grant(&envelope, &client, None, "approval-resend");
            let recorder = fx.recorder(None, fx.writer());
            let result = submit(&client, &envelope, &recorder, grant).await;

            result.unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(sends(&server).await, 1, "{label}");
            assert!(!fx.is_open(fresh), "{label}: the fresh grant is used");
        }
    }

    /// A writer whose index the lookup builds through the bounded walk reads
    /// only to its tip: a failed row appended past the tip, outside the
    /// writer, leaves the owed original refusing its resend.
    #[tokio::test]
    #[serial]
    async fn a_lazily_indexed_writer_reads_only_to_its_tip_on_the_authorized_path() {
        let fx = AuthorizedSubmissionFixture::new("bound-lazy-tip", NOW);
        let envelope = fx.envelope(100, NOW / 1000 + 30 * 86_400);
        let (server, client) = endpoint(&envelope).await;
        let hash = envelope_hash_hex(envelope.signed.envelope_xdr());
        let path = fx.dir().join("lazy.jsonl");
        // Without an anchor store the writer runs no verification walk, so
        // the first lookup builds its index.
        let mut writer =
            AuditWriter::open_keyed_unanchored_for_test(path.clone(), zeroize::Zeroizing::new(KEY))
                .unwrap();
        writer.write_entry(pending(&hash)).unwrap();
        rotate(&mut writer, &path);
        writer.write_entry(pending(&hash)).unwrap();
        let lazy: AuditWriterHandle = Arc::new(Mutex::new(writer));
        append_forged_entry(&path, closing("failed", &hash), |_| None);
        let bytes_before = audit_bytes(&path);

        let (fresh, grant) = fx.grant(&envelope, &client, None, "approval-resend");
        let recorder = fx.recorder(None, Arc::clone(&lazy));
        let result = submit(&client, &envelope, &recorder, grant).await;

        let error = result.expect_err("the resend is refused");
        assert_eq!(error.code(), ALREADY_SUBMITTED, "{error}");
        assert_eq!(sends(&server).await, 0);
        assert_eq!(audit_bytes(&path), bytes_before);
        assert!(fx.is_open(fresh));
    }

    /// The fixture's ledger inspection fails on a window store it cannot
    /// read or decode, rather than reporting no record and no hold.
    #[tokio::test]
    #[serial]
    async fn ledger_inspection_fails_on_an_unreadable_window_store() {
        let fx = AuthorizedSubmissionFixture::new("bound-inspection", NOW);
        let envelope = fx.envelope(100, NOW / 1000 + 30 * 86_400);
        let (_server, client) = endpoint(&envelope).await;
        let (id, _grant) = fx.grant(&envelope, &client, Some(100), "approval-inspect");
        assert!(fx.is_recorded(id));
        assert_eq!(fx.holds_recorded(), 1);

        let store = fx.window_store_path().to_path_buf();
        let tag = vec![0u8; 32];
        let fails = |damage: &str| {
            for (inspection, result) in [
                (
                    "is_recorded",
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = fx.is_recorded(id);
                    })),
                ),
                (
                    "holds_recorded",
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = fx.holds_recorded();
                    })),
                ),
            ] {
                assert!(result.is_err(), "{inspection} fails on {damage}");
            }
        };
        std::fs::write(&store, &tag[..10]).unwrap();
        fails("a truncated store");
        std::fs::write(&store, [tag.as_slice(), b"{not json"].concat()).unwrap();
        fails("a body that does not decode");
        std::fs::write(&store, [tag.as_slice(), b"[]"].concat()).unwrap();
        fails("a body that is not an object");
        std::fs::write(
            &store,
            [tag.as_slice(), br#"{"authorizations":5,"holds":5}"#].concat(),
        )
        .unwrap();
        fails("lists of the wrong shape");
        std::fs::write(
            &store,
            [tag.as_slice(), br#"{"authorizations":[{}],"holds":[{}]}"#].concat(),
        )
        .unwrap();
        fails("entries without their fields");

        // Malformed scalars: each inspection names the field it rejects.
        let message = |inspect: &dyn Fn()| -> String {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(inspect))
                .expect_err("a malformed field fails the inspection");
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_default()
        };
        let hex = "ab".repeat(32);
        for (damage, body, recorded_field, holds_field) in [
            (
                "numeric identifiers",
                r#"{"authorizations":[{"id":7,"state":"open"}],"holds":[{"authorization_id":7,"amount":"1"}]}"#.to_owned(),
                "authorizations[0].id",
                "holds[0].authorization_id",
            ),
            (
                "an unknown state and a non-decimal amount",
                format!(
                    r#"{{"authorizations":[{{"id":"{hex}","state":"pending"}}],"holds":[{{"authorization_id":"{hex}","amount":"1.5"}}]}}"#
                ),
                "authorizations[0].state",
                "holds[0].amount",
            ),
            (
                "an amount that is a number",
                format!(
                    r#"{{"authorizations":[{{"id":"{hex}","state":"used"}}],"holds":[{{"authorization_id":"{hex}","amount":100}}]}}"#
                ),
                "",
                "holds[0].amount",
            ),
        ] {
            std::fs::write(&store, [tag.as_slice(), body.as_bytes()].concat()).unwrap();
            if !recorded_field.is_empty() {
                let text = message(&|| {
                    let _ = fx.is_recorded(id);
                });
                assert!(text.contains(recorded_field), "{damage}: is_recorded: {text}");
            }
            let text = message(&|| {
                let _ = fx.holds_recorded();
            });
            assert!(text.contains(holds_field), "{damage}: holds_recorded: {text}");
        }

        std::fs::remove_file(&store).unwrap();
        std::fs::create_dir(&store).unwrap();
        fails("a store that does not read");
    }

    /// A submitted or failed row closing `envelope_hash`.
    fn closing(kind: &str, envelope_hash: &str) -> AuditEntry {
        if kind == "submitted" {
            AuditEntry::new_value_action_submitted(
                "stellar_pay_commit",
                Some("stellar:pubnet".to_owned()),
                vec![],
                "6ba7aaac...69060003",
                9,
                PolicyDecision::Allow,
                Some(envelope_hash.to_owned()),
                None,
                None,
                "req-submitted",
                None,
            )
        } else {
            AuditEntry::new_value_action_failed(
                "stellar_pay_commit",
                Some("stellar:pubnet".to_owned()),
                vec![],
                "6ba7aaac...69060003",
                "submission.failed",
                PolicyDecision::Allow,
                Some(envelope_hash.to_owned()),
                None,
                None,
                "req-failed",
            )
        }
    }
}
