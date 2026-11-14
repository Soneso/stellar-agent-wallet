//! Checked receipt repair: the receipt of each retained committed recovery
//! decision, projected from the verified window and acknowledged on it.
//!
//! The receipt is display data. The authenticated projection marker on the
//! decision, never the receipt, admits a successor attempt.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::profile::receipt::{
    CheckedReceiptProjection, ReceiptStore, ReceiptStoreError,
};
use stellar_agent_core::profile::schema::Profile;

use crate::policy_state::{
    CommitId, CommittedDecision, OperationRecorder, OperationStatus, PersistedWindowStore,
    WindowStoreError,
};

/// The maximum number of repair decisions named in a diagnostic detail.
const REPAIR_DECISION_DETAIL_LIMIT: usize = 16;

/// A checked receipt repair pass that refuses at least one decision, or
/// refuses its verified read.
///
/// It retains every repaired and refused decision. Its display names the
/// first `REPAIR_DECISION_DETAIL_LIMIT` decisions with exact total counts.
/// Each displayed refusal carries its code and detail. It holds no receipt
/// or window content.
#[derive(Debug)]
pub(crate) struct RepairRefused {
    repaired: Vec<CommitId>,
    /// Each refusal in pass order; `None` names the verified read.
    refused: Vec<(Option<CommitId>, WalletError)>,
    /// The bounded prefix of decisions in their stored order.
    displayed: Vec<CommitId>,
}

impl RepairRefused {
    /// The first refusal's stable code.
    pub(crate) fn code(&self) -> &'static str {
        self.refused
            .first()
            .map_or("submission.record_unavailable", |(_, error)| error.code())
    }
}

/// The detail of `error` without the pre-send wording of its display: the
/// inner detail of a record refusal, or the display of any other error.
fn refusal_detail(error: &WalletError) -> String {
    match error {
        WalletError::Submission(SubmissionError::RecordUnavailable { detail }) => detail.clone(),
        other => other.to_string(),
    }
}

impl std::fmt::Display for RepairRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = |commits: &[CommitId]| {
            commits
                .iter()
                .filter(|commit| self.displayed.contains(commit))
                .map(CommitId::to_hex)
                .collect::<Vec<_>>()
                .join(", ")
        };
        write!(
            f,
            "checked receipt repair: {} repaired [{}], {} refused",
            self.repaired.len(),
            hex(&self.repaired),
            self.refused.len()
        )?;
        for (commit, error) in &self.refused {
            if commit.is_some_and(|commit| !self.displayed.contains(&commit)) {
                continue;
            }
            let subject = commit.map_or_else(
                || "the verified window read".to_owned(),
                |commit| format!("decision {}", commit.to_hex()),
            );
            write!(
                f,
                "; {subject} refused with {}: {}",
                error.code(),
                refusal_detail(error)
            )?;
        }
        let omitted = self.repaired.len()
            + self
                .refused
                .iter()
                .filter(|(commit, _)| commit.is_some())
                .count()
            - self.displayed.len();
        if omitted > 0 {
            write!(f, "; and {omitted} more decisions")?;
        }
        Ok(())
    }
}

/// Projects the receipt of every retained committed recovery decision, then
/// acknowledges each projection on its decision.
///
/// One verified window read enumerates the decisions, acknowledged ones
/// included; `tx_hash` selects one attempt's decision. A refused read
/// projects nothing. Each decision is attempted in turn, and the next
/// decision still runs after a refusal.
///
/// A refused projection or a refusal before the receipt rename leaves that
/// decision's durable receipt and marker unchanged. A refusal after the
/// rename can leave the complete replacement visible with the marker unset.
/// An acknowledgement that reaches its window commit point keeps its true
/// marker even when an error returns.
///
/// After a replacement succeeds and the receipt lock is released, the exact
/// operation, attempt and commit are acknowledged. A decision already
/// acknowledged keeps its marker, and its repeated acknowledgement commits
/// nothing; its receipt is still repaired. Repair makes no RPC request,
/// changes no accounting or native release, and appends no audit row.
///
/// # Errors
///
/// [`RepairRefused`] after every decision is attempted, retaining the repaired
/// and refused decisions; its first refusal is the earliest. An
/// incomplete decision refuses with `submission.record_unavailable` and
/// detail `missing_projection_fact:<field>`. A replacement or an
/// acknowledgement refuses with its receipt-store or window-store refusal.
pub(crate) fn repair_committed_receipts(
    window: &PersistedWindowStore,
    profile: &Profile,
    receipts: &ReceiptStore,
    writer: &Arc<Mutex<AuditWriter>>,
    tx_hash: Option<&[u8; 32]>,
) -> Result<(), RepairRefused> {
    #[cfg(test)]
    tests::trace("repair");
    let decisions = OperationStatus::new(window, profile)
        .committed_decisions(tx_hash)
        .map_err(|error| RepairRefused {
            repaired: Vec::new(),
            refused: vec![(None, window_refusal(&error))],
            displayed: Vec::new(),
        })?;
    let mut repaired = Vec::new();
    let mut refused = Vec::new();
    for decision in &decisions {
        match repair_proof(
            window,
            profile,
            receipts,
            writer,
            decision,
            decision.receipt_projection(),
        ) {
            Ok(()) => repaired.push(decision.commit_id),
            Err(error) => refused.push((Some(decision.commit_id), error)),
        }
    }
    if refused.is_empty() {
        Ok(())
    } else {
        Err(RepairRefused {
            repaired,
            refused,
            displayed: decisions
                .iter()
                .take(REPAIR_DECISION_DETAIL_LIMIT)
                .map(|decision| decision.commit_id)
                .collect(),
        })
    }
}

/// Repairs one decision: replaces its receipt with `projection`, then
/// acknowledges the decision. An acknowledgement of a set marker commits
/// nothing. A refused projection or a refusal before the receipt rename
/// leaves the durable receipt and the marker unchanged; a refusal after the
/// rename can leave the replacement visible with the marker unset.
fn repair_proof(
    window: &PersistedWindowStore,
    profile: &Profile,
    receipts: &ReceiptStore,
    writer: &Arc<Mutex<AuditWriter>>,
    decision: &CommittedDecision,
    projection: Result<CheckedReceiptProjection, WalletError>,
) -> Result<(), WalletError> {
    #[cfg(test)]
    tests::trace("proof");
    receipts
        .replace_checked(&projection?)
        .map_err(|error| receipt_refusal(&error))?;
    #[cfg(test)]
    tests::after_replacement()?;
    let mut guard = writer.lock().map_err(|_| {
        record_unavailable("the audit writer mutex is poisoned; acknowledgement is unavailable")
    })?;
    OperationRecorder::new(
        window,
        profile,
        &mut *guard,
        uuid::Uuid::new_v4().to_string(),
    )
    .acknowledge_projection(
        decision.operation_id,
        decision.attempt_index,
        decision.commit_id,
    )
    .map_err(|error| window_refusal(&error))
}

fn record_unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Submission(SubmissionError::RecordUnavailable {
        detail: detail.into(),
    })
}

fn window_refusal(error: &WindowStoreError) -> WalletError {
    record_unavailable(format!(
        "the spending-window state could not be read or written: {error}"
    ))
}

fn receipt_refusal(error: &ReceiptStoreError) -> WalletError {
    record_unavailable(format!("the checked receipt could not be written: {error}"))
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use std::fs;

    use serde_json::json;
    use serial_test::serial;
    use stellar_agent_core::audit_log::tip_anchor::{
        InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
    };
    use stellar_agent_core::profile::receipt::{
        AccountingExpiryProjection, BeginSubmissionOutcome, ReceiptStatus, ReleaseEvidence,
        SubmissionReceipt,
    };
    use stellar_agent_test_support::{EchoIdResponder, StellarAgentHomeGuard};
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};

    use super::*;
    use crate::StellarRpcClient;
    use crate::policy_state::operations::ReceiptProjectionIdentity;
    use crate::policy_state::operations::tests::{
        CONSUMED_LEDGER, Checked, FAILED_CODE, Fx, PROJECTED_LEDGER, accounting_state,
        checked_transition, commit_approved, commit_checked, commit_on, consumed_ledger,
        consumed_zero_entry, decided_attempt, envelope_id, expire_reservation, exposure_facts,
        exposure_keys, failed_result_xdr, forget_failure_code, historical_without, retained_result,
        successor_attempt, successor_refusal, unknown_named, zero_entry_committed,
    };
    use crate::policy_state::{
        CommitId, RECONCILE_BUDGET, RecoveryError, store::arm_accounting_fault,
    };
    use crate::submission_flow::{
        ReconcilePass, StatusFailure, StatusOutcome, StatusRequest, finish_reconciliation,
        reconcile_legacy_pass, reconcile_pass, transaction_status,
    };

    /// The fixed store clock of [`Fx`].
    const T0: u64 = 1_800_000_000_000;
    /// The source account every [`Fx`] binding names.
    const SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM";

    type ReplacementHook = Box<dyn FnMut() -> Result<(), WalletError>>;

    thread_local! {
        static AFTER_REPLACEMENT: std::cell::RefCell<Option<ReplacementHook>> = std::cell::RefCell::new(None);
        static TRACE: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Records a reconciliation step on this thread.
    pub(crate) fn trace(step: &'static str) {
        TRACE.with_borrow_mut(|trace| trace.push(step));
    }

    /// Runs the armed hook between a replacement and its acknowledgement.
    pub(super) fn after_replacement() -> Result<(), WalletError> {
        let Some(mut hook) = AFTER_REPLACEMENT.with_borrow_mut(Option::take) else {
            return Ok(());
        };
        let result = hook();
        AFTER_REPLACEMENT.with_borrow_mut(|slot| {
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
        result
    }

    /// Disarms the replacement hook on this thread when dropped.
    pub(crate) struct ArmedReplacement;
    impl Drop for ArmedReplacement {
        fn drop(&mut self) {
            AFTER_REPLACEMENT.with_borrow_mut(|hook| *hook = None);
        }
    }

    /// Runs `hook` between each replacement and its acknowledgement on this
    /// thread until the returned guard drops.
    pub(crate) fn on_replacement(
        hook: impl FnMut() -> Result<(), WalletError> + 'static,
    ) -> ArmedReplacement {
        AFTER_REPLACEMENT.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
        ArmedReplacement
    }

    /// Takes the steps this thread recorded.
    pub(crate) fn take_trace() -> Vec<&'static str> {
        TRACE.with_borrow_mut(std::mem::take)
    }

    /// A keyed, anchored audit writer over a log at `path`.
    pub(crate) fn writer_at(path: &std::path::Path) -> Arc<Mutex<AuditWriter>> {
        let anchors = Arc::new(InMemoryTipAnchorStore::new());
        let access = KeyedAuditAccess::new(
            zeroize::Zeroizing::new([0x5c; 32]),
            anchors as Arc<dyn TipAnchorStore>,
        );
        Arc::new(Mutex::new(
            AuditWriter::open(path.to_path_buf(), Some(access)).unwrap(),
        ))
    }

    /// Holds the receipt store's sidecar lock until the returned file drops.
    fn hold_receipt_lock(receipts: &ReceiptStore) -> fs::File {
        let held = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(receipts.lock_file_path().unwrap())
            .unwrap();
        held.try_lock().unwrap();
        held
    }

    fn tx_hash(n: u8) -> [u8; 32] {
        [n ^ 0x80; 32]
    }

    fn tx_hex(n: u8) -> String {
        stellar_agent_core::hex::encode(&tx_hash(n))
    }

    /// The status, ledger and release code of a checked `checked` receipt.
    fn expected(checked: Checked) -> (ReceiptStatus, Option<u32>, Option<ReleaseEvidence>) {
        match checked {
            Checked::Succeeded => (ReceiptStatus::Success, Some(120), None),
            Checked::Failed => (
                ReceiptStatus::Failed {
                    code: FAILED_CODE.to_owned(),
                },
                Some(120),
                None,
            ),
            Checked::NotIncluded => (
                ReceiptStatus::Ambiguous,
                None,
                Some(ReleaseEvidence::ReleasedOnEvidence),
            ),
        }
    }

    fn outcome(
        receipt: &SubmissionReceipt,
    ) -> (ReceiptStatus, Option<u32>, Option<ReleaseEvidence>) {
        (receipt.status.clone(), receipt.ledger, receipt.release_code)
    }

    /// Asserts that `receipt` names attempt `n` at `sequence` and decision
    /// `commit`, submitted and not recovered from a reservation.
    fn assert_linked(receipt: &SubmissionReceipt, n: u8, sequence: i64, commit: CommitId) {
        assert_eq!(
            (
                receipt.envelope_hash.as_str(),
                receipt.tx_hash.as_str(),
                receipt.source.as_str(),
                receipt.sequence,
                receipt.max_time,
            ),
            (
                envelope_id(n).as_str(),
                tx_hex(n).as_str(),
                SOURCE,
                sequence,
                T0 / 1_000 + 60,
            ),
            "the receipt names attempt {n}"
        );
        assert_eq!(
            receipt.settlement_decision_id.as_deref(),
            Some(commit.to_hex().as_str())
        );
        assert!(receipt.submitted && !receipt.recovered_from_reservation);
    }

    /// A window fixture with its receipt store under a temporary home and a
    /// keyed writer.
    struct Rig {
        fx: Fx,
        receipts: ReceiptStore,
        writer: Arc<Mutex<AuditWriter>>,
        home: tempfile::TempDir,
        _guard: StellarAgentHomeGuard,
    }

    impl Rig {
        fn new() -> Self {
            let fx = Fx::new();
            let home = tempfile::tempdir().unwrap();
            let guard = StellarAgentHomeGuard::new(home.path());
            let receipts = crate::submission_flow::open_receipts("ops").unwrap();
            let writer = writer_at(&fx.profile.audit_log_path);
            Self {
                fx,
                receipts,
                writer,
                home,
                _guard: guard,
            }
        }

        fn repair(&self, n: Option<u8>) -> Result<(), RepairRefused> {
            let hash = n.map(tx_hash);
            repair_committed_receipts(
                &self.fx.store,
                &self.fx.profile,
                &self.receipts,
                &self.writer,
                hash.as_ref(),
            )
        }

        fn decision(&self, n: u8) -> CommittedDecision {
            let mut decisions = OperationStatus::new(&self.fx.store, &self.fx.profile)
                .committed_decisions(Some(&tx_hash(n)))
                .unwrap();
            assert_eq!(decisions.len(), 1);
            decisions.pop().unwrap()
        }

        fn projected(&self, n: u8) -> bool {
            self.decision(n).projected
        }

        fn receipt(&self, n: u8) -> Option<SubmissionReceipt> {
            self.receipts.get(&envelope_id(n)).unwrap()
        }

        fn receipt_bytes(&self) -> Vec<u8> {
            fs::read(self.receipts.file_path().unwrap()).unwrap_or_default()
        }

        fn window_bytes(&self) -> Vec<u8> {
            fs::read(self.fx.store.path()).unwrap()
        }

        fn audit_bytes(&self) -> Vec<u8> {
            fs::read(&self.fx.profile.audit_log_path).unwrap_or_default()
        }

        /// Reopens the window and receipt stores from their files.
        fn reopen(&mut self) {
            self.fx.store = PersistedWindowStore::at_path(self.fx.store.path().to_owned());
            self.receipts = crate::submission_flow::open_receipts("ops").unwrap();
        }

        /// Edits the receipt file's JSON map directly.
        fn edit_receipts(
            &self,
            change: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
        ) {
            let path = self.receipts.file_path().unwrap();
            let mut map: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            change(&mut map);
            fs::write(&path, serde_json::to_vec_pretty(&map).unwrap()).unwrap();
        }

        /// The profile's pending approval store file.
        fn approvals_path(&self) -> std::path::PathBuf {
            self.home.path().join("approvals").join("ops.toml")
        }

        /// Inserts a pending payment approval under `nonce` into the
        /// profile's approval store.
        fn seed_pending_approval(&self, nonce: &str) {
            use stellar_agent_core::approval::{PendingApproval, PendingApprovalStore};
            let path = self.approvals_path();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut store = PendingApprovalStore::open(path).unwrap();
            let mut entry = PendingApproval::new_payment_pending(
                "AAAA".to_owned(),
                b"AAAA",
                crate::operation_entry::tests::DESTINATION.to_owned(),
                25,
                "XLM".to_owned(),
                None,
                100,
                101,
                "1000".to_owned(),
                600_000,
            )
            .unwrap();
            entry.approval_nonce = nonce.to_owned();
            store
                .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
                .unwrap();
        }

        /// The kind of the approval under `nonce`, read from a freshly
        /// opened store.
        fn approval_kind(&self, nonce: &str) -> Option<stellar_agent_core::approval::ApprovalKind> {
            stellar_agent_core::approval::PendingApprovalStore::open(self.approvals_path())
                .unwrap()
                .get(nonce)
                .map(|entry| entry.kind.clone())
        }

        /// Asserts that the approval under `nonce` is a durable consumption of
        /// attempt `n`'s transaction.
        fn assert_approval_consumed(&self, nonce: &str, n: u8) {
            let kind = self.approval_kind(nonce);
            assert!(
                matches!(
                    &kind,
                    Some(stellar_agent_core::approval::ApprovalKind::Consumed { tx_hash, .. })
                        if *tx_hash == tx_hex(n)
                ),
                "the approval store holds the consumed tombstone: {kind:?}"
            );
        }

        /// Writes a sent pending receipt for attempt `n` at `sequence`.
        fn legacy_receipt(&self, n: u8, sequence: i64) {
            self.receipts
                .begin_submission(&envelope_id(n), &tx_hex(n), SOURCE, sequence, 0, 1)
                .unwrap();
            self.receipts.mark_submitted(&envelope_id(n)).unwrap();
        }

        /// Alters attempt `n`'s committed outcome in the window file without
        /// updating its HMAC tag.
        fn tamper(&self, n: u8) {
            let path = self.fx.store.path();
            let bytes = fs::read(path).unwrap();
            let mut wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
            let hex = tx_hex(n);
            for record in wire["operations"]["records"].as_array_mut().unwrap() {
                for attempt in record["attempts"].as_array_mut().unwrap() {
                    if attempt["exposure"]["identity"]["classic"]["tx_hash"] == hex.as_str() {
                        attempt["outcome"] = json!("succeeded");
                    }
                }
            }
            let mut tampered = bytes[..32].to_vec();
            tampered.extend(serde_json::to_vec(&wire).unwrap());
            fs::write(path, tampered).unwrap();
        }

        async fn status(
            &self,
            n: u8,
            client: &StellarRpcClient,
        ) -> Result<StatusOutcome, StatusFailure> {
            let hex = tx_hex(n);
            let approvals = self.home.path().join("approvals");
            transaction_status(
                StatusRequest {
                    profile: &self.fx.profile,
                    profile_name: "ops",
                    tx_hash: &hex,
                    window: &self.fx.store,
                    client,
                    oracle: None,
                },
                || Ok(approvals),
                || Ok(Arc::clone(&self.writer)),
            )
            .await
        }

        async fn dispatch(
            &self,
            client: &StellarRpcClient,
            receipts: Option<&ReceiptStore>,
            legacy_only: bool,
        ) -> ReconcilePass {
            let writer = || Ok(Arc::clone(&self.writer));
            if legacy_only {
                reconcile_legacy_pass(
                    &self.fx.profile,
                    &self.fx.store,
                    client,
                    None,
                    receipts,
                    T0,
                    writer,
                )
                .await
            } else {
                reconcile_pass(
                    &self.fx.profile,
                    &self.fx.store,
                    client,
                    None,
                    receipts,
                    T0,
                    writer,
                )
                .await
            }
        }
    }

    /// A primary endpoint that answers `getTransaction` with `NOT_FOUND`.
    async fn endpoint() -> (MockServer, StellarRpcClient) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getTransaction"})))
            .respond_with(EchoIdResponder::new(json!({
                "status": "NOT_FOUND", "latestLedger": 7, "oldestLedger": 1,
                "latestLedgerCloseTime": (T0 / 1_000).to_string(),
                "oldestLedgerCloseTime": "1",
            })))
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        (server, client)
    }

    async fn requests(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[tokio::test]
    #[serial]
    async fn recovery_dispatch_keeps_both_refusals() {
        let mut rig = Rig::new();
        unknown_named(&mut rig.fx, 1);
        let (_, missing_ledger) =
            historical_without(&mut rig.fx, 2, Checked::NotIncluded, "submission_ledger");
        let (_, repaired) = commit_checked(&mut rig.fx, 3, Checked::Succeeded);
        let (_, missing_source) =
            historical_without(&mut rig.fx, 4, Checked::NotIncluded, "source");
        rig.reopen();
        let (primary, client) = endpoint().await;
        let (oracle, oracle_client) = endpoint().await;
        for (server, passphrase) in [
            (
                &primary,
                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            ),
            (&oracle, "wrong"),
        ] {
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method": "getNetwork"})))
                .respond_with(EchoIdResponder::new(
                    stellar_agent_test_support::signed_envelope::get_network_result(passphrase),
                ))
                .mount(server)
                .await;
        }
        for _ in 0..2 {
            let pass = reconcile_pass(
                &rig.fx.profile,
                &rig.fx.store,
                &client,
                Some(&oracle_client),
                Some(&rig.receipts),
                T0,
                || Ok(Arc::clone(&rig.writer)),
            )
            .await;
            let ReconcilePass::RecoveryFailed { error, .. } = &pass else {
                panic!("both stages refuse: {pass:?}");
            };
            assert_eq!(error.code(), "network.witness_unavailable");
            let detail = error.to_string();
            for (commit, fragment) in [
                (
                    repaired,
                    format!("1 repaired [{}], 2 refused", repaired.to_hex()),
                ),
                (
                    missing_ledger,
                    format!(
                        "decision {} refused with submission.record_unavailable: missing_projection_fact:submission_ledger",
                        missing_ledger.to_hex()
                    ),
                ),
                (
                    missing_source,
                    format!(
                        "decision {} refused with submission.record_unavailable: missing_projection_fact:source",
                        missing_source.to_hex()
                    ),
                ),
            ] {
                assert!(
                    detail.contains(&fragment),
                    "complete repair detail: {detail}"
                );
                assert_eq!(detail.matches(&commit.to_hex()).count(), 1);
            }
            let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
            finish_reconciliation(
                &rig.fx.profile,
                "ops",
                &rig.fx.store,
                Some(&rig.receipts),
                &pass,
                || Ok(Arc::clone(&rig.writer)),
            )
            .unwrap();
            drop(guard);
            let seen = warnings.seen();
            let logged = seen
                .iter()
                .find(|fields| fields.get("error") == Some(&detail))
                .unwrap();
            assert_eq!(
                logged.get("code").map(String::as_str),
                Some("\"network.witness_unavailable\"")
            );
            assert_eq!(
                logged.get("message").map(String::as_str),
                Some("recovery: the stage refused; every sequence stays held"),
                "a refusal before a sequence commit keeps the all-held warning"
            );
            assert!(rig.projected(3) && !rig.projected(2) && !rig.projected(4));
            rig.reopen();
        }
        assert_eq!(requests(&primary).await, 2);
        assert_eq!(requests(&oracle).await, 2);
    }

    fn assert_bounded_repair_detail(count: u8) {
        let mut rig = Rig::new();
        for n in 1..=count {
            historical_without(&mut rig.fx, n, Checked::Succeeded, "source");
        }
        let decisions = OperationStatus::new(&rig.fx.store, &rig.fx.profile)
            .committed_decisions(None)
            .unwrap();
        assert_eq!(decisions.len(), usize::from(count));
        let refused = rig.repair(None).unwrap_err();
        let error = RecoveryError::Store(WindowStoreError::Invalid {
            detail: "sequence commit refused".to_owned(),
        })
        .with_context(refused.to_string());
        let RecoveryError::Context { detail, .. } = &error else {
            panic!("the repair report supplies error context");
        };
        let mut expected = format!("checked receipt repair: 0 repaired [], {count} refused");
        for decision in &decisions[..16] {
            expected.push_str(&format!(
                "; decision {} refused with submission.record_unavailable: missing_projection_fact:source",
                decision.commit_id.to_hex()
            ));
        }
        expected.push_str(&format!("; and {} more decisions", count - 16));
        assert_eq!(
            detail, &expected,
            "the repair detail has the exact bounded text"
        );
        for decision in &decisions[16..] {
            assert!(
                !error.to_string().contains(&decision.commit_id.to_hex()),
                "no decision beyond the stored prefix appears in the error"
            );
        }
    }

    #[test]
    #[serial]
    fn recovery_repair_detail_bounds_17_refusals() {
        assert_bounded_repair_detail(17);
    }

    #[test]
    #[serial]
    fn recovery_repair_detail_bounds_40_refusals() {
        assert_bounded_repair_detail(40);
    }

    #[test]
    #[serial]
    fn recovery_poisoned_writer_reports_unknown_acknowledgement() {
        let mut rig = Rig::new();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        commit_checked(&mut rig.fx, 2, Checked::Succeeded);
        rig.repair(Some(1)).unwrap();
        let before = (rig.window_bytes(), rig.audit_bytes());
        let anchors = Arc::clone(rig.writer.lock().unwrap().tip_anchor_store().unwrap());
        let writer = Arc::clone(&rig.writer);
        assert!(
            std::thread::spawn(move || {
                let _guard = writer.lock().unwrap();
                panic!("poison the writer");
            })
            .join()
            .is_err()
        );
        for _ in 0..2 {
            let error = rig.repair(None).unwrap_err();
            assert_eq!(error.code(), "submission.record_unavailable");
            let detail = error.to_string();
            assert_eq!(
                detail
                    .matches("the audit writer mutex is poisoned; acknowledgement is unavailable")
                    .count(),
                2,
                "a poisoned writer makes no marker-state claim: {detail}"
            );
            assert!(!detail.contains("stays owed"));
            assert!(rig.projected(1) && !rig.projected(2));
            assert!(rig.receipt(1).is_some() && rig.receipt(2).is_some());
            assert_eq!((rig.window_bytes(), rig.audit_bytes()), before);
            rig.reopen();
        }
        drop(rig.writer);
        rig.writer = Arc::new(Mutex::new(
            AuditWriter::open(
                rig.fx.profile.audit_log_path.clone(),
                Some(KeyedAuditAccess::new(
                    zeroize::Zeroizing::new([0x5c; 32]),
                    anchors,
                )),
            )
            .unwrap(),
        ));
        rig.repair(None).unwrap();
        assert!(rig.projected(1) && rig.projected(2));
        let after = (rig.window_bytes(), rig.receipt_bytes(), rig.audit_bytes());
        rig.reopen();
        rig.repair(None).unwrap();
        assert_eq!(
            (rig.window_bytes(), rig.receipt_bytes(), rig.audit_bytes()),
            after
        );
        assert_eq!(after.2, before.1);
    }

    /// Only committed attempts get a checked receipt. Missing and edited
    /// rows, acknowledged ones included, are restored after a restart, and
    /// receipt edits neither grant a retry nor redirect a proof.
    #[test]
    #[serial]
    fn recovery_receipt_projection_requires_committed_proof_and_repairs_after_restart() {
        let mut rig = Rig::new();
        let (_, success) = commit_checked(&mut rig.fx, 1, Checked::Succeeded);
        let (_, failure) = commit_checked(&mut rig.fx, 2, Checked::Failed);
        let (_, gone) = commit_checked(&mut rig.fx, 3, Checked::NotIncluded);
        let unknown = unknown_named(&mut rig.fx, 4);
        rig.repair(None).unwrap();
        assert!(rig.projected(1) && rig.projected(2) && rig.projected(3));
        let (late, _) = commit_checked(&mut rig.fx, 5, Checked::NotIncluded);

        // Remove one row, edit two acknowledged rows, and forge the
        // unacknowledged non-inclusion's projection.
        rig.edit_receipts(|map| {
            map.remove(&envelope_id(1));
            let failed = map.get_mut(&envelope_id(2)).unwrap();
            failed["status"] = json!({"state": "success"});
            failed["source"] = json!("GFORGED");
            let ambiguous = map.get_mut(&envelope_id(3)).unwrap();
            ambiguous["tx_hash"] = json!("00".repeat(32));
            ambiguous["settlement_decision_id"] = json!("ff".repeat(16));
            let mut forged = ambiguous.clone();
            forged["envelope_hash"] = json!(envelope_id(5));
            forged["tx_hash"] = json!(tx_hex(5));
            map.insert(envelope_id(5), forged);
        });
        assert_eq!(
            successor_refusal(&mut rig.fx, &late),
            "recovery.retry_refused",
            "a forged receipt grants no retry"
        );

        rig.reopen();
        rig.repair(None).unwrap();
        for (n, checked, commit) in [
            (1, Checked::Succeeded, success),
            (2, Checked::Failed, failure),
            (3, Checked::NotIncluded, gone),
        ] {
            let receipt = rig.receipt(n).unwrap();
            assert_eq!(outcome(&receipt), expected(checked), "attempt {n}");
            assert_linked(&receipt, n, 100 + i64::from(n), commit);
        }
        assert!(
            rig.receipts
                .find_by_tx_hash(&"00".repeat(32))
                .unwrap()
                .is_none(),
            "an edited row redirects no proof"
        );
        let mut keys: Vec<String> = rig
            .receipts
            .all()
            .unwrap()
            .into_iter()
            .map(|receipt| receipt.envelope_hash)
            .collect();
        keys.sort();
        let mut committed: Vec<String> = [1, 2, 3, 5].into_iter().map(envelope_id).collect();
        committed.sort();
        assert_eq!(keys, committed, "the uncommitted attempt gets no receipt");
        assert!(
            OperationStatus::new(&rig.fx.store, &rig.fx.profile)
                .committed_decisions(None)
                .unwrap()
                .iter()
                .all(|decision| decision.operation_id != unknown.id())
        );
        assert!(rig.projected(5));
    }

    /// A refused replacement leaves the receipt bytes and the unset marker,
    /// and the successor stays refused. Without the fault a restart
    /// completes the replacement and acknowledgement once.
    #[test]
    #[serial]
    fn recovery_projection_write_failure_keeps_retry_refused() {
        let mut rig = Rig::new();
        let (handle, commit) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        rig.legacy_receipt(1, 101);
        let before = rig.receipt_bytes();
        let held = hold_receipt_lock(&rig.receipts);
        let error = rig.repair(None).unwrap_err();
        assert_eq!(error.code(), "submission.record_unavailable");
        assert_eq!(rig.receipt_bytes(), before);
        assert!(!rig.projected(1), "the marker stays unset");
        assert_eq!(
            successor_refusal(&mut rig.fx, &handle),
            "recovery.retry_refused"
        );
        drop(held);

        rig.reopen();
        rig.repair(None).unwrap();
        assert!(rig.projected(1));
        let receipt = rig.receipt(1).unwrap();
        assert_eq!(outcome(&receipt), expected(Checked::NotIncluded));
        assert_linked(&receipt, 1, 101, commit);
        let (_, generation) = accounting_state(&rig.fx.store, &rig.fx.profile);
        let bytes = rig.receipt_bytes();
        rig.repair(None).unwrap();
        assert_eq!(
            accounting_state(&rig.fx.store, &rig.fx.profile).1,
            generation,
            "the acknowledgement commits once"
        );
        assert_eq!(rig.receipt_bytes(), bytes);
    }

    /// An acknowledgement refused after a durable replacement returns its
    /// error and keeps the receipt and the unset marker. The replay
    /// acknowledges without a second receipt write, release or audit row.
    #[test]
    #[serial]
    fn recovery_projection_ack_failure_replays_once() {
        let mut rig = Rig::new();
        let (_, commit) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        let (state, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
        let audit = rig.audit_bytes();
        let first = {
            let _armed =
                arm_accounting_fault(crate::policy_state::store::COMMIT_FAULT_AFTER_PREPARED);
            rig.repair(None)
        };
        assert!(first.is_err(), "the refused acknowledgement is returned");
        let expected_receipt = rig.decision(1).receipt_projection().unwrap().receipt;
        assert_eq!(rig.receipt(1), Some(expected_receipt.clone()));
        rig.reopen();
        assert!(!rig.projected(1), "the marker stays unset");

        let bytes = rig.receipt_bytes();
        rig.repair(None).unwrap();
        assert!(rig.projected(1));
        assert_eq!(rig.receipt_bytes(), bytes, "no second receipt write");
        assert_eq!(rig.receipt(1), Some(expected_receipt));
        assert_linked(&rig.receipt(1).unwrap(), 1, 101, commit);
        let (after, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
        assert_eq!(after, state, "no release or expiry repeats");
        assert_eq!(rig.audit_bytes(), audit, "no audit row");

        let window = rig.window_bytes();
        rig.repair(None).unwrap();
        assert_eq!(rig.window_bytes(), window);
        assert_eq!(rig.receipt_bytes(), bytes);
    }

    /// A predecessor's non-inclusion and its successor's success share a
    /// source and sequence. Each receipt names its own attempt, and a
    /// targeted repair leaves the other receipt and marker unchanged.
    #[test]
    #[serial]
    fn recovery_projection_names_only_its_attempt() {
        let mut rig = Rig::new();
        let (handle, predecessor) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        rig.repair(Some(1)).unwrap();
        let first = rig.receipt(1).unwrap();
        assert_eq!(outcome(&first), expected(Checked::NotIncluded));
        assert_linked(&first, 1, 101, predecessor);
        successor_attempt(&mut rig.fx, &handle, 2, 101);
        let successor = commit_on(
            &mut rig.fx,
            tx_hash(2),
            checked_transition(2, Checked::Succeeded, ""),
        );
        assert!(rig.receipt(2).is_none());

        rig.repair(Some(2)).unwrap();
        let second = rig.receipt(2).unwrap();
        assert_eq!(outcome(&second), expected(Checked::Succeeded));
        assert_linked(&second, 2, 101, successor);
        assert_eq!(rig.receipt(1), Some(first.clone()));
        assert!(rig.projected(1) && rig.projected(2));
        rig.repair(Some(1)).unwrap();
        assert_eq!(rig.receipt(2), Some(second.clone()));

        rig.edit_receipts(|map| {
            map.remove(&envelope_id(2));
        });
        rig.repair(None).unwrap();
        assert_eq!(
            rig.receipt(2),
            Some(second),
            "the successor's own receipt is restored"
        );
        assert_eq!(rig.receipt(1), Some(first));
    }

    /// With the clock fixed, a pass over acknowledged proofs after a
    /// restart changes no receipt byte, window byte, generation, marker,
    /// accounting or audit row.
    #[test]
    #[serial]
    fn recovery_projection_second_pass_is_byte_identical() {
        let mut rig = Rig::new();
        for (n, checked) in [
            (1, Checked::Succeeded),
            (2, Checked::Failed),
            (3, Checked::NotIncluded),
        ] {
            commit_checked(&mut rig.fx, n, checked);
        }
        rig.repair(None).unwrap();
        rig.reopen();
        let receipts = rig.receipt_bytes();
        let window = rig.window_bytes();
        let state = accounting_state(&rig.fx.store, &rig.fx.profile);
        let audit = rig.audit_bytes();
        let rows = rig.fx.sink.entries.len();
        for _ in 0..2 {
            rig.repair(None).unwrap();
            assert_eq!(rig.window_bytes(), window, "the window bytes stay");
            assert_eq!(accounting_state(&rig.fx.store, &rig.fx.profile), state);
            assert_eq!(rig.receipt_bytes(), receipts);
            assert_eq!(rig.audit_bytes(), audit);
            assert_eq!(rig.fx.sink.entries.len(), rows);
        }
        assert!((1..=3).all(|n| rig.projected(n)));
    }

    /// A committed record altered without its HMAC refuses every verified
    /// read: neither the direct repair nor the targeted status changes a
    /// receipt, a marker, accounting or the audit log.
    #[tokio::test]
    #[serial]
    async fn recovery_projection_tampered_window_refuses() {
        let mut rig = Rig::new();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        rig.legacy_receipt(1, 101);
        let receipts = rig.receipt_bytes();
        let audit = rig.audit_bytes();
        let rows = rig.fx.sink.entries.len();
        rig.tamper(1);
        let tampered = rig.window_bytes();

        assert!(rig.repair(None).is_err());
        assert_eq!(rig.receipt_bytes(), receipts, "the receipt stays unchanged");
        assert_eq!(rig.window_bytes(), tampered, "no acknowledgement commits");

        let (server, client) = endpoint().await;
        let status = rig.status(1, &client).await;
        assert!(
            matches!(status, Err(StatusFailure::WindowUnreadable(_))),
            "{status:?}"
        );
        assert_eq!(requests(&server).await, 0);
        assert_eq!(rig.receipt_bytes(), receipts);
        assert_eq!(rig.window_bytes(), tampered);
        assert_eq!(rig.audit_bytes(), audit);
        assert_eq!(rig.fx.sink.entries.len(), rows);
    }

    /// An incomplete proof enumerated first keeps its receipt and marker; the
    /// later proof is repaired and acknowledged, and the first error returns
    /// after the loop. Dispatch runs the sequence stage before repair, and
    /// the later operation can retry.
    #[tokio::test]
    #[serial]
    async fn recovery_projection_continues_after_missing_fact() {
        let mut rig = Rig::new();
        historical_without(&mut rig.fx, 1, Checked::NotIncluded, "submission_ledger");
        let (later, commit) = commit_checked(&mut rig.fx, 2, Checked::NotIncluded);
        let error = rig.repair(None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing_projection_fact:submission_ledger"),
            "{error}"
        );
        assert!(rig.receipt(1).is_none());
        assert!(!rig.projected(1));
        assert!(rig.projected(2), "the later proof is acknowledged");
        let receipt = rig.receipt(2).unwrap();
        assert_eq!(outcome(&receipt), expected(Checked::NotIncluded));
        assert_linked(&receipt, 2, 102, commit);

        let (server, client) = endpoint().await;
        take_trace();
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        assert!(
            matches!(pass, ReconcilePass::RecoveryFailed { .. }),
            "{pass:?}"
        );
        assert_eq!(take_trace(), ["sequences", "repair", "proof", "proof"]);
        assert_eq!(requests(&server).await, 0);
        assert_eq!(successor_refusal(&mut rig.fx, &later), "none");
    }

    /// Each authenticated historical fixture names its missing fact, and the
    /// defensive approval-nonce DTO does too. No replacement or
    /// acknowledgement runs, and the successor stays refused.
    #[test]
    #[serial]
    fn recovery_exact_projection_names_missing_fact() {
        for (checked, field, refusal) in [
            (Checked::NotIncluded, "source", "recovery.retry_refused"),
            (
                Checked::NotIncluded,
                "submission_ledger",
                "recovery.retry_refused",
            ),
            (Checked::Failed, "failure_code", "internal.unexpected_state"),
        ] {
            let mut rig = Rig::new();
            let (handle, _) = historical_without(&mut rig.fx, 1, checked, field);
            let decision = rig.decision(1);
            assert_eq!(decision.missing_projection_fact.as_deref(), Some(field));
            let window = rig.window_bytes();
            let receipts = rig.receipt_bytes();
            let error = rig.repair(None).unwrap_err();
            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(
                error
                    .to_string()
                    .ends_with(&format!("missing_projection_fact:{field}")),
                "{error}"
            );
            assert_eq!(rig.window_bytes(), window, "{field}: no acknowledgement");
            assert_eq!(rig.receipt_bytes(), receipts, "{field}: no replacement");
            assert!(!rig.projected(1));
            assert_eq!(successor_refusal(&mut rig.fx, &handle), refusal, "{field}");
        }

        let mut rig = Rig::new();
        commit_approved(&mut rig.fx, 1, Checked::NotIncluded);
        let mut decision = rig.decision(1);
        assert!(decision.projection_identity.is_some());
        decision.projection_identity = None;
        decision.missing_projection_fact = Some("approval_nonce".to_owned());
        let projection = decision.receipt_projection();
        let error = repair_proof(
            &rig.fx.store,
            &rig.fx.profile,
            &rig.receipts,
            &rig.writer,
            &decision,
            projection,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .ends_with("missing_projection_fact:approval_nonce"),
            "{error}"
        );
        assert!(rig.receipt(1).is_none());
        assert!(!rig.projected(1));
    }

    /// A failure whose result exceeds the stored bound keeps its digest and
    /// the exact stable code across restart; the checked receipt carries
    /// it. A retained complete historical result derives the same code.
    #[test]
    #[serial]
    fn recovery_projection_failure_code_survives_truncation() {
        use sha2::{Digest as _, Sha256};
        let mut rig = Rig::new();
        decided_attempt(&mut rig.fx, 1);
        let oversized = failed_result_xdr(32);
        assert!(oversized.len() > 2_048, "{}", oversized.len());
        commit_on(
            &mut rig.fx,
            tx_hash(1),
            checked_transition(1, Checked::Failed, &oversized),
        );
        rig.reopen();
        let (text, truncated, stored) = retained_result(&rig.fx.store, &rig.fx.profile, tx_hash(1));
        assert!(truncated);
        assert_eq!(
            text,
            stellar_agent_core::hex::encode(&Sha256::digest(oversized.as_bytes()))
        );
        assert_eq!(stored.as_deref(), Some(FAILED_CODE));
        assert_eq!(rig.decision(1).failure_code.as_deref(), Some(FAILED_CODE));
        rig.repair(None).unwrap();
        assert_eq!(
            rig.receipt(1).unwrap().status,
            ReceiptStatus::Failed {
                code: FAILED_CODE.to_owned()
            }
        );

        decided_attempt(&mut rig.fx, 2);
        let complete = failed_result_xdr(0);
        commit_on(
            &mut rig.fx,
            tx_hash(2),
            checked_transition(2, Checked::Failed, &complete),
        );
        forget_failure_code(&rig.fx, tx_hash(2));
        let (text, truncated, stored) = retained_result(&rig.fx.store, &rig.fx.profile, tx_hash(2));
        assert_eq!(
            (text.as_str(), truncated, stored),
            (complete.as_str(), false, None)
        );
        assert_eq!(rig.decision(2).failure_code.as_deref(), Some(FAILED_CODE));
        rig.repair(None).unwrap();
        assert_eq!(
            rig.receipt(2).unwrap().status,
            ReceiptStatus::Failed {
                code: FAILED_CODE.to_owned()
            }
        );
    }

    /// Each checked outcome builds its receipt: status, inclusion ledger,
    /// non-inclusion release code, flags and decision linkage.
    #[test]
    #[serial]
    fn recovery_projection_maps_checked_outcomes() {
        let mut rig = Rig::new();
        for (n, checked) in [
            (1, Checked::Succeeded),
            (2, Checked::Failed),
            (3, Checked::NotIncluded),
        ] {
            let (_, commit) = commit_checked(&mut rig.fx, n, checked);
            let projection = rig.decision(n).receipt_projection().unwrap();
            let receipt = &projection.receipt;
            assert_eq!(outcome(receipt), expected(checked), "{checked:?}");
            assert_eq!(projection.decision_id, commit.to_hex());
            assert_linked(receipt, n, 100 + i64::from(n), commit);
            assert_eq!(receipt.approval_nonce, None);
            assert!(!receipt.approval_consumed);
            assert_eq!(receipt.recorded_at_ledger, PROJECTED_LEDGER);
        }
    }

    /// An operator clear between replacement and acknowledgement keeps the
    /// cleared status through repeated repair, with the receipt's own
    /// identity and linkage and no repeated accounting or audit effect.
    #[test]
    #[serial]
    fn recovery_projection_preserves_operator_clear() {
        let mut rig = Rig::new();
        let (_, commit) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        let receipts = rig.receipts.clone();
        let mut cleared = false;
        let armed = on_replacement(move || {
            if !cleared {
                cleared = true;
                receipts
                    .clear_by_operator(&envelope_id(1))
                    .map_err(|error| record_unavailable(error.to_string()))?;
            }
            Ok(())
        });
        rig.repair(None).unwrap();
        drop(armed);
        assert!(rig.projected(1));
        let state = accounting_state(&rig.fx.store, &rig.fx.profile).0;
        let audit = rig.audit_bytes();
        for _ in 0..2 {
            rig.repair(None).unwrap();
            let receipt = rig.receipt(1).unwrap();
            assert_eq!(
                receipt.status,
                ReceiptStatus::ClearedByOperator,
                "the clear stands"
            );
            assert_eq!(
                receipt.release_code,
                Some(ReleaseEvidence::ReleasedOnEvidence)
            );
            assert_linked(&receipt, 1, 101, commit);
        }
        assert_eq!(accounting_state(&rig.fx.store, &rig.fx.profile).0, state);
        assert_eq!(rig.audit_bytes(), audit);
    }

    /// Approval consumption survives restart and repeated repair with its
    /// nonce exclusion and linkage; a new receipt starts unconsumed.
    #[test]
    #[serial]
    fn recovery_projection_preserves_approval_consumption() {
        let mut rig = Rig::new();
        let (_, commit, nonce) = commit_approved(&mut rig.fx, 1, Checked::NotIncluded);
        rig.seed_pending_approval(&nonce);
        rig.repair(None).unwrap();
        let receipt = rig.receipt(1).unwrap();
        assert_eq!(receipt.approval_nonce.as_deref(), Some(nonce.as_str()));
        assert!(!receipt.approval_consumed);
        assert!(
            matches!(
                rig.approval_kind(&nonce),
                Some(stellar_agent_core::approval::ApprovalKind::PaymentSimulated { .. })
            ),
            "the approval is pending before its consumption"
        );
        crate::submission_record::repair_approval_consumption(
            &rig.receipts,
            &envelope_id(1),
            &rig.home.path().join("approvals"),
            "ops",
        )
        .unwrap();
        assert!(rig.receipt(1).unwrap().approval_consumed);
        rig.assert_approval_consumed(&nonce, 1);
        let approvals = fs::read(rig.approvals_path()).unwrap();

        for _ in 0..2 {
            rig.reopen();
            rig.repair(None).unwrap();
            let receipt = rig.receipt(1).unwrap();
            assert!(receipt.approval_consumed, "the consumption stands");
            assert_eq!(receipt.approval_nonce.as_deref(), Some(nonce.as_str()));
            assert_linked(&receipt, 1, 101, commit);
            rig.assert_approval_consumed(&nonce, 1);
            assert_eq!(fs::read(rig.approvals_path()).unwrap(), approvals);
        }
        assert!(matches!(
            rig.receipts
                .begin_submission_with_approval(
                    &"0c".repeat(32),
                    &"0d".repeat(32),
                    SOURCE,
                    999,
                    0,
                    1,
                    Some(&nonce)
                )
                .unwrap(),
            BeginSubmissionOutcome::DuplicateApproval(_)
        ));

        let (_, _, other) = commit_approved(&mut rig.fx, 2, Checked::Succeeded);
        rig.repair(None).unwrap();
        let fresh = rig.receipt(2).unwrap();
        assert_eq!(fresh.approval_nonce.as_deref(), Some(other.as_str()));
        assert!(!fresh.approval_consumed, "a new receipt starts unconsumed");
    }

    /// Accounting expires first; each checked outcome then commits and is
    /// repaired, and the owed expiry delivered at dispatch completion keeps
    /// the checked status, release code and linkage. No charge revives and
    /// no release repeats.
    #[test]
    #[serial]
    fn recovery_projection_after_accounting_expiry_keeps_decision_precedence() {
        for (n, checked) in [
            (1, Checked::NotIncluded),
            (2, Checked::Succeeded),
            (3, Checked::Failed),
        ] {
            let mut rig = Rig::new();
            decided_attempt(&mut rig.fx, n);
            let decision_id = expire_reservation(&mut rig.fx, n, None);
            let commit = commit_on(
                &mut rig.fx,
                tx_hash(n),
                checked_transition(n, checked, &failed_result_xdr(0)),
            );
            let (state, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
            rig.repair(None).unwrap();
            let report = finish_reconciliation(
                &rig.fx.profile,
                "ops",
                &rig.fx.store,
                Some(&rig.receipts),
                &ReconcilePass::Completed(crate::policy_state::ReconcileReport::default()),
                || Ok(Arc::clone(&rig.writer)),
            )
            .unwrap();
            assert_eq!(report.projected, 1, "{checked:?}: {report:?}");
            let receipt = rig.receipt(n).unwrap();
            assert_eq!(outcome(&receipt), expected(checked), "{checked:?}");
            assert_linked(&receipt, n, 100 + i64::from(n), commit);
            assert_ne!(receipt.settlement_decision_id, Some(decision_id));
            let (after, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
            assert_eq!(after["entries"], state["entries"], "{checked:?}");
            assert_eq!(after["releases"], state["releases"], "{checked:?}");
        }
    }

    /// An expiry projected first is replaced by each checked outcome, a
    /// zero-entry exposure's identity included, while expired accounting
    /// rows and native releases stay as they are.
    #[test]
    #[serial]
    fn recovery_projection_repairs_expiry_first() {
        for (n, checked) in [
            (1, Checked::Succeeded),
            (2, Checked::Failed),
            (3, Checked::NotIncluded),
        ] {
            let mut rig = Rig::new();
            decided_attempt(&mut rig.fx, n);
            let decision_id = expire_reservation(&mut rig.fx, n, Some(&rig.receipts));
            let expired = rig.receipts.get(&envelope_id(n)).unwrap().unwrap();
            assert_eq!(
                expired.release_code,
                Some(ReleaseEvidence::AccountingExpired)
            );
            assert_eq!(expired.settlement_decision_id, Some(decision_id));
            let commit = commit_on(
                &mut rig.fx,
                tx_hash(n),
                checked_transition(n, checked, &failed_result_xdr(0)),
            );
            let (state, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
            rig.repair(None).unwrap();
            let receipt = rig.receipt(n).unwrap();
            assert_eq!(outcome(&receipt), expected(checked), "{checked:?}");
            assert_linked(&receipt, n, 100 + i64::from(n), commit);
            let (after, _) = accounting_state(&rig.fx.store, &rig.fx.profile);
            assert_eq!(after["entries"], state["entries"], "{checked:?}");
            assert_eq!(after["releases"], state["releases"], "{checked:?}");
        }

        let mut rig = Rig::new();
        let (_, commit) = zero_entry_committed(&mut rig.fx, 4, Checked::NotIncluded);
        rig.receipts
            .project_accounting_expiry(&AccountingExpiryProjection {
                envelope_hash: &envelope_id(4),
                tx_hash: &tx_hex(4),
                source: SOURCE,
                sequence: 104,
                max_time: T0 / 1_000 + 60,
                recorded_at_ledger: 1,
                decision_id: &"e4".repeat(32),
            })
            .unwrap();
        rig.repair(None).unwrap();
        let receipt = rig.receipt(4).unwrap();
        assert_eq!(outcome(&receipt), expected(Checked::NotIncluded));
        assert_linked(&receipt, 4, 104, commit);
        assert_eq!(
            receipt.recorded_at_ledger, PROJECTED_LEDGER,
            "the exposure supplies the ledger"
        );
    }

    /// A zero-entry consumption whose exposure stores no projection facts
    /// keeps its ledger in the authenticated consumption. After a crash
    /// before acknowledgement, repair rebuilds the exact receipt from that
    /// consumption, the exposure and the attempt's authority.
    #[test]
    #[serial]
    fn recovery_projection_reads_historical_consumption_ledger() {
        for approval in [true, false] {
            let mut rig = Rig::new();
            let (handle, nonce) = consumed_zero_entry(&mut rig.fx, 1, approval);
            assert_eq!(nonce.is_some(), approval);
            let commit = commit_on(
                &mut rig.fx,
                tx_hash(1),
                checked_transition(1, Checked::NotIncluded, ""),
            );
            rig.reopen();
            assert_eq!(
                exposure_keys(&rig.fx.store, tx_hash(1)),
                ["commit_id", "exposed_at_ms", "identity"],
                "the exposure stores no projection facts"
            );
            assert_eq!(
                exposure_facts(&rig.fx.store, &rig.fx.profile, tx_hash(1)),
                (None, None)
            );
            assert_eq!(
                consumed_ledger(&rig.fx.store, &rig.fx.profile, tx_hash(1)),
                Some(CONSUMED_LEDGER),
                "the verified consumption keeps its ledger"
            );
            let decision = rig.decision(1);
            assert_eq!(
                decision.missing_projection_fact, None,
                "the authenticated consumption supplies the submission ledger"
            );
            assert_eq!(
                decision.projection_identity,
                Some(ReceiptProjectionIdentity {
                    source: SOURCE.to_owned(),
                    sequence: 101,
                    max_time: T0 / 1_000 + 60,
                    receipt_reference: envelope_id(1),
                    submission_ledger: CONSUMED_LEDGER,
                    approval_nonce: nonce.clone(),
                })
            );
            assert_eq!(
                successor_refusal(&mut rig.fx, &handle),
                "recovery.retry_refused"
            );

            rig.repair(None).unwrap();
            assert!(rig.projected(1), "approval {approval}");
            let receipt = rig.receipt(1).unwrap();
            assert_eq!(outcome(&receipt), expected(Checked::NotIncluded));
            assert_linked(&receipt, 1, 101, commit);
            assert_eq!(receipt.recorded_at_ledger, CONSUMED_LEDGER);
            assert_eq!(receipt.approval_nonce, nonce);
            if !approval {
                assert_eq!(successor_refusal(&mut rig.fx, &handle), "none");
            }
        }
    }

    /// A refused replacement for the requested hash is logged with its code
    /// and detail. The status answer returns with its receipt and
    /// reservation fields, and the proof stays readable with its marker
    /// unset.
    #[tokio::test]
    #[serial]
    async fn recovery_status_logs_projection_refusal_and_returns_answer() {
        use stellar_agent_test_support::log_capture::CaptureWriter;
        let mut rig = Rig::new();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        let (_server, client) = endpoint().await;
        let capture = CaptureWriter::new();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(capture.clone())
                .finish(),
        );
        let held = hold_receipt_lock(&rig.receipts);
        let status = rig.status(1, &client).await;
        drop(held);
        let answer = status.unwrap();
        assert_eq!(answer.chain_status, "NOT_FOUND");
        assert_eq!(answer.record, None);
        assert_eq!(answer.reservation, None);
        assert!(!answer.reservation_open);
        let log = capture.captured_str();
        assert!(
            log.contains("checked receipt repair refused")
                && log.contains("submission.record_unavailable")
                && log.contains("checked receipt could not be written"),
            "{log}"
        );
        assert!(
            !log.contains("nothing was sent") && log.contains("completed work remains committed"),
            "the log states what is committed: {log}"
        );
        let decision = rig.decision(1);
        assert!(!decision.projected);
        assert!(rig.receipt(1).is_none());
    }

    /// A replacement refusal after the sequence stage maps to
    /// `RecoveryFailed` with the legacy report and a store refusal naming the
    /// repair's code and detail. Later proofs are attempted and the
    /// accounting drain still runs.
    #[tokio::test]
    #[serial]
    async fn recovery_dispatch_reports_projection_refusal_after_sequence_recovery() {
        let mut rig = Rig::new();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        commit_checked(&mut rig.fx, 2, Checked::Succeeded);
        let (server, client) = endpoint().await;
        let expected_report = rig
            .fx
            .store
            .reconcile_due(
                &rig.fx.profile,
                &client,
                None,
                Some(&rig.receipts),
                T0,
                RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        take_trace();
        let held = hold_receipt_lock(&rig.receipts);
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        drop(held);
        let ReconcilePass::RecoveryFailed { legacy, error } = &pass else {
            panic!("the repair refusal maps to a recovery failure: {pass:?}");
        };
        assert_eq!(legacy, &expected_report);
        assert!(
            matches!(
                error,
                RecoveryError::Store(crate::policy_state::WindowStoreError::Invalid { detail })
                    if detail.contains("submission.record_unavailable")
                        && detail.contains("checked receipt could not be written")
            ),
            "{error:?}"
        );
        assert!(
            matches!(
                error,
                RecoveryError::Store(crate::policy_state::WindowStoreError::Invalid { detail })
                    if detail.starts_with("sequence recovery completed; checked receipt repair: 0 repaired [], 2 refused; ")
                        && !detail.contains("nothing was sent")
            ),
            "the detail states the completed work: {error:?}"
        );
        assert_eq!(take_trace(), ["sequences", "repair", "proof", "proof"]);
        assert_eq!(requests(&server).await, 0);
        assert!(!rig.projected(1) && !rig.projected(2));
        finish_reconciliation(
            &rig.fx.profile,
            "ops",
            &rig.fx.store,
            Some(&rig.receipts),
            &pass,
            || Ok(Arc::clone(&rig.writer)),
        )
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn recovery_repair_refusal_precedes_missing_sequence_evidence() {
        let mut rig = Rig::new();
        let (_, refused) =
            historical_without(&mut rig.fx, 1, Checked::NotIncluded, "submission_ledger");
        unknown_named(&mut rig.fx, 2);
        let (_server, client) = endpoint().await;
        let repair = rig.repair(None).unwrap_err().to_string();
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
        finish_reconciliation(
            &rig.fx.profile,
            "ops",
            &rig.fx.store,
            Some(&rig.receipts),
            &pass,
            || Ok(Arc::clone(&rig.writer)),
        )
        .unwrap();
        drop(guard);
        let seen = warnings.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(
            seen[0].get("message").map(String::as_str),
            Some(
                "recovery: checked receipt repair refused after sequence recovery; completed work remains committed"
            )
        );
        let ReconcilePass::RecoveryFailed {
            error: RecoveryError::Store(WindowStoreError::Invalid { detail }),
            ..
        } = &pass
        else {
            panic!("the repair refusal precedes missing evidence: {pass:?}");
        };
        assert_eq!(
            detail,
            &format!("sequence recovery evidence missing; {repair}")
        );
        assert!(detail.contains(&refused.to_hex()));
        assert!(detail.contains("missing_projection_fact:submission_ledger"));
        assert_eq!(seen[0].get("detail"), Some(detail));
        assert!(!rig.projected(1));
        assert_eq!(
            OperationStatus::new(&rig.fx.store, &rig.fx.profile)
                .recovery_snapshot(None)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    #[serial]
    async fn recovery_missing_sequence_evidence_precedes_completion() {
        use crate::policy_state::recovery::{
            RecoveryEndpoint, RecoveryFailure, RecoveryMethod, RecoveryReason,
        };

        let mut rig = Rig::new();
        unknown_named(&mut rig.fx, 1);
        let (_server, client) = endpoint().await;
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        assert!(
            matches!(
                pass,
                ReconcilePass::RecoveryFailed {
                    error: RecoveryError::NeedsEvidence(RecoveryFailure {
                        reason: RecoveryReason::MissingField,
                        endpoint: RecoveryEndpoint::Oracle,
                        method: RecoveryMethod::GetNetwork,
                        ledger: None,
                    }),
                    ..
                }
            ),
            "missing sequence evidence refuses a pass with successful repair: {pass:?}"
        );
    }

    /// A sent decision and an incomplete historical decision survive a
    /// crash. After sequence recovery, dispatch repairs the first and
    /// refuses the second. Its detail, its completion log and the status log
    /// name each decision, the refusal and the completed sequence stage.
    #[tokio::test]
    #[serial]
    async fn recovery_partial_repair_renders_completed_work() {
        let mut rig = Rig::new();
        let (_, refused) =
            historical_without(&mut rig.fx, 1, Checked::NotIncluded, "submission_ledger");
        let (_, repaired) = commit_checked(&mut rig.fx, 2, Checked::Succeeded);
        rig.reopen();
        let (_server, client) = endpoint().await;
        let refusal = format!(
            "decision {} refused with submission.record_unavailable: \
             missing_projection_fact:submission_ledger",
            refused.to_hex()
        );

        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        let ReconcilePass::RecoveryFailed {
            error: RecoveryError::Store(WindowStoreError::Invalid { detail }),
            ..
        } = &pass
        else {
            panic!("the repair refusal maps to a store refusal: {pass:?}");
        };
        assert_eq!(
            detail,
            &format!(
                "sequence recovery completed; checked receipt repair: 1 repaired [{}], \
                 1 refused; {refusal}",
                repaired.to_hex()
            ),
            "the dispatch detail names the completed work"
        );
        assert!(rig.projected(2) && !rig.projected(1));

        let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
        finish_reconciliation(
            &rig.fx.profile,
            "ops",
            &rig.fx.store,
            Some(&rig.receipts),
            &pass,
            || Ok(Arc::clone(&rig.writer)),
        )
        .unwrap();
        rig.status(1, &client).await.unwrap();
        drop(guard);
        let seen = warnings.seen();
        let logged = |prefix: &str| {
            seen.iter()
                .find(|fields| {
                    fields
                        .get("message")
                        .is_some_and(|message| message.starts_with(prefix))
                })
                .unwrap_or_else(|| panic!("{prefix}: {seen:?}"))
                .clone()
        };
        let completion = logged("recovery: checked receipt repair refused");
        assert_eq!(
            completion.get("message").map(String::as_str),
            Some(
                "recovery: checked receipt repair refused after sequence recovery; \
                 completed work remains committed"
            )
        );
        assert_eq!(completion.get("detail"), Some(detail));
        let status = logged("transaction status: checked receipt repair refused");
        assert_eq!(
            status.get("message").map(String::as_str),
            Some(
                "transaction status: checked receipt repair refused; completed work remains committed"
            )
        );
        assert_eq!(
            status.get("detail"),
            Some(&format!(
                "checked receipt repair: 0 repaired [], 1 refused; {refusal}"
            )),
            "the status detail names the refused decision"
        );
        // The capture records a string field in its debug form.
        assert_eq!(
            status.get("code").map(String::as_str),
            Some("\"submission.record_unavailable\"")
        );
        assert_eq!(
            status.get("sequence_recovery").map(String::as_str),
            Some("\"completed\"")
        );
        for fields in [&completion, &status] {
            for value in fields.values() {
                for claim in ["nothing was sent", "every sequence stays held"] {
                    assert!(!value.contains(claim), "{claim}: {fields:?}");
                }
                for content in [
                    SOURCE,
                    &envelope_id(1),
                    &envelope_id(2),
                    &tx_hex(1),
                    &tx_hex(2),
                ] {
                    assert!(!value.contains(content), "no row content: {fields:?}");
                }
            }
        }
    }

    /// Dispatch without a receipt store or writer, a stored-replay pass and
    /// a failed legacy stage run no checked repair; a complete idle dispatch
    /// repairs the retained terminal proof.
    #[tokio::test]
    #[serial]
    async fn recovery_projection_skips_missing_inputs_and_stored_replay() {
        let mut rig = Rig::new();
        let (_, commit) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        let (server, client) = endpoint().await;
        take_trace();
        let pass = rig.dispatch(&client, None, false).await;
        assert!(matches!(pass, ReconcilePass::Completed(_)), "{pass:?}");
        assert!(!rig.projected(1), "no receipt store, no repair");
        let pass = reconcile_pass(
            &rig.fx.profile,
            &rig.fx.store,
            &client,
            None,
            Some(&rig.receipts),
            T0,
            || Err(record_unavailable("no writer")),
        )
        .await;
        assert!(matches!(pass, ReconcilePass::Completed(_)), "{pass:?}");
        assert!(!rig.projected(1), "no writer, no repair");
        let pass = rig.dispatch(&client, Some(&rig.receipts), true).await;
        assert!(matches!(pass, ReconcilePass::Completed(_)), "{pass:?}");
        assert!(!rig.projected(1), "a stored replay repairs nothing");
        assert!(rig.receipt(1).is_none());
        assert!(!take_trace().contains(&"repair"));

        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        assert!(matches!(pass, ReconcilePass::Completed(_)), "{pass:?}");
        assert!(rig.projected(1), "an idle dispatch repairs");
        assert_linked(&rig.receipt(1).unwrap(), 1, 101, commit);
        assert_eq!(requests(&server).await, 0);

        commit_checked(&mut rig.fx, 2, Checked::NotIncluded);
        rig.tamper(2);
        take_trace();
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        assert!(matches!(pass, ReconcilePass::Failed(_)), "{pass:?}");
        assert!(!take_trace().contains(&"repair"));
    }

    /// Status after an approval receipt's removal restores its nonce, and
    /// the same call consumes it and marks the restored receipt. After a
    /// reopen the nonce stays excluded with no second consumption.
    #[tokio::test]
    #[serial]
    async fn recovery_status_rereads_projected_approval_nonce() {
        let mut rig = Rig::new();
        let (_, commit, nonce) = commit_approved(&mut rig.fx, 1, Checked::NotIncluded);
        rig.seed_pending_approval(&nonce);
        rig.repair(None).unwrap();
        rig.edit_receipts(|map| {
            map.remove(&envelope_id(1));
        });
        let (_server, client) = endpoint().await;
        let answer = rig.status(1, &client).await.unwrap();
        let receipt = rig.receipt(1).unwrap();
        assert!(
            receipt.approval_consumed,
            "the same call consumes the nonce"
        );
        rig.assert_approval_consumed(&nonce, 1);
        assert_eq!(receipt.approval_nonce.as_deref(), Some(nonce.as_str()));
        assert_linked(&receipt, 1, 101, commit);
        assert_eq!(answer.record, Some(receipt));

        let approvals = rig.home.path().join("approvals").join("ops.toml");
        let consumed = (fs::read(&approvals).ok(), rig.receipt_bytes());
        rig.reopen();
        rig.status(1, &client).await.unwrap();
        assert_eq!(
            (fs::read(&approvals).ok(), rig.receipt_bytes()),
            consumed,
            "no second consumption"
        );
        rig.assert_approval_consumed(&nonce, 1);
        assert!(rig.receipt(1).unwrap().approval_consumed);
        assert!(matches!(
            rig.receipts
                .begin_submission_with_approval(
                    &"0c".repeat(32),
                    &"0d".repeat(32),
                    SOURCE,
                    999,
                    0,
                    1,
                    Some(&nonce)
                )
                .unwrap(),
            BeginSubmissionOutcome::DuplicateApproval(_)
        ));
    }

    /// A zero-entry consumption stores only the source and the submission
    /// ledger beside the exposure; reopened, the exact receipt identity is
    /// rebuilt from the exposure and the attempt's authority alone.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial]
    async fn recovery_exposure_persists_zero_entry_identity() {
        use crate::mainnet::fixtures::{self, LedgerFixture, SEQUENCE, SIGNER_SEED};
        use crate::policy_state::operations::tests::{
            decide, not_included_proof, policy_authority,
        };
        use crate::policy_state::{DecidedTransition, EvidenceInput, SequenceReleaseInput};
        use crate::{MainnetSubmitGrant, SubmissionOutcome, SubmissionRecorder};
        let fx = LedgerFixture::new("zero-entry", T0);
        let unsigned = fixtures::unsigned_envelope();
        let signed = fixtures::signed_envelope();
        let intent = fixtures::intent(&signed);
        let (attempt, authorization) = fx.linked_attempt(
            fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            &[],
            "order-1",
        );
        let recorder = fx
            .recorder(vec![], Some(Arc::clone(&fx.writer)))
            .with_operation(Some(attempt));
        recorder
            .pre_send_authorized(&intent, MainnetSubmitGrant::Tx(authorization))
            .await
            .unwrap();
        let hash = stellar_agent_core::hex::decode_hex32(&intent.tx_hash).unwrap();
        // The consumption commit itself holds both facts: reopened before the
        // outcome, evidence or decision writes.
        let consumed = PersistedWindowStore::at_path(fx.window.path().to_owned());
        assert_eq!(
            exposure_facts(&consumed, &fx.profile, hash),
            (Some(fixtures::account(SIGNER_SEED)), Some(100)),
            "the consumed image stores both projection facts"
        );
        assert_eq!(
            consumed_ledger(&consumed, &fx.profile, hash),
            Some(100),
            "the consumed image records the consumption"
        );
        recorder
            .outcome(
                &intent,
                &SubmissionOutcome::Timeout {
                    tx_hash: intent.tx_hash.clone(),
                },
            )
            .await;
        drop(recorder);

        let window = PersistedWindowStore::at_path(fx.window.path().to_owned());
        {
            let mut guard = fx.writer.lock().unwrap();
            let mut recorder =
                OperationRecorder::new(&window, &fx.profile, &mut *guard, "recovery");
            recorder
                .record_evidence(
                    attempt.operation_id,
                    attempt.attempt_index,
                    &EvidenceInput {
                        sequence_released: Some(SequenceReleaseInput {
                            primary_ledger: 10,
                            witness_ledger: 10,
                            min_close_time_ms: T0,
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
            let snapshot = OperationStatus::new(&window, &fx.profile)
                .outcome_snapshot(Some(&hash))
                .unwrap()
                .pop()
                .unwrap();
            recorder
                .commit_decision(&decide(
                    &snapshot,
                    DecidedTransition::NotIncluded(not_included_proof()),
                ))
                .unwrap();
        }
        fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
        let identity = |window: &PersistedWindowStore| {
            OperationStatus::new(window, &fx.profile)
                .committed_decisions(Some(&hash))
                .unwrap()
                .pop()
                .unwrap()
                .projection_identity
        };
        let reopened = PersistedWindowStore::at_path(fx.window.path().to_owned());
        assert_eq!(
            identity(&reopened)
                .as_ref()
                .map(|identity| identity.submission_ledger),
            Some(100),
            "the exposure supplies the submission ledger"
        );
        assert_eq!(
            exposure_keys(&reopened, hash),
            [
                "commit_id",
                "exposed_at_ms",
                "identity",
                "source",
                "submission_ledger"
            ],
            "the exposure adds only the source and the submission ledger"
        );
        let mut exact = ReceiptProjectionIdentity {
            source: fixtures::account(SIGNER_SEED),
            sequence: SEQUENCE,
            max_time: intent.max_time,
            receipt_reference: intent.envelope_hash.clone(),
            submission_ledger: 100,
            approval_nonce: Some("approval-1".to_owned()),
        };
        assert_eq!(identity(&reopened), Some(exact.clone()));
        policy_authority(&reopened, &fx.profile, hash);
        exact.approval_nonce = None;
        assert_eq!(
            identity(&PersistedWindowStore::at_path(fx.window.path().to_owned())),
            Some(exact),
            "a policy authority authenticates the approval's absence"
        );
    }
}
