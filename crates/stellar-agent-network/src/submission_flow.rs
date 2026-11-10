//! The submission flow after the policy gate shared by the CLI and MCP server.
//! Each binary renders the results in its own wire form.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::{AuditWriter, PolicyDecision};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::policy::v1::{CheckedSizing, SizingOutcome};
use stellar_agent_core::profile::receipt::{ReceiptStore, ReceiptStoreError, SubmissionReceipt};
use stellar_agent_core::profile::schema::{Profile, StateDirError};
use stellar_agent_core::wallet::WalletLifecycleError;

use crate::mainnet::consumed::AuthorizationConsumed;
use crate::policy_state::{
    DeliveryReport, PersistedWindowStore, RECONCILE_BUDGET, ReconcileReport, SubmissionHold,
    WindowStoreError, drain_accounting_obligations,
};
use crate::submission_record::repair_approval_consumption;
use crate::{
    IntentBinding, IntentProof, MainnetSubmitGrant, NetworkContext, SignedIntentPlan,
    StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, envelope_hash_hex,
};

/// Opens the submission receipt store for a profile.
///
/// # Errors
/// Returns a recording refusal when the store cannot be opened.
pub fn open_receipts(profile_name: &str) -> Result<ReceiptStore, WalletError> {
    open_receipt_store(profile_name)
        .map_err(|detail| WalletError::Submission(SubmissionError::RecordUnavailable { detail }))
}

/// Opens the receipt store; a failure is the recording refusal text both
/// binaries render.
fn open_receipt_store(profile_name: &str) -> Result<ReceiptStore, String> {
    ReceiptStore::open(profile_name)
        .map_err(|e| format!("the submission receipt store could not be opened: {e}"))
}

/// Extracts certified sizing or preserves the policy refusal.
///
/// # Errors
/// Returns the policy denial or the caller's unsupported-outcome error.
pub fn checked_sizing(
    outcome: SizingOutcome,
    unsupported: impl FnOnce() -> WalletError,
) -> Result<CheckedSizing, WalletError> {
    match outcome {
        SizingOutcome::Sized(sizing) => Ok(sizing),
        SizingOutcome::Refused(reason) => Err(WalletError::PolicyDenied {
            reason: Box::new(reason),
        }),
        _ => Err(unsupported()),
    }
}

/// Inputs the policy gate supplies to a submission recorder.
pub struct RecorderInputs<'a> {
    /// The governing profile.
    pub profile: &'a Profile,
    /// The profile's store name.
    pub profile_name: String,
    /// The registered tool name in audit rows.
    pub tool: &'static str,
    /// The CAIP-2 chain identifier.
    pub chain_id: String,
    /// The decision admitting the submission.
    pub policy_decision: PolicyDecision,
    /// The sized value legs in audit form.
    pub legs: Vec<ValueLegRecord>,
    /// The writer acquired by the audit preflight.
    pub audit: Option<Arc<Mutex<AuditWriter>>>,
    /// The commit nonce prefix for audit rows.
    pub nonce_id: Option<String>,
    /// The caller's Unix clock in milliseconds.
    pub now_ms: u64,
}

/// Assembles the stores, window entries and signing sizing for a recorder.
pub fn assemble_recorder(
    inputs: RecorderInputs<'_>,
    receipts: ReceiptStore,
    sizing: Option<CheckedSizing>,
) -> WalletSubmissionRecorder<'_> {
    let window_entries = sizing
        .as_ref()
        .map(|sizing| sizing.entries().to_vec())
        .unwrap_or_default();
    let window = PersistedWindowStore::for_profile(&inputs.profile_name);
    let recorder = WalletSubmissionRecorder::new(
        inputs.profile,
        inputs.profile_name,
        inputs.tool,
        Some(inputs.chain_id),
        inputs.policy_decision,
        inputs.legs,
        window_entries,
        receipts,
        window,
        inputs.audit,
        inputs.nonce_id,
        uuid::Uuid::new_v4().to_string(),
        inputs.now_ms,
    );
    match sizing {
        Some(sizing) => recorder.with_signing_sizing(sizing),
        None => recorder,
    }
}

/// The recorder of a mainnet write, marking entry into the authorized pre-send hook.
///
/// The mark separates the two refusals of the submit that share a code: a
/// refusal of the submit gate before the hook, and a refusal inside it.
pub struct StageMarkedRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    pre_send_entered: AtomicBool,
}

impl<'a> StageMarkedRecorder<'a> {
    /// Wraps a recorder with an unset authorized pre-send mark.
    pub fn new(inner: WalletSubmissionRecorder<'a>) -> Self {
        Self {
            inner,
            pre_send_entered: AtomicBool::new(false),
        }
    }

    /// Whether submission enters [`SubmissionRecorder::pre_send_authorized`].
    #[must_use]
    pub fn pre_send_entered(&self) -> bool {
        self.pre_send_entered.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for StageMarkedRecorder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageMarkedRecorder")
            .field("inner", &self.inner)
            .field("pre_send_entered", &self.pre_send_entered())
            .finish()
    }
}

#[async_trait::async_trait]
impl SubmissionRecorder for StageMarkedRecorder<'_> {
    async fn admit_signed_intent(
        &self,
        plan: &SignedIntentPlan,
    ) -> Result<IntentProof, WalletError> {
        self.inner.admit_signed_intent(plan).await
    }
    async fn cancel_unexposed(&self, proof: IntentProof) -> Result<(), WalletError> {
        self.inner.cancel_unexposed(proof).await
    }
    async fn pre_send_bound(
        &self,
        intent: &SubmissionIntent,
        binding: &IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        self.inner.pre_send_bound(intent, binding).await
    }

    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.pre_send_entered.store(true, Ordering::SeqCst);
        self.inner.pre_send_authorized(intent, grant).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.inner.outcome(intent, outcome).await;
    }
}

/// Structured recovery details for a submission with an unknown outcome.
///
/// Returns `None` for every error other than a submission timeout, an
/// already-submitted transaction and a hash mismatch: those are the
/// submissions whose outcome the wallet does not know. `reconcile_with`
/// names the tool or verb that resolves the outcome.
pub fn submission_details(
    err: &WalletError,
    signed_xdr: &str,
    reconcile_with: &str,
) -> Option<serde_json::Value> {
    let WalletError::Submission(submission) = err else {
        return None;
    };
    let mut details = serde_json::Map::new();
    match submission {
        SubmissionError::TxTimeout { tx_hash, seconds } => {
            details.insert("tx_hash".to_owned(), tx_hash.clone().into());
            details.insert("timeout_seconds".to_owned(), (*seconds).into());
        }
        SubmissionError::TxAlreadySubmitted { hash } => {
            details.insert("tx_hash".to_owned(), hash.clone().into());
        }
        SubmissionError::HashMismatch { local, server } => {
            details.insert("tx_hash".to_owned(), local.clone().into());
            details.insert("server_tx_hash".to_owned(), server.clone().into());
        }
        _ => return None,
    }
    // The envelope hash names the submission record the operator verbs
    // address. A caller that does not hold the signed bytes reports the
    // transaction hash alone rather than a hash of nothing.
    if !signed_xdr.is_empty() {
        details.insert(
            "envelope_hash".to_owned(),
            envelope_hash_hex(signed_xdr).into(),
        );
    }
    details.insert("outcome".to_owned(), "unknown".into());
    details.insert("reconcile_with".to_owned(), reconcile_with.into());
    Some(serde_json::Value::Object(details))
}

/// Renders a wallet error with submission recovery details when available.
///
/// An error without [`submission_details`] renders as a plain error envelope.
pub fn submission_error_envelope(
    err: &WalletError,
    signed_xdr: &str,
    reconcile_with: &str,
) -> Envelope<()> {
    match submission_details(err, signed_xdr, reconcile_with) {
        Some(details) => Envelope::err_with_details(err, details),
        None => Envelope::err(err),
    }
}

/// Builds the mainnet settlement oracle, logging a client construction refusal.
///
/// Returns `None` off mainnet, when the window store cannot name the chain
/// scope of `profile`, when the profile configures no oracle, and when the
/// oracle client cannot be built. Without an oracle, a negative answer of
/// the primary endpoint settles nothing.
pub fn settlement_oracle(
    window: &PersistedWindowStore,
    profile: &Profile,
    context: &NetworkContext,
) -> Option<StellarRpcClient> {
    let scope = window.chain_scope(profile).ok()?;
    if !scope.chain().is_mainnet() {
        return None;
    }
    match context.oracle_client(profile) {
        Ok(oracle) => oracle,
        Err(error) => {
            tracing::warn!(
                code = %error.code(),
                "window reconcile: the oracle client could not be built; negative answers \
                 of the primary endpoint settle nothing"
            );
            None
        }
    }
}

/// The outcome of a dispatch-time reconciliation pass.
#[derive(Debug)]
pub enum ReconcilePass {
    /// The pass completes over the due reservations.
    Completed(ReconcileReport),
    /// The system clock is unavailable, so the pass is skipped.
    ClockUnavailable,
    /// The primary RPC client is unavailable, so the pass is skipped.
    ClientUnavailable,
    /// The pass refuses; every open reservation stands.
    Failed(WindowStoreError),
}

/// Logs the outcome of a dispatch-time reconciliation pass, then drains every
/// owed accounting obligation.
///
/// The drain runs for every pass outcome: a skipped or refused pass leaves
/// the durable obligations of earlier passes in place, and they are
/// delivered here. The writer is the keyed one every value verb uses,
/// acquired only when an audit event is owed.
///
/// # Errors
/// Returns a refusal from accounting delivery or writer acquisition.
pub fn finish_reconciliation(
    profile: &Profile,
    profile_name: &str,
    window: &PersistedWindowStore,
    receipts: Option<&ReceiptStore>,
    pass: &ReconcilePass,
    writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> Result<DeliveryReport, WalletError> {
    match pass {
        ReconcilePass::Completed(report) if report.receipt_write_failed > 0 => tracing::warn!(
            profile = %profile_name,
            receipt_write_failed = report.receipt_write_failed,
            "window reconcile: receipt writes stay owed"
        ),
        ReconcilePass::Completed(_) => {}
        ReconcilePass::ClockUnavailable => {
            tracing::debug!("window reconcile: system clock unavailable; reservations stand");
        }
        ReconcilePass::ClientUnavailable => {
            tracing::debug!("window reconcile: no primary client; reservations stand");
        }
        ReconcilePass::Failed(error) => tracing::debug!(
            profile = %profile_name,
            error = ?error,
            "window reconcile: pass failed; open reservations stand"
        ),
    }
    drain_accounting_obligations(window, profile, profile_name, receipts, writer)
}

/// Runs the bounded dispatch-time reconciliation pass.
///
/// A completed pass maps to [`ReconcilePass::Completed`]; a refusal of the
/// window store maps to [`ReconcilePass::Failed`] and leaves every open
/// reservation in place.
pub async fn reconcile_pass(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
) -> ReconcilePass {
    match window
        .reconcile_due(profile, client, oracle, receipts, now_ms, RECONCILE_BUDGET)
        .await
    {
        Ok(report) => ReconcilePass::Completed(report),
        Err(error) => ReconcilePass::Failed(error),
    }
}

/// Inputs for reconciling and displaying one transaction.
pub struct StatusRequest<'a> {
    /// The governing profile.
    pub profile: &'a Profile,
    /// The profile's store name.
    pub profile_name: &'a str,
    /// The validated transaction hash.
    pub tx_hash: &'a str,
    /// The authenticated spending-window store.
    pub window: &'a PersistedWindowStore,
    /// The primary endpoint.
    pub client: &'a StellarRpcClient,
    /// The mainnet settlement oracle, when available.
    pub oracle: Option<&'a StellarRpcClient>,
}

/// The chain observation and the records after reconciliation and delivery.
#[derive(Debug)]
pub struct StatusOutcome {
    /// The endpoint's transaction status.
    pub chain_status: String,
    /// The ledger the endpoint reports.
    pub ledger: Option<u32>,
    /// The resulting submission receipt.
    pub record: Option<SubmissionReceipt>,
    /// The resulting open reservation.
    pub reservation: Option<SubmissionHold>,
    /// Whether the reservation belongs to the receipt.
    pub reservation_open: bool,
}

/// A status failure whose wire rendering belongs to the caller.
#[derive(Debug)]
pub enum StatusFailure {
    /// The authenticated window cannot be read.
    WindowUnreadable(WindowStoreError),
    /// Opening the receipt store fails; `detail` is the recording refusal text.
    ReceiptStoreOpen {
        /// The refusal text the caller renders as `submission.record_unavailable`.
        detail: String,
    },
    /// Reading a receipt fails.
    ReceiptStoreRead(ReceiptStoreError),
    /// The system clock cannot be read.
    ClockUnavailable(WalletLifecycleError),
    /// Reconciliation refuses after accounting delivery is attempted.
    ReconcileRefused(WindowStoreError),
    /// Resolving the approval store directory fails.
    ApprovalDirUnavailable(StateDirError),
    /// Repairing approval consumption refuses.
    RepairRefused(WalletError),
    /// Querying the chain fails.
    ChainQueryFailed(NetworkError),
}

/// Reconciles one transaction and reads its resulting receipt and reservation.
/// The writer is acquired only when accounting delivery needs it.
///
/// # Errors
/// Returns the typed failure at the step that refuses the status lookup.
pub async fn transaction_status(
    request: StatusRequest<'_>,
    approval_dir: impl FnOnce() -> Result<PathBuf, StateDirError>,
    writer: impl Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> Result<StatusOutcome, StatusFailure> {
    let StatusRequest {
        profile,
        profile_name,
        tx_hash,
        window,
        client,
        oracle,
    } = request;
    let held = window
        .pending_reservations(profile)
        .map_err(StatusFailure::WindowUnreadable)?
        .into_iter()
        .find(|r| r.tx_hash == tx_hash);
    let receipts = open_receipt_store(profile_name)
        .map_err(|detail| StatusFailure::ReceiptStoreOpen { detail })?;
    let receipt = receipts
        .find_by_tx_hash(tx_hash)
        .map_err(StatusFailure::ReceiptStoreRead)?;
    let envelope_hash = receipt
        .as_ref()
        .map(|r| r.envelope_hash.as_str())
        .or_else(|| held.as_ref().map(|r| r.id.as_str()));
    // The caller asked about this transaction by name, so the reservation and
    // the receipt reconcile together with no budget. A submission whose
    // receipt is missing reconciles from its authenticated reservation. On a
    // mainnet profile the oracle witnesses the primary's negative answers.
    if let Some(envelope_hash) = envelope_hash {
        let now_ms =
            stellar_agent_core::timefmt::now_unix_ms().map_err(StatusFailure::ClockUnavailable)?;
        match window
            .reconcile_one(
                profile,
                client,
                oracle,
                Some(&receipts),
                envelope_hash,
                now_ms,
            )
            .await
        {
            Ok(report) if report.receipt_write_failed > 0 => tracing::warn!(
                receipt_write_failed = report.receipt_write_failed,
                "transaction status: reconciliation could not record the receipt"
            ),
            Ok(_) => {}
            Err(error) => {
                // A refused pass leaves the obligations of earlier calls in
                // place; they are delivered before the refusal returns. The
                // drain logs its own refusal and leaves the obligations owed.
                let _ = drain_accounting_obligations(
                    window,
                    profile,
                    profile_name,
                    Some(&receipts),
                    &writer,
                );
                return Err(StatusFailure::ReconcileRefused(error));
            }
        }
    }
    // The status answer does not depend on the drain: a refusal is logged by
    // the drain and leaves the obligations owed for a later call.
    let _ = drain_accounting_obligations(window, profile, profile_name, Some(&receipts), &writer);
    if let Some(record) = &receipt
        && record.approval_nonce.is_some()
    {
        let approval_dir = approval_dir().map_err(StatusFailure::ApprovalDirUnavailable)?;
        repair_approval_consumption(
            &receipts,
            &record.envelope_hash,
            &approval_dir,
            profile_name,
        )
        .map_err(StatusFailure::RepairRefused)?;
    }
    let chain = client
        .get_transaction_status(tx_hash)
        .await
        .map_err(StatusFailure::ChainQueryFailed)?;
    // Both reads reflect reconciliation and the projection of owed accounting decisions.
    let reservation = window
        .pending_reservations(profile)
        .map_err(StatusFailure::WindowUnreadable)?
        .into_iter()
        .find(|r| r.tx_hash == tx_hash);
    let record = receipts
        .find_by_tx_hash(tx_hash)
        .map_err(StatusFailure::ReceiptStoreRead)?;
    let reservation_open = record.as_ref().is_some_and(|record| {
        reservation
            .as_ref()
            .is_some_and(|r| r.id == record.envelope_hash)
    });
    Ok(StatusOutcome {
        chain_status: chain.status,
        ledger: chain.ledger,
        record,
        reservation,
        reservation_open,
    })
}

/// Returns true when `value` is 64 lowercase hex characters.
pub fn is_tx_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    #[test]
    fn checked_sizing_maps_refused_to_policy_denied() {
        let error = checked_sizing(
            SizingOutcome::Refused(stellar_agent_core::policy::DenyReason::EvaluationError {
                detail: "sizing refusal".to_owned(),
            }),
            || unreachable!(),
        )
        .unwrap_err();
        let WalletError::PolicyDenied { reason } = error else {
            panic!("expected policy denial");
        };
        assert!(
            matches!(*reason, stellar_agent_core::policy::DenyReason::EvaluationError { detail } if detail == "sizing refusal")
        );
    }

    #[test]
    fn submission_details_names_the_reconcile_verb() {
        let error = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: "ab".repeat(32),
            seconds: 30,
        });
        for verb in ["stellar_transaction_status", "stellar-agent tx status"] {
            let details = submission_details(&error, "", verb).unwrap();
            assert_eq!(details["reconcile_with"], verb);
            assert_eq!(details["outcome"], "unknown");
        }
    }

    #[test]
    #[serial_test::serial]
    fn settlement_oracle_preserves_the_configured_mainnet_client() {
        use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("oracle.window"));
        let mut profile = Profile::builder_mainnet_named(
            "flow-oracle",
            "https://primary.example",
            "signer",
            "account",
            "nonce",
            "account",
        )
        .primary_provider(PrimaryProviderRecord::new("Primary", "primary.example"))
        .oracle_provider_url(url::Url::parse("https://oracle.example").unwrap())
        .oracle_provider(ProviderRecord::new("Oracle", "oracle.example", true))
        .build();
        let context = NetworkContext::from_profile(&profile);
        assert!(settlement_oracle(&window, &profile, &context).is_some());
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        let context = NetworkContext::from_profile(&profile);
        assert!(settlement_oracle(&window, &profile, &context).is_none());
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn stage_marked_recorder_marks_only_the_authorized_pre_send() {
        use crate::mainnet::fixtures::{self, LedgerFixture};
        let fx = LedgerFixture::new("stage-mark", 1000);
        let unsigned = fixtures::unsigned_envelope();
        let signed = fixtures::signed_envelope();
        let intent = fixtures::intent(&signed);
        let authorization = fx.mint(
            fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            &[],
            None,
            "stage-approval",
        );
        let recorder = StageMarkedRecorder::new(fx.recorder(vec![], Some(Arc::clone(&fx.writer))));
        assert!(!recorder.pre_send_entered());
        let _ = recorder.pre_send(&intent).await;
        assert!(!recorder.pre_send_entered());
        recorder
            .outcome(
                &intent,
                &SubmissionOutcome::Success {
                    ledger: 1500,
                    created_at: None,
                },
            )
            .await;
        assert!(!recorder.pre_send_entered());
        let _ = recorder
            .pre_send_authorized(&intent, MainnetSubmitGrant::Tx(authorization))
            .await;
        assert!(recorder.pre_send_entered());
        assert!(format!("{recorder:?}").contains("pre_send_entered: true"));
    }

    #[test]
    fn accepts_a_lowercase_64_hex_hash() {
        assert!(is_tx_hash(&"ab".repeat(32)));
    }

    #[test]
    fn refuses_uppercase_wrong_length_and_non_hex() {
        assert!(!is_tx_hash(&"AB".repeat(32)));
        assert!(!is_tx_hash(&"ab".repeat(31)));
        assert!(!is_tx_hash(&"zz".repeat(32)));
    }
}
