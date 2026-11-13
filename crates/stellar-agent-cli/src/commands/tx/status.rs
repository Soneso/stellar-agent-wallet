//! `stellar-agent tx status <HASH>` — reconcile one submitted transaction
//! against the chain.
//!
//! # What it is for
//!
//! A value verb records its submission before the transaction is sent, so a
//! submission whose confirmation never arrived leaves a receipt behind. It
//! also leaves a spending-window reservation when the policy produced window
//! entries for the submission. Those hold the operator's caps and the
//! wallet's duplicate check. This verb asks the endpoint what became of the
//! transaction. It records a reported success on the receipt and classifies
//! a missing transaction against the endpoint's retention. Accounting expiry
//! ends the reservation independently of any answer.
//!
//! It is also the answer to `submission.tx_timeout`: rebuilding and
//! re-submitting the same intent is never the answer, because the sequence the
//! transaction consumes may already be spent by it.
//!
//! # What it changes
//!
//! - `SUCCESS` is recorded on the receipt as a report, unless the receipt of
//!   an untimed hold already records another network answer, which it keeps.
//!   The reservation keeps counting through the transaction's accounting
//!   horizon. No submitted row is written, and the pending row stays open.
//! - A reported failure or missing transaction does not release possible
//!   spending. `FAILED`, and `NOT_FOUND` with a consumed sequence or a ledger
//!   close time past the time bound, keep the reservation, preserve the
//!   existing receipt status, and owe no `value_action_failed` row.
//! - The accounting horizon is the later of the signed time bound and the
//!   first local success observation, plus each affected window's duration.
//!   Once it has passed on this host's clock, the reservation ends with the
//!   outcome unknown, and no failed row is owed. A `pending` or `ambiguous`
//!   receipt is marked ambiguous with `release_code`
//!   `submission.accounting_expired`; a receipt with another status keeps its
//!   status and code. Every projected receipt carries the decision
//!   identifier. The expiry owes one `submission_accounting_expired` audit event,
//!   which this verb delivers from the verified window state. An absent
//!   receipt is rebuilt from the committed expiry.
//! - The receipt is display data. `record` carries
//!   `settlement_evidence: "unavailable"`, and no receipt status writes an
//!   audit row.
//! - When the submission ledger predates the endpoint's retention floor,
//!   `NOT_FOUND` proves nothing, so the reservation stands. A `pending` or
//!   `ambiguous` receipt is marked ambiguous and keeps any release evidence
//!   it already carries; `tx receipt clear` resolves it. The receipt of an
//!   untimed hold keeps a recorded network answer. Any other receipt refuses
//!   the transition, which the verb logs as a receipt write failure. An
//!   absent receipt leaves an authenticated hold marked `operator_required`
//!   unless the hold records a reported success.
//!
//! No step sends the transaction again.
//!
//! # Concurrency
//!
//! Delivering an accounting audit event needs the audit writer's exclusive
//! lock, and the verb acquires the writer only for an unacknowledged event.
//! While an MCP server holds that profile's writer, the verb still reconciles
//! and reports. The event stays owed, and the refusal is logged at WARN. Stop
//! that server and run the verb again to deliver it. The server acquires its
//! writer when needed, including for V1 reservation reconciliation during
//! simulation. The registry normally retains it until exit. A replaced-file
//! refusal during acquisition marks it for eviction; a later acquisition
//! drops it once callers release it.
//!
//! # Exit codes
//!
//! - 0 when the lookup completes, whatever the chain reported.
//! - 1 when the profile, the record, or the endpoint could not be reached.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReleaseEvidence, SubmissionReceipt};
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submission_flow::{self, StatusFailure, StatusRequest, is_tx_hash};

use crate::common::profile_access::load_profile_or_synthesize_testnet;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for the `tx status` subcommand.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct StatusArgs {
    /// Transaction hash to reconcile, 64 lowercase hex characters.
    ///
    /// This is the `details.tx_hash` a `submission.tx_timeout` response
    /// carries.
    #[arg(value_name = "HASH")]
    pub tx_hash: String,

    /// Profile whose submission records and spending window are reconciled.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format.
    #[arg(long, value_parser = OutputFormat::parse, default_value = "json")]
    pub output: OutputFormat,
}

/// The wallet's record of one submission, as reported to the operator.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct RecordView {
    /// The envelope hash the record is stored under. `tx receipt clear` takes
    /// this value.
    envelope_hash: String,
    /// The receipt's settled status.
    status: String,
    /// Stable wire code for a failed submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    /// The ledger the transaction confirmed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<u32>,
    /// The source account, redacted first-5-last-5.
    source_redacted: String,
    /// The sequence number the transaction consumes.
    sequence: i64,
    /// Whether the transaction was sent.
    submitted: bool,
    /// Whether a spending-window reservation is still open for it.
    reservation_open: bool,
    /// A display observation or the accounting disposition, such as
    /// `submission.accounting_expired`. Absent when the receipt records none.
    #[serde(skip_serializing_if = "Option::is_none")]
    release_code: Option<&'static str>,
    /// Always `"unavailable"`: no receipt field authenticates a settlement.
    settlement_evidence: &'static str,
    /// The authenticated accounting decision a projection recorded. A copied
    /// identifier proves nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement_decision_id: Option<String>,
}

/// Authenticated hold identity, available even when its receipt is absent.
#[derive(Debug, Serialize)]
struct ReservationView {
    envelope_hash: String,
    operator_required: bool,
}

/// Success payload for the `tx status` envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct StatusData {
    /// The transaction hash that was reconciled.
    tx_hash: String,
    /// What the endpoint reported: `SUCCESS`, `FAILED` or `NOT_FOUND`.
    chain_status: String,
    /// The ledger the endpoint reports the transaction in.
    #[serde(skip_serializing_if = "Option::is_none")]
    ledger: Option<u32>,
    /// The wallet's record of the submission, when it holds one.
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<RecordView>,
    /// A held debit, including an orphan requiring operator recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    reservation: Option<ReservationView>,
}

/// Runs `tx status`.
///
/// Returns an exit code: `0` on success, `1` on any error.
pub async fn run(args: &StatusArgs) -> i32 {
    if !is_tx_hash(&args.tx_hash) {
        render_json(&Envelope::<()>::err_raw(
            "validation.address_invalid",
            "HASH must be 64 lowercase hex characters",
        ));
        return 1;
    }

    let resolved = resolve_profile_name(args.profile.as_deref());
    // The same origin rule the value verbs use. A zero-config operator's
    // submission is recorded on a synthesized profile, and the verb that
    // settles it has to be runnable on that same profile: refusing here would
    // leave a dropped submission holding its sequence with nothing able to
    // free it.
    let (profile, origin) = match load_profile_or_synthesize_testnet(&resolved) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(e.code(), e.message()));
            return 1;
        }
    };

    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let window = PersistedWindowStore::for_profile(&resolved.name);

    let context = crate::common::network::profile_network_context(&profile);
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            // An unreadable window file refuses before a client failure, as
            // the window is read first.
            if let Err(error) = window.pending_reservations(&profile) {
                render_json(&status_error_envelope(StatusFailure::WindowUnreadable(
                    error,
                )));
            } else {
                render_json(&Envelope::<()>::err(&e));
            }
            return 1;
        }
    };

    let oracle = crate::commands::submission_record::settlement_oracle_in(&profile, &context);
    let outcome = match submission_flow::transaction_status(
        StatusRequest {
            profile: &profile,
            profile_name: &resolved.name,
            tx_hash: &args.tx_hash,
            window: &window,
            client: &client,
            oracle: oracle.as_ref(),
        },
        stellar_agent_core::profile::schema::default_approval_dir,
        || {
            crate::commands::submission_record::accounting_audit_writer(
                &profile,
                &resolved.name,
                origin,
            )
        },
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            render_json(&status_error_envelope(error));
            return 1;
        }
    };
    let record = outcome
        .record
        .as_ref()
        .map(|settled| record_view(settled, outcome.reservation_open));

    render_json(&Envelope::ok(StatusData {
        tx_hash: args.tx_hash.clone(),
        chain_status: outcome.chain_status,
        ledger: outcome.ledger,
        record,
        reservation: outcome.reservation.map(|r| ReservationView {
            envelope_hash: r.id,
            operator_required: r.operator_required,
        }),
    }));
    0
}

fn record_view(receipt: &SubmissionReceipt, reservation_open: bool) -> RecordView {
    RecordView {
        envelope_hash: receipt.envelope_hash.clone(),
        status: receipt.status.label().to_owned(),
        failure_code: match &receipt.status {
            ReceiptStatus::Failed { code } => Some(code.clone()),
            _ => None,
        },
        ledger: receipt.ledger,
        source_redacted: stellar_agent_core::observability::redact_strkey_first5_last5(
            &receipt.source,
        ),
        sequence: receipt.sequence,
        submitted: receipt.submitted,
        reservation_open,
        release_code: receipt.release_code.map(ReleaseEvidence::code),
        settlement_evidence: "unavailable",
        settlement_decision_id: receipt.settlement_decision_id.clone(),
    }
}

fn status_error_envelope(error: StatusFailure) -> Envelope<()> {
    match error {
        StatusFailure::WindowUnreadable(e) => Envelope::err_raw(
            e.submission_code(),
            format!("the spending-window file could not be read: {e}"),
        ),
        StatusFailure::ReceiptStoreOpen { detail } => {
            Envelope::err_raw("submission.record_unavailable", detail)
        }
        StatusFailure::ApprovalDirUnavailable(e) => {
            Envelope::err_raw("submission.record_unavailable", e.to_string())
        }
        StatusFailure::ReceiptStoreRead(e) => Envelope::err_raw(
            "submission.record_unavailable",
            format!("the submission receipt store could not be read: {e}"),
        ),
        StatusFailure::ClockUnavailable(e) => {
            Envelope::err_raw("wallet.clock_error", e.to_string())
        }
        StatusFailure::ReconcileRefused(e) => Envelope::err_raw(e.submission_code(), e.to_string()),
        StatusFailure::RepairRefused(e) => Envelope::err(&e),
        StatusFailure::ChainQueryFailed(e) => Envelope::err(&WalletError::Network(e)),
    }
}
