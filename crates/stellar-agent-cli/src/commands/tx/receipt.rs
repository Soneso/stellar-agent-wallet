//! `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`: close a
//! submission record after reconciling it against the chain.
//!
//! # When this is needed
//!
//! A submission whose outcome never came back leaves a receipt behind and,
//! under a policy with a stateful criterion, a spending-window reservation
//! that counts against the operator's caps. `tx status` settles most of them
//! by asking the endpoint. This verb closes a record the operator has decided
//! about, and it reconciles first, so it decides on the chain's latest answer
//! rather than on the record as it was left.
//!
//! An absent receipt can be recovered from its authenticated reservation when
//! the endpoint reports `NOT_FOUND` and its submission ledger is below
//! retention. The recovered receipt records its provenance and carries no
//! approval metadata.
//!
//! # The decision
//!
//! Before anything else, the record's own state: a receipt recorded as
//! `success`, `failed`, `reorged` or `cleared_by_operator` is refused with
//! `submission.not_clearable`, with no side effects. Then the chain: an
//! endpoint that reports the transaction `SUCCESS` or `FAILED` is refused the
//! same way, because reconciliation settles it (`tx status`), and so is an
//! endpoint that cannot answer. An orphan needs `NOT_FOUND` and a submission
//! ledger below the endpoint's retention floor.
//!
//! Without `--acknowledge` nothing is reconciled or written: the verb exits 1
//! with `submission.acknowledgement_required`, and the message names the next
//! step, computed from the record. While a sent transaction's time bound is
//! open, that is to wait for it to pass or run `tx status`; otherwise it is
//! `--acknowledge`.
//!
//! With `--acknowledge` the verb acquires the audit writer, restores an
//! orphan's receipt from its reservation, reconciles the submission with the
//! pass `tx status` runs, re-reads the receipt and the reservation, and then:
//!
//! - **Receipt write failed.** Refused with `submission.record_unavailable`,
//!   naming the receipt-store error; run `tx status` again.
//! - **Receipt disagrees with reconciliation.** Refused with
//!   `submission.record_unavailable`; run `tx status` again.
//! - **Released on chain evidence.** The receipt carries `release_code`
//!   (`submission.sequence_consumed` or `submission.time_bound_passed`). The
//!   settled `value_action_failed` row is written under that code first, and
//!   only once it is in the log is the receipt cleared; the clear row records
//!   the evidence. A settled row that cannot be written refuses with the audit
//!   error and leaves the receipt clearable for a retry.
//! - **Outcome unknown.** An `ambiguous` receipt without evidence (the
//!   endpoint's retention window closed), a `pending` receipt with no time
//!   bound, a `pending` receipt that was never sent, or a recovered orphan.
//!   The reservation is released and the receipt cleared; the clear row
//!   records no evidence.
//! - **Still able to apply.** A sent `pending` receipt with a time bound that
//!   has not passed on the endpoint's latest ledger and a sequence that is
//!   unconsumed. Refused with `submission.still_pending`, naming the time
//!   bound; nothing changes.
//! - **Endpoint failure.** A reconciliation read failed and the reservation
//!   stood. Refused with `network.rpc_unreachable`, the code `tx status`
//!   reports when the endpoint cannot be asked; nothing more changes.
//!
//! A reconciliation that settles the transaction definitively in the meantime
//! is refused with `submission.not_clearable`; `tx status` writes its row.
//!
//! # Why the acknowledgement is required
//!
//! Clearing a record whose outcome is unknown states that the transaction did
//! not move value. The wallet cannot establish that: it is the operator's
//! judgement, made from a block explorer or a second endpoint. An untimed
//! transaction cleared this way can still apply, and its spend is then not
//! counted against the window.
//!
//! # What it leaves behind
//!
//! The receipt is marked `cleared_by_operator`, not removed, so the envelope
//! keeps its idempotency anchor: a byte-identical resubmission of those exact
//! bytes is still recognised. That costs nothing in practice, because a
//! follow-up runs a fresh simulate whose fee moves the bytes. An audit row
//! names the state the clear replaced and any release evidence. A cleared
//! receipt owes no settlement row.
//!
//! # Concurrency
//!
//! Writing the audit rows needs the audit writer's exclusive lock. If an MCP
//! server holds that profile's writer, stop it, clear, and start it again.
//! The server acquires its writer when needed, including for V1 reservation
//! reconciliation during simulation. The registry normally retains it until
//! exit. A replaced-file refusal during acquisition marks it for eviction.
//! A later acquisition drops it once callers release it.
//!
//! # Exit codes
//!
//! - 0 on success.
//! - 1 without `--acknowledge`, on every refusal above, and on any failure.
//!
//! # Where each refusal comes from
//!
//! `submission.not_clearable` and `submission.still_pending` are this verb's
//! own: the record state the local rule refuses, the chain answer that
//! contradicts the operator, and a transaction that can still apply. The
//! receipt store applies the local rule again when it is asked to mark the
//! receipt, but by then the verb has already passed it, so a refusal from the
//! store can only mean the record changed between the two checks. That is a
//! store condition rather than an operator one, and it is reported as
//! `submission.record_unavailable` along with every other write failure and a
//! reconciliation that could not read or write the spending-window file.

use clap::{Args, Subcommand};
use serde::Serialize;
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, SubmissionReceipt};
use stellar_agent_network::NetworkContext;
use stellar_agent_network::policy_state::PersistedWindowStore;

use crate::common::profile_access::{ProfileOrigin, load_profile_or_synthesize_testnet};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for the `tx receipt` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ReceiptArgs {
    /// The receipt subcommand to run.
    #[command(subcommand)]
    pub subcommand: ReceiptSubcommand,
}

/// Subcommands of `stellar-agent tx receipt`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ReceiptSubcommand {
    /// Close a submission record after reconciling it against the chain.
    Clear(ClearArgs),
}

/// Arguments for `tx receipt clear`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ClearArgs {
    /// Envelope hash of the submission to clear, 64 lowercase hex characters.
    ///
    /// `tx status` reports this as `record.envelope_hash`.
    #[arg(value_name = "ENVELOPE_HASH")]
    pub envelope_hash: String,

    /// Profile whose submission record and spending window are cleared.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// State that the transaction did not move value, and reconcile before
    /// clearing.
    ///
    /// Required. Without it the verb reports the receipt it would clear and
    /// the next step, reconciles nothing, changes nothing, and exits 1.
    #[arg(long)]
    pub acknowledge: bool,

    /// Output format.
    #[arg(long, value_parser = OutputFormat::parse, default_value = "json")]
    pub output: OutputFormat,
}

impl ReceiptArgs {
    /// The profile name this invocation operates on.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            ReceiptSubcommand::Clear(a) => a.profile.as_deref(),
        }
    }
}

/// Success payload for the `tx receipt clear` envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct ClearData {
    /// The envelope hash that was cleared.
    envelope_hash: String,
    /// The transaction hash the cleared submission carried, redacted
    /// first-8-last-8.
    tx_hash_redacted: String,
    /// The receipt status the clear replaced.
    cleared_from: String,
    /// Whether a spending-window reservation was released.
    reservation_released: bool,
}

/// Runs the `tx receipt` subcommand group.
pub async fn run(args: &ReceiptArgs) -> i32 {
    match &args.subcommand {
        ReceiptSubcommand::Clear(a) => run_clear(a).await,
    }
}

async fn run_clear(args: &ClearArgs) -> i32 {
    if !crate::commands::tx::status::is_tx_hash(&args.envelope_hash) {
        render_json(&Envelope::<()>::err_raw(
            "validation.address_invalid",
            "ENVELOPE_HASH must be 64 lowercase hex characters",
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
            render_json(&Envelope::<()>::err_raw(
                e.code(),
                e.message(&resolved.name),
            ));
            return 1;
        }
    };

    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let receipts = match ReceiptStore::open(&resolved.name) {
        Ok(store) => store,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission receipt store could not be opened: {e}"),
            ));
            return 1;
        }
    };

    let existing = match receipts.get(&args.envelope_hash) {
        Ok(record) => record,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission receipt store could not be read: {e}"),
            ));
            return 1;
        }
    };
    let window = PersistedWindowStore::for_profile(&resolved.name);
    let held = match open_reservation(&window, &profile, &args.envelope_hash) {
        Ok(held) => held,
        Err(code) => return code,
    };
    if existing.is_none() && held.is_none() {
        render_json(&Envelope::<()>::err_raw(
            "submission.record_unavailable",
            "no receipt or authenticated reservation exists for this envelope hash",
        ));
        return 1;
    }
    let recovered_identity = existing
        .as_ref()
        .is_none_or(|r| r.recovered_from_reservation);
    let tx_hash = match (&existing, &held) {
        (Some(record), _) => record.tx_hash.clone(),
        (None, Some(reservation)) => {
            if !super::status::is_tx_hash(&reservation.tx_hash)
                || stellar_strkey::ed25519::PublicKey::from_string(&reservation.source).is_err()
                || reservation.sequence <= 0
                || reservation.submission_ledger == 0
            {
                render_json(&Envelope::<()>::err_raw(
                    "submission.record_unavailable",
                    "the reservation has no complete submission identity",
                ));
                return 1;
            }
            reservation.tx_hash.clone()
        }
        (None, None) => return 1,
    };

    // The local rule first, before anything is reconciled, released or
    // written. Every precondition is evaluated ahead of the first side
    // effect, so a clear this verb will refuse leaves the wallet exactly as it
    // found it: a re-run on an already-cleared receipt, or a receipt the
    // network has answered for, writes nothing.
    if let Some(existing) = &existing
        && !existing.status.is_operator_clearable()
    {
        render_json(&Envelope::<()>::err_raw(
            "submission.not_clearable",
            format!(
                "a submission recorded as '{}' is not cleared by an operator; only a \
                 submission the endpoint cannot account for, and one whose outcome is \
                 recorded as ambiguous, are",
                existing.status.label()
            ),
        ));
        return 1;
    }

    // Then the chain. Clearing states that the transaction did not move value,
    // and the endpoint is the only thing that can contradict that. An endpoint
    // that cannot answer is not a licence to clear: a transaction in flight is
    // exactly the case the operator would be wrong about.
    let context = NetworkContext::from_profile(&profile);
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    let chain = match client.get_transaction_status(&tx_hash).await {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.not_clearable",
                format!(
                    "the endpoint could not say what became of this transaction, so the \
                     submission cannot be cleared: {e}"
                ),
            ));
            return 1;
        }
    };
    if chain.status == "SUCCESS" || chain.status == "FAILED" {
        render_json(&settled_by_reconciliation(
            &chain.status.to_lowercase(),
            &tx_hash,
        ));
        return 1;
    }

    if recovered_identity {
        let floor = match client.get_health().await {
            Ok(health) => health.oldest_ledger,
            Err(e) => {
                render_json(&Envelope::<()>::err_raw(
                    "submission.not_clearable",
                    format!("the retention floor could not be checked: {e}"),
                ));
                return 1;
            }
        };
        let submission_ledger = existing
            .as_ref()
            .map(|r| r.recorded_at_ledger)
            .or_else(|| held.as_ref().map(|r| r.submission_ledger));
        if chain.status != "NOT_FOUND"
            || !submission_ledger.is_some_and(|ledger| ledger > 0 && ledger < floor)
        {
            render_json(&Envelope::<()>::err_raw(
                "submission.not_clearable",
                "orphan recovery requires NOT_FOUND and a submission ledger below retention",
            ));
            return 1;
        }
    }

    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "wallet.clock_error",
                e.to_string(),
            ));
            return 1;
        }
    };

    if !args.acknowledge {
        render_json(&acknowledgement_required(
            existing.as_ref(),
            held.as_ref(),
            &tx_hash,
            now_ms,
        ));
        return 1;
    }

    // Prove the audit writer is acquirable before the record is changed or
    // reconciled: the clear is only recorded if the rows that name it can be
    // written. A persisted profile fails closed on it; the synthesized
    // zero-config profile has no audit key to fail on, and clearing is the
    // only thing that frees its sequence.
    let audit_writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
        &profile,
        &resolved.name,
        origin,
    ) {
        Ok(w) => w,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // An orphan's receipt is restored before the reconciliation runs. The
    // restored receipt is the durable checkpoint a re-run resumes from, and it
    // is what reconciliation records a retention-window answer on, so no
    // marker write on the window file is needed for it.
    if existing.is_none() {
        let Some(held) = &held else {
            return 1;
        };
        match receipts.recover_from_reservation(
            &held.id,
            &held.tx_hash,
            &held.source,
            held.sequence,
            held.max_time,
            held.submission_ledger,
        ) {
            Ok(record) if record.status.is_operator_clearable() => {}
            Ok(_) => {
                render_json(&Envelope::<()>::err_raw(
                    "submission.not_clearable",
                    "the receipt acquired a settled outcome during recovery",
                ));
                return 1;
            }
            Err(e) => {
                render_json(&Envelope::<()>::err_raw(
                    "submission.record_unavailable",
                    format!("the recovered receipt could not be written: {e}"),
                ));
                return 1;
            }
        }
    }

    // Reconcile with the pass `tx status` runs, so the decision below rests
    // on the chain's latest answer.
    let report = match window
        .reconcile_one(
            &profile,
            &client,
            Some(&receipts),
            &args.envelope_hash,
            now_ms,
        )
        .await
    {
        Ok(report) => report,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission could not be reconciled: {e:?}"),
            ));
            return 1;
        }
    };
    let receipt = match receipts.get(&args.envelope_hash) {
        Ok(Some(record)) => record,
        Ok(None) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                "the submission receipt is missing after reconciliation",
            ));
            return 1;
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission receipt store could not be read: {e}"),
            ));
            return 1;
        }
    };
    let held_now = match open_reservation(&window, &profile, &args.envelope_hash) {
        Ok(held) => held,
        Err(code) => return code,
    };

    let evidence = match clear_decision(&receipt, &report) {
        ClearDecision::Clear { evidence } => evidence,
        ClearDecision::Refuse(envelope) => {
            render_json(&envelope);
            return 1;
        }
    };

    // Release precedes the rows and the mark. A recovered receipt stays
    // clearable at every intermediate write, so retries finish the remaining
    // work without duplicating a row.
    if held_now.is_some()
        && let Err(e) = window.release(&profile, &args.envelope_hash)
    {
        render_json(&Envelope::<()>::err_raw(
            "submission.record_unavailable",
            format!("the spending-window reservation could not be released: {e:?}"),
        ));
        return 1;
    }
    let reservation_released = held.is_some() || held_now.is_some();
    match record_and_mark_clear(
        &profile,
        &resolved.name,
        origin,
        audit_writer.as_ref(),
        &receipts,
        &receipt,
        evidence,
        reservation_released,
        context.chain_id.caip2_str(),
    ) {
        Ok(data) => {
            render_json(&Envelope::ok(data));
            0
        }
        Err(envelope) => {
            render_json(&envelope);
            1
        }
    }
}

/// Writes the rows a clear owes and marks the receipt `cleared_by_operator`,
/// in that order.
///
/// A release on chain evidence settles the submission's value action, so its
/// settled row goes through `audit_writer` first, and the receipt is closed
/// only once that row is in the log: a failed append returns the audit error
/// before the clear row and the mark, which leaves the receipt carrying its
/// evidence and still clearable. The clear row follows, only where the log
/// does not already carry one for this submission. It precedes the mark, so a
/// failure at the mark leaves a reservation already released rather than one
/// stranded under a receipt no verb accepts again; a re-run after such a
/// failure reaches here with the rows already written and writes neither
/// again.
///
/// `audit_writer` is `None` only for a synthesized profile whose writer could
/// not be acquired; nothing is recorded for it, and the receipt is marked.
///
/// # Errors
///
/// The refusal envelope: the audit error of a row that could not be written,
/// or `submission.record_unavailable` for a receipt that could not be marked.
#[allow(
    clippy::too_many_arguments,
    reason = "the clear records the submission, its evidence and the profile's audit context"
)]
fn record_and_mark_clear(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    origin: ProfileOrigin,
    audit_writer: Option<
        &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    >,
    receipts: &ReceiptStore,
    receipt: &SubmissionReceipt,
    evidence: Option<stellar_agent_core::profile::receipt::ReleaseEvidence>,
    reservation_released: bool,
    chain_id: &str,
) -> Result<ClearData, Envelope<()>> {
    let cleared_from = receipt.status.label().to_owned();
    let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&receipt.tx_hash);

    if let (Some(evidence), Some(audit)) = (evidence, audit_writer) {
        crate::commands::submission_record::append_settled_row(
            profile,
            profile_name,
            audit,
            &receipt.envelope_hash,
            &receipt.tx_hash,
            &receipt.status,
            Some(evidence),
            stellar_agent_core::audit_log::PolicyDecision::Allow,
        )
        .map_err(|e| Envelope::<()>::err(&e))?;
    }

    let already_recorded = stellar_agent_core::audit_log::reader::submission_receipt_cleared_exists(
        &profile.audit_log_path,
        &receipt.envelope_hash,
    );
    if !already_recorded && audit_writer.is_some() {
        let request_id = uuid::Uuid::new_v4().to_string();
        let entry = AuditEntry::new_submission_receipt_cleared(
            "tx receipt clear",
            chain_id,
            tx_hash_redacted.as_str(),
            cleared_from.as_str(),
            reservation_released,
            evidence.map(|e| e.code().to_owned()),
            Some(receipt.envelope_hash.clone()),
            &request_id,
        );
        emit_clear_row(profile, profile_name, origin, entry)
            .map_err(|e| Envelope::<()>::err(&e))?;
    }

    receipts
        .clear_by_operator(&receipt.envelope_hash)
        .map_err(|e| {
            Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission receipt could not be written: {e}"),
            )
        })?;

    Ok(ClearData {
        envelope_hash: receipt.envelope_hash.clone(),
        tx_hash_redacted,
        cleared_from,
        reservation_released,
    })
}

/// Reads the reservation the window file holds pending for `envelope_hash`,
/// or renders the read failure and returns the exit code.
fn open_reservation(
    window: &PersistedWindowStore,
    profile: &stellar_agent_core::profile::schema::Profile,
    envelope_hash: &str,
) -> Result<Option<stellar_agent_network::policy_state::WindowReservation>, i32> {
    match window.pending_reservations(profile) {
        Ok(open) => Ok(open.into_iter().find(|r| r.id == envelope_hash)),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the spending-window file could not be read: {e:?}"),
            ));
            Err(1)
        }
    }
}

/// What the clear does with a reconciled submission.
#[derive(Debug)]
enum ClearDecision {
    /// Clear the receipt. `evidence` is the chain evidence its reservation was
    /// released on, whose settled row precedes the clear; `None` records an
    /// unknown outcome.
    Clear {
        /// The release evidence the receipt carries.
        evidence: Option<stellar_agent_core::profile::receipt::ReleaseEvidence>,
    },
    /// Refuse with this envelope; nothing more changes.
    Refuse(Envelope<()>),
}

/// Applies the decision table to the receipt as reconciliation left it.
///
/// An orphan's receipt restored under the retention rule is `Ambiguous`
/// without evidence, so it is cleared with an unknown outcome.
fn clear_decision(
    receipt: &SubmissionReceipt,
    report: &stellar_agent_network::policy_state::ReconcileReport,
) -> ClearDecision {
    // A definitive answer that arrived during reconciliation settles the
    // submission; reconciliation's own surface writes its row.
    if !receipt.status.is_operator_clearable() {
        return ClearDecision::Refuse(settled_by_reconciliation(
            receipt.status.label(),
            &receipt.tx_hash,
        ));
    }
    if let Some(error) = &report.receipt_write_error {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.record_unavailable",
            format!(
                "the reconciled outcome of this submission could not be recorded on its receipt: \
                 {error}; run `stellar-agent tx status` on it again"
            ),
        ));
    }
    if report.settled.iter().any(|settled| {
        settled.envelope_hash == receipt.envelope_hash
            && (settled.status != receipt.status || settled.release_code != receipt.release_code)
    }) {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.record_unavailable",
            "the submission receipt disagrees with its reconciliation; \
             run `stellar-agent tx status` on it again",
        ));
    }
    // Released on chain evidence: the settled row, then the clear.
    if receipt.status == ReceiptStatus::Ambiguous && receipt.release_code.is_some() {
        return ClearDecision::Clear {
            evidence: receipt.release_code,
        };
    }
    // A reservation the endpoint could not answer for stood: nothing about
    // the transaction was established, so nothing is cleared on it.
    if report.kept_pending > 0
        && let Some(failure) = &report.endpoint_failure
    {
        return ClearDecision::Refuse(Envelope::<()>::err(
            &stellar_agent_core::error::WalletError::Network(failure.to_network_error()),
        ));
    }
    // A sent transaction whose time bound has not passed on the endpoint's
    // latest ledger, and whose sequence is unconsumed, can still apply.
    if receipt.status == ReceiptStatus::Pending && receipt.submitted && receipt.max_time > 0 {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.still_pending",
            format!(
                "transaction {} can still apply: its time bound (maxTime {}) has not passed on \
                 the endpoint's latest ledger and its sequence is unconsumed; wait for the \
                 bound to pass and run 'stellar-agent tx status' on it, which releases the \
                 reservation",
                stellar_agent_network::redact_tx_hash(&receipt.tx_hash),
                receipt.max_time,
            ),
        ));
    }
    // The outcome is unknown and nothing more can establish it: the
    // operator's acknowledgement decides.
    ClearDecision::Clear { evidence: None }
}

/// The refusal for a submission the chain answered for.
fn settled_by_reconciliation(answer: &str, tx_hash: &str) -> Envelope<()> {
    Envelope::<()>::err_raw(
        "submission.not_clearable",
        format!(
            "the endpoint reports this transaction as {answer}, so the submission is settled \
             by reconciliation rather than by an operator; run 'stellar-agent tx status {}'",
            stellar_agent_network::redact_tx_hash(tx_hash),
        ),
    )
}

/// The refusal without `--acknowledge`, naming the next step computed from
/// the record without reconciling: a sent transaction whose time bound is
/// still open on the host clock waits or goes to `tx status`, and every other
/// record needs the acknowledgement.
fn acknowledgement_required(
    existing: Option<&SubmissionReceipt>,
    held: Option<&stellar_agent_network::policy_state::WindowReservation>,
    tx_hash: &str,
    now_ms: u64,
) -> Envelope<()> {
    let label = existing.map_or("orphaned", |r| r.status.label());
    let redacted = stellar_agent_network::redact_tx_hash(tx_hash);
    let releasing = if held.is_some() {
        ", releasing its spending-window reservation"
    } else {
        ""
    };
    let open_bound = existing.and_then(|r| {
        (r.status == ReceiptStatus::Pending
            && r.submitted
            && r.max_time > 0
            && now_ms / 1_000 <= r.max_time)
            .then_some(r.max_time)
    });
    let next = match open_bound {
        Some(max_time) => format!(
            "its time bound (maxTime {max_time}) is still open, so it can still apply: wait for \
             the bound to pass, or run 'stellar-agent tx status {redacted}'"
        ),
        None => "pass --acknowledge to state that the transaction did not move value; the clear \
                 reconciles the submission first"
            .to_owned(),
    };
    Envelope::<()>::err_raw(
        "submission.acknowledgement_required",
        format!(
            "this would clear the {label} submission for transaction {redacted}{releasing}; \
             {next}"
        ),
    )
}

/// Writes the clear's row under the audit binding check of the profile's
/// origin, so a synthesized profile records no binding.
fn emit_clear_row(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    origin: ProfileOrigin,
    entry: AuditEntry,
) -> Result<(), stellar_agent_core::error::WalletError> {
    crate::commands::value_audit::emit_value_audit_row_strict(
        profile,
        profile_name,
        origin.binding_check(),
        entry,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only assertions")]

    use serial_test::serial;
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_network::keyring::{KeyringAuditBindingStore, rotate_keyring_secret_32};
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    fn cleared_entry() -> AuditEntry {
        AuditEntry::new_submission_receipt_cleared(
            "tx receipt clear",
            "stellar:testnet",
            "2222…22bb",
            "pending",
            true,
            None,
            None,
            "req-receipt-clear",
        )
    }

    /// The clear's row records an absent binding for a persisted profile and
    /// records none for a synthesized one; both rows are written.
    #[test]
    #[serial]
    fn the_clear_row_applies_the_binding_check_of_the_origin() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        for (name, origin, recorded) in [
            ("receipt-synthesized", ProfileOrigin::Synthesized, false),
            ("receipt-persisted", ProfileOrigin::Persisted, true),
        ] {
            let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
            profile.audit_log_path = dir.path().join(format!("{name}.jsonl"));
            let coord = &profile.audit_log_hash_chain_key_id;
            rotate_keyring_secret_32(&coord.service, &coord.account).expect("seed audit key");

            emit_clear_row(&profile, name, origin, cleared_entry()).expect("the row is written");

            assert!(
                std::fs::read_to_string(&profile.audit_log_path)
                    .expect("read log")
                    .contains("submission_receipt_cleared"),
                "{name}: the row is written"
            );
            assert_eq!(
                KeyringAuditBindingStore::for_profile(name)
                    .load_raw()
                    .expect("read binding")
                    .is_some(),
                recorded,
                "{name}: a binding is recorded for a persisted profile only"
            );
        }
    }

    /// The clear is recorded and the receipt marked only once the settled row
    /// of a release on chain evidence is in the log.
    ///
    /// The settled row's writer cannot append while the profile's own log
    /// can. The failed settlement keeps the receipt clearable for a retry.
    #[test]
    #[serial]
    fn a_clear_waits_for_the_settled_row_of_an_evidence_release() {
        use stellar_agent_core::profile::receipt::{ReceiptStatus, ReleaseEvidence};

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "receipt-settled-first";
        let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
        profile.audit_log_path = dir.path().join("audit").join("log.jsonl");
        let coord = &profile.audit_log_hash_chain_key_id;
        rotate_keyring_secret_32(&coord.service, &coord.account).expect("seed audit key");

        let envelope_hash = "1a".repeat(32);
        let receipts = ReceiptStore::open_at(&dir.path().join("receipts"), name).expect("store");
        receipts
            .try_begin(
                &envelope_hash,
                &"2b".repeat(32),
                "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
                1,
                0,
                100,
            )
            .expect("receipt");
        receipts.mark_submitted(&envelope_hash).expect("sent");
        receipts
            .finalize_released(&envelope_hash, ReleaseEvidence::SequenceConsumed)
            .expect("released");
        let receipt = receipts
            .get(&envelope_hash)
            .expect("read")
            .expect("present");

        // A keyed writer, for a log of its own, that stops being appendable
        // after it was acquired.
        let broken_name = "receipt-settled-broken";
        let mut broken_profile =
            Profile::builder_testnet_named(broken_name, "s", broken_name, "n", broken_name).build();
        let broken_dir = dir.path().join("broken");
        broken_profile.audit_log_path = broken_dir.join("log.jsonl");
        let broken_coord = &broken_profile.audit_log_hash_chain_key_id;
        rotate_keyring_secret_32(&broken_coord.service, &broken_coord.account)
            .expect("seed the second audit key");
        let broken =
            crate::commands::value_audit::require_value_audit_writer(&broken_profile, broken_name)
                .expect("the second writer");
        std::fs::rename(&broken_dir, dir.path().join("moved")).expect("move");
        std::fs::write(&broken_dir, b"not a directory").expect("block");

        let refused = record_and_mark_clear(
            &profile,
            name,
            ProfileOrigin::Persisted,
            Some(&broken),
            &receipts,
            &receipt,
            Some(ReleaseEvidence::SequenceConsumed),
            false,
            "stellar:testnet",
        )
        .expect_err("a settled row that cannot be appended refuses the clear");
        let code = refused.error.as_ref().expect("error").code.clone();
        assert!(code.starts_with("audit."), "{code}");
        let kept = receipts
            .get(&envelope_hash)
            .expect("read")
            .expect("present");
        assert_eq!(
            kept.status,
            ReceiptStatus::Ambiguous,
            "the receipt stays clearable"
        );
        assert_eq!(kept.release_code, Some(ReleaseEvidence::SequenceConsumed));
        assert!(
            std::fs::read_to_string(&profile.audit_log_path)
                .unwrap_or_default()
                .is_empty(),
            "no clear row precedes the settled row"
        );

        let writer = crate::commands::value_audit::require_value_audit_writer(&profile, name)
            .expect("the profile's writer");
        let cleared = record_and_mark_clear(
            &profile,
            name,
            ProfileOrigin::Persisted,
            Some(&writer),
            &receipts,
            &receipt,
            Some(ReleaseEvidence::SequenceConsumed),
            false,
            "stellar:testnet",
        )
        .expect("the retry clears");
        assert_eq!(cleared.cleared_from, "ambiguous");
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .expect("log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("row"))
            .collect();
        let kinds: Vec<&str> = rows
            .iter()
            .map(|r| r["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(kinds, ["value_action_failed", "submission_receipt_cleared"]);
        assert_eq!(rows[0]["code"], "submission.sequence_consumed");
        assert_eq!(rows[1]["evidence"], "submission.sequence_consumed");
        assert_eq!(
            receipts
                .get(&envelope_hash)
                .expect("read")
                .expect("present")
                .status,
            ReceiptStatus::ClearedByOperator
        );
    }

    /// A failed receipt write or a disagreement prevents the operator clear.
    #[test]
    fn a_clear_refuses_an_unrecorded_reconciliation() {
        use stellar_agent_network::policy_state::{ReconcileReport, SettledSubmission};

        let dir = tempfile::tempdir().expect("tmp dir");
        let receipts = ReceiptStore::open_at(dir.path(), "clear-checkpoint").expect("store");
        let id = "5a".repeat(32);
        receipts
            .try_begin(&id, &"6b".repeat(32), "GSOURCE", 7, 0, 100)
            .expect("receipt");
        let receipt = receipts.get(&id).expect("read").expect("present");
        let failed = ReconcileReport {
            receipt_write_failed: 1,
            receipt_write_error: Some("receipt store writer is locked".to_owned()),
            ..ReconcileReport::default()
        };
        let disagrees = ReconcileReport {
            settled: vec![SettledSubmission {
                envelope_hash: id,
                tx_hash: receipt.tx_hash.clone(),
                status: ReceiptStatus::Success,
                release_code: None,
                ledger: Some(150),
            }],
            ..ReconcileReport::default()
        };
        for report in [failed, disagrees] {
            let decision = clear_decision(&receipt, &report);
            assert!(matches!(decision, ClearDecision::Refuse(_)));
            if let ClearDecision::Refuse(refusal) = decision {
                assert_eq!(
                    refusal.error.as_ref().expect("refusal").code,
                    "submission.record_unavailable"
                );
                if let Some(error) = report.receipt_write_error {
                    assert!(refusal.error.expect("refusal").message.contains(&error));
                }
            }
        }
    }
}
