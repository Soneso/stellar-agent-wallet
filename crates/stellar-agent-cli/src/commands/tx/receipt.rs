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
//! endpoint that cannot answer. On a mainnet profile that names an oracle,
//! the oracle is asked as well and refuses the clear the same way: its
//! `SUCCESS` or `FAILED`, an oracle that cannot answer, an oracle that does
//! not report the mainnet passphrase or whose identity cannot be read, and an
//! oracle client that cannot be built. Every oracle read of the command,
//! these and reconciliation's below, ends by one deadline: the profile's
//! submit timeout, counted from the oracle's identity read. A mainnet profile without an oracle
//! has no second answer to ask for: the primary's `FAILED` is a claim nothing
//! confirms and reconciliation does not settle on it, so it is not refused
//! here and the clear proceeds on the acknowledgement; the primary's
//! `SUCCESS` is still refused. An orphan needs `NOT_FOUND` and a submission
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
//! - **Audit history lookup fails.** Refused with the verifier's code, such as
//!   `audit.chain_broken` for a broken chain, where the profile has an audit
//!   writer. The receipt remains clearable for a retry.
//! - **Released on chain evidence.** The receipt carries `release_code`
//!   (`submission.sequence_consumed` or `submission.time_bound_passed`), and
//!   the release is established by the authenticated spending window rather
//!   than by the receipt: this run's reconciliation released the reservation
//!   under that code, or the window no longer holds it because an earlier
//!   pass did. The settled `value_action_failed` row is written under that
//!   code first, and only once it is in the log is the receipt cleared; the
//!   clear row records the evidence. A settled row that cannot be written
//!   refuses with the audit error and leaves the receipt clearable for a
//!   retry. A receipt whose code the window does not bear out is decided by
//!   the rows below, as an unknown outcome.
//! - **Outcome unknown.** An `ambiguous` receipt without evidence (the
//!   endpoint's retention window closed), a `pending` receipt with no time
//!   bound, a `pending` receipt that was never sent, or a recovered orphan.
//!   The reservation is released and the receipt cleared; the clear row
//!   records no evidence.
//! - **Still able to apply.** A sent `pending` receipt with a time bound that
//!   has not passed on the endpoint's latest ledger and a sequence that is
//!   unconsumed. Refused with `submission.still_pending`, naming the time
//!   bound; nothing changes. On a mainnet profile without an oracle,
//!   reconciliation establishes neither, so the time bound is read on this
//!   host's clock: refused while it has not passed, and an unknown outcome
//!   once it has.
//! - **Endpoint failure.** A reconciliation read of the endpoint or the
//!   oracle failed, or a read of the oracle was still open at the command's
//!   oracle deadline, and the reservation stood. Refused with
//!   `network.rpc_unreachable`, the code `tx status` reports when the
//!   endpoint cannot be asked; nothing more changes. Reconciliation asks the
//!   oracle the pre-check found serving mainnet and does not read its
//!   identity again, so the audit writer is held for at most that deadline
//!   while the oracle is asked.
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
use stellar_agent_network::MainnetOracle;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, ReconcileFailureKind, ReconcileReport, SubmissionHold,
};

use crate::common::profile_access::load_profile_or_synthesize_testnet;
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
    let context = crate::common::network::profile_network_context(&profile);
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    // On a mainnet profile the primary endpoint's answer is not the only one
    // that counts: the oracle the profile names is asked the same question
    // below. Without an oracle there is no second answer.
    let oracle = if profile.chain_id.is_mainnet() {
        match context.oracle_client(&profile) {
            Ok(oracle) => oracle,
            Err(e) => {
                render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        }
    } else {
        None
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
    // A mainnet primary's FAILED without an oracle is a claim nothing can
    // confirm: reconciliation keeps the reservation on it, and `tx status`
    // cannot settle it either. It goes on to the acknowledged unknown outcome
    // and its time-bound guard rather than being refused here.
    let unconfirmable_failure =
        chain.status == "FAILED" && profile.chain_id.is_mainnet() && oracle.is_none();
    if chain.status == "SUCCESS" || (chain.status == "FAILED" && !unconfirmable_failure) {
        render_json(&settled_by_reconciliation(
            "the endpoint",
            &chain.status.to_lowercase(),
            &tx_hash,
        ));
        return 1;
    }

    // One deadline ends every oracle read of this command: the pre-check's
    // here and the reconciliation's below, which runs while the verb holds
    // the audit writer, so a stalled oracle cannot keep the writer past the
    // profile's submit timeout.
    let oracle_deadline = tokio::time::Instant::now() + profile.submit_timeout();
    // The oracle is refused on the same terms as the endpoint, and only an
    // oracle that reports mainnet answers at all. The oracle checked here is
    // the one reconciliation asks.
    let checked_oracle = match &oracle {
        Some(oracle) => match oracle_precheck(oracle, &tx_hash, oracle_deadline).await {
            Ok(checked) => Some(checked),
            Err(refusal) => {
                render_json(&refusal);
                return 1;
            }
        },
        None => None,
    };

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
    // on the chain's latest answer, asking the oracle the pre-check checked
    // and ending each of its reads by the command's oracle deadline.
    let report = match window
        .reconcile_one_within(
            &profile,
            &client,
            checked_oracle,
            Some(&receipts),
            &args.envelope_hash,
            now_ms,
            oracle_deadline,
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

    let evidence = match clear_decision(&receipt, &report, held_now.as_ref(), now_ms) {
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
/// Where the profile has an audit writer, a release on chain evidence
/// settles the submission's value action through `audit_writer` first.
/// A failed append or an unreadable settlement history refuses before the
/// clear row and the mark. The receipt keeps its evidence and stays clearable.
/// The clear row follows only where retained history carries none for this
/// submission. With an audit writer, an unreadable clear history also refuses
/// before the row and the mark.
///
/// The clear row precedes the mark, so a failed mark leaves the reservation
/// released and the receipt clearable. A repeated clear finds the rows already
/// written and writes neither again.
///
/// The clear's history lookup and its row run under one guard of
/// `audit_writer`, the writer the caller acquired under the audit binding
/// check of the profile's origin. The lookup reads up to the writer's
/// verified tip, so a clear row appended to the file outside the writer does
/// not stand in for the one this clear writes.
///
/// `audit_writer` is `None` only for a synthesized profile whose writer could
/// not be acquired; nothing is recorded for it, no history is read, and the
/// receipt is marked.
///
/// # Errors
///
/// The refusal envelope: the audit error of a row that could not be written,
/// the verifier's `audit.*` code and message for a history that could not be
/// read, or `submission.record_unavailable` for a receipt that could not be
/// marked.
#[allow(
    clippy::too_many_arguments,
    reason = "the clear records the submission, its evidence and the profile's audit context"
)]
fn record_and_mark_clear(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
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
        )?;
    }

    if let Some(audit) = audit_writer {
        let mut guard = audit.lock().map_err(|_| {
            Envelope::<()>::err(&crate::commands::value_audit::audit_writer_open_failed(
                profile_name,
            ))
        })?;
        let already_recorded =
            stellar_agent_core::audit_log::reader::try_submission_receipt_cleared_exists(
                &guard,
                &receipt.envelope_hash,
            )
            .map_err(|error| Envelope::err_raw(error.wire_code(), error.to_string()))?;
        if !already_recorded {
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
            crate::commands::value_audit::append_value_audit_row_strict(
                &mut guard,
                profile_name,
                entry,
            )
            .map_err(|e| Envelope::<()>::err(&e))?;
        }
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
) -> Result<Option<stellar_agent_network::policy_state::SubmissionHold>, i32> {
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
/// `held_now` is the reservation the window holds for the submission after
/// reconciliation, and `now_ms` the host clock.
///
/// An orphan's receipt restored under the retention rule is `Ambiguous`
/// without evidence, so it is cleared with an unknown outcome.
fn clear_decision(
    receipt: &SubmissionReceipt,
    report: &ReconcileReport,
    held_now: Option<&SubmissionHold>,
    now_ms: u64,
) -> ClearDecision {
    // A definitive answer that arrived during reconciliation settles the
    // submission; reconciliation's own surface writes its row.
    if !receipt.status.is_operator_clearable() {
        return ClearDecision::Refuse(settled_by_reconciliation(
            "reconciliation",
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
    // Released on chain evidence: the settled row, then the clear. The
    // receipt file is unauthenticated, so its code is evidence only where the
    // authenticated window bears it out: this run's reconciliation released
    // the reservation under that code, or the window no longer holds the
    // reservation because an earlier pass released it. Any other code is
    // decided below as an unknown outcome.
    if receipt.status == ReceiptStatus::Ambiguous
        && let Some(code) = receipt.release_code
        && (held_now.is_none()
            || report.settled.iter().any(|settled| {
                settled.envelope_hash == receipt.envelope_hash && settled.release_code == Some(code)
            }))
    {
        return ClearDecision::Clear {
            evidence: Some(code),
        };
    }
    // On a mainnet profile without an oracle, reconciliation reports the
    // missing witness rather than an endpoint it could not read; the
    // acknowledgement decides there.
    let unwitnessed = report
        .endpoint_failure
        .as_ref()
        .is_some_and(|failure| failure.kind == ReconcileFailureKind::OracleNotConfigured);
    // A reservation the endpoint could not answer for stood: nothing about
    // the transaction was established, so nothing is cleared on it.
    if report.kept_pending > 0
        && !unwitnessed
        && let Some(failure) = &report.endpoint_failure
    {
        return ClearDecision::Refuse(Envelope::<()>::err(
            &stellar_agent_core::error::WalletError::Network(failure.to_network_error()),
        ));
    }
    // Without a witness nothing establishes whether a timed transaction can
    // still apply, so its time bound is read on the host clock: it can apply
    // until the bound passes.
    if unwitnessed
        && receipt.status == ReceiptStatus::Pending
        && receipt.submitted
        && receipt.max_time > 0
        && now_ms / 1_000 <= receipt.max_time
    {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.still_pending",
            format!(
                "transaction {} can still apply: its time bound (maxTime {}) has not passed on \
                 this host's clock, and the profile names no oracle to establish more; wait for \
                 the bound to pass and run this command again",
                stellar_agent_network::redact_tx_hash(&receipt.tx_hash),
                receipt.max_time,
            ),
        ));
    }
    // A sent transaction whose time bound has not passed on the endpoint's
    // latest ledger, and whose sequence is unconsumed, can still apply.
    if !unwitnessed
        && receipt.status == ReceiptStatus::Pending
        && receipt.submitted
        && receipt.max_time > 0
    {
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

/// Checks that the oracle serves mainnet and asks it what became of
/// `tx_hash`, both reads bounded by `deadline`, and returns the checked
/// oracle for the reconciliation that follows.
///
/// # Errors
///
/// The refusal of the clear, when the oracle does not report the mainnet
/// passphrase, reports the transaction `SUCCESS` or `FAILED`, or cannot
/// answer. A `NOT_FOUND` from the oracle refuses nothing: the acknowledgement
/// and reconciliation decide.
async fn oracle_precheck<'o>(
    oracle: &'o stellar_agent_network::StellarRpcClient,
    tx_hash: &str,
    deadline: tokio::time::Instant,
) -> Result<MainnetOracle<'o>, Envelope<()>> {
    let oracle = match MainnetOracle::verify(oracle, deadline).await {
        Ok(oracle) => oracle,
        Err(e) => {
            return Err(Envelope::<()>::err_raw(
                "submission.not_clearable",
                format!(
                    "the oracle did not establish that it serves mainnet, so its answer does \
                     not count and the submission cannot be cleared: {e}"
                ),
            ));
        }
    };
    let answer =
        match tokio::time::timeout_at(deadline, oracle.client().get_transaction_status(tx_hash))
            .await
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => {
                return Err(Envelope::<()>::err_raw(
                    "submission.not_clearable",
                    format!(
                        "the oracle could not say what became of this transaction, so the \
                     submission cannot be cleared: {e}"
                    ),
                ));
            }
            Err(_) => {
                return Err(Envelope::<()>::err_raw(
                    "submission.not_clearable",
                    "the oracle did not say what became of this transaction in time, so the \
                 submission cannot be cleared",
                ));
            }
        };
    if answer.status == "SUCCESS" || answer.status == "FAILED" {
        return Err(settled_by_reconciliation(
            "the oracle",
            &answer.status.to_lowercase(),
            tx_hash,
        ));
    }
    Ok(oracle)
}

/// The refusal for a submission the chain answered for, as `source` (the
/// endpoint, the oracle, or the reconciliation that recorded the answer)
/// reported it.
fn settled_by_reconciliation(source: &str, answer: &str, tx_hash: &str) -> Envelope<()> {
    Envelope::<()>::err_raw(
        "submission.not_clearable",
        format!(
            "{source} reports this transaction as {answer}, so the submission is settled by \
             reconciliation rather than by an operator; run 'stellar-agent tx status {}'",
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
    held: Option<&stellar_agent_network::policy_state::SubmissionHold>,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only assertions")]

    use serial_test::serial;
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_network::keyring::{KeyringAuditBindingStore, rotate_keyring_secret_32};
    use stellar_agent_test_support::keyring_mock;

    use super::*;
    use crate::common::profile_access::ProfileOrigin;

    /// A receipt store under `dir` holding one submitted receipt for
    /// `envelope_hash`, and that receipt.
    fn submitted_receipt_in(
        dir: &std::path::Path,
        name: &str,
        envelope_hash: &str,
    ) -> (ReceiptStore, SubmissionReceipt) {
        let receipts = ReceiptStore::open_at(dir, name).expect("store");
        receipts
            .try_begin(
                envelope_hash,
                &"9c".repeat(32),
                "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
                1,
                0,
                100,
            )
            .expect("receipt");
        receipts.mark_submitted(envelope_hash).expect("sent");
        let receipt = receipts.get(envelope_hash).expect("read").expect("present");
        (receipts, receipt)
    }

    /// The clear's row is written through the writer acquired under the
    /// binding check of the profile's origin: a persisted profile records its
    /// binding and a synthesized one records none; both rows are written.
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

            let writer = crate::commands::value_audit::require_value_audit_writer_for_origin(
                &profile, name, origin,
            )
            .expect("the writer")
            .expect("a keyed writer");
            let (receipts, receipt) = submitted_receipt_in(
                &dir.path().join(format!("{name}-receipts")),
                name,
                &"7a".repeat(32),
            );
            record_and_mark_clear(
                &profile,
                name,
                Some(&writer),
                &receipts,
                &receipt,
                None,
                true,
                "stellar:testnet",
            )
            .expect("the clear is recorded");

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
        assert_eq!(
            kinds,
            [
                "audit_entry_tags_started",
                "value_action_failed",
                "submission_receipt_cleared"
            ]
        );
        assert_eq!(rows[1]["code"], "submission.sequence_consumed");
        assert_eq!(rows[2]["evidence"], "submission.sequence_consumed");
        assert_eq!(
            receipts
                .get(&envelope_hash)
                .expect("read")
                .expect("present")
                .status,
            ReceiptStatus::ClearedByOperator
        );
    }

    /// Keeps the active file valid while a lookup into its archive refuses.
    fn break_clear_history(
        path: &std::path::Path,
        writer: &mut stellar_agent_core::audit_log::AuditWriter,
    ) {
        use stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold;
        use stellar_agent_core::audit_log::test_helpers::break_newest_archive_link;
        use stellar_agent_core::audit_log::{NewToolInvocation, PolicyDecision};

        let unrelated = |request_id: &str| {
            AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_balance",
                "stellar:testnet",
                Vec::new(),
                PolicyDecision::Allow,
                request_id,
            ))
        };
        for request_id in ["first", "second"] {
            writer.write_entry(unrelated(request_id)).expect("row");
        }
        let size = std::fs::metadata(path).expect("log size").len();
        let threshold = set_rotation_threshold(path, size);
        writer.write_entry(unrelated("active")).expect("row");
        drop(threshold);
        break_newest_archive_link(path);
    }

    /// A clear lookup that cannot read the retained history refuses before the
    /// clear row and the mark, and the receipt stays as it was.
    ///
    /// The receipt carries no release evidence, so no settled row is owed and
    /// the strict settlement has nothing to look up. The active file holds no
    /// clear row for the submission, so the clear lookup visits the archive,
    /// whose interior link is broken.
    #[test]
    #[serial]
    fn a_clear_lookup_that_cannot_read_the_history_refuses_and_keeps_the_receipt() {
        use stellar_agent_core::profile::receipt::ReceiptStatus;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "receipt-clear-unreadable";
        let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
        profile.audit_log_path = dir.path().join("audit").join("log.jsonl");
        let coord = &profile.audit_log_hash_chain_key_id;
        rotate_keyring_secret_32(&coord.service, &coord.account).expect("seed audit key");
        let writer = crate::commands::value_audit::require_value_audit_writer(&profile, name)
            .expect("the profile's writer");
        break_clear_history(
            &profile.audit_log_path,
            &mut writer.lock().expect("writer lock"),
        );
        let active = std::fs::read(&profile.audit_log_path).expect("active file");

        let envelope_hash = "3c".repeat(32);
        let receipts = ReceiptStore::open_at(&dir.path().join("receipts"), name).expect("store");
        receipts
            .try_begin(
                &envelope_hash,
                &"4d".repeat(32),
                "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
                1,
                0,
                100,
            )
            .expect("receipt");
        receipts.mark_submitted(&envelope_hash).expect("sent");
        let receipt = receipts
            .get(&envelope_hash)
            .expect("read")
            .expect("present");

        let refused = record_and_mark_clear(
            &profile,
            name,
            Some(&writer),
            &receipts,
            &receipt,
            None,
            false,
            "stellar:testnet",
        )
        .expect_err("a clear lookup that cannot read the history refuses the clear");
        let error = refused.error.as_ref().expect("error");
        assert_eq!(error.code, "audit.chain_broken", "{}", error.message);
        assert!(
            error.message.contains("audit.chain_broken"),
            "the refusal names the integrity error: {}",
            error.message
        );
        assert!(
            !error.message.contains("on open"),
            "a lookup failure is not a writer-open failure: {}",
            error.message
        );
        assert_eq!(
            receipts
                .get(&envelope_hash)
                .expect("read")
                .expect("present")
                .status,
            ReceiptStatus::Pending,
            "the receipt stays as it was"
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).expect("active file"),
            active,
            "no clear row is written"
        );
    }

    /// A clear row appended past the writer's verified tip does not stand in
    /// for the clear's own row: the clear writes its row.
    #[test]
    fn a_forged_cleared_row_past_the_tip_does_not_suppress_the_clear_row() {
        use stellar_agent_core::audit_log::AuditWriter;

        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "receipt-clear-forged";
        let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let writer = std::sync::Arc::new(std::sync::Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).expect("writer"),
        ));
        let envelope_hash = "8b".repeat(32);
        stellar_agent_core::audit_log::test_helpers::append_forged_entry(
            &profile.audit_log_path,
            AuditEntry::new_submission_receipt_cleared(
                "tx receipt clear",
                "stellar:testnet",
                "9c9c9c9c...9c9c9c9c",
                "pending",
                false,
                None,
                Some(envelope_hash.clone()),
                "req-forged-clear",
            ),
            |_| None,
        );
        let (receipts, receipt) =
            submitted_receipt_in(&dir.path().join("receipts"), name, &envelope_hash);

        record_and_mark_clear(
            &profile,
            name,
            Some(&writer),
            &receipts,
            &receipt,
            None,
            false,
            "stellar:testnet",
        )
        .expect("the clear is recorded");

        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .expect("log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("row"))
            .collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[1]["kind"], "submission_receipt_cleared");
        assert_ne!(rows[1]["request_id"], "req-forged-clear");
    }

    /// A synthesized profile without a writer clears its receipt even when
    /// retained audit history cannot be read, since it owes no audit row.
    #[test]
    fn a_synthesized_clear_without_a_writer_skips_broken_history() {
        use stellar_agent_core::audit_log::{AuditWriter, reader, verify::VerifyError};
        use stellar_agent_core::profile::receipt::ReceiptStatus;

        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "receipt-clear-no-writer";
        let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let envelope_hash = "5e".repeat(32);
        {
            let mut writer =
                AuditWriter::open(profile.audit_log_path.clone(), None).expect("fixture writer");
            break_clear_history(&profile.audit_log_path, &mut writer);
            assert!(matches!(
                reader::try_submission_receipt_cleared_exists(&writer, &envelope_hash),
                Err(VerifyError::ChainBroken { .. })
            ));
        }
        let active = std::fs::read(&profile.audit_log_path).expect("active file");
        let receipts = ReceiptStore::open_at(&dir.path().join("receipts"), name).expect("store");
        receipts
            .try_begin(
                &envelope_hash,
                &"6f".repeat(32),
                "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
                1,
                0,
                100,
            )
            .expect("receipt");
        receipts.mark_submitted(&envelope_hash).expect("sent");
        let receipt = receipts
            .get(&envelope_hash)
            .expect("read")
            .expect("present");
        let cleared = record_and_mark_clear(
            &profile,
            name,
            None,
            &receipts,
            &receipt,
            None,
            false,
            "stellar:testnet",
        )
        .expect("a clear without a writer skips the broken history");
        assert_eq!(cleared.cleared_from, "pending");
        assert_eq!(
            receipts
                .get(&envelope_hash)
                .expect("read")
                .expect("present")
                .status,
            ReceiptStatus::ClearedByOperator
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).expect("active file"),
            active,
            "no clear row is written"
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
            let decision = clear_decision(&receipt, &report, None, 0);
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

    /// A submitted receipt for `clear_decision`, read back from a store.
    fn submitted_receipt(max_time: u64) -> SubmissionReceipt {
        let dir = tempfile::tempdir().expect("tmp dir");
        let receipts = ReceiptStore::open_at(dir.path(), "clear-decision").expect("store");
        let id = "7c".repeat(32);
        receipts
            .try_begin(&id, &"8d".repeat(32), "GSOURCE", 7, max_time, 100)
            .expect("receipt");
        receipts.mark_submitted(&id).expect("submitted");
        receipts.get(&id).expect("read").expect("present")
    }

    /// The reservation the window holds for `receipt`.
    fn held_for(receipt: &SubmissionReceipt) -> SubmissionHold {
        SubmissionHold {
            id: receipt.envelope_hash.clone(),
            tx_hash: receipt.tx_hash.clone(),
            source: receipt.source.clone(),
            sequence: 7,
            max_time: receipt.max_time,
            pending_since_ms: 0,
            submission_ledger: 100,
            operator_required: false,
        }
    }

    /// The code and message of a refusal, or `None` for a clear.
    fn refusal_of(decision: ClearDecision) -> Option<(String, String)> {
        match decision {
            ClearDecision::Refuse(refusal) => {
                refusal.error.map(|error| (error.code, error.message))
            }
            ClearDecision::Clear { .. } => None,
        }
    }

    /// A receipt's release code is evidence only where the window bears it
    /// out: this run released the reservation under it, or the window no
    /// longer holds the reservation. A code on a receipt whose reservation
    /// stands, with no release this run, clears as an unknown outcome.
    #[test]
    fn a_release_code_the_window_does_not_bear_out_is_no_evidence() {
        use stellar_agent_core::profile::receipt::ReleaseEvidence;
        use stellar_agent_network::policy_state::SettledSubmission;

        let mut receipt = submitted_receipt(0);
        receipt.status = ReceiptStatus::Ambiguous;
        receipt.release_code = Some(ReleaseEvidence::SequenceConsumed);
        let held = held_for(&receipt);

        let decision = clear_decision(&receipt, &ReconcileReport::default(), Some(&held), 0);
        assert!(
            matches!(decision, ClearDecision::Clear { evidence: None }),
            "{decision:?}"
        );

        let released_now = ReconcileReport {
            released: 1,
            settled: vec![SettledSubmission {
                envelope_hash: receipt.envelope_hash.clone(),
                tx_hash: receipt.tx_hash.clone(),
                status: ReceiptStatus::Ambiguous,
                release_code: Some(ReleaseEvidence::SequenceConsumed),
                ledger: None,
            }],
            ..ReconcileReport::default()
        };
        let decision = clear_decision(&receipt, &released_now, Some(&held), 0);
        assert!(
            matches!(
                decision,
                ClearDecision::Clear {
                    evidence: Some(ReleaseEvidence::SequenceConsumed)
                }
            ),
            "{decision:?}"
        );

        let decision = clear_decision(&receipt, &ReconcileReport::default(), None, 0);
        assert!(
            matches!(
                decision,
                ClearDecision::Clear {
                    evidence: Some(ReleaseEvidence::SequenceConsumed)
                }
            ),
            "{decision:?}"
        );
    }

    /// Without an oracle a timed submission is decided on the host clock: it
    /// can apply until its time bound passes, and the acknowledgement decides
    /// after. An endpoint that could not answer refuses whatever the clock.
    #[test]
    fn an_unwitnessed_timed_submission_waits_for_its_bound_on_the_host_clock() {
        use stellar_agent_network::policy_state::ReconcileFailure;

        let max_time = 1_700_000_000;
        let receipt = submitted_receipt(max_time);
        let held = held_for(&receipt);
        let report = |kind| ReconcileReport {
            examined: 1,
            kept_pending: 1,
            endpoint_failure: Some(ReconcileFailure {
                endpoint: String::new(),
                reason: "no witness".to_owned(),
                kind,
            }),
            ..ReconcileReport::default()
        };
        let unwitnessed = report(ReconcileFailureKind::OracleNotConfigured);

        for now_s in [max_time - 60, max_time] {
            let decision = clear_decision(&receipt, &unwitnessed, Some(&held), now_s * 1_000);
            let (code, message) = refusal_of(decision).expect("a bound not yet passed refuses");
            assert_eq!(code, "submission.still_pending");
            assert!(message.contains("host's clock"), "{message}");
        }

        let decision = clear_decision(&receipt, &unwitnessed, Some(&held), (max_time + 1) * 1_000);
        assert!(
            matches!(decision, ClearDecision::Clear { evidence: None }),
            "{decision:?}"
        );

        let unreachable = report(ReconcileFailureKind::Unreachable);
        let decision = clear_decision(&receipt, &unreachable, Some(&held), (max_time + 1) * 1_000);
        let (code, _) = refusal_of(decision).expect("an endpoint that could not answer refuses");
        assert_eq!(code, "network.rpc_unreachable");
    }

    /// A mock oracle reporting `passphrase` and answering every
    /// `getTransaction` with `status`, and a client of it.
    async fn oracle_reporting(
        passphrase: &str,
        status: &str,
    ) -> (
        wiremock::MockServer,
        stellar_agent_network::StellarRpcClient,
    ) {
        oracle_reporting_after(passphrase, status, std::time::Duration::ZERO).await
    }

    /// [`oracle_reporting`] with every `getTransaction` answer arriving after
    /// `delay`.
    async fn oracle_reporting_after(
        passphrase: &str,
        status: &str,
        delay: std::time::Duration,
    ) -> (
        wiremock::MockServer,
        stellar_agent_network::StellarRpcClient,
    ) {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({ "method": "getNetwork" }),
            ))
            .respond_with(EchoIdResponder::new(
                stellar_agent_test_support::signed_envelope::get_network_result(passphrase),
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({ "method": "getTransaction" }),
            ))
            .respond_with(DelayedResponder {
                inner: EchoIdResponder::new(serde_json::json!({
                    "status": status,
                    "latestLedger": 1006,
                    "oldestLedger": 1,
                    "ledger": 1005,
                    "createdAt": "1700000000"
                })),
                delay,
            })
            .mount(&server)
            .await;
        let oracle = stellar_agent_network::StellarRpcClient::new(&server.uri()).expect("client");
        (server, oracle)
    }

    /// Answers as `inner` does, after `delay`.
    struct DelayedResponder {
        inner: stellar_agent_test_support::EchoIdResponder,
        delay: std::time::Duration,
    }

    impl wiremock::Respond for DelayedResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            wiremock::Respond::respond(&self.inner, request).set_delay(self.delay)
        }
    }

    /// The deadline the clear gives the oracle's reads in these tests.
    fn oracle_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_secs(10)
    }

    /// The code and message of the refusal `oracle_precheck` returned.
    fn oracle_refusal_error(checked: Result<MainnetOracle<'_>, Envelope<()>>) -> (String, String) {
        let error = checked
            .err()
            .and_then(|refusal| refusal.error)
            .expect("the clear is refused");
        (error.code, error.message)
    }

    /// The oracle's `SUCCESS` and `FAILED` refuse a clear, and so does an
    /// oracle that cannot answer; its `NOT_FOUND` refuses nothing.
    #[tokio::test]
    async fn the_oracle_answer_decides_whether_a_clear_is_refused() {
        use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
        use stellar_agent_network::StellarRpcClient;

        let tx_hash = "af".repeat(32);
        for (status, refused) in [("SUCCESS", true), ("FAILED", true), ("NOT_FOUND", false)] {
            let (_server, oracle) = oracle_reporting(MAINNET_PASSPHRASE, status).await;

            let checked = oracle_precheck(&oracle, &tx_hash, oracle_deadline()).await;

            assert_eq!(checked.is_err(), refused, "{status}");
            if refused {
                let (code, message) = oracle_refusal_error(checked);
                assert_eq!(code, "submission.not_clearable", "{status}");
                assert!(
                    message.starts_with(&format!(
                        "the oracle reports this transaction as {}",
                        status.to_lowercase()
                    )),
                    "{message}"
                );
            }
        }

        let unreachable = StellarRpcClient::new("http://127.0.0.1:9").expect("client");
        let (code, message) = oracle_refusal_error(
            oracle_precheck(
                &unreachable,
                &tx_hash,
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .await,
        );
        assert_eq!(code, "submission.not_clearable");
        assert!(
            message.starts_with("the oracle did not establish that it serves mainnet"),
            "{message}"
        );
    }

    /// An oracle that reports another network refuses the clear whatever it
    /// answers about the transaction, and its transaction is never asked.
    #[tokio::test]
    async fn an_oracle_on_another_network_refuses_the_clear() {
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

        let tx_hash = "af".repeat(32);
        let (server, oracle) = oracle_reporting(TESTNET_PASSPHRASE, "NOT_FOUND").await;

        let (code, message) =
            oracle_refusal_error(oracle_precheck(&oracle, &tx_hash, oracle_deadline()).await);

        assert_eq!(code, "submission.not_clearable");
        assert!(
            message.starts_with("the oracle did not establish that it serves mainnet"),
            "{message}"
        );
        let asked: Vec<String> = server
            .received_requests()
            .await
            .expect("recorded")
            .iter()
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).expect("json")["method"]
                    .as_str()
                    .expect("method")
                    .to_owned()
            })
            .collect();
        assert_eq!(asked, ["getNetwork"], "the transaction is never asked");
    }

    /// An oracle whose transaction answer arrives after the deadline refuses
    /// the clear at the deadline, not when the late answer arrives.
    #[tokio::test]
    async fn an_oracle_answer_after_the_deadline_refuses_the_clear() {
        use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;

        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);
        let tx_hash = "af".repeat(32);
        let (_server, oracle) = oracle_reporting_after(
            MAINNET_PASSPHRASE,
            "NOT_FOUND",
            std::time::Duration::from_secs(30),
        )
        .await;

        let started = std::time::Instant::now();
        let checked =
            oracle_precheck(&oracle, &tx_hash, tokio::time::Instant::now() + DEADLINE).await;
        let elapsed = started.elapsed();

        let (code, message) = oracle_refusal_error(checked);
        assert_eq!(code, "submission.not_clearable");
        assert!(message.contains("in time"), "{message}");
        assert!(
            elapsed < DEADLINE + std::time::Duration::from_secs(1),
            "the deadline ends the wait: {elapsed:?}"
        );
    }

    /// `run_clear` on a stored mainnet profile whose primary and oracle hosts
    /// are routed to mocked endpoints.
    #[cfg(feature = "mainnet-write")]
    mod mainnet_clear {
        use serde_json::{Value, json};
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

        use super::*;
        use crate::common::mainnet_write_fixture::{AGENT_SEED, MainnetFixture, Spec};
        use crate::test_rpc::{ClassicRpc, last_rendered};

        const ENVELOPE_HASH: &str =
            "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
        const TX_HASH: &str = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";

        /// A mainnet endpoint funding the agent that answers every
        /// `getTransaction` with `status`.
        fn answering(status: &'static str) -> ClassicRpc {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            scripted(ClassicRpc::mainnet(&[&agent]), status)
        }

        /// `rpc` answering every `getTransaction` with `status`.
        fn scripted(rpc: ClassicRpc, status: &'static str) -> ClassicRpc {
            rpc.with_script(move |method, _, _| {
                (method == "getTransaction").then(|| match status {
                    "FAILED" => json!({
                        "status": "FAILED",
                        "latestLedger": 1006,
                        "oldestLedger": 1,
                        "resultXdr": "AAAAAAAAAGT////7AAAAAA=="
                    }),
                    "SUCCESS" => json!({
                        "status": "SUCCESS",
                        "latestLedger": 1006,
                        "oldestLedger": 1,
                        "ledger": 1005,
                        "createdAt": "1700000000"
                    }),
                    other => json!({ "status": other, "latestLedger": 1006, "oldestLedger": 1 }),
                })
            })
        }

        /// The current time in unix seconds.
        fn now_secs() -> u64 {
            stellar_agent_core::timefmt::now_unix_ms().expect("clock") / 1_000
        }

        /// Records a sent submission with time bound `max_time`: its receipt
        /// and its reservation in the spending window.
        fn seed_submission(fixture: &MainnetFixture, max_time: u64) {
            let profile = fixture.profile();
            let source =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            let receipts = ReceiptStore::open(fixture.name).expect("receipt store");
            receipts
                .try_begin(ENVELOPE_HASH, TX_HASH, &source, 7, max_time, 1_000)
                .expect("receipt");
            receipts.mark_submitted(ENVELOPE_HASH).expect("sent");
            let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
            PersistedWindowStore::for_profile(fixture.name)
                .record_pending(
                    &profile,
                    &[WindowEntry::new(
                        StateKey::new(fixture.name, 1, "native", 86_400),
                        now_ms,
                        75,
                        WindowLimit::Amount {
                            asset: "native".to_owned(),
                            window: "1d".to_owned(),
                            max_stroops: 1_000_000,
                        },
                    )],
                    &SubmissionHold {
                        id: ENVELOPE_HASH.to_owned(),
                        tx_hash: TX_HASH.to_owned(),
                        source,
                        sequence: 7,
                        max_time,
                        pending_since_ms: now_ms - 400_000,
                        submission_ledger: 1_000,
                        operator_required: false,
                    },
                )
                .expect("reservation");
        }

        /// Runs `tx receipt clear --acknowledge` on the seeded submission.
        async fn clear(fixture: &MainnetFixture) -> (i32, Value) {
            crate::common::render::take_rendered_for_test();
            let code = run_clear(&ClearArgs {
                envelope_hash: ENVELOPE_HASH.to_owned(),
                profile: Some(fixture.name.to_owned()),
                acknowledge: true,
                output: OutputFormat::Json,
            })
            .await;
            (code, last_rendered())
        }

        /// The seeded submission's receipt status.
        fn receipt_status(fixture: &MainnetFixture) -> ReceiptStatus {
            ReceiptStore::open(fixture.name)
                .expect("receipt store")
                .get(ENVELOPE_HASH)
                .expect("read")
                .expect("present")
                .status
        }

        /// Asserts that the clear was refused with `code` and left the
        /// submission as it was.
        fn assert_refused_untouched(fixture: &MainnetFixture, run: &(i32, Value), code: &str) {
            assert_eq!(run.0, 1, "{}", run.1);
            assert_eq!(run.1["error"]["code"], code, "{}", run.1);
            assert_eq!(fixture.pending_reservations(), 1, "the reservation stands");
            assert_eq!(receipt_status(fixture), ReceiptStatus::Pending);
            assert!(fixture.audit_rows("submission_receipt_cleared").is_empty());
        }

        /// Without an oracle, a primary `FAILED` is a claim nothing confirms:
        /// the clear is not refused on it, and a timed submission waits for
        /// its bound on the host clock.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_unconfirmed_failure_waits_for_the_time_bound_without_an_oracle() {
            let fixture = Spec::new("clear-mainnet-failed-open-bound")
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() + 600);

            let run = clear(&fixture).await;

            assert_refused_untouched(&fixture, &run, "submission.still_pending");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(message.contains("host's clock"), "{message}");
            assert!(fixture.oracle_methods().await.is_empty());
        }

        /// Without an oracle, a primary `FAILED` whose time bound has passed
        /// on the host clock clears as an unknown outcome under the
        /// acknowledgement, releasing the reservation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_unconfirmed_failure_clears_after_the_time_bound_without_an_oracle() {
            let fixture = Spec::new("clear-mainnet-failed-passed-bound")
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let (code, envelope) = clear(&fixture).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(envelope["data"]["cleared_from"], "pending", "{envelope}");
            assert_eq!(envelope["data"]["reservation_released"], true);
            assert_eq!(
                fixture.pending_reservations(),
                0,
                "the reservation is released"
            );
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            assert_eq!(fixture.audit_rows("submission_receipt_cleared").len(), 1);
            assert!(fixture.oracle_methods().await.is_empty());
        }

        /// Without an oracle, a primary `SUCCESS` still refuses the clear:
        /// a debit the endpoint reports applied is not the operator's to
        /// erase.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_success_refuses_the_clear_without_an_oracle() {
            let fixture = Spec::new("clear-mainnet-success-no-oracle")
                .without_oracle()
                .primary(answering("SUCCESS"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let run = clear(&fixture).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
        }

        /// With an oracle, a primary `FAILED` refuses the clear at the
        /// pre-check, as it did: reconciliation settles it on the oracle.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_failure_refuses_the_clear_with_an_oracle() {
            let fixture = Spec::new("clear-mainnet-failed-oracle")
                .primary(answering("FAILED"))
                .oracle(answering("NOT_FOUND"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let run = clear(&fixture).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(
                message.starts_with("the endpoint reports this transaction as failed"),
                "{message}"
            );
        }

        /// An oracle that reports the testnet passphrase refuses the clear:
        /// its answer cannot count for a mainnet submission, and its
        /// transaction is never asked.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_oracle_on_another_network_refuses_the_clear() {
            let oracle = answering("NOT_FOUND");
            let fixture = Spec::new("clear-mainnet-oracle-testnet")
                .primary(answering("NOT_FOUND"))
                .oracle(oracle.clone())
                .build()
                .await;
            oracle.report(TESTNET_PASSPHRASE);
            seed_submission(&fixture, 0);
            let asked_before = fixture.oracle_methods().await.len();

            let run = clear(&fixture).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(
                message.starts_with("the oracle did not establish that it serves mainnet"),
                "{message}"
            );
            assert_eq!(
                fixture.oracle_methods().await[asked_before..],
                ["getNetwork"],
                "the oracle's transaction is never asked"
            );
        }

        /// The reconciliation the clear runs under the audit writer ends its
        /// oracle reads by the command's deadline. The pre-check's
        /// `NOT_FOUND` arrives at once and the reconciliation's transaction
        /// answer stalls past a one-second submit timeout: the clear refuses
        /// by then, with the submission as it was and the audit writer free.
        /// The oracle checked by the pre-check is the one reconciliation asks,
        /// so its identity is read once.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_stalled_oracle_does_not_hold_the_audit_writer_past_the_deadline() {
            const SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
            let oracle = answering("NOT_FOUND");
            let fixture = Spec::new("clear-mainnet-oracle-stalls")
                .submit_timeout_seconds(SUBMIT_TIMEOUT.as_secs())
                .primary(answering("NOT_FOUND"))
                .oracle(oracle.clone())
                .build()
                .await;
            seed_submission(&fixture, 0);
            oracle.stall_after("getTransaction", 1, std::time::Duration::from_secs(30));
            let asked_before = fixture.oracle_methods().await.len();

            let started = std::time::Instant::now();
            let run = clear(&fixture).await;
            let elapsed = started.elapsed();

            assert_refused_untouched(&fixture, &run, "network.rpc_unreachable");
            assert!(
                elapsed < SUBMIT_TIMEOUT + std::time::Duration::from_millis(1500),
                "the deadline ends the oracle's reads: {elapsed:?}"
            );
            assert_eq!(
                fixture.oracle_methods().await[asked_before..],
                ["getNetwork", "getTransaction", "getTransaction"],
                "one identity read, the pre-check's question, reconciliation's question"
            );
            let writer = crate::commands::value_audit::require_value_audit_writer_for_origin(
                &fixture.profile(),
                fixture.name,
                crate::common::profile_access::ProfileOrigin::Persisted,
            )
            .expect("the audit writer is acquirable")
            .expect("a persisted profile has a writer");
            assert!(writer.try_lock().is_ok(), "the audit writer is free");
        }

        /// On testnet a primary `FAILED` refuses the clear, as it always
        /// has: the endpoint's answer settles the submission there.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_failure_refuses_the_clear_on_testnet() {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            let fixture = Spec::new("clear-testnet-failed")
                .testnet()
                .primary(scripted(ClassicRpc::testnet(&[&agent]), "FAILED"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let run = clear(&fixture).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
        }
    }
}
