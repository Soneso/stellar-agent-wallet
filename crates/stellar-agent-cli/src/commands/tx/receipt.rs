//! `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge` — release a
//! submission record reconciliation cannot settle.
//!
//! # When this is needed
//!
//! Reconciliation settles a submission by asking the endpoint about it. Two
//! states it cannot settle:
//!
//! - A submitted `Pending` receipt whose transaction the endpoint reports
//!   `NOT_FOUND`, while the sequence it needs is still unconsumed and its time
//!   bound has not passed. The transaction can still apply, so nothing may
//!   release its reservation.
//! - An `Ambiguous` receipt whose reservation is still open because the
//!   submission ledger has fallen outside the endpoint's retention window. The
//!   endpoint cannot answer for that transaction at all. `tx status` surfaces
//!   this state and stops there.
//!
//! An absent receipt can be recovered from its authenticated reservation when
//! the endpoint reports `NOT_FOUND` and its submission ledger is below retention.
//! The recovered receipt records its provenance and carries no approval metadata.
//!
//! These holds count against the operator's spending caps until someone decides.
//! This verb is that decision.
//!
//! # Why the acknowledgement is required
//!
//! Releasing the reservation states that the transaction did not move value.
//! The wallet cannot establish that: it is the operator's judgement, made from
//! a block explorer or a second endpoint. Without `--acknowledge` nothing is
//! written and the exit code is 1.
//!
//! # What it leaves behind
//!
//! The receipt is marked `cleared_by_operator`, not removed, so the envelope
//! keeps its idempotency anchor: a byte-identical resubmission of those exact
//! bytes is still recognised. That costs nothing in practice, because a
//! follow-up runs a fresh simulate whose fee moves the bytes. An audit row
//! names the state the clear replaced.
//!
//! # Concurrency
//!
//! Writing the audit row needs the audit writer's exclusive lock, which a
//! running MCP server holds for its lifetime. Stop the server, clear, start it
//! again.
//!
//! # Exit codes
//!
//! - 0 on success.
//! - 1 without `--acknowledge`, on a receipt in any other state, and on any
//!   failure.
//!
//! # Where each refusal comes from
//!
//! `submission.not_clearable` is this verb's own: the record state the local
//! rule refuses, and the chain answer that contradicts the operator. The
//! receipt store applies the same rule when it is asked to mark the receipt,
//! but by then the local rule has already passed, so a refusal from the store
//! can only mean the record changed between the two checks. That is a store
//! condition rather than an operator one, and it is reported as
//! `submission.record_unavailable` along with every other write failure.

use clap::{Args, Subcommand};
use serde::Serialize;
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::PersistedWindowStore;

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
    /// Release a submission record reconciliation cannot settle.
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

    /// State that the transaction did not move value.
    ///
    /// Required. Without it the verb reports the receipt it would clear,
    /// changes nothing, and exits 1.
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
    let held = match window.pending_reservations(&profile) {
        Ok(open) => open.into_iter().find(|r| r.id == args.envelope_hash),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the spending-window file could not be read: {e:?}"),
            ));
            return 1;
        }
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
        (Some(record), _) => record.tx_hash.as_str(),
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
            reservation.tx_hash.as_str()
        }
        (None, None) => return 1,
    };

    // The local rule first, before anything is released and before any row is
    // written. Every precondition is evaluated ahead of the first side effect,
    // so a clear this verb will refuse leaves the wallet exactly as it found
    // it: a re-run on an already-cleared receipt, or a receipt the network has
    // answered for, writes nothing.
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
    let client = match StellarRpcClient::new(&profile.rpc_url) {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    let chain = match client.get_transaction_status(tx_hash).await {
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
        render_json(&Envelope::<()>::err_raw(
            "submission.not_clearable",
            format!(
                "the endpoint reports this transaction as {}, so the submission is settled \
                 by reconciliation rather than by an operator; run 'stellar-agent tx status \
                 {}'",
                chain.status.to_lowercase(),
                stellar_agent_network::redact_tx_hash(tx_hash),
            ),
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

    if !args.acknowledge {
        render_json(&Envelope::<()>::err_raw(
            "submission.acknowledgement_required",
            format!(
                "this would clear the {} submission for transaction {}, releasing its \
                 spending-window reservation; pass --acknowledge to state that the \
                 transaction did not move value",
                existing.as_ref().map_or("orphaned", |r| r.status.label()),
                stellar_agent_network::redact_tx_hash(tx_hash),
            ),
        ));
        return 1;
    }

    // Prove the audit writer is acquirable before the record is changed: the
    // clear is only recorded if the row that names it can be written. A
    // persisted profile fails closed on it; the synthesized zero-config
    // profile has no audit key to fail on, and clearing is the only thing that
    // frees its sequence.
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

    let existing = match existing {
        Some(record) => record,
        None => {
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
                Ok(record) if record.status.is_operator_clearable() => record,
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
    };

    let cleared_from = existing.status.label().to_owned();

    // Final marking follows release and the deduplicated audit row. A recovered
    // receipt stays clearable at every intermediate write, so retries finish
    // the remaining work without duplicating the audit row.
    let reservation_released = match window.pending_reservations(&profile) {
        Ok(open) => open.iter().any(|r| r.id == args.envelope_hash),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the spending-window file could not be read: {e:?}"),
            ));
            return 1;
        }
    };
    if reservation_released && let Err(e) = window.release(&profile, &args.envelope_hash) {
        render_json(&Envelope::<()>::err_raw(
            "submission.record_unavailable",
            format!("the spending-window reservation could not be released: {e:?}"),
        ));
        return 1;
    }

    let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&existing.tx_hash);

    // A row only where the log does not already carry one for this
    // submission. The row precedes the mark, so a failure at the mark leaves a
    // reservation already released rather than one stranded under a receipt no
    // verb accepts again; the cost is that a re-run after such a failure
    // reaches here with the row already written, and one clear is one row.
    let already_recorded = stellar_agent_core::audit_log::reader::submission_receipt_cleared_exists(
        &profile.audit_log_path,
        &args.envelope_hash,
    );
    if !already_recorded && audit_writer.is_some() {
        let request_id = uuid::Uuid::new_v4().to_string();
        let entry = AuditEntry::new_submission_receipt_cleared(
            "tx receipt clear",
            profile.chain_id.caip2_str(),
            tx_hash_redacted.as_str(),
            cleared_from.as_str(),
            reservation_released,
            Some(args.envelope_hash.clone()),
            &request_id,
        );
        if let Err(e) = crate::commands::value_audit::emit_value_audit_row_strict(
            &profile,
            &resolved.name,
            entry,
        ) {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    }

    if let Err(e) = receipts.clear_by_operator(&args.envelope_hash) {
        render_json(&Envelope::<()>::err_raw(
            "submission.record_unavailable",
            format!("the submission receipt could not be written: {e}"),
        ));
        return 1;
    }

    render_json(&Envelope::ok(ClearData {
        envelope_hash: args.envelope_hash.clone(),
        tx_hash_redacted,
        cleared_from,
        reservation_released,
    }));
    0
}
