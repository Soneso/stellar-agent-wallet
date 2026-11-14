//! `stellar-agent tx receipt clear <ENVELOPE_HASH> --acknowledge`: close a
//! submission record after reconciling it against the chain.
//!
//! `--acknowledge` records the operator's decision; clearing establishes no
//! chain outcome. A reported failure or missing transaction does not release
//! possible spending.
//!
//! An authenticated hold without a time bound can apply for as long as its
//! sequence stays unconsumed, so no endpoint or oracle report settles it. On
//! every network it stays clearable with both `--acknowledge` and
//! `--acknowledge-unbounded`, whatever its receipt records and whatever the
//! endpoint or the oracle reported before or during the clear. The clear row
//! records that the bytes can still apply while their spend stops counting
//! against the window, and is written before capacity changes. A receipt
//! that records a network answer keeps it through the reconciliation; an
//! endpoint answer the reconciliation did not record on it, a `SUCCESS` or a
//! `NOT_FOUND` below the retention floor, is the clear row's `evidence`.
//!
//! # When this is needed
//!
//! A submission whose outcome never came back leaves a receipt behind and,
//! under a policy with a stateful criterion, a spending-window reservation
//! that counts against the operator's caps. `tx status` reconciles the
//! submission; a negative answer keeps its receipt and exposure. This verb
//! closes a record the operator has decided
//! about, and it reconciles first, so it decides on the chain's latest answer
//! rather than on the record as it was left.
//!
//! An absent receipt can be recovered from its authenticated reservation. A
//! reservation with a time bound is recovered only when the endpoint reports
//! `NOT_FOUND` and its submission ledger is below retention; an untimed one
//! is recovered on its hold. The recovered receipt records its provenance and
//! carries no approval metadata.
//!
//! # The decision
//!
//! Under an untimed authenticated hold, a receipt already cleared by an
//! operator is refused with `submission.not_clearable`; every other receipt
//! state and every endpoint or oracle report go on to reconciliation, and the
//! clear needs `--acknowledge-unbounded` as well.
//!
//! Otherwise, the record's own state comes first: a receipt recorded as
//! `success`, `reorged` or `cleared_by_operator`, or as `failed` under a held
//! reservation, is refused with `submission.not_clearable`. With
//! `--acknowledge`, a terminal receipt without a hold first acquires the audit
//! writer to look for an interrupted clear; the acquisition can drain queued
//! rows or return an audit error. Without a matching row a `success` or
//! `reorged` receipt is refused without reconciliation, release or marking,
//! and a `failed` one goes on to the endpoint. Then the chain: an endpoint
//! that reports `SUCCESS`, or `FAILED` for a held reservation, is refused the
//! same way and left for `tx status`, and so is an endpoint that cannot
//! answer. On a mainnet profile that names an oracle, the oracle is asked as
//! well and refuses the clear the same way. Its `SUCCESS` refuses, and so does
//! its `FAILED` for a held reservation. So do an oracle that cannot answer
//! and one that does not report the mainnet passphrase or whose identity
//! cannot be read. An oracle client that cannot be built refuses with its own
//! error. A credential refusal keeps its code, such as
//! `network.rpc_credential_refused`, and any other construction failure is
//! `network.witness_unavailable`. Every oracle read
//! of the command, these and reconciliation's below, ends by one deadline: the
//! profile's submit timeout, counted from the oracle's identity read. A mainnet
//! profile without an oracle has no second answer to ask for: the primary's
//! `FAILED` is a claim nothing confirms, so it is not refused here and the
//! clear proceeds on the acknowledgement; the primary's `SUCCESS` is still
//! refused.
//!
//! Without `--acknowledge` nothing is reconciled or written: the verb exits 1
//! with `submission.acknowledgement_required`, and the message names the next
//! step, computed from the record. An unbounded exposure needs `--acknowledge`
//! and `--acknowledge-unbounded`. That is an authenticated hold without a time
//! bound on every network and, on mainnet, a sent `pending`, `ambiguous` or
//! `failed` receipt without one when no hold exists. Otherwise, for a sent
//! `pending` receipt whose time bound is open on the host clock, the next step
//! is to wait for the bound to pass or run `tx status`. Every other record
//! needs `--acknowledge`.
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
//! - **Endpoint failure.** A reconciliation read of the endpoint or the
//!   oracle failed, or a read of the oracle was still open at the command's
//!   oracle deadline, and the reservation stood. Refused with
//!   `network.rpc_unreachable`, the code `tx status` reports when the
//!   endpoint cannot be asked; nothing more changes. Reconciliation asks the
//!   oracle the pre-check found serving mainnet and does not read its
//!   identity again, so the audit writer is held for at most that deadline
//!   while the oracle is asked.
//! - **Untimed hold.** Without `--acknowledge-unbounded`, refused with
//!   `submission.unbounded_exposure`. With it, the receipt is cleared and the
//!   hold released whatever the receipt records; the clear row records the
//!   unbounded exposure and `reservation_released: true`.
//! - **Accounting disposition.** The verified spending window holds an
//!   accounting-expiry decision for the submission and no reservation for
//!   it, and the `ambiguous` receipt carries that decision's projection: its
//!   decision identifier and `release_code` `submission.accounting_expired`.
//!   The clear row records the code as `evidence`; it is an observation, not
//!   a chain outcome. A `release_code` on the receipt alone is display data,
//!   and such a receipt is decided by the rows below, as an unknown outcome.
//! - **Still able to apply.** A `pending` or `ambiguous` receipt with a held
//!   reservation or a sent receipt, or a sent `failed` receipt with no held
//!   reservation, whose time bound has not passed on this host's clock. Refused with `submission.still_pending`, naming the time
//!   bound; nothing changes.
//! - **Outcome unknown.** An `ambiguous` receipt without evidence (the
//!   endpoint's retention window closed), a `pending` receipt whose time bound
//!   has passed, an unsent `pending` receipt with no held reservation, or a
//!   recovered orphan with a passed bound. The receipt is cleared and the
//!   clear row records no evidence. A bounded hold keeps counting through its
//!   accounting horizon, so the clear releases nothing.
//!
//! During reconciliation, a `SUCCESS` on a bounded hold refuses the clear
//! with `submission.not_clearable`. A `FAILED` retains exposure; clearing
//! after the execution bound preserves its accounting horizon.
//!
//! # Why the acknowledgement is required
//!
//! The wallet cannot establish what became of the transaction: clearing is
//! the operator's judgement, made from a block explorer or a second endpoint,
//! and `--acknowledge` records that decision. An untimed transaction cleared
//! this way can still apply, and its spend is then not counted against the
//! window.
//!
//! # What it leaves behind
//!
//! The receipt is marked `cleared_by_operator`, not removed, so the envelope
//! keeps its idempotency anchor: a byte-identical resubmission of those exact
//! bytes is still recognised. That costs nothing in practice, because a
//! follow-up runs a fresh simulate whose fee moves the bytes. An audit row
//! names the state the clear replaced and any authenticated accounting
//! disposition. No receipt status or release code writes a settlement row.
//!
//! The row is written first, then the accounting transition, then the mark.
//! A re-run after a failure part-way writes no second row. A clear of an
//! untimed hold stopped after the release leaves no hold: the re-run, with
//! both acknowledgements, finds the row with the unbounded acknowledgement
//! and the release in the authenticated audit history and finishes the mark,
//! reporting `reservation_released: true`.
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
//! `submission.not_clearable`, `submission.still_pending` and
//! `submission.unbounded_exposure` are this verb's own: the record state the
//! local rule refuses, the chain answer that contradicts the operator, a
//! transaction that can still apply, and an untimed hold without the second
//! acknowledgement. The receipt store applies the local rule again when it is
//! asked to mark the receipt, but by then the verb has already passed it, so
//! a refusal from the store can only mean the record changed between the two
//! checks. That is a store condition rather than an operator one, and it is
//! reported as `submission.record_unavailable` along with every other write
//! failure and a reconciliation that could not read or write the
//! spending-window file.

use clap::{Args, Subcommand};
use serde::Serialize;
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::profile::receipt::{
    ReceiptStatus, ReceiptStore, ReleaseEvidence, SubmissionReceipt,
};
use stellar_agent_network::MainnetOracle;
use stellar_agent_network::policy_state::{
    PersistedWindowStore, ReconcileFailureKind, ReconcileReport, ReportedAnswer, SubmissionHold,
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

    /// Record the operator's decision to clear, and reconcile before
    /// clearing. Clearing establishes no chain outcome.
    ///
    /// Required. Without it the verb reports the receipt it would clear and
    /// the next step, reconciles nothing, changes nothing, and exits 1.
    #[arg(long)]
    pub acknowledge: bool,

    /// Accept that this untimed transaction can still apply and that its
    /// spend is then not counted.
    ///
    /// Required on every network for an authenticated hold without a time
    /// bound, whatever its receipt records or the endpoint reports. Also
    /// required on mainnet for a sent `pending`, `ambiguous` or `failed`
    /// receipt without one when no hold exists. Both acknowledgement flags are also required to finish a
    /// recorded unbounded clear.
    #[arg(long)]
    pub acknowledge_unbounded: bool,

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
    /// The full muxed `M...` payment destination the receipt records.
    /// Absent for every other receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
}

/// Runs the `tx receipt` subcommand group.
pub async fn run(args: &ReceiptArgs) -> i32 {
    match &args.subcommand {
        ReceiptSubcommand::Clear(a) => run_clear(a).await,
    }
}

async fn run_clear(args: &ClearArgs) -> i32 {
    if !stellar_agent_network::submission_flow::is_tx_hash(&args.envelope_hash) {
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
            render_json(&Envelope::<()>::err_raw(e.code(), e.message()));
            return 1;
        }
    };

    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let window = PersistedWindowStore::for_profile(&resolved.name);
    let scope = stellar_agent_network::policy_state::ChainScope::for_chain(profile.chain_id);
    if let Err(error) = window.require_chain_scope(&profile, &scope) {
        render_json(&Envelope::<()>::err_raw(
            error.submission_code(),
            error.to_string(),
        ));
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
            if !stellar_agent_network::submission_flow::is_tx_hash(&reservation.tx_hash)
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

    // An authenticated hold without an execution bound stays clearable with
    // both acknowledgements whatever its receipt records and whatever an
    // endpoint or oracle reports: its bytes can apply for as long as their
    // sequence stays unconsumed, so no report settles the exposure, and the
    // unauthenticated receipt cannot narrow the operator's decision.
    let unbounded_hold = held.as_ref().is_some_and(|hold| hold.max_time == 0);

    // A clear of an untimed hold writes its row, releases the hold, then marks
    // the receipt. Interrupted after the release, it leaves an unmarked
    // receipt and no hold. The row is the durable decision: where the
    // authenticated audit history holds this envelope's row with the unbounded
    // acknowledgement and the release, the re-run finishes the mark on it,
    // reconciles nothing and writes no second row. A receipt that records a
    // network answer is otherwise refused by the local rule below, so for it
    // the audit writer is acquired here, under `--acknowledge`, to look for
    // that row; a `pending` or `ambiguous` receipt is looked up once the
    // audit writer is acquired below.
    if args.acknowledge
        && held.is_none()
        && let Some(record) = &existing
        && matches!(
            record.status,
            ReceiptStatus::Success | ReceiptStatus::Failed { .. } | ReceiptStatus::Reorged
        )
    {
        let writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
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
        if let Some(code) = finish_recorded_unbounded_clear(
            args,
            &resolved.name,
            writer.as_ref(),
            &receipts,
            record,
            profile.chain_id.caip2_str(),
        ) {
            return code;
        }
    }

    // The local rule, before anything is reconciled, released or marked.
    // With `--acknowledge`, a terminal receipt without a hold has already
    // acquired the audit writer above to look for an interrupted clear; the
    // acquisition can drain queued rows or return an audit error. A `failed`
    // receipt without a hold proceeds to the endpoint check. Any other
    // receipt this rule refuses writes no row: a re-run on a cleared receipt,
    // or a bounded receipt the network has answered for.
    if let Some(existing) = &existing
        && !clearable(&existing.status, held.as_ref())
    {
        render_json(&Envelope::<()>::err_raw(
            "submission.not_clearable",
            if unbounded_hold {
                format!(
                    "a submission recorded as '{}' is already cleared by an operator",
                    existing.status.label()
                )
            } else {
                format!(
                    "a submission recorded as '{}' is not cleared by an operator; only a \
                     submission the endpoint cannot account for, one whose outcome is \
                     recorded as ambiguous, a failed one without an authenticated hold, and \
                     one whose authenticated hold has no time bound, are",
                    existing.status.label()
                )
            },
        ));
        return 1;
    }

    // Then the chain. A bounded hold's chain answer is reconciliation's:
    // `tx status` reconciles the submission, and a negative answer keeps its
    // receipt and exposure. The endpoint is the only thing that can contradict
    // the operator. An endpoint that cannot answer is not a license to clear: a
    // transaction in flight is exactly the case in which the operator's
    // decision can be wrong.
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
    let oracle = if scope.chain().is_mainnet() {
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
    // cannot settle it either. A FAILED for a submission without a held
    // reservation is an unauthenticated report reconciliation records
    // nothing on. Both go on to the acknowledged unknown outcome and its
    // time-bound guard rather than being refused here.
    let unconfirmable_failure = chain.status == "FAILED"
        && ((profile.chain_id.is_mainnet() && oracle.is_none()) || held.is_none());
    if !unbounded_hold
        && (chain.status == "SUCCESS" || (chain.status == "FAILED" && !unconfirmable_failure))
    {
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
    let veto = if unbounded_hold {
        OracleVeto::Nothing
    } else if held.is_none() {
        OracleVeto::Success
    } else {
        OracleVeto::SuccessAndFailure
    };
    let checked_oracle = match &oracle {
        Some(oracle) => match oracle_precheck(oracle, &tx_hash, oracle_deadline, veto).await {
            Ok(checked) => Some(checked),
            Err(refusal) => {
                render_json(&refusal);
                return 1;
            }
        },
        None => None,
    };

    // A bounded orphan is recovered only where the endpoint cannot answer
    // for it; an untimed one is the operator's to clear on its
    // authenticated hold.
    if recovered_identity && !unbounded_hold {
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
            context.chain_id.is_mainnet(),
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

    if held.is_none()
        && let Some(record) = &existing
        && let Some(code) = finish_recorded_unbounded_clear(
            args,
            &resolved.name,
            audit_writer.as_ref(),
            &receipts,
            record,
            context.chain_id.caip2_str(),
        )
    {
        return code;
    }

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
            Ok(record) if clearable(&record.status, Some(held)) => {}
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
                e.submission_code(),
                format!("the submission could not be reconciled: {e}"),
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
    // The accounting decision comes from the verified window state, never
    // from the receipt's release code.
    let verified_decision = match window.accounting_expiry_for(&profile, &args.envelope_hash) {
        Ok(decision) => decision,
        Err(error) => {
            render_json(&Envelope::<()>::err_raw(
                error.submission_code(),
                format!("the spending-window file could not be read: {error}"),
            ));
            return 1;
        }
    };

    let (evidence, exposure) = match clear_decision(
        &receipt,
        &report,
        held_now.as_ref(),
        verified_decision.as_deref(),
        now_ms,
        context.chain_id.is_mainnet(),
        args.acknowledge_unbounded,
    ) {
        ClearDecision::Clear {
            evidence,
            unbounded_exposure,
        } => (evidence, unbounded_exposure),
        ClearDecision::Refuse(envelope) => {
            render_json(&envelope);
            return 1;
        }
    };

    let decision = if held_now.is_some() {
        match window.operator_clear_decision(
            &profile,
            &args.envelope_hash,
            args.acknowledge,
            args.acknowledge_unbounded,
        ) {
            Ok(decision) => Some(decision),
            Err(error) => {
                render_json(&Envelope::<()>::err_raw(
                    error.submission_code(),
                    error.to_string(),
                ));
                return 1;
            }
        }
    } else {
        None
    };
    // The operator's decision releases an untimed hold on every network. A
    // bounded hold stays counted until its accounting horizon, which the
    // decision leaves unchanged. A hold this run's reconciliation ended is
    // released too.
    let reservation_released = held_now.as_ref().is_some_and(|hold| hold.max_time == 0)
        || (held.is_some() && held_now.is_none());
    let data = match record_and_mark_clear_with(
        &resolved.name,
        audit_writer.as_ref(),
        &receipts,
        &receipt,
        evidence,
        reservation_released,
        exposure,
        ClearMark::for_hold(held_now.as_ref()),
        context.chain_id.caip2_str(),
        || {
            if let Some(decision) = decision {
                window
                    .apply_accounting_decision(&profile, decision)
                    .map_err(|error| {
                        Envelope::<()>::err_raw(error.submission_code(), error.to_string())
                    })?;
            }
            Ok(())
        },
    ) {
        Ok(data) => data,
        Err(envelope) => {
            render_json(&envelope);
            return 1;
        }
    };
    render_json(&Envelope::ok(data));
    0
}

/// Records the clear, applies its checked accounting transition, and marks
/// the receipt `cleared_by_operator`, in that order.
///
/// 1. **Clear row.** Where the profile has an audit writer, the
///    `submission_receipt_cleared` row is appended unless retained history
///    already carries one for this submission. It records `evidence`,
///    whether capacity is released, and the unbounded acknowledgement, so the
///    operator's decision is durable before capacity changes. A failed append
///    or an unreadable history refuses, and nothing else changes.
/// 2. **Checked transition.** `apply` applies the accounting decision the
///    store checked against the authenticated hold. A refusal leaves the clear
///    row in place and the receipt clearable.
/// 3. **Mark.** The receipt is marked `cleared_by_operator` under the rule
///    `mark` names: under an untimed authenticated hold every state but an
///    earlier clear, without a hold also a failure report, and otherwise only
///    a state the operator may clear. A failed mark leaves the receipt
///    clearable.
///
/// A re-run after a failure part-way finds the clear row already written and
/// writes none again. After a failed transition the hold stands and the
/// re-run applies it; after a failed mark of an untimed hold the hold is
/// released and the re-run finishes the mark on the row alone.
///
/// The history lookup and the row run under one guard of `audit_writer`, the
/// writer the caller acquired under the audit binding check of the profile's
/// origin. The lookup reads up to the writer's verified tip, so a clear row
/// appended to the file outside the writer does not stand in for the one this
/// clear writes.
///
/// `audit_writer` is `None` only for a synthesized profile whose writer could
/// not be acquired; nothing is recorded for it, no history is read, and the
/// receipt is marked.
///
/// # Errors
///
/// The refusal envelope: the audit error of a row that could not be written,
/// the verifier's `audit.*` code and message for a history that could not be
/// read, the store's refusal of the transition, or
/// `submission.record_unavailable` for a receipt that could not be marked.
#[allow(
    clippy::too_many_arguments,
    reason = "the clear binds its audit row, receipt, and checked accounting transition"
)]
fn record_and_mark_clear_with(
    profile_name: &str,
    audit_writer: Option<
        &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    >,
    receipts: &ReceiptStore,
    receipt: &SubmissionReceipt,
    evidence: Option<ClearEvidence>,
    reservation_released: bool,
    unbounded_exposure: bool,
    mark: ClearMark,
    chain_id: &str,
    apply: impl FnOnce() -> Result<(), Envelope<()>>,
) -> Result<ClearData, Envelope<()>> {
    let cleared_from = receipt.status.label().to_owned();
    let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&receipt.tx_hash);

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
                unbounded_exposure,
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

    apply()?;

    let marked = match mark {
        ClearMark::UntimedHold => receipts.clear_unbounded_by_operator(&receipt.envelope_hash),
        ClearMark::BoundedHold => receipts.clear_by_operator(&receipt.envelope_hash),
        ClearMark::Unheld => receipts.clear_unheld_by_operator(&receipt.envelope_hash),
    };
    marked.map_err(|e| {
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
        destination: receipt.destination.clone(),
    })
}

/// Finishes the clear of an untimed hold that a run interrupted after its
/// accounting transition, and returns the exit code; `None` when the retained
/// history holds no such clear for `record`.
///
/// The decision is the envelope's clear row with the unbounded
/// acknowledgement and the release, read through `audit_writer`. With it the
/// receipt is marked under the untimed rule, no second row is written, and the
/// output reports `reservation_released: true`; the second acknowledgement is
/// required as on the run that wrote the row. A synthesized profile without a
/// writer records no row, so nothing is finished on it.
fn finish_recorded_unbounded_clear(
    args: &ClearArgs,
    profile_name: &str,
    audit_writer: Option<
        &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    >,
    receipts: &ReceiptStore,
    record: &SubmissionReceipt,
    chain_id: &str,
) -> Option<i32> {
    let writer = audit_writer?;
    match unbounded_clear_recorded(profile_name, writer, &args.envelope_hash) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(envelope) => {
            render_json(&envelope);
            return Some(1);
        }
    }
    if !args.acknowledge_unbounded {
        render_json(&Envelope::<()>::err_raw(
            "submission.unbounded_exposure",
            format!(
                "the clear of untimed transaction {} is recorded and its hold released; pass \
                 --acknowledge --acknowledge-unbounded to finish marking its receipt",
                stellar_agent_network::redact_tx_hash(&record.tx_hash),
            ),
        ));
        return Some(1);
    }
    match record_and_mark_clear_with(
        profile_name,
        Some(writer),
        receipts,
        record,
        None,
        true,
        true,
        ClearMark::UntimedHold,
        chain_id,
        || Ok(()),
    ) {
        Ok(data) => {
            render_json(&Envelope::ok(data));
            Some(0)
        }
        Err(envelope) => {
            render_json(&envelope);
            Some(1)
        }
    }
}

/// Whether the retained history holds this envelope's clear row with the
/// unbounded acknowledgement and the release, read under one guard of
/// `audit_writer` up to its verified tip.
///
/// # Errors
///
/// The refusal envelope for a writer that cannot be locked, and the
/// verifier's `audit.*` code and message for a history that cannot be read.
fn unbounded_clear_recorded(
    profile_name: &str,
    audit_writer: &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    envelope_hash: &str,
) -> Result<bool, Envelope<()>> {
    let guard = audit_writer.lock().map_err(|_| {
        Envelope::<()>::err(&crate::commands::value_audit::audit_writer_open_failed(
            profile_name,
        ))
    })?;
    stellar_agent_core::audit_log::reader::try_unbounded_submission_receipt_cleared_exists(
        &guard,
        envelope_hash,
    )
    .map_err(|error| Envelope::err_raw(error.wire_code(), error.to_string()))
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
                e.submission_code(),
                format!("the spending-window file could not be read: {e}"),
            ));
            Err(1)
        }
    }
}

/// What the clear row records as `evidence`. Neither kind establishes a
/// chain outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearEvidence {
    /// The accounting disposition the verified window state committed.
    Disposition(ReleaseEvidence),
    /// The endpoint's answer this run's reconciliation did not record, because
    /// the receipt of an untimed hold keeps its recorded network answer.
    Answer(ReportedAnswer),
}

impl ClearEvidence {
    /// The wire code the clear row carries.
    fn code(self) -> &'static str {
        match self {
            Self::Disposition(evidence) => evidence.code(),
            Self::Answer(answer) => answer.code(),
        }
    }
}

impl From<ReleaseEvidence> for ClearEvidence {
    fn from(evidence: ReleaseEvidence) -> Self {
        Self::Disposition(evidence)
    }
}

/// What the clear does with a reconciled submission.
#[derive(Debug)]
enum ClearDecision {
    /// Clear the receipt. `evidence` describes its accounting disposition or
    /// the endpoint's unrecorded answer; neither an observation nor
    /// accounting expiry establishes chain failure.
    Clear {
        /// What the clear row records as `evidence`.
        evidence: Option<ClearEvidence>,
        /// Whether the operator acknowledged that the untimed bytes can still
        /// apply once their spend stops counting; the clear row records it.
        unbounded_exposure: bool,
    },
    /// Refuse with this envelope; nothing more changes.
    Refuse(Envelope<()>),
}

/// Which receipt rule marks a clear, by the authenticated hold the clear
/// acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearMark {
    /// An untimed hold: every state but an earlier clear.
    UntimedHold,
    /// A bounded hold: the states [`ReceiptStatus::is_operator_clearable`]
    /// names.
    BoundedHold,
    /// No hold: the states
    /// [`ReceiptStatus::is_operator_clearable_without_hold`] names.
    Unheld,
}

impl ClearMark {
    /// The rule for a clear of a submission whose authenticated hold is
    /// `held`.
    fn for_hold(held: Option<&SubmissionHold>) -> Self {
        match held {
            Some(hold) if hold.max_time == 0 => Self::UntimedHold,
            Some(_) => Self::BoundedHold,
            None => Self::Unheld,
        }
    }
}

/// Whether the operator may clear a receipt in `status` whose authenticated
/// hold is `held`: any state but an earlier clear under an untimed hold, the
/// states [`ReceiptStatus::is_operator_clearable`] names under a bounded hold,
/// and also a failure report without a hold. An endpoint failure report is
/// unauthenticated, so it settles nothing; without a hold the clear releases
/// no counted exposure.
fn clearable(status: &ReceiptStatus, held: Option<&SubmissionHold>) -> bool {
    match ClearMark::for_hold(held) {
        ClearMark::UntimedHold => status.is_clearable_with_unbounded_hold(),
        ClearMark::BoundedHold => status.is_operator_clearable(),
        ClearMark::Unheld => status.is_operator_clearable_without_hold(),
    }
}

/// Whether clearing this submission needs `--acknowledge-unbounded`.
///
/// The authenticated hold decides when present: one without an execution
/// bound needs it on every network, whatever the receipt records. Without a
/// hold, a sent mainnet receipt the operator can clear needs it when the
/// receipt carries no time bound.
fn unbounded_exposure(
    receipt: Option<&SubmissionReceipt>,
    held: Option<&SubmissionHold>,
    mainnet: bool,
) -> bool {
    match held {
        Some(hold) => hold.max_time == 0,
        None => {
            mainnet
                && receipt.is_some_and(|receipt| {
                    receipt.status.is_operator_clearable_without_hold()
                        && receipt.submitted
                        && receipt.max_time == 0
                })
        }
    }
}

/// Applies the decision table to the receipt as reconciliation left it.
///
/// `held_now` is the reservation the window holds for the submission after
/// reconciliation, and `now_ms` the host clock.
///
/// An untimed held reservation is decided on the operator's acknowledgements
/// alone once the receipt and its reconciliation agree: a reported success or
/// failure, an accounting observation, and a missing transaction all leave its
/// exposure open. A receipt that keeps its recorded network answer carries
/// the endpoint's unrecorded answer into the clear row as `evidence`.
///
/// An orphan's receipt restored under the retention rule is `Ambiguous`
/// without evidence, so it is cleared with an unknown outcome.
///
/// `verified_decision` is the accounting-expiry decision the verified window
/// state holds for the submission. Only that decision, projected onto the
/// receipt, makes the clear row's evidence `submission.accounting_expired`; a
/// release code on the receipt alone is display data and no evidence.
fn clear_decision(
    receipt: &SubmissionReceipt,
    report: &ReconcileReport,
    held_now: Option<&SubmissionHold>,
    verified_decision: Option<&str>,
    now_ms: u64,
    mainnet: bool,
    acknowledge_unbounded: bool,
) -> ClearDecision {
    let unbounded_hold = held_now.is_some_and(|hold| hold.max_time == 0);
    let max_time = held_now.map_or(receipt.max_time, |hold| hold.max_time);
    // A terminal receipt report is not operator-clearable under a bounded hold.
    if !clearable(&receipt.status, held_now) {
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
    // The receipt must carry the projection of every authenticated decision:
    // the one this run committed and the one the verified window state holds.
    // Projection gives an open receipt the accounting code and leaves every
    // other status and its code in place, so only an open receipt needs it.
    let projected = |decision_id: &str| {
        receipt.settlement_decision_id.as_deref() == Some(decision_id)
            && (!matches!(
                receipt.status,
                ReceiptStatus::Pending | ReceiptStatus::Ambiguous
            ) || (receipt.status == ReceiptStatus::Ambiguous
                && receipt.release_code == Some(ReleaseEvidence::AccountingExpired)))
    };
    if report.settled.iter().any(|settled| {
        settled.envelope_hash == receipt.envelope_hash
            && (!projected(&settled.decision_id)
                || verified_decision != Some(settled.decision_id.as_str()))
    }) || verified_decision.is_some_and(|decision_id| !projected(decision_id))
        || report.unrecorded.iter().any(|unrecorded| {
            unrecorded.envelope_hash == receipt.envelope_hash
                && unrecorded.recorded != receipt.status
        })
    {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.record_unavailable",
            "the submission receipt disagrees with its reconciliation; \
             run `stellar-agent tx status` on it again",
        ));
    }
    // An authenticated accounting expiry ended the hold. The clear row
    // records that disposition; it creates no definitive chain outcome row.
    if !unbounded_hold
        && held_now.is_none()
        && receipt.status == ReceiptStatus::Ambiguous
        && let Some(decision_id) = verified_decision
        && projected(decision_id)
    {
        return ClearDecision::Clear {
            evidence: Some(ClearEvidence::Disposition(
                ReleaseEvidence::AccountingExpired,
            )),
            unbounded_exposure: false,
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
    if unbounded_exposure(Some(receipt), held_now, mainnet) {
        if !acknowledge_unbounded {
            return ClearDecision::Refuse(Envelope::<()>::err_raw(
                "submission.unbounded_exposure",
                format!(
                    "transaction {} carries no time bound and can apply for as long as \
                     sequence {} of its source stays unconsumed; clearing stops counting its \
                     spend against the window. Pass --acknowledge --acknowledge-unbounded to \
                     clear it and record that exposure",
                    stellar_agent_network::redact_tx_hash(&receipt.tx_hash),
                    receipt.sequence,
                ),
            ));
        }
        return ClearDecision::Clear {
            evidence: report
                .unrecorded
                .iter()
                .find(|unrecorded| unrecorded.envelope_hash == receipt.envelope_hash)
                .map(|unrecorded| ClearEvidence::Answer(unrecorded.answer)),
            unbounded_exposure: true,
        };
    }
    // Without a witness nothing establishes whether a timed transaction can
    // still apply, so its time bound is read on the host clock: it can apply
    // until the bound passes.
    if unwitnessed
        && (held_now.is_some() || receipt.submitted)
        && max_time > 0
        && now_ms / 1_000 <= max_time
    {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.still_pending",
            format!(
                "transaction {} can still apply: its time bound (maxTime {}) has not passed on \
                 this host's clock, and the profile names no oracle to establish more; wait for \
                 the bound to pass and run this command again",
                stellar_agent_network::redact_tx_hash(&receipt.tx_hash),
                max_time,
            ),
        ));
    }
    // A sent transaction can still apply through its signed bound on the host clock.
    if !unwitnessed
        && now_ms / 1000 <= held_now.map_or(max_time, |hold| hold.max_time)
        && (held_now.is_some() || receipt.submitted)
        && max_time > 0
    {
        return ClearDecision::Refuse(Envelope::<()>::err_raw(
            "submission.still_pending",
            format!(
                "transaction {} can still apply: its time bound (maxTime {}) has not passed on \
                 this host's clock; wait for the bound to pass and run 'stellar-agent tx status' \
                 on it. Accounting remains charged through each affected spending window",
                stellar_agent_network::redact_tx_hash(&receipt.tx_hash),
                max_time,
            ),
        ));
    }
    // The outcome is unknown and nothing more can establish it: the
    // operator's acknowledgement decides.
    ClearDecision::Clear {
        evidence: None,
        unbounded_exposure: false,
    }
}

/// The oracle reports that refuse a clear, by the submission's
/// authenticated hold. The endpoint's own answer is refused on the same
/// terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleVeto {
    /// An untimed hold: no report settles its exposure.
    Nothing,
    /// No hold: a `FAILED` report is unauthenticated and settles nothing,
    /// so only `SUCCESS` refuses.
    Success,
    /// A bounded hold: `SUCCESS` and `FAILED` both refuse the clear.
    SuccessAndFailure,
}

impl OracleVeto {
    /// Whether the oracle's `status` refuses the clear.
    fn refuses(self, status: &str) -> bool {
        match self {
            Self::Nothing => false,
            Self::Success => status == "SUCCESS",
            Self::SuccessAndFailure => status == "SUCCESS" || status == "FAILED",
        }
    }
}

/// Checks that the oracle serves mainnet and asks it what became of
/// `tx_hash`, both reads bounded by `deadline`, and returns the checked
/// oracle for the reconciliation that follows.
///
/// # Errors
///
/// The refusal of the clear. An oracle identity that is read and names
/// another network or an unsupported protocol gives evidence against the
/// clear: `submission.not_clearable`. So does a transaction status `veto`
/// refuses. An identity or transaction read that fails in transport or does
/// not answer by `deadline` is an unreachable endpoint and keeps its cause:
/// `network.rpc_unreachable`. A `NOT_FOUND` from the oracle refuses nothing:
/// the acknowledgement and reconciliation decide.
async fn oracle_precheck<'o>(
    oracle: &'o stellar_agent_network::StellarRpcClient,
    tx_hash: &str,
    deadline: tokio::time::Instant,
    veto: OracleVeto,
) -> Result<MainnetOracle<'o>, Envelope<()>> {
    use stellar_agent_core::error::{NetworkError, WalletError, WitnessUnavailableReason};
    let client = oracle;
    let oracle = match MainnetOracle::verify(client, deadline).await {
        Ok(oracle) => oracle,
        Err(
            e @ WalletError::Network(NetworkError::WitnessUnavailable {
                reason:
                    WitnessUnavailableReason::IdentityNetworkMismatch { .. }
                    | WitnessUnavailableReason::IdentityProtocolUnsupported { .. },
            }),
        ) => {
            return Err(Envelope::<()>::err_raw(
                "submission.not_clearable",
                format!(
                    "the oracle did not establish that it serves mainnet, so its answer does \
                     not count and the submission cannot be cleared: {e}"
                ),
            ));
        }
        Err(
            e @ WalletError::Network(NetworkError::WitnessUnavailable {
                reason: WitnessUnavailableReason::IdentityUnavailable { .. },
            }),
        ) => {
            return Err(Envelope::<()>::err(&WalletError::Network(
                NetworkError::RpcUnreachable {
                    url: stellar_agent_network::redact_url_authority(client.url()),
                    reason: format!(
                        "the oracle's identity could not be read, so the submission cannot be \
                         cleared: {e}"
                    ),
                },
            )));
        }
        Err(e) => return Err(Envelope::<()>::err(&e)),
    };
    let answer =
        match tokio::time::timeout_at(deadline, oracle.client().get_transaction_status(tx_hash))
            .await
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => {
                return Err(Envelope::<()>::err(
                    &stellar_agent_core::error::WalletError::Network(e),
                ));
            }
            Err(_) => {
                return Err(Envelope::<()>::err(
                    &stellar_agent_core::error::WalletError::Network(
                        stellar_agent_core::error::NetworkError::RpcUnreachable {
                            url: stellar_agent_network::redact_url_authority(oracle.client().url()),
                            reason: "getTransaction did not answer in time, before the \
                                     command's deadline, so the submission cannot be cleared"
                                .to_owned(),
                        },
                    ),
                ));
            }
        };
    if veto.refuses(&answer.status) {
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
            "{source} reports this transaction as {answer}, so the submission is not the \
             operator's to clear; run 'stellar-agent tx status {}'",
            stellar_agent_network::redact_tx_hash(tx_hash),
        ),
    )
}

/// The refusal without `--acknowledge`, naming the next step computed from
/// the record without reconciling.
///
/// An unbounded exposure comes first and needs both acknowledgement flags.
/// Otherwise a sent `pending` receipt whose time bound is open on the host
/// clock waits or goes to `tx status`. Every other record needs
/// `--acknowledge`.
fn acknowledgement_required(
    existing: Option<&SubmissionReceipt>,
    held: Option<&stellar_agent_network::policy_state::SubmissionHold>,
    tx_hash: &str,
    now_ms: u64,
    mainnet: bool,
) -> Envelope<()> {
    let label = existing.map_or("orphaned", |r| r.status.label());
    let redacted = stellar_agent_network::redact_tx_hash(tx_hash);
    let releasing = match held {
        Some(hold) if hold.max_time == 0 => ", releasing its spending-window reservation",
        Some(_) => {
            ", whose spending-window reservation keeps counting until its accounting horizon"
        }
        None => "",
    };
    let open_bound = existing.and_then(|r| {
        (r.status == ReceiptStatus::Pending
            && r.submitted
            && r.max_time > 0
            && now_ms / 1_000 <= r.max_time)
            .then_some(r.max_time)
    });
    // The held time bound decides wherever a reservation is held, an
    // orphan's included.
    let exposure = unbounded_exposure(existing, held, mainnet);
    let next = if exposure {
        "pass --acknowledge --acknowledge-unbounded to state that this untimed transaction can \
         still apply and its spend stops counting against the window"
            .to_owned()
    } else {
        match open_bound {
            Some(max_time) => format!(
                "its time bound (maxTime {max_time}) is still open, so it can still apply: wait \
                 for the bound to pass, or run 'stellar-agent tx status {redacted}'"
            ),
            None => "pass --acknowledge to record the decision to clear it; clearing establishes \
                     no chain outcome, and the clear reconciles the submission first"
                .to_owned(),
        }
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

    /// Records the clear with no accounting transition, for the tests of the
    /// clear row and the mark; see [`record_and_mark_clear_with`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the clear records the submission, its evidence and the profile's audit context"
    )]
    fn record_and_mark_clear(
        profile_name: &str,
        audit_writer: Option<
            &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
        >,
        receipts: &ReceiptStore,
        receipt: &SubmissionReceipt,
        evidence: Option<ClearEvidence>,
        reservation_released: bool,
        unbounded_exposure: bool,
        chain_id: &str,
    ) -> Result<ClearData, Envelope<()>> {
        record_and_mark_clear_with(
            profile_name,
            audit_writer,
            receipts,
            receipt,
            evidence,
            reservation_released,
            unbounded_exposure,
            ClearMark::BoundedHold,
            chain_id,
            || Ok(()),
        )
    }

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
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
                name,
                Some(&writer),
                &receipts,
                &receipt,
                None,
                true,
                false,
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

    /// A clear row that cannot be appended refuses the clear before the mark,
    /// and the receipt keeps its disposition and stays clearable.
    ///
    /// The first writer cannot append while the profile's own log can. The
    /// retry through the profile's writer records the one clear row, carrying
    /// the disposition as `evidence`, and marks the receipt.
    #[test]
    #[serial]
    fn a_clear_row_that_cannot_be_appended_keeps_the_disposition_clearable() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
            name,
            Some(&broken),
            &receipts,
            &receipt,
            Some(ReleaseEvidence::SequenceConsumed.into()),
            false,
            false,
            "stellar:testnet",
        )
        .expect_err("a clear row that cannot be appended refuses the clear");
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
            "a refused clear writes nothing to the profile's log"
        );

        let writer = crate::commands::value_audit::require_value_audit_writer(&profile, name)
            .expect("the profile's writer");
        let cleared = record_and_mark_clear(
            name,
            Some(&writer),
            &receipts,
            &receipt,
            Some(ReleaseEvidence::SequenceConsumed.into()),
            false,
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
            ["audit_entry_tags_started", "submission_receipt_cleared"]
        );
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
    /// No receipt status writes a settlement row, so the clear lookup is the
    /// only history read. The active file holds no
    /// clear row for the submission, so the clear lookup visits the archive,
    /// whose interior link is broken.
    #[test]
    #[serial]
    fn a_clear_lookup_that_cannot_read_the_history_refuses_and_keeps_the_receipt() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
            name,
            Some(&writer),
            &receipts,
            &receipt,
            None,
            false,
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
    #[serial_test::serial]
    fn a_forged_cleared_row_past_the_tip_does_not_suppress_the_clear_row() {
        let storage_sandbox =
            stellar_agent_test_support::sandbox::StateSandbox::new().expect("fixture sandbox");
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
            name,
            Some(&writer),
            &receipts,
            &receipt,
            None,
            false,
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
    #[serial_test::serial]
    fn a_synthesized_clear_without_a_writer_skips_broken_history() {
        let storage_sandbox =
            stellar_agent_test_support::sandbox::StateSandbox::new().expect("fixture sandbox");
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
            name,
            None,
            &receipts,
            &receipt,
            None,
            false,
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

    /// A failed receipt projection or a disagreement with the verified
    /// accounting state prevents the operator clear.
    #[test]
    fn a_clear_refuses_an_unrecorded_reconciliation() {
        use stellar_agent_core::profile::receipt::ReleaseEvidence;
        use stellar_agent_network::policy_state::{ReconcileReport, SettledSubmission};

        let dir = tempfile::tempdir().expect("tmp dir");
        let receipts = ReceiptStore::open_at(dir.path(), "clear-checkpoint").expect("store");
        let id = "5a".repeat(32);
        receipts
            .try_begin(&id, &"6b".repeat(32), "GSOURCE", 7, 0, 100)
            .expect("receipt");
        let receipt = receipts.get(&id).expect("read").expect("present");
        let decision_id = "d1".repeat(32);
        let failed = ReconcileReport {
            receipt_write_failed: 1,
            receipt_write_error: Some("receipt store writer is locked".to_owned()),
            ..ReconcileReport::default()
        };
        let committed = ReconcileReport {
            released: 1,
            settled: vec![SettledSubmission {
                envelope_hash: id.clone(),
                tx_hash: receipt.tx_hash.clone(),
                decision_id: decision_id.clone(),
            }],
            ..ReconcileReport::default()
        };
        let mut projected = receipt.clone();
        projected.status = ReceiptStatus::Ambiguous;
        projected.release_code = Some(ReleaseEvidence::AccountingExpired);
        projected.settlement_decision_id = Some(decision_id.clone());
        let mut other = projected.clone();
        other.settlement_decision_id = Some("d2".repeat(32));
        // Projection keeps a failed receipt's status and code and adds only
        // the identifier.
        let mut failed_projected = receipt.clone();
        failed_projected.status = ReceiptStatus::Failed {
            code: "ledger.op_failed".to_owned(),
        };
        failed_projected.settlement_decision_id = Some(decision_id.clone());
        let mut failed_other = failed_projected.clone();
        failed_other.settlement_decision_id = Some("d2".repeat(32));
        let cases: [(&SubmissionReceipt, &ReconcileReport, Option<&str>); 7] = [
            // The receipt projection of this run's expiry failed.
            (&receipt, &failed, None),
            // This run committed an expiry the receipt does not carry.
            (&receipt, &committed, Some(decision_id.as_str())),
            // The receipt names another decision than the committed one.
            (&other, &committed, Some(decision_id.as_str())),
            // The verified state holds an expiry the receipt does not carry.
            (
                &receipt,
                &ReconcileReport::default(),
                Some(decision_id.as_str()),
            ),
            // This run's expiry is absent from the verified state.
            (&projected, &committed, None),
            // A failed receipt names another decision than the verified one.
            (
                &failed_other,
                &ReconcileReport::default(),
                Some(decision_id.as_str()),
            ),
            (&failed_other, &committed, Some(decision_id.as_str())),
        ];
        for (receipt, report, verified) in cases {
            let decision = clear_decision(receipt, report, None, verified, 0, false, false);
            let (code, message) = refusal_of(decision).expect("the clear is refused");
            assert_eq!(code, "submission.record_unavailable", "{message}");
            if let Some(error) = &report.receipt_write_error {
                assert!(message.contains(error), "{message}");
            }
        }
        assert!(matches!(
            clear_decision(
                &projected,
                &committed,
                None,
                Some(decision_id.as_str()),
                0,
                false,
                false
            ),
            ClearDecision::Clear {
                evidence: Some(ClearEvidence::Disposition(
                    ReleaseEvidence::AccountingExpired
                )),
                unbounded_exposure: false,
            }
        ));
        // An unheld failed receipt that carries the verified identifier
        // clears on the acknowledgement, whether this run or an earlier one
        // committed the expiry.
        for report in [&ReconcileReport::default(), &committed] {
            assert!(
                matches!(
                    clear_decision(
                        &failed_projected,
                        report,
                        None,
                        Some(decision_id.as_str()),
                        0,
                        false,
                        false
                    ),
                    ClearDecision::Clear {
                        evidence: None,
                        unbounded_exposure: false,
                    }
                ),
                "{report:?}"
            );
        }
    }

    /// An authenticated hold without a time bound needs the second flag on
    /// every network, whatever the receipt records, and the decision carries
    /// the exposure for the clear row. A receipt that records a network answer
    /// keeps it when the endpoint now answers otherwise, and that answer is
    /// the clear row's evidence; a receipt store that failed still refuses,
    /// and so does an answer reported against another recorded status. A
    /// bounded hold decides on its bound. Without a hold, only a sent untimed
    /// mainnet receipt needs the flag.
    #[test]
    fn an_untimed_hold_needs_the_unbounded_acknowledgement_on_every_network() {
        use stellar_agent_network::policy_state::UnrecordedAnswer;

        let changed_answer =
            |receipt: &SubmissionReceipt, recorded: ReceiptStatus, answer| ReconcileReport {
                examined: 1,
                confirmed: usize::from(answer == ReportedAnswer::Success),
                retention_expired: usize::from(answer == ReportedAnswer::RetentionExpired),
                unrecorded: vec![UnrecordedAnswer {
                    envelope_hash: receipt.envelope_hash.clone(),
                    recorded,
                    answer,
                }],
                ..ReconcileReport::default()
            };
        let statuses = [
            ReceiptStatus::Pending,
            ReceiptStatus::Ambiguous,
            ReceiptStatus::Success,
            ReceiptStatus::Failed {
                code: "ledger.op_failed".to_owned(),
            },
        ];
        for mainnet in [true, false] {
            for status in &statuses {
                for (receipt_max, hold_max) in [(0, 0), (123, 0), (0, 123)] {
                    let mut receipt = submitted_receipt(receipt_max);
                    receipt.status = status.clone();
                    let mut held = held_for(&receipt);
                    held.max_time = hold_max;
                    // Under an untimed hold the endpoint now contradicts a
                    // recorded answer: absence beyond retention after a
                    // success, a success after a failure.
                    let (report, evidence) = match status {
                        ReceiptStatus::Success if hold_max == 0 => (
                            changed_answer(
                                &receipt,
                                status.clone(),
                                ReportedAnswer::RetentionExpired,
                            ),
                            Some(ClearEvidence::Answer(ReportedAnswer::RetentionExpired)),
                        ),
                        ReceiptStatus::Failed { .. } if hold_max == 0 => (
                            changed_answer(&receipt, status.clone(), ReportedAnswer::Success),
                            Some(ClearEvidence::Answer(ReportedAnswer::Success)),
                        ),
                        _ => (ReconcileReport::default(), None),
                    };
                    let refused =
                        clear_decision(&receipt, &report, Some(&held), None, 0, mainnet, false);
                    if hold_max > 0 {
                        let expected = if status.is_operator_clearable() {
                            "submission.still_pending"
                        } else {
                            "submission.not_clearable"
                        };
                        assert_eq!(
                            refusal_of(refused).expect("bounded refusal").0,
                            expected,
                            "mainnet={mainnet} {status:?}"
                        );
                        continue;
                    }
                    let (code, message) = refusal_of(refused).expect("unbounded exposure refuses");
                    assert_eq!(
                        code, "submission.unbounded_exposure",
                        "mainnet={mainnet} {status:?}"
                    );
                    assert!(message.contains("--acknowledge --acknowledge-unbounded"));
                    assert!(message.contains("sequence 7"));
                    let decision =
                        clear_decision(&receipt, &report, Some(&held), None, 0, mainnet, true);
                    assert!(
                        matches!(
                            decision,
                            ClearDecision::Clear {
                                evidence: recorded,
                                unbounded_exposure: true
                            } if recorded == evidence
                        ),
                        "mainnet={mainnet} {status:?}: {decision:?}"
                    );
                    let store_failed = ReconcileReport {
                        examined: 1,
                        receipt_write_failed: 1,
                        receipt_write_error: Some("the receipt store could not be read".to_owned()),
                        ..ReconcileReport::default()
                    };
                    assert_eq!(
                        refusal_of(clear_decision(
                            &receipt,
                            &store_failed,
                            Some(&held),
                            None,
                            0,
                            mainnet,
                            true
                        ))
                        .expect("a failed receipt store refuses")
                        .0,
                        "submission.record_unavailable",
                        "mainnet={mainnet} {status:?}"
                    );
                    let elsewhere =
                        changed_answer(&receipt, ReceiptStatus::Reorged, ReportedAnswer::Success);
                    assert_eq!(
                        refusal_of(clear_decision(
                            &receipt,
                            &elsewhere,
                            Some(&held),
                            None,
                            0,
                            mainnet,
                            true
                        ))
                        .expect("an answer against another recorded status refuses")
                        .0,
                        "submission.record_unavailable",
                        "mainnet={mainnet} {status:?}"
                    );
                    let hint = acknowledgement_required(
                        Some(&receipt),
                        Some(&held),
                        &receipt.tx_hash,
                        0,
                        mainnet,
                    );
                    assert!(
                        hint.error
                            .expect("hint")
                            .message
                            .contains("--acknowledge-unbounded")
                    );
                }
            }
        }
        let receipt = submitted_receipt(0);
        let held = held_for(&receipt);
        for mainnet in [true, false] {
            let orphan_hint =
                acknowledgement_required(None, Some(&held), &receipt.tx_hash, 0, mainnet);
            assert!(
                orphan_hint
                    .error
                    .expect("hint")
                    .message
                    .contains("--acknowledge --acknowledge-unbounded"),
                "an untimed orphan names the second flag, mainnet={mainnet}"
            );
        }
        assert_eq!(
            refusal_of(clear_decision(
                &receipt,
                &ReconcileReport::default(),
                None,
                None,
                0,
                true,
                false
            ))
            .expect("a sent untimed mainnet receipt refuses")
            .0,
            "submission.unbounded_exposure"
        );
        assert!(matches!(
            clear_decision(
                &receipt,
                &ReconcileReport::default(),
                None,
                None,
                0,
                false,
                false
            ),
            ClearDecision::Clear {
                evidence: None,
                unbounded_exposure: false
            }
        ));
    }

    #[test]
    fn edited_receipt_cannot_hide_authenticated_unbounded_exposure() {
        let mut receipt = submitted_receipt(0);
        let held = held_for(&receipt);
        receipt.max_time = 123;
        receipt.submitted = false;
        let report = ReconcileReport::default();
        let refusal = clear_decision(&receipt, &report, Some(&held), None, 200_000, true, false);
        assert_eq!(
            refusal_of(refusal).expect("unbounded refusal").0,
            "submission.unbounded_exposure"
        );
        let decision = clear_decision(&receipt, &report, Some(&held), None, 200_000, true, true);
        assert!(matches!(
            decision,
            ClearDecision::Clear {
                unbounded_exposure: true,
                ..
            }
        ));
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
            chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Testnet,
            ),
            id: receipt.envelope_hash.clone(),
            tx_hash: receipt.tx_hash.clone(),
            source: receipt.source.clone(),
            sequence: 7,
            max_time: receipt.max_time,
            pending_since_ms: 0,
            submission_ledger: 100,
            submission_anchor: None,
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

    /// A receipt's release code is display data: a fabricated code
    /// establishes no accounting decision, with or without a hold, and the
    /// clear proceeds on the operator's acknowledgement alone. A verified
    /// accounting expiry, projected onto the receipt, supplies
    /// `submission.accounting_expired` as the clear row's evidence.
    #[test]
    fn a_release_code_the_window_does_not_bear_out_is_no_evidence() {
        use stellar_agent_core::profile::receipt::ReleaseEvidence;
        use stellar_agent_network::policy_state::SettledSubmission;

        // A bound that passed before `NOW_MS`, so the hold's bound decides
        // nothing here.
        const NOW_MS: u64 = 200_000;
        let mut receipt = submitted_receipt(100);
        receipt.status = ReceiptStatus::Ambiguous;
        receipt.release_code = Some(ReleaseEvidence::SequenceConsumed);
        let held = held_for(&receipt);
        let no_evidence = |decision: ClearDecision| {
            matches!(
                decision,
                ClearDecision::Clear {
                    evidence: None,
                    unbounded_exposure: false
                }
            )
        };

        for (code, hold) in [
            (ReleaseEvidence::SequenceConsumed, Some(&held)),
            (ReleaseEvidence::SequenceConsumed, None),
            (ReleaseEvidence::TimeBoundPassed, None),
            (ReleaseEvidence::AccountingExpired, None),
        ] {
            receipt.release_code = Some(code);
            let decision = clear_decision(
                &receipt,
                &ReconcileReport::default(),
                hold,
                None,
                NOW_MS,
                false,
                false,
            );
            assert!(no_evidence(decision), "{code:?}");
        }

        let decision_id = "e7".repeat(32);
        receipt.release_code = Some(ReleaseEvidence::AccountingExpired);
        receipt.settlement_decision_id = Some(decision_id.clone());
        let released_now = ReconcileReport {
            released: 1,
            settled: vec![SettledSubmission {
                envelope_hash: receipt.envelope_hash.clone(),
                tx_hash: receipt.tx_hash.clone(),
                decision_id: decision_id.clone(),
            }],
            ..ReconcileReport::default()
        };
        for report in [&released_now, &ReconcileReport::default()] {
            let decision = clear_decision(
                &receipt,
                report,
                None,
                Some(decision_id.as_str()),
                NOW_MS,
                false,
                false,
            );
            assert!(
                matches!(
                    decision,
                    ClearDecision::Clear {
                        evidence: Some(ClearEvidence::Disposition(
                            ReleaseEvidence::AccountingExpired
                        )),
                        unbounded_exposure: false
                    }
                ),
                "{decision:?}"
            );
        }

        // A copied identifier proves nothing without the verified record.
        let decision = clear_decision(
            &receipt,
            &ReconcileReport::default(),
            None,
            None,
            NOW_MS,
            false,
            false,
        );
        assert!(no_evidence(decision));
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
            let decision = clear_decision(
                &receipt,
                &unwitnessed,
                Some(&held),
                None,
                now_s * 1_000,
                false,
                false,
            );
            let (code, message) = refusal_of(decision).expect("a bound not yet passed refuses");
            assert_eq!(code, "submission.still_pending");
            assert!(message.contains("host's clock"), "{message}");
        }

        let decision = clear_decision(
            &receipt,
            &unwitnessed,
            Some(&held),
            None,
            (max_time + 1) * 1_000,
            false,
            false,
        );
        assert!(
            matches!(
                decision,
                ClearDecision::Clear {
                    evidence: None,
                    unbounded_exposure: false
                }
            ),
            "{decision:?}"
        );

        let unreachable = report(ReconcileFailureKind::Unreachable);
        let decision = clear_decision(
            &receipt,
            &unreachable,
            Some(&held),
            None,
            (max_time + 1) * 1_000,
            false,
            false,
        );
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

    /// The oracle's `SUCCESS` and `FAILED` refuse a clear of a bounded hold,
    /// and so does an oracle that cannot answer; its `NOT_FOUND` refuses
    /// nothing. Without a hold only its `SUCCESS` refuses. For an untimed
    /// hold no oracle report refuses the clear.
    #[tokio::test]
    async fn the_oracle_answer_decides_whether_a_clear_is_refused() {
        use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
        use stellar_agent_network::StellarRpcClient;

        let tx_hash = "af".repeat(32);
        for status in ["SUCCESS", "FAILED", "NOT_FOUND"] {
            let (_server, oracle) = oracle_reporting(MAINNET_PASSPHRASE, status).await;
            assert!(
                oracle_precheck(&oracle, &tx_hash, oracle_deadline(), OracleVeto::Nothing)
                    .await
                    .is_ok(),
                "{status}: an untimed hold's clear is not refused on an oracle report"
            );
        }
        for (veto, status, refused) in [
            (OracleVeto::SuccessAndFailure, "SUCCESS", true),
            (OracleVeto::SuccessAndFailure, "FAILED", true),
            (OracleVeto::SuccessAndFailure, "NOT_FOUND", false),
            (OracleVeto::Success, "SUCCESS", true),
            (OracleVeto::Success, "FAILED", false),
            (OracleVeto::Success, "NOT_FOUND", false),
        ] {
            let (_server, oracle) = oracle_reporting(MAINNET_PASSPHRASE, status).await;

            let checked = oracle_precheck(&oracle, &tx_hash, oracle_deadline(), veto).await;

            assert_eq!(checked.is_err(), refused, "{veto:?} {status}");
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
                OracleVeto::Nothing,
            )
            .await,
        );
        assert_eq!(code, "network.rpc_unreachable");
        assert!(
            message.contains("the oracle's identity could not be read"),
            "{message}"
        );
    }

    /// An oracle whose identity answer arrives after the deadline is an
    /// unreachable endpoint: the clear refuses with `network.rpc_unreachable`
    /// at the deadline, and its transaction is never asked.
    #[tokio::test]
    async fn an_identity_read_past_the_deadline_reports_the_unreachable_oracle() {
        use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({ "method": "getNetwork" }),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": stellar_agent_test_support::signed_envelope::get_network_result(
                            MAINNET_PASSPHRASE
                        ),
                    }))
                    .set_delay(std::time::Duration::from_secs(30)),
            )
            .mount(&server)
            .await;
        let oracle = stellar_agent_network::StellarRpcClient::new(&server.uri()).expect("client");

        let started = std::time::Instant::now();
        let (code, message) = oracle_refusal_error(
            oracle_precheck(
                &oracle,
                &"af".repeat(32),
                tokio::time::Instant::now() + DEADLINE,
                OracleVeto::SuccessAndFailure,
            )
            .await,
        );
        let elapsed = started.elapsed();

        assert_eq!(code, "network.rpc_unreachable", "{message}");
        assert!(
            message.contains("the oracle's identity could not be read"),
            "{message}"
        );
        assert!(
            elapsed < DEADLINE + std::time::Duration::from_secs(2),
            "the deadline ends the identity read: {elapsed:?}"
        );
        let asked = server.received_requests().await.expect("recorded");
        assert!(
            asked.iter().all(|request| {
                !String::from_utf8_lossy(&request.body).contains("getTransaction")
            }),
            "the transaction is never asked"
        );
    }

    /// An oracle that reports another network refuses the clear whatever it
    /// answers about the transaction, and its transaction is never asked.
    #[tokio::test]
    async fn an_oracle_on_another_network_refuses_the_clear() {
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

        let tx_hash = "af".repeat(32);
        let (server, oracle) = oracle_reporting(TESTNET_PASSPHRASE, "NOT_FOUND").await;

        let (code, message) = oracle_refusal_error(
            oracle_precheck(&oracle, &tx_hash, oracle_deadline(), OracleVeto::Nothing).await,
        );

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
        let checked = oracle_precheck(
            &oracle,
            &tx_hash,
            tokio::time::Instant::now() + DEADLINE,
            OracleVeto::SuccessAndFailure,
        )
        .await;
        let elapsed = started.elapsed();

        let (code, message) = oracle_refusal_error(checked);
        assert_eq!(code, "network.rpc_unreachable");
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
                        chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                            profile.chain_id,
                        ),
                        id: ENVELOPE_HASH.to_owned(),
                        tx_hash: TX_HASH.to_owned(),
                        source,
                        sequence: 7,
                        max_time,
                        pending_since_ms: now_ms - 400_000,
                        submission_ledger: 1_000,
                        submission_anchor: None,
                        operator_required: false,
                    },
                )
                .expect("reservation");
        }

        /// Runs `tx receipt clear --acknowledge` on the seeded submission,
        /// with `--acknowledge-unbounded` when `acknowledge_unbounded` is set.
        async fn clear(fixture: &MainnetFixture, acknowledge_unbounded: bool) -> (i32, Value) {
            crate::common::render::take_rendered_for_test();
            let code = run_clear(&ClearArgs {
                envelope_hash: ENVELOPE_HASH.to_owned(),
                profile: Some(fixture.name.to_owned()),
                acknowledge: true,
                acknowledge_unbounded,
                output: OutputFormat::Json,
            })
            .await;
            (code, last_rendered())
        }

        /// A mainnet endpoint funding the agent that answers every
        /// `getTransaction` with `NOT_FOUND` and whose retention floor lies
        /// above the seeded submission's ledger.
        fn past_retention() -> ClassicRpc {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            past_retention_on(ClassicRpc::mainnet(&[&agent]))
        }

        /// A testnet endpoint funding the agent, otherwise as
        /// [`past_retention`].
        fn testnet_past_retention() -> ClassicRpc {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            past_retention_on(ClassicRpc::testnet(&[&agent]))
        }

        /// `rpc` answering every `getTransaction` with `NOT_FOUND`, with a
        /// retention floor above the seeded submission's ledger.
        fn past_retention_on(rpc: ClassicRpc) -> ClassicRpc {
            rpc.with_script(|method, _, _| match method {
                "getTransaction" => Some(json!({
                    "status": "NOT_FOUND",
                    "latestLedger": 2000,
                    "oldestLedger": 1500
                })),
                "getHealth" => Some(json!({
                    "status": "healthy",
                    "latestLedger": 2000,
                    "oldestLedger": 1500,
                    "ledgerRetentionWindow": 500
                })),
                _ => None,
            })
        }

        /// The profile's audit log as it stands, empty while it is absent.
        fn audit_log(fixture: &MainnetFixture) -> String {
            std::fs::read_to_string(&fixture.profile().audit_log_path).unwrap_or_default()
        }

        /// Runs the clear on the seeded untimed submission twice: without
        /// `--acknowledge-unbounded` it refuses with
        /// `submission.unbounded_exposure` and leaves the receipt in `status`,
        /// the reservation and the audit log as they were; with it the
        /// reservation is released, the receipt cleared and the clear row
        /// records the exposure and `evidence`.
        async fn assert_clear_needs_the_unbounded_acknowledgement(
            fixture: &MainnetFixture,
            status: ReceiptStatus,
            evidence: Option<&str>,
        ) {
            let log_before = audit_log(fixture);

            let (code, envelope) = clear(fixture, false).await;

            assert_eq!(code, 1, "{envelope}");
            assert_eq!(
                envelope["error"]["code"], "submission.unbounded_exposure",
                "{envelope}"
            );
            assert_eq!(fixture.pending_reservations(), 1, "the reservation stands");
            assert_eq!(receipt_status(fixture), status);
            assert_eq!(audit_log(fixture), log_before, "the audit log is untouched");

            let (code, envelope) = clear(fixture, true).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(
                envelope["data"]["cleared_from"],
                status.label(),
                "{envelope}"
            );
            assert_eq!(
                fixture.pending_reservations(),
                0,
                "the reservation is released"
            );
            assert_eq!(receipt_status(fixture), ReceiptStatus::ClearedByOperator);
            assert_eq!(envelope["data"]["reservation_released"], true, "{envelope}");
            let rows = fixture.audit_rows("submission_receipt_cleared");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["envelope_hash"], ENVELOPE_HASH, "{}", rows[0]);
            assert_eq!(rows[0]["unbounded_exposure"], true, "{}", rows[0]);
            assert_eq!(rows[0]["reservation_released"], true, "{}", rows[0]);
            assert_eq!(rows[0]["evidence"].as_str(), evidence, "{}", rows[0]);
        }

        /// Records `status` on the seeded submission's receipt.
        fn record_receipt_status(fixture: &MainnetFixture, status: ReceiptStatus) {
            ReceiptStore::open(fixture.name)
                .expect("receipt store")
                .finalize(ENVELOPE_HASH, status, Some(1_005))
                .expect("record the answer");
        }

        /// Holds the receipt store's writer lock until the returned file drops.
        fn hold_receipt_writer(fixture: &MainnetFixture) -> std::fs::File {
            let held = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(
                    ReceiptStore::open(fixture.name)
                        .expect("receipt store")
                        .lock_file_path()
                        .expect("lock path"),
                )
                .expect("lock file");
            held.try_lock().expect("the receipt writer lock");
            held
        }

        /// The profile's spending-window file as it stands.
        fn window_bytes(fixture: &MainnetFixture) -> Vec<u8> {
            std::fs::read(PersistedWindowStore::for_profile(fixture.name).path())
                .expect("window file")
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

            let run = clear(&fixture, false).await;

            assert_refused_untouched(&fixture, &run, "submission.still_pending");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(message.contains("host's clock"), "{message}");
            assert!(fixture.oracle_methods().await.is_empty());
        }

        /// Without an oracle, a primary `FAILED` whose time bound has passed
        /// on the host clock clears as an unknown outcome under the
        /// acknowledgement. The bounded reservation keeps counting until its
        /// accounting horizon, so the clear releases nothing.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_unconfirmed_failure_clears_after_the_time_bound_without_an_oracle() {
            let fixture = Spec::new("clear-mainnet-failed-passed-bound")
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let (code, envelope) = clear(&fixture, false).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(envelope["data"]["cleared_from"], "pending", "{envelope}");
            assert_eq!(envelope["data"]["reservation_released"], false);
            assert_eq!(
                fixture.pending_reservations(),
                1,
                "the bounded reservation counts until its horizon"
            );
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            let rows = fixture.audit_rows("submission_receipt_cleared");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["reservation_released"], false, "{}", rows[0]);
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

            let run = clear(&fixture, false).await;

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

            let run = clear(&fixture, false).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(
                message.starts_with("the endpoint reports this transaction as failed"),
                "{message}"
            );
        }

        /// An oracle `FAILED` report refuses a bounded hold's clear before
        /// reconciliation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_oracle_failure_refuses_the_clear_of_a_held_submission() {
            let fixture = Spec::new("clear-mainnet-oracle-failed-held")
                .primary(answering("NOT_FOUND"))
                .oracle(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);

            let run = clear(&fixture, false).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
            let message = run.1["error"]["message"].as_str().expect("message");
            assert!(
                message.starts_with("the oracle reports this transaction as failed"),
                "{message}"
            );
        }

        /// A `failed` receipt without a hold clears on the acknowledgement
        /// while the endpoint and the oracle both report `FAILED`: the reports
        /// are unauthenticated, and no counted exposure stands.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_unheld_failure_clears_while_endpoint_and_oracle_report_it() {
            let fixture = Spec::new("clear-mainnet-unheld-failed")
                .primary(answering("FAILED"))
                .oracle(answering("FAILED"))
                .build()
                .await;
            let source =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            let receipts = ReceiptStore::open(fixture.name).expect("receipt store");
            receipts
                .try_begin(ENVELOPE_HASH, TX_HASH, &source, 7, now_secs() - 10, 1_000)
                .expect("receipt");
            receipts.mark_submitted(ENVELOPE_HASH).expect("sent");
            record_receipt_status(&fixture, failed_on_chain());

            let (code, envelope) = clear(&fixture, false).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(envelope["data"]["cleared_from"], "failed", "{envelope}");
            assert_eq!(envelope["data"]["reservation_released"], false);
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            assert_eq!(fixture.pending_reservations(), 0);
            let rows = fixture.audit_rows("submission_receipt_cleared");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["envelope_hash"], ENVELOPE_HASH, "{}", rows[0]);
            assert_eq!(rows[0]["reservation_released"], false, "{}", rows[0]);
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

            let run = clear(&fixture, false).await;

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

        /// A mainnet `tx status` whose primary reports a valid success while
        /// the oracle reports no inclusion decides nothing. The record stays
        /// pending, the reservation stays open, and no settlement or release
        /// code is recorded.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn mainnet_status_keeps_pending_before_recovery_integration() {
            let fixture = Spec::new("status-mainnet-primary-success")
                .primary(answering("SUCCESS"))
                .oracle(answering("NOT_FOUND"))
                .build()
                .await;
            seed_submission(&fixture, now_secs() - 10);
            crate::common::render::take_rendered_for_test();

            let code = crate::commands::tx::status::run(&crate::commands::tx::status::StatusArgs {
                tx_hash: TX_HASH.to_owned(),
                profile: Some(fixture.name.to_owned()),
                output: OutputFormat::Json,
            })
            .await;
            let envelope = last_rendered();

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(
                envelope["data"]["record"]["status"], "pending",
                "{envelope}"
            );
            assert!(
                envelope["data"]["record"]["release_code"].is_null(),
                "{envelope}"
            );
            assert!(envelope["data"]["settled"].is_null(), "{envelope}");
            assert_eq!(
                fixture.pending_reservations(),
                1,
                "the reservation stays open"
            );
            assert_eq!(receipt_status(&fixture), ReceiptStatus::Pending);
            assert!(fixture.audit_rows("value_action_submitted").is_empty());
            assert!(
                fixture
                    .audit_rows("submission_accounting_expired")
                    .is_empty()
            );
            assert!(
                fixture
                    .primary_methods()
                    .await
                    .iter()
                    .any(|method| method == "getTransaction"),
                "the diagnostic read reaches the primary"
            );
        }

        /// The clear ends its oracle reads by the command's deadline. The
        /// pre-check's transaction answer, the last oracle request, stalls
        /// past a one-second submit timeout. The clear refuses by then; the
        /// submission stays as it is and the audit writer is free. The
        /// oracle's identity is read once.
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
            oracle.stall_after("getTransaction", 0, std::time::Duration::from_secs(30));
            let asked_before = fixture.oracle_methods().await.len();

            let started = std::time::Instant::now();
            let run = clear(&fixture, false).await;
            let elapsed = started.elapsed();

            assert_refused_untouched(&fixture, &run, "network.rpc_unreachable");
            assert!(
                elapsed < SUBMIT_TIMEOUT + std::time::Duration::from_millis(1500),
                "the deadline ends the oracle's reads: {elapsed:?}"
            );
            assert_eq!(
                fixture.oracle_methods().await[asked_before..],
                ["getNetwork", "getTransaction"],
                "one identity read and the pre-check's question"
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

        /// Without an oracle, a sent untimed submission the primary reports
        /// `FAILED` stays pending, and its clear needs the unbounded
        /// acknowledgement.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_untimed_pending_submission_needs_the_unbounded_acknowledgement() {
            let fixture = Spec::new("clear-mainnet-untimed-pending")
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, 0);

            assert_clear_needs_the_unbounded_acknowledgement(
                &fixture,
                ReceiptStatus::Pending,
                None,
            )
            .await;
            assert!(fixture.oracle_methods().await.is_empty());
        }

        /// An untimed hold whose primary and oracle both keep reporting
        /// `FAILED` stays eligible for the clear: with both acknowledgements
        /// it is cleared and its hold released, and with `--acknowledge`
        /// alone it is refused.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_untimed_hold_with_a_continuing_oracle_failure_is_cleared() {
            let fixture = Spec::new("clear-mainnet-untimed-oracle-failed")
                .primary(answering("FAILED"))
                .oracle(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, 0);

            assert_clear_needs_the_unbounded_acknowledgement(
                &fixture,
                ReceiptStatus::Pending,
                None,
            )
            .await;
        }

        /// A receipt edited to carry a passed time bound and an unsent state
        /// does not hide the exposure of its untimed authenticated hold: the
        /// clear row `run_clear` writes records the unbounded exposure.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_edited_receipt_bound_does_not_hide_the_exposure_in_the_clear_row() {
            let fixture = Spec::new("clear-mainnet-edited-receipt")
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, 0);
            let path = ReceiptStore::open(fixture.name)
                .expect("receipt store")
                .file_path()
                .expect("receipt path");
            let bound = now_secs() - 10;
            let mut stored: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("receipts"))
                    .expect("receipt JSON");
            stored[ENVELOPE_HASH]["max_time"] = json!(bound);
            stored[ENVELOPE_HASH]["submitted"] = json!(false);
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&stored).expect("receipt JSON"),
            )
            .expect("edit the receipt");
            let edited = ReceiptStore::open(fixture.name)
                .expect("receipt store")
                .get(ENVELOPE_HASH)
                .expect("read")
                .expect("present");
            assert_eq!(edited.max_time, bound, "the edit is read back");
            assert!(!edited.submitted);

            assert_clear_needs_the_unbounded_acknowledgement(
                &fixture,
                ReceiptStatus::Pending,
                None,
            )
            .await;
        }

        /// A sent untimed submission below the oracle's retention floor stays
        /// `pending` with its reservation kept, because the mainnet pass runs
        /// no chain settlement. Its bytes can still apply, so its clear needs
        /// the unbounded acknowledgement.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_untimed_submission_past_retention_needs_the_unbounded_acknowledgement() {
            let fixture = Spec::new("clear-mainnet-untimed-ambiguous")
                .primary(answering("NOT_FOUND"))
                .oracle(past_retention())
                .build()
                .await;
            seed_submission(&fixture, 0);

            assert_clear_needs_the_unbounded_acknowledgement(
                &fixture,
                ReceiptStatus::Pending,
                None,
            )
            .await;
        }

        /// An untimed hold whose receipt records a success that the endpoint
        /// now reports missing beyond its retention floor keeps the recorded
        /// success through reconciliation: the clear needs both
        /// acknowledgements, ends `cleared_by_operator` with the hold
        /// released, and its row carries the endpoint's answer as evidence.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_untimed_success_outside_endpoint_retention_is_cleared() {
            let fixture = Spec::new("clear-untimed-success-retention")
                .testnet()
                .primary(testnet_past_retention())
                .build()
                .await;
            seed_submission(&fixture, 0);
            record_receipt_status(&fixture, ReceiptStatus::Success);

            assert_clear_needs_the_unbounded_acknowledgement(
                &fixture,
                ReceiptStatus::Success,
                Some("submission.retention_expired"),
            )
            .await;
        }

        /// An untimed hold whose receipt records a failure that the endpoint
        /// now reports as a success keeps the recorded failure, because the
        /// mainnet pass settles no chain answer, and clears the same way
        /// with no evidence on its row.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_untimed_failure_the_endpoint_now_reports_successful_is_cleared() {
            let fixture = Spec::new("clear-untimed-failed-success")
                .without_oracle()
                .primary(answering("SUCCESS"))
                .build()
                .await;
            seed_submission(&fixture, 0);
            let failed = ReceiptStatus::Failed {
                code: "submission.on_chain_failed".to_owned(),
            };
            record_receipt_status(&fixture, failed.clone());

            assert_clear_needs_the_unbounded_acknowledgement(&fixture, failed, None).await;
        }

        /// A clear of an untimed hold interrupted after its row, before the
        /// accounting transition, keeps the hold; the re-run applies the
        /// transition and marks the receipt through the ordinary path and
        /// writes no second row.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_clear_interrupted_after_its_row_completes_on_a_re_run() {
            let fixture = Spec::new("clear-untimed-resume-row")
                .testnet()
                .primary(testnet_past_retention())
                .build()
                .await;
            seed_submission(&fixture, 0);
            record_receipt_status(&fixture, ReceiptStatus::Success);
            let profile = fixture.profile();
            let window_lock = stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
                PersistedWindowStore::for_profile(fixture.name).path(),
                &profile.policy_window_state_key_id,
            )
            .expect("the window lock");

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 1, "{envelope}");
            assert_eq!(fixture.audit_rows("submission_receipt_cleared").len(), 1);
            assert_eq!(fixture.pending_reservations(), 1, "the hold stands");
            assert_eq!(receipt_status(&fixture), ReceiptStatus::Success);
            drop(window_lock);

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(envelope["data"]["cleared_from"], "success", "{envelope}");
            assert_eq!(envelope["data"]["reservation_released"], true, "{envelope}");
            assert_eq!(fixture.pending_reservations(), 0, "the hold is released");
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            let rows = fixture.audit_rows("submission_receipt_cleared");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["envelope_hash"], ENVELOPE_HASH, "{}", rows[0]);
            assert_eq!(rows[0]["reservation_released"], true, "{}", rows[0]);
        }

        /// A clear of an untimed hold interrupted after the accounting
        /// transition released the hold, before the mark, leaves a receipt
        /// that records a network answer and no hold. The re-run resumes from
        /// the clear row: with both acknowledgements it marks the receipt,
        /// reports the release, writes no second row and leaves the window
        /// as the first run left it; with `--acknowledge` alone it refuses.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_clear_interrupted_after_its_release_resumes_from_its_row() {
            let fixture = Spec::new("clear-untimed-resume-release")
                .testnet()
                .primary(testnet_past_retention())
                .build()
                .await;
            seed_submission(&fixture, 0);
            record_receipt_status(&fixture, ReceiptStatus::Success);
            let receipt_lock = hold_receipt_writer(&fixture);

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 1, "{envelope}");
            assert_eq!(
                envelope["error"]["code"], "submission.record_unavailable",
                "{envelope}"
            );
            assert_eq!(fixture.pending_reservations(), 0, "the hold is released");
            assert_eq!(receipt_status(&fixture), ReceiptStatus::Success);
            assert_eq!(fixture.audit_rows("submission_receipt_cleared").len(), 1);
            drop(receipt_lock);
            let window = window_bytes(&fixture);

            let (code, envelope) = clear(&fixture, false).await;

            assert_eq!(code, 1, "{envelope}");
            assert_eq!(
                envelope["error"]["code"], "submission.unbounded_exposure",
                "{envelope}"
            );
            assert_eq!(receipt_status(&fixture), ReceiptStatus::Success);

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(envelope["data"]["cleared_from"], "success", "{envelope}");
            assert_eq!(envelope["data"]["reservation_released"], true, "{envelope}");
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            let rows = fixture.audit_rows("submission_receipt_cleared");
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0]["unbounded_exposure"], true, "{}", rows[0]);
            assert_eq!(rows[0]["reservation_released"], true, "{}", rows[0]);
            assert_eq!(
                window_bytes(&fixture),
                window,
                "the re-run releases nothing again"
            );
        }

        /// Runs a clear of the seeded untimed hold whose receipt records
        /// `status`, or stays `pending` for `None`, stopped after the release
        /// and before the mark, then re-runs it: the re-run resumes from its
        /// clear row, reports the release the row records, writes no second
        /// row and releases nothing again.
        async fn assert_open_clear_resumes_from_its_row(
            name: &'static str,
            status: Option<ReceiptStatus>,
        ) {
            let fixture = Spec::new(name)
                .without_oracle()
                .primary(answering("FAILED"))
                .build()
                .await;
            seed_submission(&fixture, 0);
            if let Some(status) = &status {
                record_receipt_status(&fixture, status.clone());
            }
            let status = status.unwrap_or(ReceiptStatus::Pending);
            let receipt_lock = hold_receipt_writer(&fixture);

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 1, "{envelope}");
            assert_eq!(
                envelope["error"]["code"], "submission.record_unavailable",
                "{envelope}"
            );
            assert_eq!(fixture.pending_reservations(), 0, "the hold is released");
            assert_eq!(receipt_status(&fixture), status);
            drop(receipt_lock);
            let window = window_bytes(&fixture);

            let (code, envelope) = clear(&fixture, true).await;

            assert_eq!(code, 0, "{envelope}");
            assert_eq!(
                envelope["data"]["cleared_from"],
                status.label(),
                "{envelope}"
            );
            assert_eq!(envelope["data"]["reservation_released"], true, "{envelope}");
            assert_eq!(receipt_status(&fixture), ReceiptStatus::ClearedByOperator);
            assert_eq!(fixture.audit_rows("submission_receipt_cleared").len(), 1);
            assert_eq!(
                window_bytes(&fixture),
                window,
                "the re-run releases nothing again"
            );
        }

        /// A clear of an untimed hold whose receipt is still `pending`,
        /// stopped after the release and before the mark, resumes from its
        /// clear row as well: the re-run reports the release the row records
        /// and writes no second row.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_pending_clear_interrupted_after_its_release_resumes_from_its_row() {
            assert_open_clear_resumes_from_its_row("clear-untimed-resume-pending", None).await;
        }

        /// A clear of an untimed hold whose receipt is `ambiguous`, stopped
        /// after the release and before the mark, resumes from its clear row
        /// the same way.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_ambiguous_clear_interrupted_after_its_release_resumes_from_its_row() {
            assert_open_clear_resumes_from_its_row(
                "clear-untimed-resume-ambiguous",
                Some(ReceiptStatus::Ambiguous),
            )
            .await;
        }

        /// The bytes that make a receipt store unreadable.
        const UNREADABLE_RECEIPTS: &[u8] = b"{ not a receipt store";

        /// The failure the seeded receipt carries in the read-failure tests.
        fn failed_on_chain() -> ReceiptStatus {
            ReceiptStatus::Failed {
                code: "submission.on_chain_failed".to_owned(),
            }
        }

        /// Reconciles the seeded submission against the fixture's primary
        /// endpoint with `receipts`, as the clear does.
        async fn reconcile(fixture: &MainnetFixture, receipts: &ReceiptStore) -> ReconcileReport {
            let profile = fixture.profile();
            let client = crate::common::network::profile_network_context(&profile)
                .primary_client()
                .expect("the primary client");
            let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");
            PersistedWindowStore::for_profile(fixture.name)
                .reconcile_one(
                    &profile,
                    &client,
                    None,
                    Some(receipts),
                    ENVELOPE_HASH,
                    now_ms,
                )
                .await
                .expect("the pass runs")
        }

        /// Asserts that `report` carries the read error of the unreadable
        /// receipt store at `receipt_file` and left the window file at
        /// `window`; then makes the store readable again with `readable` and
        /// asserts that the clear decision on the receipt read from it, with
        /// both acknowledgements, still refuses with
        /// `submission.record_unavailable` naming that error.
        fn assert_read_failure_refuses_the_clear(
            fixture: &MainnetFixture,
            receipts: &ReceiptStore,
            report: &ReconcileReport,
            window: &[u8],
            receipt_file: &std::path::Path,
            readable: &[u8],
        ) {
            let read_error = receipts
                .get(ENVELOPE_HASH)
                .expect_err("the store is unreadable")
                .to_string();
            assert_eq!(report.receipt_write_failed, 1, "{report:?}");
            assert_eq!(
                report.receipt_write_error.as_deref(),
                Some(read_error.as_str()),
                "{report:?}"
            );
            assert_eq!(window_bytes(fixture), window, "the window is unchanged");

            std::fs::write(receipt_file, readable).expect("restore the receipt store");
            let receipt = receipts
                .get(ENVELOPE_HASH)
                .expect("the store reads again")
                .expect("the receipt");
            assert_eq!(receipt.status, failed_on_chain());
            let profile = fixture.profile();
            let held = PersistedWindowStore::for_profile(fixture.name)
                .pending_reservations(&profile)
                .expect("the window")
                .into_iter()
                .find(|hold| hold.id == ENVELOPE_HASH);
            assert!(held.is_some(), "the hold stands");
            let now_ms = stellar_agent_core::timefmt::now_unix_ms().expect("clock");

            let refusal = refusal_of(clear_decision(
                &receipt,
                report,
                held.as_ref(),
                None,
                now_ms,
                profile.chain_id.is_mainnet(),
                true,
            ));

            let (code, message) = refusal.expect("the clear is refused");
            assert_eq!(code, "submission.record_unavailable", "{message}");
            assert!(message.contains(&read_error), "{message}");
        }

        /// A receipt store that cannot be read when reconciliation asks about
        /// an untimed hold refuses the clear on the report's error, even once
        /// the store reads again.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_receipt_read_failure_on_the_chain_answer_path_refuses_the_clear() {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            let fixture = Spec::new("clear-untimed-unreadable-answer")
                .testnet()
                .primary(scripted(ClassicRpc::testnet(&[&agent]), "SUCCESS"))
                .build()
                .await;
            seed_submission(&fixture, 0);
            record_receipt_status(&fixture, failed_on_chain());
            let receipts = ReceiptStore::open(fixture.name).expect("receipt store");
            let receipt_file = receipts.file_path().expect("receipt file");
            let readable = std::fs::read(&receipt_file).expect("receipt bytes");
            let window = window_bytes(&fixture);
            std::fs::write(&receipt_file, UNREADABLE_RECEIPTS).expect("corrupt the store");

            let report = reconcile(&fixture, &receipts).await;

            assert_read_failure_refuses_the_clear(
                &fixture,
                &receipts,
                &report,
                &window,
                &receipt_file,
                &readable,
            );
        }

        /// A receipt store that becomes unreadable after the endpoint's
        /// `NOT_FOUND`, with the submission ledger below the retention floor,
        /// refuses the clear on the report's error, even once the store reads
        /// again.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_receipt_read_failure_on_the_retention_branch_refuses_the_clear() {
            let agent =
                stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED);
            let corrupt_at = std::sync::Arc::new(std::sync::Mutex::new(None::<std::path::PathBuf>));
            let rpc = ClassicRpc::testnet(&[&agent]).with_script({
                let corrupt_at = std::sync::Arc::clone(&corrupt_at);
                move |method, _, _| match method {
                    "getTransaction" => {
                        if let Some(path) = corrupt_at.lock().expect("path").as_ref() {
                            std::fs::write(path, UNREADABLE_RECEIPTS).expect("corrupt the store");
                        }
                        Some(json!({
                            "status": "NOT_FOUND",
                            "latestLedger": 2000,
                            "oldestLedger": 1500
                        }))
                    }
                    "getHealth" => Some(json!({
                        "status": "healthy",
                        "latestLedger": 2000,
                        "oldestLedger": 1500,
                        "ledgerRetentionWindow": 500
                    })),
                    _ => None,
                }
            });
            let fixture = Spec::new("clear-untimed-unreadable-retention")
                .testnet()
                .primary(rpc)
                .build()
                .await;
            seed_submission(&fixture, 0);
            record_receipt_status(&fixture, failed_on_chain());
            let receipts = ReceiptStore::open(fixture.name).expect("receipt store");
            let receipt_file = receipts.file_path().expect("receipt file");
            let readable = std::fs::read(&receipt_file).expect("receipt bytes");
            let window = window_bytes(&fixture);
            *corrupt_at.lock().expect("path") = Some(receipt_file.clone());

            let report = reconcile(&fixture, &receipts).await;

            *corrupt_at.lock().expect("path") = None;
            assert_eq!(report.retention_expired, 0, "{report:?}");
            assert_read_failure_refuses_the_clear(
                &fixture,
                &receipts,
                &report,
                &window,
                &receipt_file,
                &readable,
            );
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

            let run = clear(&fixture, false).await;

            assert_refused_untouched(&fixture, &run, "submission.not_clearable");
        }
    }
}
