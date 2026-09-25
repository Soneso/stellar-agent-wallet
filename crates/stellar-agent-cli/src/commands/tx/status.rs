//! `stellar-agent tx status <HASH>` — reconcile one submitted transaction
//! against the chain.
//!
//! # What it is for
//!
//! A value verb records its submission before the transaction is sent, so a
//! submission whose confirmation never arrived leaves a receipt and a
//! spending-window reservation behind. Those hold the operator's caps and the
//! wallet's duplicate check until something settles them. This verb settles
//! them by asking the endpoint what became of the transaction.
//!
//! It is also the answer to `submission.tx_timeout`: rebuilding and
//! re-submitting the same intent is never the answer, because the sequence the
//! transaction consumes may already be spent by it.
//!
//! # What it changes
//!
//! - `SUCCESS` confirms the reservation, so the spend is recorded, and
//!   finalizes the receipt.
//! - `FAILED` releases the reservation and finalizes the receipt failed.
//! - `NOT_FOUND` releases the reservation only when the transaction can no
//!   longer apply: its sequence has been consumed, or an observed ledger close
//!   time is strictly past its time bound, followed by a fresh `NOT_FOUND`.
//!   When the submission ledger predates the endpoint's retention
//!   floor, `NOT_FOUND` proves nothing, so the reservation stands and the
//!   receipt is marked ambiguous for `tx receipt clear` to resolve. An absent
//!   receipt leaves an authenticated hold marked `operator_required`.
//!
//! # Concurrency
//!
//! Settling a confirmed submission writes a value-action audit row, which
//! needs the audit writer's exclusive lock. A running MCP server holds that
//! lock for its lifetime, so this verb refuses with `audit.writer_locked`
//! while the server is up. Stop the server, reconcile, start it again.
//!
//! # Exit codes
//!
//! - 0 when the lookup completes, whatever the chain reported.
//! - 1 when the profile, the record, or the endpoint could not be reached.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::WalletError;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore, SubmissionReceipt};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::PersistedWindowStore;

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

    /// Profile whose submission records and spending window are settled.
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

    // The audit writer is proved acquirable before anything is settled: a
    // reconciliation that confirms a submission writes the value-action row
    // that submission never got to write. A persisted profile fails closed on
    // it; the synthesized zero-config profile has no audit key to fail on, and
    // reconciling is still the thing that frees its sequence.
    let audit_writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
        &profile,
        &resolved.name,
        origin,
    ) {
        Ok(writer) => writer,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let client = match StellarRpcClient::new(&profile.rpc_url) {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

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

    let receipt = match receipts.find_by_tx_hash(&args.tx_hash) {
        Ok(r) => r,
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
        Ok(open) => open.into_iter().find(|r| r.tx_hash == args.tx_hash),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the spending-window file could not be read: {e:?}"),
            ));
            return 1;
        }
    };
    let envelope_hash = receipt
        .as_ref()
        .map(|r| r.envelope_hash.as_str())
        .or_else(|| held.as_ref().map(|r| r.id.as_str()));

    // The operator asked about this transaction by name, so the reconciliation
    // runs with no budget and no minimum age: there is exactly one round
    // trip's worth of work and it was requested.
    if let Some(envelope_hash) = envelope_hash {
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
        if let Err(e) = window
            .reconcile_one(&profile, &client, Some(&receipts), envelope_hash, now_ms)
            .await
        {
            tracing::debug!(
                error = ?e,
                "tx status: reconciliation pass failed; the record stands"
            );
        }
    }

    if let Some(record) = &receipt
        && record.approval_nonce.is_some()
    {
        let approval_dir = match stellar_agent_core::profile::schema::default_approval_dir() {
            Ok(dir) => dir,
            Err(e) => {
                render_json(&Envelope::<()>::err_raw(
                    "submission.record_unavailable",
                    e.to_string(),
                ));
                return 1;
            }
        };
        if let Err(e) = stellar_agent_network::submission_record::repair_approval_consumption(
            &receipts,
            &record.envelope_hash,
            &approval_dir,
            &resolved.name,
        ) {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    }

    let chain = match client.get_transaction_status(&args.tx_hash).await {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err(&WalletError::Network(e)));
            return 1;
        }
    };

    let reservation = match window.pending_reservations(&profile) {
        Ok(open) => open.into_iter().find(|r| r.tx_hash == args.tx_hash),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the spending-window file could not be read: {e:?}"),
            ));
            return 1;
        }
    };
    // Reconciliation can restore a receipt from the authenticated hold. Read
    // the resulting record so its status and settlement audit row are surfaced.
    let receipt = match receipts.find_by_tx_hash(&args.tx_hash) {
        Ok(record) => record,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "submission.record_unavailable",
                format!("the submission receipt store could not be read: {e}"),
            ));
            return 1;
        }
    };
    let record = match receipt {
        Some(settled) => {
            // A submission the chain has now answered for gets the
            // value-action row it never got to write, carrying the legs the
            // gate sized.
            if let Some(audit) = audit_writer.as_ref() {
                crate::commands::submission_record::write_settled_row(
                    &profile,
                    &resolved.name,
                    audit,
                    &settled.envelope_hash,
                    &settled.tx_hash,
                    &settled.status,
                    settled.ledger.or(chain.ledger),
                    stellar_agent_core::audit_log::PolicyDecision::Allow,
                );
            }
            let reservation_open = reservation
                .as_ref()
                .is_some_and(|r| r.id == settled.envelope_hash);
            Some(record_view(&settled, reservation_open))
        }
        None => None,
    };

    render_json(&Envelope::ok(StatusData {
        tx_hash: args.tx_hash.clone(),
        chain_status: chain.status,
        ledger: chain.ledger,
        record,
        reservation: reservation.map(|r| ReservationView {
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
    }
}

/// Returns true when `value` is 64 lowercase hex characters.
pub(crate) fn is_tx_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

    use super::*;

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
