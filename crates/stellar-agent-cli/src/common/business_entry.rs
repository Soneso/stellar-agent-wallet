//! The business-id entry of the classic value verbs.
//!
//! A mainnet value run names itself with `--business-id`. Before the
//! confirmation ceremony the run looks the id up and opens the record that
//! binds its envelope. A retained operation answers with its stored state. A
//! waiting record signs its stored envelope. An unknown id opens a record for
//! the envelope the run built. Off mainnet a supplied id is validated and
//! echoed, and no record exists.

use std::io::Write;

use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::Profile;
use stellar_agent_network::MainnetWriteContext;
use stellar_agent_network::fees::ClassicFeeChoice;
use stellar_agent_network::operation_entry::{
    self, ClassicEntry, IdentityFacts, IntentBaseFacts, OpenedEntry,
};
use stellar_agent_network::policy_state::{
    BusinessId, OpenRequest, OperationHandle, OperationKind, OperationRecorder, OperationState,
    OperationTool, OperationView, PersistedWindowStore,
};

use crate::commands::policy_engine::MainnetPolicy;
use crate::commands::submission_record::accounting_audit_writer;
use crate::common::profile_access::ProfileOrigin;
use crate::common::render::{exit_code_after_output, render_json, write_envelope};

/// The exit code of a verb whose first run ends with an unknown outcome:
/// every refusal of a mainnet pipeline, the unknown-outcome submission
/// errors among them, exits with it.
const UNKNOWN_OUTCOME_EXIT: i32 = 1;

/// The business id a value verb enters with.
///
/// A mainnet profile requires one; every other chain validates a supplied id
/// and keeps no record of it.
///
/// # Errors
///
/// `validation.business_id_required` and `validation.business_id_invalid`.
pub(crate) fn entry_business_id(
    profile: &Profile,
    raw: Option<&str>,
) -> Result<Option<BusinessId>, WalletError> {
    operation_entry::entry_business_id(profile, raw)
}

/// The business id a mainnet value run enters with, which it requires.
///
/// # Errors
///
/// `validation.business_id_required` without an id and
/// `validation.business_id_invalid` for a malformed one.
pub(crate) fn mainnet_business_id(raw: Option<&str>) -> Result<BusinessId, WalletError> {
    BusinessId::parse(raw.unwrap_or_default())
}

/// A classic mainnet run under its business id.
#[derive(Debug)]
pub(crate) struct ClassicOperation {
    business_id: BusinessId,
    identity: [u8; 32],
    resume: Option<OperationHandle>,
}

/// How a classic mainnet run proceeds under its business id.
#[derive(Debug)]
pub(crate) enum ClassicStart {
    /// Build or resume the operation.
    Proceed(ClassicOperation),
    /// The operation needs no further work; the run prints its stored state.
    Replay(OperationView),
}

/// The record a classic mainnet run signs under.
#[derive(Debug)]
pub(crate) enum BoundEnvelope {
    /// Sign the record's envelope; its next attempt follows.
    Sign(OperationHandle),
    /// The operation needs no further work; the run prints its stored state.
    Replay(OperationView),
}

/// The unsigned envelope `handle`'s record binds, which the run signs, and
/// its fee per operation.
///
/// # Errors
///
/// `internal.unexpected_state` for a record without an envelope or with a
/// malformed one.
pub(crate) fn signing_envelope(handle: &OperationHandle) -> Result<(&str, u32), WalletError> {
    let xdr = handle.envelope_xdr().ok_or_else(|| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "a classic operation record holds no envelope".to_owned(),
        })
    })?;
    let facts = operation_entry::envelope_facts(xdr)?;
    Ok((xdr, facts.fee_per_op_stroops))
}

/// Runs `step` with an operation recorder over the profile's window store
/// and its accounting audit writer, the writer lock taken first.
fn operation_step<T>(
    context: &MainnetWriteContext,
    step: impl FnOnce(&mut OperationRecorder<'_>) -> Result<T, WalletError>,
) -> Result<T, WalletError> {
    let profile = context.profile();
    let name = context.profile_name();
    let writer = accounting_audit_writer(profile, name, ProfileOrigin::Persisted)?;
    let mut guard = writer.lock().map_err(|_| {
        WalletError::Submission(
            stellar_agent_core::error::SubmissionError::RecordUnavailable {
                detail: "the audit writer mutex is poisoned, so the operation cannot be recorded"
                    .to_owned(),
            },
        )
    })?;
    let store = PersistedWindowStore::for_profile(name);
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut recorder = OperationRecorder::new(&store, profile, &mut *guard, request_id);
    step(&mut recorder)
}

/// Looks `business_id` up before a classic mainnet run does any network
/// work.
///
/// The identity is the [`operation_entry::operation_identity`] of `facts`
/// under the verified mainnet policy.
///
/// # Errors
///
/// `operation.business_id_conflict` for an id bound to another intent,
/// `validation.mainnet_fee_cap_required` when no fee bound exists, and the
/// store's refusals.
pub(crate) fn classic_start(
    context: &MainnetWriteContext,
    policy: &MainnetPolicy,
    business_id: BusinessId,
    source: &str,
    fee_choice: ClassicFeeChoice,
    memo: &stellar_xdr::Memo,
    facts: IdentityFacts,
) -> Result<ClassicStart, WalletError> {
    let identity = operation_entry::operation_identity(
        IntentBaseFacts::new(
            context.profile(),
            source,
            &policy.verified,
            fee_choice,
            operation_entry::memo_fact(memo),
        ),
        facts,
    )?;
    let entry = operation_step(context, |recorder| {
        operation_entry::lookup_classic(recorder, &business_id, &identity)
    })?;
    let resume = match entry {
        ClassicEntry::Build => None,
        ClassicEntry::Resume(handle) => Some(handle),
        ClassicEntry::Replay(view) => return Ok(ClassicStart::Replay(view)),
    };
    Ok(ClassicStart::Proceed(ClassicOperation {
        business_id,
        identity,
        resume,
    }))
}

/// Binds the envelope a classic mainnet run signs under `operation`.
///
/// A waiting record signs its stored envelope. Otherwise `candidate`, the
/// envelope the run just built, opens the record that binds it. A record
/// another run opened between the lookup and this open answers as the lookup
/// would have.
///
/// # Errors
///
/// `operation.business_id_conflict`, `operation.capacity`, the decode
/// refusal of a malformed envelope, and the store's refusals.
pub(crate) fn bind_envelope(
    context: &MainnetWriteContext,
    operation: ClassicOperation,
    tool: OperationTool,
    kind: OperationKind,
    candidate: &str,
) -> Result<BoundEnvelope, WalletError> {
    if let Some(handle) = operation.resume {
        return Ok(BoundEnvelope::Sign(handle));
    }
    let max_time = operation_entry::envelope_max_time(candidate)?;
    let request = OpenRequest {
        business_id: operation.business_id,
        tool,
        kind,
        intent: operation_entry::envelope_slot(&operation.identity, candidate, max_time),
        envelope_xdr: Some(candidate.to_owned()),
        prepared_decision: None,
        rule_ttl_ms: None,
    };
    Ok(
        match operation_step(context, |recorder| {
            operation_entry::open_classic(recorder, &request)
        })? {
            OpenedEntry::Resume(handle) => BoundEnvelope::Sign(handle),
            OpenedEntry::Replay(view) => BoundEnvelope::Replay(view),
        },
    )
}

/// The exit code of a run that answers with `view`: `0` for a succeeded
/// operation, the verb's unknown-outcome code while the outcome is open,
/// and `1` otherwise.
#[must_use]
pub(crate) fn replay_exit_code(view: &OperationView) -> i32 {
    match view.state {
        OperationState::Succeeded => 0,
        OperationState::Sending | OperationState::SentOutcomeUnknown => UNKNOWN_OUTCOME_EXIT,
        _ => 1,
    }
}

/// The one-line form of a replayed operation.
#[must_use]
pub(crate) fn replay_line(view: &OperationView) -> String {
    let mut line = format!(
        "Operation replayed: business_id {}  state {}",
        view.business_id.as_str(),
        view.state.wire_name()
    );
    if let Some(result) = view.result.as_ref() {
        if let Some(hash) = result.tx_hash {
            line.push_str("  tx_hash ");
            line.push_str(&stellar_agent_network::submit::redact_tx_hash(
                &stellar_agent_core::hex::encode(&hash),
            ));
        }
        if let Some(ledger) = result.ledger {
            line.push_str(&format!("  ledger {ledger}"));
        }
        if let Some(code) = result.error_code.as_deref() {
            line.push_str("  error_code ");
            line.push_str(&crate::common::render::sanitize_for_table(code));
        }
    }
    line.push_str("  next ");
    line.push_str(operation_entry::replay_next(view));
    line
}

/// Prints the stored state of a replayed operation to stdout per `format`
/// and returns the run's exit code.
#[must_use]
pub(crate) fn print_replay(view: &OperationView, format: OutputFormat) -> i32 {
    let code = replay_exit_code(view);
    match format {
        OutputFormat::Table => {
            let line = replay_line(view);
            #[cfg(all(test, feature = "mainnet-write"))]
            PRINTED.with(|printed| printed.borrow_mut().push(line.clone()));
            exit_code_after_output(writeln!(std::io::stdout().lock(), "{line}"), code)
        }
        _ => {
            render_json(&Envelope::ok(operation_entry::replay_json(view)));
            code
        }
    }
}

#[cfg(all(test, feature = "mainnet-write"))]
thread_local! {
    /// Every line [`print_replay`] printed on this thread, oldest first.
    static PRINTED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drains and returns the lines [`print_replay`] printed on the calling
/// thread, oldest first, so a test reads them without capturing stdout.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn take_printed_replays_for_test() -> Vec<String> {
    PRINTED.with(|printed| printed.borrow_mut().drain(..).collect())
}

/// Writes the stored state of a replayed operation to `out` per `format`
/// and returns the run's exit code.
#[must_use]
pub(crate) fn write_replay(out: &mut dyn Write, format: OutputFormat, view: &OperationView) -> i32 {
    let code = replay_exit_code(view);
    match format {
        OutputFormat::Table => exit_code_after_output(
            writeln!(out, "{}", replay_line(view)).and_then(|()| out.flush()),
            code,
        ),
        _ => write_envelope(out, &Envelope::ok(operation_entry::replay_json(view)), code),
    }
}

/// A business id no other run of the test process names.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn fresh_business_id() -> String {
    format!("test-{}", uuid::Uuid::new_v4())
}
