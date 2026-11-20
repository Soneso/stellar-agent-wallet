//! The business-id entry of the classic value verbs.
//!
//! A mainnet value run names itself with `--business-id`. Before the
//! confirmation ceremony the run looks the id up and opens the record that
//! binds its canonical intent. A retained operation answers with its stored
//! state. A waiting record continues: a canonical record is rebuilt after the
//! confirmation, and an envelope record signs its stored envelope. An unknown
//! id opens a canonical record for the intent, the decision and the envelope
//! the run built. Off mainnet a supplied id is validated and echoed, and no
//! record exists.

use std::io::Write;

use stellar_agent_core::approval::{IntentPayload, MemoFact};
use stellar_agent_core::cross_check::ThresholdSet;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{FeeSource, InternalError, WalletError};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::profile::Profile;
use stellar_agent_core::profile::receipt::PaymentDestinations;
use stellar_agent_network::MainnetWriteContext;
use stellar_agent_network::cross_check::ClassicInputs;
use stellar_agent_network::fees::ClassicFeeChoice;
use stellar_agent_network::operation_entry::{
    self, ClassicEntry, IdentityFacts, IntentBaseFacts, OpenedEntry, Preparation,
};
use stellar_agent_network::policy_state::{
    ApprovalRecorder, BusinessId, OperationAudit, OperationHandle, OperationKind,
    OperationRecorder, OperationState, OperationTool, OperationView, PersistedWindowStore,
    SlotKind,
};

use crate::commands::policy_engine::MainnetVerdict;
use crate::commands::submission_record::accounting_audit_writer;
use crate::common::mainnet_write::RebuildInputs;
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
    base: StagedBase,
    resume: Option<OperationHandle>,
}

impl ClassicOperation {
    /// The envelope the policy evaluates: a waiting record's stored
    /// envelope, otherwise `built`, the envelope the run just built.
    pub(crate) fn candidate(&self, built: &str) -> String {
        self.resume
            .as_ref()
            .and_then(OperationHandle::envelope_xdr)
            .unwrap_or(built)
            .to_owned()
    }
}

/// What a classic mainnet run binds under its record.
pub(crate) struct Staging<'a> {
    /// The verified mainnet policy the intent names.
    pub(crate) policy: &'a VerifiedPolicy,
    /// The operation's tool.
    pub(crate) tool: OperationTool,
    /// The operation's kind.
    pub(crate) kind: OperationKind,
    /// The envelope the run just built from its fresh reads.
    pub(crate) built: &'a str,
    /// The intent payload of the request.
    pub(crate) payload: IntentPayload,
    /// The policy's verdict on the candidate envelope.
    pub(crate) verdict: MainnetVerdict,
}

/// The envelopes a classic mainnet run continues with under its record.
#[derive(Debug)]
pub(crate) struct Signing {
    handle: OperationHandle,
    built: String,
    fee_per_op_stroops: u32,
}

impl Signing {
    /// The operation record the run signs under.
    pub(crate) fn handle(&self) -> &OperationHandle {
        &self.handle
    }

    /// The record's stored envelope: the confirmation's challenge, and the
    /// envelope an envelope record signs.
    pub(crate) fn stored(&self) -> &str {
        self.handle.envelope_xdr().unwrap_or_default()
    }

    /// The fee per operation of the stored envelope.
    pub(crate) fn fee_per_op_stroops(&self) -> u32 {
        self.fee_per_op_stroops
    }

    /// The envelope the verb's oracle check before the confirmation binds.
    /// A canonical record binds the envelope the run just built, whose
    /// sequence is that of the account read it was built from; a resumed
    /// record's stored envelope may name a sequence the account has passed.
    /// An envelope record binds its stored envelope, the one it signs.
    pub(crate) fn checked(&self) -> &str {
        if self.is_canonical() {
            &self.built
        } else {
            self.stored()
        }
    }

    fn is_canonical(&self) -> bool {
        self.handle.intent().kind() == SlotKind::Canonical
    }

    /// The inputs that rebuild a canonical record's envelope after the
    /// confirmation; `None` for an envelope record, which signs its stored
    /// envelope. `default_fee_source` names where
    /// `default_fee_per_op_stroops` comes from.
    pub(crate) fn rebuild<'a>(
        &self,
        fee_choice: ClassicFeeChoice,
        (default_fee_per_op_stroops, default_fee_source): (u32, FeeSource),
        witness_inputs: impl Into<ClassicInputs>,
        thresholds: &'a ThresholdSet<'a>,
    ) -> Option<RebuildInputs<'a>> {
        self.is_canonical().then(|| RebuildInputs {
            fee_choice,
            default_fee_per_op_stroops,
            default_fee_source,
            witness_inputs: witness_inputs.into(),
            thresholds,
        })
    }
}

/// How a bound classic mainnet run proceeds.
#[derive(Debug)]
pub(crate) enum Bound {
    /// Sign under the record.
    Sign(Signing),
    /// The operation needs no further work; the run prints its stored state.
    Replay(OperationView),
}

/// Binds `operation` with [`bind_envelope`] and reads the envelope the
/// record holds.
///
/// # Errors
///
/// The refusals of [`bind_envelope`], and `internal.unexpected_state` for a
/// record without an envelope or with a malformed one.
pub(crate) fn bind_signing(
    context: &MainnetWriteContext,
    operation: ClassicOperation,
    staging: Staging<'_>,
) -> Result<Bound, WalletError> {
    let handle = match bind_envelope(
        context,
        staging.policy,
        operation,
        staging.tool,
        staging.kind,
        staging.built,
        staging.payload,
        staging.verdict,
    )? {
        BoundEnvelope::Sign(handle) => handle,
        BoundEnvelope::Replay(view) => return Ok(Bound::Replay(view)),
    };
    let fee_per_op_stroops = signing_envelope(&handle)?.1;
    Ok(Bound::Sign(Signing {
        handle,
        built: staging.built.to_owned(),
        fee_per_op_stroops,
    }))
}

/// The request facts of a classic run's intent besides its payload.
#[derive(Debug, Clone)]
struct StagedBase {
    source: String,
    fee_choice: ClassicFeeChoice,
    memo: MemoFact,
}

impl StagedBase {
    fn facts<'a>(&'a self, profile: &Profile, policy: &VerifiedPolicy) -> IntentBaseFacts<'a> {
        IntentBaseFacts::new(
            profile,
            &self.source,
            policy,
            self.fee_choice,
            self.memo.clone(),
        )
    }
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
fn signing_envelope(handle: &OperationHandle) -> Result<(&str, u32), WalletError> {
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
    with_accounting_audit(context, |store, audit, request_id| {
        step(&mut OperationRecorder::new(
            store,
            context.profile(),
            audit,
            request_id,
        ))
    })
}

/// Runs `step` with an approval recorder over the profile's window store
/// and its accounting audit writer, the writer lock taken first.
///
/// The caller holds no inbox store across the step, so the window commit
/// never waits on the inbox while it holds the window lock.
pub(crate) fn approval_step<T>(
    context: &MainnetWriteContext,
    step: impl FnOnce(&mut ApprovalRecorder<'_>) -> Result<T, WalletError>,
) -> Result<T, WalletError> {
    with_accounting_audit(context, |store, audit, request_id| {
        step(&mut ApprovalRecorder::new(
            store,
            context.profile(),
            audit,
            request_id,
        ))
    })
}

fn with_accounting_audit<T>(
    context: &MainnetWriteContext,
    step: impl FnOnce(&PersistedWindowStore, &mut dyn OperationAudit, String) -> Result<T, WalletError>,
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
    step(&store, &mut *guard, uuid::Uuid::new_v4().to_string())
}

/// Looks `business_id` up before a classic mainnet run does any network
/// work.
///
/// The lookup is [`operation_entry::lookup_canonical`] of `facts` under the
/// verified mainnet `policy`, so a claim answers from its balance and
/// claimant alone. A record prepared with its exact envelope continues with
/// that envelope and is never rebuilt.
///
/// # Errors
///
/// `operation.business_id_conflict` for an id bound to another intent,
/// `validation.mainnet_fee_cap_required` when no fee bound exists, and the
/// store's refusals.
pub(crate) fn classic_start(
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    business_id: BusinessId,
    source: &str,
    fee_choice: ClassicFeeChoice,
    memo: &stellar_xdr::Memo,
    facts: IdentityFacts,
) -> Result<ClassicStart, WalletError> {
    let base = StagedBase {
        source: source.to_owned(),
        fee_choice,
        memo: operation_entry::memo_fact(memo),
    };
    let entry = operation_step(context, |recorder| {
        operation_entry::lookup_canonical(
            recorder,
            &business_id,
            base.facts(context.profile(), policy),
            facts,
        )
    })?;
    let resume = match entry {
        ClassicEntry::Build => None,
        ClassicEntry::Resume(handle) => Some(handle),
        ClassicEntry::Replay(view) => return Ok(ClassicStart::Replay(view)),
    };
    Ok(ClassicStart::Proceed(ClassicOperation {
        business_id,
        base,
        resume,
    }))
}

/// Binds the envelope a classic mainnet run signs under `operation`.
///
/// A waiting record continues with its stored envelope. Otherwise
/// `candidate`, the envelope the run just built, opens a canonical record for
/// the intent of `payload` and the request facts under `policy`, with the
/// decision and the rule lifetime of `verdict`. A record another run opened
/// between the lookup and this open answers as the lookup would have.
///
/// # Errors
///
/// `operation.business_id_conflict`, `operation.capacity`, the decode
/// refusal of a malformed envelope, the intent's refusals, and the store's
/// refusals.
#[allow(
    clippy::too_many_arguments,
    reason = "the record binds the intent, the decision and the envelope together"
)]
pub(crate) fn bind_envelope(
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    operation: ClassicOperation,
    tool: OperationTool,
    kind: OperationKind,
    candidate: &str,
    payload: IntentPayload,
    verdict: MainnetVerdict,
) -> Result<BoundEnvelope, WalletError> {
    if let Some(handle) = operation.resume {
        return Ok(BoundEnvelope::Sign(handle));
    }
    let intent =
        operation_entry::classic_intent(operation.base.facts(context.profile(), policy), payload)?;
    let preparation = Preparation::Canonical {
        intent: Box::new(intent),
        decision: verdict.audit_decision(),
        rule_ttl_ms: match verdict {
            MainnetVerdict::RequireApproval { ttl_ms } => Some(ttl_ms),
            MainnetVerdict::Allow => None,
        },
    };
    Ok(
        match operation_step(context, |recorder| {
            preparation.open(recorder, operation.business_id, tool, kind, candidate)
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
    match &view.destinations {
        PaymentDestinations::None => {}
        PaymentDestinations::Single(destination) => {
            line.push_str("  destination ");
            line.push_str(&crate::common::render::sanitize_for_table(destination));
        }
        PaymentDestinations::PerOperation(entries) => {
            for entry in entries {
                line.push_str(&format!("  destination[{}] ", entry.operation));
                line.push_str(&crate::common::render::sanitize_for_table(
                    &entry.destination,
                ));
            }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use super::*;
    use stellar_agent_core::profile::receipt::OperationDestination;
    use stellar_agent_network::policy_state::{OperationId, OperationResult, SlotKind};

    const G: &str = "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI";
    const M_MAX: &str = "MADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP77777777777754MA";

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn canonical_staging_keeps_the_winning_handle() {
        use stellar_agent_core::approval::IntentAsset;
        let (fixture, context, envelope) =
            crate::common::mainnet_confirm::tests::confirmation_fixture("canonical-staging");
        let args = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &envelope,
            "stellar_pay_commit",
        )
        .unwrap();
        let source = args["source"].as_str().unwrap().to_owned();
        let policy = fixture.current_policy();
        let payload = IntentPayload::Pay {
            destination: args["destination"].as_str().unwrap().into(),
            asset: IntentAsset::Native,
            amount_stroops: 17,
        };
        let intent = operation_entry::classic_intent(
            IntentBaseFacts::new(
                context.profile(),
                &source,
                &policy,
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            payload.clone(),
        )
        .unwrap();
        let start = |id: &BusinessId, facts: IdentityFacts| {
            classic_start(
                &context,
                &policy,
                id.clone(),
                &source,
                ClassicFeeChoice::Explicit(500),
                &stellar_xdr::Memo::None,
                facts,
            )
            .unwrap()
        };
        let bind = |operation, tool, kind, candidate: &str, payload| {
            bind_envelope(
                &context,
                &policy,
                operation,
                tool,
                kind,
                candidate,
                payload,
                MainnetVerdict::Allow,
            )
            .unwrap()
        };
        let id = BusinessId::parse("winning-handle").unwrap();
        let ClassicStart::Proceed(first) = start(&id, IdentityFacts::Intent(payload.clone()))
        else {
            unreachable!()
        };
        let ClassicStart::Proceed(stale) = start(&id, IdentityFacts::Intent(payload.clone()))
        else {
            unreachable!()
        };
        let BoundEnvelope::Sign(winner) = bind(
            first,
            OperationTool::CliPay,
            OperationKind::Pay,
            &envelope,
            payload.clone(),
        ) else {
            unreachable!()
        };
        assert_eq!(
            winner.intent().kind(),
            SlotKind::Canonical,
            "CLI stages Canonical explicitly"
        );
        let other = operation_entry::intent_envelope(
            &intent,
            context.network_passphrase(),
            7,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
        )
        .unwrap();
        let BoundEnvelope::Sign(raced) = bind(
            stale,
            OperationTool::CliPay,
            OperationKind::Pay,
            &other,
            payload.clone(),
        ) else {
            unreachable!()
        };
        assert_eq!(
            raced.id(),
            winner.id(),
            "CLI concurrent open returns winning handle"
        );
        assert_eq!(
            raced.envelope_xdr(),
            Some(envelope.as_str()),
            "CLI concurrent open retains original envelope"
        );
        let ClassicStart::Proceed(resumed) = start(&id, IdentityFacts::Intent(payload.clone()))
        else {
            unreachable!()
        };
        let BoundEnvelope::Sign(resumed) = bind(
            resumed,
            OperationTool::CliPay,
            OperationKind::Pay,
            &other,
            payload.clone(),
        ) else {
            unreachable!()
        };
        assert_eq!(
            resumed.id(),
            winner.id(),
            "CLI resume returns winning handle"
        );
        assert_eq!(
            resumed.intent(),
            winner.intent(),
            "CLI resume retains full intent"
        );
        let legacy_id = BusinessId::parse("legacy-binding").unwrap();
        operation_step(&context, |recorder| {
            Preparation::Envelope(*intent.digest().as_bytes()).open(
                recorder,
                legacy_id.clone(),
                OperationTool::CliPay,
                OperationKind::Pay,
                &envelope,
            )
        })
        .unwrap();
        let ClassicStart::Proceed(legacy) = start(&legacy_id, IdentityFacts::Intent(payload))
        else {
            unreachable!()
        };
        assert_eq!(legacy.candidate(&other), envelope);
        let BoundEnvelope::Sign(legacy) = bind(
            legacy,
            OperationTool::CliPay,
            OperationKind::Pay,
            &other,
            IntentPayload::Pay {
                destination: args["destination"].as_str().unwrap().into(),
                asset: IntentAsset::Native,
                amount_stroops: 17,
            },
        ) else {
            unreachable!()
        };
        assert_eq!(
            legacy.intent().kind(),
            SlotKind::Envelope,
            "CLI legacy preparation stays Envelope"
        );
        let claim_payload = IntentPayload::Claim {
            balance_id: format!("00000000{}", "09".repeat(32)),
            claimant: source.clone(),
            asset: IntentAsset::Native,
            amount_stroops: 17,
        };
        let claim = operation_entry::classic_intent(
            IntentBaseFacts::new(
                context.profile(),
                &source,
                &policy,
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            claim_payload.clone(),
        )
        .unwrap();
        let claim_facts = || IdentityFacts::Claim {
            balance_id: format!("00000000{}", "09".repeat(32)),
            claimant: source.clone(),
        };
        let id = BusinessId::parse("retained-claim").unwrap();
        let ClassicStart::Proceed(operation) = start(&id, claim_facts()) else {
            unreachable!()
        };
        let xdr = operation_entry::intent_envelope(
            &claim,
            context.network_passphrase(),
            9,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
        )
        .unwrap();
        bind(
            operation,
            OperationTool::CliClaim,
            OperationKind::Claim,
            &xdr,
            claim_payload,
        );
        let ClassicStart::Proceed(partial) = start(&id, claim_facts()) else {
            unreachable!()
        };
        assert!(
            partial
                .resume
                .is_some_and(|h| h.intent().intent_digest() == *claim.digest().as_bytes()),
            "CLI partial claim retains full digest without an RPC client"
        );
    }

    fn view(destinations: PaymentDestinations, compacted: bool) -> OperationView {
        OperationView {
            operation_id: OperationId::from_bytes([0x5a; 16]),
            business_id: BusinessId::parse("order-7").unwrap(),
            state: OperationState::SentOutcomeUnknown,
            tool: None,
            kind: Some(OperationKind::Pay),
            slot_kind: SlotKind::Envelope,
            intent_digest: [1; 32],
            attempts: 1,
            result: Some(OperationResult::default()),
            created_at_ms: None,
            closed_at_ms: None,
            waiting_expires_at_ms: None,
            execution_expires_at_ms: None,
            compacted,
            history_incomplete: false,
            destinations,
        }
    }

    fn written(format: OutputFormat, view: &OperationView) -> String {
        let mut out = Vec::new();
        let _ = write_replay(&mut out, format, view);
        String::from_utf8(out).unwrap()
    }

    fn json_data(view: &OperationView) -> serde_json::Value {
        let parsed: serde_json::Value =
            serde_json::from_str(&written(OutputFormat::Json, view)).unwrap();
        parsed["data"].clone()
    }

    /// A pay replay carries the complete destination on the JSON and table
    /// outputs, a differing list as `destinations` and one indexed table
    /// entry per operation, and a tombstone carries neither.
    #[test]
    fn a_pay_replay_carries_its_destination() {
        let single = view(PaymentDestinations::Single(M_MAX.to_owned()), false);
        let data = json_data(&single);
        assert_eq!(data["destination"], M_MAX, "{data}");
        assert!(data.get("destinations").is_none(), "{data}");
        assert_eq!(
            written(OutputFormat::Table, &single),
            format!(
                "Operation replayed: business_id order-7  state sent_outcome_unknown  \
                 destination {M_MAX}  next wait\n"
            )
        );

        let listed = view(
            PaymentDestinations::PerOperation(vec![
                OperationDestination {
                    operation: 0,
                    destination: G.to_owned(),
                },
                OperationDestination {
                    operation: 2,
                    destination: M_MAX.to_owned(),
                },
            ]),
            false,
        );
        let data = json_data(&listed);
        assert_eq!(
            data["destinations"],
            serde_json::json!([
                { "operation": 0, "destination": G },
                { "operation": 2, "destination": M_MAX },
            ]),
            "{data}"
        );
        assert!(data.get("destination").is_none(), "{data}");
        assert_eq!(
            written(OutputFormat::Table, &listed),
            format!(
                "Operation replayed: business_id order-7  state sent_outcome_unknown  \
                 destination[0] {G}  destination[2] {M_MAX}  next wait\n"
            )
        );

        let tombstone = view(PaymentDestinations::None, true);
        let data = json_data(&tombstone);
        assert!(data.get("destination").is_none(), "{data}");
        assert!(data.get("destinations").is_none(), "{data}");
        assert_eq!(
            written(OutputFormat::Table, &tombstone),
            "Operation replayed: business_id order-7  state sent_outcome_unknown  next none\n"
        );
    }

    /// A stored destination with control and multibyte text renders through
    /// the table sanitizer.
    #[test]
    fn a_pay_replay_carries_its_destination_escaped() {
        let hostile = view(
            PaymentDestinations::Single("M\u{1b}[31mé\u{7}".to_owned()),
            false,
        );
        let line = written(OutputFormat::Table, &hostile);
        assert!(!line.contains('\u{1b}'), "{line:?}");
        assert!(!line.contains('\u{7}'), "{line:?}");
        assert_eq!(
            line,
            format!(
                "Operation replayed: business_id order-7  state sent_outcome_unknown  \
                 destination {}  next wait\n",
                crate::common::render::sanitize_for_table("M\u{1b}[31mé\u{7}")
            )
        );
    }
}
