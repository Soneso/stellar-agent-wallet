//! The business-id entry of the value tools.
//!
//! A mainnet value call names itself with a business id. The preparation
//! looks the id up before it builds anything. A retained operation answers
//! with its stored state, and a waiting record answers with its stored
//! envelope. An unknown id builds and opens a record. The commit looks the
//! id up before its gates and continues the record its preparation opened.
//! Off mainnet a supplied id is validated and echoed, and no record exists.

use rmcp::model::{CallToolResult, Content};
use serde_json::Value;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_network::fees::ClassicFeeChoice;
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::operation_entry::{
    self, ClassicEntry, CommitEntry, EnvelopeFacts, IdentityFacts, IntentBaseFacts, OpenedEntry,
};
use stellar_agent_network::policy_state::{
    BusinessId, OpenRequest, OperationHandle, OperationKind, OperationRecorder, OperationTool,
};

use crate::server::WalletServer;

/// A classic preparation under a business id.
#[derive(Debug)]
pub(crate) struct ClassicOperation {
    business_id: BusinessId,
    identity: [u8; 32],
    resume: Option<OperationHandle>,
}

/// The envelope a classic preparation returns under its business id.
#[derive(Debug)]
pub(crate) struct PreparedEnvelope {
    /// The unsigned envelope in base64.
    pub xdr: String,
    /// The facts read from a stored envelope; `None` for the envelope the
    /// call just built, whose facts the call computed itself.
    pub stored: Option<EnvelopeFacts>,
}

impl ClassicOperation {
    /// The envelope a waiting record holds, which the preparation returns
    /// in place of a new build.
    pub(crate) fn stored_envelope(&self) -> Option<&str> {
        self.resume.as_ref().and_then(OperationHandle::envelope_xdr)
    }
}

/// The successful answer to a call under a retained business id.
pub(crate) fn replay_result(
    view: &stellar_agent_network::policy_state::OperationView,
) -> CallToolResult {
    let envelope = stellar_agent_core::envelope::Envelope::ok(operation_entry::replay_json(view));
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    CallToolResult::success(vec![Content::text(json)])
}

/// Adds `business_id` to a result's data when the call names one, on every
/// network; without an id the data stays as it is.
pub(crate) fn echo_business_id(view: &mut Value, business_id: Option<&BusinessId>) {
    if let Some(business_id) = business_id {
        view["business_id"] = Value::String(business_id.as_str().to_owned());
    }
}

/// The refusal result of a wallet error.
fn refusal(error: &WalletError) -> CallToolResult {
    crate::tools::common::ledger_err_result(error)
}

impl WalletServer {
    /// The business id a value tool enters with.
    ///
    /// The check runs only for a call on the profile's own chain, so a call
    /// naming another chain keeps the gate's chain refusal. A mainnet call
    /// requires an id; every other chain validates a supplied one.
    ///
    /// # Errors
    ///
    /// `validation.business_id_required` and
    /// `validation.business_id_invalid`, as a tool result.
    pub(crate) fn entry_business_id(
        &self,
        chain_id: &str,
        raw: Option<&str>,
    ) -> Result<Option<BusinessId>, CallToolResult> {
        if chain_id != self.context.chain_id.caip2_str() {
            return Ok(None);
        }
        operation_entry::entry_business_id(self.security_profile(), raw)
            .map_err(|error| refusal(&error))
    }

    /// The business id a value tool echoes off mainnet, validated as
    /// [`Self::entry_business_id`] validates it. A mainnet call gives `None`
    /// here: its record lookup checks the id, after every refusal a call
    /// without one gives.
    ///
    /// # Errors
    ///
    /// `validation.business_id_invalid` for a malformed id off mainnet, as a
    /// tool result.
    pub(crate) fn echoed_business_id(
        &self,
        chain_id: &str,
        raw: Option<&str>,
    ) -> Result<Option<BusinessId>, CallToolResult> {
        if self.context.chain_id.is_mainnet() {
            return Ok(None);
        }
        self.entry_business_id(chain_id, raw)
    }

    /// Runs `step` with an operation recorder over the server's window and
    /// its keyed audit writer, the writer lock taken first.
    pub(crate) fn operation_step<T>(
        &self,
        step: impl FnOnce(&mut OperationRecorder<'_>) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let profile = self.security_profile();
        let writer = crate::tools::value_audit::require_value_audit_writer(
            profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        )?;
        let mut guard = writer.lock().map_err(|_| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: "the audit writer mutex is poisoned, so the operation cannot be recorded"
                    .to_owned(),
            })
        })?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut recorder =
            OperationRecorder::new(&self.window_store, profile, &mut *guard, request_id);
        step(&mut recorder)
    }

    /// Runs `step` as [`Self::operation_step`] does, a refusal rendered as
    /// the call's result.
    fn with_operation_recorder<T>(
        &self,
        step: impl FnOnce(&mut OperationRecorder<'_>) -> Result<T, WalletError>,
    ) -> Result<T, CallToolResult> {
        self.operation_step(step).map_err(|error| refusal(&error))
    }

    /// Looks up `business_id` before a classic preparation does any work.
    ///
    /// The identity is the [`operation_entry::operation_identity`] of
    /// `facts` under the verified mainnet policy.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result:
    ///
    /// - the replay of a retained operation;
    /// - `operation.business_id_conflict` for an id bound to another intent;
    /// - the admission refusal of a server without mainnet authority;
    /// - the store's refusals.
    pub(crate) fn classic_prepare_entry(
        &self,
        business_id: BusinessId,
        consumer: MainnetConsumer,
        source: &str,
        fee_choice: ClassicFeeChoice,
        memo: &stellar_xdr::Memo,
        facts: IdentityFacts,
    ) -> Result<ClassicOperation, CallToolResult> {
        let guard = self.mainnet_write_admission(consumer)?;
        let identity = operation_entry::operation_identity(
            IntentBaseFacts::new(
                self.security_profile(),
                source,
                guard.policy,
                fee_choice,
                operation_entry::memo_fact(memo),
            ),
            facts,
        )
        .map_err(|error| refusal(&error))?;
        let entry = self.with_operation_recorder(|recorder| {
            operation_entry::lookup_classic(recorder, &business_id, &identity)
        })?;
        let resume = match entry {
            ClassicEntry::Build => None,
            ClassicEntry::Resume(handle) => Some(handle),
            ClassicEntry::Replay(view) => return Err(replay_result(&view)),
        };
        Ok(ClassicOperation {
            business_id,
            identity,
            resume,
        })
    }

    /// The envelope a classic preparation under `operation` returns.
    ///
    /// `candidate` is the stored envelope of a waiting record or the envelope
    /// the call just built. A stored envelope returns with the facts read from
    /// it, and a built one returns once the record that binds it is open. A
    /// record another call opened between the lookup and this open answers as
    /// the lookup would have. Without an operation `candidate` returns as it
    /// is.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result: the replay of a retained
    /// operation, `operation.business_id_conflict`, `operation.capacity`,
    /// and the store's refusals.
    pub(crate) fn prepared_envelope(
        &self,
        operation: Option<&ClassicOperation>,
        tool: OperationTool,
        kind: OperationKind,
        candidate: String,
    ) -> Result<PreparedEnvelope, CallToolResult> {
        let Some(operation) = operation else {
            return Ok(PreparedEnvelope {
                xdr: candidate,
                stored: None,
            });
        };
        let stored = |xdr: &str| {
            operation_entry::envelope_facts(xdr)
                .map(|facts| PreparedEnvelope {
                    xdr: xdr.to_owned(),
                    stored: Some(facts),
                })
                .map_err(|error| refusal(&error))
        };
        if operation.stored_envelope() == Some(candidate.as_str()) {
            return stored(&candidate);
        }
        let max_time =
            operation_entry::envelope_max_time(&candidate).map_err(|error| refusal(&error))?;
        let request = OpenRequest {
            business_id: operation.business_id.clone(),
            tool,
            kind,
            intent: operation_entry::envelope_slot(&operation.identity, &candidate, max_time),
            envelope_xdr: Some(candidate.clone()),
            prepared_decision: None,
            rule_ttl_ms: None,
        };
        let entry = self.with_operation_recorder(|recorder| {
            operation_entry::open_classic(recorder, &request)
        })?;
        match entry {
            OpenedEntry::Resume(handle) => match handle.envelope_xdr() {
                Some(opened) if opened != candidate => stored(opened),
                _ => Ok(PreparedEnvelope {
                    xdr: candidate,
                    stored: None,
                }),
            },
            OpenedEntry::Replay(view) => Err(replay_result(&view)),
        }
    }

    /// Looks up `business_id` before a classic commit of `envelope_xdr`
    /// verifies its approval, rebuilds its envelope or consumes its nonce.
    ///
    /// The read writes nothing. A retained operation answers with its stored
    /// state, so a commit retried after a lost reply does no new work. A
    /// tombstone answers so only for the identity the envelope carries as an
    /// operation of `kind` under `policy`, the commit's verified mainnet policy.
    /// A record that continues,
    /// or a window the read cannot read, gives `Ok(())`, and the commit runs
    /// its gates. Off mainnet there is no record and the call proceeds.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is the replay of a
    /// retained operation or `operation.business_id_mismatch` for an id other
    /// than the preparation's. It is `operation.business_id_conflict` for an id
    /// bound to another intent.
    pub(crate) fn classic_commit_lookup(
        &self,
        policy: Option<&VerifiedPolicy>,
        kind: OperationKind,
        business_id: Option<&BusinessId>,
        envelope_xdr: &str,
    ) -> Result<(), CallToolResult> {
        let (Some(business_id), Some(policy)) = (
            business_id.filter(|_| self.context.chain_id.is_mainnet()),
            policy,
        ) else {
            return Ok(());
        };
        match operation_entry::commit_replay(
            &self.window_store,
            self.security_profile(),
            business_id,
            envelope_xdr,
            &operation_entry::commit_identities(
                self.security_profile(),
                policy,
                kind,
                envelope_xdr,
            ),
        ) {
            Ok(None) => Ok(()),
            Ok(Some(view)) => Err(replay_result(&view)),
            Err(error) => Err(refusal(&error)),
        }
    }

    /// The record a classic commit of `envelope_xdr` under `business_id`
    /// continues; `None` for a call without an operation record. `policy` is
    /// the commit's verified mainnet policy, under which the envelope's
    /// identity as an operation of `kind` must match a tombstone under the id.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is the replay of a
    /// retained operation or `operation.business_id_mismatch` for an id other
    /// than the preparation's. It is also `operation.business_id_conflict`
    /// for an id bound to another intent, or a refusal of the store.
    pub(crate) fn classic_commit_entry(
        &self,
        policy: Option<&VerifiedPolicy>,
        kind: OperationKind,
        business_id: Option<&BusinessId>,
        envelope_xdr: &str,
    ) -> Result<Option<OperationHandle>, CallToolResult> {
        let (Some(business_id), Some(policy)) = (
            business_id.filter(|_| self.context.chain_id.is_mainnet()),
            policy,
        ) else {
            return Ok(None);
        };
        let identities =
            operation_entry::commit_identities(self.security_profile(), policy, kind, envelope_xdr);
        let entry = self.with_operation_recorder(|recorder| {
            operation_entry::commit_classic(
                &self.window_store,
                recorder,
                self.security_profile(),
                business_id,
                envelope_xdr,
                &identities,
            )
        })?;
        match entry {
            CommitEntry::Proceed(handle) => Ok(Some(handle)),
            CommitEntry::Replay(view) => Err(replay_result(&view)),
        }
    }

    /// Opens the x402 record of a payment under its business id, with the
    /// intent digest the x402 crate computes; `None` off mainnet, where no
    /// record exists.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is a business-id
    /// refusal, the replay of a retained operation, or
    /// `operation.business_id_conflict` for an id bound to another intent.
    /// It is also `operation.capacity` or a refusal of the store.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn x402_entry(
        &self,
        chain_id: &str,
        raw: Option<&str>,
        tool: OperationTool,
        kind: OperationKind,
        intent_digest: [u8; 32],
        intent: stellar_agent_network::policy_state::X402Intent,
    ) -> Result<Option<OperationHandle>, CallToolResult> {
        let business_id = self.entry_business_id(chain_id, raw)?;
        let Some(id) = business_id.filter(|_| self.context.chain_id.is_mainnet()) else {
            return Ok(None);
        };
        let request = OpenRequest {
            business_id: id,
            tool,
            kind,
            intent: stellar_agent_network::policy_state::IntentSlot::X402 {
                intent_digest,
                intent,
            },
            envelope_xdr: None,
            prepared_decision: None,
            rule_ttl_ms: None,
        };
        let outcome = self.with_operation_recorder(|recorder| {
            recorder
                .open(&request)
                .map_err(operation_entry::operation_refusal)
        })?;
        use stellar_agent_network::policy_state::OpenOutcome;
        match outcome {
            OpenOutcome::New(handle) | OpenOutcome::Resumable(handle) => Ok(Some(handle)),
            OpenOutcome::Replay(view) => Err(replay_result(&view)),
            OpenOutcome::Conflict => Err(refusal(&operation_entry::operation_refusal(
                stellar_agent_network::policy_state::WindowStoreError::BusinessIdConflict,
            ))),
        }
    }
}

/// The operation steps of one authorized x402 payment.
///
/// The attempt is committed as `Sending` after the mint and before the
/// signature, and its exposure after the intent consumption and before the
/// signed re-simulation. A returned payload ends it as `PayloadReleased`; a
/// failure ends it as `SentOutcomeUnknown` after the exposure and as
/// `NotSent` before it.
#[cfg(feature = "mainnet-write")]
pub(crate) struct X402Steps<'s> {
    server: &'s WalletServer,
    handle: Option<OperationHandle>,
    attempt: std::sync::Mutex<Option<stellar_agent_network::OperationAttempt>>,
    exposed: std::sync::atomic::AtomicBool,
    refusal: std::sync::Mutex<Option<WalletError>>,
}

#[cfg(feature = "mainnet-write")]
impl std::fmt::Debug for X402Steps<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Steps")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "mainnet-write")]
impl<'s> X402Steps<'s> {
    /// The steps of a payment under `handle`; without a record every step
    /// does nothing.
    pub(crate) fn new(server: &'s WalletServer, handle: Option<OperationHandle>) -> Self {
        Self {
            server,
            handle,
            attempt: std::sync::Mutex::new(None),
            exposed: std::sync::atomic::AtomicBool::new(false),
            refusal: std::sync::Mutex::new(None),
        }
    }

    /// The link the intent authorization's mint carries.
    pub(crate) fn link(&self) -> Option<stellar_agent_network::policy_state::OperationLink> {
        self.handle.as_ref().map(operation_entry::next_attempt_link)
    }

    fn attempt(&self) -> Option<stellar_agent_network::OperationAttempt> {
        *self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Keeps `error` for [`Self::refusal_result`] and returns the gate
    /// refusal the x402 crate passes through.
    fn refuse(&self, error: WalletError) -> stellar_agent_x402::X402Error {
        let detail = format!("operation record refused: {}", error.code());
        *self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
        stellar_agent_x402::X402Error::TransmitGateRefused { detail }
    }

    /// The operation hooks of the payment.
    pub(crate) fn hooks(&self) -> stellar_agent_x402::exact::OperationHooks<'_> {
        stellar_agent_x402::exact::OperationHooks {
            before_sign: Box::new(move |_authorization| self.before_sign()),
            expose: Box::new(move |transmit| self.expose(transmit)),
        }
    }

    fn before_sign(
        &self,
    ) -> Result<Option<stellar_agent_network::OperationAttempt>, stellar_agent_x402::X402Error>
    {
        use stellar_agent_network::policy_state::{AttemptAuthorization, AttemptRequest};
        let Some(handle) = &self.handle else {
            return Ok(None);
        };
        let started = self
            .server
            .operation_step(|recorder| {
                recorder
                    .begin_attempt(
                        handle,
                        &AttemptRequest {
                            envelope: None,
                            authorization: AttemptAuthorization::Linked,
                            send_by_ms: u64::MAX,
                        },
                    )
                    .map_err(operation_entry::operation_refusal)
            })
            .map_err(|error| self.refuse(error))?;
        let attempt = stellar_agent_network::OperationAttempt {
            operation_id: handle.id(),
            attempt_index: started.attempt_index,
        };
        *self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(attempt);
        Ok(Some(attempt))
    }

    fn expose(
        &self,
        transmit: &stellar_agent_x402::exact::AuthorizationToTransmit<'_>,
    ) -> Result<(), stellar_agent_x402::X402Error> {
        use stellar_agent_network::policy_state::ExposureIdentity;
        let (Some(attempt), Some(authorization_id)) =
            (transmit.operation, transmit.authorization_id)
        else {
            return Ok(());
        };
        let identity = ExposureIdentity::X402 {
            authorization_id,
            auth_entry_sha256: transmit.signed_entries_sha256,
            signature_expiration_ledger: transmit.signature_expiration_ledger,
        };
        self.server
            .operation_step(|recorder| {
                recorder
                    .expose(attempt.operation_id, attempt.attempt_index, &identity, None)
                    .map_err(operation_entry::operation_refusal)
            })
            .map_err(|error| self.refuse(error))?;
        self.exposed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// The refusal a step kept, as the call's result.
    pub(crate) fn refusal_result(&self) -> Option<CallToolResult> {
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(|error| refusal(&error))
    }

    /// Ends the attempt as `PayloadReleased` once the payload is returned.
    pub(crate) fn released(&self) {
        self.end(
            stellar_agent_network::policy_state::OperationState::PayloadReleased,
            None,
        );
    }

    /// Ends the attempt as `SentOutcomeUnknown` when the built payload is
    /// withheld: a built payload follows the committed exposure, and the
    /// signed entries already reached the endpoint in the re-simulation.
    pub(crate) fn withheld(&self) {
        self.end(
            stellar_agent_network::policy_state::OperationState::SentOutcomeUnknown,
            None,
        );
    }

    /// Ends the attempt after a failure with wire code `code`:
    /// `SentOutcomeUnknown` once the signed entries were exposed, `NotSent`
    /// before.
    pub(crate) fn failed(&self, code: &str) {
        use stellar_agent_network::policy_state::OperationState;
        if self.exposed.load(std::sync::atomic::Ordering::SeqCst) {
            self.end(OperationState::SentOutcomeUnknown, None);
        } else {
            self.end(OperationState::NotSent, Some(code));
        }
    }

    fn end(&self, to: stellar_agent_network::policy_state::OperationState, code: Option<&str>) {
        use stellar_agent_network::policy_state::{OperationResult, TransitionEvidence};
        let Some(attempt) = self.attempt() else {
            return;
        };
        let evidence = TransitionEvidence {
            result: code.map(|code| OperationResult {
                error_code: Some(code.to_owned()),
                ..OperationResult::default()
            }),
            send_never_started: code.is_some(),
            ..TransitionEvidence::default()
        };
        let ended = self.server.operation_step(|recorder| {
            recorder
                .transition(
                    attempt.operation_id,
                    Some(attempt.attempt_index),
                    to,
                    &evidence,
                )
                .map_err(operation_entry::operation_refusal)
        });
        if let Err(error) = ended {
            tracing::warn!(
                state = to.wire_name(),
                code = error.code(),
                "operation record: the x402 attempt's end was not recorded; it stays sending \
                 until recovery reads it"
            );
        }
    }
}
