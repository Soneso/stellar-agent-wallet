//! The steps every classic CLI verb takes on mainnet from the signer choice
//! to the submit.
//!
//! A verb builds its unsigned envelope, evaluates the verified policy, checks
//! the fee and obtains its witness in its own mainnet pipeline. It then hands
//! the result to [`authorize_and_submit`], which runs the same order for all
//! four verbs:
//!
//! 1. the enrolled signer proof, which reads the identity record and never a
//!    seed;
//! 2. decision authority, with passkey confirmation for approval rules;
//!    its summary names the latest ledger from the operational check;
//! 3. the consent drain, the audit readiness, and the recorder preparation;
//! 4. the authorization mint, then the operation attempt, committed as
//!    `Sending` before any signature;
//! 5. the signer, the authorized attach, and the authorized submit.
//!
//! No step before the mint touches a seed or a device, and no refusal there
//! leaves a record. A refusal after the mint invalidates the open
//! authorization at the stage [`refusal_stage`] selects, and renders the
//! original refusal through [`render_mainnet_refusal`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use stellar_agent_core::approval::witness::ApprovalWitness;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::mainnet::oracle::require_mainnet_oracle;
use stellar_agent_core::profile::Profile;
use stellar_agent_core::profile::name::ResolvedProfileName;
use stellar_agent_network::cross_check::CrossCheckWitness;
use stellar_agent_network::keyring::{EnrolledRole, enrolled_signer};
use stellar_agent_network::mainnet::audit_readiness::audit_readiness;
use stellar_agent_network::mainnet::resolve::{
    InvalidationStage, TxSignRequest, invalidate_unconsumed, resolve_tx_sign,
};
use stellar_agent_network::mainnet::{AuthorizationId, MainnetAuthorizationError, MainnetConsumer};
use stellar_agent_network::operation_entry::{begin_classic_attempt, next_attempt_link};
use stellar_agent_network::operational::OperationalReport;
use stellar_agent_network::policy_state::{OperationHandle, PersistedWindowStore};
use stellar_agent_network::signing::envelope_signing::attach_signature_authorized;
use stellar_agent_network::submit::SubmissionResult;
use stellar_agent_network::{
    MainnetEndpointFlags, MainnetSubmitGrant, MainnetWriteContext, NetworkContext,
    StellarRpcClient, submit_authorized_transaction_and_wait,
};

use crate::commands::approve::approval_store_dir;
use crate::commands::policy_engine::{MainnetEvaluation, MainnetPolicy, MainnetVerdict};
use crate::commands::submission_record::{error_envelope, prepare_mainnet_recorder};
use crate::commands::value_audit::drain_consent_rows_before_signing;
use crate::common::mainnet_confirm::{
    ConfirmDecision, MainnetWriteSummary, cli_mainnet_authority, render_authority_refusal,
};
use crate::common::signer_ceremony::{MainnetSignerChoice, mainnet_signer};

/// The message of `network.mainnet_authorization_refused` when the signature
/// was withheld.
const WITHHELD_TEXT: &str =
    "the mainnet write was refused; the signature was withheld and nothing was sent";

/// The message of `network.mainnet_authorization_refused` when the submission
/// was refused after signing.
const AFTER_SIGNING_TEXT: &str =
    "the mainnet write was refused; the submission was refused after signing and nothing was sent";

/// The sentence a refusal under [`RenderStage::SignatureWithheld`] gains.
const WITHHELD_SENTENCE: &str = "The signature was withheld and nothing was sent.";

/// The wire code whose message [`render_mainnet_refusal`] replaces.
const AUTHORIZATION_REFUSED: &str = "network.mainnet_authorization_refused";

/// The sentence the enrolled-signer refusal gains for the Ledger choice.
const LEDGER_ENROLLMENT_SENTENCE: &str = "A Ledger key cannot be enrolled as the mainnet signer: \
                                          profile enroll-signer takes --secret-env only.";

/// The directory holding the stored profile files.
///
/// # Errors
///
/// `internal.unexpected_state` when the directory cannot be determined.
pub(crate) fn mainnet_profiles_dir() -> Result<PathBuf, WalletError> {
    stellar_agent_core::profile::schema::default_profile_dir().map_err(|err| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("could not determine profile directory: {err}"),
        })
    })
}

/// The structural refusal of a build without mainnet writes.
///
/// A verb checks it before the signer choice, so such a build reports one
/// code, `network.mainnet_write_forbidden`, for every mainnet run whatever
/// signer flags it carries. A build with mainnet writes returns `None`.
#[cfg(not(feature = "mainnet-write"))]
pub(crate) fn mainnet_write_build_refusal() -> Option<WalletError> {
    Some(WalletError::Network(
        stellar_agent_core::error::NetworkError::MainnetWriteForbidden,
    ))
}

/// The structural refusal of a build without mainnet writes.
///
/// A verb checks it before the signer choice, so such a build reports one
/// code, `network.mainnet_write_forbidden`, for every mainnet run whatever
/// signer flags it carries. A build with mainnet writes returns `None`.
#[cfg(feature = "mainnet-write")]
pub(crate) fn mainnet_write_build_refusal() -> Option<WalletError> {
    None
}

/// Builds the mainnet write context of the explicitly selected stored
/// profile.
///
/// `profile` is the merged profile the verb loaded. The context holds the
/// stored profile, read without overlays, and every later step takes its
/// profile from the context. Every mainnet verb builds its context here
/// first, so a stored profile without a usable oracle refuses before any
/// endpoint read, keyring read, or signature.
///
/// # Errors
///
/// `network.mainnet_write_forbidden` in a build without mainnet writes and
/// for every refused selection, the loader's code when the stored profile
/// cannot be read, and `profile.mainnet_oracle_required` when the stored
/// profile names no usable oracle.
pub(crate) fn mainnet_context(
    profile: &Profile,
    resolved: &ResolvedProfileName,
    flags: MainnetEndpointFlags,
) -> Result<MainnetWriteContext, WalletError> {
    let profiles_dir = mainnet_profiles_dir()?;
    let context = NetworkContext::mainnet_write(profile, resolved, &profiles_dir, flags)?;
    require_mainnet_oracle(context.profile())?;
    Ok(apply_test_routes(context))
}

/// Refuses an engine other than V1 on mainnet: only the V1 engine yields
/// the verified policy and the enablement the authorization binds.
///
/// # Errors
///
/// `network.mainnet_write_forbidden` naming the profile's engine kind.
pub(crate) fn require_v1_engine(
    verb: &str,
    context: &MainnetWriteContext,
) -> Result<(), Envelope<()>> {
    let kind = &context.profile().policy.engine;
    if matches!(
        kind,
        stellar_agent_core::profile::schema::PolicyEngineKind::V1
    ) {
        return Ok(());
    }
    Err(Envelope::<()>::err_raw(
        "network.mainnet_write_forbidden",
        format!(
            "{verb} on mainnet requires the v1 policy engine; the profile's engine is {kind:?}; \
             set policy.engine to v1, then run profile sign-policy and profile enable-mainnet"
        ),
    ))
}

/// Everything [`authorize_and_submit`] takes from the verb.
pub(crate) struct MainnetWriteRequest<'a> {
    /// The validated stored profile and endpoint.
    pub(crate) context: &'a MainnetWriteContext,
    /// The directory holding the stored profile files.
    pub(crate) profiles_dir: &'a Path,
    /// The verb's name in messages.
    pub(crate) verb: &'static str,
    /// The policy tool of the consumer.
    pub(crate) tool: &'static str,
    /// The verb consuming the authorization.
    pub(crate) consumer: MainnetConsumer,
    /// The unsigned envelope, base64.
    pub(crate) unsigned_xdr: &'a str,
    /// The context's primary client, which served every read.
    pub(crate) client: &'a StellarRpcClient,
    /// The budget of the resolver's endpoint probe.
    pub(crate) probe_deadline: Duration,
    /// The budget of the submission.
    pub(crate) submit_timeout: Duration,
    /// The source account the enrolled signer must be.
    pub(crate) source: &'a str,
    /// The flag that supplies the source account.
    pub(crate) source_flag: &'static str,
    /// The signer the flags chose.
    pub(crate) signer: MainnetSignerChoice,
    /// The verified policy and its enablement.
    pub(crate) policy: &'a MainnetPolicy,
    /// The policy's verdict and the effects it sized.
    pub(crate) evaluation: &'a MainnetEvaluation,
    /// The fee cap the summary shows.
    pub(crate) effective_cap: u32,
    /// The independent witness, when one was obtained.
    pub(crate) witness: Option<&'a CrossCheckWitness>,
    /// What the operational check observed on `client`; the build runs the
    /// check before its first account read, and the summary names the
    /// ledger.
    pub(crate) ledger: OperationalReport,
    /// The operation record the run signs under, opened before the
    /// confirmation; its next attempt opens after the mint and commits
    /// `Sending` before the signature.
    pub(crate) operation: Option<&'a OperationHandle>,
}

/// A mainnet write the network confirmed.
#[derive(Debug)]
pub(crate) struct MainnetSubmitted {
    /// The signed envelope that was sent.
    pub(crate) signed_xdr: String,
    /// What the network answered.
    pub(crate) result: SubmissionResult,
}

/// How a refusal from the consent drain on is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderStage {
    /// The refusal came before a signature left the attach.
    SignatureWithheld,
    /// The submission refused the signed envelope before the send.
    AfterSigning,
}

/// The step of [`authorize_and_submit`] a refusal came from, from the consent
/// drain on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineStep {
    /// The consent drain before the signing key loads.
    ConsentDrain,
    /// The audit readiness proof.
    Readiness,
    /// The recorder preparation.
    RecorderPreparation,
    /// The authorization resolver.
    Resolver,
    /// The operation attempt after the mint.
    Attempt,
    /// The signer constructor after the mint.
    SignerConstruction,
    /// The authorized attach.
    Attach {
        /// Whether the lazy keyring handle returned the error.
        handle_failed: bool,
    },
    /// The authorized submit.
    Submit {
        /// Whether the authorized pre-send hook was entered.
        pre_send_entered: bool,
    },
}

/// The render stage and the invalidation stage of a refusal at `step`.
///
/// The steps before the mint invalidate nothing. A refused operation
/// attempt means signing was refused. A failure of the signer constructor,
/// or of the keyring handle inside the attach, means the signer was
/// unavailable; every other attach refusal means signing was refused. A
/// submit refusal before the pre-send hook is the submit gate's, and one
/// inside it the hook's. No stage is derived from an error code.
#[must_use]
fn refusal_stage(step: PipelineStep) -> (RenderStage, Option<InvalidationStage>) {
    match step {
        PipelineStep::ConsentDrain
        | PipelineStep::Readiness
        | PipelineStep::RecorderPreparation
        | PipelineStep::Resolver => (RenderStage::SignatureWithheld, None),
        PipelineStep::Attempt => (
            RenderStage::SignatureWithheld,
            Some(InvalidationStage::SignRefused),
        ),
        PipelineStep::SignerConstruction => (
            RenderStage::SignatureWithheld,
            Some(InvalidationStage::SignerUnavailable),
        ),
        PipelineStep::Attach { handle_failed } => (
            RenderStage::SignatureWithheld,
            Some(if handle_failed {
                InvalidationStage::SignerUnavailable
            } else {
                InvalidationStage::SignRefused
            }),
        ),
        PipelineStep::Submit { pre_send_entered } => (
            RenderStage::AfterSigning,
            Some(if pre_send_entered {
                InvalidationStage::PreSendRefused
            } else {
                InvalidationStage::SubmitGateRefused
            }),
        ),
    }
}

/// Renders a mainnet refusal from the consent drain on.
///
/// The envelope is the submit path's, so a policy denial keeps its
/// `policy.deny.*` code and an unknown outcome keeps its details. A
/// `network.mainnet_authorization_refused` says whether the signature was
/// withheld or the submission was refused after signing. Every other code
/// keeps its message, and under [`RenderStage::SignatureWithheld`] gains the
/// sentence that nothing was sent, after a period when the message does not
/// already end in one; after signing a submit error may concern a
/// transaction that left, so its message stays.
#[must_use]
fn render_mainnet_refusal(
    err: &WalletError,
    stage: RenderStage,
    signed_xdr: &str,
    verb: &str,
) -> Envelope<()> {
    let mut envelope = error_envelope(err, signed_xdr, verb);
    if let Some(error) = envelope.error.as_mut() {
        if error.code == AUTHORIZATION_REFUSED {
            error.message = match stage {
                RenderStage::SignatureWithheld => WITHHELD_TEXT,
                RenderStage::AfterSigning => AFTER_SIGNING_TEXT,
            }
            .to_owned();
        } else if stage == RenderStage::SignatureWithheld {
            let separator = if error.message.ends_with(['.', '!', '?']) {
                " "
            } else {
                ". "
            };
            error.message.push_str(separator);
            error.message.push_str(WITHHELD_SENTENCE);
        }
    }
    envelope
}

/// The confirmation's decision for `verdict`.
fn confirm_decision(verdict: MainnetVerdict) -> ConfirmDecision {
    match verdict {
        MainnetVerdict::Allow => ConfirmDecision::Allow,
        MainnetVerdict::RequireApproval { ttl_ms } => ConfirmDecision::RequireApproval { ttl_ms },
    }
}

/// The enrolled-signer refusal, with the Ledger sentence for the Ledger
/// choice.
fn enrollment_refusal(err: &WalletError, choice: &MainnetSignerChoice) -> Envelope<()> {
    let mut envelope = Envelope::<()>::err(err);
    if matches!(choice, MainnetSignerChoice::Ledger { .. })
        && let Some(error) = envelope.error.as_mut()
    {
        error.message.push(' ');
        error.message.push_str(LEDGER_ENROLLMENT_SENTENCE);
    }
    envelope
}

/// The open authorization a refusal after the mint invalidates.
struct Minted<'a> {
    store: &'a PersistedWindowStore,
    context: &'a MainnetWriteContext,
    id: AuthorizationId,
}

/// Renders the refusal `err` at `step`, invalidating the open authorization
/// when the step's stage selects an invalidation.
///
/// The invalidation helper logs its own refusal once; this function adds no
/// log line and always renders the original refusal.
fn refused(
    step: PipelineStep,
    err: &WalletError,
    signed_xdr: &str,
    verb: &str,
    minted: Option<&Minted<'_>>,
) -> Envelope<()> {
    let (render, invalidation) = refusal_stage(step);
    if let (Some(stage), Some(minted)) = (invalidation, minted) {
        let result = invalidate_unconsumed(minted.store, minted.context, minted.id, stage);
        record_invalidation(stage, &result);
    }
    render_mainnet_refusal(err, render, signed_xdr, verb)
}

/// Runs a mainnet write from the signer choice to the submit.
///
/// The enrolled proof and the confirmation run before the consent drain, the
/// readiness proof, the recorder preparation and the mint, and the signer is
/// constructed only after the mint.
///
/// # Errors
///
/// A refusal before the consent drain renders with its own code. From the
/// consent drain on, every refusal renders through
/// [`render_mainnet_refusal`] at the stage [`refusal_stage`] selects.
pub(crate) async fn authorize_and_submit(
    req: MainnetWriteRequest<'_>,
) -> Result<MainnetSubmitted, Envelope<()>> {
    let MainnetWriteRequest {
        context,
        profiles_dir,
        verb,
        tool,
        consumer,
        unsigned_xdr,
        client,
        probe_deadline,
        submit_timeout,
        source,
        source_flag,
        signer: choice,
        policy,
        evaluation,
        effective_cap,
        witness: cross_check_witness,
        ledger,
        operation,
    } = req;
    let name = context.profile_name();
    let profile = context.profile();

    // The oracle confirms a negative answer of the primary endpoint after the
    // send. A profile whose oracle client cannot be built is refused here,
    // before anything is confirmed, recorded or signed.
    let oracle = context
        .oracle_client()
        .map_err(|e| Envelope::<()>::err(&e))?;

    // The enrolled proof reads the identity record, never the seed, and
    // refuses an unenrolled key before any prompt or pending entry.
    let source_key = stellar_strkey::ed25519::PublicKey::from_string(source)
        .map_err(|_| {
            Envelope::<()>::err(&WalletError::Validation(ValidationError::address_argument(
                source_flag,
            )))
        })?
        .0;
    let enrolled = enrolled_signer(
        name,
        profiles_dir,
        profile,
        EnrolledRole::Agent,
        &source_key,
        &policy.verified.owner(),
    )
    .map_err(|e| enrollment_refusal(&e, &choice))?;

    // Both decisions require a valid summary. Approval rules present it
    // during the passkey ceremony, whose store closes before recorder use.
    let summary = MainnetWriteSummary::from_envelope(unsigned_xdr, consumer, effective_cap)
        .map_err(|e| Envelope::<()>::err(&e))?
        .with_ledger(ledger.clone());
    let store_path = approval_store_dir()
        .map_err(|e| Envelope::<()>::err(&e))?
        .join(format!("{name}.toml"));
    let mut witness: Option<ApprovalWitness> = None;
    let authority = cli_mainnet_authority(
        &evaluation.decision,
        confirm_decision(evaluation.verdict),
        &summary,
        context,
        &policy.verified,
        &store_path,
        &mut witness,
    )
    .await
    .map_err(|r| render_authority_refusal(verb, r))?;

    drain_consent_rows_before_signing(profile, name)
        .map_err(|e| refused(PipelineStep::ConsentDrain, &e, "", verb, None))?;
    let readiness = audit_readiness(profile, name)
        .map_err(|e| refused(PipelineStep::Readiness, &e, "", verb, None))?;
    let prepared = prepare_mainnet_recorder(
        context,
        tool,
        evaluation.verdict.audit_decision(),
        evaluation.decision.provenance(),
        evaluation.decision.value_effects(),
        &readiness,
        cross_check_witness,
        &authority,
    )
    .map_err(|e| refused(PipelineStep::RecorderPreparation, &e, "", verb, None))?;

    let window_store = PersistedWindowStore::for_profile(name);
    let auth = resolve_tx_sign(TxSignRequest {
        context,
        consumer,
        unsigned_envelope_xdr: unsigned_xdr,
        client,
        probe_deadline,
        witness: cross_check_witness,
        signer: &enrolled,
        policy: &policy.verified,
        enablement: &policy.enablement,
        authority: &authority,
        audit: readiness,
        store: &window_store,
        operation: operation.map(next_attempt_link),
    })
    .await
    .map_err(|e: MainnetAuthorizationError| {
        refused(
            PipelineStep::Resolver,
            &WalletError::from(e),
            "",
            verb,
            None,
        )
    })?;
    let id = auth.id();
    let minted = Minted {
        store: &window_store,
        context,
        id,
    };

    // The attempt commits `Sending` under the minted authorization before
    // any signature, so a crash from here on never reads as a run that
    // signed nothing.
    let attempt = match operation {
        Some(handle) => Some(
            begin_classic_attempt(
                &window_store,
                profile,
                prepared.audit_writer(),
                prepared.request_id(),
                handle,
                unsigned_xdr,
            )
            .map_err(|e| refused(PipelineStep::Attempt, &e, "", verb, Some(&minted)))?,
        ),
        None => None,
    };
    let signer = match mainnet_signer(&choice, &enrolled, source, source_flag).await {
        Ok(signer) => signer,
        Err(e) => {
            let envelope = refused(
                PipelineStep::SignerConstruction,
                &e,
                "",
                verb,
                Some(&minted),
            );
            let recorder = prepared.bind_authorized(&auth, attempt, Default::default());
            record_bound_recorder(&recorder);
            recorder.end_refused_attempt(e.code());
            return Err(envelope);
        }
    };
    // The oracle bound read follows the last refusal before signing and
    // reuses the readiness report, so the primary sees no added request. Its
    // deadline leaves the authorization most of its lifetime. A failed or
    // late read stores no bound and changes no outcome.
    let observation = stellar_agent_network::policy_state::submission_observation(
        client,
        oracle.as_ref(),
        Some(&ledger),
        stellar_agent_network::policy_state::recovery::bound_read_deadline(&auth),
    )
    .await;
    let recorder = prepared.bind_authorized(&auth, attempt, observation);
    record_bound_recorder(&recorder);
    let signed_xdr = attach_signature_authorized(
        unsigned_xdr,
        signer.signer(),
        context.network_passphrase(),
        consumer,
        &auth,
    )
    .await
    .map_err(|e| {
        let envelope = refused(
            PipelineStep::Attach {
                handle_failed: signer.handle_failed(),
            },
            &e,
            "",
            verb,
            Some(&minted),
        );
        recorder.end_refused_attempt(e.code());
        envelope
    })?;

    let signer_kind = choice.submission_kind();
    record_submission_kind(signer_kind);
    let result = submit_authorized_transaction_and_wait(
        client,
        oracle.as_ref(),
        &signed_xdr,
        submit_timeout,
        context.network_passphrase(),
        Some(signer_kind),
        &recorder,
        consumer,
        MainnetSubmitGrant::Tx(auth),
    )
    .await
    .map_err(|e| {
        let envelope = refused(
            PipelineStep::Submit {
                pre_send_entered: recorder.pre_send_entered(),
            },
            &e,
            &signed_xdr,
            verb,
            Some(&minted),
        );
        recorder.end_refused_attempt(e.code());
        envelope
    })?;
    Ok(MainnetSubmitted { signed_xdr, result })
}

/// Returns `context` with the test route map of this thread, when a test set
/// one; production keeps every client on the profile's endpoints.
#[cfg(not(test))]
fn apply_test_routes(context: MainnetWriteContext) -> MainnetWriteContext {
    context
}

/// Records the stage and the result of an invalidation for the test seam;
/// production records nothing beyond the helper's own log line.
#[cfg(not(test))]
fn record_invalidation(_stage: InvalidationStage, _result: &Result<(), MainnetAuthorizationError>) {
}

/// Hands the bound recorder to the test seam; production does nothing.
#[cfg(not(test))]
fn record_bound_recorder(_recorder: &crate::commands::submission_record::StageMarkedRecorder<'_>) {}

/// Hands the signer kind the verb passes to the submit call to the test
/// seam; production does nothing.
#[cfg(not(test))]
fn record_submission_kind(_kind: stellar_agent_network::SubmissionSignerKind) {}

#[cfg(test)]
thread_local! {
    /// The `(host, transport URL)` routes a test set on this thread.
    static TEST_ROUTES: std::cell::RefCell<Option<Vec<(String, String)>>> =
        const { std::cell::RefCell::new(None) };
    /// The invalidations of this thread: the stage label and the result.
    static INVALIDATIONS: std::cell::RefCell<Vec<(&'static str, Result<(), MainnetAuthorizationError>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The `Debug` form of every recorder bound on this thread.
    static BOUND_RECORDERS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The signer kind every verb on this thread passed to the submit call.
    static SUBMISSION_KINDS: std::cell::RefCell<Vec<stellar_agent_network::SubmissionSignerKind>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Clears the test routes of this thread when dropped.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) struct TestRoutesGuard(());

#[cfg(all(test, feature = "mainnet-write"))]
impl Drop for TestRoutesGuard {
    fn drop(&mut self) {
        TEST_ROUTES.with(|routes| routes.borrow_mut().take());
    }
}

/// Routes the clients of every mainnet context built on this thread by
/// host, until the guard drops.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn set_test_routes(routes: &[(&str, &str)]) -> TestRoutesGuard {
    TEST_ROUTES.with(|slot| {
        *slot.borrow_mut() = Some(
            routes
                .iter()
                .map(|(host, url)| ((*host).to_owned(), (*url).to_owned()))
                .collect(),
        );
    });
    TestRoutesGuard(())
}

/// The invalidations recorded on this thread, oldest first.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn invalidations_on_this_thread()
-> Vec<(&'static str, Result<(), MainnetAuthorizationError>)> {
    INVALIDATIONS.with(|recorded| recorded.borrow().clone())
}

/// The `Debug` forms of the recorders bound on this thread, oldest first.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn bound_recorders_on_this_thread() -> Vec<String> {
    BOUND_RECORDERS.with(|recorded| recorded.borrow().clone())
}

/// The signer kinds the verbs on this thread passed to the submit call,
/// oldest first.
///
/// It records the argument before the submit runs, not a stored record.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn submission_kinds_on_this_thread() -> Vec<stellar_agent_network::SubmissionSignerKind>
{
    SUBMISSION_KINDS.with(|recorded| recorded.borrow().clone())
}

/// Returns `context` with the test route map of this thread, when a test set
/// one.
#[cfg(test)]
fn apply_test_routes(context: MainnetWriteContext) -> MainnetWriteContext {
    match TEST_ROUTES.with(|routes| routes.borrow().clone()) {
        Some(routes) => {
            let routes: Vec<(&str, &str)> = routes
                .iter()
                .map(|(host, url)| (host.as_str(), url.as_str()))
                .collect();
            context.with_test_transport_routes(&routes)
        }
        None => context,
    }
}

/// The `(host, transport URL)` routes a test set on this thread, if any.
#[cfg(test)]
pub(crate) fn test_routes_on_this_thread() -> Option<Vec<(String, String)>> {
    TEST_ROUTES.with(|routes| routes.borrow().clone())
}

/// Appends the stage label and the result of an invalidation to this
/// thread's record.
#[cfg(test)]
fn record_invalidation(stage: InvalidationStage, result: &Result<(), MainnetAuthorizationError>) {
    let label = match stage {
        InvalidationStage::SignerUnavailable => "signer_unavailable",
        InvalidationStage::SignRefused => "sign_refused",
        InvalidationStage::PreSendRefused => "pre_send_refused",
        InvalidationStage::SubmitGateRefused => "submit_gate_refused",
        _ => "other",
    };
    INVALIDATIONS.with(|recorded| recorded.borrow_mut().push((label, result.clone())));
}

/// Appends the `Debug` form of the bound recorder to this thread's record.
#[cfg(test)]
fn record_bound_recorder(recorder: &crate::commands::submission_record::StageMarkedRecorder<'_>) {
    BOUND_RECORDERS.with(|recorded| recorded.borrow_mut().push(format!("{recorder:?}")));
}

/// Records the signer kind the verb passes to the submit call for the test
/// seam.
#[cfg(test)]
fn record_submission_kind(kind: stellar_agent_network::SubmissionSignerKind) {
    SUBMISSION_KINDS.with(|recorded| recorded.borrow_mut().push(kind));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

    use super::*;
    use stellar_agent_core::error::{AuthError, NetworkError, SubmissionError};
    use stellar_agent_core::policy::DenyReason;
    use stellar_agent_network::mainnet::MainnetPrecondition;
    use stellar_agent_test_support::WarningCapture;

    /// Summary validation precedes authority selection under either decision.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn summary_validation_refuses_before_authority_for_both_decisions() {
        use crate::commands::policy_engine::load_mainnet_policy_engine;
        use crate::common::mainnet_write_fixture::{AGENT_SEED, Spec};
        use crate::common::signer_ceremony::signer_resolutions_on_this_thread;
        use stellar_agent_core::mainnet::decision::{AuthorityScope, MainnetDecision};
        use stellar_agent_core::policy::{ApprovalRequest, Decision};
        use stellar_agent_core::profile::name::ProfileNameSource;
        use stellar_xdr::*;
        for (name, approval) in [("summary-policy", false), ("summary-approval", true)] {
            let fixture = Spec::new(name).build().await;
            let context = mainnet_context(
                &fixture.profile(),
                &ResolvedProfileName::from_flag(name),
                MainnetEndpointFlags::default(),
            )
            .unwrap();
            let profiles = mainnet_profiles_dir().unwrap();
            let policy = load_mainnet_policy_engine(
                "trustline",
                "policy.engine_unavailable",
                &context,
                ProfileNameSource::Flag,
                &profiles,
            )
            .unwrap();
            let envelope = stellar_agent_test_support::SignedTestEnvelope::builder(AGENT_SEED)
                .unsigned()
                .build();
            let TransactionEnvelope::Tx(mut tx) =
                TransactionEnvelope::from_xdr_base64(envelope.envelope_xdr(), Limits::none())
                    .unwrap()
            else {
                panic!("transaction")
            };
            tx.tx.operations = vec![Operation {
                source_account: None,
                body: OperationBody::ChangeTrust(ChangeTrustOp {
                    line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4([b'U', 0x1b, b'[', 0x07]),
                        issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
                    }),
                    limit: 31,
                }),
            }]
            .try_into()
            .unwrap();
            let encoded = TransactionEnvelope::Tx(tx)
                .to_xdr_base64(Limits::none())
                .unwrap();
            let decision = MainnetDecision::for_test(
                if approval {
                    Decision::RequireApproval(ApprovalRequest::new("fixture".to_owned(), 300))
                } else {
                    Decision::Allow
                },
                None,
                policy.verified.digest(),
                policy.verified.sequence(),
                3,
                name,
                context.chain().caip2_str(),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                if approval { 300_000 } else { 600_000 },
                AuthorityScope::Classic,
            );
            let evaluation = MainnetEvaluation {
                verdict: if approval {
                    MainnetVerdict::RequireApproval { ttl_ms: 300_000 }
                } else {
                    MainnetVerdict::Allow
                },
                decision,
            };
            let before = signer_resolutions_on_this_thread();
            let client = context.primary_client().unwrap();
            let result = authorize_and_submit(MainnetWriteRequest {
                context: &context,
                profiles_dir: &profiles,
                verb: "trustline",
                tool: "stellar_trustline",
                consumer: MainnetConsumer::CliTrustline,
                unsigned_xdr: &encoded,
                client: &client,
                probe_deadline: std::time::Duration::from_secs(2),
                submit_timeout: std::time::Duration::from_secs(2),
                source: &fixture.agent.g,
                source_flag: "--from",
                signer: MainnetSignerChoice::Keyring,
                policy: &policy,
                evaluation: &evaluation,
                effective_cap: 500,
                witness: None,
                ledger: OperationalReport {
                    latest_ledger: 2000,
                    close_time_unix: 1_900_000_000,
                    close_lag_seconds: 0,
                },
                operation: None,
            })
            .await;
            let Err(envelope) = result else {
                panic!("invalid summary must refuse")
            };
            assert_eq!(envelope.error.unwrap().code, "protocol.xdr_codec_failed");
            fixture.assert_no_consent_ceremony();
            assert_eq!(signer_resolutions_on_this_thread(), before);
            assert!(
                fixture
                    .open_authorizations(stellar_agent_core::timefmt::now_unix_ms().unwrap())
                    .is_empty()
            );
            assert!(fixture.sent_envelopes().await.is_empty());
        }
    }

    /// Every pipeline step selects the render stage and the invalidation
    /// stage the step's place relative to the mint and the send gives it.
    #[test]
    fn each_step_selects_its_render_and_invalidation_stage() {
        use InvalidationStage as I;
        use RenderStage::{AfterSigning, SignatureWithheld};
        let cases = [
            (PipelineStep::ConsentDrain, SignatureWithheld, None),
            (PipelineStep::Readiness, SignatureWithheld, None),
            (PipelineStep::RecorderPreparation, SignatureWithheld, None),
            (PipelineStep::Resolver, SignatureWithheld, None),
            (
                PipelineStep::SignerConstruction,
                SignatureWithheld,
                Some(I::SignerUnavailable),
            ),
            (
                PipelineStep::Attach {
                    handle_failed: true,
                },
                SignatureWithheld,
                Some(I::SignerUnavailable),
            ),
            (
                PipelineStep::Attach {
                    handle_failed: false,
                },
                SignatureWithheld,
                Some(I::SignRefused),
            ),
            (
                PipelineStep::Submit {
                    pre_send_entered: true,
                },
                AfterSigning,
                Some(I::PreSendRefused),
            ),
            (
                PipelineStep::Submit {
                    pre_send_entered: false,
                },
                AfterSigning,
                Some(I::SubmitGateRefused),
            ),
        ];
        for (step, render, invalidation) in cases {
            let (selected_render, selected_invalidation) = refusal_stage(step);
            assert_eq!(selected_render, render, "{step:?}");
            assert_eq!(
                format!("{selected_invalidation:?}"),
                format!("{invalidation:?}"),
                "{step:?}"
            );
        }
    }

    fn rendered(err: &WalletError, stage: RenderStage, signed_xdr: &str) -> (String, String) {
        let envelope = render_mainnet_refusal(err, stage, signed_xdr, "pay");
        let error = envelope.error.unwrap();
        (error.code, error.message)
    }

    /// The generic refusal says the signature was withheld before the
    /// attach returned, and that the submission was refused after signing.
    #[test]
    fn the_generic_refusal_names_the_stage() {
        let err = WalletError::Network(NetworkError::MainnetAuthorizationRefused);
        assert_eq!(
            rendered(&err, RenderStage::SignatureWithheld, ""),
            (
                "network.mainnet_authorization_refused".to_owned(),
                "the mainnet write was refused; the signature was withheld and nothing was sent"
                    .to_owned()
            )
        );
        assert_eq!(
            rendered(&err, RenderStage::AfterSigning, "AAAA"),
            (
                "network.mainnet_authorization_refused".to_owned(),
                "the mainnet write was refused; the submission was refused after signing and \
                 nothing was sent"
                    .to_owned()
            )
        );
    }

    /// Any other code keeps its message, which gains the withheld sentence
    /// before the signature left and stays unchanged after signing.
    #[test]
    fn another_code_keeps_its_message() {
        let err = WalletError::Auth(AuthError::SignerKeyMismatch {
            what: "the expected signing account",
            expected: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            got: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
        });
        let message = err.message();
        assert_eq!(
            rendered(&err, RenderStage::SignatureWithheld, ""),
            (
                "auth.signer_key_mismatch".to_owned(),
                format!("{message}. The signature was withheld and nothing was sent.")
            )
        );
        assert_eq!(
            rendered(&err, RenderStage::AfterSigning, "AAAA"),
            ("auth.signer_key_mismatch".to_owned(), message)
        );
    }

    /// A policy denial keeps its `policy.deny.*` code before the signature
    /// left.
    #[test]
    fn a_policy_denial_keeps_its_code() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(DenyReason::ExplicitRuleDeny),
        };
        let (code, message) = rendered(&err, RenderStage::SignatureWithheld, "");
        assert_eq!(code, "policy.deny.explicit_rule_deny");
        assert_eq!(
            message,
            "pay operation denied by operator policy. The signature was withheld and nothing \
             was sent."
        );
    }

    /// A message that already ends in terminal punctuation gains the
    /// withheld sentence after a single space.
    #[test]
    fn a_punctuated_message_gains_the_sentence_after_a_space() {
        for detail in ["the store was locked.", "was the store locked?"] {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: detail.to_owned(),
            });
            let (code, message) = rendered(&err, RenderStage::SignatureWithheld, "");
            assert_eq!(code, "internal.unexpected_state");
            assert_eq!(
                message,
                format!(
                    "unexpected internal state: {detail} The signature was withheld and \
                     nothing was sent."
                )
            );
        }
    }

    /// An unknown-outcome code keeps its details after signing, because
    /// the transaction may have left.
    #[test]
    fn an_unknown_outcome_keeps_its_details() {
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: "ab".repeat(32),
            seconds: 60,
        });
        let envelope = render_mainnet_refusal(&err, RenderStage::AfterSigning, "", "pay");
        let error = envelope.error.unwrap();
        assert_eq!(error.code, "submission.tx_timeout");
        assert_eq!(error.message, err.message());
        let details = error.details.unwrap();
        assert_eq!(details["tx_hash"], "ab".repeat(32));
        assert_eq!(details["outcome"], "unknown");
    }

    /// A refused precondition renders the generic code with no warning
    /// from the surface: the resolver and the helper log it themselves.
    #[test]
    fn a_refused_precondition_maps_to_the_generic_code_without_a_surface_log() {
        let (capture, _guard) = WarningCapture::capture(None);
        let err = WalletError::from(MainnetAuthorizationError::Refused(
            MainnetPrecondition::AuditStale,
        ));
        let (code, _) = rendered(&err, RenderStage::SignatureWithheld, "");
        assert_eq!(code, "network.mainnet_authorization_refused");
        assert!(capture.seen().is_empty(), "{:?}", capture.seen());
    }

    /// A policy denial maps to its criterion's code.
    #[test]
    fn a_policy_denial_maps_to_its_code() {
        let err = WalletError::from(MainnetAuthorizationError::PolicyDenied(Box::new(
            DenyReason::ExplicitRuleDeny,
        )));
        let (code, _) = rendered(&err, RenderStage::SignatureWithheld, "");
        assert_eq!(code, "policy.deny.explicit_rule_deny");
    }

    /// A build without mainnet writes maps to the write refusal.
    #[test]
    fn a_disabled_build_maps_to_the_write_refusal() {
        let err = WalletError::from(MainnetAuthorizationError::FeatureDisabled);
        let (code, _) = rendered(&err, RenderStage::SignatureWithheld, "");
        assert_eq!(code, "network.mainnet_write_forbidden");
    }
}
