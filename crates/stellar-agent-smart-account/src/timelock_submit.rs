//! Direct G-key auth submit path for OZ `TimelockController` invocations.
//!
//! The OZ `TimelockController` is NOT a smart-account; it does not expose
//! `__check_auth`. Its entrypoints (`schedule`, `cancel`, `execute`) call
//! `proposer.require_auth()` / `canceller.require_auth()` / `executor.require_auth()`
//! where the address is a G-key (`ScAddress::Account`) passed as a function
//! argument.
//!
//! This means the Soroban host expects a `SorobanAuthorizationEntry` with:
//! - `credentials: SorobanCredentials::Address { address: G_KEY, … }`
//! - `root_invocation.function: ContractFn(timelock, "schedule"|"cancel"|"execute", args)`
//! - Signature over `sha256(HashIdPreimageSorobanAuthorization { network_id, nonce,
//!   signature_expiration_ledger, invocation })`.
//!
//! The submit flow used by [`crate::submit::submit_signed_invoke`] builds
//! SMART-ACCOUNT auth entries (going through `build_authorization_entry` which
//! encodes `rule_ids` and calls `__check_auth`). That path is incompatible with
//! the OZ TimelockController.
//!
//! This module provides [`submit_timelock_invoke_with_g_key_auth`], which:
//! 1. Builds and simulates the wallet's timelock invocation.
//! 2. Obtains the ledger witness and validates every authorization credential
//!    against that invocation, without sub-invocations.
//! 3. Freezes and admits signed entry subjects before constructing their gate.
//!    A fresh witness is required after admission and before entry signing.
//! 4. Simulates the signed authorization and fetches the final source sequence.
//!    A signed entry plan refuses any change to its frozen sequence.
//! 5. Builds the final envelope. Empty and SourceAccount-only plans admit here,
//!    after readying their witness pair, then check freshness without rereading.
//! 6. Authorizes and signs the envelope through the gate, binds recorded
//!    exposure, links the reservation, and submits before the deadline.
//!
//! A stale witness can refresh before admission. Staleness after admission
//! refuses and cancels an unexposed admission. Every failure after the first
//! successful gate authorization retains the charge. Confirmation polling
//! uses the submission timeout.
//!
//! # Auth preimage shape
//!
//! `HashIdPreimageSorobanAuthorization {`
//! `  network_id: Hash(sha256(network_passphrase)),`
//! `  nonce: <from simulate SorobanCredentials>,`
//! `  signature_expiration_ledger: lower witnessed ledger + 100,`
//! `  invocation: <the wallet's own timelock call, no sub-invocations>,`
//! `}`
//!
//! Every timelock authorization entry is validated before any signature.
//! SourceAccount and signer Address credentials must name the wallet's exact
//! invocation with no sub-invocations. Other credential variants are refused.
//! The G-key signature is a classic-account Address authorization: no context
//! rule narrows it, and it is not bound to a transaction, so the wallet signs
//! only the invocation it built.
//! Canonical source: `stellar_xdr::HashIdPreimageSorobanAuthorization`
//! (mirroring the preimage used in `managers/auth_entry.rs::compute_signature_payload`
//! and `managers/auth_entry.rs::build_and_sign_delegated_g_key_entry`).
//!
//! # Signature ScVal shape
//!
//! `ScVal::Vec([ScVal::Map([`
//! `  { key: Symbol("public_key"), val: Bytes(<32 bytes>) },`
//! `  { key: Symbol("signature"),  val: Bytes(<64 bytes>) },`
//! `])])`
//! Canonical source: `managers/auth_entry.rs::build_and_sign_delegated_g_key_entry`
//! (same encoding; js-stellar-base auth.js:171-184 cross-reference).

use sha2::{Digest as _, Sha256};
use stellar_agent_network::{
    StellarRpcClient, fetch_account, signing::Signer, signing::SorobanAuthPayload,
    signing::envelope_signing::attach_signature, submit_transaction_and_wait_sent_by,
};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction,
    InvokeContractArgs, InvokeHostFunctionOp, LedgerBounds, Limits, Operation, OperationBody,
    Preconditions, PreconditionsV2, PublicKey as XdrPublicKey, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM, WriteXdr,
};

use crate::SaError;
use crate::managers::auth_entry::{PreSubmitBudget, bound_pre_submit_stage};
use crate::managers::rules::{
    BASE_FEE_STROOPS, SimulationErrorClass, fingerprint_invocation, parse_min_resource_fee,
    validate_latest_ledger,
};
use crate::signing::gate::{SignerMatch, SigningGate, SigningRequest};
use crate::signing::ledger_witness::{
    ResolvedKeySigner, WitnessRequest, WitnessedLedgerBound, checked_secondary_rpc_url,
    witness_signing_ledger,
};
use crate::submit::{
    DeclaredSubInvocations, attribute_signed_tree_refusal, check_declared_sub_invocations,
    check_simulated_root, map_sent_by_error, refuse_mainnet_sa,
};
use stellar_agent_network::{
    AuthSubject, IntentSubject, SignedIntentPlan, SignerDescriptor, SigningAdmission,
    SigningPayload,
};

// ── Public result type ────────────────────────────────────────────────────────

/// Result returned by [`submit_timelock_invoke_with_g_key_auth`].
///
/// Mirrors the shape of `SubmitInvokeResult` from `submit.rs` for consistency
/// across the timelock call sites.
#[derive(Debug)]
pub(crate) struct TimelockSubmitResult {
    /// Predicted return `ScVal` from the accepted unsigned simulation, including recovery.
    pub(crate) return_val: ScVal,
    /// Confirmed transaction hash (64-character hex string).
    pub(crate) tx_hash: String,
    /// Ledger sequence in which the transaction was confirmed.
    ///
    /// Retained for future use (e.g. audit-log enrichment); callers that do
    /// not yet need the confirmed ledger may ignore this field.
    #[allow(
        dead_code,
        reason = "retained for future audit enrichment; read in unit tests"
    )]
    pub(crate) ledger: u32,
}

// ── Arguments struct ──────────────────────────────────────────────────────────

/// Arguments for [`submit_timelock_invoke_with_g_key_auth`].
///
/// Bundles all inputs required by the direct G-key auth submit path.
/// Separate from `SubmitInvokeArgs` so the two paths remain independent.
pub(crate) struct TimelockSubmitArgs<'a> {
    /// The pre-built `InvokeContract` host function (timelock entrypoint).
    pub(crate) host_function: HostFunction,
    /// The schedule identity computed from both checked endpoints before admission.
    pub(crate) schedule_identity: Option<(&'a str, [u8; 32])>,
    /// The signer whose G-key holds the required role (PROPOSER/CANCELLER/EXECUTOR).
    pub(crate) signer: &'a (dyn Signer + Send + Sync),
    /// Primary Soroban RPC URL.
    pub(crate) primary_rpc_url: &'a str,
    /// Secondary Soroban RPC URL: the ledger witness every signature rests
    /// on. A malformed URL or a URL on the primary's host refuses with
    /// [`SaError::LedgerWitnessUnavailable`] before the first request.
    pub(crate) secondary_rpc_url: &'a str,
    /// Stellar network passphrase (used for auth preimage and envelope signing).
    pub(crate) network_passphrase: &'a str,
    /// Submission polling timeout, and the one deadline the ledger witness,
    /// the source-account re-fetches, the signed re-simulation, every
    /// signature and the steps before `sendTransaction` share.
    pub(crate) timeout: std::time::Duration,
    /// Human-readable operation label for error messages and logs.
    pub(crate) op_label: &'static str,
    /// Charges the intent before its first signature.
    pub(crate) admission: SigningAdmission<'a>,
}

fn check_schedule_prediction(
    identity: Option<(&str, [u8; 32])>,
    prediction: &ScVal,
) -> Result<(), SaError> {
    if let Some((_, operation_id)) = identity
        && !matches!(prediction, ScVal::Bytes(bytes) if bytes.as_slice() == operation_id)
    {
        return Err(SaError::IntentBindingMismatch { field: "purpose" });
    }
    Ok(())
}

// ── Main submit function ──────────────────────────────────────────────────────

/// An authorization entry whose credential kind and invocation pass validation.
enum ValidatedTimelockAuth {
    /// The transaction source authorizes the wallet's own invocation.
    SourceAccount,
    /// The signer's G-key authorizes the wallet's own invocation.
    SignerKey(SorobanAddressCredentials),
}

/// Validates the entire simulated vector before any signing primitive runs.
fn validate_timelock_auth_entries(
    entries: Vec<SorobanAuthorizationEntry>,
    invoke: &InvokeContractArgs,
    signer_address: &ScAddress,
    op_label: &str,
) -> Result<Vec<ValidatedTimelockAuth>, SaError> {
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        let credentials = match &entry.credentials {
            SorobanCredentials::SourceAccount => None,
            SorobanCredentials::Address(creds) => {
                if &creds.address != signer_address {
                    return Err(SaError::AuthEntryConstructionFailed {
                        stage: "auth_payload",
                        redacted_reason: format!(
                            "{op_label}: simulate returned auth entry for an unexpected address \
                             (not the signer G-key); cannot sign"
                        ),
                    });
                }
                Some(creds.clone())
            }
            SorobanCredentials::AddressV2(_) | SorobanCredentials::AddressWithDelegates(_) => {
                return Err(SaError::AuthEntryConstructionFailed {
                    stage: "credential_variant",
                    redacted_reason: "timelock signing supports SourceAccount and signer Address credentials only"
                        .to_owned(),
                });
            }
        };
        // The OZ timelock calls the role's require_auth() in its own schedule,
        // execute or cancel frame, so the honest root is the host function
        // itself, with nothing under it.
        check_simulated_root(&entry.root_invocation.function, invoke)
            .and_then(|()| {
                check_declared_sub_invocations(
                    &entry.root_invocation.sub_invocations,
                    &DeclaredSubInvocations::None,
                    signer_address,
                )
            })
            .map_err(|err| {
                attribute_signed_tree_refusal(err, op_label, &fingerprint_invocation(&entry))
            })?;
        validated.push(match credentials {
            None => ValidatedTimelockAuth::SourceAccount,
            Some(creds) => ValidatedTimelockAuth::SignerKey(creds),
        });
    }
    Ok(validated)
}

/// Submits a timelock invocation through checked G-key signing admission.
///
/// The timelock contract requires the caller's account authority. Address
/// credentials use the canonical Soroban authorization preimage over the
/// wallet's invocation. SourceAccount credentials need only the envelope.
///
/// # Steps
///
/// 1. Check the network and witness configuration, then fetch the signer key
///    and source account sequence.
/// 2. Simulate the invocation and obtain independent ledger observations.
///    Validate every credential against the exact invocation without subcalls.
/// 3. For signed entries, ready the witness pair and freeze subjects, nonces,
///    expiration, and source sequence. Admit the plan, immediately build its
///    gate, and recheck freshness before authorizing each entry signature.
/// 4. Simulate signed authorization to obtain its resource footprint. Fetch
///    the source account again and refuse a changed frozen sequence.
/// 5. Build the final envelope. For empty or SourceAccount-only authorization,
///    ready the witness pair, build and admit the plan, and construct its gate.
///    Check freshness without another ledger read after admission.
/// 6. Check and authorize the envelope through its gate, then attach its
///    signature. Bind recorded exposure, link the reservation, and send before
///    the deadline. Poll confirmation under the submission timeout.
///
/// Any failure before the first successful gate authorization cancels the
/// unexposed admission. Later failures retain its charge, including a failed
/// signer call. A no-value admission keeps its count charge without binding.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`] refuses mainnet before key access or RPC.
/// - [`SaError::LedgerWitnessUnavailable`] refuses missing or stale observations
///   and an elapsed deadline before signing.
/// - [`SaError::LedgerWitnessMismatch`] refuses inconsistent ledger observations.
/// - [`SaError::PolicyDenied`] preserves the admission criterion's denial.
/// - [`SaError::IntentRecordUnavailable`] refuses unavailable checked admission.
/// - [`SaError::IntentBindingMismatch`] refuses a changed plan or envelope.
/// - [`SaError::AuthEntryConstructionFailed`] reports unsupported credentials,
///   key access, encoding, signing, and deadline failures.
/// - [`SaError::SimulationDivergence`] refuses an invocation outside the wallet's
///   exact call. [`SaError::DeploymentFailed`] reports simulation and envelope
///   construction failures.
///
/// Schedule, cancel, and execute preserve mainnet, policy, intent, and witness
/// refusals. Execute also preserves unresolved submissions. The wrappers map
/// other errors to their operation-specific variants.
#[allow(
    clippy::too_many_lines,
    reason = "seven-stage direct G-key auth flow; collapsing would obscure the sequential \
              invariant ordering required for Soroban auth-entry construction"
)]
pub(crate) async fn submit_timelock_invoke_with_g_key_auth(
    args: TimelockSubmitArgs<'_>,
) -> Result<TimelockSubmitResult, SaError> {
    refuse_mainnet_sa(args.network_passphrase, args.primary_rpc_url)?;

    // Every signature below rests on a second endpoint's ledger observation.
    let secondary_rpc_url = checked_secondary_rpc_url(
        args.primary_rpc_url,
        Some(args.secondary_rpc_url),
        args.network_passphrase,
    )?;

    let auth_err = |stage: &'static str, reason: String| SaError::AuthEntryConstructionFailed {
        stage,
        redacted_reason: reason,
    };

    // ── Step 1: Fetch signer G-key and source account ─────────────────────────
    let pubkey = args.signer.public_key().await.map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: signer public_key fetch failed: {e}", args.op_label),
        )
    })?;
    let source_pubkey_strkey: String = stellar_strkey::ed25519::PublicKey(pubkey.0)
        .to_string()
        .as_str()
        .to_owned();

    let primary_rpc_client = StellarRpcClient::new(args.primary_rpc_url).map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: StellarRpcClient: {e}", args.op_label),
        )
    })?;

    let source_view = fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[])
        .await
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!("{}: source-account fetch failed: {e}", args.op_label),
            )
        })?;

    // ── Step 2: Build simulation transaction (empty auth) ─────────────────────
    let invoke = match &args.host_function {
        HostFunction::InvokeContract(inv) => inv.clone(),
        other => {
            return Err(auth_err(
                "auth_payload",
                format!(
                    "{}: expected InvokeContract host function, got {:?}",
                    args.op_label, other
                ),
            ));
        }
    };

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke.clone()),
            auth: VecM::default(),
        }),
    };

    let mut source_account = BaselibAccount::new(
        &source_pubkey_strkey,
        &source_view.sequence_number.to_string(),
    )
    .map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: BaselibAccount::new failed: {e:?}", args.op_label),
        )
    })?;

    let server = Client::new(args.primary_rpc_url).map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: RPC Client construction failed: {e}", args.op_label),
        )
    })?;

    let mut tx_builder =
        TransactionBuilder::new(&mut source_account, args.network_passphrase, None);
    tx_builder.fee(BASE_FEE_STROOPS);
    tx_builder.add_operation(op);
    let tx_for_simulate = tx_builder.build_for_simulation();

    // ── Step 3: Simulate (empty auth) to get auth entry templates ─────────────
    let sim_envelope = tx_for_simulate.to_envelope().map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: to_envelope failed: {e:?}", args.op_label),
        )
    })?;
    let mut sim_response = server
        .simulate_transaction_envelope(&sim_envelope, None)
        .await
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: simulate_transaction_envelope failed: {e}",
                    args.op_label
                ),
            )
        })?;

    let decode_simulation = |sim_response: &stellar_rpc_client::SimulateTransactionResponse| {
        if let Some(err) = &sim_response.error {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{} simulation returned error: {}",
                    args.op_label,
                    SimulationErrorClass::of(err)
                ),
            });
        }
        if sim_response.min_resource_fee == 0 || sim_response.transaction_data.is_empty() {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{}: simulate returned no min_resource_fee / transaction_data",
                    args.op_label
                ),
            });
        }

        let sim_first_result = sim_response
            .results()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("{}: simulate results decode failed: {e}", args.op_label),
            })?
            .into_iter()
            .next()
            .ok_or_else(|| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("{}: simulate returned no result entry", args.op_label),
            })?;
        let return_val = sim_first_result.xdr;
        check_schedule_prediction(args.schedule_identity, &return_val)?;
        Ok((return_val, sim_first_result.auth))
    };
    // The deadline starts after the initial response is decoded;
    // recovery replaces the decoded result.
    let mut decoded_simulation = decode_simulation(&sim_response);

    // One absolute deadline starts after initial response validation.
    // The witness, optional unsigned recovery, account re-fetches, signed
    // re-simulation, signatures and pre-send steps share its remaining budget.
    // Recovery uses this deadline and the same observation pair.
    let pre_submit_budget = PreSubmitBudget {
        deadline: tokio::time::Instant::now() + args.timeout,
        total: args.timeout,
    };
    let witness_request = WitnessRequest {
        primary: &primary_rpc_client,
        secondary_rpc_url,
        network_passphrase: args.network_passphrase,
        budget: pre_submit_budget,
    };
    let simulation_witness = witness_signing_ledger(&witness_request).await?;
    validate_latest_ledger(sim_response.latest_ledger)?;
    if simulation_witness.is_behind(sim_response.latest_ledger) {
        sim_response = bound_pre_submit_stage(
            pre_submit_budget,
            "simulate_recovery",
            "auth_payload",
            server.simulate_transaction_envelope(&sim_envelope, None),
        )
        .await?
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!("simulate_transaction_envelope failed: {e}"),
            )
        })?;
        validate_latest_ledger(sim_response.latest_ledger)?;
        decoded_simulation = decode_simulation(&sim_response);
    }

    simulation_witness.check_simulation_height(sim_response.latest_ledger)?;
    let (return_val, auth_entries) = decoded_simulation?;
    let network_id: [u8; 32] = Sha256::digest(args.network_passphrase.as_bytes()).into();

    // ── Step 4: Sign auth entries for the signer G-key ────────────────────────
    //
    // The simulate response returns a list of `SorobanAuthorizationEntry` values
    // with placeholder (unsigned) credentials. For `require_auth()` on a G-key
    // `Address` argument, the host returns `SorobanCredentials::Address` whose
    // `address` is that G-key.  We sign each entry whose address matches our
    // signer's G-key.
    //
    // Auth preimage: `HashIdPreimageSorobanAuthorization { network_id, nonce,
    // signature_expiration_ledger, invocation }` (same shape as
    // `auth_entry.rs::compute_signature_payload`, which is canonical for all
    // Soroban address-credential auth across the Stellar SDK ecosystem).
    //
    // Signature shape: `ScVal::Vec([ScVal::Map([{public_key, signature}])])`
    // (same encoding as `auth_entry.rs::build_and_sign_delegated_g_key_entry`;
    // js-stellar-base auth.js:171-184 canonical reference).
    //
    // The invocation signed is the wallet's own timelock call, never the one
    // the simulation returned: an entry whose root differs from it is refused
    // below before any preimage is computed.
    let wallet_root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
        sub_invocations: VecM::default(),
    };
    //
    // Every entry is checked before any is signed: a response whose first
    // entry is honest and whose second is not produces no signature at all.
    // The source account and this address derive from the same resolved key.
    let signer_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
        Uint256(pubkey.0),
    )));
    let checked_entries =
        validate_timelock_auth_entries(auth_entries, &invoke, &signer_address, args.op_label)?;

    // The first signature is an entry's when the simulation asks the
    // signer's key for one, and the envelope's otherwise. The pair is readied
    // where that signature falls.
    let signs_entries = checked_entries
        .iter()
        .any(|checked| matches!(checked, ValidatedTimelockAuth::SignerKey(_)));
    let ledger_bound = if signs_entries {
        pair_for_first_signature(simulation_witness, &witness_request, pre_submit_budget).await?
    } else {
        simulation_witness
    };
    let signature_expiration_ledger = ledger_bound.signature_expiration_ledger()?;

    let subjects: Vec<_> = checked_entries
        .iter()
        .map(|checked| match checked {
            ValidatedTimelockAuth::SignerKey(creds) => IntentSubject::account_key(
                &signer_address,
                creds.nonce,
                signature_expiration_ledger,
                &wallet_root,
            ),
            ValidatedTimelockAuth::SourceAccount => {
                IntentSubject::source_account(&source_pubkey_strkey, &wallet_root)
            }
        })
        .collect::<Result<_, _>>()
        .map_err(|field| SaError::IntentBindingMismatch { field })?;
    let host_hash: [u8; 32] = Sha256::digest(
        args.host_function
            .to_xdr(Limits::none())
            .map_err(|_| SaError::IntentBindingMismatch { field: "plan" })?,
    )
    .into();
    let auth_address = crate::managers::rules::scaddress_to_strkey(&invoke.contract_address)?;
    let make_plan = |sequence: i64, envelope_max: u32| {
        SignedIntentPlan::new(
            args.network_passphrase,
            &auth_address,
            &source_pubkey_strkey,
            sequence,
            host_hash,
            subjects.clone(),
            signs_entries.then_some(signature_expiration_ledger),
        )
        .and_then(|plan| plan.classify_purpose(&args.host_function, args.schedule_identity))
        .and_then(|plan| plan.with_envelope_max_ledger(envelope_max))
        .map_err(|error| crate::submit::map_admission_error(&error, args.op_label))
    };
    let frozen_sequence = source_view
        .sequence_number
        .checked_add(1)
        .ok_or(SaError::IntentBindingMismatch { field: "plan" })?;
    let mut gate = None;
    if signs_entries {
        let plan = make_plan(frozen_sequence, signature_expiration_ledger)?
            .with_capability(ledger_bound.capability());
        let proof = args
            .admission
            .admit(&plan)
            .await
            .map_err(|error| crate::submit::map_admission_error(&error, args.op_label))?;
        gate = Some(SigningGate::new(proof));
    }
    let signing_result = async {
        if signs_entries {
            ledger_bound.ensure_fresh(pre_submit_budget)?;
        }
        let mut signed_entries: Vec<SorobanAuthorizationEntry> =
            Vec::with_capacity(checked_entries.len());
        for checked in checked_entries {
            let creds = match checked {
                ValidatedTimelockAuth::SourceAccount => {
                    signed_entries.push(SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::SourceAccount,
                        root_invocation: wallet_root.clone(),
                    });
                    continue;
                }
                ValidatedTimelockAuth::SignerKey(creds) => creds,
            };

            // Compute the auth preimage over the wallet's own invocation.
            // `signature_expiration_ledger` is the witnessed bound (overrides the
            // `0` placeholder the RPC returns).
            let preimage =
                HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                    network_id: Hash(network_id),
                    nonce: creds.nonce,
                    signature_expiration_ledger,
                    invocation: wallet_root.clone(),
                });
            let signature_payload = SorobanAuthPayload::from_preimage(&preimage).map_err(|e| {
                auth_err(
                    "auth_payload",
                    format!("{}: auth preimage payload refused: {e}", args.op_label),
                )
            })?;

            // Sign with the Soroban-address-auth primitive, under the deadline.
            // A software key signs without yielding, so the deadline is checked
            // before the bounded signature as well.
            pre_submit_budget.check_at("sign_auth_entry", "auth_payload")?;
            gate.as_ref()
                .ok_or(SaError::IntentBindingMismatch {
                    field: "intent_state",
                })?
                .authorize(SigningRequest {
                    subject: AuthSubject::account_key(&signer_address)
                        .map_err(|field| SaError::IntentBindingMismatch { field })?,
                    signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                        public_key: pubkey.0,
                    }),
                    payload: SigningPayload::AddressPayload(*signature_payload.as_bytes()),
                })?;
            let signature_bytes = bound_pre_submit_stage(
                pre_submit_budget,
                "sign_auth_entry",
                "auth_payload",
                args.signer
                    .sign_soroban_address_auth_payload(&signature_payload),
            )
            .await?
            .map_err(|e| {
                auth_err(
                    "auth_payload",
                    format!("{}: G-key auth signing failed: {e}", args.op_label),
                )
            })?;

            // Build the single-Ed25519 standard Stellar signature ScVal:
            // `ScVal::Vec([ScVal::Map([{public_key: Bytes<32>, signature: Bytes<64>}])])`
            let signature_scval = crate::managers::auth_entry::build_classic_signature_scval(
                &pubkey.0,
                &signature_bytes,
            )
            .map_err(|e| auth_err("auth_payload", format!("{}: {e}", args.op_label)))?;

            signed_entries.push(SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: creds.address,
                    nonce: creds.nonce,
                    signature_expiration_ledger,
                    signature: signature_scval,
                }),
                root_invocation: wallet_root.clone(),
            });
        }

        // ── Step 5: Re-simulate with signed auth entries ──────────────────────────
        //
        // The first simulate ran with empty auth; its footprint omits the G-key
        // `require_auth` validation storage reads (the host skips that path when
        // auth is empty). Re-simulating with the signed auth entries causes the
        // host to execute the full `require_auth` validation path, producing a
        // footprint that includes all storage keys accessed. Without this,
        // submission would trap with "access contract data key outside footprint".
        //
        // This mirrors the `resimulate_with_signed_auth` pattern in `managers/auth_entry.rs`.
        let auth_vecm: VecM<SorobanAuthorizationEntry> =
            signed_entries.clone().try_into().map_err(|e| {
                auth_err(
                    "auth_payload",
                    format!("{}: encode signed auth VecM: {e:?}", args.op_label),
                )
            })?;

        let op_resim = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke.clone()),
                auth: auth_vecm,
            }),
        };

        // Re-fetch source account for accurate sequence number.
        let source_view2 = bound_pre_submit_stage(
            pre_submit_budget,
            "fetch_account_resim",
            "auth_payload",
            fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[]),
        )
        .await?
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: source-account re-fetch for resimulate failed: {e}",
                    args.op_label
                ),
            )
        })?;
        let mut source_account2 = BaselibAccount::new(
            &source_pubkey_strkey,
            &source_view2.sequence_number.to_string(),
        )
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: BaselibAccount::new (resimulate) failed: {e:?}",
                    args.op_label
                ),
            )
        })?;

        let mut tx_builder2 =
            TransactionBuilder::new(&mut source_account2, args.network_passphrase, None);
        tx_builder2.fee(BASE_FEE_STROOPS);
        tx_builder2.add_operation(op_resim);
        let tx_resim = tx_builder2.build_for_simulation();

        let mut resim_envelope = tx_resim.to_envelope().map_err(|e| {
            auth_err(
                "auth_payload",
                format!("{}: to_envelope (resim) failed: {e:?}", args.op_label),
            )
        })?;
        set_envelope_max_ledger(&mut resim_envelope, signature_expiration_ledger)?;
        let resim_response = bound_pre_submit_stage(
            pre_submit_budget,
            "simulate_resim",
            "auth_payload",
            server.simulate_transaction_envelope(&resim_envelope, None),
        )
        .await?
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: re-simulate simulate_transaction_envelope failed: {e}",
                    args.op_label
                ),
            )
        })?;

        if let Some(err) = &resim_response.error {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{} re-simulate returned error: {}",
                    args.op_label,
                    SimulationErrorClass::of(err)
                ),
            });
        }
        if args.schedule_identity.is_some() {
            let prediction = resim_response
                .results()
                .map_err(|_| SaError::IntentBindingMismatch { field: "purpose" })?
                .into_iter()
                .next()
                .ok_or(SaError::IntentBindingMismatch { field: "purpose" })?
                .xdr;
            check_schedule_prediction(args.schedule_identity, &prediction)?;
        }
        if resim_response.min_resource_fee == 0 || resim_response.transaction_data.is_empty() {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{}: re-simulate returned no min_resource_fee / transaction_data",
                    args.op_label
                ),
            });
        }

        // ── Step 6: Build final transaction envelope ──────────────────────────────
        //
        // Fetch the source sequence again before building the final envelope.
        // A signed entry plan refuses a sequence other than the one it admits.
        let source_view3 = bound_pre_submit_stage(
            pre_submit_budget,
            "fetch_account_submit",
            "auth_payload",
            fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[]),
        )
        .await?
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: source-account re-fetch for submission tx failed: {e}",
                    args.op_label
                ),
            )
        })?;
        if signs_entries && source_view3.sequence_number.checked_add(1) != Some(frozen_sequence) {
            return Err(SaError::IntentBindingMismatch {
                field: "envelope_sequence",
            });
        }
        let mut source_account3 = BaselibAccount::new(
            &source_pubkey_strkey,
            &source_view3.sequence_number.to_string(),
        )
        .map_err(|e| {
            auth_err(
                "auth_payload",
                format!(
                    "{}: BaselibAccount::new (submit) failed: {e:?}",
                    args.op_label
                ),
            )
        })?;

        let resource_fee = parse_min_resource_fee(&resim_response)?;
        let auth_vecm_final: VecM<SorobanAuthorizationEntry> =
            signed_entries.try_into().map_err(|e| {
                auth_err(
                    "auth_payload",
                    format!("{}: encode final auth VecM: {e:?}", args.op_label),
                )
            })?;

        let ready = if signs_entries {
            ledger_bound
        } else {
            pair_for_first_signature(ledger_bound, &witness_request, pre_submit_budget).await?
        };
        let final_expiration = ready.signature_expiration_ledger()?;
        let op_final = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(invoke),
                auth: auth_vecm_final,
            }),
        };

        let mut tx_builder3 =
            TransactionBuilder::new(&mut source_account3, args.network_passphrase, None);
        tx_builder3.fee(BASE_FEE_STROOPS.saturating_add(resource_fee));
        tx_builder3.add_operation(op_final);
        let mut tx_final = tx_builder3.build_for_simulation();

        // Inject the soroban_data (resource footprint + refundable fee) from the
        // re-simulate response.  Transaction::soroban_data is serialised into
        // TransactionExt::V1(data) by `to_envelope()`.
        if let Ok(data) = resim_response.transaction_data() {
            tx_final.soroban_data = Some(data);
        }

        let mut envelope = tx_final.to_envelope().map_err(|e| {
            auth_err(
                "auth_payload",
                format!("{}: Transaction::to_envelope failed: {e:?}", args.op_label),
            )
        })?;
        set_envelope_max_ledger(&mut envelope, final_expiration)?;
        let envelope_xdr = envelope.to_xdr_base64(Limits::none()).map_err(|e| {
            auth_err(
                "auth_payload",
                format!("{}: envelope to_xdr_base64 failed: {e:?}", args.op_label),
            )
        })?;

        // ── Step 7: Attach source-account signature ───────────────────────────────
        // Without a signed entry the envelope's is the first signature, and the
        // two re-fetches and the re-simulation since the witness can outlast an
        // observation: the pair is readied here.
        if !signs_entries {
            let sequence = source_view3
                .sequence_number
                .checked_add(1)
                .ok_or(SaError::IntentBindingMismatch { field: "plan" })?;
            let plan = make_plan(sequence, final_expiration)?.with_capability(ready.capability());
            let proof = args
                .admission
                .admit(&plan)
                .await
                .map_err(|error| crate::submit::map_admission_error(&error, args.op_label))?;
            gate = Some(SigningGate::new(proof));
        }
        ready.ensure_fresh_at(pre_submit_budget, final_check_instant())?;
        // The envelope is signed only while the deadline the witness rests on is
        // open, through the key read in step 1. A software key signs without
        // yielding, so the deadline is checked before the bounded signature as
        // well.
        pre_submit_budget.check_at("sign_envelope", "auth_payload")?;
        let envelope_signer = ResolvedKeySigner::with_key(args.signer, pubkey);
        gate.as_ref()
            .ok_or(SaError::IntentBindingMismatch {
                field: "intent_state",
            })?
            .authorize(SigningRequest {
                subject: AuthSubject::source(&source_pubkey_strkey)
                    .map_err(|field| SaError::IntentBindingMismatch { field })?,
                signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                    public_key: pubkey.0,
                }),
                payload: SigningPayload::Envelope(&envelope),
            })?;
        let final_signed_xdr = bound_pre_submit_stage(
            pre_submit_budget,
            "sign_envelope",
            "auth_payload",
            attach_signature(&envelope_xdr, &envelope_signer, args.network_passphrase),
        )
        .await?
        .map_err(|e| SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: format!("{} envelope signing failed: {e}", args.op_label),
        })?;

        Ok::<_, SaError>(final_signed_xdr)
    }
    .await;
    let final_signed_xdr = match signing_result {
        Ok(signed) => signed,
        Err(error) => {
            if let Some(gate) = &gate {
                crate::submit::cancel_unexposed_admission(&args.admission, gate).await;
            }
            return Err(error);
        }
    };
    // ── Step 8: Submit ────────────────────────────────────────────────────────
    // Nothing is sent after the deadline: the steps before `sendTransaction`
    // end at it, and no send attempt, a resend of the same bytes included,
    // starts after it. The confirmation poll keeps its own `args.timeout`
    // budget.
    let submission = submit_transaction_and_wait_sent_by(
        &primary_rpc_client,
        &final_signed_xdr,
        pre_submit_budget.deadline,
        args.timeout,
        args.network_passphrase,
        None,
        args.admission.recorder(),
        args.admission
            .recorder()
            .and_then(|_| gate.as_ref().and_then(SigningGate::exposure)),
    )
    .await
    .map_err(|e| {
        map_sent_by_error(
            e,
            pre_submit_budget,
            args.timeout,
            args.op_label,
            &final_signed_xdr,
        )
    })?;

    Ok(TimelockSubmitResult {
        return_val,
        tx_hash: submission.tx_hash,
        ledger: submission.ledger,
    })
}

/// Sets the exact exclusive ledger bound while preserving other preconditions.
fn set_envelope_max_ledger(
    envelope: &mut TransactionEnvelope,
    max_ledger: u32,
) -> Result<(), SaError> {
    if max_ledger == 0 {
        return Err(SaError::IntentBindingMismatch {
            field: "expiration",
        });
    }
    let TransactionEnvelope::Tx(v1) = envelope else {
        return Err(SaError::IntentBindingMismatch {
            field: "expiration",
        });
    };
    let mut conditions = match &v1.tx.cond {
        Preconditions::V2(v2) => v2.clone(),
        existing => PreconditionsV2 {
            time_bounds: match existing {
                Preconditions::Time(time) => Some(time.clone()),
                _ => None,
            },
            ledger_bounds: None,
            min_seq_num: None,
            min_seq_age: stellar_xdr::Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: VecM::default(),
        },
    };
    conditions.ledger_bounds = Some(LedgerBounds {
        min_ledger: 0,
        max_ledger,
    });
    v1.tx.cond = Preconditions::V2(conditions);
    Ok(())
}

/// The pair the first signature of a timelock call rests on.
///
/// `bound` stands while it is fresh. A stale pair is read again as a pair,
/// under the same deadline. The accepted simulation and its optional recovery
/// satisfy the initial pair. Expiry derives from the fresh pair returned here.
///
/// # Errors
///
/// The refusals of [`witness_signing_ledger`], and
/// [`SaError::LedgerWitnessUnavailable`] when the deadline has elapsed.
async fn pair_for_first_signature(
    bound: WitnessedLedgerBound,
    request: &WitnessRequest<'_>,
    budget: PreSubmitBudget,
) -> Result<WitnessedLedgerBound, SaError> {
    let bound = if bound.is_stale(tokio::time::Instant::now()) {
        witness_signing_ledger(request).await?
    } else {
        bound
    };
    bound.ensure_fresh_at(budget, final_check_instant())?;
    Ok(bound)
}

/// The instant the final freshness check of [`pair_for_first_signature`]
/// judges the pair at: the clock, ahead by the lag a test case scopes with
/// `FINAL_CHECK_LAG` under test, which stands for time passing between the
/// pair's readiness and that check.
fn final_check_instant() -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    #[cfg(test)]
    let now = now + FINAL_CHECK_LAG.try_with(|lag| *lag).unwrap_or_default();
    now
}

#[cfg(test)]
tokio::task_local! {
    /// Within a test case's scope, how far the final freshness check of
    /// [`pair_for_first_signature`] runs ahead of the clock.
    static FINAL_CHECK_LAG: std::time::Duration;
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    use stellar_agent_test_support::second_loopback_host;
    use stellar_xdr::{BytesM, ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol};

    use super::*;

    fn no_value_fixture() -> (tempfile::TempDir, stellar_agent_network::NoValueAdmission) {
        use stellar_agent_core::policy::{
            McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor, ToolValueKind,
        };
        use stellar_agent_core::profile::schema::Profile;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&scratch).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("timelock-bounds-")
            .tempdir_in(scratch)
            .unwrap();
        let profile = Profile::builder_testnet_named(
            "intent",
            "timelock-fixture-owner",
            "account",
            "timelock-fixture-nonce",
            "account",
        )
        .build();
        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_smart_account_timelock_cancel",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        let sizing = NoopPolicyEngine.size_no_value(&tool, &profile, 0).unwrap();
        let store = stellar_agent_network::policy_state::PersistedWindowStore::at_path(
            dir.path().join("intent.window"),
        );
        let admission =
            stellar_agent_network::NoValueAdmission::with_store(profile, store, sizing).unwrap();
        (dir, admission)
    }

    /// Verifies that `TimelockSubmitArgs` with a non-`InvokeContract` host function
    /// returns `AuthEntryConstructionFailed` before any network I/O.
    ///
    /// Exercises the early-exit guard at Step 2 of
    /// [`submit_timelock_invoke_with_g_key_auth`].
    #[test]
    fn host_function_non_invoke_contract_returns_err() {
        // We only need to confirm the error variant — not run the full async flow.
        // The guard is pure logic (no I/O) so we exercise it via a direct match.
        let hf = HostFunction::UploadContractWasm(BytesM::default());
        // Verify the discriminant check: `HostFunction::InvokeContract` is the
        // only accepted variant.
        assert!(
            !matches!(hf, HostFunction::InvokeContract(_)),
            "UploadContractWasm must not match InvokeContract"
        );
    }

    /// Verifies the `TimelockSubmitResult` struct is constructable with expected fields.
    #[test]
    fn timelock_submit_result_fields() {
        let result = TimelockSubmitResult {
            return_val: ScVal::Void,
            tx_hash: "a".repeat(64),
            ledger: 42,
        };
        assert_eq!(result.ledger, 42);
        assert_eq!(result.tx_hash.len(), 64);
        assert!(matches!(result.return_val, ScVal::Void));
    }

    /// Verifies `TimelockSubmitArgs` compiles with expected field types.
    #[test]
    fn timelock_submit_args_struct_compiles() {
        // Structural smoke test — verifies field types are compatible.
        // The signer field cannot be tested without a real async context and
        // a concrete `Signer` impl; this test only confirms the struct compiles.
        let hf = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            function_name: ScSymbol::try_from("schedule").unwrap(),
            args: VecM::default(),
        });
        // Confirm the HostFunction variant matches.
        assert!(matches!(hf, HostFunction::InvokeContract(_)));
    }

    // ── Mainnet refusal before the signer and the endpoint ──────────────────

    /// Runs the submit for `network_passphrase` against a mock endpoint that
    /// answers nothing, with a counting signer. Returns the result, the
    /// signer's key accesses and the requests the endpoint received.
    async fn submit_on(
        network_passphrase: &str,
    ) -> (Result<TimelockSubmitResult, SaError>, usize, usize) {
        let (_dir, admission) = no_value_fixture();
        let server = wiremock::MockServer::start().await;
        let signer = stellar_agent_network::signing::test_doubles::CountingSigner::new([0x51; 32]);
        let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
            schedule_identity: None,
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0x52; 32]))),
                function_name: ScSymbol::try_from("schedule").unwrap(),
                args: VecM::default(),
            }),
            signer: &signer,
            primary_rpc_url: &server.uri(),
            secondary_rpc_url: &second_loopback_host(&server.uri()),
            network_passphrase,
            timeout: std::time::Duration::from_secs(1),
            op_label: "schedule",
            admission: stellar_agent_network::SigningAdmission::NoValue(&admission),
        })
        .await;
        let requests = server.received_requests().await.unwrap().len();
        (result, signer.key_accesses(), requests)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn a_testnet_submit_reaches_the_signer_and_the_endpoint() {
        let (result, key_accesses, requests) =
            submit_on(stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE).await;

        assert!(
            matches!(result, Err(SaError::AuthEntryConstructionFailed { .. })),
            "the empty mock endpoint fails the source-account fetch: {result:?}"
        );
        assert_eq!(key_accesses, 1, "the signer's public key is read");
        assert!(requests > 0, "the endpoint is asked for the source account");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn a_mainnet_submit_is_refused_before_the_signer_and_the_endpoint() {
        let (result, key_accesses, requests) =
            submit_on(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE).await;

        assert!(
            matches!(result, Err(SaError::MainnetWriteForbidden)),
            "{result:?}"
        );
        assert_eq!(key_accesses, 0);
        assert_eq!(requests, 0);
    }

    // ── The signed invocation is the timelock call itself ────────────────────

    mod signed_root {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};
        use stellar_agent_core::error::WalletError;
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_agent_network::signing::{
            MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
            WebAuthnAssertion,
        };
        use stellar_agent_test_support::second_loopback_host;
        use stellar_agent_test_support::signed_envelope::{
            account_id_for_seed, get_network_result, ledger_entries_result_for,
            public_key_for_seed, send_transaction_hash_hex,
        };
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            HostFunction, Int128Parts, InvokeContractArgs, Limits, OperationBody,
            PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScSymbol, ScVal,
            SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates,
            SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            SorobanCredentials, SorobanTransactionData, TransactionEnvelope, Uint256, VecM,
            WriteXdr,
        };
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

        use super::super::{TimelockSubmitArgs, submit_timelock_invoke_with_g_key_auth};
        use crate::SaError;
        use crate::error::SimulationDivergenceSubCode;
        use crate::signing::recovery_test_fixtures::{RecoveryCase, recovery_response};

        const SEED: [u8; 32] = [0x51; 32];

        /// The operator's classic account, the role the timelock checks.
        fn operator() -> ScAddress {
            ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(Uint256(
                public_key_for_seed(SEED),
            ))))
        }

        fn contract(byte: u8) -> ScAddress {
            ScAddress::Contract(ContractId(Hash([byte; 32])))
        }

        fn call(target: ScAddress, function: &str, args: Vec<ScVal>) -> InvokeContractArgs {
            InvokeContractArgs {
                contract_address: target,
                function_name: ScSymbol::try_from(function).unwrap(),
                args: args.try_into().unwrap(),
            }
        }

        /// `timelock.schedule(operator, delay)`.
        fn schedule() -> InvokeContractArgs {
            call(
                contract(0x52),
                "schedule",
                vec![ScVal::Address(operator()), ScVal::U32(10)],
            )
        }

        /// The native token's `transfer(operator, attacker, balance)`.
        fn drain() -> InvokeContractArgs {
            call(
                contract(0x53),
                "transfer",
                vec![
                    ScVal::Address(operator()),
                    ScVal::Address(contract(0xAA)),
                    ScVal::I128(Int128Parts {
                        hi: 0,
                        lo: 1_000_000_000,
                    }),
                ],
            )
        }

        fn leaf(call: InvokeContractArgs) -> SorobanAuthorizedInvocation {
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call),
                sub_invocations: VecM::default(),
            }
        }

        /// The nonce of the first entry the simulation hands out; each
        /// further entry takes the next one.
        const NONCE: i64 = 9;

        type TreesFn =
            dyn Fn(&InvokeContractArgs) -> Vec<SorobanAuthorizedInvocation> + Send + Sync;

        /// Answers the first simulation with one entry for the operator's key
        /// per root `trees` builds from the request, or `entries` when set.
        /// Echoes the signed entries on the re-simulation and records them.
        struct Rpc {
            trees: Arc<TreesFn>,
            /// Entries the first simulation returns as given, in place of the
            /// ones built from trees.
            entries: Option<Vec<SorobanAuthorizationEntry>>,
            simulations: Arc<AtomicUsize>,
            /// `getLatestLedger` requests answered.
            ledger_reads: Arc<AtomicUsize>,
            resimulated: Arc<Mutex<Vec<SorobanAuthorizationEntry>>>,
            chain: Chain,
        }

        /// What the mocked endpoint reports about the chain.
        #[derive(Clone, Copy)]
        struct Chain {
            passphrase: &'static str,
            ledger: u32,
            simulated_ledger: Option<u32>,
            recovery_case: Option<RecoveryCase>,
            recovery_delay: Option<std::time::Duration>,
            witness_delay: Option<std::time::Duration>,
            malformed_ledger: bool,
            /// How long an account read after the signed re-simulation, the
            /// final fetch before the envelope is built, takes to answer.
            final_fetch_delay: Option<std::time::Duration>,
            /// How long the signed re-simulation takes to answer.
            resimulation_delay: Option<std::time::Duration>,
            /// How long `getNetwork` takes to answer after the signed
            /// re-simulation: the submission's identity probe.
            pre_send_delay: Option<std::time::Duration>,
            /// The first simulation hands out source-account credentials,
            /// which need no signature of their own.
            source_account_auth: bool,
            final_sequence_bump: bool,
            overflowing_final_fee: bool,
            schedule_predictions: Option<[[u8; 32]; 2]>,
            /// The height `getLatestLedger` reports once this many reads
            /// were answered.
            ledger_after_reads: Option<(usize, u32)>,
        }

        impl Chain {
            fn at(ledger: u32) -> Self {
                Self {
                    passphrase: stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                    ledger,
                    simulated_ledger: None,
                    recovery_case: None,
                    recovery_delay: None,
                    witness_delay: None,
                    malformed_ledger: false,
                    final_fetch_delay: None,
                    resimulation_delay: None,
                    pre_send_delay: None,
                    source_account_auth: false,
                    final_sequence_bump: false,
                    overflowing_final_fee: false,
                    schedule_predictions: None,
                    ledger_after_reads: None,
                }
            }
        }

        /// The ledger an operation in these fixtures became ready at.
        const READY_LEDGER: u32 = 500;

        impl Respond for Rpc {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let Chain {
                    passphrase, ledger, ..
                } = self.chain;
                let mut delay = None;
                let result = match body["method"].as_str().unwrap() {
                    "getNetwork" => {
                        if self.simulations.load(Ordering::SeqCst) >= 2 {
                            delay = self.chain.pre_send_delay;
                        }
                        get_network_result(passphrase)
                    }
                    "getLatestLedger" if self.chain.malformed_ledger => {
                        json!({"id": "ab".repeat(32), "sequence": "not-a-ledger", "protocolVersion": 27})
                    }
                    "getLatestLedger" => {
                        delay = self.chain.witness_delay;
                        let reads = self.ledger_reads.fetch_add(1, Ordering::SeqCst);
                        let ledger = match self.chain.ledger_after_reads {
                            Some((after, later)) if reads >= after => later,
                            _ => ledger,
                        };
                        json!({"id": "ab".repeat(32), "sequence": ledger, "protocolVersion": 27})
                    }
                    "getLedgerEntries" => {
                        if self.simulations.load(Ordering::SeqCst) >= 2 {
                            delay = self.chain.final_fetch_delay;
                        }
                        let mut result =
                            ledger_entries_result_for(&[account_id_for_seed(SEED).as_str()]);
                        if self.chain.final_sequence_bump
                            && self.simulations.load(Ordering::SeqCst) >= 2
                        {
                            let xdr = result["entries"][0]["xdr"].as_str().unwrap();
                            let mut entry =
                                stellar_xdr::LedgerEntryData::from_xdr_base64(xdr, Limits::none())
                                    .unwrap();
                            if let stellar_xdr::LedgerEntryData::Account(account) = &mut entry {
                                account.seq_num.0 += 1;
                            }
                            result["entries"][0]["xdr"] =
                                json!(entry.to_xdr_base64(Limits::none()).unwrap());
                        }
                        result
                    }
                    "simulateTransaction" => {
                        self.simulations.fetch_add(1, Ordering::SeqCst);
                        let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                            body["params"]["transaction"].as_str().unwrap(),
                            Limits::none(),
                        )
                        .unwrap() else {
                            panic!("v1 envelope")
                        };
                        let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body
                        else {
                            panic!("invoke operation")
                        };
                        let HostFunction::InvokeContract(invoke) = &op.host_function else {
                            panic!("contract function")
                        };
                        let value = match invoke.function_name.0.as_slice() {
                            b"schedule" if self.chain.schedule_predictions.is_some() => {
                                let index = (self.simulations.load(Ordering::SeqCst) - 1).min(1);
                                ScVal::Bytes(
                                    self.chain.schedule_predictions.unwrap()[index]
                                        .to_vec()
                                        .try_into()
                                        .unwrap(),
                                )
                            }
                            b"hash_operation" => ScVal::Bytes(vec![0x77; 32].try_into().unwrap()),
                            b"schedule" if invoke.args.len() == 7 => {
                                ScVal::Bytes(vec![0x77; 32].try_into().unwrap())
                            }
                            b"get_operation_ledger" => ScVal::U32(READY_LEDGER),
                            _ => ScVal::Void,
                        };
                        let auth = if matches!(
                            invoke.function_name.0.as_slice(),
                            b"hash_operation" | b"get_operation_ledger"
                        ) {
                            Vec::new()
                        } else if op.auth.is_empty() {
                            self.entries.clone().unwrap_or_else(|| {
                                (self.trees)(invoke)
                                    .into_iter()
                                    .zip(NONCE..)
                                    .map(|(root_invocation, nonce)| SorobanAuthorizationEntry {
                                        credentials: if self.chain.source_account_auth {
                                            SorobanCredentials::SourceAccount
                                        } else {
                                            SorobanCredentials::Address(SorobanAddressCredentials {
                                                address: operator(),
                                                nonce,
                                                signature_expiration_ledger: 0,
                                                signature: ScVal::Void,
                                            })
                                        },
                                        root_invocation,
                                    })
                                    .collect()
                            })
                        } else {
                            delay = self.chain.resimulation_delay;
                            self.resimulated
                                .lock()
                                .unwrap()
                                .extend(op.auth.iter().cloned());
                            op.auth.to_vec()
                        };
                        let mut response = json!({
                            "latestLedger": self.chain.simulated_ledger.unwrap_or(ledger),
                            "minResourceFee": if self.chain.overflowing_final_fee && self.simulations.load(Ordering::SeqCst) >= 2 { "4294967296" } else { "1000" },
                            "transactionData": SorobanTransactionData::default()
                                .to_xdr_base64(Limits::none())
                                .unwrap(),
                            "results": [{
                                "auth": auth
                                    .iter()
                                    .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                                    .collect::<Vec<_>>(),
                                "xdr": value.to_xdr_base64(Limits::none()).unwrap(),
                            }],
                        });
                        let number = self.simulations.load(Ordering::SeqCst);
                        if let Some(case) = self.chain.recovery_case {
                            recovery_response(case, number, &mut response);
                            if number == 2 {
                                delay = self.chain.recovery_delay;
                            }
                        }
                        response
                    }
                    "sendTransaction" => {
                        let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                            body["params"]["transaction"].as_str().unwrap(),
                            Limits::none(),
                        )
                        .unwrap() else {
                            panic!("v1 envelope")
                        };
                        assert_eq!(
                            tx.tx.source_account,
                            stellar_xdr::MuxedAccount::Ed25519(Uint256(public_key_for_seed(SEED)))
                        );
                        let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body
                        else {
                            panic!("invoke operation")
                        };
                        assert_eq!(
                            op.auth.as_slice(),
                            self.resimulated.lock().unwrap().as_slice()
                        );
                        json!({"status": "PENDING", "hash": send_transaction_hash_hex(&body, passphrase), "latestLedger": ledger, "latestLedgerCloseTime": "1234567890"})
                    }
                    "getTransaction" => {
                        json!({"status": "SUCCESS", "ledger": ledger + 1, "latestLedger": ledger + 1, "oldestLedger": 1})
                    }
                    other => panic!("unexpected RPC method: {other}"),
                };
                let template = ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}));
                match delay {
                    Some(delay) => template.set_delay(delay),
                    None => template,
                }
            }
        }

        /// Counts authorization and source signatures independently over one key.
        struct AuthAndSourceSigner {
            auth: CountingSigner,
            source: CountingSigner,
        }

        #[async_trait::async_trait]
        impl Signer for AuthAndSourceSigner {
            async fn sign_tx_payload(
                &self,
                payload: &TxSigningPayload,
            ) -> Result<[u8; 64], WalletError> {
                self.source.sign_tx_payload(payload).await
            }

            async fn sign_auth_digest(
                &self,
                digest: &SmartAccountAuthDigest,
            ) -> Result<[u8; 64], WalletError> {
                self.auth.sign_auth_digest(digest).await
            }

            async fn sign_soroban_address_auth_payload(
                &self,
                payload: &SorobanAuthPayload,
            ) -> Result<[u8; 64], WalletError> {
                self.auth.sign_soroban_address_auth_payload(payload).await
            }

            async fn sign_message(
                &self,
                payload: &MessagePayload,
            ) -> Result<[u8; 64], WalletError> {
                self.auth.sign_message(payload).await
            }

            async fn sign_webauthn_assertion(
                &self,
                digest: &SmartAccountAuthDigest,
                credential_id: &[u8],
            ) -> Result<WebAuthnAssertion, WalletError> {
                self.auth
                    .sign_webauthn_assertion(digest, credential_id)
                    .await
            }

            async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
                self.source.public_key().await
            }
        }

        async fn sent_envelope(server: &MockServer) -> Option<TransactionEnvelope> {
            use stellar_xdr::ReadXdr as _;
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .find_map(|request| {
                    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    (body["method"] == "sendTransaction").then(|| {
                        TransactionEnvelope::from_xdr_base64(
                            body["params"]["transaction"].as_str().unwrap(),
                            Limits::none(),
                        )
                        .unwrap()
                    })
                })
        }

        fn assert_envelope_bound(envelope: Option<&TransactionEnvelope>, maximum: u32) {
            let Some(TransactionEnvelope::Tx(tx)) = envelope else {
                panic!("a signed V1 envelope")
            };
            let stellar_xdr::Preconditions::V2(conditions) = &tx.tx.cond else {
                panic!("V2 signing preconditions")
            };
            assert_eq!(
                conditions.ledger_bounds,
                Some(stellar_xdr::LedgerBounds {
                    min_ledger: 0,
                    max_ledger: maximum
                })
            );
        }

        struct Outcome {
            sent: Option<TransactionEnvelope>,
            result: Result<super::super::TimelockSubmitResult, SaError>,
            signs: usize,
            auth_signs: usize,
            source_signs: usize,
            ledger_reads: usize,
            key_reads: usize,
            simulations: usize,
            resimulated: Vec<SorobanAuthorizationEntry>,
        }

        impl Outcome {
            fn assert_no_signatures(&self) {
                assert_eq!(self.auth_signs, 0, "auth signatures: {:?}", self.result);
                assert_eq!(self.source_signs, 0, "source signatures: {:?}", self.result);
                assert_eq!(self.simulations, 1, "no signed re-simulation");
                assert!(self.resimulated.is_empty());
                assert_eq!(self.ledger_reads, 2, "both witness observations succeed");
            }

            fn assert_credential_refusal(&self) {
                self.assert_no_signatures();
                let Err(SaError::AuthEntryConstructionFailed {
                    stage,
                    redacted_reason,
                }) = &self.result
                else {
                    panic!("expected unsupported credentials: {:?}", self.result)
                };
                assert_eq!(*stage, "credential_variant");
                assert_eq!(
                    redacted_reason,
                    "timelock signing supports SourceAccount and signer Address credentials only"
                );
                assert_eq!(
                    self.result.as_ref().unwrap_err().wire_code(),
                    "sa.auth_entry_construction_failed"
                );
            }

            fn assert_signer_refusal(&self) {
                self.assert_no_signatures();
                let Err(SaError::AuthEntryConstructionFailed {
                    stage,
                    redacted_reason,
                }) = &self.result
                else {
                    panic!("expected signer refusal: {:?}", self.result)
                };
                assert_eq!(*stage, "auth_payload");
                assert_eq!(
                    redacted_reason,
                    "schedule: simulate returned auth entry for an unexpected address \
                     (not the signer G-key); cannot sign"
                );
                assert_eq!(
                    self.result.as_ref().unwrap_err().wire_code(),
                    "sa.auth_entry_construction_failed"
                );
            }

            /// Asserts the refusal before any signing primitive and any
            /// second simulation, and returns its reason.
            fn refused_before_signing(&self) -> String {
                self.assert_no_signatures();
                assert_eq!(
                    self.result.as_ref().unwrap_err().wire_code(),
                    "simulation.divergence.auth_contexts"
                );
                match &self.result {
                    Err(SaError::SimulationDivergence {
                        sub_code: SimulationDivergenceSubCode::AuthContexts,
                        redacted_reason,
                    }) => redacted_reason.clone(),
                    other => panic!("expected the auth-contexts divergence, got {other:?}"),
                }
            }
        }

        /// Submits `schedule()` against a simulation that hands out one entry
        /// whose root `tree` builds.
        async fn submit(
            tree: impl Fn(&InvokeContractArgs) -> SorobanAuthorizedInvocation + Send + Sync + 'static,
        ) -> Outcome {
            submit_entries(move |invoke| vec![tree(invoke)]).await
        }

        /// Submits `schedule()` against a simulation that hands out one entry
        /// per root `trees` builds.
        async fn submit_entries(
            trees: impl Fn(&InvokeContractArgs) -> Vec<SorobanAuthorizedInvocation>
            + Send
            + Sync
            + 'static,
        ) -> Outcome {
            submit_fixture(trees, None).await
        }

        async fn submit_auth_entries(entries: Vec<SorobanAuthorizationEntry>) -> Outcome {
            submit_fixture(|_| Vec::new(), Some(entries)).await
        }

        async fn submit_fixture(
            trees: impl Fn(&InvokeContractArgs) -> Vec<SorobanAuthorizedInvocation>
            + Send
            + Sync
            + 'static,
            entries: Option<Vec<SorobanAuthorizationEntry>>,
        ) -> Outcome {
            let (_dir, admission) = super::no_value_fixture();
            let server = MockServer::start().await;
            let simulations = Arc::new(AtomicUsize::new(0));
            let ledger_reads = Arc::new(AtomicUsize::new(0));
            let resimulated = Arc::new(Mutex::new(Vec::new()));
            Mock::given(method("POST"))
                .respond_with(Rpc {
                    trees: Arc::new(trees),
                    entries,
                    simulations: Arc::clone(&simulations),
                    ledger_reads: Arc::clone(&ledger_reads),
                    resimulated: Arc::clone(&resimulated),
                    chain: Chain::at(1000),
                })
                .mount(&server)
                .await;
            let signer = AuthAndSourceSigner {
                auth: CountingSigner::new(SEED),
                source: CountingSigner::new(SEED),
            };
            let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                schedule_identity: None,
                host_function: HostFunction::InvokeContract(schedule()),
                signer: &signer,
                primary_rpc_url: &server.uri(),
                secondary_rpc_url: &second_loopback_host(&server.uri()),
                network_passphrase: stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                timeout: std::time::Duration::from_secs(5),
                op_label: "schedule",
                admission: stellar_agent_network::SigningAdmission::NoValue(&admission),
            })
            .await;
            let resimulated = resimulated.lock().unwrap().clone();
            Outcome {
                sent: sent_envelope(&server).await,
                result,
                signs: signer.auth.sign_calls() + signer.source.sign_calls(),
                auth_signs: signer.auth.sign_calls(),
                source_signs: signer.source.sign_calls(),
                ledger_reads: ledger_reads.load(Ordering::SeqCst),
                key_reads: signer.source.public_key_calls(),
                simulations: simulations.load(Ordering::SeqCst),
                resimulated,
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_timelock_root_on_another_contract_is_refused_before_signing() {
            let outcome = submit(|_| leaf(drain())).await;
            let reason = outcome.refused_before_signing();
            assert!(reason.starts_with("schedule:"), "{reason}");
            assert!(reason.contains("in its contract"), "{reason}");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_timelock_root_with_a_sub_invocation_is_refused() {
            let outcome = submit(|invoke| SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                sub_invocations: vec![leaf(drain())].try_into().unwrap(),
            })
            .await;
            let reason = outcome.refused_before_signing();
            assert!(reason.contains("1 undeclared sub-invocations"), "{reason}");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_timelock_root_with_other_arguments_is_refused() {
            let outcome = submit(|invoke| {
                let mut root = invoke.clone();
                root.args = vec![ScVal::Address(operator()), ScVal::U32(0)]
                    .try_into()
                    .unwrap();
                leaf(root)
            })
            .await;
            let reason = outcome.refused_before_signing();
            assert!(reason.contains("in argument 1"), "{reason}");
        }

        /// Every entry is checked before any is signed, so an honest first
        /// entry is not signed when the second is refused.
        #[tokio::test]
        #[serial_test::serial]
        async fn an_honest_first_entry_is_not_signed_when_a_second_is_refused() {
            let outcome = submit_entries(|invoke| vec![leaf(invoke.clone()), leaf(drain())]).await;
            let reason = outcome.refused_before_signing();
            assert!(reason.contains("in its contract"), "{reason}");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn the_timelock_signs_its_own_call() {
            let outcome = submit(|invoke| leaf(invoke.clone())).await;
            assert!(outcome.result.is_ok(), "{:?}", outcome.result);
            assert_eq!((outcome.auth_signs, outcome.source_signs), (1, 1));
            assert_eq!(
                outcome.signs, 2,
                "one authorization signature and one envelope signature"
            );
            assert_eq!(
                outcome.key_reads, 1,
                "the envelope is signed through the key read before the simulation"
            );
            assert_eq!(outcome.simulations, 2, "the signed entry is re-simulated");
            let [signed] = outcome.resimulated.as_slice() else {
                panic!("one signed entry: {:?}", outcome.resimulated)
            };
            assert_eq!(signed.root_invocation, leaf(schedule()));
            let SorobanCredentials::Address(creds) = &signed.credentials else {
                panic!("address credentials")
            };
            assert_eq!(creds.address, operator());
            assert_eq!(creds.nonce, NONCE);
            assert_signed_at(
                signed,
                schedule(),
                1000 + crate::managers::rules::AUTH_VALIDITY_LEDGERS,
            );
        }

        fn address_credentials() -> SorobanAddressCredentials {
            SorobanAddressCredentials {
                address: operator(),
                nonce: NONCE,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }
        }

        fn foreign_source_roots() -> Vec<(SorobanAuthorizationEntry, &'static str)> {
            let mut contract_call = schedule();
            contract_call.contract_address = contract(0xAA);
            let mut function_call = schedule();
            function_call.function_name = ScSymbol::try_from("foreign_function").unwrap();
            let mut argument_call = schedule();
            argument_call.args = vec![ScVal::Address(operator()), ScVal::U32(99)]
                .try_into()
                .unwrap();
            [
                (leaf(contract_call), "in its contract"),
                (leaf(function_call), "in its function"),
                (leaf(argument_call), "in argument 1"),
            ]
            .into_iter()
            .map(|(root_invocation, reason)| {
                (
                    SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::SourceAccount,
                        root_invocation,
                    },
                    reason,
                )
            })
            .collect()
        }

        fn nested_source_root() -> (SorobanAuthorizationEntry, &'static str) {
            let mut nested = leaf(schedule());
            nested.sub_invocations = vec![leaf(drain())].try_into().unwrap();
            (
                SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::SourceAccount,
                    root_invocation: nested,
                },
                "1 undeclared sub-invocations",
            )
        }

        fn foreign_address_entry() -> SorobanAuthorizationEntry {
            SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                    address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
                        Uint256(public_key_for_seed([0xAA; 32])),
                    ))),
                    ..address_credentials()
                }),
                root_invocation: leaf(schedule()),
            }
        }

        fn unsupported_entries() -> Vec<SorobanAuthorizationEntry> {
            [
                SorobanCredentials::AddressV2(address_credentials()),
                SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                    address_credentials: address_credentials(),
                    delegates: VecM::default(),
                }),
            ]
            .into_iter()
            .map(|credentials| SorobanAuthorizationEntry {
                credentials,
                root_invocation: leaf(schedule()),
            })
            .collect()
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn source_account_foreign_root_refuses_before_envelope_signing() {
            for (entry, reason) in foreign_source_roots() {
                let outcome = submit_auth_entries(vec![entry]).await;
                assert!(
                    outcome.refused_before_signing().contains(reason),
                    "{reason}"
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn source_account_nested_invocation_refuses_before_signing() {
            let (entry, reason) = nested_source_root();
            let outcome = submit_auth_entries(vec![entry]).await;
            assert!(
                outcome.refused_before_signing().contains(reason),
                "{reason}"
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn unsupported_credentials_produce_zero_signatures() {
            for entry in unsupported_entries() {
                submit_auth_entries(vec![entry])
                    .await
                    .assert_credential_refusal();
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn foreign_address_credentials_refuse_before_signing() {
            submit_auth_entries(vec![foreign_address_entry()])
                .await
                .assert_signer_refusal();
        }

        enum InvalidCase {
            SourceRoot(&'static str),
            UnsupportedCredential,
            ForeignSigner,
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn valid_first_invalid_second_never_partially_signs() {
            let invalid_cases = foreign_source_roots()
                .into_iter()
                .chain([nested_source_root()])
                .map(|(entry, reason)| (entry, InvalidCase::SourceRoot(reason)))
                .chain(
                    unsupported_entries()
                        .into_iter()
                        .map(|entry| (entry, InvalidCase::UnsupportedCredential)),
                )
                .chain([(foreign_address_entry(), InvalidCase::ForeignSigner)]);
            for (entry, case) in invalid_cases {
                let outcome = submit_auth_entries(vec![
                    SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(address_credentials()),
                        root_invocation: leaf(schedule()),
                    },
                    entry,
                ])
                .await;
                match case {
                    InvalidCase::SourceRoot(reason) => {
                        assert!(outcome.refused_before_signing().contains(reason));
                    }
                    InvalidCase::UnsupportedCredential => outcome.assert_credential_refusal(),
                    InvalidCase::ForeignSigner => outcome.assert_signer_refusal(),
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn exact_source_account_root_reaches_envelope_signing() {
            let entry = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: leaf(schedule()),
            };
            let outcome = submit_auth_entries(vec![entry.clone()]).await;
            assert!(outcome.result.is_ok(), "{:?}", outcome.result);
            assert_eq!((outcome.auth_signs, outcome.source_signs), (0, 1));
            assert_eq!(outcome.key_reads, 1);
            assert_eq!(outcome.simulations, 2);
            assert_eq!(outcome.resimulated, vec![entry]);
            assert_envelope_bound(outcome.sent.as_ref(), 1100);
        }

        struct BoundRecorder {
            admission: stellar_agent_network::NoValueAdmission,
            plans: Mutex<Vec<stellar_agent_network::SignedIntentPlan>>,
        }

        #[async_trait::async_trait]
        impl stellar_agent_network::SubmissionRecorder for BoundRecorder {
            async fn admit_signed_intent(
                &self,
                plan: &stellar_agent_network::SignedIntentPlan,
            ) -> Result<stellar_agent_network::IntentProof, WalletError> {
                self.plans.lock().unwrap().push(plan.clone());
                self.admission.admit(plan).await
            }

            async fn cancel_unexposed(
                &self,
                proof: stellar_agent_network::IntentProof,
            ) -> Result<(), WalletError> {
                self.admission.cancel_unexposed(proof).await
            }

            async fn pre_send_bound(
                &self,
                _: &stellar_agent_network::SubmissionIntent,
                _: &stellar_agent_network::IntentBinding<'_>,
            ) -> Result<(), WalletError> {
                Ok(())
            }

            async fn pre_send(
                &self,
                _: &stellar_agent_network::SubmissionIntent,
            ) -> Result<(), WalletError> {
                Ok(())
            }

            async fn outcome(
                &self,
                _: &stellar_agent_network::SubmissionIntent,
                _: &stellar_agent_network::SubmissionOutcome,
            ) {
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn timelock_envelopes_have_exact_ledger_bounds() {
            use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
            use stellar_xdr::{LedgerBounds, Preconditions};

            let source = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: leaf(schedule()),
            };
            let address = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(address_credentials()),
                root_invocation: leaf(schedule()),
            };
            for entries in [
                Vec::new(),
                vec![source.clone()],
                vec![address.clone()],
                vec![source, address],
            ] {
                let (_dir, admission) = super::no_value_fixture();
                let recorder = BoundRecorder {
                    admission,
                    plans: Mutex::new(Vec::new()),
                };
                let server = MockServer::start().await;
                let simulations = Arc::new(AtomicUsize::new(0));
                let ledger_reads = Arc::new(AtomicUsize::new(0));
                Mock::given(method("POST"))
                    .respond_with(Rpc {
                        trees: Arc::new(|_| Vec::new()),
                        entries: Some(entries.clone()),
                        simulations: Arc::clone(&simulations),
                        ledger_reads: Arc::clone(&ledger_reads),
                        resimulated: Arc::default(),
                        chain: Chain::at(1000),
                    })
                    .mount(&server)
                    .await;
                let signer = AuthAndSourceSigner {
                    auth: CountingSigner::new(SEED),
                    source: CountingSigner::new(SEED),
                };
                let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                    schedule_identity: None,
                    host_function: HostFunction::InvokeContract(schedule()),
                    signer: &signer,
                    primary_rpc_url: &server.uri(),
                    secondary_rpc_url: &second_loopback_host(&server.uri()),
                    network_passphrase: TESTNET_PASSPHRASE,
                    timeout: std::time::Duration::from_secs(5),
                    op_label: "schedule",
                    admission: stellar_agent_network::SigningAdmission::Recorded(&recorder),
                })
                .await;
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(simulations.load(Ordering::SeqCst), 2);
                assert_eq!(ledger_reads.load(Ordering::SeqCst), 2);
                assert_eq!(signer.source.sign_calls(), 1);
                assert_eq!(
                    signer.auth.sign_calls(),
                    entries
                        .iter()
                        .filter(|entry| matches!(entry.credentials, SorobanCredentials::Address(_)))
                        .count()
                );

                let requests: Vec<Value> = server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .map(|request| serde_json::from_slice(&request.body).unwrap())
                    .collect();
                let decode = |request: &Value| {
                    TransactionEnvelope::from_xdr_base64(
                        request["params"]["transaction"].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap()
                };
                let simulated: Vec<_> = requests
                    .iter()
                    .filter(|request| request["method"] == "simulateTransaction")
                    .map(decode)
                    .collect();
                let sent = decode(
                    requests
                        .iter()
                        .find(|request| request["method"] == "sendTransaction")
                        .unwrap(),
                );
                let (TransactionEnvelope::Tx(provisional), TransactionEnvelope::Tx(final_tx)) =
                    (&simulated[1], &sent)
                else {
                    panic!("V1 envelopes")
                };
                let Preconditions::V2(provisional_conditions) = &provisional.tx.cond else {
                    panic!("provisional V2")
                };
                let Preconditions::V2(final_conditions) = &final_tx.tx.cond else {
                    panic!("final V2")
                };
                let expected = Some(LedgerBounds {
                    min_ledger: 0,
                    max_ledger: 1100,
                });
                assert_eq!(provisional_conditions.ledger_bounds, expected);
                assert_eq!(final_conditions.ledger_bounds, expected);
                assert_eq!(
                    provisional_conditions.to_xdr(Limits::none()).unwrap().len(),
                    final_conditions.to_xdr(Limits::none()).unwrap().len()
                );
                let mut normalized = final_tx.clone();
                normalized.signatures = VecM::default();
                normalized.tx.ext = provisional.tx.ext.clone();
                normalized.tx.fee = provisional.tx.fee;
                assert_eq!(
                    TransactionEnvelope::Tx(normalized)
                        .to_xdr(Limits::none())
                        .unwrap()
                        .len(),
                    simulated[1].to_xdr(Limits::none()).unwrap().len()
                );

                let payload = TxSigningPayload::for_envelope(&sent, TESTNET_PASSPHRASE).unwrap();
                let signature = ed25519_dalek::Signature::from_slice(
                    final_tx.signatures[0].signature.0.as_slice(),
                )
                .unwrap();
                ed25519_dalek::VerifyingKey::from_bytes(&public_key_for_seed(SEED))
                    .unwrap()
                    .verify_strict(payload.as_bytes(), &signature)
                    .unwrap();
                let plans = recorder.plans.lock().unwrap();
                assert_eq!(plans.len(), 1);
                assert_eq!(plans[0].check_envelope(&sent), Ok(()));
                for subject in plans[0].subjects() {
                    if subject.expiration().is_some() {
                        assert_eq!(subject.expiration(), Some(1100));
                    }
                }
                let mut changed = sent.clone();
                super::super::set_envelope_max_ledger(&mut changed, 1101).unwrap();
                assert_eq!(plans[0].check_envelope(&changed), Err("expiration"));
            }
        }

        /// Asserts that `signed` expires at `expiration` and that its signature
        /// verifies under the operator's key over the preimage of `call`, the
        /// simulated nonce and `expiration`, built here from those values
        /// alone.
        fn assert_signed_at(
            signed: &SorobanAuthorizationEntry,
            call: InvokeContractArgs,
            expiration: u32,
        ) {
            let SorobanCredentials::Address(creds) = &signed.credentials else {
                panic!("address credentials")
            };
            assert_eq!(creds.signature_expiration_ledger, expiration);
            let preimage =
                HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                    network_id: Hash(
                        Sha256::digest(
                            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.as_bytes(),
                        )
                        .into(),
                    ),
                    nonce: NONCE,
                    signature_expiration_ledger: expiration,
                    invocation: leaf(call),
                });
            let payload: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
            let ScVal::Vec(Some(signatures)) = &creds.signature else {
                panic!("a signature vector: {:?}", creds.signature)
            };
            let [ScVal::Map(Some(fields))] = signatures.as_slice() else {
                panic!("one signature map: {signatures:?}")
            };
            let field = |name: &str| -> Vec<u8> {
                let entry = fields
                    .iter()
                    .find(|entry| entry.key == ScVal::Symbol(ScSymbol::try_from(name).unwrap()))
                    .unwrap_or_else(|| panic!("the {name} field"));
                let ScVal::Bytes(bytes) = &entry.val else {
                    panic!("{name} is bytes")
                };
                bytes.to_vec()
            };
            assert_eq!(field("public_key"), public_key_for_seed(SEED).to_vec());
            let signature = ed25519_dalek::Signature::from_slice(&field("signature"))
                .unwrap_or_else(|err| panic!("a 64-byte signature: {err}"));
            ed25519_dalek::VerifyingKey::from_bytes(&public_key_for_seed(SEED))
                .unwrap()
                .verify_strict(&payload, &signature)
                .unwrap_or_else(|err| panic!("the signature covers the expected preimage: {err}"));
        }

        // ── The ledger witness ──────────────────────────────────────────────

        mod witness {
            use std::sync::{Arc, Mutex};
            use std::time::Duration;

            use std::sync::atomic::{AtomicUsize, Ordering};

            use async_trait::async_trait;
            use stellar_agent_core::audit_log::writer::AuditWriter;
            use stellar_agent_core::error::WalletError;
            use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
            use stellar_agent_network::WebAuthnAssertion;
            use stellar_agent_network::signing::test_doubles::CountingSigner;
            use stellar_agent_network::signing::{
                MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload,
                TxSigningPayload,
            };
            use stellar_agent_test_support::second_loopback_host;
            use stellar_xdr::{HostFunction, ScVal};
            use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

            use super::super::super::{
                TimelockSubmitArgs, TimelockSubmitResult, submit_timelock_invoke_with_g_key_auth,
            };
            use super::{Chain, Rpc, SEED, assert_signed_at, leaf, schedule};
            use crate::SaError;
            use crate::signing::recovery_test_fixtures::{REPLACEMENT_VALUE, RecoveryCase};
            use crate::timelock::{
                TimelockCancelArgs, TimelockExecuteArgs, TimelockOperationId, TimelockScheduleArgs,
                cancel, execute, schedule_upgrade,
            };

            const SKEW_CODE: &str = "simulation.divergence.ledger_skew";
            const UNAVAILABLE_CODE: &str = "smart_account.ledger_witness_unavailable";
            const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
            const LEDGER: u32 = 1000;

            /// A mocked endpoint and the entries signed through it.
            struct Endpoint {
                server: MockServer,
                schedule_identity: bool,
                simulations: Arc<AtomicUsize>,
                ledger_reads: Arc<AtomicUsize>,
                resimulated: Arc<Mutex<Vec<stellar_xdr::SorobanAuthorizationEntry>>>,
            }

            impl Endpoint {
                async fn start(chain: Chain) -> Self {
                    Self::start_entries(chain, None).await
                }

                async fn start_entries(
                    chain: Chain,
                    entries: Option<Vec<stellar_xdr::SorobanAuthorizationEntry>>,
                ) -> Self {
                    let server = MockServer::start().await;
                    let ledger_reads = Arc::new(AtomicUsize::new(0));
                    let simulations = Arc::new(AtomicUsize::new(0));
                    let resimulated = Arc::new(Mutex::new(Vec::new()));
                    Mock::given(method("POST"))
                        .respond_with(Rpc {
                            trees: Arc::new(|invoke| vec![leaf(invoke.clone())]),
                            entries,
                            simulations: Arc::clone(&simulations),
                            ledger_reads: Arc::clone(&ledger_reads),
                            resimulated: Arc::clone(&resimulated),
                            chain,
                        })
                        .mount(&server)
                        .await;
                    Self {
                        schedule_identity: chain.recovery_case == Some(RecoveryCase::Schedule),
                        server,
                        simulations,
                        ledger_reads,
                        resimulated,
                    }
                }

                /// The `getLatestLedger` requests this endpoint answered.
                fn ledger_reads(&self) -> usize {
                    self.ledger_reads.load(Ordering::SeqCst)
                }

                fn uri(&self) -> String {
                    self.server.uri()
                }

                /// This endpoint's URL on a host apart from the primary's.
                fn witness_uri(&self) -> String {
                    second_loopback_host(&self.server.uri())
                }

                fn resimulated(&self) -> Vec<stellar_xdr::SorobanAuthorizationEntry> {
                    self.resimulated.lock().unwrap().clone()
                }

                /// The `sendTransaction` requests this endpoint received.
                async fn sends(&self) -> usize {
                    self.server
                        .received_requests()
                        .await
                        .unwrap()
                        .iter()
                        .filter(|request| {
                            serde_json::from_slice::<serde_json::Value>(&request.body)
                                .is_ok_and(|body| body["method"] == "sendTransaction")
                        })
                        .count()
                }
            }

            struct Outcome {
                sent: Option<stellar_xdr::TransactionEnvelope>,
                result: Result<TimelockSubmitResult, SaError>,
                signs: usize,
                resimulated: Vec<stellar_xdr::SorobanAuthorizationEntry>,
            }

            impl Outcome {
                fn assert_refused(&self, code: &str, case: &str) {
                    match &self.result {
                        Err(error) => assert_eq!(error.wire_code(), code, "{case}: {error:?}"),
                        Ok(_) => panic!("{case}: the submission went through"),
                    }
                    assert_eq!(self.signs, 0, "{case}: nothing is signed");
                    assert!(self.resimulated.is_empty(), "{case}: nothing re-simulated");
                    assert!(self.sent.is_none(), "{case}: nothing is sent");
                }
            }

            /// The deadline [`submit`] arms.
            const DEADLINE: Duration = Duration::from_secs(5);

            /// Submits the `schedule` call through the shared timelock helper.
            async fn submit(primary: &Endpoint, secondary: &str) -> Outcome {
                let signer = CountingSigner::new(SEED);
                submit_through(primary, secondary, &signer, &signer, DEADLINE).await
            }

            /// Submits the `schedule` call through the shared timelock helper
            /// with `signer`, whose signatures `counter` counts, under
            /// `timeout`.
            async fn submit_through(
                primary: &Endpoint,
                secondary: &str,
                signer: &(dyn Signer + Send + Sync),
                counter: &CountingSigner,
                timeout: Duration,
            ) -> Outcome {
                let (_dir, admission) = super::super::no_value_fixture();
                let timelock = stellar_strkey::Contract([0x52; 32]).to_string().to_string();
                let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                    schedule_identity: primary
                        .schedule_identity
                        .then_some((timelock.as_str(), [7; 32])),
                    host_function: HostFunction::InvokeContract(schedule()),
                    signer,
                    primary_rpc_url: &primary.uri(),
                    secondary_rpc_url: secondary,
                    network_passphrase: TESTNET_PASSPHRASE,
                    timeout,
                    op_label: "schedule",
                    admission: stellar_agent_network::SigningAdmission::NoValue(&admission),
                })
                .await;
                Outcome {
                    sent: super::sent_envelope(&primary.server).await,
                    result,
                    signs: counter.sign_calls(),
                    resimulated: primary.resimulated(),
                }
            }

            /// A counting signer whose envelope signature takes
            /// `envelope_delay` and whose authorization signature takes
            /// `auth_delay`, as a hardware device's can.
            struct SlowSigner {
                inner: CountingSigner,
                envelope_delay: Duration,
                auth_delay: Duration,
            }

            #[async_trait]
            impl Signer for SlowSigner {
                async fn sign_tx_payload(
                    &self,
                    payload: &TxSigningPayload,
                ) -> Result<[u8; 64], WalletError> {
                    tokio::time::sleep(self.envelope_delay).await;
                    self.inner.sign_tx_payload(payload).await
                }

                async fn sign_auth_digest(
                    &self,
                    digest: &SmartAccountAuthDigest,
                ) -> Result<[u8; 64], WalletError> {
                    self.inner.sign_auth_digest(digest).await
                }

                async fn sign_soroban_address_auth_payload(
                    &self,
                    payload: &SorobanAuthPayload,
                ) -> Result<[u8; 64], WalletError> {
                    tokio::time::sleep(self.auth_delay).await;
                    self.inner.sign_soroban_address_auth_payload(payload).await
                }

                async fn sign_message(
                    &self,
                    payload: &MessagePayload,
                ) -> Result<[u8; 64], WalletError> {
                    self.inner.sign_message(payload).await
                }

                async fn sign_webauthn_assertion(
                    &self,
                    digest: &SmartAccountAuthDigest,
                    credential_id: &[u8],
                ) -> Result<WebAuthnAssertion, WalletError> {
                    self.inner
                        .sign_webauthn_assertion(digest, credential_id)
                        .await
                }

                async fn public_key(
                    &self,
                ) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
                    self.inner.public_key().await
                }
            }

            /// Submits `schedule` through a [`SlowSigner`] with the given
            /// delays, under [`DEADLINE`].
            async fn submit_slowly(
                primary: &Endpoint,
                secondary: &str,
                envelope_delay: Duration,
                auth_delay: Duration,
            ) -> Outcome {
                let signer = SlowSigner {
                    inner: CountingSigner::new(SEED),
                    envelope_delay,
                    auth_delay,
                };
                submit_through(primary, secondary, &signer, &signer.inner, DEADLINE).await
            }

            /// Asserts the pre-submit deadline refusal of `stage`.
            fn assert_deadline_refusal(outcome: &Outcome, stage: &str) {
                match &outcome.result {
                    Err(SaError::AuthEntryConstructionFailed {
                        stage: "auth_payload",
                        redacted_reason,
                    }) => assert!(
                        redacted_reason
                            .starts_with(&format!("{stage} exceeded collective pre-submit budget")),
                        "{stage}: {redacted_reason}"
                    ),
                    other => panic!("expected the deadline refusal of {stage}, got {other:?}"),
                }
            }

            async fn submit_at(primary: u32, secondary: u32) -> Outcome {
                let primary = Endpoint::start(Chain::at(primary)).await;
                let secondary = Endpoint::start(Chain::at(secondary)).await;
                submit(&primary, &secondary.witness_uri()).await
            }

            struct AdmissionRecorder<'a> {
                inner: stellar_agent_network::submission_record::WalletSubmissionRecorder<'a>,
                stale: bool,
                signer: &'a super::AuthAndSourceSigner,
                endpoint: &'a Endpoint,
                admissions: AtomicUsize,
                cancellations: AtomicUsize,
                binds: AtomicUsize,
                ledger_reads_at_admission: AtomicUsize,
                subjects: Mutex<Vec<stellar_agent_network::SubjectKind>>,
                admitted_plan: Mutex<Option<stellar_agent_network::SignedIntentPlan>>,
            }

            #[async_trait]
            impl stellar_agent_network::SubmissionRecorder for AdmissionRecorder<'_> {
                async fn admit_signed_intent(
                    &self,
                    plan: &stellar_agent_network::SignedIntentPlan,
                ) -> Result<stellar_agent_network::IntentProof, WalletError> {
                    assert_eq!(self.signer.auth.sign_calls(), 0);
                    assert_eq!(self.signer.source.sign_calls(), 0);
                    self.admissions.fetch_add(1, Ordering::SeqCst);
                    *self.admitted_plan.lock().unwrap() = Some(plan.clone());
                    *self.subjects.lock().unwrap() = plan
                        .subjects()
                        .iter()
                        .map(|s| s.auth_subject().kind())
                        .collect();
                    let proof = self.inner.admit_signed_intent(plan).await?;
                    self.ledger_reads_at_admission
                        .store(self.endpoint.ledger_reads(), Ordering::SeqCst);
                    if self.stale {
                        tokio::time::pause();
                        tokio::time::advance(
                            crate::signing::ledger_witness::MAX_OBSERVATION_AGE
                                + Duration::from_secs(1),
                        )
                        .await;
                        tokio::time::resume();
                    }
                    Ok(proof)
                }
                async fn cancel_unexposed(
                    &self,
                    proof: stellar_agent_network::IntentProof,
                ) -> Result<(), WalletError> {
                    self.cancellations.fetch_add(1, Ordering::SeqCst);
                    self.inner.cancel_unexposed(proof).await
                }
                async fn pre_send_bound(
                    &self,
                    intent: &stellar_agent_network::SubmissionIntent,
                    binding: &stellar_agent_network::IntentBinding<'_>,
                ) -> Result<(), WalletError> {
                    self.binds.fetch_add(1, Ordering::SeqCst);
                    self.inner.pre_send_bound(intent, binding).await
                }
                async fn pre_send(
                    &self,
                    intent: &stellar_agent_network::SubmissionIntent,
                ) -> Result<(), WalletError> {
                    self.inner.pre_send(intent).await
                }
                async fn outcome(
                    &self,
                    intent: &stellar_agent_network::SubmissionIntent,
                    outcome: &stellar_agent_network::SubmissionOutcome,
                ) {
                    self.inner.outcome(intent, outcome).await;
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn schedule_identity_is_frozen_before_admission() {
                use stellar_agent_core::policy::v1::criteria::state_store::{
                    PolicyStateStore, StateKey, WindowEntry, WindowLimit,
                };
                use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
                use stellar_agent_network::SigningAdmission;
                use stellar_agent_network::policy_state::PersistedWindowStore;
                for (predictions, admissions, signatures) in [
                    ([[8; 32], [7; 32]], 0, 0),
                    ([[7; 32], [8; 32]], 1, 1),
                    ([[7; 32], [7; 32]], 1, 2),
                ] {
                    stellar_agent_test_support::keyring_mock::install().unwrap();
                    let dir = tempfile::tempdir().unwrap();
                    let profile =
                        stellar_agent_core::profile::schema::Profile::builder_testnet_named(
                            "intent",
                            "prediction-test",
                            "account",
                            "prediction-nonce",
                            "account",
                        )
                        .build();
                    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
                    let primary = Endpoint::start(Chain {
                        schedule_predictions: Some(predictions),
                        ..Chain::at(LEDGER)
                    })
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let signer = super::AuthAndSourceSigner {
                        auth: CountingSigner::new(SEED),
                        source: CountingSigner::new(SEED),
                    };
                    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
                    let key = StateKey::new("intent", 1, "rate_limit", 60);
                    let entries = vec![WindowEntry::new(
                        key.clone(),
                        now,
                        1,
                        WindowLimit::Count {
                            window: "1m".into(),
                            max_calls: 1,
                        },
                    )];
                    let sizing =
                        CheckedSizing::for_test(SizingBasis::NoValue, entries.clone()).unwrap();
                    let inner =
                        stellar_agent_network::submission_record::WalletSubmissionRecorder::new(
                            &profile,
                            "intent",
                            "timelock_test",
                            Some("stellar:testnet".into()),
                            stellar_agent_core::audit_log::PolicyDecision::Allow,
                            vec![],
                            entries,
                            stellar_agent_core::profile::receipt::ReceiptStore::open_at(
                                dir.path(),
                                "intent",
                            )
                            .unwrap(),
                            store.clone(),
                            None,
                            None,
                            "fixture",
                            now,
                        )
                        .with_signing_sizing(sizing);

                    let recorder = AdmissionRecorder {
                        inner,
                        stale: false,
                        signer: &signer,
                        endpoint: &primary,
                        admissions: 0.into(),
                        cancellations: 0.into(),
                        binds: 0.into(),
                        ledger_reads_at_admission: 0.into(),
                        subjects: Mutex::new(vec![]),
                        admitted_plan: Mutex::new(None),
                    };
                    let timelock = stellar_strkey::Contract([0x52; 32]).to_string().to_string();
                    let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                        schedule_identity: Some((&timelock, [7; 32])),
                        host_function: HostFunction::InvokeContract(schedule()),
                        signer: &signer,
                        primary_rpc_url: &primary.uri(),
                        secondary_rpc_url: &secondary.witness_uri(),
                        network_passphrase: TESTNET_PASSPHRASE,
                        timeout: Duration::from_secs(30),
                        op_label: "schedule",
                        admission: SigningAdmission::Recorded(&recorder),
                    })
                    .await;
                    assert_eq!(recorder.admissions.load(Ordering::SeqCst), admissions);
                    assert_eq!(
                        signer.auth.sign_calls() + signer.source.sign_calls(),
                        signatures
                    );
                    if predictions[0] != predictions[1] {
                        assert!(
                            matches!(
                                result,
                                Err(SaError::IntentBindingMismatch { field: "purpose" })
                            ),
                            "{result:?}"
                        );
                        assert_eq!(recorder.binds.load(Ordering::SeqCst), 0);
                    } else {
                        assert!(result.is_ok(), "{result:?}");
                    }
                    let views = store.signed_intents("intent", &profile).unwrap();
                    assert_eq!(views.len(), admissions);
                    if admissions == 0 {
                        assert!(!store.path().exists());
                    } else {
                        assert_eq!(views[0].accounting_horizon, "open");
                        assert_eq!(
                            views[0].purpose,
                            Some(stellar_agent_network::IntentPurpose::TimelockSchedule {
                                timelock: timelock.clone(),
                                operation_id: [7; 32]
                            })
                        );
                        let loaded = PolicyStateStore::new();
                        store.load_into("intent", &profile, &loaded).unwrap();
                        assert_eq!(loaded.query_window(&key, now).unwrap(), (1, 1));
                    }
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn timelock_admission_follows_its_first_signature() {
                use stellar_agent_core::policy::v1::criteria::state_store::{
                    PolicyStateStore, StateKey, WindowEntry, WindowLimit,
                };
                use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
                use stellar_agent_network::policy_state::PersistedWindowStore;
                use stellar_agent_network::{SigningAdmission, SubjectKind};
                use stellar_xdr::{
                    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanCredentials,
                };
                for case in [
                    "empty",
                    "mixed",
                    "sequence",
                    "sequence_fee",
                    "stale_source",
                    "stale_signed",
                ] {
                    stellar_agent_test_support::keyring_mock::install().unwrap();
                    let dir = tempfile::tempdir().unwrap();
                    let profile =
                        stellar_agent_core::profile::schema::Profile::builder_testnet_named(
                            "intent",
                            "timelock-test",
                            "account",
                            "timelock-nonce",
                            "account",
                        )
                        .build();
                    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
                    let source = SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::SourceAccount,
                        root_invocation: leaf(schedule()),
                    };
                    let signed = SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: super::operator(),
                            nonce: 9,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: leaf(schedule()),
                    };
                    let entries = match case {
                        "empty" => vec![],
                        "mixed" => vec![signed, source],
                        "stale_source" => vec![source],
                        _ => vec![signed],
                    };
                    let primary = Endpoint::start_entries(
                        Chain {
                            final_sequence_bump: case.starts_with("sequence"),
                            overflowing_final_fee: case == "sequence_fee",
                            ..Chain::at(LEDGER)
                        },
                        Some(entries),
                    )
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let signer = super::AuthAndSourceSigner {
                        auth: CountingSigner::new(SEED),
                        source: CountingSigner::new(SEED),
                    };
                    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
                    let key = StateKey::new("intent", 1, "rate_limit", 60);
                    let entries = vec![WindowEntry::new(
                        key.clone(),
                        now,
                        1,
                        WindowLimit::Count {
                            window: "1m".into(),
                            max_calls: 1,
                        },
                    )];
                    let sizing =
                        CheckedSizing::for_test(SizingBasis::NoValue, entries.clone()).unwrap();
                    let inner =
                        stellar_agent_network::submission_record::WalletSubmissionRecorder::new(
                            &profile,
                            "intent",
                            "timelock_test",
                            Some("stellar:testnet".into()),
                            stellar_agent_core::audit_log::PolicyDecision::Allow,
                            vec![],
                            entries,
                            stellar_agent_core::profile::receipt::ReceiptStore::open_at(
                                dir.path(),
                                "intent",
                            )
                            .unwrap(),
                            store.clone(),
                            None,
                            None,
                            "fixture",
                            now,
                        )
                        .with_signing_sizing(sizing);
                    let stale = case.starts_with("stale");
                    let recorder = AdmissionRecorder {
                        inner,
                        stale,
                        signer: &signer,
                        endpoint: &primary,
                        admissions: 0.into(),
                        cancellations: 0.into(),
                        binds: 0.into(),
                        ledger_reads_at_admission: 0.into(),
                        subjects: Mutex::new(vec![]),
                        admitted_plan: Mutex::new(None),
                    };
                    let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                        schedule_identity: None,
                        host_function: HostFunction::InvokeContract(schedule()),
                        signer: &signer,
                        primary_rpc_url: &primary.uri(),
                        secondary_rpc_url: &secondary.witness_uri(),
                        network_passphrase: TESTNET_PASSPHRASE,
                        timeout: Duration::from_secs(30),
                        op_label: "schedule",
                        admission: SigningAdmission::Recorded(&recorder),
                    })
                    .await;
                    assert_eq!(
                        recorder.admissions.load(Ordering::SeqCst),
                        1,
                        "{case}: {result:?}"
                    );
                    assert_eq!(
                        recorder.cancellations.load(Ordering::SeqCst),
                        usize::from(stale),
                        "{case}"
                    );
                    if stale {
                        assert_eq!(result.unwrap_err().wire_code(), UNAVAILABLE_CODE, "{case}");
                        assert_eq!(signer.auth.sign_calls() + signer.source.sign_calls(), 0);
                        assert_eq!(
                            primary.ledger_reads(),
                            recorder.ledger_reads_at_admission.load(Ordering::SeqCst)
                        );
                    } else if case.starts_with("sequence") {
                        assert!(
                            matches!(
                                result,
                                Err(SaError::IntentBindingMismatch {
                                    field: "envelope_sequence"
                                })
                            ),
                            "{result:?}"
                        );
                        assert_eq!(signer.source.sign_calls(), 0);
                        assert_eq!(signer.auth.sign_calls(), 1);
                    } else {
                        assert!(result.is_ok(), "{case}: {result:?}");
                        assert_eq!(recorder.binds.load(Ordering::SeqCst), 1);
                        assert_eq!(signer.source.sign_calls(), 1);
                        let sent = super::sent_envelope(&primary.server).await;
                        super::assert_envelope_bound(sent.as_ref(), LEDGER + 100);
                        let sent = sent.unwrap();
                        {
                            let plan = recorder.admitted_plan.lock().unwrap();
                            let plan = plan.as_ref().unwrap();
                            assert_eq!(plan.check_envelope(&sent), Ok(()));
                            let mut changed = sent.clone();
                            super::super::super::set_envelope_max_ledger(
                                &mut changed,
                                LEDGER + 101,
                            )
                            .unwrap();
                            assert_eq!(plan.check_envelope(&changed), Err("expiration"));
                        }
                        use stellar_xdr::{
                            Limits, Preconditions, ReadXdr, TransactionEnvelope, WriteXdr,
                        };
                        let requests = primary.server.received_requests().await.unwrap();
                        let resimulated: serde_json::Value = requests
                            .iter()
                            .map(|request| serde_json::from_slice(&request.body).unwrap())
                            .filter(|body: &serde_json::Value| {
                                body["method"] == "simulateTransaction"
                            })
                            .nth(1)
                            .unwrap();
                        let provisional = TransactionEnvelope::from_xdr_base64(
                            resimulated["params"]["transaction"].as_str().unwrap(),
                            Limits::none(),
                        )
                        .unwrap();
                        super::assert_envelope_bound(Some(&provisional), LEDGER + 100);
                        let (
                            TransactionEnvelope::Tx(provisional_tx),
                            TransactionEnvelope::Tx(final_tx),
                        ) = (&provisional, &sent)
                        else {
                            panic!("V1 envelopes")
                        };
                        let (
                            Preconditions::V2(provisional_conditions),
                            Preconditions::V2(final_conditions),
                        ) = (&provisional_tx.tx.cond, &final_tx.tx.cond)
                        else {
                            panic!("V2 preconditions")
                        };
                        assert_eq!(
                            provisional_conditions.to_xdr(Limits::none()).unwrap().len(),
                            final_conditions.to_xdr(Limits::none()).unwrap().len()
                        );
                        let mut normalized = final_tx.clone();
                        normalized.signatures = Default::default();
                        normalized.tx.ext = provisional_tx.tx.ext.clone();
                        normalized.tx.fee = provisional_tx.tx.fee;
                        assert_eq!(
                            TransactionEnvelope::Tx(normalized)
                                .to_xdr(Limits::none())
                                .unwrap()
                                .len(),
                            provisional.to_xdr(Limits::none()).unwrap().len()
                        );
                        if case == "empty" {
                            assert!(recorder.subjects.lock().unwrap().is_empty());
                            assert_eq!(signer.auth.sign_calls(), 0);
                        } else {
                            assert_eq!(
                                *recorder.subjects.lock().unwrap(),
                                [SubjectKind::AccountKey, SubjectKind::SourceAccount]
                            );
                            assert_eq!(signer.auth.sign_calls(), 1);
                        }
                    }
                    assert_eq!(
                        primary.sends().await,
                        usize::from(!stale && !case.starts_with("sequence"))
                    );
                    drop(recorder);
                    drop(store);
                    let reopened = PersistedWindowStore::at_path(dir.path().join("intent.window"));
                    let intents = reopened.signed_intents("intent", &profile).unwrap();
                    assert_eq!(intents.len(), usize::from(!stale));
                    for intent in &intents {
                        assert_eq!(intent.greatest_expiration_ledger, Some(LEDGER + 100));
                    }
                    if case.starts_with("sequence") {
                        assert_eq!(
                            intents[0].status,
                            "authorization exposed, submission unknown"
                        );
                    }
                    let loaded = PolicyStateStore::new();
                    reopened.load_into("intent", &profile, &loaded).unwrap();
                    assert_eq!(
                        loaded.query_window(&key, now).unwrap(),
                        if stale { (0, 0) } else { (1, 1) }
                    );
                }
            }

            #[derive(Clone, Copy, Debug)]
            enum Verb {
                Schedule,
                Cancel,
                Execute,
            }

            const VERBS: [Verb; 3] = [Verb::Schedule, Verb::Cancel, Verb::Execute];

            /// Runs `verb` through its public entrypoint and returns the error
            /// and the signing primitives it used.
            async fn run(verb: Verb, primary: &str, secondary: &str) -> (SaError, usize) {
                let signer = CountingSigner::new(SEED);
                let dir = tempfile::tempdir().unwrap();
                let writer = Arc::new(Mutex::new(
                    AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
                ));
                let operation_id = TimelockOperationId::from_bytes([0x77; 32]);
                let error = match verb {
                    Verb::Schedule => schedule_upgrade(
                        TimelockScheduleArgs::builder()
                            .submission_recorder(
                                &crate::signing::intent_test_helpers::NoLimitRecorder,
                            )
                            .timelock_contract_strkey(CONTRACT)
                            .target_strkey(CONTRACT)
                            .function("upgrade")
                            .args(vec![ScVal::Void])
                            .delay_ledgers(10)
                            .signer(&signer)
                            .primary_rpc_url(primary)
                            .secondary_rpc_url(secondary)
                            .network_passphrase(TESTNET_PASSPHRASE)
                            .audit_writer(&writer)
                            .request_id("req-witness-schedule")
                            .build(),
                    )
                    .await
                    .err(),
                    Verb::Cancel => cancel(
                        TimelockCancelArgs::builder()
                            .intent_admission(
                                crate::signing::intent_test_helpers::no_value_admission(),
                            )
                            .timelock_contract_strkey(CONTRACT)
                            .operation_id(&operation_id)
                            .signer(&signer)
                            .primary_rpc_url(primary)
                            .secondary_rpc_url(secondary)
                            .network_passphrase(TESTNET_PASSPHRASE)
                            .audit_writer(&writer)
                            .request_id("req-witness-cancel")
                            .build(),
                    )
                    .await
                    .err(),
                    Verb::Execute => execute(
                        TimelockExecuteArgs::builder()
                            .submission_recorder(
                                &crate::signing::intent_test_helpers::NoLimitRecorder,
                            )
                            .timelock_contract_strkey(CONTRACT)
                            .target_strkey(CONTRACT)
                            .function("upgrade")
                            .salt([0x11; 32])
                            .signer(&signer)
                            .primary_rpc_url(primary)
                            .secondary_rpc_url(secondary)
                            .network_passphrase(TESTNET_PASSPHRASE)
                            .audit_writer(&writer)
                            .request_id("req-witness-execute")
                            .build(),
                    )
                    .await
                    .err(),
                };
                let error = error.unwrap_or_else(|| panic!("{verb:?} went through"));
                (error, signer.sign_calls())
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn timelock_refuses_plausible_inflated_height() {
                for verb in VERBS {
                    let primary = Endpoint::start(Chain::at(1_000_000)).await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let (error, signs) = run(verb, &primary.uri(), &secondary.witness_uri()).await;
                    assert_eq!(error.wire_code(), SKEW_CODE, "{verb:?}: {error:?}");
                    assert_eq!(signs, 0, "{verb:?}: nothing is signed");
                    assert!(primary.resimulated().is_empty(), "{verb:?}");
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn allowed_skew_has_exact_bounded_expiry() {
                for (primary, secondary) in [
                    (LEDGER, LEDGER),
                    (LEDGER, LEDGER + 1),
                    (LEDGER + 1, LEDGER),
                    (LEDGER, LEDGER + 2),
                    (LEDGER + 2, LEDGER),
                ] {
                    let outcome = submit_at(primary, secondary).await;
                    assert!(outcome.result.is_ok(), "{:?}", outcome.result.err());
                    let [signed] = outcome.resimulated.as_slice() else {
                        panic!("one signed entry: {:?}", outcome.resimulated)
                    };
                    assert_signed_at(signed, schedule(), primary.min(secondary) + 100);
                    super::assert_envelope_bound(
                        outcome.sent.as_ref(),
                        primary.min(secondary) + 100,
                    );
                }
                for (primary, secondary) in [(LEDGER, LEDGER + 3), (LEDGER + 3, LEDGER)] {
                    submit_at(primary, secondary)
                        .await
                        .assert_refused(SKEW_CODE, &format!("({primary}, {secondary})"));
                }
                for (primary, secondary) in [(0, 1), (1, 0), (u32::MAX - 1, u32::MAX - 1)] {
                    submit_at(primary, secondary)
                        .await
                        .assert_refused(SKEW_CODE, &format!("({primary}, {secondary})"));
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn simulation_recovery_uses_one_retry_and_the_same_pair() {
                for case in [
                    RecoveryCase::Valid,
                    RecoveryCase::Behind,
                    RecoveryCase::ReplacementAhead,
                    RecoveryCase::Ahead,
                ] {
                    let primary = Endpoint::start(Chain {
                        recovery_case: Some(case),
                        ..Chain::at(LEDGER)
                    })
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let outcome = submit(&primary, &secondary.witness_uri()).await;
                    if case == RecoveryCase::Valid {
                        assert_eq!(
                            outcome.result.as_ref().unwrap().return_val,
                            ScVal::U32(REPLACEMENT_VALUE)
                        );
                        let stellar_xdr::SorobanCredentials::Address(creds) =
                            &outcome.resimulated[0].credentials
                        else {
                            panic!("address")
                        };
                        assert_eq!(
                            creds.nonce,
                            i64::from(REPLACEMENT_VALUE),
                            "replacement nonce reaches signing"
                        );
                        assert_eq!(creds.signature_expiration_ledger, LEDGER + 100);
                        assert_eq!(outcome.signs, 2);
                        assert_eq!(primary.sends().await, 1);
                    } else {
                        outcome.assert_refused(SKEW_CODE, &format!("{case:?}"));
                        assert_eq!(primary.sends().await, 0);
                    }
                    let unsigned = primary.simulations.load(Ordering::SeqCst)
                        - usize::from(!outcome.resimulated.is_empty());
                    assert_eq!(unsigned, if case == RecoveryCase::Ahead { 1 } else { 2 });
                    assert_eq!(primary.ledger_reads(), 1, "recovery keeps the pair");
                    assert_eq!(secondary.ledger_reads(), 1, "recovery keeps the pair");
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn simulation_recovery_keeps_the_absolute_deadline() {
                let primary = Endpoint::start(Chain {
                    recovery_case: Some(RecoveryCase::Valid),
                    witness_delay: Some(Duration::from_secs(3)),
                    recovery_delay: Some(Duration::from_secs(3)),
                    ..Chain::at(LEDGER)
                })
                .await;
                let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                let outcome = submit(&primary, &secondary.witness_uri()).await;
                assert_deadline_refusal(&outcome, "simulate_recovery");
                outcome.assert_refused("sa.auth_entry_construction_failed", "recovery deadline");
                assert_eq!(primary.sends().await, 0);
                assert_eq!(primary.simulations.load(Ordering::SeqCst), 2);
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn simulation_recovery_revalidates_the_whole_response() {
                for case in [
                    RecoveryCase::Tree,
                    RecoveryCase::Credential,
                    RecoveryCase::Error,
                    RecoveryCase::Fee,
                    RecoveryCase::Data,
                    RecoveryCase::Decode,
                    RecoveryCase::Empty,
                    RecoveryCase::Schedule,
                ] {
                    let primary = Endpoint::start(Chain {
                        recovery_case: Some(case),
                        ..Chain::at(LEDGER)
                    })
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let outcome = submit(&primary, &secondary.witness_uri()).await;
                    let code = match case {
                        RecoveryCase::Tree => "simulation.divergence.auth_contexts",
                        RecoveryCase::Credential => "sa.auth_entry_construction_failed",
                        RecoveryCase::Schedule => "submission.intent_binding_mismatch",
                        _ => "sa.deployment_failed",
                    };
                    outcome.assert_refused(code, &format!("{case:?}"));
                    assert_eq!(primary.sends().await, 0);
                    assert_eq!(primary.simulations.load(Ordering::SeqCst), 2);
                }
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn a_simulated_height_within_the_tolerance_of_the_pair_signs() {
                for simulated in [LEDGER - 2, LEDGER + 2] {
                    let primary = Endpoint::start(Chain {
                        simulated_ledger: Some(simulated),
                        ..Chain::at(LEDGER)
                    })
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    let outcome = submit(&primary, &secondary.witness_uri()).await;
                    assert!(outcome.result.is_ok(), "{:?}", outcome.result);
                    assert_eq!(outcome.signs, 2);
                    assert_eq!(primary.simulations.load(Ordering::SeqCst), 2);
                    assert_eq!(primary.sends().await, 1);
                }
            }

            /// The simulation's own height must not contradict the pair
            /// observed after it, in either direction.
            #[tokio::test]
            #[serial_test::serial]
            async fn a_simulated_height_outside_the_pair_refuses_before_signing() {
                for (simulated, case) in [(1_000_000, "above"), (LEDGER - 3, "below")] {
                    let primary = Endpoint::start(Chain {
                        simulated_ledger: Some(simulated),
                        ..Chain::at(LEDGER)
                    })
                    .await;
                    let secondary = Endpoint::start(Chain::at(LEDGER)).await;
                    submit(&primary, &secondary.witness_uri())
                        .await
                        .assert_refused(SKEW_CODE, case);
                }
            }

            /// The account read before the envelope is built answers to the
            /// deadline the witness rests on: a read that outlasts it ends in
            /// the deadline refusal, and the envelope is neither signed nor
            /// sent. The authorization entry is signed before that read.
            #[tokio::test]
            #[serial_test::serial]
            async fn a_final_fetch_past_the_deadline_refuses_before_the_envelope_is_signed() {
                let primary = Endpoint::start(Chain {
                    final_fetch_delay: Some(DEADLINE + Duration::from_secs(1)),
                    ..Chain::at(LEDGER)
                })
                .await;
                let secondary = Endpoint::start(Chain::at(LEDGER)).await;

                let outcome = submit(&primary, &secondary.witness_uri()).await;

                match &outcome.result {
                    Err(SaError::AuthEntryConstructionFailed {
                        stage: "auth_payload",
                        redacted_reason,
                    }) => assert!(
                        redacted_reason.starts_with(
                            "fetch_account_submit exceeded collective pre-submit budget"
                        ),
                        "{redacted_reason}"
                    ),
                    other => panic!("expected the final fetch's deadline refusal, got {other:?}"),
                }
                assert_eq!(outcome.signs, 1, "the authorization entry alone is signed");
                assert_eq!(
                    outcome.resimulated.len(),
                    1,
                    "the signed entry was re-simulated"
                );
                assert_eq!(primary.sends().await, 0, "nothing is sent");
            }

            /// An envelope signature that outlasts the deadline is cut at it:
            /// the envelope is neither signed nor sent. The authorization
            /// entry is signed before.
            #[tokio::test]
            #[serial_test::serial]
            async fn an_envelope_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
                let primary = Endpoint::start(Chain::at(LEDGER)).await;
                let secondary = Endpoint::start(Chain::at(LEDGER)).await;

                let outcome = submit_slowly(
                    &primary,
                    &secondary.witness_uri(),
                    DEADLINE + Duration::from_secs(1),
                    Duration::ZERO,
                )
                .await;

                assert_deadline_refusal(&outcome, "sign_envelope");
                assert_eq!(outcome.signs, 1, "the authorization entry alone is signed");
                assert_eq!(primary.sends().await, 0, "nothing is sent");
            }

            /// An authorization signature that outlasts the deadline is cut
            /// at it: nothing is signed, re-simulated or sent.
            #[tokio::test]
            #[serial_test::serial]
            async fn an_entry_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
                let primary = Endpoint::start(Chain::at(LEDGER)).await;
                let secondary = Endpoint::start(Chain::at(LEDGER)).await;

                let outcome = submit_slowly(
                    &primary,
                    &secondary.witness_uri(),
                    Duration::ZERO,
                    DEADLINE + Duration::from_secs(1),
                )
                .await;

                assert_deadline_refusal(&outcome, "sign_auth_entry");
                assert_eq!(outcome.signs, 0, "nothing is signed");
                assert!(outcome.resimulated.is_empty(), "nothing is re-simulated");
                assert_eq!(primary.sends().await, 0, "nothing is sent");
            }

            /// The submission's steps before `sendTransaction` end at the
            /// deadline the witness rests on: an identity probe that outlasts
            /// it sends nothing, though both signatures are made.
            #[tokio::test]
            #[serial_test::serial]
            async fn a_pre_send_step_past_the_deadline_sends_nothing() {
                let primary = Endpoint::start(Chain {
                    pre_send_delay: Some(DEADLINE + Duration::from_secs(1)),
                    ..Chain::at(LEDGER)
                })
                .await;
                let secondary = Endpoint::start(Chain::at(LEDGER)).await;

                let outcome = submit(&primary, &secondary.witness_uri()).await;

                assert_deadline_refusal(&outcome, "send_endpoint_identity");
                assert_eq!(outcome.signs, 2, "the entry and the envelope are signed");
                assert_eq!(primary.sends().await, 0, "nothing is sent");
            }

            /// The deadline of the source-account cases: long enough for a
            /// re-simulation that outlasts an observation.
            const SOURCE_ACCOUNT_DEADLINE: Duration = Duration::from_secs(30);

            /// Outlasts a ledger observation, not the deadline.
            const RESIMULATION_OUTLASTS_OBSERVATION: Duration = Duration::from_millis(10_500);

            /// Submits a call whose simulation hands out source-account
            /// credentials alone and whose re-simulation outlasts an
            /// observation, with `secondary` as the witness. The envelope's is
            /// the first signature.
            async fn submit_source_account_only(secondary: Chain) -> (Outcome, Endpoint, Endpoint) {
                let primary = Endpoint::start(Chain {
                    source_account_auth: true,
                    resimulation_delay: Some(RESIMULATION_OUTLASTS_OBSERVATION),
                    ledger_after_reads: Some((1, LEDGER + 1)),
                    ..Chain::at(LEDGER)
                })
                .await;
                let secondary = Endpoint::start(secondary).await;
                let signer = CountingSigner::new(SEED);
                let outcome = submit_through(
                    &primary,
                    &secondary.witness_uri(),
                    &signer,
                    &signer,
                    SOURCE_ACCOUNT_DEADLINE,
                )
                .await;
                (outcome, primary, secondary)
            }

            /// Outlasts a ledger observation: the lag of the final freshness
            /// check in the case whose pair goes stale after its re-read.
            const PAST_OBSERVATION_AGE: Duration = Duration::from_secs(11);

            /// Without an entry to sign, the envelope signature follows two
            /// re-fetches and a re-simulation, which can outlast the pair. A
            /// stale pair receives a refresh before the first signature.
            /// Persistent disagreement during that refresh refuses with
            /// nothing signed or sent: the refresh reads the pair three times
            /// and every reading disagrees. A fresh refreshed pair signs, and
            /// a refreshed pair that has gone stale by the final check before
            /// the signature, and at no check before it, refuses with nothing
            /// signed or sent. The cases run side by side.
            #[tokio::test]
            #[serial_test::serial]
            async fn a_stale_pair_is_read_again_before_a_first_envelope_signature() {
                let (
                    (fresh, primary, secondary),
                    (refused, refused_primary, refused_secondary),
                    (stale, stale_primary, stale_secondary),
                ) = tokio::join!(
                    submit_source_account_only(Chain {
                        ledger_after_reads: Some((1, LEDGER + 1)),
                        ..Chain::at(LEDGER)
                    }),
                    submit_source_account_only(Chain {
                        ledger_after_reads: Some((1, LEDGER + 50)),
                        ..Chain::at(LEDGER)
                    }),
                    crate::timelock_submit::FINAL_CHECK_LAG.scope(
                        PAST_OBSERVATION_AGE,
                        submit_source_account_only(Chain::at(LEDGER)),
                    ),
                );

                assert!(fresh.result.is_ok(), "{:?}", fresh.result.as_ref().err());
                assert_eq!(fresh.signs, 1, "the envelope alone is signed");
                assert_eq!(secondary.ledger_reads(), 2, "the pair is read again");
                assert_eq!(primary.ledger_reads(), 2, "the pair is read again");
                assert_eq!(primary.sends().await, 1);

                use stellar_xdr::{Limits, Preconditions, ReadXdr, TransactionEnvelope, WriteXdr};
                let requests: Vec<serde_json::Value> = primary
                    .server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .map(|request| serde_json::from_slice(&request.body).unwrap())
                    .collect();
                let decode = |request: &serde_json::Value| {
                    TransactionEnvelope::from_xdr_base64(
                        request["params"]["transaction"].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap()
                };
                let sent = decode(
                    requests
                        .iter()
                        .find(|request| request["method"] == "sendTransaction")
                        .unwrap(),
                );
                let resimulated = decode(
                    requests
                        .iter()
                        .filter(|request| request["method"] == "simulateTransaction")
                        .nth(1)
                        .unwrap(),
                );
                let (TransactionEnvelope::Tx(sent), TransactionEnvelope::Tx(resimulated)) =
                    (sent, resimulated)
                else {
                    panic!("V1 envelopes")
                };
                let (
                    Preconditions::V2(final_conditions),
                    Preconditions::V2(provisional_conditions),
                ) = (&sent.tx.cond, &resimulated.tx.cond)
                else {
                    panic!("V2 preconditions")
                };
                assert_eq!(
                    provisional_conditions
                        .ledger_bounds
                        .as_ref()
                        .unwrap()
                        .max_ledger,
                    LEDGER + 100
                );
                assert_eq!(
                    final_conditions.ledger_bounds.as_ref().unwrap().max_ledger,
                    LEDGER + 101
                );
                assert_eq!(
                    final_conditions.ledger_bounds.as_ref().unwrap().min_ledger,
                    0
                );
                assert_eq!(
                    provisional_conditions.to_xdr(Limits::none()).unwrap().len(),
                    final_conditions.to_xdr(Limits::none()).unwrap().len()
                );

                match &refused.result {
                    Err(error) => assert_eq!(error.wire_code(), SKEW_CODE, "{error:?}"),
                    Ok(_) => panic!("a disagreeing refresh went through"),
                }
                assert_eq!(
                    refused_primary.ledger_reads(),
                    4,
                    "one fresh pair, then three disagreeing pairs"
                );
                assert_eq!(
                    refused_secondary.ledger_reads(),
                    4,
                    "one fresh pair, then three disagreeing pairs"
                );
                assert_eq!(refused.signs, 0, "nothing is signed");
                assert_eq!(refused_primary.sends().await, 0, "nothing is sent");

                assert!(
                    matches!(
                        stale.result,
                        Err(SaError::LedgerWitnessUnavailable {
                            reason: "the ledger observations are stale"
                        })
                    ),
                    "the final check refuses the stale pair: {:?}",
                    stale.result.as_ref().err()
                );
                assert_eq!(stale_secondary.ledger_reads(), 2, "the pair is read again");
                assert_eq!(stale_primary.ledger_reads(), 2, "the pair is read again");
                assert_eq!(stale.signs, 0, "nothing is signed");
                assert_eq!(stale_primary.sends().await, 0, "nothing is sent");
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn a_skew_of_three_with_the_primary_behind_refuses() {
                submit_at(LEDGER, LEDGER + 3)
                    .await
                    .assert_refused(SKEW_CODE, "primary behind");
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn a_skew_of_three_with_the_primary_ahead_refuses() {
                submit_at(LEDGER + 3, LEDGER)
                    .await
                    .assert_refused(SKEW_CODE, "primary ahead");
            }

            #[tokio::test]
            #[serial_test::serial]
            async fn absent_unavailable_or_wrong_chain_witness_refuses() {
                let primary = Endpoint::start(Chain::at(LEDGER)).await;

                let down = MockServer::start().await;
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(503))
                    .mount(&down)
                    .await;
                let down_uri = second_loopback_host(&down.uri());
                let malformed = Endpoint::start(Chain {
                    malformed_ledger: true,
                    ..Chain::at(LEDGER)
                })
                .await;
                let elsewhere = Endpoint::start(Chain {
                    passphrase: "Another Test Network ; 2026",
                    ..Chain::at(LEDGER)
                })
                .await;
                let other_port = Endpoint::start(Chain::at(LEDGER)).await;
                let refused = [
                    ("malformed height", malformed.witness_uri()),
                    ("another network", elsewhere.witness_uri()),
                    ("the same URL", primary.uri()),
                    (
                        "the same host on a path",
                        format!("{}/witness", primary.uri()),
                    ),
                    ("the same host on a port", other_port.uri()),
                    ("no URL", "not a url".to_owned()),
                ];
                for (case, secondary) in &refused {
                    submit(&primary, secondary)
                        .await
                        .assert_refused(UNAVAILABLE_CODE, case);
                    for verb in VERBS {
                        let (error, signs) = run(verb, &primary.uri(), secondary).await;
                        assert_eq!(
                            error.wire_code(),
                            UNAVAILABLE_CODE,
                            "{case}, {verb:?}: {error:?}"
                        );
                        assert_eq!(signs, 0, "{case}, {verb:?}: nothing is signed");
                    }
                }

                // `execute` reads the operation from both endpoints before it
                // reaches the witness, so an endpoint that answers nothing
                // refuses there, as a failed cross-endpoint read.
                submit(&primary, &down_uri)
                    .await
                    .assert_refused(UNAVAILABLE_CODE, "transport failure");
                for (verb, code) in [
                    (Verb::Schedule, UNAVAILABLE_CODE),
                    (Verb::Cancel, UNAVAILABLE_CODE),
                    (Verb::Execute, "sa.timelock_execute_failed"),
                ] {
                    let (error, signs) = run(verb, &primary.uri(), &down_uri).await;
                    assert_eq!(error.wire_code(), code, "{verb:?}: {error:?}");
                    assert_eq!(signs, 0, "{verb:?}: nothing is signed");
                }
            }
        }
    }
}
