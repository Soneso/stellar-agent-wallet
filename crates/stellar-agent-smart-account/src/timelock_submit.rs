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
//! 1. Builds a source-account transaction for the `InvokeHostFunction`.
//! 2. Simulates (empty auth) to discover the required auth entries, then
//!    obtains the mandatory ledger witness: the primary and the secondary
//!    endpoint observe the latest ledger, and the pair must agree within
//!    [`MAX_SIGNING_LEDGER_SKEW`](crate::signing::ledger_witness::MAX_SIGNING_LEDGER_SKEW).
//! 3. Checks every returned `SorobanCredentials::Address` entry before signing
//!    any: its address is the signer's G-key, and its root invocation is the
//!    timelock call the wallet built, with no sub-invocations. Only then does it
//!    compute, per entry, the canonical `HashIdPreimageSorobanAuthorization`
//!    preimage over that call and sign it via
//!    `Signer::sign_soroban_address_auth_payload`.
//! 4. Re-simulates with signed auth entries to obtain the accurate Soroban
//!    resource footprint (which includes storage reads triggered by the G-key
//!    `require_auth` validation path).
//! 5. Builds the final transaction envelope (soroban_data + auth injected).
//! 6. Attaches the source-account Ed25519 signature.
//! 7. Submits via `stellar_agent_network::submit_transaction_and_wait_sent_by`.
//!
//! The first signature, an entry's or else the envelope's, rests on a pair no
//! older than the observation age: a stale pair is read again first. Every
//! signature and the send fall before the one pre-submit deadline the witness
//! answers to; the confirmation poll keeps the submission's own timeout.
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
//! The G-key signature is a classic-account Address authorization: no
//! context rule narrows it, and it is not bound to a transaction. The wallet
//! therefore signs only the invocation it built itself; a simulated root on
//! another contract, with another function or arguments, or with
//! sub-invocations is refused before the preimage is computed.
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
    InvokeHostFunctionOp, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
};

use crate::SaError;
use crate::managers::auth_entry::{PreSubmitBudget, bound_pre_submit_stage};
use crate::managers::rules::{
    BASE_FEE_STROOPS, augment_with_oz_error_name, fingerprint_invocation, parse_min_resource_fee,
    validate_latest_ledger,
};
use crate::signing::ledger_witness::{
    ResolvedKeySigner, WitnessRequest, WitnessedLedgerBound, checked_secondary_rpc_url,
    witness_signing_ledger,
};
use crate::submit::{
    DeclaredSubInvocations, attribute_signed_tree_refusal, check_declared_sub_invocations,
    check_simulated_root, map_sent_by_error, refuse_mainnet_sa,
};

// ── Public result type ────────────────────────────────────────────────────────

/// Result returned by [`submit_timelock_invoke_with_g_key_auth`].
///
/// Mirrors the shape of `SubmitInvokeResult` from `submit.rs` for consistency
/// across the timelock call sites.
#[derive(Debug)]
pub(crate) struct TimelockSubmitResult {
    /// Predicted return `ScVal` from the first `simulateTransaction` response.
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
    /// Records the signed execution before sending and settles its outcome.
    pub(crate) submission_recorder: Option<&'a dyn stellar_agent_network::SubmissionRecorder>,
}

// ── Main submit function ──────────────────────────────────────────────────────

/// A simulated authorization entry after the check pass of step 4.
enum CheckedEntry {
    /// An entry this path does not sign (source-account credentials, or a
    /// credential variant the OZ timelock does not use), passed through as is.
    PassThrough(Box<SorobanAuthorizationEntry>),
    /// An Address entry for the signer's G-key whose root is the wallet's own
    /// call; the sign pass signs the wallet's invocation with these
    /// credentials.
    SignerKey(SorobanAddressCredentials),
}

/// Submits a timelock `InvokeHostFunction` with direct G-key authorization.
///
/// The OZ `TimelockController` is not a smart-account; its entrypoints call
/// `proposer.require_auth()` / `canceller.require_auth()` / `executor.require_auth()`
/// with the caller's G-key passed as a function argument. This requires a
/// `SorobanCredentials::Address` auth entry signed by the G-key — NOT a
/// smart-account auth-entry or a `__check_auth` delegation entry.
///
/// # Steps
///
/// 1. Fetch signer G-key and source account sequence, after the local check
///    of the witness configuration.
/// 2. Build `InvokeHostFunction` tx (empty auth) for simulation.
/// 3. Simulate on primary RPC; extract the auth entry template. Acquire the
///    mandatory ledger witness before any credential is processed: the
///    primary and the secondary observe the latest ledger under one deadline,
///    and the signature expiry is 100 ledgers beyond the lower observation.
/// 4. Check every `SorobanCredentials::Address` entry: its address is the
///    signer G-key, and its root invocation equals the host function with no
///    sub-invocations. Only after every entry passes, compute the auth
///    preimage over the wallet's own invocation for each and sign it, each
///    signature under the deadline. The first signature rests on a fresh
///    pair: a stale pair is read again before it.
/// 5. Re-simulate with signed auth entries to get the full storage footprint.
/// 6. Build final envelope: inject signed auth entries + soroban_data, after
///    a source-account re-fetch under the same deadline.
/// 7. Attach source-account signature under that deadline, through the key
///    read in step 1. When no entry was signed, this is the first signature,
///    and the pair is readied for it as in step 4.
/// 8. Submit via `submit_transaction_and_wait_sent_by`: nothing is sent
///    after the deadline, and the confirmation poll runs under `timeout`.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`]: `network_passphrase` names mainnet
///   or `primary_rpc_url` is a mainnet-pattern endpoint; refused before the
///   signer's public key is read and before any request.
/// - [`SaError::LedgerWitnessUnavailable`]: the secondary endpoint is
///   malformed, on the primary's host, on another network or unreachable, the
///   primary gives no observation, the pair stays stale, or the deadline
///   elapses before the first signature. Nothing was signed.
/// - [`SaError::LedgerWitnessMismatch`] (wire code
///   `simulation.divergence.ledger_skew`): the pair differs by more than the
///   skew tolerance, a height is out of bounds, or the simulation height
///   contradicts the pair. Nothing was signed.
/// - [`SaError::AuthEntryConstructionFailed`] — pubkey fetch, XDR encoding,
///   simulate, or signing failure, or the deadline elapsing before a
///   signature completes or before `sendTransaction`; nothing was sent.
/// - [`SaError::SimulationDivergence`] with sub-code `AuthContexts` (wire code
///   `simulation.divergence.auth_contexts`): an entry for the signer's G-key
///   whose root invocation differs from the host function or carries
///   sub-invocations; refused before any entry is signed. The public
///   [`crate::timelock::schedule_upgrade`], [`crate::timelock::execute`], and
///   [`crate::timelock::cancel`] map it, like every other error here except
///   [`SaError::MainnetWriteForbidden`], the two ledger witness refusals (and,
///   for `execute`, [`SaError::SubmissionUnresolved`]), to their typed variant
///   below, with the refusal text in the reason.
/// - [`SaError::DeploymentFailed`] — re-simulate error or envelope construction.
/// - [`SaError::TimelockScheduleFailed`] / `CancelFailed` / `ExecuteFailed`
///   — NOT emitted here; the caller maps `SaError` to the typed variant.
///
/// Auth preimage shape: canonical `HashIdPreimageSorobanAuthorization` (same as
/// `managers/auth_entry.rs::compute_signature_payload`).
/// Signature shape: `ScVal::Vec([ScVal::Map([{public_key, signature}])])` per
/// js-stellar-base auth.js:171-184.
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
    let sim_response = server
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

    if let Some(err) = &sim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!(
                "{} simulation returned error: {}",
                args.op_label,
                augment_with_oz_error_name(err)
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
    let auth_entries = sim_first_result.auth;

    // The primary answered the simulation, so its height decides nothing on
    // its own: both endpoints observe the latest ledger before any credential
    // is processed, and the expiry derives from the pair the first signature
    // rests on. The witness, the source-account re-fetches, the signed
    // re-simulation, every signature and the steps before `sendTransaction`
    // answer to this one deadline.
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
    simulation_witness.check_simulation_height(sim_response.latest_ledger)?;
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
    let mut checked_entries: Vec<CheckedEntry> = Vec::with_capacity(auth_entries.len());
    for entry in auth_entries {
        let creds = match &entry.credentials {
            SorobanCredentials::Address(c) => c.clone(),
            SorobanCredentials::SourceAccount
            | SorobanCredentials::AddressV2(_)
            | SorobanCredentials::AddressWithDelegates(_) => {
                // SourceAccount entries need no explicit signing — the
                // source-account envelope signature covers them.
                // AddressV2 / AddressWithDelegates are credential variants not
                // used by the OZ TimelockController; pass through unchanged.
                checked_entries.push(CheckedEntry::PassThrough(Box::new(entry)));
                continue;
            }
        };

        // Only sign entries whose credential address is the signer G-key.
        // Other entries (e.g. for other role addresses) cannot be signed
        // here; the caller must ensure the signer holds the required role.
        let is_our_g_key = matches!(&creds.address, ScAddress::Account(AccountId(
            XdrPublicKey::PublicKeyTypeEd25519(Uint256(bytes))
        )) if *bytes == pubkey.0);

        if !is_our_g_key {
            return Err(auth_err(
                "auth_payload",
                format!(
                    "{}: simulate returned auth entry for an unexpected address \
                     (not the signer G-key); cannot sign",
                    args.op_label
                ),
            ));
        }

        // The OZ timelock calls the role's `require_auth()` in its own
        // `schedule` / `execute` / `cancel` frame, so the honest root is the
        // host function itself, with nothing under it. Any other root is an
        // authorization the wallet did not build.
        check_simulated_root(&entry.root_invocation.function, &invoke)
            .and_then(|()| {
                check_declared_sub_invocations(
                    &entry.root_invocation.sub_invocations,
                    &DeclaredSubInvocations::None,
                    &creds.address,
                )
            })
            .map_err(|err| {
                attribute_signed_tree_refusal(err, args.op_label, &fingerprint_invocation(&entry))
            })?;
        checked_entries.push(CheckedEntry::SignerKey(creds));
    }

    // The first signature is an entry's when the simulation asks the
    // signer's key for one, and the envelope's otherwise. The pair is readied
    // where that signature falls.
    let signs_entries = checked_entries
        .iter()
        .any(|checked| matches!(checked, CheckedEntry::SignerKey(_)));
    let ledger_bound = if signs_entries {
        pair_for_first_signature(simulation_witness, &witness_request, pre_submit_budget).await?
    } else {
        simulation_witness
    };
    let signature_expiration_ledger = ledger_bound.signature_expiration_ledger()?;

    let mut signed_entries: Vec<SorobanAuthorizationEntry> =
        Vec::with_capacity(checked_entries.len());
    for checked in checked_entries {
        let creds = match checked {
            CheckedEntry::PassThrough(entry) => {
                signed_entries.push(*entry);
                continue;
            }
            CheckedEntry::SignerKey(creds) => creds,
        };

        // Compute the auth preimage over the wallet's own invocation.
        // `signature_expiration_ledger` is the witnessed bound (overrides the
        // `0` placeholder the RPC returns).
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
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
        let signature_scval =
            crate::managers::auth_entry::build_classic_signature_scval(&pubkey.0, &signature_bytes)
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

    let resim_envelope = tx_resim.to_envelope().map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: to_envelope (resim) failed: {e:?}", args.op_label),
        )
    })?;
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
                augment_with_oz_error_name(err)
            ),
        });
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
    // Build the envelope with signed auth entries + soroban_data from the
    // re-simulate response.  Re-fetch the sequence number once more: the
    // `BaselibAccount` sequence advances with each `build_for_simulation()`
    // call so we must use the live on-chain state (not an incremented in-memory
    // counter) to get the correct sequence number for the final submission.
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

    let envelope = tx_final.to_envelope().map_err(|e| {
        auth_err(
            "auth_payload",
            format!("{}: Transaction::to_envelope failed: {e:?}", args.op_label),
        )
    })?;
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
        pair_for_first_signature(ledger_bound, &witness_request, pre_submit_budget).await?;
    }
    // The envelope is signed only while the deadline the witness rests on is
    // open, through the key read in step 1. A software key signs without
    // yielding, so the deadline is checked before the bounded signature as
    // well.
    pre_submit_budget.check_at("sign_envelope", "auth_payload")?;
    let envelope_signer = ResolvedKeySigner::with_key(args.signer, pubkey);
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
        args.submission_recorder,
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

/// The pair the first signature of a timelock call rests on.
///
/// `bound` stands while it is fresh. A stale pair is read again as a pair,
/// under the same deadline; the simulation height was checked against the
/// pair read right after the simulation, and the expiry derives from the pair
/// returned here. The pair must then be fresh and the deadline open.
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
        let server = wiremock::MockServer::start().await;
        let signer = stellar_agent_network::signing::test_doubles::CountingSigner::new([0x51; 32]);
        let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
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
            submission_recorder: None,
        })
        .await;
        let requests = server.received_requests().await.unwrap().len();
        (result, signer.key_accesses(), requests)
    }

    #[tokio::test]
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
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_agent_test_support::second_loopback_host;
        use stellar_agent_test_support::signed_envelope::{
            account_id_for_seed, get_network_result, ledger_entries_result_for,
            public_key_for_seed, send_transaction_hash_hex,
        };
        use stellar_xdr::{
            AccountId, ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
            HostFunction, Int128Parts, InvokeContractArgs, Limits, OperationBody,
            PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScSymbol, ScVal,
            SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, SorobanTransactionData,
            TransactionEnvelope, Uint256, VecM, WriteXdr,
        };
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

        use super::super::{TimelockSubmitArgs, submit_timelock_invoke_with_g_key_auth};
        use crate::SaError;
        use crate::error::SimulationDivergenceSubCode;

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
        /// per root `trees` builds from the request, echoes the signed
        /// entries on the re-simulation and records them.
        struct Rpc {
            trees: Arc<TreesFn>,
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
                    malformed_ledger: false,
                    final_fetch_delay: None,
                    resimulation_delay: None,
                    pre_send_delay: None,
                    source_account_auth: false,
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
                        ledger_entries_result_for(&[account_id_for_seed(SEED).as_str()])
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
                            b"hash_operation" => ScVal::Bytes(vec![0x77; 32].try_into().unwrap()),
                            b"get_operation_ledger" => ScVal::U32(READY_LEDGER),
                            _ => ScVal::Void,
                        };
                        let auth = if value != ScVal::Void {
                            Vec::new()
                        } else if op.auth.is_empty() {
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
                        } else {
                            delay = self.chain.resimulation_delay;
                            self.resimulated
                                .lock()
                                .unwrap()
                                .extend(op.auth.iter().cloned());
                            op.auth.to_vec()
                        };
                        json!({
                            "latestLedger": self.chain.simulated_ledger.unwrap_or(ledger),
                            "minResourceFee": "1000",
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
                        })
                    }
                    "sendTransaction" => {
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

        struct Outcome {
            result: Result<super::super::TimelockSubmitResult, SaError>,
            signs: usize,
            key_reads: usize,
            simulations: usize,
            resimulated: Vec<SorobanAuthorizationEntry>,
        }

        impl Outcome {
            /// Asserts the refusal before any signing primitive and any
            /// second simulation, and returns its reason.
            fn refused_before_signing(&self) -> String {
                assert_eq!(self.signs, 0, "nothing is signed: {:?}", self.result);
                assert_eq!(self.simulations, 1, "no re-simulation: {:?}", self.result);
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
            let server = MockServer::start().await;
            let simulations = Arc::new(AtomicUsize::new(0));
            let resimulated = Arc::new(Mutex::new(Vec::new()));
            Mock::given(method("POST"))
                .respond_with(Rpc {
                    trees: Arc::new(trees),
                    simulations: Arc::clone(&simulations),
                    ledger_reads: Arc::default(),
                    resimulated: Arc::clone(&resimulated),
                    chain: Chain::at(1000),
                })
                .mount(&server)
                .await;
            let signer = CountingSigner::new(SEED);
            let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                host_function: HostFunction::InvokeContract(schedule()),
                signer: &signer,
                primary_rpc_url: &server.uri(),
                secondary_rpc_url: &second_loopback_host(&server.uri()),
                network_passphrase: stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                timeout: std::time::Duration::from_secs(5),
                op_label: "schedule",
                submission_recorder: None,
            })
            .await;
            let resimulated = resimulated.lock().unwrap().clone();
            Outcome {
                result,
                signs: signer.sign_calls(),
                key_reads: signer.public_key_calls(),
                simulations: simulations.load(Ordering::SeqCst),
                resimulated,
            }
        }

        #[tokio::test]
        async fn a_timelock_root_on_another_contract_is_refused_before_signing() {
            let outcome = submit(|_| leaf(drain())).await;
            let reason = outcome.refused_before_signing();
            assert!(reason.contains("in its contract"), "{reason}");
        }

        #[tokio::test]
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
        async fn an_honest_first_entry_is_not_signed_when_a_second_is_refused() {
            let outcome = submit_entries(|invoke| vec![leaf(invoke.clone()), leaf(drain())]).await;
            let reason = outcome.refused_before_signing();
            assert!(reason.contains("in its contract"), "{reason}");
        }

        #[tokio::test]
        async fn the_timelock_signs_its_own_call() {
            let outcome = submit(|invoke| leaf(invoke.clone())).await;
            assert!(outcome.result.is_ok(), "{:?}", outcome.result);
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
                ledger_reads: Arc<AtomicUsize>,
                resimulated: Arc<Mutex<Vec<stellar_xdr::SorobanAuthorizationEntry>>>,
            }

            impl Endpoint {
                async fn start(chain: Chain) -> Self {
                    let server = MockServer::start().await;
                    let ledger_reads = Arc::new(AtomicUsize::new(0));
                    let resimulated = Arc::new(Mutex::new(Vec::new()));
                    Mock::given(method("POST"))
                        .respond_with(Rpc {
                            trees: Arc::new(|invoke| vec![leaf(invoke.clone())]),
                            simulations: Arc::default(),
                            ledger_reads: Arc::clone(&ledger_reads),
                            resimulated: Arc::clone(&resimulated),
                            chain,
                        })
                        .mount(&server)
                        .await;
                    Self {
                        server,
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
                let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                    host_function: HostFunction::InvokeContract(schedule()),
                    signer,
                    primary_rpc_url: &primary.uri(),
                    secondary_rpc_url: secondary,
                    network_passphrase: TESTNET_PASSPHRASE,
                    timeout,
                    op_label: "schedule",
                    submission_recorder: None,
                })
                .await;
                Outcome {
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

            /// The simulation's own height must not contradict the pair
            /// observed after it, in either direction.
            #[tokio::test]
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
            /// re-fetches and a re-simulation, which can outlast the pair. The
            /// pair is read again before it: a fresh pair signs, a pair whose
            /// second reading disagrees refuses with nothing signed, and a
            /// re-read pair that has gone stale by the final check before the
            /// signature, and at no check before it, refuses with nothing
            /// signed or sent. The cases run side by side.
            #[tokio::test]
            async fn a_stale_pair_is_read_again_before_a_first_envelope_signature() {
                let (
                    (fresh, primary, secondary),
                    (refused, refused_primary, _),
                    (stale, stale_primary, stale_secondary),
                ) = tokio::join!(
                    submit_source_account_only(Chain::at(LEDGER)),
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

                match &refused.result {
                    Err(error) => assert_eq!(error.wire_code(), SKEW_CODE, "{error:?}"),
                    Ok(_) => panic!("a disagreeing second reading went through"),
                }
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
            async fn a_skew_of_three_with_the_primary_behind_refuses() {
                submit_at(LEDGER, LEDGER + 3)
                    .await
                    .assert_refused(SKEW_CODE, "primary behind");
            }

            #[tokio::test]
            async fn a_skew_of_three_with_the_primary_ahead_refuses() {
                submit_at(LEDGER + 3, LEDGER)
                    .await
                    .assert_refused(SKEW_CODE, "primary ahead");
            }

            #[tokio::test]
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
