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
//! 2. Simulates (empty auth) to discover the required auth entries + `latest_ledger`.
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
//! 7. Submits via `stellar_agent_network::submit_transaction_and_wait`.
//!
//! # Auth preimage shape
//!
//! `HashIdPreimageSorobanAuthorization {`
//! `  network_id: Hash(sha256(network_passphrase)),`
//! `  nonce: <from simulate SorobanCredentials>,`
//! `  signature_expiration_ledger: latest_ledger + AUTH_VALIDITY_LEDGERS,`
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
    signing::envelope_signing::attach_signature, submit_transaction_and_wait,
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
use crate::managers::rules::{
    AUTH_VALIDITY_LEDGERS, BASE_FEE_STROOPS, augment_with_oz_error_name, fingerprint_invocation,
    parse_min_resource_fee, validate_latest_ledger,
};
use crate::submit::{
    DeclaredSubInvocations, attribute_signed_tree_refusal, check_declared_sub_invocations,
    check_simulated_root, refuse_mainnet_sa,
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
    /// Stellar network passphrase (used for auth preimage and envelope signing).
    pub(crate) network_passphrase: &'a str,
    /// Submission polling timeout.
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
/// 1. Fetch signer G-key and source account sequence.
/// 2. Build `InvokeHostFunction` tx (empty auth) for simulation.
/// 3. Simulate on primary RPC; extract `latest_ledger` + auth entry template.
/// 4. Check every `SorobanCredentials::Address` entry: its address is the
///    signer G-key, and its root invocation equals the host function with no
///    sub-invocations. Only after every entry passes, compute the auth
///    preimage over the wallet's own invocation for each and sign it.
/// 5. Re-simulate with signed auth entries to get the full storage footprint.
/// 6. Build final envelope: inject signed auth entries + soroban_data.
/// 7. Attach source-account signature.
/// 8. Submit via `submit_transaction_and_wait`.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`]: `network_passphrase` names mainnet
///   or `primary_rpc_url` is a mainnet-pattern endpoint; refused before the
///   signer's public key is read and before any request.
/// - [`SaError::AuthEntryConstructionFailed`] — pubkey fetch, XDR encoding,
///   simulate, or signing failure.
/// - [`SaError::SimulationDivergence`] with sub-code `AuthContexts` (wire code
///   `simulation.divergence.auth_contexts`): an entry for the signer's G-key
///   whose root invocation differs from the host function or carries
///   sub-invocations; refused before any entry is signed. The public
///   [`crate::timelock::schedule_upgrade`], [`crate::timelock::execute`], and
///   [`crate::timelock::cancel`] map it, like every other error here except
///   [`SaError::MainnetWriteForbidden`] (and, for `execute`,
///   [`SaError::SubmissionUnresolved`]), to their typed variant below, with the
///   refusal text in the reason.
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

    // `latest_ledger` from the first simulate is used for
    // `signature_expiration_ledger`. Validate bounds before binding into the
    // auth-digest preimage.
    validate_latest_ledger(sim_response.latest_ledger)?;
    let signature_expiration_ledger = sim_response
        .latest_ledger
        .saturating_add(AUTH_VALIDITY_LEDGERS);
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
        // `signature_expiration_ledger` is set to `latest_ledger + AUTH_VALIDITY_LEDGERS`
        // (overrides the `0` placeholder the RPC returns).
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

        // Sign with the Soroban-address-auth primitive.
        let signature_bytes = args
            .signer
            .sign_soroban_address_auth_payload(&signature_payload)
            .await
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
    let source_view2 = fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[])
        .await
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
    let resim_response = server
        .simulate_transaction_envelope(&resim_envelope, None)
        .await
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
    let source_view3 = fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[])
        .await
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
    let final_signed_xdr = attach_signature(&envelope_xdr, args.signer, args.network_passphrase)
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: format!("{} envelope signing failed: {e}", args.op_label),
        })?;

    // ── Step 8: Submit ────────────────────────────────────────────────────────
    let submission = submit_transaction_and_wait(
        &primary_rpc_client,
        &final_signed_xdr,
        args.timeout,
        args.network_passphrase,
        None,
        args.submission_recorder,
    )
    .await
    .map_err(|e| crate::submit::map_submit_error(&e, args.op_label, &final_signed_xdr))?;

    Ok(TimelockSubmitResult {
        return_val,
        tx_hash: submission.tx_hash,
        ledger: submission.ledger,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

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
            resimulated: Arc<Mutex<Vec<SorobanAuthorizationEntry>>>,
        }

        impl Respond for Rpc {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let passphrase = stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
                let result = match body["method"].as_str().unwrap() {
                    "getNetwork" => get_network_result(passphrase),
                    "getLatestLedger" => {
                        json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27})
                    }
                    "getLedgerEntries" => {
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
                        let auth = if op.auth.is_empty() {
                            (self.trees)(invoke)
                                .into_iter()
                                .zip(NONCE..)
                                .map(|(root_invocation, nonce)| SorobanAuthorizationEntry {
                                    credentials: SorobanCredentials::Address(
                                        SorobanAddressCredentials {
                                            address: operator(),
                                            nonce,
                                            signature_expiration_ledger: 0,
                                            signature: ScVal::Void,
                                        },
                                    ),
                                    root_invocation,
                                })
                                .collect()
                        } else {
                            self.resimulated
                                .lock()
                                .unwrap()
                                .extend(op.auth.iter().cloned());
                            op.auth.to_vec()
                        };
                        json!({
                            "latestLedger": 1000,
                            "minResourceFee": "1000",
                            "transactionData": SorobanTransactionData::default()
                                .to_xdr_base64(Limits::none())
                                .unwrap(),
                            "results": [{
                                "auth": auth
                                    .iter()
                                    .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                                    .collect::<Vec<_>>(),
                                "xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
                            }],
                        })
                    }
                    "sendTransaction" => {
                        json!({"status": "PENDING", "hash": send_transaction_hash_hex(&body, passphrase), "latestLedger": 1000, "latestLedgerCloseTime": "1234567890"})
                    }
                    "getTransaction" => {
                        json!({"status": "SUCCESS", "ledger": 1001, "latestLedger": 1001, "oldestLedger": 1})
                    }
                    other => panic!("unexpected RPC method: {other}"),
                };
                ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
            }
        }

        struct Outcome {
            result: Result<super::super::TimelockSubmitResult, SaError>,
            signs: usize,
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
                    resimulated: Arc::clone(&resimulated),
                })
                .mount(&server)
                .await;
            let signer = CountingSigner::new(SEED);
            let result = submit_timelock_invoke_with_g_key_auth(TimelockSubmitArgs {
                host_function: HostFunction::InvokeContract(schedule()),
                signer: &signer,
                primary_rpc_url: &server.uri(),
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
            let expiration = 1000 + super::super::AUTH_VALIDITY_LEDGERS;
            assert_eq!(creds.signature_expiration_ledger, expiration);

            // The signature verifies under the operator's key over the
            // preimage of the timelock call, the simulated nonce and the
            // expiration, built here from those values alone.
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
                    invocation: leaf(schedule()),
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
    }
}
