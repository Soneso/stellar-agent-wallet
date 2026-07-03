//! Smart-account Soroban authorisation-entry construction.
//!
//! Builds the pre-signature state for a `SorobanAuthorizationEntry`:
//! the root invocation, Soroban authorization signature payload, rule-ID XDR,
//! and auth digest. Signer bytes are attached through the network-crate
//! `Signer::sign_auth_digest` sibling primitive.

use sha2::{Digest as _, Sha256};
use stellar_agent_core::smart_account::auth_digest::compute_auth_digest;
use stellar_agent_core::smart_account::rule_id::{ContextRuleId, encode_context_rule_ids};
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction,
    InvokeContractArgs, InvokeHostFunctionOp, Limits, Operation, OperationBody, PublicKey,
    ScAddress, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Uint256, VecM, WriteXdr,
};

use crate::SaError;
use crate::error::SimulationDivergenceSubCode;
use crate::signing::divergence::{
    EnvelopeContext, SimulationContext, detect_simulation_divergence,
};

/// Simulation metadata required to build the smart-account auth digest.
///
/// Uses Soroban authorization preimage fields matching the OZ `__check_auth`
/// recompute path. Carries the simulation context whose `context_rule_ids`
/// must align with the signed envelope, along with the Soroban auth-entry
/// nonce, expiration, and root invocation data needed for invoker auth.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizationSimulation {
    /// Narrow simulation projection used by the divergence detector.
    pub context: SimulationContext,
    /// SHA-256 network ID bytes for the target network.
    pub network_id: [u8; 32],
    /// Soroban address-credential nonce obtained from simulation.
    pub nonce: i64,
    /// Signature expiration ledger obtained from simulation.
    pub signature_expiration_ledger: u32,
}

/// Pre-signature smart-account authorisation-entry state.
///
/// This deliberately does not store a full `SorobanAuthorizationEntry` with a
/// placeholder signature. The signing step consumes this state, calls
/// `Signer::sign_auth_digest`, and only then assembles the final credentials.
///
/// Stores the digest bytes that must be signed for OZ v0.7.1 `__check_auth`.
/// Preserves the Soroban-side root invocation and address-credential fields
/// needed to complete the auth entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartialSorobanAuthorizationEntry {
    /// Smart-account contract address whose credentials will carry the signature.
    pub smart_account: ScAddress,
    /// Soroban address-credential nonce obtained from simulation.
    pub nonce: i64,
    /// Signature expiration ledger obtained from simulation.
    pub signature_expiration_ledger: u32,
    /// Root invocation that the auth entry authorises.
    pub root_invocation: SorobanAuthorizedInvocation,
    /// SHA-256 of `HashIdPreimage::SorobanAuthorization` XDR.
    pub signature_payload: [u8; 32],
    /// SHA-256 of `signature_payload || encode_context_rule_ids(rule_ids)`.
    pub auth_digest: [u8; 32],
    /// Context-rule IDs bound into `auth_digest`.
    pub context_rule_ids: Vec<ContextRuleId>,
}

/// Builds pre-signature state for a smart-account-targeted invocation.
///
/// This is the call-site-of-record that prepares the auth digest later signed
/// by `Signer::sign_auth_digest`. Returns [`PartialSorobanAuthorizationEntry`]
/// rather than a complete `SorobanAuthorizationEntry` because the signer
/// bytes are attached in a separate step.
///
/// # Sub-invocations
///
/// The `prepared_sub_invocations` parameter carries the sub-invocations list
/// from Soroban-RPC's `simulateTransaction` response. For single-contract
/// invocations (all non-multicall paths), this is `VecM::default()` (empty).
/// For the multicall router path, the simulate response returns the router's
/// sub-invocations (one per inner); passing them here ensures the auth digest
/// is computed over the correct `SorobanAuthorizedInvocation` tree, which
/// matches what the on-chain `__check_auth` will re-hash.
///
/// # Refusal path
///
/// - Empty `rule_ids` returns [`SaError::RuleIdMismatch`].
/// - `rule_ids.len() != auth_contexts.len()` returns [`SaError::RuleIdMismatch`].
/// - Simulation/envelope mismatch returns [`SaError::SimulationDivergence`].
/// - Wallet-internal XDR encode/conversion failure returns
///   [`SaError::AuthEntryConstructionFailed`] with the corresponding stage.
///
/// # Errors
///
/// - [`SaError::RuleIdMismatch`] — index-alignment failures between `rule_ids`
///   and the simulation auth-context list.
/// - [`SaError::SimulationDivergence`] — simulation context diverges from the
///   to-be-submitted envelope (tamper detection: checks both cryptographic binding
///   and simulation-context consistency).
/// - [`SaError::AuthEntryConstructionFailed`] — wallet-internal XDR encoding
///   or container-conversion failure during auth-entry assembly. Stage values:
///   `"context_rule_ids"` (rule-IDs encode), `"auth_contexts_args"` (args
///   `VecM` overflow), `"signature_payload"` (preimage XDR encode).
pub async fn build_authorization_entry(
    target_contract: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &EnvelopeContext,
) -> Result<PartialSorobanAuthorizationEntry, SaError> {
    build_authorization_entry_with_sub_invocations(
        target_contract,
        function_name,
        args,
        rule_ids,
        simulation,
        envelope,
        VecM::default(),
    )
    .await
}

/// Builds pre-signature state with an explicit `sub_invocations` tree.
///
/// Identical to [`build_authorization_entry`] but allows the caller to inject
/// a pre-constructed `sub_invocations` tree into the root invocation.
///
/// Used by the multicall path (`submit_multicall_bundle`) where the
/// Soroban-RPC simulate response returns sub-invocations for each inner
/// contract call. Threading these into the auth digest ensures the wallet
/// signs the correct invocation tree, matching what the on-chain
/// `__check_auth` will re-verify.
///
/// # Errors
///
/// Returns `SaError::RuleIdMismatch` when `rule_ids` is empty or its length
/// does not match `simulation.context.auth_contexts.len()`.  Returns other
/// `SaError` variants from the underlying `build_authorization_entry` logic
/// (nonce construction, XDR encoding, signer errors).
///
pub async fn build_authorization_entry_with_sub_invocations(
    target_contract: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &EnvelopeContext,
    sub_invocations: VecM<SorobanAuthorizedInvocation>,
) -> Result<PartialSorobanAuthorizationEntry, SaError> {
    let expected_len = simulation.context.auth_contexts.len();
    if rule_ids.is_empty() {
        return Err(SaError::RuleIdMismatch {
            expected_len,
            observed_len: 0,
        });
    }

    if rule_ids.len() != expected_len {
        return Err(SaError::RuleIdMismatch {
            expected_len,
            observed_len: rule_ids.len(),
        });
    }

    if rule_ids != envelope.context_rule_ids {
        return Err(SaError::SimulationDivergence {
            sub_code: SimulationDivergenceSubCode::ContextRuleIds,
            redacted_reason: "builder rule_ids differ from envelope context_rule_ids".to_owned(),
        });
    }

    detect_simulation_divergence(&simulation.context, envelope)?;

    let root_invocation = root_contract_invocation(
        target_contract.clone(),
        function_name,
        args,
        sub_invocations,
    )?;
    let signature_payload = compute_signature_payload(
        simulation.network_id,
        simulation.nonce,
        simulation.signature_expiration_ledger,
        root_invocation.clone(),
    )?;
    let rule_ids_xdr =
        encode_context_rule_ids(&rule_ids).map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "context_rule_ids",
            redacted_reason: format!("context_rule_ids XDR encode failed before signing: {e}"),
        })?;
    let auth_digest = compute_auth_digest(&signature_payload, &rule_ids_xdr);

    Ok(PartialSorobanAuthorizationEntry {
        smart_account: target_contract,
        nonce: simulation.nonce,
        signature_expiration_ledger: simulation.signature_expiration_ledger,
        root_invocation,
        signature_payload,
        auth_digest: *auth_digest.as_bytes(),
        context_rule_ids: rule_ids,
    })
}

fn root_contract_invocation(
    target_contract: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    sub_invocations: VecM<SorobanAuthorizedInvocation>,
) -> Result<SorobanAuthorizedInvocation, SaError> {
    // Manual InvokeContractArgs construction. The OZ `stellar-accounts` v0.7.1
    // surface exposes context-rule operations through contract trait/client
    // methods, not as standalone argument helper types — re-using a generated
    // helper would tie us to a particular client harness. Constructing the
    // ScVal vector here keeps the builder host-agnostic.
    let args: VecM<ScVal> = args
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_contexts_args",
            redacted_reason: format!(
                "invoke args XDR vector conversion failed before signing: {e:?}"
            ),
        })?;
    Ok(SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: target_contract,
            function_name,
            args,
        }),
        sub_invocations,
    })
}

fn compute_signature_payload(
    network_id: [u8; 32],
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: SorobanAuthorizedInvocation,
) -> Result<[u8; 32], SaError> {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger,
        invocation,
    });
    let preimage_xdr =
        preimage
            .to_xdr(Limits::none())
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "signature_payload",
                redacted_reason: format!(
                    "soroban authorization preimage XDR encode failed before signing: {e:?}"
                ),
            })?;
    let digest: [u8; 32] = Sha256::digest(preimage_xdr).into();
    Ok(digest)
}

/// Completes a [`PartialSorobanAuthorizationEntry`] by attaching the signer's
/// signature over `partial.auth_digest`, producing a fully-signed
/// [`SorobanAuthorizationEntry`] suitable for transaction submission.
///
/// Binds the user's ed25519 signature to the auth-digest constructed by
/// `build_authorization_entry`, which is computed as
/// `sha256(signature_payload || encode_context_rule_ids(rule_ids))`. The OZ
/// on-chain `__check_auth` recomputes the same digest from the submitted
/// `context_rule_ids` and verifies the signature; a sponsor-rewritten
/// `context_rule_ids` produces a different digest and the verification fails.
///
/// The function calls [`Signer::public_key`] once to derive the user's
/// Stellar address, then [`Signer::sign_auth_digest`] once to produce the
/// 64-byte ed25519 signature, then assembles the on-chain canonical
/// `AuthPayload` ScVal and wraps it
/// in [`SorobanCredentials::Address`].
///
/// # Single call site
///
/// This is the single call site of [`Signer::sign_auth_digest`] across the
/// workspace. Any additional caller is architecturally invalid — smart-account
/// code paths must not invoke the `sign_tx_payload` primitive.
///
/// # AuthPayload shape (OZ canonical)
///
/// The signature ScVal stored in `SorobanCredentials::Address::signature`
/// follows the v0.7.0 OZ smart-account contract format:
///
/// ```text
/// ScVal::Map([
///   { key: Symbol("context_rule_ids"), val: Vec([U32(id), ...]) },
///   { key: Symbol("signers"),          val: Map([{ key: signer_scval, val: Bytes(sig_64) }]) }
/// ])
/// ```
///
/// where `signer_scval` for the single Native ed25519 signer is
/// `Vec([Symbol("Delegated"), Address(g_strkey)])`. The Map keys are sorted
/// alphabetically (`context_rule_ids` precedes `signers`) per the on-chain
/// canonical encoding rule.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` —
///   signer `public_key()` fetch or `sign_auth_digest()` failure, or any of
///   the bounded ScVal/ScMap/VecM/BytesM conversions used to build the
///   AuthPayload shape. The conversions are infallible by construction for
///   bounded inputs (1 signer, ≤ 15 rule_ids per OZ caps, fixed
///   pubkey/signature byte widths) but the result type is preserved for
///   trait uniformity and for the future hardware-signer paths where the
///   upstream `WalletError` propagation is the substantive failure case.
pub async fn complete_authorization_entry(
    partial: PartialSorobanAuthorizationEntry,
    signer: &(dyn Signer + Send + Sync),
) -> Result<SorobanAuthorizationEntry, SaError> {
    let pubkey = signer
        .public_key()
        .await
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("signer public_key fetch failed before signing: {e}"),
        })?;

    let signature_bytes = signer
        .sign_auth_digest(&partial.auth_digest)
        .await
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("auth-digest signing failed: {e}"),
        })?;

    let auth_payload =
        build_auth_payload_scval(pubkey.0, &signature_bytes, &partial.context_rule_ids)?;

    let credentials = SorobanCredentials::Address(SorobanAddressCredentials {
        address: partial.smart_account,
        nonce: partial.nonce,
        signature_expiration_ledger: partial.signature_expiration_ledger,
        signature: auth_payload,
    });

    Ok(SorobanAuthorizationEntry {
        credentials,
        root_invocation: partial.root_invocation,
    })
}

/// Constructs the on-chain canonical `AuthPayload` ScVal for a single
/// Delegated ed25519 signer.
///
/// See [`complete_authorization_entry`] for the encoding contract.
fn build_auth_payload_scval(
    pubkey_bytes: [u8; 32],
    signature_bytes: &[u8; 64],
    context_rule_ids: &[ContextRuleId],
) -> Result<ScVal, SaError> {
    build_multi_signer_auth_payload_scval(&[(pubkey_bytes, *signature_bytes)], context_rule_ids)
}

/// Constructs the on-chain canonical `AuthPayload` ScVal for multiple
/// Delegated ed25519 signers.
///
/// All signers contribute signatures over the **same** auth digest (produced by
/// [`build_authorization_entry`] for the shared invocation root). The entries
/// in the `signers` map are sorted by XDR-encoded key (`Vec([Symbol("Delegated"),
/// Address(...)])`) in ascending byte order, which is the canonical
/// `ScMap` sort order enforced by the Soroban host.
///
/// In practice, because the key XDR encodes as `[discriminant(Vec), ...,
/// discriminant(Symbol), "Delegated", discriminant(Address),
/// discriminant(AccountId), pubkey_bytes]`, sorting by pubkey bytes is
/// equivalent to sorting by the full key XDR for Delegated signers — the
/// common prefix is identical for all entries.  Both orderings are applied
/// (sort by pubkey bytes first; XDR-level order is maintained by construction
/// since pubkey bytes are the only differing suffix for the `Delegated` variant).
///
/// The on-chain canonical shape is
/// `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids: Vec<u32> }`
/// per the OpenZeppelin smart-account contract, with the outer map keys in
/// canonical order and the signers map encoded over the signer keys.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` on
/// any XDR encoding failure or `signers` empty.
fn build_multi_signer_auth_payload_scval(
    signers: &[([u8; 32], [u8; 64])],
    context_rule_ids: &[ContextRuleId],
) -> Result<ScVal, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    if signers.is_empty() {
        return Err(auth_payload_err(
            "build_multi_signer_auth_payload_scval: signers must not be empty".to_owned(),
        ));
    }

    // Sort signers by pubkey bytes for canonical ScMap key order.
    // For Delegated signers the XDR key is Vec([Symbol("Delegated"), Address(pubkey)]);
    // since the Symbol prefix is identical for all entries, pubkey bytes are the
    // effective sort key.
    //
    // Sort-by-pubkey is valid only for homogeneous Delegated-only groups.
    // When External-variant signers are added the Symbol prefix differs
    // across entries (ScVal::Vec([Symbol("External"), ...])); the sort must
    // switch to full XDR-encoded-key byte comparison over the hex-encoded
    // canonical key.
    // Not yet supported: heterogeneous signer-set sorting.
    let mut sorted = signers.to_vec();
    sorted.sort_by_key(|(pk, _)| *pk);

    // Build the signers Map entries.
    // Key: Vec([Symbol("Delegated"), Address(g_strkey)]) per the OpenZeppelin
    // smart-account contract's tuple-variant encoding.
    // Value: Bytes(64-byte signature).
    let mut signers_map_entries: Vec<ScMapEntry> = Vec::with_capacity(sorted.len());
    for (pubkey_bytes, sig_bytes) in &sorted {
        let user_address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            *pubkey_bytes,
        ))));
        let delegated_sym = ScSymbol::try_from("Delegated")
            .map_err(|e| auth_payload_err(format!("encode Delegated symbol: {e:?}")))?;
        let signer_key_vec: VecM<ScVal> =
            vec![ScVal::Symbol(delegated_sym), ScVal::Address(user_address)]
                .try_into()
                .map_err(|e| auth_payload_err(format!("encode signer-key ScVec: {e:?}")))?;
        let signer_key = ScVal::Vec(Some(ScVec(signer_key_vec)));

        let signature_bytes_m: BytesM = sig_bytes
            .to_vec()
            .try_into()
            .map_err(|e| auth_payload_err(format!("encode signature BytesM: {e:?}")))?;
        let signature_value = ScVal::Bytes(ScBytes(signature_bytes_m));

        signers_map_entries.push(ScMapEntry {
            key: signer_key,
            val: signature_value,
        });
    }

    let signers_entries: VecM<ScMapEntry> = signers_map_entries
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode signers ScMap: {e:?}")))?;
    let signers_map = ScVal::Map(Some(ScMap(signers_entries)));

    // context_rule_ids Vec: Vec<ScVal::U32>.
    let rule_ids_scval: Vec<ScVal> = context_rule_ids
        .iter()
        .map(|id| ScVal::U32(id.as_u32()))
        .collect();
    let rule_ids_vec: VecM<ScVal> = rule_ids_scval
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode rule_ids ScVec: {e:?}")))?;
    let rule_ids_value = ScVal::Vec(Some(ScVec(rule_ids_vec)));

    // Outer AuthPayload Map. Keys are sorted alphabetically per the on-chain
    // canonical encoding rule: `context_rule_ids` precedes `signers`. This
    // mirrors the canonical multi-signer auth-payload key order
    // byte-for-byte.
    let context_rule_ids_sym = ScSymbol::try_from("context_rule_ids")
        .map_err(|e| auth_payload_err(format!("encode context_rule_ids symbol: {e:?}")))?;
    let signers_sym = ScSymbol::try_from("signers")
        .map_err(|e| auth_payload_err(format!("encode signers symbol: {e:?}")))?;

    let outer_entries: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(context_rule_ids_sym),
            val: rule_ids_value,
        },
        ScMapEntry {
            key: ScVal::Symbol(signers_sym),
            val: signers_map,
        },
    ]
    .try_into()
    .map_err(|e| auth_payload_err(format!("encode AuthPayload outer ScMap: {e:?}")))?;

    Ok(ScVal::Map(Some(ScMap(outer_entries))))
}

/// Completes a [`PartialSorobanAuthorizationEntry`] for multiple qualifying
/// Delegated ed25519 signers.
///
/// All signers sign the **same** `partial.auth_digest`. Their signatures are
/// collected into a single `AuthPayload` with N entries in the `signers` map,
/// producing ONE `SorobanAuthorizationEntry` for the smart account contract.
///
/// This is the multi-signer counterpart to [`complete_authorization_entry`]:
/// single-signer callers use the existing function; the quorum path uses this
/// one.
///
/// # On-chain authentication
///
/// The on-chain canonical shape is `AuthPayload { signers: Map<Signer, Bytes>,
/// ... }` per the OpenZeppelin smart-account contract.
/// All N signers' entries reside in the SAME map; the on-chain `do_check_auth`
/// iterates the map and authenticates each entry in turn before delegating to
/// the policy's `enforce(authenticated_signers)`.
///
/// # Signers-map value choice
///
/// The OpenZeppelin `authenticate(Delegated(addr))` path only calls
/// `addr.require_auth_for_args((auth_digest,))` — it does NOT verify the Map value's
/// `sig_data` parameter for the `Delegated` variant, so an empty-bytes placeholder
/// would also pass. The real signature lives in the
/// separate per-signer delegated G-key sub-auth-entry which the wallet emits at
/// `authorization.rs::collect_group_entries`.
///
/// The wallet stores the actual 64-byte Ed25519 signature here (not empty bytes) for
/// audit-trail completeness — every byte sent on the wire is grep-able to the producing
/// signer. Functionally both shapes pass `__check_auth`; storing the signature adds ~64 bytes
/// per signer to the wire payload + chain XDR. This choice is intentional
/// (audit-trail completeness over minimal wire size).
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` on:
/// - `signers` is empty.
/// - Any signer's `public_key()` fetch fails.
/// - Any signer's `sign_auth_digest()` fails.
/// - Any XDR encoding failure.
///
pub async fn complete_authorization_entry_multi_signer(
    partial: PartialSorobanAuthorizationEntry,
    signers: &[&(dyn Signer + Send + Sync)],
) -> Result<SorobanAuthorizationEntry, SaError> {
    if signers.is_empty() {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: "complete_authorization_entry_multi_signer: signers must not be empty"
                .to_owned(),
        });
    }

    // Collect (pubkey, signature) pairs for all qualifying signers.
    let mut signer_pairs: Vec<([u8; 32], [u8; 64])> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;

        let signature_bytes = signer
            .sign_auth_digest(&partial.auth_digest)
            .await
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("auth-digest signing failed: {e}"),
            })?;

        signer_pairs.push((pubkey.0, signature_bytes));
    }

    let auth_payload =
        build_multi_signer_auth_payload_scval(&signer_pairs, &partial.context_rule_ids)?;

    let credentials = SorobanCredentials::Address(SorobanAddressCredentials {
        address: partial.smart_account,
        nonce: partial.nonce,
        signature_expiration_ledger: partial.signature_expiration_ledger,
        signature: auth_payload,
    });

    Ok(SorobanAuthorizationEntry {
        credentials,
        root_invocation: partial.root_invocation,
    })
}

/// Builds and signs the secondary "Delegated G-key" auth entry that OZ
/// smart accounts require alongside the smart-account auth entry whenever
/// the validating context rule includes `Signer::Delegated(addr)` where
/// `addr` is a Stellar G-key.
///
/// # Why this entry exists
///
/// The OpenZeppelin `do_check_auth` for `Signer::Delegated(addr)` calls
/// `addr.require_auth_for_args((auth_digest,))`.
/// The Soroban host requires this nested auth call to be satisfied by an
/// explicit `SorobanAuthorizationEntry` whose credentials are the G-key.
/// Source-account auto-auth from the SEP-23 envelope signature does NOT
/// propagate into nested __check_auth calls.
///
/// The simulator does not auto-discover this entry (per OZ docs:
/// "authorization entry for that signer is not included in the simulation
/// output"); the wallet must construct it manually.
///
/// # Design notes
///
/// 1. **Smart-account entry's signers-map signature value.** An empty-bytes
///    placeholder would also pass, since the OpenZeppelin
///    `authenticate(Delegated, ...)` path ignores the `sig_data` parameter
///    on the Delegated branch. This wallet places the actual
///    ed25519 signature over `auth_digest` (per
///    [`build_auth_payload_scval`]). Storing the real signature
///    preserves a uniform signature shape across all signer types at the
///    cost of one extra ed25519 sign per mutating operation.
/// 2. **Auth-entry construction style.** This wallet constructs the entry via
///    raw `stellar_xdr::*` types inline rather than through a higher-level
///    helper that encapsulates nonce generation + preimage construction +
///    signature shape assembly. The inline form keeps the on-chain wire shape
///    explicit.
/// 3. **Nonce source.** The wallet uses `rand_core::OsRng` (CSPRNG) for the
///    nonce, giving collision-resistance under same-millisecond retries rather
///    than a millisecond-timestamp source.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] (`stage = "auth_payload"`)
///   if XDR encoding, ScVal construction, or `Signer` operations fail.
pub(crate) async fn build_and_sign_delegated_g_key_entry(
    smart_account: &ScAddress,
    auth_digest: &[u8; 32],
    signature_expiration_ledger: u32,
    signer: &(dyn Signer + Send + Sync),
    network_passphrase: &str,
) -> Result<SorobanAuthorizationEntry, SaError> {
    use stellar_xdr::{
        AccountId, BytesM, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, PublicKey,
        ScBytes, ScMap, ScMapEntry, SorobanAddressCredentials, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, Uint256, WriteXdr,
    };

    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    // The G-key whose require_auth_for_args call must be authorised.
    // In the single-signer flow the manager's signer doubles as both the
    // smart-account-rule signer AND the Delegated G-key.
    let pubkey = signer.public_key().await.map_err(|e| {
        auth_payload_err(format!(
            "delegated entry: signer public_key fetch failed: {e}"
        ))
    })?;
    let g_key_address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        pubkey.0,
    ))));

    // root_invocation: __check_auth(auth_digest) on the smart account.
    //
    // OZ's authenticate(Delegated) calls
    // `addr.require_auth_for_args((auth_digest,))` from inside __check_auth.
    // The require_auth-for-args context is therefore (current_contract =
    // smart_account, function = __check_auth, args = (auth_digest,)).
    let auth_digest_bytesm: BytesM = auth_digest.to_vec().try_into().map_err(|e| {
        auth_payload_err(format!("delegated entry: encode auth_digest BytesM: {e:?}"))
    })?;
    let auth_digest_scval = ScVal::Bytes(ScBytes(auth_digest_bytesm));

    let check_auth_sym = ScSymbol::try_from("__check_auth").map_err(|e| {
        auth_payload_err(format!(
            "delegated entry: encode __check_auth Symbol: {e:?}"
        ))
    })?;
    let check_auth_args: VecM<ScVal> = vec![auth_digest_scval].try_into().map_err(|e| {
        auth_payload_err(format!(
            "delegated entry: encode __check_auth args VecM: {e:?}"
        ))
    })?;

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: smart_account.clone(),
            function_name: check_auth_sym,
            args: check_auth_args,
        }),
        sub_invocations: VecM::default(),
    };

    // Fresh CSPRNG-sourced nonce for the Delegated entry. Soroban requires
    // distinct (address, nonce) pairs across all auth entries in a single
    // transaction; the smart-account entry's nonce comes from RPC simulate,
    // and this entry must not collide with it. Sourced from `OsRng` for
    // collision-resistance under retry: an earlier revision derived the
    // nonce from the `auth_digest` tail bytes, but auth_digest is itself
    // deterministic given the same simulate output, so same-ledger retry
    // would produce colliding nonces. The value is non-secret. Same RNG
    // source as `deployment/deploy.rs::generate_random_hex_8` (8-byte OsRng).
    let nonce: i64 = {
        use rand_core::RngCore as _;
        let mut bytes = [0_u8; 8];
        rand_core::OsRng.fill_bytes(&mut bytes);
        i64::from_le_bytes(bytes)
    };

    // Compute the Soroban auth-entry signature_payload.
    let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let preimage_xdr = preimage.to_xdr(Limits::none()).map_err(|e| {
        auth_payload_err(format!(
            "delegated entry: signature_payload XDR encode: {e:?}"
        ))
    })?;
    let signature_payload: [u8; 32] = Sha256::digest(preimage_xdr).into();

    // Sign with the dedicated Soroban-address-auth primitive. Distinct
    // call-site from `sign_tx_payload` and `sign_auth_digest` per the
    // Signer trait's call-site discipline.
    let signature_bytes = signer
        .sign_soroban_address_auth_payload(&signature_payload)
        .await
        .map_err(|e| auth_payload_err(format!("delegated entry: signing failed: {e}")))?;

    // Stellar source-account auth signature shape:
    // ScVal::Vec([ScVal::Map([{public_key: BytesN<32>, signature: BytesN<64>}])])
    // Cross-reference: js-stellar-base auth.js:171-184 (canonical encoding
    // for SorobanCredentials::Address whose address is a Stellar account).
    let public_key_sym = ScSymbol::try_from("public_key").map_err(|e| {
        auth_payload_err(format!("delegated entry: encode public_key Symbol: {e:?}"))
    })?;
    let signature_sym = ScSymbol::try_from("signature").map_err(|e| {
        auth_payload_err(format!("delegated entry: encode signature Symbol: {e:?}"))
    })?;

    let pubkey_bytesm: BytesM =
        pubkey.0.to_vec().try_into().map_err(|e| {
            auth_payload_err(format!("delegated entry: encode pubkey BytesM: {e:?}"))
        })?;
    let sig_bytesm: BytesM = signature_bytes.to_vec().try_into().map_err(|e| {
        auth_payload_err(format!("delegated entry: encode signature BytesM: {e:?}"))
    })?;

    let inner_map_entries: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(public_key_sym),
            val: ScVal::Bytes(ScBytes(pubkey_bytesm)),
        },
        ScMapEntry {
            key: ScVal::Symbol(signature_sym),
            val: ScVal::Bytes(ScBytes(sig_bytesm)),
        },
    ]
    .try_into()
    .map_err(|e| auth_payload_err(format!("delegated entry: encode inner ScMap: {e:?}")))?;
    let inner_map = ScVal::Map(Some(ScMap(inner_map_entries)));

    let outer_vec: VecM<ScVal> = vec![inner_map]
        .try_into()
        .map_err(|e| auth_payload_err(format!("delegated entry: encode outer ScVec: {e:?}")))?;
    let signature_scval = ScVal::Vec(Some(ScVec(outer_vec)));

    Ok(SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: g_key_address,
            nonce,
            signature_expiration_ledger,
            signature: signature_scval,
        }),
        root_invocation: invocation,
    })
}

/// Re-simulates the InvokeHostFunction op with the signed smart-account
/// auth entry attached, returning the new simulation response. The new
/// response's `transaction_data` carries the proper footprint (including
/// `ContextRuleData(rule_id)` and `SignerData(signer_id)` keys read by
/// the on-chain `__check_auth`); the new `min_resource_fee` reflects the
/// real cost of running `__check_auth` on top of the entrypoint body.
///
/// Without this re-simulation step the first simulate's footprint would
/// be used, which omits `__check_auth`'s storage reads (because the
/// first simulate ran with empty `auth` and the host's auto-discovery
/// path skips `__check_auth` invocation). Submitting on that footprint
/// traps with `OpInner(InvokeHostFunction(Trapped))` and the on-chain
/// diagnostic reports "trying to access contract data key outside of
/// the footprint".
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible RPC + smart-account + auth-entry-list + source-account context required \
              for the off-chain re-simulate-with-signed-auth flow; collapsing into a struct would \
              hide the per-call lifetime contracts of `&Server` and `&StellarRpcClient`"
)]
pub(crate) async fn resimulate_with_signed_auth(
    server: &Client,
    rpc_client: &StellarRpcClient,
    smart_account: &ScAddress,
    function_name: ScSymbol,
    args: VecM<ScVal>,
    signed_auth_entries: Vec<SorobanAuthorizationEntry>,
    source_account_strkey: &str,
    network_passphrase: &str,
) -> Result<stellar_rpc_client::SimulateTransactionResponse, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    let invoke = InvokeContractArgs {
        contract_address: smart_account.clone(),
        function_name,
        args,
    };
    let host_fn = HostFunction::InvokeContract(invoke);
    let auth_vecm: VecM<SorobanAuthorizationEntry> = signed_auth_entries
        .try_into()
        .map_err(|e| auth_payload_err(format!("re-simulate: encode auth VecM: {e:?}")))?;

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_fn,
            auth: auth_vecm,
        }),
    };

    // Refetch the source account view; the first simulate may have left
    // its sequence stable but build_for_simulation reads `current+1`, and
    // we want a fresh BaselibAccount snapshot that mirrors the final
    // submitted tx's source-account state.
    let source_view = fetch_account(rpc_client, source_account_strkey, &[])
        .await
        .map_err(|e| auth_payload_err(format!("re-simulate: source-account fetch failed: {e}")))?;
    let mut source_account = BaselibAccount::new(
        source_account_strkey,
        &source_view.sequence_number.to_string(),
    )
    .map_err(|e| auth_payload_err(format!("re-simulate: BaselibAccount::new failed: {e:?}")))?;

    let mut tx_builder = TransactionBuilder::new(&mut source_account, network_passphrase, None);
    tx_builder.fee(crate::managers::rules::BASE_FEE_STROOPS);
    tx_builder.add_operation(op);
    let resim_tx = tx_builder.build_for_simulation();

    let resim_envelope = resim_tx
        .to_envelope()
        .map_err(|e| auth_payload_err(format!("re-simulate: to_envelope failed: {e:?}")))?;
    let resim_response = server
        .simulate_transaction_envelope(&resim_envelope, None)
        .await
        .map_err(|e| {
            auth_payload_err(format!(
                "re-simulate: simulate_transaction_envelope failed: {e}"
            ))
        })?;

    if let Some(sim_error) = &resim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!(
                "re-simulate returned error: {}",
                crate::managers::rules::augment_with_oz_error_name(sim_error)
            ),
        });
    }
    if resim_response.min_resource_fee == 0 || resim_response.transaction_data.is_empty() {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "re-simulate returned no min_resource_fee / \
                              transaction_data"
                .to_owned(),
        });
    }

    Ok(resim_response)
}

/// Test-only construction helpers for [`AuthorizationSimulation`] and
/// [`crate::signing::divergence::EnvelopeContext`].
///
/// These helpers exist because [`AuthorizationSimulation`] and the divergence
/// context types are `#[non_exhaustive]` — adversarial fixture tests in
/// `tests/` crates (separate compilation units) cannot construct them via
/// struct literal.  Using these builders isolates the tests from future field
/// additions.
///
/// Gated under `#[cfg(any(test, feature = "test-helpers", feature = "testnet-integration"))]` per
/// Test-only public helpers must be feature-gated.
#[cfg(any(test, feature = "test-helpers", feature = "testnet-integration"))]
pub mod test_helpers {
    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::smart_account::rule_id::ContextRuleId;

    use super::AuthorizationSimulation;
    use crate::signing::divergence::{
        AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext,
        SequenceContext, SimulationContext,
    };

    /// Returns a baseline `AuthorizationSimulation` suitable for offline
    /// adversarial fixture tests.
    ///
    /// The returned value uses SHA-256 fingerprints of `passphrase` and
    /// `chain_id` to match what `submit_signed_invoke` would derive at
    /// runtime.  `nonce` and `signature_expiration_ledger` are set to
    /// arbitrary stable values (42 / 9999); override for specific tests.
    ///
    /// # Arguments
    ///
    /// * `passphrase` — Stellar network passphrase (e.g.
    ///   `"Test SDF Network ; September 2015"`).
    /// * `chain_id` — CAIP-2 chain ID (e.g. `"stellar:testnet"`).
    /// * `rule_ids` — context-rule IDs for the simulated context.
    #[must_use]
    pub fn baseline_authorization_simulation(
        passphrase: &str,
        chain_id: &str,
        rule_ids: Vec<ContextRuleId>,
    ) -> AuthorizationSimulation {
        let passphrase_fingerprint = {
            let d = Sha256::digest(passphrase.as_bytes());
            let hex: String = d.iter().take(8).map(|b| format!("{b:02x}")).collect();
            format!("net:{hex}")
        };
        let chain_id_fingerprint = {
            let d = Sha256::digest(chain_id.as_bytes());
            let hex: String = d.iter().take(8).map(|b| format!("{b:02x}")).collect();
            format!("chain:{hex}")
        };
        let network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();

        let context = SimulationContext {
            context_rule_ids: rule_ids,
            auth_contexts: vec![AuthContextFingerprint::new("offline:fixture".to_owned())],
            network: NetworkContext {
                passphrase_fingerprint,
                ledger_protocol_version: 23,
                chain_id_fingerprint,
            },
            sequence: SequenceContext {
                source_account_sequence: 1,
                min_sequence_number: None,
            },
            fee_envelope: FeeEnvelopeContext {
                tx_fee: 1_000_000,
                resource_fee: 0,
            },
        };

        AuthorizationSimulation {
            context,
            network_id,
            nonce: 42,
            signature_expiration_ledger: 9999,
        }
    }

    /// Returns an [`EnvelopeContext`] that exactly matches the given
    /// [`AuthorizationSimulation`].
    ///
    /// Use together with [`baseline_authorization_simulation`] to construct
    /// paired simulation + envelope for offline fixture tests.
    #[must_use]
    pub fn matching_envelope_context(simulation: &AuthorizationSimulation) -> EnvelopeContext {
        EnvelopeContext {
            context_rule_ids: simulation.context.context_rule_ids.clone(),
            auth_contexts: simulation.context.auth_contexts.clone(),
            network: simulation.context.network.clone(),
            sequence: simulation.context.sequence.clone(),
            fee_envelope: simulation.context.fee_envelope.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only XDR fixture construction; panics signal correct failure modes for shape assertions"
    )]

    use super::*;
    use crate::signing::divergence::{
        AuthContextFingerprint, FeeEnvelopeContext, NetworkContext, SequenceContext,
    };

    fn contract_address(byte: u8) -> ScAddress {
        ScAddress::Contract(stellar_xdr::ContractId(Hash([byte; 32])))
    }

    fn symbol(name: &str) -> ScSymbol {
        ScSymbol::try_from(name).unwrap()
    }

    fn contexts() -> (AuthorizationSimulation, EnvelopeContext) {
        let context = SimulationContext {
            context_rule_ids: vec![ContextRuleId::new(42)],
            auth_contexts: vec![AuthContextFingerprint::new("invoke:abcd1234".to_owned())],
            network: NetworkContext {
                passphrase_fingerprint: "testnet".to_owned(),
                ledger_protocol_version: 23,
                chain_id_fingerprint: "00112233...aabbccdd".to_owned(),
            },
            sequence: SequenceContext {
                source_account_sequence: 100,
                min_sequence_number: Some(99),
            },
            fee_envelope: FeeEnvelopeContext {
                tx_fee: 100,
                resource_fee: 1000,
            },
        };
        let envelope = EnvelopeContext {
            context_rule_ids: context.context_rule_ids.clone(),
            auth_contexts: context.auth_contexts.clone(),
            network: context.network.clone(),
            sequence: context.sequence.clone(),
            fee_envelope: context.fee_envelope.clone(),
        };
        let simulation = AuthorizationSimulation {
            context,
            network_id: [9; 32],
            nonce: 123,
            signature_expiration_ledger: 456,
        };
        (simulation, envelope)
    }

    #[tokio::test]
    async fn happy_path_returns_expected_auth_digest() {
        let (simulation, envelope) = contexts();
        let rule_ids = vec![ContextRuleId::new(42)];

        let partial = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            rule_ids.clone(),
            &simulation,
            &envelope,
        )
        .await
        .unwrap();

        let rule_ids_xdr = encode_context_rule_ids(&rule_ids).unwrap();
        let expected_digest = compute_auth_digest(&partial.signature_payload, &rule_ids_xdr);
        assert_eq!(partial.auth_digest, *expected_digest.as_bytes());
        assert_eq!(partial.context_rule_ids, rule_ids);
        assert_eq!(partial.nonce, simulation.nonce);
        assert_eq!(
            partial.signature_expiration_ledger,
            simulation.signature_expiration_ledger
        );
    }

    #[tokio::test]
    async fn empty_rule_ids_refuse_with_rule_id_mismatch() {
        let (simulation, envelope) = contexts();
        let err = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            vec![],
            &simulation,
            &envelope,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            SaError::RuleIdMismatch {
                expected_len: 1,
                observed_len: 0,
            }
        ));
    }

    #[tokio::test]
    async fn mismatched_rule_id_count_refuses_with_rule_id_mismatch() {
        let (simulation, mut envelope) = contexts();
        let rule_ids = vec![ContextRuleId::new(42), ContextRuleId::new(43)];
        envelope.context_rule_ids = rule_ids.clone();

        let err = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            rule_ids,
            &simulation,
            &envelope,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            SaError::RuleIdMismatch {
                expected_len: 1,
                observed_len: 2,
            }
        ));
    }

    #[tokio::test]
    async fn simulation_divergence_refuses_before_digest_construction() {
        let (simulation, mut envelope) = contexts();
        envelope.network.ledger_protocol_version += 1;

        let err = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            vec![ContextRuleId::new(42)],
            &simulation,
            &envelope,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            SaError::SimulationDivergence {
                sub_code: SimulationDivergenceSubCode::Network,
                ..
            }
        ));
    }

    // ── ContextRuleIds divergence path ───────────────────────────────────────

    /// When `rule_ids` length matches `simulation.context.auth_contexts` but the
    /// values differ from `envelope.context_rule_ids`, the builder must refuse
    /// with `SimulationDivergence { sub_code: ContextRuleIds }` before any
    /// XDR construction occurs.
    #[tokio::test]
    async fn rule_ids_value_mismatch_with_envelope_refuses_context_rule_ids_divergence() {
        let (simulation, envelope) = contexts();
        // simulation.context.auth_contexts has length 1; envelope.context_rule_ids = [42].
        // Supply rule_id 99 (count-matches, value-differs → ContextRuleIds divergence).
        let mismatched_rule_ids = vec![ContextRuleId::new(99)];

        let err = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            mismatched_rule_ids,
            &simulation,
            &envelope,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::ContextRuleIds,
                    ..
                }
            ),
            "expected ContextRuleIds divergence, got: {err:?}"
        );
    }

    // ── build_multi_signer_auth_payload_scval ────────────────────────────────

    /// `build_multi_signer_auth_payload_scval` (called via `complete_authorization_entry_multi_signer`)
    /// returns `AuthEntryConstructionFailed` when the signers slice is empty.
    #[test]
    fn multi_signer_auth_payload_empty_signers_returns_error() {
        let rule_ids = vec![ContextRuleId::new(7)];
        let err = build_multi_signer_auth_payload_scval(&[], &rule_ids).unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "expected AuthEntryConstructionFailed(auth_payload), got: {err:?}"
        );
        let SaError::AuthEntryConstructionFailed {
            redacted_reason, ..
        } = &err
        else {
            unreachable!()
        };
        assert!(
            redacted_reason.contains("signers must not be empty"),
            "reason must mention signers-empty, got: {redacted_reason}"
        );
    }

    /// `build_multi_signer_auth_payload_scval` with a single signer produces the
    /// canonical two-entry outer Map shape with `context_rule_ids` and `signers`
    /// keys in alphabetical order and the signer bytes of the correct length.
    #[test]
    fn multi_signer_auth_payload_single_signer_shape() {
        let pubkey = [0x11u8; 32];
        let signature = [0xAAu8; 64];
        let rule_ids = vec![ContextRuleId::new(1), ContextRuleId::new(5)];

        let scval = build_multi_signer_auth_payload_scval(&[(pubkey, signature)], &rule_ids)
            .expect("single signer must succeed");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("AuthPayload must be ScVal::Map");
        };
        assert_eq!(outer.len(), 2);

        // First key must be "context_rule_ids" (alphabetically before "signers").
        let ScVal::Symbol(k0) = &outer[0].key else {
            panic!("first key must be Symbol")
        };
        assert_eq!(k0.to_utf8_string_lossy(), "context_rule_ids");
        let ScVal::Vec(Some(ScVec(rule_ids_vec))) = &outer[0].val else {
            panic!("context_rule_ids val must be Vec")
        };
        assert_eq!(rule_ids_vec.len(), 2);
        assert!(matches!(rule_ids_vec[0], ScVal::U32(1)));
        assert!(matches!(rule_ids_vec[1], ScVal::U32(5)));

        // Second key must be "signers".
        let ScVal::Symbol(k1) = &outer[1].key else {
            panic!("second key must be Symbol")
        };
        assert_eq!(k1.to_utf8_string_lossy(), "signers");
        let ScVal::Map(Some(ScMap(signers_map))) = &outer[1].val else {
            panic!("signers val must be ScMap")
        };
        assert_eq!(signers_map.len(), 1);

        // Signer key: Vec([Symbol("Delegated"), Address(pubkey)]).
        let ScVal::Vec(Some(ScVec(skey_vec))) = &signers_map[0].key else {
            panic!("signer map key must be Vec")
        };
        assert_eq!(skey_vec.len(), 2);
        let ScVal::Symbol(tag) = &skey_vec[0] else {
            panic!("tag must be Symbol")
        };
        assert_eq!(tag.to_utf8_string_lossy(), "Delegated");
        let ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(pk_in),
        )))) = &skey_vec[1]
        else {
            panic!("signer key[1] must be Account(Ed25519)")
        };
        assert_eq!(*pk_in, pubkey);

        // Signer value: Bytes(64).
        let ScVal::Bytes(ScBytes(sig_bytesm)) = &signers_map[0].val else {
            panic!("signer val must be ScBytes")
        };
        let sig_vec: Vec<u8> = sig_bytesm.clone().into();
        assert_eq!(sig_vec.len(), 64);
        assert_eq!(sig_vec.as_slice(), &signature);
    }

    /// Two signers are sorted by pubkey bytes so the resulting ScMap satisfies the
    /// Soroban canonical sort order. If supplied in reverse pubkey order the output
    /// must still have the lower pubkey first.
    #[test]
    fn multi_signer_auth_payload_sorts_signers_by_pubkey() {
        let pk_lo = [0x10u8; 32]; // numerically lower
        let pk_hi = [0x20u8; 32]; // numerically higher
        let sig_lo = [0x01u8; 64];
        let sig_hi = [0x02u8; 64];
        let rule_ids = vec![ContextRuleId::new(3)];

        // Supply in reversed order — hi before lo.
        let scval =
            build_multi_signer_auth_payload_scval(&[(pk_hi, sig_hi), (pk_lo, sig_lo)], &rule_ids)
                .expect("two signers must succeed");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("outer must be Map")
        };
        let ScVal::Map(Some(ScMap(signers_map))) = &outer[1].val else {
            panic!("signers must be Map")
        };
        assert_eq!(signers_map.len(), 2);

        // First entry must be pk_lo (lower pubkey bytes come first in sort).
        let ScVal::Vec(Some(ScVec(key0))) = &signers_map[0].key else {
            panic!("key0 must be Vec")
        };
        let ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(pk0),
        )))) = &key0[1]
        else {
            panic!("key0[1] must be Account(Ed25519)")
        };
        assert_eq!(*pk0, pk_lo, "lower pubkey must be first after sort");

        // Second entry must be pk_hi.
        let ScVal::Vec(Some(ScVec(key1))) = &signers_map[1].key else {
            panic!("key1 must be Vec")
        };
        let ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
            Uint256(pk1),
        )))) = &key1[1]
        else {
            panic!("key1[1] must be Account(Ed25519)")
        };
        assert_eq!(*pk1, pk_hi, "higher pubkey must be second after sort");
    }

    // ── complete_authorization_entry_multi_signer ────────────────────────────

    /// `complete_authorization_entry_multi_signer` refuses immediately when the
    /// `signers` slice is empty, without touching the partial entry.
    #[tokio::test]
    async fn multi_signer_complete_empty_signers_guard() {
        let (simulation, envelope) = contexts();
        let partial = build_authorization_entry(
            contract_address(2),
            symbol("transfer"),
            vec![],
            vec![ContextRuleId::new(42)],
            &simulation,
            &envelope,
        )
        .await
        .unwrap();

        let err = complete_authorization_entry_multi_signer(partial, &[])
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "expected AuthEntryConstructionFailed, got: {err:?}"
        );
        let SaError::AuthEntryConstructionFailed {
            redacted_reason, ..
        } = &err
        else {
            unreachable!()
        };
        assert!(
            redacted_reason.contains("signers must not be empty"),
            "reason must mention empty-signers, got: {redacted_reason}"
        );
    }

    /// `complete_authorization_entry_multi_signer` with two software signers
    /// assembles a single `SorobanAuthorizationEntry` whose AuthPayload signers
    /// map contains two entries sorted by pubkey, each with a valid 64-byte
    /// signature that cryptographically verifies against the same auth_digest.
    #[tokio::test]
    async fn multi_signer_complete_two_signers_assembles_correct_auth_payload() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use stellar_agent_network::SoftwareSigningKey;

        let (simulation, envelope) = contexts();
        let rule_ids = vec![ContextRuleId::new(42)];

        let partial = build_authorization_entry(
            contract_address(3),
            symbol("invoke"),
            vec![],
            rule_ids.clone(),
            &simulation,
            &envelope,
        )
        .await
        .unwrap();

        let auth_digest = partial.auth_digest;
        let smart_account = partial.smart_account.clone();
        let nonce = partial.nonce;
        let expiry = partial.signature_expiration_ledger;

        // Seeds chosen so pk_a < pk_b (sort order is verifiable from output).
        let signer_a = SoftwareSigningKey::new_from_bytes([0x01u8; 32]);
        let signer_b = SoftwareSigningKey::new_from_bytes([0x07u8; 32]);
        let pk_a = signer_a.public_key().await.unwrap().0;
        let pk_b = signer_b.public_key().await.unwrap().0;

        let s_a: &(dyn stellar_agent_network::signing::Signer + Send + Sync) = &signer_a;
        let s_b: &(dyn stellar_agent_network::signing::Signer + Send + Sync) = &signer_b;

        let entry = complete_authorization_entry_multi_signer(partial, &[s_a, s_b])
            .await
            .unwrap();

        // Credentials shape.
        let SorobanCredentials::Address(addr_creds) = entry.credentials else {
            panic!("expected SorobanCredentials::Address");
        };
        assert_eq!(addr_creds.address, smart_account);
        assert_eq!(addr_creds.nonce, nonce);
        assert_eq!(addr_creds.signature_expiration_ledger, expiry);

        // Outer AuthPayload map.
        let ScVal::Map(Some(ScMap(outer))) = &addr_creds.signature else {
            panic!("AuthPayload must be ScVal::Map");
        };
        assert_eq!(outer.len(), 2);
        let ScVal::Symbol(k0) = &outer[0].key else {
            panic!()
        };
        assert_eq!(k0.to_utf8_string_lossy(), "context_rule_ids");

        // Signers map must have 2 entries.
        let ScVal::Map(Some(ScMap(signers_map))) = &outer[1].val else {
            panic!("signers val must be Map");
        };
        assert_eq!(signers_map.len(), 2);

        // Both entries must have valid 64-byte signatures over auth_digest.
        for signer_entry in signers_map.iter() {
            let ScVal::Vec(Some(ScVec(key_vec))) = &signer_entry.key else {
                panic!("signer map key must be Vec");
            };
            let ScVal::Symbol(tag) = &key_vec[0] else {
                panic!("tag must be Symbol")
            };
            assert_eq!(tag.to_utf8_string_lossy(), "Delegated");
            let ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256(pk_in_entry),
            )))) = &key_vec[1]
            else {
                panic!("signer key[1] must be Account(Ed25519)");
            };

            let ScVal::Bytes(ScBytes(sig_bytesm)) = &signer_entry.val else {
                panic!("signer val must be Bytes");
            };
            let sig_vec: Vec<u8> = sig_bytesm.clone().into();
            assert_eq!(sig_vec.len(), 64, "each signature must be 64 bytes");

            let sig_arr: [u8; 64] = sig_vec.try_into().unwrap();
            let sig = Signature::from_bytes(&sig_arr);
            let vk = VerifyingKey::from_bytes(pk_in_entry).unwrap();
            vk.verify(&auth_digest, &sig)
                .expect("each signer's signature must verify against the shared auth_digest");
        }

        // Verify the pubkeys present in the signers map are exactly the two we supplied.
        let pks_in_map: Vec<[u8; 32]> = signers_map
            .iter()
            .map(|e| {
                let ScVal::Vec(Some(ScVec(kv))) = &e.key else {
                    panic!()
                };
                let ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                    Uint256(pk),
                )))) = &kv[1]
                else {
                    panic!()
                };
                *pk
            })
            .collect();
        assert!(
            pks_in_map.contains(&pk_a),
            "signer_a pubkey must be in the signers map"
        );
        assert!(
            pks_in_map.contains(&pk_b),
            "signer_b pubkey must be in the signers map"
        );
    }

    // ── build_and_sign_delegated_g_key_entry ─────────────────────────────────

    /// `build_and_sign_delegated_g_key_entry` produces a `SorobanAuthorizationEntry`
    /// whose credentials are the signer's G-key (not the smart account), whose
    /// root invocation targets `__check_auth` on the smart-account contract with
    /// the auth_digest as argument, and whose signature cryptographically verifies
    /// against the signer's public key applied to the Soroban preimage of the
    /// entry's own nonce / expiration.
    #[tokio::test]
    async fn delegated_g_key_entry_shape_and_signature_verify() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sha2::{Digest as _, Sha256};
        use stellar_agent_network::SoftwareSigningKey;
        use stellar_xdr::{HashIdPreimage, HashIdPreimageSorobanAuthorization};

        let smart_account = contract_address(0x5A);
        let auth_digest = [0x42u8; 32];
        let expiry = 8888u32;
        let network_passphrase = "Test SDF Network ; September 2015";

        let signer = SoftwareSigningKey::new_from_bytes([0x03u8; 32]);
        let pk = signer.public_key().await.unwrap().0;

        let entry = build_and_sign_delegated_g_key_entry(
            &smart_account,
            &auth_digest,
            expiry,
            &signer,
            network_passphrase,
        )
        .await
        .unwrap();

        // The credentials address must be the signer's G-key, NOT the smart account.
        let SorobanCredentials::Address(addr_creds) = entry.credentials else {
            panic!("expected SorobanCredentials::Address");
        };
        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(cred_pk)))) =
            addr_creds.address
        else {
            panic!("credentials address must be Account(Ed25519)");
        };
        assert_eq!(
            cred_pk, pk,
            "credentials address must be the signer's own G-key"
        );
        assert_eq!(
            addr_creds.signature_expiration_ledger, expiry,
            "expiry must be forwarded"
        );

        // Root invocation: ContractFn(__check_auth, [auth_digest]) on smart_account.
        let SorobanAuthorizedFunction::ContractFn(invoke_args) =
            entry.root_invocation.function.clone()
        else {
            panic!("root invocation must be ContractFn");
        };
        assert_eq!(
            invoke_args.contract_address, smart_account,
            "invocation contract must be the smart account"
        );
        assert_eq!(
            invoke_args.function_name.to_utf8_string_lossy(),
            "__check_auth",
            "function name must be __check_auth"
        );
        assert_eq!(
            invoke_args.args.len(),
            1,
            "__check_auth must take one argument (the auth_digest)"
        );
        let ScVal::Bytes(ScBytes(arg_bytesm)) = &invoke_args.args[0] else {
            panic!("__check_auth arg must be Bytes");
        };
        let arg_vec: Vec<u8> = arg_bytesm.clone().into();
        assert_eq!(
            arg_vec.as_slice(),
            &auth_digest,
            "__check_auth arg must be the auth_digest bytes"
        );

        // Sub-invocations must be empty for the Delegated G-key entry.
        assert_eq!(
            entry.root_invocation.sub_invocations.len(),
            0,
            "Delegated G-key entry must have no sub-invocations"
        );

        // The signature in the credentials must be ScVal::Vec([ScVal::Map([{public_key, signature}])]).
        let ScVal::Vec(Some(ScVec(outer_vec))) = &addr_creds.signature else {
            panic!("signature scval must be ScVal::Vec");
        };
        assert_eq!(outer_vec.len(), 1, "outer Vec must contain one Map");
        let ScVal::Map(Some(ScMap(inner_map))) = &outer_vec[0] else {
            panic!("inner element must be ScVal::Map");
        };
        assert_eq!(
            inner_map.len(),
            2,
            "inner map must have public_key and signature"
        );

        let ScVal::Symbol(k0) = &inner_map[0].key else {
            panic!("first map key must be Symbol")
        };
        assert_eq!(k0.to_utf8_string_lossy(), "public_key");
        let ScVal::Bytes(ScBytes(pk_bytesm)) = &inner_map[0].val else {
            panic!("public_key val must be Bytes")
        };
        let pk_vec: Vec<u8> = pk_bytesm.clone().into();
        assert_eq!(pk_vec.len(), 32, "public_key must be 32 bytes");
        assert_eq!(
            pk_vec.as_slice(),
            &pk,
            "public_key bytes must match signer's ed25519 pubkey"
        );

        let ScVal::Symbol(k1) = &inner_map[1].key else {
            panic!("second map key must be Symbol")
        };
        assert_eq!(k1.to_utf8_string_lossy(), "signature");
        let ScVal::Bytes(ScBytes(sig_bytesm)) = &inner_map[1].val else {
            panic!("signature val must be Bytes")
        };
        let sig_vec: Vec<u8> = sig_bytesm.clone().into();
        assert_eq!(sig_vec.len(), 64, "signature must be 64 bytes");

        // Cryptographic closure: re-derive the signature_payload from the XDR
        // preimage using the nonce extracted from the credentials, then verify the
        // signature against the signer's pubkey.
        //
        // OZ canonical: the G-key entry is a standard SorobanCredentials::Address
        // whose signature covers sha256(HashIdPreimage::SorobanAuthorization) where
        // the invocation is the __check_auth call on the smart-account contract.
        // Cross-reference: js-stellar-base auth.js:171-184.
        let nonce_from_entry = addr_creds.nonce;
        let network_id: [u8; 32] = Sha256::digest(network_passphrase.as_bytes()).into();
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: stellar_xdr::Hash(network_id),
            nonce: nonce_from_entry,
            signature_expiration_ledger: expiry,
            invocation: entry.root_invocation,
        });
        let preimage_xdr = preimage.to_xdr(Limits::none()).unwrap();
        let expected_payload: [u8; 32] = Sha256::digest(preimage_xdr).into();

        let sig_arr: [u8; 64] = sig_vec.try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(&expected_payload, &sig)
            .expect("delegated G-key entry signature must verify against its own preimage payload");
    }

    // ── test_helpers module ──────────────────────────────────────────────────

    /// `baseline_authorization_simulation` produces a deterministic `AuthorizationSimulation`
    /// whose `network_id` matches `sha256(passphrase)` and whose `SimulationContext`
    /// fields derive fingerprints from the supplied passphrase and chain_id using
    /// the documented SHA-256/8-byte-hex scheme.
    #[test]
    fn test_helpers_baseline_authorization_simulation_fields() {
        use sha2::{Digest as _, Sha256};

        let passphrase = "Test SDF Network ; September 2015";
        let chain_id = "stellar:testnet";
        let rule_ids = vec![ContextRuleId::new(1), ContextRuleId::new(2)];

        let sim =
            test_helpers::baseline_authorization_simulation(passphrase, chain_id, rule_ids.clone());

        // network_id must be sha256(passphrase).
        let expected_network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
        assert_eq!(
            sim.network_id, expected_network_id,
            "network_id must be sha256(passphrase)"
        );

        // Stable arbitrary nonce and expiry.
        assert_eq!(sim.nonce, 42);
        assert_eq!(sim.signature_expiration_ledger, 9999);

        // context_rule_ids forwarded.
        assert_eq!(sim.context.context_rule_ids, rule_ids);

        // auth_contexts has exactly one entry.
        assert_eq!(sim.context.auth_contexts.len(), 1);

        // passphrase_fingerprint: "net:" + first-8-bytes-of-sha256(passphrase)-as-hex.
        let passphrase_digest = Sha256::digest(passphrase.as_bytes());
        let expected_fp: String = passphrase_digest
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected_passphrase_fp = format!("net:{expected_fp}");
        assert_eq!(
            sim.context.network.passphrase_fingerprint,
            expected_passphrase_fp
        );

        // chain_id_fingerprint: "chain:" + first-8-bytes-of-sha256(chain_id)-as-hex.
        let chain_digest = Sha256::digest(chain_id.as_bytes());
        let expected_chain_fp: String = chain_digest
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected_chain_id_fp = format!("chain:{expected_chain_fp}");
        assert_eq!(
            sim.context.network.chain_id_fingerprint,
            expected_chain_id_fp
        );

        assert_eq!(sim.context.network.ledger_protocol_version, 23);
    }

    /// `matching_envelope_context` returns an `EnvelopeContext` that exactly mirrors
    /// the `SimulationContext` inside the supplied `AuthorizationSimulation`.
    /// Pairing the two must make `detect_simulation_divergence` succeed.
    #[test]
    fn test_helpers_matching_envelope_context_no_divergence() {
        use crate::signing::divergence::detect_simulation_divergence;

        let passphrase = "Test SDF Network ; September 2015";
        let chain_id = "stellar:testnet";
        let rule_ids = vec![ContextRuleId::new(10)];

        let sim = test_helpers::baseline_authorization_simulation(passphrase, chain_id, rule_ids);
        let envelope = test_helpers::matching_envelope_context(&sim);

        // The paired envelope must not trigger any divergence.
        detect_simulation_divergence(&sim.context, &envelope)
            .expect("matching_envelope_context must produce a divergence-free pair");
    }

    /// End-to-end test: build a partial entry, complete it via a
    /// software signer, then verify the signature inside the resulting
    /// `AuthPayload` ScVal verifies cryptographically against the signer's
    /// pubkey when applied to the auth-digest (cryptographic closure:
    /// signature ↔ auth_digest ↔ context_rule_ids binding).
    #[tokio::test]
    async fn complete_authorization_entry_signs_and_assembles_authpayload() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use stellar_agent_network::SoftwareSigningKey;

        let (simulation, envelope) = contexts();
        let rule_ids = vec![ContextRuleId::new(42)];

        let partial = build_authorization_entry(
            contract_address(1),
            symbol("pay"),
            vec![],
            rule_ids.clone(),
            &simulation,
            &envelope,
        )
        .await
        .unwrap();

        let signer = SoftwareSigningKey::new_from_bytes([7u8; 32]);
        let pubkey = signer.public_key().await.unwrap();
        let saved_auth_digest = partial.auth_digest;
        let saved_smart_account = partial.smart_account.clone();
        let saved_nonce = partial.nonce;
        let saved_expiry = partial.signature_expiration_ledger;

        let entry = complete_authorization_entry(partial, &signer)
            .await
            .unwrap();

        assert_eq!(entry.root_invocation.sub_invocations.len(), 0);

        let SorobanCredentials::Address(addr_creds) = entry.credentials else {
            panic!("expected SorobanCredentials::Address");
        };
        assert_eq!(addr_creds.address, saved_smart_account);
        assert_eq!(addr_creds.nonce, saved_nonce);
        assert_eq!(addr_creds.signature_expiration_ledger, saved_expiry);

        // Pull the AuthPayload outer Map and verify shape + signature recovery.
        let ScVal::Map(Some(ScMap(outer_entries))) = &addr_creds.signature else {
            panic!("AuthPayload must be ScVal::Map");
        };
        assert_eq!(outer_entries.len(), 2, "AuthPayload has two outer entries");

        // First entry: context_rule_ids = Vec([U32(42)]).
        let first = &outer_entries[0];
        let ScVal::Symbol(first_key) = &first.key else {
            panic!("first key must be Symbol");
        };
        assert_eq!(first_key.to_utf8_string_lossy(), "context_rule_ids");
        let ScVal::Vec(Some(ScVec(rule_ids_vec))) = &first.val else {
            panic!("rule_ids val must be ScVec");
        };
        assert_eq!(rule_ids_vec.len(), 1);
        assert!(matches!(rule_ids_vec[0], ScVal::U32(42)));

        // Second entry: signers = Map([{ key: Vec([Symbol("Delegated"), Address(g_strkey)]), val: Bytes(64) }]).
        let second = &outer_entries[1];
        let ScVal::Symbol(second_key) = &second.key else {
            panic!("second key must be Symbol");
        };
        assert_eq!(second_key.to_utf8_string_lossy(), "signers");
        let ScVal::Map(Some(ScMap(signers_entries))) = &second.val else {
            panic!("signers val must be ScMap");
        };
        assert_eq!(signers_entries.len(), 1);

        let signer_entry = &signers_entries[0];
        let ScVal::Vec(Some(ScVec(key_vec))) = &signer_entry.key else {
            panic!("signers map key must be ScVec");
        };
        assert_eq!(key_vec.len(), 2);
        let ScVal::Symbol(tag) = &key_vec[0] else {
            panic!("signer-key tag must be Symbol");
        };
        assert_eq!(tag.to_utf8_string_lossy(), "Delegated");
        let ScVal::Address(addr_in_key) = &key_vec[1] else {
            panic!("signer-key address slot must be Address");
        };
        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_in_payload)))) =
            addr_in_key
        else {
            panic!("Delegated signer Address must be Account(Ed25519)");
        };
        assert_eq!(*pk_in_payload, pubkey.0);

        let ScVal::Bytes(ScBytes(sig_bytesm)) = &signer_entry.val else {
            panic!("signer-val must be ScBytes");
        };
        let sig_vec: Vec<u8> = sig_bytesm.clone().into();
        assert_eq!(sig_vec.len(), 64);

        // Cryptographic closure: signature verifies against pubkey + auth_digest.
        let sig_arr: [u8; 64] = sig_vec.try_into().expect("signature must be 64 bytes");
        let signature = Signature::from_bytes(&sig_arr);
        let vk = VerifyingKey::from_bytes(&pubkey.0).unwrap();
        vk.verify(&saved_auth_digest, &signature)
            .expect("signature must verify against auth_digest using signer pubkey");
    }
}
