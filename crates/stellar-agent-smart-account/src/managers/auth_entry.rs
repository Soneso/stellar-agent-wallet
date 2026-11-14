//! Smart-account Soroban authorisation-entry construction.
//!
//! Builds the pre-signature state for a `SorobanAuthorizationEntry`:
//! the root invocation, Soroban authorization signature payload, rule-ID XDR,
//! and auth digest. Signer bytes are attached through the network-crate
//! `Signer::sign_auth_digest` sibling primitive.

use crate::submit::CheckedSigningRules;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_agent_core::smart_account::auth_digest::compute_auth_digest;
use stellar_agent_core::smart_account::rule_id::{ContextRuleId, encode_context_rule_ids};
use stellar_agent_network::signing::{Signer, SmartAccountAuthDigest, SorobanAuthPayload};
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
use crate::signing::gate::{SignerMatch, SigningGate, SigningRequest};
use stellar_agent_network::{AuthSubject, SignerDescriptor, SigningPayload};

// ─────────────────────────────────────────────────────────────────────────────
// Classic (Ed25519) source-account auth signature ScVal
// ─────────────────────────────────────────────────────────────────────────────

/// One `TryFrom` step of [`build_classic_signature_scval`], pre-formatted as
/// `"encode <step>: {e:?}"` so callers can prepend their own call-site prefix
/// without losing the step detail.
pub(crate) struct ClassicSigScValStep(String);

impl std::fmt::Display for ClassicSigScValStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Builds the standard single-Ed25519 Stellar source-account auth signature
/// ScVal: `ScVal::Vec([ScVal::Map([{public_key: Bytes<32>, signature: Bytes<64>}])])`.
///
/// Cross-reference: js-stellar-base auth.js:171-184 (canonical encoding for
/// `SorobanCredentials::Address` whose address is a Stellar account).
///
/// Shared by [`build_and_sign_delegated_g_key_entry`] and
/// `timelock_submit`'s per-signer re-signing loop — both attach a classic
/// G-key signature to a `SorobanCredentials::Address` entry.
///
/// # Errors
///
/// Every step's `TryFrom` conversion is unreachable in practice — `pubkey`
/// and `signature_bytes` are always fixed-size (32 and 64 bytes) and the
/// symbol literals are short ASCII, none of which can exceed their target
/// XDR types' length limits — but the typed [`ClassicSigScValStep`] error
/// keeps each call site's existing error text exact.
pub(crate) fn build_classic_signature_scval(
    pubkey: &[u8; 32],
    signature_bytes: &[u8],
) -> Result<ScVal, ClassicSigScValStep> {
    let public_key_sym = ScSymbol::try_from("public_key")
        .map_err(|e| ClassicSigScValStep(format!("encode public_key Symbol: {e:?}")))?;
    let signature_sym = ScSymbol::try_from("signature")
        .map_err(|e| ClassicSigScValStep(format!("encode signature Symbol: {e:?}")))?;
    let pubkey_bytesm: BytesM = pubkey
        .to_vec()
        .try_into()
        .map_err(|e| ClassicSigScValStep(format!("encode pubkey BytesM: {e:?}")))?;
    let sig_bytesm: BytesM = signature_bytes
        .to_vec()
        .try_into()
        .map_err(|e| ClassicSigScValStep(format!("encode signature BytesM: {e:?}")))?;
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
    .map_err(|e| ClassicSigScValStep(format!("encode inner ScMap: {e:?}")))?;
    let outer_vec: VecM<ScVal> = vec![ScVal::Map(Some(ScMap(inner_map_entries)))]
        .try_into()
        .map_err(|e| ClassicSigScValStep(format!("encode outer ScVec: {e:?}")))?;
    Ok(ScVal::Vec(Some(ScVec(outer_vec))))
}

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
/// Stores the digest bytes that must be signed for OZ v0.7.2 `__check_auth`.
/// Preserves the Soroban-side root invocation and address-credential fields
/// needed to complete the auth entry.
///
/// The fields are public, so the digests are only as trustworthy as the
/// facts they were computed from: [`Self::validate`] recomputes both from
/// `network_id`, `nonce`, `signature_expiration_ledger`, `root_invocation`
/// and `context_rule_ids`, and every function in this crate that signs a
/// partial calls it before any signer key access.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PartialSorobanAuthorizationEntry {
    /// Smart-account contract address whose credentials will carry the signature.
    pub smart_account: ScAddress,
    /// SHA-256 network ID the `signature_payload` commits to.
    pub network_id: [u8; 32],
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

impl PartialSorobanAuthorizationEntry {
    /// Checks that the entry may be signed: its network is not mainnet, and
    /// its `signature_payload` and `auth_digest` are the values its own facts
    /// produce.
    ///
    /// Recomputes `signature_payload` from `network_id`, `nonce`,
    /// `signature_expiration_ledger` and `root_invocation`, and `auth_digest`
    /// from that payload and `context_rule_ids`, so `network_id` cannot
    /// misstate the network the signature commits to. `smart_account` is
    /// part of neither digest and is not checked.
    ///
    /// # Errors
    ///
    /// - [`SaError::MainnetWriteForbidden`]: `network_id` is the mainnet
    ///   network ID.
    /// - [`SaError::AuthEntryBindingMismatch`] with `field`
    ///   `"signature_payload"` or `"auth_digest"`: the stored digest differs
    ///   from the recomputed one.
    /// - [`SaError::AuthEntryConstructionFailed`] at stage
    ///   `"signature_payload"` or `"context_rule_ids"`: the recomputation
    ///   could not encode its XDR input.
    pub fn validate(&self) -> Result<(), SaError> {
        if self.network_id == network_id_of(MAINNET_PASSPHRASE) {
            return Err(SaError::MainnetWriteForbidden);
        }
        let (signature_payload, auth_digest) = derive_digests(
            self.network_id,
            self.nonce,
            self.signature_expiration_ledger,
            &self.root_invocation,
            &self.context_rule_ids,
        )?;
        if signature_payload != self.signature_payload {
            return Err(SaError::AuthEntryBindingMismatch {
                field: "signature_payload",
            });
        }
        if auth_digest != self.auth_digest {
            return Err(SaError::AuthEntryBindingMismatch {
                field: "auth_digest",
            });
        }
        Ok(())
    }

    /// Validates the entry with [`Self::validate`] and returns the digest a
    /// signer signs for it, built through
    /// [`SmartAccountAuthDigest::new`] from the entry's own facts: the type 9
    /// preimage of `network_id`, `nonce`, `signature_expiration_ledger` and
    /// `root_invocation`, bound to `context_rule_ids`. Its bytes equal
    /// `auth_digest`, which validation has just recomputed.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::validate`], and
    /// [`SaError::AuthEntryConstructionFailed`] at stage `"context_rule_ids"`
    /// or `"signature_payload"` when the typed digest cannot be built.
    pub(crate) fn signing_digest(&self) -> Result<SmartAccountAuthDigest, SaError> {
        self.validate()?;
        let preimage = soroban_authorization_preimage(
            self.network_id,
            self.nonce,
            self.signature_expiration_ledger,
            self.root_invocation.clone(),
        );
        let rule_ids_xdr = encode_context_rule_ids(&self.context_rule_ids).map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "context_rule_ids",
                redacted_reason: format!("context_rule_ids XDR encode failed before signing: {e}"),
            }
        })?;
        SmartAccountAuthDigest::new(&preimage, &rule_ids_xdr).map_err(|e| match e {
            WalletError::Network(NetworkError::MainnetWriteForbidden) => {
                SaError::MainnetWriteForbidden
            }
            other => SaError::AuthEntryConstructionFailed {
                stage: "signature_payload",
                redacted_reason: format!("auth digest construction failed before signing: {other}"),
            },
        })
    }
}

/// SHA-256 of a network passphrase: the network ID a Soroban authorization
/// preimage commits to.
pub(crate) fn network_id_of(network_passphrase: &str) -> [u8; 32] {
    Sha256::digest(network_passphrase.as_bytes()).into()
}

/// Refuses a passphrase that names mainnet, or whose network ID differs from
/// the network ID `partial` commits to, validates `partial`, and returns the
/// digest a signer signs for it.
///
/// The boundary for every signing function that takes a partial together
/// with a passphrase: the passphrase drives the delegated G-key entries, the
/// partial drives the smart-account entry, and both must name one non-mainnet
/// network.
fn check_partial_against_passphrase(
    partial: &PartialSorobanAuthorizationEntry,
    network_passphrase: &str,
) -> Result<SmartAccountAuthDigest, SaError> {
    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(SaError::MainnetWriteForbidden);
    }
    let digest = partial.signing_digest()?;
    if network_id_of(network_passphrase) != partial.network_id {
        return Err(SaError::AuthEntryBindingMismatch {
            field: "network_id",
        });
    }
    Ok(digest)
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
/// The root invocation carries no sub-invocations. A caller that signs a
/// tree with sub-invocations uses
/// [`build_authorization_entry_with_sub_invocations`].
///
/// # Refusal path
///
/// - Empty `rule_ids` returns [`SaError::RuleIdMismatch`].
/// - `rule_ids.len() != auth_contexts.len()` returns [`SaError::RuleIdMismatch`].
/// - Simulation/envelope mismatch returns [`SaError::SimulationDivergence`].
/// - Wallet-internal XDR encode/conversion failure returns
///   [`SaError::AuthEntryConstructionFailed`] with the corresponding stage.
///
/// # Divergence check
///
/// [`detect_simulation_divergence`] compares `simulation.context` with
/// `envelope`. In [`crate::submit::submit_signed_invoke`] the two sides come
/// from different sources: `simulation.context.auth_contexts` holds the node
/// fingerprints of the simulated invocation tree, and
/// `envelope.auth_contexts` those of the tree the wallet signs (its own root
/// with the accepted subtree). A tree the wallet does not sign therefore
/// refuses here, as a second check behind the root binding and the declared
/// sub-invocations that `submit_signed_invoke` applies first.
///
/// # Errors
///
/// - [`SaError::RuleIdMismatch`] — index-alignment failures between `rule_ids`
///   and the simulation auth-context list.
/// - [`SaError::SimulationDivergence`]: the simulation context differs from
///   the envelope context: rule IDs, the per-node auth-context fingerprints
///   of the simulated and the signed tree, network, sequence or fee envelope.
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
/// Used by [`crate::submit::submit_signed_invoke`], which passes the
/// simulated sub-invocations only after they matched the caller's
/// [`crate::submit::DeclaredSubInvocations`]: a router's token transfer from
/// the wallet, a DeFindex deposit's transfers, or a multicall router's
/// wallet-authorized calls. The auth digest then covers the same tree the
/// on-chain `__check_auth` re-verifies.
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
    let (signature_payload, auth_digest) = derive_digests(
        simulation.network_id,
        simulation.nonce,
        simulation.signature_expiration_ledger,
        &root_invocation,
        &rule_ids,
    )?;

    Ok(PartialSorobanAuthorizationEntry {
        smart_account: target_contract,
        network_id: simulation.network_id,
        nonce: simulation.nonce,
        signature_expiration_ledger: simulation.signature_expiration_ledger,
        root_invocation,
        signature_payload,
        auth_digest,
        context_rule_ids: rule_ids,
    })
}

/// Derives the Soroban authorization `signature_payload` and the
/// smart-account `auth_digest` from the facts they commit to.
///
/// The one derivation shared by the builder and by
/// [`PartialSorobanAuthorizationEntry::validate`], so a partial validates
/// exactly when its digests are the ones the builder would produce.
fn derive_digests(
    network_id: [u8; 32],
    nonce: i64,
    signature_expiration_ledger: u32,
    root_invocation: &SorobanAuthorizedInvocation,
    rule_ids: &[ContextRuleId],
) -> Result<([u8; 32], [u8; 32]), SaError> {
    let signature_payload = compute_signature_payload(
        network_id,
        nonce,
        signature_expiration_ledger,
        root_invocation.clone(),
    )?;
    let rule_ids_xdr =
        encode_context_rule_ids(rule_ids).map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "context_rule_ids",
            redacted_reason: format!("context_rule_ids XDR encode failed before signing: {e}"),
        })?;
    let auth_digest = compute_auth_digest(&signature_payload, &rule_ids_xdr);
    Ok((signature_payload, *auth_digest.as_bytes()))
}

fn root_contract_invocation(
    target_contract: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    sub_invocations: VecM<SorobanAuthorizedInvocation>,
) -> Result<SorobanAuthorizedInvocation, SaError> {
    // Manual InvokeContractArgs construction. The OZ `stellar-accounts` v0.7.2
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

/// The envelope type 9 preimage a smart-account auth entry is signed over:
/// `network_id`, the entry's `nonce` and `signature_expiration_ledger`, and
/// its root `invocation`.
pub(crate) fn soroban_authorization_preimage(
    network_id: [u8; 32],
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: SorobanAuthorizedInvocation,
) -> HashIdPreimage {
    HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger,
        invocation,
    })
}

fn compute_signature_payload(
    network_id: [u8; 32],
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: SorobanAuthorizedInvocation,
) -> Result<[u8; 32], SaError> {
    let preimage =
        soroban_authorization_preimage(network_id, nonce, signature_expiration_ledger, invocation);
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
/// The function first validates `partial` with
/// [`PartialSorobanAuthorizationEntry::validate`], then calls
/// [`Signer::public_key`] once to derive the user's Stellar address, then
/// [`Signer::sign_auth_digest`] once to produce the 64-byte ed25519
/// signature, then assembles the on-chain canonical `AuthPayload` ScVal and
/// wraps it in [`SorobanCredentials::Address`].
///
/// # Call sites
///
/// One of the three call sites of [`Signer::sign_auth_digest`] in the
/// workspace, beside [`complete_authorization_entry_multi_signer`] and the
/// crate-internal mixed-signer collector; each validates its partial before
/// any signer key access. Smart-account code paths must not invoke the
/// `sign_tx_payload` primitive.
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
/// Consumes the manager's checked rule set. The account, network and rule IDs
/// must match the entry, or `AuthEntryBindingMismatch` refuses before key access.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`] and
///   [`SaError::AuthEntryBindingMismatch`]: `partial` fails
///   [`PartialSorobanAuthorizationEntry::validate`]; no signer method was
///   called.
/// - [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` —
///   signer `public_key()` fetch or `sign_auth_digest()` failure, or any of
///   the bounded ScVal/ScMap/VecM/BytesM conversions used to build the
///   AuthPayload shape. The conversions are infallible by construction for
///   bounded inputs (1 signer, ≤ 15 rule_ids per OZ caps, fixed
///   pubkey/signature byte widths) but the result type is preserved for
///   trait uniformity and for the future hardware-signer paths where the
///   upstream `WalletError` propagation is the substantive failure case.
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub async fn complete_authorization_entry(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signer: &(dyn Signer + Send + Sync),
) -> Result<SorobanAuthorizationEntry, SaError> {
    complete_authorization_entry_within_budget(gate, checked_rules, partial, signer, None).await
}

/// [`complete_authorization_entry`] with each signer call bounded by `budget`
/// when there is one, at [`SIGN_AUTH_DIGEST_STAGE`] (see
/// [`sign_within_budget`]).
///
/// # Errors
///
/// The errors of [`complete_authorization_entry`], and the deadline refusal
/// of [`sign_within_budget`].
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub(crate) async fn complete_authorization_entry_within_budget(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signer: &(dyn Signer + Send + Sync),
    budget: Option<PreSubmitBudget>,
) -> Result<SorobanAuthorizationEntry, SaError> {
    checked_rules.check_binding(
        &partial.smart_account,
        partial.network_id,
        &partial.context_rule_ids,
    )?;
    let digest = partial.signing_digest()?;

    let pubkey = sign_within_budget(budget, SIGN_AUTH_DIGEST_STAGE, signer.public_key())
        .await?
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("signer public_key fetch failed before signing: {e}"),
        })?;

    gate.authorize(SigningRequest {
        subject: AuthSubject::smart_account(&partial.smart_account)
            .map_err(|field| SaError::IntentBindingMismatch { field })?,
        signer: SignerMatch::Exact(SignerDescriptor::Delegated { account: pubkey.0 }),
        payload: SigningPayload::AuthDigest(*digest.as_bytes()),
    })?;
    let signature_bytes = sign_within_budget(
        budget,
        SIGN_AUTH_DIGEST_STAGE,
        signer.sign_auth_digest(&digest),
    )
    .await?
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

/// One signer's contribution to the `AuthPayload` `signers` map.
///
/// Discriminates how the signer is keyed in the map and carries the 64-byte
/// signature that becomes the map value. All variants sign the **same**
/// `auth_digest`; the only difference is the map-key shape and whether the
/// on-chain `authenticate` branch verifies the signature.
///
/// Byte-layout source: OZ `packages/accounts/src/smart_account/storage.rs:96-102`
/// (SHA `a9c4216`), `pub enum Signer { Delegated(Address), External(Address, Bytes) }`.
#[derive(Clone, Debug)]
pub(crate) enum AuthPayloadSigner {
    /// OZ `Signer::Delegated(Address)`. Map key
    /// `Vec([Symbol("Delegated"), Address(g_key)])`; the signature is the raw
    /// ed25519 signature over `auth_digest`, stored for audit-trail
    /// completeness (the on-chain `authenticate(Delegated)` branch does NOT
    /// verify this value — it calls `addr.require_auth_for_args((auth_digest,))`
    /// instead, satisfied by a separate G-key sub-entry;
    /// `storage.rs:352-354`, SHA `a9c4216`).
    Delegated {
        /// The signer's raw ed25519 public-key bytes.
        pubkey: [u8; 32],
        /// The raw 64-byte ed25519 signature over `auth_digest`.
        signature: [u8; 64],
    },
    /// OZ `Signer::External(Address, Bytes)` verified by an Ed25519 verifier
    /// contract. Map key `Vec([Symbol("External"), Address(verifier),
    /// Bytes(pubkey32)])`; the signature is the raw 64-byte ed25519 signature
    /// over the 32-byte `auth_digest` and is **load-bearing** — on-chain
    /// `authenticate(External)` passes `sig_payload = auth_digest.to_bytes()`,
    /// `key_data`, and this value to `VerifierClient::verify`
    /// (`storage.rs:341-350`, SHA `a9c4216`), which for the Ed25519 verifier is
    /// `e.crypto().ed25519_verify(pubkey, auth_digest, signature)`
    /// (`packages/accounts/src/verifiers/ed25519.rs:31-40`, SHA `a9c4216`).
    /// There is NO nested host-level auth entry for an External signer.
    ExternalEd25519 {
        /// The Ed25519 verifier contract address named by the External signer.
        verifier: ScAddress,
        /// The signer's raw 32-byte ed25519 public key (the `key_data`).
        pubkey: [u8; 32],
        /// The raw 64-byte ed25519 signature over the 32-byte `auth_digest`.
        signature: [u8; 64],
    },
}

impl AuthPayloadSigner {
    /// Builds the `signers`-map KEY ScVal for this signer.
    ///
    /// - Delegated → `Vec([Symbol("Delegated"), Address(Account(pubkey))])`.
    /// - ExternalEd25519 → `Vec([Symbol("External"), Address(verifier),
    ///   Bytes(pubkey32)])` (built via
    ///   [`crate::managers::signers::build_external_signer_scval`], the
    ///   single canonical source for the External signer ScVal shape).
    fn map_key(&self) -> Result<ScVal, SaError> {
        let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: reason,
        };
        match self {
            AuthPayloadSigner::Delegated { pubkey, .. } => {
                let user_address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                    Uint256(*pubkey),
                )));
                let delegated_sym = ScSymbol::try_from("Delegated")
                    .map_err(|e| auth_payload_err(format!("encode Delegated symbol: {e:?}")))?;
                let key_vec: VecM<ScVal> =
                    vec![ScVal::Symbol(delegated_sym), ScVal::Address(user_address)]
                        .try_into()
                        .map_err(|e| auth_payload_err(format!("encode signer-key ScVec: {e:?}")))?;
                Ok(ScVal::Vec(Some(ScVec(key_vec))))
            }
            AuthPayloadSigner::ExternalEd25519 {
                verifier, pubkey, ..
            } => crate::managers::signers::build_external_signer_scval(verifier.clone(), pubkey),
        }
    }

    /// Returns the 64-byte signature that becomes the `signers`-map value.
    fn signature(&self) -> &[u8; 64] {
        match self {
            AuthPayloadSigner::Delegated { signature, .. }
            | AuthPayloadSigner::ExternalEd25519 { signature, .. } => signature,
        }
    }
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
    build_multi_signer_auth_payload_scval(
        &[AuthPayloadSigner::Delegated {
            pubkey: pubkey_bytes,
            signature: *signature_bytes,
        }],
        context_rule_ids,
    )
}

/// Constructs the on-chain canonical `AuthPayload` ScVal for a heterogeneous
/// set of Delegated and/or External-Ed25519 signers.
///
/// All signers contribute signatures over the **same** auth digest (produced by
/// [`build_authorization_entry`] for the shared invocation root).
///
/// # ScMap key ordering
///
/// The entries in the `signers` map are sorted by their full key `ScVal` in
/// ascending order using the `ScVal` `Ord` implementation. `stellar_xdr::ScVal`
/// derives `Ord`; for `ScVal::Vec` this compares element-wise lexicographically
/// (with length as the tie-breaker), matching the soroban host's
/// `Compare<ScVal>` total order that the on-chain `ScMap` validity check
/// enforces. This is the canonical rule for a heterogeneous signer set: a
/// Delegated key `Vec([Symbol("Delegated"), Address])` and an External key
/// `Vec([Symbol("External"), Address, Bytes])` differ at element 0
/// (`"Delegated"` < `"External"`), so all Delegated entries precede all External
/// entries; within a kind the order reduces to the differing suffix (pubkey /
/// verifier). For an all-Delegated set this is byte-identical to sorting by
/// pubkey bytes (the keys share the `"Delegated"` tag and differ only in the
/// Account address suffix), so there is no regression for the existing
/// quorum/multi-signer paths.
///
/// The on-chain canonical shape is
/// `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids: Vec<u32> }`
/// per the OpenZeppelin smart-account contract
/// (`packages/accounts/src/smart_account/storage.rs:105-138`, SHA `a9c4216`),
/// with the outer map keys in canonical alphabetical order.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` on
/// any XDR encoding failure or `signers` empty.
fn build_multi_signer_auth_payload_scval(
    signers: &[AuthPayloadSigner],
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

    // Build (key, value) pairs, then sort by the key ScVal's canonical Ord.
    let mut keyed: Vec<(ScVal, ScVal)> = Vec::with_capacity(signers.len());
    for signer in signers {
        let signer_key = signer.map_key()?;
        let signature_bytes_m: BytesM = signer
            .signature()
            .to_vec()
            .try_into()
            .map_err(|e| auth_payload_err(format!("encode signature BytesM: {e:?}")))?;
        let signature_value = ScVal::Bytes(ScBytes(signature_bytes_m));
        keyed.push((signer_key, signature_value));
    }

    // Canonical ScMap key order: ascending by the key ScVal (element-wise for
    // ScVal::Vec), matching the soroban host's Compare<ScVal>.
    keyed.sort_by(|(a, _), (b, _)| a.cmp(b));

    let signers_map_entries: Vec<ScMapEntry> = keyed
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();

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
/// Consumes the manager's checked rule set. The account, network and rule IDs
/// must match the entry, or `AuthEntryBindingMismatch` refuses before key access.
///
/// # Errors
///
/// Returns [`SaError::MainnetWriteForbidden`] or
/// [`SaError::AuthEntryBindingMismatch`] when `partial` fails
/// [`PartialSorobanAuthorizationEntry::validate`], before any signer method
/// is called.
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"` on:
/// - `signers` is empty.
/// - Any signer's `public_key()` fetch fails.
/// - Any signer's `sign_auth_digest()` fails.
/// - Any XDR encoding failure.
///
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub async fn complete_authorization_entry_multi_signer(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signers: &[&(dyn Signer + Send + Sync)],
) -> Result<SorobanAuthorizationEntry, SaError> {
    complete_authorization_entry_multi_signer_within_budget(
        gate,
        checked_rules,
        partial,
        signers,
        None,
    )
    .await
}

/// [`complete_authorization_entry_multi_signer`] with each signer call
/// bounded by `budget` when there is one, at [`SIGN_AUTH_DIGEST_STAGE`] (see
/// [`sign_within_budget`]): a signature cut at the deadline is followed by no
/// other signer's.
///
/// # Errors
///
/// The errors of [`complete_authorization_entry_multi_signer`], and the
/// deadline refusal of [`sign_within_budget`].
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub(crate) async fn complete_authorization_entry_multi_signer_within_budget(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signers: &[&(dyn Signer + Send + Sync)],
    budget: Option<PreSubmitBudget>,
) -> Result<SorobanAuthorizationEntry, SaError> {
    checked_rules.check_binding(
        &partial.smart_account,
        partial.network_id,
        &partial.context_rule_ids,
    )?;
    let digest = partial.signing_digest()?;

    if signers.is_empty() {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: "complete_authorization_entry_multi_signer: signers must not be empty"
                .to_owned(),
        });
    }

    // Collect Delegated AuthPayload descriptors for all qualifying signers.
    // This is the homogeneous Delegated quorum path; the External-Ed25519 arm
    // is driven through `sign_with_ed25519_rule` /
    // `complete_authorization_entry_mixed`.
    let mut descriptors: Vec<AuthPayloadSigner> = Vec::with_capacity(signers.len());
    for signer in signers {
        let pubkey = sign_within_budget(budget, SIGN_AUTH_DIGEST_STAGE, signer.public_key())
            .await?
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("signer public_key fetch failed: {e}"),
            })?;

        gate.authorize(SigningRequest {
            subject: AuthSubject::smart_account(&partial.smart_account)
                .map_err(|field| SaError::IntentBindingMismatch { field })?,
            signer: SignerMatch::Exact(SignerDescriptor::Delegated { account: pubkey.0 }),
            payload: SigningPayload::AuthDigest(*digest.as_bytes()),
        })?;
        let signature_bytes = sign_within_budget(
            budget,
            SIGN_AUTH_DIGEST_STAGE,
            signer.sign_auth_digest(&digest),
        )
        .await?
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("auth-digest signing failed: {e}"),
        })?;

        descriptors.push(AuthPayloadSigner::Delegated {
            pubkey: pubkey.0,
            signature: signature_bytes,
        });
    }

    let auth_payload =
        build_multi_signer_auth_payload_scval(&descriptors, &partial.context_rule_ids)?;

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

// ─────────────────────────────────────────────────────────────────────────────
// Heterogeneous (Delegated + External-Ed25519) signing
// ─────────────────────────────────────────────────────────────────────────────

/// How one signer authenticates against the smart-account rule.
///
/// Byte-layout source: OZ `packages/accounts/src/smart_account/storage.rs:96-102`
/// (SHA `a9c4216`), `pub enum Signer { Delegated(Address), External(Address, Bytes) }`.
#[derive(Clone, Debug)]
pub(crate) enum MixedSignerKind {
    /// OZ `Signer::Delegated(Address)`: authenticated via a nested host-level
    /// `require_auth_for_args((auth_digest,))`, which requires a **separate**
    /// G-key `SorobanAuthorizationEntry` (`storage.rs:352-354`, SHA `a9c4216`).
    ///
    /// Part of the heterogeneous-signer contract [`collect_mixed_signer_entries`]
    /// implements (a caller may mix Delegated and External signers); the
    /// production caller that supplies a Delegated kind through the mixed
    /// collector is the CLI submit path, wired alongside the delegation
    /// acceptance. Exercised by the mixed-set unit tests in the meantime.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "spec-mandated heterogeneous-signer variant; production mixed-collector \
                      caller lands with the CLI submit wiring; unit-tested now"
        )
    )]
    Delegated,
    /// OZ `Signer::External(Address, Bytes)` verified by an Ed25519 verifier
    /// contract at `verifier`: authenticated entirely inside the WASM-to-WASM
    /// `VerifierClient::verify` call (`storage.rs:341-350`, SHA `a9c4216`).
    /// There is NO nested host-level auth call, so an External signer needs NO
    /// secondary G-key sub-entry.
    ExternalEd25519 {
        /// The Ed25519 verifier contract address named by the External signer.
        verifier: ScAddress,
    },
}

/// A signer paired with the way it authenticates against the rule.
///
/// Used by [`collect_mixed_signer_entries`] to build a heterogeneous signer set
/// (any mix of Delegated and External-Ed25519 signers) that all sign the same
/// `auth_digest`.
pub(crate) struct MixedSigner<'a> {
    /// The signing capability (raw ed25519 key held by software or keyring).
    pub signer: &'a (dyn Signer + Send + Sync),
    /// How this signer authenticates (drives both the AuthPayload key shape and
    /// whether a G-key sub-entry is emitted).
    pub kind: MixedSignerKind,
}

/// Completes a [`PartialSorobanAuthorizationEntry`] for a heterogeneous set of
/// Delegated and/or External-Ed25519 signers, returning the smart-account auth
/// entry **plus** exactly one Delegated G-key sub-entry per Delegated signer.
///
/// This is the External-Ed25519-capable counterpart to
/// [`complete_authorization_entry_multi_signer`] +
/// [`crate::managers::authorization`]'s G-key loop. Every signer signs the same
/// `partial.auth_digest` via [`Signer::sign_auth_digest`], which for both kinds
/// produces the raw 64-byte ed25519 signature over the 32-byte digest.
///
/// # Delegated vs External routing
///
/// - **Delegated** signers are keyed as
///   `Vec([Symbol("Delegated"), Address(g_key)])` in the AuthPayload `signers`
///   map, and each one gets a secondary G-key `SorobanAuthorizationEntry` (the
///   OZ `authenticate(Delegated)` branch calls
///   `addr.require_auth_for_args((auth_digest,))`, which the host requires an
///   explicit entry for — `storage.rs:352-354`, SHA `a9c4216`).
/// - **External-Ed25519** signers are keyed as
///   `Vec([Symbol("External"), Address(verifier), Bytes(pubkey32)])`, and the
///   signature value is **load-bearing**: the OZ `authenticate(External)` branch
///   verifies it inside `VerifierClient::verify` (`storage.rs:341-350`,
///   SHA `a9c4216`). An External signer therefore gets **no** G-key sub-entry —
///   building one would target a non-existent G-key address and is unnecessary
///   because possession is already proven by the verifier-contract call.
///
/// The returned vector is `[smart_account_entry, delegated_g_key_entry*]`; its
/// length is `1 + (number of Delegated signers)`.
///
/// # Mainnet and network binding
///
/// This is the boundary for [`sign_with_ed25519_rule`] and for the
/// External-Ed25519 arm of `submit_signed_invoke`. Before any signer key
/// access it refuses a mainnet `network_passphrase`, validates `partial`
/// with [`PartialSorobanAuthorizationEntry::validate`], and refuses a
/// `network_passphrase` whose network ID differs from `partial.network_id`,
/// so the smart-account entry and the delegated G-key entries are signed for
/// one network.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`]: `network_passphrase` is the mainnet
///   passphrase, or `partial.network_id` is the mainnet network ID.
/// - [`SaError::AuthEntryBindingMismatch`]: `partial` fails validation
///   (`field` `"signature_payload"` or `"auth_digest"`), or
///   `network_passphrase` names another network than `partial.network_id`
///   (`field` `"network_id"`).
/// - [`SaError::AuthEntryConstructionFailed`] with `stage = "auth_payload"`
///   when `signers` is empty, when any signer's `public_key()` /
///   `sign_auth_digest()` fails, or on any XDR encoding failure.
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub(crate) async fn collect_mixed_signer_entries(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signers: &[MixedSigner<'_>],
    signature_expiration_ledger: u32,
    network_passphrase: &str,
) -> Result<Vec<SorobanAuthorizationEntry>, SaError> {
    collect_mixed_signer_entries_within_budget(
        gate,
        checked_rules,
        partial,
        signers,
        signature_expiration_ledger,
        network_passphrase,
        None,
    )
    .await
}

/// [`collect_mixed_signer_entries`] with each signer call bounded by `budget`
/// when there is one (see [`sign_within_budget`]): the auth-digest
/// signatures at [`SIGN_AUTH_DIGEST_STAGE`], the delegated G-key entries at
/// [`SIGN_DELEGATED_ENTRY_STAGE`]. A signature cut at the deadline is
/// followed by no other.
///
/// # Errors
///
/// The errors of [`collect_mixed_signer_entries`], and the deadline refusal
/// of [`sign_within_budget`].
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub(crate) async fn collect_mixed_signer_entries_within_budget(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    partial: PartialSorobanAuthorizationEntry,
    signers: &[MixedSigner<'_>],
    signature_expiration_ledger: u32,
    network_passphrase: &str,
    budget: Option<PreSubmitBudget>,
) -> Result<Vec<SorobanAuthorizationEntry>, SaError> {
    checked_rules.check_binding(
        &partial.smart_account,
        partial.network_id,
        &partial.context_rule_ids,
    )?;
    let digest = check_partial_against_passphrase(&partial, network_passphrase)?;

    if signers.is_empty() {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: "collect_mixed_signer_entries: signers must not be empty".to_owned(),
        });
    }

    let auth_digest: [u8; 32] = *digest.as_bytes();
    let smart_account = partial.smart_account.clone();

    // Build the AuthPayload descriptors: sign the shared auth_digest with each
    // signer's raw ed25519 key and route by kind.
    let mut descriptors: Vec<AuthPayloadSigner> = Vec::with_capacity(signers.len());
    for entry in signers {
        let pubkey = sign_within_budget(budget, SIGN_AUTH_DIGEST_STAGE, entry.signer.public_key())
            .await?
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("signer public_key fetch failed: {e}"),
            })?;
        let descriptor = match &entry.kind {
            MixedSignerKind::Delegated => SignerDescriptor::Delegated { account: pubkey.0 },
            MixedSignerKind::ExternalEd25519 { verifier } => SignerDescriptor::External {
                verifier: stellar_agent_core::sc_address::scaddress_to_strkey(verifier).map_err(
                    |_| SaError::IntentBindingMismatch {
                        field: "auth_subjects",
                    },
                )?,
                key_data_sha256: Sha256::digest(pubkey.0).into(),
            },
        };
        gate.authorize(SigningRequest {
            subject: AuthSubject::smart_account(&partial.smart_account)
                .map_err(|field| SaError::IntentBindingMismatch { field })?,
            signer: SignerMatch::Exact(descriptor),
            payload: SigningPayload::AuthDigest(*digest.as_bytes()),
        })?;
        let signature_bytes = sign_within_budget(
            budget,
            SIGN_AUTH_DIGEST_STAGE,
            entry.signer.sign_auth_digest(&digest),
        )
        .await?
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("auth-digest signing failed: {e}"),
        })?;

        let descriptor = match &entry.kind {
            MixedSignerKind::Delegated => AuthPayloadSigner::Delegated {
                pubkey: pubkey.0,
                signature: signature_bytes,
            },
            MixedSignerKind::ExternalEd25519 { verifier } => AuthPayloadSigner::ExternalEd25519 {
                verifier: verifier.clone(),
                pubkey: pubkey.0,
                signature: signature_bytes,
            },
        };
        descriptors.push(descriptor);
    }

    let auth_payload =
        build_multi_signer_auth_payload_scval(&descriptors, &partial.context_rule_ids)?;

    let smart_account_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: partial.smart_account,
            nonce: partial.nonce,
            signature_expiration_ledger: partial.signature_expiration_ledger,
            signature: auth_payload,
        }),
        root_invocation: partial.root_invocation,
    };

    let mut entries: Vec<SorobanAuthorizationEntry> = Vec::with_capacity(1 + signers.len());
    entries.push(smart_account_entry);

    // Emit a G-key sub-entry ONLY for Delegated signers; External-Ed25519
    // signers are proven by the verifier-contract call and require none.
    for entry in signers {
        if !matches!(entry.kind, MixedSignerKind::Delegated) {
            continue;
        }
        let public_key = sign_within_budget(
            budget,
            SIGN_DELEGATED_ENTRY_STAGE,
            entry.signer.public_key(),
        )
        .await?
        .map_err(|error| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("delegated entry: signer public_key fetch failed: {error}"),
        })?;
        let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            public_key.0,
        ))));
        let invocation = delegated_g_key_invocation(&smart_account, &auth_digest)?;
        let nonce = gate.delegated_nonce(&address, &invocation)?;
        let delegated = build_and_sign_delegated_g_key_entry(
            gate,
            nonce,
            &smart_account,
            &auth_digest,
            signature_expiration_ledger,
            entry.signer,
            network_passphrase,
            budget,
        )
        .await?;
        entries.push(delegated);
    }

    Ok(entries)
}

/// Produces the signed `SorobanAuthorizationEntry` set for an invocation
/// authorised by a single External-Ed25519 signer.
///
/// This is the External-Ed25519 analog of the WebAuthn `sign_with_passkey_rule`
/// path, without the browser-bridge / ceremony machinery: an External-Ed25519
/// signer holds a raw ed25519 key, so it signs the auth digest directly with no
/// UI ceremony, no bridge address, and no polling.
///
/// It builds the pre-signature state via [`build_authorization_entry`] — which
/// runs the rule-ID / simulation-divergence checks that defend every signing
/// path in this crate — then signs the `auth_digest` with the supplied ed25519
/// capability and assembles the AuthPayload with the OZ `External` signers-map
/// entry via the crate-internal mixed-signer collector. Because the signer is
/// External, the returned set contains exactly the smart-account entry and NO
/// G-key sub-entry (`storage.rs:341-350`, SHA `a9c4216`).
///
/// The `signature_payload` fed to the OZ verifier is the raw 32-byte
/// `auth_digest` (`storage.rs:346`, SHA `a9c4216`), so [`Signer::sign_auth_digest`]
/// — which produces a raw ed25519 signature over exactly those 32 bytes — is the
/// correct primitive.
///
/// # Mainnet
///
/// The mixed-signer collector is this function's mainnet and network-binding
/// boundary: it refuses a mainnet passphrase, a mainnet
/// `simulation.network_id` and a passphrase naming another network than the
/// simulation before any signer key access. Building the partial touches no
/// key, so this function carries no check of its own.
///
/// Consumes the manager's checked rule set. The account, network and rule IDs
/// must match the entry, or `AuthEntryBindingMismatch` refuses before key access.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`]: `network_passphrase` or
///   `simulation.network_id` names mainnet.
/// - [`SaError::AuthEntryBindingMismatch`]: `network_passphrase` names
///   another network than `simulation.network_id`.
/// - [`SaError::RuleIdMismatch`] — `rule_ids` empty or misaligned with the
///   simulation auth-context list.
/// - [`SaError::SimulationDivergence`] — the simulation context diverges from
///   the to-be-submitted envelope.
/// - [`SaError::AuthEntryConstructionFailed`] — signing or XDR-encoding failure.
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible invocation (contract/fn/args/rule_ids) + simulation + envelope + \
              signer + verifier + passphrase context for the External-Ed25519 signing path; \
              collapsing into a struct would hide the per-call lifetime contracts of the \
              borrowed signer and simulation/envelope references"
)]
///
/// The gate checks the credential, signer and payload before each signature.
/// Authorization consumes the cancellation proof, so later failures retain the charge.
pub async fn sign_with_ed25519_rule(
    gate: &SigningGate,
    checked_rules: CheckedSigningRules,
    target_contract: ScAddress,
    function_name: ScSymbol,
    args: Vec<ScVal>,
    rule_ids: Vec<ContextRuleId>,
    simulation: &AuthorizationSimulation,
    envelope: &EnvelopeContext,
    signer: &(dyn Signer + Send + Sync),
    verifier: ScAddress,
    network_passphrase: &str,
) -> Result<Vec<SorobanAuthorizationEntry>, SaError> {
    let partial = build_authorization_entry(
        target_contract,
        function_name,
        args,
        rule_ids,
        simulation,
        envelope,
    )
    .await?;

    let expiry = partial.signature_expiration_ledger;
    let signers = [MixedSigner {
        signer,
        kind: MixedSignerKind::ExternalEd25519 { verifier },
    }];

    collect_mixed_signer_entries(
        gate,
        checked_rules,
        partial,
        &signers,
        expiry,
        network_passphrase,
    )
    .await
}

/// Builds the invocation shared by planning and delegated signing.
pub(crate) fn delegated_g_key_invocation(
    smart_account: &ScAddress,
    auth_digest: &[u8; 32],
) -> Result<SorobanAuthorizedInvocation, SaError> {
    let auth_payload_err = |redacted_reason| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason,
    };
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

    Ok(SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: smart_account.clone(),
            function_name: check_auth_sym,
            args: check_auth_args,
        }),
        sub_invocations: VecM::default(),
    })
}

/// Signs the admitted account-key entry for the smart account's delegated signer.
///
/// The entry authorizes `__check_auth(auth_digest)` with the plan's frozen nonce.
/// The gate checks its credential, signer and payload before the signer runs.
/// Once authorization succeeds, every later failure retains the charge.
///
/// # Errors
/// Refuses mainnet, an unplanned signing, expired budget, or encoding and signer errors.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit nonce and gate bind this signing to its plan"
)]
pub(crate) async fn build_and_sign_delegated_g_key_entry(
    gate: &SigningGate,
    nonce: i64,
    smart_account: &ScAddress,
    auth_digest: &[u8; 32],
    signature_expiration_ledger: u32,
    signer: &(dyn Signer + Send + Sync),
    network_passphrase: &str,
    budget: Option<PreSubmitBudget>,
) -> Result<SorobanAuthorizationEntry, SaError> {
    use stellar_xdr::{
        AccountId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, PublicKey,
        SorobanAddressCredentials, SorobanCredentials, Uint256,
    };

    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(SaError::MainnetWriteForbidden);
    }

    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    // The G-key whose require_auth_for_args call must be authorised.
    // In the single-signer flow the manager's signer doubles as both the
    // smart-account-rule signer AND the Delegated G-key.
    let pubkey = sign_within_budget(budget, SIGN_DELEGATED_ENTRY_STAGE, signer.public_key())
        .await?
        .map_err(|e| {
            auth_payload_err(format!(
                "delegated entry: signer public_key fetch failed: {e}"
            ))
        })?;
    let g_key_address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        pubkey.0,
    ))));

    let invocation = delegated_g_key_invocation(smart_account, auth_digest)?;

    // Compute the Soroban auth-entry signature_payload.
    let network_id = network_id_of(network_passphrase);
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let signature_payload = SorobanAuthPayload::from_preimage(&preimage)
        .map_err(|e| auth_payload_err(format!("delegated entry: signature_payload: {e}")))?;

    gate.authorize(SigningRequest {
        subject: AuthSubject::account_key(&g_key_address)
            .map_err(|field| SaError::IntentBindingMismatch { field })?,
        signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
            public_key: pubkey.0,
        }),
        payload: SigningPayload::AddressPayload(*signature_payload.as_bytes()),
    })?;

    // Sign with the Soroban-address-auth primitive.
    let signature_bytes = sign_within_budget(
        budget,
        SIGN_DELEGATED_ENTRY_STAGE,
        signer.sign_soroban_address_auth_payload(&signature_payload),
    )
    .await?
    .map_err(|e| auth_payload_err(format!("delegated entry: signing failed: {e}")))?;

    // Stellar source-account auth signature shape:
    // ScVal::Vec([ScVal::Map([{public_key: BytesN<32>, signature: BytesN<64>}])])
    // Cross-reference: js-stellar-base auth.js:171-184 (canonical encoding
    // for SorobanCredentials::Address whose address is a Stellar account).
    let signature_scval = build_classic_signature_scval(&pubkey.0, &signature_bytes)
        .map_err(|e| auth_payload_err(format!("delegated entry: {e}")))?;

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

/// The collective pre-submit deadline shared across every pre-submit stage
/// of a single `submit_signed_invoke` call.
///
/// `deadline` is the absolute instant (`Instant::now() + args.timeout`)
/// computed once at the top of `submit_signed_invoke`; `total` is the
/// `args.timeout` value it was derived from, carried only for the budget
/// figure in the timeout error message. `Copy`, so it threads through the
/// pre-submit call sites, [`resimulate_with_signed_auth`] and the rule-lock
/// acquisition included, as one argument.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PreSubmitBudget {
    /// Absolute instant past which a pre-submit stage is refused.
    pub deadline: tokio::time::Instant,
    /// The `args.timeout` value `deadline` was derived from.
    pub total: std::time::Duration,
}

impl PreSubmitBudget {
    /// Refuses once the deadline has passed, with the elapse identity of
    /// [`bound_pre_submit_stage`] for `stage`.
    ///
    /// An audit-log scan is synchronous and never yields, so a deadline that
    /// passes during a scan is not observed by the `timeout_at` around it.
    /// Each scan on the pre-submit path is followed by this check.
    ///
    /// # Errors
    ///
    /// [`SaError::AuthEntryConstructionFailed`] with `stage` as its stage
    /// when `Instant::now()` is at or past the deadline.
    pub(crate) fn check(self, stage: &'static str) -> Result<(), SaError> {
        self.check_at(stage, stage)
    }

    /// Refuses once the deadline has passed, with the elapse identity of
    /// [`bound_pre_submit_stage`] for `stage` reported at `elapse_stage`: the
    /// check after a synchronous scan inside a stage that the closed stage
    /// set reports at another stage.
    ///
    /// # Errors
    ///
    /// [`SaError::AuthEntryConstructionFailed`] with `elapse_stage` as its
    /// stage and `stage` named in the reason when `Instant::now()` is at or
    /// past the deadline.
    pub(crate) fn check_at(
        self,
        stage: &'static str,
        elapse_stage: &'static str,
    ) -> Result<(), SaError> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(self.elapsed(stage, elapse_stage));
        }
        Ok(())
    }

    /// The refusal of a submission bounded by this deadline whose send-by
    /// instant passed at `stage`, before anything was sent; reported at
    /// `"auth_payload"`, as the RPC stages are.
    pub(crate) fn send_refusal(self, stage: stellar_agent_network::PreSendStage) -> SaError {
        self.elapsed(stage.label(), "auth_payload")
    }

    /// The refusal of a pre-submit stage `stage` that met the deadline,
    /// reported at `elapse_stage`.
    pub(crate) fn elapsed(self, stage: &'static str, elapse_stage: &'static str) -> SaError {
        SaError::AuthEntryConstructionFailed {
            stage: elapse_stage,
            redacted_reason: format!(
                "{stage} exceeded collective pre-submit budget of {}s",
                self.total.as_secs()
            ),
        }
    }
}

/// Bounds one pre-submit stage against the collective [`PreSubmitBudget`]
/// and records its wall-clock duration on the `sa_submit_timing` debug span.
///
/// Every pre-submit stage on the submit path shares ONE `budget.deadline`
/// rather than each re-arming a fresh `args.timeout` window. The stages are
/// the rule-lock acquisition, the signer-set baseline read of each checked
/// rule, the pinned-hash drift check of each checked rule, the signer-set
/// comparison of each checked rule, the initial fetch, the initial simulate,
/// the unsigned recovery simulate, each authorization signature (see
/// [`sign_within_budget`]), the re-fetch,
/// the re-simulate and the envelope signature. Time spent in an earlier
/// stage shrinks the budget left for a later one. A stage can
/// therefore elapse because earlier stages consumed the collective budget,
/// not because that stage itself ran long; the timeout message says
/// "collective" for that reason.
///
/// On elapse, returns [`SaError::AuthEntryConstructionFailed`] with
/// `elapse_stage` as its stage and `stage` named in the reason. The RPC
/// stages pass `"auth_payload"`, the stage tag their transport-error mapping
/// already uses, so a timed-out stage and a transport failure at that stage
/// surface through the identical error. The signer-set stages pass their own
/// stage (`"baseline_read"`, `"signer_set_compare"`), so their elapses are
/// distinguishable.
pub(crate) async fn bound_pre_submit_stage<T>(
    budget: PreSubmitBudget,
    stage: &'static str,
    elapse_stage: &'static str,
    fut: impl std::future::Future<Output = T>,
) -> Result<T, SaError> {
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout_at(budget.deadline, fut)
        .await
        .map_err(|_elapsed| budget.elapsed(stage, elapse_stage));
    tracing::debug!(
        target: "sa_submit_timing",
        stage,
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "sa_submit_timing: pre-submit stage elapsed"
    );
    outcome
}

/// The stage of an authorization signature over a smart account's auth
/// digest, and of the key read that precedes it.
pub(crate) const SIGN_AUTH_DIGEST_STAGE: &str = "sign_auth_digest";

/// The stage of a delegated G-key entry's signature, and of the key read
/// that precedes it.
pub(crate) const SIGN_DELEGATED_ENTRY_STAGE: &str = "sign_delegated_entry";

/// Runs one signer call under `budget` when there is one, as pre-submit
/// stage `stage` reported at `"auth_payload"`; `None` runs it unbounded.
///
/// A software key signs without yielding, so the deadline is checked before
/// the call; the call is cut at the deadline; and a call that completes at or
/// after it is refused as well. A signature that finishes after the deadline
/// is therefore never used, and the refusal ends the signing: no further
/// signer call and no send follows it.
///
/// # Errors
///
/// [`SaError::AuthEntryConstructionFailed`] with stage `"auth_payload"` and
/// `stage` named in the reason when the deadline has passed before the call
/// returns.
pub(crate) async fn sign_within_budget<T>(
    budget: Option<PreSubmitBudget>,
    stage: &'static str,
    call: impl std::future::Future<Output = T>,
) -> Result<T, SaError> {
    let Some(budget) = budget else {
        return Ok(call.await);
    };
    budget.check_at(stage, "auth_payload")?;
    let answer = bound_pre_submit_stage(budget, stage, "auth_payload", call).await?;
    budget.check_at(stage, "auth_payload")?;
    Ok(answer)
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
///
/// `budget` carries the collective pre-submit deadline `submit_signed_invoke`
/// computes once at function entry (see [`PreSubmitBudget`]) — the re-fetch
/// and re-simulate below are bounded against that same deadline, not a fresh
/// per-call timeout.
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible RPC + smart-account + auth-entry-list + source-account + \
              pre-submit-budget context required for the off-chain re-simulate-with-signed-auth \
              flow; collapsing the borrows into a struct would hide the per-call lifetime \
              contracts of `&Server` and `&StellarRpcClient`"
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
    budget: PreSubmitBudget,
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
    let source_view = bound_pre_submit_stage(
        budget,
        "fetch_account_resimulate",
        "auth_payload",
        fetch_account(rpc_client, source_account_strkey, &[]),
    )
    .await?
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
    let resim_response = bound_pre_submit_stage(
        budget,
        "simulate_resimulate",
        "auth_payload",
        stellar_agent_network::retry::retry_preflight_busy(Some(budget.deadline), || {
            server.simulate_transaction_envelope(&resim_envelope, None)
        }),
    )
    .await?
    .map_err(|e| match e {
        stellar_agent_network::retry::BusyRetryError::Rpc(e) => auth_payload_err(format!(
            "re-simulate: simulate_transaction_envelope failed: {e}"
        )),
        stellar_agent_network::retry::BusyRetryError::Expired => {
            budget.elapsed("simulate_resimulate", "auth_payload")
        }
    })?;

    if let Some(sim_error) = &resim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!(
                "re-simulate returned error: {}",
                crate::managers::rules::refusal_text(
                    sim_error,
                    &resim_response.events,
                    &resim_envelope
                )
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

    use stellar_xdr::{ScAddress, ScSymbol, VecM};

    use super::{
        AuthorizationSimulation, PartialSorobanAuthorizationEntry, derive_digests, network_id_of,
        root_contract_invocation,
    };
    use crate::SaError;
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

    /// Returns a [`PartialSorobanAuthorizationEntry`] for `smart_account`
    /// whose digests are derived for the network of `network_passphrase` and
    /// for `rule_ids`, so it passes
    /// [`PartialSorobanAuthorizationEntry::validate`] unless the passphrase
    /// names mainnet.
    ///
    /// The root invocation is a no-argument `execute` call on
    /// `smart_account`; the nonce and expiration are the stable values of
    /// [`baseline_authorization_simulation`] (42 / 9999).
    ///
    /// # Errors
    ///
    /// [`SaError::AuthEntryConstructionFailed`] if the digest inputs cannot
    /// be XDR-encoded, which bounded fixture inputs never trigger.
    pub fn partial_authorization_entry(
        smart_account: ScAddress,
        network_passphrase: &str,
        rule_ids: Vec<ContextRuleId>,
    ) -> Result<PartialSorobanAuthorizationEntry, SaError> {
        let network_id = network_id_of(network_passphrase);
        let function_name =
            ScSymbol::try_from("execute").map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_contexts_args",
                redacted_reason: format!("fixture function symbol encode failed: {e:?}"),
            })?;
        let root_invocation = root_contract_invocation(
            smart_account.clone(),
            function_name,
            Vec::new(),
            VecM::default(),
        )?;
        let nonce = 42;
        let signature_expiration_ledger = 9999;
        let (signature_payload, auth_digest) = derive_digests(
            network_id,
            nonce,
            signature_expiration_ledger,
            &root_invocation,
            &rule_ids,
        )?;
        Ok(PartialSorobanAuthorizationEntry {
            smart_account,
            network_id,
            nonce,
            signature_expiration_ledger,
            root_invocation,
            signature_payload,
            auth_digest,
            context_rule_ids: rule_ids,
        })
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
    use crate::signing::intent_test_helpers as admission_fixture;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_network::SignerDescriptor;
    use stellar_agent_network::signing::test_doubles::CountingSigner;

    /// A non-mainnet network other than testnet.
    const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

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
            network_id: network_id_of(TESTNET_PASSPHRASE),
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
        let empty: &[AuthPayloadSigner] = &[];
        let err = build_multi_signer_auth_payload_scval(empty, &rule_ids).unwrap_err();

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

        let scval = build_multi_signer_auth_payload_scval(
            &[AuthPayloadSigner::Delegated { pubkey, signature }],
            &rule_ids,
        )
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
        let scval = build_multi_signer_auth_payload_scval(
            &[
                AuthPayloadSigner::Delegated {
                    pubkey: pk_hi,
                    signature: sig_hi,
                },
                AuthPayloadSigner::Delegated {
                    pubkey: pk_lo,
                    signature: sig_lo,
                },
            ],
            &rule_ids,
        )
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
    #[serial_test::serial]
    async fn multi_signer_complete_empty_signers_guard() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
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

        let err = complete_authorization_entry_multi_signer(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial),
            partial,
            &[],
        )
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
    #[serial_test::serial]
    async fn multi_signer_complete_two_signers_assembles_correct_auth_payload() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
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

        let entry = complete_authorization_entry_multi_signer(
            &admission_fixture::partial_gate(
                &partial,
                vec![
                    SignerDescriptor::Delegated { account: pk_a },
                    SignerDescriptor::Delegated { account: pk_b },
                ],
                false,
            ),
            crate::submit::checked_rules_for_test(&partial),
            partial,
            &[s_a, s_b],
        )
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
    #[serial_test::serial]
    async fn delegated_g_key_entry_shape_and_signature_verify() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
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
            &admission_fixture::delegated_gate(&smart_account, &auth_digest, expiry, pk, 1),
            1,
            &smart_account,
            &auth_digest,
            expiry,
            &signer,
            network_passphrase,
            None,
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
    #[serial_test::serial]
    async fn complete_authorization_entry_signs_and_assembles_authpayload() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
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

        let entry = complete_authorization_entry(
            &admission_fixture::partial_gate(
                &partial,
                vec![SignerDescriptor::Delegated { account: pubkey.0 }],
                false,
            ),
            crate::submit::checked_rules_for_test(&partial),
            partial,
            &signer,
        )
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

    // ── External-Ed25519 auth-payload arm ────────────────────────────────────

    fn ed25519_signature_over(seed: [u8; 32], digest: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        use ed25519_dalek::{Signer as _, SigningKey};
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(digest).to_bytes();
        (pk, sig)
    }

    /// A single External-Ed25519 signer produces the OZ External signers-map
    /// entry: key `Vec([Symbol("External"), Address(verifier), Bytes(pubkey32)])`
    /// and value `Bytes(sig64)`, where the signature is a RAW ed25519 signature
    /// over the 32-byte `auth_digest` (not a preimage-wrapped variant) that
    /// independently verifies against the pubkey.
    ///
    /// Byte-layout: OZ `storage.rs:96-102` (Signer::External three-element key)
    /// and `storage.rs:341-350` (`sig_payload = auth_digest.to_bytes()`),
    /// SHA `a9c4216`.
    #[test]
    fn external_ed25519_auth_payload_shape_and_signature() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let auth_digest = [0x33u8; 32];
        let verifier = contract_address(0x99);
        let (pubkey, signature) = ed25519_signature_over([0x05u8; 32], &auth_digest);
        let rule_ids = vec![ContextRuleId::new(4)];

        let scval = build_multi_signer_auth_payload_scval(
            &[AuthPayloadSigner::ExternalEd25519 {
                verifier: verifier.clone(),
                pubkey,
                signature,
            }],
            &rule_ids,
        )
        .expect("external signer must succeed");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("AuthPayload must be Map");
        };
        let ScVal::Map(Some(ScMap(signers_map))) = &outer[1].val else {
            panic!("signers val must be Map");
        };
        assert_eq!(signers_map.len(), 1);

        // Key: Vec([Symbol("External"), Address(verifier), Bytes(pubkey32)]).
        let ScVal::Vec(Some(ScVec(key_vec))) = &signers_map[0].key else {
            panic!("signer key must be Vec")
        };
        assert_eq!(key_vec.len(), 3, "External key has three elements");
        let ScVal::Symbol(tag) = &key_vec[0] else {
            panic!("tag must be Symbol")
        };
        assert_eq!(tag.to_utf8_string_lossy(), "External");
        assert_eq!(
            key_vec[1],
            ScVal::Address(verifier),
            "element 1 must be the verifier address"
        );
        let ScVal::Bytes(ScBytes(kd)) = &key_vec[2] else {
            panic!("element 2 must be Bytes")
        };
        let kd_vec: Vec<u8> = kd.clone().into();
        assert_eq!(
            kd_vec.as_slice(),
            &pubkey,
            "key_data must be the raw pubkey"
        );

        // Value: Bytes(64) — the raw ed25519 signature over auth_digest.
        let ScVal::Bytes(ScBytes(sig_bytesm)) = &signers_map[0].val else {
            panic!("signer val must be Bytes")
        };
        let sig_vec: Vec<u8> = sig_bytesm.clone().into();
        assert_eq!(sig_vec.len(), 64);
        let sig_arr: [u8; 64] = sig_vec.try_into().unwrap();
        assert_eq!(sig_arr, signature);

        // The signature must verify against pubkey + the RAW auth_digest.
        let vk = VerifyingKey::from_bytes(&pubkey).unwrap();
        vk.verify(&auth_digest, &Signature::from_bytes(&sig_arr))
            .expect("External Ed25519 signature must verify over the raw auth_digest");
    }

    /// A mixed Delegated + External signer set orders the `signers` map by
    /// canonical `ScVal` `Ord`: the Delegated entry (tag `"Delegated"`) precedes
    /// the External entry (tag `"External"`) because element 0 differs and
    /// `"Delegated" < "External"`. Verified regardless of insertion order.
    #[test]
    fn mixed_delegated_external_scmap_ordering() {
        let auth_digest = [0x44u8; 32];
        let verifier = contract_address(0xAB);
        let (ext_pk, ext_sig) = ed25519_signature_over([0x06u8; 32], &auth_digest);
        // Delegated pubkey chosen high (0xff..) to prove ordering is by tag,
        // not by pubkey bytes — a pubkey-only sort could otherwise misorder.
        let del_pk = [0xffu8; 32];
        let del_sig = [0x01u8; 64];
        let rule_ids = vec![ContextRuleId::new(9)];

        // Insert External first to prove the sort reorders it after Delegated.
        let scval = build_multi_signer_auth_payload_scval(
            &[
                AuthPayloadSigner::ExternalEd25519 {
                    verifier,
                    pubkey: ext_pk,
                    signature: ext_sig,
                },
                AuthPayloadSigner::Delegated {
                    pubkey: del_pk,
                    signature: del_sig,
                },
            ],
            &rule_ids,
        )
        .expect("mixed signer set must succeed");

        let ScVal::Map(Some(ScMap(outer))) = &scval else {
            panic!("AuthPayload must be Map")
        };
        let ScVal::Map(Some(ScMap(signers_map))) = &outer[1].val else {
            panic!("signers val must be Map")
        };
        assert_eq!(signers_map.len(), 2);

        // First entry must be Delegated, second External.
        let ScVal::Vec(Some(ScVec(k0))) = &signers_map[0].key else {
            panic!("k0 must be Vec")
        };
        let ScVal::Symbol(t0) = &k0[0] else {
            panic!("k0[0] Symbol")
        };
        assert_eq!(
            t0.to_utf8_string_lossy(),
            "Delegated",
            "Delegated must sort before External"
        );
        let ScVal::Vec(Some(ScVec(k1))) = &signers_map[1].key else {
            panic!("k1 must be Vec")
        };
        let ScVal::Symbol(t1) = &k1[0] else {
            panic!("k1[0] Symbol")
        };
        assert_eq!(t1.to_utf8_string_lossy(), "External");

        // The map key ordering must equal the canonical ScVal Ord (the rule the
        // soroban host enforces): sorting the keys must be a no-op.
        let mut keys: Vec<&ScVal> = signers_map.iter().map(|e| &e.key).collect();
        let before = keys.clone();
        keys.sort();
        assert_eq!(
            keys, before,
            "signers map keys must already be in ScVal Ord"
        );
    }

    /// `collect_mixed_signer_entries` emits a Delegated G-key sub-entry ONLY for
    /// Delegated signers: an External-only set yields exactly one entry (the
    /// smart-account entry, no G-key), and a mixed set yields one smart-account
    /// entry plus exactly one G-key entry per Delegated signer.
    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_gkey_only_for_delegated() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        use stellar_agent_network::SoftwareSigningKey;

        let (simulation, envelope) = contexts();
        let rule_ids = vec![ContextRuleId::new(42)];
        let network_passphrase = "Test SDF Network ; September 2015";
        let verifier = contract_address(0xC1);

        let make_partial = || {
            build_authorization_entry(
                contract_address(7),
                symbol("transfer"),
                vec![],
                rule_ids.clone(),
                &simulation,
                &envelope,
            )
        };

        let del_a = SoftwareSigningKey::new_from_bytes([0x11u8; 32]);
        let del_b = SoftwareSigningKey::new_from_bytes([0x12u8; 32]);
        let ext = SoftwareSigningKey::new_from_bytes([0x13u8; 32]);

        // External-only qualifying set → one entry, no G-key sub-entry.
        {
            let partial = make_partial().await.unwrap();
            let signers = [MixedSigner {
                signer: &ext,
                kind: MixedSignerKind::ExternalEd25519 {
                    verifier: verifier.clone(),
                },
            }];
            let entries = collect_mixed_signer_entries(
                &admission_fixture::mixed_gate(&partial, &signers).await,
                crate::submit::checked_rules_for_test(&partial),
                partial,
                &signers,
                simulation.signature_expiration_ledger,
                network_passphrase,
            )
            .await
            .unwrap();
            assert_eq!(
                entries.len(),
                1,
                "External-only set must produce zero G-key sub-entries"
            );
        }

        // Mixed set (2 Delegated + 1 External) → 1 + 2 = 3 entries.
        {
            let partial = make_partial().await.unwrap();
            let signers = [
                MixedSigner {
                    signer: &del_a,
                    kind: MixedSignerKind::Delegated,
                },
                MixedSigner {
                    signer: &ext,
                    kind: MixedSignerKind::ExternalEd25519 {
                        verifier: verifier.clone(),
                    },
                },
                MixedSigner {
                    signer: &del_b,
                    kind: MixedSignerKind::Delegated,
                },
            ];
            let entries = collect_mixed_signer_entries(
                &admission_fixture::mixed_gate(&partial, &signers).await,
                crate::submit::checked_rules_for_test(&partial),
                partial,
                &signers,
                simulation.signature_expiration_ledger,
                network_passphrase,
            )
            .await
            .unwrap();
            assert_eq!(
                entries.len(),
                3,
                "mixed set must produce exactly one G-key sub-entry per Delegated signer"
            );

            // The first entry is the smart-account entry (its credentials
            // address is the smart-account contract, not a G-key).
            let SorobanCredentials::Address(sa) = &entries[0].credentials else {
                panic!("first entry must be Address credentials")
            };
            assert!(
                matches!(sa.address, ScAddress::Contract(_)),
                "first entry must be the smart-account contract entry"
            );
            // The two sub-entries must be G-key (Account) credentials.
            for e in &entries[1..] {
                let SorobanCredentials::Address(c) = &e.credentials else {
                    panic!("sub-entry must be Address credentials")
                };
                assert!(
                    matches!(c.address, ScAddress::Account(_)),
                    "sub-entries must be Delegated G-key (Account) entries"
                );
            }
        }
    }

    // ── sign_within_budget ────────────────────────────────────────────────────

    /// Asserts the deadline refusal of `stage`.
    fn assert_signing_refusal(outcome: Result<u32, SaError>, stage: &str) {
        match outcome {
            Err(SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason,
            }) => assert!(
                redacted_reason
                    .starts_with(&format!("{stage} exceeded collective pre-submit budget")),
                "{redacted_reason}"
            ),
            other => panic!("expected the deadline refusal of {stage}, got {other:?}"),
        }
    }

    /// A signer call that signs without yielding and completes only after
    /// the deadline, on the one poll the deadline timer cannot cut, is
    /// refused: its signature is not used.
    #[tokio::test]
    async fn a_signer_call_completing_past_the_deadline_is_refused() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_millis(100),
            total: std::time::Duration::from_secs(1),
        };

        let outcome = sign_within_budget(Some(budget), SIGN_AUTH_DIGEST_STAGE, async {
            std::thread::sleep(std::time::Duration::from_millis(200));
            7_u32
        })
        .await;

        assert_signing_refusal(outcome, SIGN_AUTH_DIGEST_STAGE);
    }

    /// A deadline already passed refuses before the signer call runs.
    #[tokio::test]
    async fn a_passed_deadline_refuses_before_the_signer_call_runs() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now(),
            total: std::time::Duration::from_secs(1),
        };
        let calls = std::sync::atomic::AtomicUsize::new(0);

        let outcome = sign_within_budget(Some(budget), SIGN_DELEGATED_ENTRY_STAGE, async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            7_u32
        })
        .await;

        assert_signing_refusal(outcome, SIGN_DELEGATED_ENTRY_STAGE);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the signer is not called"
        );
    }

    // ── bound_pre_submit_stage ────────────────────────────────────────────────

    /// A future that resolves well within the deadline passes its `Ok` value
    /// through unchanged.
    #[tokio::test]
    async fn bound_pre_submit_stage_passes_through_ok_before_deadline() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(30),
        };
        let outcome: Result<Result<u32, &str>, SaError> =
            bound_pre_submit_stage(budget, "unit_test_stage", "auth_payload", async {
                Ok::<u32, &str>(7)
            })
            .await;

        let inner = outcome.expect("the outer timeout must not fire before the deadline");
        assert_eq!(inner, Ok(7));
    }

    /// A future that resolves well within the deadline surfaces its `Err`
    /// value unchanged (the timeout wrapper is transparent to the inner
    /// `Result`).
    #[tokio::test]
    async fn bound_pre_submit_stage_passes_through_inner_err_before_deadline() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(30),
        };
        let outcome = bound_pre_submit_stage(budget, "unit_test_stage", "auth_payload", async {
            Err::<u32, &str>("inner transport failure")
        })
        .await
        .expect("the outer timeout must not fire before the deadline");

        assert_eq!(outcome.unwrap_err(), "inner transport failure");
    }

    /// A deadline that has already elapsed before the future is polled
    /// surfaces `SaError::AuthEntryConstructionFailed { stage: "auth_payload" }`
    /// with the stage description and configured budget in the message —
    /// never the inner future's own `Ok`/`Err` outcome.
    #[tokio::test]
    async fn bound_pre_submit_stage_times_out_when_deadline_already_elapsed() {
        // A deadline in the past: `Instant::now() - a small duration`.
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("test host clock must be well past 1 second of monotonic time"),
            total: std::time::Duration::from_secs(45),
        };
        // The inner future sleeps past any reasonable poll granularity so a
        // same-poll fast-path resolution cannot mask the timeout.
        let result: Result<Result<u32, &str>, SaError> =
            bound_pre_submit_stage(budget, "unit_test_elapsed_stage", "auth_payload", async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok::<u32, &str>(1)
            })
            .await;

        let err = result.expect_err("an already-elapsed deadline must surface a timeout error");
        match err {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(stage, "auth_payload");
                assert!(
                    redacted_reason.contains("unit_test_elapsed_stage")
                        && redacted_reason.contains("exceeded collective pre-submit budget of 45s"),
                    "redacted_reason must name the stage and the configured budget: \
                     {redacted_reason}"
                );
            }
            other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
        }
    }
    /// The elapse of a stage reports the caller's elapse stage and names the
    /// stage in the reason.
    #[tokio::test]
    async fn bound_pre_submit_stage_reports_the_elapse_stage_it_is_given() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("test host clock must be well past 1 second of monotonic time"),
            total: std::time::Duration::from_secs(9),
        };
        let err =
            bound_pre_submit_stage(budget, "signer_set_compare", "signer_set_compare", async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            })
            .await
            .expect_err("an already-elapsed deadline must surface a timeout error");
        let SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } = err
        else {
            panic!("expected AuthEntryConstructionFailed; got {err:?}");
        };
        assert_eq!(stage, "signer_set_compare");
        assert_eq!(
            redacted_reason,
            "signer_set_compare exceeded collective pre-submit budget of 9s"
        );
    }

    /// `check` passes before the deadline and refuses once it has passed,
    /// with the checked stage as both the stage and the reason's subject.
    #[test]
    fn pre_submit_budget_check_refuses_once_the_deadline_has_passed() {
        let open = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(30),
        };
        open.check("baseline_read")
            .expect("the deadline has not passed");

        let passed = PreSubmitBudget {
            deadline: tokio::time::Instant::now(),
            total: std::time::Duration::from_secs(5),
        };
        let err = passed
            .check("baseline_read")
            .expect_err("the deadline has been reached");
        let SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } = err
        else {
            panic!("expected AuthEntryConstructionFailed; got {err:?}");
        };
        assert_eq!(stage, "baseline_read");
        assert_eq!(
            redacted_reason,
            "baseline_read exceeded collective pre-submit budget of 5s"
        );
    }

    /// `check_at` passes before the deadline and, once it has passed, refuses
    /// at the elapse stage with the checked stage named in the reason.
    #[test]
    fn pre_submit_budget_check_at_reports_the_elapse_stage() {
        let open = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(30),
        };
        open.check_at("pin_plan", "auth_payload")
            .expect("the deadline has not passed");

        let passed = PreSubmitBudget {
            deadline: tokio::time::Instant::now(),
            total: std::time::Duration::from_secs(4),
        };
        let err = passed
            .check_at("pin_plan", "auth_payload")
            .expect_err("the deadline has been reached");
        let SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } = err
        else {
            panic!("expected AuthEntryConstructionFailed; got {err:?}");
        };
        assert_eq!(stage, "auth_payload");
        assert_eq!(
            redacted_reason,
            "pin_plan exceeded collective pre-submit budget of 4s"
        );
    }

    // ── Mainnet refusal and network binding before any key access ───────────

    /// A validated partial for the smart account `contract_address(7)` over
    /// rule 42, derived for the network of `network_passphrase`.
    fn partial_on(network_passphrase: &str) -> PartialSorobanAuthorizationEntry {
        test_helpers::partial_authorization_entry(
            contract_address(7),
            network_passphrase,
            vec![ContextRuleId::new(42)],
        )
        .unwrap()
    }

    /// A testnet partial whose `auth_digest` differs from the recomputed one.
    fn tampered_testnet_partial() -> PartialSorobanAuthorizationEntry {
        let mut partial = partial_on(TESTNET_PASSPHRASE);
        partial.auth_digest[0] ^= 0x01;
        partial
    }

    fn external_signer(signer: &CountingSigner) -> [MixedSigner<'_>; 1] {
        [MixedSigner {
            signer,
            kind: MixedSignerKind::ExternalEd25519 {
                verifier: contract_address(0xC1),
            },
        }]
    }

    #[test]
    fn validate_accepts_a_testnet_partial_from_the_builder_derivation() {
        partial_on(TESTNET_PASSPHRASE).validate().unwrap();
    }

    /// The typed digest a signer receives for a validated partial equals the
    /// partial's `auth_digest`, and equals `SmartAccountAuthDigest::new` over
    /// the partial's own preimage and rule ids.
    #[test]
    fn signing_digest_equals_the_validated_auth_digest() {
        let partial = partial_on(TESTNET_PASSPHRASE);
        let digest = partial.signing_digest().unwrap();
        assert_eq!(*digest.as_bytes(), partial.auth_digest);

        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(partial.network_id),
            nonce: partial.nonce,
            signature_expiration_ledger: partial.signature_expiration_ledger,
            invocation: partial.root_invocation.clone(),
        });
        let rule_ids_xdr = encode_context_rule_ids(&partial.context_rule_ids).unwrap();
        assert_eq!(
            SmartAccountAuthDigest::new(&preimage, &rule_ids_xdr).unwrap(),
            digest
        );
    }

    /// No typed digest exists for a mainnet partial or a tampered one.
    #[test]
    fn signing_digest_refuses_a_mainnet_or_tampered_partial() {
        assert!(matches!(
            partial_on(MAINNET_PASSPHRASE).signing_digest(),
            Err(SaError::MainnetWriteForbidden)
        ));
        assert!(matches!(
            tampered_testnet_partial().signing_digest(),
            Err(SaError::AuthEntryBindingMismatch {
                field: "auth_digest"
            })
        ));
    }

    #[test]
    fn validate_refuses_a_mainnet_network_id() {
        let partial = partial_on(MAINNET_PASSPHRASE);

        assert!(matches!(
            partial.validate(),
            Err(SaError::MainnetWriteForbidden)
        ));
    }

    #[test]
    fn validate_refuses_a_changed_signature_payload() {
        let mut partial = partial_on(TESTNET_PASSPHRASE);
        partial.signature_payload[31] ^= 0x01;

        assert!(matches!(
            partial.validate(),
            Err(SaError::AuthEntryBindingMismatch {
                field: "signature_payload"
            })
        ));
    }

    #[test]
    fn validate_refuses_a_changed_auth_digest() {
        assert!(matches!(
            tampered_testnet_partial().validate(),
            Err(SaError::AuthEntryBindingMismatch {
                field: "auth_digest"
            })
        ));
    }

    /// The network ID cannot be restated without the digests: a testnet
    /// partial relabelled as futurenet no longer validates.
    #[test]
    fn validate_refuses_a_network_id_the_digests_were_not_computed_for() {
        let mut partial = partial_on(TESTNET_PASSPHRASE);
        partial.network_id = network_id_of(FUTURENET_PASSPHRASE);

        assert!(matches!(
            partial.validate(),
            Err(SaError::AuthEntryBindingMismatch {
                field: "signature_payload"
            })
        ));
    }

    /// The context-rule IDs are bound into `auth_digest`: a rewritten rule
    /// list no longer validates.
    #[test]
    fn validate_refuses_changed_context_rule_ids() {
        let mut partial = partial_on(TESTNET_PASSPHRASE);
        partial.context_rule_ids = vec![ContextRuleId::new(43)];

        assert!(matches!(
            partial.validate(),
            Err(SaError::AuthEntryBindingMismatch {
                field: "auth_digest"
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_refuses_a_different_checked_rule() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let partial = partial_on(TESTNET_PASSPHRASE);
        let mut other = partial.clone();
        other.context_rule_ids = vec![ContextRuleId::new(999)];
        let checked = crate::submit::checked_rules_for_test(&other);
        let signer = CountingSigner::new([0x46; 32]);
        let error = complete_authorization_entry(
            &admission_fixture::gate(vec![]),
            checked,
            partial,
            &signer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                SaError::AuthEntryBindingMismatch {
                    field: "checked_signing_rules"
                }
            ),
            "{error:?}"
        );
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn multi_signer_completion_refuses_a_different_checked_account() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let partial = partial_on(TESTNET_PASSPHRASE);
        let mut other = partial.clone();
        other.smart_account = contract_address(0x99);
        let checked = crate::submit::checked_rules_for_test(&other);
        let signer = CountingSigner::new([0x46; 32]);
        let error = complete_authorization_entry_multi_signer(
            &admission_fixture::gate(vec![]),
            checked,
            partial,
            &[&signer],
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                SaError::AuthEntryBindingMismatch {
                    field: "checked_signing_rules"
                }
            ),
            "{error:?}"
        );
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ed25519_rule_signing_refuses_a_different_checked_network() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let (simulation, envelope) = contexts();
        let checked = crate::submit::checked_context_for_test(
            &contract_address(7),
            [0x99; 32],
            &[ContextRuleId::new(42)],
        );
        let signer = CountingSigner::new([0x46; 32]);
        let error = sign_with_ed25519_rule(
            &admission_fixture::gate(vec![]),
            checked,
            contract_address(7),
            symbol("transfer"),
            vec![],
            vec![ContextRuleId::new(42)],
            &simulation,
            &envelope,
            &signer,
            contract_address(0xc1),
            TESTNET_PASSPHRASE,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                SaError::AuthEntryBindingMismatch {
                    field: "checked_signing_rules"
                }
            ),
            "{error:?}"
        );
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_signs_a_testnet_partial() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x41; 32]);

        complete_authorization_entry(
            &admission_fixture::partial_gate(
                &partial_on(TESTNET_PASSPHRASE),
                vec![SignerDescriptor::Delegated {
                    account: ed25519_dalek::SigningKey::from_bytes(&[0x41; 32])
                        .verifying_key()
                        .to_bytes(),
                }],
                false,
            ),
            crate::submit::checked_rules_for_test(&partial_on(TESTNET_PASSPHRASE)),
            partial_on(TESTNET_PASSPHRASE),
            &signer,
        )
        .await
        .unwrap();

        assert_eq!(signer.public_key_calls(), 1);
        assert_eq!(signer.sign_calls(), 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_refuses_a_mainnet_partial_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x41; 32]);

        let err = complete_authorization_entry(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial_on(MAINNET_PASSPHRASE)),
            partial_on(MAINNET_PASSPHRASE),
            &signer,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(err.wire_code(), "network.mainnet_write_forbidden");
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_refuses_a_tampered_digest_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x41; 32]);

        let err = complete_authorization_entry(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&tampered_testnet_partial()),
            tampered_testnet_partial(),
            &signer,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryBindingMismatch {
                    field: "auth_digest"
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.wire_code(), "sa.auth_entry_binding_mismatch");
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_multi_signer_signs_a_testnet_partial() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let a = CountingSigner::new([0x42; 32]);
        let b = CountingSigner::new([0x43; 32]);

        complete_authorization_entry_multi_signer(
            &admission_fixture::partial_gate(
                &partial_on(TESTNET_PASSPHRASE),
                vec![
                    SignerDescriptor::Delegated {
                        account: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                    SignerDescriptor::Delegated {
                        account: ed25519_dalek::SigningKey::from_bytes(&[0x43; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                ],
                false,
            ),
            crate::submit::checked_rules_for_test(&partial_on(TESTNET_PASSPHRASE)),
            partial_on(TESTNET_PASSPHRASE),
            &[&a, &b],
        )
        .await
        .unwrap();

        assert_eq!(a.key_accesses() + b.key_accesses(), 4);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_multi_signer_refuses_a_mainnet_partial_before_any_key_access()
     {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let a = CountingSigner::new([0x42; 32]);
        let b = CountingSigner::new([0x43; 32]);

        let err = complete_authorization_entry_multi_signer(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial_on(MAINNET_PASSPHRASE)),
            partial_on(MAINNET_PASSPHRASE),
            &[&a, &b],
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(a.key_accesses() + b.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn complete_authorization_entry_multi_signer_refuses_a_tampered_digest_before_any_key_access()
     {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let a = CountingSigner::new([0x42; 32]);
        let b = CountingSigner::new([0x43; 32]);

        let err = complete_authorization_entry_multi_signer(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&tampered_testnet_partial()),
            tampered_testnet_partial(),
            &[&a, &b],
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryBindingMismatch {
                    field: "auth_digest"
                }
            ),
            "{err:?}"
        );
        assert_eq!(a.key_accesses() + b.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_signs_a_testnet_partial_with_the_testnet_passphrase() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x44; 32]);

        let entries = collect_mixed_signer_entries(
            &admission_fixture::partial_gate(
                &partial_on(TESTNET_PASSPHRASE),
                vec![admission_fixture::external(
                    &contract_address(0xc1),
                    ed25519_dalek::SigningKey::from_bytes(&[0x44; 32])
                        .verifying_key()
                        .to_bytes(),
                )],
                false,
            ),
            crate::submit::checked_rules_for_test(&partial_on(TESTNET_PASSPHRASE)),
            partial_on(TESTNET_PASSPHRASE),
            &external_signer(&signer),
            9999,
            TESTNET_PASSPHRASE,
        )
        .await
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(signer.key_accesses(), 2);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_refuses_the_mainnet_passphrase_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x44; 32]);

        let err = collect_mixed_signer_entries(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial_on(TESTNET_PASSPHRASE)),
            partial_on(TESTNET_PASSPHRASE),
            &external_signer(&signer),
            9999,
            MAINNET_PASSPHRASE,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_refuses_a_mainnet_partial_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x44; 32]);

        let err = collect_mixed_signer_entries(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial_on(MAINNET_PASSPHRASE)),
            partial_on(MAINNET_PASSPHRASE),
            &external_signer(&signer),
            9999,
            TESTNET_PASSPHRASE,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_refuses_a_tampered_digest_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x44; 32]);

        let err = collect_mixed_signer_entries(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&tampered_testnet_partial()),
            tampered_testnet_partial(),
            &external_signer(&signer),
            9999,
            TESTNET_PASSPHRASE,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryBindingMismatch {
                    field: "auth_digest"
                }
            ),
            "{err:?}"
        );
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn collect_mixed_signer_entries_refuses_a_passphrase_of_another_network_before_any_key_access()
     {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x44; 32]);

        let err = collect_mixed_signer_entries(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_rules_for_test(&partial_on(TESTNET_PASSPHRASE)),
            partial_on(TESTNET_PASSPHRASE),
            &external_signer(&signer),
            9999,
            FUTURENET_PASSPHRASE,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                SaError::AuthEntryBindingMismatch {
                    field: "network_id"
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.wire_code(), "sa.auth_entry_binding_mismatch");
        assert_eq!(signer.key_accesses(), 0);
    }

    /// The rule signer reaches the collector's mainnet refusal before any key
    /// access; the function has no check of its own.
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_with_ed25519_rule_refuses_the_mainnet_passphrase_before_any_key_access() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let (simulation, envelope) = contexts();
        let signer = CountingSigner::new([0x45; 32]);

        let err = sign_with_ed25519_rule(
            &admission_fixture::gate(vec![]),
            crate::submit::checked_context_for_test(
                &contract_address(7),
                simulation.network_id,
                &[ContextRuleId::new(42)],
            ),
            contract_address(7),
            symbol("transfer"),
            vec![],
            vec![ContextRuleId::new(42)],
            &simulation,
            &envelope,
            &signer,
            contract_address(0xC1),
            MAINNET_PASSPHRASE,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(signer.key_accesses(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn build_and_sign_delegated_g_key_entry_signs_on_testnet() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x46; 32]);
        let partial = partial_on(TESTNET_PASSPHRASE);

        build_and_sign_delegated_g_key_entry(
            &admission_fixture::delegated_gate(
                &partial.smart_account,
                &partial.auth_digest,
                9999,
                ed25519_dalek::SigningKey::from_bytes(&[0x46; 32])
                    .verifying_key()
                    .to_bytes(),
                1,
            ),
            1,
            &partial.smart_account,
            &partial.auth_digest,
            9999,
            &signer,
            TESTNET_PASSPHRASE,
            None,
        )
        .await
        .unwrap();

        assert_eq!(signer.key_accesses(), 2);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn build_and_sign_delegated_g_key_entry_refuses_the_mainnet_passphrase_before_any_key_access()
     {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = CountingSigner::new([0x46; 32]);
        let partial = partial_on(TESTNET_PASSPHRASE);

        let err = build_and_sign_delegated_g_key_entry(
            &admission_fixture::gate(vec![]),
            1,
            &partial.smart_account,
            &partial.auth_digest,
            9999,
            &signer,
            MAINNET_PASSPHRASE,
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SaError::MainnetWriteForbidden), "{err:?}");
        assert_eq!(signer.key_accesses(), 0);
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn the_gate_refuses_what_the_plan_does_not_name() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        admission_fixture::assert_envelope_bounds_refuse_before_signing().await;
        let partial = partial_on(TESTNET_PASSPHRASE);
        let seed = [0x51; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let mut other = partial.clone();
        other.smart_account = contract_address(8);
        assert_eq!(partial.auth_digest, other.auth_digest);
        let mut other_nonce = partial.clone();
        other_nonce.nonce += 1;
        (other_nonce.signature_payload, other_nonce.auth_digest) = derive_digests(
            other_nonce.network_id,
            other_nonce.nonce,
            other_nonce.signature_expiration_ledger,
            &other_nonce.root_invocation,
            &other_nonce.context_rule_ids,
        )
        .unwrap();
        for changed in [
            other_nonce.clone(),
            other,
            test_helpers::partial_authorization_entry(
                contract_address(8),
                TESTNET_PASSPHRASE,
                vec![ContextRuleId::new(42)],
            )
            .unwrap(),
        ] {
            let signer = CountingSigner::new(seed);
            let gate = admission_fixture::partial_gate(
                &partial,
                vec![SignerDescriptor::Delegated { account: key }],
                false,
            );
            let error = complete_authorization_entry(
                &gate,
                crate::submit::checked_rules_for_test(&changed),
                changed.clone(),
                &signer,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                SaError::IntentBindingMismatch {
                    field: "signing_request"
                }
            ));
            assert_eq!(signer.sign_calls(), 0);
            assert!(gate.take_unexposed().is_some());
            let gate = admission_fixture::partial_gate(
                &partial,
                vec![admission_fixture::external(&contract_address(0xc1), key)],
                false,
            );
            let error = collect_mixed_signer_entries(
                &gate,
                crate::submit::checked_rules_for_test(&changed),
                changed.clone(),
                &external_signer(&signer),
                changed.signature_expiration_ledger,
                TESTNET_PASSPHRASE,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                error,
                SaError::IntentBindingMismatch {
                    field: "signing_request"
                }
            ));
            assert_eq!(signer.sign_calls(), 0);
            assert!(gate.take_unexposed().is_some());
        }
        let signer = CountingSigner::new(seed);
        let gate = admission_fixture::partial_gate(
            &partial,
            vec![admission_fixture::external(&contract_address(0xc2), key)],
            false,
        );
        let result = collect_mixed_signer_entries(
            &gate,
            crate::submit::checked_rules_for_test(&partial),
            partial.clone(),
            &external_signer(&signer),
            partial.signature_expiration_ledger,
            TESTNET_PASSPHRASE,
        )
        .await;
        assert_eq!(signer.sign_calls(), 0);
        assert!(matches!(
            result,
            Err(SaError::IntentBindingMismatch {
                field: "signing_request"
            })
        ));
        assert!(gate.take_unexposed().is_some());
        let signer = CountingSigner::new(seed);
        let gate = admission_fixture::partial_gate(
            &partial,
            vec![SignerDescriptor::Delegated { account: key }],
            false,
        );
        complete_authorization_entry(
            &gate,
            crate::submit::checked_rules_for_test(&partial),
            partial.clone(),
            &signer,
        )
        .await
        .unwrap();
        assert_eq!(signer.sign_calls(), 1);
        assert!(gate.exposure().is_some());
        assert!(gate.take_unexposed().is_none());
        let error = complete_authorization_entry(
            &gate,
            crate::submit::checked_rules_for_test(&other_nonce),
            other_nonce,
            &signer,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            SaError::IntentBindingMismatch {
                field: "signing_request"
            }
        ));
        assert_eq!(signer.sign_calls(), 1);
        let error = complete_authorization_entry(
            &gate,
            crate::submit::checked_rules_for_test(&partial),
            partial,
            &signer,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            SaError::IntentBindingMismatch {
                field: "signing_request"
            }
        ));
        assert_eq!(signer.sign_calls(), 1);
    }

    /// The signed re-simulation names the code the RPC 30.0.1 events confirm,
    /// with the same variant, phase and wire code.
    #[tokio::test]
    async fn resimulation_refusal_names_the_code_on_rpc30() {
        use crate::managers::rules::event_reason_tests::{
            RPC30_ERROR, SAC, SMART_ACCOUNT, address, address_entry, read_only_server,
            refusal_result, rpc30_events,
        };
        let source = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        let server = read_only_server(&source, refusal_result(RPC30_ERROR, &rpc30_events())).await;
        let rpc = Client::new(&server.uri()).unwrap();
        let rpc_client = StellarRpcClient::new(&server.uri()).unwrap();
        let error = resimulate_with_signed_auth(
            &rpc,
            &rpc_client,
            &address(SAC),
            ScSymbol::try_from("transfer").unwrap(),
            VecM::default(),
            vec![address_entry(address(SMART_ACCOUNT), &address(SAC), vec![])],
            &source,
            TESTNET_PASSPHRASE,
            PreSubmitBudget {
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                total: std::time::Duration::from_secs(30),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.wire_code(), "sa.deployment_failed");
        match error {
            SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason,
            } => assert_eq!(
                redacted_reason,
                "re-simulate returned error: Error(Contract, #3221) [OZ:SpendingLimitExceeded]"
            ),
            other => panic!("expected the simulate refusal, got {other:?}"),
        }
    }

    async fn busy_resimulation(
        server: &wiremock::MockServer,
        budget: PreSubmitBudget,
    ) -> Result<stellar_rpc_client::SimulateTransactionResponse, SaError> {
        use crate::managers::rules::event_reason_tests::{
            SAC, SMART_ACCOUNT, address, address_entry,
        };
        let source = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        resimulate_with_signed_auth(
            &Client::new(&server.uri()).unwrap(),
            &StellarRpcClient::new(&server.uri()).unwrap(),
            &address(SAC),
            ScSymbol::try_from("transfer").unwrap(),
            VecM::default(),
            vec![address_entry(address(SMART_ACCOUNT), &address(SAC), vec![])],
            &source,
            TESTNET_PASSPHRASE,
            budget,
        )
        .await
    }

    #[tokio::test]
    async fn busy_resimulation_fails_as_transport() {
        use crate::managers::rules::event_reason_tests::{
            RPC30_ERROR, busy_replies, read_only_server, refusal_result, rpc30_events,
        };
        let source = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        for busy in [1, 4] {
            let server =
                read_only_server(&source, refusal_result(RPC30_ERROR, &rpc30_events())).await;
            busy_replies(&server, busy).await;
            let budget = PreSubmitBudget {
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                total: std::time::Duration::from_secs(30),
            };
            let error = crate::managers::rules::event_reason_tests::drive_busy_paused(
                busy_resimulation(&server, budget),
            )
            .await
            .unwrap_err();
            if busy == 1 {
                assert!(
                    matches!(error, SaError::DeploymentFailed { phase: "simulate", ref redacted_reason } if redacted_reason.contains("[OZ:SpendingLimitExceeded]")),
                    "{error:?}"
                );
            } else {
                assert!(
                    matches!(
                        error,
                        SaError::AuthEntryConstructionFailed {
                            stage: "auth_payload",
                            ..
                        }
                    ),
                    "{error:?}"
                );
                assert!(tokio::time::Instant::now() < budget.deadline);
            }
            assert_eq!(
                stellar_agent_test_support::rpc_request_count(&server, "simulateTransaction").await,
                if busy == 1 { 2 } else { 4 }
            );
        }
    }

    #[tokio::test]
    async fn resimulation_expiry_keeps_the_stage_error() {
        use crate::managers::rules::event_reason_tests::{
            busy_replies, read_only_server, successful_read_result,
        };
        let source = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        let server = read_only_server(&source, successful_read_result()).await;
        wiremock::Mock::given(wiremock::matchers::body_partial_json(
            serde_json::json!({"method": "simulateTransaction"}),
        ))
        .respond_with(|request: &wiremock::Request| {
            let body: serde_json::Value = request.body_json().unwrap();
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": successful_read_result()
                }))
                .set_delay(std::time::Duration::from_secs(3))
        })
        .with_priority(2)
        .mount(&server)
        .await;
        busy_replies(&server, 1).await;
        let start = tokio::time::Instant::now();
        let budget = PreSubmitBudget {
            deadline: start + std::time::Duration::from_secs(2),
            total: std::time::Duration::from_secs(2),
        };
        let error = busy_resimulation(&server, budget).await.unwrap_err();
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::to_value(budget.elapsed("simulate_resimulate", "auth_payload")).unwrap()
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(2500));
    }

    #[tokio::test]
    async fn busy_resimulation_reuses_the_envelope() {
        use crate::managers::rules::event_reason_tests::{
            RPC30_ERROR, busy_replies, read_only_server, refusal_result, rpc30_events,
        };
        let source = stellar_strkey::ed25519::PublicKey([7; 32]).to_string();
        let server = read_only_server(&source, refusal_result(RPC30_ERROR, &rpc30_events())).await;
        busy_replies(&server, 2).await;
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(30),
        };
        let error = busy_resimulation(&server, budget).await.unwrap_err();
        assert!(matches!(
            error,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ));
        let bodies: Vec<serde_json::Value> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.body_json().unwrap())
            .collect();
        let envelopes: Vec<_> = bodies
            .iter()
            .filter(|r| r["method"] == "simulateTransaction")
            .map(|r| &r["params"]["transaction"])
            .collect();
        assert_eq!(envelopes.len(), 3);
        assert!(envelopes.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(
            stellar_agent_test_support::rpc_request_count(&server, "getLedgerEntries").await,
            1
        );
    }
}
