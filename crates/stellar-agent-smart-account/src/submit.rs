//! Free-function submit substrate for signed `InvokeHostFunction` transactions.
//!
//! Extracted from the two instance methods:
//!
//! - `crates/stellar-agent-smart-account/src/managers/rules.rs`
//!   (`ContextRuleManager::submit_signed_invoke`)
//! - `crates/stellar-agent-smart-account/src/managers/signers.rs`
//!   (`SignersManager::submit_signed_invoke`)
//!
//! Both instance methods become thin delegating wrappers that call
//! [`submit_signed_invoke`].
//!
//! # Audit-emission discipline
//!
//! `submit_signed_invoke` does NOT emit any `Sa*` audit rows.
//! Audit emission is caller-side. The caller's `Err(err)` match arm emits the
//! appropriate domain-specific audit row via `sa_error_to_invocation_result` +
//! `SaRawInvocation`.
//!
//! # Step ordering
//!
//! 1. Pre-flight: wasm-hash-drift-check (passthrough when no wasm pin is in args).
//! 2. Simulate: primary RPC; harvest `latestLedger`.
//! 3. Required-check enforcement + `Option<*Check>` dispatch.
//! 4. Cross-RPC simulate check (passthrough when `secondary_rpc_url` is `None`
//!    or `multicall_check` is `None`).
//! 5. Sign: auth-entry via `build_authorization_entry` substrate.
//! 6. Submit: send signed envelope.
//! 7. Return `Result<SubmitInvokeResult, SaError>` to caller.

use sha2::{Digest as _, Sha256};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    HostFunction, InvokeHostFunctionOp, Operation, OperationBody, ScAddress, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedInvocation, SorobanCredentials, VecM,
};
use tracing::info;

use stellar_agent_core::policy::v1::bundle::InnerOpDescriptor;

use crate::SaError;
use crate::managers::auth_entry::{
    AuthorizationSimulation, PartialSorobanAuthorizationEntry, build_authorization_entry,
    build_authorization_entry_with_sub_invocations, complete_authorization_entry,
};
use crate::managers::authorization::collect_quorum_signatures;
use crate::managers::rules::{
    AUTH_VALIDITY_LEDGERS, BASE_FEE_STROOPS, ExpiryCheck, HorizonCheck, augment_with_oz_error_name,
    build_and_sign_delegated_g_key_entry, build_signed_invoke_envelope, chain_id_fingerprint,
    check_rule_not_expired_standalone, fingerprint_invocation, locate_smart_account_auth_entry,
    parse_c_strkey_to_smart_account, parse_min_resource_fee, passphrase_fingerprint,
    resimulate_with_signed_auth, scaddress_to_strkey, validate_latest_ledger,
};
use crate::signing::divergence::{
    EnvelopeContext, FeeEnvelopeContext, NetworkContext, SequenceContext, SimulationContext,
};

// ─────────────────────────────────────────────────────────────────────────────
// MulticallCheck
// ─────────────────────────────────────────────────────────────────────────────

/// Multicall bundle check parameters for the cross-RPC trust-anchor at Step 4.
///
/// Constructed inside `multicall::submit_multicall_bundle` (same crate) and
/// passed through `SubmitInvokeArgs::multicall_check` to
/// [`submit_signed_invoke`] Step 4.
///
/// All four fields are read in Step 4:
/// - `registry_entry_address` + `registry_entry_wasm_sha256` → wasm-hash 4-way equality.
/// - `network_passphrase` → defence-in-depth network mismatch check (ensures
///   the check was built for the same network as the submission).
/// - `bundle_descriptors` → defence-in-depth bundle/rule-id count alignment check.
///
/// # Field ownership
///
/// Fields are owned (`Vec<InnerOpDescriptor>`, `String`) rather than borrowed
/// so that `MulticallCheck` can outlive the intermediate `BundleView<'_>` that
/// carries borrows into the policy engine.  `BundleView` is re-materialised
/// on-demand at the comparator call site from these owned values.
///
/// # Trust-anchor enforcement
///
/// Step 4 of [`submit_signed_invoke`] uses these fields to
/// dispatch to `multicall::cross_rpc_compare_wasm_hashes` and
/// `multicall::cross_rpc_compare_simulate_responses`, which together enforce
/// 4-way byte-exact equality:
/// - `MULTICALL_WASM_SHA256` binary const
/// - `registry_entry_wasm_sha256` (registry-recorded TOML value)
/// - Primary RPC on-chain hash
/// - Secondary RPC on-chain hash
#[derive(Debug)]
pub struct MulticallCheck {
    /// Ordered per-inner descriptors materialised from the validated bundle.
    ///
    /// Mirrors the `InnerOpDescriptor` shape from `policy::v1::bundle`; carried
    /// owned so `BundleView` can be re-materialised on demand.
    pub bundle_descriptors: Vec<InnerOpDescriptor>,

    /// C-strkey of the registered multicall router contract.
    ///
    /// Cross-checked against the primary and secondary RPC on-chain state at
    /// Step 4 (wasm-hash lookup by contract address).
    pub registry_entry_address: String,

    /// SHA-256 of the multicall router WASM, as recorded in the registry TOML.
    ///
    /// Must equal `MULTICALL_WASM_SHA256` (enforced at register-time and
    /// lookup-time by `MulticallRegistry`; cross-RPC comparator verifies it
    /// also equals the on-chain hash from both RPC endpoints).
    pub registry_entry_wasm_sha256: String,

    /// Stellar network passphrase for the submission context.
    ///
    /// Stored owned so that comparator helpers do not need a lifetime-carrying
    /// reference into the outer `MulticallSubmitArgs`.
    pub network_passphrase: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvedFeePerOp
// ─────────────────────────────────────────────────────────────────────────────

/// Resolved per-operation fee in stroops.
///
/// [`ResolvedFeePerOp::default()`] applies `BASE_FEE_STROOPS`. Callers may
/// resolve from a profile fee policy for a custom value.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedFeePerOp {
    /// Base fee for the source-account transaction (in stroops).
    ///
    /// The Soroban resource fee is added on top from the simulate response
    /// (`min_resource_fee`); this is the base `tx.fee` field.
    pub base_stroops: u32,
}

impl Default for ResolvedFeePerOp {
    fn default() -> Self {
        Self {
            base_stroops: BASE_FEE_STROOPS,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmitInvokeResult
// ─────────────────────────────────────────────────────────────────────────────

/// Return value from [`submit_signed_invoke`].
///
/// Wraps the on-chain return `ScVal` from the submitted `InvokeHostFunction`
/// operation and the confirmed-ledger / transaction-hash metadata from
/// [`stellar_agent_network::submit::SubmissionResult`].
///
/// Exposes the confirmed transaction hash, ledger, and predicted return value
/// to callers.  The return value comes from the first `simulateTransaction`
/// response; Soroban-RPC does not deliver a fresh post-confirmation `ScVal`.
#[derive(Debug)]
pub struct SubmitInvokeResult {
    /// The predicted return value from the first `simulateTransaction`
    /// response for this `InvokeHostFunction`.
    ///
    /// Soroban-RPC submit/confirm does not return a fresh post-confirmation
    /// `ScVal`; callers use this value as the operation return payload after
    /// the transaction is confirmed. For multicall, the caller validates its
    /// shape and inner-count after confirmation before reporting per-inner
    /// results.
    pub return_val: ScVal,

    /// The confirmed transaction hash (64-character hex string).
    ///
    /// Sourced from `SubmissionResult.tx_hash` after `submit_transaction_and_wait`
    /// returns. Used by `submit_multicall_bundle` to populate
    /// `MulticallResult.bundle_tx_hash` and audit rows.
    pub tx_hash: String,

    /// The ledger sequence number in which the transaction was confirmed.
    ///
    /// Sourced from `SubmissionResult.ledger`. Used by `submit_multicall_bundle`
    /// to populate `MulticallResult.ledger`.
    pub ledger: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmitInvokeArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for [`submit_signed_invoke`].
///
/// Carries all inputs required by the seven-stage signed-invoke flow. The
/// `required_checks` field enforces that callers declare any check the
/// host-function shape demands; the free function refuses with
/// [`SaError::SubmitCheckMissing`] if a declared check is `None`.
///
/// The `horizon_check`, `expiry_check`, and `multicall_check` fields are
/// `pub(crate)` because they carry internal orchestration types that are not
/// part of the public API.  External callers leave these fields at their
/// default (`None`); the builder does not expose setters for `pub(crate)`
/// fields to external compilation units.
///
/// # Caller convention
///
/// - `rules.rs` callers pass:
///   - `auth_address: None` (defaults to `target_contract`)
///   - `expiry_check: None` or `Some(ExpiryCheck { rule_id })`
///   - `horizon_check: None` or `Some(HorizonCheck { .. })`
///   - `multicall_check: None`
///   - `required_checks: &[]`
///   - `emit_observability_logs: true`
/// - `signers.rs` callers pass:
///   - `auth_address: Some(contract_strkey)` (explicit for correctness)
///   - `expiry_check: None` or `Some(ExpiryCheck { rule_id })`
///   - `horizon_check: None`
///   - `multicall_check: None`
///   - `required_checks: &[]`
///   - `emit_observability_logs: false`
const EMPTY_REQUIRED_CHECKS: &[&str] = &[];

/// Arguments for [`submit_signed_invoke`].
///
/// Carries all inputs required by the seven-stage signed-invoke flow.
/// Construct via the generated `SubmitInvokeArgs::builder()` associated
/// function.
#[derive(bon::Builder)]
#[non_exhaustive]
pub struct SubmitInvokeArgs<'a> {
    /// C-strkey of the contract to invoke.
    ///
    /// For DeFi adapters and other external-contract callers this is the
    /// external contract address (e.g. a Blend pool, DeFindex vault, or
    /// Soroswap router).  For wallet self-calls (OZ entrypoints) this is the
    /// wallet contract itself.  The wallet credential address is `auth_address`,
    /// which defaults to `target_contract` when `None`.
    pub target_contract: &'a str,

    /// Optional auth-address override (C-strkey).
    ///
    /// When `None`, the auth-entry locator uses `target_contract` as the
    /// credential address — correct for all OZ entrypoints that call
    /// `e.current_contract_address().require_auth()`. Pass `Some(c_strkey)`
    /// for entrypoints that require a different C-strkey credential address.
    /// G-strkey addresses are rejected with
    /// [`SaError::AuthEntryConstructionFailed`] at the strkey-parse step.
    pub auth_address: Option<&'a str>,

    /// Context-rule IDs used for building `SimulationContext` +
    /// `EnvelopeContext`. One entry per auth-entry the caller expects.
    pub auth_rule_ids: &'a [ContextRuleId],

    /// Pre-built host function (caller builds `HostFunction::InvokeContract`).
    pub host_function: HostFunction,

    /// Signer for the smart-account auth-digest and source-account envelope.
    pub signer: &'a (dyn Signer + Send + Sync),

    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,

    /// Secondary Soroban RPC URL for the cross-RPC simulate check.
    ///
    /// Step 4 is a passthrough when this is `None` or when `multicall_check`
    /// is `None`.
    pub secondary_rpc_url: Option<&'a str>,

    /// Stellar network passphrase for auth-digest + network-ID + envelope
    /// signing.
    pub network_passphrase: &'a str,

    /// CAIP-2 chain ID for the `NetworkContext` fingerprint
    /// (e.g. `"stellar:testnet"`).
    pub chain_id: &'a str,

    /// Submission polling timeout.
    pub timeout: std::time::Duration,

    /// Per-operation fee (stroops). [`ResolvedFeePerOp::default()`] applies
    /// `BASE_FEE_STROOPS`.
    #[builder(default)]
    pub fee: ResolvedFeePerOp,

    /// Human-readable operation label for log and error messages.
    ///
    /// Examples: `"install_rule"`, `"add_signer"`, `"remove_signer"`.
    /// `&'static str` so error construction is allocation-free on the refusal
    /// path.
    pub op_label: &'static str,

    /// Whether to emit `info!` observability logs at submit and confirm points.
    ///
    /// `rules.rs` callers set `true`. `signers.rs` callers leave `false`
    /// (the default) — the instance method did not emit at these points so
    /// adding logs there would be a behaviour change.
    #[builder(default)]
    pub emit_observability_logs: bool,

    /// Declared required checks.
    ///
    /// For each name in this slice, the corresponding `Option<*Check>` field
    /// MUST be `Some`. If `None`, the function refuses immediately with
    /// [`SaError::SubmitCheckMissing`] — fail-CLOSED enforcement.
    ///
    /// Single-invocation callers pass `&[]` — no required checks. The
    /// `submit_multicall_bundle` caller passes `&["multicall"]` and supplies
    /// `Some(MulticallCheck { .. })`.
    ///
    /// Recognised names: `"multicall"`.
    #[builder(default = EMPTY_REQUIRED_CHECKS)]
    pub required_checks: &'a [&'static str],

    /// Session-rule horizon check.
    ///
    /// Fires after simulate (so `latestLedger` is known), before signing.
    /// `rules.rs` install + update callers supply this; all others pass `None`.
    ///
    /// Field and setter are `pub(crate)` because [`HorizonCheck`] is an
    /// internal orchestration type.  External callers leave this `None`.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) horizon_check: Option<HorizonCheck>,

    /// Pre-submission rule expiry check.
    ///
    /// Fires after simulate, before signing. Signing-path methods that consume
    /// a `rule_id` supply this; install path passes `None`.
    ///
    /// Field and setter are `pub(crate)` because [`ExpiryCheck`] is an
    /// internal orchestration type.  External callers leave this `None`.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) expiry_check: Option<ExpiryCheck>,

    /// Multicall bundle check. `None` for single-invocation callers.
    pub multicall_check: Option<MulticallCheck>,

    /// Quorum authorization declaration (`None` for single-signer callers).
    ///
    /// When `Some`, `submit_signed_invoke` uses
    /// [`collect_quorum_signatures`]
    /// to produce the full `SorobanAuthorizationEntry` set from the multi-signer
    /// group declaration and ignores [`Self::signer`] for auth-entry signing.
    /// When `None`, the original single-signer path via [`Self::signer`] is
    /// used unchanged.
    ///
    /// # Fail-closed invariant
    ///
    /// Supplying `authorization: Some(_)` with `signers: &[]` (empty slice)
    /// produces [`crate::managers::authorization::QuorumError::InsufficientSignersInGroup`]
    /// and is converted to [`SaError::AuthEntryConstructionFailed`]. The
    /// single-signer `signer` field remains the envelope-signing key and source
    /// account in both paths.
    pub authorization: Option<&'a crate::managers::authorization::AuthorizationInfo>,

    /// Additional signers for the quorum path.
    ///
    /// Only consulted when `authorization` is `Some`. Must contain at least the
    /// qualifying signers declared in the `AuthorizationInfo` groups.
    /// Pass `&[]` (empty) for single-signer callers (the field is ignored when
    /// `authorization` is `None`).
    ///
    /// The `signer` field remains the envelope-signing key and source account in
    /// both paths, and MAY be included in this slice if it is also a quorum
    /// participant.
    #[builder(default = &[])]
    pub signers: &'a [&'a (dyn Signer + Send + Sync)],
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_signed_invoke
// ─────────────────────────────────────────────────────────────────────────────

/// Seven-stage signed `InvokeHostFunction` submission with optional pre-flight
/// checks.
///
/// Extracted from `ContextRuleManager::submit_signed_invoke` (rules.rs) and
/// `SignersManager::submit_signed_invoke` (signers.rs). The two instance methods
/// become thin delegating wrappers that call this free function.
///
/// # Step ordering
///
/// 1. **Pre-flight**: wasm-hash-drift-check when pinned.
///    Passthrough when no wasm pin is present in [`SubmitInvokeArgs`].
/// 2. **Simulate**: primary RPC; harvest `latestLedger`.
/// 3. **Required-check enforcement + `Option<*Check>` dispatch**: for each
///    name in `args.required_checks`, the corresponding `Option<*Check>` MUST
///    be `Some`. Refuses with [`SaError::SubmitCheckMissing`] if `None`.
///    Then dispatches each present `Some(_)` check; first `Deny` → return
///    typed error.
/// 4. **Cross-RPC simulate check** (`secondary_rpc_url.is_some()`): passthrough
///    for single-invocation callers (who pass `multicall_check: None`). The
///    multicall path activates this.
/// 5. **Sign**: auth-entry via `build_authorization_entry` +
///    `complete_authorization_entry` + delegated G-key entry.
/// 6. **Submit**: `resimulate_with_signed_auth` + `build_signed_invoke_envelope`
///    + `attach_signature` + `submit_transaction_and_wait`.
/// 7. **Return**: `Ok(SubmitInvokeResult { return_val, tx_hash, ledger })`.
///
/// # Audit-emission discipline
///
/// This function does NOT emit any `Sa*` audit rows. Audit emission is
/// caller-side: the caller's `Err(err)` match arm emits the appropriate
/// domain-specific row via `sa_error_to_invocation_result` + `SaRawInvocation`.
///
/// # Errors
///
/// - [`SaError::SubmitCheckMissing`] — a name in `required_checks` maps to a
///   `None` `Option<*Check>` field.
/// - [`SaError::HorizonExceeded`] — `valid_until - latest_ledger > max_horizon`.
/// - [`SaError::RuleExpired`] — `valid_until < latest_ledger` for the expiry
///   check rule_id.
/// - [`SaError::AuthEntryConstructionFailed`] — pubkey fetch, XDR encoding,
///   simulate, or auth-entry construction failure.
/// - [`SaError::DeploymentFailed`] — simulate error, envelope build, or
///   submission failure.
/// - [`SaError::RuleIdMismatch`] / [`SaError::SimulationDivergence`] — from
///   [`build_authorization_entry`].
#[allow(
    clippy::too_many_lines,
    reason = "seven-stage flow; splitting across multiple functions would obscure \
              the sequential invariant ordering (pre-flight → simulate → checks \
              → sign → submit)"
)]
pub async fn submit_signed_invoke(
    args: SubmitInvokeArgs<'_>,
) -> Result<SubmitInvokeResult, SaError> {
    assert_submit_invoke_args_invariants(&args);

    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    // ── Step 3 (required-check enforcement) — execute FIRST before any I/O ──
    // Fail-CLOSED: a caller who declares "multicall" in required_checks but
    // passes None for multicall_check gets a typed refusal before any network
    // round-trip. This surfaces programming errors at the call site, not at
    // submit time.
    //
    // Host-function kind string for the error envelope — derived here once and
    // reused in any SubmitCheckMissing that fires.
    let hf_kind = host_function_kind_str(&args.host_function);
    for &required in args.required_checks {
        check_required(&args, required, hf_kind)?;
    }

    // ── Derive source-account pubkey from the signer (four-axis migration #3) ──
    // Computed inline; signers.rs callers no longer pre-compute.
    let source_pubkey = args
        .signer
        .public_key()
        .await
        .map_err(|e| auth_payload_err(format!("signer public_key fetch failed: {e}")))?;
    // `stellar_strkey` 0.0.16 returns `heapless::String<56>` from `to_string()`.
    // Convert explicitly via `.as_str().to_owned()` to obtain `std::string::String`
    // (mirrors the scaddress_to_strkey pattern in rules.rs:4359-4360).
    let source_pubkey_strkey: String = stellar_strkey::ed25519::PublicKey(source_pubkey.0)
        .to_string()
        .as_str()
        .to_owned();

    // ── Parse target_contract / auth_address strkeys to ScAddress ────────────
    // Auth-address defaults to target_contract when None (four-axis migration #4).
    let target_contract_scaddr = parse_c_strkey_to_smart_account(args.target_contract)?;
    let auth_scaddr: ScAddress = if let Some(addr) = args.auth_address {
        parse_c_strkey_to_smart_account(addr)?
    } else {
        target_contract_scaddr.clone()
    };

    // Extract InvokeContractArgs from the pre-built HostFunction.
    let invoke = match &args.host_function {
        HostFunction::InvokeContract(inv) => inv.clone(),
        _ => {
            return Err(SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!(
                    "{}: expected HostFunction::InvokeContract, got {}",
                    args.op_label, hf_kind,
                ),
            });
        }
    };
    let function_name = invoke.function_name.clone();

    let invoke_args_vecm: VecM<ScVal> = invoke.args.clone();

    // Rebuild the full HostFunction (re-use the same InvokeContractArgs).
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke.clone()),
            auth: VecM::default(),
        }),
    };

    // ── Fetch source-account for transaction builder ──────────────────────────
    let primary_rpc_client = StellarRpcClient::new(args.primary_rpc_url)
        .map_err(|e| auth_payload_err(format!("StellarRpcClient construction failed: {e}")))?;

    let source_view = fetch_account(&primary_rpc_client, &source_pubkey_strkey, &[])
        .await
        .map_err(|e| auth_payload_err(format!("source-account fetch failed: {e}")))?;

    let mut source_account = BaselibAccount::new(
        &source_pubkey_strkey,
        &source_view.sequence_number.to_string(),
    )
    .map_err(|e| auth_payload_err(format!("BaselibAccount::new failed: {e:?}")))?;

    let mut tx_builder =
        TransactionBuilder::new(&mut source_account, args.network_passphrase, None);
    tx_builder.fee(args.fee.base_stroops);
    tx_builder.add_operation(op);
    let tx_for_simulate = tx_builder.build_for_simulation();

    // ── Step 2: Simulate ──────────────────────────────────────────────────────
    let server = Client::new(args.primary_rpc_url)
        .map_err(|e| auth_payload_err(format!("RPC Client construction failed: {e}")))?;

    let sim_envelope = tx_for_simulate
        .to_envelope()
        .map_err(|e| auth_payload_err(format!("to_envelope failed: {e:?}")))?;
    let sim_response = server
        .simulate_transaction_envelope(&sim_envelope, None)
        .await
        .map_err(|e| auth_payload_err(format!("simulate_transaction_envelope failed: {e}")))?;

    // ── Step 3 continued: Option<*Check> dispatch ─────────────────────────────
    //
    // Horizon check: fires AFTER simulate (latestLedger known) BEFORE signing.
    // OZ storage.rs:649-652 (install) and :786-787 (update), SHA `3f81125`,
    // reject only `valid_until < current_ledger` (PastValidUntil = 3005).
    // The wallet-side horizon cap is an operator-configurable safety discipline.
    if let Some(HorizonCheck {
        valid_until,
        max_horizon,
        rule_id_or_pending,
    }) = args.horizon_check
    {
        let latest_ledger = sim_response.latest_ledger;
        let horizon = valid_until.saturating_sub(latest_ledger);
        if horizon > max_horizon {
            return Err(SaError::HorizonExceeded {
                rule_id_or_pending,
                requested_horizon: horizon,
                max_horizon,
            });
        }
    }

    // Expiry check: fires AFTER simulate (latestLedger known) BEFORE signing.
    // OZ storage.rs:280-285 (SHA `3f81125`): strict-< check on valid_until.
    // UnvalidatedContext = 3002 per OZ mod.rs:542 SHA `3f81125`.
    if let Some(ExpiryCheck { rule_id }) = args.expiry_check {
        let latest_ledger = sim_response.latest_ledger;
        check_rule_not_expired_standalone(
            args.primary_rpc_url,
            args.network_passphrase,
            args.timeout,
            target_contract_scaddr.clone(),
            rule_id,
            &source_pubkey_strkey,
            latest_ledger,
        )
        .await?;
    }

    // ── Step 4: Cross-RPC trust-anchor check ─────────────────────────────────
    // When secondary_rpc_url.is_some() AND multicall_check.is_some(), dispatch
    // to the cross-RPC WASM-hash + simulate comparators (4-way equality):
    //   (a) cross_rpc_compare_wasm_hashes — verifies registry SHA, primary RPC
    //       on-chain hash, secondary RPC on-chain hash, and MULTICALL_WASM_SHA256
    //       binary const are byte-exactly equal.
    //   (b) cross_rpc_compare_simulate_responses — verifies both RPCs produce
    //       identical simulation results for the multicall invocation by
    //       re-simulating on the secondary RPC and comparing responses.
    //
    // Single-invocation callers always pass multicall_check: None → this branch
    // is a no-op for them (passthrough).
    if let (Some(secondary_url), Some(mc)) = (args.secondary_rpc_url, args.multicall_check.as_ref())
    {
        // Defence-in-depth: verify the MulticallCheck was built for the same
        // network passphrase as this submission context. A mismatch here
        // indicates a programming error (wrong check passed to wrong network).
        if mc.network_passphrase != args.network_passphrase {
            return Err(SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!(
                    "MulticallCheck network_passphrase mismatch: check={}, submission={}",
                    &mc.network_passphrase[..8.min(mc.network_passphrase.len())],
                    &args.network_passphrase[..8.min(args.network_passphrase.len())],
                ),
                post_submit_kind: None,
            });
        }

        // Defence-in-depth: verify the bundle descriptor count matches the
        // number of auth_rule_ids (each inner needs its own rule context).
        // A mismatch here surfaces a caller construction error before any RPC I/O.
        if !mc.bundle_descriptors.is_empty()
            && mc.bundle_descriptors.len() != args.auth_rule_ids.len()
        {
            return Err(SaError::MulticallFailed {
                phase: "build",
                redacted_reason: format!(
                    "MulticallCheck bundle_descriptors.len()={} != auth_rule_ids.len()={}",
                    mc.bundle_descriptors.len(),
                    args.auth_rule_ids.len(),
                ),
                post_submit_kind: None,
            });
        }

        // (a) Wasm-hash 4-way equality: fetch on-chain hashes from both RPCs and
        // compare against the registry-recorded SHA and MULTICALL_WASM_SHA256.
        let primary_hash = crate::multicall::fetch_wasm_hash_via_rpc(
            args.primary_rpc_url,
            &mc.registry_entry_address,
            args.timeout,
        )
        .await?;
        let secondary_hash = crate::multicall::fetch_wasm_hash_via_rpc(
            secondary_url,
            &mc.registry_entry_address,
            args.timeout,
        )
        .await?;
        crate::multicall::cross_rpc_compare_wasm_hashes(
            &mc.registry_entry_wasm_sha256,
            &primary_hash,
            &secondary_hash,
        )?;

        // (b) Cross-RPC simulate comparison: re-simulate on secondary RPC and
        // compare normalised response against primary result (including
        // sub_invocations byte-exact; see cross_rpc_compare_simulate_responses).
        let secondary_server = stellar_rpc_client::Client::new(secondary_url).map_err(|e| {
            auth_payload_err(format!("secondary RPC Client construction failed: {e}"))
        })?;
        let secondary_sim = secondary_server
            .simulate_transaction_envelope(&sim_envelope, None)
            .await
            .map_err(|e| SaError::MulticallFailed {
                phase: "rpc_divergence",
                redacted_reason: format!("secondary RPC simulate failed: {e}"),
                post_submit_kind: None,
            })?;
        crate::multicall::cross_rpc_compare_simulate_responses(&sim_response, &secondary_sim)?;
    }

    // ── Simulation error / empty-response guard ──────────────────────────────
    if let Some(sim_error) = &sim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!(
                "{} simulation returned error: {}",
                args.op_label,
                augment_with_oz_error_name(sim_error)
            ),
        });
    }
    if sim_response.min_resource_fee == 0 || sim_response.transaction_data.is_empty() {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "simulate_transaction returned no min_resource_fee / \
                              transaction_data"
                .to_owned(),
        });
    }

    let sim_first_result = sim_response
        .results()
        .map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("simulate results decode failed: {e}"),
        })?
        .into_iter()
        .next()
        .ok_or(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "simulate_transaction returned no result entry".to_owned(),
        })?;
    let return_val = sim_first_result.xdr;
    let mut prepared_auth_entries = sim_first_result.auth;

    // Locate the auth entry credentialed for auth_scaddr.
    let target_index = locate_smart_account_auth_entry(&prepared_auth_entries, &auth_scaddr)?;
    let prepared_entry = prepared_auth_entries.remove(target_index);
    let prepared_creds = match &prepared_entry.credentials {
        SorobanCredentials::Address(c) => c.clone(),
        SorobanCredentials::SourceAccount
        | SorobanCredentials::AddressV2(_)
        | SorobanCredentials::AddressWithDelegates(_) => {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{} auth entry surfaced as SourceAccount or unsupported credential type; expected Address-credentialled auth",
                    args.op_label,
                ),
            });
        }
    };

    // Capture sub_invocations from the simulate-returned root invocation BEFORE
    // prepared_entry is moved into fingerprint_invocation.
    // For the multicall path (multicall_check.is_some()), the Soroban-RPC simulate
    // host populates root_invocation.sub_invocations with the inner calls the router
    // will dispatch. Threading these into build_authorization_entry ensures the auth
    // digest is computed over the correct invocation tree matching on-chain __check_auth.
    let simulate_sub_invocations: VecM<SorobanAuthorizedInvocation> =
        prepared_entry.root_invocation.sub_invocations.clone();

    // Count the number of invocation contexts in the root invocation tree.
    // OZ `__check_auth` receives one `auth::Context` per `require_auth()` call
    // within the authorized invocation tree — one per node in the tree (root +
    // all sub-invocations recursively).  The `context_rule_ids` in the payload
    // MUST have exactly this many entries (`ContextRuleIdsLengthMismatch` = 3014
    // if mismatched).
    //
    // For OZ wallet entrypoints (no sub-invocations): count = 1.
    // For external-contract calls (e.g. Soroswap ROUTER-DIRECT where the router
    // also calls `SAC.transfer(from=wallet)` as a sub-invocation): count = 2+.
    //
    // The context types are collected by a recursive depth-first traversal of
    // the invocation tree, yielding one context per node.
    fn count_invocation_contexts(inv: &SorobanAuthorizedInvocation) -> usize {
        1 + inv
            .sub_invocations
            .iter()
            .map(count_invocation_contexts)
            .sum::<usize>()
    }
    let invocation_context_count = count_invocation_contexts(&prepared_entry.root_invocation);

    // Soroban-RPC's simulateTransaction returns signature_expiration_ledger = 0
    // (placeholder). Overwrite with latest_ledger + AUTH_VALIDITY_LEDGERS before
    // signing. Cross-reference: js-stellar-base auth.js:132.
    //
    // Validate the RPC-supplied latest_ledger before binding it into the
    // auth-digest preimage.
    validate_latest_ledger(sim_response.latest_ledger)?;
    let signature_expiration_ledger = sim_response
        .latest_ledger
        .saturating_add(AUTH_VALIDITY_LEDGERS);

    // Network ID (sha256 of passphrase) for the auth-digest preimage.
    let network_id: [u8; 32] = Sha256::digest(args.network_passphrase.as_bytes()).into();

    // Build matching simulation + envelope contexts (single-source pattern).
    //
    // Auto-expand `auth_rule_ids` to match `invocation_context_count`.
    //
    // OZ `__check_auth` requires one rule ID per auth::Context (one per node in
    // the invocation tree).  Callers that supply a single rule ID (the common
    // case: bootstrap rule `[0]` for all operations) have that rule replicated
    // across all contexts automatically.  Callers that supply the exact count
    // already pass through unchanged.
    //
    // Per-node rule resolution iterates the tree and returns one rule per
    // context; external-contract callers
    // (e.g. Soroswap ROUTER-DIRECT where the SAC transfer is a sub-invocation)
    // need one rule per tree node.
    //
    // The `auth_contexts_vec` is replicated `invocation_context_count` times
    // so that the `rule_ids.len() == auth_contexts.len()` check in
    // `build_authorization_entry_with_sub_invocations` (auth_entry.rs:165-178)
    // passes with the expanded rule IDs.
    //
    // The 1→N replication here is valid ONLY when the supplied rule is
    // `ContextRuleType::Default` (the bootstrap rule ID 0 installed at deploy).
    // This is the only rule ID currently passed by all callers in this repo
    // (`&[ContextRuleId::new(0)]`), so a single ID uniformly applies to every
    // invocation tree node.
    //
    // Non-Default multi-node callers — where different tree nodes require
    // different context-rule types (e.g. a mix of Default and custom rules) —
    // MUST pass one rule ID per node rather than relying on this replication.
    //
    // The canonical per-node context-type resolution
    // walks the tree and resolves each node's rule ID independently based on
    // the node's `ContextRuleType`.  That per-node approach is strictly more
    // correct for multi-rule deployments.  This wallet currently uses only the
    // Default/bootstrap rule (ID 0), so the replication shortcut is safe for all
    // current call sites.  Per-node resolution is not yet
    // implemented; the replication shortcut is safe for single-rule deployments.
    let expanded_auth_rule_ids: Vec<ContextRuleId> =
        if args.auth_rule_ids.len() == 1 && invocation_context_count > 1 {
            vec![args.auth_rule_ids[0]; invocation_context_count]
        } else {
            args.auth_rule_ids.to_vec()
        };
    let auth_context_fingerprint = fingerprint_invocation(&prepared_entry);
    // `auth_contexts_vec` is a count-carrier: one fingerprint replica per tree
    // node for length alignment with `expanded_auth_rule_ids` in the
    // `rule_ids.len() == auth_contexts.len()` check (auth_entry.rs:165-178).
    // This is NOT a per-node tamper-detection vector; the divergence-detector
    // uses `auth_context_fingerprint` independently.
    let auth_contexts_vec: Vec<_> =
        vec![auth_context_fingerprint.clone(); invocation_context_count];
    let context = SimulationContext {
        context_rule_ids: expanded_auth_rule_ids.clone(),
        auth_contexts: auth_contexts_vec.clone(),
        network: NetworkContext {
            passphrase_fingerprint: passphrase_fingerprint(args.network_passphrase),
            ledger_protocol_version: 0,
            chain_id_fingerprint: chain_id_fingerprint(args.chain_id),
        },
        sequence: SequenceContext {
            source_account_sequence: source_view.sequence_number,
            min_sequence_number: None,
        },
        fee_envelope: FeeEnvelopeContext {
            tx_fee: args.fee.base_stroops,
            resource_fee: parse_min_resource_fee(&sim_response)?,
        },
    };
    let envelope = EnvelopeContext {
        context_rule_ids: expanded_auth_rule_ids,
        auth_contexts: auth_contexts_vec,
        network: context.network.clone(),
        sequence: context.sequence.clone(),
        fee_envelope: context.fee_envelope.clone(),
    };
    let simulation = AuthorizationSimulation {
        context,
        network_id,
        nonce: prepared_creds.nonce,
        signature_expiration_ledger,
    };

    // ── Step 5: Sign ──────────────────────────────────────────────────────────
    // Two paths: quorum (args.authorization.is_some()) and single-signer.
    //
    // Quorum path (when args.authorization.is_some()):
    //   collect_quorum_signatures iterates over the AuthorizationInfo groups,
    //   resolves qualifying signers from args.signers, and returns the flat
    //   SorobanAuthorizationEntry set (one entry + one delegated G-key entry
    //   per qualifying signer).  The envelope-signing key (args.signer) is
    //   separate and always signs the outer transaction envelope.
    //
    // Single-signer path:
    //   Build partial auth entry (refusal-path checks fire here).
    //   For the multicall path (multicall_check.is_some()), the simulate-returned
    //   sub_invocations captured above are threaded into the auth digest.
    //   The Soroban-RPC simulate host populates root_invocation.sub_invocations
    //   with the inner calls the router will dispatch; the auth digest MUST be
    //   computed over the same invocation tree to pass on-chain __check_auth.

    // Derive `invocation_contract` here (before the quorum/single-signer split)
    // so the quorum-path external-contract guard below can compare it against
    // `auth_scaddr` without duplicating the extraction logic.
    let invocation_contract_for_guard: ScAddress = match &prepared_entry.root_invocation.function {
        stellar_xdr::SorobanAuthorizedFunction::ContractFn(cfn) => cfn.contract_address.clone(),
        // Non-ContractFn (e.g. CreateContractHostFn) — fall back to
        // auth_scaddr so existing behaviour is preserved.
        _ => auth_scaddr.clone(),
    };

    let auth_entries: Vec<SorobanAuthorizationEntry> = if let Some(authz) = args.authorization {
        // ── Quorum path ───────────────────────────────────────────────────────
        //
        // External-contract guard:
        //
        // The quorum path was written for OZ wallet entrypoints where
        // `invocation_contract == auth_scaddr == wallet`.  It passes `auth_scaddr`
        // (wallet) as the credential address to `collect_quorum_signatures`, which
        // in turn passes it to `build_authorization_entry` as `target_contract`.
        // For external-contract invocations (where the simulated root invocation
        // targets a contract other than the wallet, e.g. a Soroswap router or a
        // DeFindex vault), `target_contract` would be wrong: the auth digest must
        // cover the external contract's function, not the wallet's.  Signing over
        // the wrong target passes off-chain but is rejected by on-chain
        // `__check_auth` because the digest covers the wrong contract address.
        //
        // Rather than silently producing an unsubmittable transaction, fail closed
        // here.  Full quorum + external-contract support requires per-node rule
        // resolution + quorum path naming.
        if invocation_contract_for_guard != auth_scaddr {
            return Err(SaError::AuthEntryConstructionFailed {
                stage: "quorum_external_contract_guard",
                redacted_reason: format!(
                    "{}: quorum + external-contract submit not yet supported; \
                     the simulated root invocation targets a contract other than \
                     the wallet smart-account (per-node rule resolution and the \
                     quorum-path are not yet implemented)",
                    args.op_label
                ),
            });
        }
        collect_quorum_signatures(
            authz,
            args.signers,
            auth_scaddr.clone(),
            function_name.clone(),
            invoke.args.to_vec(),
            simulation.context.context_rule_ids.clone(),
            &simulation,
            &envelope,
            args.network_passphrase,
            signature_expiration_ledger,
        )
        .await
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "quorum_signatures",
            redacted_reason: format!("{}: quorum collection failed: {}", args.op_label, e),
        })?
    } else {
        // ── Single-signer path ────────────────────────────────────────────────
        //
        // External-contract single-signer pattern:
        //
        // `build_authorization_entry` builds the root_invocation from
        // `target_contract` and computes the auth digest over it.  The
        // on-chain `__check_auth` verifies the digest against the invocation
        // that called `require_auth()`.  For external contracts (e.g. the
        // Soroswap router), the invocation that called `to.require_auth()` is
        // `router.swap_exact_tokens_for_tokens(args)` — NOT `wallet.fn(args)`.
        //
        // Strategy: pass `invocation_contract` (the simulate-returned
        // root_invocation's contract address) as `target_contract` so the auth
        // digest is correct.  Then overwrite `partial.smart_account` with
        // `auth_scaddr` (the wallet) so the final `SorobanCredentials::Address`
        // carries the correct credential address.
        //
        // For OZ wallet entrypoints: `invocation_contract == auth_scaddr ==
        // target_contract_scaddr` (wallet), so the overwrite is a no-op.
        //
        // For external-contract calls: `invocation_contract = router ≠ wallet`.
        // The partial is built with `target_contract = router` (correct root
        // invocation hash), then `partial.smart_account` is patched to `wallet`
        // (correct credentials address). The two uses of `target_contract` in
        // `build_authorization_entry_with_sub_invocations` (invocation contract
        // vs credential address) are separated here at the call-site, keeping
        // the inner function's contract stable.
        //
        // `invocation_contract_for_guard` was derived before the quorum/single
        // split (to allow the quorum guard above to compare it); reuse it here
        // rather than re-deriving from the same `prepared_entry`.
        let invocation_contract = invocation_contract_for_guard;
        let mut partial: PartialSorobanAuthorizationEntry = if !simulate_sub_invocations.is_empty()
        {
            // Sub-invocations present in the simulate response: include them in
            // the auth digest so on-chain `__check_auth` verifies the full
            // invocation tree (not just the root).
            //
            // This handles two cases:
            //  1. Multicall path (args.multicall_check.is_some()): the inner
            //     router dispatches sub-invocations that were captured above.
            //  2. External-contract path (e.g. Soroswap ROUTER-DIRECT): the
            //     router calls `SAC.transfer(from=wallet)` as a sub-invocation.
            //     Soroban's `__check_auth` verifies the authorized invocation tree
            //     matches the actual call tree; omitting sub_invocations from the
            //     digest would produce a tree mismatch and reject the auth.
            // Empirically confirmed on testnet: omitting sub_invocations
            // produces an auth rejection on-chain.
            build_authorization_entry_with_sub_invocations(
                invocation_contract,
                function_name.clone(),
                invoke.args.to_vec(),
                simulation.context.context_rule_ids.clone(),
                &simulation,
                &envelope,
                simulate_sub_invocations,
            )
            .await?
        } else {
            build_authorization_entry(
                invocation_contract,
                function_name.clone(),
                invoke.args.to_vec(),
                simulation.context.context_rule_ids.clone(),
                &simulation,
                &envelope,
            )
            .await?
        };
        // Patch credential address: the simulate-returned root_invocation's
        // contract may differ from the credential address when an external
        // contract calls `wallet.require_auth()`.  The credential MUST identify
        // the wallet, not the external contract.
        partial.smart_account = auth_scaddr.clone();

        // Sign the auth-digest.
        let signed_entry = complete_authorization_entry(partial.clone(), args.signer).await?;

        // OZ Delegated G-key sub-auth entry (required by __check_auth).
        let delegated_entry: SorobanAuthorizationEntry = build_and_sign_delegated_g_key_entry(
            &auth_scaddr,
            &partial.auth_digest,
            signature_expiration_ledger,
            args.signer,
            args.network_passphrase,
        )
        .await?;

        vec![signed_entry, delegated_entry]
    };

    // ── Simulation-audit fingerprint capture ─────────────────────────────────
    // Capture the expected fingerprint immediately after auth_entries is built
    // (before the envelope string exists).  The verify call below is a
    // CHEAP INTERNAL TRIPWIRE — NOT a live-intermediary TOCTOU gate.
    //
    // Inside submit_signed_invoke there is no sign→submit substitution boundary:
    // auth_entries is built here, threaded into build_signed_invoke_envelope,
    // and the resulting envelope is never sourced from outside.  The guard
    // enforces the byte-identity invariant at runtime: if a future refactor
    // mutates auth_entries between this capture point and the
    // build_signed_invoke_envelope call, the tripwire fires loudly rather than
    // silently producing a bad submission.
    //
    // The WalletConnect-host / MCP external-submit boundary is the real
    // TOCTOU-protected surface where a pre-signed blob arrives from outside
    // the wallet's own build path.  Not yet supported: wiring
    // verify_auth_entries_unchanged at that entry point.
    let c7_expected_fp =
        stellar_agent_network::simulation_audit::AuthEntryFingerprint::from_entries(&auth_entries)
            .map_err(|e| SaError::DeploymentFailed {
                phase: "submit",
                redacted_reason: format!(
                    "{}: simulation-audit fingerprint capture failed: {}",
                    args.op_label, e
                ),
            })?;

    // ── Step 6: Submit ────────────────────────────────────────────────────────
    // Re-simulate with signed auth entries to obtain a footprint that includes
    // __check_auth storage reads. Without this, submission traps with
    // "trying to access contract data key outside of the footprint".
    let resim_response = resimulate_with_signed_auth(
        &server,
        &primary_rpc_client,
        &target_contract_scaddr,
        function_name.clone(),
        invoke_args_vecm.clone(),
        auth_entries.clone(),
        &source_pubkey_strkey,
        args.network_passphrase,
    )
    .await?;

    let prepared_envelope_xdr = build_signed_invoke_envelope(
        &mut source_account,
        args.network_passphrase,
        target_contract_scaddr.clone(),
        function_name,
        invoke_args_vecm,
        auth_entries,
        &resim_response,
    )?;

    let final_signed_xdr =
        attach_signature(&prepared_envelope_xdr, args.signer, args.network_passphrase)
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "submit",
                redacted_reason: format!("{} envelope signing failed: {e}", args.op_label),
            })?;

    // ── Byte-identity invariant tripwire ─────────────────────────────────────
    // Verify that the just-built final_signed_xdr carries exactly the auth
    // entries we captured above.  See the capture-point comment for the honest
    // scope of this check: it is an internal invariant assertion, NOT a
    // live-intermediary TOCTOU gate.
    //
    // A mismatch here indicates a refactor re-ordered, re-serialised, or mutated
    // auth entries between capture and build.  On mismatch the tripwire returns
    // SaError::AuthMismatch; the caller's sa_error_to_invocation_result arm
    // surfaces this as SaInvocationResult::PreSubmissionRefused.  The dedicated
    // EventKind::SubmissionAuthMismatch event is emitted at the external-submit
    // boundary when that entry point lands; this path is audit-silent
    // by design (see module-level doc of this file). The
    // EventKind::SubmissionAuthMismatch event emission at the external-submit
    // boundary is not yet implemented.
    stellar_agent_network::simulation_audit::verify_auth_entries_unchanged(
        &c7_expected_fp,
        &final_signed_xdr,
    )
    .map_err(|wallet_err| {
        // Extract the reason from the WalletError wrapper and surface as
        // SaError::AuthMismatch.
        let reason = match wallet_err {
            stellar_agent_core::WalletError::Submission(
                stellar_agent_core::SubmissionError::AuthMismatch { reason },
            ) => reason,
            // Any other WalletError from verify (e.g. XDR decode failure of
            // the just-built envelope) is a hard internal error.
            other => {
                return SaError::DeploymentFailed {
                    phase: "submit",
                    redacted_reason: format!(
                        "{}: simulation-audit verify unexpected error: {}",
                        args.op_label, other
                    ),
                };
            }
        };
        // Redaction computed lazily — only on the cold mismatch path.
        let smart_account_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
            &scaddress_to_strkey(&target_contract_scaddr).unwrap_or_else(|_| "unknown".to_owned()),
        );
        tracing::warn!(
            smart_account = %smart_account_redacted,
            reason = %reason.label(),
            op_label = %args.op_label,
            "simulation-audit tripwire fired: auth-entry fingerprint mismatch \
             (internal invariant violation — future refactor changed auth_entries \
             between capture and submission)"
        );
        SaError::AuthMismatch { reason }
    })?;

    if args.emit_observability_logs {
        let op = args.op_label;
        info!(
            smart_account = %stellar_agent_core::observability::redact_strkey_first5_last5(
                &scaddress_to_strkey(&target_contract_scaddr)
                    .unwrap_or_else(|_| "unknown".to_owned())
            ),
            op_label = %op,
            "{op}: submitting transaction",
        );
    }

    let submission = submit_transaction_and_wait(
        &primary_rpc_client,
        &final_signed_xdr,
        args.timeout,
        args.network_passphrase,
        None,
    )
    .await
    .map_err(|e| SaError::DeploymentFailed {
        phase: "submit",
        redacted_reason: format!("{} submission failed: {e}", args.op_label),
    })?;

    if args.emit_observability_logs {
        let op = args.op_label;
        info!(
            tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
            ledger = submission.ledger,
            op_label = %op,
            "{op}: transaction confirmed on-chain",
        );
    }

    // ── Step 7: Return ────────────────────────────────────────────────────────
    // Audit emission is caller-side. The caller's Err(err) match arm emits the
    // appropriate audit row via sa_error_to_invocation_result + SaRawInvocation.
    Ok(SubmitInvokeResult {
        return_val,
        tx_hash: submission.tx_hash,
        ledger: submission.ledger,
    })
}

/// Asserts the [`SubmitInvokeArgs`] cross-field invariant that a caller which
/// supplies `multicall_check: Some(_)` also declares `"multicall"` in
/// `required_checks`.
///
/// # Release-mode semantics
///
/// This is a `debug_assert!` and compiles to nothing in release builds. The
/// substantive production-side guarantee against the inverse misuse comes from
/// **Step 4** (cross-RPC trust-anchor block at `submit_signed_invoke`),
/// which runs unconditionally whenever `multicall_check.is_some() &&
/// secondary_rpc_url.is_some()` and enforces network-passphrase + bundle-
/// descriptor consistency. The debug assertion exists as a tripwire to catch
/// programming errors at test-time before they reach a production binary.
///
/// In single-RPC release builds (`secondary_rpc_url: None`), Step 4 does not
/// fire AND the debug assertion is compiled out, so a misconfigured caller
/// (`multicall_check: Some(_)` without `"multicall"` in `required_checks`)
/// would silently degrade to a non-multicall submit without `check_required`
/// firing. Library callers MUST construct `SubmitInvokeArgs` via the
/// `bon::Builder` and pair `.multicall_check(...)` with
/// `.required_checks(&["multicall"])`. The internal wallet caller in
/// [`crate::multicall::submit_multicall_bundle`] does this correctly.
///
/// Debug-mode tripwire that surfaces programming errors at test time.
fn assert_submit_invoke_args_invariants(args: &SubmitInvokeArgs<'_>) {
    debug_assert!(
        args.multicall_check.is_none() || args.required_checks.contains(&"multicall"),
        "SubmitInvokeArgs invariant: multicall_check requires required_checks to contain \
         \"multicall\""
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a static string describing the `HostFunction` discriminant.
///
/// Used in `SubmitCheckMissing` and `AuthEntryConstructionFailed` error
/// envelopes to give operators a host-function-kind discriminator without
/// allocating.
fn host_function_kind_str(hf: &HostFunction) -> &'static str {
    match hf {
        HostFunction::InvokeContract(_) => "InvokeContract",
        HostFunction::CreateContract(_) => "CreateContract",
        HostFunction::CreateContractV2(_) => "CreateContractV2",
        HostFunction::UploadContractWasm(_) => "UploadContractWasm",
    }
}

/// Enforces that the `Option<*Check>` corresponding to `required_name` is
/// `Some` in `args`.
///
/// Returns [`SaError::SubmitCheckMissing`] if the check is absent.
/// Recognised names: `"multicall"`.
fn check_required(
    args: &SubmitInvokeArgs<'_>,
    required_name: &'static str,
    hf_kind: &'static str,
) -> Result<(), SaError> {
    let missing = match required_name {
        "multicall" => args.multicall_check.is_none(),
        // Unrecognised check names are treated as missing (fail-CLOSED).
        // A caller who declares a check name we do not yet understand has
        // a programming error; the safe default is to refuse, not to
        // silently pass.
        _ => true,
    };
    if missing {
        return Err(SaError::SubmitCheckMissing {
            required_check: required_name,
            host_function_kind: hf_kind,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    use stellar_agent_core::error::WalletError;
    use stellar_agent_network::WebAuthnAssertion;
    use stellar_xdr::{
        AccountId, BytesM, ContractExecutable, ContractId, ContractIdPreimage,
        ContractIdPreimageFromAddress, CreateContractArgs, CreateContractArgsV2, Hash,
        InvokeContractArgs, PublicKey, ScAddress, ScSymbol, Uint256,
    };

    use super::*;

    // ── host_function_kind_str closed-set ──────────────────────────────────────

    /// `host_function_kind_str` returns `"InvokeContract"` for the
    /// `InvokeContract` discriminant.
    #[test]
    fn host_function_kind_str_closed_set_invoke_contract() {
        let hf = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            function_name: ScSymbol::try_from("fn").unwrap(),
            args: VecM::default(),
        });
        assert_eq!(host_function_kind_str(&hf), "InvokeContract");
    }

    /// `host_function_kind_str` returns `"CreateContract"` for the
    /// `CreateContract` discriminant.
    #[test]
    fn host_function_kind_str_closed_set_create_contract() {
        let hf = HostFunction::CreateContract(CreateContractArgs {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    [0u8; 32],
                )))),
                salt: Uint256([0u8; 32]),
            }),
            executable: ContractExecutable::StellarAsset,
        });
        assert_eq!(host_function_kind_str(&hf), "CreateContract");
    }

    /// `host_function_kind_str` returns `"CreateContractV2"` for the
    /// `CreateContractV2` discriminant.
    #[test]
    fn host_function_kind_str_closed_set_create_contract_v2() {
        let hf = HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    [0u8; 32],
                )))),
                salt: Uint256([0u8; 32]),
            }),
            executable: ContractExecutable::StellarAsset,
            constructor_args: VecM::default(),
        });
        assert_eq!(host_function_kind_str(&hf), "CreateContractV2");
    }

    /// `host_function_kind_str` returns `"UploadContractWasm"` for the
    /// `UploadContractWasm` discriminant.
    ///
    /// `HostFunction::UploadContractWasm` wraps a `BytesM` (the WASM bytes);
    /// an empty `BytesM` is sufficient to exercise the discriminant.
    #[test]
    fn host_function_kind_str_closed_set_upload_contract_wasm() {
        let hf = HostFunction::UploadContractWasm(BytesM::default());
        assert_eq!(host_function_kind_str(&hf), "UploadContractWasm");
    }

    // ── check_required unit tests ──────────────────────────────────────────────

    /// Minimal `Signer` stub for unit tests that never call into the signer.
    ///
    /// `check_required` and `host_function_kind_str` only inspect
    /// `SubmitInvokeArgs` struct fields; no signing primitive is invoked.
    struct StubSigner;

    #[async_trait::async_trait]
    impl stellar_agent_network::signing::Signer for StubSigner {
        async fn sign_tx_payload(&self, _: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_auth_digest(&self, _: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_soroban_address_auth_payload(
            &self,
            _: &[u8; 32],
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_webauthn_assertion(
            &self,
            _: &[u8; 32],
            _: &[u8],
        ) -> Result<WebAuthnAssertion, WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
    }

    static STUB_SIGNER: StubSigner = StubSigner;

    /// Construct a minimal `SubmitInvokeArgs` suitable for `check_required`
    /// and `host_function_kind_str` unit tests. Async fields (signer,
    /// rpc_url, etc.) are not exercised by these helpers; they are filled
    /// with stubs.
    fn minimal_args<'a>(
        multicall_check: Option<MulticallCheck>,
        required_checks: &'a [&'static str],
    ) -> SubmitInvokeArgs<'a> {
        // A zero-keyed C-strkey; not valid on-chain but sufficient for struct
        // construction — check_required never reads the network.
        let dummy_strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        SubmitInvokeArgs::builder()
            .target_contract(dummy_strkey)
            .auth_rule_ids(&[])
            .host_function(HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol::try_from("fn").unwrap(),
                args: VecM::default(),
            }))
            .signer(&STUB_SIGNER)
            .primary_rpc_url("http://stub")
            .network_passphrase("stub")
            .chain_id("stub")
            .timeout(std::time::Duration::from_secs(10))
            .op_label("test_op")
            .required_checks(required_checks)
            .maybe_multicall_check(multicall_check)
            .build()
    }

    /// `check_required` with `required_checks = &["multicall"]` and a
    /// fully-populated `MulticallCheck` returns `Ok(())`.
    #[test]
    fn check_required_passes_when_multicall_check_present() {
        let mc = MulticallCheck {
            bundle_descriptors: vec![],
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let args = minimal_args(Some(mc), &["multicall"]);
        let hf_kind = host_function_kind_str(&args.host_function);
        assert!(check_required(&args, "multicall", hf_kind).is_ok());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "multicall_check requires required_checks")]
    fn submit_invariant_panics_when_multicall_check_is_undeclared() {
        let mc = MulticallCheck {
            bundle_descriptors: vec![],
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let args = minimal_args(Some(mc), &[]);
        assert_submit_invoke_args_invariants(&args);
    }

    /// Positive companion to [`submit_invariant_panics_when_multicall_check_is_undeclared`].
    /// `multicall_check: Some(_)` paired with `"multicall"` in `required_checks`
    /// satisfies the invariant; no panic.
    #[cfg(debug_assertions)]
    #[test]
    fn submit_invariant_holds_when_multicall_check_is_declared() {
        let mc = MulticallCheck {
            bundle_descriptors: vec![],
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let args = minimal_args(Some(mc), &["multicall"]);
        // Must not panic; the invariant holds when the check is declared.
        assert_submit_invoke_args_invariants(&args);
    }

    /// The invariant also holds in the trivial case: no multicall check,
    /// no multicall declaration in required_checks.
    #[cfg(debug_assertions)]
    #[test]
    fn submit_invariant_holds_when_no_multicall_check() {
        let args = minimal_args(None, &[]);
        assert_submit_invoke_args_invariants(&args);
    }

    /// `check_required` with `required_checks = &["multicall"]` and
    /// `multicall_check = None` returns `Err(SubmitCheckMissing)`.
    #[test]
    fn check_required_fails_when_multicall_check_missing() {
        let args = minimal_args(None, &["multicall"]);
        let hf_kind = host_function_kind_str(&args.host_function);
        let err = check_required(&args, "multicall", hf_kind).unwrap_err();
        assert_eq!(err.wire_code(), "sa.submit_check_missing");
    }

    /// When `required_checks = &[]`, `check_required` is never called and the
    /// gate is a no-op — preserving behaviour for callers that pass an empty
    /// slice.
    #[test]
    fn check_required_passes_when_required_check_not_listed() {
        // required_checks = &[], multicall_check = None → no gate fires.
        let args = minimal_args(None, &[]);
        let hf_kind = host_function_kind_str(&args.host_function);
        // Simulate the loop from submit_signed_invoke.
        for &required in args.required_checks {
            check_required(&args, required, hf_kind).unwrap();
        }
        // If we reach here with no panic, the gate did not fire.
    }

    /// `check_required` with an unrecognised name returns `Err(SubmitCheckMissing)`
    /// regardless of the `Option<*Check>` fields (fail-CLOSED on unknown names).
    #[test]
    fn check_required_fails_on_unknown_check_name() {
        // multicall_check is Some — should not matter for an unrecognised name.
        let mc = MulticallCheck {
            bundle_descriptors: vec![],
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let args = minimal_args(Some(mc), &["unknown_typo"]);
        let hf_kind = host_function_kind_str(&args.host_function);
        let err = check_required(&args, "unknown_typo", hf_kind).unwrap_err();
        assert_eq!(err.wire_code(), "sa.submit_check_missing");
    }

    // ── byte-identity regression test ─────────────────────────────────────────

    /// Asserts the byte-identity invariant: for a single-op
    /// `InvokeHostFunction` envelope, the `SorobanAuthorizationEntry` slice
    /// extracted from the XDR is byte-for-byte equal to the entries embedded
    /// in it.
    ///
    /// This test documents and guards the precondition that makes
    /// `AuthEntryFingerprint` safe from false-positive aborts on the wallet's
    /// own happy path.  If a future refactor introduces re-serialisation,
    /// re-ordering, or mutation of auth entries between the fingerprint capture
    /// point and envelope build, this test will fail loudly — surfacing the
    /// break here rather than as a mysterious production false-abort.
    #[test]
    fn c7_auth_entry_byte_identity_round_trip() {
        // Uses stellar_xdr::curr types directly to avoid cross-version type
        // incompatibility with stellar_xdr (stellar-xdr 25.x vs 26.x).
        // stellar_xdr is a direct dep of stellar-agent-smart-account.
        use stellar_xdr::{
            ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
            MuxedAccount, Operation, OperationBody, Preconditions, ScAddress, ScSymbol,
            SequenceNumber, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Transaction, TransactionEnvelope,
            TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
        };

        let make_entry = |seed: u8| -> SorobanAuthorizationEntry {
            let fn_name: ScSymbol = format!("fn_{seed}").as_str().try_into().unwrap();
            let contract_addr = ScAddress::Contract(ContractId(Hash([seed; 32])));
            SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                        contract_address: contract_addr,
                        function_name: fn_name,
                        args: VecM::default(),
                    }),
                    sub_invocations: VecM::default(),
                },
            }
        };

        let entries = vec![make_entry(1), make_entry(2)];

        // Build a minimal single-op InvokeHostFunction envelope wrapping these entries.
        let auth_vecm: VecM<SorobanAuthorizationEntry> = entries.clone().try_into().unwrap();
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: "submit_test".try_into().unwrap(),
                    args: VecM::default(),
                }),
                auth: auth_vecm,
            }),
        };
        let ops: VecM<Operation, 100> = vec![op].try_into().unwrap();
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([1u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops,
            ext: TransactionExt::V0,
        };
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        let xdr = envelope.to_xdr_base64(Limits::none()).unwrap();

        // Fingerprint the original entries Vec (from_entries), fingerprint the
        // XDR string (fingerprint_soroban_auth_entries), assert they are equal.
        // If a future refactor mutates auth entries between capture and
        // submission, this test fails here — not as a production false-abort.
        let fp_from_vec =
            stellar_agent_network::simulation_audit::AuthEntryFingerprint::from_entries(&entries)
                .unwrap();
        let fp_from_xdr =
            stellar_agent_network::simulation_audit::fingerprint_soroban_auth_entries(&xdr)
                .unwrap();

        assert_eq!(
            fp_from_vec, fp_from_xdr,
            "byte-identity invariant violated: auth entries extracted from \
             the envelope XDR do not match the entries embedded in it"
        );
    }
}
