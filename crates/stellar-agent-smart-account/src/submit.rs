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
//! 1. Pre-flight: argument guards, the witness configuration check, then, for
//!    every distinct non-zero rule in
//!    `auth_rule_ids` in ascending order, the rule locks, the signer-set
//!    baseline read, the pinned-hash drift check and the signer-set
//!    comparison (see [`PinCheck`]), then the source-account fetch. Each
//!    check refuses before anything is simulated or signed. Rule 0, the
//!    bootstrap rule, is exempt from the rule lock, the signer-set check and
//!    the pin check; it has no pins, and the submit path never reads a
//!    baseline for it. A submission under rule 0 only may omit the check.
//! 2. Simulate: primary RPC; check the shape of the simulated return value
//!    when the caller set one.
//! 3. Ledger witness, mandatory on every submission: the primary and the
//!    secondary observe the latest ledger, and the pair must agree within
//!    [`MAX_SIGNING_LEDGER_SKEW`](crate::signing::ledger_witness::MAX_SIGNING_LEDGER_SKEW).
//!    Required-check enforcement + `Option<*Check>` dispatch against that pair.
//! 4. Cross-RPC simulate check (`multicall_check` is `Some`).
//! 5. Sign: the simulated root invocation must be the caller's host function
//!    and its sub-invocations must match the caller's
//!    [`DeclaredSubInvocations`]; the wallet then signs its own root with the
//!    accepted subtree via the `build_authorization_entry` substrate.
//! 6. Submit: send signed envelope.
//! 7. Return `Result<SubmitInvokeResult, SaError>` to caller.

use std::collections::HashMap;

use sha2::{Digest as _, Sha256};
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    SentByError, StellarRpcClient, refuse_mainnet_write, submit_transaction_and_wait_sent_by,
};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Operation, OperationBody, ScAddress,
    ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, VecM,
};
use tracing::info;

use crate::SaError;
use crate::error::{SimulationDivergenceSubCode, pin_check_reason};
use crate::managers::auth_entry::{
    AuthorizationSimulation, PartialSorobanAuthorizationEntry, PreSubmitBudget,
    bound_pre_submit_stage, build_authorization_entry_with_sub_invocations,
    collect_mixed_signer_entries_within_budget, complete_authorization_entry_within_budget,
};
use crate::managers::authorization::{
    QuorumFailure, plan_quorum_signatures_within_budget, sign_quorum_plan_within_budget,
};
use crate::managers::rules::{
    BASE_FEE_STROOPS, ExpiryCheck, HorizonCheck, SimulationErrorClass,
    build_and_sign_delegated_g_key_entry, build_signed_invoke_envelope, chain_id_fingerprint,
    check_rule_not_expired_standalone, fingerprint_invocation, fingerprint_invocation_nodes,
    locate_smart_account_auth_entry, parse_c_strkey_to_smart_account, parse_min_resource_fee,
    passphrase_fingerprint, resimulate_with_signed_auth, scaddress_to_strkey,
    validate_latest_ledger,
};
use crate::managers::signers::{
    BorrowedRuleLocks, RuleLockGuard, SignersManager, V1Handling, find_rule_guard,
    rule_lock_missing,
};
use crate::managers::verifiers::{
    verify_pinned_policy_against_chain, verify_pinned_verifier_against_chain,
    verify_policy_pins_present,
};
use crate::signing::divergence::{
    AuthContextFingerprint, EnvelopeContext, FeeEnvelopeContext, NetworkContext, SequenceContext,
    SimulationContext,
};
use crate::signing::gate::{SignerMatch, SigningGate, SigningRequest};
use crate::signing::ledger_witness::{
    ResolvedKeySigner, WitnessRequest, WitnessedLedgerBound, checked_secondary_rpc_url,
    witness_signing_ledger,
};
use stellar_agent_network::{
    AuthSubject, IntentSubject, SignedIntentPlan, SignerDescriptor, SigningAdmission,
    SigningPayload,
};
use stellar_xdr::{ReadXdr as _, WriteXdr as _};

// ─────────────────────────────────────────────────────────────────────────────
// MulticallCheck
// ─────────────────────────────────────────────────────────────────────────────

/// Multicall bundle check parameters for the cross-RPC trust-anchor at Step 4.
///
/// Constructed inside `multicall::submit_multicall_bundle` (same crate) and
/// passed through `SubmitInvokeArgs::multicall_check` to
/// [`submit_signed_invoke`] Step 4.
///
/// The fields supply the cross-RPC trust-anchor checks:
/// - `registry_entry_address` + `registry_entry_wasm_sha256` → wasm-hash 4-way equality.
/// - `network_passphrase` → defence-in-depth network mismatch check (ensures
///   the check was built for the same network as the submission).
///
/// # Field ownership
///
/// The contract address, registered WASM hash and network passphrase are
/// owned strings so the submit path can retain the check across RPC calls.
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
// Ed25519RuleSigner
// ─────────────────────────────────────────────────────────────────────────────

/// External-Ed25519 rule signer for the single-signer submit path.
///
/// Selects the OZ `Signer::External(Address, Bytes)` authentication branch
/// (`packages/accounts/src/smart_account/storage.rs:96-102`, SHA `a9c4216`)
/// instead of the default `Signer::Delegated(Address)` branch used by the
/// single-signer path when [`SubmitInvokeArgs::ed25519_rule_signer`] is
/// `None`. An External-Ed25519 signer authenticates entirely inside the
/// `VerifierClient::verify` WASM-to-WASM call (`storage.rs:341-350`, SHA
/// `a9c4216`) and therefore needs no G-key sub-entry: [`submit_signed_invoke`]
/// routes to the crate-internal `collect_mixed_signer_entries` mixed-signer
/// collector with a single `MixedSignerKind::ExternalEd25519` descriptor
/// instead of calling `complete_authorization_entry` +
/// `build_and_sign_delegated_g_key_entry`.
///
/// # Recommended agent-signer doctrine
///
/// This is the preferred signer shape for an autonomous agent's own signing
/// key: it needs no funded classic (`G...`) account (unlike `Delegated`,
/// which requires a G-key `SorobanAuthorizationEntry` satisfied by a live
/// classic account), can be held in an HSM or keyring, and rotates cheaply
/// (updating the OZ `External` signer entry is a policy-mutator call, not an
/// account-funding operation).
///
/// # Mutual exclusivity
///
/// Mutually exclusive with [`SubmitInvokeArgs::authorization`] (the quorum
/// path): supplying both returns [`SaError::AuthEntryConstructionFailed`]
/// before any network I/O (checked at the top of [`submit_signed_invoke`],
/// ahead of the required-check enforcement).
pub struct Ed25519RuleSigner<'a> {
    /// The raw ed25519 signing capability that authenticates via the
    /// `verifier` contract.
    ///
    /// Distinct from [`SubmitInvokeArgs::signer`], which remains the
    /// source-account / envelope-signing key in both the Delegated and
    /// External-Ed25519 paths.
    pub signer: &'a (dyn Signer + Send + Sync),

    /// The Ed25519 verifier contract address named by the OZ
    /// `Signer::External(Address, Bytes)` entry.
    pub verifier: ScAddress,
}

// ─────────────────────────────────────────────────────────────────────────────
// PinCheck
// ─────────────────────────────────────────────────────────────────────────────

/// Inputs of the pre-signing checks [`submit_signed_invoke`] runs for every
/// distinct non-zero rule in [`SubmitInvokeArgs::auth_rule_ids`].
///
/// For each such rule, in ascending order and under one pre-submit
/// deadline, the submit path:
///
/// 1. holds the rule's lock: it acquires it through `signers_manager`, or
///    finds it in the caller's held-lock context;
/// 2. reads the rule's newest signer-set state row from the audit log of
///    `signers_manager`, with no RPC;
/// 3. runs the pinned-hash drift check: it fetches the rule's verifier and
///    policy addresses from chain through [`SignersManager`], then compares
///    each live executable against the rule's pin record, the newest
///    `SaContextRuleCreated` or `SaContextRulePinsUpdated` row. One per-call
///    cache of observed executables is shared across the rules, so a
///    contract referenced by several rules is fetched once;
/// 4. compares the rule's signer set, observed through both endpoints of
///    `signers_manager`, with the state row.
///
/// Each step runs for every rule before the next step starts. The smart
/// account and its redaction are derived inside [`submit_signed_invoke`]
/// from `auth_address` (or `target_contract`), never from the caller.
///
/// Outcomes, all before any simulation or signature, in the order the steps
/// reach them:
///
/// - a lock not acquired within the deadline refuses with
///   [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock`, and a
///   held-lock context without a guard for a named rule at stage
///   `rule_lock_missing`;
/// - a rule without a state row refuses with
///   [`SaError::SignerSetMissingBaseline`], and an audit-log integrity
///   error with [`SaError::AuditLog`];
/// - drift refuses with [`SaError::VerifierHashDrift`] or
///   [`SaError::PolicyHashDrift`], and the check writes a
///   `SaVerifierHashDrift` / `SaPolicyHashDrift` row carrying `request_id`;
/// - a rule with no policy on chain whose pin record holds policy pins
///   refuses with [`SaError::PinnedPolicyAbsent`]. A rule with a live
///   `External` signer whose pin record pins no verifier refuses with
///   [`SaError::PinnedVerifierAbsent`]. A rule whose pin record holds
///   eight-byte hash prefixes refuses with [`SaError::WasmPinIncomplete`].
///   None of them writes a drift row;
/// - any other failure of the address fetch or of a check (RPC failure or
///   divergence, audit-log integrity error, a record with more than one
///   verifier or policy pin, an unpinnable instance, the pre-submit budget
///   elapsing) refuses with [`SaError::PinCheckUnavailable`] carrying the
///   inner error's wire code;
/// - a rule without a pin record passes the check; a rule with no
///   `External` signer passes its verifier half, and a rule with no policy
///   and no policy pin passes its policy half;
/// - a signer set that differs from the state row refuses with
///   [`SaError::SignerSetDiverged`] and writes a `SaSignerSetDiverged` row
///   carrying `request_id`; endpoints that disagree refuse with
///   [`SaError::NetworkRpcDivergence`]; a version-1 row the observation
///   cannot be projected onto refuses with the projection's error.
///
/// The signer-set refusals propagate as themselves and are never folded
/// into [`SaError::PinCheckUnavailable`]. An elapse of the deadline during
/// the baseline read or the comparison refuses with
/// [`SaError::AuthEntryConstructionFailed`] at stage `baseline_read` or
/// `signer_set_compare`.
///
/// The execute path does not run the verifier diversification gate: a rule
/// with two pinned verifiers already refuses here through
/// `sa.multiple_pinned_hashes_unsupported`, and the gate's value-threshold
/// semantics, with its `accept_single_verifier` opt-in, belong to
/// `sign_with_passkey_rule`.
#[derive(Clone, Copy)]
pub struct PinCheck<'a> {
    /// Manager whose RPC clients fetch the rule and the live executables and
    /// whose audit writer holds the pin records and receives drift rows.
    pub signers_manager: &'a SignersManager,
    /// Correlation id carried by drift rows and refusals.
    pub request_id: &'a str,
    /// The rule a verifier migration is rewriting; see [`MigratingRule`].
    ///
    /// `Some` is accepted only when `auth_rule_ids` is exactly the migrating
    /// rule. Any other combination is refused with
    /// [`SaError::AuthEntryConstructionFailed`] at stage
    /// `"migrating_rule_mismatch"`, so only a submission signed under the
    /// migrating rule alone skips its verifier check. Every other caller
    /// passes `None`.
    pub migrating_rule: Option<MigratingRule>,
}

/// Proof that the manager ran the pinned-hash drift check, with its verifier
/// status gate, for these rules.
///
/// Obtain it through [`SignersManager::check_signing_rules`]. Signing consumes
/// the proof and checks its account, network and rule set against the entry.
/// Rule 0 and a rule without a pin record pass unchecked: neither has a pin
/// to compare the live verifier with, so neither is status-checked.
///
/// The proof has no public constructor:
///
/// ```compile_fail
/// use stellar_agent_smart_account::submit::CheckedSigningRules;
/// let proof = CheckedSigningRules::new();
/// ```
///
/// Code outside this crate cannot construct or clone it.
/// The quorum signer copies it once per planned group, so each group
/// consumes its own copy of the same checked rules.
///
/// ```compile_fail
/// use stellar_agent_smart_account::submit::CheckedSigningRules;
/// fn f(p: &CheckedSigningRules) -> CheckedSigningRules { p.clone() }
/// ```
#[derive(Debug)]
pub struct CheckedSigningRules {
    smart_account: ScAddress,
    network_id: [u8; 32],
    rule_ids: Vec<u32>,
}

impl CheckedSigningRules {
    pub(crate) fn for_planned_signing(&self) -> Self {
        Self {
            smart_account: self.smart_account.clone(),
            network_id: self.network_id,
            rule_ids: self.rule_ids.clone(),
        }
    }

    pub(crate) fn check_binding(
        &self,
        smart_account: &ScAddress,
        network_id: [u8; 32],
        rule_ids: &[ContextRuleId],
    ) -> Result<(), SaError> {
        if self.smart_account != *smart_account
            || self.network_id != network_id
            || self.rule_ids != distinct_rule_ids(rule_ids)
        {
            return Err(SaError::AuthEntryBindingMismatch {
                field: "checked_signing_rules",
            });
        }
        Ok(())
    }

    // A quorum uses the same checked rule set for each group's shared entry.
    pub(crate) fn into_groups(self, count: usize) -> Vec<Self> {
        (0..count)
            .map(|_| Self {
                smart_account: self.smart_account.clone(),
                network_id: self.network_id,
                rule_ids: self.rule_ids.clone(),
            })
            .collect()
    }
}

/// The distinct rule ids of `rules`, in ascending order: the form the
/// pinned-hash drift check runs over and a [`CheckedSigningRules`] binds.
fn distinct_rule_ids(rules: &[ContextRuleId]) -> Vec<u32> {
    let mut ids: Vec<u32> = rules.iter().map(ContextRuleId::as_u32).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
pub(crate) fn checked_rules_for_test(
    partial: &PartialSorobanAuthorizationEntry,
) -> CheckedSigningRules {
    checked_context_for_test(
        &partial.smart_account,
        partial.network_id,
        &partial.context_rule_ids,
    )
}

#[cfg(test)]
pub(crate) fn checked_context_for_test(
    smart_account: &ScAddress,
    network_id: [u8; 32],
    rules: &[ContextRuleId],
) -> CheckedSigningRules {
    CheckedSigningRules {
        smart_account: smart_account.clone(),
        network_id,
        rule_ids: distinct_rule_ids(rules),
    }
}

/// Checks the manager's rules and produces their consumed signing proof.
pub(crate) async fn check_signing_rules(
    manager: &SignersManager,
    smart_account: &ScAddress,
    rules: &[ContextRuleId],
    request_id: &str,
    budget: PreSubmitBudget,
) -> Result<CheckedSigningRules, SaError> {
    run_pin_check(
        &PinCheck {
            signers_manager: manager,
            request_id,
            migrating_rule: None,
        },
        &distinct_rule_ids(rules),
        smart_account,
        budget,
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// MigratingRule
// ─────────────────────────────────────────────────────────────────────────────

/// The rule a verifier migration rewrites, whose verifier check a
/// submission signed under it alone skips.
///
/// The verifier check of the pinned-hash drift check is skipped; the policy
/// check still runs. The migration's own preflight identifies, allowlists
/// and probes the destination verifier, and its remove step signs while the
/// source verifier, which may be the drifted contract the migration moves
/// away from, is still live. The rule is compared by the entry that holds
/// its lock: the migration compares it with its newest state row before
/// each of its two steps and records the state each step leaves.
///
/// Only the migration step constructs one. A caller outside this crate
/// cannot, except through the test constructor the `test-helpers` feature
/// compiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigratingRule(u32);

impl MigratingRule {
    /// The migrating rule `rule_id`.
    pub(crate) fn new(rule_id: u32) -> Self {
        Self(rule_id)
    }

    /// The migrating rule `rule_id`, for tests that sign under a migrating
    /// rule or exercise the exemption's argument guard.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn for_tests(rule_id: u32) -> Self {
        Self(rule_id)
    }

    /// The migrating rule's id.
    #[must_use]
    pub fn rule_id(&self) -> u32 {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpectedReturn
// ─────────────────────────────────────────────────────────────────────────────

/// The shape a submission's simulated return value must have before the
/// transaction is signed.
///
/// A caller that reads an id from the confirmed transaction's return value
/// sets the shape it reads, so a simulation that returns another shape is
/// refused before anything is signed or sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpectedReturn {
    /// `ScVal::U32`: the id `add_signer` and `add_policy` assign.
    U32,
    /// A map whose `id` entry is `ScVal::U32`: the `ContextRule`
    /// `add_context_rule` returns.
    ContextRuleId,
}

impl ExpectedReturn {
    /// Checks `value`, the first simulated result of the `op_label`
    /// submission, against this shape.
    ///
    /// # Errors
    ///
    /// [`SaError::DeploymentFailed`] at phase `simulate`, naming the
    /// expected shape and the variant `value` holds.
    fn check(self, value: &ScVal, op_label: &str) -> Result<(), SaError> {
        let matches = match self {
            Self::U32 => matches!(value, ScVal::U32(_)),
            Self::ContextRuleId => {
                crate::managers::rules::parse_context_rule_id_from_return(value).is_ok()
            }
        };
        if matches {
            return Ok(());
        }
        let variant = stellar_agent_core::scval::scval_variant_name(value);
        let redacted_reason = match self {
            Self::U32 => format!("{op_label}: expected ScVal::U32 return, got {variant}"),
            Self::ContextRuleId => {
                format!("{op_label}: expected a map with a u32 id, got {variant}")
            }
        };
        Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeclaredSubInvocations
// ─────────────────────────────────────────────────────────────────────────────

/// The sub-invocations a submission authorizes under the wallet's root
/// invocation.
///
/// [`submit_signed_invoke`] signs the caller's own host function as the root
/// of the authorized tree and refuses a simulated root that differs from it.
/// The sub-invocations under that root come from the simulation, so the
/// caller declares the ones it means: a simulated subtree outside the
/// declaration is refused before anything is signed, with
/// [`SaError::SimulationDivergence`] and wire code
/// `simulation.divergence.auth_contexts`. Every accepted sub-invocation is a
/// leaf; a nested node under any of them is refused.
///
/// A wallet entrypoint authorizes its own frame, and the contracts it calls
/// are authorized through invoker-contract auth without adding a node to the
/// wallet's tree, so wallet self-calls keep the default [`Self::None`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeclaredSubInvocations<'a> {
    /// The simulated root carries no sub-invocations.
    #[default]
    None,
    /// Each sub-invocation is a leaf `transfer(from, to, amount)` on a declared
    /// token, `from` is the authorizing address, and the amounts per token sum
    /// to at most the declared bound.
    ///
    /// A transfer counts against the first declared entry whose token matches
    /// and whose recipient, when set, matches. A negative amount is refused.
    TokenTransfers(&'a [DeclaredTransfer]),
    /// The sub-invocations are leaves equal to declared calls, in declared
    /// order, each used at most once.
    ///
    /// A declared call that requires no authorization from the wallet adds no
    /// node to its tree, so the simulated sub-invocations may skip declared
    /// calls but never reorder or repeat them.
    Calls(&'a [InvokeContractArgs]),
}

/// One token transfer a submission authorizes under
/// [`DeclaredSubInvocations::TokenTransfers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredTransfer {
    /// The token contract whose `transfer` is authorized.
    pub token: ScAddress,
    /// The recipient, or `None` when the invoked contract chooses it.
    pub to: Option<ScAddress>,
    /// The upper bound of the amounts this entry's transfers move together.
    pub max_amount: i128,
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
/// Wraps the predicted return `ScVal` from the accepted unsigned simulation
/// and the confirmed-ledger / transaction-hash metadata from
/// [`stellar_agent_network::submit::SubmissionResult`].
///
/// Exposes the confirmed transaction hash, ledger, and predicted return value
/// to callers. The accepted simulation supplies the prediction, including after
/// recovery. Soroban-RPC does not deliver a fresh post-confirmation `ScVal`.
#[derive(Debug)]
pub struct SubmitInvokeResult {
    /// The predicted return value from the accepted unsigned simulation,
    /// including its replacement after height recovery.
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
/// - Callers signing with an External-Ed25519 rule signer (see the
///   recommended-agent-signer doctrine on [`Ed25519RuleSigner`]) pass:
///   - `ed25519_rule_signer: Some(Ed25519RuleSigner { signer, verifier })`
///   - `authorization: None` (mutually exclusive; see [`Ed25519RuleSigner`])
/// - `pin_check` ([`PinCheck`]): `signers.rs` callers pass the manager
///   itself, with `migrating_rule: Some(_)` only on the migration step;
///   `rules.rs` callers pass their configured manager and refuse a non-zero
///   rule without one; `smart-account execute` and the multicall submit pass
///   a manager built from the profile; the DeFi adapters sign under rule 0
///   only and pass `None`.
/// - `sub_invocations` ([`DeclaredSubInvocations`]): `rules.rs`, `signers.rs`
///   and `smart-account execute` keep the default `None`; the DEX adapter
///   declares the router's transfer of the input token, the DeFindex deposit
///   one transfer per vault asset to the vault, and the multicall submit its
///   bundle entries as calls.
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
    /// external contract address (e.g. a DeFindex vault, Soroswap router, or
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
    ///
    /// Every distinct non-zero entry is drift-checked before simulation; see
    /// [`Self::pin_check`].
    pub auth_rule_ids: &'a [ContextRuleId],

    /// Pre-built host function (caller builds `HostFunction::InvokeContract`).
    ///
    /// It is the root of the invocation tree the wallet signs: a simulated
    /// root that differs from it in contract, function name or any argument
    /// is refused before signing with [`SaError::SimulationDivergence`].
    pub host_function: HostFunction,

    /// The sub-invocations the wallet authorizes under
    /// [`Self::host_function`]; see [`DeclaredSubInvocations`].
    ///
    /// The default, [`DeclaredSubInvocations::None`], accepts a simulated
    /// root without sub-invocations, the shape of every wallet entrypoint. A
    /// caller whose invoked contract moves the wallet's tokens or calls
    /// further contracts on the wallet's authority declares those calls here;
    /// a simulated subtree outside the declaration is refused before signing.
    #[builder(default)]
    pub sub_invocations: DeclaredSubInvocations<'a>,

    /// Signer for the smart-account auth-digest and source-account envelope.
    pub signer: &'a (dyn Signer + Send + Sync),

    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,

    /// Secondary Soroban RPC URL: the ledger witness of every submission and
    /// the second endpoint of the multicall cross-RPC check.
    ///
    /// The field stays optional so a caller passes its resolved configuration
    /// through unchanged, but signing requires it: `None`, a malformed URL, or
    /// a URL on the primary's host refuses with
    /// [`SaError::LedgerWitnessUnavailable`] before the first request.
    pub secondary_rpc_url: Option<&'a str>,

    /// Stellar network passphrase for auth-digest + network-ID + envelope
    /// signing.
    pub network_passphrase: &'a str,

    /// CAIP-2 chain ID for the `NetworkContext` fingerprint
    /// (e.g. `"stellar:testnet"`).
    pub chain_id: &'a str,

    /// RPC budget, spent as two independent per-phase budgets. All pre-submit
    /// stages (the pinned-hash drift check of each checked rule, initial
    /// fetch, initial simulate, ledger witness, re-fetch, re-simulate, the
    /// envelope signature, and the submission's steps before
    /// `sendTransaction`) share ONE collective
    /// deadline of this duration, armed once before the first of them; the
    /// submit-and-confirm poll then spends its own separate budget of this
    /// same duration, so the base rule-install path worst case is ~2x this
    /// value of wall clock. The optional intervening checks (rule-expiry,
    /// multicall cross-RPC verification) run outside the collective
    /// pre-submit deadline but consume wall clock after it is armed; they
    /// carry their own separate budgets, so the ~2x figure describes the base
    /// path only.
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
    /// Fires after the ledger witness, before signing, against the lower
    /// member of the witnessed pair.
    /// `rules.rs` install + update callers supply this; all others pass `None`.
    ///
    /// Field and setter are `pub(crate)` because [`HorizonCheck`] is an
    /// internal orchestration type.  External callers leave this `None`.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) horizon_check: Option<HorizonCheck>,

    /// Pre-submission rule expiry check.
    ///
    /// Fires after the ledger witness, before signing, against the higher
    /// member of the witnessed pair. Signing-path methods that consume a
    /// `rule_id` supply this; install path passes `None`.
    ///
    /// Field and setter are `pub(crate)` because [`ExpiryCheck`] is an
    /// internal orchestration type.  External callers leave this `None`.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) expiry_check: Option<ExpiryCheck>,

    /// Multicall bundle check. `None` for single-invocation callers.
    pub multicall_check: Option<MulticallCheck>,

    /// Quorum authorization declaration (`None` for single-signer callers).
    ///
    /// The quorum path plans its selected signers and nonces, admits that plan,
    /// and calls `sign_quorum_plan` through its signing gate.
    /// The single-signer path uses [`Self::signer`] for authorization entries.
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

    /// External-Ed25519 rule signer for the single-signer path (`None` for
    /// single-signer callers, which keeps the original `Signer::Delegated`
    /// G-key path unchanged).
    ///
    /// When `Some`, `submit_signed_invoke`'s single-signer branch routes to
    /// the crate-internal `collect_mixed_signer_entries` mixed-signer
    /// collector with a single `ExternalEd25519` descriptor instead of
    /// calling `complete_authorization_entry` +
    /// `build_and_sign_delegated_g_key_entry` — see [`Ed25519RuleSigner`] for
    /// the on-chain rationale and the recommended-agent-signer doctrine.
    ///
    /// # Fail-closed invariant
    ///
    /// Mutually exclusive with `authorization` (the quorum path): supplying
    /// both is a caller programming error and `submit_signed_invoke` refuses
    /// immediately with [`SaError::AuthEntryConstructionFailed`], before any
    /// network I/O.
    pub ed25519_rule_signer: Option<Ed25519RuleSigner<'a>>,

    /// Confirmed-sequence floor hook (see
    /// `stellar_agent_network::sequence_floor::SequenceFloorHook`).
    ///
    /// When `Some`, the initial source-account fetch (Step 1's pre-submit
    /// stage) routes through the hook's bounded catch-up poll instead of a
    /// plain fetch, and a confirmed submit (Step 6) records its consumed
    /// sequence back into the hook. `None` (the default) reproduces the
    /// original plain-fetch, no-recording behaviour exactly — every caller
    /// other than the DeFi adapter submit paths leaves this unset.
    pub sequence_floor: Option<&'a dyn stellar_agent_network::SequenceFloorHook>,

    /// The admission capability that charges this intent before its first signature.
    /// `Recorded` binds the final envelope to the charge; `NoValue` charges count limits only.
    pub admission: SigningAdmission<'a>,

    /// Pinned-hash drift check inputs; see [`PinCheck`].
    ///
    /// `None` is accepted only when every entry of `auth_rule_ids` is rule 0,
    /// the bootstrap rule, which has no pins. A submission naming any other
    /// rule without a check is refused before any network I/O with
    /// [`SaError::AuthEntryConstructionFailed`] at stage
    /// `"pin_check_required"`.
    pub pin_check: Option<PinCheck<'a>>,

    /// The caller's held-lock context, when it holds the locks of the rules
    /// it signs under.
    ///
    /// With `None`, the submit path acquires the lock of every checked rule
    /// itself, holds the locks through the checks, the simulation and the
    /// signing, and releases them immediately before the transaction is sent.
    /// With `Some`, it acquires nothing: it refuses a checked rule the
    /// context holds no guard for on this account and in the log of the
    /// `pin_check` manager at stage `"rule_lock_missing"`, skips the
    /// signer-set steps of a rule the context already compared, and leaves
    /// the locks to the caller. A context without a `pin_check` is refused at
    /// stage `"rule_locks_without_pin_check"`.
    ///
    /// Field and setter are `pub(crate)`: a context is built only by the
    /// signers manager, from the guards of one lock acquisition.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) rule_locks: Option<&'a BorrowedRuleLocks<'a>>,

    /// The shape the simulated return value must have; see
    /// [`ExpectedReturn`].
    ///
    /// With `Some`, the first simulated result is checked right after the
    /// simulation and before anything is signed: another shape refuses with
    /// [`SaError::DeploymentFailed`] at phase `simulate`, and nothing is
    /// signed or sent. `None` checks nothing.
    ///
    /// Field and setter are `pub(crate)`: the callers that read an id from
    /// the return value are the crate's own managers.
    #[builder(setters(vis = "pub(crate)"))]
    pub(crate) expected_return: Option<ExpectedReturn>,
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_signed_invoke
// ─────────────────────────────────────────────────────────────────────────────

/// Submits a signed invocation through checked intent admission.
///
/// Mainnet refuses before any key access or request. Every signature requires
/// an independent ledger observation through a usable secondary endpoint.
///
/// # Step ordering
///
/// 1. Check arguments, the network, and the witness configuration. Acquire
///    each nonzero rule's lock in ascending order under one submission deadline.
///    Verify its signer baseline, pinned hashes, and signer set before fetching
///    the source account. Rule zero needs no baseline, pins, or rule lock.
/// 2. Simulate the invocation and check the expected return shape. Obtain the
///    ledger witness, enforce required checks, and compare both endpoints where
///    the caller requires a multicall check.
/// 3. Validate the simulated invocation against the wallet's declared tree.
///    Resolve keys, refresh the witness when necessary, and repeat rule checks.
///    The signature expiration is 100 ledgers beyond the lower observation.
/// 4. Build every partial, choose the quorum, and freeze delegated nonces.
///    Build the complete intent plan, admit it, and immediately construct its
///    signing gate. Recheck witness freshness after admission.
/// 5. Sign the frozen plan through the gate. Every signature authorizes its
///    subject, signer, and payload before the signer future exists. Quorum
///    signing resolves the planned keys without selecting another quorum.
/// 6. Simulate again with signed authorization, then build the final envelope.
///    The gate checks that envelope before its signature. Release rule locks,
///    bind recorded exposure, link the pending reservation, and send before
///    the submission deadline. Confirmation polling uses its own timeout.
/// 7. Return the transaction hash, ledger, and contract return value.
///
/// A refusal before the first successful gate authorization cancels the
/// unexposed admission. From that authorization on, every failure retains its
/// charge, including signer, simulation, binding, and send failures.
/// `SigningAdmission::NoValue` retains count charges without binding an envelope.
///
/// # Audit emission
///
/// The caller emits domain audit rows through its invocation result mapping.
/// This function emits no smart account audit event.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`] refuses a mainnet network or endpoint.
/// - Baseline, pin, and signer comparison errors preserve their typed codes.
/// - [`SaError::SubmitCheckMissing`] refuses an absent required check.
/// - [`SaError::LedgerWitnessUnavailable`] refuses unavailable or stale
///   observations and an elapsed deadline before signing.
/// - [`SaError::LedgerWitnessMismatch`] refuses inconsistent ledger observations.
/// - [`SaError::HorizonExceeded`] and [`SaError::RuleExpired`] refuse rule timing.
/// - [`SaError::PolicyDenied`] preserves the admission criterion's denial.
/// - [`SaError::IntentRecordUnavailable`] refuses unavailable checked admission.
/// - [`SaError::IntentBindingMismatch`] refuses an authority or envelope outside
///   the admitted plan. Existing exposed charges remain.
/// - [`SaError::AuthEntryConstructionFailed`] reports argument, rule lock, key,
///   encoding, signing, and submission deadline failures.
/// - [`SaError::DeploymentFailed`] reports simulation, return shape, envelope,
///   and submission failures.
/// - [`SaError::SimulationDivergence`] refuses an invocation outside the declared
///   tree. [`SaError::RuleIdMismatch`] refuses inconsistent rule identifiers.
#[allow(
    clippy::too_many_lines,
    reason = "seven-stage flow; splitting across multiple functions would obscure \
              the sequential invariant ordering (pre-flight → simulate → checks \
              → sign → submit)"
)]
pub async fn submit_signed_invoke(
    args: SubmitInvokeArgs<'_>,
) -> Result<SubmitInvokeResult, SaError> {
    check_invoke_address_forms(&args.host_function)?;
    validate_submit_invoke_args(&args)?;

    // ── Signing-path mutual-exclusivity guard — execute FIRST before any I/O ──
    // `ed25519_rule_signer` (External-Ed25519, no G-key sub-entry) and
    // `authorization` (the quorum path) select different auth-entry
    // construction strategies; supplying both is a caller programming error.
    // Fail-CLOSED before any network round-trip, mirroring the required-check
    // enforcement below.
    if args.authorization.is_some() && args.ed25519_rule_signer.is_some() {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "ed25519_rule_signer_quorum_guard",
            redacted_reason: format!(
                "{}: ed25519_rule_signer and authorization (quorum) are mutually exclusive; \
                 a caller must supply at most one signing-path selector",
                args.op_label
            ),
        });
    }

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

    // ── Mainnet refusal: before the first signer call and the first request ──
    // A mainnet passphrase or a mainnet-pattern primary URL never reaches the
    // signer, the simulation, or the signed re-simulation.
    refuse_mainnet_sa(args.network_passphrase, args.primary_rpc_url)?;

    // ── Witness configuration: before the first signer call and request ──────
    // Every signature below rests on a second endpoint's ledger observation.
    let secondary_rpc_url = checked_secondary_rpc_url(
        args.primary_rpc_url,
        args.secondary_rpc_url,
        args.network_passphrase,
    )?;

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

    // One absolute deadline bounds rule checks, initial account and simulation
    // reads, the ledger witness, optional unsigned recovery, signed re-simulation,
    // every signature and all steps before each send attempt.
    // Recovery consumes the remaining budget and keeps the same witness pair.
    // Rule-expiry and multicall cross-RPC checks carry their own budgets.
    // An in-flight send and confirmation polling use their separate timeout.
    let pre_submit_budget = PreSubmitBudget {
        deadline: tokio::time::Instant::now() + args.timeout,
        total: args.timeout,
    };

    // ── Step 1: rule locks and rule checks, before anything is simulated ──
    // `validate_submit_invoke_args` refused a submission naming a non-zero
    // rule without a check, so `None` here means rule 0 only. The locks
    // acquired here are held through the simulation and the signing and
    // released immediately before the send; a held-lock context's locks
    // belong to its holder.
    let (owned_rule_locks, checked_rules) = match &args.pin_check {
        Some(pin_check) => {
            run_rule_checks(
                pin_check,
                args.rule_locks,
                args.auth_rule_ids,
                &auth_scaddr,
                &source_pubkey_strkey,
                pre_submit_budget,
            )
            .await?
        }
        None => (
            Vec::new(),
            CheckedSigningRules {
                smart_account: auth_scaddr.clone(),
                network_id: Sha256::digest(args.network_passphrase.as_bytes()).into(),
                rule_ids: vec![0],
            },
        ),
    };

    let source_view = bound_pre_submit_stage(
        pre_submit_budget,
        "fetch_account_initial",
        "auth_payload",
        stellar_agent_network::sequence_floor::fetch_account_with_sequence_catchup(
            args.sequence_floor,
            &primary_rpc_client,
            &source_pubkey_strkey,
            &[],
        ),
    )
    .await?
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
    let mut sim_response = bound_pre_submit_stage(
        pre_submit_budget,
        "simulate_initial",
        "auth_payload",
        server.simulate_transaction_envelope(&sim_envelope, None),
    )
    .await?
    .map_err(|e| auth_payload_err(format!("simulate_transaction_envelope failed: {e}")))?;

    // ── Step 3 continued: ledger witness + Option<*Check> dispatch ────────────
    //
    // The primary answered the simulation, so its height decides nothing on
    // its own: both endpoints observe the latest ledger before any check that
    // reads a height, on every submission.
    let witness_request = WitnessRequest {
        primary: &primary_rpc_client,
        secondary_rpc_url,
        network_passphrase: args.network_passphrase,
        budget: pre_submit_budget,
    };
    let simulation_witness = witness_signing_ledger(&witness_request).await?;
    // A lagging simulation gets one unsigned retry against the same pair.
    // All response validation below consumes the accepted response in full.
    validate_latest_ledger(sim_response.latest_ledger)?;
    if simulation_witness.is_behind(sim_response.latest_ledger) {
        sim_response = bound_pre_submit_stage(
            pre_submit_budget,
            "simulate_recovery",
            "auth_payload",
            server.simulate_transaction_envelope(&sim_envelope, None),
        )
        .await?
        .map_err(|e| auth_payload_err(format!("simulate_transaction_envelope failed: {e}")))?;
        validate_latest_ledger(sim_response.latest_ledger)?;
    }
    simulation_witness.check_simulation_height(sim_response.latest_ledger)?;

    enforce_rule_ledger_checks(
        &args,
        &target_contract_scaddr,
        &source_pubkey_strkey,
        &simulation_witness,
    )
    .await?;

    // ── Step 4: Cross-RPC trust-anchor check ─────────────────────────────────
    // When multicall_check.is_some(), dispatch to the cross-RPC WASM-hash +
    // simulate comparators (4-way equality):
    //   (a) cross_rpc_compare_wasm_hashes — verifies registry SHA, primary RPC
    //       on-chain hash, secondary RPC on-chain hash, and MULTICALL_WASM_SHA256
    //       binary const are byte-exactly equal.
    //   (b) cross_rpc_compare_simulate_responses — verifies both RPCs produce
    //       identical simulation results for the multicall invocation by
    //       re-simulating on the secondary RPC and comparing responses.
    //
    // The comparators exclude ledger heights; the witness above supplies those
    // for this path as for every other. Single-invocation callers pass
    // multicall_check: None and have no contract hash or simulation to compare
    // here.
    if let Some(mc) = args.multicall_check.as_ref() {
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

        // (a) Wasm-hash 4-way equality: fetch on-chain hashes from both RPCs and
        // compare against the registry-recorded SHA and MULTICALL_WASM_SHA256.
        let primary_hash = crate::multicall::fetch_wasm_hash_via_rpc(
            args.primary_rpc_url,
            &mc.registry_entry_address,
            args.timeout,
        )
        .await?;
        let secondary_hash = crate::multicall::fetch_wasm_hash_via_rpc(
            secondary_rpc_url,
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
        // compare normalized response against primary result (including
        // sub_invocations byte-exact; see cross_rpc_compare_simulate_responses).
        let secondary_server = stellar_rpc_client::Client::new(secondary_rpc_url).map_err(|e| {
            auth_payload_err(format!("secondary RPC Client construction failed: {e}"))
        })?;
        let secondary_sim = secondary_server
            .simulate_transaction_envelope(&sim_envelope, None)
            .await
            .map_err(|e| {
                crate::multicall::rpc_client_divergence("secondary RPC simulate failed", &e)
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
                SimulationErrorClass::of(sim_error)
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
    // A caller that reads an id from the return value checks its shape here,
    // before anything is signed or sent.
    if let Some(expected) = args.expected_return {
        expected.check(&return_val, args.op_label)?;
    }
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

    // ── Signed-tree binding ───────────────────────────────────────────────────
    // The root of the tree the wallet signs is its own host function, and the
    // sub-invocations under it are the ones the caller declared. The simulated
    // tree comes from the RPC, and Address credentials are not bound to a
    // transaction: a signature over an RPC-chosen tree is an authorization the
    // RPC could submit on its own. Both checks refuse before anything is
    // signed.
    let simulated_root_fingerprint = fingerprint_invocation(&prepared_entry);
    check_simulated_root(&prepared_entry.root_invocation.function, &invoke)
        .and_then(|()| {
            check_declared_sub_invocations(
                &prepared_entry.root_invocation.sub_invocations,
                &args.sub_invocations,
                &auth_scaddr,
            )
        })
        .map_err(|err| {
            attribute_signed_tree_refusal(err, args.op_label, &simulated_root_fingerprint)
        })?;

    // The tree the wallet signs: its own root with the accepted subtree. An
    // external contract that moves the wallet's tokens (the Soroswap router's
    // `transfer(from = wallet)`, a DeFindex deposit) or a multicall router
    // dispatching wallet-authorized calls places those calls under the root,
    // and on-chain `__check_auth` verifies the digest over the whole tree.
    let signed_root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
        sub_invocations: prepared_entry.root_invocation.sub_invocations.clone(),
    };

    // OZ `__check_auth` receives one `auth::Context` per node of the
    // authorized invocation tree (the root and every sub-invocation, depth
    // first), and the payload's `context_rule_ids` MUST have exactly that many
    // entries (`ContextRuleIdsLengthMismatch` = 3014 otherwise). The node
    // fingerprints of the simulated and of the signed tree feed the
    // divergence check of the auth-entry builder.
    let simulated_auth_contexts = fingerprint_invocation_nodes(&prepared_entry.root_invocation);
    let signed_auth_contexts = fingerprint_invocation_nodes(&signed_root);
    let invocation_context_count = signed_auth_contexts.len();

    // A multicall's authorization rules follow the simulated invocation tree.
    // A single rule expands across that tree; an explicit list must cover it.
    if args.multicall_check.is_some()
        && args.auth_rule_ids.len() != 1
        && args.auth_rule_ids.len() != invocation_context_count
    {
        return Err(SaError::MulticallFailed {
            phase: "build",
            redacted_reason: format!(
                "authorization rule count {} does not cover {invocation_context_count} invocation contexts",
                args.auth_rule_ids.len(),
            ),
            post_submit_kind: None,
        });
    }

    // Soroban-RPC's simulateTransaction returns signature_expiration_ledger = 0
    // (placeholder). Overwrite with the witnessed bound before signing.
    // Cross-reference: js-stellar-base auth.js:132.
    //
    // The accepted simulation satisfies the same observation pair, including
    // after recovery. Its own height never reaches the preimage.

    // ── Signer keys: read before the last witness check ──────────────────────
    // A key lookup can reach a hardware device or a keyring and take any time.
    // Every key the signing below reads is resolved here, so the freshness
    // check at the signing boundary is not followed by a lookup. The envelope
    // signer's key is the source key read above.
    let envelope_signer = ResolvedKeySigner::with_key(args.signer, source_pubkey);
    let rule_signer = match &args.ed25519_rule_signer {
        Some(rule_signer) => Some((
            ResolvedKeySigner::resolve(rule_signer.signer)
                .await
                .map_err(|e| auth_payload_err(format!("signer public_key fetch failed: {e}")))?,
            &rule_signer.verifier,
        )),
        None => None,
    };
    let mut quorum_signers: Vec<ResolvedKeySigner<'_>> = Vec::new();
    if args.authorization.is_some() {
        for &signer in args.signers {
            quorum_signers.push(ResolvedKeySigner::resolve(signer).await.map_err(|e| {
                SaError::AuthEntryConstructionFailed {
                    stage: "quorum_signatures",
                    redacted_reason: format!(
                        "{}: quorum collection failed: public_key fetch failed: {e}",
                        args.op_label
                    ),
                }
            })?);
        }
    }
    let quorum_signer_refs: Vec<&(dyn Signer + Send + Sync)> = quorum_signers
        .iter()
        .map(|signer| signer as &(dyn Signer + Send + Sync))
        .collect();

    // The steps since the witness can outlast an observation. A stale pair is
    // read again as a pair, and every check that read a height runs against
    // the new one; a signature never rests on a pair past the deadline.
    let ledger_bound = if simulation_witness.is_stale(tokio::time::Instant::now()) {
        let refreshed = witness_signing_ledger(&witness_request).await?;
        enforce_rule_ledger_checks(
            &args,
            &target_contract_scaddr,
            &source_pubkey_strkey,
            &refreshed,
        )
        .await?;
        refreshed
    } else {
        simulation_witness
    };
    let signature_expiration_ledger = ledger_bound.signature_expiration_ledger()?;

    // Network ID (sha256 of passphrase) for the auth-digest preimage.
    let network_id: [u8; 32] = Sha256::digest(args.network_passphrase.as_bytes()).into();

    // A singleton `auth_rule_ids` list is replicated to every invocation context.
    // The caller must choose a rule valid for every context receiving that ID.
    // An explicit list passes through unchanged and must contain one ID per context.
    // Multicall rejects mismatched lengths above; authorization-entry construction
    // rejects mismatched rule and context counts before signing.
    let expanded_auth_rule_ids: Vec<ContextRuleId> =
        if args.auth_rule_ids.len() == 1 && invocation_context_count > 1 {
            vec![args.auth_rule_ids[0]; invocation_context_count]
        } else {
            args.auth_rule_ids.to_vec()
        };
    // The builder's divergence check compares the simulated tree with the
    // tree the wallet signs, node by node: a second check behind the root
    // binding and the declared sub-invocations above.
    let context = SimulationContext {
        context_rule_ids: expanded_auth_rule_ids.clone(),
        auth_contexts: simulated_auth_contexts,
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
        auth_contexts: signed_auth_contexts,
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

    ledger_bound.ensure_fresh(pre_submit_budget)?;
    // Every partial and delegated nonce is fixed before admission.
    let (quorum_plan, single_plan, subjects) = if let Some(authz) = args.authorization {
        if invoke.contract_address != auth_scaddr || !signed_root.sub_invocations.is_empty() {
            return Err(SaError::AuthEntryConstructionFailed {
                stage: "quorum_external_contract_guard",
                redacted_reason: format!(
                    "{}: the quorum path signs the wallet's own entrypoints only. The host function targets a contract other than the wallet smart-account or the simulated tree carries sub-invocations",
                    args.op_label
                ),
            });
        }
        let quorum = plan_quorum_signatures_within_budget(
            checked_rules,
            authz,
            &quorum_signer_refs,
            auth_scaddr.clone(),
            function_name.clone(),
            invoke.args.to_vec(),
            simulation.context.context_rule_ids.clone(),
            &simulation,
            &envelope,
            args.network_passphrase,
            signature_expiration_ledger,
            Some(pre_submit_budget),
        )
        .await
        .map_err(|failure| quorum_failure_error(failure, args.op_label))?;
        let subjects = quorum.intent_subjects();
        (Some(quorum), None, subjects)
    } else {
        let mut partial: PartialSorobanAuthorizationEntry =
            build_authorization_entry_with_sub_invocations(
                invoke.contract_address.clone(),
                function_name.clone(),
                invoke.args.to_vec(),
                simulation.context.context_rule_ids.clone(),
                &simulation,
                &envelope,
                signed_root.sub_invocations.clone(),
            )
            .await?;
        partial.smart_account = auth_scaddr.clone();
        let descriptor = if let Some((resolved, verifier)) = &rule_signer {
            let key = resolved
                .public_key()
                .await
                .map_err(|error| auth_payload_err(error.to_string()))?;
            SignerDescriptor::External {
                verifier: scaddress_to_strkey(verifier)?,
                key_data_sha256: Sha256::digest(key.0).into(),
            }
        } else {
            SignerDescriptor::Delegated {
                account: source_pubkey.0,
            }
        };
        let mut subjects = vec![
            IntentSubject::smart_account(
                &auth_scaddr,
                partial.nonce,
                signature_expiration_ledger,
                &partial.root_invocation,
                partial
                    .context_rule_ids
                    .iter()
                    .map(ContextRuleId::as_u32)
                    .collect(),
                vec![descriptor],
            )
            .map_err(|field| SaError::IntentBindingMismatch { field })?,
        ];
        let nonce = if rule_signer.is_none() {
            use rand_core::RngCore as _;
            let nonce = i64::from_ne_bytes(rand_core::OsRng.next_u64().to_ne_bytes());
            let root = crate::managers::auth_entry::delegated_g_key_invocation(
                &auth_scaddr,
                &partial.auth_digest,
            )?;
            let address = ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(source_pubkey.0)),
            ));
            subjects.push(
                IntentSubject::account_key(&address, nonce, signature_expiration_ledger, &root)
                    .map_err(|field| SaError::IntentBindingMismatch { field })?,
            );
            Some(nonce)
        } else {
            None
        };
        (None, Some((checked_rules, partial, nonce)), subjects)
    };
    let host_bytes = args
        .host_function
        .to_xdr(stellar_xdr::Limits::none())
        .map_err(|_| SaError::IntentBindingMismatch { field: "plan" })?;
    let sequence = source_view
        .sequence_number
        .checked_add(1)
        .ok_or(SaError::IntentBindingMismatch { field: "plan" })?;
    let plan = SignedIntentPlan::new(
        args.network_passphrase,
        &scaddress_to_strkey(&auth_scaddr)?,
        &source_pubkey_strkey,
        sequence,
        Sha256::digest(host_bytes).into(),
        subjects,
        Some(signature_expiration_ledger),
    )
    .map_err(|error| map_admission_error(&error, args.op_label))?
    .classify_purpose(&args.host_function, None)
    .map_err(|error| map_admission_error(&error, args.op_label))?
    .with_capability(ledger_bound.capability());
    let proof = args
        .admission
        .admit(&plan)
        .await
        .map_err(|error| map_admission_error(&error, args.op_label))?;
    let gate = SigningGate::new(proof);
    let signing_result = async {
        ledger_bound.ensure_fresh(pre_submit_budget)?;
        let auth_entries = if let Some(quorum) = &quorum_plan {
            sign_quorum_plan_within_budget(
                quorum,
                &quorum_signer_refs,
                &gate,
                Some(pre_submit_budget),
            )
            .await
            .map_err(|failure| quorum_failure_error(failure, args.op_label))?
        } else if let Some((checked, partial, nonce)) = single_plan {
            if let Some((resolved, verifier)) = &rule_signer {
                let mixed_signers = [crate::managers::auth_entry::MixedSigner {
                    signer: resolved,
                    kind: crate::managers::auth_entry::MixedSignerKind::ExternalEd25519 {
                        verifier: (*verifier).clone(),
                    },
                }];
                collect_mixed_signer_entries_within_budget(
                    &gate,
                    checked,
                    partial,
                    &mixed_signers,
                    signature_expiration_ledger,
                    args.network_passphrase,
                    Some(pre_submit_budget),
                )
                .await?
            } else {
                let signed = complete_authorization_entry_within_budget(
                    &gate,
                    checked,
                    partial.clone(),
                    &envelope_signer,
                    Some(pre_submit_budget),
                )
                .await?;
                let delegated = build_and_sign_delegated_g_key_entry(
                    &gate,
                    nonce.ok_or(SaError::IntentBindingMismatch { field: "plan" })?,
                    &auth_scaddr,
                    &partial.auth_digest,
                    signature_expiration_ledger,
                    &envelope_signer,
                    args.network_passphrase,
                    Some(pre_submit_budget),
                )
                .await?;
                vec![signed, delegated]
            }
        } else {
            return Err(SaError::IntentBindingMismatch { field: "plan" });
        };
        // ── Simulation-audit fingerprint capture ─────────────────────────────────
        // Capture the expected fingerprint after the auth entries are built.
        // The later check compares the assembled invocation with the simulation.
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
            stellar_agent_network::simulation_audit::AuthEntryFingerprint::from_entries(
                &auth_entries,
            )
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
        //
        // `pre_submit_budget` carries the same collective deadline armed at the
        // top of this function, so the re-fetch and re-simulate inside
        // `resimulate_with_signed_auth` share that budget with the stages already
        // run above (initial fetch, initial simulate, and the off-chain signing
        // step just completed).
        let resim_response = resimulate_with_signed_auth(
            &server,
            &primary_rpc_client,
            &target_contract_scaddr,
            function_name.clone(),
            invoke_args_vecm.clone(),
            auth_entries.clone(),
            &source_pubkey_strkey,
            args.network_passphrase,
            pre_submit_budget,
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

        // The envelope is signed only while the deadline the witness rests on is
        // open, through the key resolved before the signing boundary. A software
        // key signs without yielding, so the deadline is checked before the
        // bounded signature as well.
        pre_submit_budget.check_at("sign_envelope", "auth_payload")?;
        let decoded = stellar_xdr::TransactionEnvelope::from_xdr_base64(
            &prepared_envelope_xdr,
            stellar_xdr::Limits::none(),
        )
        .map_err(|_| SaError::IntentBindingMismatch {
            field: "host_invocation",
        })?;
        gate.authorize(SigningRequest {
            subject: AuthSubject::source(&source_pubkey_strkey)
                .map_err(|field| SaError::IntentBindingMismatch { field })?,
            signer: SignerMatch::Exact(SignerDescriptor::AccountKey {
                public_key: source_pubkey.0,
            }),
            payload: SigningPayload::Envelope(&decoded),
        })?;
        let final_signed_xdr = bound_pre_submit_stage(
            pre_submit_budget,
            "sign_envelope",
            "auth_payload",
            attach_signature(
                &prepared_envelope_xdr,
                &envelope_signer,
                args.network_passphrase,
            ),
        )
        .await?
        .map_err(|e| SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: format!("{} envelope signing failed: {e}", args.op_label),
        })?;

        Ok::<_, SaError>((final_signed_xdr, c7_expected_fp))
    }
    .await;
    let (final_signed_xdr, c7_expected_fp) = match signing_result {
        Ok(value) => value,
        Err(error) => {
            cancel_unexposed_admission(&args.admission, &gate).await;
            return Err(error);
        }
    };

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

    // The send and the confirmation poll run without the rule locks this
    // call acquired: every check they guard has run, and the signed
    // envelope is final.
    drop(owned_rule_locks);

    // Nothing is sent after the pre-submit deadline: the steps before
    // `sendTransaction` end at it, and no send attempt, a resend of the same
    // bytes included, starts after it. The confirmation poll keeps its own
    // `args.timeout` budget.
    let sa_submit_timing_t_submit = std::time::Instant::now();
    let submission = submit_transaction_and_wait_sent_by(
        &primary_rpc_client,
        &final_signed_xdr,
        pre_submit_budget.deadline,
        args.timeout,
        args.network_passphrase,
        None,
        args.admission.recorder(),
        args.admission.recorder().and_then(|_| gate.exposure()),
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
    tracing::debug!(
        target: "sa_submit_timing",
        stage = "submit_and_wait",
        elapsed_ms = u64::try_from(sa_submit_timing_t_submit.elapsed().as_millis())
            .unwrap_or(u64::MAX),
        "sa_submit_timing: submit+poll stage elapsed (poll under the separate args.timeout budget)"
    );

    if args.emit_observability_logs {
        let op = args.op_label;
        info!(
            tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
            ledger = submission.ledger,
            op_label = %op,
            "{op}: transaction confirmed on-chain",
        );
    }

    // Record the confirmed sequence for this source account so a later build
    // in this same process (e.g. the next DeFi submit for the same signer)
    // can wait out avoidable read-after-write propagation lag.
    // `source_view.sequence_number` is the PRE-submit value fetched at Step 1
    // (via the catch-up-aware fetch above); the submitted envelope's sequence
    // is that value plus one, mirroring the MCP classic-verb tool layer's own
    // `record_confirmed(&args.source, source_sequence + 1)` call.
    if let Some(hook) = args.sequence_floor {
        hook.record_confirmed(&source_pubkey_strkey, source_view.sequence_number + 1)
            .await;
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

/// Runs the checks of a submission that read a ledger height, against the
/// witnessed pair.
///
/// The session-rule horizon is measured from the lower member, so a higher
/// claim cannot shorten a requested horizon below the cap. A rule must be
/// valid at the higher member, so a lower claim cannot revive an expired rule.
async fn enforce_rule_ledger_checks(
    args: &SubmitInvokeArgs<'_>,
    target_contract: &ScAddress,
    source_pubkey_strkey: &str,
    bound: &WitnessedLedgerBound,
) -> Result<(), SaError> {
    // OZ storage.rs:649-652 (install) and :786-787 (update), SHA `a9c4216`,
    // reject only `valid_until < current_ledger` (PastValidUntil = 3005).
    // The wallet-side horizon cap is an operator-configurable safety discipline.
    if let Some(HorizonCheck {
        valid_until,
        max_horizon,
        rule_id_or_pending,
    }) = args.horizon_check
    {
        let horizon = valid_until.saturating_sub(bound.lower());
        if horizon > max_horizon {
            return Err(SaError::HorizonExceeded {
                rule_id_or_pending,
                requested_horizon: horizon,
                max_horizon,
            });
        }
    }

    // OZ storage.rs:280-285 (SHA `a9c4216`): strict-< check on valid_until.
    // UnvalidatedContext = 3002 per OZ mod.rs:542 SHA `a9c4216`.
    if let Some(ExpiryCheck { rule_id }) = args.expiry_check {
        check_rule_not_expired_standalone(
            args.primary_rpc_url,
            args.network_passphrase,
            args.timeout,
            target_contract.clone(),
            rule_id,
            source_pubkey_strkey,
            bound.higher(),
        )
        .await?;
    }
    Ok(())
}

/// Refuses a write declared for mainnet or aimed at a mainnet-pattern endpoint
/// with [`SaError::MainnetWriteForbidden`].
///
/// The smart-account form of [`refuse_mainnet_write`]: the same two local
/// checks, and no I/O. `submit_signed_invoke` and the three public timelock
/// functions call it before any signing call and any request.
pub(crate) fn refuse_mainnet_sa(network_passphrase: &str, rpc_url: &str) -> Result<(), SaError> {
    refuse_mainnet_write(network_passphrase, rpc_url).map_err(|_| SaError::MainnetWriteForbidden)
}

/// Maps a failed submission sent by the pre-submit deadline `budget` into the
/// smart-account error surface.
///
/// A deadline that passed before anything was sent is the pre-submit refusal
/// of the stage it passed at. A deadline that passed before a resend, after a
/// send whose answer was lost, leaves that send's outcome unknown: it maps as
/// the unresolved timeout of the transaction sent, so the caller reconciles
/// its hash instead of rebuilding. `timeout` is the submission's own budget.
/// Every other failure maps as [`map_submit_error`] maps it.
pub(crate) fn map_sent_by_error(
    error: SentByError,
    budget: PreSubmitBudget,
    timeout: std::time::Duration,
    op_label: &'static str,
    signed_xdr: &str,
) -> SaError {
    match error {
        SentByError::Elapsed {
            stage,
            sent_tx_hash: None,
        } => budget.send_refusal(stage),
        SentByError::Elapsed {
            sent_tx_hash: Some(tx_hash),
            ..
        } => map_submit_error(
            &stellar_agent_core::error::WalletError::Submission(
                stellar_agent_core::error::SubmissionError::TxTimeout {
                    tx_hash,
                    seconds: timeout.as_secs(),
                },
            ),
            op_label,
            signed_xdr,
        ),
        SentByError::Failed(error) => map_submit_error(&error, op_label, signed_xdr),
    }
}

/// Maps a submit-layer failure into the smart-account error surface.
///
/// A submission whose outcome is unknown, and one refused because it could not
/// be recorded, keep their own wire code and their identifiers: the caller's
/// next step is to reconcile a transaction hash, and a generic deployment
/// failure would send it to rebuild and re-submit instead. A policy denial
/// keeps the criterion's own code for the same reason. A mainnet refusal keeps
/// the canonical `network.mainnet_write_forbidden` code. Every other failure is
/// a deployment failure at the submit phase.
pub(crate) fn map_admission_error(
    error: &stellar_agent_core::WalletError,
    op_label: &'static str,
) -> SaError {
    map_submit_error(error, op_label, "")
}

pub(crate) async fn cancel_unexposed_admission(
    admission: &SigningAdmission<'_>,
    gate: &SigningGate,
) {
    if let Some(proof) = gate.take_unexposed()
        && let Err(error) = admission.cancel_unexposed(proof).await
    {
        tracing::warn!(code = error.code(), "unexposed intent cancellation refuses");
    }
}

fn quorum_failure_error(failure: QuorumFailure, op_label: &str) -> SaError {
    match failure {
        QuorumFailure::Deadline(error) | QuorumFailure::Intent(error) => error,
        QuorumFailure::Quorum(error) => SaError::AuthEntryConstructionFailed {
            stage: "quorum_signatures",
            redacted_reason: format!("{op_label}: quorum collection failed: {error}"),
        },
    }
}

pub(crate) fn map_submit_error(
    error: &stellar_agent_core::error::WalletError,
    op_label: &'static str,
    signed_xdr: &str,
) -> SaError {
    use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};

    match error {
        WalletError::Submission(SubmissionError::IntentRecordUnavailable { class }) => {
            return SaError::IntentRecordUnavailable { class };
        }
        WalletError::Submission(SubmissionError::IntentBindingMismatch { field }) => {
            return SaError::IntentBindingMismatch { field };
        }
        _ => {}
    }
    // A refusal the wallet's own policy decided keeps the criterion's code:
    // nothing was sent, and an agent told the deployment failed would rebuild
    // and re-submit against a cap that has already refused it.
    if let WalletError::PolicyDenied { reason } = error {
        return SaError::PolicyDenied {
            reason: reason.clone(),
        };
    }

    // A submit-layer mainnet refusal, such as an endpoint that reports the
    // mainnet passphrase, sent nothing and carries the one cross-surface code.
    if matches!(
        error,
        WalletError::Network(NetworkError::MainnetWriteForbidden)
    ) {
        return SaError::MainnetWriteForbidden;
    }

    let unresolved = match error {
        WalletError::Submission(SubmissionError::TxTimeout { tx_hash, seconds }) => Some((
            crate::error::SubmissionUnresolvedKind::Timeout,
            Some(tx_hash.clone()),
            Some(*seconds),
        )),
        WalletError::Submission(SubmissionError::TxAlreadySubmitted { hash }) => Some((
            crate::error::SubmissionUnresolvedKind::AlreadySubmitted,
            Some(hash.clone()),
            None,
        )),
        WalletError::Submission(SubmissionError::HashMismatch { local, .. }) => Some((
            crate::error::SubmissionUnresolvedKind::HashMismatch,
            Some(local.clone()),
            None,
        )),
        WalletError::Submission(SubmissionError::RecordUnavailable { .. }) => Some((
            crate::error::SubmissionUnresolvedKind::RecordUnavailable,
            None,
            None,
        )),
        _ => None,
    };

    match unresolved {
        Some((kind, tx_hash, timeout_seconds)) => SaError::SubmissionUnresolved {
            kind,
            message: error.message(),
            tx_hash,
            timeout_seconds,
            envelope_hash: Some(stellar_agent_network::envelope_hash_hex(signed_xdr)),
        },
        None => SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: format!("{op_label} submission failed: {error}"),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signed-tree checks
// ─────────────────────────────────────────────────────────────────────────────

/// The refusal of a simulated invocation tree the wallet does not sign.
fn signed_tree_divergence(redacted_reason: String) -> SaError {
    SaError::SimulationDivergence {
        sub_code: SimulationDivergenceSubCode::AuthContexts,
        redacted_reason,
    }
}

/// Prefixes a signed-tree refusal with the operation label and the
/// redaction-safe fingerprint of the simulated root invocation, so an
/// operator can attribute the refused tree without seeing its values.
pub(crate) fn attribute_signed_tree_refusal(
    err: SaError,
    op_label: &str,
    simulated_root: &AuthContextFingerprint,
) -> SaError {
    match err {
        SaError::SimulationDivergence {
            sub_code,
            redacted_reason,
        } => SaError::SimulationDivergence {
            sub_code,
            redacted_reason: format!(
                "{op_label}: simulated tree {}: {redacted_reason}",
                simulated_root.as_str()
            ),
        },
        other => other,
    }
}

/// Requires the simulated root invocation to be the wallet's own host
/// function: contract, function name and every argument, compared as XDR
/// values.
///
/// # Errors
///
/// [`SaError::SimulationDivergence`] with sub-code `AuthContexts`, naming the
/// part that differs (the contract, the function, the argument count, or the
/// index of the first differing argument), never a value.
pub(crate) fn check_simulated_root(
    simulated: &SorobanAuthorizedFunction,
    invoke: &InvokeContractArgs,
) -> Result<(), SaError> {
    let SorobanAuthorizedFunction::ContractFn(simulated) = simulated else {
        return Err(signed_tree_divergence(
            "the simulated root invocation is not a contract call".to_owned(),
        ));
    };
    let part = if simulated.contract_address != invoke.contract_address {
        "its contract".to_owned()
    } else if simulated.function_name != invoke.function_name {
        "its function".to_owned()
    } else if simulated.args.len() != invoke.args.len() {
        format!(
            "its argument count ({} against {})",
            simulated.args.len(),
            invoke.args.len()
        )
    } else if let Some(index) = simulated
        .args
        .iter()
        .zip(invoke.args.iter())
        .position(|(simulated, wallet)| simulated != wallet)
    {
        format!("argument {index}")
    } else {
        return Ok(());
    };
    Err(signed_tree_divergence(format!(
        "the simulated root invocation differs from the host function in {part}"
    )))
}

/// Requires the simulated sub-invocations under the root to be the ones the
/// caller declared; see [`DeclaredSubInvocations`].
///
/// `authorizer` is the wallet whose credentials sign the tree: a declared
/// token transfer must move its tokens. Every accepted sub-invocation is a
/// leaf.
///
/// # Errors
///
/// [`SaError::SimulationDivergence`] with sub-code `AuthContexts`, naming the
/// index of the refused sub-invocation and the reason, never a value.
pub(crate) fn check_declared_sub_invocations(
    subs: &[SorobanAuthorizedInvocation],
    declared: &DeclaredSubInvocations<'_>,
    authorizer: &ScAddress,
) -> Result<(), SaError> {
    if let Some(index) = subs.iter().position(|sub| !sub.sub_invocations.is_empty()) {
        return Err(signed_tree_divergence(format!(
            "sub-invocation {index} carries nested sub-invocations"
        )));
    }
    match declared {
        DeclaredSubInvocations::None => {
            if subs.is_empty() {
                Ok(())
            } else {
                Err(signed_tree_divergence(format!(
                    "the simulated root carries {} undeclared sub-invocations",
                    subs.len()
                )))
            }
        }
        DeclaredSubInvocations::TokenTransfers(declared) => {
            check_declared_transfers(subs, declared, authorizer)
        }
        DeclaredSubInvocations::Calls(declared) => check_declared_calls(subs, declared),
    }
}

/// The parts of a leaf `transfer(from, to, amount)` call.
struct TransferCall<'a> {
    token: &'a ScAddress,
    from: &'a ScAddress,
    to: &'a ScAddress,
    amount: i128,
}

/// Reads `function` as `transfer(Address from, Address to, I128 amount)`;
/// any other function name or argument shape is `None`.
fn transfer_call(function: &SorobanAuthorizedFunction) -> Option<TransferCall<'_>> {
    let SorobanAuthorizedFunction::ContractFn(call) = function else {
        return None;
    };
    if call.function_name.0.as_slice() != b"transfer" {
        return None;
    }
    let [
        ScVal::Address(from),
        ScVal::Address(to),
        ScVal::I128(amount),
    ] = call.args.as_slice()
    else {
        return None;
    };
    Some(TransferCall {
        token: &call.contract_address,
        from,
        to,
        amount: (i128::from(amount.hi) << 64) | i128::from(amount.lo),
    })
}

/// [`DeclaredSubInvocations::TokenTransfers`]: every sub-invocation is a
/// transfer from `authorizer` on a declared token to an accepted recipient,
/// and the transfers counted against each declared entry stay within its
/// bound.
fn check_declared_transfers(
    subs: &[SorobanAuthorizedInvocation],
    declared: &[DeclaredTransfer],
    authorizer: &ScAddress,
) -> Result<(), SaError> {
    let mut totals = vec![0_i128; declared.len()];
    for (index, sub) in subs.iter().enumerate() {
        let Some(transfer) = transfer_call(&sub.function) else {
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} is not a transfer(from, to, amount) call"
            )));
        };
        if transfer.from != authorizer {
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} transfers from an address other than the authorizing one"
            )));
        }
        if transfer.amount < 0 {
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} transfers a negative amount"
            )));
        }
        let Some((entry, total)) = declared.iter().zip(totals.iter_mut()).find(|(entry, _)| {
            entry.token == *transfer.token && entry.to.as_ref().is_none_or(|to| to == transfer.to)
        }) else {
            let reason = if declared.iter().any(|entry| entry.token == *transfer.token) {
                "to an undeclared recipient"
            } else {
                "on an undeclared token"
            };
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} transfers {reason}"
            )));
        };
        *total = total
            .checked_add(transfer.amount)
            .filter(|sum| *sum <= entry.max_amount)
            .ok_or_else(|| {
                signed_tree_divergence(format!(
                    "the transfers through sub-invocation {index} exceed the declared bound"
                ))
            })?;
    }
    Ok(())
}

/// [`DeclaredSubInvocations::Calls`]: every sub-invocation equals a declared
/// call, in declared order, each declared call used at most once.
fn check_declared_calls(
    subs: &[SorobanAuthorizedInvocation],
    declared: &[InvokeContractArgs],
) -> Result<(), SaError> {
    let mut remaining = declared.iter();
    for (index, sub) in subs.iter().enumerate() {
        let SorobanAuthorizedFunction::ContractFn(call) = &sub.function else {
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} is not a contract call"
            )));
        };
        if !remaining.any(|declared_call| declared_call == call) {
            return Err(signed_tree_divergence(format!(
                "sub-invocation {index} is not a declared call in declared order"
            )));
        }
    }
    Ok(())
}

/// Refuses a W target or argument before signing admission records a plan.
pub(crate) fn check_invoke_address_forms(host_function: &HostFunction) -> Result<(), SaError> {
    if let HostFunction::InvokeContract(invoke) = host_function
        && (matches!(invoke.contract_address, ScAddress::MuxedContract(_))
            || invoke
                .args
                .iter()
                .any(stellar_agent_core::sc_address::scval_has_muxed_contract))
    {
        return Err(SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: stellar_agent_core::sc_address::MUXED_CONTRACT_REFUSAL.to_owned(),
        });
    }
    Ok(())
}

/// Refuses a [`SubmitInvokeArgs`] whose fields contradict each other,
/// before any network I/O.
///
/// - `multicall_check: Some(_)` requires `"multicall"` in `required_checks`,
///   so the required-check enforcement always covers a multicall submission
///   (stage `"multicall_check_undeclared"`).
/// - `rule_locks: Some(_)` requires a `pin_check`, whatever the auth rules
///   are (stage `"rule_locks_without_pin_check"`).
/// - `pin_check: None` is accepted only when every entry of `auth_rule_ids`
///   is rule 0, the bootstrap rule with no pins (stage
///   `"pin_check_required"`).
/// - `pin_check.migrating_rule: Some(rule)`, which skips the rule's
///   verifier check, is accepted only when `auth_rule_ids` is exactly that
///   rule (stage `"migrating_rule_mismatch"`).
///
/// # Errors
///
/// [`SaError::AuthEntryConstructionFailed`] at the stage named above.
fn validate_submit_invoke_args(args: &SubmitInvokeArgs<'_>) -> Result<(), SaError> {
    if args.multicall_check.is_some() && !args.required_checks.contains(&"multicall") {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "multicall_check_undeclared",
            redacted_reason: format!(
                "{}: multicall_check requires \"multicall\" in required_checks",
                args.op_label
            ),
        });
    }
    if args.rule_locks.is_some() && args.pin_check.is_none() {
        return Err(SaError::AuthEntryConstructionFailed {
            stage: "rule_locks_without_pin_check",
            redacted_reason: format!(
                "{}: a held rule-lock context is accepted only with a pinned-hash drift check",
                args.op_label
            ),
        });
    }
    match &args.pin_check {
        None => {
            if let Some(rule_id) = args
                .auth_rule_ids
                .iter()
                .map(ContextRuleId::as_u32)
                .find(|id| *id != 0)
            {
                return Err(SaError::AuthEntryConstructionFailed {
                    stage: "pin_check_required",
                    redacted_reason: format!(
                        "{}: rule {rule_id} is authorized without a pinned-hash drift check; \
                         only rule 0 may sign without one",
                        args.op_label
                    ),
                });
            }
        }
        Some(PinCheck {
            migrating_rule: Some(migrating_rule),
            ..
        }) => {
            let migrating_rule = migrating_rule.rule_id();
            if args.auth_rule_ids != [ContextRuleId::new(migrating_rule)] {
                return Err(SaError::AuthEntryConstructionFailed {
                    stage: "migrating_rule_mismatch",
                    redacted_reason: format!(
                        "{}: the verifier-check exemption of migrating rule \
                         {migrating_rule} requires auth_rule_ids to be exactly \
                         [{migrating_rule}]",
                        args.op_label
                    ),
                });
            }
        }
        Some(PinCheck {
            migrating_rule: None,
            ..
        }) => {}
    }
    Ok(())
}

/// Runs the pre-submission checks of the distinct non-zero rules in
/// `auth_rule_ids`, ascending, under `budget`; see [`PinCheck`] for the
/// steps and the outcomes.
///
/// 1. Locks: with no `rule_locks`, one acquisition of every checked rule's
///    lock on the account of `smart_account`; with a held-lock context,
///    none, and a checked rule the context holds no guard for, on that
///    account and in the log of the `pin_check` manager, refuses.
/// 2. Baseline reads, each followed by a deadline check, skipping the rules
///    the context compared.
/// 3. The pinned-hash drift check ([`run_pin_check`]).
/// 4. The signer-set comparison of each rule read in step 2.
///
/// Returns the locks step 1 acquires, empty for a held-lock context,
/// and the signing proof from the pin and status checks.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock`,
///   `rule_lock_missing`, `baseline_read` or `signer_set_compare`.
/// - The baseline-read refusals ([`SaError::SignerSetMissingBaseline`],
///   [`SaError::AuditLog`]), the pin-check refusals of [`run_pin_check`],
///   and the comparison refusals ([`SaError::SignerSetDiverged`],
///   [`SaError::NetworkRpcDivergence`] and the observation errors), each as
///   itself.
async fn run_rule_checks(
    pin_check: &PinCheck<'_>,
    rule_locks: Option<&BorrowedRuleLocks<'_>>,
    auth_rule_ids: &[ContextRuleId],
    smart_account: &ScAddress,
    source_account_strkey: &str,
    budget: PreSubmitBudget,
) -> Result<(Vec<RuleLockGuard>, CheckedSigningRules), SaError> {
    let manager = pin_check.signers_manager;
    let smart_account_strkey = scaddress_to_strkey(smart_account)?;
    let signing_ids = distinct_rule_ids(auth_rule_ids);
    let rule_ids: Vec<u32> = signing_ids
        .iter()
        .copied()
        .filter(|rule_id| *rule_id != 0)
        .collect();

    // Step 1: the locks.
    let owned = match rule_locks {
        None => {
            manager
                .acquire_rule_locks(&smart_account_strkey, rule_ids.iter().copied(), budget)
                .await?
        }
        Some(borrowed) => {
            // A guard counts only when it locks the rule on this account in
            // the log of the manager that checks it.
            if let Some(rule_id) = rule_ids.iter().copied().find(|rule_id| {
                borrowed
                    .guard_for(&smart_account_strkey, *rule_id)
                    .is_none_or(|guard| guard.audit_log_path() != manager.audit_log_path())
            }) {
                return Err(rule_lock_missing(rule_id));
            }
            Vec::new()
        }
    };
    let guard_of = |rule_id: u32| {
        match rule_locks {
            Some(borrowed) => borrowed.guard_for(&smart_account_strkey, rule_id),
            None => find_rule_guard(&owned, &smart_account_strkey, rule_id),
        }
        .ok_or_else(|| rule_lock_missing(rule_id))
    };

    // Step 2: the baseline reads, before any RPC.
    let mut baselines = Vec::with_capacity(rule_ids.len());
    for &rule_id in &rule_ids {
        let compared_by_holder =
            rule_locks.is_some_and(|borrowed| borrowed.compared_for(rule_id).is_some());
        if compared_by_holder {
            continue;
        }
        let baseline = bound_pre_submit_stage(
            budget,
            "baseline_read",
            "baseline_read",
            manager.read_baseline_locked(
                guard_of(rule_id)?,
                V1Handling::Compare,
                pin_check.request_id,
            ),
        )
        .await??;
        budget.check("baseline_read")?;
        baselines.push((rule_id, baseline));
    }

    // Step 3: the pinned-hash drift check.
    let checked = run_pin_check(pin_check, &signing_ids, smart_account, budget).await?;

    // Step 4: the signer-set comparisons.
    for (rule_id, baseline) in baselines {
        bound_pre_submit_stage(
            budget,
            "signer_set_compare",
            "signer_set_compare",
            manager.compare_locked(
                guard_of(rule_id)?,
                baseline,
                Some(source_account_strkey),
                pin_check.request_id,
            ),
        )
        .await??;
    }

    Ok((owned, checked))
}

/// Runs the pinned-hash drift check of each rule in `rule_ids`, the distinct
/// auth rules in ascending order, each bounded by `budget` as stage
/// `"pin_check"`; see [`PinCheck`] for the outcomes. Rule 0 is skipped, and
/// the returned proof binds every rule of `rule_ids`, rule 0 included.
///
/// # Errors
///
/// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
///   [`SaError::PinnedPolicyAbsent`] / [`SaError::PinnedVerifierAbsent`] /
///   [`SaError::WasmPinIncomplete`] unchanged from the check.
/// - [`SaError::VerifierWasmRevoked`] / [`SaError::VerifierWasmRetired`]
///   unchanged from the status gate, with no drift row.
/// - [`SaError::PinCheckUnavailable`] for every other failure, including the
///   budget elapsing.
/// - [`SaError::ScAddressEncodingFailed`] when the smart account has no
///   strkey form.
async fn run_pin_check(
    pin_check: &PinCheck<'_>,
    rule_ids: &[u32],
    smart_account: &ScAddress,
    budget: PreSubmitBudget,
) -> Result<CheckedSigningRules, SaError> {
    let smart_account_redacted = redact_strkey_first5_last5(&scaddress_to_strkey(smart_account)?);
    let mut cache = HashMap::new();
    for &rule_id in rule_ids {
        if rule_id == 0 {
            continue;
        }
        let outcome = bound_pre_submit_stage(
            budget,
            "pin_check",
            "auth_payload",
            check_rule_pins(
                pin_check,
                smart_account,
                rule_id,
                &smart_account_redacted,
                &mut cache,
                budget,
            ),
        )
        .await;
        let inner = match outcome {
            Ok(Ok(())) => continue,
            Ok(Err(
                refusal @ (SaError::VerifierHashDrift { .. }
                | SaError::PolicyHashDrift { .. }
                | SaError::PinnedPolicyAbsent { .. }
                | SaError::PinnedVerifierAbsent { .. }
                | SaError::WasmPinIncomplete { .. }
                | SaError::VerifierWasmRevoked { .. }
                | SaError::VerifierWasmRetired { .. }),
            )) => {
                return Err(refusal);
            }
            Ok(Err(inner)) | Err(inner) => inner,
        };
        tracing::warn!(
            rule_id,
            smart_account = %smart_account_redacted,
            error_code = inner.wire_code(),
            "pinned-hash drift check could not run; refusing before signing"
        );
        return Err(SaError::PinCheckUnavailable {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                smart_account_redacted.as_str(),
            ),
            reason: pin_check_reason(&inner),
            request_id: pin_check.request_id.to_owned(),
        });
    }
    Ok(CheckedSigningRules {
        smart_account: smart_account.clone(),
        network_id: pin_check.signers_manager.signing_network_id(),
        rule_ids: rule_ids.to_vec(),
    })
}

/// Checks one rule: fetches its verifier and policy addresses, compares
/// each verifier (unless the rule is the migrating rule) and each policy
/// against the rule's pin record, sharing `cache` across calls, then
/// refuses a rule with no policy on chain whose record pins policies. The
/// migrating rule skips its verifiers only; its policies are checked like
/// any rule's.
///
/// Each comparison and the presence check scan the audit log
/// synchronously; `budget` is checked after each, with the elapse identity
/// of the pin stage (`"auth_payload"`).
async fn check_rule_pins(
    pin_check: &PinCheck<'_>,
    smart_account: &ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    cache: &mut HashMap<Vec<u8>, crate::managers::signers::ObservedExecutable>,
    budget: PreSubmitBudget,
) -> Result<(), SaError> {
    let manager = pin_check.signers_manager;
    let (verifier_addrs, policy_addrs) = manager
        .fetch_verifier_and_policy_addresses(smart_account.clone(), rule_id, None)
        .await?;
    if pin_check.migrating_rule.map(|rule| rule.rule_id()) == Some(rule_id) {
        tracing::debug!(
            rule_id,
            "pinned-hash drift check: verifier check skipped for the migrating rule"
        );
    } else {
        for verifier_addr in verifier_addrs {
            verify_pinned_verifier_against_chain(
                manager,
                verifier_addr,
                rule_id,
                smart_account_redacted,
                pin_check.request_id,
                cache,
                crate::managers::verifiers::VerifierStatusGate::Refuse,
            )
            .await?;
            budget.check("auth_payload")?;
        }
    }
    for policy_addr in &policy_addrs {
        verify_pinned_policy_against_chain(
            manager,
            policy_addr.clone(),
            rule_id,
            smart_account_redacted,
            pin_check.request_id,
            cache,
        )
        .await?;
        budget.check("auth_payload")?;
    }
    verify_policy_pins_present(
        manager,
        rule_id,
        smart_account_redacted,
        pin_check.request_id,
        &policy_addrs,
    )?;
    budget.check("auth_payload")
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

/// Emits the caller-side `SaRawInvocation` failure row for a
/// [`submit_signed_invoke`] call that returned `Err`.
///
/// Implements the audit discipline documented at the top of this module: the
/// caller's `Err` arm records the domain-specific failure row (mapping the
/// [`SaError`] to a [`stellar_agent_core::audit_log::schema::SaInvocationResult`]
/// and the stable wire code) so failed value operations are not audit-silent.
///
/// Non-fatal: a write failure logs a `tracing::warn!` and does not change the
/// caller's error. `smart_account_redacted` MUST already be first-5-last-5
/// redacted. `context_rule_ids_count` is the number of context-rule ids passed
/// to the submit.
pub fn emit_sa_raw_invocation_failure(
    writer: &std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::AuditWriter>>,
    smart_account_redacted: &str,
    err: &SaError,
    context_rule_ids_count: u32,
    chain_id: Option<&str>,
    request_id: &str,
) {
    let result = crate::managers::rules::sa_error_to_invocation_result(err);
    let raw = stellar_agent_core::audit_log::AuditEntry::new_sa_raw_invocation(
        smart_account_redacted,
        err.wire_code(),
        None,
        context_rule_ids_count,
        result,
        chain_id,
        request_id,
    );
    match writer.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.write_entry(raw) {
                tracing::warn!(
                    error = %e,
                    "defi submit failure audit: write_entry failed; SaRawInvocation NOT emitted"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                "defi submit failure audit: writer mutex poisoned; SaRawInvocation NOT emitted"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    #[test]
    fn quorum_failure_keeps_intent_codes() {
        for error in [
            crate::SaError::IntentBindingMismatch { field: "signers" },
            crate::SaError::IntentRecordUnavailable {
                class: "window_unavailable",
            },
        ] {
            let code = error.wire_code();
            assert_eq!(
                super::quorum_failure_error(super::QuorumFailure::Intent(error), "fixture")
                    .wire_code(),
                code
            );
        }
    }

    use stellar_agent_core::error::WalletError;
    use stellar_agent_network::WebAuthnAssertion;
    use stellar_xdr::{
        AccountId, BytesM, ContractExecutable, ContractId, ContractIdPreimage,
        ContractIdPreimageFromAddress, CreateContractArgs, CreateContractArgsV2, Hash,
        InvokeContractArgs, PublicKey, ScAddress, ScSymbol, Uint256,
    };

    use super::*;

    /// A refusal the spending window decided reaches the smart-account
    /// surface as a policy denial, under the criterion's own code.
    ///
    /// Reporting it as a deployment failure would send an agent to rebuild and
    /// re-submit against a cap that has already refused it.
    #[test]
    fn a_policy_refusal_keeps_its_code_through_the_submit_mapping() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let mapped = map_submit_error(&err, "multicall", "AAAAAgAAAAA=");
        assert_eq!(mapped.wire_code(), "policy.deny.per_period_cap_exceeded");
        assert!(
            matches!(mapped, SaError::PolicyDenied { .. }),
            "expected a typed policy denial, got {mapped:?}"
        );
    }

    /// Every other submit failure is still a deployment failure at the submit
    /// phase.
    #[test]
    fn a_malformed_transaction_is_still_a_deployment_failure() {
        let err =
            WalletError::Submission(stellar_agent_core::error::SubmissionError::TxMalformed {
                detail: "txINSUFFICIENT_FEE".to_owned(),
            });
        assert_eq!(
            map_submit_error(&err, "multicall", "AAAAAgAAAAA=").wire_code(),
            "sa.deployment_failed"
        );
    }

    /// A submit-layer mainnet refusal, such as an endpoint that reports the
    /// mainnet passphrase, keeps the canonical code.
    #[test]
    fn a_submit_layer_mainnet_refusal_keeps_the_canonical_code() {
        let err =
            WalletError::Network(stellar_agent_core::error::NetworkError::MainnetWriteForbidden);
        let mapped = map_submit_error(&err, "multicall", "AAAAAgAAAAA=");
        assert!(
            matches!(mapped, SaError::MainnetWriteForbidden),
            "expected the mainnet refusal, got {mapped:?}"
        );
        assert_eq!(mapped.wire_code(), "network.mainnet_write_forbidden");
    }

    /// A send-by deadline that passes before a resend, after a send whose
    /// answer was lost, maps as the unresolved timeout of the transaction
    /// sent, so the caller reconciles its hash. One that passes before
    /// anything was sent maps as the pre-submit refusal of its stage.
    #[tokio::test]
    async fn a_resend_refused_at_the_deadline_is_an_unresolved_submission() {
        let budget = PreSubmitBudget {
            deadline: tokio::time::Instant::now(),
            total: std::time::Duration::from_secs(5),
        };
        let tx_hash = "ab".repeat(32);

        let mapped = map_sent_by_error(
            SentByError::Elapsed {
                stage: stellar_agent_network::PreSendStage::Send,
                sent_tx_hash: Some(tx_hash.clone()),
            },
            budget,
            std::time::Duration::from_secs(30),
            "multicall",
            "AAAAAgAAAAA=",
        );
        assert_eq!(mapped.wire_code(), "submission.tx_timeout");
        match &mapped {
            SaError::SubmissionUnresolved {
                tx_hash: Some(reported),
                timeout_seconds: Some(30),
                envelope_hash: Some(_),
                ..
            } => assert_eq!(reported, &tx_hash),
            other => panic!("expected the unresolved submission, got {other:?}"),
        }

        let refused = map_sent_by_error(
            SentByError::Elapsed {
                stage: stellar_agent_network::PreSendStage::Send,
                sent_tx_hash: None,
            },
            budget,
            std::time::Duration::from_secs(30),
            "multicall",
            "AAAAAgAAAAA=",
        );
        match &refused {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason,
            } => assert!(
                redacted_reason
                    .starts_with("send_transaction exceeded collective pre-submit budget"),
                "{redacted_reason}"
            ),
            other => panic!("expected the pre-submit refusal, got {other:?}"),
        }
    }

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

    /// `emit_sa_raw_invocation_failure` writes exactly one `sa_raw_invocation`
    /// row carrying the error's wire code and the mapped invocation result.
    ///
    /// This is the offline (push-CI) guard for the DeFi adapters' Err-arm
    /// emission plumbing: a `submit`-phase `SaError` maps to `on_chain_rejected`
    /// and the row records the redacted smart account, the wire code, and the
    /// context-rule count. The adapter call sites (which invoke this helper in
    /// their submit Err arm) are additionally covered by the DeFi testnet
    /// acceptance tests.
    #[test]
    fn emit_sa_raw_invocation_failure_writes_a_raw_invocation_row() {
        use std::io::BufRead as _;
        use std::sync::{Arc, Mutex};
        use stellar_agent_core::audit_log::AuditWriter;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));

        let err = SaError::DeploymentFailed {
            phase: "submit",
            redacted_reason: "on-chain rejected: GBPXX...MWIVL".to_owned(),
        };
        emit_sa_raw_invocation_failure(
            &writer,
            "CAAAA…D2KM",
            &err,
            1,
            Some("stellar:testnet"),
            "req-sa-1",
        );

        let file = std::fs::File::open(&path).unwrap();
        let rows: Vec<serde_json::Value> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();

        assert_eq!(rows.len(), 1, "exactly one row must be written");
        let row = &rows[0];
        assert_eq!(row["kind"], "sa_raw_invocation", "row kind");
        assert_eq!(row["wire_code"], "sa.deployment_failed", "error wire code");
        assert_eq!(
            row["result"], "on_chain_rejected",
            "a submit-phase failure maps to on_chain_rejected"
        );
        assert_eq!(row["context_rule_ids_count"], 1, "context-rule count");
        assert_eq!(row["chain_id"], "stellar:testnet", "chain id");
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
        async fn sign_tx_payload(
            &self,
            _: &stellar_agent_network::signing::TxSigningPayload,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_auth_digest(
            &self,
            _: &stellar_agent_network::signing::SmartAccountAuthDigest,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_soroban_address_auth_payload(
            &self,
            _: &stellar_agent_network::signing::SorobanAuthPayload,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub — not called by check_required tests")
        }
        async fn sign_message(
            &self,
            _: &stellar_agent_network::signing::MessagePayload,
        ) -> Result<[u8; 64], WalletError> {
            unimplemented!("stub: not called by check_required tests")
        }
        async fn sign_webauthn_assertion(
            &self,
            _: &stellar_agent_network::signing::SmartAccountAuthDigest,
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
            .admission(stellar_agent_network::SigningAdmission::NoValue(
                crate::signing::intent_test_helpers::no_value_admission(),
            ))
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

    #[tokio::test]
    #[serial_test::serial]
    async fn muxed_contract_submit_intake_refuses_before_admission() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let signer = stellar_agent_network::signing::test_doubles::CountingSigner::new([5; 32]);
        let endpoint = format!("http://{}:9", std::net::Ipv4Addr::LOCALHOST);
        let secondary = format!("http://{}:9", std::net::Ipv4Addr::new(127, 0, 0, 2));
        let mut args = minimal_args(None, &[]);
        args.signer = &signer;
        args.primary_rpc_url = &endpoint;
        args.secondary_rpc_url = Some(&secondary);
        args.network_passphrase = stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
        args.host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: stellar_agent_test_support::xdr_fixtures::muxed_contract_address(),
            ..Default::default()
        });
        let error = submit_signed_invoke(args).await.unwrap_err();
        assert_eq!(signer.sign_calls(), 0);
        assert_eq!(signer.key_accesses(), 0);
        assert_eq!(error.wire_code(), "sa.deployment_failed");
        assert!(
            error
                .to_string()
                .ends_with("a muxed contract address (W) is not accepted on this path")
        );
    }

    /// `check_required` with `required_checks = &["multicall"]` and a
    /// fully-populated `MulticallCheck` returns `Ok(())`.
    #[test]
    #[serial_test::serial]
    fn check_required_passes_when_multicall_check_present() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mc = MulticallCheck {
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

    /// `multicall_check: Some(_)` without `"multicall"` in `required_checks`
    /// is refused with a typed error in every build profile.
    #[test]
    #[serial_test::serial]
    fn submit_guard_refuses_an_undeclared_multicall_check() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mc = MulticallCheck {
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        let args = minimal_args(Some(mc), &[]);
        let err = validate_submit_invoke_args(&args).unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "multicall_check_undeclared",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    /// Positive companion: `multicall_check: Some(_)` paired with
    /// `"multicall"` in `required_checks`, and no multicall check at all,
    /// both pass the guard.
    #[test]
    #[serial_test::serial]
    fn submit_guard_accepts_a_declared_or_absent_multicall_check() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mc = MulticallCheck {
            registry_entry_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            registry_entry_wasm_sha256:
                "267e94a092df01fa02ad4edf8320a98bd65e4d4d6575254ac9521cb65727f3d4".to_owned(),
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
        };
        validate_submit_invoke_args(&minimal_args(Some(mc), &["multicall"])).unwrap();
        validate_submit_invoke_args(&minimal_args(None, &[])).unwrap();
    }

    /// `check_required` with `required_checks = &["multicall"]` and
    /// `multicall_check = None` returns `Err(SubmitCheckMissing)`.
    #[test]
    #[serial_test::serial]
    fn check_required_fails_when_multicall_check_missing() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let args = minimal_args(None, &["multicall"]);
        let hf_kind = host_function_kind_str(&args.host_function);
        let err = check_required(&args, "multicall", hf_kind).unwrap_err();
        assert_eq!(err.wire_code(), "sa.submit_check_missing");
    }

    /// When `required_checks = &[]`, `check_required` is never called and the
    /// gate is a no-op — preserving behaviour for callers that pass an empty
    /// slice.
    #[test]
    #[serial_test::serial]
    fn check_required_passes_when_required_check_not_listed() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
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
    #[serial_test::serial]
    fn check_required_fails_on_unknown_check_name() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        // multicall_check is Some — should not matter for an unrecognised name.
        let mc = MulticallCheck {
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
        // Uses the workspace `stellar_xdr` types, a direct dependency of
        // stellar-agent-smart-account, so every value below shares one XDR
        // type family.
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

    // ── Ed25519RuleSigner: mutual-exclusivity guard ──────────────────────────

    /// `submit_signed_invoke` refuses immediately — before any network I/O —
    /// when a caller supplies both `authorization` (quorum) and
    /// `ed25519_rule_signer`. The guard is the first statement in the
    /// function body, ahead of the required-check loop and every `.await`
    /// that touches the network, so this test drives the real production
    /// function (not a stand-in) without a live RPC endpoint: `primary_rpc_url`
    /// is a URL that is never dialed.
    #[tokio::test]
    #[serial_test::serial]
    async fn submit_signed_invoke_rejects_ed25519_rule_signer_with_quorum_before_network_io() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        use crate::managers::authorization::{AuthorizationInfo, Combinator};
        use stellar_agent_network::SoftwareSigningKey;

        let dummy_strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let rule_signer_key = SoftwareSigningKey::new_from_bytes([0x21u8; 32]);
        let verifier = ScAddress::Contract(ContractId(Hash([0x22u8; 32])));
        let authz = AuthorizationInfo::new(vec![], Combinator::And);

        let args = SubmitInvokeArgs::builder()
            .admission(stellar_agent_network::SigningAdmission::NoValue(
                crate::signing::intent_test_helpers::no_value_admission(),
            ))
            .target_contract(dummy_strkey)
            .auth_rule_ids(&[])
            .host_function(HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol::try_from("fn").unwrap(),
                args: VecM::default(),
            }))
            .signer(&STUB_SIGNER)
            .primary_rpc_url("http://stub-must-not-be-dialed.invalid")
            .network_passphrase("stub")
            .chain_id("stub")
            .timeout(std::time::Duration::from_secs(10))
            .op_label("test_op")
            .maybe_authorization(Some(&authz))
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: &rule_signer_key,
                verifier,
            })
            .build();

        let err = submit_signed_invoke(args).await.unwrap_err();
        assert_eq!(err.wire_code(), "sa.auth_entry_construction_failed");
    }

    // ── Mainnet refusal before the signer and the endpoint ──────────────────

    /// `SubmitInvokeArgs` over [`StubSigner`], whose every method panics, for
    /// `network_passphrase` and `primary_rpc_url`.
    fn mainnet_refusal_args<'a>(
        network_passphrase: &'a str,
        primary_rpc_url: &'a str,
    ) -> SubmitInvokeArgs<'a> {
        SubmitInvokeArgs::builder()
            .admission(stellar_agent_network::SigningAdmission::NoValue(
                crate::signing::intent_test_helpers::no_value_admission(),
            ))
            .target_contract("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM")
            .auth_rule_ids(&[])
            .host_function(HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol::try_from("fn").unwrap(),
                args: VecM::default(),
            }))
            .signer(&STUB_SIGNER)
            .primary_rpc_url(primary_rpc_url)
            .network_passphrase(network_passphrase)
            .chain_id("stellar:mainnet")
            .timeout(std::time::Duration::from_secs(10))
            .op_label("test_op")
            .build()
    }

    /// The mainnet passphrase is refused with the canonical code before the
    /// signer, which panics on any call, and before any request to the mock
    /// primary endpoint.
    #[tokio::test]
    #[serial_test::serial]
    async fn submit_signed_invoke_refuses_mainnet_passphrase_before_signer_and_request() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mock = wiremock::MockServer::start().await;
        let primary = mock.uri();
        let args = mainnet_refusal_args(
            stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            &primary,
        );
        let err = submit_signed_invoke(args).await.unwrap_err();
        assert!(
            matches!(err, SaError::MainnetWriteForbidden),
            "expected the mainnet refusal, got {err:?}"
        );
        assert_eq!(err.wire_code(), "network.mainnet_write_forbidden");
        assert!(
            mock.received_requests().await.unwrap().is_empty(),
            "a refused mainnet submission must send no request"
        );
    }

    /// A testnet passphrase with a dialable mainnet-pattern primary URL is
    /// refused the same way.
    #[tokio::test]
    #[serial_test::serial]
    async fn submit_signed_invoke_refuses_mainnet_pattern_url_before_signer_and_request() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let mock = wiremock::MockServer::start().await;
        let primary = format!("{}/pubnet", mock.uri());
        let args = mainnet_refusal_args(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            &primary,
        );
        let err = submit_signed_invoke(args).await.unwrap_err();
        assert!(
            matches!(err, SaError::MainnetWriteForbidden),
            "expected the mainnet refusal, got {err:?}"
        );
        assert!(
            mock.received_requests().await.unwrap().is_empty(),
            "a refused mainnet submission must send no request"
        );
    }

    // ── Ed25519RuleSigner: single-signer routing composition ────────────────

    /// The External-Ed25519 single-signer arm added to `submit_signed_invoke`
    /// (Step 5) reuses `collect_mixed_signer_entries` with a single
    /// `ExternalEd25519` descriptor. This test exercises the exact composition
    /// the arm performs — build a partial via `build_authorization_entry`
    /// (pure computation, no network I/O), patch `partial.smart_account` to
    /// the wallet address (the same credential patch the arm applies for
    /// external-contract calls), then sign via the mixed-signer collector —
    /// and asserts:
    ///  - exactly one `SorobanAuthorizationEntry` is produced (no G-key
    ///    sub-entry, per the OZ `authenticate(External)` on-chain branch,
    ///    `storage.rs:341-350`, SHA `a9c4216`);
    ///  - the entry's credential address is the patched wallet address, not
    ///    the invocation-target contract the partial was originally built for
    ///    (the external-contract shape, e.g. `SAC.transfer` invoked as a
    ///    sub-invocation of an external router).
    #[tokio::test]
    #[serial_test::serial]
    async fn ed25519_rule_signer_arm_patches_credential_and_omits_g_key() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        use crate::managers::auth_entry::{
            MixedSigner, MixedSignerKind, build_authorization_entry, collect_mixed_signer_entries,
        };
        use crate::signing::divergence::AuthContextFingerprint;
        use stellar_agent_network::SoftwareSigningKey;

        let rule_ids = vec![ContextRuleId::new(0)];
        let context = SimulationContext {
            context_rule_ids: rule_ids.clone(),
            auth_contexts: vec![AuthContextFingerprint::new(
                "invoke:ed25519-rule-test".to_owned(),
            )],
            network: NetworkContext {
                passphrase_fingerprint: "testnet".to_owned(),
                ledger_protocol_version: 23,
                chain_id_fingerprint: "00112233".to_owned(),
            },
            sequence: SequenceContext {
                source_account_sequence: 100,
                min_sequence_number: None,
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
            network_id: crate::managers::auth_entry::network_id_of(
                "Test SDF Network ; September 2015",
            ),
            nonce: 123,
            signature_expiration_ledger: 456,
        };

        // The invocation-target contract differs from the wallet address —
        // mirroring the external-contract shape.
        let invocation_target = ScAddress::Contract(ContractId(Hash([0x30u8; 32])));
        let wallet_address = ScAddress::Contract(ContractId(Hash([0x40u8; 32])));
        let verifier = ScAddress::Contract(ContractId(Hash([0x50u8; 32])));

        let mut partial = build_authorization_entry(
            invocation_target,
            ScSymbol::try_from("transfer").unwrap(),
            vec![],
            rule_ids,
            &simulation,
            &envelope,
        )
        .await
        .unwrap();

        // The credential-address patch `submit_signed_invoke`'s single-signer
        // branch applies before routing to either signing arm.
        partial.smart_account = wallet_address.clone();

        let rule_signer_key = SoftwareSigningKey::new_from_bytes([0x60u8; 32]);
        let mixed_signers = [MixedSigner {
            signer: &rule_signer_key,
            kind: MixedSignerKind::ExternalEd25519 {
                verifier: verifier.clone(),
            },
        }];

        let entries = collect_mixed_signer_entries(
            &crate::signing::intent_test_helpers::mixed_gate(&partial, &mixed_signers).await,
            crate::submit::checked_rules_for_test(&partial),
            partial,
            &mixed_signers,
            simulation.signature_expiration_ledger,
            "Test SDF Network ; September 2015",
        )
        .await
        .unwrap();

        assert_eq!(
            entries.len(),
            1,
            "External-Ed25519 single-signer arm must produce exactly one entry \
             (no G-key sub-entry)"
        );
        let SorobanCredentials::Address(creds) = &entries[0].credentials else {
            panic!("entry must carry Address credentials");
        };
        assert_eq!(
            creds.address, wallet_address,
            "credential address must be the patched wallet address, not the \
             invocation-target contract"
        );
    }

    // ── Signed-tree checks ───────────────────────────────────────────────────

    mod signed_tree {
        use stellar_xdr::{
            ContractId, Hash, Int128Parts, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        };

        use super::super::{
            DeclaredSubInvocations, DeclaredTransfer, check_declared_sub_invocations,
            check_simulated_root,
        };
        use crate::SaError;
        use crate::error::SimulationDivergenceSubCode;

        fn contract(byte: u8) -> ScAddress {
            ScAddress::Contract(ContractId(Hash([byte; 32])))
        }

        fn wallet() -> ScAddress {
            contract(0x57)
        }

        fn token() -> ScAddress {
            contract(0x70)
        }

        fn other() -> ScAddress {
            contract(0xAA)
        }

        fn call(target: ScAddress, function: &str, args: Vec<ScVal>) -> InvokeContractArgs {
            InvokeContractArgs {
                contract_address: target,
                function_name: ScSymbol(function.try_into().unwrap()),
                args: args.try_into().unwrap(),
            }
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
        )]
        fn amount(value: i128) -> ScVal {
            ScVal::I128(Int128Parts {
                hi: (value >> 64) as i64,
                lo: value as u64,
            })
        }

        fn transfer(
            token: ScAddress,
            from: ScAddress,
            to: ScAddress,
            value: i128,
        ) -> InvokeContractArgs {
            call(
                token,
                "transfer",
                vec![ScVal::Address(from), ScVal::Address(to), amount(value)],
            )
        }

        fn leaf(call: InvokeContractArgs) -> SorobanAuthorizedInvocation {
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call),
                sub_invocations: Default::default(),
            }
        }

        fn with_child(
            call: InvokeContractArgs,
            child: SorobanAuthorizedInvocation,
        ) -> SorobanAuthorizedInvocation {
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call),
                sub_invocations: vec![child].try_into().unwrap(),
            }
        }

        /// The reason of a signed-tree refusal; panics on anything else.
        fn refusal(result: Result<(), SaError>) -> String {
            match result {
                Err(SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::AuthContexts,
                    redacted_reason,
                }) => redacted_reason,
                other => panic!("expected the auth-contexts divergence, got {other:?}"),
            }
        }

        fn check(
            subs: &[SorobanAuthorizedInvocation],
            declared: &DeclaredSubInvocations<'_>,
        ) -> Result<(), SaError> {
            check_declared_sub_invocations(subs, declared, &wallet())
        }

        const BOUND: i128 = 100;

        fn bounded(to: Option<ScAddress>) -> [DeclaredTransfer; 1] {
            [DeclaredTransfer {
                token: token(),
                to,
                max_amount: BOUND,
            }]
        }

        #[test]
        fn the_root_must_be_the_host_function() {
            let wallet_call = call(wallet(), "set_limit", vec![ScVal::U32(5)]);
            let as_fn = |call: InvokeContractArgs| SorobanAuthorizedFunction::ContractFn(call);

            check_simulated_root(&as_fn(wallet_call.clone()), &wallet_call).unwrap();

            let mut on_other = wallet_call.clone();
            on_other.contract_address = other();
            assert!(
                refusal(check_simulated_root(&as_fn(on_other), &wallet_call))
                    .contains("in its contract")
            );

            let mut renamed = wallet_call.clone();
            renamed.function_name = ScSymbol("upgrade".try_into().unwrap());
            assert!(
                refusal(check_simulated_root(&as_fn(renamed), &wallet_call))
                    .contains("in its function")
            );

            let mut longer = wallet_call.clone();
            longer.args = vec![ScVal::U32(5), ScVal::U32(6)].try_into().unwrap();
            assert!(
                refusal(check_simulated_root(&as_fn(longer), &wallet_call))
                    .contains("in its argument count (2 against 1)")
            );

            let mut changed = wallet_call.clone();
            changed.args = vec![ScVal::U32(6)].try_into().unwrap();
            assert!(
                refusal(check_simulated_root(&as_fn(changed), &wallet_call))
                    .contains("in argument 0")
            );

            let not_a_call =
                SorobanAuthorizedFunction::CreateContractHostFn(stellar_xdr::CreateContractArgs {
                    contract_id_preimage: stellar_xdr::ContractIdPreimage::Address(
                        stellar_xdr::ContractIdPreimageFromAddress {
                            address: wallet(),
                            salt: stellar_xdr::Uint256([0; 32]),
                        },
                    ),
                    executable: stellar_xdr::ContractExecutable::StellarAsset,
                });
            assert!(
                refusal(check_simulated_root(&not_a_call, &wallet_call))
                    .contains("not a contract call")
            );
        }

        #[test]
        fn none_accepts_only_an_empty_subtree() {
            check(&[], &DeclaredSubInvocations::None).unwrap();
            let drain = leaf(transfer(token(), wallet(), other(), 1));
            assert!(
                refusal(check(&[drain], &DeclaredSubInvocations::None))
                    .contains("1 undeclared sub-invocations")
            );
        }

        #[test]
        fn a_declared_transfer_within_its_bound_is_accepted() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            check(
                &[leaf(transfer(token(), wallet(), other(), BOUND))],
                &declaration,
            )
            .unwrap();
            check(
                &[
                    leaf(transfer(token(), wallet(), other(), BOUND / 2)),
                    leaf(transfer(token(), wallet(), other(), BOUND / 2)),
                ],
                &declaration,
            )
            .unwrap();
            check(&[], &declaration).unwrap();
        }

        #[test]
        fn a_transfer_above_its_bound_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            assert!(
                refusal(check(
                    &[leaf(transfer(token(), wallet(), other(), BOUND + 1))],
                    &declaration
                ))
                .contains("through sub-invocation 0 exceed the declared bound")
            );
        }

        #[test]
        fn two_transfers_above_the_bound_together_are_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            let part = BOUND / 2 + 1;
            assert!(
                refusal(check(
                    &[
                        leaf(transfer(token(), wallet(), other(), part)),
                        leaf(transfer(token(), wallet(), other(), part)),
                    ],
                    &declaration,
                ))
                .contains("through sub-invocation 1 exceed the declared bound")
            );
        }

        #[test]
        fn a_sum_that_overflows_is_refused() {
            let declared = [DeclaredTransfer {
                token: token(),
                to: None,
                max_amount: i128::MAX,
            }];
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            assert!(
                refusal(check(
                    &[
                        leaf(transfer(token(), wallet(), other(), i128::MAX)),
                        leaf(transfer(token(), wallet(), other(), 1)),
                    ],
                    &declaration,
                ))
                .contains("exceed the declared bound")
            );
        }

        #[test]
        fn a_negative_amount_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            assert!(
                refusal(check(
                    &[
                        leaf(transfer(token(), wallet(), other(), -BOUND)),
                        leaf(transfer(token(), wallet(), other(), BOUND)),
                    ],
                    &declaration,
                ))
                .contains("sub-invocation 0 transfers a negative amount")
            );
        }

        #[test]
        fn a_transfer_on_another_token_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            assert!(
                refusal(check(
                    &[leaf(transfer(other(), wallet(), other(), 1))],
                    &declaration
                ))
                .contains("on an undeclared token")
            );
        }

        #[test]
        fn a_transfer_from_another_address_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            assert!(
                refusal(check(
                    &[leaf(transfer(token(), other(), other(), 1))],
                    &declaration
                ))
                .contains("from an address other than the authorizing one")
            );
        }

        #[test]
        fn a_declared_transfer_to_another_recipient_is_refused() {
            let declared = bounded(Some(contract(0x73)));
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            check(
                &[leaf(transfer(token(), wallet(), contract(0x73), 1))],
                &declaration,
            )
            .unwrap();
            assert!(
                refusal(check(
                    &[leaf(transfer(token(), wallet(), other(), 1))],
                    &declaration
                ))
                .contains("to an undeclared recipient")
            );
        }

        #[test]
        fn another_shape_than_transfer_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            let approve = call(
                token(),
                "approve",
                vec![ScVal::Address(wallet()), ScVal::Address(other()), amount(1)],
            );
            let short = call(
                token(),
                "transfer",
                vec![ScVal::Address(wallet()), amount(1)],
            );
            let wrong_amount = call(
                token(),
                "transfer",
                vec![
                    ScVal::Address(wallet()),
                    ScVal::Address(other()),
                    ScVal::U64(1),
                ],
            );
            for shape in [approve, short, wrong_amount] {
                assert!(
                    refusal(check(&[leaf(shape)], &declaration))
                        .contains("is not a transfer(from, to, amount) call")
                );
            }
        }

        #[test]
        fn a_nested_node_under_a_transfer_is_refused() {
            let declared = bounded(None);
            let declaration = DeclaredSubInvocations::TokenTransfers(&declared);
            let nested = with_child(
                transfer(token(), wallet(), other(), 1),
                leaf(transfer(token(), wallet(), other(), 1)),
            );
            assert!(
                refusal(check(&[nested], &declaration))
                    .contains("sub-invocation 0 carries nested sub-invocations")
            );
        }

        fn first() -> InvokeContractArgs {
            call(contract(0x81), "deposit", vec![ScVal::U32(1)])
        }

        fn second() -> InvokeContractArgs {
            call(contract(0x82), "stake", vec![ScVal::U32(2)])
        }

        #[test]
        fn declared_calls_in_order_are_accepted() {
            let declared = [first(), second()];
            let declaration = DeclaredSubInvocations::Calls(&declared);
            check(&[leaf(first()), leaf(second())], &declaration).unwrap();
            check(&[leaf(second())], &declaration).unwrap();
            check(&[], &declaration).unwrap();
        }

        #[test]
        fn an_extra_or_reordered_call_is_refused() {
            let declared = [first(), second()];
            let declaration = DeclaredSubInvocations::Calls(&declared);
            for subs in [
                vec![leaf(second()), leaf(first())],
                vec![leaf(first()), leaf(first())],
                vec![leaf(first()), leaf(transfer(token(), wallet(), other(), 1))],
            ] {
                assert!(
                    refusal(check(&subs, &declaration))
                        .contains("sub-invocation 1 is not a declared call in declared order")
                );
            }
            let mut changed = first();
            changed.args = vec![ScVal::U32(9)].try_into().unwrap();
            assert!(
                refusal(check(&[leaf(changed)], &declaration))
                    .contains("sub-invocation 0 is not a declared call")
            );
            let nested = with_child(first(), leaf(second()));
            assert!(
                refusal(check(&[nested], &declaration))
                    .contains("sub-invocation 0 carries nested sub-invocations")
            );
        }
    }

    // ── The ledger witness ──────────────────────────────────────────────────

    mod witness {
        use std::sync::Mutex;
        use std::time::Duration;

        use async_trait::async_trait;
        use sha2::{Digest, Sha256};
        use stellar_agent_core::error::WalletError;
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
        use stellar_agent_core::smart_account::rule_id::{ContextRuleId, encode_context_rule_ids};
        use stellar_agent_network::WebAuthnAssertion;
        use stellar_agent_network::signing::test_doubles::CountingSigner;
        use stellar_agent_network::signing::{
            MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
        };
        use stellar_agent_test_support::auth_tree_rpc::{AuthTreeEndpoint, AuthTreeRpc};
        use stellar_agent_test_support::second_loopback_host;
        use stellar_agent_test_support::signed_envelope::{
            account_id_for_seed, public_key_for_seed,
        };
        use stellar_xdr::{
            ContractExecutable, ContractId, Hash, HostFunction, InvokeContractArgs, Limits,
            OperationBody, ScAddress, ScContractInstance, ScSymbol, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
            TransactionEnvelope, WriteXdr,
        };

        use super::super::{
            DeclaredSubInvocations, Ed25519RuleSigner, HorizonCheck, MulticallCheck,
            SubmitInvokeArgs, SubmitInvokeResult, submit_signed_invoke,
        };
        use crate::SaError;
        use crate::managers::auth_entry::{network_id_of, soroban_authorization_preimage};
        use crate::managers::authorization::{AuthorizationInfo, Combinator, SignerGroup};
        use crate::multicall::MULTICALL_WASM_SHA256;
        use crate::signing::recovery_test_fixtures::{
            REPLACEMENT_VALUE, RecoveryCase, recovery_response,
        };

        const SEED: [u8; 32] = [0x61; 32];
        const WALLET: [u8; 32] = [0x62; 32];
        const LEDGER: u32 = 1000;
        const SKEW_CODE: &str = "simulation.divergence.ledger_skew";
        const UNAVAILABLE_CODE: &str = "smart_account.ledger_witness_unavailable";

        fn wallet() -> ScAddress {
            ScAddress::Contract(ContractId(Hash(WALLET)))
        }

        fn wallet_strkey() -> String {
            stellar_strkey::Contract(WALLET).to_string().to_string()
        }

        /// The call the simulated tree places under a multicall's `exec`.
        fn nested_call() -> InvokeContractArgs {
            InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0x63; 32]))),
                function_name: ScSymbol("nested".try_into().unwrap()),
                args: Default::default(),
            }
        }

        fn leaf(call: InvokeContractArgs) -> SorobanAuthorizedInvocation {
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call),
                sub_invocations: Default::default(),
            }
        }

        /// The honest tree of `invoke`: a multicall's `exec` carries the nested
        /// call, every other call stands alone.
        fn tree_of(invoke: &InvokeContractArgs) -> SorobanAuthorizedInvocation {
            let subs = if invoke.function_name.0.as_slice() == b"exec" {
                vec![leaf(nested_call())]
            } else {
                Vec::new()
            };
            SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                sub_invocations: subs.try_into().unwrap(),
            }
        }

        /// An endpoint for `passphrase` at `ledger` that serves the wallet as
        /// the registered multicall router.
        fn endpoint_on(passphrase: &str, ledger: u32) -> AuthTreeRpc {
            let wasm_hash: [u8; 32] = hex::decode(MULTICALL_WASM_SHA256)
                .unwrap()
                .try_into()
                .unwrap();
            AuthTreeRpc::new(passphrase, wallet())
                .account(&account_id_for_seed(SEED))
                .instance(
                    wallet(),
                    ScContractInstance {
                        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
                        storage: None,
                    },
                )
                .latest_ledger(ledger)
                .tree(|invoke| Some(tree_of(invoke)))
        }

        fn endpoint(ledger: u32) -> AuthTreeRpc {
            endpoint_on(TESTNET_PASSPHRASE, ledger)
        }

        /// A counting signer that keeps every authorization digest it signs,
        /// smart-account and classic, and whose envelope signature takes
        /// `envelope_delay` when one is set, as a hardware device's can.
        struct RecordingSigner {
            inner: CountingSigner,
            auth_digests: Mutex<Vec<[u8; 32]>>,
            envelope_delay: Option<Duration>,
            fail_auth: bool,
        }

        impl RecordingSigner {
            fn new() -> Self {
                Self {
                    inner: CountingSigner::new(SEED),
                    auth_digests: Mutex::new(Vec::new()),
                    envelope_delay: None,
                    fail_auth: false,
                }
            }

            fn with_envelope_delay(delay: Duration) -> Self {
                Self {
                    envelope_delay: Some(delay),
                    ..Self::new()
                }
            }
        }

        #[async_trait]
        impl Signer for RecordingSigner {
            async fn sign_tx_payload(
                &self,
                payload: &TxSigningPayload,
            ) -> Result<[u8; 64], WalletError> {
                if let Some(delay) = self.envelope_delay {
                    tokio::time::sleep(delay).await;
                }
                self.inner.sign_tx_payload(payload).await
            }

            async fn sign_auth_digest(
                &self,
                digest: &SmartAccountAuthDigest,
            ) -> Result<[u8; 64], WalletError> {
                self.auth_digests.lock().unwrap().push(*digest.as_bytes());
                let result = self.inner.sign_auth_digest(digest).await;
                if self.fail_auth {
                    return Err(WalletError::Submission(
                        stellar_agent_core::SubmissionError::IntentRecordUnavailable {
                            class: "fixture_signer",
                        },
                    ));
                }
                result
            }

            async fn sign_soroban_address_auth_payload(
                &self,
                payload: &SorobanAuthPayload,
            ) -> Result<[u8; 64], WalletError> {
                self.auth_digests.lock().unwrap().push(*payload.as_bytes());
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

            async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
                self.inner.public_key().await
            }
        }

        #[derive(Clone, Copy, Debug)]
        enum SigningPath {
            Single,
            Multicall,
        }

        const PATHS: [SigningPath; 2] = [SigningPath::Single, SigningPath::Multicall];

        impl SigningPath {
            fn rule_ids(self) -> Vec<ContextRuleId> {
                match self {
                    Self::Single => vec![ContextRuleId::new(0)],
                    Self::Multicall => vec![ContextRuleId::new(0), ContextRuleId::new(0)],
                }
            }

            fn host_function(self) -> HostFunction {
                let function = match self {
                    Self::Single => "noop",
                    Self::Multicall => "exec",
                };
                HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: wallet(),
                    function_name: ScSymbol(function.try_into().unwrap()),
                    args: Default::default(),
                })
            }
        }

        struct Outcome {
            result: Result<SubmitInvokeResult, SaError>,
            signs: usize,
            /// Public-key reads of the envelope signer.
            key_reads: usize,
            auth_digests: Vec<[u8; 32]>,
            signed_simulations: usize,
            sent: Vec<TransactionEnvelope>,
        }

        impl Outcome {
            /// Asserts the refusal `code` before any signing primitive, any
            /// signed re-simulation and any send.
            fn assert_refused(&self, code: &str, case: &str) {
                match &self.result {
                    Err(error) => assert_eq!(error.wire_code(), code, "{case}: {error:?}"),
                    Ok(_) => panic!("{case}: the submission went through"),
                }
                assert_eq!(self.signs, 0, "{case}: nothing is signed");
                assert_eq!(self.signed_simulations, 0, "{case}: nothing re-simulated");
                assert!(self.sent.is_empty(), "{case}: nothing is sent");
            }

            /// Asserts that every signed entry of the sent envelope carries
            /// `expiry` and that the digest signed for it commits to `expiry`:
            /// the smart account's own entry over its rule ids, a delegated
            /// signer's entry over its preimage alone.
            fn assert_every_signature_expires_at(
                &self,
                expiry: u32,
                rule_ids: &[ContextRuleId],
                case: &str,
            ) {
                assert!(
                    self.result.is_ok(),
                    "{case}: {:?}",
                    self.result.as_ref().err()
                );
                let [TransactionEnvelope::Tx(envelope)] = self.sent.as_slice() else {
                    panic!("{case}: one sent v1 envelope")
                };
                let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
                    panic!("{case}: an invoke operation")
                };
                assert!(!op.auth.is_empty(), "{case}: a signed entry");
                let rule_ids_xdr = encode_context_rule_ids(rule_ids).unwrap();
                for entry in op.auth.iter() {
                    let SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(credentials),
                        root_invocation,
                    } = entry
                    else {
                        panic!("{case}: address credentials")
                    };
                    assert_eq!(credentials.signature_expiration_ledger, expiry, "{case}");
                    let preimage = soroban_authorization_preimage(
                        network_id_of(TESTNET_PASSPHRASE),
                        credentials.nonce,
                        expiry,
                        root_invocation.clone(),
                    );
                    let digest = if credentials.address == wallet() {
                        *SmartAccountAuthDigest::new(&preimage, &rule_ids_xdr)
                            .unwrap()
                            .as_bytes()
                    } else {
                        let preimage_xdr = preimage.to_xdr(Limits::none()).unwrap();
                        Sha256::digest(preimage_xdr).into()
                    };
                    assert!(
                        self.auth_digests.contains(&digest),
                        "{case}: the signed digest commits to expiry {expiry}"
                    );
                }
            }
        }

        /// Submits on `path` through `primary` with `secondary` as the witness.
        async fn submit_with(
            path: SigningPath,
            primary: &AuthTreeEndpoint,
            secondary: Option<&str>,
            horizon: Option<HorizonCheck>,
        ) -> Outcome {
            submit_with_control(
                path,
                primary,
                secondary,
                horizon,
                &RecordingSigner::new(),
                stellar_agent_network::SigningAdmission::NoValue(
                    crate::signing::intent_test_helpers::no_value_admission(),
                ),
            )
            .await
        }

        async fn submit_with_control(
            path: SigningPath,
            primary: &AuthTreeEndpoint,
            secondary: Option<&str>,
            horizon: Option<HorizonCheck>,
            signer: &RecordingSigner,
            admission: stellar_agent_network::SigningAdmission<'_>,
        ) -> Outcome {
            submit_with_options(path, primary, secondary, horizon, signer, admission, None).await
        }

        async fn submit_with_options(
            path: SigningPath,
            primary: &AuthTreeEndpoint,
            secondary: Option<&str>,
            horizon: Option<HorizonCheck>,
            signer: &RecordingSigner,
            admission: stellar_agent_network::SigningAdmission<'_>,
            expected_return: Option<super::super::ExpectedReturn>,
        ) -> Outcome {
            let target = wallet_strkey();
            let rule_ids = path.rule_ids();
            let declared = [nested_call()];
            let (sub_invocations, required_checks, multicall_check): (
                _,
                &[&'static str],
                Option<MulticallCheck>,
            ) = match path {
                SigningPath::Single => (DeclaredSubInvocations::None, &[], None),
                SigningPath::Multicall => (
                    DeclaredSubInvocations::Calls(&declared),
                    &["multicall"],
                    Some(MulticallCheck {
                        registry_entry_address: target.clone(),
                        registry_entry_wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
                        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
                    }),
                ),
            };
            let result = submit_signed_invoke(
                SubmitInvokeArgs::builder()
                    .admission(admission)
                    .target_contract(&target)
                    .auth_rule_ids(&rule_ids)
                    .host_function(path.host_function())
                    .sub_invocations(sub_invocations)
                    .signer(signer)
                    .primary_rpc_url(&primary.uri())
                    .maybe_secondary_rpc_url(secondary)
                    .network_passphrase(TESTNET_PASSPHRASE)
                    .chain_id("stellar:testnet")
                    .timeout(Duration::from_secs(5))
                    .op_label("witness_test")
                    .required_checks(required_checks)
                    .maybe_multicall_check(multicall_check)
                    .maybe_horizon_check(horizon)
                    .maybe_expected_return(expected_return)
                    .build(),
            )
            .await;
            let auth_digests = signer.auth_digests.lock().unwrap().clone();
            Outcome {
                result,
                signs: signer.inner.sign_calls(),
                key_reads: signer.inner.public_key_calls(),
                auth_digests,
                signed_simulations: primary.signed_simulations(),
                sent: primary.sent(),
            }
        }

        /// Submits on `path` through `primary` with `secondary` as the witness
        /// on a host apart from the primary's.
        async fn submit_pair(
            path: SigningPath,
            primary: AuthTreeRpc,
            secondary: AuthTreeRpc,
            horizon: Option<HorizonCheck>,
        ) -> Outcome {
            let primary = primary.start().await;
            let secondary = secondary.start().await;
            let secondary_uri = second_loopback_host(&secondary.uri());
            submit_with(path, &primary, Some(&secondary_uri), horizon).await
        }

        /// Submits on `path` through endpoints at the two heights.
        async fn submit_at(path: SigningPath, primary: u32, secondary: u32) -> Outcome {
            submit_pair(path, endpoint(primary), endpoint(secondary), None).await
        }

        #[derive(Clone, Copy)]
        enum AdmissionProbe {
            Stale,
            WrongPlan,
            FailingSigner,
        }

        struct ProbeRecorder<'a> {
            inner: stellar_agent_network::submission_record::WalletSubmissionRecorder<'a>,
            mode: AdmissionProbe,
            admissions: std::sync::atomic::AtomicUsize,
            cancellations: std::sync::atomic::AtomicUsize,
        }

        #[async_trait]
        impl stellar_agent_network::SubmissionRecorder for ProbeRecorder<'_> {
            async fn admit_signed_intent(
                &self,
                plan: &stellar_agent_network::SignedIntentPlan,
            ) -> Result<stellar_agent_network::IntentProof, WalletError> {
                self.admissions
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let wrong;
                let plan = if matches!(self.mode, AdmissionProbe::WrongPlan) {
                    wrong = stellar_agent_network::SignedIntentPlan::new(
                        TESTNET_PASSPHRASE,
                        &wallet_strkey(),
                        &account_id_for_seed(SEED),
                        1,
                        [7; 32],
                        vec![],
                        None,
                    )?;
                    &wrong
                } else {
                    plan
                };
                let proof = self.inner.admit_signed_intent(plan).await?;
                if matches!(self.mode, AdmissionProbe::Stale) {
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
                self.cancellations
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.inner.cancel_unexposed(proof).await
            }
            async fn pre_send_bound(
                &self,
                intent: &stellar_agent_network::SubmissionIntent,
                binding: &stellar_agent_network::IntentBinding<'_>,
            ) -> Result<(), WalletError> {
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
        async fn a_refusal_before_the_first_signature_cancels_the_admission() {
            use stellar_agent_core::policy::v1::criteria::state_store::{
                PolicyStateStore, StateKey, WindowEntry, WindowLimit,
            };
            use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
            use stellar_agent_network::policy_state::PersistedWindowStore;
            for mode in [
                AdmissionProbe::Stale,
                AdmissionProbe::WrongPlan,
                AdmissionProbe::FailingSigner,
            ] {
                stellar_agent_test_support::keyring_mock::install().unwrap();
                let dir = tempfile::tempdir().unwrap();
                let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
                    "intent",
                    "intent-test",
                    "account",
                    "intent-nonce",
                    "account",
                )
                .build();
                let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
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
                        "witness_test",
                        Some("stellar:testnet".into()),
                        stellar_agent_core::audit_log::PolicyDecision::Allow,
                        vec![],
                        entries.clone(),
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
                let recorder = ProbeRecorder {
                    inner,
                    mode,
                    admissions: 0.into(),
                    cancellations: 0.into(),
                };
                let signer = RecordingSigner {
                    fail_auth: matches!(mode, AdmissionProbe::FailingSigner),
                    ..RecordingSigner::new()
                };
                let primary = endpoint(LEDGER).start().await;
                let secondary = endpoint(LEDGER).start().await;
                let url = second_loopback_host(&secondary.uri());
                let result = submit_with_control(
                    SigningPath::Single,
                    &primary,
                    Some(&url),
                    None,
                    &signer,
                    stellar_agent_network::SigningAdmission::Recorded(&recorder),
                )
                .await;
                assert_eq!(
                    recorder
                        .admissions
                        .load(std::sync::atomic::Ordering::SeqCst),
                    1
                );
                let exposed = matches!(mode, AdmissionProbe::FailingSigner);
                let cancellations = recorder
                    .cancellations
                    .load(std::sync::atomic::Ordering::SeqCst);
                if matches!(mode, AdmissionProbe::Stale) {
                    result.assert_refused(UNAVAILABLE_CODE, "post-admission staleness");
                }
                if matches!(mode, AdmissionProbe::WrongPlan) {
                    result.assert_refused("submission.intent_binding_mismatch", "first request");
                }
                if exposed {
                    assert!(result.result.is_err());
                    assert_eq!(result.signs, 1);
                }
                assert_eq!(result.signed_simulations, 0);
                assert!(result.sent.is_empty());
                drop(recorder);
                drop(store);
                let reopened = PersistedWindowStore::at_path(dir.path().join("intent.window"));
                let intents = reopened.signed_intents("intent", &profile).unwrap();
                assert_eq!(intents.len(), usize::from(exposed));
                assert_eq!(cancellations, usize::from(!exposed));
                if exposed {
                    assert_eq!(
                        intents[0].status,
                        "authorization exposed, submission unknown"
                    );
                    assert_eq!(intents[0].legs.len(), 1);
                }
                if exposed {
                    let admission = stellar_agent_network::NoValueAdmission::with_store(
                        profile.clone(),
                        reopened.clone(),
                        CheckedSizing::for_test(SizingBasis::NoValue, entries).unwrap(),
                    )
                    .unwrap();
                    let fresh =
                        stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(
                            99, 1,
                        )
                        .0;
                    let error = admission.admit(&fresh).await.err().unwrap();
                    assert_eq!(error.code(), "policy.deny.rate_limit_exceeded");
                }
                let state = PolicyStateStore::new();
                reopened.load_into("intent", &profile, &state).unwrap();
                assert_eq!(
                    state.query_window(&key, now).unwrap(),
                    if exposed { (1, 1) } else { (0, 0) }
                );
            }
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
            std::fs::create_dir_all(&scratch).unwrap();
            let dir = tempfile::Builder::new()
                .prefix("cancel-progress-")
                .tempdir_in(scratch)
                .unwrap();
            let profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
                "intent",
                "progress-test",
                "account",
                "progress-nonce",
                "account",
            )
            .build();
            let primary = endpoint(LEDGER).start().await;
            let secondary = endpoint(LEDGER).start().await;
            let secondary_url = second_loopback_host(&secondary.uri());
            std::fs::write(
                dir.path().join("intent.toml"),
                format!(
                    "chain_id = \"stellar:testnet\"\nrpc_url = {:?}\nsecondary_rpc_url = {:?}\n",
                    primary.uri(),
                    secondary_url,
                ),
            )
            .unwrap();
            let store = PersistedWindowStore::at_path(dir.path().join("intent.window"))
                .with_profile_directory("intent", dir.path().to_owned());
            let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(1000);
            let retained_key = StateKey::new("intent", 1, "retained-rate", 60);
            let retained_entries = [WindowEntry::new(
                retained_key.clone(),
                1000,
                1,
                WindowLimit::Count {
                    window: "1m".into(),
                    max_calls: 1,
                },
            )];
            let (prior, envelope) =
                stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(99, 1);
            let TransactionEnvelope::Tx(tx) = envelope else {
                panic!("V1")
            };
            let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                panic!("invoke")
            };
            let prior = prior
                .classify_purpose(&op.host_function, None)
                .unwrap()
                .with_envelope_max_ledger(100)
                .unwrap();
            let prior = stellar_agent_network::signed_intent::test_helpers::with_legs(
                &prior,
                &retained_entries,
            );
            let retained = store
                .admit_signed_intent(&profile, &prior)
                .unwrap()
                .expose();
            let retained_id = retained.intent_id().unwrap().to_owned();
            clock.set(2000);
            let current_key = StateKey::new("intent", 1, "rate_limit", 60);
            let entries = vec![WindowEntry::new(
                current_key.clone(),
                2000,
                1,
                WindowLimit::Count {
                    window: "1m".into(),
                    max_calls: 1,
                },
            )];
            let inner = stellar_agent_network::submission_record::WalletSubmissionRecorder::new(
                &profile,
                "intent",
                "witness_test",
                Some("stellar:testnet".into()),
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                vec![],
                entries.clone(),
                stellar_agent_core::profile::receipt::ReceiptStore::open_at(dir.path(), "intent")
                    .unwrap(),
                store.clone(),
                None,
                None,
                "progress-fixture",
                2000,
            )
            .with_signing_sizing(CheckedSizing::for_test(SizingBasis::NoValue, entries).unwrap());
            let recorder = ProbeRecorder {
                inner,
                mode: AdmissionProbe::Stale,
                admissions: 0.into(),
                cancellations: 0.into(),
            };
            let signer = RecordingSigner::new();
            let result = submit_with_control(
                SigningPath::Single,
                &primary,
                Some(&secondary_url),
                None,
                &signer,
                stellar_agent_network::SigningAdmission::Recorded(&recorder),
            )
            .await;
            result.assert_refused(
                UNAVAILABLE_CODE,
                "stale admission preserves independent progress",
            );
            assert_eq!(
                recorder
                    .admissions
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(
                recorder
                    .cancellations
                    .load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(result.signs, 0);
            assert_eq!(result.signed_simulations, 0);
            assert!(result.sent.is_empty());
            drop(recorder);
            let reopened = PersistedWindowStore::at_path(store.path().to_owned());
            let intents = reopened.signed_intents("intent", &profile).unwrap();
            assert_eq!(intents.len(), 1);
            assert_eq!(intents[0].intent_id, retained_id);
            assert_eq!(intents[0].expiry_observed_at_ms, Some(2000));
            assert_eq!(intents[0].accounting_horizon, "62000");
            let memory = PolicyStateStore::new();
            reopened.load_into("intent", &profile, &memory).unwrap();
            assert_eq!(memory.query_window(&retained_key, 2000).unwrap(), (1, 1));
            assert_eq!(memory.query_window(&current_key, 2000).unwrap(), (0, 0));
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn single_invoke_refuses_plausible_inflated_height() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let outcome = submit_at(SigningPath::Single, 1_000_000, LEDGER).await;
            outcome.assert_refused(SKEW_CODE, "an inflated primary");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn allowed_skew_has_exact_bounded_expiry() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for path in PATHS {
                for (primary, secondary) in [
                    (LEDGER, LEDGER),
                    (LEDGER, LEDGER + 1),
                    (LEDGER + 1, LEDGER),
                    (LEDGER, LEDGER + 2),
                    (LEDGER + 2, LEDGER),
                ] {
                    let case = format!("{path:?} ({primary}, {secondary})");
                    let outcome = submit_at(path, primary, secondary).await;
                    outcome.assert_every_signature_expires_at(
                        primary.min(secondary) + 100,
                        &path.rule_ids(),
                        &case,
                    );
                }
                for (primary, secondary) in [(LEDGER, LEDGER + 3), (LEDGER + 3, LEDGER)] {
                    let case = format!("{path:?} ({primary}, {secondary})");
                    submit_at(path, primary, secondary)
                        .await
                        .assert_refused(SKEW_CODE, &case);
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_skew_of_three_with_the_primary_behind_refuses() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for path in PATHS {
                submit_at(path, LEDGER, LEDGER + 3)
                    .await
                    .assert_refused(SKEW_CODE, &format!("{path:?}"));
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_skew_of_three_with_the_primary_ahead_refuses() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for path in PATHS {
                submit_at(path, LEDGER + 3, LEDGER)
                    .await
                    .assert_refused(SKEW_CODE, &format!("{path:?}"));
            }
        }

        /// Heights no ledger can have refuse as a pair that cannot bound an
        /// expiry, whichever endpoint reports them.
        #[tokio::test]
        #[serial_test::serial]
        async fn out_of_bounds_heights_refuse_before_signing() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for path in PATHS {
                for (primary, secondary) in [(0, 1), (1, 0), (0, 0), (u32::MAX - 1, u32::MAX - 1)] {
                    let case = format!("{path:?} ({primary}, {secondary})");
                    submit_at(path, primary, secondary)
                        .await
                        .assert_refused(SKEW_CODE, &case);
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn simulation_recovery_uses_one_retry_and_the_same_pair() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for case in [
                RecoveryCase::Valid,
                RecoveryCase::Behind,
                RecoveryCase::ReplacementAhead,
                RecoveryCase::Ahead,
            ] {
                let primary = endpoint(LEDGER)
                    .simulation_response(move |n, response| {
                        recovery_response(case, n, response);
                    })
                    .start()
                    .await;
                let secondary = endpoint(LEDGER).start().await;
                let outcome = submit_with(
                    SigningPath::Single,
                    &primary,
                    Some(&second_loopback_host(&secondary.uri())),
                    None,
                )
                .await;
                if case == RecoveryCase::Valid {
                    outcome.assert_every_signature_expires_at(
                        LEDGER + 100,
                        &SigningPath::Single.rule_ids(),
                        &format!("{case:?}"),
                    );
                    assert_eq!(
                        outcome.result.as_ref().unwrap().return_val,
                        stellar_xdr::ScVal::U32(REPLACEMENT_VALUE)
                    );
                    let TransactionEnvelope::Tx(tx) = &outcome.sent[0] else {
                        panic!("v1")
                    };
                    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                        panic!("invoke")
                    };
                    let SorobanCredentials::Address(creds) = &op.auth[0].credentials else {
                        panic!("address")
                    };
                    assert_eq!(
                        creds.nonce,
                        i64::from(REPLACEMENT_VALUE),
                        "replacement nonce reaches signing"
                    );
                } else {
                    outcome.assert_refused(SKEW_CODE, &format!("{case:?}"));
                }
                assert_eq!(
                    primary.simulations() - primary.signed_simulations(),
                    if case == RecoveryCase::Ahead { 1 } else { 2 }
                );
                assert_eq!(primary.ledger_reads(), 1, "recovery keeps the pair");
                assert_eq!(secondary.ledger_reads(), 1, "recovery keeps the pair");
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn simulation_recovery_keeps_the_absolute_deadline() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let primary = endpoint(LEDGER)
                .simulation_response(|n, response| {
                    recovery_response(RecoveryCase::Valid, n, response);
                })
                .slow_simulations(1..3, Duration::from_secs(3))
                .start()
                .await;
            let secondary = endpoint(LEDGER).start().await;
            let outcome = submit_with(
                SigningPath::Single,
                &primary,
                Some(&second_loopback_host(&secondary.uri())),
                None,
            )
            .await;
            assert_deadline_refusal(&outcome, "simulate_recovery");
            outcome.assert_refused("sa.auth_entry_construction_failed", "recovery deadline");
            assert_eq!(primary.simulations(), 2);
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn simulation_recovery_revalidates_the_whole_response() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for case in [
                RecoveryCase::Tree,
                RecoveryCase::Credential,
                RecoveryCase::Error,
                RecoveryCase::Fee,
                RecoveryCase::Data,
                RecoveryCase::Decode,
                RecoveryCase::Empty,
                RecoveryCase::Cross,
                RecoveryCase::Count,
                RecoveryCase::Prediction,
            ] {
                let primary = endpoint(LEDGER)
                    .simulation_response(move |n, response| {
                        recovery_response(case, n, response);
                    })
                    .start()
                    .await;
                let secondary = endpoint(LEDGER)
                    .simulation_response(move |_, response| {
                        if case == RecoveryCase::Count {
                            recovery_response(case, 2, response);
                        }
                    })
                    .start()
                    .await;
                let path = if matches!(case, RecoveryCase::Cross | RecoveryCase::Count) {
                    SigningPath::Multicall
                } else {
                    SigningPath::Single
                };
                let outcome = submit_with_options(
                    path,
                    &primary,
                    Some(&second_loopback_host(&secondary.uri())),
                    None,
                    &RecordingSigner::new(),
                    stellar_agent_network::SigningAdmission::NoValue(
                        crate::signing::intent_test_helpers::no_value_admission(),
                    ),
                    Some(super::super::ExpectedReturn::U32),
                )
                .await;
                let code = match case {
                    RecoveryCase::Tree => "simulation.divergence.auth_contexts",
                    RecoveryCase::Cross | RecoveryCase::Count => "sa.multicall_failed",
                    _ => "sa.deployment_failed",
                };
                outcome.assert_refused(code, &format!("{case:?}"));
                assert_eq!(primary.simulations(), 2, "{case:?}");
            }
        }

        /// A simulation that answers from a height the primary's own
        /// observation contradicts is not a base for a signature.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_simulated_height_outside_the_pair_refuses_before_signing() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for (simulated, case) in [(1_000_000, "above"), (LEDGER - 3, "below")] {
                let primary = endpoint(LEDGER).simulated_ledger(simulated);
                submit_pair(SigningPath::Single, primary, endpoint(LEDGER), None)
                    .await
                    .assert_refused(SKEW_CODE, case);
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_simulated_height_within_the_tolerance_of_the_pair_signs() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for simulated in [LEDGER - 2, LEDGER + 2] {
                let path = SigningPath::Single;
                let primary = endpoint(LEDGER).simulated_ledger(simulated).start().await;
                let secondary = endpoint(LEDGER).start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&secondary.uri())),
                    None,
                )
                .await
                .assert_every_signature_expires_at(
                    LEDGER + 100,
                    &path.rule_ids(),
                    "a simulation within the tolerance",
                );
                assert_eq!(primary.simulations() - primary.signed_simulations(), 1);
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn absent_unavailable_or_wrong_chain_witness_refuses() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            for path in PATHS {
                let case = |name: &str| format!("{path:?}: {name}");

                let primary = endpoint(LEDGER).start().await;
                submit_with(path, &primary, None, None)
                    .await
                    .assert_refused(UNAVAILABLE_CODE, &case("no secondary"));

                // Transport failure: the endpoint answers 503 to every request.
                let down = wiremock::MockServer::start().await;
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .respond_with(wiremock::ResponseTemplate::new(503))
                    .mount(&down)
                    .await;
                let primary = endpoint(LEDGER).start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&down.uri())),
                    None,
                )
                .await
                .assert_refused(UNAVAILABLE_CODE, &case("secondary transport failure"));

                let malformed = endpoint(LEDGER).malformed_latest_ledger().start().await;
                let primary = endpoint(LEDGER).start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&malformed.uri())),
                    None,
                )
                .await
                .assert_refused(UNAVAILABLE_CODE, &case("malformed secondary height"));

                let healthy = endpoint(LEDGER).start().await;
                let primary = endpoint(LEDGER).malformed_latest_ledger().start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&healthy.uri())),
                    None,
                )
                .await
                .assert_refused(UNAVAILABLE_CODE, &case("malformed primary height"));

                let elsewhere = endpoint_on("Another Test Network ; 2026", LEDGER)
                    .start()
                    .await;
                let primary = endpoint(LEDGER).start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&elsewhere.uri())),
                    None,
                )
                .await
                .assert_refused(UNAVAILABLE_CODE, &case("secondary on another network"));

                let mainnet = endpoint_on(
                    stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
                    LEDGER,
                )
                .start()
                .await;
                let primary = endpoint(LEDGER).start().await;
                submit_with(
                    path,
                    &primary,
                    Some(&second_loopback_host(&mainnet.uri())),
                    None,
                )
                .await
                .assert_refused(
                    "network.mainnet_write_forbidden",
                    &case("secondary on mainnet"),
                );

                let other_port = endpoint(LEDGER).start().await;
                let primary = endpoint(LEDGER).start().await;
                for (name, secondary) in [
                    ("the same URL", primary.uri()),
                    (
                        "the same host on a path",
                        format!("{}/witness", primary.uri()),
                    ),
                    ("the same host on a port", other_port.uri()),
                    (
                        "the same host in another spelling",
                        primary
                            .uri()
                            .replace("http://127.0.0.1", "HTTP://127.0.0.1"),
                    ),
                    ("no URL", "not a url".to_owned()),
                ] {
                    submit_with(path, &primary, Some(&secondary), None)
                        .await
                        .assert_refused(UNAVAILABLE_CODE, &case(name));
                }
            }
        }

        /// A refused configuration sends nothing: the reason is local.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_refused_witness_configuration_reaches_no_endpoint() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let primary = endpoint(LEDGER).start().await;
            let outcome = submit_with(
                SigningPath::Single,
                &primary,
                Some(&format!("{}/witness", primary.uri())),
                None,
            )
            .await;
            outcome.assert_refused(UNAVAILABLE_CODE, "the same host");
            assert_eq!(
                primary.simulations(),
                0,
                "the refusal precedes the simulation"
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn rule_horizon_uses_witnessed_ledger() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let horizon = HorizonCheck {
                valid_until: 1101,
                max_horizon: 100,
                rule_id_or_pending: None,
            };
            let outcome = submit_pair(
                SigningPath::Single,
                endpoint(1002),
                endpoint(1000),
                Some(horizon),
            )
            .await;
            match &outcome.result {
                Err(SaError::HorizonExceeded {
                    requested_horizon,
                    max_horizon,
                    ..
                }) => {
                    assert_eq!(*requested_horizon, 101);
                    assert_eq!(*max_horizon, 100);
                }
                other => panic!(
                    "expected the horizon refusal, got {:?}",
                    other.as_ref().err()
                ),
            }
            assert_eq!(outcome.signs, 0);
            assert_eq!(outcome.signed_simulations, 0);
            assert!(outcome.sent.is_empty());
        }

        /// The same pair admits a horizon of exactly the maximum from the
        /// lower height.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_rule_horizon_at_the_maximum_from_the_lower_ledger_signs() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let path = SigningPath::Single;
            let horizon = HorizonCheck {
                valid_until: 1100,
                max_horizon: 100,
                rule_id_or_pending: None,
            };
            submit_pair(path, endpoint(1002), endpoint(1000), Some(horizon))
                .await
                .assert_every_signature_expires_at(1100, &path.rule_ids(), "the maximum horizon");
        }

        // ── Signer key lookups and the signing boundary ─────────────────────

        /// The deadline of [`submit_with_slow_key`].
        const SLOW_KEY_DEADLINE: Duration = Duration::from_secs(5);

        /// Outlasts a ledger observation, and the deadline with it.
        const LOOKUP_OUTLASTS_OBSERVATION: Duration = Duration::from_millis(10_500);

        /// Outlasts the deadline, but not a ledger observation.
        const LOOKUP_OUTLASTS_DEADLINE: Duration = Duration::from_millis(5_500);

        /// A signer whose key lookup takes `delay`, as a hardware device's
        /// can, and that counts its signatures.
        struct SlowKeySigner {
            inner: CountingSigner,
            delay: Duration,
        }

        #[async_trait]
        impl Signer for SlowKeySigner {
            async fn sign_tx_payload(
                &self,
                payload: &TxSigningPayload,
            ) -> Result<[u8; 64], WalletError> {
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

            async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
                tokio::time::sleep(self.delay).await;
                self.inner.public_key().await
            }
        }

        /// The signing paths that read a signer key of their own after the
        /// simulation.
        #[derive(Clone, Copy, Debug)]
        enum LookupPath {
            Quorum,
            RuleSigner,
        }

        /// Submits a single invocation on `path`, whose own signer takes
        /// `delay` to report its key. The outcome counts the signatures of
        /// both signers.
        async fn submit_with_slow_key(path: LookupPath, delay: Duration) -> Outcome {
            let primary = endpoint(LEDGER).start().await;
            let secondary = endpoint(LEDGER).start().await;
            let primary_uri = primary.uri();
            let secondary_uri = second_loopback_host(&secondary.uri());
            let signer = RecordingSigner::new();
            let slow = SlowKeySigner {
                inner: CountingSigner::new(SEED),
                delay,
            };
            let quorum_signers: [&(dyn Signer + Send + Sync); 1] = [&slow];
            let authorization = AuthorizationInfo::new(
                vec![
                    SignerGroup::new("slow".to_owned(), vec![public_key_for_seed(SEED)], 1)
                        .unwrap(),
                ],
                Combinator::And,
            );
            let target = wallet_strkey();
            let rule_ids = SigningPath::Single.rule_ids();
            let builder = SubmitInvokeArgs::builder()
                .admission(stellar_agent_network::SigningAdmission::NoValue(
                    crate::signing::intent_test_helpers::no_value_admission(),
                ))
                .target_contract(&target)
                .auth_rule_ids(&rule_ids)
                .host_function(SigningPath::Single.host_function())
                .sub_invocations(DeclaredSubInvocations::None)
                .signer(&signer)
                .primary_rpc_url(&primary_uri)
                .secondary_rpc_url(&secondary_uri)
                .network_passphrase(TESTNET_PASSPHRASE)
                .chain_id("stellar:testnet")
                .timeout(SLOW_KEY_DEADLINE)
                .op_label("witness_test");
            let args = match path {
                LookupPath::Quorum => builder
                    .authorization(&authorization)
                    .signers(&quorum_signers)
                    .build(),
                LookupPath::RuleSigner => builder
                    .ed25519_rule_signer(Ed25519RuleSigner {
                        signer: &slow,
                        verifier: ScAddress::Contract(ContractId(Hash([0x64; 32]))),
                    })
                    .build(),
            };
            let result = submit_signed_invoke(args).await;
            let auth_digests = signer.auth_digests.lock().unwrap().clone();
            Outcome {
                result,
                signs: signer.inner.sign_calls() + slow.inner.sign_calls(),
                key_reads: signer.inner.public_key_calls(),
                auth_digests,
                signed_simulations: primary.signed_simulations(),
                sent: primary.sent(),
            }
        }

        /// A signer key that arrives after the pair went stale, or after the
        /// deadline, never reaches a signature: the lookups precede the last
        /// witness check, which refuses. The cases run side by side.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_key_lookup_delayed_past_the_freshness_limit_refuses_before_signing() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let (quorum_stale, rule_signer_stale, quorum_late, rule_signer_late) = tokio::join!(
                submit_with_slow_key(LookupPath::Quorum, LOOKUP_OUTLASTS_OBSERVATION),
                submit_with_slow_key(LookupPath::RuleSigner, LOOKUP_OUTLASTS_OBSERVATION),
                submit_with_slow_key(LookupPath::Quorum, LOOKUP_OUTLASTS_DEADLINE),
                submit_with_slow_key(LookupPath::RuleSigner, LOOKUP_OUTLASTS_DEADLINE),
            );
            quorum_stale.assert_refused(UNAVAILABLE_CODE, "quorum, past the observation age");
            rule_signer_stale
                .assert_refused(UNAVAILABLE_CODE, "rule signer, past the observation age");
            for (outcome, case) in [
                (&quorum_late, "quorum, past the deadline"),
                (&rule_signer_late, "rule signer, past the deadline"),
            ] {
                outcome.assert_refused(UNAVAILABLE_CODE, case);
                assert!(
                    matches!(
                        outcome.result,
                        Err(SaError::LedgerWitnessUnavailable {
                            reason: "the pre-submit deadline elapsed"
                        })
                    ),
                    "{case}: the signing boundary refuses: {:?}",
                    outcome.result.as_ref().err()
                );
            }
        }

        // ── Authorization signatures under the deadline ─────────────────────

        /// The deadline of [`submit_with_slow_signature`].
        const SLOW_SIGNATURE_DEADLINE: Duration = Duration::from_secs(5);

        /// Outlasts [`SLOW_SIGNATURE_DEADLINE`].
        const SIGNATURE_OUTLASTS_DEADLINE: Duration = Duration::from_secs(6);

        /// The signer call [`SlowSignatureSigner`] delays.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum SlowCall {
            /// The signature over a smart account's auth digest.
            AuthDigest,
            /// The signature over a delegated G-key entry's payload.
            DelegatedEntry,
        }

        /// A signer whose call `slow` names answers only after `delay`, as a
        /// hardware device's can, and that counts its signatures. Its other
        /// calls answer at once.
        struct SlowSignatureSigner {
            inner: CountingSigner,
            slow: SlowCall,
            delay: Duration,
        }

        impl SlowSignatureSigner {
            /// Waits out `delay` when `call` is the delayed one.
            async fn wait_for(&self, call: SlowCall) {
                if self.slow == call {
                    tokio::time::sleep(self.delay).await;
                }
            }
        }

        #[async_trait]
        impl Signer for SlowSignatureSigner {
            async fn sign_tx_payload(
                &self,
                payload: &TxSigningPayload,
            ) -> Result<[u8; 64], WalletError> {
                self.inner.sign_tx_payload(payload).await
            }

            async fn sign_auth_digest(
                &self,
                digest: &SmartAccountAuthDigest,
            ) -> Result<[u8; 64], WalletError> {
                self.wait_for(SlowCall::AuthDigest).await;
                self.inner.sign_auth_digest(digest).await
            }

            async fn sign_soroban_address_auth_payload(
                &self,
                payload: &SorobanAuthPayload,
            ) -> Result<[u8; 64], WalletError> {
                self.wait_for(SlowCall::DelegatedEntry).await;
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

            async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
                self.inner.public_key().await
            }
        }

        /// The arms that sign a single invocation's authorization.
        #[derive(Clone, Copy, Debug)]
        enum SigningArm {
            /// A quorum signer signs the smart account's entry.
            Quorum,
            /// An External-Ed25519 rule signer signs the smart account's entry.
            RuleSigner,
            /// The envelope signer signs the smart account's entry and its
            /// delegated G-key entry.
            Delegated,
        }

        /// Submits a single invocation on `arm`, whose signer answers the call
        /// `slow` names only after [`SIGNATURE_OUTLASTS_DEADLINE`]. The
        /// outcome counts the signatures of every signer.
        async fn submit_with_slow_signature(arm: SigningArm, slow: SlowCall) -> Outcome {
            let primary = endpoint(LEDGER).start().await;
            let secondary = endpoint(LEDGER).start().await;
            let primary_uri = primary.uri();
            let secondary_uri = second_loopback_host(&secondary.uri());
            let signer = RecordingSigner::new();
            let slow = SlowSignatureSigner {
                inner: CountingSigner::new(SEED),
                slow,
                delay: SIGNATURE_OUTLASTS_DEADLINE,
            };
            let quorum_signers: [&(dyn Signer + Send + Sync); 1] = [&slow];
            let authorization = AuthorizationInfo::new(
                vec![
                    SignerGroup::new("slow".to_owned(), vec![public_key_for_seed(SEED)], 1)
                        .unwrap(),
                ],
                Combinator::And,
            );
            let target = wallet_strkey();
            let rule_ids = SigningPath::Single.rule_ids();
            let builder = SubmitInvokeArgs::builder()
                .admission(stellar_agent_network::SigningAdmission::NoValue(
                    crate::signing::intent_test_helpers::no_value_admission(),
                ))
                .target_contract(&target)
                .auth_rule_ids(&rule_ids)
                .host_function(SigningPath::Single.host_function())
                .sub_invocations(DeclaredSubInvocations::None)
                .primary_rpc_url(&primary_uri)
                .secondary_rpc_url(&secondary_uri)
                .network_passphrase(TESTNET_PASSPHRASE)
                .chain_id("stellar:testnet")
                .timeout(SLOW_SIGNATURE_DEADLINE)
                .op_label("witness_test");
            let args = match arm {
                SigningArm::Quorum => builder
                    .signer(&signer)
                    .authorization(&authorization)
                    .signers(&quorum_signers)
                    .build(),
                SigningArm::RuleSigner => builder
                    .signer(&signer)
                    .ed25519_rule_signer(Ed25519RuleSigner {
                        signer: &slow,
                        verifier: ScAddress::Contract(ContractId(Hash([0x64; 32]))),
                    })
                    .build(),
                SigningArm::Delegated => builder.signer(&slow).build(),
            };
            let result = submit_signed_invoke(args).await;
            let auth_digests = signer.auth_digests.lock().unwrap().clone();
            Outcome {
                result,
                signs: signer.inner.sign_calls() + slow.inner.sign_calls(),
                key_reads: signer.inner.public_key_calls(),
                auth_digests,
                signed_simulations: primary.signed_simulations(),
                sent: primary.sent(),
            }
        }

        /// Asserts that the auth-digest signature of `arm` was cut at the
        /// deadline: the refusal names its stage, no signature was made, the
        /// cut one included, and nothing was re-simulated or sent.
        async fn assert_auth_signature_cut(arm: SigningArm) {
            let outcome = submit_with_slow_signature(arm, SlowCall::AuthDigest).await;

            assert_deadline_refusal(&outcome, "sign_auth_digest");
            assert_eq!(outcome.signs, 0, "{arm:?}: nothing is signed");
            assert_eq!(
                outcome.signed_simulations, 0,
                "{arm:?}: nothing is re-simulated"
            );
        }

        /// A quorum signer's signature that outlasts the deadline is cut at
        /// it: no further signature, nothing sent.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_quorum_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            assert_auth_signature_cut(SigningArm::Quorum).await;
        }

        /// A rule signer's signature that outlasts the deadline is cut at it:
        /// no further signature, nothing sent.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_rule_signer_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            assert_auth_signature_cut(SigningArm::RuleSigner).await;
        }

        /// The smart account's own entry signature that outlasts the deadline
        /// is cut at it: its delegated entry and the envelope are not signed,
        /// and nothing is sent.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_delegated_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            assert_auth_signature_cut(SigningArm::Delegated).await;
        }

        /// The delegated G-key entry's signature that outlasts the deadline is
        /// cut at it after the smart account's own entry is signed: the
        /// envelope is not signed, nothing is re-simulated, and nothing is
        /// sent.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_delegated_entry_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let outcome =
                submit_with_slow_signature(SigningArm::Delegated, SlowCall::DelegatedEntry).await;

            assert_deadline_refusal(&outcome, "sign_delegated_entry");
            assert_eq!(
                outcome.signs, 1,
                "the smart account's own entry alone is signed"
            );
            assert_eq!(outcome.signed_simulations, 0, "nothing is re-simulated");
        }

        /// The deadline of [`submit_with_late_send`].
        const LATE_SEND_DEADLINE: Duration = Duration::from_secs(5);

        /// Outlasts [`LATE_SEND_DEADLINE`].
        const PAST_THE_DEADLINE: Duration = Duration::from_secs(6);

        /// Submits a single invocation whose envelope signature takes
        /// `envelope_delay`, through a primary whose identity probe after the
        /// signed re-simulation takes `pre_send_delay`.
        async fn submit_with_late_send(
            envelope_delay: Option<Duration>,
            pre_send_delay: Option<Duration>,
        ) -> Outcome {
            let primary = match pre_send_delay {
                Some(delay) => endpoint(LEDGER).slow_network_after_signed_simulation(delay),
                None => endpoint(LEDGER),
            }
            .start()
            .await;
            let secondary = endpoint(LEDGER).start().await;
            let primary_uri = primary.uri();
            let secondary_uri = second_loopback_host(&secondary.uri());
            let signer = match envelope_delay {
                Some(delay) => RecordingSigner::with_envelope_delay(delay),
                None => RecordingSigner::new(),
            };
            let target = wallet_strkey();
            let rule_ids = SigningPath::Single.rule_ids();
            let result = submit_signed_invoke(
                SubmitInvokeArgs::builder()
                    .admission(stellar_agent_network::SigningAdmission::NoValue(
                        crate::signing::intent_test_helpers::no_value_admission(),
                    ))
                    .target_contract(&target)
                    .auth_rule_ids(&rule_ids)
                    .host_function(SigningPath::Single.host_function())
                    .sub_invocations(DeclaredSubInvocations::None)
                    .signer(&signer)
                    .primary_rpc_url(&primary_uri)
                    .secondary_rpc_url(&secondary_uri)
                    .network_passphrase(TESTNET_PASSPHRASE)
                    .chain_id("stellar:testnet")
                    .timeout(LATE_SEND_DEADLINE)
                    .op_label("witness_test")
                    .build(),
            )
            .await;
            let auth_digests = signer.auth_digests.lock().unwrap().clone();
            Outcome {
                result,
                signs: signer.inner.sign_calls(),
                key_reads: signer.inner.public_key_calls(),
                auth_digests,
                signed_simulations: primary.signed_simulations(),
                sent: primary.sent(),
            }
        }

        /// Asserts the pre-submit deadline refusal of `stage` with nothing
        /// sent.
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
            assert!(outcome.sent.is_empty(), "{stage}: nothing is sent");
        }

        /// An envelope signature that outlasts the deadline is cut at it: the
        /// envelope is neither signed nor sent. The smart account's entry and
        /// its delegated entry are signed before.
        #[tokio::test]
        #[serial_test::serial]
        async fn an_envelope_signature_past_the_deadline_is_cut_and_nothing_is_sent() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let outcome = submit_with_late_send(Some(PAST_THE_DEADLINE), None).await;

            assert_deadline_refusal(&outcome, "sign_envelope");
            assert_eq!(
                outcome.signs, 2,
                "the two authorization entries alone are signed"
            );
            assert_eq!(outcome.signed_simulations, 1);
        }

        /// The submission's steps before `sendTransaction` end at the
        /// pre-submit deadline: an identity probe that outlasts it sends
        /// nothing. Every signature is made, and the envelope signer's key is
        /// the one read before the signing boundary.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_pre_send_step_past_the_deadline_sends_nothing() {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let outcome = submit_with_late_send(None, Some(PAST_THE_DEADLINE)).await;

            assert_deadline_refusal(&outcome, "send_endpoint_identity");
            assert_eq!(outcome.signs, 3, "both entries and the envelope are signed");
            assert_eq!(
                outcome.key_reads, 1,
                "the envelope signer's key is read once"
            );
        }
    }
}
