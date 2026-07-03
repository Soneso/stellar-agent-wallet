//! Upgrade timelock surface (configurable on-chain execution delay).
//!
//! Production wrapper for the OZ `stellar-governance v0.7.1` `Timelock`
//! contract surface (`packages/governance/src/timelock/`, SHA `3f81125`).
//!
//! # What this module does
//!
//! Provides four off-chain primitives that wrap on-chain OZ Timelock calls:
//!
//! - [`schedule_upgrade`] — schedules a timelock operation via `Timelock::schedule`.
//! - [`cancel`] — cancels a pending operation via `Timelock::cancel`.
//! - [`execute`] — executes a ready operation via `Timelock::execute`.
//! - [`list_pending`] — enumerates pending operations from the audit log +
//!   cross-RPC `get_operation_state` validation.
//!
//! # What this module does NOT do
//!
//! - Administer timelock roles (PROPOSER / CANCELLER / EXECUTOR / Admin) — that
//!   is the timelock controller contract's own governance surface.
//! - Update the minimum delay (`update_delay`) — not currently exposed.
//! - Govern which contracts can be targets — policy is the operator's concern.
//!
//! # Security properties
//!
//! 1. **Authorisation model on `schedule`** — proposer = signer's account_id;
//!    PROPOSER_ROLE must be granted on-chain; unauthorised invocations surface
//!    as [`SaError::TimelockScheduleFailed`] with reason `Unauthorized`.
//! 2. **Salt derivation** — `sha256(request_id_bytes || timestamp_nanos_be)`.
//!    Non-deterministic per call; same args with different request_id or time
//!    produce different operation_ids.
//! 3. **Event-emission integrity** — every submit path cross-confirms the
//!    expected OZ event (`OperationScheduled`, `OperationCancelled`,
//!    `OperationExecuted`) in the transaction meta before returning `Ok`.
//! 4. **`execute()` ready-window race** — pre-check `get_operation_state`
//!    cross-RPC before submitting; fail-CLOSED if not `Ready`.
//! 5. **`list_pending` cross-RPC** — query both RPCs; divergence returns
//!    [`SaError::NetworkRpcDivergence`].
//!
//! # Canonical authority
//!
//! There is no timelock off-chain handler outside this wallet module, so the
//! OpenZeppelin on-chain contract is the sole canonical authority. All error
//! codes, event shapes, operation-state sentinel values, and the
//! `hash_operation` ABI are sourced from
//! `packages/governance/src/timelock/mod.rs` and
//! `packages/governance/src/timelock/storage.rs` in the
//! `stellar-governance v0.7.1` contract source.
//!
//! All timelock logic in this module is wallet-only with no off-chain reference
//! counterpart. The OpenZeppelin on-chain contract is the single authority for
//! correctness.

use sha2::{Digest as _, Sha256};
use std::sync::{Arc, Mutex};
use stellar_agent_core::{
    audit_log::{entry::AuditEntry, writer::AuditWriter},
    observability::{RedactedStrkey, redact_strkey_first5_last5},
};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::signing::Signer;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::{Client, GetTransactionResponse};
use stellar_xdr::{
    AccountId, BytesM, ContractEventBody, ContractEventV0, Hash, HostFunction, InvokeContractArgs,
    InvokeHostFunctionOp, Operation, OperationBody, ScAddress, ScSymbol, ScVal, ScVec, VecM,
};
// Use the upstream typed error enum from stellar-governance v0.7.1
// (packages/governance/src/timelock/mod.rs:325-340, SHA 3f81125) instead of
// hand-rolled u32 constants. TimelockError is #[repr(u32)] so `as u32` is safe and
// produces the same wire codes as the on-chain contract.
use stellar_governance::timelock::TimelockError as OzTimelockError;
use tracing::info;

use crate::SaError;
use crate::error::{
    TimelockCancelFailureReason, TimelockExecuteFailureReason, TimelockScheduleFailureReason,
};
use crate::managers::credentials::AuditWriterPoisonContext;
use crate::managers::rules::{
    BASE_FEE_STROOPS, augment_with_oz_error_name, parse_c_strkey_to_smart_account,
};

// ── OZ Timelock error codes ───────────────────────────────────────────────────
// Referenced as `OzTimelockError::Variant as u32`.
// Enum: stellar-governance v0.7.1, packages/governance/src/timelock/mod.rs:325-340,
// SHA 3f81125. All codes are #[repr(u32)] with fixed values that match the on-chain
// contract ABI.
//
// OzTimelockError::OperationAlreadyScheduled  = 4000
// OzTimelockError::InsufficientDelay          = 4001
// OzTimelockError::InvalidOperationState      = 4002
// OzTimelockError::UnexecutedPredecessor      = 4003
// OzTimelockError::Unauthorized               = 4004
// OzTimelockError::MinDelayNotSet             = 4005
// OzTimelockError::OperationNotScheduled      = 4006

// ── State sentinel values (storage.rs:UNSET_LEDGER / DONE_LEDGER) ────────────
// packages/governance/src/timelock/mod.rs:352-357 (SHA 3f81125)
const UNSET_LEDGER: u32 = 0;
const DONE_LEDGER: u32 = 1;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Opaque 32-byte operation identifier returned by `schedule_upgrade`.
///
/// Corresponds to the `BytesN<32>` returned by `Timelock::schedule` / computed
/// by `Timelock::hash_operation` on the OZ contract
/// (`packages/governance/src/timelock/storage.rs:403`, SHA `3f81125`).
/// The hash is produced on-chain by `hash_operation` (storage.rs:403, SHA `3f81125`).
///
/// # Redaction
///
/// `redacted()` exposes first-8-last-8 hex (16 + 16 = 32 hex chars) for
/// operator-facing log output. Operation IDs are public on-chain so `to_hex()`
/// (64-char full hex) is used in the audit log `operation_id_full_hex` field;
/// no PII is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelockOperationId {
    inner: [u8; 32],
}

impl TimelockOperationId {
    /// Constructs a `TimelockOperationId` from a raw 32-byte array.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_smart_account::timelock::TimelockOperationId;
    /// let id = TimelockOperationId::from_bytes([0u8; 32]);
    /// assert_eq!(id.to_hex().len(), 64);
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Returns the full 64-character lowercase hex representation.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.inner.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Returns the redacted form: first-8-last-8 hex chars (32 chars total).
    ///
    /// Used in log messages and error fields. Only first-8-last-8 hex is exposed.
    #[must_use]
    pub fn redacted(&self) -> String {
        let hex = self.to_hex();
        format!("{}...{}", &hex[..8], &hex[hex.len() - 8..])
    }

    /// Returns a reference to the raw 32-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

/// Outcome of a successful [`schedule_upgrade`] call.
///
/// Carries both the on-chain operation identifier and the 32-byte salt that was
/// supplied to the OZ `schedule` call. The salt is derived non-deterministically
/// at schedule time (`sha256(request_id_bytes || timestamp_nanos_be)`) and is not
/// stored on-chain. The caller MUST persist it — it cannot be recomputed later and
/// is required by the matching `execute` and `cancel` calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledTimelockOperation {
    /// On-chain operation identifier returned by `Timelock::schedule`.
    pub operation_id: TimelockOperationId,
    /// 32-byte salt supplied to `Timelock::schedule`.
    ///
    /// Must be passed verbatim to the matching `execute` or `cancel` call.
    /// Non-deterministic and not stored anywhere — record it at schedule time.
    pub salt: [u8; 32],
}

/// View of an operation's state, enriched with current-ledger context.
///
/// Returned by `query_operation_state_cross_rpc` and used by `list_pending`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimelockOperationStateView {
    /// Operation has not been scheduled (`UNSET_LEDGER`).
    Unset,
    /// Operation is scheduled and the delay period has not yet passed.
    Waiting {
        /// Ledger at which the operation becomes `Ready`.
        ready_ledger: u32,
        /// Current ledger sequence at the time of the query.
        current_ledger: u32,
    },
    /// Operation is ready to be executed.
    Ready {
        /// Ledger at which the operation became `Ready`.
        ready_ledger: u32,
        /// Current ledger sequence at the time of the query.
        current_ledger: u32,
    },
    /// Operation has been executed (`DONE_LEDGER`).
    Done,
}

/// A pending timelock operation returned by [`list_pending`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PendingTimelockOperation {
    /// The operation identifier.
    pub operation_id: TimelockOperationId,
    /// The current state of the operation.
    pub state: TimelockOperationStateView,
    /// The timelock contract address.
    pub timelock_contract: ScAddress,
    /// The `request_id` from the `SaTimelockScheduled` audit row that originated
    /// this operation.
    pub scheduled_at_request_id: String,
}

// ── Builder-pattern argument structs ─────────────────────────────────────────
//
// Each public timelock function takes a single `*Args` struct with named builder
// fields (via [`bon::Builder`]), mirroring the `SubmitInvokeArgs` pattern in
// `submit.rs` and keeping call sites free of positional-argument ordering
// constraints.

/// Arguments for [`schedule_upgrade`].
///
/// Construct via the [`bon::Builder`]-generated `.builder()` method.
#[derive(bon::Builder)]
#[non_exhaustive]
pub struct TimelockScheduleArgs<'a> {
    /// C-strkey of the timelock controller contract.
    pub timelock_contract_strkey: &'a str,
    /// C-strkey of the target contract to invoke when the operation executes.
    pub target_strkey: &'a str,
    /// Name of the target function to invoke.
    pub function: &'a str,
    /// Soroban `ScVal` arguments passed to the target function at execute time.
    #[builder(default)]
    pub args: Vec<ScVal>,
    /// 32-byte predecessor operation ID. Pass `[0u8; 32]` for no predecessor.
    #[builder(default)]
    pub predecessor: [u8; 32],
    /// Minimum delay in ledgers before the operation can be executed.
    pub delay_ledgers: u32,
    /// Signer holding the proposer role on the timelock contract.
    pub signer: &'a (dyn Signer + Send + Sync),
    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,
    /// Secondary Soroban RPC URL for `cross_confirm_event` dual-RPC defence.
    ///
    /// Use the same URL as `primary_rpc_url` to disable divergence detection.
    /// A warning is emitted at INFO level when primary and secondary are equal.
    pub secondary_rpc_url: &'a str,
    /// Stellar network passphrase.
    pub network_passphrase: &'a str,
    /// Audit-log writer.
    pub audit_writer: &'a Arc<Mutex<AuditWriter>>,
    /// Per-request correlation identifier.
    pub request_id: &'a str,
}

/// Arguments for [`cancel`].
///
/// Construct via the [`bon::Builder`]-generated `.builder()` method.
#[derive(bon::Builder)]
#[non_exhaustive]
pub struct TimelockCancelArgs<'a> {
    /// C-strkey of the timelock controller contract.
    pub timelock_contract_strkey: &'a str,
    /// The operation identifier to cancel (must be in `Pending` state).
    pub operation_id: &'a TimelockOperationId,
    /// Signer holding the canceller role on the timelock contract.
    pub signer: &'a (dyn Signer + Send + Sync),
    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,
    /// Secondary Soroban RPC URL for `cross_confirm_event` dual-RPC defence.
    pub secondary_rpc_url: &'a str,
    /// Stellar network passphrase.
    pub network_passphrase: &'a str,
    /// Audit-log writer.
    pub audit_writer: &'a Arc<Mutex<AuditWriter>>,
    /// Per-request correlation identifier.
    pub request_id: &'a str,
}

/// Arguments for [`execute`].
///
/// Construct via the [`bon::Builder`]-generated `.builder()` method.
#[derive(bon::Builder)]
#[non_exhaustive]
pub struct TimelockExecuteArgs<'a> {
    /// C-strkey of the timelock controller contract.
    pub timelock_contract_strkey: &'a str,
    /// C-strkey of the target contract (must match the scheduled operation).
    pub target_strkey: &'a str,
    /// Name of the target function (must match the scheduled operation).
    pub function: &'a str,
    /// Soroban `ScVal` arguments (must match the scheduled operation).
    #[builder(default)]
    pub args: Vec<ScVal>,
    /// 32-byte predecessor operation ID (must match scheduled; `[0u8; 32]` for none).
    #[builder(default)]
    pub predecessor: [u8; 32],
    /// 32-byte salt used when the operation was scheduled.
    pub salt: [u8; 32],
    /// Signer holding the executor role on the timelock contract.
    pub signer: &'a (dyn Signer + Send + Sync),
    /// Primary Soroban RPC URL (simulate + submit).
    pub primary_rpc_url: &'a str,
    /// Secondary Soroban RPC URL for cross-RPC state pre-check + event confirm.
    pub secondary_rpc_url: &'a str,
    /// Stellar network passphrase.
    pub network_passphrase: &'a str,
    /// Audit-log writer.
    pub audit_writer: &'a Arc<Mutex<AuditWriter>>,
    /// Per-request correlation identifier.
    pub request_id: &'a str,
    /// Caller-supplied operation identifier for pre-flight state check and
    /// mismatch validation.
    ///
    /// When `Some`, the state is queried FIRST (before `simulate_hash_operation`)
    /// to skip the hash round-trip for non-Ready ops. Pass `None` when no prior
    /// ID is available; state check is deferred to after hash derivation.
    pub expected_operation_id: Option<&'a TimelockOperationId>,
}

// ── Salt derivation ───────────────────────────────────────────────────────────

/// Derives a non-deterministic 32-byte salt for a timelock schedule call.
///
/// Salt = `sha256(request_id_bytes || timestamp_nanos_be)`.
///
/// Two calls with different `request_id` values (or different wall-clock times)
/// produce different salts, ensuring that identical `(target, function, args,
/// predecessor)` arguments schedule DIFFERENT operations with distinct IDs.
///
/// # Security
///
/// Salt non-determinism prevents operation-ID collisions from a replayed
/// schedule request. The `request_id` component anchors the salt to the
/// specific scheduling invocation; the `timestamp_nanos_be` component adds
/// entropy independent of the caller.
///
/// # Test-helper visibility
///
/// Production code calls `derive_schedule_salt_impl` (private, always compiled).
/// External test consumers access the public wrapper `derive_schedule_salt` via
/// the `#[cfg(any(test, feature = "test-helpers"))]`-gated re-export in `src/lib.rs`.
/// Test-only public helpers must be feature-gated; `#[doc(hidden)] pub fn`
/// without a feature gate is reviewer-blocking.  The private `_impl` splits
/// compilation from exposure so the production call site never depends on the
/// `test-helpers` feature flag.
fn derive_schedule_salt_impl(request_id: &str, timestamp_nanos: u128) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(timestamp_nanos.to_be_bytes());
    hasher.finalize().into()
}

/// Feature-gated public wrapper around `derive_schedule_salt_impl`.
///
/// Exposes the internal salt-derivation logic for adversarial fixture tests
/// that must call the function directly so hashing-order refactors are caught
/// at compile time.  Only compiled when the `test-helpers` feature is active
/// or in `#[cfg(test)]` builds.
///
/// See the rustdoc on `derive_schedule_salt_impl` for the algorithm.
#[cfg(any(test, feature = "test-helpers"))]
pub fn derive_schedule_salt(request_id: &str, timestamp_nanos: u128) -> [u8; 32] {
    derive_schedule_salt_impl(request_id, timestamp_nanos)
}

// ── OZ error code → failure reason mappers ───────────────────────────────────

/// Maps an OZ Timelock wire error string to a [`TimelockScheduleFailureReason`].
///
/// OZ contract error codes are embedded in simulation error strings as numeric
/// suffixes (e.g., `"Error(Contract, #4004)"` or `"HostError: Value(Status(ContractError(4004)))"`).
/// This parser extracts the numeric code and maps it to the typed enum.
fn classify_schedule_error(sim_error: &str) -> TimelockScheduleFailureReason {
    // Extract once and reuse; avoids repeated regex/scan over the same input.
    let oz_code = extract_oz_error_code(sim_error);
    if oz_code == Some(OzTimelockError::Unauthorized as u32) {
        TimelockScheduleFailureReason::Unauthorized
    } else if oz_code == Some(OzTimelockError::OperationAlreadyScheduled as u32) {
        TimelockScheduleFailureReason::OperationAlreadyScheduled
    } else if oz_code == Some(OzTimelockError::InsufficientDelay as u32) {
        TimelockScheduleFailureReason::InsufficientDelay
    } else if sim_error.contains("simulation") || sim_error.contains("simulate") {
        TimelockScheduleFailureReason::SimulationFailed
    } else {
        TimelockScheduleFailureReason::Other
    }
}

/// Maps an OZ Timelock wire error string to a [`TimelockCancelFailureReason`].
///
/// # Canonical failure mode
///
/// `Timelock::cancel` delegates to `cancel_operation` in
/// `packages/governance/src/timelock/storage.rs:376-378` (SHA `3f81125`),
/// which panics with `TimelockError::InvalidOperationState` (code 4002) when
/// the operation is not in the `Pending` state. An unscheduled operation has
/// `ready_ledger == UNSET_LEDGER (0)` and `is_operation_pending` returns `false`
/// → code 4002 fires. Code 4006 (`OperationNotScheduled`) is NOT reachable
/// from the canonical OZ cancel path.
fn classify_cancel_error(sim_error: &str) -> TimelockCancelFailureReason {
    // Use OzTimelockError typed enum values for comparison.
    // Code 4006 branch is absent — unreachable from canonical OZ
    // cancel_operation (storage.rs:376-378, SHA 3f81125).
    match extract_oz_error_code(sim_error) {
        Some(c) if c == OzTimelockError::Unauthorized as u32 => {
            TimelockCancelFailureReason::Unauthorized
        }
        Some(c) if c == OzTimelockError::InvalidOperationState as u32 => {
            TimelockCancelFailureReason::InvalidOperationState
        }
        _ if sim_error.contains("simulation") || sim_error.contains("simulate") => {
            TimelockCancelFailureReason::SimulationFailed
        }
        _ => TimelockCancelFailureReason::Other,
    }
}

/// Maps an OZ Timelock wire error string to a [`TimelockExecuteFailureReason`].
fn classify_execute_error(sim_error: &str) -> TimelockExecuteFailureReason {
    // Use OzTimelockError typed enum values for comparison.
    match extract_oz_error_code(sim_error) {
        Some(c) if c == OzTimelockError::InvalidOperationState as u32 => {
            TimelockExecuteFailureReason::InvalidOperationState
        }
        Some(c) if c == OzTimelockError::UnexecutedPredecessor as u32 => {
            TimelockExecuteFailureReason::UnexecutedPredecessor
        }
        _ if sim_error.contains("simulation") || sim_error.contains("simulate") => {
            TimelockExecuteFailureReason::SimulationFailed
        }
        _ => TimelockExecuteFailureReason::Other,
    }
}

/// Extracts the numeric error code from an OZ contract simulation error string.
///
/// Matches patterns like `"#4004"` or `"ContractError(4004)"` in the error
/// message produced by Soroban RPC when the OZ contract panics with a
/// `contracterror`.
fn extract_oz_error_code(error: &str) -> Option<u32> {
    // Pattern: "#4004" (Soroban RPC canonical form per stellar-rpc 26.x)
    if let Some(pos) = error.find('#') {
        let rest = &error[pos + 1..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end > 0
            && let Ok(n) = rest[..end].parse::<u32>()
        {
            return Some(n);
        }
    }
    // Pattern: "ContractError(4004)"
    if let Some(pos) = error.find("ContractError(") {
        let rest = &error[pos + "ContractError(".len()..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if end > 0
            && let Ok(n) = rest[..end].parse::<u32>()
        {
            return Some(n);
        }
    }
    None
}

// ── Cross-RPC operation state query ──────────────────────────────────────────

/// Queries `get_operation_state` and `get_operation_ledger` via primary and
/// secondary RPCs concurrently and returns the agreed-upon state view.
///
/// The RPC call is a read-only simulate of `get_operation_state(operation_id)`
/// followed by `get_operation_ledger(operation_id)` on the timelock contract.
/// Both RPCs must agree on the `ready_ledger` value; divergence is returned
/// as [`SaError::NetworkRpcDivergence`].
///
/// # Errors
///
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPCs return
///   different `ready_ledger` values for the same `operation_id`.
/// - [`SaError::DeploymentFailed`] — RPC query or parse failure.
pub(crate) async fn query_operation_state_cross_rpc(
    primary: &StellarRpcClient,
    secondary: &StellarRpcClient,
    timelock_contract_strkey: &str,
    operation_id: &TimelockOperationId,
    network_passphrase: &str,
    request_id: &str,
) -> Result<TimelockOperationStateView, SaError> {
    let (primary_ledger, secondary_ledger) = tokio::join!(
        query_operation_ready_ledger(
            primary,
            timelock_contract_strkey,
            operation_id,
            network_passphrase
        ),
        query_operation_ready_ledger(
            secondary,
            timelock_contract_strkey,
            operation_id,
            network_passphrase
        ),
    );

    let primary_val = primary_ledger.map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("primary RPC timelock state query failed: {e}"),
    })?;
    let secondary_val = secondary_ledger.map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("secondary RPC timelock state query failed: {e}"),
    })?;

    if primary_val != secondary_val {
        // Compute digest of each value for the divergence forensic spine.
        let primary_digest = Sha256::digest(primary_val.to_be_bytes());
        let secondary_digest = Sha256::digest(secondary_val.to_be_bytes());
        let primary_first8: String = primary_digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let secondary_first8: String = secondary_digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(SaError::NetworkRpcDivergence {
            rule_id: 0, // Timelock queries are not rule-scoped; use sentinel 0.
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                redact_strkey_first5_last5(timelock_contract_strkey),
            ),
            primary_view_digest_first8: primary_first8,
            secondary_view_digest_first8: secondary_first8,
            request_id: request_id.to_owned(),
        });
    }

    Ok(ready_ledger_to_state_view(primary_val))
}

/// Converts the raw `ready_ledger` storage value to a `TimelockOperationStateView`.
///
/// Per OZ `packages/governance/src/timelock/storage.rs:116-126` (SHA `3f81125`):
/// - `ready_ledger == UNSET_LEDGER (0)` → `Unset`.
/// - `ready_ledger == DONE_LEDGER (1)` → `Done`.
/// - `ready_ledger > current_ledger` → `Waiting`.
/// - `ready_ledger <= current_ledger` → `Ready`.
///
/// The `current_ledger` field in `Waiting` and `Ready` is set to 0 in the
/// offline path (no live ledger sequence available without an additional RPC
/// call). The `list_pending` path supplies the primary RPC's latest ledger.
fn ready_ledger_to_state_view(ready_ledger: u32) -> TimelockOperationStateView {
    // We cannot fetch `current_ledger` in this helper without an additional RPC
    // call. The caller is responsible for enriching the view when needed.
    // For divergence detection, only `ready_ledger` equality matters.
    match ready_ledger {
        UNSET_LEDGER => TimelockOperationStateView::Unset,
        DONE_LEDGER => TimelockOperationStateView::Done,
        _ => {
            // Approximate: use ready_ledger as both ready_ledger and
            // current_ledger placeholder. Callers that need the accurate
            // current_ledger (list_pending) enrich via get_latest_ledger.
            TimelockOperationStateView::Waiting {
                ready_ledger,
                current_ledger: 0, // enriched by caller
            }
        }
    }
}

/// Enriches a `TimelockOperationStateView` with the actual `current_ledger`.
///
/// Converts `Waiting { ready_ledger, current_ledger: 0 }` to either
/// `Waiting` or `Ready` based on whether `current_ledger >= ready_ledger`.
fn enrich_state_view_with_current_ledger(
    state: TimelockOperationStateView,
    current_ledger: u32,
) -> TimelockOperationStateView {
    match state {
        TimelockOperationStateView::Waiting { ready_ledger, .. } => {
            if current_ledger >= ready_ledger {
                TimelockOperationStateView::Ready {
                    ready_ledger,
                    current_ledger,
                }
            } else {
                TimelockOperationStateView::Waiting {
                    ready_ledger,
                    current_ledger,
                }
            }
        }
        other => other,
    }
}

/// Queries the `ready_ledger` raw storage value for an operation from a single RPC.
///
/// Simulates `get_operation_ledger(operation_id)` on the timelock contract.
/// Returns the raw `u32` ready_ledger sentinel value.
///
/// # Parameters
///
/// - `network_passphrase` — threaded from the caller for testnet/mainnet parity.
async fn query_operation_ready_ledger(
    rpc: &StellarRpcClient,
    timelock_contract_strkey: &str,
    operation_id: &TimelockOperationId,
    network_passphrase: &str,
) -> Result<u32, String> {
    // Build a dummy simulate transaction targeting `get_operation_ledger`.
    // This is a read-only view function on the OZ timelock contract.
    // Timelock::get_operation_ledger(e, operation_id: BytesN<32>) -> u32
    // OZ mod.rs:116 (SHA 3f81125).
    //
    // We cannot use the stellar-governance crate's types directly here because
    // that crate provides a soroban-sdk `contracttrait` which requires a host
    // `Env` that only exists inside a soroban-sdk simulation environment.
    // Instead, we construct the InvokeHostFunction XDR directly, which is the
    // established pattern in this codebase (see rules.rs::simulate_read_only).

    let server =
        Client::new(rpc.url()).map_err(|e| format!("RPC Client construction failed: {e}"))?;

    // Encode operation_id as ScVal::Bytes(BytesM<32>)
    let op_id_bytes: BytesM<32> = operation_id
        .inner
        .to_vec()
        .try_into()
        .map_err(|e| format!("operation_id BytesM encoding failed: {e:?}"))?;
    let op_id_scval = ScVal::Bytes(stellar_xdr::ScBytes(
        op_id_bytes
            .as_slice()
            .to_vec()
            .try_into()
            .map_err(|e| format!("ScBytes encoding failed: {e:?}"))?,
    ));

    let timelock_sc_address = parse_c_strkey_to_smart_account(timelock_contract_strkey)
        .map_err(|e| format!("timelock address parse failed: {e:?}"))?;

    // The OZ Timelock trait method is `get_operation_ledger`
    // (`packages/governance/src/timelock/mod.rs:116`, SHA `3f81125`).
    // Soroban Symbols permit up to 32 chars; `get_operation_ledger` is 21 chars
    // and fits. Any abbreviated name triggers "function not found" at simulate-time,
    // silently breaking the ready-window pre-check and list_pending cross-RPC query.
    let fn_name = ScSymbol::try_from("get_operation_ledger")
        .map_err(|e| format!("function name encoding failed: {e:?}"))?;
    let args_vecm: VecM<ScVal> = vec![op_id_scval]
        .try_into()
        .map_err(|e| format!("args VecM encoding failed: {e:?}"))?;

    let host_fn = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: timelock_sc_address.clone(),
        function_name: fn_name,
        args: args_vecm,
    });

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_fn,
            auth: VecM::default(),
        }),
    };

    // Build a fee-less transaction for simulation. We use a minimal placeholder
    // for the source account since the `get_operation_ledger` view function does
    // not require auth and cannot be auth-gated. `BaselibAccount::new` requires a
    // G-strkey (not a C-strkey) so we use the zero-pubkey G-strkey constant —
    // structurally valid and accepted by Soroban RPC for fee-less view-function
    // simulate calls (resourceFee=0; sequence-number 0 is acceptable for read-only
    // simulate of view functions).
    let dummy_source_g_strkey: String = stellar_strkey::ed25519::PublicKey([0u8; 32])
        .to_string()
        .as_str()
        .to_owned();
    let source_account = BaselibAccount::new(&dummy_source_g_strkey, "0")
        .map_err(|e| format!("BaselibAccount: {e:?}"))?;
    let mut source_account_mut = source_account;

    // The caller-supplied `network_passphrase` is used (not a hard-coded network
    // string) so this path works correctly on mainnet and testnet alike.
    let mut tx_builder = TransactionBuilder::new(&mut source_account_mut, network_passphrase, None);
    tx_builder.fee(BASE_FEE_STROOPS);
    tx_builder.add_operation(op);
    let tx_for_sim = tx_builder.build_for_simulation();

    let sim_envelope = tx_for_sim
        .to_envelope()
        .map_err(|e| format!("to_envelope failed: {e:?}"))?;
    let sim_response = server
        .simulate_transaction_envelope(&sim_envelope, None)
        .await
        .map_err(|e| format!("simulate_transaction_envelope failed: {e}"))?;

    if let Some(err) = &sim_response.error {
        // If the operation is unscheduled, OZ `get_operation_ledger` returns
        // UNSET_LEDGER (0) directly — it does not panic. Any simulation error
        // here indicates a real RPC failure, not an "operation not found".
        return Err(format!("simulation error: {err}"));
    }

    let return_val = sim_response
        .results()
        .map_err(|e| format!("simulate results decode failed: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "simulate returned no result".to_owned())?
        .xdr;

    match return_val {
        ScVal::U32(n) => Ok(n),
        other => Err(format!(
            "get_operation_ledger returned unexpected ScVal: {other:?}"
        )),
    }
}

// ── Audit emission helpers ────────────────────────────────────────────────────

/// Emits a `SaTimelockScheduled` audit row.
///
/// # Errors
///
/// Returns [`SaError::TimelockScheduleFailed`] with reason
/// [`TimelockScheduleFailureReason::AuditWriterPoisoned`] if the shared
/// `AuditWriter` mutex is poisoned.
///
/// Write failures (I/O errors on the audit file) are logged as warnings and
/// treated as non-fatal; only mutex poison is a hard fail-CLOSED.
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible audit-field set: mirrors SaTimelockScheduled EventKind shape"
)]
fn emit_scheduled_audit(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    operation_id: &TimelockOperationId,
    timelock_contract_strkey: &str,
    target_strkey: &str,
    function: &str,
    delay_ledgers: u32,
    proposer_strkey: &str,
    schedule_tx_hash: &str,
    request_id: &str,
) -> Result<(), SaError> {
    let op_id_hex = operation_id.to_hex();
    let op_id_redacted = operation_id.redacted();
    let hash_len = schedule_tx_hash.len();
    let tx_redacted = if hash_len >= 16 {
        format!(
            "{}...{}",
            &schedule_tx_hash[..8],
            &schedule_tx_hash[hash_len - 8..]
        )
    } else {
        schedule_tx_hash.to_owned()
    };

    let timelock_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(timelock_contract_strkey));
    let target_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(target_strkey));
    let proposer_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(proposer_strkey));

    let entry = AuditEntry::new_sa_timelock_scheduled(
        op_id_redacted,
        op_id_hex,
        timelock_redacted,
        target_redacted,
        function,
        delay_ledgers,
        proposer_redacted,
        tx_redacted,
        None::<&str>, // chain_id: not available in the audit helper scope
        request_id,
    );

    // Fail-CLOSED on mutex poison: do not silently swallow audit failures.
    let mut guard = audit_writer.lock().map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            context = %AuditWriterPoisonContext::TimelockScheduleEmission,
            "audit writer mutex poisoned during SaTimelockScheduled emission"
        );
        SaError::TimelockScheduleFailed {
            failure_reason: TimelockScheduleFailureReason::AuditWriterPoisoned,
            redacted_reason: format!(
                "audit writer poisoned: {}",
                AuditWriterPoisonContext::TimelockScheduleEmission
            ),
            request_id: request_id.to_owned(),
        }
    })?;

    if let Err(e) = guard.write_entry(entry) {
        tracing::warn!(
            request_id = %request_id,
            error = %e,
            "SaTimelockScheduled audit write failed (I/O error)"
        );
    }

    Ok(())
}

/// Emits a `SaTimelockCancelled` audit row.
///
/// # Errors
///
/// Returns [`SaError::TimelockCancelFailed`] with reason
/// [`TimelockCancelFailureReason::AuditWriterPoisoned`] if the shared
/// `AuditWriter` mutex is poisoned.
fn emit_cancelled_audit(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    operation_id: &TimelockOperationId,
    timelock_contract_strkey: &str,
    canceller_strkey: &str,
    cancel_tx_hash: &str,
    request_id: &str,
) -> Result<(), SaError> {
    let hash_len = cancel_tx_hash.len();
    let tx_redacted = if hash_len >= 16 {
        format!(
            "{}...{}",
            &cancel_tx_hash[..8],
            &cancel_tx_hash[hash_len - 8..]
        )
    } else {
        cancel_tx_hash.to_owned()
    };

    let timelock_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(timelock_contract_strkey));
    let canceller_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(canceller_strkey));

    // Pass operation_id_full_hex so the audit writer can deduplicate exact entries.
    let entry = AuditEntry::new_sa_timelock_cancelled(
        operation_id.redacted(),
        operation_id.to_hex(),
        timelock_redacted,
        canceller_redacted,
        tx_redacted,
        None::<&str>, // chain_id: not available in the audit helper scope
        request_id,
    );

    // Fail-CLOSED on mutex poison: do not silently swallow audit failures.
    let mut guard = audit_writer.lock().map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            context = %AuditWriterPoisonContext::TimelockCancelEmission,
            "audit writer mutex poisoned during SaTimelockCancelled emission"
        );
        SaError::TimelockCancelFailed {
            failure_reason: TimelockCancelFailureReason::AuditWriterPoisoned,
            redacted_reason: format!(
                "audit writer poisoned: {}",
                AuditWriterPoisonContext::TimelockCancelEmission
            ),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?;

    if let Err(e) = guard.write_entry(entry) {
        tracing::warn!(
            request_id = %request_id,
            error = %e,
            "SaTimelockCancelled audit write failed (I/O error)"
        );
    }

    Ok(())
}

/// Emits a `SaTimelockExecuted` audit row.
///
/// # Errors
///
/// Returns [`SaError::TimelockExecuteFailed`] with reason
/// [`TimelockExecuteFailureReason::AuditWriterPoisoned`] if the shared
/// `AuditWriter` mutex is poisoned.
fn emit_executed_audit(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    operation_id: &TimelockOperationId,
    timelock_contract_strkey: &str,
    executor_strkey: Option<&str>,
    execute_tx_hash: &str,
    request_id: &str,
) -> Result<(), SaError> {
    let hash_len = execute_tx_hash.len();
    let tx_redacted = if hash_len >= 16 {
        format!(
            "{}...{}",
            &execute_tx_hash[..8],
            &execute_tx_hash[hash_len - 8..]
        )
    } else {
        execute_tx_hash.to_owned()
    };

    let timelock_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(timelock_contract_strkey));
    let executor_redacted = executor_strkey
        .map(|s| RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(s)));

    // Pass operation_id_full_hex so the audit writer can deduplicate exact entries.
    let entry = AuditEntry::new_sa_timelock_executed(
        operation_id.redacted(),
        operation_id.to_hex(),
        timelock_redacted,
        executor_redacted,
        tx_redacted,
        None::<&str>, // chain_id: not available in the audit helper scope
        request_id,
    );

    // Fail-CLOSED on mutex poison: do not silently swallow audit failures.
    let mut guard = audit_writer.lock().map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            context = %AuditWriterPoisonContext::TimelockExecuteEmission,
            "audit writer mutex poisoned during SaTimelockExecuted emission"
        );
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::AuditWriterPoisoned,
            redacted_reason: format!(
                "audit writer poisoned: {}",
                AuditWriterPoisonContext::TimelockExecuteEmission
            ),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?;

    if let Err(e) = guard.write_entry(entry) {
        tracing::warn!(
            request_id = %request_id,
            error = %e,
            "SaTimelockExecuted audit write failed (I/O error)"
        );
    }

    Ok(())
}

// ── Event cross-confirmation (event-emission integrity check) ────────────────

/// Error type returned by [`cross_confirm_event`].
///
/// Distinguishes between a missing-event failure (maps to `EventConfirmationMissing`
/// in callers) and an RPC-divergence failure (propagated as
/// `SaError::NetworkRpcDivergence` — dual-RPC defence-in-depth).
enum CrossConfirmError {
    /// The expected event was not found in the transaction meta (at least one RPC).
    EventMissing(String),
    /// Primary and secondary RPCs returned divergent event presence for the same tx.
    ///
    /// A compromised primary RPC that accepted `sendTransaction` could return doctored
    /// `getTransaction` meta without the expected event, causing the wallet to treat a
    /// successfully-scheduled operation as failed and retry with a new salt — duplicate
    /// ops, fee waste, DoS. Requiring event presence on BOTH RPCs closes this vector.
    ///
    /// Carries `primary_present` / `secondary_present` so the call site can emit a
    /// `SaTimelockDivergencePostSubmit` audit row before propagating the error.
    Divergence {
        sa_err: SaError,
        primary_present: bool,
        secondary_present: bool,
    },
}

/// Verifies that a submitted transaction emitted the expected OZ timelock event
/// on BOTH primary and secondary RPCs concurrently.
///
/// Fetches the transaction meta via `stellar_rpc_client::Client::get_transaction` on
/// BOTH RPCs concurrently (via `tokio::join!`). The expected event MUST be present
/// in BOTH responses. If either RPC fails to confirm the event, or if the two RPCs
/// disagree (event present in primary but not secondary, or vice-versa), returns
/// the appropriate [`CrossConfirmError`].
///
/// For each event in each transaction response, checks:
///
/// 1. The event `contract_id` matches `timelock_contract_strkey` (C-strkey →
///    raw 32-byte hash comparison via stellar-strkey decode).
/// 2. The first topic (`ScVal::Symbol`) equals the OZ snake_case event name
///    (`"operation_scheduled"` / `"operation_cancelled"` / `"operation_executed"`).
///    This is the topic emitted by the `#[contractevent]` macro for the struct
///    name converted to snake_case (OZ mod.rs:382-392 / 433-442 / 479-481, SHA 3f81125;
///    macro derive in rs-soroban-sdk soroban-sdk-macros/src/derive_event.rs:105).
/// 3. The second topic (`ScVal::Bytes`) contains the expected 32-byte operation_id.
///
/// # Event format (OZ timelock-controller v0.7.1, SHA 3f81125)
///
/// | event_kind | topic[0] | topic[1] | topic[2] |
/// |---|---|---|---|
/// | `OperationScheduled` | `Symbol("operation_scheduled")` | `Bytes(id)` | `Address(target)` |
/// | `OperationCancelled` | `Symbol("operation_cancelled")` | `Bytes(id)` | — |
/// | `OperationExecuted` | `Symbol("operation_executed")` | `Bytes(id)` | `Address(target)` |
///
/// Reference: OZ `packages/governance/src/timelock/mod.rs:157,221,279` (SHA 3f81125).
///
/// # Cross-RPC divergence digest
///
/// When the two RPCs disagree, the forensic spine encodes each side independently
/// as `SHA-256(tx_hash || event_kind || presence_byte)[..8]` (first-8 hex chars).
/// The digest changes per incident, per event kind, and per side — providing
/// per-incident forensic signal rather than a constant two-value set.
///
/// There is no canonical dual-RPC `getTransaction` primitive for this check;
/// `cross_confirm_event` is wallet-specific defence-in-depth.
///
/// # Errors
///
/// - [`CrossConfirmError::EventMissing`] — event not found on at least one RPC or
///   tx fetch failed.
/// - [`CrossConfirmError::Divergence`] — primary and secondary RPCs disagree on
///   event presence; wraps a [`SaError::NetworkRpcDivergence`].
#[allow(clippy::too_many_arguments)]
async fn cross_confirm_event(
    event_kind: &str,
    tx_hash: &str,
    expected_operation_id: &TimelockOperationId,
    timelock_contract_strkey: &str,
    primary_rpc: &str,
    secondary_rpc: &str,
    request_id: &str,
) -> Result<(), CrossConfirmError> {
    // Derive the snake_case topic symbol from the PascalCase event_kind.
    // OZ macro: struct OperationScheduled → topic[0] = "operation_scheduled".
    // rs-soroban-sdk soroban-sdk-macros/src/derive_event.rs:105 (to_snake_case).
    let expected_topic_symbol = to_snake_case(event_kind);

    // Parse the contract_id bytes once; shared between both RPC checks.
    // Fail-CLOSED on malformed C-strkey rather than falling back to zero-hash,
    // which would silently match any event with zero contract_id.
    let expected_contract_bytes: [u8; 32] =
        stellar_strkey::Contract::from_string(timelock_contract_strkey)
            .map(|c| c.0)
            .map_err(|e| {
                CrossConfirmError::EventMissing(format!(
                    "invalid timelock C-strkey for event confirmation: {e:?}"
                ))
            })?;

    let build_server = |url: &str| {
        Client::new(url)
            .map_err(|e| format!("RPC Client construction for event confirmation failed: {e}"))
    };

    let primary_server = build_server(primary_rpc).map_err(CrossConfirmError::EventMissing)?;
    let secondary_server = build_server(secondary_rpc).map_err(CrossConfirmError::EventMissing)?;

    // stellar-rpc-client get_transaction takes &Hash (XDR), not &str.
    // Convert hex tx_hash string → [u8; 32] → Hash.
    let tx_hash_bytes: [u8; 32] = hex::decode(tx_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            CrossConfirmError::EventMissing(format!("invalid tx_hash hex: {tx_hash}"))
        })?;
    let tx_hash_xdr = Hash(tx_hash_bytes);

    // Fetch transaction meta from both RPCs concurrently.
    let (primary_result, secondary_result) = tokio::join!(
        primary_server.get_transaction(&tx_hash_xdr),
        secondary_server.get_transaction(&tx_hash_xdr),
    );

    let primary_response = primary_result.map_err(|e| {
        CrossConfirmError::EventMissing(format!("primary get_transaction failed: {e}"))
    })?;
    let secondary_response = secondary_result.map_err(|e| {
        CrossConfirmError::EventMissing(format!("secondary get_transaction failed: {e}"))
    })?;

    // Check event presence on both RPCs.
    let primary_found = event_present_in_response(
        &primary_response,
        &expected_contract_bytes,
        &expected_topic_symbol,
        expected_operation_id,
    );
    let secondary_found = event_present_in_response(
        &secondary_response,
        &expected_contract_bytes,
        &expected_topic_symbol,
        expected_operation_id,
    );

    match (primary_found, secondary_found) {
        (true, true) => {
            tracing::debug!(
                tx_hash = %&tx_hash[..tx_hash.len().min(16)],
                event_kind = %event_kind,
                operation_id = %expected_operation_id.redacted(),
                "timelock: cross-confirmed event on both RPCs"
            );
            Ok(())
        }
        (true, false) => {
            // (true, false): primary confirms the event; secondary does not.
            // Compromised secondary or secondary lagging behind ledger close.
            // Divergence: fail-CLOSED.
            Err(CrossConfirmError::Divergence {
                sa_err: make_event_confirm_divergence_error(
                    true,  // primary_present
                    false, // secondary_present
                    tx_hash,
                    event_kind,
                    timelock_contract_strkey,
                    request_id,
                ),
                primary_present: true,
                secondary_present: false,
            })
        }
        (false, true) => {
            // (false, true): primary drops the event; secondary confirms it.
            // Most likely scenario: a compromised primary that accepted `sendTransaction`
            // but doctored `getTransaction` meta to omit the event. Fail-CLOSED.
            Err(CrossConfirmError::Divergence {
                sa_err: make_event_confirm_divergence_error(
                    false, // primary_present
                    true,  // secondary_present
                    tx_hash,
                    event_kind,
                    timelock_contract_strkey,
                    request_id,
                ),
                primary_present: false,
                secondary_present: true,
            })
        }
        (false, false) => {
            // Event not found on either RPC.
            // Redact tx_hash to first-8-last-8 (redaction policy).
            let hash_len = tx_hash.len();
            let tx_redacted = if hash_len >= 16 {
                format!("{}...{}", &tx_hash[..8], &tx_hash[hash_len - 8..])
            } else {
                tx_hash.to_owned()
            };
            Err(CrossConfirmError::EventMissing(format!(
                "event '{event_kind}' with operation_id {} not found in tx meta for tx {tx_redacted} \
                 (checked primary and secondary RPCs)",
                expected_operation_id.redacted()
            )))
        }
    }
}

/// Constructs a `SaError::NetworkRpcDivergence` for [`cross_confirm_event`] divergence.
///
/// Each side's digest is `SHA-256(tx_hash_bytes || event_kind_bytes || presence_byte)`:
///
/// - `tx_hash_bytes` — the raw UTF-8 bytes of the submitted transaction hash.
/// - `event_kind_bytes` — the raw UTF-8 bytes of the OZ PascalCase event name
///   (e.g. `"OperationCancelled"`).
/// - `presence_byte` — `0x01` if the event was found on that RPC; `0x00` if absent.
///
/// The digest changes per incident (different tx hash), per event kind, and per side —
/// so the forensic spine carries meaningful signal rather than a constant two-value set.
/// Each side's digest is computed independently from its own `presence_byte`.
/// The first-8-hex truncation discipline from `query_operation_state_cross_rpc` is preserved.
///
/// `primary_present` and `secondary_present` are asymmetric: the caller passes the
/// direction so the digest fields are ordered consistently: primary digest first, secondary
/// digest second.
fn make_event_confirm_divergence_error(
    primary_present: bool,
    secondary_present: bool,
    tx_hash: &str,
    event_kind: &str,
    timelock_contract_strkey: &str,
    request_id: &str,
) -> SaError {
    // Digest input: tx_hash || event_kind || presence_byte.
    // Each side hashed independently so the digest reflects its own view.
    let compute_digest = |present: bool| -> String {
        let mut hasher = Sha256::new();
        hasher.update(tx_hash.as_bytes());
        hasher.update(event_kind.as_bytes());
        hasher.update([u8::from(present)]);
        let digest = hasher.finalize();
        digest[..8].iter().map(|b| format!("{b:02x}")).collect()
    };
    let primary_first8 = compute_digest(primary_present);
    let secondary_first8 = compute_digest(secondary_present);
    SaError::NetworkRpcDivergence {
        rule_id: 0, // Timelock queries are not rule-scoped; use sentinel 0.
        smart_account_redacted: RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(
            timelock_contract_strkey,
        )),
        primary_view_digest_first8: primary_first8,
        secondary_view_digest_first8: secondary_first8,
        request_id: request_id.to_owned(),
    }
}

/// Emits a [`stellar_agent_core::audit_log::schema::EventKind::SaTimelockDivergencePostSubmit`]
/// audit row when [`cross_confirm_event`] returns `Divergence` on a timelock path.
///
/// The on-chain op may have landed; this forensic row captures what the two RPCs observed
/// so the operator can reconcile the ledger state.  Write failures are warn-logged but
/// never propagated — divergence emission is best-effort (the error is the primary signal).
///
/// # Redaction
///
/// `smart_account_redacted` is the timelock contract address redacted to first-5-last-5;
/// `operation_id_redacted` is the operation ID redacted form; `tx_hash_redacted` is
/// first-8-last-8 hex of the transaction hash.
#[allow(clippy::too_many_arguments)]
fn emit_timelock_divergence_audit(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    timelock_contract_strkey: &str,
    operation_id: &TimelockOperationId,
    tx_hash: &str,
    path: &str,
    primary_present: bool,
    secondary_present: bool,
    chain_id: Option<&str>,
    request_id: &str,
) {
    let smart_account_redacted =
        RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(timelock_contract_strkey));
    let operation_id_redacted = operation_id.redacted();
    let hash_len = tx_hash.len();
    let tx_hash_redacted = if hash_len >= 16 {
        format!("{}...{}", &tx_hash[..8], &tx_hash[hash_len - 8..])
    } else {
        tx_hash.to_owned()
    };

    use stellar_agent_core::audit_log::entry::AuditEntry;
    let entry = AuditEntry::new_sa_timelock_divergence_post_submit(
        smart_account_redacted,
        operation_id_redacted,
        tx_hash_redacted,
        path,
        primary_present,
        secondary_present,
        chain_id,
        request_id,
    );

    match audit_writer.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.write_entry(entry) {
                tracing::warn!(
                    error = %e,
                    path = %path,
                    "timelock divergence audit write failed"
                );
            }
        }
        Err(_poison) => {
            tracing::warn!(
                target: "stellar_agent::audit",
                path = %path,
                "audit-writer mutex poisoned; SaTimelockDivergencePostSubmit row dropped"
            );
        }
    }
}

/// Checks whether the expected timelock event is present in a `getTransaction` response.
///
/// Returns `true` if the event with the given `expected_topic_symbol` (snake_case),
/// matching `expected_contract_bytes`, and carrying the expected `operation_id` bytes
/// in `topic[1]` is found in the response. Returns `false` if the response contains
/// no events or the event is absent.
///
/// Used by [`cross_confirm_event`] to check both primary and secondary RPC responses
/// independently before comparing them.
fn event_present_in_response(
    tx_response: &GetTransactionResponse,
    expected_contract_bytes: &[u8; 32],
    expected_topic_symbol: &str,
    expected_operation_id: &TimelockOperationId,
) -> bool {
    // stellar-rpc-client GetTransactionResponse exposes events.contract_events:
    // Vec<Vec<ContractEvent>> (outer = per-op, inner = events for that op).
    let contract_events_by_op = &tx_response.events.contract_events;

    // Flatten across all operations (we expect exactly one InvokeHostFunction op).
    for events_for_op in contract_events_by_op {
        for event in events_for_op {
            // Check contract_id matches the timelock contract.
            // Hash is stellar_xdr::Hash(Uint256([u8;32])); compare inner bytes.
            let contract_id_matches = event
                .contract_id
                .as_ref()
                .is_some_and(|hash| hash.0.0 == *expected_contract_bytes);
            if !contract_id_matches {
                continue;
            }

            // Destructure the ContractEvent body.
            let ContractEventBody::V0(ContractEventV0 { topics, data: _ }) = &event.body;
            // VecM implements Deref<Target=Vec<T>>; use as_slice() directly.
            let topics_slice = topics.as_slice();

            // topic[0] must be ScVal::Symbol matching the expected snake_case name.
            let Some(ScVal::Symbol(sym)) = topics_slice.first() else {
                continue;
            };
            // ScSymbol implements as_slice() → &[u8]; compare via UTF-8 decode.
            let sym_str = std::str::from_utf8(sym.as_slice()).unwrap_or("");
            if sym_str != expected_topic_symbol {
                continue;
            }

            // topic[1] must be ScVal::Bytes containing the 32-byte operation_id.
            let Some(ScVal::Bytes(op_id_bytes)) = topics_slice.get(1) else {
                continue;
            };
            // ScBytes implements as_slice() → &[u8].
            if op_id_bytes.as_slice() == expected_operation_id.as_bytes() {
                return true;
            }
        }
    }

    false
}

/// Converts a PascalCase event name to snake_case for OZ event topic matching.
///
/// `OperationScheduled` → `"operation_scheduled"`.
/// `OperationCancelled` → `"operation_cancelled"`.
/// `OperationExecuted` → `"operation_executed"`.
///
/// This mirrors the `to_snake_case()` conversion in
/// `rs-soroban-sdk/soroban-sdk-macros/src/derive_event.rs:105`.
fn to_snake_case(pascal: &str) -> String {
    let mut out = String::with_capacity(pascal.len() + 4);
    for (i, ch) in pascal.char_indices() {
        if ch.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

// ── Soroban function name constants ──────────────────────────────────────────
// OZ timelock-controller function names from examples/timelock-controller/src/contract.rs
// (SHA 3f81125): schedule = "schedule", cancel = "cancel", execute = "execute".
// The OZ `contracttrait` macro expands these as the on-chain function names.
// OZ contract.rs:272-315 (SHA 3f81125).
const FN_SCHEDULE: &str = "schedule";
const FN_CANCEL: &str = "cancel";
const FN_EXECUTE: &str = "execute";

// ── Public API ────────────────────────────────────────────────────────────────

/// Schedules an upgrade timelock operation on the OZ timelock contract.
///
/// Wraps `Timelock::schedule(target, function, args, predecessor, salt, delay, proposer)`.
/// The proposer is `signer.account_id()` (the operator G-key); the caller MUST
/// have previously granted `PROPOSER_ROLE` on the timelock contract to that address.
///
/// # Salt derivation
///
/// Salt = `sha256(request_id_bytes || timestamp_nanos_be)`. Non-deterministic per
/// call: two identical `(target, function, args, predecessor, delay)` inputs produce
/// different `operation_id` values when called with different `request_id` values
/// or at different wall-clock times. This prevents operation-ID collisions from
/// replayed schedule requests.
///
/// # Return value
///
/// Returns a [`ScheduledTimelockOperation`] containing the on-chain operation id
/// and the derived salt. The salt is not stored on-chain and cannot be recomputed;
/// the caller MUST record it for subsequent `execute` or `cancel` calls.
///
/// # Event cross-confirmation
///
/// After submission, the presence of an `OperationScheduled` event in the
/// transaction meta is verified on both primary and secondary RPCs concurrently
/// via `cross_confirm_event`.
///
/// # Errors
///
/// - [`SaError::TimelockScheduleFailed`] — authorisation, delay, or submission
///   failure; typed `failure_reason` from the OZ error code.
pub async fn schedule_upgrade(
    args: TimelockScheduleArgs<'_>,
) -> Result<ScheduledTimelockOperation, SaError> {
    let TimelockScheduleArgs {
        timelock_contract_strkey,
        target_strkey,
        function,
        args,
        predecessor,
        delay_ledgers,
        signer,
        primary_rpc_url,
        secondary_rpc_url,
        network_passphrase,
        audit_writer,
        request_id,
    } = args;

    let timestamp_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128 + d.as_secs() as u128 * 1_000_000_000)
        .unwrap_or(0u128);

    let salt_bytes = derive_schedule_salt_impl(request_id, timestamp_nanos);

    // Build the `schedule` InvokeHostFunction call.
    // OZ TimelockController::schedule signature (contract.rs:272-285, SHA 3f81125):
    //   fn schedule(e, target: Address, function: Symbol, args: Vec<Val>,
    //               predecessor: BytesN<32>, salt: BytesN<32>, delay: u32, proposer: Address)
    //   -> BytesN<32>
    let timelock_sc_address =
        parse_c_strkey_to_smart_account(timelock_contract_strkey).map_err(|e| {
            SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("timelock address parse failed: {e:?}"),
                request_id: request_id.to_owned(),
            }
        })?;

    let target_sc_address = parse_c_strkey_to_smart_account(target_strkey).map_err(|e| {
        SaError::TimelockScheduleFailed {
            failure_reason: TimelockScheduleFailureReason::SimulationFailed,
            redacted_reason: format!("target address parse failed: {e:?}"),
            request_id: request_id.to_owned(),
        }
    })?;

    let fn_sym = ScSymbol::try_from(function).map_err(|e| SaError::TimelockScheduleFailed {
        failure_reason: TimelockScheduleFailureReason::SimulationFailed,
        redacted_reason: format!("function symbol encoding failed: {e:?}"),
        request_id: request_id.to_owned(),
    })?;

    // Build ScVal arguments for the `schedule` call:
    // (target: Address, function: Symbol, args: Vec<Val>, predecessor: BytesN<32>,
    //  salt: BytesN<32>, delay: u32, proposer: Address)
    let predecessor_bytes: BytesM<32> =
        predecessor
            .to_vec()
            .try_into()
            .map_err(|e| SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("predecessor encoding failed: {e:?}"),
                request_id: request_id.to_owned(),
            })?;
    let salt_bytesm: BytesM<32> =
        salt_bytes
            .to_vec()
            .try_into()
            .map_err(|e| SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("salt encoding failed: {e:?}"),
                request_id: request_id.to_owned(),
            })?;

    // args ScVec (the args passed to the target function when executed)
    let args_vecm: VecM<ScVal> =
        args.clone()
            .try_into()
            .map_err(|e| SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("target-function args VecM encoding failed: {e:?}"),
                request_id: request_id.to_owned(),
            })?;
    let args_scval = ScVal::Vec(Some(ScVec(args_vecm)));

    let proposer_strkey = signer
        .public_key()
        .await
        .map(|pk| pk.to_string())
        .map_err(|e| SaError::TimelockScheduleFailed {
            failure_reason: TimelockScheduleFailureReason::SimulationFailed,
            redacted_reason: format!("proposer public key fetch failed: {e}"),
            request_id: request_id.to_owned(),
        })?;
    let proposer_sc_address = {
        use stellar_strkey::Strkey;
        let strkey =
            Strkey::from_string(&proposer_strkey).map_err(|e| SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("proposer strkey parse failed: {e:?}"),
                request_id: request_id.to_owned(),
            })?;
        match strkey {
            Strkey::PublicKeyEd25519(pk) => ScAddress::Account(AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk.0)),
            )),
            _ => {
                return Err(SaError::TimelockScheduleFailed {
                    failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                    redacted_reason: "proposer must be a G-strkey (ed25519 public key)".to_owned(),
                    request_id: request_id.to_owned(),
                });
            }
        }
    };

    // Invoke arguments for the timelock `schedule` call:
    let invoke_args: Vec<ScVal> = vec![
        ScVal::Address(target_sc_address),
        ScVal::Symbol(fn_sym),
        args_scval,
        ScVal::Bytes(stellar_xdr::ScBytes(
            predecessor_bytes
                .as_slice()
                .to_vec()
                .try_into()
                .map_err(|e| SaError::TimelockScheduleFailed {
                    failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                    redacted_reason: format!("predecessor ScBytes failed: {e:?}"),
                    request_id: request_id.to_owned(),
                })?,
        )),
        ScVal::Bytes(stellar_xdr::ScBytes(
            salt_bytesm.as_slice().to_vec().try_into().map_err(|e| {
                SaError::TimelockScheduleFailed {
                    failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                    redacted_reason: format!("salt ScBytes failed: {e:?}"),
                    request_id: request_id.to_owned(),
                }
            })?,
        )),
        ScVal::U32(delay_ledgers),
        ScVal::Address(proposer_sc_address),
    ];

    let invoke_args_vecm: VecM<ScVal> =
        invoke_args
            .try_into()
            .map_err(|e| SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::SimulationFailed,
                redacted_reason: format!("schedule args VecM encoding failed: {e:?}"),
                request_id: request_id.to_owned(),
            })?;

    let schedule_fn_sym =
        ScSymbol::try_from(FN_SCHEDULE).map_err(|e| SaError::TimelockScheduleFailed {
            failure_reason: TimelockScheduleFailureReason::SimulationFailed,
            redacted_reason: format!("'schedule' symbol encoding failed: {e:?}"),
            request_id: request_id.to_owned(),
        })?;

    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: timelock_sc_address.clone(),
        function_name: schedule_fn_sym,
        args: invoke_args_vecm,
    });

    // The OZ TimelockController is NOT a smart-account; `schedule` calls
    // `proposer.require_auth()` on the G-key Address argument. The smart-account
    // submit path (`submit_signed_invoke`) builds `__check_auth` entries which
    // the OZ TimelockController does not expose — all three production submit
    // calls were failing at `build_authorization_entry` (empty rule_ids rejected
    // with `SaError::RuleIdMismatch`). Use the direct G-key auth path instead.
    // OZ mod.rs:180-181 (SHA 3f81125): `proposer.require_auth()`.
    let result = crate::timelock_submit::submit_timelock_invoke_with_g_key_auth(
        crate::timelock_submit::TimelockSubmitArgs {
            host_function,
            signer,
            primary_rpc_url,
            network_passphrase,
            timeout: std::time::Duration::from_secs(60),
            op_label: "timelock_schedule",
        },
    )
    .await
    .map_err(|e| {
        let reason = format!("{e}");
        let classified = classify_schedule_error(&reason);
        SaError::TimelockScheduleFailed {
            failure_reason: classified,
            redacted_reason: augment_with_oz_error_name(&reason),
            request_id: request_id.to_owned(),
        }
    })?;

    // Extract the returned BytesN<32> operation_id from the ScVal return.
    let operation_id_bytes: [u8; 32] = match &result.return_val {
        ScVal::Bytes(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b.as_slice());
            arr
        }
        other => {
            return Err(SaError::TimelockScheduleFailed {
                failure_reason: TimelockScheduleFailureReason::Other,
                redacted_reason: format!(
                    "schedule returned unexpected ScVal (expected 32-byte Bytes): {other:?}"
                ),
                request_id: request_id.to_owned(),
            });
        }
    };

    let operation_id = TimelockOperationId::from_bytes(operation_id_bytes);

    // Cross-confirm OperationScheduled event on BOTH primary and secondary RPCs.
    cross_confirm_event(
        "OperationScheduled",
        &result.tx_hash,
        &operation_id,
        timelock_contract_strkey,
        primary_rpc_url,
        secondary_rpc_url,
        request_id,
    )
    .await
    .map_err(|e| match e {
        CrossConfirmError::EventMissing(reason) => SaError::TimelockScheduleFailed {
            failure_reason: TimelockScheduleFailureReason::EventConfirmationMissing,
            redacted_reason: reason,
            request_id: request_id.to_owned(),
        },
        CrossConfirmError::Divergence {
            sa_err,
            primary_present,
            secondary_present,
        } => {
            // Emit the divergence audit row before propagating.
            // The on-chain op may have landed; this forensic row records the
            // divergent RPC views so the operator can reconcile ledger state.
            emit_timelock_divergence_audit(
                audit_writer,
                timelock_contract_strkey,
                &operation_id,
                &result.tx_hash,
                "schedule",
                primary_present,
                secondary_present,
                None, // chain_id not available in timelock helper scope
                request_id,
            );
            sa_err
        }
    })?;

    info!(
        operation_id = %operation_id.redacted(),
        timelock = %redact_strkey_first5_last5(timelock_contract_strkey),
        tx_hash = %&result.tx_hash[..result.tx_hash.len().min(16)],
        "timelock: operation scheduled"
    );

    // Audit emission is fail-CLOSED; propagate mutex-poison error.
    emit_scheduled_audit(
        audit_writer,
        &operation_id,
        timelock_contract_strkey,
        target_strkey,
        function,
        delay_ledgers,
        &proposer_strkey,
        &result.tx_hash,
        request_id,
    )?;

    Ok(ScheduledTimelockOperation {
        operation_id,
        salt: salt_bytes,
    })
}

/// Cancels a pending timelock operation.
///
/// Wraps `Timelock::cancel(operation_id, canceller)`. The canceller must hold
/// `CANCELLER_ROLE` on the timelock contract. In the default OZ timelock-controller
/// configuration, proposers are automatically granted the canceller role at
/// initialisation time (contract.rs:255-258, SHA `3f81125`).
///
/// # Event cross-confirmation
///
/// After submission, the presence of an `OperationCancelled` event in the
/// transaction meta is verified. If absent, returns
/// [`SaError::TimelockCancelFailed`] with reason `EventConfirmationMissing`.
///
/// # Errors
///
/// - [`SaError::TimelockCancelFailed`] — authorisation, invalid state, or
///   submission failure; typed `failure_reason` from the OZ error code.
///   The canonical cancel failure mode is `InvalidOperationState` (OZ code
///   4002), fired by `cancel_operation` (`packages/governance/src/timelock/
///   storage.rs:378`, SHA `3f81125`) when the operation is not in `Pending`
///   state — including when it was never scheduled. Code 4006
///   (`OperationNotScheduled`) is not reachable from the canonical cancel
///   path.
pub async fn cancel(args: TimelockCancelArgs<'_>) -> Result<(), SaError> {
    let TimelockCancelArgs {
        timelock_contract_strkey,
        operation_id,
        signer,
        primary_rpc_url,
        secondary_rpc_url,
        network_passphrase,
        audit_writer,
        request_id,
    } = args;

    let timelock_sc_address =
        parse_c_strkey_to_smart_account(timelock_contract_strkey).map_err(|e| {
            SaError::TimelockCancelFailed {
                failure_reason: TimelockCancelFailureReason::SimulationFailed,
                redacted_reason: format!("timelock address parse failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?;

    // Build canceller ScVal (G-key Address)
    let canceller_strkey = signer
        .public_key()
        .await
        .map(|pk| pk.to_string())
        .map_err(|e| SaError::TimelockCancelFailed {
            failure_reason: TimelockCancelFailureReason::SimulationFailed,
            redacted_reason: format!("canceller public key fetch failed: {e}"),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        })?;
    let canceller_sc_address = {
        use stellar_strkey::Strkey;
        let strkey =
            Strkey::from_string(&canceller_strkey).map_err(|e| SaError::TimelockCancelFailed {
                failure_reason: TimelockCancelFailureReason::SimulationFailed,
                redacted_reason: format!("canceller strkey parse failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            })?;
        match strkey {
            stellar_strkey::Strkey::PublicKeyEd25519(pk) => ScAddress::Account(AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk.0)),
            )),
            _ => {
                return Err(SaError::TimelockCancelFailed {
                    failure_reason: TimelockCancelFailureReason::SimulationFailed,
                    redacted_reason: "canceller must be a G-strkey".to_owned(),
                    operation_id_redacted: operation_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
        }
    };

    // Build ScVal for operation_id (BytesN<32>)
    let op_id_scbytes =
        stellar_xdr::ScBytes(operation_id.inner.to_vec().try_into().map_err(|e| {
            SaError::TimelockCancelFailed {
                failure_reason: TimelockCancelFailureReason::SimulationFailed,
                redacted_reason: format!("operation_id ScBytes failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?);

    // OZ TimelockController::cancel(e, operation_id: BytesN<32>, canceller: Address)
    // contract.rs:307-309, SHA 3f81125.
    let invoke_args: Vec<ScVal> = vec![
        ScVal::Bytes(op_id_scbytes),
        ScVal::Address(canceller_sc_address),
    ];
    let invoke_args_vecm: VecM<ScVal> =
        invoke_args
            .try_into()
            .map_err(|e| SaError::TimelockCancelFailed {
                failure_reason: TimelockCancelFailureReason::SimulationFailed,
                redacted_reason: format!("cancel args VecM encoding failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            })?;

    let cancel_fn_sym =
        ScSymbol::try_from(FN_CANCEL).map_err(|e| SaError::TimelockCancelFailed {
            failure_reason: TimelockCancelFailureReason::SimulationFailed,
            redacted_reason: format!("'cancel' symbol encoding failed: {e:?}"),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        })?;

    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: timelock_sc_address.clone(),
        function_name: cancel_fn_sym,
        args: invoke_args_vecm,
    });

    // The OZ TimelockController is NOT a smart-account; `cancel` calls
    // `canceller.require_auth()` on the G-key Address argument.
    // OZ mod.rs:292 (SHA 3f81125): `canceller.require_auth()`.
    let result = crate::timelock_submit::submit_timelock_invoke_with_g_key_auth(
        crate::timelock_submit::TimelockSubmitArgs {
            host_function,
            signer,
            primary_rpc_url,
            network_passphrase,
            timeout: std::time::Duration::from_secs(60),
            op_label: "timelock_cancel",
        },
    )
    .await
    .map_err(|e| {
        let reason = format!("{e}");
        let classified = classify_cancel_error(&reason);
        // OZ `cancel_operation` fires `InvalidOperationState` (4002) for any
        // non-pending op (including never-scheduled ones). Code 4006
        // (`OperationNotScheduled`) is unreachable from the canonical OZ
        // storage.rs:376-378 (SHA 3f81125); all cancel failures route through
        // `classify_cancel_error` which extracts the OZ code internally.
        SaError::TimelockCancelFailed {
            failure_reason: classified,
            redacted_reason: augment_with_oz_error_name(&reason),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?;

    // Cross-confirm OperationCancelled event on BOTH primary and secondary RPCs.
    cross_confirm_event(
        "OperationCancelled",
        &result.tx_hash,
        operation_id,
        timelock_contract_strkey,
        primary_rpc_url,
        secondary_rpc_url,
        request_id,
    )
    .await
    .map_err(|e| match e {
        CrossConfirmError::EventMissing(reason) => SaError::TimelockCancelFailed {
            failure_reason: TimelockCancelFailureReason::EventConfirmationMissing,
            redacted_reason: reason,
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        },
        CrossConfirmError::Divergence {
            sa_err,
            primary_present,
            secondary_present,
        } => {
            // Emit the divergence audit row before propagating.
            emit_timelock_divergence_audit(
                audit_writer,
                timelock_contract_strkey,
                operation_id,
                &result.tx_hash,
                "cancel",
                primary_present,
                secondary_present,
                None, // chain_id not available in timelock helper scope
                request_id,
            );
            sa_err
        }
    })?;

    info!(
        operation_id = %operation_id.redacted(),
        timelock = %redact_strkey_first5_last5(timelock_contract_strkey),
        tx_hash = %&result.tx_hash[..result.tx_hash.len().min(16)],
        "timelock: operation cancelled"
    );

    // Audit emission is fail-CLOSED; propagate mutex-poison error.
    emit_cancelled_audit(
        audit_writer,
        operation_id,
        timelock_contract_strkey,
        &canceller_strkey,
        &result.tx_hash,
        request_id,
    )?;

    Ok(())
}

/// Executes a ready timelock operation.
///
/// Pre-checks the operation state cross-RPC BEFORE simulating the hash or
/// submitting the transaction. If the state is not `Ready`, returns
/// [`SaError::TimelockExecuteFailed`] with reason `OperationNotReady` — fail-CLOSED
/// without wasting a `simulate_hash_operation` round-trip.
///
/// When `expected_operation_id` is `Some`, the pre-check runs against the
/// caller-supplied id immediately. After `simulate_hash_operation` confirms the
/// authoritative id, the two are validated; a mismatch returns
/// [`SaError::TimelockExecuteFailed`] with reason `OperationIdMismatch`.
///
/// # Pre-check ordering
///
/// 1. Build RPC clients.
/// 2. If `expected_operation_id` is `Some`, query state cross-RPC using it first.
///    If state is not `Ready`, return early (skip hash simulate — avoids wasted work).
/// 3. Call `simulate_hash_operation` to derive the authoritative `operation_id`.
/// 4. If `expected_operation_id` was `Some`, validate against derived id.
/// 5. If `expected_operation_id` was `None`, query state now using the derived id.
/// 6. Proceed with submission.
///
/// # Event cross-confirmation
///
/// After submission, the presence of an `OperationExecuted` event in the
/// transaction meta is verified. If absent, returns
/// [`SaError::TimelockExecuteFailed`] with reason `EventConfirmationMissing`.
///
/// # Errors
///
/// - [`SaError::TimelockExecuteFailed`] — pre-check failure, invalid state,
///   operation-id mismatch, or submission failure.
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPCs disagree
///   on the operation state during pre-check.
pub async fn execute(args: TimelockExecuteArgs<'_>) -> Result<String, SaError> {
    let TimelockExecuteArgs {
        timelock_contract_strkey,
        target_strkey,
        function,
        args,
        predecessor,
        salt,
        signer,
        primary_rpc_url,
        secondary_rpc_url,
        network_passphrase,
        audit_writer,
        request_id,
        expected_operation_id,
    } = args;

    // Pre-check operation state cross-RPC before submitting.
    // Fail-CLOSED if not Ready to avoid a wasted on-chain panic round-trip.
    let primary_rpc =
        StellarRpcClient::new(primary_rpc_url).map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("primary RPC client construction failed: {e}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;
    let secondary_rpc =
        StellarRpcClient::new(secondary_rpc_url).map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("secondary RPC client construction failed: {e}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;

    // If the caller supplies the operation_id (CLI path), run the cross-RPC state
    // pre-check immediately using that id. If the state is not Ready, return early
    // and skip the `simulate_hash_operation` network round-trip entirely.
    //
    // This preserves the fail-CLOSED pre-check while eliminating a
    // wasted simulate for Done / Unset / Waiting operations.
    if let Some(pre_check_id) = expected_operation_id {
        let state = query_operation_state_cross_rpc(
            &primary_rpc,
            &secondary_rpc,
            timelock_contract_strkey,
            pre_check_id,
            network_passphrase,
            request_id,
        )
        .await?;

        // query_operation_state_cross_rpc returns current_ledger as a 0
        // placeholder; enrich with the live ledger so a Ready operation is not
        // misclassified as Waiting. Fail closed if the ledger cannot be fetched.
        let current_ledger = fetch_latest_ledger(&primary_rpc).await.ok_or_else(|| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: "fetch_latest_ledger returned None for primary RPC; \
                                  cannot determine operation readiness"
                    .to_owned(),
                operation_id_redacted: pre_check_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?;
        let state = enrich_state_view_with_current_ledger(state, current_ledger);

        match &state {
            TimelockOperationStateView::Ready { .. } => {
                // Proceed to hash simulate + submission.
            }
            TimelockOperationStateView::Waiting {
                ready_ledger,
                current_ledger,
            } => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::OperationNotReady {
                        observed_state: "Waiting".to_owned(),
                        // current_ledger was fetched during the cross-RPC state query.
                        current_ledger: Some(*current_ledger),
                        ready_ledger: *ready_ledger,
                    },
                    redacted_reason: format!(
                        "operation is Waiting; ready at ledger {ready_ledger}, \
                         current {current_ledger}"
                    ),
                    operation_id_redacted: pre_check_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
            TimelockOperationStateView::Unset => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::OperationNotReady {
                        observed_state: "Unset".to_owned(),
                        // No current-ledger value is meaningful for an Unset
                        // operation (never scheduled / already cancelled).
                        current_ledger: None,
                        ready_ledger: 0,
                    },
                    redacted_reason: "operation is Unset (not scheduled or already cancelled)"
                        .to_owned(),
                    operation_id_redacted: pre_check_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
            TimelockOperationStateView::Done => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::InvalidOperationState,
                    redacted_reason: "operation is already Done (already executed)".to_owned(),
                    operation_id_redacted: pre_check_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
        }
    }

    // Derive operation_id by simulating `hash_operation(target, function, args,
    // predecessor, salt)` on the OZ Timelock contract (mod.rs:98-108, SHA 3f81125)
    // instead of an off-chain Keccak-256 re-implementation. Both primary and
    // secondary RPCs simulate; hashes must match (divergence is a security failure).
    let operation_id = simulate_hash_operation(
        timelock_contract_strkey,
        target_strkey,
        function,
        &args,
        &predecessor,
        &salt,
        primary_rpc_url,
        secondary_rpc_url,
        network_passphrase,
        request_id,
    )
    .await?;

    // If the caller supplied `expected_operation_id`, the simulate-derived id is
    // the authoritative value. A mismatch means the caller's args or id are wrong;
    // return a typed `OperationIdMismatch` so the operator can triage without
    // inspecting RPC responses.
    if let Some(expected) = expected_operation_id
        && *expected != operation_id
    {
        return Err(SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::OperationIdMismatch {
                user_supplied: expected.to_hex(),
                simulate_derived: operation_id.to_hex(),
            },
            redacted_reason: format!(
                "caller-supplied operation_id {} does not match \
                 simulate-derived {} — check --operation-id, --target, \
                 --function, --salt, and predecessor match the scheduled operation",
                expected.redacted(),
                operation_id.redacted()
            ),
            operation_id_redacted: expected.redacted(),
            request_id: request_id.to_owned(),
        });
    }

    // ── State check when no expected_operation_id was supplied ────────────────
    //
    // When the caller did not provide an expected_operation_id (e.g. integration
    // tests), the state pre-check runs now using the simulate-derived id.
    // This is the fallback path; the CLI path always provides an id.
    if expected_operation_id.is_none() {
        let state = query_operation_state_cross_rpc(
            &primary_rpc,
            &secondary_rpc,
            timelock_contract_strkey,
            &operation_id,
            network_passphrase,
            request_id,
        )
        .await?;

        // query_operation_state_cross_rpc returns current_ledger as a 0
        // placeholder; enrich with the live ledger so a Ready operation is not
        // misclassified as Waiting. Fail closed if the ledger cannot be fetched.
        let current_ledger = fetch_latest_ledger(&primary_rpc).await.ok_or_else(|| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: "fetch_latest_ledger returned None for primary RPC; \
                                  cannot determine operation readiness"
                    .to_owned(),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?;
        let state = enrich_state_view_with_current_ledger(state, current_ledger);

        match &state {
            TimelockOperationStateView::Ready { .. } => {
                // Proceed.
            }
            TimelockOperationStateView::Waiting {
                ready_ledger,
                current_ledger,
            } => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::OperationNotReady {
                        observed_state: "Waiting".to_owned(),
                        current_ledger: Some(*current_ledger),
                        ready_ledger: *ready_ledger,
                    },
                    redacted_reason: format!(
                        "operation is Waiting; ready at ledger {ready_ledger}, \
                         current {current_ledger}"
                    ),
                    operation_id_redacted: operation_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
            TimelockOperationStateView::Unset => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::OperationNotReady {
                        observed_state: "Unset".to_owned(),
                        // No current-ledger value is meaningful for Unset state.
                        current_ledger: None,
                        ready_ledger: 0,
                    },
                    redacted_reason: "operation is Unset (not scheduled or already cancelled)"
                        .to_owned(),
                    operation_id_redacted: operation_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
            TimelockOperationStateView::Done => {
                return Err(SaError::TimelockExecuteFailed {
                    failure_reason: TimelockExecuteFailureReason::InvalidOperationState,
                    redacted_reason: "operation is already Done (already executed)".to_owned(),
                    operation_id_redacted: operation_id.redacted(),
                    request_id: request_id.to_owned(),
                });
            }
        }
    }

    // Build the `execute` call.
    // OZ TimelockController::execute signature (contract.rs:286-304, SHA 3f81125):
    //   fn execute(e, target: Address, function: Symbol, args: Vec<Val>,
    //              predecessor: BytesN<32>, salt: BytesN<32>, executor: Option<Address>)
    //   -> Val
    let timelock_sc_address =
        parse_c_strkey_to_smart_account(timelock_contract_strkey).map_err(|e| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("timelock address parse failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?;

    let target_sc_address = parse_c_strkey_to_smart_account(target_strkey).map_err(|e| {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("target address parse failed: {e:?}"),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?;

    let fn_sym = ScSymbol::try_from(function).map_err(|e| SaError::TimelockExecuteFailed {
        failure_reason: TimelockExecuteFailureReason::SimulationFailed,
        redacted_reason: format!("function symbol encoding failed: {e:?}"),
        operation_id_redacted: operation_id.redacted(),
        request_id: request_id.to_owned(),
    })?;

    let predecessor_scbytes =
        stellar_xdr::ScBytes(predecessor.to_vec().try_into().map_err(|e| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("predecessor ScBytes failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            }
        })?);
    let salt_scbytes = stellar_xdr::ScBytes(salt.to_vec().try_into().map_err(|e| {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("salt ScBytes failed: {e:?}"),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?);

    let args_vecm: VecM<ScVal> =
        args.clone()
            .try_into()
            .map_err(|e| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("target-function args VecM encoding failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            })?;
    let args_scval = ScVal::Vec(Some(ScVec(args_vecm)));

    // executor: Option<Address> — for open-execution, pass ScVal::Vec(None) (Soroban None).
    // The OZ timelock-controller allows open execution when no executors are configured
    // (contract.rs:295-296, SHA 3f81125). We use open-execution as the default.
    // Expose executor: Option<&str> in the public API for closed-execution mode.
    let executor_scval = ScVal::Void; // Soroban `None` for Option<Address>

    let executor_strkey: Option<&str> = None;

    let invoke_args: Vec<ScVal> = vec![
        ScVal::Address(target_sc_address),
        ScVal::Symbol(fn_sym),
        args_scval,
        ScVal::Bytes(predecessor_scbytes),
        ScVal::Bytes(salt_scbytes),
        executor_scval,
    ];
    let invoke_args_vecm: VecM<ScVal> =
        invoke_args
            .try_into()
            .map_err(|e| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("execute args VecM encoding failed: {e:?}"),
                operation_id_redacted: operation_id.redacted(),
                request_id: request_id.to_owned(),
            })?;

    let execute_fn_sym =
        ScSymbol::try_from(FN_EXECUTE).map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("'execute' symbol encoding failed: {e:?}"),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        })?;

    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: timelock_sc_address.clone(),
        function_name: execute_fn_sym,
        args: invoke_args_vecm,
    });

    // The OZ TimelockController is NOT a smart-account; `execute` calls
    // `executor.require_auth()` on the G-key Address argument (only when an
    // explicit executor is supplied; open execution passes None).
    // OZ mod.rs:244-245 (SHA 3f81125): `if let Some(ref exec) = executor { exec.require_auth() }`.
    let result = crate::timelock_submit::submit_timelock_invoke_with_g_key_auth(
        crate::timelock_submit::TimelockSubmitArgs {
            host_function,
            signer,
            primary_rpc_url,
            network_passphrase,
            timeout: std::time::Duration::from_secs(60),
            op_label: "timelock_execute",
        },
    )
    .await
    .map_err(|e| {
        let reason = format!("{e}");
        let classified = classify_execute_error(&reason);
        SaError::TimelockExecuteFailed {
            failure_reason: classified,
            redacted_reason: augment_with_oz_error_name(&reason),
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        }
    })?;

    // Cross-confirm OperationExecuted event on BOTH primary and secondary RPCs.
    cross_confirm_event(
        "OperationExecuted",
        &result.tx_hash,
        &operation_id,
        timelock_contract_strkey,
        primary_rpc_url,
        secondary_rpc_url,
        request_id,
    )
    .await
    .map_err(|e| match e {
        CrossConfirmError::EventMissing(reason) => SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::EventConfirmationMissing,
            redacted_reason: reason,
            operation_id_redacted: operation_id.redacted(),
            request_id: request_id.to_owned(),
        },
        CrossConfirmError::Divergence {
            sa_err,
            primary_present,
            secondary_present,
        } => {
            // Emit the divergence audit row before propagating.
            emit_timelock_divergence_audit(
                audit_writer,
                timelock_contract_strkey,
                &operation_id,
                &result.tx_hash,
                "execute",
                primary_present,
                secondary_present,
                None, // chain_id not available in timelock helper scope
                request_id,
            );
            sa_err
        }
    })?;

    info!(
        operation_id = %operation_id.redacted(),
        timelock = %redact_strkey_first5_last5(timelock_contract_strkey),
        tx_hash = %&result.tx_hash[..result.tx_hash.len().min(16)],
        "timelock: operation executed"
    );

    // Audit emission is fail-CLOSED; propagate mutex-poison error.
    emit_executed_audit(
        audit_writer,
        &operation_id,
        timelock_contract_strkey,
        executor_strkey,
        &result.tx_hash,
        request_id,
    )?;

    Ok(result.tx_hash)
}

/// Returns all pending (Waiting or Ready) timelock operations for a given
/// timelock contract, derived from the wallet's audit log.
///
/// Scans the audit log for `SaTimelockScheduled` rows that are not matched
/// by a `SaTimelockCancelled` or `SaTimelockExecuted` row. For each candidate
/// operation_id, queries `get_operation_state` cross-RPC and filters to
/// `Waiting` or `Ready` states.
///
/// # Errors
///
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPCs disagree
///   on `get_operation_state` for any candidate operation.
/// - [`SaError::AuditLog`] — audit-log integrity error.
pub async fn list_pending(
    timelock_contract_strkey: &str,
    audit_writer: &Arc<Mutex<AuditWriter>>,
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    network_passphrase: &str,
    request_id: &str,
) -> Result<Vec<PendingTimelockOperation>, SaError> {
    use stellar_agent_core::audit_log::reader::AuditReader;

    // Acquire reader from the audit writer Arc.
    let reader = AuditReader::new(Arc::clone(audit_writer), None);

    // Audit rows store strkeys in first-5-last-5 redacted form. The reader's
    // `find_pending_timelock_operations` matches on the redacted form, NOT the
    // full C-strkey. Passing the full strkey would silently return Ok(vec![])
    // for every call. Redact at the call site to match the reader contract.
    let timelock_contract_redacted = redact_strkey_first5_last5(timelock_contract_strkey);
    let candidates = reader
        .find_pending_timelock_operations(&timelock_contract_redacted)
        .map_err(SaError::AuditLog)?;

    // Use TimelockListPendingFailed for read-path failures; omit the full URL
    // from the error message to avoid leaking internal infrastructure hostnames.
    let primary_rpc = StellarRpcClient::new(primary_rpc_url).map_err(|_e| {
        SaError::TimelockListPendingFailed {
            redacted_reason: "primary RPC client construction failed: invalid URL".to_owned(),
        }
    })?;
    let secondary_rpc = StellarRpcClient::new(secondary_rpc_url).map_err(|_e| {
        SaError::TimelockListPendingFailed {
            redacted_reason: "secondary RPC client construction failed: invalid URL".to_owned(),
        }
    })?;

    // Fetch the current ledger from the primary RPC for state enrichment.
    // Fail-CLOSED: if the RPC is unreachable we cannot determine Waiting vs
    // Ready for any pending operation. Returning an error (rather than
    // unwrap_or(0)) prevents Waiting ops from being surfaced as Waiting when
    // they are actually Ready — stale state could delay a time-sensitive execution.
    let current_ledger = fetch_latest_ledger(&primary_rpc).await.ok_or_else(|| {
        SaError::TimelockListPendingFailed {
            redacted_reason: "fetch_latest_ledger returned None for primary RPC; \
                     cannot enrich operation states for list_pending — \
                     check RPC reachability"
                .to_owned(),
        }
    })?;

    let timelock_sc_address =
        parse_c_strkey_to_smart_account(timelock_contract_strkey).map_err(|e| {
            SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("timelock address parse for list_pending: {e:?}"),
            }
        })?;

    let mut results = Vec::with_capacity(candidates.len());

    for (op_id_hex, scheduled_request_id, _timelock_redacted) in candidates {
        // Decode full hex operation_id.
        let op_bytes = decode_hex32(&op_id_hex).ok_or_else(|| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("invalid operation_id hex in audit log: {op_id_hex}"),
        })?;
        let operation_id = TimelockOperationId::from_bytes(op_bytes);

        let state = query_operation_state_cross_rpc(
            &primary_rpc,
            &secondary_rpc,
            timelock_contract_strkey,
            &operation_id,
            network_passphrase,
            request_id,
        )
        .await?;

        let enriched_state = enrich_state_view_with_current_ledger(state, current_ledger);

        // Filter: only Waiting and Ready operations.
        match &enriched_state {
            TimelockOperationStateView::Waiting { .. }
            | TimelockOperationStateView::Ready { .. } => {
                results.push(PendingTimelockOperation {
                    operation_id,
                    state: enriched_state,
                    timelock_contract: timelock_sc_address.clone(),
                    scheduled_at_request_id: scheduled_request_id,
                });
            }
            TimelockOperationStateView::Unset | TimelockOperationStateView::Done => {
                // Skip: operation is no longer pending on-chain.
            }
        }
    }

    Ok(results)
}

/// Fetches the latest ledger sequence from an RPC endpoint.
async fn fetch_latest_ledger(rpc: &StellarRpcClient) -> Option<u32> {
    let server = Client::new(rpc.url()).ok()?;
    let info = server.get_latest_ledger().await.ok()?;
    Some(info.sequence)
}

/// Decodes a 64-character hex string to a `[u8; 32]` array.
///
/// Delegates to [`stellar_agent_core::hex::decode_hex32`].
fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    stellar_agent_core::hex::decode_hex32(hex).ok()
}

/// Derives the OZ timelock operation ID by simulating `hash_operation` on-chain
/// against BOTH primary and secondary RPCs concurrently.
///
/// Calls `Timelock::hash_operation(e, target, function, args, predecessor, salt) -> BytesN<32>`
/// (`packages/governance/src/timelock/mod.rs:98-108`, SHA `3f81125`) rather than
/// an off-chain Keccak-256 re-implementation — the result is authoritative.
///
/// Both RPCs MUST return the identical 32-byte hash. A mismatch yields
/// [`SaError::NetworkRpcDivergence`]. This prevents a compromised primary RPC
/// from returning a fake hash that would only be caught after fees are wasted.
///
/// Uses the same fee-less simulate-transaction pattern as [`query_operation_ready_ledger`].
///
/// There is no canonical dual-RPC `simulateTransaction` for `hash_operation`;
/// this is wallet-specific defence-in-depth.
///
/// # Errors
///
/// - [`SaError::TimelockExecuteFailed`] with reason `SimulationFailed` — RPC, encoding,
///   or unexpected return type from either RPC.
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPCs returned different
///   `hash_operation` results. Wire code `network.rpc_divergence`; forensic spine uses
///   first-8 hex chars of SHA-256 of each returned hash.
#[allow(clippy::too_many_arguments)]
async fn simulate_hash_operation(
    timelock_contract_strkey: &str,
    target_strkey: &str,
    function: &str,
    args: &[ScVal],
    predecessor: &[u8; 32],
    salt: &[u8; 32],
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    network_passphrase: &str,
    request_id: &str,
) -> Result<TimelockOperationId, SaError> {
    // Build the shared transaction body once; both RPC simulations use the same tx.
    let timelock_sc_address =
        parse_c_strkey_to_smart_account(timelock_contract_strkey).map_err(|e| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("timelock address parse failed: {e:?}"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            }
        })?;
    let target_sc_address = parse_c_strkey_to_smart_account(target_strkey).map_err(|e| {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("target address parse failed: {e:?}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        }
    })?;
    let fn_sym = ScSymbol::try_from(function).map_err(|e| SaError::TimelockExecuteFailed {
        failure_reason: TimelockExecuteFailureReason::SimulationFailed,
        redacted_reason: format!("function symbol encoding failed: {e:?}"),
        operation_id_redacted: "unknown".to_owned(),
        request_id: request_id.to_owned(),
    })?;

    // Encode args as ScVal::Vec(Some(ScVec(...)))
    let args_vecm: VecM<ScVal> =
        args.to_vec()
            .try_into()
            .map_err(|e| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("args VecM encoding failed: {e:?}"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            })?;
    let args_scval = ScVal::Vec(Some(ScVec(args_vecm)));

    let predecessor_scbytes =
        stellar_xdr::ScBytes(predecessor.to_vec().try_into().map_err(|e| {
            SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("predecessor ScBytes encoding failed: {e:?}"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            }
        })?);
    let salt_scbytes = stellar_xdr::ScBytes(salt.to_vec().try_into().map_err(|e| {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("salt ScBytes encoding failed: {e:?}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        }
    })?);

    // OZ hash_operation(e, target: Address, function: Symbol, args: Vec<Val>,
    //                   predecessor: BytesN<32>, salt: BytesN<32>) -> BytesN<32>
    // mod.rs:98-108 (SHA 3f81125). Argument order mirrors the trait signature exactly.
    let invoke_args: Vec<ScVal> = vec![
        ScVal::Address(target_sc_address),
        ScVal::Symbol(fn_sym),
        args_scval,
        ScVal::Bytes(predecessor_scbytes),
        ScVal::Bytes(salt_scbytes),
    ];
    let invoke_args_vecm: VecM<ScVal> =
        invoke_args
            .try_into()
            .map_err(|e| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("invoke args VecM encoding failed: {e:?}"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            })?;

    let fn_name =
        ScSymbol::try_from("hash_operation").map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("'hash_operation' symbol encoding failed: {e:?}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;

    let host_fn = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: timelock_sc_address.clone(),
        function_name: fn_name,
        args: invoke_args_vecm,
    });

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_fn,
            auth: VecM::default(),
        }),
    };

    // Fee-less simulation — view function `hash_operation` doesn't require auth.
    // BaselibAccount::new requires a G-strkey, NOT a C-strkey; use the zero-pubkey
    // G-strkey constant (structurally valid; accepted by Soroban RPC for fee-less
    // view-function simulate when resource_fee=0).
    let dummy_source_g_strkey: String = stellar_strkey::ed25519::PublicKey([0u8; 32])
        .to_string()
        .as_str()
        .to_owned();
    let source_account = BaselibAccount::new(&dummy_source_g_strkey, "0").map_err(|e| {
        SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("BaselibAccount: {e:?}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        }
    })?;
    let mut source_account_mut = source_account;

    // The caller-supplied `network_passphrase` is used (not a hard-coded network
    // string) so this path works correctly on mainnet and testnet alike.
    let mut tx_builder = TransactionBuilder::new(&mut source_account_mut, network_passphrase, None);
    tx_builder.fee(BASE_FEE_STROOPS);
    tx_builder.add_operation(op);
    let tx_for_sim = tx_builder.build_for_simulation();

    let build_rpc_server = |url: &str| Client::new(url);
    let primary_server =
        build_rpc_server(primary_rpc_url).map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("primary RPC Client construction failed: {e}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;
    let secondary_server =
        build_rpc_server(secondary_rpc_url).map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("secondary RPC Client construction failed: {e}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;

    // Simulate concurrently on both RPCs.
    let sim_envelope = tx_for_sim
        .to_envelope()
        .map_err(|e| SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("to_envelope failed: {e:?}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        })?;
    let (primary_sim, secondary_sim) = tokio::join!(
        primary_server.simulate_transaction_envelope(&sim_envelope, None),
        secondary_server.simulate_transaction_envelope(&sim_envelope, None),
    );

    let primary_sim = primary_sim.map_err(|e| SaError::TimelockExecuteFailed {
        failure_reason: TimelockExecuteFailureReason::SimulationFailed,
        redacted_reason: format!("primary simulate_transaction_envelope failed: {e}"),
        operation_id_redacted: "unknown".to_owned(),
        request_id: request_id.to_owned(),
    })?;
    let secondary_sim = secondary_sim.map_err(|e| SaError::TimelockExecuteFailed {
        failure_reason: TimelockExecuteFailureReason::SimulationFailed,
        redacted_reason: format!("secondary simulate_transaction_envelope failed: {e}"),
        operation_id_redacted: "unknown".to_owned(),
        request_id: request_id.to_owned(),
    })?;

    if let Some(err) = &primary_sim.error {
        return Err(SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("primary simulation error: {err}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        });
    }
    if let Some(err) = &secondary_sim.error {
        return Err(SaError::TimelockExecuteFailed {
            failure_reason: TimelockExecuteFailureReason::SimulationFailed,
            redacted_reason: format!("secondary simulation error: {err}"),
            operation_id_redacted: "unknown".to_owned(),
            request_id: request_id.to_owned(),
        });
    }

    // Extract the 32-byte hash from both responses.
    let extract_hash = |sim: &stellar_rpc_client::SimulateTransactionResponse,
                        label: &str|
     -> Result<[u8; 32], SaError> {
        let return_val = sim
            .results()
            .map_err(|e| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("{label} simulate results decode failed: {e}"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            })?
            .into_iter()
            .next()
            .ok_or_else(|| SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!("{label} simulate returned no result"),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            })?
            .xdr;
        // hash_operation returns BytesN<32> which the Soroban runtime encodes as ScVal::Bytes.
        match return_val {
            ScVal::Bytes(b) => {
                let slice = b.0.as_slice();
                if slice.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(slice);
                    Ok(arr)
                } else {
                    Err(SaError::TimelockExecuteFailed {
                        failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                        redacted_reason: format!(
                            "{label} hash_operation returned {} bytes, expected 32",
                            slice.len()
                        ),
                        operation_id_redacted: "unknown".to_owned(),
                        request_id: request_id.to_owned(),
                    })
                }
            }
            other => Err(SaError::TimelockExecuteFailed {
                failure_reason: TimelockExecuteFailureReason::SimulationFailed,
                redacted_reason: format!(
                    "{label} hash_operation returned unexpected ScVal: {other:?}"
                ),
                operation_id_redacted: "unknown".to_owned(),
                request_id: request_id.to_owned(),
            }),
        }
    };

    let primary_hash = extract_hash(&primary_sim, "primary")?;
    let secondary_hash = extract_hash(&secondary_sim, "secondary")?;

    // Dual-RPC divergence check: both RPCs MUST agree on the hash value.
    if primary_hash != secondary_hash {
        let primary_digest = Sha256::digest(primary_hash);
        let secondary_digest = Sha256::digest(secondary_hash);
        let primary_first8: String = primary_digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let secondary_first8: String = secondary_digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(SaError::NetworkRpcDivergence {
            rule_id: 0, // Timelock queries are not rule-scoped; use sentinel 0.
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                redact_strkey_first5_last5(timelock_contract_strkey),
            ),
            primary_view_digest_first8: primary_first8,
            secondary_view_digest_first8: secondary_first8,
            request_id: request_id.to_owned(),
        });
    }

    Ok(TimelockOperationId::from_bytes(primary_hash))
}

// ── Test helpers ──────────────────────────────────────────────────────────────
//
// These items are only compiled when `feature = "test-helpers"` is active
// or during internal tests.  They expose internal functions for integration-
// test assertions without leaking them into the production public API.
//
// Gate visibility at the re-export, not the definition.

/// URL-based wrapper around `query_operation_state_cross_rpc` for integration tests.
///
/// Constructs [`StellarRpcClient`] instances from URL strings, then delegates
/// to the internal `query_operation_state_cross_rpc` for the cross-RPC state
/// check.  Exposed under `feature = "test-helpers"` so acceptance tests can
/// directly assert the on-chain state after a cancel without going through
/// `list_pending`.
///
/// # Errors
///
/// Returns [`SaError::DeploymentFailed`] on RPC client construction failure.
/// Propagates [`SaError::NetworkRpcDivergence`] from the inner call.
///
#[cfg(any(test, feature = "test-helpers"))]
pub async fn query_operation_state(
    timelock_contract_strkey: &str,
    operation_id: &TimelockOperationId,
    primary_rpc_url: &str,
    secondary_rpc_url: &str,
    network_passphrase: &str,
    request_id: &str,
) -> Result<TimelockOperationStateView, SaError> {
    let primary =
        StellarRpcClient::new(primary_rpc_url).map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("primary RPC client construction failed: {e}"),
        })?;
    let secondary =
        StellarRpcClient::new(secondary_rpc_url).map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("secondary RPC client construction failed: {e}"),
        })?;
    query_operation_state_cross_rpc(
        &primary,
        &secondary,
        timelock_contract_strkey,
        operation_id,
        network_passphrase,
        request_id,
    )
    .await
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(
        clippy::expect_used,
        reason = "test-only: expects are correct failure mode"
    )]
    #![allow(clippy::panic, reason = "test-only: panics are correct failure mode")]

    use super::*;

    #[test]
    fn timelock_operation_id_hex_roundtrip() {
        let bytes = [0xabu8; 32];
        let id = TimelockOperationId::from_bytes(bytes);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn timelock_operation_id_redacted_has_correct_format() {
        let bytes = [0u8; 32];
        let id = TimelockOperationId::from_bytes(bytes);
        let redacted = id.redacted();
        // Should be "00000000...00000000" (8 + 3 + 8 = 19 chars)
        assert!(redacted.contains("..."));
        let parts: Vec<&str> = redacted.splitn(2, "...").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 8);
    }

    #[test]
    fn derive_schedule_salt_is_non_deterministic_on_different_inputs() {
        let salt1 = derive_schedule_salt("req-id-1", 1_000_000);
        let salt2 = derive_schedule_salt("req-id-2", 1_000_000);
        let salt3 = derive_schedule_salt("req-id-1", 1_000_001);
        assert_ne!(
            salt1, salt2,
            "different request_id must produce different salt"
        );
        assert_ne!(
            salt1, salt3,
            "different timestamp must produce different salt"
        );
    }

    #[test]
    fn derive_schedule_salt_is_deterministic_on_same_inputs() {
        let salt1 = derive_schedule_salt("req-id-fixed", 9_999_999);
        let salt2 = derive_schedule_salt("req-id-fixed", 9_999_999);
        assert_eq!(salt1, salt2, "same inputs must produce same salt");
    }

    #[test]
    fn extract_oz_error_code_parses_hash_prefix() {
        assert_eq!(extract_oz_error_code("Error(Contract, #4004)"), Some(4004));
        assert_eq!(extract_oz_error_code("Error(Contract, #4000)"), Some(4000));
        assert_eq!(extract_oz_error_code("no error code"), None);
    }

    #[test]
    fn extract_oz_error_code_parses_contract_error_suffix() {
        assert_eq!(
            extract_oz_error_code("HostError: Value(Status(ContractError(4006)))"),
            Some(4006)
        );
    }

    #[test]
    fn ready_ledger_to_state_view_unset() {
        assert_eq!(
            ready_ledger_to_state_view(UNSET_LEDGER),
            TimelockOperationStateView::Unset
        );
    }

    #[test]
    fn ready_ledger_to_state_view_done() {
        assert_eq!(
            ready_ledger_to_state_view(DONE_LEDGER),
            TimelockOperationStateView::Done
        );
    }

    #[test]
    fn ready_ledger_to_state_view_pending_is_waiting() {
        let state = ready_ledger_to_state_view(1000);
        assert_eq!(
            state,
            TimelockOperationStateView::Waiting {
                ready_ledger: 1000,
                current_ledger: 0
            },
            "pending ledger must map to Waiting {{ ready_ledger: 1000, current_ledger: 0 }}; got {state:?}"
        );
    }

    #[test]
    fn enrich_state_view_promotes_waiting_to_ready() {
        let state = TimelockOperationStateView::Waiting {
            ready_ledger: 100,
            current_ledger: 0,
        };
        let enriched = enrich_state_view_with_current_ledger(state, 150);
        assert_eq!(
            enriched,
            TimelockOperationStateView::Ready {
                ready_ledger: 100,
                current_ledger: 150,
            }
        );
    }

    #[test]
    fn enrich_state_view_keeps_waiting_if_not_ready() {
        let state = TimelockOperationStateView::Waiting {
            ready_ledger: 200,
            current_ledger: 0,
        };
        let enriched = enrich_state_view_with_current_ledger(state, 150);
        assert_eq!(
            enriched,
            TimelockOperationStateView::Waiting {
                ready_ledger: 200,
                current_ledger: 150,
            }
        );
    }

    #[test]
    fn classify_schedule_error_unauthorized() {
        let reason = classify_schedule_error("Error(Contract, #4004)");
        assert_eq!(reason, TimelockScheduleFailureReason::Unauthorized);
    }

    #[test]
    fn classify_cancel_error_not_scheduled_falls_through_to_other() {
        // OZ code 4006 (`OperationNotScheduled`) is unreachable from the canonical
        // cancel path (storage.rs:376-378, SHA 3f81125); code 4006 falls through
        // to `Other`.
        let reason = classify_cancel_error("Error(Contract, #4006)");
        assert_eq!(reason, TimelockCancelFailureReason::Other);
    }

    #[test]
    fn classify_execute_error_invalid_state() {
        let reason = classify_execute_error("Error(Contract, #4002)");
        assert_eq!(reason, TimelockExecuteFailureReason::InvalidOperationState);
    }

    #[test]
    fn decode_hex32_roundtrip() {
        let bytes = [0xdeu8; 32];
        let id = TimelockOperationId::from_bytes(bytes);
        let hex = id.to_hex();
        let decoded = decode_hex32(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_hex32_rejects_wrong_length() {
        assert!(decode_hex32("abcd").is_none());
        assert!(decode_hex32(&"ab".repeat(31)).is_none()); // 62 chars
    }

    // ── OperationNotReady current_ledger: Option<u32> ────────────────────────

    /// `OperationNotReady` with `current_ledger: None` represents the `Unset`
    /// case where no current-ledger value was meaningful at pre-check time.
    ///
    /// `current_ledger: None` (rather than a sentinel `0`) makes `Unset`
    /// distinguishable from a genuine ledger-zero value.
    #[test]
    fn operation_not_ready_none_current_ledger_display() {
        use crate::error::TimelockExecuteFailureReason;
        let reason = TimelockExecuteFailureReason::OperationNotReady {
            observed_state: "Unset".to_owned(),
            current_ledger: None,
            ready_ledger: 0,
        };
        let display = reason.to_string();
        assert!(
            display.contains("unknown"),
            "None current_ledger must render as 'unknown'; got: {display}"
        );
        assert!(
            display.contains("Unset"),
            "Display must contain observed_state 'Unset'; got: {display}"
        );
    }

    /// `OperationNotReady` with `current_ledger: Some(n)` represents the
    /// `Waiting` case where the current ledger was fetched from the RPC.
    #[test]
    fn operation_not_ready_some_current_ledger_display() {
        use crate::error::TimelockExecuteFailureReason;
        let reason = TimelockExecuteFailureReason::OperationNotReady {
            observed_state: "Waiting".to_owned(),
            current_ledger: Some(4_900_000),
            ready_ledger: 5_000_000,
        };
        let display = reason.to_string();
        assert!(
            display.contains("4900000"),
            "Some(n) current_ledger must render the numeric value; got: {display}"
        );
        assert!(
            display.contains("Waiting"),
            "Display must contain observed_state 'Waiting'; got: {display}"
        );
        assert!(
            display.contains("5000000"),
            "Display must contain ready_ledger value; got: {display}"
        );
    }

    /// `OperationNotReady` with `current_ledger: None` serialises to JSON with
    /// `"current_ledger": null` — not `"current_ledger": 0`.
    #[test]
    fn operation_not_ready_none_serialises_as_null() {
        use crate::error::TimelockExecuteFailureReason;
        let reason = TimelockExecuteFailureReason::OperationNotReady {
            observed_state: "Unset".to_owned(),
            current_ledger: None,
            ready_ledger: 0,
        };
        let json = serde_json::to_string(&reason).unwrap();
        assert!(
            json.contains("\"current_ledger\":null"),
            "None must serialise as null, not 0; json: {json}"
        );
        assert!(
            !json.contains("\"current_ledger\":0"),
            "Should not serialise None as 0; json: {json}"
        );
    }

    /// `OperationNotReady` with `current_ledger: Some(n)` serialises to JSON with
    /// the numeric value, not null.
    #[test]
    fn operation_not_ready_some_serialises_as_number() {
        use crate::error::TimelockExecuteFailureReason;
        let reason = TimelockExecuteFailureReason::OperationNotReady {
            observed_state: "Waiting".to_owned(),
            current_ledger: Some(12_345),
            ready_ledger: 20_000,
        };
        let json = serde_json::to_string(&reason).unwrap();
        assert!(
            json.contains("\"current_ledger\":12345"),
            "Some(12345) must serialise as 12345; json: {json}"
        );
    }

    // ── list_pending fail-CLOSED ──────────────────────────────────────────────

    /// `list_pending` fails-CLOSED when `fetch_latest_ledger` returns `None`.
    ///
    /// An unreachable primary RPC (connection refused) causes `Server::get_latest_ledger`
    /// to fail, making `fetch_latest_ledger` return `None`. The function must return
    /// `SaError::TimelockListPendingFailed` (not a silent `unwrap_or(0)` sentinel).
    #[tokio::test]
    async fn list_pending_fails_closed_when_rpc_unreachable() {
        use std::sync::{Arc, Mutex};
        use stellar_agent_core::audit_log::writer::AuditWriter;

        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_path, None).expect("AuditWriter::open must succeed"),
        ));

        // Port 1 on loopback is privileged / always refused in CI; StellarRpcClient::new
        // accepts the URL syntactically but get_latest_ledger will fail at connect time,
        // causing fetch_latest_ledger to return None.
        let result = list_pending(
            // Use a syntactically valid C-strkey so that parse_c_strkey_to_smart_account
            // does not fire before the RPC path; the empty audit log makes candidates
            // = [] so the per-op loop does not run.
            "CTESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACN7ALK",
            &audit_writer,
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            "Test SDF Network ; September 2015",
            "test-req-fail-closed",
        )
        .await;

        match result {
            Err(SaError::TimelockListPendingFailed { redacted_reason }) => {
                assert!(
                    !redacted_reason.is_empty(),
                    "TimelockListPendingFailed must carry a non-empty reason"
                );
            }
            other => panic!(
                "expected SaError::TimelockListPendingFailed, got: {:?}",
                other
            ),
        }
    }
}
