//! `stellar-agent smart-account signers` — signer-set lifecycle subcommands.
//!
//! CLI surface for
//! [`stellar_agent_smart_account::managers::signers::SignersManager`].
//!
//! # Subcommands
//!
//! - [`ListArgs`], `smart-account signers list`: reads the on-chain signer set;
//!   writes a `SaSignerSetBaselinedV2` audit row if no prior baseline exists,
//!   and otherwise reports how the chain compares with it.
//! - [`RefreshArgs`], `smart-account signers refresh`: compares the chain with
//!   the baseline and writes a new `SaSignerSetBaselinedV2` row (programmatic
//!   re-anchor after intentional out-of-band mutation, and the one-time upgrade
//!   of a version 1 baseline); a changed or incomparable set needs
//!   `--accept-divergence`.
//! - [`AddArgs`], `smart-account signers add`: adds one signer via OZ
//!   `add_signer` and emits `SaSignerAddedV2`. Four signer-source flags are exclusive:
//!   - `--signer-delegated <G-strkey>`: ed25519 delegated signer.
//!   - `--signer-external <verifier-C-strkey> --signer-key-data <hex>`:
//!     external-verifier signer with raw key data.
//!   - `--signer-webauthn <credential-name>`: WebAuthn passkey signer from
//!     the credential store and `VerifierRegistry`.
//!   - `--signer-ed25519 <64-hex-pubkey>`: External Ed25519 signer using the
//!     registered verifier, or an explicit `--verifier`.
//! - [`RemoveArgs`], `smart-account signers remove`: removes a signer by id
//!   and emits `SaSignerRemovedV2`. An unreachable threshold refuses with `safe_ordering_hint`.
//! - [`SetThresholdArgs`], `smart-account signers set-threshold`: changes the
//!   simple-threshold value and emits `SaThresholdChangedV2`.
//! - [`BatchAddArgs`], `smart-account signers batch-add`: adds multiple signers
//!   and emits one `SaSignerAddedV2` row per signer.
//! - [`SetWeightedThresholdArgs`], `smart-account signers set-weighted-threshold`:
//!   changes a weighted-threshold value.
//! - [`SetSignerWeightArgs`], `smart-account signers set-signer-weight`:
//!   changes one signer's weight.
//!
//! # Signer-source modes (mirror of `smart-account rules`)
//!
//! Write subcommands accept exactly one of:
//! - `--signer-secret-env <VAR>` — read S-strkey from env var.
//! - `--sign-with-ledger` — Ledger hardware wallet (BIP-44 `--account-index`).
//!
//! Read subcommands (`list`, `refresh`) also accept these modes because the
//! manager requires a `source_account_strkey` for the fee-paying envelope.
//!
//! # Mainnet defence
//!
//! All subcommands (including `list` and `refresh`, which trigger baseline-write
//! audit rows) structurally refuse mainnet before any RPC or signing call.
//!
//! # Inverse-bypass discipline
//!
//! All write paths invoke `Signer::sign_auth_digest` exclusively via the
//! `SignersManager`'s `complete_authorization_entry` call site.
//!
//! # Wire codes rendered
//!
//! - `sa.context_rule_caps_exceeded`: `SaError::ContextRuleCapsExceeded`
//! - `sa.weighted_threshold_install_refused`: `SaError::WeightedThresholdInstallRefused`
//! - `sa.weighted_threshold_not_installed`: `SaError::WeightedThresholdNotInstalled`
//! - `sa.weighted_threshold_policy_identification_failed`: `SaError::WeightedThresholdPolicyIdentificationFailed`
//! - `sa.rule_expired`: `SaError::RuleExpired`
//! - `sa.threshold_unreachable`: `SaError::ThresholdUnreachable`
//! - `sa.signer_set_missing_baseline`: `SaError::SignerSetMissingBaseline`
//! - `sa.signer_set_baseline_legacy`: `SaError::SignerSetBaselineLegacy`
//! - `sa.signer_set_diverged`: `SaError::SignerSetDiverged`
//! - `sa.baseline_write_failed`: `SaError::BaselineWriteFailed`
//! - `sa.threshold_policy_not_installed`: `SaError::ThresholdPolicyNotInstalled`
//! - `sa.threshold_policy_identification_failed`: `SaError::ThresholdPolicyIdentificationFailed`
//! - `sa.threshold_read_failed`: `SaError::ThresholdReadFailed`
//! - `sa.pinned_verifier_absent`: `SaError::PinnedVerifierAbsent`
//! - `sa.pinned_policy_absent`: `SaError::PinnedPolicyAbsent`
//! - `sa.verifier_hash_drift`: `SaError::VerifierHashDrift`
//! - `sa.policy_hash_drift`: `SaError::PolicyHashDrift`
//! - `sa.pin_check_unavailable`: `SaError::PinCheckUnavailable`
//! - `sa.auth_entry_construction_failed`: `SaError::AuthEntryConstructionFailed` (stage `rule_lock` for lock timeout)
//! - `sa.verifier_mutable`: `SaError::VerifierMutable`
//! - `sa.verifier_wasm_not_in_allowlist`: `SaError::VerifierWasmNotInAllowlist`
//! - `sa.contract_instance_unsupported`: `SaError::ContractInstanceUnsupported`
//! - `sa.multiple_pinned_hashes_unsupported`: `SaError::MultiplePinnedHashesUnsupported`
//! - `sa.audit_log`: `SaError::AuditLog`
//! - `sa.deployment_failed`: `SaError::DeploymentFailed`
//! - `submission.tx_timeout`, `submission.tx_already_submitted`,
//!   `submission.hash_mismatch`: `SaError::SubmissionUnresolved`, by kind
//! - `network.rpc_divergence`: `SaError::NetworkRpcDivergence`

use base64::Engine as _;
use clap::{ArgGroup, Args, Subcommand};
use serde::{Deserialize, Serialize};
use stellar_agent_core::audit_log::signer_set::{SignerIdentityV2, SignerPubkey, SignerSetView};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{CapKind, NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use stellar_agent_smart_account::managers::rules::{
    OZ_MAX_SIGNERS, decode_signer_count_from_scval, parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::{
    PreviousBaseline, RefreshOptions, RefreshOutcome, SignersManager, build_delegated_signer_scval,
    build_external_signer_scval,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use tracing::info;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    CommonArgsView, CommonHandlerContext, SignerSourceFlags, wrap_sa_error,
};
use crate::common::network::{TESTNET_RPC_URL, TargetNetwork};
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// Cap-enforcement helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `Err(ContextRuleCapsExceeded { kind: Signer, attempted, … })` when
/// `attempted > OZ_MAX_SIGNERS`.  `attempted` is the signer count that would
/// result from adding one signer to a rule that currently has
/// `current_signer_count` signers (`attempted = current + 1`).  The on-chain
/// `TooManySigners = 3010` error is the authoritative last-line defence; this
/// check produces an actionable error before the simulate/submit cycle.
fn enforce_add_signer_cap(attempted: u32) -> Result<(), ValidationError> {
    if attempted > OZ_MAX_SIGNERS {
        return Err(ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Signer,
            attempted,
            max: OZ_MAX_SIGNERS,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `smart-account signers` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct SignersArgs {
    /// The signers subcommand to run.
    #[command(subcommand)]
    pub subcommand: SignersSubcommand,
}

/// Subcommands of `stellar-agent smart-account signers`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SignersSubcommand {
    /// List the on-chain signer set for a context rule.
    ///
    /// Reads the signer set through both RPC endpoints, which must agree.
    /// With no state row, emits `SaSignerSetBaselinedV2`.
    /// With an existing row, compares it and reports `baseline`.
    List(Box<ListArgs>),

    /// Compare and record a fresh `SaSignerSetBaselinedV2` audit row.
    ///
    /// A changed or incomparable set requires `--accept-divergence`.
    /// Upgrades version 1 state and reconciles the pin record: pins a live
    /// unpinned verifier, or drops the sole verifier pin when the rule has
    /// no `External` signer.
    Refresh(Box<RefreshArgs>),

    /// Add a signer to a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling OZ
    /// `add_signer(rule_id, new_signer)`. Emits `SaSignerAddedV2`.
    ///
    /// Refuses operations that would violate `threshold <= signer_count`
    /// with `SaError::ThresholdUnreachable` + `safe_ordering_hint`.
    ///
    /// Accepts exactly one of:
    /// - `--signer-delegated <G-strkey>` — ed25519 delegated signer.
    /// - `--signer-external <verifier-C-strkey> --signer-key-data <hex>` —
    ///   external-verifier signer with raw hex key-data.
    /// - `--signer-webauthn <credential-name>` — WebAuthn passkey signer.
    /// - `--signer-ed25519 <64-hex-pubkey> [--verifier <C-strkey>]` — first-class
    ///   Ed25519 external signer (verifier resolved from the registry when
    ///   `--verifier` is omitted).
    Add(Box<AddArgs>),

    /// Remove a signer from a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling OZ
    /// `remove_signer(rule_id, signer_id)`. Emits `SaSignerRemovedV2`.
    ///
    /// Refuses if removing the signer would drop `signer_count` below
    /// `threshold`; the error includes `safe_ordering_hint` naming the safe
    /// two-command sequence (lower threshold first, then remove).
    Remove(Box<RemoveArgs>),

    /// Change the signing threshold for a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling the OZ
    /// threshold-policy contract's `set_threshold(rule_id, new_threshold)`.
    /// Emits `SaThresholdChangedV2`.
    ///
    /// The threshold-policy contract is identified by wasm-hash allowlist
    /// lookup (`THRESHOLD_POLICY_WASM_HASHES`); zero or multiple matches
    /// refuse with `sa.threshold_policy_identification_failed`.
    SetThreshold(Box<SetThresholdArgs>),

    /// Change the threshold of an installed weighted-threshold policy.
    ///
    /// Constructs and submits `set_threshold(threshold, context_rule,
    /// smart_account)` against the weighted-threshold-policy contract,
    /// routed through the smart account's `execute()` entrypoint. Emits
    /// `SaWeightedThresholdChanged`.
    ///
    /// `--auth-rule-id` defaults to `--rule-id` (a weighted policy commonly
    /// sits on a Default-scoped rule that self-authorizes); pass an explicit
    /// admin-capable rule when the target rule is scoped (a CallContract- or
    /// CreateContract-scoped rule cannot authorize the `execute` context).
    #[command(name = "set-weighted-threshold")]
    SetWeightedThreshold(Box<SetWeightedThresholdArgs>),

    /// Change one signer's weight in an installed weighted-threshold policy.
    ///
    /// Constructs and submits `set_signer_weight(signer, weight,
    /// context_rule, smart_account)` against the weighted-threshold-policy
    /// contract, routed through `execute()`. Emits `SaSignerWeightChanged`.
    /// Accepts the same signer-source flags as `signers add` to identify the
    /// TARGET signer.
    ///
    /// `--auth-rule-id` defaults to `--rule-id`, same convention as
    /// `set-weighted-threshold`.
    #[command(name = "set-signer-weight")]
    SetSignerWeight(Box<SetSignerWeightArgs>),

    /// Add multiple signers to a context rule in ONE transaction via OZ
    /// `batch_add_signer(rule_id, signers)`.
    ///
    /// Accepts REPEATED typed signer flags (each occurrence adds one signer;
    /// mixed kinds allowed) — `signers add` keeps its single-select
    /// semantics unchanged. Refuses client-side if the batch would exceed
    /// `OZ_MAX_SIGNERS` (15). Emits one `SaSignerAdded` row per signer.
    #[command(name = "batch-add")]
    BatchAdd(Box<BatchAddArgs>),
}

/// Runs the `smart-account signers` subcommand group.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &SignersArgs) -> i32 {
    match &args.subcommand {
        SignersSubcommand::List(a) => list_run(a).await,
        SignersSubcommand::Refresh(a) => refresh_run(a).await,
        SignersSubcommand::Add(a) => add_run(a).await,
        SignersSubcommand::Remove(a) => remove_run(a).await,
        SignersSubcommand::SetThreshold(a) => set_threshold_run(a).await,
        SignersSubcommand::SetWeightedThreshold(a) => set_weighted_threshold_run(a).await,
        SignersSubcommand::SetSignerWeight(a) => set_signer_weight_run(a).await,
        SignersSubcommand::BatchAdd(a) => batch_add_run(a).await,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers list`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers list`.
///
/// Reads the on-chain signer set; writes `SaSignerSetBaselinedV2` if no prior
/// baseline exists, and otherwise compares the chain with it and writes
/// nothing. Mainnet is structurally refused.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    override_usage = "stellar-agent smart-account signers list [OPTIONS] --account <C_STRKEY> --rule-id <U32>"
)]
pub struct ListArgs {
    /// Smart-account contract C-strkey to query.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to query.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation. Defaults to `--rpc-url`
    /// (degrades to single-RPC; both will agree trivially).
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers list`.
///
/// Carries the observed signer set and `baseline`, how it compared with the
/// rule's audit-log state row before the call: `none` when this call recorded
/// the first baseline, otherwise `matched`, `diverged` or `not_comparable` (a
/// version 1 baseline the chain state has no version 1 form for).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResult {
    /// Smart-account C-strkey (caller-supplied; not fetched from chain).
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// Number of signers in the rule.
    pub signer_count: u32,
    /// Threshold of the rule's simple-threshold policy; `null` when the rule
    /// has none.
    pub threshold: Option<u32>,
    /// Snapshot version of the observed set.
    pub snapshot_version: u8,
    /// Signer IDs (parallel to `signer_kinds` and `signer_summaries`).
    pub signer_ids: Vec<u32>,
    /// Signer-kind labels (parallel to `signer_ids`): `delegated_ed25519`,
    /// `external` (a passkey signer included) or `delegated_contract`.
    pub signer_kinds: Vec<String>,
    /// Signer identity summaries of first-8 hex projections (parallel to
    /// `signer_ids`).
    pub signer_summaries: Vec<String>,
    /// How the observation compared with the prior state row.
    pub baseline: PreviousBaseline,
}

/// The fields every signer-set envelope reports for a view.
struct ViewFields {
    signer_count: u32,
    threshold: Option<u32>,
    snapshot_version: u8,
    signer_ids: Vec<u32>,
    signer_kinds: Vec<String>,
    signer_summaries: Vec<String>,
}

/// Projects a signer-set view to its envelope fields, signers in the view's
/// order.
fn view_fields(view: &SignerSetView) -> ViewFields {
    match view {
        SignerSetView::V2(snapshot) => ViewFields {
            signer_count: snapshot.signer_count(),
            threshold: snapshot.threshold.as_ref().map(|t| t.threshold),
            snapshot_version: view.version(),
            signer_ids: snapshot.signers.iter().map(|entry| entry.id).collect(),
            signer_kinds: snapshot
                .signers
                .iter()
                .map(|entry| identity_kind_label(&entry.identity).to_owned())
                .collect(),
            signer_summaries: snapshot
                .signers
                .iter()
                .map(|entry| entry.identity.summary())
                .collect(),
        },
        // The manager's outcomes carry version 2 views; a version 1 view
        // summarizes each signer by its kind label.
        SignerSetView::V1(state) => {
            let signer_kinds: Vec<String> =
                state.signer_pubkeys.iter().map(signer_kind_label).collect();
            ViewFields {
                signer_count: state.signer_count,
                threshold: Some(state.threshold),
                snapshot_version: view.version(),
                signer_ids: state.signer_ids.clone(),
                signer_summaries: signer_kinds.clone(),
                signer_kinds,
            }
        }
    }
}

/// Builds the `signers list` envelope from the observed view and its
/// comparison with the prior state row.
fn list_result(
    smart_account: &str,
    rule_id: u32,
    view: &SignerSetView,
    baseline: PreviousBaseline,
) -> ListResult {
    let fields = view_fields(view);
    ListResult {
        smart_account: smart_account.to_owned(),
        rule_id,
        signer_count: fields.signer_count,
        threshold: fields.threshold,
        snapshot_version: fields.snapshot_version,
        signer_ids: fields.signer_ids,
        signer_kinds: fields.signer_kinds,
        signer_summaries: fields.signer_summaries,
        baseline,
    }
}

async fn list_run(args: &ListArgs) -> i32 {
    let request_id = new_request_id();

    // Mainnet defence.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers list: querying on-chain signer set"
    );

    match manager
        .list_signers(
            ctx.smart_account,
            args.rule_id,
            Some(&source_account_strkey),
            request_id.clone(),
        )
        .await
    {
        Ok(outcome) => emit_success(
            &list_result(&args.account, args.rule_id, &outcome.view, outcome.baseline),
            &request_id,
        ),
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers refresh`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers refresh`.
///
/// Observes the signer set, compares it with the rule's audit-log baseline
/// and writes a new `SaSignerSetBaselinedV2` row. A set that differs from the
/// baseline, or a version 1 baseline the chain state cannot be compared with,
/// is recorded only with `--accept-divergence`. On a rule whose pin record
/// pins no verifier while the rule holds `External` signers, the refresh also
/// pins the live verifier, probed as `rules create` probes one.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct RefreshArgs {
    /// Smart-account contract C-strkey to baseline.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to baseline.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Record the chain state even when it differs from the rule's audit-log
    /// baseline, or when a version 1 baseline cannot be compared with it.
    /// Without this flag such a refresh writes the divergence row (for a
    /// differing set) and refuses with `sa.signer_set_diverged`.
    #[arg(long)]
    pub accept_divergence: bool,

    /// Opt-in to pinning a live verifier that is mutable: it has an admin /
    /// owner storage key, or its executable is an owner-managed external
    /// reference.
    ///
    /// Applies only to a rule that holds `External` signers while its pin
    /// record pins no verifier, which signing refuses with
    /// `sa.pinned_verifier_absent`. Each live verifier is identified and
    /// probed as `rules create` probes one. A mutable verifier fails with
    /// `sa.verifier_mutable` unless this flag is set. With it the refresh pins
    /// the verifier and the audit log emits `SaMutableContractOverride`
    /// carrying the rule id. The flag does not admit an unpinnable instance
    /// (`sa.contract_instance_unsupported`).
    #[arg(long)]
    pub accept_mutable_verifier: bool,

    /// Opt-in to pinning a live verifier whose wasm hash is outside the
    /// verifier allowlist.
    ///
    /// Applies under the same conditions as `--accept-mutable-verifier`; an
    /// unknown hash fails with `sa.verifier_wasm_not_in_allowlist` unless
    /// this flag is set, in which case the refresh pins it and the audit log
    /// emits `SaUnknownContractOverride` carrying the rule id.
    #[arg(long)]
    pub accept_unknown_verifier: bool,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers refresh`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// Number of signers in the rule at refresh time.
    pub signer_count: u32,
    /// Threshold of the rule's simple-threshold policy at refresh time;
    /// `null` when the rule has none.
    pub threshold: Option<u32>,
    /// Snapshot version of the recorded baseline.
    pub snapshot_version: u8,
    /// How the chain compared with the baseline the refresh replaced:
    /// `none`, `matched`, `diverged` or `not_comparable`.
    pub previous_baseline: PreviousBaseline,
    /// Whether the refresh pinned the live verifier of a pin record that
    /// pinned no verifier while the rule held `External` signers.
    pub verifier_pinned: bool,
}

/// Builds the `signers refresh` envelope from the recorded view, its
/// comparison with the state row it replaced and whether it pinned the live
/// verifier.
fn refresh_result(
    smart_account: &str,
    rule_id: u32,
    view: &SignerSetView,
    previous_baseline: PreviousBaseline,
    verifier_pinned: bool,
) -> RefreshResult {
    let fields = view_fields(view);
    RefreshResult {
        smart_account: smart_account.to_owned(),
        rule_id,
        signer_count: fields.signer_count,
        threshold: fields.threshold,
        snapshot_version: fields.snapshot_version,
        previous_baseline,
        verifier_pinned,
    }
}

/// The warning lines a refresh prints: one when it accepted a changed or
/// incomparable set, and one when it pinned the live verifier of a pin
/// record that pinned none. Empty when the chain matched the baseline, or
/// there was none, and no verifier was pinned.
fn refresh_warnings(
    rule_id: u32,
    previous_baseline: PreviousBaseline,
    verifier_pinned: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    match previous_baseline {
        PreviousBaseline::Diverged => lines.push(format!(
            "warning: rule {rule_id}'s on-chain signer set differed from its audit-log \
             baseline; the refresh recorded the current chain state"
        )),
        PreviousBaseline::NotComparable => lines.push(format!(
            "warning: rule {rule_id}'s version 1 baseline could not be compared with the \
             chain; the refresh recorded the current chain state"
        )),
        _ => {}
    }
    if verifier_pinned {
        lines.push(format!(
            "warning: rule {rule_id}'s pin record pinned no verifier while the rule held \
             External signers; the refresh pinned the live verifier"
        ));
    }
    lines
}

/// Runs the manager's refresh for `args`, passing `--accept-divergence` and
/// the two verifier overrides through.
#[allow(
    clippy::result_large_err,
    reason = "returns the manager's own error type unchanged"
)]
async fn refresh_outcome(
    manager: &SignersManager,
    smart_account: stellar_xdr::ScAddress,
    args: &RefreshArgs,
    source_account_strkey: Option<&str>,
    request_id: String,
) -> Result<RefreshOutcome, SaError> {
    manager
        .refresh_signer_baseline(
            smart_account,
            args.rule_id,
            source_account_strkey,
            RefreshOptions::new(args.accept_divergence)
                .with_accept_mutable_verifier(args.accept_mutable_verifier)
                .with_accept_unknown_verifier(args.accept_unknown_verifier),
            request_id,
        )
        .await
}

async fn refresh_run(args: &RefreshArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers refresh: writing fresh baseline"
    );

    match refresh_outcome(
        &manager,
        ctx.smart_account,
        args,
        Some(&source_account_strkey),
        request_id.clone(),
    )
    .await
    {
        Ok(outcome) => {
            for warning in refresh_warnings(
                args.rule_id,
                outcome.previous_baseline,
                outcome.verifier_pinned,
            ) {
                #[allow(
                    clippy::print_stderr,
                    reason = "warning lines beside the JSON envelope on stdout"
                )]
                {
                    eprintln!("{warning}");
                }
            }
            emit_success(
                &refresh_result(
                    &args.account,
                    args.rule_id,
                    &outcome.view,
                    outcome.previous_baseline,
                    outcome.verifier_pinned,
                ),
                &request_id,
            )
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers add`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers add`.
///
/// Adds one signer to a context rule via OZ `add_signer`.
///
/// Exactly one of `--signer-delegated`, `--signer-external` /
/// `--signer-key-data`, or `--signer-webauthn` MUST be supplied (enforced by
/// the `new_signer_source` `ArgGroup`).
///
/// # Signer-source paths
///
/// - `--signer-delegated <G-strkey>` — ed25519 delegated signer; encoded as
///   OZ `Signer::Delegated(Address)`.
/// - `--signer-external <verifier-C-strkey> --signer-key-data <hex>` — custom
///   external-verifier signer; encoded as OZ `Signer::External(Address, Bytes)`.
/// - `--signer-webauthn <credential-name>` — WebAuthn passkey signer; resolved
///   from the local credential store. key_data is `pubkey_65_bytes ||
///   credential_id_bytes` per the OZ WebAuthn verifier
///   (`canonicalize_key` strips credential ID at verify time; full concat stored).
///   The verifier address is read from the `VerifierRegistry` for the target network.
/// - `--signer-ed25519 <64-hex-pubkey>` — first-class Ed25519 external signer;
///   encoded as OZ `Signer::External(verifier, key_data)` where `key_data` is the
///   raw 32-byte Ed25519 public key. The verifier address resolves from
///   `--verifier <C-strkey>` when supplied, else from the `VerifierRegistry`'s
///   registered Ed25519 verifier for the target network (fail-closed if neither).
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("new_signer_source")
        .args(["signer_delegated", "signer_external", "signer_webauthn", "signer_ed25519"])
        .required(true)
        .multiple(false))
)]
pub struct AddArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to add the signer to.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// G-strkey of the delegated ed25519 signer to add.
    ///
    /// Encodes as OZ `Signer::Delegated(Address)` on-chain.
    /// Mutually exclusive with `--signer-external` and `--signer-webauthn`.
    #[arg(
        long = "signer-delegated",
        visible_alias = "new-signer",
        value_name = "G_STRKEY",
        group = "new_signer_source"
    )]
    pub signer_delegated: Option<String>,

    /// C-strkey of the deployed verifier contract for an external signer.
    ///
    /// Must be paired with `--signer-key-data`. Together they encode as
    /// OZ `Signer::External(verifier, key_data)` on-chain.
    /// Mutually exclusive with `--signer-delegated` and `--signer-webauthn`.
    #[arg(
        long = "signer-external",
        value_name = "C_STRKEY",
        requires = "signer_key_data",
        group = "new_signer_source"
    )]
    pub signer_external: Option<String>,

    /// Hex-encoded raw key-data for an external signer.
    ///
    /// Required when `--signer-external` is supplied.
    #[arg(
        long = "signer-key-data",
        value_name = "HEX",
        requires = "signer_external"
    )]
    pub signer_key_data: Option<String>,

    /// Credential name from the local passkeys registry to add as a WebAuthn
    /// signer.
    ///
    /// The verifier contract address is read from the `VerifierRegistry` for
    /// the target network (written by `smart-account deploy-webauthn-verifier`).
    /// key_data is constructed as `pubkey_65_bytes || credential_id_bytes` per
    /// the OZ WebAuthn verifier's expected layout.
    /// Mutually exclusive with `--signer-delegated` and `--signer-external`.
    #[arg(
        long = "signer-webauthn",
        value_name = "CREDENTIAL_NAME",
        group = "new_signer_source"
    )]
    pub signer_webauthn: Option<String>,

    /// 64-hex-character raw Ed25519 public key of a first-class external signer.
    ///
    /// Decoded to exactly 32 bytes (invalid hex or a non-64-char length is
    /// refused fail-closed, never silently truncated or padded) and encoded as
    /// OZ `Signer::External(verifier, key_data)` where `key_data` is the raw
    /// public key. The verifier contract address resolves from `--verifier` when
    /// supplied, else from the `VerifierRegistry`'s registered Ed25519 verifier
    /// for the target network (deploy one via
    /// `smart-account deploy-ed25519-verifier`).
    /// Mutually exclusive with `--signer-delegated`, `--signer-external`, and
    /// `--signer-webauthn`.
    #[arg(
        long = "signer-ed25519",
        value_name = "HEX_PUBKEY_64",
        group = "new_signer_source"
    )]
    pub signer_ed25519: Option<String>,

    /// Ed25519 verifier contract C-strkey override for `--signer-ed25519`.
    ///
    /// When omitted, the verifier address resolves from the `VerifierRegistry`
    /// for the target network. Only meaningful with `--signer-ed25519`.
    #[arg(
        long = "verifier",
        value_name = "C_STRKEY",
        requires = "signer_ed25519"
    )]
    pub verifier: Option<String>,

    /// Opt-in to pinning a new verifier that is mutable: it has an admin /
    /// owner storage key, or its executable is an owner-managed external
    /// reference.
    ///
    /// Applies only when the rule has a pin record (it was installed by the
    /// wallet) and a new `External` signer references a verifier address the
    /// rule does not already use. That verifier is identified and probed as
    /// `rules create` probes one; a mutable verifier fails with
    /// `sa.verifier_mutable` unless this flag is set, in which case the add
    /// proceeds and the audit log emits `SaMutableContractOverride` carrying
    /// the rule id. The flag does not admit an unpinnable instance
    /// (`sa.contract_instance_unsupported`).
    #[arg(long)]
    pub accept_mutable_verifier: bool,

    /// Opt-in to pinning a new verifier whose wasm hash is outside the
    /// verifier allowlist.
    ///
    /// Applies under the same conditions as `--accept-mutable-verifier`; an
    /// unknown hash fails with `sa.verifier_wasm_not_in_allowlist` unless
    /// this flag is set, in which case the add proceeds and the audit log
    /// emits `SaUnknownContractOverride` carrying the rule id.
    #[arg(long)]
    pub accept_unknown_verifier: bool,

    /// Profile name for audit-log path resolution and credential store lookup
    /// (used by `--signer-webauthn`).
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers add`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// On-chain ID assigned to the new signer.
    pub new_signer_id: u32,
    /// Human-readable signer-source type label.
    ///
    /// One of `"delegated"`, `"external"`, `"webauthn"`, or `"ed25519"`.
    pub signer_source: String,
    /// Display string for the added signer (G-strkey for delegated; verifier
    /// C-strkey for external/webauthn; redacted to first-5-last-5 for
    /// external/webauthn in log output, but full value returned to the caller
    /// for confirmation).
    pub new_signer: String,
}

async fn add_run(args: &AddArgs) -> i32 {
    let request_id = new_request_id();

    // Mainnet defence.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    // ── Resolve signer-source: build the signer ScVal for each path ───────────
    //
    // Exactly one of `signer_delegated` / `signer_external` / `signer_webauthn`
    // / `signer_ed25519` is non-None, enforced by the `new_signer_source`
    // ArgGroup at parse time. The manager decodes the signer's identity from
    // the ScVal itself.

    let (new_signer_scval, signer_source_label, new_signer_display) = if let Some(g_strkey) =
        &args.signer_delegated
    {
        // ── Delegated (ed25519) ───────────────────────────────────────────
        // Encoded as OZ `Signer::Delegated(Address)`.
        let scval = match build_delegated_signer_scval(g_strkey) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("--signer-delegated: {e}"),
                    }),
                    &request_id,
                );
            }
        };
        (scval, "delegated".to_owned(), g_strkey.clone())
    } else if let Some(verifier_c_strkey) = &args.signer_external {
        // ── External (custom verifier) ────────────────────────────────────
        // Encoded as OZ `Signer::External(Address, Bytes)`.
        // key_data is operator-supplied raw hex; no canonicalisation applied here
        // (operator takes responsibility for correct layout matching the verifier).
        let key_data_hex = args.signer_key_data.as_deref().unwrap_or("");
        let key_data = match hex::decode(key_data_hex) {
            Ok(b) => b,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("--signer-key-data is not valid hex: {e}"),
                    }),
                    &request_id,
                );
            }
        };
        if key_data.is_empty() {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: "--signer-key-data must be non-empty".to_owned(),
                }),
                &request_id,
            );
        }
        let verifier_sc_addr = match parse_c_strkey_to_smart_account(verifier_c_strkey) {
            Ok(addr) => addr,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!("--signer-external: {e}"),
                    },
                    &request_id,
                );
            }
        };
        let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!("--signer-external ScVal encode: {e}"),
                    },
                    &request_id,
                );
            }
        };
        (scval, "external".to_owned(), verifier_c_strkey.clone())
    } else if let Some(credential_name) = &args.signer_webauthn {
        // ── WebAuthn passkey ──────────────────────────────────────────────
        // key_data = pubkey_65_bytes || credential_id_bytes, matching the OZ
        // WebAuthn verifier (`canonicalize_key` strips the credential-ID
        // suffix at verify time; the full concat is stored on-chain).
        // Verifier address is read from `VerifierRegistry` for the target network.

        let verifier_registry = match VerifierRegistry::open() {
            Ok(r) => r,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("could not open verifier registry: {e}"),
                    }),
                    &request_id,
                );
            }
        };

        let network_passphrase = args.network.passphrase();
        let verifier_entry = match verifier_registry.webauthn_verifier_for(network_passphrase) {
            Some(e) => e,
            None => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "no WebAuthn verifier deployed for network '{network_passphrase}'; \
                                 run: smart-account deploy-webauthn-verifier"
                        ),
                    }),
                    &request_id,
                );
            }
        };

        let verifier_sc_addr = match parse_c_strkey_to_smart_account(&verifier_entry.address) {
            Ok(addr) => addr,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!(
                            "verifier registry address '{}' is not a valid C-strkey: {e}",
                            verifier_entry.address
                        ),
                    },
                    &request_id,
                );
            }
        };

        let profile = resolve_profile_name(args.profile.as_deref()).name;
        if let Err(reason) = validate_path_component_ascii_safe(&profile) {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("invalid profile name '{profile}': {reason}"),
                }),
                &request_id,
            );
        }

        let creds_mgr = match CredentialsManager::from_defaults_readonly(&profile, "localhost") {
            Ok(m) => m,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("could not open passkeys registry: {e}"),
                    }),
                    &request_id,
                );
            }
        };

        let metadata = match creds_mgr.show(credential_name) {
            Ok(m) => m,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("--signer-webauthn '{credential_name}': {e}"),
                    }),
                    &request_id,
                );
            }
        };

        if metadata.public_key_sec1_b64.is_empty() {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-webauthn '{credential_name}': credential is missing \
                             public_key_sec1_b64 (delete and re-register)"
                    ),
                }),
                &request_id,
            );
        }

        // Decode public key (65-byte uncompressed SEC1 P-256 point).
        let pubkey_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&metadata.public_key_sec1_b64)
        {
            Ok(b) => b,
            Err(_) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{credential_name}': \
                                 public_key_sec1_b64 is not valid base64url"
                        ),
                    }),
                    &request_id,
                );
            }
        };
        if pubkey_bytes.len() != 65 {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-webauthn '{credential_name}': public_key_sec1_b64 \
                             decodes to {} bytes, expected 65",
                        pubkey_bytes.len()
                    ),
                }),
                &request_id,
            );
        }

        // Decode credential_id bytes.
        let credential_id_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&metadata.credential_id_b64url)
        {
            Ok(b) => b,
            Err(_) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{credential_name}': \
                                 credential_id_b64url is not valid base64url"
                        ),
                    }),
                    &request_id,
                );
            }
        };
        if credential_id_bytes.is_empty() {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-webauthn '{credential_name}': credential_id_b64url is empty \
                             (corrupted credential store entry; delete and re-register)"
                    ),
                }),
                &request_id,
            );
        }

        // key_data = pubkey_65_bytes || credential_id_bytes.
        // Canonical layout expected by the OZ WebAuthn verifier:
        //   `canonicalize_key` reads bytes 0..65 as the public key; the credential-ID
        //   suffix at bytes 65+ is metadata used for credential lookup on the off-chain
        //   side and ignored by the on-chain verifier.
        let mut key_data = Vec::with_capacity(65 + credential_id_bytes.len());
        key_data.extend_from_slice(&pubkey_bytes);
        key_data.extend_from_slice(&credential_id_bytes);

        let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!("--signer-webauthn ScVal encode: {e}"),
                    },
                    &request_id,
                );
            }
        };

        (scval, "webauthn".to_owned(), credential_name.clone())
    } else if let Some(hex_pubkey) = &args.signer_ed25519 {
        // ── First-class Ed25519 external signer ───────────────────────────
        // key_data is the raw 32-byte Ed25519 public key; encoded as OZ
        // `Signer::External(verifier, key_data)`: the same on-chain shape as
        // `--signer-external`, resolved through the same
        // `build_external_signer_scval`. The OZ Ed25519 verifier's
        // `canonicalize_key` returns the 32-byte key verbatim
        // (`packages/accounts/src/verifiers/ed25519.rs`, SHA `a9c4216`).

        // Decode exactly 32 bytes; fail closed on invalid hex or wrong length.
        let key_data = match hex::decode(hex_pubkey) {
            Ok(b) => b,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("--signer-ed25519 is not valid hex: {e}"),
                    }),
                    &request_id,
                );
            }
        };
        if key_data.len() != 32 {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-ed25519 must decode to exactly 32 bytes (a raw Ed25519 \
                             public key), got {} bytes",
                        key_data.len()
                    ),
                }),
                &request_id,
            );
        }

        // Resolve the verifier address: explicit `--verifier` override, else
        // the network's registered Ed25519 verifier. Fail closed if neither
        // is available.
        let verifier_c_strkey = if let Some(explicit) = &args.verifier {
            explicit.clone()
        } else {
            let verifier_registry = match VerifierRegistry::open() {
                Ok(r) => r,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("could not open verifier registry: {e}"),
                        }),
                        &request_id,
                    );
                }
            };
            let network_passphrase = args.network.passphrase();
            match verifier_registry.ed25519_verifier_for(network_passphrase) {
                Some(entry) => entry.address.clone(),
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "no Ed25519 verifier registered for network \
                                     '{network_passphrase}'; run: \
                                     smart-account deploy-ed25519-verifier (or pass --verifier)"
                            ),
                        }),
                        &request_id,
                    );
                }
            }
        };

        let verifier_sc_addr = match parse_c_strkey_to_smart_account(&verifier_c_strkey) {
            Ok(addr) => addr,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!("--signer-ed25519 verifier '{verifier_c_strkey}': {e}"),
                    },
                    &request_id,
                );
            }
        };

        let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: format!("--signer-ed25519 ScVal encode: {e}"),
                    },
                    &request_id,
                );
            }
        };

        (scval, "ed25519".to_owned(), verifier_c_strkey)
    } else {
        // ArgGroup enforces that one of the four is always set; this branch
        // is unreachable at runtime but required for exhaustive match.
        unreachable!("ArgGroup `new_signer_source` guarantees one signer-source flag is set")
    };

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    // Pre-simulate cap check: fetch the current rule's signer count via
    // `get_rule` and refuse fail-CLOSED if adding one more signer would exceed
    // OZ_MAX_SIGNERS.
    // TOCTOU note: the fetch is non-atomic. A concurrent mutation landing
    // between fetch and submit surfaces as `SaError::DeploymentFailed` with
    // `[OZ:TooManySigners]`. Retry via `smart-account rules get` + re-submit.
    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let cr_manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    let smart_account_for_cap_check = ctx.smart_account.clone();

    match cr_manager
        .get_rule(
            smart_account_for_cap_check,
            args.rule_id,
            &source_account_strkey,
        )
        .await
    {
        Ok(Some(scval)) => {
            // Decode the current signer count from the returned ContextRule ScVal.
            // `decode_signer_count_from_scval` reads the `signer_ids` field of
            // the OZ context-rule storage layout.
            match decode_signer_count_from_scval(&scval) {
                Ok(current_signer_count) => {
                    let attempted = current_signer_count.saturating_add(1);
                    if let Err(e) = enforce_add_signer_cap(attempted) {
                        return emit_error(&WalletError::Validation(e), &request_id);
                    }
                }
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: e.to_string(),
                        },
                        &request_id,
                    );
                }
            }
        }
        Ok(None) => {
            // Rule not found. Let the `add_signer` call below surface the
            // `ContextRuleNotFound` (discriminant 3000) error at simulate time.
        }
        Err(e) => {
            return emit_error(
                &WalletError::SmartAccount {
                    wire_code: e.wire_code(),
                    message: e.to_string(),
                },
                &request_id,
            );
        }
    }

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        signer_source = %signer_source_label,
        "smart-account signers add: submitting add_signer"
    );

    match manager
        .add_signer(
            ctx.smart_account,
            args.rule_id,
            new_signer_scval,
            ctx.signer.as_ref(),
            request_id.clone(),
            args.accept_mutable_verifier,
            args.accept_unknown_verifier,
        )
        .await
    {
        Ok(new_signer_id) => {
            let result = AddResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_signer_id,
                signer_source: signer_source_label,
                new_signer: new_signer_display,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers remove`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers remove`.
///
/// Removes a signer by its on-chain `signer_id`.  Use `smart-account signers list`
/// to obtain the current signer IDs.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID from which to remove the signer.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// On-chain signer ID to remove (from `smart-account signers list`).
    #[arg(long = "signer-id", value_name = "U32", required = true)]
    pub signer_id: u32,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers remove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The signer ID that was removed.
    pub removed_signer_id: u32,
}

async fn remove_run(args: &RemoveArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        signer_id = args.signer_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers remove: submitting remove_signer"
    );

    match manager
        .remove_signer(
            ctx.smart_account,
            args.rule_id,
            args.signer_id,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = RemoveResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                removed_signer_id: args.signer_id,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers set-threshold`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers set-threshold`.
///
/// Changes the threshold of a context rule's threshold-policy contract.
/// The policy is identified via wasm-hash allowlist lookup; single-match
/// required (zero / multi-match refuse with
/// `sa.threshold_policy_identification_failed`).
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetThresholdArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID whose threshold to change.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New threshold value (`1 <= new_threshold <= signer_count`).
    #[arg(long = "new-threshold", value_name = "U32", required = true)]
    pub new_threshold: u32,

    /// Profile name for audit-log path resolution.
    ///
    /// Note: there is no `--auth-rule-id` flag. The manager internally sets
    /// `auth_rule_ids = vec![rule_id]`; there is no supported override path at
    /// this CLI surface.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers set-threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetThresholdResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The new threshold value that was applied.
    pub new_threshold: u32,
}

macro_rules! impl_common_args_view {
    ($ty:ty) => {
        impl CommonArgsView for $ty {
            fn account(&self) -> &str {
                &self.account
            }

            fn profile(&self) -> Option<&str> {
                self.profile.as_deref()
            }

            fn signer_source(&self) -> &SignerSourceFlags {
                &self.signer_source
            }

            fn network(&self) -> TargetNetwork {
                self.network
            }

            fn rpc_url(&self) -> &str {
                &self.rpc_url
            }

            fn secondary_rpc_url(&self) -> Option<&str> {
                self.secondary_rpc_url.as_deref()
            }

            fn timeout_seconds(&self) -> u64 {
                self.timeout_seconds
            }
        }
    };
}

impl_common_args_view!(ListArgs);
impl_common_args_view!(RefreshArgs);
impl_common_args_view!(AddArgs);
impl_common_args_view!(RemoveArgs);
impl_common_args_view!(SetThresholdArgs);

async fn set_threshold_run(args: &SetThresholdArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        new_threshold = args.new_threshold,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers set-threshold: submitting set_threshold"
    );

    match manager
        .set_threshold(
            ctx.smart_account,
            args.rule_id,
            args.new_threshold,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = SetThresholdResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_threshold: args.new_threshold,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers set-weighted-threshold`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers set-weighted-threshold`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetWeightedThresholdArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID whose weighted-threshold policy to change.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New threshold value.
    #[arg(long = "new-threshold", value_name = "U32", required = true)]
    pub new_threshold: u32,

    /// Auth rule-id whose signers authorise this update. Default: `--rule-id`
    /// (a weighted policy commonly sits on a Default-scoped rule that
    /// self-authorizes). Pass an explicit admin-capable rule when the target
    /// rule is scoped — a CallContract- or CreateContract-scoped rule cannot
    /// validate the `execute` auth context (mirrors the `set-spending-limit`
    /// lesson: a scoped target rule can never authorize its own retune).
    #[arg(long, value_name = "U32")]
    pub auth_rule_id: Option<u32>,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers set-weighted-threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetWeightedThresholdResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The new threshold value that was applied.
    pub new_threshold: u32,
}

impl_common_args_view!(SetWeightedThresholdArgs);

async fn set_weighted_threshold_run(args: &SetWeightedThresholdArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    let auth_rule_ids = vec![
        stellar_agent_core::smart_account::rule_id::ContextRuleId::new(
            args.auth_rule_id.unwrap_or(args.rule_id),
        ),
    ];

    info!(
        rule_id = args.rule_id,
        new_threshold = args.new_threshold,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers set-weighted-threshold: submitting set_threshold"
    );

    match manager
        .set_weighted_threshold(
            ctx.smart_account,
            args.rule_id,
            args.new_threshold,
            &auth_rule_ids,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = SetWeightedThresholdResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_threshold: args.new_threshold,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers set-signer-weight`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers set-signer-weight`.
///
/// Accepts the same signer-source flags as `smart-account signers add` to
/// identify the TARGET signer whose weight changes.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("target_signer_source")
        .args(["signer_delegated", "signer_external", "signer_webauthn", "signer_ed25519"])
        .required(true)
        .multiple(false))
)]
pub struct SetSignerWeightArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID whose weighted-threshold policy to change.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New weight value for the target signer.
    #[arg(long = "new-weight", value_name = "U32", required = true)]
    pub new_weight: u32,

    /// G-strkey of the TARGET delegated signer.
    #[arg(
        long = "signer-delegated",
        value_name = "G_STRKEY",
        group = "target_signer_source"
    )]
    pub signer_delegated: Option<String>,

    /// C-strkey of the TARGET signer's verifier contract (raw escape hatch).
    #[arg(
        long = "signer-external",
        value_name = "C_STRKEY",
        requires = "signer_key_data",
        group = "target_signer_source"
    )]
    pub signer_external: Option<String>,

    /// Hex-encoded raw key-data for the TARGET external signer.
    #[arg(
        long = "signer-key-data",
        value_name = "HEX",
        requires = "signer_external"
    )]
    pub signer_key_data: Option<String>,

    /// Credential name of the TARGET WebAuthn signer.
    #[arg(
        long = "signer-webauthn",
        value_name = "CREDENTIAL_NAME",
        group = "target_signer_source"
    )]
    pub signer_webauthn: Option<String>,

    /// 64-hex-character raw Ed25519 public key of the TARGET first-class
    /// external signer.
    #[arg(
        long = "signer-ed25519",
        value_name = "HEX_PUBKEY_64",
        group = "target_signer_source"
    )]
    pub signer_ed25519: Option<String>,

    /// Ed25519 verifier contract C-strkey override for `--signer-ed25519`.
    #[arg(
        long = "verifier",
        value_name = "C_STRKEY",
        requires = "signer_ed25519"
    )]
    pub verifier: Option<String>,

    /// Auth rule-id whose signers authorise this update. Default: `--rule-id`.
    /// See `set-weighted-threshold` for the scoped-rule override rationale.
    #[arg(long, value_name = "U32")]
    pub auth_rule_id: Option<u32>,

    /// Profile name for audit-log path resolution and credential store lookup.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers set-signer-weight`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSignerWeightResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The new weight value that was applied.
    pub new_weight: u32,
}

impl_common_args_view!(SetSignerWeightArgs);

async fn set_signer_weight_run(args: &SetSignerWeightArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let target_signer = match resolve_weighted_signer_input(
        WeightedSignerSourceSpec {
            delegated: args.signer_delegated.as_deref(),
            external_verifier: args.signer_external.as_deref(),
            external_key_data_hex: args.signer_key_data.as_deref(),
            webauthn_credential: args.signer_webauthn.as_deref(),
            ed25519_hex_pubkey: args.signer_ed25519.as_deref(),
            ed25519_verifier_override: args.verifier.as_deref(),
        },
        args.network,
        args.profile.as_deref(),
    )
    .await
    {
        Ok(input) => input,
        Err(e) => return emit_error(&e, &request_id),
    };

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    let auth_rule_ids = vec![
        stellar_agent_core::smart_account::rule_id::ContextRuleId::new(
            args.auth_rule_id.unwrap_or(args.rule_id),
        ),
    ];

    info!(
        rule_id = args.rule_id,
        new_weight = args.new_weight,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers set-signer-weight: submitting set_signer_weight"
    );

    match manager
        .set_signer_weight(
            ctx.smart_account,
            args.rule_id,
            target_signer,
            args.new_weight,
            &auth_rule_ids,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = SetSignerWeightResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_weight: args.new_weight,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers batch-add`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers batch-add`.
///
/// Accepts REPEATED typed signer flags (each occurrence adds one signer to
/// the batch; mixed kinds allowed). `smart-account signers add` keeps its
/// single-select semantics — this is an additive verb for the batch case.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct BatchAddArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to add signers to.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// One delegated (ed25519) signer G-strkey per occurrence. Repeatable.
    #[arg(long = "signer-delegated", value_name = "G_STRKEY",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub signer_delegated: Vec<String>,

    /// One WebAuthn passkey credential name per occurrence. Repeatable.
    #[arg(long = "signer-webauthn", value_name = "CREDENTIAL_NAME",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub signer_webauthn: Vec<String>,

    /// One first-class Ed25519 external signer (64-hex pubkey) per
    /// occurrence. Repeatable. Uses `--verifier` (if given) or the
    /// network's registered Ed25519 verifier for ALL entries in this flag.
    #[arg(long = "signer-ed25519", value_name = "HEX_PUBKEY_64",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub signer_ed25519: Vec<String>,

    /// Ed25519 verifier contract C-strkey override for `--signer-ed25519`
    /// entries.
    #[arg(long = "verifier", value_name = "C_STRKEY")]
    pub verifier: Option<String>,

    /// Same as `--accept-mutable-verifier` on `smart-account signers add`,
    /// for every new verifier the batch pins.
    #[arg(long)]
    pub accept_mutable_verifier: bool,

    /// Same as `--accept-unknown-verifier` on `smart-account signers add`,
    /// for every new verifier the batch pins.
    #[arg(long)]
    pub accept_unknown_verifier: bool,

    /// Profile name for audit-log path resolution and credential store lookup.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers batch-add`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAddResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// On-chain IDs assigned to the new signers, in the order supplied.
    pub new_signer_ids: Vec<u32>,
}

impl_common_args_view!(BatchAddArgs);

async fn batch_add_run(args: &BatchAddArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    if args.signer_delegated.is_empty()
        && args.signer_webauthn.is_empty()
        && args.signer_ed25519.is_empty()
    {
        return emit_error(
            &WalletError::Validation(ValidationError::AddressInvalid {
                input: "batch-add requires at least one --signer-delegated / \
                        --signer-webauthn / --signer-ed25519"
                    .to_owned(),
            }),
            &request_id,
        );
    }

    let mut new_signers: Vec<stellar_xdr::ScVal> = Vec::with_capacity(
        args.signer_delegated.len() + args.signer_webauthn.len() + args.signer_ed25519.len(),
    );

    for g_strkey in &args.signer_delegated {
        let spec = WeightedSignerSourceSpec {
            delegated: Some(g_strkey.as_str()),
            external_verifier: None,
            external_key_data_hex: None,
            webauthn_credential: None,
            ed25519_hex_pubkey: None,
            ed25519_verifier_override: None,
        };
        match resolve_batch_signer_scval(spec, args.network, args.profile.as_deref()).await {
            Ok(scval) => new_signers.push(scval),
            Err(e) => return emit_error(&e, &request_id),
        }
    }
    for credential_name in &args.signer_webauthn {
        let spec = WeightedSignerSourceSpec {
            delegated: None,
            external_verifier: None,
            external_key_data_hex: None,
            webauthn_credential: Some(credential_name.as_str()),
            ed25519_hex_pubkey: None,
            ed25519_verifier_override: None,
        };
        match resolve_batch_signer_scval(spec, args.network, args.profile.as_deref()).await {
            Ok(scval) => new_signers.push(scval),
            Err(e) => return emit_error(&e, &request_id),
        }
    }
    for hex_pubkey in &args.signer_ed25519 {
        let spec = WeightedSignerSourceSpec {
            delegated: None,
            external_verifier: None,
            external_key_data_hex: None,
            webauthn_credential: None,
            ed25519_hex_pubkey: Some(hex_pubkey.as_str()),
            ed25519_verifier_override: args.verifier.as_deref(),
        };
        match resolve_batch_signer_scval(spec, args.network, args.profile.as_deref()).await {
            Ok(scval) => new_signers.push(scval),
            Err(e) => return emit_error(&e, &request_id),
        }
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        batch_len = new_signers.len(),
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers batch-add: submitting batch_add_signer"
    );

    match manager
        .batch_add_signers(
            ctx.smart_account,
            args.rule_id,
            new_signers,
            ctx.signer.as_ref(),
            request_id.clone(),
            args.accept_mutable_verifier,
            args.accept_unknown_verifier,
        )
        .await
    {
        Ok(new_signer_ids) => {
            let result = BatchAddResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_signer_ids,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared signer-source resolution (set-signer-weight target + batch-add)
// ─────────────────────────────────────────────────────────────────────────────

/// One signer-source specification, mirroring `AddArgs`'s four mutually
/// exclusive flag kinds. Exactly one field group should be populated by the
/// caller (delegated / external / webauthn / ed25519).
struct WeightedSignerSourceSpec<'a> {
    delegated: Option<&'a str>,
    external_verifier: Option<&'a str>,
    external_key_data_hex: Option<&'a str>,
    webauthn_credential: Option<&'a str>,
    ed25519_hex_pubkey: Option<&'a str>,
    ed25519_verifier_override: Option<&'a str>,
}

/// Resolves a webauthn-credential-name signer source to `(verifier_sc_addr,
/// key_data)`, shared by `set-signer-weight` and `batch-add`.
async fn resolve_webauthn_source(
    credential_name: &str,
    network: TargetNetwork,
    profile: Option<&str>,
) -> Result<(stellar_xdr::ScAddress, Vec<u8>), WalletError> {
    let verifier_registry = VerifierRegistry::open().map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("could not open verifier registry: {e}"),
        })
    })?;
    let network_passphrase = network.passphrase();
    let verifier_entry = verifier_registry
        .webauthn_verifier_for(network_passphrase)
        .ok_or_else(|| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "no WebAuthn verifier deployed for network '{network_passphrase}'; run: \
                     smart-account deploy-webauthn-verifier"
                ),
            })
        })?;
    let verifier_sc_addr =
        parse_c_strkey_to_smart_account(&verifier_entry.address).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!(
                    "verifier registry address '{}' is not a valid C-strkey: {e}",
                    verifier_entry.address
                ),
            }
        })?;

    let profile_name = resolve_profile_name(profile).name;
    validate_path_component_ascii_safe(&profile_name).map_err(|reason| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("invalid profile name '{profile_name}': {reason}"),
        })
    })?;
    let creds_mgr = CredentialsManager::from_defaults_readonly(&profile_name, "localhost")
        .map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("could not open passkeys registry: {e}"),
            })
        })?;
    let metadata = creds_mgr.show(credential_name).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--signer-webauthn '{credential_name}': {e}"),
        })
    })?;
    if metadata.public_key_sec1_b64.is_empty() {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--signer-webauthn '{credential_name}': credential is missing \
                 public_key_sec1_b64 (delete and re-register)"
            ),
        }));
    }
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--signer-webauthn '{credential_name}': public_key_sec1_b64 is not valid \
                     base64url"
                ),
            })
        })?;
    if pubkey_bytes.len() != 65 {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--signer-webauthn '{credential_name}': public_key_sec1_b64 decodes to {} \
                 bytes, expected 65",
                pubkey_bytes.len()
            ),
        }));
    }
    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.credential_id_b64url)
        .map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--signer-webauthn '{credential_name}': credential_id_b64url is not valid \
                     base64url"
                ),
            })
        })?;
    let mut key_data = Vec::with_capacity(65 + credential_id_bytes.len());
    key_data.extend_from_slice(&pubkey_bytes);
    key_data.extend_from_slice(&credential_id_bytes);
    Ok((verifier_sc_addr, key_data))
}

/// Resolves an ed25519-hex-pubkey signer source to `(verifier_sc_addr,
/// key_data)`, shared by `set-signer-weight` and `batch-add`.
fn resolve_ed25519_source(
    hex_pubkey: &str,
    verifier_override: Option<&str>,
    network: TargetNetwork,
) -> Result<(stellar_xdr::ScAddress, Vec<u8>), WalletError> {
    let key_data = hex::decode(hex_pubkey).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--signer-ed25519 is not valid hex: {e}"),
        })
    })?;
    if key_data.len() != 32 {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--signer-ed25519 must decode to exactly 32 bytes (a raw Ed25519 public key), \
                 got {} bytes",
                key_data.len()
            ),
        }));
    }
    let verifier_c_strkey = if let Some(explicit) = verifier_override {
        explicit.to_owned()
    } else {
        let verifier_registry = VerifierRegistry::open().map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("could not open verifier registry: {e}"),
            })
        })?;
        let network_passphrase = network.passphrase();
        verifier_registry
            .ed25519_verifier_for(network_passphrase)
            .map(|entry| entry.address.clone())
            .ok_or_else(|| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "no Ed25519 verifier registered for network '{network_passphrase}'; \
                         run: smart-account deploy-ed25519-verifier (or pass --verifier)"
                    ),
                })
            })?
    };
    let verifier_sc_addr = parse_c_strkey_to_smart_account(&verifier_c_strkey).map_err(|e| {
        WalletError::SmartAccount {
            wire_code: e.wire_code(),
            message: format!("--signer-ed25519 verifier '{verifier_c_strkey}': {e}"),
        }
    })?;
    Ok((verifier_sc_addr, key_data))
}

/// Resolves a [`WeightedSignerSourceSpec`] to a
/// [`stellar_agent_smart_account::weighted_threshold_policy::WeightedThresholdSignerInput`]
/// for `set-signer-weight`'s TARGET-signer identification.
async fn resolve_weighted_signer_input(
    spec: WeightedSignerSourceSpec<'_>,
    network: TargetNetwork,
    profile: Option<&str>,
) -> Result<
    stellar_agent_smart_account::weighted_threshold_policy::WeightedThresholdSignerInput,
    WalletError,
> {
    use stellar_agent_smart_account::weighted_threshold_policy::WeightedThresholdSignerInput;

    if let Some(g_strkey) = spec.delegated {
        if let Err(e) = stellar_strkey::ed25519::PublicKey::from_string(g_strkey) {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--signer-delegated: {e}"),
            }));
        }
        return Ok(WeightedThresholdSignerInput::Delegated {
            g_strkey: g_strkey.to_owned(),
        });
    }
    if let Some(verifier_c_strkey) = spec.external_verifier {
        let key_data_hex = spec.external_key_data_hex.unwrap_or("");
        let key_data = hex::decode(key_data_hex).map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--signer-key-data is not valid hex: {e}"),
            })
        })?;
        if key_data.is_empty() {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: "--signer-key-data must be non-empty".to_owned(),
            }));
        }
        let verifier_sc_addr = parse_c_strkey_to_smart_account(verifier_c_strkey).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-external: {e}"),
            }
        })?;
        return Ok(WeightedThresholdSignerInput::External {
            verifier: verifier_sc_addr,
            key_data,
        });
    }
    if let Some(credential_name) = spec.webauthn_credential {
        let (verifier, key_data) =
            resolve_webauthn_source(credential_name, network, profile).await?;
        return Ok(WeightedThresholdSignerInput::External { verifier, key_data });
    }
    if let Some(hex_pubkey) = spec.ed25519_hex_pubkey {
        let (verifier, key_data) =
            resolve_ed25519_source(hex_pubkey, spec.ed25519_verifier_override, network)?;
        return Ok(WeightedThresholdSignerInput::External { verifier, key_data });
    }

    // Unreachable: the `target_signer_source` ArgGroup requires exactly one.
    Err(WalletError::Validation(ValidationError::AddressInvalid {
        input: "no target signer source supplied".to_owned(),
    }))
}

/// Resolves a [`WeightedSignerSourceSpec`] to the signer `ScVal` for
/// `batch-add`'s per-flag signer resolution; the manager decodes each
/// signer's identity and verifier from it.
async fn resolve_batch_signer_scval(
    spec: WeightedSignerSourceSpec<'_>,
    network: TargetNetwork,
    profile: Option<&str>,
) -> Result<stellar_xdr::ScVal, WalletError> {
    if let Some(g_strkey) = spec.delegated {
        return build_delegated_signer_scval(g_strkey).map_err(|e| WalletError::SmartAccount {
            wire_code: e.wire_code(),
            message: format!("--signer-delegated: {e}"),
        });
    }
    if let Some(credential_name) = spec.webauthn_credential {
        let (verifier, key_data) =
            resolve_webauthn_source(credential_name, network, profile).await?;
        return build_external_signer_scval(verifier, &key_data).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-webauthn ScVal encode: {e}"),
            }
        });
    }
    if let Some(hex_pubkey) = spec.ed25519_hex_pubkey {
        let (verifier, key_data) =
            resolve_ed25519_source(hex_pubkey, spec.ed25519_verifier_override, network)?;
        return build_external_signer_scval(verifier, &key_data).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-ed25519 ScVal encode: {e}"),
            }
        });
    }

    Err(WalletError::Validation(ValidationError::AddressInvalid {
        input: "no batch signer source supplied".to_owned(),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh UUID-v4 request-id for audit-log forensic correlation.
fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Returns the `signer_kinds` label of a version 2 signer identity. An
/// on-chain passkey signer is an `External` identity and reads `external`.
/// The manager's threshold refusals use their own labels (`ed25519`).
fn identity_kind_label(identity: &SignerIdentityV2) -> &'static str {
    match identity {
        SignerIdentityV2::Ed25519 { .. } => "delegated_ed25519",
        SignerIdentityV2::External { .. } => "external",
        SignerIdentityV2::DelegatedContract { .. } => "delegated_contract",
        // SignerIdentityV2 is #[non_exhaustive]; future variants are rendered as "unknown".
        _ => "unknown",
    }
}

/// Returns the `signer_kinds` label of a version 1 signer.
fn signer_kind_label(pk: &SignerPubkey) -> String {
    match pk {
        SignerPubkey::Ed25519 { .. } => "delegated_ed25519".to_owned(),
        SignerPubkey::External { .. } => "external".to_owned(),
        SignerPubkey::WebAuthn { .. } => "webauthn".to_owned(),
        // SignerPubkey is #[non_exhaustive]; future variants are rendered as "unknown".
        _ => "unknown".to_owned(),
    }
}

/// Renders an envelope around an `Ok` result.
fn emit_success<T: Serialize>(result: &T, request_id: &str) -> i32 {
    let envelope = Envelope::ok_with_request_id(result, request_id.to_owned());
    render_json(&envelope);
    0
}

/// Renders an envelope around a [`WalletError`].
fn emit_error(err: &WalletError, request_id: &str) -> i32 {
    let envelope = Envelope::<()>::err_with_request_id(err, request_id.to_owned());
    render_json(&envelope);
    1
}

/// Maps an [`SaError`] into the `WalletError::SmartAccount { wire_code, message }`
/// envelope shape, threading `request_id`.
fn emit_error_sa(err: &SaError, request_id: &str) -> i32 {
    emit_error(&wrap_sa_error(err), request_id)
}

impl SignersArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`] falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            SignersSubcommand::List(a) => a.profile.as_deref(),
            SignersSubcommand::Refresh(a) => a.profile.as_deref(),
            SignersSubcommand::Add(a) => a.profile.as_deref(),
            SignersSubcommand::Remove(a) => a.profile.as_deref(),
            SignersSubcommand::SetThreshold(a) => a.profile.as_deref(),
            SignersSubcommand::SetWeightedThreshold(a) => a.profile.as_deref(),
            SignersSubcommand::SetSignerWeight(a) => a.profile.as_deref(),
            SignersSubcommand::BatchAdd(a) => a.profile.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;
    use clap::Parser;
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVal, ScVec};

    // ── Per-rule signer cap at `smart-account signers add` ──────────────────────────
    //
    // The `add_run` handler pre-fetches the current rule via `get_rule`,
    // decodes the signer count from the returned ScVal, and refuses fail-CLOSED
    // when `current_signer_count + 1 > OZ_MAX_SIGNERS`.
    //
    // These tests exercise `decode_signer_count_from_scval` + the
    // `ContextRuleCapsExceeded` error construction directly (the async `add_run`
    // path would require a live RPC or a full wiremock harness).

    /// Helper: builds a minimal `ContextRule` ScVal::Map with a given number of
    /// signer IDs in the `signer_ids` field.
    ///
    /// Layout per the OZ context-rule storage: the `signer_ids`
    /// field is a `ScVal::Vec(Some(ScVec([...])))` of `ScVal::U32` values.
    fn make_rule_scval(signer_id_count: usize) -> ScVal {
        let signer_ids: Vec<ScVal> = (0..signer_id_count as u32).map(ScVal::U32).collect();
        ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol("signer_ids".try_into().unwrap())),
                val: ScVal::Vec(Some(ScVec(signer_ids.try_into().unwrap()))),
            }]
            .try_into()
            .unwrap(),
        )))
    }

    /// `signer_count = 15` → cap exceeded, error returned.
    ///
    /// Decodes the count from a real ScVal (exercising production code) then
    /// feeds `attempted = 16` to `enforce_add_signer_cap`.  The helper must
    /// return `Err(ContextRuleCapsExceeded { kind: Signer, attempted: 16, max: 15 })`.
    /// If the `>` predicate in the helper were inverted or deleted this test
    /// would fail.
    #[test]
    fn signers_add_on_full_rule_returns_cap_error() {
        let scval = make_rule_scval(15);
        let current = decode_signer_count_from_scval(&scval).unwrap();
        assert_eq!(current, 15);

        let attempted = current.saturating_add(1);
        // Call the real guard — NOT the predicate directly.
        let err = enforce_add_signer_cap(attempted)
            .expect_err("enforce_add_signer_cap must return Err for attempted=16");
        let wallet_err = WalletError::Validation(err);
        assert_eq!(wallet_err.code(), "validation.context_rule_caps_exceeded");
        let msg = wallet_err.to_string();
        assert!(
            msg.contains("cannot add Signer #16"),
            "error must name kind and attempted; got: {msg}"
        );
        assert!(
            msg.contains("current cap: 15"),
            "error must name the cap; got: {msg}"
        );
    }

    /// `signer_count = 14` → NOT at cap; error NOT triggered.
    ///
    /// Boundary condition: `attempted = 15`, which equals `OZ_MAX_SIGNERS`.
    /// `enforce_add_signer_cap` must return `Ok(())` — the guard allows exactly
    /// `OZ_MAX_SIGNERS`.  If the predicate were `>=` instead of `>` this
    /// assertion would fail.
    #[test]
    fn signers_add_on_14_signer_rule_does_not_trigger_cap() {
        let scval = make_rule_scval(14);
        let current = decode_signer_count_from_scval(&scval).unwrap();
        assert_eq!(current, 14);

        let attempted = current.saturating_add(1);
        assert_eq!(attempted, 15, "14 + 1 = 15");
        // Must be Ok — adding to a 14-signer rule yields attempted=15 which is within cap.
        enforce_add_signer_cap(attempted)
            .expect("enforce_add_signer_cap must return Ok(()) for attempted=15");
    }

    // ── list ─────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct ListArgsHarness {
        #[command(flatten)]
        args: ListArgs,
    }

    #[test]
    fn list_args_parse_minimal() {
        let parsed = ListArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 1);
        assert_eq!(parsed.args.network, TargetNetwork::Testnet);
    }

    #[test]
    fn list_args_accepts_secondary_rpc_url() {
        let parsed = ListArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--secondary-rpc-url",
            "https://soroban-testnet.stellar.org",
        ]);
        assert_eq!(
            parsed.args.secondary_rpc_url.as_deref(),
            Some("https://soroban-testnet.stellar.org")
        );
    }

    #[test]
    fn list_args_reject_output() {
        let err = ListArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── refresh ───────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct RefreshArgsHarness {
        #[command(flatten)]
        args: RefreshArgs,
    }

    #[test]
    fn refresh_args_parse_minimal() {
        let parsed = RefreshArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 2);
    }

    #[test]
    fn refresh_args_reject_output() {
        let err = RefreshArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── add ───────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct AddArgsHarness {
        #[command(flatten)]
        args: AddArgs,
    }

    // ── add: --signer-delegated (renamed from --new-signer; alias kept) ─────────

    #[test]
    fn add_args_parse_signer_delegated() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 1);
        assert_eq!(
            parsed.args.signer_delegated.as_deref(),
            Some(SIMULATE_SENTINEL_G)
        );
        assert!(parsed.args.signer_external.is_none());
        assert!(parsed.args.signer_webauthn.is_none());
    }

    /// The two pin overrides default to `false` on `signers add` and
    /// `signers batch-add`, and each flag sets only its own field.
    #[test]
    fn add_and_batch_add_parse_the_pin_override_flags() {
        let base = [
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ];
        let parsed = AddArgsHarness::parse_from(base);
        assert!(!parsed.args.accept_mutable_verifier);
        assert!(!parsed.args.accept_unknown_verifier);

        let parsed =
            AddArgsHarness::parse_from(base.iter().copied().chain(["--accept-mutable-verifier"]));
        assert!(parsed.args.accept_mutable_verifier);
        assert!(!parsed.args.accept_unknown_verifier);

        let parsed =
            AddArgsHarness::parse_from(base.iter().copied().chain(["--accept-unknown-verifier"]));
        assert!(!parsed.args.accept_mutable_verifier);
        assert!(parsed.args.accept_unknown_verifier);

        let parsed = BatchAddArgsHarness::parse_from(base);
        assert!(!parsed.args.accept_mutable_verifier);
        assert!(!parsed.args.accept_unknown_verifier);

        let parsed = BatchAddArgsHarness::parse_from(
            base.iter()
                .copied()
                .chain(["--accept-mutable-verifier", "--accept-unknown-verifier"]),
        );
        assert!(parsed.args.accept_mutable_verifier);
        assert!(parsed.args.accept_unknown_verifier);
    }

    /// `--new-signer` alias must still parse so existing scripts continue to work.
    #[test]
    fn add_args_parse_legacy_new_signer_alias() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-signer",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        // The visible_alias maps --new-signer to signer_delegated.
        assert_eq!(
            parsed.args.signer_delegated.as_deref(),
            Some(SIMULATE_SENTINEL_G)
        );
    }

    // ── add: --signer-external --signer-key-data ──────────────────────────────

    #[test]
    fn add_args_parse_signer_external() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-key-data",
            "deadbeef01020304",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 2);
        assert!(parsed.args.signer_delegated.is_none());
        assert_eq!(
            parsed.args.signer_external.as_deref(),
            Some("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM")
        );
        assert_eq!(
            parsed.args.signer_key_data.as_deref(),
            Some("deadbeef01020304")
        );
        assert!(parsed.args.signer_webauthn.is_none());
    }

    /// `--signer-external` without `--signer-key-data` must be rejected.
    #[test]
    fn add_args_external_requires_key_data() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("--signer-external without --signer-key-data should be rejected");
        // clap emits MissingRequiredArgument when the requires constraint fails.
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    // ── add: --signer-webauthn ────────────────────────────────────────────────

    #[test]
    fn add_args_parse_signer_webauthn() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--signer-webauthn",
            "my-passkey",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 3);
        assert!(parsed.args.signer_delegated.is_none());
        assert!(parsed.args.signer_external.is_none());
        assert_eq!(parsed.args.signer_webauthn.as_deref(), Some("my-passkey"));
    }

    // ── add: mutual-exclusion ─────────────────────────────────────────────────

    /// Supplying both `--signer-delegated` and `--signer-external` must be rejected.
    #[test]
    fn add_args_reject_delegated_and_external_together() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-key-data",
            "deadbeef",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("two signer-source flags should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// Supplying both `--signer-delegated` and `--signer-webauthn` must be rejected.
    #[test]
    fn add_args_reject_delegated_and_webauthn_together() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-webauthn",
            "my-passkey",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("two signer-source flags should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// Supplying no signer-source flag must be rejected.
    #[test]
    fn add_args_reject_no_signer_source() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("no signer-source flag should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn add_args_reject_output() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── remove ────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct RemoveArgsHarness {
        #[command(flatten)]
        args: RemoveArgs,
    }

    #[test]
    fn remove_args_parse_minimal() {
        let parsed = RemoveArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.signer_id, 0);
    }

    #[test]
    fn remove_args_reject_output() {
        let err = RemoveArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── set-threshold ─────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct SetThresholdArgsHarness {
        #[command(flatten)]
        args: SetThresholdArgs,
    }

    #[test]
    fn set_threshold_args_parse_minimal() {
        let parsed = SetThresholdArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-threshold",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.new_threshold, 2);
        assert_eq!(parsed.args.rule_id, 1);
    }

    #[test]
    fn set_threshold_args_reject_output() {
        let err = SetThresholdArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-threshold",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── set-weighted-threshold ────────────────────────────────────────────────

    #[derive(Parser)]
    struct SetWeightedThresholdArgsHarness {
        #[command(flatten)]
        args: SetWeightedThresholdArgs,
    }

    /// `--auth-rule-id` is optional and defaults to `None` (the handler
    /// defaults to `--rule-id` at call time).
    #[test]
    fn set_weighted_threshold_args_auth_rule_id_defaults_to_none() {
        let parsed = SetWeightedThresholdArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-threshold",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.auth_rule_id, None);
        assert_eq!(parsed.args.new_threshold, 2);
    }

    /// An explicit `--auth-rule-id` overrides the default.
    #[test]
    fn set_weighted_threshold_args_accepts_explicit_auth_rule_id() {
        let parsed = SetWeightedThresholdArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--new-threshold",
            "2",
            "--auth-rule-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.auth_rule_id, Some(0));
    }

    // ── set-signer-weight ──────────────────────────────────────────────────────

    #[derive(Parser)]
    struct SetSignerWeightArgsHarness {
        #[command(flatten)]
        args: SetSignerWeightArgs,
    }

    #[test]
    fn set_signer_weight_args_parse_minimal_delegated() {
        let parsed = SetSignerWeightArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-weight",
            "3",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.new_weight, 3);
        assert_eq!(
            parsed.args.signer_delegated.as_deref(),
            Some(SIMULATE_SENTINEL_G)
        );
    }

    /// The `target_signer_source` ArgGroup requires exactly one of
    /// `--signer-delegated` / `--signer-external` / `--signer-webauthn` /
    /// `--signer-ed25519`; supplying none is a clap grammar error.
    #[test]
    fn set_signer_weight_args_requires_one_target_signer_source() {
        let result = SetSignerWeightArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-weight",
            "3",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert!(
            result.is_err(),
            "no target signer source flag must be a clap grammar error"
        );
    }

    /// Supplying both `--signer-delegated` and `--signer-webauthn` is
    /// refused (mutual exclusivity).
    #[test]
    fn set_signer_weight_args_target_signer_source_is_mutually_exclusive() {
        let result = SetSignerWeightArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-weight",
            "3",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-webauthn",
            "some-credential",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert!(
            result.is_err(),
            "--signer-delegated and --signer-webauthn must be mutually exclusive"
        );
    }

    // ── batch-add ──────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct BatchAddArgsHarness {
        #[command(flatten)]
        args: BatchAddArgs,
    }

    #[test]
    fn batch_add_args_accept_repeated_mixed_signer_flags() {
        let parsed = BatchAddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-webauthn",
            "some-credential",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.signer_delegated.len(), 2);
        assert_eq!(
            parsed.args.signer_webauthn,
            vec!["some-credential".to_owned()]
        );
    }

    /// `batch-add` with no signer flags at all is a clap grammar error only
    /// if `num_args = 1..` alone enforced it — it does NOT (each flag is
    /// independently optional); the runtime refusal fires in `batch_add_run`
    /// instead. This test documents that the args struct itself parses fine
    /// with zero signer flags (the empty-batch guard is a runtime check).
    #[test]
    fn batch_add_args_parse_with_no_signer_flags() {
        let parsed = BatchAddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert!(parsed.args.signer_delegated.is_empty());
        assert!(parsed.args.signer_webauthn.is_empty());
        assert!(parsed.args.signer_ed25519.is_empty());
    }

    /// `batch-add` with zero signer flags is refused at runtime (client-side,
    /// before any RPC call).
    #[tokio::test]
    async fn batch_add_run_refuses_empty_batch() {
        let args = BatchAddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .args;
        let code = batch_add_run(&args).await;
        assert_eq!(code, 1, "an empty signer batch must be refused");
    }

    // ── signer_kind_label ─────────────────────────────────────────────────────

    #[test]
    fn signer_kind_label_ed25519() {
        let pk = SignerPubkey::Ed25519 { pubkey: [0u8; 32] };
        assert_eq!(signer_kind_label(&pk), "delegated_ed25519");
    }

    #[test]
    fn signer_kind_label_webauthn() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [
                0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        assert_eq!(signer_kind_label(&pk), "webauthn");
    }

    // ── list and refresh envelopes ────────────────────────────────────────────

    /// A version-2 view of three signers, one of each identity kind, with
    /// `threshold`.
    fn v2_view(threshold: Option<u32>) -> SignerSetView {
        use stellar_agent_core::audit_log::signer_set::{
            SignerEntryV2, SignerSetSnapshotV2, ThresholdObservation,
        };
        SignerSetView::V2(SignerSetSnapshotV2 {
            signers: vec![
                SignerEntryV2 {
                    id: 0,
                    identity: SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] },
                },
                SignerEntryV2 {
                    id: 3,
                    identity: SignerIdentityV2::External {
                        verifier: [0x22; 32],
                        key_data_sha256: [0x33; 32],
                        key_data_len: 81,
                    },
                },
                SignerEntryV2 {
                    id: 5,
                    identity: SignerIdentityV2::DelegatedContract {
                        contract: [0x44; 32],
                    },
                },
            ],
            threshold: threshold.map(|threshold| ThresholdObservation {
                policy: [0x55; 32],
                threshold,
            }),
        })
    }

    const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    /// The `signers list` envelope of a policyless version-2 set reports a
    /// `null` threshold, snapshot version 2, and the kind and summary of
    /// every signer, a contract delegate included.
    #[test]
    fn list_result_reports_a_version_2_set_as_json() {
        let json = serde_json::to_value(list_result(
            ACCOUNT,
            4,
            &v2_view(None),
            PreviousBaseline::None,
        ))
        .unwrap();
        assert_eq!(json["rule_id"], 4);
        assert_eq!(json["signer_count"], 3);
        assert!(json["threshold"].is_null(), "{json}");
        assert!(json.as_object().unwrap().contains_key("threshold"));
        assert_eq!(json["snapshot_version"], 2);
        assert_eq!(json["signer_ids"], serde_json::json!([0, 3, 5]));
        assert_eq!(
            json["signer_kinds"],
            serde_json::json!(["delegated_ed25519", "external", "delegated_contract"])
        );
        assert_eq!(
            json["signer_summaries"],
            serde_json::json!([
                "ed25519:1111111111111111",
                "external:2222222222222222:3333333333333333",
                "delegated_contract:4444444444444444"
            ])
        );
        assert_eq!(json["baseline"], "none");
    }

    /// `baseline` renders each comparison outcome.
    #[test]
    fn list_result_renders_each_baseline_value() {
        for (baseline, expected) in [
            (PreviousBaseline::None, "none"),
            (PreviousBaseline::Matched, "matched"),
            (PreviousBaseline::Diverged, "diverged"),
            (PreviousBaseline::NotComparable, "not_comparable"),
        ] {
            let json =
                serde_json::to_value(list_result(ACCOUNT, 1, &v2_view(Some(2)), baseline)).unwrap();
            assert_eq!(json["baseline"], expected);
            assert_eq!(json["threshold"], 2);
        }
    }

    /// The `signers refresh` envelope reports the recorded set's threshold,
    /// its snapshot version and the comparison with the replaced row.
    #[test]
    fn refresh_result_reports_the_comparison_as_json() {
        let json = serde_json::to_value(refresh_result(
            ACCOUNT,
            2,
            &v2_view(Some(2)),
            PreviousBaseline::NotComparable,
            true,
        ))
        .unwrap();
        assert_eq!(json["signer_count"], 3);
        assert_eq!(json["threshold"], 2);
        assert_eq!(json["snapshot_version"], 2);
        assert_eq!(json["previous_baseline"], "not_comparable");
        assert_eq!(json["verifier_pinned"], true);

        let json = serde_json::to_value(refresh_result(
            ACCOUNT,
            2,
            &v2_view(None),
            PreviousBaseline::Matched,
            false,
        ))
        .unwrap();
        assert!(json["threshold"].is_null(), "{json}");
        assert_eq!(json["previous_baseline"], "matched");
        assert_eq!(json["verifier_pinned"], false);
    }

    /// A refresh that recorded a changed or incomparable set prints one
    /// warning line, and one more when it pinned the live verifier; a
    /// matching or first refresh that pinned nothing prints none.
    #[test]
    fn refresh_warning_names_an_accepted_change() {
        assert!(refresh_warnings(3, PreviousBaseline::None, false).is_empty());
        assert!(refresh_warnings(3, PreviousBaseline::Matched, false).is_empty());
        let [diverged] = refresh_warnings(3, PreviousBaseline::Diverged, false)
            .try_into()
            .unwrap();
        assert!(diverged.starts_with("warning: rule 3's"), "{diverged}");
        assert!(!diverged.contains('\n'));
        let [not_comparable] = refresh_warnings(3, PreviousBaseline::NotComparable, false)
            .try_into()
            .unwrap();
        assert!(
            not_comparable.contains("version 1 baseline"),
            "{not_comparable}"
        );

        let [pinned] = refresh_warnings(3, PreviousBaseline::Matched, true)
            .try_into()
            .unwrap();
        assert!(
            pinned.starts_with("warning: rule 3's pin record"),
            "{pinned}"
        );
        assert!(pinned.contains("pinned the live verifier"), "{pinned}");
        assert!(!pinned.contains('\n'));
        let [diverged, pinned] = refresh_warnings(3, PreviousBaseline::Diverged, true)
            .try_into()
            .unwrap();
        assert!(
            diverged.contains("differed from its audit-log"),
            "{diverged}"
        );
        assert!(pinned.contains("pinned the live verifier"), "{pinned}");
    }

    /// The two verifier overrides default to off, and each flag sets its
    /// own field.
    #[test]
    fn refresh_args_verifier_overrides_default_off() {
        let base = [
            "test",
            "--account",
            ACCOUNT,
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ];
        let default = RefreshArgsHarness::parse_from(base).args;
        assert!(!default.accept_mutable_verifier);
        assert!(!default.accept_unknown_verifier);
        let with = |flag: &'static str| {
            let argv: Vec<&str> = base.iter().copied().chain(std::iter::once(flag)).collect();
            RefreshArgsHarness::parse_from(argv).args
        };
        let mutable = with("--accept-mutable-verifier");
        assert!(mutable.accept_mutable_verifier);
        assert!(!mutable.accept_unknown_verifier);
        let unknown = with("--accept-unknown-verifier");
        assert!(unknown.accept_unknown_verifier);
        assert!(!unknown.accept_mutable_verifier);
    }

    /// `--accept-divergence` defaults to off.
    #[test]
    fn refresh_args_accept_divergence_defaults_off() {
        let base = [
            "test",
            "--account",
            ACCOUNT,
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ];
        assert!(!RefreshArgsHarness::parse_from(base).args.accept_divergence);
        let with_flag: Vec<&str> = base
            .iter()
            .copied()
            .chain(std::iter::once("--accept-divergence"))
            .collect();
        assert!(
            RefreshArgsHarness::parse_from(with_flag)
                .args
                .accept_divergence
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Manager pass-through tests and fixtures
    // ─────────────────────────────────────────────────────────────────────────────

    fn rule_scval(id: u32, signers: Vec<ScVal>, policies: Vec<ScVal>) -> ScVal {
        let entry = |key: &str, val| ScMapEntry {
            key: ScVal::Symbol(ScSymbol(key.try_into().unwrap())),
            val,
        };
        let vec_of = |items: Vec<ScVal>| ScVal::Vec(Some(ScVec(items.try_into().unwrap())));
        let signer_ids = (0..u32::try_from(signers.len()).unwrap())
            .map(ScVal::U32)
            .collect();
        ScVal::Map(Some(ScMap(
            vec![
                entry("id", ScVal::U32(id)),
                entry("policies", vec_of(policies)),
                entry("signer_ids", vec_of(signer_ids)),
                entry("signers", vec_of(signers)),
                entry("valid_until", ScVal::Void),
            ]
            .try_into()
            .unwrap(),
        )))
    }

    /// Each override reaches the manager's pin gate, and an absent flag
    /// leaves that gate closed, including when only the other flag is set.
    #[tokio::test]
    #[serial_test::serial]
    async fn add_and_batch_add_pass_pin_overrides_to_the_manager() {
        use stellar_agent_core::audit_log::AuditEntry;
        use stellar_agent_core::profile::schema::Profile;
        use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};

        let dir = tempfile::tempdir().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        keyring_mock::install().unwrap();
        let _secret = OverrideSecretGuard::new();
        let profile_name = format!("signers-overrides-{}", Uuid::new_v4());
        let profile = Profile::builder_testnet("overrides", "owner", "overrides", "nonce")
            .with_profile_name(&profile_name)
            .audit_log_path(dir.path().join("audit.jsonl"))
            .build();
        let profiles = dir.path().join("profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::write(
            profiles.join(format!("{profile_name}.toml")),
            toml::to_string(&profile).unwrap(),
        )
        .unwrap();
        let key = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();

        let server = wiremock::MockServer::start().await;
        let verifier = stellar_strkey::Contract([0x42; 32]).to_string();
        let pubkey = "ab".repeat(32);
        let rpc_url = server.uri();
        let base = [
            "test",
            "--account",
            ACCOUNT,
            "--rule-id",
            "1",
            "--profile",
            &profile_name,
            "--rpc-url",
            &rpc_url,
            "--signer-secret-env",
            OverrideSecretGuard::NAME,
            "--signer-ed25519",
            &pubkey,
            "--verifier",
            &verifier,
        ];
        let args = AddArgsHarness::parse_from(base).args;
        let ctx = CommonHandlerContext::new(&args).await.unwrap();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(OverrideRpcResponder::new(
                &verifier,
                VerifierFixture::UnknownImmutable,
            ))
            .mount(&server)
            .await;
        ctx.signers_manager()
            .unwrap()
            .list_signers(
                ctx.smart_account.clone(),
                1,
                Some(SIMULATE_SENTINEL_G),
                "baseline".to_owned(),
            )
            .await
            .unwrap();
        ctx.audit_writer
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_sa_context_rule_created(
                redact_strkey_first5_last5(ACCOUNT),
                1,
                "default",
                1,
                0,
                None,
                "stellar:testnet",
                "pins",
                vec![],
                vec![],
                false,
                false,
                vec![],
                vec![],
            ))
            .unwrap();

        for verb in ["add", "batch-add"] {
            for (flag, field, fixture, other_flag) in [
                (
                    "--accept-mutable-verifier",
                    "accept_mutable_verifier",
                    VerifierFixture::AllowlistedMutable,
                    "--accept-unknown-verifier",
                ),
                (
                    "--accept-unknown-verifier",
                    "accept_unknown_verifier",
                    VerifierFixture::UnknownImmutable,
                    "--accept-mutable-verifier",
                ),
            ] {
                for flags in [vec![], vec![other_flag], vec![flag], vec![flag, other_flag]] {
                    server.reset().await;
                    let responder = OverrideRpcResponder::new(&verifier, fixture);
                    let invokes = responder.invokes.clone();
                    let probes = responder.probes.clone();
                    wiremock::Mock::given(wiremock::matchers::method("POST"))
                        .respond_with(responder)
                        .mount(&server)
                        .await;
                    let argv = base.iter().copied().chain(flags.iter().copied());
                    let exit = if verb == "add" {
                        add_run(&AddArgsHarness::parse_from(argv).args).await
                    } else {
                        batch_add_run(&BatchAddArgsHarness::parse_from(argv).args).await
                    };
                    let case = format!("{verb}: {flag} -> {field}; flags={flags:?}");
                    assert_eq!(exit, 1, "{case}: the mock refuses mutation simulation");
                    assert!(
                        probes.load(std::sync::atomic::Ordering::SeqCst) > 0,
                        "{case}: manager must probe the new verifier"
                    );
                    let expected = if flags.contains(&flag) {
                        vec![if verb == "add" {
                            "add_signer"
                        } else {
                            "batch_add_signer"
                        }]
                    } else {
                        vec![]
                    };
                    assert_eq!(*invokes.lock().unwrap(), expected, "{case}");
                }
            }
        }
    }

    const OVERRIDE_SIGNER_SEED: [u8; 32] = [0x11; 32];

    struct OverrideSecretGuard(Option<std::ffi::OsString>);

    impl OverrideSecretGuard {
        const NAME: &str = "__STELLAR_AGENT_SIGNERS_OVERRIDE_SECRET";

        fn new() -> Self {
            let previous = std::env::var_os(Self::NAME);
            // SAFETY: the caller holds the serial test lock for this guard's lifetime.
            #[allow(unsafe_code, reason = "serial test environment fixture")]
            unsafe {
                std::env::set_var(
                    Self::NAME,
                    stellar_strkey::ed25519::PrivateKey(OVERRIDE_SIGNER_SEED)
                        .as_unredacted()
                        .to_string()
                        .as_str(),
                );
            }
            Self(previous)
        }
    }

    impl Drop for OverrideSecretGuard {
        fn drop(&mut self) {
            // SAFETY: the caller holds the serial test lock until the guard drops.
            #[allow(unsafe_code, reason = "restore the serial test environment on unwind")]
            unsafe {
                if let Some(previous) = self.0.take() {
                    std::env::set_var(Self::NAME, previous);
                } else {
                    std::env::remove_var(Self::NAME);
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum VerifierFixture {
        AllowlistedMutable,
        UnknownImmutable,
    }

    struct OverrideRpcResponder {
        instance: serde_json::Value,
        invokes: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl OverrideRpcResponder {
        fn new(verifier: &str, fixture: VerifierFixture) -> Self {
            use stellar_agent_test_support::xdr_fixtures::contract_instance_ledger_entries_json;
            use stellar_xdr::{LedgerEntryData, Limits, ReadXdr, WriteXdr};
            let hash = match fixture {
                VerifierFixture::AllowlistedMutable => {
                    stellar_agent_smart_account::VERIFIER_ALLOWLIST[0].wasm_hash
                }
                VerifierFixture::UnknownImmutable => [0xdd; 32],
            };
            let mut body: serde_json::Value =
                serde_json::from_str(&contract_instance_ledger_entries_json(verifier, hash))
                    .unwrap();
            if matches!(fixture, VerifierFixture::AllowlistedMutable) {
                let xdr = &mut body["result"]["entries"][0]["xdr"];
                let mut data =
                    LedgerEntryData::from_xdr_base64(xdr.as_str().unwrap(), Limits::none())
                        .unwrap();
                let LedgerEntryData::ContractData(entry) = &mut data else {
                    panic!("contract data")
                };
                let ScVal::ContractInstance(instance) = &mut entry.val else {
                    panic!("contract instance")
                };
                instance.storage = Some(ScMap(
                    vec![ScMapEntry {
                        key: ScVal::Vec(Some(ScVec(
                            vec![ScVal::Symbol(ScSymbol("Admin".try_into().unwrap()))]
                                .try_into()
                                .unwrap(),
                        ))),
                        val: ScVal::Address(parse_c_strkey_to_smart_account(verifier).unwrap()),
                    }]
                    .try_into()
                    .unwrap(),
                ));
                *xdr = data.to_xdr_base64(Limits::none()).unwrap().into();
            }
            Self {
                instance: body["result"].clone(),
                invokes: Default::default(),
                probes: Default::default(),
            }
        }
    }

    impl wiremock::Respond for OverrideRpcResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            use stellar_agent_test_support::xdr_fixtures::account_entry_xdr_with_seq;
            use stellar_xdr::{
                HostFunction, LedgerKey, Limits, OperationBody, ReadXdr, TransactionEnvelope,
                WriteXdr,
            };
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let result = match body["method"].as_str().unwrap() {
                "getLedgerEntries" => {
                    let key = &body["params"]["keys"][0];
                    match LedgerKey::from_xdr_base64(key.as_str().unwrap(), Limits::none()).unwrap()
                    {
                        LedgerKey::Account(_) => {
                            let source = stellar_strkey::ed25519::PublicKey(
                                ed25519_dalek::SigningKey::from_bytes(&OVERRIDE_SIGNER_SEED)
                                    .verifying_key()
                                    .to_bytes(),
                            )
                            .to_string();
                            serde_json::json!({"entries": [{"key": key, "xdr": account_entry_xdr_with_seq(&source, 100_000_000, 0, 100), "lastModifiedLedgerSeq": 100}], "latestLedger": 1000})
                        }
                        LedgerKey::ContractData(_) => {
                            self.probes
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            self.instance.clone()
                        }
                        other => panic!("unexpected ledger key: {other:?}"),
                    }
                }
                "simulateTransaction" => {
                    let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                        body["params"]["transaction"].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap() else {
                        panic!("transaction")
                    };
                    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                        panic!("invoke")
                    };
                    let HostFunction::InvokeContract(invoke) = &op.host_function else {
                        panic!("contract invoke")
                    };
                    let function = invoke.function_name.to_utf8_string_lossy();
                    if function == "get_context_rule" {
                        let rule = rule_scval(
                            1,
                            vec![build_delegated_signer_scval(SIMULATE_SENTINEL_G).unwrap()],
                            vec![],
                        );
                        serde_json::json!({"results": [{"auth": [], "xdr": rule.to_xdr_base64(Limits::none()).unwrap()}], "latestLedger": 1000})
                    } else {
                        assert!(
                            matches!(function.as_str(), "add_signer" | "batch_add_signer"),
                            "{function}"
                        );
                        self.invokes.lock().unwrap().push(function);
                        serde_json::json!({"error": "mutation simulation stopped by fixture", "latestLedger": 1000})
                    }
                }
                other => panic!("unexpected RPC method: {other}"),
            };
            wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"jsonrpc": "2.0", "id": body["id"], "result": result}),
            )
        }
    }

    /// A mock endpoint answering every `get_context_rule` simulation with
    /// `rule`.
    struct RuleResponder(ScVal);

    impl wiremock::Respond for RuleResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            use stellar_xdr::{Limits, WriteXdr};
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["method"], "simulateTransaction", "{body}");
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "results": [{"auth": [], "xdr": self.0.to_xdr_base64(Limits::none()).unwrap()}],
                    "latestLedger": 1000
                }
            }))
        }
    }

    /// `--accept-divergence` reaches the manager: over a baseline the chain
    /// differs from, the refresh refuses without the flag and records the
    /// chain state with it.
    #[tokio::test]
    async fn refresh_passes_accept_divergence_to_the_manager() {
        use std::sync::{Arc, Mutex};
        use stellar_agent_core::audit_log::entry::AuditEntry;
        use stellar_agent_core::audit_log::signer_set::{
            BaselineReason, SignerEntryV2, SignerSetSnapshotV2, account_digest,
        };
        use stellar_agent_core::audit_log::writer::AuditWriter;
        use stellar_agent_core::observability::RedactedStrkey;
        use stellar_agent_smart_account::managers::signers::SignersManagerConfig;
        use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

        const PASSPHRASE: &str = "Test SDF Network ; September 2015";
        let delegated = |byte: u8| {
            ScVal::Vec(Some(ScVec(
                vec![
                    ScVal::Symbol(ScSymbol("Delegated".try_into().unwrap())),
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
                    ))),
                ]
                .try_into()
                .unwrap(),
            )))
        };
        let rule = rule_scval(1, vec![delegated(0x11)], vec![]);

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(RuleResponder(rule))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(log_path.clone(), None).unwrap(),
        ));
        {
            // A baseline recording another signer than the one on chain.
            let snapshot = SignerSetSnapshotV2 {
                signers: vec![SignerEntryV2 {
                    id: 0,
                    identity: SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
                }],
                threshold: None,
            };
            let mut writer = audit.lock().unwrap();
            let tip = writer.current_chain_tip();
            writer
                .write_entry(AuditEntry::new_sa_signer_set_baselined_v2(
                    1,
                    &snapshot,
                    1000,
                    1_700_000_000_000,
                    BaselineReason::first_observation(),
                    tip,
                    account_digest(PASSPHRASE, ACCOUNT),
                    RedactedStrkey::from_already_redacted(redact_strkey_first5_last5(ACCOUNT)),
                    "stellar:testnet",
                    "req-baseline",
                ))
                .unwrap();
        }
        let manager = SignersManager::new(SignersManagerConfig::new(
            server.uri(),
            server.uri(),
            Arc::clone(&audit),
            log_path,
            PASSPHRASE.to_owned(),
            "refresh-pass-through".to_owned(),
            std::time::Duration::from_secs(10),
            "stellar:testnet".to_owned(),
        ))
        .unwrap();
        let smart_account = parse_c_strkey_to_smart_account(ACCOUNT).unwrap();
        let args_with = |flag: bool| {
            let mut argv = vec![
                "test",
                "--account",
                ACCOUNT,
                "--rule-id",
                "1",
                "--signer-secret-env",
                "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            ];
            if flag {
                argv.push("--accept-divergence");
            }
            RefreshArgsHarness::parse_from(argv).args
        };

        let refused = refresh_outcome(
            &manager,
            smart_account.clone(),
            &args_with(false),
            None,
            "req-refresh-no".to_owned(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.wire_code(), "sa.signer_set_diverged");

        let accepted = refresh_outcome(
            &manager,
            smart_account,
            &args_with(true),
            None,
            "req-refresh-yes".to_owned(),
        )
        .await
        .unwrap();
        assert_eq!(accepted.previous_baseline, PreviousBaseline::Diverged);
    }

    // ── signers add --signer-ed25519 tests ───────────────────────────────────

    /// A canonical all-zeros verifier C-strkey fixture (never a real verifier;
    /// only exercises the encode path).
    const ED25519_TEST_VERIFIER: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    fn add_args_ed25519(hex_pubkey: &str, verifier: Option<String>) -> AddArgs {
        AddArgs {
            account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            signer_delegated: None,
            signer_external: None,
            signer_key_data: None,
            signer_webauthn: None,
            signer_ed25519: Some(hex_pubkey.to_owned()),
            verifier,
            accept_mutable_verifier: false,
            accept_unknown_verifier: false,
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: Some("__STELLAR_AGENT_SIGNERS_ED25519_DUMMY".to_owned()),
                sign_with_ledger: false,
                account_index: Some(0),
            },
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            secondary_rpc_url: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    /// The typed `--signer-ed25519` attach produces the exact same on-chain
    /// `Signer::External(verifier, key_data)` ScVal as the raw
    /// `--signer-external <C> --signer-key-data <same-hex>` escape hatch, because
    /// both funnel through `build_external_signer_scval` with identical inputs.
    /// The wire shape is byte-asserted so the equivalence is not tautological.
    #[test]
    fn signer_ed25519_scval_equals_raw_external_scval() {
        use stellar_xdr::ScBytes;

        let pubkey_hex = "ab".repeat(32); // 64 hex chars → 32 bytes.

        // ed25519 branch decode: exactly 32 bytes.
        let kd_ed25519 = hex::decode(&pubkey_hex).unwrap();
        assert_eq!(kd_ed25519.len(), 32);

        // raw --signer-external branch decode: same hex, any non-empty length.
        let kd_external = hex::decode(&pubkey_hex).unwrap();

        let addr_ed25519 = parse_c_strkey_to_smart_account(ED25519_TEST_VERIFIER).unwrap();
        let addr_external = parse_c_strkey_to_smart_account(ED25519_TEST_VERIFIER).unwrap();

        let sc_ed25519 = build_external_signer_scval(addr_ed25519.clone(), &kd_ed25519).unwrap();
        let sc_external = build_external_signer_scval(addr_external, &kd_external).unwrap();

        assert_eq!(
            sc_ed25519, sc_external,
            "typed ed25519 attach must produce byte-identical ScVal to raw external"
        );

        // Byte-exact OZ External wire shape: Vec([Symbol("External"), Address, Bytes]).
        let ScVal::Vec(Some(ScVec(elems))) = &sc_ed25519 else {
            panic!("expected ScVal::Vec, got {sc_ed25519:?}");
        };
        assert_eq!(elems.len(), 3, "External encodes as a 3-element Vec");
        let ScVal::Symbol(tag) = &elems[0] else {
            panic!("expected Symbol tag, got {:?}", elems[0]);
        };
        assert_eq!(tag.to_utf8_string_lossy(), "External");
        assert!(
            matches!(&elems[1], ScVal::Address(a) if *a == addr_ed25519),
            "vec[1] must be the verifier Address"
        );
        let ScVal::Bytes(ScBytes(b)) = &elems[2] else {
            panic!("expected Bytes payload, got {:?}", elems[2]);
        };
        assert_eq!(b.as_slice(), &kd_ed25519[..], "key_data bytes must match");
    }

    /// `--signer-ed25519` with invalid hex is refused fail-closed before any
    /// network call.
    #[tokio::test]
    async fn signer_ed25519_rejects_invalid_hex() {
        let args = add_args_ed25519(&"zz".repeat(32), Some(ED25519_TEST_VERIFIER.to_owned()));
        let code = add_run(&args).await;
        assert_eq!(code, 1, "invalid hex must be refused");
    }

    /// `--signer-ed25519` that decodes to a non-32-byte length is refused
    /// fail-closed (never silently truncated or padded) before any network call.
    #[tokio::test]
    async fn signer_ed25519_rejects_wrong_length() {
        // 62 hex chars → 31 bytes.
        let args = add_args_ed25519(&"ab".repeat(31), Some(ED25519_TEST_VERIFIER.to_owned()));
        let code = add_run(&args).await;
        assert_eq!(code, 1, "a 31-byte key must be refused");
    }

    /// `--signer-ed25519` with no `--verifier` and no registered Ed25519 verifier
    /// for the network fails closed before any network call.
    #[tokio::test]
    #[serial_test::serial]
    async fn signer_ed25519_missing_verifier_and_registry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("networks.toml");

        // SAFETY: serialised by #[serial]; no concurrent env access.
        #[allow(unsafe_code, reason = "test-only env override; #[serial] serialises")]
        unsafe {
            std::env::set_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                &registry_path,
            );
        }

        let args = add_args_ed25519(&"ab".repeat(32), None);
        let code = add_run(&args).await;

        // SAFETY: same as set; serialised by #[serial].
        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] serialises")]
        unsafe {
            std::env::remove_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            );
        }

        assert_eq!(
            code, 1,
            "missing verifier and empty registry must fail closed"
        );
    }
}
