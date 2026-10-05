//! Testnet-only sponsored MPP charge CLI.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::{
    approval::{store::PendingApprovalStore, user_id::process_uid_for_attestation},
    audit_log::{AuditEntry, NewToolInvocation, PolicyDecision, ValueLegRecord},
    envelope::Envelope,
    error::WalletError,
    observability::RedactedStrkey,
    policy::v1::ValueClass,
    policy::{Decision, McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind},
    profile::{
        caip2::Caip2,
        schema::{Profile, default_approval_dir},
    },
};
use stellar_agent_mpp::{
    ApprovalDisposition, ChallengeInput, MppAuthorizationStore, MppError, MppErrorCode,
    ReceiptInput, StellarReconciliationRpc, StellarSponsoredRpc,
    absent_state_approval_lookup_error, absent_state_lookup_error, authorization_status,
    commit_authorization, mpp_value_effects, parse_receipt, persist_prepared_authorization,
    prepare_sponsored, reconcile_transaction, select_and_validate, verify_pending_approval,
};
use stellar_agent_network::NetworkContext;
use stellar_agent_network::{
    init_platform_keyring_store,
    keyring::{lazy_signer_from_keyring, load_hmac_key_32},
};

use crate::commands::{
    policy_engine::build_v1_policy_engine,
    value_audit::{drain_consent_rows_before_signing, emit_value_audit_row_strict},
};
use crate::common::profile_access::{
    ProfileAccessError, load_profile_reconciled, profile_access_envelope,
};
use crate::common::resolve_profile_name;

const MAX_INPUT_BYTES: usize = 128 * 1024;
const MAX_REASON_BYTES: usize = 4 * 1024;

/// MPP command group.
#[derive(Debug, Args)]
pub struct MppArgs {
    /// MPP operation family.
    #[command(subcommand)]
    command: MppCommand,
}

#[derive(Debug, Subcommand)]
enum MppCommand {
    /// Sponsored charge authorization.
    Charge(MppChargeArgs),
    /// Authorization state inspection.
    Authorization(MppAuthorizationArgs),
    /// Trusted-host receipt recording.
    Receipt(MppReceiptGroupArgs),
    /// Independent ledger settlement reconciliation.
    Settlement(MppSettlementArgs),
    /// Durable MPP state maintenance.
    State(MppStateArgs),
}

#[derive(Debug, Args)]
struct MppChargeArgs {
    #[command(subcommand)]
    command: MppChargeCommand,
}

#[derive(Debug, Subcommand)]
enum MppChargeCommand {
    /// Prepare and authorize, or resume one approved exact authorization.
    Authorize(MppAuthorizeArgs),
}

/// Arguments for `mpp charge authorize`.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("authorization_source")
        .required(true)
        .args(["input_stdin", "input_file", "approval_id"])
))]
struct MppAuthorizeArgs {
    /// Wallet profile (default: `STELLAR_AGENT_PROFILE` env var, then `"default"`).
    #[arg(long = "profile", value_name = "NAME")]
    profile: Option<String>,
    /// Read a tagged ChallengeInput JSON object from stdin.
    #[arg(long, conflicts_with_all = ["input_file", "approval_id"])]
    input_stdin: bool,
    /// Read a tagged ChallengeInput JSON object from a bounded regular file.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["input_stdin", "approval_id"])]
    input_file: Option<PathBuf>,
    /// Resume only the exact stored authorization attached to this approval.
    #[arg(long, value_name = "ID", allow_hyphen_values = true, conflicts_with_all = ["input_stdin", "input_file"])]
    approval_id: Option<String>,
}

#[derive(Debug, Args)]
struct MppAuthorizationArgs {
    #[command(subcommand)]
    command: MppAuthorizationCommand,
}

#[derive(Debug, Subcommand)]
enum MppAuthorizationCommand {
    /// Show redacted authorization state.
    Status(MppStatusArgs),
}

#[derive(Debug, Args)]
struct MppStatusArgs {
    /// Wallet profile (default: `STELLAR_AGENT_PROFILE` env var, then `"default"`).
    #[arg(long = "profile", value_name = "NAME")]
    profile: Option<String>,
    #[arg(long)]
    authorization_id: String,
}

#[derive(Debug, Args)]
struct MppReceiptGroupArgs {
    #[command(subcommand)]
    command: MppReceiptCommand,
}

#[derive(Debug, Subcommand)]
enum MppReceiptCommand {
    /// Record a trusted-host receipt without claiming settlement.
    Record(MppReceiptArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReceiptTransport {
    Http,
    Mcp,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("receipt_source")
        .required(true)
        .args(["receipt_stdin", "receipt_file"])
))]
struct MppReceiptArgs {
    /// Wallet profile (default: `STELLAR_AGENT_PROFILE` env var, then `"default"`).
    #[arg(long = "profile", value_name = "NAME")]
    profile: Option<String>,
    #[arg(long)]
    authorization_id: String,
    #[arg(long)]
    transport: ReceiptTransport,
    #[arg(long, conflicts_with = "receipt_file")]
    receipt_stdin: bool,
    #[arg(long, value_name = "PATH", conflicts_with = "receipt_stdin")]
    receipt_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct MppSettlementArgs {
    #[command(subcommand)]
    command: MppSettlementCommand,
}

#[derive(Debug, Subcommand)]
enum MppSettlementCommand {
    /// Verify a final transaction against a stored authorization.
    Reconcile(MppReconcileArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("reference_source")
        .required(true)
        .args(["reference_stdin", "reference_file"])
))]
struct MppReconcileArgs {
    /// Wallet profile (default: `STELLAR_AGENT_PROFILE` env var, then `"default"`).
    #[arg(long = "profile", value_name = "NAME")]
    profile: Option<String>,
    #[arg(long)]
    authorization_id: String,
    #[arg(long, conflicts_with = "reference_file")]
    reference_stdin: bool,
    #[arg(long, value_name = "PATH", conflicts_with = "reference_stdin")]
    reference_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct MppStateArgs {
    #[command(subcommand)]
    command: MppStateCommand,
}

#[derive(Debug, Subcommand)]
enum MppStateCommand {
    /// Prune only old terminal records.
    Prune(MppPruneArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("reason_source")
        .required(true)
        .args(["reason_stdin", "reason_file"])
))]
struct MppPruneArgs {
    #[arg(long)]
    profile: String,
    #[arg(long, conflicts_with = "reason_file")]
    reason_stdin: bool,
    #[arg(long, value_name = "PATH", conflicts_with = "reason_stdin")]
    reason_file: Option<PathBuf>,
}

/// Dispatches the MPP command group.
pub async fn run(args: MppArgs) -> i32 {
    match args.command {
        MppCommand::Charge(group) => match group.command {
            MppChargeCommand::Authorize(args) => authorize(args).await,
        },
        MppCommand::Authorization(group) => match group.command {
            MppAuthorizationCommand::Status(args) => status(&args),
        },
        MppCommand::Receipt(group) => match group.command {
            MppReceiptCommand::Record(args) => record_receipt(&args),
        },
        MppCommand::Settlement(group) => match group.command {
            MppSettlementCommand::Reconcile(args) => reconcile(args).await,
        },
        MppCommand::State(group) => match group.command {
            MppStateCommand::Prune(args) => prune(&args),
        },
    }
}

async fn authorize(args: MppAuthorizeArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();
    let (profile, context) = match load_testnet_profile(&resolved) {
        Ok(profile) => profile,
        Err(error) => return render_profile_error(&error, &profile_name),
    };

    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(now) => now,
        Err(_) => return render_error(&state_error()),
    };
    let now_unix = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
    if let Some(approval_id) = args.approval_id.as_deref() {
        let state = match MppAuthorizationStore::open_for_read(
            &profile_name,
            &profile,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        ) {
            Ok(Some(state)) => state,
            // A profile with no MPP state holds no authorization under any
            // approval, which is the same answer as a store that holds none.
            Ok(None) => return render_error(&absent_state_approval_lookup_error(approval_id)),
            Err(error) => return render_error(&error),
        };
        let record = match state.load_by_approval_nonce(approval_id) {
            Ok(record) => record,
            Err(error) => return render_error(&error),
        };
        return commit_cli(&context, &profile_name, &profile, &state, &record, now_unix).await;
    }
    // First-use key material is created only after validation and successful simulation.
    prepare_and_authorize_without_state(&context, &args, &profile_name, profile, now_unix).await
}

async fn prepare_and_authorize_without_state(
    context: &NetworkContext,
    args: &MppAuthorizeArgs,
    profile_name: &str,
    profile: Profile,
    now_unix: i64,
) -> i32 {
    let input = match read_authorize_input(args) {
        Ok(input) => input,
        Err(error) => return render_error(&error),
    };
    let selected = match select_and_validate(&input, now_unix) {
        Ok(selected) => selected,
        Err(error) => return render_error(&error),
    };
    let rpc = match StellarSponsoredRpc::new(&context.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return render_error(&error),
    };
    let prepared = match prepare_sponsored(
        selected,
        &profile.mcp_signer_default.account,
        context.network_passphrase(),
        &rpc,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return render_error(&error),
    };
    let state = match MppAuthorizationStore::open_for_prepare(
        profile_name,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(state) => state,
        Err(error) => return render_error(&error),
    };
    persist_and_maybe_commit(context, profile_name, &profile, &state, prepared, now_unix).await
}

async fn persist_and_maybe_commit(
    context: &NetworkContext,
    profile_name: &str,
    profile: &Profile,
    state: &MppAuthorizationStore,
    prepared: stellar_agent_mpp::PreparedSponsoredCharge,
    now_unix: i64,
) -> i32 {
    let engine =
        match build_v1_policy_engine("mpp charge", &profile.policy.engine, profile, profile_name) {
            Ok(engine) => engine,
            Err(_) => return render_error(&state_error()),
        };
    let disposition = match evaluate_policy(
        context,
        engine.as_ref(),
        profile,
        "stellar_mpp_charge_prepare",
        &mpp_value_effects(prepared.selected()),
    ) {
        Ok(disposition) => disposition,
        Err(error) => return render_error(&error),
    };
    let mut approvals = if disposition == ApprovalDisposition::RequireApproval {
        match approval_store(profile_name) {
            Ok(store) => Some(store),
            Err(error) => return render_error(&error),
        }
    } else {
        None
    };
    let uid = match process_uid_for_attestation() {
        Ok(uid) => uid,
        Err(_) => return render_error(&state_error()),
    };
    let preview = match persist_prepared_authorization(
        profile_name,
        context.network_passphrase(),
        &prepared,
        disposition,
        &uid,
        now_unix,
        state,
        approvals.as_mut(),
    ) {
        Ok(preview) => preview,
        Err(error) => return render_error(&error),
    };
    if disposition == ApprovalDisposition::RequireApproval {
        print_json(&json!({
            "ok": false,
            "error": {
                "code": "mpp.approval_required",
                "message": "MPP authorization requires operator approval"
            },
            "data": {
                "authorization_id": &preview.authorization_id,
                "approval_id": &preview.approval_id,
                "preview": preview,
            }
        }));
        return 1;
    }
    let record = match state.load(&preview.authorization_id) {
        Ok(record) => record,
        Err(error) => return render_error(&error),
    };
    commit_cli(context, profile_name, profile, state, &record, now_unix).await
}

async fn commit_cli(
    context: &NetworkContext,
    profile_name: &str,
    profile: &Profile,
    state: &MppAuthorizationStore,
    record: &stellar_agent_mpp::AuthorizationRecord,
    now_unix: i64,
) -> i32 {
    let engine =
        match build_v1_policy_engine("mpp charge", &profile.policy.engine, profile, profile_name) {
            Ok(engine) => engine,
            Err(_) => return render_error(&state_error()),
        };
    let prepared = match record.prepared_charge() {
        Ok(prepared) => prepared,
        Err(error) => return render_error(&error),
    };
    let disposition = match evaluate_policy(
        context,
        engine.as_ref(),
        profile,
        "stellar_mpp_charge_commit",
        &mpp_value_effects(prepared.selected()),
    ) {
        Ok(disposition) => disposition,
        Err(error) => return render_error(&error),
    };
    if disposition == ApprovalDisposition::RequireApproval && record.approval_nonce().is_none() {
        return render_error(&approval_error());
    }
    let mut approvals = None;
    let mut approval_key = None;
    if record.approval_nonce().is_some() {
        approvals = match approval_store(profile_name) {
            Ok(store) => Some(store),
            Err(error) => return render_error(&error),
        };
        approval_key = match load_mpp_attestation_key(profile, profile_name) {
            Ok(key) => Some(key),
            Err(_) => return render_error(&approval_error()),
        };
    }
    if let Err(error) = verify_pending_approval(
        state,
        approvals.as_ref(),
        approval_key.as_deref(),
        &stellar_agent_core::approval::AttestationBinding::new(
            profile_name,
            context.chain_id.caip2_str(),
        ),
        record.authorization_id(),
        now_unix,
    ) {
        return render_error(&error);
    }
    // The approval has been read. Acquiring the keyed writer drains the audit
    // outbox at open, so a consent row `stellar-agent approve` queued for this
    // charge is in the log before the signing key loads. Fail closed: no
    // drain, no signing.
    if let Err(error) = drain_consent_rows_before_signing(profile, profile_name) {
        return render_wallet_error(&error);
    }
    let signer = match lazy_signer_from_keyring(
        &profile.mcp_signer_default,
        &profile.mcp_signer_default.account,
    ) {
        Ok(signer) => signer,
        Err(_) => return render_error(&signing_error()),
    };
    let rpc = match StellarSponsoredRpc::new(&context.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return render_error(&error),
    };
    let descriptor = policy_descriptor(context, "stellar_mpp_charge_commit");
    // Policy and audit refusals retain their wallet code while the MPP
    // service withholds the credential at its accounting or delivery gate.
    let wallet_refusal: Arc<Mutex<Option<WalletError>>> = Arc::new(Mutex::new(None));
    let delivery_refusal = Arc::clone(&wallet_refusal);
    let accounting_refusal = Arc::clone(&wallet_refusal);
    let result = commit_authorization(
        state,
        approvals.as_ref(),
        approval_key.as_deref(),
        &stellar_agent_core::approval::AttestationBinding::new(
            profile_name,
            context.chain_id.caip2_str(),
        ),
        record.authorization_id(),
        now_unix,
        context.network_passphrase(),
        &signer,
        &rpc,
        |_record, _prepared, effects| {
            stellar_agent_network::policy_state::record_authorized_window_state(
                engine.as_ref(),
                &descriptor,
                profile,
                profile_name,
                &ValueClass::Value(effects.clone()),
            )
            .map_err(|error| accounting_error(error, &accounting_refusal))
        },
        |authorized| {
            let entry = AuditEntry::new_mpp_charge_authorized(
                "stellar_mpp_charge_commit",
                context.chain_id.caip2_str(),
                hex::encode(Sha256::digest(
                    authorized.record.authorization_id().as_bytes(),
                )),
                hex::encode(authorized.record.fingerprint()),
                authorized
                    .value_effects
                    .legs()
                    .iter()
                    .map(ValueLegRecord::from)
                    .collect(),
                RedactedStrkey::from_full(authorized.payer),
                authorized.record.approval_nonce().is_some(),
                PolicyDecision::Allow,
                uuid::Uuid::new_v4().to_string(),
            );
            emit_value_audit_row_strict(
                profile,
                profile_name,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
                entry,
            )
            .map_err(|error| {
                if let Ok(mut slot) = delivery_refusal.lock() {
                    *slot = Some(error);
                }
                state_error()
            })
        },
        |withheld| {
            let entry = AuditEntry::new_mpp_authorization_withheld(
                hex::encode(Sha256::digest(
                    withheld.record.authorization_id().as_bytes(),
                )),
                hex::encode(withheld.record.fingerprint()),
                withheld.failure_stage,
                withheld.key_access_began,
                withheld.policy_budget_consumed,
                uuid::Uuid::new_v4().to_string(),
            );
            // The primary error is what the caller sees; a withheld row that
            // cannot be written is logged and does not replace it.
            if let Err(error) = emit_value_audit_row_strict(
                profile,
                profile_name,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
                entry,
            ) {
                tracing::error!(
                    event_kind = "mpp_authorization_withheld",
                    failure_stage = withheld.failure_stage,
                    code = %error.code(),
                    error = %error,
                    "mpp: the withheld-authorization audit row was not written"
                );
            }
        },
    )
    .await;
    match result {
        Ok(credential) => {
            print_success(json!({
                "authorization_id": record.authorization_id(),
                "credential": credential,
            }));
            0
        }
        Err(error) => match wallet_refusal.lock().ok().and_then(|mut slot| slot.take()) {
            Some(wallet_error) => render_wallet_error(&wallet_error),
            None => render_error(&error),
        },
    }
}

fn status(args: &MppStatusArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();
    let (profile, _context) = match load_testnet_profile(&resolved) {
        Ok(profile) => profile,
        Err(error) => return render_profile_error(&error, &profile_name),
    };
    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let state = match MppAuthorizationStore::open_for_read(
        &profile_name,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(Some(state)) => state,
        // A profile that has never prepared a charge holds no authorization
        // under any identifier — the store's own answer for an unknown one.
        Ok(None) => return render_error(&absent_state_lookup_error(&args.authorization_id)),
        Err(error) => return render_error(&error),
    };
    match authorization_status(&state, &args.authorization_id, now_unix()) {
        Ok(view) => {
            print_success(view);
            0
        }
        Err(error) => render_error(&error),
    }
}

fn record_receipt(args: &MppReceiptArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();
    let (profile, _context) = match load_testnet_profile(&resolved) {
        Ok(profile) => profile,
        Err(error) => return render_profile_error(&error, &profile_name),
    };
    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let bytes = match read_selected_input(
        args.receipt_stdin,
        args.receipt_file.as_deref(),
        MAX_INPUT_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return render_error(&error),
    };
    let input = match args.transport {
        ReceiptTransport::Http => match String::from_utf8(bytes) {
            Ok(value) => ReceiptInput::Http {
                value: value.trim().to_owned(),
            },
            Err(_) => return render_error(&receipt_error()),
        },
        ReceiptTransport::Mcp => match stellar_agent_mpp::json::parse_strict_json(&bytes) {
            Ok(receipt) => ReceiptInput::Mcp { receipt },
            Err(error) => return render_error(&error),
        },
    };
    let receipt = match parse_receipt(&input) {
        Ok(receipt) => receipt,
        Err(error) => return render_error(&error),
    };
    let state = match MppAuthorizationStore::open_for_read(
        &profile_name,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(Some(state)) => state,
        Ok(None) => return render_error(&absent_state_lookup_error(&args.authorization_id)),
        Err(error) => return render_error(&error),
    };
    let now = now_unix();
    let record = match state.record_receipt(&args.authorization_id, &receipt, now) {
        Ok(record) => record,
        Err(error) => return render_error(&error),
    };
    let entry = AuditEntry::new_mpp_receipt_observed(
        hex::encode(Sha256::digest(args.authorization_id.as_bytes())),
        hex::encode(receipt.digest()),
        redact_reference(receipt.reference()),
        match args.transport {
            ReceiptTransport::Http => "http",
            ReceiptTransport::Mcp => "mcp",
        },
        receipt.status(),
        uuid::Uuid::new_v4().to_string(),
    );
    if let Err(error) = emit_value_audit_row_strict(
        &profile,
        &profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
        entry,
    ) {
        return render_wallet_error(&error);
    }
    print_success(json!({
        "authorization_id": record.authorization_id(),
        "status": record.status(),
        "receipt_observed": true,
        "ledger_settlement": "unknown",
    }));
    0
}

async fn reconcile(args: MppReconcileArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();
    let (profile, context) = match load_testnet_profile(&resolved) {
        Ok(profile) => profile,
        Err(error) => return render_profile_error(&error, &profile_name),
    };

    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let reference =
        match read_selected_input(args.reference_stdin, args.reference_file.as_deref(), 128) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(value) => value.trim().to_owned(),
                Err(_) => return render_error(&reconciliation_error()),
            },
            Err(error) => return render_error(&error),
        };
    let state = match MppAuthorizationStore::open_for_read(
        &profile_name,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(Some(state)) => state,
        Ok(None) => return render_error(&absent_state_lookup_error(&args.authorization_id)),
        Err(error) => return render_error(&error),
    };
    let rpc = match StellarReconciliationRpc::new(&context.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return render_error(&error),
    };
    let result =
        match reconcile_transaction(&state, &args.authorization_id, &reference, now_unix(), &rpc)
            .await
        {
            Ok(result) => result,
            Err(error) => return render_error(&error),
        };
    let entry = AuditEntry::new_mpp_settlement_reconciled(
        hex::encode(Sha256::digest(args.authorization_id.as_bytes())),
        result.transaction_reference_redacted.clone(),
        result.ledger,
        result.outcome.clone(),
        uuid::Uuid::new_v4().to_string(),
    );
    if let Err(error) = emit_value_audit_row_strict(
        &profile,
        &profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
        entry,
    ) {
        return render_wallet_error(&error);
    }
    print_success(result);
    0
}

fn prune(args: &MppPruneArgs) -> i32 {
    let (profile, context) =
        match load_testnet_profile(&ResolvedProfileName::from_flag(&args.profile)) {
            Ok(profile) => profile,
            Err(error) => return render_profile_error(&error, &args.profile),
        };

    let reason = match read_selected_input(
        args.reason_stdin,
        args.reason_file.as_deref(),
        MAX_REASON_BYTES,
    ) {
        Ok(reason) if !reason.is_empty() => reason,
        _ => return render_error(&state_error()),
    };
    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let state = match MppAuthorizationStore::open_for_read(
        &args.profile,
        &profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(state) => state,
        Err(error) => return render_error(&error),
    };
    let reason_sha256 = hex::encode(Sha256::digest(&reason));
    let mut audit = NewToolInvocation::new(
        "stellar_mpp_state_prune",
        context.chain_id.caip2_str(),
        vec!["profile".to_owned(), "reason_sha256".to_owned()],
        PolicyDecision::Allow,
        uuid::Uuid::new_v4().to_string(),
    );
    audit.decision_reason = Some(format!("reason_sha256={reason_sha256}"));
    if let Err(error) = emit_value_audit_row_strict(
        &profile,
        &args.profile,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
        AuditEntry::new_tool_invocation(audit),
    ) {
        return render_wallet_error(&error);
    }
    // The maintenance request is recorded before the outcome is known, so the
    // audit trail carries the operator's reason whether or not there was
    // anything to prune. A profile with no MPP state prunes nothing, which is
    // the same result as pruning a store holding no removable record.
    let pruned = match state {
        Some(state) => match state.prune(now_unix()) {
            Ok(pruned) => pruned,
            Err(error) => return render_error(&error),
        },
        None => 0,
    };
    print_success(json!({
        "profile": args.profile,
        "pruned": pruned,
        "reason_sha256": reason_sha256,
    }));
    0
}

fn evaluate_policy(
    context: &NetworkContext,
    engine: &dyn PolicyEngine,
    profile: &Profile,
    tool_name: &'static str,
    effects: &stellar_agent_core::policy::v1::ValueEffects,
) -> Result<ApprovalDisposition, MppError> {
    let descriptor = policy_descriptor(context, tool_name);
    let evaluation = engine
        .evaluate_with_value_full(
            &descriptor,
            &json!({}),
            profile,
            ValueClass::Value(effects.clone()),
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|_| state_error())?;
    match evaluation.decision {
        Decision::Allow => Ok(ApprovalDisposition::Allow),
        Decision::RequireApproval(_) => Ok(ApprovalDisposition::RequireApproval),
        Decision::Deny(_) => Err(MppError::new(
            MppErrorCode::ApprovalInvalid,
            "MPP authorization was denied by operator policy",
        )),
        _ => Err(state_error()),
    }
}

fn policy_descriptor(context: &NetworkContext, tool_name: &'static str) -> ToolDescriptor {
    let registration = McpToolRegistration {
        name: tool_name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut descriptor = ToolDescriptor::from_registration(&registration);
    descriptor.chain_id = context.chain_id.caip2_str().to_owned();
    descriptor
}

/// Why MPP could not obtain a usable profile.
///
/// The profile step is the one place in this command where a failure is about
/// the operator's configuration rather than about MPP state, so it carries its
/// own cause instead of collapsing into `state_error()`. "The profile file is a
/// copy of another profile" and "MPP authorization state is unavailable" have
/// nothing in common and are not recoverable by the same action.
enum MppProfileError {
    /// The profile could not be loaded, or names a different profile.
    Access(ProfileAccessError),
    /// The profile loaded but does not target testnet.
    Network(MppError),
}

fn load_testnet_profile(
    resolved: &ResolvedProfileName,
) -> Result<(Profile, NetworkContext), MppProfileError> {
    let profile = load_profile_reconciled(resolved).map_err(MppProfileError::Access)?;
    let context = testnet_context(&profile)?;
    Ok((profile, context))
}

fn testnet_context(profile: &Profile) -> Result<NetworkContext, MppProfileError> {
    let context = NetworkContext::from_profile(profile);
    if context.chain_id != Caip2::Testnet {
        return Err(MppProfileError::Network(network_error()));
    }
    Ok(context)
}

/// Renders an [`MppProfileError`] and returns the CLI exit code.
///
/// The access arm keeps the profile subsystem's own wire code — including
/// `profile.name_mismatch` — so an agent can tell a mistyped or copied profile
/// apart from an MPP state failure.
fn render_profile_error(error: &MppProfileError, profile_name: &str) -> i32 {
    match error {
        MppProfileError::Access(e) => {
            print_json(&profile_access_envelope(e, profile_name));
            1
        }
        MppProfileError::Network(e) => render_error(e),
    }
}

fn approval_store(profile_name: &str) -> Result<PendingApprovalStore, MppError> {
    let root = default_approval_dir().map_err(|_| state_error())?;
    PendingApprovalStore::open(root.join(format!("{profile_name}.toml"))).map_err(|_| state_error())
}

fn read_authorize_input(args: &MppAuthorizeArgs) -> Result<ChallengeInput, MppError> {
    let bytes = read_selected_input(
        args.input_stdin,
        args.input_file.as_deref(),
        MAX_INPUT_BYTES,
    )?;
    let value = stellar_agent_mpp::json::parse_strict_json(&bytes)?;
    serde_json::from_value(value).map_err(|_| {
        MppError::new(
            MppErrorCode::ChallengeInvalid,
            "invalid tagged MPP challenge input",
        )
    })
}

fn read_selected_input(
    stdin_selected: bool,
    file: Option<&Path>,
    limit: usize,
) -> Result<Vec<u8>, MppError> {
    match (stdin_selected, file) {
        (true, None) => read_bounded(io::stdin().lock(), limit),
        (false, Some(path)) => read_regular_file(path, limit),
        _ => Err(MppError::new(
            MppErrorCode::ChallengeInvalid,
            "exactly one stdin or file input must be selected",
        )),
    }
}

fn read_regular_file(path: &Path, limit: usize) -> Result<Vec<u8>, MppError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| state_error())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || usize::try_from(metadata.len()).unwrap_or(usize::MAX) > limit
    {
        return Err(state_error());
    }
    read_bounded(fs::File::open(path).map_err(|_| state_error())?, limit)
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, MppError> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| state_error())?;
    if bytes.len() > limit {
        return Err(MppError::new(
            MppErrorCode::InputTooLarge,
            "MPP input exceeds the size limit",
        ));
    }
    Ok(bytes)
}

fn print_success(value: impl Serialize) {
    print_json(&Envelope::ok(value));
}

#[allow(clippy::print_stdout, reason = "CLI result channel")]
fn print_json(value: &impl Serialize) {
    println!(
        "{}",
        serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned())
    );
}

fn render_error(error: &MppError) -> i32 {
    print_json(&Envelope::<()>::err_raw(error.code(), error.message()));
    1
}

/// Loads the attestation key the MPP approval check verifies against.
///
/// A coordinate in the owner key namespace is refused before the read, and a
/// key equal to the owner public key of `profile` selected as `profile_name`
/// after decoding. The caller renders every failure as the uniform approval
/// refusal, so an owner refusal is logged here with its code.
fn load_mpp_attestation_key(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, WalletError> {
    use stellar_agent_core::approval::attest::ATTESTATION_KEY_FIELD;
    use stellar_agent_core::profile::owner_key;
    let log_owner_refusal = |e: WalletError| {
        if matches!(
            e,
            WalletError::Validation(
                stellar_agent_core::error::ValidationError::KeyMatchesOwnerPublicKey { .. }
            )
        ) {
            tracing::warn!(
                profile = %profile_name,
                code = %e.code(),
                "mpp: attestation key refused: it is or may be the owner public key"
            );
        }
        e
    };
    owner_key::refuse_owner_key_coordinate(&profile.attestation_key_id, ATTESTATION_KEY_FIELD)
        .map_err(log_owner_refusal)?;
    let key = load_hmac_key_32(&profile.attestation_key_id)?;
    owner_key::refuse_owner_public_key(
        key.as_ref(),
        &owner_key::OwnerKeyContext::for_profile(profile_name, profile),
        ATTESTATION_KEY_FIELD,
    )
    .map_err(log_owner_refusal)?;
    Ok(key)
}

/// Renders policy and audit refusals with their wallet code and diagnostic.
fn render_wallet_error(error: &WalletError) -> i32 {
    print_json(&crate::commands::submission_record::error_envelope(
        error,
        "",
        "mpp charge authorize",
    ));
    1
}

fn now_unix() -> i64 {
    stellar_agent_core::timefmt::now_unix_ms()
        .map(|ms| i64::try_from(ms / 1_000).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

fn redact_reference(value: &str) -> String {
    format!("{}...{}", &value[..8], &value[value.len() - 8..])
}

/// Retains a typed policy refusal across the service's MPP error boundary.
fn accounting_error(
    error: stellar_agent_network::policy_state::WindowStoreError,
    refusal: &Mutex<Option<WalletError>>,
) -> stellar_agent_mpp::BeforeSignError {
    if let stellar_agent_network::policy_state::WindowStoreError::PolicyDenied { reason } = error {
        if let Ok(mut slot) = refusal.lock() {
            *slot = Some(WalletError::PolicyDenied { reason });
        }
        stellar_agent_mpp::BeforeSignError::PolicyRefused(state_error())
    } else {
        stellar_agent_mpp::BeforeSignError::Accounting(state_error())
    }
}

/// The uniform state refusal.
///
/// Byte-identical to `stellar_agent_mpp::store`'s definition and to
/// `stellar-agent-mcp`'s MPP adapter: the three exist because this code is
/// raised on paths that hold no store handle, and one refusal must not be
/// distinguishable from another by its text.
const fn state_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state is unavailable",
    )
}

const fn network_error() -> MppError {
    MppError::new(
        MppErrorCode::NetworkForbidden,
        "MPP charge is enabled only on Stellar testnet",
    )
}

const fn approval_error() -> MppError {
    MppError::new(
        MppErrorCode::ApprovalInvalid,
        "MPP approval is missing, invalid, or expired",
    )
}

const fn signing_error() -> MppError {
    MppError::new(
        MppErrorCode::SigningFailed,
        "sponsored authorization signing failed",
    )
}

const fn receipt_error() -> MppError {
    MppError::new(MppErrorCode::ReceiptInvalid, "invalid MPP receipt")
}

const fn reconciliation_error() -> MppError {
    MppError::new(
        MppErrorCode::ReconciliationUnavailable,
        "ledger reconciliation could not verify the MPP transaction",
    )
}

impl MppArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`] falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    ///
    /// `mpp state prune` takes a required `--profile`, so its arm is always
    /// `Some`.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.command {
            MppCommand::Charge(g) => match &g.command {
                MppChargeCommand::Authorize(a) => a.profile.as_deref(),
            },
            MppCommand::Authorization(g) => match &g.command {
                MppAuthorizationCommand::Status(a) => a.profile.as_deref(),
            },
            MppCommand::Receipt(g) => match &g.command {
                MppReceiptCommand::Record(a) => a.profile.as_deref(),
            },
            MppCommand::Settlement(g) => match &g.command {
                MppSettlementCommand::Reconcile(a) => a.profile.as_deref(),
            },
            MppCommand::State(g) => match &g.command {
                MppStateCommand::Prune(a) => Some(a.profile.as_str()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures use expect for concise setup"
    )]

    use clap::Parser;
    use tempfile::TempDir;

    use super::*;

    fn put_raw(entry_ref: &stellar_agent_core::profile::schema::KeyringEntryRef, value: &str) {
        keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
            .expect("entry")
            .set_password(value)
            .expect("plant");
    }

    /// The attestation key loader of `mpp charge` refuses a key equal to the
    /// owner public key in the older form and logs the code at `warn`; the
    /// caller renders the uniform approval refusal. A G-strkey owner value and
    /// an owner-namespace coordinate refuse too. The raw value is never
    /// logged.
    #[test]
    #[serial_test::serial]
    fn the_attestation_loader_refuses_owner_key_forms() {
        use base64::Engine as _;
        use stellar_agent_core::profile::schema::KeyringEntryRef;
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let name = "mpp-attest-owner";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        let older_form = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x4f_u8; 32]);
        put_raw(&profile.attestation_key_id, &older_form);
        assert!(load_mpp_attestation_key(&profile, name).is_ok());

        put_raw(&KeyringEntryRef::default_owner_key(name), &older_form);
        let mut refused = None;
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            refused = load_mpp_attestation_key(&profile, name).err();
        });
        let err = refused.expect("the owner key refuses");
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(!logs.contains(&older_form), "the raw value is never logged");
        assert!(logs.contains("WARN"), "{logs}");
        assert!(
            logs.contains("validation.key_matches_owner_public_key"),
            "{logs}"
        );

        put_raw(
            &profile.attestation_key_id,
            &stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x4f; 32]),
        );
        let Err(err) = load_mpp_attestation_key(&profile, name) else {
            panic!("a G-strkey refuses");
        };
        assert!(err.to_string().contains("got 42"), "{err}");

        profile.attestation_key_id = KeyringEntryRef::new("stellar-agent-owner-B", "default");
        let Err(err) = load_mpp_attestation_key(&profile, name) else {
            panic!("an owner coordinate refuses");
        };
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
    }

    #[test]
    fn testnet_context_derives_the_canonical_passphrase() {
        let mut profile = Profile::builder_testnet_named("context", "s", "a", "n", "a")
            .with_noop_engine()
            .build();
        profile.network_passphrase = "not the passphrase".to_owned();
        let context = testnet_context(&profile).ok().expect("testnet context");
        assert_eq!(
            context.network_passphrase(),
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE
        );
    }

    #[test]
    fn testnet_context_refuses_mainnet_with_network_error() {
        let profile = Profile::builder_mainnet_named(
            "context",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .with_noop_engine()
        .build();
        assert!(matches!(
            testnet_context(&profile),
            Err(MppProfileError::Network(error)) if error.code() == network_error().code()
        ));
    }

    #[test]
    fn accounting_denial_preserves_the_policy_code() {
        let reason = stellar_agent_core::policy::DenyReason::RateLimitExceeded {
            window: "1m".to_owned(),
            max_calls: 1,
            calls_in_window: 1,
        };
        let refusal = Mutex::new(None);
        let classified = accounting_error(
            stellar_agent_network::policy_state::WindowStoreError::PolicyDenied {
                reason: Box::new(reason),
            },
            &refusal,
        );
        assert!(matches!(
            classified,
            stellar_agent_mpp::BeforeSignError::PolicyRefused(_)
        ));
        let error = refusal
            .lock()
            .expect("refusal lock")
            .take()
            .expect("typed policy refusal");
        assert_eq!(error.code(), "policy.deny.rate_limit_exceeded");
        let failure = accounting_error(
            stellar_agent_network::policy_state::WindowStoreError::Io {
                kind: std::io::ErrorKind::Other,
            },
            &refusal,
        );
        assert!(matches!(
            failure,
            stellar_agent_mpp::BeforeSignError::Accounting(_)
        ));
        assert!(refusal.lock().expect("refusal lock").is_none());
    }

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        mpp: MppArgs,
    }

    #[test]
    fn parses_hyphen_prefixed_approval_id() {
        let nonce = "-AbCdEfGhIjKlMnOpQrStU";
        let parsed =
            Harness::try_parse_from(["mpp", "charge", "authorize", "--approval-id", nonce])
                .expect("hyphen-prefixed approval id parses");
        let MppCommand::Charge(charge) = parsed.mpp.command else {
            unreachable!("expected charge");
        };
        let MppChargeCommand::Authorize(args) = charge.command;
        assert_eq!(args.approval_id.as_deref(), Some(nonce));

        let parsed = Harness::try_parse_from([
            "mpp",
            "charge",
            "authorize",
            "--approval-id",
            "--input-stdin",
        ])
        .expect("the next token is the approval id");
        let MppCommand::Charge(charge) = parsed.mpp.command else {
            unreachable!("expected charge");
        };
        let MppChargeCommand::Authorize(args) = charge.command;
        assert_eq!(args.approval_id.as_deref(), Some("--input-stdin"));
        assert!(!args.input_stdin);
    }

    #[test]
    fn command_tree_parses_every_public_operation() {
        for args in [
            vec!["mpp", "charge", "authorize", "--input-stdin"],
            vec![
                "mpp",
                "charge",
                "authorize",
                "--approval-id",
                "AAAAAAAAAAAAAAAAAAAAAA",
            ],
            vec![
                "mpp",
                "authorization",
                "status",
                "--authorization-id",
                "mpp_00000000000000000000000000000000",
            ],
            vec![
                "mpp",
                "receipt",
                "record",
                "--authorization-id",
                "mpp_00000000000000000000000000000000",
                "--transport",
                "mcp",
                "--receipt-stdin",
            ],
            vec![
                "mpp",
                "settlement",
                "reconcile",
                "--authorization-id",
                "mpp_00000000000000000000000000000000",
                "--reference-stdin",
            ],
            vec![
                "mpp",
                "state",
                "prune",
                "--profile",
                "default",
                "--reason-stdin",
            ],
        ] {
            Harness::try_parse_from(args).expect("command must parse");
        }
    }

    #[test]
    fn authorize_requires_exactly_one_source() {
        assert!(Harness::try_parse_from(["mpp", "charge", "authorize"]).is_err());
        assert!(
            Harness::try_parse_from([
                "mpp",
                "charge",
                "authorize",
                "--input-stdin",
                "--input-file",
                "challenge.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn bounded_file_reader_accepts_regular_file_and_rejects_oversize() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("input.json");
        fs::write(&path, b"{}").expect("write fixture");
        assert_eq!(read_regular_file(&path, 2).expect("bounded read"), b"{}");
        assert_eq!(
            read_regular_file(&path, 1).expect_err("oversize").code(),
            "mpp.state_unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("tempdir");
        let target = directory.path().join("target.json");
        let link = directory.path().join("link.json");
        fs::write(&target, b"{}").expect("write fixture");
        symlink(&target, &link).expect("symlink");
        assert!(read_regular_file(&link, 2).is_err());
    }

    // ── Sponsored commit: withheld stages and the queued consent row ─────────

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use stellar_xdr::{
        AccountId, HostFunction, Limits, OperationBody, PublicKey as XdrPublicKey, ReadXdr,
        ScAddress, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
        TransactionEnvelope, Uint256, VecM, WriteXdr,
    };

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
    const RECIPIENT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const TRANSACTION_DATA: &str = "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw==";
    const SIGNER_SERVICE: &str = "cli-mpp-stage-svc";

    /// Simulate endpoint for the sponsored charge: the unsigned simulate is
    /// answered with the payer's authorization entry, the signed one by
    /// `on_signed` and then, unless `fail_signed`, with no entries.
    struct Simulate {
        payer: ScAddress,
        fail_signed: bool,
        on_signed: Option<Arc<dyn Fn() + Send + Sync>>,
        signed: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl wiremock::Respond for Simulate {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("JSON-RPC body");
            let id = body["id"].clone();
            let envelope = TransactionEnvelope::from_xdr_base64(
                body["params"]["transaction"].as_str().expect("envelope"),
                Limits::none(),
            )
            .expect("decodable envelope");
            let TransactionEnvelope::Tx(transaction) = envelope else {
                unreachable!("v1 envelope");
            };
            let OperationBody::InvokeHostFunction(host) = transaction.tx.operations[0].body.clone()
            else {
                unreachable!("invoke host function");
            };
            let HostFunction::InvokeContract(invoke) = host.host_function else {
                unreachable!("contract invocation");
            };
            let auth = if host.auth.is_empty() {
                vec![
                    SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: self.payer.clone(),
                            nonce: 7,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke),
                            sub_invocations: VecM::default(),
                        },
                    }
                    .to_xdr_base64(Limits::none())
                    .expect("entry encodes"),
                ]
            } else {
                self.signed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(hook) = &self.on_signed {
                    hook();
                }
                if self.fail_signed {
                    return wiremock::ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {"error": "re-simulation trapped", "latestLedger": 1000},
                    }));
                }
                Vec::new()
            };
            wiremock::ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "transactionData": TRANSACTION_DATA,
                    "minResourceFee": "1000",
                    "results": [{
                        "auth": auth,
                        "xdr": ScVal::Void.to_xdr_base64(Limits::none()).expect("void"),
                    }],
                    "latestLedger": 1000,
                },
            }))
        }
    }

    fn g_strkey(seed: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
        .to_string()
        .to_string()
    }

    fn payer_address(payer: &str) -> ScAddress {
        let key = stellar_strkey::ed25519::PublicKey::from_string(payer).expect("G-strkey");
        ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(Uint256(
            key.0,
        ))))
    }

    fn sponsored_challenge(round: u8) -> ChallengeInput {
        let request = json!({
            "amount": "10000000",
            "currency": CONTRACT,
            "methodDetails": {"feePayer": true, "network": "stellar:testnet"},
            "recipient": RECIPIENT,
        });
        let encoded = URL_SAFE_NO_PAD
            .encode(stellar_agent_mpp::json::canonical_json(&request).expect("canonical request"));
        ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=\"cli-challenge-{round}\", realm=\"merchant.example\", \
                 method=\"stellar\", intent=\"charge\", request={encoded}"
            )],
            selected_challenge_id: None,
            context: stellar_agent_mpp::HttpRequestContext::new(
                "https://merchant.example",
                "POST",
                &format!("https://merchant.example/cli/{round}"),
                None,
                None,
            )
            .expect("request context"),
        }
    }

    /// A testnet profile for `name` with an audit key and its log in `dir`.
    fn stage_profile(name: &str, payer: &str, dir: &Path, rpc_url: &str) -> Profile {
        let mut profile =
            Profile::builder_testnet_named(name, SIGNER_SERVICE, payer, "n-svc", "n-acct")
                .with_noop_engine()
                .build();
        profile.rpc_url = rpc_url.to_owned();
        profile.audit_log_path = dir.join("audit").join(format!("{name}.jsonl"));
        let coord = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coord.service, &coord.account)
            .expect("Entry::new")
            .set_password(&URL_SAFE_NO_PAD.encode([0x29_u8; 32]))
            .expect("seed audit key");
        profile
    }

    /// Prepares one sponsored charge for `profile` and returns its stored
    /// record, with an approval pending when `approvals` is supplied.
    async fn prepare_charge(
        profile: &Profile,
        name: &str,
        round: u8,
        approvals: Option<&mut PendingApprovalStore>,
    ) -> (
        MppAuthorizationStore,
        stellar_agent_mpp::AuthorizationRecord,
    ) {
        let now = now_unix();
        let selected = select_and_validate(&sponsored_challenge(round), now).expect("challenge");
        let rpc = StellarSponsoredRpc::new(&profile.rpc_url).expect("RPC");
        let prepared = prepare_sponsored(
            selected,
            &profile.mcp_signer_default.account,
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            &rpc,
        )
        .await
        .expect("prepare");
        let state = MppAuthorizationStore::open_for_prepare(
            name,
            profile,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .expect("state");
        let disposition = if approvals.is_some() {
            ApprovalDisposition::RequireApproval
        } else {
            ApprovalDisposition::Allow
        };
        let preview = persist_prepared_authorization(
            name,
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            &prepared,
            disposition,
            &process_uid_for_attestation().expect("uid"),
            now,
            &state,
            approvals,
        )
        .expect("persist");
        let record = state.load(&preview.authorization_id).expect("record");
        (state, record)
    }

    fn log_rows(profile: &Profile) -> Vec<serde_json::Value> {
        fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("JSON row"))
            .collect()
    }

    fn withheld(profile: &Profile) -> serde_json::Value {
        let rows = log_rows(profile);
        let withheld: Vec<_> = rows
            .iter()
            .filter(|row| row["kind"] == "mpp_authorization_withheld")
            .collect();
        assert_eq!(withheld.len(), 1, "one withheld row: {rows:?}");
        withheld[0].clone()
    }

    struct StageCase {
        _home: TempDir,
        _guard: stellar_agent_test_support::StellarAgentHomeGuard,
        _mock: wiremock::MockServer,
        profile: Profile,
        signed: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn stage_case(
        name: &str,
        seed: [u8; 32],
        seed_secret: bool,
        configure: impl FnOnce(&mut Simulate, &Path),
    ) -> StageCase {
        let home = TempDir::new().expect("home");
        let guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring");
        let payer = g_strkey(seed);
        if seed_secret {
            keyring_core::Entry::new(SIGNER_SERVICE, &payer)
                .expect("Entry::new")
                .set_password(
                    stellar_strkey::ed25519::PrivateKey(seed)
                        .as_unredacted()
                        .to_string()
                        .as_str(),
                )
                .expect("seed signer");
        }
        let mut simulate = Simulate {
            payer: payer_address(&payer),
            fail_signed: false,
            on_signed: None,
            signed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let log_dir = home.path().join("audit");
        configure(&mut simulate, &log_dir.join(format!("{name}.jsonl")));
        let signed = Arc::clone(&simulate.signed);
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(simulate)
            .mount(&mock)
            .await;
        let profile = stage_profile(name, &payer, home.path(), &mock.uri());
        StageCase {
            _home: home,
            _guard: guard,
            _mock: mock,
            profile,
            signed,
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cli_commit_failure_at_the_sign_call_records_signing() {
        let case = stage_case("cli-stage-signing", [0x61; 32], false, |_, _| {}).await;
        let (state, record) = prepare_charge(&case.profile, "cli-stage-signing", 1, None).await;
        let context = testnet_context(&case.profile).ok().expect("context");
        let code = commit_cli(
            &context,
            "cli-stage-signing",
            &case.profile,
            &state,
            &record,
            now_unix(),
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(case.signed.load(std::sync::atomic::Ordering::SeqCst), 0);
        let row = withheld(&case.profile);
        assert_eq!(row["failure_stage"], "signing");
        assert_eq!(row["key_access_began"], true);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cli_commit_failure_at_the_send_records_resimulation() {
        let case = stage_case("cli-stage-resim", [0x62; 32], true, |simulate, _| {
            simulate.fail_signed = true;
        })
        .await;
        let (state, record) = prepare_charge(&case.profile, "cli-stage-resim", 2, None).await;
        let context = testnet_context(&case.profile).ok().expect("context");
        let code = commit_cli(
            &context,
            "cli-stage-resim",
            &case.profile,
            &state,
            &record,
            now_unix(),
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(case.signed.load(std::sync::atomic::Ordering::SeqCst), 1);
        let row = withheld(&case.profile);
        assert_eq!(row["failure_stage"], "resimulation");
        assert_eq!(row["key_access_began"], true);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cli_commit_failure_before_the_sign_call_records_pre_signing() {
        let case = stage_case("cli-stage-pre", [0x63; 32], true, |_, _| {}).await;
        let (state, record) = prepare_charge(&case.profile, "cli-stage-pre", 3, None).await;
        // The same profile with another signer: the payer check refuses before
        // the sign call.
        let mut other = case.profile.clone();
        other.mcp_signer_default.account = g_strkey([0x64; 32]);
        let context = testnet_context(&other).ok().expect("context");
        let code = commit_cli(
            &context,
            "cli-stage-pre",
            &other,
            &state,
            &record,
            now_unix(),
        )
        .await;
        assert_eq!(code, 1);
        assert_eq!(case.signed.load(std::sync::atomic::Ordering::SeqCst), 0);
        let row = withheld(&case.profile);
        assert_eq!(row["failure_stage"], "pre_signing");
        assert_eq!(row["key_access_began"], false);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cli_withheld_row_write_failure_is_logged_and_the_primary_error_returned() {
        use stellar_agent_test_support::CaptureWriter;

        let case = stage_case("cli-stage-logged", [0x65; 32], true, |simulate, log| {
            let log = log.to_path_buf();
            simulate.fail_signed = true;
            simulate.on_signed = Some(Arc::new(move || {
                fs::write(&log, b"").expect("roll the audit log back");
            }));
        })
        .await;
        // A non-empty, anchored log, so the rollback is a mismatch.
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &case.profile,
            "cli-stage-logged",
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .expect("audit access");
        stellar_agent_core::audit_log::AuditWriterRegistry::get_or_open_keyed(
            "cli-stage-logged",
            &case.profile.audit_log_path,
            access,
        )
        .expect("writer")
        .lock()
        .expect("lock")
        .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "test",
            "stellar:testnet",
            vec![],
            PolicyDecision::Allow,
            "anchor-row",
        )))
        .expect("anchor row");
        let (state, record) = prepare_charge(&case.profile, "cli-stage-logged", 4, None).await;
        let context = testnet_context(&case.profile).ok().expect("context");

        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let code = commit_cli(
            &context,
            "cli-stage-logged",
            &case.profile,
            &state,
            &record,
            now_unix(),
        )
        .await;
        drop(guard);

        assert_eq!(code, 1, "the primary error is returned");
        let logs = capture.captured_str();
        let line = logs
            .lines()
            .find(|line| line.contains("mpp_authorization_withheld"))
            .unwrap_or_else(|| unreachable!("the refused withheld row is logged: {logs}"));
        assert!(line.contains("ERROR"), "{line}");
        assert!(line.contains("audit.tip_anchor_mismatch"), "{line}");
        assert!(line.contains("resimulation"), "{line}");
    }

    /// A consent row queued while this process held the writer is in the log
    /// when the signed entry reaches the RPC.
    #[tokio::test]
    #[serial_test::serial]
    async fn cli_commit_drains_a_queued_consent_row_before_the_signed_resimulation() {
        use stellar_agent_core::approval::{
            AttestationBinding, ConsentAudit, Surface, attest_and_persist,
        };
        use stellar_agent_core::audit_log::{AuditOutbox, AuditWriterRegistry};

        const NAME: &str = "cli-consent-drain";
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_handler = Arc::clone(&seen);
        let case = stage_case(NAME, [0x66; 32], true, |simulate, log| {
            let log = log.to_path_buf();
            simulate.on_signed = Some(Arc::new(move || {
                seen_in_handler.lock().expect("seen").push(
                    fs::read_to_string(&log)
                        .unwrap_or_default()
                        .contains(r#""kind":"approval_attested""#),
                );
            }));
        })
        .await;
        let attestation_key = [0x4b_u8; 32];
        keyring_core::Entry::new(
            &case.profile.attestation_key_id.service,
            &case.profile.attestation_key_id.account,
        )
        .expect("Entry::new")
        .set_password(&URL_SAFE_NO_PAD.encode(attestation_key))
        .expect("seed attestation key");
        let mut approvals = approval_store(NAME).expect("approval store");
        let (state, record) = prepare_charge(&case.profile, NAME, 5, Some(&mut approvals)).await;
        let nonce = record
            .approval_nonce()
            .expect("approval required")
            .to_owned();

        // An earlier keyed call caches the writer in this process.
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &case.profile,
            NAME,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .expect("access");
        let _cached =
            AuditWriterRegistry::get_or_open_keyed(NAME, &case.profile.audit_log_path, access)
                .expect("writer cached");

        // `approve --id` beside this process: queue the row, then persist.
        let entry = approvals.get(&nonce).expect("pending entry").clone();
        let outbox = AuditOutbox::for_log(&case.profile.audit_log_path);
        attest_and_persist(
            &mut approvals,
            &entry,
            &attestation_key,
            &AttestationBinding::new(NAME, "stellar:testnet"),
            Surface::Cli,
            ConsentAudit::Outbox(&outbox),
            None,
            |_, _| Err("no grant".to_owned()),
        )
        .expect("approve");
        drop(approvals);

        let context = testnet_context(&case.profile).ok().expect("context");
        let code = commit_cli(&context, NAME, &case.profile, &state, &record, now_unix()).await;
        assert_eq!(code, 0, "the commit succeeds");
        assert_eq!(
            *seen.lock().expect("seen"),
            vec![true],
            "the consent row must be in the log when the signed entry reaches the RPC"
        );
    }
}
