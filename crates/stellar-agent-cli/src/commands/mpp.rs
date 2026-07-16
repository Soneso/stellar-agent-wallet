//! Testnet-only sponsored MPP charge CLI.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::{
    approval::{store::PendingApprovalStore, user_id::process_uid_for_attestation},
    audit_log::{AuditEntry, NewToolInvocation, PolicyDecision, ValueLegRecord},
    envelope::Envelope,
    observability::RedactedStrkey,
    policy::v1::ValueClass,
    policy::{Decision, McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind},
    profile::{caip2::TESTNET_PASSPHRASE, loader, schema::default_approval_dir},
};
use stellar_agent_mpp::{
    ApprovalDisposition, ChallengeInput, MppAuthorizationStore, MppError, MppErrorCode,
    ReceiptInput, StellarReconciliationRpc, StellarSponsoredRpc, authorization_status,
    commit_authorization, mpp_value_effects, parse_receipt, persist_prepared_authorization,
    prepare_sponsored, reconcile_transaction, select_and_validate, verify_pending_approval,
};
use stellar_agent_network::{
    init_platform_keyring_store,
    keyring::{lazy_signer_from_keyring, load_hmac_key_32},
};

use crate::commands::{
    policy_engine::build_v1_policy_engine, value_audit::emit_value_audit_row_strict,
};

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
    /// Wallet profile.
    #[arg(long, default_value = "default")]
    profile: String,
    /// Read a tagged ChallengeInput JSON object from stdin.
    #[arg(long, conflicts_with_all = ["input_file", "approval_id"])]
    input_stdin: bool,
    /// Read a tagged ChallengeInput JSON object from a bounded regular file.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["input_stdin", "approval_id"])]
    input_file: Option<PathBuf>,
    /// Resume only the exact stored authorization attached to this approval.
    #[arg(long, value_name = "ID", conflicts_with_all = ["input_stdin", "input_file"])]
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
    #[arg(long, default_value = "default")]
    profile: String,
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
    #[arg(long, default_value = "default")]
    profile: String,
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
    #[arg(long, default_value = "default")]
    profile: String,
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
    let profile = match load_testnet_profile(&args.profile) {
        Ok(profile) => profile,
        Err(error) => return render_error(&error),
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
        let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, false) {
            Ok(state) => state,
            Err(error) => return render_error(&error),
        };
        let record = match state.load_by_approval_nonce(approval_id) {
            Ok(record) => record,
            Err(error) => return render_error(&error),
        };
        return commit_cli(&args.profile, &profile, &state, &record, now_unix).await;
    }
    // First-use key material is created only after validation and successful simulation.
    prepare_and_authorize_without_state(args, profile, now_unix).await
}

async fn prepare_and_authorize_without_state(
    args: MppAuthorizeArgs,
    profile: stellar_agent_core::profile::schema::Profile,
    now_unix: i64,
) -> i32 {
    let input = match read_authorize_input(&args) {
        Ok(input) => input,
        Err(error) => return render_error(&error),
    };
    let selected = match select_and_validate(&input, now_unix) {
        Ok(selected) => selected,
        Err(error) => return render_error(&error),
    };
    let rpc = match StellarSponsoredRpc::new(&profile.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return render_error(&error),
    };
    let prepared = match prepare_sponsored(
        selected,
        &profile.mcp_signer_default.account,
        &profile.network_passphrase,
        &rpc,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => return render_error(&error),
    };
    let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, true) {
        Ok(state) => state,
        Err(error) => return render_error(&error),
    };
    persist_and_maybe_commit(&args.profile, &profile, &state, prepared, now_unix).await
}

async fn persist_and_maybe_commit(
    profile_name: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
    state: &MppAuthorizationStore,
    prepared: stellar_agent_mpp::PreparedSponsoredCharge,
    now_unix: i64,
) -> i32 {
    let engine = match build_v1_policy_engine("mpp charge", &profile.policy.engine, profile) {
        Ok(engine) => engine,
        Err(_) => return render_error(&state_error()),
    };
    let disposition = match evaluate_policy(
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
        &profile.network_passphrase,
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
    commit_cli(profile_name, profile, state, &record, now_unix).await
}

async fn commit_cli(
    profile_name: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
    state: &MppAuthorizationStore,
    record: &stellar_agent_mpp::AuthorizationRecord,
    now_unix: i64,
) -> i32 {
    let engine = match build_v1_policy_engine("mpp charge", &profile.policy.engine, profile) {
        Ok(engine) => engine,
        Err(_) => return render_error(&state_error()),
    };
    let prepared = match record.prepared_charge() {
        Ok(prepared) => prepared,
        Err(error) => return render_error(&error),
    };
    let disposition = match evaluate_policy(
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
        approval_key = match load_hmac_key_32(&profile.attestation_key_id) {
            Ok(key) => Some(key),
            Err(_) => return render_error(&approval_error()),
        };
    }
    if let Err(error) = verify_pending_approval(
        state,
        approvals.as_ref(),
        approval_key.as_deref(),
        record.authorization_id(),
        now_unix,
    ) {
        return render_error(&error);
    }
    let signer = match lazy_signer_from_keyring(
        &profile.mcp_signer_default,
        &profile.mcp_signer_default.account,
    ) {
        Ok(signer) => signer,
        Err(_) => return render_error(&signing_error()),
    };
    let rpc = match StellarSponsoredRpc::new(&profile.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return render_error(&error),
    };
    let descriptor = policy_descriptor("stellar_mpp_charge_commit");
    let result = commit_authorization(
        state,
        approvals.as_ref(),
        approval_key.as_deref(),
        record.authorization_id(),
        now_unix,
        &profile.network_passphrase,
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
            .map_err(|_| state_error())
        },
        |authorized| {
            let entry = AuditEntry::new_mpp_charge_authorized(
                "stellar_mpp_charge_commit",
                "stellar:testnet",
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
            emit_value_audit_row_strict(profile, profile_name, entry).map_err(|()| state_error())
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
            let _ = emit_value_audit_row_strict(profile, profile_name, entry);
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
        Err(error) => render_error(&error),
    }
}

fn status(args: &MppStatusArgs) -> i32 {
    if let Err(error) = load_testnet_profile(&args.profile) {
        return render_error(&error);
    }
    if init_platform_keyring_store().is_err() {
        return render_error(&state_error());
    }
    let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, false) {
        Ok(state) => state,
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
    let profile = match load_testnet_profile(&args.profile) {
        Ok(profile) => profile,
        Err(error) => return render_error(&error),
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
    let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, false) {
        Ok(state) => state,
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
    if emit_value_audit_row_strict(&profile, &args.profile, entry).is_err() {
        return render_error(&state_error());
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
    let profile = match load_testnet_profile(&args.profile) {
        Ok(profile) => profile,
        Err(error) => return render_error(&error),
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
    let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, false) {
        Ok(state) => state,
        Err(error) => return render_error(&error),
    };
    let rpc = match StellarReconciliationRpc::new(&profile.rpc_url) {
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
    if emit_value_audit_row_strict(&profile, &args.profile, entry).is_err() {
        return render_error(&state_error());
    }
    print_success(result);
    0
}

fn prune(args: &MppPruneArgs) -> i32 {
    let profile = match load_testnet_profile(&args.profile) {
        Ok(profile) => profile,
        Err(error) => return render_error(&error),
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
    let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, false) {
        Ok(state) => state,
        Err(error) => return render_error(&error),
    };
    let reason_sha256 = hex::encode(Sha256::digest(&reason));
    let mut audit = NewToolInvocation::new(
        "stellar_mpp_state_prune",
        "stellar:testnet",
        vec!["profile".to_owned(), "reason_sha256".to_owned()],
        PolicyDecision::Allow,
        uuid::Uuid::new_v4().to_string(),
    );
    audit.decision_reason = Some(format!("reason_sha256={reason_sha256}"));
    if emit_value_audit_row_strict(
        &profile,
        &args.profile,
        AuditEntry::new_tool_invocation(audit),
    )
    .is_err()
    {
        return render_error(&state_error());
    }
    match state.prune(now_unix()) {
        Ok(pruned) => {
            print_success(json!({
                "profile": args.profile,
                "pruned": pruned,
                "reason_sha256": reason_sha256,
            }));
            0
        }
        Err(error) => render_error(&error),
    }
}

fn evaluate_policy(
    engine: &dyn PolicyEngine,
    profile: &stellar_agent_core::profile::schema::Profile,
    tool_name: &'static str,
    effects: &stellar_agent_core::policy::v1::ValueEffects,
) -> Result<ApprovalDisposition, MppError> {
    let descriptor = policy_descriptor(tool_name);
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

fn policy_descriptor(tool_name: &'static str) -> ToolDescriptor {
    let registration = McpToolRegistration {
        name: tool_name,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut descriptor = ToolDescriptor::from_registration(&registration);
    descriptor.chain_id = "stellar:testnet".to_owned();
    descriptor
}

fn load_testnet_profile(
    profile_name: &str,
) -> Result<stellar_agent_core::profile::schema::Profile, MppError> {
    let profile = loader::load(profile_name, None).map_err(|_| state_error())?;
    if profile.network_passphrase != TESTNET_PASSPHRASE {
        return Err(network_error());
    }
    Ok(profile)
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

fn now_unix() -> i64 {
    stellar_agent_core::timefmt::now_unix_ms()
        .map(|ms| i64::try_from(ms / 1_000).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

fn redact_reference(value: &str) -> String {
    format!("{}...{}", &value[..8], &value[value.len() - 8..])
}

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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use clap::Parser;
    use tempfile::TempDir;

    use super::*;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        mpp: MppArgs,
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
}
