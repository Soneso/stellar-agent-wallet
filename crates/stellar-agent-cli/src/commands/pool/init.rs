//! Sponsored channel creation with a durable seed and public recovery checkpoints.
//!
//! The profile records channel identities before the keyring seed is written.
//! The seed is durable before the submission can leave. A pending lifecycle
//! excludes replacement; `pool init --resume` completes it using the same keys.
//! A sent attempt is retried only after an operator acknowledges it through
//! `tx receipt clear --acknowledge`, whose clear row the verified audit
//! history holds. An endpoint failure report is not that acknowledgement.
//! An unsent attempt, proved by the durable send barrier, is retired with one
//! `submission.not_transmitted` row when its pending row is still open.
//! Only the pool keys in the stored profile are patched, so runtime environment
//! overlays remain transient. The profile contains no signing material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use std::{fs::OpenOptions, path::Path, sync::Mutex, time::Duration};
use stellar_agent_core::audit_log::{
    entry::AuditEntry,
    reader::{AuditReader, audit_history_refusal},
};
use stellar_agent_core::cross_check::CrossCheckValue;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::FeeSource;
use stellar_agent_core::error::{
    AuthError, InternalError, NetworkError, SubmissionError, WalletError,
};
use stellar_agent_core::file_lock::HeldFileLock;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PoolChannelRecord, PoolConfig, PoolInitSubmission, PoolInitialization, Profile,
};
use stellar_agent_core::profile::{
    loader,
    receipt::{ReceiptStatus, ReceiptStore},
};
use stellar_agent_network::NetworkContext;
use stellar_agent_network::cross_check::{
    AccountObservation, CrossCheckView, PoolInitWitnessInputs, obtain_classic_witness,
};
use stellar_agent_network::fees::check_classic_fee_cap;
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, fetch_account,
    keyring::{KeyringOperation, enrolled_keyring_signer},
};
use stellar_agent_pool::{
    PoolError,
    derive::{derive_channel_signer, load_pool_master_seed_from_keyring},
    init::{InitParams, init_pool, total_init_fee},
};
use stellar_agent_sep5::Sep5Wallet;
use zeroize::Zeroizing;

use crate::commands::submission_record::{SubmitRecord, build_recorder};
use crate::common::network::{check_endpoint_identity, mainnet_write_refusal};
use crate::common::profile_access::load_profile_reconciled;
use crate::common::{render::render_json, resolve_profile_name};

/// Default deadline for the endpoint check and for confirming the creation
/// transaction, in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

/// Arguments for sponsored pool creation and recovery.
#[derive(Debug, Args)]
pub struct PoolInitArgs {
    /// Number of channels to create (1..=19).
    #[arg(
        long,
        value_name = "N",
        required_unless_present = "resume",
        conflicts_with = "resume"
    )]
    pub size: Option<usize>,
    /// Profile whose funder and pool seed are used.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Replace a completed pool; its funded channels lose their signing seed.
    /// A pending initialization must be resumed before replacement.
    #[arg(long, conflicts_with = "resume")]
    pub force: bool,
    /// Complete an interrupted initialization using its persisted seed.
    #[arg(long)]
    pub resume: bool,
    /// Deadline in seconds for the endpoint check and, separately, for
    /// confirming the creation transaction.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
    /// Output format.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Completed sponsored pool creation. Secret material is never returned.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct PoolInitResult {
    /// Profile containing the completed pool.
    pub profile: String,
    /// Number of channels in the pool.
    pub channel_count: usize,
    /// Recorded transaction hash, redacted for display when available.
    pub tx_hash_redacted: Option<String>,
    /// Ledger establishing that the channels exist.
    pub ledger: u32,
    /// Public channel identities and derivation indices.
    pub channels: Vec<PoolChannelRecord>,
    /// Redacted sponsor identity.
    pub funder_redacted: String,
    /// Keyring service containing the pool seed.
    pub pool_master_keyring_service: String,
    /// Keyring account containing the pool seed.
    pub pool_master_keyring_account: String,
    /// Witness outcome when this invocation sends the initialization transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_check: Option<CrossCheckView>,
}

fn unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Submission(SubmissionError::RecordUnavailable {
        detail: detail.into(),
    })
}

fn pool_err_to_wallet_err(error: &PoolError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: error.to_string(),
    })
}

fn persist(
    name: &str,
    master: &KeyringEntryRef,
    pending: &PoolInitialization,
) -> Result<(), WalletError> {
    loader::set_pool_initialization(name, master, Some(pending))
        .map(|_| ())
        .map_err(|error| unavailable(format!("pool recovery state could not be saved: {error}")))
}

/// Serializes seed replacement, recovery and completion across processes.
fn lifecycle_lock(name: &str) -> Result<HeldFileLock, WalletError> {
    let dir = loader::default_profile_dir().map_err(|error| unavailable(error.to_string()))?;
    lifecycle_lock_in_dir(name, &dir)
}

/// Takes the `<name>.pool-init.lock` file lock in `dir` for [`lifecycle_lock`] and the tests.
fn lifecycle_lock_in_dir(name: &str, dir: &Path) -> Result<HeldFileLock, WalletError> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(dir.join(format!("{name}.pool-init.lock")))
        .map_err(|error| unavailable(error.to_string()))?;
    HeldFileLock::try_lock(file).map_err(|_| unavailable("another pool initialization is running"))
}

fn fresh_seed() -> Zeroizing<[u8; 64]> {
    let mut seed = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(seed.as_mut());
    seed
}

fn channels(
    seed: &Zeroizing<[u8; 64]>,
    size: usize,
) -> Result<Vec<PoolChannelRecord>, WalletError> {
    if !(1..=stellar_agent_pool::ChannelPool::MAX_SIZE).contains(&size) {
        return Err(pool_err_to_wallet_err(&PoolError::SizeOutOfRange));
    }
    let mut seed_copy = Zeroizing::new([0u8; 64]);
    seed_copy.copy_from_slice(seed.as_ref());
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(seed_copy);
    (1..=size as u32)
        .map(|index| {
            wallet
                .derive_account(index)
                .map(|key| PoolChannelRecord::new(index, key.public_key_strkey()))
                .map_err(|_| pool_err_to_wallet_err(&PoolError::DeriveFailed))
        })
        .collect()
}

/// An incomplete seed write can be retried only while the checkpoint proves
/// that no submission has started. A ready seed must match every stored key.
fn prepare_seed(
    name: &str,
    master: &KeyringEntryRef,
    pending: &mut PoolInitialization,
    generated: Option<Zeroizing<[u8; 64]>>,
) -> Result<Zeroizing<[u8; 64]>, WalletError> {
    if pending.seed_ready {
        let seed = load_pool_master_seed_from_keyring(&master.service, &master.account)
            .map_err(|error| pool_err_to_wallet_err(&error))?;
        if channels(&seed, pending.channels.len())? != pending.channels {
            return Err(unavailable(
                "persisted pool seed does not derive the recorded channels",
            ));
        }
        return Ok(seed);
    }
    if pending.submission.is_some() || pending.completion_ledger.is_some() {
        return Err(unavailable(
            "pool seed checkpoint is inconsistent with its submission",
        ));
    }
    let seed = match generated {
        Some(seed) => seed,
        None => match probe_keyring_entry(&master.service, &master.account) {
            KeyringProbe::Present => {
                let seed = load_pool_master_seed_from_keyring(&master.service, &master.account)
                    .map_err(|error| pool_err_to_wallet_err(&error))?;
                if channels(&seed, pending.channels.len())? == pending.channels {
                    seed
                } else {
                    fresh_seed()
                }
            }
            KeyringProbe::Absent => fresh_seed(),
            KeyringProbe::BackendError(error, operation) => {
                return Err(classify_probe_backend_error(&error, operation, master));
            }
        },
    };
    pending.channels = channels(&seed, pending.channels.len())?;
    persist(name, master, pending)?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(seed.as_ref()));
    write_pool_seed(master, &encoded)?;
    pending.seed_ready = true;
    persist(name, master, pending)?;
    Ok(seed)
}

/// The send barrier is written only after the normal wallet recorder succeeds.
/// A false barrier on restart proves that an interrupted attempt was unsent.
struct InitRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    name: &'a str,
    master: &'a KeyringEntryRef,
    pending: Mutex<PoolInitialization>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for InitRecorder<'_> {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        let mut state = self
            .pending
            .lock()
            .map_err(|_| unavailable("pool checkpoint mutex is poisoned"))?
            .clone();
        state.submission = Some(PoolInitSubmission {
            envelope_hash: intent.envelope_hash.clone(),
            tx_hash: intent.tx_hash.clone(),
            sequence: intent.sequence,
            send_started: false,
        });
        persist(self.name, self.master, &state)?;
        self.inner.pre_send(intent).await?;
        if let Some(submission) = &mut state.submission {
            submission.send_started = true;
        }
        persist(self.name, self.master, &state)?;
        *self
            .pending
            .lock()
            .map_err(|_| unavailable("pool checkpoint mutex is poisoned"))? = state;
        Ok(())
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.inner.outcome(intent, outcome).await;
    }
}

fn pending_data(name: &str, pending: &PoolInitialization) -> serde_json::Value {
    serde_json::json!({
        "initialised": false, "pending": true,
        "tx_hash": pending.submission.as_ref().map(|submission| &submission.tx_hash),
        "resume_with": format!("stellar-agent pool init --resume --profile {name}")
    })
}

/// Runs pool initialization or recovery. Errors leave the durable checkpoint
/// available to the completion command. Returns zero when the request succeeds.
pub async fn run(args: &PoolInitArgs) -> i32 {
    run_with_dependencies(
        args,
        stellar_agent_network::keyring::init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the platform-keyring initialiser injected.
///
/// Production callers use [`run`], which supplies
/// [`stellar_agent_network::keyring::init_platform_keyring_store`]. Tests
/// substitute an initialiser that panics, so a refusal ahead of it is shown to
/// leave the keyring untouched.
async fn run_with_dependencies<InitKeyring>(args: &PoolInitArgs, init_keyring: InitKeyring) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    match execute(args, init_keyring).await {
        Ok(value) => {
            render_json(&Envelope::ok(value));
            0
        }
        Err(error) => {
            let resolved = resolve_profile_name(args.profile.as_deref());
            let envelope = match load_profile_reconciled(&resolved) {
                Ok(profile) if profile.pool_initialization.is_some() => {
                    Envelope::<()>::err_with_details(
                        &error,
                        serde_json::json!({
                            "resume_with": format!(
                                "stellar-agent pool init --resume --profile {}", resolved.name,
                            ),
                        }),
                    )
                }
                _ => Envelope::<()>::err(&error),
            };
            render_json(&envelope);
            1
        }
    }
}

async fn execute<InitKeyring>(
    args: &PoolInitArgs,
    init_keyring: InitKeyring,
) -> Result<serde_json::Value, WalletError>
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    if let Some(size) = args.size
        && !(1..=stellar_agent_pool::ChannelPool::MAX_SIZE).contains(&size)
    {
        return Err(pool_err_to_wallet_err(&PoolError::SizeOutOfRange));
    }
    let resolved = resolve_profile_name(args.profile.as_deref());
    // Validate the name and existing profile before constructing the sidecar path.
    load_profile_reconciled(&resolved).map_err(|error| error.to_wallet_error())?;
    let _lock = lifecycle_lock(&resolved.name)?;
    let profile = load_profile_reconciled(&resolved).map_err(|error| error.to_wallet_error())?;
    // Halt check: ahead of the fresh and the resume branch, the keyring store,
    // the seed, the signer and any RPC request.
    stellar_agent_core::profile::halt::ensure_not_halted(&resolved.name)?;
    let context = NetworkContext::from_profile(&profile);
    // Structural mainnet refusal: ahead of the pending-initialization branch,
    // the keyring store, the seed, the signer, and any RPC request, on both the
    // fresh and the resume path.
    if let Some(error) = mainnet_write_refusal(context.chain_id) {
        return Err(error);
    }
    let name = &resolved.name;
    if profile.pool_initialization.is_some() && !args.resume {
        return Err(unavailable(format!(
            "pool initialization is pending; run 'stellar-agent pool init --resume --profile {name}'; --force cannot replace its seed"
        )));
    }
    if args.resume && profile.pool_initialization.is_none() {
        return match profile.pool_config {
            Some(config) => Ok(
                serde_json::json!({"initialised":true,"channel_count":config.pool_size,"channels":config.channels}),
            ),
            None => Err(unavailable("there is no pool initialization to resume")),
        };
    }
    let master = profile
        .pool_master_key_id
        .clone()
        .unwrap_or_else(|| KeyringEntryRef::default_pool_master_key(name));
    stellar_agent_core::profile::owner_key::refuse_policy_pin_coordinate(
        &master,
        "pool_master_key_id",
    )?;
    stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
        &master,
        "pool_master_key_id",
    )?;
    init_keyring()?;
    let audit = crate::commands::value_audit::require_value_audit_writer(&profile, name)?;
    let fee_per_op = profile
        .classic_fee_per_op_stroops
        .unwrap_or(stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS);
    let (mut pending, generated) = match profile.pool_initialization.clone() {
        Some(pending) => (pending, None),
        None => {
            match probe_keyring_entry(&master.service, &master.account) {
                KeyringProbe::Present if !args.force => {
                    return Err(pool_err_to_wallet_err(&PoolError::AlreadyInitialised));
                }
                KeyringProbe::BackendError(error, operation) => {
                    return Err(classify_probe_backend_error(&error, operation, &master));
                }
                _ => {}
            }
            let size = args
                .size
                .ok_or_else(|| unavailable("pool size is required"))?;
            precheck_init_fee(fee_per_op, size, &profile, name)?;
            let signer =
                enrolled_keyring_signer(name, &profile, &profile.mcp_signer_default.account, None)
                    .await?;
            let seed = fresh_seed();
            let pending = PoolInitialization {
                id: uuid::Uuid::new_v4().to_string(),
                network_passphrase: context.network_passphrase().to_owned(),
                funder: signer.public_key().to_string().as_str().to_owned(),
                channels: channels(&seed, size)?,
                seed_ready: false,
                attempt: 0,
                submission: None,
                completion_ledger: None,
            };
            persist(name, &master, &pending)?;
            (pending, Some(seed))
        }
    };
    if pending.network_passphrase != context.network_passphrase() {
        return Err(unavailable(
            "the pending pool belongs to a different network",
        ));
    }
    let seed = prepare_seed(name, &master, &mut pending, generated)?;
    if pending.completion_ledger.is_some() {
        return complete(&profile, name, &master, &pending, &audit, None);
    }
    // The endpoint check precedes the channel observations and runs on the
    // client that later sends, under its own budget of `--timeout-seconds`.
    let client = context.primary_client()?;
    check_endpoint_identity(&client, &context, Duration::from_secs(args.timeout_seconds)).await?;
    let mut present = 0;
    let mut absent_channels = Vec::new();
    for channel in &pending.channels {
        match fetch_account(&client, &channel.public_key, &[]).await {
            Ok(_) => present += 1,
            Err(WalletError::Network(NetworkError::AccountNotFound { .. })) => {
                absent_channels.push(channel.public_key.clone());
            }
            Err(error) => return Err(error),
        }
    }
    let receipts = ReceiptStore::open(name).map_err(|error| unavailable(error.to_string()))?;
    if present == pending.channels.len() {
        let ledger = client.get_health().await?.latest_ledger;
        if ledger == 0 {
            return Err(unavailable("the channel observation has no ledger"));
        }
        // The endpoint's answer is recorded on the receipt for display;
        // account existence finishes configuration, also when the transaction
        // is outside RPC retention. Neither writes a transaction outcome row.
        if let Some(submission) = &pending.submission {
            settle_record(&client, &receipts, submission).await?;
        }
        pending.completion_ledger = Some(ledger);
        persist(name, &master, &pending)?;
        return complete(&profile, name, &master, &pending, &audit, None);
    }
    if present != 0 {
        return Ok(pending_data(name, &pending));
    }
    if let Some(submission) = &pending.submission {
        if submission.send_started {
            // No channel account exists, so a fresh envelope cannot create one
            // twice. Retry requires the operator's verified clear row. The
            // endpoint must not report success. An endpoint failure report, an
            // unknown outcome and a receipt status each hold the checkpoint.
            settle_record(&client, &receipts, submission).await?;
            if !operator_clear_recorded(name, &audit, submission)? {
                return Ok(pending_data(name, &pending));
            }
        } else {
            // The durable barrier proves that no bytes left for this attempt.
            if let Some(receipt) = receipts
                .get(&submission.envelope_hash)
                .map_err(|error| unavailable(error.to_string()))?
                && receipt.status == ReceiptStatus::Success
            {
                return Err(unavailable("an unsent checkpoint has a successful receipt"));
            }
            write_not_transmitted_row(name, &audit, submission)?;
            // The receipt is display data; it follows the audit decision.
            if receipts
                .get(&submission.envelope_hash)
                .map_err(|error| unavailable(error.to_string()))?
                .is_some_and(|receipt| receipt.status == ReceiptStatus::Pending)
            {
                receipts
                    .finalize(
                        &submission.envelope_hash,
                        ReceiptStatus::Failed {
                            code: NOT_TRANSMITTED_CODE.to_owned(),
                        },
                        None,
                    )
                    .map_err(|error| unavailable(error.to_string()))?;
            }
        }
    }
    if args.resume {
        precheck_init_fee(fee_per_op, pending.channels.len(), &profile, name)?;
    }
    if pending.submission.is_some() {
        pending.attempt = pending
            .attempt
            .checked_add(1)
            .ok_or_else(|| unavailable("pool attempt counter overflow"))?;
        pending.submission = None;
        persist(name, &master, &pending)?;
    }
    let funder = fetch_account(&client, &pending.funder, &[]).await?;
    let cross_check = obtain_classic_witness(
        &profile,
        &context,
        CrossCheckValue::Unvalued,
        PoolInitWitnessInputs {
            funder: AccountObservation::from_view(&funder)?,
            absent_channels,
        },
        "pool init",
    )
    .await?;
    let signer =
        enrolled_keyring_signer(name, &profile, &profile.mcp_signer_default.account, None).await?;
    if signer.public_key().to_string().as_str() != pending.funder {
        return Err(unavailable(
            "the profile signer is not the recorded pool funder",
        ));
    }
    let inner = build_recorder(SubmitRecord {
        policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
        profile: &profile,
        profile_name: name.clone(),
        verb: "pool init",
        tool: "pool init",
        chain_id: context.chain_id.caip2_str(),
        effects: None,
        audit: Some(audit.clone()),
        now_ms: stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|error| unavailable(error.to_string()))?,
    })?
    .with_witness(cross_check.witness());
    let recorder = InitRecorder {
        inner,
        name,
        master: &master,
        pending: Mutex::new(pending.clone()),
    };
    let signers: Vec<SoftwareSigningKey> = pending
        .channels
        .iter()
        .map(|channel| {
            let mut seed_copy = Zeroizing::new([0u8; 64]);
            seed_copy.copy_from_slice(seed.as_ref());
            derive_channel_signer(seed_copy, channel.index)
                .map_err(|error| pool_err_to_wallet_err(&error))
        })
        .collect::<Result<_, _>>()?;
    let result = init_pool(
        &client,
        InitParams {
            funder_strkey: &pending.funder,
            funder_sequence: funder.sequence_number,
            funder_signer: &signer,
            channel_signers: signers,
            channel_strkeys: pending
                .channels
                .iter()
                .map(|channel| channel.public_key.clone())
                .collect(),
            channel_indices: pending
                .channels
                .iter()
                .map(|channel| channel.index)
                .collect(),
            network_passphrase: context.network_passphrase(),
            fee_per_op,
            recorder: &recorder,
            attempt: pending.attempt,
            timeout: std::time::Duration::from_secs(args.timeout_seconds),
        },
    )
    .await
    .map_err(|error| map_init_error(error, name))?;
    pending = recorder
        .pending
        .into_inner()
        .map_err(|_| unavailable("pool checkpoint mutex is poisoned"))?;
    pending.completion_ledger = Some(result.ledger);
    persist(name, &master, &pending)?;
    complete(
        &profile,
        name,
        &master,
        &pending,
        &audit,
        Some(cross_check.view()),
    )
}

fn precheck_init_fee(
    per_op: u32,
    count: usize,
    profile: &Profile,
    name: &str,
) -> Result<(), WalletError> {
    check_classic_fee_cap(per_op, FeeSource::ProfileDefault, profile)?;
    total_init_fee(per_op, count).map_err(|error| map_init_error(error, name))?;
    Ok(())
}

fn map_init_error(error: PoolError, name: &str) -> WalletError {
    match error {
        // Nothing was built, signed, or sent: the operator lowers the fee.
        PoolError::FeeOverflow { op_count } => WalletError::Validation(
            stellar_agent_core::error::ValidationError::FeeTotalOverflow { op_count },
        ),
        other => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("{other}; run 'stellar-agent pool init --resume --profile {name}'"),
        }),
    }
}

/// The failure code of an attempt the send barrier proves was never sent.
const NOT_TRANSMITTED_CODE: &str = "submission.not_transmitted";

/// The audit tool name of the pool initialization's pending row.
const POOL_INIT_TOOL: &str = "pool init";

/// Records the endpoint's answer for a sent attempt on its receipt, for
/// display, and returns the receipt's status.
///
/// `SUCCESS` records success. `FAILED` moves only a `Pending` receipt, to
/// `Ambiguous` without evidence: an endpoint failure report is
/// unauthenticated and authorizes neither a failure row nor a retry. A receipt
/// already `Ambiguous`, `Failed` or `ClearedByOperator` keeps its status. The
/// checkpoint stays in every case.
///
/// # Errors
///
/// `submission.record_unavailable` for a missing or unreadable receipt, and
/// the endpoint's error for an answer it could not give.
async fn settle_record(
    client: &StellarRpcClient,
    receipts: &ReceiptStore,
    submission: &PoolInitSubmission,
) -> Result<Option<ReceiptStatus>, WalletError> {
    let Some(recorded) = receipts
        .get(&submission.envelope_hash)
        .map_err(|error| unavailable(error.to_string()))?
    else {
        return Err(unavailable(
            "the pending pool receipt is missing; restore it before resuming",
        ));
    };
    let answer = client.get_transaction_status(&submission.tx_hash).await?;
    match answer.status.as_str() {
        "SUCCESS" => receipts
            .finalize(
                &submission.envelope_hash,
                ReceiptStatus::Success,
                answer.ledger,
            )
            .map_err(|error| unavailable(error.to_string()))?,
        "FAILED" if recorded.status == ReceiptStatus::Pending => receipts
            .finalize(&submission.envelope_hash, ReceiptStatus::Ambiguous, None)
            .map_err(|error| unavailable(error.to_string()))?,
        _ => {}
    }
    Ok(receipts
        .get(&submission.envelope_hash)
        .map_err(|error| unavailable(error.to_string()))?
        .map(|receipt| receipt.status))
}

/// Takes the writer guard and verifies its tip anchor and retained history.
fn verified_guard<'a>(
    profile_name: &str,
    audit: &'a stellar_agent_network::submission_record::AuditWriterHandle,
) -> Result<std::sync::MutexGuard<'a, stellar_agent_core::audit_log::AuditWriter>, WalletError> {
    let mut guard = audit
        .lock()
        .map_err(|_| unavailable("audit writer mutex is poisoned"))?;
    guard.verify_tip_anchor().map_err(|error| {
        stellar_agent_core::audit_log::audit_writer_refusal(profile_name, &error)
    })?;
    Ok(guard)
}

/// Whether the verified audit history holds an operator's
/// `submission_receipt_cleared` row for the attempt.
///
/// The row is read under the writer guard, up to the writer's verified tip.
/// The receipt's own `cleared_by_operator` status authorizes nothing.
///
/// # Errors
///
/// The writer's refusal of its tip anchor or retained history, and
/// `audit.chain_key_unavailable` for a history the lookup cannot read.
fn operator_clear_recorded(
    profile_name: &str,
    audit: &stellar_agent_network::submission_record::AuditWriterHandle,
    submission: &PoolInitSubmission,
) -> Result<bool, WalletError> {
    let guard = verified_guard(profile_name, audit)?;
    stellar_agent_core::audit_log::reader::try_submission_receipt_cleared_exists(
        &guard,
        &submission.envelope_hash,
    )
    .map_err(|error| audit_history_refusal(profile_name, &error))
}

/// Settles the audit record of an attempt the durable send barrier proves
/// was never sent, before the attempt is retired.
///
/// `submission` is the durable checkpoint's attempt; it must record
/// `send_started == false`.
///
/// The writer guard spans the verification, the lookup and the append. The
/// lookup reads the verified history for the checkpoint's envelope hash:
///
/// - an open pending row written by `pool init` takes one
///   `value_action_failed` row with the fixed code
///   `submission.not_transmitted`, carrying that pending row's legs, nonce,
///   policy decision and approval nonce;
/// - a latest `value_action_failed` row, or no row at all, means no pending
///   row is open, and nothing is appended;
/// - an open pending row of another tool, or a latest
///   `value_action_submitted` row, refuses with
///   `submission.record_unavailable` and keeps the checkpoint.
///
/// No receipt status or receipt code takes part.
///
/// # Errors
///
/// The refusals above, the writer's refusal of its tip anchor, retained
/// history or append, and `audit.chain_key_unavailable` for a history the
/// lookup cannot read.
fn write_not_transmitted_row(
    profile_name: &str,
    audit: &stellar_agent_network::submission_record::AuditWriterHandle,
    submission: &PoolInitSubmission,
) -> Result<(), WalletError> {
    use stellar_agent_core::audit_log::reader::{
        SettledValueAction, ValueActionSettlement, try_value_action_settled_row,
        try_value_action_settlement,
    };

    if submission.send_started {
        return Err(unavailable(
            "a sent pool attempt cannot be recorded as not transmitted",
        ));
    }
    let mut guard = verified_guard(profile_name, audit)?;
    let settlement = try_value_action_settlement(&guard, &submission.envelope_hash)
        .map_err(|error| audit_history_refusal(profile_name, &error))?;
    let open = match settlement {
        ValueActionSettlement::Owed(open) if open.tool == POOL_INIT_TOOL => open,
        ValueActionSettlement::Owed(_) => {
            return Err(unavailable(
                "the unsent pool attempt's envelope has an open pending row of another tool",
            ));
        }
        ValueActionSettlement::OwedWithoutLegs => return Ok(()),
        ValueActionSettlement::Settled => {
            return match try_value_action_settled_row(&guard, &submission.envelope_hash)
                .map_err(|error| audit_history_refusal(profile_name, &error))?
            {
                Some(SettledValueAction::Failed { .. }) => Ok(()),
                _ => Err(unavailable(
                    "the unsent pool attempt's envelope has a submitted row",
                )),
            };
        }
    };
    let entry = AuditEntry::new_value_action_failed(
        POOL_INIT_TOOL,
        open.chain_id,
        open.legs,
        stellar_agent_network::redact_tx_hash(&submission.tx_hash).as_str(),
        NOT_TRANSMITTED_CODE,
        open.policy_decision,
        Some(submission.envelope_hash.clone()),
        open.nonce_id,
        open.approval_nonce,
        uuid::Uuid::new_v4().to_string(),
    );
    crate::commands::value_audit::append_value_audit_row_strict(&mut guard, profile_name, entry)
}

fn complete(
    profile: &Profile,
    name: &str,
    master: &KeyringEntryRef,
    pending: &PoolInitialization,
    audit: &stellar_agent_network::submission_record::AuditWriterHandle,
    cross_check: Option<CrossCheckView>,
) -> Result<serde_json::Value, WalletError> {
    let ledger = pending
        .completion_ledger
        .ok_or_else(|| unavailable("pool completion has no ledger observation"))?;
    loader::set_pool_state(
        name,
        master,
        &PoolConfig::new(pending.channels.len(), pending.channels.clone()),
    )
    .map_err(|error| {
        unavailable(format!(
            "pool config could not be saved; resume initialization: {error}"
        ))
    })?;
    let key = crate::commands::profile::audit_emit::load_audit_hmac_key(profile, name)?;
    let reader = AuditReader::new(audit.clone(), Some(*key));
    let tx_hash_redacted = pending
        .submission
        .as_ref()
        .map(|submission| stellar_agent_network::redact_tx_hash(&submission.tx_hash));
    if !reader
        .pool_initialization_exists(&pending.id)
        .map_err(|error| unavailable(error.to_string()))?
    {
        let entry = AuditEntry::new_channel_pool_initialised(
            redact_strkey_first5_last5(&pending.funder),
            pending.channels.len(),
            tx_hash_redacted
                .clone()
                .unwrap_or_else(|| "unrecorded".to_owned()),
            ledger,
            &pending.id,
        );
        audit
            .lock()
            .map_err(|_| unavailable("audit writer mutex is poisoned"))?
            .write_entry(entry)
            .map_err(|error| {
                unavailable(format!("pool completion audit could not be saved: {error}"))
            })?;
    }
    loader::set_pool_initialization(name, master, None)
        .map_err(|error| unavailable(error.to_string()))?;
    serde_json::to_value(PoolInitResult {
        profile: name.to_owned(),
        channel_count: pending.channels.len(),
        tx_hash_redacted,
        ledger,
        channels: pending.channels.clone(),
        funder_redacted: redact_strkey_first5_last5(&pending.funder),
        pool_master_keyring_service: master.service.clone(),
        pool_master_keyring_account: master.account.clone(),
        cross_check,
    })
    .map_err(|error| unavailable(error.to_string()))
}
// ── Keyring existence probe ───────────────────────────────────────────────────

/// The result of probing whether a keyring entry exists.
///
/// Distinguishes "definitely absent" (NoEntry) from "backend error"
/// (ambiguous; cannot determine whether a key exists).
enum KeyringProbe {
    /// The entry exists and its password is readable.
    Present,
    /// The entry does not exist (`keyring_core::Error::NoEntry`).
    Absent,
    /// Construction or a read failed, so existence is unknown. Construction
    /// failures include `NoEntry`; only a missing read proves absence.
    BackendError(keyring_core::Error, KeyringOperation),
}

/// Probes whether a keyring entry exists, distinguishing `NoEntry` from backend
/// errors.
///
/// Only a read returning `keyring_core::Error::NoEntry` proves absence.
/// Construction failures and other read errors retain their operation.
fn probe_keyring_entry(service: &str, account: &str) -> KeyringProbe {
    let entry = match KeyringEntry::new(service, account) {
        Ok(e) => e,
        Err(e) => {
            return KeyringProbe::BackendError(e, KeyringOperation::Construct);
        }
    };
    match entry.get_password() {
        Ok(secret) => {
            drop(Zeroizing::new(secret));
            KeyringProbe::Present
        }
        Err(keyring_core::Error::NoEntry) => KeyringProbe::Absent,
        Err(e) => KeyringProbe::BackendError(e, KeyringOperation::Read),
    }
}

/// Classifies a failed probe and explains why existence is unknown.
fn classify_probe_backend_error(
    e: &keyring_core::Error,
    operation: KeyringOperation,
    pool_master_ref: &KeyringEntryRef,
) -> WalletError {
    match stellar_agent_network::keyring::map_keyring_operation_error(
        e,
        operation,
        &pool_master_ref.service,
    ) {
        WalletError::Auth(AuthError::KeyringPlatformError { detail }) => {
            WalletError::Auth(AuthError::KeyringPlatformError {
                detail: format!("{detail}; cannot determine existence"),
            })
        }
        classified => classified,
    }
}

/// Writes the seed with the operation that failed and the resume instruction.
fn write_pool_seed(master: &KeyringEntryRef, encoded: &str) -> Result<(), WalletError> {
    let entry = KeyringEntry::new(&master.service, &master.account).map_err(|error| {
        classify_pool_seed_write_failure(&error, KeyringOperation::Construct, master)
    })?;
    entry.set_password(encoded).map_err(|error| {
        classify_pool_seed_write_failure(&error, KeyringOperation::Write, master)
    })?;
    Ok(())
}

/// Preserves the error classification and names the completion command.
fn classify_pool_seed_write_failure(
    e: &keyring_core::Error,
    operation: KeyringOperation,
    pool_master_ref: &KeyringEntryRef,
) -> WalletError {
    match stellar_agent_network::keyring::map_keyring_operation_error(
        e,
        operation,
        &pool_master_ref.service,
    ) {
        WalletError::Auth(AuthError::KeyringPlatformError { detail }) => {
            WalletError::Auth(AuthError::KeyringPlatformError {
                detail: format!("{detail}; seed persistence pending; re-run with --resume"),
            })
        }
        classified => classified,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;
    use serial_test::serial;
    use stellar_agent_core::profile::schema::Profile;

    #[cfg(unix)]
    #[test]
    fn dropping_lifecycle_lock_unlocks_with_a_duplicate_descriptor_alive() {
        let dir = tempfile::tempdir().unwrap();
        let guard = lifecycle_lock_in_dir("pool-lock-test", dir.path()).unwrap();
        let duplicate = guard.try_clone_file().unwrap();
        assert_contended(dir.path());
        drop(guard);
        let _next = lifecycle_lock_in_dir("pool-lock-test", dir.path()).unwrap();
        drop(duplicate);
        assert_contended(dir.path());
    }

    #[cfg(unix)]
    fn assert_contended(dir: &Path) {
        let error = lifecycle_lock_in_dir("pool-lock-test", dir)
            .expect_err("a held lifecycle lock excludes a second opener");
        assert!(
            error
                .to_string()
                .contains("another pool initialization is running"),
            "{error}"
        );
    }

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(var: String, value: &str) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    /// End-to-end environment immunity for the pool persistence step, through
    /// the PRODUCTION loader functions `run()` uses: a `STELLAR_AGENT_RPC_URL`
    /// overlay is visible in the env-merged runtime view (asserted as a
    /// sanity check) but must never reach the on-disk document, and the
    /// persisted profile must differ from its pre-init form only in the two
    /// pool keys. The profile lives in a real temp dir; the write is the
    /// production `set_pool_state_on_disk` over that dir.
    #[test]
    #[serial]
    fn env_overlay_never_reaches_the_persisted_pool_state() {
        let _overlay = EnvGuard::set(
            "STELLAR_AGENT_RPC_URL".to_owned(),
            "https://env-injected.example.org",
        );

        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet(
            "stellar-agent-signer-pool-init-test",
            "acct",
            "stellar-agent-nonce-pool-init-test",
            "acct",
        )
        .with_profile_name("pool-init-test")
        .audit_log_path(dir.path().join("audit.log"))
        .build();
        loader::save_to_dir("pool-init-test", &profile, dir.path()).unwrap();
        let before = std::fs::read_to_string(dir.path().join("pool-init-test.toml")).unwrap();

        // Sanity: the env-merged runtime view DOES see the overlay — this is
        // exactly the view the persistence step must never write back.
        let merged = loader::load_from_dir("pool-init-test", dir.path(), None).unwrap();
        assert_eq!(merged.rpc_url, "https://env-injected.example.org");

        let master_ref = KeyringEntryRef::default_pool_master_key("pool-init-test");
        let cfg = PoolConfig::new(1, vec![PoolChannelRecord::new(1, "GABC...CH1")]);
        loader::set_pool_state_on_disk("pool-init-test", dir.path(), &master_ref, &cfg).unwrap();

        let written = std::fs::read_to_string(dir.path().join("pool-init-test.toml")).unwrap();
        assert!(
            !written.contains("env-injected"),
            "no environment overlay value may leak into the stored document; got:\n{written}"
        );

        let mut after: toml::Value = toml::from_str(&written).unwrap();
        let table = after.as_table_mut().unwrap();
        let got_ref: KeyringEntryRef = table
            .remove("pool_master_key_id")
            .expect("pool_master_key_id must be written")
            .try_into()
            .unwrap();
        let got_cfg: PoolConfig = table
            .remove("pool_config")
            .expect("pool_config must be written")
            .try_into()
            .unwrap();
        assert_eq!(got_ref, master_ref);
        assert_eq!(got_cfg, cfg);

        let before_doc: toml::Value = toml::from_str(&before).unwrap();
        assert_eq!(
            after, before_doc,
            "the persisted profile must differ from its pre-init form only in \
             the pool keys; got:\n{written}"
        );
    }

    /// A non-interactive Windows session failure keeps its typed
    /// classification through the existence probe and both
    /// seed write phases: the operator sees
    /// `auth.keyring_interactive_session_required`, not a generic
    /// backend-error or not-found shape.
    #[test]
    fn pool_keyring_failures_classify_interactive_session_required() {
        use stellar_agent_test_support::keyring_mock::WINDOWS_NO_LOGON_SESSION_TEXT;
        let r = KeyringEntryRef::new("stellar-agent-pool-classify", "master");
        let e = keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other(
            WINDOWS_NO_LOGON_SESSION_TEXT,
        )));
        assert_eq!(
            classify_probe_backend_error(&e, KeyringOperation::Construct, &r).code(),
            "auth.keyring_interactive_session_required"
        );
        assert_eq!(
            classify_pool_seed_write_failure(&e, KeyringOperation::Write, &r).code(),
            "auth.keyring_interactive_session_required"
        );
    }

    #[test]
    #[serial]
    fn pool_keyring_no_entry_distinguishes_construct_read_and_write() {
        use keyring_core::api::CredentialStoreApi;
        use stellar_agent_test_support::keyring_mock;
        struct MissingConstruction;
        impl CredentialStoreApi for MissingConstruction {
            fn vendor(&self) -> String {
                "hostile-vendor".to_owned()
            }
            fn id(&self) -> String {
                "hostile-id".to_owned()
            }
            fn build(
                &self,
                _: &str,
                _: &str,
                _: Option<&std::collections::HashMap<&str, &str>>,
            ) -> keyring_core::Result<KeyringEntry> {
                Err(keyring_core::Error::NoEntry)
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        let r = KeyringEntryRef::new("private-service", "private-account");
        keyring_core::set_default_store(std::sync::Arc::new(MissingConstruction));
        let KeyringProbe::BackendError(error, operation) =
            probe_keyring_entry(&r.service, &r.account)
        else {
            panic!("construction failure must refuse the probe");
        };
        assert_eq!(operation, KeyringOperation::Construct);
        let probe = classify_probe_backend_error(&error, operation, &r);
        assert_eq!(probe.code(), "auth.keyring_platform_error");
        assert_eq!(
            probe.message(),
            "keyring operation failed: construct unknown credential store: no matching credential; cannot determine existence"
        );
        let construct = write_pool_seed(&r, "seed-sentinel").unwrap_err();
        assert_eq!(construct.code(), "auth.keyring_platform_error");
        assert_eq!(
            construct.message(),
            "keyring operation failed: construct unknown credential store: no matching credential; seed persistence pending; re-run with --resume"
        );

        keyring_mock::install().unwrap();
        assert!(matches!(
            probe_keyring_entry(&r.service, &r.account),
            KeyringProbe::Absent
        ));
        let entry = KeyringEntry::new(&r.service, &r.account).unwrap();
        entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .unwrap()
            .set_error(keyring_core::Error::NoEntry);
        let write = write_pool_seed(&r, "seed-sentinel").unwrap_err();
        assert_eq!(write.code(), "auth.keyring_platform_error");
        assert_eq!(
            write.message(),
            "keyring operation failed: write unknown credential store: no matching credential; seed persistence pending; re-run with --resume"
        );
    }

    /// Persists a mainnet profile named `pool-mainnet` whose endpoint is
    /// `rpc_url`, with `pending` as its pool initialization, under a temporary
    /// home with `STELLAR_AGENT_PROFILE` cleared.
    fn mainnet_pool_fixture(
        rpc_url: &str,
        pending: Option<PoolInitialization>,
    ) -> (
        tempfile::TempDir,
        stellar_agent_test_support::StellarAgentHomeGuard,
        stellar_agent_test_support::ProfileEnvVarGuard,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let mut profile =
            Profile::builder_mainnet_named("pool-mainnet", rpc_url, "s", "default", "n", "a")
                .audit_log_path(dir.path().join("audit.jsonl"))
                .with_noop_engine()
                .build();
        profile.pool_initialization = pending;
        loader::save_new_to_dir("pool-mainnet", &profile, &dir.path().join("profiles")).unwrap();
        (dir, home, env)
    }

    fn pool_init_args(size: Option<usize>, resume: bool) -> PoolInitArgs {
        PoolInitArgs {
            size,
            profile: Some("pool-mainnet".to_owned()),
            force: false,
            resume,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            output: OutputFormat::Json,
        }
    }

    /// A fresh `pool init` on a mainnet profile exits 1 before the keyring
    /// initialiser, which panics if called, and before any connection to the
    /// profile's endpoint.
    #[tokio::test]
    #[serial]
    async fn fresh_pool_init_refuses_mainnet_before_keyring_and_any_connection() {
        let counter = stellar_agent_test_support::ConnectionCounter::start().unwrap();
        let _fixture = mainnet_pool_fixture(&counter.https_uri(), None);
        let code = run_with_dependencies(&pool_init_args(Some(1), false), || {
            panic!("a mainnet pool init must not initialise the keyring")
        })
        .await;
        assert_eq!(code, 1, "a mainnet pool init must exit with code 1");
        assert_eq!(
            counter.accepted().unwrap(),
            0,
            "a mainnet pool init must open no connection"
        );
    }

    /// `pool init --resume` over a pending initialization on a mainnet profile
    /// exits 1 before the keyring initialiser, the seed, the endpoint probe,
    /// and the signer.
    #[tokio::test]
    #[serial]
    async fn resumed_pool_init_refuses_mainnet_before_keyring_and_any_connection() {
        let counter = stellar_agent_test_support::ConnectionCounter::start().unwrap();
        let funder = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let pending = PoolInitialization {
            id: "pool-init-mainnet".to_owned(),
            network_passphrase: stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.to_owned(),
            funder: funder.to_owned(),
            channels: vec![PoolChannelRecord::new(1, funder)],
            seed_ready: true,
            attempt: 0,
            submission: None,
            completion_ledger: None,
        };
        let _fixture = mainnet_pool_fixture(&counter.https_uri(), Some(pending));
        let code = run_with_dependencies(&pool_init_args(None, true), || {
            panic!("a mainnet pool init must not initialise the keyring")
        })
        .await;
        assert_eq!(code, 1, "a resumed mainnet pool init must exit with code 1");
        assert_eq!(
            counter.accepted().unwrap(),
            0,
            "a resumed mainnet pool init must open no connection"
        );
    }

    /// A fresh `pool init` builds one client: the endpoint check is its first
    /// request, the channel and funder reads follow, and the creation is sent
    /// through it, whose submit layer checks it again. A `--resume` once the
    /// pool is complete answers from the profile and builds no client.
    #[tokio::test]
    #[serial]
    async fn a_fresh_init_sends_through_one_checked_client_and_a_completed_resume_makes_no_request()
    {
        use base64::Engine as _;
        const NAME: &str = "pool-one-client";
        const FUNDER_SEED: [u8; 32] = [0x91; 32];
        let funder = stellar_agent_test_support::signed_envelope::account_id_for_seed(FUNDER_SEED);
        let server = crate::test_rpc::ClassicRpc::testnet(&[&funder])
            .serve()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let profile =
            Profile::builder_testnet("pool-one-signer", &funder, "pool-one-nonce", "default")
                .with_profile_name(NAME)
                .rpc_url(server.uri())
                .audit_log_path(dir.path().join(format!("audit/{NAME}.jsonl")))
                .build();
        loader::save_to_dir(NAME, &profile, &dir.path().join("profiles")).unwrap();
        KeyringEntry::new(
            &profile.mcp_signer_default.service,
            &profile.mcp_signer_default.account,
        )
        .unwrap()
        .set_password(
            stellar_strkey::ed25519::PrivateKey(FUNDER_SEED)
                .as_unredacted()
                .to_string()
                .as_str(),
        )
        .unwrap();
        crate::common::identity_fixture::store_signer_identity_of_seed(NAME, &profile, FUNDER_SEED);
        KeyringEntry::new(
            &profile.audit_log_hash_chain_key_id.service,
            &profile.audit_log_hash_chain_key_id.account,
        )
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
        .unwrap();
        let mut args = PoolInitArgs {
            size: Some(2),
            profile: Some(NAME.to_owned()),
            force: false,
            resume: false,
            timeout_seconds: 5,
            output: OutputFormat::Json,
        };

        let (created, built) = crate::test_rpc::clients_built_by(execute(&args, || Ok(()))).await;
        created.expect("the fresh initialization completes");
        let methods = crate::test_rpc::methods(&server).await;
        assert_eq!(built, 1, "one client reads and sends: {methods:?}");
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 2, "{methods:?}");
        assert!(
            methods.iter().any(|m| m == "sendTransaction"),
            "{methods:?}"
        );

        args.size = None;
        args.resume = true;
        let (resumed, built) = crate::test_rpc::clients_built_by(execute(&args, || Ok(()))).await;
        let resumed = resumed.expect("a completed pool resumes from the profile");
        assert_eq!(resumed["initialised"], true, "{resumed}");
        assert_eq!(built, 0, "a completed resume builds no client");
        assert_eq!(
            crate::test_rpc::methods(&server).await.len(),
            methods.len(),
            "a completed resume makes no request"
        );
    }

    /// Source-scan companion to the env-immunity test above: `run()`'s
    /// persistence step uses raw-document patches so environment overlays remain transient. This
    /// also pins the production call site. The production half of this
    /// module must persist through the raw-document patch
    /// (`loader::set_pool_state`) and must not contain a full-profile
    /// `loader::save`, whose load-merge-save shape would write the env-merged
    /// view into the trust root.
    #[test]
    fn production_persistence_call_site_is_the_raw_document_patch() {
        let source = include_str!("init.rs");
        let (production, _tests) = source
            .split_once("#[cfg(test)]")
            .expect("this module must contain a #[cfg(test)] marker");

        assert!(
            production.contains("loader::set_pool_state("),
            "pool init must persist via the raw-document patch loader::set_pool_state"
        );
        assert!(
            !production.contains("loader::save("),
            "pool init must not persist via loader::save: re-saving a loaded \
             profile writes the env-merged view into the profile TOML"
        );
    }

    /// A fee per operation that overflows the transaction fee is refused
    /// with the fixed text, on the pool error and on the wallet error it maps
    /// to, and stays out of the events of the check.
    #[test]
    fn overflowing_fee_stays_out_of_the_refusal() {
        use stellar_agent_test_support::rejected_value::{
            assert_no_marker, assert_no_marker_in_text,
        };

        const OVERFLOWING_FEE: &str = "4294967295";
        let produced = total_init_fee(u32::MAX, 1).unwrap_err();
        assert_no_marker(&produced, OVERFLOWING_FEE);
        let profile = Profile::builder_testnet_named("pool-fee-test", "s", "a", "n", "a")
            .with_noop_engine()
            .build();
        let mut mapped = None;
        let logs = stellar_agent_test_support::log_capture::with_captured_trace_logs(|| {
            mapped = precheck_init_fee(u32::MAX, 1, &profile, "pool-fee-test").err();
        });
        let mapped = mapped.expect("the fee overflows");
        assert_eq!(mapped.code(), "validation.fee_total_overflow");
        assert_eq!(
            mapped.to_string(),
            "classic_fee_per_op_stroops multiplied by the operation count must fit in u32; lower \
             classic_fee_per_op_stroops."
        );
        assert_no_marker(&mapped, OVERFLOWING_FEE);
        assert_no_marker_in_text(&logs, OVERFLOWING_FEE);
    }

    #[test]
    fn fee_overflow_maps_to_validation() {
        let error = map_init_error(PoolError::FeeOverflow { op_count: 3 }, "pool-fee-test");
        assert_eq!(error.code(), "validation.fee_total_overflow");
        assert_eq!(
            error.to_string(),
            "classic_fee_per_op_stroops multiplied by the operation count must fit in u32; lower \
             classic_fee_per_op_stroops."
        );
    }
    #[test]
    fn pool_result_omits_an_absent_witness_and_reads_legacy_json() {
        let legacy = serde_json::json!({
            "profile": "pool-json", "channel_count": 0, "tx_hash_redacted": null,
            "ledger": 1001, "channels": [], "funder_redacted": "funder",
            "pool_master_keyring_service": "pool-json", "pool_master_keyring_account": "master"
        });
        let result: PoolInitResult = serde_json::from_value(legacy).unwrap();
        assert!(result.cross_check.is_none());
        assert!(
            serde_json::to_value(result)
                .unwrap()
                .get("cross_check")
                .is_none()
        );
    }

    #[test]
    fn pool_fee_precheck_caps_before_checking_total() {
        let mut profile = Profile::builder_testnet("fee", "default", "nonce", "default")
            .with_noop_engine()
            .build();
        profile.classic_max_fee_per_op_stroops = Some(100);
        let error = precheck_init_fee(u32::MAX, 2, &profile, "fee").unwrap_err();
        assert_eq!(error.code(), "fees.percentile_exceeds_cap");
        assert!(
            error
                .to_string()
                .contains("classic_fee_per_op_stroops must not exceed")
        );
        profile.classic_max_fee_per_op_stroops = None;
        let error = precheck_init_fee(u32::MAX, 2, &profile, "fee").unwrap_err();
        assert_eq!(error.code(), "validation.fee_total_overflow");
    }

    mod witness {
        use super::*;
        use crate::test_rpc::{
            ACCOUNT_SEQUENCE, ClassicRpc, account_key, account_xdr,
            assert_pending_row_carries_witness, methods, sent,
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use stellar_agent_test_support::keyring_mock::{ReadHook, install_with_read_hooks};

        /// Answers as `oracle` and, before each answer, records every way the
        /// persisted state contradicts a completed seed recovery. The saved
        /// checkpoint must mark the seed ready and the keyring must hold the
        /// seed. No signer read may have happened yet.
        struct RecoveredBeforeWitness {
            oracle: ClassicRpc,
            name: String,
            profile_path: std::path::PathBuf,
            master: KeyringEntryRef,
            signer_reads: Arc<AtomicUsize>,
            violations: Arc<Mutex<Vec<String>>>,
        }

        impl wiremock::Respond for RecoveredBeforeWitness {
            fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
                let saved = loader::load_from_path(&self.name, &self.profile_path, None).unwrap();
                let mut violations = self.violations.lock().unwrap();
                if !saved
                    .pool_initialization
                    .is_some_and(|pending| pending.seed_ready)
                {
                    violations.push("the checkpoint does not mark the seed ready".to_owned());
                }
                if KeyringEntry::new(&self.master.service, &self.master.account)
                    .and_then(|entry| entry.get_password())
                    .is_err()
                {
                    violations.push("the keyring holds no pool seed".to_owned());
                }
                if self.signer_reads.load(Ordering::SeqCst) != 0 {
                    violations.push("the signer was read before the witness".to_owned());
                }
                drop(violations);
                self.oracle.respond(request)
            }
        }

        #[derive(Debug)]
        enum Case {
            Pass,
            FreshDivergence,
            RetryDivergence,
            Channel,
            Unavailable,
            Invalid,
            Skipped,
            Cap,
            Overflow,
            RetryCap,
            IncompleteSeed,
            Complete,
            Present,
        }

        async fn exercise(case: Case) {
            let dir = tempfile::tempdir().unwrap();
            let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
            let _env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
            let name = format!("pool-witness-{case:?}").to_ascii_lowercase();
            let funder =
                stellar_agent_test_support::signed_envelope::account_id_for_seed([0x91; 32]);
            let seed = Zeroizing::new([0x24; 64]);
            let channel_records = channels(&seed, 2).unwrap();
            let mut primary_rpc = ClassicRpc::testnet(&[&funder]);
            if matches!(case, Case::Present) {
                for channel in &channel_records {
                    primary_rpc = primary_rpc.with_entry(
                        account_key(&channel.public_key),
                        account_xdr(&channel.public_key, 0, 0, ""),
                    );
                }
            }
            let primary = primary_rpc.serve().await;
            let mut oracle_rpc = ClassicRpc::testnet(&[]).with_entry(
                account_key(&funder),
                account_xdr(
                    &funder,
                    if matches!(case, Case::FreshDivergence | Case::RetryDivergence) {
                        ACCOUNT_SEQUENCE + 9
                    } else {
                        ACCOUNT_SEQUENCE
                    },
                    0,
                    "",
                ),
            );
            if matches!(case, Case::Channel) {
                let channel = &channel_records[0].public_key;
                oracle_rpc =
                    oracle_rpc.with_entry(account_key(channel), account_xdr(channel, 0, 0, ""));
            }
            if matches!(case, Case::Unavailable) {
                oracle_rpc.report(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE);
            }
            let oracle = oracle_rpc.serve().await;
            let mut profile = Profile::builder_testnet_named(
                &name,
                "pool-witness-signer",
                &funder,
                "pool-witness-nonce",
                &name,
            )
            .with_noop_engine()
            .rpc_url(primary.uri())
            .audit_log_path(dir.path().join("audit.jsonl"))
            .oracle_provider_url(Some(url::Url::parse(&oracle.uri()).unwrap()))
            .build();
            if matches!(case, Case::Skipped) {
                profile.oracle_provider_url = None;
            }
            if matches!(case, Case::Invalid) {
                // The profile loader accepts this URL; the RPC transport
                // refuses a URI longer than 65 534 bytes, so the oracle client
                // cannot be built.
                let long = format!("http://oracle.test/{}", "a".repeat(65_535));
                profile.oracle_provider_url = Some(url::Url::parse(&long).unwrap());
            }
            if matches!(
                case,
                Case::Cap | Case::RetryCap | Case::Complete | Case::Present
            ) {
                profile.classic_max_fee_per_op_stroops = Some(99);
            }
            if matches!(case, Case::Overflow | Case::Complete | Case::Present) {
                profile.classic_fee_per_op_stroops = Some(u32::MAX);
            }
            let resumed = matches!(
                case,
                Case::RetryDivergence
                    | Case::RetryCap
                    | Case::Channel
                    | Case::IncompleteSeed
                    | Case::Complete
                    | Case::Present
            );
            let master = KeyringEntryRef::default_pool_master_key(&name);
            if resumed {
                profile.pool_initialization = Some(PoolInitialization {
                    id: format!("{name}-initialization"),
                    network_passphrase: profile.network_passphrase.clone(),
                    funder: funder.clone(),
                    channels: channel_records,
                    seed_ready: !matches!(case, Case::IncompleteSeed),
                    attempt: 0,
                    completion_ledger: matches!(case, Case::Complete).then_some(1001),
                    submission: matches!(case, Case::RetryDivergence | Case::RetryCap).then(|| {
                        PoolInitSubmission {
                            envelope_hash: "ab".repeat(32),
                            tx_hash: "cd".repeat(32),
                            sequence: 1,
                            send_started: false,
                        }
                    }),
                });
                profile.pool_master_key_id = Some(master.clone());
            }
            loader::save_to_dir(&name, &profile, &dir.path().join("profiles")).unwrap();
            let reads = Arc::new(AtomicUsize::new(0));
            let count = reads.clone();
            let profile_path = dir.path().join(format!("profiles/{name}.toml"));
            let recovery_path = profile_path.clone();
            let recovery_name = name.clone();
            let incomplete = matches!(case, Case::IncompleteSeed);
            install_with_read_hooks(vec![ReadHook::new(
                &profile.mcp_signer_default.service,
                &profile.mcp_signer_default.account,
                Arc::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    if incomplete {
                        let saved =
                            loader::load_from_path(&recovery_name, &recovery_path, None).unwrap();
                        assert!(saved.pool_initialization.unwrap().seed_ready);
                    }
                }),
            )])
            .unwrap();
            KeyringEntry::new(
                &profile.audit_log_hash_chain_key_id.service,
                &profile.audit_log_hash_chain_key_id.account,
            )
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();
            if !matches!(
                case,
                Case::Cap
                    | Case::Overflow
                    | Case::RetryCap
                    | Case::RetryDivergence
                    | Case::Channel
                    | Case::Complete
                    | Case::Present
            ) {
                KeyringEntry::new(
                    &profile.mcp_signer_default.service,
                    &profile.mcp_signer_default.account,
                )
                .unwrap()
                .set_password(
                    stellar_strkey::ed25519::PrivateKey([0x91; 32])
                        .as_unredacted()
                        .to_string()
                        .as_str(),
                )
                .unwrap();
                crate::common::identity_fixture::store_signer_identity_of_seed(
                    &name, &profile, [0x91; 32],
                );
            }
            if resumed {
                KeyringEntry::new(&master.service, &master.account)
                    .unwrap()
                    .set_password(&URL_SAFE_NO_PAD.encode(seed.as_ref()))
                    .unwrap();
            }
            let mut args = PoolInitArgs {
                profile: Some(name.clone()),
                size: if resumed { None } else { Some(2) },
                resume: resumed,
                force: false,
                timeout_seconds: 5,
                output: OutputFormat::Json,
            };
            let violations = Arc::new(Mutex::new(Vec::new()));
            if incomplete {
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .respond_with(RecoveredBeforeWitness {
                        oracle: oracle_rpc.clone(),
                        name: name.clone(),
                        profile_path: profile_path.clone(),
                        master: master.clone(),
                        signer_reads: reads.clone(),
                        violations: violations.clone(),
                    })
                    .with_priority(1)
                    .mount(&oracle)
                    .await;
            }
            let rc = run_with_dependencies(&args, || Ok(())).await;
            let value = crate::test_rpc::last_rendered();
            if incomplete {
                assert!(
                    methods(&oracle)
                        .await
                        .contains(&"getLedgerEntries".to_owned()),
                    "the witness read the oracle"
                );
                assert_eq!(*violations.lock().unwrap(), Vec::<String>::new());
            }
            let saved = loader::load_from_path(&name, &profile_path, None).unwrap();
            let refusal = match case {
                Case::FreshDivergence | Case::RetryDivergence | Case::Channel => {
                    Some("simulation.divergence")
                }
                Case::Unavailable | Case::Invalid => Some("network.witness_unavailable"),
                Case::Cap | Case::RetryCap => Some("fees.percentile_exceeds_cap"),
                Case::Overflow => Some("validation.fee_total_overflow"),
                _ => None,
            };
            if let Some(code) = refusal {
                assert_eq!(rc, 1, "{value}");
                assert_eq!(value["error"]["code"], code, "{value}");
                assert!(!sent(&primary).await);
                let message = value["error"]["message"].as_str().unwrap();
                if matches!(case, Case::FreshDivergence | Case::RetryDivergence) {
                    assert!(
                        message.contains("funder account sequence (sequence delta 9)"),
                        "{message}"
                    );
                }
                if matches!(case, Case::Channel) {
                    assert!(
                        message.contains("pool channel account existence"),
                        "{message}"
                    );
                }
                if matches!(case, Case::Invalid) {
                    assert!(message.contains("could not be built"), "{message}");
                }
                let expected_reads = usize::from(matches!(
                    case,
                    Case::FreshDivergence | Case::Unavailable | Case::Invalid
                ));
                assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
                if matches!(case, Case::Cap | Case::Overflow) {
                    assert!(saved.pool_initialization.is_none());
                    assert!(methods(&oracle).await.is_empty());
                } else {
                    let pending = saved.pool_initialization.as_ref().unwrap();
                    assert!(
                        value["error"]["details"]["resume_with"]
                            .as_str()
                            .unwrap()
                            .contains("pool init --resume")
                    );
                    if matches!(case, Case::RetryDivergence) {
                        assert_eq!(pending.attempt, 1);
                        assert!(pending.submission.is_none());
                    }
                    if matches!(case, Case::RetryCap) {
                        assert_eq!(pending.attempt, 0);
                        assert!(pending.submission.is_some());
                        assert!(methods(&oracle).await.is_empty());
                    }
                }
                if matches!(case, Case::FreshDivergence) {
                    let mut capped = saved.clone();
                    capped.classic_max_fee_per_op_stroops = Some(99);
                    loader::save_to_dir(&name, &capped, &dir.path().join("profiles")).unwrap();
                    args.resume = true;
                    args.size = None;
                    reads.store(0, Ordering::SeqCst);
                    let requests = methods(&oracle).await.len();
                    let error = execute(&args, || Ok(())).await.unwrap_err();
                    assert_eq!(error.code(), "fees.percentile_exceeds_cap");
                    assert_eq!(reads.load(Ordering::SeqCst), 0);
                    assert_eq!(methods(&oracle).await.len(), requests);
                    loader::save_to_dir(&name, &saved, &dir.path().join("profiles")).unwrap();
                    oracle.reset().await;
                    wiremock::Mock::given(wiremock::matchers::method("POST"))
                        .respond_with(ClassicRpc::testnet(&[&funder]))
                        .mount(&oracle)
                        .await;
                    let result = execute(&args, || Ok(())).await.unwrap();
                    assert_eq!(result["cross_check"]["status"], "passed");
                    // The resume loads the signer after the witness and reads
                    // it again to sign.
                    assert_eq!(reads.load(Ordering::SeqCst), 2);
                    assert_eq!(methods(&oracle).await, ["getNetwork", "getLedgerEntries"]);
                }
            } else {
                assert_eq!(rc, 0, "{value}");
                assert!(saved.pool_initialization.is_none());
                if matches!(case, Case::Complete | Case::Present) {
                    assert!(value["data"].get("cross_check").is_none());
                    assert!(methods(&oracle).await.is_empty());
                    assert_eq!(reads.load(Ordering::SeqCst), 0);
                    assert!(!sent(&primary).await);
                } else {
                    assert_eq!(
                        value["data"]["cross_check"]["status"],
                        if matches!(case, Case::Skipped) {
                            "skipped"
                        } else {
                            "passed"
                        }
                    );
                    if !matches!(case, Case::Skipped) {
                        assert_pending_row_carries_witness(&profile, &oracle.uri());
                    }
                    // A resume loads the signer after the witness and reads
                    // it again to sign. The fresh path also loads it once
                    // before the checkpoint as the funder identity.
                    assert_eq!(reads.load(Ordering::SeqCst), if resumed { 2 } else { 3 });
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn pool_send_records_witness_and_rows() {
            exercise(Case::Pass).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn fresh_divergence_is_resumable_and_rechecks_cap_and_witness() {
            exercise(Case::FreshDivergence).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn retry_divergence_retires_attempt_without_loading_signer() {
            exercise(Case::RetryDivergence).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn oracle_channel_presence_refuses() {
            exercise(Case::Channel).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn unavailable_pool_oracle_precedes_send_signer() {
            exercise(Case::Unavailable).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn invalid_pool_oracle_precedes_send_signer() {
            exercise(Case::Invalid).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn missing_pool_oracle_reports_skipped() {
            exercise(Case::Skipped).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn fresh_cap_refuses_before_signer_and_checkpoint() {
            exercise(Case::Cap).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn fresh_overflow_refuses_before_signer_and_checkpoint() {
            exercise(Case::Overflow).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn retry_cap_preserves_attempt() {
            exercise(Case::RetryCap).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn incomplete_seed_recovers_before_witness_and_signer() {
            exercise(Case::IncompleteSeed).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn completed_resume_has_no_cap_or_witness() {
            exercise(Case::Complete).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn present_channels_complete_without_cap_or_witness() {
            exercise(Case::Present).await;
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn policy_pin_coordinate_refuses_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let name = "pin-refusal";
        let coordinate = KeyringEntryRef::new("custom", "default-PoLiCy-PiN");
        for initial in [None, Some("untouched")] {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let entry = KeyringEntry::new(&coordinate.service, &coordinate.account).unwrap();
            if let Some(value) = initial {
                entry.set_password(value).unwrap();
            }
            let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
            profile.pool_master_key_id = Some(coordinate.clone());
            loader::save_to_dir(name, &profile, &dir.path().join("profiles")).unwrap();
            let args = PoolInitArgs {
                size: Some(2),
                profile: Some(name.to_owned()),
                force: true,
                resume: false,
                timeout_seconds: 5,
                output: OutputFormat::Json,
            };
            let calls = std::cell::Cell::new(0);
            let error = execute(&args, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .await
            .unwrap_err();
            assert_eq!(error.code(), "validation.policy_pin_coordinate");
            assert_eq!(calls.get(), 0);
            assert_eq!(entry.get_password().ok().as_deref(), initial);
        }
    }

    /// Pool initialization refuses an installation coordinate before opening keys.
    #[tokio::test]
    #[serial_test::serial]
    async fn installation_coordinate_refuses_without_writing() {
        use crate::common::installation_key_fixture::InstallationKeyFixture;
        let fixture = InstallationKeyFixture::new("stellar-agent-toolsets");
        let name = "pin-coordinate-refusal";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.pool_master_key_id = Some(fixture.coordinate.clone());
        loader::save_to_dir(name, &profile, &fixture.home().join("profiles")).unwrap();
        let args = PoolInitArgs {
            size: Some(2),
            profile: Some(name.to_owned()),
            force: true,
            resume: false,
            timeout_seconds: 5,
            output: OutputFormat::Json,
        };
        let error = execute(&args, || fixture.init()).await.unwrap_err();
        assert_eq!(error.code(), "validation.installation_key_coordinate");
        fixture.assert_refused(1);
    }
}
