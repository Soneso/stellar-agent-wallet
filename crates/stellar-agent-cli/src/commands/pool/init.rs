//! Sponsored channel creation with a durable seed and public recovery checkpoints.
//!
//! The profile records channel identities before the keyring seed is written.
//! The seed is durable before the submission can leave. A pending lifecycle
//! excludes replacement; `pool init --resume` completes it using the same keys.
//! An attempt whose outcome is recorded as unknown is retried only after an
//! operator acknowledges it through `tx receipt clear --acknowledge`.
//! Only the pool keys in the stored profile are patched, so runtime environment
//! overlays remain transient. The profile contains no signing material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use std::{
    fs::{File, OpenOptions},
    sync::Mutex,
    time::Duration,
};
use stellar_agent_core::audit_log::{entry::AuditEntry, reader::AuditReader};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{
    AuthError, InternalError, NetworkError, SubmissionError, WalletError,
};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PoolChannelRecord, PoolConfig, PoolInitSubmission, PoolInitialization, Profile,
};
use stellar_agent_core::profile::{
    loader,
    receipt::{ReceiptStatus, ReceiptStore},
};
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, fetch_account, keyring::signer_from_keyring,
};
use stellar_agent_pool::{
    PoolError,
    derive::{derive_channel_signer, load_pool_master_seed_from_keyring},
    init::{InitParams, init_pool},
};
use stellar_agent_sep5::Sep5Wallet;
use zeroize::Zeroizing;

use crate::commands::submission_record::{SubmitRecord, build_recorder, write_settled_row};
use crate::common::profile_access::load_profile_reconciled;
use crate::common::{render::render_json, resolve_profile_name};

/// Default confirmation deadline for the creation transaction, in seconds.
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
    /// Confirmation deadline for the creation transaction, in seconds.
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

/// Serialises seed replacement, recovery and completion across processes.
fn lifecycle_lock(name: &str) -> Result<File, WalletError> {
    let dir = loader::default_profile_dir().map_err(|error| unavailable(error.to_string()))?;
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
    file.try_lock()
        .map_err(|_| unavailable("another pool initialization is running"))?;
    Ok(file)
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
        return Err(pool_err_to_wallet_err(&PoolError::SizeOutOfRange {
            requested: size,
        }));
    }
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(**seed));
    (1..=size as u32)
        .map(|index| {
            wallet
                .derive_account(index)
                .map(|key| PoolChannelRecord::new(index, key.public_key_strkey()))
                .map_err(|error| pool_err_to_wallet_err(&PoolError::from(error)))
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
            KeyringProbe::BackendError(error) => {
                return Err(classify_probe_backend_error(&error, master));
            }
        },
    };
    pending.channels = channels(&seed, pending.channels.len())?;
    persist(name, master, pending)?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(seed.as_ref()));
    KeyringEntry::new(&master.service, &master.account)
        .and_then(|entry| entry.set_password(&encoded))
        .map_err(|error| {
            classify_pool_seed_write_failure(&error, master, "keyring write failed")
        })?;
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
    match execute(args).await {
        Ok(value) => {
            render_json(&Envelope::ok(value));
            0
        }
        Err(error) => {
            render_json(&Envelope::<()>::err(&error));
            1
        }
    }
}

async fn execute(args: &PoolInitArgs) -> Result<serde_json::Value, WalletError> {
    if let Some(size) = args.size
        && !(1..=stellar_agent_pool::ChannelPool::MAX_SIZE).contains(&size)
    {
        return Err(pool_err_to_wallet_err(&PoolError::SizeOutOfRange {
            requested: size,
        }));
    }
    let resolved = resolve_profile_name(args.profile.as_deref());
    // Validate the name and existing profile before constructing the sidecar path.
    load_profile_reconciled(&resolved, None)
        .map_err(|error| error.to_wallet_error(&resolved.name))?;
    let _lock = lifecycle_lock(&resolved.name)?;
    let profile = load_profile_reconciled(&resolved, None)
        .map_err(|error| error.to_wallet_error(&resolved.name))?;
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
    stellar_agent_network::keyring::init_platform_keyring_store()?;
    let audit = crate::commands::value_audit::require_value_audit_writer(&profile, name)?;
    let master = profile
        .pool_master_key_id
        .clone()
        .unwrap_or_else(|| KeyringEntryRef::default_pool_master_key(name));
    let (mut pending, generated) = match profile.pool_initialization.clone() {
        Some(pending) => (pending, None),
        None => {
            match probe_keyring_entry(&master.service, &master.account) {
                KeyringProbe::Present if !args.force => {
                    return Err(pool_err_to_wallet_err(&PoolError::AlreadyInitialised));
                }
                KeyringProbe::BackendError(error) => {
                    return Err(classify_probe_backend_error(&error, &master));
                }
                _ => {}
            }
            let signer = signer_from_keyring(
                &profile.mcp_signer_default,
                &profile.mcp_signer_default.account,
            )
            .await?;
            let seed = fresh_seed();
            let size = args
                .size
                .ok_or_else(|| unavailable("pool size is required"))?;
            let pending = PoolInitialization {
                id: uuid::Uuid::new_v4().to_string(),
                network_passphrase: profile.network_passphrase.clone(),
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
    if pending.network_passphrase != profile.network_passphrase {
        return Err(unavailable(
            "the pending pool belongs to a different network",
        ));
    }
    let seed = prepare_seed(name, &master, &mut pending, generated)?;
    if pending.completion_ledger.is_some() {
        return complete(&profile, name, &master, &pending, &audit);
    }
    let client = StellarRpcClient::new(&profile.rpc_url)?;
    client
        .verify_network_passphrase(
            &pending.network_passphrase,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await?;
    let mut present = 0;
    for channel in &pending.channels {
        match fetch_account(&client, &channel.public_key, &[]).await {
            Ok(_) => present += 1,
            Err(WalletError::Network(NetworkError::AccountNotFound { .. })) => {}
            Err(error) => return Err(error),
        }
    }
    let receipts = ReceiptStore::open(name).map_err(|error| unavailable(error.to_string()))?;
    if present == pending.channels.len() {
        let ledger = client.get_health().await?.latest_ledger;
        if ledger == 0 {
            return Err(unavailable("the channel observation has no ledger"));
        }
        // A definitive answer also settles the receipt; account existence can
        // finish configuration when the transaction is outside RPC retention.
        if let Some(submission) = &pending.submission {
            settle_record(&client, &receipts, submission).await?;
            if let Some(receipt) = receipts
                .get(&submission.envelope_hash)
                .map_err(|error| unavailable(error.to_string()))?
            {
                write_settled_row(
                    &profile,
                    name,
                    &audit,
                    &receipt.envelope_hash,
                    &receipt.tx_hash,
                    &receipt.status,
                    receipt.ledger,
                    stellar_agent_core::audit_log::PolicyDecision::Allow,
                );
            }
        }
        pending.completion_ledger = Some(ledger);
        persist(name, &master, &pending)?;
        return complete(&profile, name, &master, &pending, &audit);
    }
    if present != 0 {
        return Ok(pending_data(name, &pending));
    }
    if let Some(submission) = &pending.submission {
        let status = if submission.send_started {
            settle_record(&client, &receipts, submission).await?
        } else {
            // The durable barrier proves that no bytes left for this receipt.
            if let Some(receipt) = receipts
                .get(&submission.envelope_hash)
                .map_err(|error| unavailable(error.to_string()))?
            {
                if receipt.status == ReceiptStatus::Success {
                    return Err(unavailable("an unsent checkpoint has a successful receipt"));
                }
                receipts
                    .finalize(
                        &submission.envelope_hash,
                        ReceiptStatus::Failed {
                            code: "submission.not_transmitted".to_owned(),
                        },
                        None,
                    )
                    .map_err(|error| unavailable(error.to_string()))?;
            }
            Some(ReceiptStatus::Failed {
                code: "submission.not_transmitted".to_owned(),
            })
        };
        // No channel account exists at this point, so a fresh envelope cannot
        // create one twice. Two records permit it. A definitive failure is one.
        // The other is the operator's acknowledgement through
        // `tx receipt clear --acknowledge`, which states that the transaction
        // did not apply and which that verb writes only after the endpoint
        // declines to report the transaction as successful or failed. An
        // outcome recorded as merely unknown is not that statement: it is the
        // state where a second envelope could create the channels a second
        // time, so it holds the checkpoint until an operator resolves it.
        let Some(ReceiptStatus::Failed { .. } | ReceiptStatus::ClearedByOperator) = status else {
            return Ok(pending_data(name, &pending));
        };
        if let Some(receipt) = receipts
            .get(&submission.envelope_hash)
            .map_err(|error| unavailable(error.to_string()))?
        {
            write_settled_row(
                &profile,
                name,
                &audit,
                &receipt.envelope_hash,
                &receipt.tx_hash,
                &receipt.status,
                receipt.ledger,
                stellar_agent_core::audit_log::PolicyDecision::Allow,
            );
        }
        pending.attempt = pending
            .attempt
            .checked_add(1)
            .ok_or_else(|| unavailable("pool attempt counter overflow"))?;
        pending.submission = None;
        persist(name, &master, &pending)?;
    }
    let signer = signer_from_keyring(
        &profile.mcp_signer_default,
        &profile.mcp_signer_default.account,
    )
    .await?;
    if signer.public_key().to_string().as_str() != pending.funder {
        return Err(unavailable(
            "the profile signer is not the recorded pool funder",
        ));
    }
    let funder = fetch_account(&client, &pending.funder, &[]).await?;
    let inner = build_recorder(SubmitRecord {
        policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
        profile: &profile,
        profile_name: name.clone(),
        verb: "pool init",
        tool: "pool init",
        chain_id: profile.chain_id.caip2_str(),
        effects: None,
        audit: Some(audit.clone()),
        now_ms: stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|error| unavailable(error.to_string()))?,
    })?;
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
            derive_channel_signer(Zeroizing::new(*seed), channel.index)
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
            network_passphrase: &pending.network_passphrase,
            fee_per_op: profile
                .classic_fee_per_op_stroops
                .unwrap_or(stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS),
            recorder: &recorder,
            attempt: pending.attempt,
            timeout: std::time::Duration::from_secs(args.timeout_seconds),
        },
    )
    .await
    .map_err(|error| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("{error}; run 'stellar-agent pool init --resume --profile {name}'"),
        })
    })?;
    pending = recorder
        .pending
        .into_inner()
        .map_err(|_| unavailable("pool checkpoint mutex is poisoned"))?;
    pending.completion_ledger = Some(result.ledger);
    persist(name, &master, &pending)?;
    complete(&profile, name, &master, &pending, &audit)
}

async fn settle_record(
    client: &StellarRpcClient,
    receipts: &ReceiptStore,
    submission: &PoolInitSubmission,
) -> Result<Option<ReceiptStatus>, WalletError> {
    if receipts
        .get(&submission.envelope_hash)
        .map_err(|error| unavailable(error.to_string()))?
        .is_none()
    {
        return Err(unavailable(
            "the pending pool receipt is missing; restore it before resuming",
        ));
    }
    let answer = client.get_transaction_status(&submission.tx_hash).await?;
    let status = match answer.status.as_str() {
        "SUCCESS" => Some(ReceiptStatus::Success),
        "FAILED" => Some(ReceiptStatus::Failed {
            code: "ledger.op_failed".to_owned(),
        }),
        _ => None,
    };
    if let Some(status) = status {
        receipts
            .finalize(&submission.envelope_hash, status, answer.ledger)
            .map_err(|error| unavailable(error.to_string()))?;
    }
    Ok(receipts
        .get(&submission.envelope_hash)
        .map_err(|error| unavailable(error.to_string()))?
        .map(|receipt| receipt.status))
}

fn complete(
    profile: &Profile,
    name: &str,
    master: &KeyringEntryRef,
    pending: &PoolInitialization,
    audit: &stellar_agent_network::submission_record::AuditWriterHandle,
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
    let key =
        stellar_agent_network::keyring::load_hmac_key_32(&profile.audit_log_hash_chain_key_id)?;
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
    /// The keyring backend returned an error other than `NoEntry`; presence
    /// is ambiguous. Carries the typed error so the refusal site can
    /// classify environmental causes (a non-interactive Windows session)
    /// instead of reporting a generic backend failure.
    BackendError(keyring_core::Error),
}

/// Probes whether a keyring entry exists, distinguishing `NoEntry` from backend
/// errors.
///
/// Only `keyring_core::Error::NoEntry` is treated as
/// "definitely absent".  All other errors are returned as `BackendError`.
fn probe_keyring_entry(service: &str, account: &str) -> KeyringProbe {
    let entry = match KeyringEntry::new(service, account) {
        Ok(e) => e,
        Err(e) => {
            return KeyringProbe::BackendError(e);
        }
    };
    match entry.get_password() {
        Ok(_) => KeyringProbe::Present,
        Err(keyring_core::Error::NoEntry) => KeyringProbe::Absent,
        Err(e) => KeyringProbe::BackendError(e),
    }
}

/// Classifies an ambiguous existence-probe failure for the pool master
/// coordinate.
///
/// Environmental causes keep their typed classification — most notably a
/// non-interactive Windows session, which surfaces as
/// `auth.keyring_interactive_session_required`. Only when the classification
/// falls back to the generic not-found shape does the error carry the
/// cannot-determine-existence guidance that explains why the probe refuses
/// even with `--force`.
fn classify_probe_backend_error(
    e: &keyring_core::Error,
    pool_master_ref: &KeyringEntryRef,
) -> WalletError {
    match stellar_agent_network::keyring::map_keyring_error(e, &pool_master_ref.service) {
        WalletError::Auth(AuthError::KeyringNotFound { .. }) => {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!(
                    "{}:{} (keyring backend error — cannot determine existence)",
                    pool_master_ref.service, pool_master_ref.account
                ),
            })
        }
        classified => classified,
    }
}

/// Preserves the keyring error classification and names the completion command.
fn classify_pool_seed_write_failure(
    e: &keyring_core::Error,
    pool_master_ref: &KeyringEntryRef,
    phase: &str,
) -> WalletError {
    match stellar_agent_network::keyring::map_keyring_error(e, &pool_master_ref.service) {
        WalletError::Auth(AuthError::KeyringNotFound { .. }) => {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!(
                    "{}:{} (seed persistence pending; {phase}; \
                     re-run with --resume)",
                    pool_master_ref.service, pool_master_ref.account
                ),
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
            classify_probe_backend_error(&e, &r).code(),
            "auth.keyring_interactive_session_required"
        );
        assert_eq!(
            classify_pool_seed_write_failure(&e, &r, "keyring write failed").code(),
            "auth.keyring_interactive_session_required"
        );
    }

    /// Failures that classify to the generic not-found shape keep the
    /// pool-specific operator guidance: the probe refusal explains the
    /// cannot-determine-existence stance, and the seed write
    /// failure carries the completion instruction.
    #[test]
    fn pool_keyring_generic_failures_keep_operator_guidance() {
        let r = KeyringEntryRef::new("stellar-agent-pool-classify", "master");
        let e = keyring_core::Error::NoEntry;

        let probe = classify_probe_backend_error(&e, &r);
        assert_eq!(probe.code(), "auth.keyring_not_found");
        assert!(
            probe.message().contains("cannot determine existence"),
            "probe guidance lost: {}",
            probe.message()
        );

        let write = classify_pool_seed_write_failure(&e, &r, "keyring write failed");
        assert_eq!(write.code(), "auth.keyring_not_found");
        assert!(
            write.message().contains("seed persistence pending")
                && write.message().contains("re-run with --resume"),
            "write guidance lost: {}",
            write.message()
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
}
