//! `stellar-agent pool init` subcommand.
//!
//! Builds and submits the CAP-33 sponsored-reserve sandwich to create N channel
//! accounts on-chain.  The pool master 64-byte seed is held in memory for the
//! duration of the init flow, then written to the OS keyring ONLY AFTER the
//! on-chain transaction confirms.  The public pool bookkeeping (`PoolConfig`) is
//! persisted into the profile TOML immediately after the keyring write.  A
//! failure before on-chain confirmation leaves NO keyring entry and NO config —
//! clean retry with no `--force` needed.
//!
//! # Persistence discipline
//!
//! The profile TOML is a trust root: the persistence step patches ONLY the two
//! pool keys (`pool_master_key_id`, `[pool_config]`) on the raw on-disk
//! document via `loader::set_pool_state`.  The env-merged profile view loaded
//! at the start of the run is used for runtime decisions only (RPC endpoint,
//! signer, fees, audit paths) and is never written back: a `STELLAR_AGENT_*`
//! overlay present during the one-time init must not become persistent
//! configuration, and loader-derived defaults must not be materialised into
//! the stored document.
//!
//! # Secret handling
//!
//! - The pool master 64-byte seed lives ONLY in the OS keyring (URL-safe
//!   base64, no padding — same encoding as `profile/key_ops.rs` rotate helpers).
//! - Channel private keys are NEVER persisted; re-derived on demand from the
//!   keyring master at `m/44'/148'/<index>'` via `stellar-agent-sep5`.
//! - The init result JSON contains: funder (redacted), channel G-strkeys
//!   (public), channel_count, tx_hash (redacted), ledger.  NO seed bytes.
//!
//! # Ordering invariant
//!
//! The execution sequence is strictly:
//! 1. Generate seed (in memory, `Zeroizing`).
//! 2. Derive channels + build + submit the sandwich transaction.
//! 3. On-chain confirmation received.
//! 4. Write seed to OS keyring.
//! 5. Persist `PoolConfig` to profile TOML.
//!
//! Steps 4 and 5 are performed only after step 3 completes.  A failure at any
//! step before confirmation leaves no keyring entry and no config — clean retry
//! without `--force`.
//!
//! # --force guard
//!
//! If a pool master key already exists in the keyring for this profile,
//! `pool init` refuses with `pool.already_initialised` unless `--force` is
//! passed.  Overwriting the master orphans all previously funded channels
//! (whether or not a `pool_config` entry exists).
//!
//! The existence probe distinguishes `keyring::NotFound` (definitely absent)
//! from backend errors (ambiguous) — only `NotFound` is treated as absent.
//! An ambiguous backend error refuses even without `--force` to avoid silently
//! overwriting a key that may exist but be temporarily unreadable.
//!
//! # Size guard
//!
//! `--size 0` and `--size > ChannelPool::MAX_SIZE` (currently 19) are rejected
//! before any network call.  N+1 signatures (funder + each channel) must not
//! exceed the 20-signature `VecM` cap.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriterRegistry;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader::{self, ProfileLoadError};
use stellar_agent_core::profile::schema::{KeyringEntryRef, PoolChannelRecord, PoolConfig};
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, fetch_account, keyring::signer_from_keyring,
};
use stellar_agent_pool::PoolError;
use stellar_agent_pool::derive::derive_channel_signer;
use stellar_agent_pool::init::{InitParams, init_pool};
use stellar_agent_sep5::Sep5Wallet;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::render::render_json;

/// Arguments for `stellar-agent pool init`.
#[derive(Debug, Args)]
pub struct PoolInitArgs {
    /// Number of channel accounts to create (1..=19).
    ///
    /// N+1 signatures (funder + each channel) must fit within the 20-signature
    /// VecM cap on the sandwich envelope (`ChannelPool::MAX_SIZE = 19`).
    #[arg(long, value_name = "N")]
    pub size: usize,

    /// Profile name to use for funder key + RPC URL.
    ///
    /// Defaults to `"default"` when absent.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Overwrite an existing pool master key.
    ///
    /// **WARNING**: orphans all previously funded channel accounts.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Result of a successful `pool init`.
///
/// The pool master seed is NOT included — it lives in the OS keyring.
/// `channels` holds only public G-strkeys and BIP-44 indices.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct PoolInitResult {
    /// Profile the pool was initialised for.
    pub profile: String,
    /// Number of channels created.
    pub channel_count: usize,
    /// Redacted transaction hash (first-8-last-8 hex).
    pub tx_hash_redacted: String,
    /// Network ledger at confirmation.
    pub ledger: u32,
    /// Channel records (BIP-44 index + G-strkey public key).  No secrets.
    pub channels: Vec<PoolChannelRecord>,
    /// Redacted funder G-strkey (first-5-last-5).
    pub funder_redacted: String,
    /// Keyring service name where the pool master seed is stored.
    pub pool_master_keyring_service: String,
    /// Keyring account name for the pool master seed.
    pub pool_master_keyring_account: String,
}

/// Maps a [`PoolError`] into a [`WalletError`] for envelope serialisation.
fn pool_err_to_wallet_err(e: &PoolError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: e.to_string(),
    })
}

/// Runs `stellar-agent pool init`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err`; errors are captured in the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &PoolInitArgs) -> i32 {
    // ── Size guard ────────────────────────────────────────────────────────────
    // Reference ChannelPool::MAX_SIZE so the CLI and pool crate stay in sync
    // without hard-coding 19 in two places.
    if !matches!(
        args.size,
        stellar_agent_pool::pool::ChannelPool::MIN_SIZE
            ..=stellar_agent_pool::pool::ChannelPool::MAX_SIZE
    ) {
        let err = pool_err_to_wallet_err(&PoolError::SizeOutOfRange {
            requested: args.size,
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // ── Load profile ──────────────────────────────────────────────────────────
    let profile_name = args.profile.as_deref().unwrap_or("default");
    let profile = match loader::load(profile_name, None) {
        Ok(p) => p,
        Err(e) => {
            let err = match e {
                ProfileLoadError::NotFound { name, .. } => {
                    WalletError::Validation(ValidationError::ProfileNotFound { name })
                }
                _ => WalletError::Validation(ValidationError::ProfileNotFound {
                    name: profile_name.to_owned(),
                }),
            };
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // ── Initialise platform keyring store ─────────────────────────────────────
    if let Err(e) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    // ── Resolve pool master keyring entry reference ───────────────────────────
    let pool_master_ref = profile
        .pool_master_key_id
        .clone()
        .unwrap_or_else(|| KeyringEntryRef::default_pool_master_key(profile_name));

    // ── Check for existing pool master (--force guard) ────────────────────────
    // Distinguish "definitely absent" (NoEntry) from "backend error" (ambiguous).
    // Only NoEntry is treated as absent.  A backend error refuses regardless of
    // --force: we cannot safely determine whether a key exists or not.
    let existence = probe_keyring_entry(&pool_master_ref.service, &pool_master_ref.account);
    match existence {
        KeyringProbe::Present => {
            if !args.force {
                let err = pool_err_to_wallet_err(&PoolError::AlreadyInitialised);
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
            // --force: proceed to overwrite.
            // WARNING: overwriting the master orphans all previously funded
            // channel accounts (whether or not pool_config is present).
        }
        KeyringProbe::Absent => {
            // Definitely not present; safe to proceed.
        }
        KeyringProbe::BackendError(ref e) => {
            // Cannot determine presence; refuse to proceed rather than risk
            // silently overwriting a key that may exist but be temporarily
            // unreadable.
            tracing::debug!(
                service = %pool_master_ref.service,
                error = %e,
                "pool init: keyring existence probe returned a backend error; \
                 refusing to proceed"
            );
            let err = classify_probe_backend_error(e, &pool_master_ref);
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    }

    // ── Generate pool master seed (in memory only — NOT written yet) ──────────
    // The seed is kept in a Zeroizing wrapper so the stack copy zeroizes on drop.
    // The seed is NEVER written to the keyring or persisted until AFTER on-chain
    // confirmation (custody/ordering invariant).
    // The seed NEVER appears in JSON output, logs, or error messages.
    let mut raw = [0u8; 64];
    OsRng.fill_bytes(&mut raw);
    let seed_zeroizing: Zeroizing<[u8; 64]> = Zeroizing::new(raw);

    // ── Build funder signer ───────────────────────────────────────────────────
    let funder_signer = match signer_from_keyring(
        &profile.mcp_signer_default,
        &profile.mcp_signer_default.account,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // `KeyringSignHandle::public_key()` is the synchronous method (not the
    // async `Signer::public_key`) — no await needed.
    let funder_strkey: String = funder_signer.public_key().to_string().as_str().to_owned();

    // ── Connect to RPC + fetch funder sequence ────────────────────────────────
    let client = match StellarRpcClient::new(&profile.rpc_url) {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let funder_view = match fetch_account(&client, &funder_strkey, &[]).await {
        Ok(v) => v,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    // ── Derive channel keypairs from the pool master seed ─────────────────────
    // Clone the seed into a Zeroizing wrapper for the wallet constructor.
    // Use from_bip39_seed_zeroizing so no bare [u8;64] stack temporary forms.
    // `seed_zeroizing` remains alive for the keyring-store step below.
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(*seed_zeroizing));
    let n = args.size;

    let mut channel_strkeys: Vec<String> = Vec::with_capacity(n);
    let mut channel_signers: Vec<SoftwareSigningKey> = Vec::with_capacity(n);
    let mut channel_indices: Vec<u32> = Vec::with_capacity(n);

    for idx in 1..=(n as u32) {
        let derived: stellar_agent_sep5::DerivedAccount = match wallet.derive_account(idx) {
            Ok(d) => d,
            Err(e) => {
                let err = pool_err_to_wallet_err(&PoolError::from(e));
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        };
        let strkey = derived.public_key_strkey();

        // derive_channel_signer takes a fresh copy of the master seed by value
        // (Zeroizing<[u8;64]> is not Clone, so we copy the inner array).
        let fresh_seed: Zeroizing<[u8; 64]> = Zeroizing::new(*seed_zeroizing);
        let signer = match derive_channel_signer(fresh_seed, idx) {
            Ok(s) => s,
            Err(e) => {
                let err = pool_err_to_wallet_err(&e);
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        };

        channel_strkeys.push(strkey);
        channel_signers.push(signer);
        channel_indices.push(idx);
    }

    // ── Resolve fee per op ────────────────────────────────────────────────────
    let fee_per_op = profile
        .classic_fee_per_op_stroops
        .unwrap_or(stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS);

    // ── Build and submit the CAP-33 sponsored-reserve sandwich ───────────────
    // The seed is still in memory (not yet in keyring).  If this fails, no
    // keyring entry is written and the caller can retry cleanly.
    let params = InitParams {
        funder_strkey: &funder_strkey,
        funder_sequence: funder_view.sequence_number,
        funder_signer: &funder_signer,
        channel_signers,
        channel_strkeys: channel_strkeys.clone(),
        channel_indices: channel_indices.clone(),
        network_passphrase: &profile.network_passphrase,
        fee_per_op,
    };

    let result = match init_pool(&client, params).await {
        Ok(r) => r,
        Err(e) => {
            let err = pool_err_to_wallet_err(&e);
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let redacted_hash = stellar_agent_network::redact_tx_hash(&result.tx_hash);
    let redacted_funder = redact_strkey_first5_last5(&funder_strkey);

    tracing::info!(
        profile = %profile_name,
        funder = %redacted_funder,
        channel_count = n,
        tx_hash = %redacted_hash,
        ledger = result.ledger,
        "pool init: {} channels created on-chain",
        n
    );

    // ── On-chain confirmation received — now persist the seed ─────────────────
    // Only after a successful on-chain submission do we write the seed to the
    // OS keyring.  Failure here means the channels are funded but unreachable;
    // the operator should re-run `pool init --force` to re-sync.
    let encoded: Zeroizing<String> =
        Zeroizing::new(URL_SAFE_NO_PAD.encode(seed_zeroizing.as_ref()));
    // seed_zeroizing is no longer needed after encoding; drop it now.
    drop(seed_zeroizing);

    let keyring_entry = match KeyringEntry::new(&pool_master_ref.service, &pool_master_ref.account)
    {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                service = %pool_master_ref.service,
                error = %e,
                "pool init: keyring Entry::new failed AFTER on-chain success; \
                 channels are funded but seed is NOT persisted — re-run `pool init --force`"
            );
            let err = classify_pool_seed_write_failure(
                &e,
                &pool_master_ref,
                "keyring entry creation failed",
            );
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    if let Err(e) = keyring_entry.set_password(&encoded) {
        tracing::warn!(
            service = %pool_master_ref.service,
            error = %e,
            "pool init: set_password failed AFTER on-chain success; \
             channels are funded but seed is NOT persisted — re-run `pool init --force`"
        );
        let err = classify_pool_seed_write_failure(&e, &pool_master_ref, "keyring write failed");
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }
    // `encoded` zeroizes on drop.  The only live copy of the seed is now in the
    // OS keyring.

    // ── Build PoolChannelRecord list for persistence ──────────────────────────
    let pool_channels: Vec<PoolChannelRecord> = result
        .channel_records
        .iter()
        .map(|r| PoolChannelRecord::new(r.index, r.public_key.clone()))
        .collect();

    // ── Persist PoolConfig + pool_master_key_id into profile TOML ────────────
    // Raw-document patch: writes ONLY the two pool keys and preserves every
    // other stored key verbatim.  A load + save round trip here would persist
    // the env-merged view (`STELLAR_AGENT_*` overlays and loader-derived
    // defaults baked into the trust root).
    let pool_config = PoolConfig::new(n, pool_channels.clone());
    if let Err(e) = loader::set_pool_state(profile_name, &pool_master_ref, &pool_config) {
        tracing::warn!(
            profile = %profile_name,
            error = %e,
            "pool init: channels funded and seed in keyring, but profile save failed; \
             re-run `pool init --force` to re-sync"
        );
        let err = WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("pool init succeeded on-chain but profile save failed: {e}"),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    // ── Emit ChannelPoolInitialised audit event ───────────────────────────────
    // Best-effort: audit failure does NOT abort the command (the on-chain init
    // already succeeded and the profile is saved).  Log a warning so the
    // operator knows the audit record is missing.
    let request_id = Uuid::new_v4().to_string();
    let audit_entry = AuditEntry::new_channel_pool_initialised(
        &redacted_funder,
        pool_channels.len(),
        &redacted_hash,
        result.ledger,
        &request_id,
    );
    emit_pool_init_audit(&profile, profile_name, audit_entry);

    // ── Emit result JSON — no seed bytes ──────────────────────────────────────
    let pool_result = PoolInitResult {
        profile: profile_name.to_owned(),
        channel_count: pool_channels.len(),
        tx_hash_redacted: redacted_hash,
        ledger: result.ledger,
        channels: pool_channels,
        funder_redacted: redacted_funder,
        pool_master_keyring_service: pool_master_ref.service,
        pool_master_keyring_account: pool_master_ref.account,
    };

    render_json(&Envelope::ok(pool_result));
    0
}

// ── Audit helper ──────────────────────────────────────────────────────────────

/// Emits a `ChannelPoolInitialised` audit entry to the profile's audit log.
///
/// Best-effort: opens the audit writer via [`AuditWriterRegistry::get_or_open`],
/// writes the entry, and logs a warning on any failure.  The pool init already
/// succeeded at this point; audit failure does NOT abort the command.
fn emit_pool_init_audit(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    entry: AuditEntry,
) {
    // Load the audit HMAC key from the keyring; best-effort only.
    let hmac_key = match load_pool_init_audit_hmac_key(profile) {
        Ok(k) => Some(k),
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                error = %e,
                "pool init: could not load audit HMAC key; \
                 ChannelPoolInitialised will be written without HMAC"
            );
            None
        }
    };

    // Obtain or create the per-profile audit writer via the registry singleton.
    let writer_arc =
        match AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, hmac_key) {
            Ok(arc) => arc,
            Err(e) => {
                tracing::warn!(
                    profile = %profile_name,
                    error = %e,
                    "pool init: could not open audit writer; \
                     ChannelPoolInitialised NOT emitted"
                );
                return;
            }
        };

    // Lock and write the entry.
    match writer_arc.lock() {
        Ok(mut guard) => {
            if let Err(e) = guard.write_entry(entry) {
                tracing::warn!(
                    profile = %profile_name,
                    error = %e,
                    "pool init: audit write_entry failed; \
                     ChannelPoolInitialised NOT emitted"
                );
            }
        }
        Err(_) => {
            tracing::warn!(
                profile = %profile_name,
                "pool init: audit writer mutex poisoned; \
                 ChannelPoolInitialised NOT emitted"
            );
        }
    }
}

/// Loads and decodes the profile's audit-log HMAC key from the OS keyring.
fn load_pool_init_audit_hmac_key(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<zeroize::Zeroizing<[u8; 32]>, WalletError> {
    let entry_ref = &profile.audit_log_hash_chain_key_id;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "keyring Entry::new failed for pool-init audit HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?;

    let secret_b64 = zeroize::Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "get_password failed for pool-init audit HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?);

    let decoded = URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("pool-init audit HMAC key base64 decode failed: {e}"),
        })
    })?;
    if decoded.len() != 32 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "pool-init audit HMAC key length mismatch: expected 32 bytes, got {}",
                decoded.len()
            ),
        }));
    }
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
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
/// Only `keyring_core::Error::NoEntry` (and `NoDefaultStore`) is treated as
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
        Err(keyring_core::Error::NoEntry) | Err(keyring_core::Error::NoDefaultStore) => {
            KeyringProbe::Absent
        }
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

/// Classifies a post-confirmation keyring failure while persisting the pool
/// master seed.
///
/// The on-chain init has already succeeded when these failures occur, so the
/// re-sync guidance matters as much as the cause: environmental causes keep
/// their typed classification (a non-interactive Windows session surfaces as
/// `auth.keyring_interactive_session_required`; the `tracing::warn!` at the
/// call site carries the re-run guidance), while the generic not-found shape
/// carries the guidance in its coordinate label.
fn classify_pool_seed_write_failure(
    e: &keyring_core::Error,
    pool_master_ref: &KeyringEntryRef,
    phase: &str,
) -> WalletError {
    match stellar_agent_network::keyring::map_keyring_error(e, &pool_master_ref.service) {
        WalletError::Auth(AuthError::KeyringNotFound { .. }) => {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!(
                    "{}:{} (on-chain init succeeded; {phase} — \
                     re-run with --force to re-sync)",
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
    /// post-confirmation write phases: the operator sees
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
    /// cannot-determine-existence stance, and the post-confirmation write
    /// failure carries the re-sync instruction.
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
            write.message().contains("on-chain init succeeded")
                && write.message().contains("re-run with --force"),
            "write guidance lost: {}",
            write.message()
        );
    }

    /// Source-scan companion to the env-immunity test above: `run()`'s
    /// persistence step cannot be exercised without a live network, so this
    /// pins the production call site instead. The production half of this
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
