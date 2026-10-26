//! Shared durable consent sink for CLI approval surfaces.

use crate::commands::value_audit::{KeyedAcquireError, acquire_keyed_audit_writer};
use std::sync::{Arc, Mutex};
use stellar_agent_core::approval::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF};
use stellar_agent_core::audit_log::{
    AuditOutbox, drain_lock_is_held,
    writer::{AuditWriter, WriterError},
};
use stellar_agent_core::{error::WalletError, profile::schema::Profile};

/// The sink `approve --id` writes its consent row through.
pub(crate) enum ConsentSink {
    /// This process holds the keyed writer.
    Writer(Arc<Mutex<AuditWriter>>),
    /// A draining writer in another process holds the log.
    Outbox(AuditOutbox),
}

/// Returns `true` when an acquisition failure is contention for the writer's
/// sidecar lock, the one failure `approve --id` retries and then resolves by
/// probing the drain lock.
///
/// Classified by the typed error. Every other failure, `audit.outbox_busy`
/// included, refuses the approval.
pub(crate) fn is_sidecar_contention(error: &KeyedAcquireError) -> bool {
    matches!(error, KeyedAcquireError::Writer(WriterError::FileLocked))
}

/// Acquires the sink for the consent row.
///
/// The keyed writer is acquired through the registry, which drains any queued
/// rows at open. Sidecar contention is retried with the approval store's
/// bounded retry, since a CLI command's startup advisory holds the lock
/// briefly. Still locked, one `try_lock` on the drain lock, released at once,
/// decides. Held means a draining writer owns the log, and the row is queued.
/// Free means the holder does not drain, and the approval is refused with
/// `audit.writer_locked`.
///
/// # Errors
///
/// The [`WalletError`] for any acquisition failure other than contention, and
/// for contention with a holder that does not drain.
pub(crate) fn acquire_consent_sink(
    profile: &Profile,
    profile_name: &str,
) -> Result<ConsentSink, WalletError> {
    let mut attempt = 0_u32;
    let contention = loop {
        attempt += 1;
        match acquire_keyed_audit_writer(
            profile,
            profile_name,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        ) {
            Ok(writer) => return Ok(ConsentSink::Writer(writer)),
            Err(error) if is_sidecar_contention(&error) => {
                if attempt >= DEFAULT_RETRY_ATTEMPTS {
                    break error;
                }
                std::thread::sleep(DEFAULT_RETRY_BACKOFF);
            }
            Err(error) => return Err(error.into_wallet_error(profile_name)),
        }
    };
    match drain_lock_is_held(&profile.audit_log_path) {
        Ok(true) => Ok(ConsentSink::Outbox(AuditOutbox::for_log(
            &profile.audit_log_path,
        ))),
        Ok(false) => Err(contention.into_wallet_error(profile_name)),
        Err(error) => Err(KeyedAcquireError::Writer(error).into_wallet_error(profile_name)),
    }
}
