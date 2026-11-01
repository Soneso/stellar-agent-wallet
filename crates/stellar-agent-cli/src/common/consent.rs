//! The shared sink for the operator rows the CLI writes: the consent rows of
//! the approval surfaces, and the halt and resume rows of `profile halt` and
//! `profile resume`.

use crate::commands::value_audit::{KeyedAcquireError, acquire_keyed_audit_writer};
use std::sync::{Arc, Mutex};
use stellar_agent_core::approval::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF};
use stellar_agent_core::audit_log::{
    AuditOutbox, BindingCheck, drain_lock_is_held,
    writer::{AuditWriter, WriterError},
};
use stellar_agent_core::{error::WalletError, profile::schema::Profile};

/// The sink an operator row is written through: the consent row of
/// `approve --id` and of the mainnet confirmation, and the halt and resume
/// rows of `profile halt` and `profile resume`.
pub(crate) enum OperatorRowSink {
    /// This process holds the keyed writer.
    Writer(Arc<Mutex<AuditWriter>>),
    /// A draining writer in another process holds the log.
    Outbox(AuditOutbox),
}

/// Returns `true` when an acquisition failure is contention for the writer's
/// sidecar lock, the one failure [`acquire_operator_row_sink`] retries and then
/// resolves by probing the drain lock.
///
/// Classified by the typed error. Every other failure, `audit.outbox_busy`
/// included, refuses the row.
fn is_sidecar_contention(error: &KeyedAcquireError) -> bool {
    matches!(error, KeyedAcquireError::Writer(WriterError::FileLocked))
}

/// Acquires the sink for an operator row.
///
/// The keyed writer is acquired through the registry, which drains any queued
/// rows at open. Sidecar contention is retried with the approval store's
/// bounded retry, since a CLI command's startup advisory holds the lock
/// briefly. Still locked, one `try_lock` on the drain lock, released at once,
/// decides. Held means a draining writer owns the log, such as a running MCP
/// server, and the row is queued. Free means the holder does not drain, and
/// the row is refused with `audit.writer_locked`.
///
/// # Errors
///
/// The [`WalletError`] for any acquisition failure other than contention, and
/// for contention with a holder that does not drain.
pub(crate) fn acquire_operator_row_sink(
    profile: &Profile,
    profile_name: &str,
) -> Result<OperatorRowSink, WalletError> {
    let mut attempt = 0_u32;
    let contention = loop {
        attempt += 1;
        match acquire_keyed_audit_writer(profile, profile_name, BindingCheck::Enforce) {
            Ok(writer) => return Ok(OperatorRowSink::Writer(writer)),
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
        Ok(true) => Ok(OperatorRowSink::Outbox(AuditOutbox::for_log(
            &profile.audit_log_path,
            stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        ))),
        Ok(false) => Err(contention.into_wallet_error(profile_name)),
        Err(error) => Err(KeyedAcquireError::Writer(error).into_wallet_error(profile_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operator-row acquisition is classified by the typed writer error:
    /// only sidecar contention is retried and resolved through the drain lock.
    #[test]
    fn only_sidecar_contention_is_resolved_through_the_drain_lock() {
        assert!(is_sidecar_contention(&KeyedAcquireError::Writer(
            WriterError::FileLocked
        )));
        for refused in [
            KeyedAcquireError::KeyUnavailable,
            KeyedAcquireError::BindingChanged(WalletError::Validation(
                stellar_agent_core::error::ValidationError::AuditLogBindingChanged {
                    profile: "p".to_owned(),
                },
            )),
            KeyedAcquireError::Writer(WriterError::OutboxBusy),
            KeyedAcquireError::Writer(WriterError::OutboxUnusable {
                line: 1,
                column: 1,
                reason: "invalid JSON",
            }),
            KeyedAcquireError::Writer(WriterError::TipAnchorMismatch {
                expected_count: 2,
                expected_offset: 10,
                actual_len: 0,
                reason: "file is shorter than the anchor",
            }),
            KeyedAcquireError::Writer(WriterError::Io(std::io::Error::other("disk"))),
            KeyedAcquireError::Writer(WriterError::TipAnchorUnavailable),
            KeyedAcquireError::Writer(WriterError::HmacKeyMismatch {
                profile_name: "p".to_owned(),
            }),
        ] {
            assert!(!is_sidecar_contention(&refused), "{refused:?}");
        }
    }
}
