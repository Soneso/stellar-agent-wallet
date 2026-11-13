//! The shared sink for the operator rows the CLI writes: the consent rows of
//! the approval surfaces, and the halt and resume rows of `profile halt` and
//! `profile resume`.

use crate::commands::value_audit::{KeyedAcquireError, is_binding_refusal};
use std::sync::{Arc, Mutex};
use stellar_agent_core::approval::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF};
use stellar_agent_core::audit_log::{
    AuditOutbox, BindingCheck, KeyedAuditAccess, drain_lock_is_held,
    writer::{AuditWriter, AuditWriterRegistry, WriterError},
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
/// briefly. Still locked, a probe of the drain lock through the carrier record
/// decides. The probe try-locks once. If it acquires the lock, it compares the
/// held identity with the carrier record before releasing it. Contention
/// returns a held result without a record check. Held means a draining writer
/// owns the log, such as a running MCP server, and the row is queued. Free means the holder does not drain, and the row is refused
/// with `audit.writer_locked`. A free drain lock file that is not the recorded
/// one refuses with its carrier code instead.
///
/// # Errors
///
/// The [`WalletError`] for any acquisition failure other than contention, and
/// for contention with a holder that does not drain.
pub(crate) fn acquire_operator_row_sink(
    profile: &Profile,
    profile_name: &str,
) -> Result<OperatorRowSink, WalletError> {
    let access = stellar_agent_network::keyring::keyed_audit_access(
        profile,
        profile_name,
        BindingCheck::Enforce,
    )
    .map_err(|error| {
        let refusal = if is_binding_refusal(&error) {
            tracing::warn!(
                profile = %profile_name,
                code = %error.code(),
                "value audit: audit binding differs; refusing"
            );
            KeyedAcquireError::BindingChanged(error)
        } else {
            tracing::warn!(
                profile = %profile_name,
                error = %error,
                "value audit: cannot load audit chain key; refusing"
            );
            KeyedAcquireError::KeyUnavailable
        };
        refusal.into_wallet_error(profile_name)
    })?;
    let history = access.binding_history();
    let (key, anchor) = access.into_parts();
    let mut attempt = 0_u32;
    let contention = loop {
        attempt += 1;
        match AuditWriterRegistry::get_or_open_keyed(
            profile_name,
            &profile.audit_log_path,
            KeyedAuditAccess::new(key.clone(), Arc::clone(&anchor)).with_binding_history(history),
        )
        .map_err(KeyedAcquireError::Writer)
        {
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
    match drain_lock_is_held(
        &profile.audit_log_path,
        &stellar_agent_network::keyring::KeyringTipAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        ),
    ) {
        Ok(true) => Ok(OperatorRowSink::Outbox(AuditOutbox::for_log_keyed(
            &profile.audit_log_path,
            anchor,
            key,
        ))),
        Ok(false) => Err(contention.into_wallet_error(profile_name)),
        Err(error) => Err(KeyedAcquireError::Writer(error).into_wallet_error(profile_name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    fn contended_sink_queues_a_tagged_row_with_the_loaded_key() {
        use base64::Engine as _;
        use stellar_agent_core::audit_log::AuditEntry;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet_named(
            "queued-key",
            "fixture",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "nonce-fixture",
            "nonce-account",
        )
        .with_noop_engine()
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let coordinate = &profile.audit_log_hash_chain_key_id;
        let credential =
            keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
        credential
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]))
            .unwrap();
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            "queued-key",
            BindingCheck::Enforce,
        )
        .unwrap();
        let mut holder = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
        let sink = acquire_operator_row_sink(&profile, "queued-key").unwrap();
        let OperatorRowSink::Outbox(outbox) = sink else {
            panic!("the draining holder selects the outbox")
        };
        credential.delete_credential().unwrap();
        assert!(stellar_agent_network::keyring::load_hmac_key_32(coordinate).is_err());
        outbox
            .append(&AuditEntry::new_profile_resumed("fixture", true, "queued"))
            .unwrap();
        let bytes = std::fs::read(outbox.path()).unwrap();
        assert!(bytes.starts_with(b"{\"k\":\"row\",\"g\":0,\"s\":1,\"r\":0,"));
        assert_eq!(
            holder.drain_outbox().unwrap(),
            1,
            "the original key verifies the queued row"
        );
        let text = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        let entry: AuditEntry = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(entry.request_id, "queued");
    }

    /// A keyed profile fixture whose audit key is stored in the mock keyring.
    #[allow(clippy::unwrap_used, reason = "test fixture")]
    fn keyed_profile(name: &str, dir: &tempfile::TempDir) -> Profile {
        use base64::Engine as _;
        let mut profile = Profile::builder_testnet_named(
            name,
            "fixture",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "nonce-fixture",
            "nonce-account",
        )
        .with_noop_engine()
        .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let coordinate = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42; 32]))
            .unwrap();
        profile
    }

    fn anchor_store(profile: &Profile) -> stellar_agent_network::keyring::KeyringTipAnchorStore {
        stellar_agent_network::keyring::KeyringTipAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        )
    }

    /// Rows queued past the commitment while a draining writer holds the log
    /// form a tagged legacy suffix that verification, loss detection and the
    /// holder's drain all accept.
    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    fn contended_enqueue_verifies_without_loss() {
        use stellar_agent_core::audit_log::{AuditEntry, TipAnchorStore, check_outbox_commitment};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = keyed_profile("contended-suffix", &dir);
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            "contended-suffix",
            BindingCheck::Enforce,
        )
        .unwrap();
        let mut holder = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
        let store = anchor_store(&profile);
        let commitment = store.load_outbox_state(1).unwrap();
        for id in ["first", "second"] {
            let OperatorRowSink::Outbox(outbox) =
                acquire_operator_row_sink(&profile, "contended-suffix").unwrap()
            else {
                panic!("the draining holder selects the outbox")
            };
            outbox
                .append(&AuditEntry::new_profile_resumed("fixture", true, id))
                .unwrap();
        }
        let queued = std::fs::read(stellar_agent_core::audit_log::outbox_path(
            &profile.audit_log_path,
        ))
        .unwrap();
        let text = std::str::from_utf8(&queued).unwrap();
        assert_eq!(text.lines().count(), 2);
        for (index, line) in text.lines().enumerate() {
            assert!(
                line.starts_with(&format!("{{\"k\":\"row\",\"g\":0,\"s\":{},", index + 1)),
                "{line}"
            );
        }
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            commitment,
            "the queue leaves the commitment"
        );
        check_outbox_commitment(&profile.audit_log_path, &store).unwrap();
        assert_eq!(holder.outbox_loss().unwrap(), None);
        assert_eq!(holder.drain_outbox().unwrap(), 2);
        let log = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        let ids: Vec<_> = log
            .lines()
            .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap().request_id)
            .collect();
        assert_eq!(&ids[ids.len() - 2..], ["first", "second"]);
    }

    /// Without a draining holder the sink is this process's own writer, which
    /// drains the queue and records the owner state itself.
    #[test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    fn a_standalone_writer_holder_keeps_direct_access() {
        use stellar_agent_core::audit_log::{AuditEntry, TipAnchorStore};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = keyed_profile("standalone-holder", &dir);
        let access = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            "standalone-holder",
            BindingCheck::Enforce,
        )
        .unwrap();
        drop(AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap());
        let store = std::sync::Arc::new(anchor_store(&profile));
        AuditOutbox::for_log_keyed(
            &profile.audit_log_path,
            store.clone(),
            zeroize::Zeroizing::new([0x42; 32]),
        )
        .append(&AuditEntry::new_profile_resumed("fixture", true, "queued"))
        .unwrap();
        assert_eq!(store.load_outbox_owner_state(1).unwrap(), None);
        let sink = acquire_operator_row_sink(&profile, "standalone-holder").unwrap();
        let OperatorRowSink::Writer(writer) = sink else {
            panic!("a free log selects this process's writer")
        };
        assert!(
            store.load_outbox_owner_state(1).unwrap().is_some(),
            "the writer's open drain records the owner state"
        );
        crate::commands::value_audit::append_value_audit_row_strict(
            &mut writer.lock().unwrap(),
            "standalone-holder",
            AuditEntry::new_profile_resumed("fixture", true, "direct"),
        )
        .unwrap();
        drop(writer);
        AuditWriterRegistry::remove_for_test("standalone-holder");
        let log = std::fs::read_to_string(&profile.audit_log_path).unwrap();
        let ids: Vec<_> = log
            .lines()
            .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap().request_id)
            .collect();
        assert_eq!(&ids[ids.len() - 2..], ["queued", "direct"]);
        let queue = std::fs::read(stellar_agent_core::audit_log::outbox_path(
            &profile.audit_log_path,
        ))
        .unwrap();
        assert!(
            queue.starts_with(b"{\"k\":\"gen\",\"g\":1,\"tag\":\""),
            "only the generation line remains"
        );
        assert_eq!(queue.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

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
