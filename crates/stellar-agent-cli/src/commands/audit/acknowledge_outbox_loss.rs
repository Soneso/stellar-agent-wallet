//! Acknowledges lost queued consent after revoking the profile's permissions.

use std::path::Path;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::{
    approval::{
        store::{ApprovalKind, PendingApprovalStore},
        toolset_grant::{ToolsetGrantStore, default_toolset_grants_path},
    },
    audit_log::{AuditWriter, BindingCheck, OutboxLossReport, RevokedCounts, WriterError},
    envelope::Envelope,
    error::{AuthError, InternalError, WalletError},
    profile::{ResolvedProfileName, schema::Profile},
};
use stellar_agent_network::keyring::{
    KeyringTipAnchorStore, check_audit_binding, init_platform_keyring_store,
};

use crate::commands::approve::{approval_store_dir, approval_store_open_error};
use crate::commands::profile::audit_emit::load_audit_hmac_key;
use crate::common::{profile_access::load_profile_reconciled, render};

/// Arguments for acknowledging an outbox loss.
#[derive(Debug, Args)]
pub struct AcknowledgeOutboxLossArgs {
    /// Profile whose queued consent is lost or changed.
    #[arg(long)]
    pub profile: String,
    /// Operator's explanation, recorded in the audit log.
    #[arg(long, value_parser = nonempty_reason)]
    pub reason: String,
}

fn nonempty_reason(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("reason must not be empty".to_owned());
    }
    Ok(value.to_owned())
}

#[derive(Debug, Serialize)]
struct AcknowledgementResult {
    profile: String,
    #[serde(flatten)]
    report: OutboxLossReport,
}

/// Runs the acknowledgement and renders its result. Returns 1 on refusal.
pub async fn run(args: &AcknowledgeOutboxLossArgs) -> i32 {
    let result = (|| {
        let profile = load_profile(&args.profile)?;
        init_platform_keyring_store()?;
        let approvals = approval_store_dir()?.join(format!("{}.toml", args.profile));
        let grants = default_toolset_grants_path(&args.profile)
            .map_err(|e| approval_store_open_error(&e))?;
        acknowledge(args, &profile, &approvals, &grants)
    })();
    match result {
        Ok(data) => {
            render::render_json(&Envelope::ok(data));
            0
        }
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            1
        }
    }
}

/// Loads the named profile, reconciled, mapping the failure into the CLI
/// envelope model.
fn load_profile(profile_name: &str) -> Result<Profile, WalletError> {
    load_profile_reconciled(&ResolvedProfileName::from_flag(profile_name)).map_err(|e| {
        tracing::debug!(
            profile = %profile_name,
            error = %e,
            "profile access refused for audit acknowledge-outbox-loss"
        );
        e.to_wallet_error(profile_name)
    })
}

fn acknowledge(
    args: &AcknowledgeOutboxLossArgs,
    profile: &Profile,
    approvals_path: &Path,
    grants_path: &Path,
) -> Result<AcknowledgementResult, WalletError> {
    let binding = check_audit_binding(profile, &args.profile, BindingCheck::CheckOnly)?;
    // A profile with no chain-root key yet opens unkeyed, as `audit reanchor`
    // does: the tip anchor and the outbox commitment do not depend on that
    // key. Every other key failure refuses, an owner-key refusal included, so
    // a key the profile must not use never writes the acknowledgement row.
    let hmac_key = match load_audit_hmac_key(profile, &args.profile) {
        Ok(key) => Some(key),
        Err(WalletError::Auth(AuthError::KeyringNotFound { .. })) => None,
        Err(e) => return Err(e),
    };
    let mut writer = AuditWriter::open_for_outbox_acknowledgement(
        profile.audit_log_path.clone(),
        hmac_key,
        KeyringTipAnchorStore::shared(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        ),
        binding,
    )
    .map_err(|e| writer_error(&e, &args.profile))?;
    writer
        .outbox_loss()
        .map_err(|e| writer_error(&e, &args.profile))?
        .ok_or_else(|| writer_error(&WriterError::OutboxLossNotFound, &args.profile))?;
    let now = stellar_agent_core::timefmt::now_unix_ms().map_err(|e| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: e.to_string(),
        })
    })?;
    // The approval lock precedes the outbox lock and stays held through
    // acknowledgement, so concurrent approval persistence cannot escape revocation.
    let mut approvals = PendingApprovalStore::open(approvals_path.to_path_buf())
        .map_err(|e| approval_store_open_error(&e))?;
    // Load without expiry pruning so every recorded grant is removed.
    let mut grants = ToolsetGrantStore::open(grants_path.to_path_buf(), 0)
        .map_err(|e| approval_store_open_error(&e))?;
    let revoked = revoke_permissions(&mut approvals, &mut grants, now)?;
    let report = writer
        .acknowledge_outbox_loss(&args.reason, revoked)
        .map_err(|e| writer_error(&e, &args.profile))?;
    Ok(AcknowledgementResult {
        profile: args.profile.clone(),
        report,
    })
}

fn revoke_permissions(
    approvals: &mut PendingApprovalStore,
    grants: &mut ToolsetGrantStore,
    now: u64,
) -> Result<RevokedCounts, WalletError> {
    let mut revoked = RevokedCounts::default();
    for view in approvals.snapshot(now) {
        let decided = approvals.get(&view.approval_nonce).is_some_and(|entry| {
            !entry.is_expired(now)
                && !matches!(
                    entry.kind,
                    ApprovalKind::Consumed { .. } | ApprovalKind::Rejected { .. }
                )
                && (entry.attestation_blob_b64.is_some() || entry.passkey_assertion.is_some())
        });
        if decided
            && approvals
                .remove(&view.approval_nonce)
                .map_err(|e| approval_store_open_error(&e))?
        {
            revoked.approvals += 1;
        }
    }
    revoked.grants = grants
        .revoke_all()
        .map_err(|e| approval_store_open_error(&e))?;
    Ok(revoked)
}

fn writer_error(error: &WriterError, profile: &str) -> WalletError {
    super::audit_writer_error(error, "audit.outbox_acknowledgement_failed", profile)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    use super::*;
    use clap::Parser;
    use stellar_agent_core::approval::{attestation::AttestedApprover, store::PendingApproval};
    use stellar_agent_core::audit_log::{
        AuditEntry, AuditOutbox, NewToolInvocation, PolicyDecision, TipAnchorStore, outbox_path,
    };
    use stellar_agent_test_support::keyring_mock;

    fn fixture(dir: &Path) -> (AcknowledgeOutboxLossArgs, Profile) {
        let args = AcknowledgeOutboxLossArgs {
            profile: "outbox-loss".to_owned(),
            reason: "queue inspection".to_owned(),
        };
        let mut profile =
            Profile::builder_testnet(&args.profile, "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.join("audit.jsonl");
        let key = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
        (args, profile)
    }

    fn commitment_store(profile: &Profile) -> KeyringTipAnchorStore {
        KeyringTipAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        )
    }

    /// Queues one committed consent row for `profile`.
    fn queue(profile: &Profile) {
        AuditOutbox::for_log(
            &profile.audit_log_path,
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .append(&AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "AAAAAAAAAAAAAAAAAAAAAA",
            "cli",
            "lost",
        ))
        .unwrap();
    }

    fn queue_and_lose(profile: &Profile) {
        queue(profile);
        std::fs::remove_file(outbox_path(&profile.audit_log_path)).unwrap();
    }

    fn pending() -> PendingApproval {
        PendingApproval::new_payment_pending(
            "eGRy".to_owned(),
            b"xdr",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
            100,
            "XLM".to_owned(),
            None,
            100,
            1,
            "1000".to_owned(),
            60_000,
        )
        .unwrap()
    }

    /// A decided approval, an undecided pending entry, and one toolset grant,
    /// in stores under `dir`.
    struct Permissions {
        approvals_path: std::path::PathBuf,
        grants_path: std::path::PathBuf,
        decided: String,
        undecided: String,
    }

    impl Permissions {
        fn seed(dir: &Path) -> Self {
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            let approvals_path = dir.join("approvals.toml");
            let grants_path = dir.join("grants.toml");
            let decided = pending();
            let undecided = pending();
            let mut approvals = PendingApprovalStore::open(approvals_path.clone()).unwrap();
            approvals.insert(decided.clone(), now).unwrap();
            approvals.insert(undecided.clone(), now).unwrap();
            approvals
                .record_attestation(&decided.approval_nonce, [0x42; 32], AttestedApprover::Local)
                .unwrap();
            let mut grants = ToolsetGrantStore::open(grants_path.clone(), now).unwrap();
            let grant = serde_json::from_value(serde_json::json!({
                "grant_id": "AAAAAAAAAAAAAAAAAAAAAA", "toolset_name": "fixture", "capability": "sign-payment",
                "destination": "fixture-destination", "asset": "XLM", "amount_min_stroops": 0,
                "amount_max_stroops": 100, "granted_at_unix_ms": now, "expires_at_unix_ms": now + 60_000,
                "process_uid_at_grant": "1000", "attestation_blob_b64": null, "attestation_version": 3
            })).unwrap();
            grants.insert(grant).unwrap();
            Self {
                approvals_path,
                grants_path,
                decided: decided.approval_nonce,
                undecided: undecided.approval_nonce,
            }
        }

        fn acknowledge(
            &self,
            args: &AcknowledgeOutboxLossArgs,
            profile: &Profile,
        ) -> Result<AcknowledgementResult, WalletError> {
            acknowledge(args, profile, &self.approvals_path, &self.grants_path)
        }

        /// Asserts that the decided approval and the grant are still in force.
        fn assert_untouched(&self) {
            let approvals = PendingApprovalStore::open(self.approvals_path.clone()).unwrap();
            assert!(
                approvals.get(&self.decided).is_some(),
                "decided approval revoked"
            );
            assert!(approvals.get(&self.undecided).is_some());
            assert_eq!(
                ToolsetGrantStore::open(self.grants_path.clone(), 0)
                    .unwrap()
                    .len(),
                1,
                "grant revoked"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn acknowledging_a_loss_revokes_decided_approvals_and_grants() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        queue_and_lose(&profile);
        let result = permissions.acknowledge(&args, &profile).unwrap();
        assert_eq!(
            (
                result.report.revoked_approvals,
                result.report.revoked_grants
            ),
            (1, 1)
        );
        let approvals = PendingApprovalStore::open(permissions.approvals_path.clone()).unwrap();
        assert!(approvals.get(&permissions.decided).is_none());
        assert!(approvals.get(&permissions.undecided).is_some());
        assert!(
            ToolsetGrantStore::open(permissions.grants_path.clone(), 0)
                .unwrap()
                .is_empty()
        );
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["kind"], "audit_entry_tags_started");
        let row = &rows[1];
        assert_eq!(row["kind"], "audit_outbox_loss_acknowledged");
        assert_eq!(row["revoked_approvals"], 1);
        assert_eq!(row["revoked_grants"], 1);
        assert_eq!(
            commitment_store(&profile)
                .load_outbox_state()
                .unwrap()
                .unwrap()
                .pending,
            0
        );
    }

    /// An intact queue is no loss: the verb refuses with its own code before
    /// it revokes anything, and the queue and its commitment stay as they are.
    #[test]
    #[serial_test::serial]
    fn the_verb_without_a_loss_refuses_and_revokes_nothing() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        queue(&profile);
        let outbox = std::fs::read(outbox_path(&profile.audit_log_path)).unwrap();
        let state = commitment_store(&profile).load_outbox_state().unwrap();

        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert_eq!(error.code(), "audit.outbox_loss_not_found", "{error}");
        permissions.assert_untouched();
        assert_eq!(
            std::fs::read(outbox_path(&profile.audit_log_path)).unwrap(),
            outbox
        );
        assert_eq!(
            commitment_store(&profile).load_outbox_state().unwrap(),
            state
        );
        assert_eq!(
            log_kinds(&profile),
            ["audit_entry_tags_started"],
            "no acknowledgement row"
        );
    }

    /// An outbox commitment the keyring holds in a form that does not parse
    /// refuses the acknowledgement. With that entry removed, the queued line
    /// is past the absent commitment: no acquisition drains it, and the
    /// acknowledgement records the loss, revokes the decided approvals,
    /// appends no queued row and empties the outbox.
    #[test]
    #[serial_test::serial]
    fn a_removed_unusable_commitment_is_recovered_by_the_acknowledgement() {
        use stellar_agent_core::audit_log::{
            BindingHistory, log_path_sha256, tip_anchor::AuditKeyringEntries,
        };

        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        queue(&profile);
        let commitment = AuditKeyringEntries::for_path_digest(
            &profile.audit_log_hash_chain_key_id,
            &log_path_sha256(&profile.audit_log_path),
        )
        .outbox_state;
        let entry = keyring_core::Entry::new(&commitment.service, &commitment.account).unwrap();
        entry.set_password("not a commitment").unwrap();

        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert!(
            error.message().contains("outbox state is unusable"),
            "{error}"
        );
        permissions.assert_untouched();

        entry.delete_credential().unwrap();
        let drained = AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            Some(load_audit_hmac_key(&profile, &args.profile).unwrap()),
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
            BindingHistory::NotRecorded,
        );
        assert!(
            matches!(
                drained,
                Err(WriterError::OutboxRowsMissing {
                    recorded: 0,
                    found: 1
                })
            ),
            "a keyed acquisition drains nothing past an absent commitment"
        );

        let result = permissions.acknowledge(&args, &profile).unwrap();
        assert_eq!(
            (
                result.report.expected_rows,
                result.report.found_rows,
                result.report.drained,
                result.report.discarded
            ),
            (0, 1, 0, 1)
        );
        assert_eq!(result.report.revoked_approvals, 1);
        assert!(
            !log_kinds(&profile)
                .iter()
                .any(|kind| kind == "approval_attested"),
            "the queued row is not appended"
        );
        assert!(
            log_kinds(&profile)
                .iter()
                .any(|kind| kind == "audit_outbox_loss_acknowledged")
        );
        assert!(
            std::fs::read(outbox_path(&profile.audit_log_path))
                .unwrap()
                .is_empty()
        );
    }

    /// An outbox commitment that does not parse, removed beside an absent
    /// outbox, leaves no detectable loss: the acknowledgement refuses with
    /// its own code and revokes nothing, and a keyed acquisition proceeds.
    #[test]
    #[serial_test::serial]
    fn a_removed_unusable_commitment_without_queued_lines_leaves_no_loss() {
        use stellar_agent_core::audit_log::{
            BindingHistory, log_path_sha256, tip_anchor::AuditKeyringEntries,
        };

        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        let commitment = AuditKeyringEntries::for_path_digest(
            &profile.audit_log_hash_chain_key_id,
            &log_path_sha256(&profile.audit_log_path),
        )
        .outbox_state;
        let entry = keyring_core::Entry::new(&commitment.service, &commitment.account).unwrap();
        entry.set_password("not a commitment").unwrap();
        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert!(
            error.message().contains("outbox state is unusable"),
            "{error}"
        );

        entry.delete_credential().unwrap();
        assert!(!outbox_path(&profile.audit_log_path).exists());
        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert_eq!(error.code(), "audit.outbox_loss_not_found", "{error}");
        permissions.assert_untouched();
        assert!(
            !log_kinds(&profile)
                .iter()
                .any(|kind| kind == "audit_outbox_loss_acknowledged")
        );
        AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            Some(load_audit_hmac_key(&profile, &args.profile).unwrap()),
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
            BindingHistory::NotRecorded,
        )
        .unwrap();
    }

    /// A lost audit key on a keyed log with a committed queue: the log and
    /// its outbox moved aside, the re-anchor of the new log stands while the
    /// commitment still names the moved rows, the acknowledgement records
    /// that loss, and a writer without a key then opens the new log, as the
    /// first mint of the key rotation does.
    #[test]
    #[serial_test::serial]
    fn a_lost_key_recovery_acknowledges_the_moved_queue() {
        use crate::commands::audit::reanchor::{ReanchorArgs, reanchor};
        use stellar_agent_core::audit_log::BindingHistory;

        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        let store = || {
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            )
        };
        drop(
            AuditWriter::open_with_tip_anchor(
                profile.audit_log_path.clone(),
                Some(load_audit_hmac_key(&profile, &args.profile).unwrap()),
                store(),
                BindingHistory::NotRecorded,
            )
            .unwrap(),
        );
        queue(&profile);
        let key = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&key.service, &key.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let saved = dir.path().join("saved");
        std::fs::create_dir(&saved).unwrap();
        for file in std::fs::read_dir(dir.path()).unwrap() {
            let file = file.unwrap().path();
            if file.is_file() && file.extension().is_none_or(|extension| extension != "lock") {
                std::fs::rename(&file, saved.join(file.file_name().unwrap())).unwrap();
            }
        }

        let cloned_profile = profile.clone();
        reanchor(
            &ReanchorArgs {
                profile: args.profile.clone(),
                acknowledge_rollback: true,
                acknowledge_binding_change: false,
                acknowledge_unauthenticated_tail: false,
            },
            move |_name| Ok(cloned_profile.clone()),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            commitment_store(&profile)
                .load_outbox_state()
                .unwrap()
                .map(|state| state.pending),
            Some(1),
            "the commitment still names the moved row"
        );
        assert!(matches!(
            AuditWriter::open_with_tip_anchor(
                profile.audit_log_path.clone(),
                None,
                store(),
                BindingHistory::NotRecorded,
            ),
            Err(WriterError::OutboxRowsMissing {
                recorded: 1,
                found: 0
            })
        ));

        let result = permissions.acknowledge(&args, &profile).unwrap();
        assert_eq!(
            (result.report.expected_rows, result.report.found_rows),
            (1, 0)
        );
        assert_eq!(
            log_kinds(&profile),
            ["audit_tip_anchored", "audit_outbox_loss_acknowledged"]
        );
        AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            None,
            store(),
            BindingHistory::NotRecorded,
        )
        .unwrap();
    }

    /// The kinds of the rows in `profile`'s log.
    fn log_kinds(profile: &Profile) -> Vec<String> {
        std::fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// The acknowledgement checks the tip anchor: over a log rolled back
    /// behind it, the verb refuses with the anchor's code, revokes nothing,
    /// and writes nothing.
    #[test]
    #[serial_test::serial]
    fn the_verb_refuses_a_log_rolled_back_behind_its_anchor() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let key = load_audit_hmac_key(&profile, &args.profile).unwrap();
        let snapshot = {
            let mut writer = AuditWriter::open_with_tip_anchor(
                profile.audit_log_path.clone(),
                Some(key),
                KeyringTipAnchorStore::shared(
                    &profile.audit_log_hash_chain_key_id,
                    &profile.audit_log_path,
                ),
                stellar_agent_core::audit_log::BindingHistory::NotRecorded,
            )
            .unwrap();
            let row = || {
                AuditEntry::new_tool_invocation(NewToolInvocation::new(
                    "stellar_pay_commit",
                    "stellar:testnet",
                    vec![],
                    PolicyDecision::Allow,
                    "own".to_owned(),
                ))
            };
            writer.write_entry(row()).unwrap();
            writer.write_entry(row()).unwrap();
            let snapshot = std::fs::read(&profile.audit_log_path).unwrap();
            writer.write_entry(row()).unwrap();
            snapshot
        };
        std::fs::write(&profile.audit_log_path, &snapshot).unwrap();
        let permissions = Permissions::seed(dir.path());
        queue_and_lose(&profile);
        let state = commitment_store(&profile).load_outbox_state().unwrap();

        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert_eq!(error.code(), "audit.tip_anchor_mismatch", "{error}");
        permissions.assert_untouched();
        assert_eq!(std::fs::read(&profile.audit_log_path).unwrap(), snapshot);
        assert_eq!(
            commitment_store(&profile).load_outbox_state().unwrap(),
            state
        );
    }

    /// A committed queued line the acknowledgement cannot append refuses the
    /// verb before it revokes anything or writes a row: here a committed row
    /// that is not a consent row, beside a line past the commitment.
    #[test]
    #[serial_test::serial]
    fn an_unusable_remaining_line_refuses_before_any_revocation() {
        use std::io::Write as _;

        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let permissions = Permissions::seed(dir.path());
        AuditOutbox::for_log(
            &profile.audit_log_path,
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .append(&AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            vec![],
            PolicyDecision::Allow,
            "queued-tool-row".to_owned(),
        )))
        .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(outbox_path(&profile.audit_log_path))
            .unwrap()
            .write_all(b"past the commitment\n")
            .unwrap();

        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert!(
            matches!(error, WalletError::Internal(InternalError::UnexpectedState { ref detail })
            if detail.starts_with("audit.outbox_unusable: line 1")),
            "{error}"
        );
        permissions.assert_untouched();
        assert_eq!(
            log_kinds(&profile),
            ["audit_entry_tags_started"],
            "no acknowledgement row"
        );
        assert_eq!(
            commitment_store(&profile)
                .load_outbox_state()
                .unwrap()
                .map(|state| state.pending),
            Some(1)
        );
    }

    /// An audit key the profile must not use refuses the verb; only an absent
    /// key opens the acknowledgement writer unkeyed.
    #[test]
    #[serial_test::serial]
    fn an_owner_key_as_the_audit_key_refuses_the_verb() {
        use base64::Engine as _;
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let owner_form = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x3e_u8; 32]);
        for entry_ref in [
            profile.audit_log_hash_chain_key_id.clone(),
            stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(&args.profile),
        ] {
            keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                .unwrap()
                .set_password(&owner_form)
                .unwrap();
        }
        let permissions = Permissions::seed(dir.path());
        queue_and_lose(&profile);

        let error = permissions.acknowledge(&args, &profile).unwrap_err();
        assert_eq!(
            error.code(),
            "validation.key_matches_owner_public_key",
            "{error}"
        );
        permissions.assert_untouched();
        assert!(!profile.audit_log_path.exists(), "no acknowledgement row");
    }

    #[test]
    fn revocation_includes_passkeys_and_preserves_expired_and_consumed_entries() {
        use stellar_agent_core::approval::assertion_input::AssertionInput;
        let dir = tempfile::tempdir().unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let mut approvals = PendingApprovalStore::open(dir.path().join("approvals.toml")).unwrap();
        let passkey = PendingApproval::new_passkey_pending(
            [1; 32],
            vec![2; 32],
            "CAAAA...BBBBB".to_owned(),
            vec![1],
            [3; 32],
            "localhost".to_owned(),
            "1000".to_owned(),
            60_000,
        )
        .unwrap();
        approvals.insert(passkey.clone(), now).unwrap();
        approvals
            .record_passkey_assertion(
                &passkey.approval_nonce,
                AssertionInput::new(vec![2; 32], vec![4; 37], vec![5; 50], vec![6; 64]).unwrap(),
            )
            .unwrap();
        let mut consumed = pending();
        consumed.expires_at_unix_ms += 120_000;
        approvals.insert(consumed.clone(), now).unwrap();
        approvals
            .record_attestation(
                &consumed.approval_nonce,
                [0x42; 32],
                AttestedApprover::Local,
            )
            .unwrap();
        approvals
            .consume(
                &consumed.approval_nonce,
                &"ab".repeat(32),
                stellar_agent_core::approval::store::ConsumedOutcome::Confirmed,
            )
            .unwrap();
        let expired = pending();
        approvals.insert(expired.clone(), now).unwrap();
        approvals
            .record_attestation(&expired.approval_nonce, [0x42; 32], AttestedApprover::Local)
            .unwrap();
        // The supplied recovery clock expires only this entry.
        let expiry = expired.expires_at_unix_ms;
        let mut passkey = approvals.get(&passkey.approval_nonce).unwrap().clone();
        approvals.remove(&passkey.approval_nonce).unwrap();
        passkey.expires_at_unix_ms = expiry + 60_000;
        approvals.insert(passkey.clone(), now).unwrap();
        let mut grants = ToolsetGrantStore::open(dir.path().join("grants.toml"), 0).unwrap();
        let revoked = revoke_permissions(&mut approvals, &mut grants, expiry).unwrap();
        assert_eq!(revoked.approvals, 1);
        assert!(approvals.get(&passkey.approval_nonce).is_none());
        assert!(approvals.get(&expired.approval_nonce).is_some());
        assert!(approvals.get(&consumed.approval_nonce).is_some());
    }

    /// A rejection marker is never revoked, even one that still carries an
    /// attestation: the marker refuses the next commit with its own code, and
    /// removing it would turn that refusal into a missing approval.
    #[test]
    fn a_rejection_marker_is_never_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let mut approvals = PendingApprovalStore::open(dir.path().join("approvals.toml")).unwrap();
        let entry = pending();
        approvals.insert(entry.clone(), now).unwrap();
        approvals
            .record_attestation(&entry.approval_nonce, [0x42; 32], AttestedApprover::Local)
            .unwrap();
        let mut rejected = approvals.get(&entry.approval_nonce).unwrap().clone();
        assert!(rejected.attestation_blob_b64.is_some());
        rejected.kind = ApprovalKind::Rejected {
            original_kind_name: "PaymentSimulated".to_owned(),
        };
        approvals.remove(&entry.approval_nonce).unwrap();
        approvals.insert(rejected, now).unwrap();
        let mut grants = ToolsetGrantStore::open(dir.path().join("grants.toml"), 0).unwrap();

        let revoked = revoke_permissions(&mut approvals, &mut grants, now).unwrap();
        assert_eq!(revoked.approvals, 0);
        assert!(matches!(
            approvals.get(&entry.approval_nonce).map(|kept| &kept.kind),
            Some(ApprovalKind::Rejected { .. })
        ));
    }

    #[test]
    #[serial_test::serial]
    fn the_verb_refuses_beside_a_held_writer() {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (args, profile) = fixture(dir.path());
        let _writer = AuditWriter::open(profile.audit_log_path.clone(), None).unwrap();
        queue_and_lose(&profile);
        let error = acknowledge(
            &args,
            &profile,
            &dir.path().join("approvals.toml"),
            &dir.path().join("grants.toml"),
        )
        .unwrap_err();
        assert!(
            matches!(error, WalletError::Internal(InternalError::UnexpectedState { ref detail })
            if detail.starts_with("audit.writer_locked")),
            "{error}"
        );
        assert!(!dir.path().join("approvals.toml").exists());
    }

    #[test]
    fn the_verb_requires_a_reason() {
        for args in [
            vec![
                "stellar-agent",
                "audit",
                "acknowledge-outbox-loss",
                "--profile",
                "fixture",
            ],
            vec![
                "stellar-agent",
                "audit",
                "acknowledge-outbox-loss",
                "--profile",
                "fixture",
                "--reason",
                "  ",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
        assert!(
            crate::Cli::try_parse_from([
                "stellar-agent",
                "audit",
                "acknowledge-outbox-loss",
                "--profile",
                "fixture",
                "--reason",
                "inspection"
            ])
            .is_ok()
        );
    }
}
