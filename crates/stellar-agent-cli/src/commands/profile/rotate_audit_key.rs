//! `stellar-agent profile rotate-audit-key <name>` — rotate the hash-chained
//! audit-log chain-root HMAC key.
//!
//! Generates 32 bytes from `OsRng`, encodes as URL-safe base64 (no padding),
//! and atomically replaces the keyring entry identified by
//! `profile.audit_log_hash_chain_key_id`.
//!
//! # Impact on the audit log
//!
//! The chain-root key signs the **first** entry per audit-log file (the chain
//! root); the entry-to-entry chain is key-independent.  Rotation therefore
//! re-signs every existing file's chain-root sidecar with the new key so that
//! `stellar-agent audit verify` under the new key stays green over the entire
//! log — pre-rotation entries and the new `KeyringKeyWritten` row alike.  The
//! old key is destroyed by the rotation; only the new key verifies afterward.
//!
//! Ordering is load-bearing.  The audit writer's exclusive sidecar lock is taken
//! FIRST and held throughout, so no other process can append or rotate while the
//! per-file sidecars are being rewritten; a live MCP server holding that lock
//! makes this verb refuse rather than race it.  The new key is then persisted to
//! the keyring, the audit row is appended, the tip anchor is reconciled and the
//! audit outbox drained, and the sidecars are re-signed LAST.  A row that
//! happens to open a new file, the verb's own or a drained consent row, has its
//! chain root brought onto the new key by the same pass.  The writer appends
//! nothing after it.  The re-sign pass reads the replacement key from the
//! keyring after persistence.  If re-signing fails partway (some sidecars carry
//! the new key, some the old), re-running the command
//! converges: the re-sign step recomputes every sidecar deterministically.
//!
//! The lock acquisition also runs the audit log's tip-anchor check, before the
//! key is touched: a log that was rolled back or truncated is refused with
//! `audit.tip_anchor_mismatch` and the profile's key is left alone.
//!
//! The profile's audit binding is checked before the lock is taken. A binding
//! that names another log path or audit key refuses with
//! `audit.log_binding_changed`, and nothing is created or anchored at the path
//! the profile names. An absent binding is recorded. The key rotates in place
//! at the same keyring coordinate, so the binding is otherwise unchanged.
//!
//! See `docs/runbooks/profile-migration.md` for operator guidance on key
//! rotation scheduling.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "rotated": true,
//!     "key_kind": "hmac_32_bytes"
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded or the keyring
//! operation fails.

use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::audit_log::{
    AuditWriter, BindingCheck, KeyPurpose, SidecarResignError, resign_chain_root_sidecars,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::owner_key;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::{
    AUDIT_KEY_FIELD, KeyringTipAnchorStore, check_audit_binding, init_platform_keyring_store,
};
use uuid::Uuid;

use crate::common::profile_access::{
    ProfileAccessError, injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::render;

use super::audit_emit::{emit_keyring_key_written_with_writer, load_audit_hmac_key};
use super::key_ops::rotate_hmac_like_key;

/// Opens the profile's audit writer under its current chain-root key, taking the
/// exclusive sidecar lock and running the tip-anchor check.
///
/// Opened directly rather than through `AuditWriterRegistry` because the
/// registry pins one `(path, key)` pair per profile name for the process
/// lifetime: rotation changes the key mid-process, and a cached registration
/// made under the old key would refuse every later acquisition.  This verb is
/// the sole audit-writer user in its own process, so there is nothing for a
/// registry entry to share with.
///
/// A profile with no chain-root key yet opens unkeyed: a first rotation on an
/// `init`-minted profile has no key to read, and refusing here would make
/// minting one impossible.
fn open_locked_audit_writer(
    profile: &Profile,
    profile_name: &str,
) -> Result<AuditWriter, WalletError> {
    let hmac_key = load_audit_hmac_key(profile, profile_name).ok();
    let tip_anchor = KeyringTipAnchorStore::shared(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    AuditWriter::open_with_tip_anchor(profile.audit_log_path.clone(), hmac_key, tip_anchor).map_err(
        |e| {
            crate::commands::audit::audit_writer_error(&e, "audit.writer_unavailable", profile_name)
        },
    )
}

/// Arguments for `stellar-agent profile rotate-audit-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct RotateAuditKeyArgs {
    /// Profile name whose audit-log chain-root key should be rotated,
    /// positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile name whose audit-log chain-root key should be rotated, flag
    /// form; an alternative to the positional `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,
}

impl RotateAuditKeyArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// Success payload for the `rotate-audit-key` envelope.
#[derive(Debug, Serialize)]
struct RotateAuditKeyData {
    /// Name of the profile whose audit key was rotated.
    profile: String,
    /// Always `true` on success.
    rotated: bool,
    /// Cryptographic primitive kind: `"hmac_32_bytes"` identifies the stored
    /// bytes as a 32-byte HMAC key (not an ed25519 seed).
    key_kind: &'static str,
    /// Number of per-file chain-root sidecars re-signed with the new key.
    sidecars_resigned: usize,
}

/// Maps a re-sign failure to an operator-actionable error stating that the key
/// rotated but the log is not yet verifiable under it, and a re-run converges.
fn resign_failure_error(e: &SidecarResignError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!(
            "audit.resign_incomplete: audit key rotated but chain-root re-sign failed ({e}); \
             re-run rotate-audit-key to converge"
        ),
    })
}

/// Runs `stellar-agent profile rotate-audit-key <name>`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &RotateAuditKeyArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile
/// (backed by a temp-dir audit log) and a spy initialiser so the rotate →
/// re-sign → emit sequence can be exercised against a mock keyring store
/// without touching the OS keychain or a persisted profile file.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &RotateAuditKeyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    match rotate(args, load_profile, init_keyring).await {
        Ok(data) => {
            render::render_json(&Envelope::ok(data));
            0
        }
        Err(RotateRefusal::ProfileAccess(e)) => {
            tracing::debug!(profile = %args.profile_name(), error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, args.profile_name()));
            1
        }
        Err(RotateRefusal::Wallet(e)) => {
            render::render_json(&Envelope::<()>::err(&e));
            1
        }
    }
}

/// What the rotation refused with, before it is rendered.
///
/// The profile-access refusal carries its own envelope shape, so the two cannot
/// be folded into one error type. Returning the refusal rather than an exit code
/// is what lets a test assert the code an operator would read.
enum RotateRefusal {
    /// The profile could not be loaded or did not reconcile against the name.
    ProfileAccess(ProfileAccessError),
    /// Every other refusal.
    Wallet(WalletError),
}

impl From<WalletError> for RotateRefusal {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}

/// Performs the rotation and returns what the verb renders.
async fn rotate<LoadProfile, InitKeyring>(
    args: &RotateAuditKeyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> Result<RotateAuditKeyData, RotateRefusal>
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Setup A: load the profile FIRST so a nonexistent profile never reaches
    // the keyring init.  Eliminates the process-global keyring-store race.
    // Reconciled in the CALLER of the injected loader: a check inside the
    // closure would be bypassed by every test that supplies its own.
    let profile = reconcile_loaded_profile(
        load_profile(args.profile_name()),
        &ResolvedProfileName::from_flag(args.profile_name()),
    )
    .map_err(RotateRefusal::ProfileAccess)?;

    let entry_ref = &profile.audit_log_hash_chain_key_id;

    // ── Owner namespace: a coordinate in the owner key namespace refuses
    // before the keyring opens, so the rotation never writes over an owner
    // entry and the binding never records an owner coordinate.
    owner_key::refuse_owner_key_coordinate(entry_ref, AUDIT_KEY_FIELD)?;

    // ── Setup B: initialise the platform keyring store.
    init_keyring()?;

    // ── Binding: checked before the writer opens, because opening creates the
    // directory, the lock sidecar, and the log file, and anchors the file it
    // finds. A binding that names another log or key refuses with
    // `audit.log_binding_changed` and nothing is created at the path the
    // profile names. An absent binding is recorded. The key rotates in place
    // at the same coordinate, so an equal binding stays as it is.
    check_audit_binding(&profile, args.profile_name(), BindingCheck::Enforce)?;

    // ── Step 0: take the audit writer's sidecar lock and hold it for the whole
    // rotation.  Re-signing walks the file chain and rewrites every `.root_hmac`
    // sidecar; a writer running concurrently could append to a file, or rotate
    // and create a NEW file, between the walk and the rewrite, leaving that
    // file's sidecar signed with the destroyed key.  The lock is exclusive
    // across processes, so a live MCP server holding it makes this verb refuse
    // rather than race it.
    //
    // Opening also runs the tip-anchor check, BEFORE the key is touched: a log
    // that was rolled back or truncated is refused here, leaving the profile's
    // key untouched and the operator free to investigate and run
    // `audit reanchor`.
    let mut writer = open_locked_audit_writer(&profile, args.profile_name()).map_err(|e| {
        tracing::warn!(error = %e, "rotate-audit-key: audit writer unavailable");
        e
    })?;

    // ── Step 1: persist the new chain-root key (destroys the old key).
    rotate_hmac_like_key(entry_ref, "rotate_audit_key")?;

    // ── Step 2: emit the KeyringKeyWritten row through the held writer
    // (non-fatal), BEFORE re-signing.  The row may be the first entry of a file,
    // in which case the writer signs that file's chain root with the key it was
    // opened under; running the re-sign afterwards brings that sidecar — and
    // every other — onto the new key in one pass.
    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written_with_writer(
        &mut writer,
        args.profile_name(),
        "profile_rotate_audit_key",
        KeyPurpose::AuditHashChainHmac,
        entry_ref,
        None,
        &request_id,
    );

    // ── Step 3: bring the tip anchor onto the file as it stands and drain
    // any consent row queued since the open, BEFORE the re-sign.  A drained row
    // that starts a new file is signed with the key this writer was opened
    // under; the re-sign below brings that sidecar onto the new key with the
    // rest.  The writer appends nothing after the re-sign, so no sidecar is
    // signed with the old key once the pass completes.  A row queued later
    // drains at the next acquisition, which opens under the new key.
    // Non-fatal: the key has rotated, and the next acquisition reconciles and
    // drains anyway.
    if let Err(e) = writer.verify_tip_anchor() {
        tracing::warn!(
            error = %e,
            "audit key rotated but the tip anchor could not be brought current"
        );
    }

    // ── Step 4: re-sign every existing per-file chain-root sidecar with the new
    // key so `audit verify` under the new key stays green.  Rotation does not
    // surface the generated bytes, so read the new key back from the keyring.
    let new_key = load_audit_hmac_key(&profile, args.profile_name()).map_err(|e| {
        tracing::error!(
            error = %e,
            "audit key rotated but could not be reloaded to re-sign sidecars; \
             re-run rotate-audit-key to converge"
        );
        e
    })?;
    let sidecars_resigned =
        resign_chain_root_sidecars(&profile.audit_log_path, &new_key).map_err(|e| {
            tracing::error!(
                error = %e,
                "audit key rotated but chain-root re-sign failed; \
                 re-run rotate-audit-key to converge"
            );
            resign_failure_error(&e)
        })?;
    drop(writer);

    // Info-level log omits the keyring service name to avoid leaking it.
    tracing::info!("audit-log chain-root key rotated; chain-root sidecars re-signed under new key");
    Ok(RotateAuditKeyData {
        profile: args.profile_name().to_owned(),
        rotated: true,
        key_kind: "hmac_32_bytes",
        sidecars_resigned,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use clap::Parser;
    use clap::error::ErrorKind;
    use serial_test::serial;

    use super::*;

    /// Local flatten wrapper so the `RotateAuditKeyArgs` clap contract can be
    /// parsed in isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: RotateAuditKeyArgs,
    }

    #[test]
    fn positional_name_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "acme"]).expect("positional parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn profile_flag_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme"]).expect("flag parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn both_positional_and_flag_is_a_conflict() {
        let err = Wrap::try_parse_from(["prog", "acme", "--profile", "other"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn neither_positional_nor_flag_is_missing_required() {
        let err = Wrap::try_parse_from(["prog"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    // Defensive #[serial] — see enroll_signer.rs for full rationale; the
    // test binary observes a flaky race during parallel execution that
    // clobbers sibling #[serial] keyring tests' mock store.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_nonexistent_profile_returns_exit_1() {
        let args = RotateAuditKeyArgs {
            name: Some("__nonexistent_rotate_audit_key__".to_owned()),
            profile: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    /// Calls `run_with_dependencies` against an existing log. Checks that the
    /// complete log verifies with the persisted replacement key, that the old
    /// key fails verification, and that the rotation row is present.
    /// `a_rotation_row_that_opens_a_new_file_is_resigned_under_the_new_key`
    /// covers a rotation row that opens a new file.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_run_resign_keeps_verify_green_under_new_key_and_emits_row() {
        use std::io::BufRead as _;

        use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, PolicyDecision, verify_log};
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        // Named so the profile's own keyring coordinates match the name it is
        // rotated under: `run_with_dependencies` reconciles the loaded profile
        // against the requested name before rotating anything.
        let mut profile = Profile::builder_testnet("rotate-run-e2e", "acct", "n-svc", "n-acct")
            .with_profile_name("rotate-run-e2e")
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let entry_ref = profile.audit_log_hash_chain_key_id.clone();

        // Seed the OLD chain-root key and write a pre-rotation chain under it.
        rotate_hmac_like_key(&entry_ref, "test_seed").expect("seed old key");
        let old_key = load_audit_hmac_key(&profile, "test-profile").expect("load old key");
        {
            let mut writer = AuditWriter::open_keyed_unanchored_for_test(
                profile.audit_log_path.clone(),
                old_key.clone(),
            )
            .expect("open under old key");
            for ledger in 0..2u32 {
                let entry = AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    ledger,
                    PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-pre",
                );
                writer.write_entry(entry).expect("write pre-rotation entry");
            }
        }
        assert!(
            verify_log(&profile.audit_log_path, Some(&old_key))
                .expect("verify old")
                .hmac_verified,
            "pre-rotation log must verify under the old key"
        );

        let args = RotateAuditKeyArgs {
            name: Some("rotate-run-e2e".to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let code =
            run_with_dependencies(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        assert_eq!(code, 0, "run_with_dependencies must succeed");

        let new_key =
            load_audit_hmac_key(&profile, "test-profile").expect("load new key after rotation");
        assert_ne!(
            *new_key, *old_key,
            "rotation must replace the chain-root key"
        );

        assert!(
            verify_log(&profile.audit_log_path, Some(&new_key))
                .expect("verify new")
                .hmac_verified,
            "the whole log must verify under the new key after run_with_dependencies"
        );
        assert!(
            verify_log(&profile.audit_log_path, Some(&old_key)).is_err(),
            "the old key must no longer verify after rotation"
        );

        let file = std::fs::File::open(&profile.audit_log_path).expect("log exists");
        let has_key_row = std::io::BufReader::new(file).lines().any(|line| {
            let value: serde_json::Value =
                serde_json::from_str(&line.expect("line")).expect("valid JSON row");
            value["kind"] == "keyring_key_written"
                && value["key_purpose"] == "audit_hash_chain_hmac"
        });
        assert!(
            has_key_row,
            "a keyring_key_written row must be present under the new key"
        );
    }

    /// A consent row queued after the verb's own row drains BEFORE the
    /// re-sign, even when its append rotates the log, so the whole chain
    /// verifies under the new key.
    ///
    /// A read hook at the tip-anchor coordinate queues the row once the verb's
    /// `keyring_key_written` row is in the log, after the drain that row's
    /// append ran. The rotation threshold is set so that the verb's row fits
    /// and the queued row's append rotates the log, during the final
    /// reconciliation. The queued row then opens the new file, whose chain
    /// root the writer signs with the key it was opened under.
    #[tokio::test]
    #[serial]
    async fn a_consent_row_drained_by_the_final_reconciliation_is_resigned_under_the_new_key() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use stellar_agent_core::audit_log::rotation::test_seam;
        use stellar_agent_core::audit_log::{
            AuditEntry, AuditOutbox, PolicyDecision, inspect_outbox, tip_anchor_account, verify_log,
        };
        use stellar_agent_test_support::keyring_mock::{ReadHook, install_with_read_hooks};

        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-drain-resign";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let log_path = profile.audit_log_path.clone();
        let entry_ref = profile.audit_log_hash_chain_key_id.clone();

        let queued = Arc::new(AtomicBool::new(false));
        let hook = {
            let queued = Arc::clone(&queued);
            let log_path = log_path.clone();
            Arc::new(move || {
                if queued.load(Ordering::SeqCst) {
                    return;
                }
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                if !log.contains(r#""kind":"keyring_key_written""#) {
                    return;
                }
                queued.store(true, Ordering::SeqCst);
                AuditOutbox::for_log(&log_path)
                    .append(&AuditEntry::new_approval_attested(
                        "PaymentSimulated",
                        "stellar_pay_commit",
                        None,
                        "ABCDEFGHIJKLMNOPQRSTUV",
                        "cli",
                        "queued-after-the-verb-row",
                    ))
                    .expect("queue a consent row");
            }) as Arc<dyn Fn() + Send + Sync>
        };
        install_with_read_hooks(vec![ReadHook::new(
            &entry_ref.service,
            &tip_anchor_account(&entry_ref.account, &log_path),
            hook,
        )])
        .expect("mock keyring store");

        rotate_hmac_like_key(&entry_ref, "test_seed").expect("seed the old key");
        let old_key = load_audit_hmac_key(&profile, name).expect("load the old key");
        {
            let mut writer = open_locked_audit_writer(&profile, name).expect("open the writer");
            writer
                .write_entry(AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    7,
                    PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-pre",
                ))
                .expect("append a pre-rotation row");
        }
        // The verb's own row fits under the threshold; the next append rotates.
        let threshold = std::fs::metadata(&log_path).expect("log").len() + 1;
        let threshold_guard = test_seam::set_rotation_threshold(&log_path, threshold);

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let result = rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        drop(threshold_guard);
        match result {
            Ok(_) => {}
            Err(RotateRefusal::Wallet(e)) => panic!("the rotation must succeed: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the rotation must succeed: {e}"),
        }

        assert!(
            queued.load(Ordering::SeqCst),
            "the consent row was queued after the verb's row"
        );
        assert_eq!(
            inspect_outbox(&log_path).expect("inspect").pending,
            0,
            "the verb drained the queued row"
        );
        let first_active: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&log_path)
                .expect("read the active file")
                .lines()
                .next()
                .expect("the active file has a row"),
        )
        .expect("a JSON row");
        assert_eq!(
            first_active["request_id"], "queued-after-the-verb-row",
            "the queued row's append rotated the log and opened the new file"
        );

        let new_key = load_audit_hmac_key(&profile, name).expect("load the new key");
        assert_ne!(*new_key, *old_key, "the key rotated");
        let verified =
            verify_log(&log_path, Some(&new_key)).expect("every file verifies under the new key");
        assert!(verified.hmac_verified, "{verified:?}");
        assert_eq!(verified.files_walked, 2, "{verified:?}");
    }

    /// The verb's row opens a file before the re-sign pass, so both chain
    /// roots verify under the persisted replacement key.
    #[tokio::test]
    #[serial]
    async fn a_rotation_row_that_opens_a_new_file_is_resigned_under_the_new_key() {
        use stellar_agent_core::audit_log::rotation::test_seam;
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, verify_log};
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-own-row-resign";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let log_path = profile.audit_log_path.clone();
        let entry_ref = profile.audit_log_hash_chain_key_id.clone();

        rotate_hmac_like_key(&entry_ref, "test_seed").expect("seed the old key");
        let old_key = load_audit_hmac_key(&profile, name).expect("load the old key");
        {
            let mut writer = open_locked_audit_writer(&profile, name).expect("open the writer");
            writer
                .write_entry(AuditEntry::new_value_action_submitted(
                    "stellar_pay",
                    "stellar:testnet",
                    Vec::new(),
                    "abcd1234…wxyz5678",
                    7,
                    PolicyDecision::Allow,
                    None,
                    None,
                    None,
                    "req-pre",
                ))
                .expect("append a pre-rotation row");
        }
        let threshold = std::fs::metadata(&log_path).expect("log").len();
        let threshold_guard = test_seam::set_rotation_threshold(&log_path, threshold);
        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let result = rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        drop(threshold_guard);
        match result {
            Ok(_) => {}
            Err(RotateRefusal::Wallet(e)) => panic!("the rotation must succeed: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the rotation must succeed: {e}"),
        }

        let first_active: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&log_path)
                .expect("read the active file")
                .lines()
                .next()
                .expect("the active file has a row"),
        )
        .expect("a JSON row");
        assert_eq!(
            first_active["kind"], "keyring_key_written",
            "the verb's row rotated the log and opened the new file"
        );
        assert_eq!(
            first_active["key_purpose"], "audit_hash_chain_hmac",
            "{first_active}"
        );
        let new_key = load_audit_hmac_key(&profile, name).expect("load the new key");
        assert_ne!(*new_key, *old_key, "the key rotated");
        let verified =
            verify_log(&log_path, Some(&new_key)).expect("every file verifies under the new key");
        assert!(verified.hmac_verified, "{verified:?}");
        assert_eq!(verified.files_walked, 2, "{verified:?}");
        assert!(
            verify_log(&log_path, Some(&old_key)).is_err(),
            "the old key no longer verifies"
        );
    }

    /// A rolled-back log refuses the rotation with `audit.tip_anchor_mismatch`
    /// and leaves the chain-root key exactly as it was.
    ///
    /// The verb takes the audit writer before it touches the key, and taking the
    /// writer runs the tip-anchor check. Rotating first would destroy the key the
    /// existing chain-root sidecars were signed under while the operator still
    /// has a rollback to investigate, and the re-sign pass would then bless the
    /// truncated log under the new key.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_a_rolled_back_log_and_rotates_nothing() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");

        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-anchor-rollback";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        rotate_hmac_like_key(&profile.audit_log_hash_chain_key_id, "test_seed")
            .expect("seed the chain-root key");
        let key_before =
            load_audit_hmac_key(&profile, "test-profile").expect("load the seeded key");

        let row = |request_id: &str| {
            AuditEntry::new_value_action_submitted(
                "stellar_pay",
                "stellar:testnet",
                Vec::new(),
                "abcd1234…wxyz5678",
                7,
                PolicyDecision::Allow,
                None,
                None,
                None,
                request_id,
            )
        };
        // Two anchored rows, with the file snapshotted between them, so the
        // snapshot is a log the anchor does not describe.
        let snapshot = {
            let mut writer =
                open_locked_audit_writer(&profile, name).expect("open the anchored writer");
            writer.write_entry(row("req-anchor-1")).expect("append");
            let snapshot = std::fs::read(&profile.audit_log_path).expect("read the log");
            writer.write_entry(row("req-anchor-2")).expect("append");
            snapshot
        };
        std::fs::write(&profile.audit_log_path, &snapshot).expect("roll the log back");

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let error = match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Err(RotateRefusal::Wallet(error)) => error,
            Err(RotateRefusal::ProfileAccess(e)) => {
                panic!("the refusal must come from the rotation, not from profile access: {e}")
            }
            Ok(_) => panic!("a rolled-back log must refuse the rotation"),
        };
        assert_eq!(
            error.code(),
            "audit.tip_anchor_mismatch",
            "the rendered refusal must name the tip-anchor check: {error}"
        );
        assert!(
            error.message().contains("file is shorter than the anchor"),
            "the rendered refusal must carry the reason the writer gave: {error}"
        );

        let key_after =
            load_audit_hmac_key(&profile, "test-profile").expect("load the key after the refusal");
        assert_eq!(
            *key_before, *key_after,
            "the refusal must leave the chain-root key untouched"
        );
    }

    fn binding_raw(name: &str) -> Option<String> {
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .load_raw()
            .expect("read binding")
    }

    /// A changed binding refuses before the writer opens: nothing is created
    /// or anchored at the repointed path and the key is not rotated.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_a_changed_binding_and_creates_nothing() {
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-binding-changed";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("old.jsonl");
        rotate_hmac_like_key(&profile.audit_log_hash_chain_key_id, "test_seed")
            .expect("seed the chain-root key");
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &profile,
            ))
            .expect("record the binding");
        let recorded = binding_raw(name);
        let key_before = load_audit_hmac_key(&profile, name).expect("load the seeded key");

        let repointed_dir = dir.path().join("repointed");
        profile.audit_log_path = repointed_dir.join("new.jsonl");
        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let error = match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Err(RotateRefusal::Wallet(error)) => error,
            Err(RotateRefusal::ProfileAccess(e)) => panic!("unexpected profile refusal: {e}"),
            Ok(_) => panic!("a changed binding must refuse the rotation"),
        };
        assert_eq!(error.code(), "audit.log_binding_changed", "{error}");
        assert!(
            !repointed_dir.exists(),
            "nothing is created at the repointed path"
        );
        assert_eq!(
            stellar_agent_core::audit_log::TipAnchorStore::load_raw(&KeyringTipAnchorStore::new(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ))
            .expect("read anchor"),
            None,
            "nothing is anchored at the repointed path"
        );
        assert!(
            binding_raw(name) == recorded,
            "the refusal leaves the binding"
        );
        let key_after = load_audit_hmac_key(&profile, name).expect("load the key");
        assert!(*key_before == *key_after, "the key is not rotated");
    }

    /// An audit-key coordinate in the owner key namespace refuses before the
    /// keyring opens: the owner entry is not overwritten and no binding is
    /// recorded.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_an_owner_namespace_coordinate() {
        use stellar_agent_core::profile::schema::KeyringEntryRef;
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-audit-owner";
        let owner = KeyringEntryRef::default_owner_key(name);
        let owner_value = owner_key::encode_owner_public_key(&[0x5a; 32]);
        keyring_core::Entry::new(&owner.service, &owner.account)
            .expect("owner entry")
            .set_password(&owner_value)
            .expect("store the owner entry");
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        profile.audit_log_hash_chain_key_id = owner.clone();

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let init_calls = std::cell::Cell::new(0_u32);
        let cloned_profile = profile.clone();
        let result = rotate(
            &args,
            move |_name| Ok(cloned_profile.clone()),
            || {
                init_calls.set(init_calls.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(
            keyring_core::Entry::new(&owner.service, &owner.account)
                .expect("owner entry")
                .get_password()
                .ok()
                == Some(owner_value),
            "the owner entry is not overwritten"
        );
        assert!(binding_raw(name).is_none(), "no binding is recorded");
        assert!(!profile.audit_log_path.exists(), "nothing is created");
        assert_eq!(init_calls.get(), 0, "the refusal precedes the keyring");
        let error = match result {
            Err(RotateRefusal::Wallet(error)) => error,
            Err(RotateRefusal::ProfileAccess(e)) => panic!("unexpected profile refusal: {e}"),
            Ok(_) => panic!("an owner-namespace coordinate must refuse the rotation"),
        };
        assert_eq!(error.code(), "validation.key_matches_owner_public_key");
        assert!(error.to_string().contains(AUDIT_KEY_FIELD), "{error}");
    }

    /// An absent binding is recorded, and an equal one is left byte-identical
    /// by a rotation, which keeps the key's coordinate.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_records_an_absent_binding_and_keeps_an_equal_one() {
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-binding-equal";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };

        assert!(binding_raw(name).is_none(), "nothing recorded yet");
        let cloned_profile = profile.clone();
        assert!(
            rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(()))
                .await
                .is_ok(),
            "the first rotation succeeds"
        );
        let recorded = binding_raw(name).expect("an absent binding is recorded");
        assert!(
            recorded
                == stellar_agent_core::audit_log::AuditBinding::for_profile(&profile)
                    .to_keyring_value(),
            "the first rotation records the profile's binding"
        );

        let cloned_profile = profile.clone();
        assert!(
            rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(()))
                .await
                .is_ok(),
            "a rotation over an equal binding succeeds"
        );
        assert!(binding_raw(name) == Some(recorded), "byte-identical");
    }
}
