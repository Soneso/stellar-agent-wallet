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
//! the new key, some the old), re-running the command converges: the re-sign
//! step recomputes every sidecar deterministically.
//!
//! The lock acquisition also runs the audit log's tip-anchor check, before the
//! key is touched: a log that was rolled back or truncated is refused with
//! `audit.tip_anchor_mismatch` and the profile's key is left alone.
//!
//! Directly before the key write, under the same lock, the anchor must cover
//! the writer's last row, which carries a tag under the key being replaced.
//! Rows the open drained whose anchor write failed would otherwise lie past
//! the anchor with no key left to authenticate them. The refusal
//! (`audit.chain_key_unavailable` with the `audit.tip_anchor_unavailable`
//! detail) writes nothing and leaves the key as it is; the rotation is retried
//! once the keyring is reachable.
//!
//! The profile's audit binding is checked before the lock is taken. A binding
//! that names another log path or audit key refuses with
//! `audit.log_binding_changed`, and nothing is created or anchored at the path
//! the profile names. An absent binding is recorded once the writer has
//! opened. The key rotates in place at the same keyring coordinate, so the
//! binding is otherwise unchanged.
//!
//! A log with no tip anchor that shows it was anchored before refuses with
//! `audit.tip_anchor_missing`. A recorded binding is such evidence only while
//! the profile has a key: a profile minting its first key has had no keyed use
//! of its log, so its first rotation adopts a log written only by unkeyed
//! writers.
//!
//! See `docs/cli-reference/profile-and-governance.md#key-rotation-subcommands`
//! for the writer lock and the prerequisites of a rotation.
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
    AuditWriter, BindingCheck, BindingHistory, KeyPurpose, SidecarResignError, WriterError,
    audit_writer_refusal, resign_chain_root_sidecars, verify::VerifyError, verify_entry_tags,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::owner_key;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::{
    AUDIT_KEY_FIELD, KeyringTipAnchorStore, check_audit_binding, init_platform_keyring_store,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::profile_access::{
    ProfileAccessError, injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::render;

use super::audit_emit::{emit_keyring_key_written_with_writer, load_audit_hmac_key};
use super::key_ops::rotate_hmac_like_key;

/// Opens the profile's audit writer under its current chain-root key, as
/// [`existing_audit_key`] reads it, through
/// [`open_locked_audit_writer_with_key`].
#[cfg(test)]
fn open_locked_audit_writer(
    profile: &Profile,
    profile_name: &str,
    binding: BindingHistory,
) -> Result<AuditWriter, WalletError> {
    let hmac_key = existing_audit_key(profile, profile_name)?;
    open_locked_audit_writer_with_key(profile, profile_name, binding, hmac_key)
}

/// The profile's current chain-root key, or `None` when none is stored.
///
/// # Errors
///
/// Every key-read failure other than an absent entry, through
/// [`unusable_stored_key`]. The caller reads the key before any binding, key
/// or log write, so such a failure leaves all three unchanged.
fn existing_audit_key(
    profile: &Profile,
    profile_name: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>, WalletError> {
    match load_audit_hmac_key(profile, profile_name) {
        Ok(key) => Ok(Some(key)),
        // Only NoEntry maps to the bare service name; NoDefaultStore adds
        // session guidance to its KeyringNotFound name.
        Err(WalletError::Auth(AuthError::KeyringNotFound { name }))
            if name == profile.audit_log_hash_chain_key_id.service =>
        {
            Ok(None)
        }
        Err(error) => Err(unusable_stored_key(error, profile_name)),
    }
}

/// Opens the profile's audit writer under `hmac_key`, the chain-root key
/// [`existing_audit_key`] read, taking the exclusive sidecar lock and running
/// the tip-anchor check.
///
/// Opened directly rather than through `AuditWriterRegistry` because the
/// registry pins one `(path, key)` pair per profile name for the process
/// lifetime: rotation changes the key mid-process, and a cached registration
/// made under the old key would refuse every later acquisition.  This verb is
/// the sole audit-writer user in its own process, so there is nothing for a
/// registry entry to share with.
///
/// A missing chain-root key (`hmac_key` is `None`) opens unkeyed and passes
/// `NotRecorded` to the anchor check, allowing the first key to be minted. A
/// recorded binding alone does not prove that a key existed. `binding` is
/// passed to the anchor check when the key loads.
fn open_locked_audit_writer_with_key(
    profile: &Profile,
    profile_name: &str,
    binding: BindingHistory,
    hmac_key: Option<Zeroizing<[u8; 32]>>,
) -> Result<AuditWriter, WalletError> {
    let binding = if hmac_key.is_some() {
        binding
    } else {
        BindingHistory::NotRecorded
    };
    let tip_anchor = KeyringTipAnchorStore::shared(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    AuditWriter::open_with_tip_anchor(
        profile.audit_log_path.clone(),
        hmac_key,
        tip_anchor,
        binding,
    )
    .map_err(|e| {
        crate::commands::audit::audit_writer_error(&e, "audit.writer_unavailable", profile_name)
    })
}

/// The refusal for an anchor that does not cover the writer's last row when
/// the key is about to be replaced.
///
/// An owed anchor write the keyring still rejects names its recovery: the key
/// is unchanged, and the rotation is retried once the keyring is reachable.
/// Every other refusal is the one the writer's other strict callers report.
fn anchor_not_current(profile_name: &str, e: &WriterError) -> WalletError {
    tracing::warn!(error = %e, "rotate-audit-key: the tip anchor is not current; key left as it is");
    match e {
        WriterError::TipAnchorStore(detail) => {
            WalletError::Validation(ValidationError::AuditLogUnusable {
                profile: profile_name.to_owned(),
                detail: format!(
                    "audit.tip_anchor_unavailable: the tip anchor does not cover the audit log's \
                     last entry and could not be written ({detail}); the audit key was not \
                     rotated: retry `stellar-agent profile rotate-audit-key {profile_name}` once \
                     the keyring is reachable"
                ),
            })
        }
        other => audit_writer_refusal(profile_name, other),
    }
}

/// The refusal for a stored audit key this verb cannot read or decode.
///
/// Rotation never writes over a key it cannot read: the entry may hold the key
/// the log's chain-root sidecars are signed under, and a read failure may be
/// the keyring itself failing, which a new write would hide. The wire code
/// stays the read failure's own. A keyring operation failure and an
/// undecodable value gain the remedy in their message: investigate, and only
/// for a corrupt key restore it from a copy, since a log under entry tags
/// takes rows only under its own key and a first mint applies only to a log
/// without them; the recovery runbook covers a tagged log without a copy.
/// The other refusals already name their own remedy: an
/// unavailable credential store, a required interactive session, or a key
/// refused as the owner key.
fn unusable_stored_key(error: WalletError, profile_name: &str) -> WalletError {
    let remedy = format!(
        "investigate; if the stored audit key is corrupt, restore it from a copy of its keyring \
         entry: a log under entry tags takes rows only under its own key, and \
         `stellar-agent profile rotate-audit-key {profile_name}` mints a key only for a log \
         without entry tags, once the entry is removed; without a copy, see \
         docs/maintainers/audit-log-recovery.md section 10"
    );
    match error {
        WalletError::Internal(InternalError::UnexpectedState { detail }) => {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("{detail}; {remedy}"),
            })
        }
        WalletError::Auth(AuthError::KeyringPlatformError { detail }) => {
            WalletError::Auth(AuthError::KeyringPlatformError {
                detail: format!("{detail}; {remedy}"),
            })
        }
        other => other,
    }
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
        Err(RotateRefusal::Integrity(e)) => {
            render::render_json(&Envelope::<()>::err_raw(e.wire_code(), e.to_string()));
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
    /// The log's entry tags failed under the key being replaced. Rendered
    /// with the verifier's own wire code and message.
    Integrity(VerifyError),
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

    // Installation and owner namespaces refuse before the keyring opens,
    // so rotation preserves reserved entries and the binding excludes them.
    owner_key::refuse_installation_key_coordinate(entry_ref, AUDIT_KEY_FIELD)?;
    owner_key::refuse_owner_key_coordinate(entry_ref, AUDIT_KEY_FIELD)?;

    // ── Setup B: initialise the platform keyring store.
    init_keyring()?;

    // ── Binding: checked before the writer opens, because opening creates the
    // directory, the lock sidecar, and the log file, and anchors the file it
    // finds. A binding that names another log or key refuses with
    // `audit.log_binding_changed` and nothing is created at the path the
    // profile names. An absent binding is recorded once the writer has opened,
    // so a refused open records none. The key rotates in place at the same
    // coordinate, so an equal binding stays as it is.
    let binding = check_audit_binding(&profile, args.profile_name(), BindingCheck::CheckOnly)?;

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
    let old_key = existing_audit_key(&profile, args.profile_name())?;
    let mut writer =
        open_locked_audit_writer_with_key(&profile, args.profile_name(), binding, old_key.clone())
            .map_err(|e| {
                tracing::warn!(error = %e, "rotate-audit-key: audit writer unavailable");
                e
            })?;
    check_audit_binding(&profile, args.profile_name(), BindingCheck::Enforce)?;

    // ── Step 1: under the held lock, check the log's entry tags under the key
    // being replaced, BEFORE any key write.  The rekey row written below
    // covers every entry before it under the new key, so an entry whose tag
    // fails under the old key refuses here, while that key can still judge it.
    // The sidecar and prune-marker checks are left out: an interrupted earlier
    // run may have re-signed some sidecars under a key it already replaced.
    if let Some(old_key) = &old_key {
        verify_entry_tags(&profile.audit_log_path, old_key).map_err(RotateRefusal::Integrity)?;
    }

    // ── Step 2: under the held lock, directly before the key write, require
    // the anchor to cover the writer's last row.  Every row up to there
    // carries a tag under the key being replaced; a row the open drained whose
    // anchor write failed would lie past the anchor once that key is gone, and
    // no key would be left to authenticate it.  The refusal writes nothing.
    writer
        .require_anchor_current()
        .map_err(|e| anchor_not_current(args.profile_name(), &e))?;

    // ── Step 3: persist the new chain-root key (destroys the old key).
    rotate_hmac_like_key(entry_ref, "rotate_audit_key")?;

    // ── Step 4: switch the held writer to the new key.  Rotation does not
    // surface the generated bytes, so read the new key back from the keyring.
    // With tags in force the writer appends `audit_entry_tags_rekeyed
    // { cause: rotation }`, tagged under the new key.  Non-fatal: the key is
    // switched either way, and the next keyed open appends an `open_repair`
    // rekey row for entries the old key tagged after the newest keyed start.
    let new_key = load_audit_hmac_key(&profile, args.profile_name()).map_err(|e| {
        tracing::error!(
            error = %e,
            "audit key rotated but could not be reloaded to re-sign sidecars; \
             re-run rotate-audit-key to converge"
        );
        e
    })?;
    let request_id = Uuid::new_v4().to_string();
    if let Err(e) = writer.switch_entry_tag_key(new_key.clone(), &request_id) {
        tracing::warn!(
            error = %e,
            "audit key rotated but the rekey row could not be appended; the next keyed \
             open repairs it"
        );
    }

    // ── Step 5: emit the KeyringKeyWritten row through the held writer
    // (non-fatal), BEFORE re-signing.  The row is tagged under the new key.
    // It may be the first entry of a file, in which case the writer signs that
    // file's chain root; running the re-sign afterwards brings every sidecar
    // onto the new key in one pass.
    emit_keyring_key_written_with_writer(
        &mut writer,
        args.profile_name(),
        "profile_rotate_audit_key",
        KeyPurpose::AuditHashChainHmac,
        entry_ref,
        None,
        &request_id,
    );

    // ── Step 6: bring the tip anchor onto the file as it stands and drain
    // any consent row queued since the open, BEFORE the re-sign.  The writer
    // holds the new key since step 4, so a drained row is tagged under it, and
    // one that starts a new file has its chain root signed under it too; the
    // re-sign below rewrites every sidecar under the new key in one pass.  The
    // writer appends nothing after the re-sign.  A row queued later drains at
    // the next acquisition, which opens under the new key.
    // Non-fatal: the key has rotated, and the next acquisition reconciles and
    // drains anyway.
    if let Err(e) = writer.verify_tip_anchor() {
        tracing::warn!(
            error = %e,
            "audit key rotated but the tip anchor could not be brought current"
        );
    }

    // ── Step 7: re-sign every existing per-file chain-root sidecar with the new
    // key so `audit verify` under the new key stays green.
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

        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, verify_log};
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

        // Seed the OLD chain-root key and write a pre-rotation chain under it,
        // through the anchored writer the verb itself opens.
        rotate_hmac_like_key(&entry_ref, "test_seed").expect("seed old key");
        let old_key = load_audit_hmac_key(&profile, "test-profile").expect("load old key");
        {
            let mut writer =
                open_locked_audit_writer(&profile, "rotate-run-e2e", BindingHistory::NotRecorded)
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
                    None,
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
    /// append ran, and lowers the rotation threshold to the log's length at
    /// that moment: the verb's rekey row and its own row fit, and the queued
    /// row's append rotates the log, during the final
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
            let outbox_store = stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &log_path,
            );
            Arc::new(move || {
                if queued.load(Ordering::SeqCst) {
                    return;
                }
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                if !log.contains(r#""kind":"keyring_key_written""#) {
                    return;
                }
                queued.store(true, Ordering::SeqCst);
                // The guard set before the verb restores the default when it
                // drops; this lowered value replaces its threshold until then.
                std::mem::forget(test_seam::set_rotation_threshold(
                    &log_path,
                    u64::try_from(log.len()).expect("log length"),
                ));
                AuditOutbox::for_log(&log_path, outbox_store.clone())
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
            let mut writer = open_locked_audit_writer(&profile, name, BindingHistory::NotRecorded)
                .expect("open the writer");
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
                    None,
                ))
                .expect("append a pre-rotation row");
        }
        // No append rotates until the hook lowers the threshold.
        let threshold_guard = test_seam::set_rotation_threshold(&log_path, u64::MAX);

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let result = rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        drop(threshold_guard);
        match result {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
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

    /// The verb's first row, its rekey row, opens a file before the re-sign
    /// pass, so both chain roots verify under the persisted replacement key.
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
            let mut writer = open_locked_audit_writer(&profile, name, BindingHistory::NotRecorded)
                .expect("open the writer");
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
                    None,
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
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(e)) => panic!("the rotation must succeed: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the rotation must succeed: {e}"),
        }

        let active: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
            .expect("read the active file")
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON row"))
            .collect();
        assert_eq!(
            active[0]["kind"], "audit_entry_tags_rekeyed",
            "the verb's rekey row rotated the log and opened the new file"
        );
        assert_eq!(active[0]["cause"], "rotation", "{}", active[0]);
        assert_eq!(active[1]["kind"], "keyring_key_written", "{}", active[1]);
        assert_eq!(
            active[1]["key_purpose"], "audit_hash_chain_hmac",
            "{}",
            active[1]
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
                None,
            )
        };
        // Two anchored rows, with the file snapshotted between them, so the
        // snapshot is a log the anchor does not describe.
        let snapshot = {
            let mut writer = open_locked_audit_writer(&profile, name, BindingHistory::NotRecorded)
                .expect("open the anchored writer");
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
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
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

    /// Audit-key read failures other than NoEntry keep the mapped error's code,
    /// add the corrupt-key remedy to a keyring operation failure, and leave the
    /// binding, key, anchor, and log untouched.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_key_read_errors_and_writes_nothing() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, TipAnchorStore};
        use stellar_agent_network::keyring::{KeyringOperation, map_keyring_operation_error};
        use stellar_agent_test_support::keyring_mock;

        for injected in [
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            ))),
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(
                "credential store locked",
            ))),
            keyring_core::Error::NoDefaultStore,
            keyring_core::Error::BadEncoding(vec![0xff]),
        ] {
            keyring_mock::install().expect("mock keyring store");
            let dir = tempfile::tempdir().expect("tmp dir");
            let name = "rotate-key-read-error";
            let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
                .with_profile_name(name)
                .build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            {
                let mut writer = AuditWriter::open(profile.audit_log_path.clone(), None)
                    .expect("unkeyed writer");
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
                        "req-before-read-error",
                        None,
                    ))
                    .expect("append");
            }
            let log_before = std::fs::read(&profile.audit_log_path).expect("read log");
            assert!(binding_raw(name).is_none(), "no binding before rotation");
            let entry_ref = &profile.audit_log_hash_chain_key_id;
            let names_its_own_remedy = matches!(injected, keyring_core::Error::NoDefaultStore);
            let expected =
                map_keyring_operation_error(&injected, KeyringOperation::Read, &entry_ref.service);
            keyring_mock::inject_error(&entry_ref.service, &entry_ref.account, injected)
                .expect("inject audit-key read failure");
            let args = RotateAuditKeyArgs {
                name: Some(name.to_owned()),
                profile: None,
            };
            let cloned_profile = profile.clone();
            let error = match rotate(&args, move |_| Ok(cloned_profile.clone()), || Ok(())).await {
                Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
                Err(RotateRefusal::Wallet(error)) => error,
                Err(RotateRefusal::ProfileAccess(error)) => {
                    panic!("unexpected profile refusal: {error}")
                }
                Ok(_) => panic!("an audit-key read failure must refuse rotation: {expected}"),
            };
            assert_eq!(error.code(), expected.code());
            if names_its_own_remedy {
                assert_eq!(error.message(), expected.message());
            } else {
                assert_eq!(
                    error.message(),
                    format!(
                        "{}; investigate; if the stored audit key is corrupt, restore it from \
                         a copy of its keyring entry: a log under entry tags takes rows only \
                         under its own key, and `stellar-agent profile rotate-audit-key {name}` \
                         mints a key only for a log without entry tags, once the entry is \
                         removed; without a copy, see docs/maintainers/audit-log-recovery.md \
                         section 10",
                        expected.message()
                    )
                );
            }
            assert!(binding_raw(name).is_none(), "no binding is recorded");
            assert!(
                matches!(
                    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                        .expect("audit-key entry")
                        .get_password(),
                    Err(keyring_core::Error::NoEntry)
                ),
                "no audit key is minted"
            );
            assert_eq!(
                std::fs::read(&profile.audit_log_path).expect("read log after refusal"),
                log_before,
                "the log is byte-identical"
            );
            assert_eq!(
                KeyringTipAnchorStore::new(entry_ref, &profile.audit_log_path)
                    .load_raw()
                    .expect("read anchor"),
                None,
                "no anchor is recorded"
            );
        }
    }

    /// A stored audit key that is not base64 or not 32 bytes refuses with its
    /// decode code and the corrupt-key remedy, and rotation writes nothing:
    /// the stored value, the binding, the anchor, and the log stay as they
    /// were, and no audit key replaces the undecodable one.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_an_undecodable_key_with_the_remedy_and_writes_nothing() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, TipAnchorStore};
        use stellar_agent_test_support::keyring_mock;

        for (stored, sub_code) in [
            ("not base64!", "audit.key_decode_failed"),
            ("AAAA", "audit.key_length_error"),
        ] {
            keyring_mock::install().expect("mock keyring store");
            let dir = tempfile::tempdir().expect("tmp dir");
            let name = "rotate-key-undecodable";
            let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
                .with_profile_name(name)
                .build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            AuditWriter::open(profile.audit_log_path.clone(), None)
                .expect("unkeyed writer")
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
                    "req-before-undecodable-key",
                    None,
                ))
                .expect("append");
            let log_before = std::fs::read(&profile.audit_log_path).expect("read log");
            let entry_ref = &profile.audit_log_hash_chain_key_id;
            let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
                .expect("audit-key entry");
            entry
                .set_password(stored)
                .expect("store an undecodable key");

            let args = RotateAuditKeyArgs {
                name: Some(name.to_owned()),
                profile: None,
            };
            let cloned_profile = profile.clone();
            let error = match rotate(&args, move |_| Ok(cloned_profile.clone()), || Ok(())).await {
                Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
                Err(RotateRefusal::Wallet(error)) => error,
                Err(RotateRefusal::ProfileAccess(error)) => {
                    panic!("unexpected profile refusal: {error}")
                }
                Ok(_) => panic!("an undecodable audit key must refuse rotation"),
            };
            assert_eq!(error.code(), "internal.unexpected_state");
            let message = error.message();
            assert!(message.contains(sub_code), "{message}");
            assert!(
                message.contains(&format!(
                    "investigate; if the stored audit key is corrupt, restore it from a copy of \
                     its keyring entry: a log under entry tags takes rows only under its own \
                     key, and `stellar-agent profile rotate-audit-key {name}` mints a key only \
                     for a log without entry tags, once the entry is removed; without a copy, \
                     see docs/maintainers/audit-log-recovery.md section 10"
                )),
                "{message}"
            );
            assert_eq!(
                entry.get_password().expect("the stored value survives"),
                stored,
                "no audit key replaces the undecodable one"
            );
            assert!(binding_raw(name).is_none(), "no binding is recorded");
            assert_eq!(
                std::fs::read(&profile.audit_log_path).expect("read log after refusal"),
                log_before,
                "the log is byte-identical"
            );
            assert_eq!(
                KeyringTipAnchorStore::new(entry_ref, &profile.audit_log_path)
                    .load_raw()
                    .expect("read anchor"),
                None,
                "no anchor is recorded"
            );
        }
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
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
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
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
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

    /// A profile minting its first key adopts a log written only by unkeyed
    /// writers, even with its binding already recorded: a profile with no key
    /// has had no keyed use of its log. The adopted log then opens under the
    /// keyed path.
    #[tokio::test]
    #[serial]
    async fn the_first_key_adopts_a_quickstart_log_under_a_recorded_binding() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        use stellar_agent_test_support::keyring_mock;

        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-quickstart";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        {
            let mut writer =
                AuditWriter::open(profile.audit_log_path.clone(), None).expect("unkeyed writer");
            for request_id in ["req-quickstart-1", "req-quickstart-2"] {
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
                        request_id,
                        None,
                    ))
                    .expect("append");
            }
        }
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &profile,
            ))
            .expect("record the binding");

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(error)) => {
                panic!("the first key must adopt a quickstart log: {error}")
            }
            Err(RotateRefusal::ProfileAccess(error)) => panic!("profile access refused: {error}"),
        }
        let adopted = std::fs::read_to_string(&profile.audit_log_path)
            .expect("read the log")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| {
                let row: serde_json::Value = serde_json::from_str(line).expect("JSON row");
                row["kind"] == "audit_tip_anchored" && row["reason"] == "adopted"
            })
            .count();
        assert_eq!(adopted, 1, "the first key adopts the log once");

        let access = stellar_agent_network::keyring::keyed_audit_access(
            &profile,
            name,
            BindingCheck::Enforce,
        )
        .expect("keyed access");
        drop(
            AuditWriter::open(profile.audit_log_path.clone(), Some(access))
                .expect("the adopted log opens under the keyed path"),
        );
    }

    /// A profile whose old key is seeded and whose log holds the boundary row
    /// and one more row, written by the keyed, keyring-anchored writer.
    fn tagged_profile(name: &str, dir: &std::path::Path) -> Profile {
        use stellar_agent_core::audit_log::{AuditEntry, NewToolInvocation, PolicyDecision};

        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.join("audit.jsonl");
        rotate_hmac_like_key(&profile.audit_log_hash_chain_key_id, "test_seed")
            .expect("seed the old key");
        let mut writer = open_locked_audit_writer(&profile, name, BindingHistory::NotRecorded)
            .expect("open the writer");
        writer
            .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_pay_commit",
                "stellar:testnet",
                vec![],
                PolicyDecision::Allow,
                "req-pre",
            )))
            .expect("append a pre-rotation row");
        profile
    }

    /// The rotation appends `audit_entry_tags_rekeyed { cause: rotation }`
    /// and then its `keyring_key_written` row, both tagged under the new key:
    /// keyed verify under the new key checks every tag and reports the rekey
    /// row as the boundary.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_appends_a_rekey_row_under_the_new_key() {
        use stellar_agent_core::audit_log::verify_log;

        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-rekey";
        let profile = tagged_profile(name, dir.path());

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(e)) => panic!("the rotation must succeed: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the rotation must succeed: {e}"),
        }

        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .expect("read the log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON row"))
            .collect();
        let kinds: Vec<&str> = rows
            .iter()
            .map(|row| row["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(
            kinds,
            [
                "audit_entry_tags_started",
                "tool_invocation",
                "audit_entry_tags_rekeyed",
                "keyring_key_written"
            ]
        );
        assert_eq!(rows[2]["cause"], "rotation");
        let new_key = load_audit_hmac_key(&profile, name).expect("load the new key");
        let verified = verify_log(&profile.audit_log_path, Some(&new_key))
            .expect("the log verifies under the new key");
        assert!(verified.entry_tags_verified, "{verified:?}");
        let boundary = verified.entry_tags_boundary.expect("a boundary");
        assert_eq!(boundary.kind, "audit_entry_tags_rekeyed");
        assert_eq!(boundary.line, 3);
    }

    /// A log whose entry tags fail under the key being replaced refuses the
    /// rotation with `audit.entry_tag_invalid` before any key write: the
    /// stored key stays the old one.
    ///
    /// The failing row sits in a rotated archive, which the writer's open
    /// does not replay, so the open succeeds and the tag walk under the old
    /// key is what refuses.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_a_log_whose_tags_fail_under_the_old_key() {
        use stellar_agent_core::audit_log::rotation::test_seam;
        use stellar_agent_core::audit_log::test_helpers::rotated_archives_newest_first;
        use stellar_agent_core::audit_log::{AuditEntry, NewToolInvocation, PolicyDecision};

        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-old-tags";
        let profile = tagged_profile(name, dir.path());
        let old_key = load_audit_hmac_key(&profile, name).expect("load the old key");
        {
            let threshold = test_seam::set_rotation_threshold(&profile.audit_log_path, 1);
            let mut writer = open_locked_audit_writer(&profile, name, BindingHistory::NotRecorded)
                .expect("reopen the writer");
            writer
                .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
                    "stellar_pay_commit",
                    "stellar:testnet",
                    vec![],
                    PolicyDecision::Allow,
                    "req-rotated",
                )))
                .expect("append across a rotation");
            drop(threshold);
        }
        let archive = rotated_archives_newest_first(&profile.audit_log_path)
            .pop()
            .expect("an archive");
        // Strip the tag of the archive's second row; the chain is unchanged,
        // because the tag is outside the hashed body.
        let stripped: String = std::fs::read_to_string(&archive)
            .expect("read the archive")
            .split_inclusive('\n')
            .enumerate()
            .map(|(index, line)| {
                if index != 1 {
                    return line.to_owned();
                }
                let mut entry: AuditEntry = serde_json::from_str(line).expect("row");
                assert!(entry.entry_tag.take().is_some(), "the row was tagged");
                let mut bytes = serde_json::to_string(&entry).expect("serialize");
                bytes.push('\n');
                bytes
            })
            .collect();
        std::fs::write(&archive, stripped).expect("write the archive");

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let refused = rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        let Err(RotateRefusal::Integrity(error)) = refused else {
            panic!("the tag walk under the old key must refuse the rotation");
        };
        assert_eq!(error.wire_code(), "audit.entry_tag_invalid", "{error}");
        assert_eq!(
            *load_audit_hmac_key(&profile, name).expect("load the key"),
            *old_key,
            "the stored key is unchanged"
        );
    }

    /// The kinds of the rows of the log at `path`, oldest first.
    fn log_kinds(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .expect("read the log")
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("JSON row")["kind"]
                    .as_str()
                    .expect("kind")
                    .to_owned()
            })
            .collect()
    }

    /// A consent row the rotation's open drains while the anchor write fails
    /// lies past the anchor: the rotation refuses before the key write, with
    /// the recovery in the message, the old key in the keyring and no rekey
    /// row in the log.
    #[tokio::test]
    #[serial]
    async fn rotate_audit_key_refuses_while_the_anchor_is_behind_the_last_row() {
        use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox};

        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-anchor-behind";
        let log_path = dir.path().join("audit.jsonl");
        let audit_key = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build()
            .audit_log_hash_chain_key_id;
        let anchor = KeyringTipAnchorStore::new(&audit_key, &log_path)
            .anchor_entry_ref()
            .clone();
        let failing = stellar_agent_test_support::keyring_mock::install_with_write_failure_switch(
            &anchor.service,
            &anchor.account,
        )
        .expect("mock keyring store");
        let profile = tagged_profile(name, dir.path());
        let old_key = load_audit_hmac_key(&profile, name).expect("load the old key");
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
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            "req-queued",
        ))
        .expect("queue a consent row");
        failing.store(true, std::sync::atomic::Ordering::SeqCst);

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        let refused = rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await;
        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        let error = match refused {
            Err(RotateRefusal::Wallet(error)) => error,
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("unexpected profile refusal: {e}"),
            Ok(_) => panic!("a rotation with the anchor behind the last row must refuse"),
        };
        assert_eq!(error.code(), "audit.chain_key_unavailable", "{error}");
        assert!(
            error.message().contains("audit.tip_anchor_unavailable")
                && error.message().contains("the audit key was not rotated"),
            "{error}"
        );
        assert_eq!(
            *load_audit_hmac_key(&profile, name).expect("load the key"),
            *old_key,
            "the stored key is unchanged"
        );
        let kinds = log_kinds(&profile.audit_log_path);
        assert_eq!(
            kinds,
            [
                "audit_entry_tags_started",
                "tool_invocation",
                "approval_attested"
            ],
            "the open drained the consent row and the rotation wrote nothing"
        );
    }

    /// A rotation stopped after its key write, with the anchor covering every
    /// row tagged under the replaced key, is repaired by the next keyed open:
    /// the rerun opens under the persisted key, which appends the
    /// `open_repair` rekey row, and then rotates.
    #[tokio::test]
    #[serial]
    async fn a_rotation_stopped_after_its_key_write_is_repaired_by_the_rerun() {
        use stellar_agent_core::audit_log::verify_log;

        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-stopped";
        let profile = tagged_profile(name, dir.path());
        rotate_hmac_like_key(&profile.audit_log_hash_chain_key_id, "rotate_audit_key")
            .expect("persist the replacement key");

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(e)) => panic!("the rerun must rotate: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the rerun must rotate: {e}"),
        }
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .expect("read the log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON row"))
            .collect();
        let rekeys: Vec<&str> = rows
            .iter()
            .filter(|row| row["kind"] == "audit_entry_tags_rekeyed")
            .map(|row| row["cause"].as_str().expect("cause"))
            .collect();
        assert_eq!(rekeys, ["open_repair", "rotation"]);
        let key = load_audit_hmac_key(&profile, name).expect("load the key");
        let verified = verify_log(&profile.audit_log_path, Some(&key)).expect("the log verifies");
        assert!(verified.entry_tags_verified, "{verified:?}");
    }

    /// A log under entry tags takes no first mint: with its key entry
    /// removed, the rotation refuses before it writes a key or a row. The log
    /// moved aside as evidence, the profile starts a new log once the
    /// re-anchor acknowledges the rollback of the old anchor, and the
    /// rotation then mints a key that tags the new log.
    #[tokio::test]
    #[serial]
    async fn a_lost_key_takes_no_first_mint_on_a_keyed_log() {
        use crate::commands::audit::reanchor::{ReanchorArgs, reanchor};
        use stellar_agent_core::audit_log::verify_log;

        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-lost-key";
        let profile = tagged_profile(name, dir.path());
        let entry = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&entry.service, &entry.account)
            .expect("key entry")
            .delete_credential()
            .expect("remove the key");
        let log_before = std::fs::read(&profile.audit_log_path).expect("read the log");
        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let run = || {
            let cloned_profile = profile.clone();
            rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(()))
        };

        let error = match run().await {
            Err(RotateRefusal::Wallet(error)) => error,
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("unexpected profile refusal: {e}"),
            Ok(_) => panic!("a keyed log without its key must not take a first mint"),
        };
        assert_eq!(error.code(), "audit.chain_key_unavailable", "{error}");
        assert!(
            error
                .message()
                .contains("only a writer holding the profile's audit key appends to this log"),
            "{error}"
        );
        assert!(
            load_audit_hmac_key(&profile, name).is_err(),
            "no key was minted"
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).expect("read the log"),
            log_before,
            "the log is unchanged"
        );

        let saved = dir.path().join("saved");
        std::fs::create_dir(&saved).expect("evidence directory");
        for file in std::fs::read_dir(dir.path()).expect("list the audit directory") {
            let file = file.expect("directory entry").path();
            if file.is_file() && file.extension().is_none_or(|extension| extension != "lock") {
                std::fs::rename(&file, saved.join(file.file_name().expect("file name")))
                    .expect("move the lineage aside");
            }
        }
        assert!(
            verify_log(&saved.join("audit.jsonl"), None).is_ok(),
            "the saved log keeps its hash chain"
        );
        let refused = run().await;
        assert!(
            matches!(&refused, Err(RotateRefusal::Wallet(e)) if e.code() == "audit.tip_anchor_mismatch"),
            "the old anchor names the moved log"
        );
        let cloned_profile = profile.clone();
        reanchor(
            &ReanchorArgs {
                profile: name.to_owned(),
                acknowledge_rollback: true,
                acknowledge_binding_change: false,
                acknowledge_unauthenticated_tail: false,
            },
            move |_name| Ok(cloned_profile.clone()),
            || Ok(()),
        )
        .expect("the re-anchor acknowledges the rollback");
        match run().await {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(e)) => panic!("the first mint on the new log: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the first mint on the new log: {e}"),
        }
        let key = load_audit_hmac_key(&profile, name).expect("the minted key");
        let verified =
            verify_log(&profile.audit_log_path, Some(&key)).expect("the new log verifies");
        assert!(verified.entry_tags_verified, "{verified:?}");
    }

    /// A first mint takes an anchored log without entry tags: a writer
    /// without the key and with the anchor store opens it, and the minted key
    /// tags the log from then on.
    #[tokio::test]
    #[serial]
    async fn a_first_mint_takes_an_anchored_log_without_entry_tags() {
        use stellar_agent_core::audit_log::{
            AuditEntry, NewToolInvocation, PolicyDecision, verify_log,
        };

        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let name = "rotate-anchored-untagged";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            None,
            KeyringTipAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
            BindingHistory::NotRecorded,
        )
        .expect("open an anchored writer without the key");
        writer
            .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_pay_commit",
                "stellar:testnet",
                vec![],
                PolicyDecision::Allow,
                "req-untagged",
            )))
            .expect("append an untagged anchored row");
        drop(writer);
        assert!(load_audit_hmac_key(&profile, name).is_err(), "no key yet");

        let args = RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        let cloned_profile = profile.clone();
        match rotate(&args, move |_name| Ok(cloned_profile.clone()), || Ok(())).await {
            Ok(_) => {}
            Err(RotateRefusal::Integrity(e)) => panic!("unexpected integrity refusal: {e}"),
            Err(RotateRefusal::Wallet(e)) => panic!("the first mint: {e}"),
            Err(RotateRefusal::ProfileAccess(e)) => panic!("the first mint: {e}"),
        }
        let key = load_audit_hmac_key(&profile, name).expect("the minted key");
        let verified = verify_log(&profile.audit_log_path, Some(&key)).expect("the log verifies");
        assert!(verified.entry_tags_verified, "{verified:?}");
    }

    /// Installation coordinates refuse on testnet before the keyring opens.
    #[tokio::test]
    #[serial]
    async fn installation_coordinate_refuses_without_writing() {
        crate::common::installation_key_fixture::assert_installation_profile_refusal(
            |profile| &mut profile.audit_log_hash_chain_key_id,
            async |fixture, profile, name| {
                let args = RotateAuditKeyArgs {
                    name: Some(name.to_owned()),
                    profile: None,
                };
                run_with_dependencies(&args, |_| Ok(profile.clone()), || fixture.init()).await
            },
        )
        .await;
    }
}
