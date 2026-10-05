//! `stellar-agent audit reanchor --profile <name>` with
//! `--acknowledge-rollback`, `--acknowledge-binding-change`, or both: move the
//! audit log's keyring-held tip anchor to the log's current tip.
//!
//! # When this is needed
//!
//! The tip anchor keeps the active log file's entry count, tip hash, and byte
//! offset in the keyring, outside the log file. A log that no longer contains
//! the anchored tip (restored from an older copy, truncated, or replaced) makes
//! every value-moving verb refuse with `audit.tip_anchor_mismatch`, and makes
//! `audit verify --profile` refuse the same way.
//!
//! The audit binding records the log path digest and audit-key coordinate a
//! persisted profile writes under. A profile edited to name another log or key
//! makes every keyed audit writer refuse with `audit.log_binding_changed`. This
//! verb is the only way out of either state.
//!
//! The anchor, the re-anchor counter, and the audit binding live in the
//! keyring, outside the log file. Anyone who can restore the keyring's own
//! storage together with the log can restore an older state. With a headless
//! keyring backend these entries are kept in a file on the same host. Anyone
//! who can write that file can restore older entries or delete one, which
//! needs no key material.
//!
//! # Why the acknowledgement is required
//!
//! Moving the anchor forgives whatever caused the disagreement, and accepting a
//! binding change forgives whatever changed the profile. Either may have been
//! the operator or tampering. The verb cannot tell them apart, so it refuses
//! until the operator acknowledges each condition. A refusal writes nothing and
//! exits 1.
//!
//! # The acknowledgement matrix
//!
//! - Binding equal or absent: `--acknowledge-rollback` is required and
//!   `--acknowledge-binding-change` is ignored. The verb re-anchors, bumps the
//!   counter, appends `rollback_acknowledged`, and records an absent binding.
//! - Binding changed or unreadable, anchor absent or agreeing:
//!   `--acknowledge-binding-change` is required and `--acknowledge-rollback` is
//!   ignored. The verb appends one `binding_changed` row.
//! - Binding changed or unreadable, anchor disagreeing: both flags are
//!   required. The verb appends `rollback_acknowledged`, then
//!   `binding_changed`.
//!
//! An anchor disagrees when the anchor-against-walk rule of `audit verify`
//! refuses it, or when it cannot be parsed. A log that moved forward past its
//! anchor agrees. The binding is checked before the repair writer opens,
//! because opening creates the directory, the lock sidecar, and the log file.
//! Disagreement is decided again under the writer's lock, and that decision is
//! the one acted on.
//!
//! # What it does
//!
//! Replays the whole active file first, so a log whose own hash chain is broken
//! is refused rather than blessed. Then it writes the current tip as the anchor,
//! increments the current path's monotonic re-anchor counter once, and appends
//! one `audit_tip_anchored` row per acknowledged condition, each carrying the
//! one bumped count. A `rollback_acknowledged` row names this path's superseded
//! anchor. A `binding_changed` row names the anchor of the log path the
//! previous binding named, or none when that binding was unreadable. The new
//! binding is stored last, so a run that stops earlier leaves the refusal in
//! place and a rerun appends its rows again.
//!
//! After the last repair row, and before the new binding is stored, it drains
//! the audit outbox. Consent rows queued while the log was refused follow the
//! repair rows. A drain refusal does not undo the repair: the verb succeeds
//! and lists the refusal under `warnings`, led by its `audit.*` sub-code, and
//! the rows stay queued. Without a required acknowledgement the log, the
//! anchors, the binding, and the outbox are left unchanged.
//!
//! # Concurrency
//!
//! Repair takes the audit writer's exclusive sidecar lock. A running MCP server
//! holds that lock for its lifetime, so this verb refuses with
//! `audit.writer_locked` while the server is up. Stop the server, repair, start
//! it again.
//!
//! # Exit codes
//!
//! - 0 on success.
//! - 1 without a required acknowledgement, and on any failure.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::{
    audit_log::{
        AuditBinding, AuditWriter, ReanchorAcknowledgement, ReanchorReport, RecordedBinding,
        StoredTipAnchor, TipAnchor, WriterError, stored_anchor_disagrees_with_walk, verify_log,
    },
    envelope::Envelope,
    error::{InternalError, ValidationError, WalletError},
    profile::schema::Profile,
};
use stellar_agent_network::keyring::{
    KeyringAuditBindingStore, KeyringTipAnchorStore, init_platform_keyring_store,
};

use crate::common::profile_access::load_profile_reconciled;
use crate::common::render;

use super::super::profile::audit_emit::load_audit_hmac_key;

/// Arguments for the `audit reanchor` subcommand.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ReanchorArgs {
    /// Profile whose audit log should be re-anchored.
    ///
    /// The anchor is held per log PATH; this names the profile whose configured
    /// `audit_log_path` and audit keyring coordinate identify it.
    #[arg(long, value_name = "NAME", required = true)]
    pub profile: String,

    /// Accept the log's current tip as authoritative.
    ///
    /// Required when the stored anchor disagrees with the log, and whenever the
    /// audit binding is equal or absent. Without it the verb reports the anchor
    /// it would replace and the one it would write, changes nothing, and exits
    /// 1.
    #[arg(long)]
    pub acknowledge_rollback: bool,

    /// Accept a profile whose audit log path or audit key differs from the
    /// audit binding recorded in the keyring.
    ///
    /// Required when the binding changed or cannot be parsed, and ignored
    /// otherwise. Without it the verb changes nothing and exits 1.
    #[arg(long)]
    pub acknowledge_binding_change: bool,
}

/// Success payload for the `audit reanchor` envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct ReanchorData {
    /// Profile whose audit log was re-anchored.
    profile: String,
    /// Coordinates of the replaced anchor as `<entry count>:<end offset>`,
    /// `None` when the log had never been anchored, or a structural description
    /// when the stored value could not be parsed.
    previous_anchor: Option<String>,
    /// Coordinates of the anchor now in force, or `none` when the repaired log
    /// has no entries to anchor.
    current_anchor: String,
    /// The current path's re-anchor counter after this run. Each run bumps it
    /// once, whether it acknowledged a rollback, a binding change, or both.
    reanchor_count: u64,
    /// The conditions this run acknowledged, in the order their rows were
    /// appended: `rollback`, `binding_change`.
    acknowledged: Vec<&'static str>,
    /// How the recorded audit binding compared with the profile before this
    /// run: `absent`, `equal`, `changed`, or `unreadable`.
    recorded_binding: &'static str,
    /// For a binding change, the anchor of the log path the previous binding
    /// named, as `<entry count>:<end offset>`. `None` when nothing was
    /// anchored there, when the recorded binding was unreadable, or when no
    /// binding change was acknowledged.
    previous_binding_anchor: Option<String>,
    /// Number of queued audit-outbox rows appended after the repair rows.
    /// Omitted when the drain refused: the rows appended before the refusal
    /// stay queued and are appended again by the next drain.
    #[serde(skip_serializing_if = "Option::is_none")]
    outbox_drained: Option<usize>,
    /// Conditions the repair stood despite, each led by its `audit.*`
    /// sub-code: `audit.outbox_unusable`, `audit.outbox_busy`, or the
    /// condition an append of the drain refused on, such as
    /// `audit.io_error`. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// Runs the `audit reanchor` subcommand.
///
/// Returns `0` on success, `1` on refusal or failure.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the envelope and exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ReanchorArgs) -> i32 {
    run_with_dependencies(args, load_profile, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`]. Tests substitute an in-memory profile backed
/// by a temp-dir audit log and a spy initialiser, so the acknowledgement gate and
/// the repair itself can be driven against a mock keyring store without touching
/// the OS keychain or a persisted profile file.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &ReanchorArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, WalletError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    match reanchor(args, load_profile, init_keyring) {
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

/// Performs the repair and returns what the verb renders, or the refusal.
fn reanchor<LoadProfile, InitKeyring>(
    args: &ReanchorArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> Result<ReanchorData, WalletError>
where
    LoadProfile: Fn(&str) -> Result<Profile, WalletError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let profile = load_profile(&args.profile)?;
    init_keyring()?;

    // The binding is read before the repair writer opens: opening creates the
    // directory, the lock sidecar, and the log file at the path the profile
    // names.
    let binding_store = KeyringAuditBindingStore::for_profile(&args.profile);
    let expected = AuditBinding::for_profile(&profile);
    let recorded = binding_store.classify(&expected)?;
    if recorded.refuses() {
        return reanchor_binding_change(args, &profile, &binding_store, &expected, &recorded);
    }

    let mut writer = open_repair_writer(&profile, &args.profile)?;
    let previous = writer
        .stored_tip_anchor()
        .map_err(|e| writer_error(&e, &args.profile))?;
    let proposed = writer
        .current_tip_anchor()
        .map_err(|e| writer_error(&e, &args.profile))?;

    if !args.acknowledge_rollback {
        return Err(WalletError::Validation(
            ValidationError::AuditReanchorNotAcknowledged {
                profile: args.profile.clone(),
                current: previous.coordinates().unwrap_or_else(|| "none".to_owned()),
                proposed: proposed
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), TipAnchor::coordinates),
            },
        ));
    }

    let report = writer
        .reanchor()
        .map_err(|e| writer_error(&e, &args.profile))?;
    // An absent binding is recorded after a successful repair.
    if recorded == RecordedBinding::Absent {
        binding_store.store(&expected)?;
    }
    Ok(reanchor_data(
        &args.profile,
        report,
        vec!["rollback"],
        recorded.label(),
        None,
    ))
}

/// The arm of [`reanchor`] for a binding that changed or does not parse.
///
/// `--acknowledge-binding-change` is required. `--acknowledge-rollback` is
/// required too when the current path's anchor disagrees with its log, and is
/// ignored otherwise. A missing flag refuses before the repair writer opens
/// and writes nothing. The new binding is stored after every row is appended.
fn reanchor_binding_change(
    args: &ReanchorArgs,
    profile: &Profile,
    binding_store: &KeyringAuditBindingStore,
    expected: &AuditBinding,
    recorded: &RecordedBinding,
) -> Result<ReanchorData, WalletError> {
    let refusal = |missing: &'static str| {
        WalletError::Validation(ValidationError::AuditBindingChangeNotAcknowledged {
            profile: args.profile.clone(),
            missing,
        })
    };

    let disagreeing = anchor_disagrees_before_open(profile)?;
    if let Some(missing) = missing_acknowledgements(args, disagreeing) {
        return Err(refusal(missing));
    }

    let mut writer = open_repair_writer(profile, &args.profile)?;
    // Decided again under the lock; this decision is the one acted on.
    let disagreeing = writer
        .stored_anchor_disagrees()
        .map_err(|e| writer_error(&e, &args.profile))?;
    if let Some(missing) = missing_acknowledgements(args, disagreeing) {
        return Err(refusal(missing));
    }

    let previous_binding_anchor = match recorded {
        RecordedBinding::Changed(old) => previous_binding_anchor(old)?,
        RecordedBinding::Absent | RecordedBinding::Equal | RecordedBinding::Unparseable => None,
    };

    let mut acknowledgements = Vec::with_capacity(2);
    let mut acknowledged = Vec::with_capacity(2);
    if disagreeing {
        acknowledgements.push(ReanchorAcknowledgement::Rollback);
        acknowledged.push("rollback");
    }
    acknowledgements.push(ReanchorAcknowledgement::BindingChange {
        previous_anchor: previous_binding_anchor.clone(),
    });
    acknowledged.push("binding_change");

    let report = writer
        .reanchor_acknowledging(&acknowledgements)
        .map_err(|e| writer_error(&e, &args.profile))?;
    // Stored last: a run that stops before this write leaves the refusal in
    // place, and a rerun appends its rows again.
    binding_store.store(expected)?;
    Ok(reanchor_data(
        &args.profile,
        report,
        acknowledged,
        recorded.label(),
        previous_binding_anchor,
    ))
}

/// The acknowledgement flags a changed binding still needs, or `None` when
/// every required flag is present.
fn missing_acknowledgements(args: &ReanchorArgs, disagreeing: bool) -> Option<&'static str> {
    let rollback_missing = disagreeing && !args.acknowledge_rollback;
    match (args.acknowledge_binding_change, rollback_missing) {
        (true, false) => None,
        (true, true) => Some("--acknowledge-rollback"),
        (false, false) => Some("--acknowledge-binding-change"),
        (false, true) => Some("--acknowledge-binding-change and --acknowledge-rollback"),
    }
}

/// Whether the current path's stored anchor disagrees with its log, decided
/// without opening a writer.
///
/// Reads the stored value and walks the log read-only. An absent anchor
/// agrees; an unparseable one disagrees. A log that cannot be walked has no
/// tip an anchor could agree with, so a present anchor disagrees with it.
fn anchor_disagrees_before_open(profile: &Profile) -> Result<bool, WalletError> {
    let store = KeyringTipAnchorStore::new(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    let raw = stellar_agent_core::audit_log::TipAnchorStore::load_raw(&store)
        .map_err(|e| tip_anchor_unavailable(&e))?;
    let stored = StoredTipAnchor::from_raw(raw.as_deref());
    if stored == StoredTipAnchor::Absent {
        return Ok(false);
    }
    let walked = verify_log(&profile.audit_log_path, None)
        .ok()
        .and_then(|ok| ok.active_tip);
    Ok(
        stored_anchor_disagrees_with_walk(&profile.audit_log_path, &stored, walked.as_ref())
            .unwrap_or(true),
    )
}

/// Reads the anchor of the log path a previous binding named, at the
/// coordinate that binding's audit key and path digest derive.
///
/// Returns its `<entry count>:<end offset>` coordinates, a structural
/// description when the stored value does not parse, or `None` when nothing
/// was anchored there.
fn previous_binding_anchor(old: &AuditBinding) -> Result<Option<String>, WalletError> {
    let store = KeyringTipAnchorStore::for_path_digest(&old.audit_key, &old.log_path_sha256);
    let raw = stellar_agent_core::audit_log::TipAnchorStore::load_raw(&store)
        .map_err(|e| tip_anchor_unavailable(&e))?;
    Ok(StoredTipAnchor::from_raw(raw.as_deref()).coordinates())
}

fn tip_anchor_unavailable(e: &impl std::fmt::Display) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!("audit.tip_anchor_unavailable: {e}"),
    })
}

/// The success payload for a completed repair.
///
/// A drain refusal after the repair is a warning: the repair stands and the
/// queued rows stay queued.
fn reanchor_data(
    profile: &str,
    report: ReanchorReport,
    acknowledged: Vec<&'static str>,
    recorded_binding: &'static str,
    previous_binding_anchor: Option<String>,
) -> ReanchorData {
    ReanchorData {
        profile: profile.to_owned(),
        previous_anchor: report.previous.coordinates(),
        current_anchor: report
            .current
            .as_ref()
            .map_or_else(|| "none".to_owned(), TipAnchor::coordinates),
        reanchor_count: report.reanchor_count,
        outbox_drained: report.outbox_drained,
        warnings: report.outbox_refusal.into_iter().collect(),
        acknowledged,
        recorded_binding,
        previous_binding_anchor,
    }
}

/// Loads the named profile, reconciled, mapping the failure into the CLI
/// envelope model.
fn load_profile(profile_name: &str) -> Result<Profile, WalletError> {
    load_profile_reconciled(&ResolvedProfileName::from_flag(profile_name)).map_err(|e| {
        tracing::debug!(
            profile = %profile_name,
            error = %e,
            "profile access refused for audit reanchor"
        );
        e.to_wallet_error(profile_name)
    })
}

/// Opens the profile's audit writer with the tip-anchor check SKIPPED.
///
/// An ordinary open would refuse on exactly the logs this verb exists to
/// repair. The writer still takes the exclusive sidecar lock, and
/// [`AuditWriter::reanchor`] still replays the whole file before moving the
/// anchor, so a broken chain is refused on its own merits.
///
/// A profile with no chain-root key yet opens unkeyed: the anchor is
/// independent of that key, and refusing would leave an unkeyed log with no
/// repair path.
fn open_repair_writer(profile: &Profile, profile_name: &str) -> Result<AuditWriter, WalletError> {
    let hmac_key = load_audit_hmac_key(profile, profile_name).ok();
    let tip_anchor = KeyringTipAnchorStore::shared(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    AuditWriter::open_for_reanchor(profile.audit_log_path.clone(), hmac_key, tip_anchor)
        .map_err(|e| writer_error(&e, profile_name))
}

/// Maps a writer failure into the CLI envelope model.
///
/// Delegates to [`super::audit_writer_error`], which gives a held writer lock
/// and a tip-anchor mismatch the codes the documentation names for them; every
/// other failure carries `audit.reanchor_failed`.
fn writer_error(e: &WriterError, profile_name: &str) -> WalletError {
    super::audit_writer_error(e, "audit.reanchor_failed", profile_name)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    use clap::Parser;
    use clap::error::ErrorKind;

    use super::*;

    /// Local flatten wrapper so the `ReanchorArgs` clap contract can be parsed
    /// in isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ReanchorArgs,
    }

    #[test]
    fn profile_flag_is_required() {
        let err = Wrap::try_parse_from(["prog", "--acknowledge-rollback"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn acknowledge_rollback_defaults_off() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme"]).expect("parses");
        assert_eq!(w.args.profile, "acme");
        assert!(
            !w.args.acknowledge_rollback,
            "the acknowledgement must never default on"
        );
    }

    #[test]
    fn acknowledge_rollback_parses() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme", "--acknowledge-rollback"])
            .expect("parses");
        assert!(w.args.acknowledge_rollback);
    }

    // ── The acknowledgement gate and the repair, end to end ──────────────────

    use serial_test::serial;
    use stellar_agent_core::audit_log::{
        AuditEntry, AuditWriter, NewToolInvocation, PolicyDecision, TipAnchorStore as _,
    };
    use stellar_agent_network::keyring::KeyringTipAnchorStore as TestAnchorStore;
    use stellar_agent_test_support::keyring_mock;

    fn sample_entry() -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            vec!["destination".to_owned()],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ))
    }

    /// Builds a keyed profile over a temp-dir audit log and rolls its log back
    /// behind the anchor, which is the state the repair verb exists to fix.
    fn rolled_back_profile(name: &'static str, dir: &std::path::Path) -> Profile {
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.join("audit.jsonl");
        let coord = &profile.audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");

        let store = TestAnchorStore::shared(coord, &profile.audit_log_path);
        let key = load_audit_hmac_key(&profile, "test-profile").expect("load key");
        let snapshot = {
            let mut writer =
                AuditWriter::open_with_tip_anchor(profile.audit_log_path.clone(), Some(key), store)
                    .expect("open anchored");
            writer.write_entry(sample_entry()).expect("append");
            writer.write_entry(sample_entry()).expect("append");
            let snapshot = std::fs::read(&profile.audit_log_path).expect("read log");
            writer.write_entry(sample_entry()).expect("append");
            snapshot
        };
        std::fs::write(&profile.audit_log_path, &snapshot).expect("roll the log back");
        profile
    }

    #[tokio::test]
    #[serial]
    async fn without_the_acknowledgement_nothing_is_written_and_the_exit_code_is_one() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = rolled_back_profile("reanchor-gate", dir.path());

        let store = TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        );
        let before = store.load_anchor().expect("read anchor");
        let log_before = std::fs::read(&profile.audit_log_path).expect("read log");

        let args = ReanchorArgs {
            profile: "reanchor-gate".to_owned(),
            acknowledge_rollback: false,
            acknowledge_binding_change: false,
        };
        let cloned = profile.clone();
        let code = run_with_dependencies(&args, move |_| Ok(cloned.clone()), || Ok(())).await;

        assert_eq!(code, 1, "the verb must refuse without the acknowledgement");
        assert_eq!(
            store.load_anchor().expect("read anchor"),
            before,
            "a refused repair must not move the anchor"
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).expect("read log"),
            log_before,
            "a refused repair must not append a row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn with_the_acknowledgement_the_log_is_repaired_and_the_counter_advances() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = rolled_back_profile("reanchor-repair", dir.path());

        let store = TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        );
        assert_eq!(store.reanchor_count().expect("read counter"), None);

        let args = ReanchorArgs {
            profile: "reanchor-repair".to_owned(),
            acknowledge_rollback: true,
            acknowledge_binding_change: false,
        };
        let cloned = profile.clone();
        let code = run_with_dependencies(&args, move |_| Ok(cloned.clone()), || Ok(())).await;

        assert_eq!(code, 0, "the repair must succeed");
        assert_eq!(
            store.reanchor_count().expect("read counter"),
            Some(1),
            "an acknowledged rollback must advance the counter"
        );

        let content = std::fs::read_to_string(&profile.audit_log_path).expect("read log");
        let repairs = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter(|line| {
                let row: serde_json::Value = serde_json::from_str(line).expect("JSON row");
                row["kind"] == "audit_tip_anchored" && row["reason"] == "rollback_acknowledged"
            })
            .count();
        assert_eq!(repairs, 1, "the repair must be recorded in the log");

        // The repaired log opens cleanly under the ordinary anchored path.
        let key = load_audit_hmac_key(&profile, "test-profile").expect("load key");
        AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            Some(key),
            TestAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .expect("the repaired log must open cleanly");
    }

    // ── The audit binding matrix ─────────────────────────────────────────────

    use stellar_agent_core::audit_log::BindingCheck;
    use stellar_agent_network::keyring::KeyringAuditBindingStore as TestBindingStore;

    fn args_with(profile: &str, rollback: bool, binding: bool) -> ReanchorArgs {
        ReanchorArgs {
            profile: profile.to_owned(),
            acknowledge_rollback: rollback,
            acknowledge_binding_change: binding,
        }
    }

    fn run_reanchor(args: &ReanchorArgs, profile: &Profile) -> Result<ReanchorData, WalletError> {
        let cloned = profile.clone();
        reanchor(args, move |_| Ok(cloned.clone()), || Ok(()))
    }

    /// A keyed profile whose log at `old.jsonl` holds `entries` anchored rows.
    fn anchored_profile(name: &str, dir: &std::path::Path, entries: usize) -> Profile {
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct")
            .with_profile_name(name)
            .build();
        profile.audit_log_path = dir.join("old.jsonl");
        let coord = profile.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");
        write_anchored(&profile, entries);
        profile
    }

    fn write_anchored(profile: &Profile, entries: usize) {
        let key = load_audit_hmac_key(profile, "test-profile").expect("load key");
        let store = TestAnchorStore::shared(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        );
        let mut writer =
            AuditWriter::open_with_tip_anchor(profile.audit_log_path.clone(), Some(key), store)
                .expect("open anchored");
        for _ in 0..entries {
            writer.write_entry(sample_entry()).expect("append");
        }
    }

    fn record_binding(name: &str, profile: &Profile) {
        TestBindingStore::for_profile(name)
            .store(&AuditBinding::for_profile(profile))
            .expect("record binding");
    }

    fn raw_binding(name: &str) -> Option<String> {
        TestBindingStore::for_profile(name)
            .load_raw()
            .expect("read binding")
    }

    fn raw_anchor(profile: &Profile) -> Option<String> {
        stellar_agent_core::audit_log::TipAnchorStore::load_raw(&TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        ))
        .expect("read anchor")
    }

    fn anchor_coordinates(profile: &Profile) -> String {
        stellar_agent_core::audit_log::TipAnchorStore::load_anchor(&TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        ))
        .expect("read anchor")
        .expect("anchored")
        .coordinates()
    }

    fn counter(profile: &Profile) -> Option<u64> {
        TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        )
        .reanchor_count()
        .expect("read counter")
    }

    fn tip_rows(profile: &Profile) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON row"))
            .filter(|row| row["kind"] == "audit_tip_anchored")
            .collect()
    }

    /// Everything a refusal must leave untouched.
    fn snapshot(name: &str, old: &Profile, new: &Profile) -> Vec<Option<Vec<u8>>> {
        vec![
            std::fs::read(&old.audit_log_path).ok(),
            std::fs::read(&new.audit_log_path).ok(),
            std::fs::read(AuditOutbox::for_log(&old.audit_log_path).path()).ok(),
            std::fs::read(AuditOutbox::for_log(&new.audit_log_path).path()).ok(),
            raw_anchor(old).map(String::into_bytes),
            raw_anchor(new).map(String::into_bytes),
            raw_binding(name).map(String::into_bytes),
            counter(new).map(|c| c.to_string().into_bytes()),
        ]
    }

    #[test]
    #[serial]
    fn rollback_flag_alone_on_a_changed_binding_refuses_and_writes_nothing() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-refuse", dir.path(), 2);
        record_binding("bind-refuse", &old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");
        AuditOutbox::for_log(&new.audit_log_path)
            .append(&queued_consent("queued-refused"))
            .expect("queue");
        let before = snapshot("bind-refuse", &old, &new);

        let err = run_reanchor(&args_with("bind-refuse", true, false), &new)
            .expect_err("the binding flag is required");
        assert_eq!(err.code(), "validation.acknowledgement_required");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AuditBindingChangeNotAcknowledged {
                    missing: "--acknowledge-binding-change",
                    ..
                })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("--acknowledge-binding-change"));
        assert!(
            snapshot("bind-refuse", &old, &new) == before,
            "the log, both anchors, the binding, and the outbox are byte-identical"
        );
        assert!(
            !new.audit_log_path.exists(),
            "nothing is created at the new path"
        );
        assert!(!dir.path().join("new.jsonl.lock").exists());
    }

    #[test]
    #[serial]
    fn the_binding_flag_on_an_equal_binding_is_ignored_and_the_rollback_rule_applies() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = anchored_profile("bind-equal", dir.path(), 2);
        record_binding("bind-equal", &profile);

        let err = run_reanchor(&args_with("bind-equal", false, true), &profile)
            .expect_err("an equal binding still needs the rollback flag");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AuditReanchorNotAcknowledged { .. })
            ),
            "{err:?}"
        );

        let data = run_reanchor(&args_with("bind-equal", true, true), &profile)
            .expect("the rollback rule applies");
        assert_eq!(data.acknowledged, vec!["rollback"]);
        assert_eq!(data.recorded_binding, "equal");
        let rows = tip_rows(&profile);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["reason"], "rollback_acknowledged");
    }

    #[test]
    #[serial]
    fn an_absent_binding_is_recorded_after_a_rollback_repair() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = anchored_profile("bind-absent", dir.path(), 2);
        assert!(raw_binding("bind-absent").is_none(), "nothing recorded yet");
        let data = run_reanchor(&args_with("bind-absent", true, false), &profile)
            .expect("repair succeeds");
        assert_eq!(data.recorded_binding, "absent");
        assert!(
            raw_binding("bind-absent")
                == Some(AuditBinding::for_profile(&profile).to_keyring_value()),
            "an absent binding is recorded after the repair"
        );
    }

    #[test]
    #[serial]
    fn the_binding_flag_alone_accepts_a_changed_binding_with_an_agreeing_anchor() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-accept", dir.path(), 2);
        record_binding("bind-accept", &old);
        let old_anchor = anchor_coordinates(&old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");

        for id in ["queued-1", "queued-2"] {
            AuditOutbox::for_log(&new.audit_log_path)
                .append(&queued_consent(id))
                .expect("queue");
        }

        let data = run_reanchor(&args_with("bind-accept", false, true), &new)
            .expect("the binding flag accepts the change");
        assert_eq!(data.acknowledged, vec!["binding_change"]);
        assert_eq!(data.recorded_binding, "changed");
        assert_eq!(
            data.previous_binding_anchor.as_deref(),
            Some(old_anchor.as_str())
        );

        assert_eq!(data.outbox_drained, Some(2));
        assert!(data.warnings.is_empty(), "{:?}", data.warnings);
        let all_rows = log_rows(&new);
        assert_eq!(all_rows.len(), 3, "{all_rows:?}");
        assert_eq!(all_rows[0]["reason"], "binding_changed");
        assert_eq!(all_rows[1]["request_id"], "queued-1");
        assert_eq!(all_rows[2]["request_id"], "queued-2");
        assert!(outbox_file(&new).is_empty());
        assert_eq!(inspect_outbox(&new.audit_log_path).unwrap().pending, 0);
        let json = serde_json::to_value(&data).expect("JSON");
        assert_eq!(json["outbox_drained"], 2);
        assert!(json.get("warnings").is_none(), "{json}");

        let rows = tip_rows(&new);
        assert_eq!(rows.len(), 1, "exactly one row: {rows:?}");
        assert_eq!(rows[0]["reason"], "binding_changed");
        assert_eq!(rows[0]["previous_anchor"], old_anchor.as_str());
        assert_eq!(rows[0]["reanchor_count"], 1);
        assert_eq!(counter(&new), Some(1), "the counter is bumped once");
        assert!(
            raw_binding("bind-accept") == Some(AuditBinding::for_profile(&new).to_keyring_value()),
            "the new binding is stored"
        );
        assert_eq!(anchor_coordinates(&new), data.current_anchor);

        let access = stellar_agent_network::keyring::keyed_audit_access(
            &new,
            "bind-accept",
            BindingCheck::Enforce,
        )
        .expect("a keyed acquisition proceeds");
        AuditWriter::open(new.audit_log_path.clone(), Some(access))
            .expect("the accepted log opens keyed");
    }

    /// On a changed binding with an agreeing anchor, the rollback flag is
    /// ignored: the repair appends one `binding_changed` row and no
    /// `rollback_acknowledged` row.
    #[test]
    #[serial]
    fn the_rollback_flag_is_ignored_on_a_changed_binding_with_an_agreeing_anchor() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-ignore-rollback", dir.path(), 2);
        record_binding("bind-ignore-rollback", &old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");

        let data = run_reanchor(&args_with("bind-ignore-rollback", true, true), &new)
            .expect("both flags accept the change");
        assert_eq!(data.acknowledged, vec!["binding_change"]);
        let rows = tip_rows(&new);
        assert_eq!(rows.len(), 1, "exactly one row: {rows:?}");
        assert_eq!(rows[0]["reason"], "binding_changed");
        assert_eq!(counter(&new), Some(1), "the counter is bumped once");
    }

    /// Rolls the log at `profile`'s path back one entry behind its anchor.
    fn roll_back(profile: &Profile) {
        let before = std::fs::read(&profile.audit_log_path).expect("read log");
        write_anchored(profile, 1);
        assert_ne!(std::fs::read(&profile.audit_log_path).unwrap(), before);
        std::fs::write(&profile.audit_log_path, &before).expect("roll back");
    }

    #[test]
    #[serial]
    fn both_flags_on_a_disagreeing_anchor_append_rollback_then_binding_changed() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-both", dir.path(), 2);
        record_binding("bind-both", &old);
        let old_anchor = anchor_coordinates(&old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");
        write_anchored(&new, 2);
        roll_back(&new);
        let superseded = anchor_coordinates(&new);
        AuditOutbox::for_log(&new.audit_log_path)
            .append(&queued_consent("queued-refused"))
            .expect("queue");
        let before = snapshot("bind-both", &old, &new);

        let err = run_reanchor(&args_with("bind-both", false, true), &new)
            .expect_err("a disagreeing anchor needs the rollback flag too");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AuditBindingChangeNotAcknowledged {
                    missing: "--acknowledge-rollback",
                    ..
                })
            ),
            "{err:?}"
        );
        assert!(
            snapshot("bind-both", &old, &new) == before,
            "nothing written"
        );

        let data =
            run_reanchor(&args_with("bind-both", true, true), &new).expect("both flags accept");
        assert_eq!(data.acknowledged, vec!["rollback", "binding_change"]);
        let rows = tip_rows(&new);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["reason"], "rollback_acknowledged");
        assert_eq!(rows[0]["previous_anchor"], superseded.as_str());
        assert_eq!(rows[1]["reason"], "binding_changed");
        assert_eq!(rows[1]["previous_anchor"], old_anchor.as_str());
        assert_eq!(rows[0]["reanchor_count"], 1);
        assert_eq!(rows[1]["reanchor_count"], 1);
        assert_eq!(counter(&new), Some(1));
    }

    /// A binding-change repair appends every repair row, drains the outbox,
    /// and then stores the binding.
    #[test]
    #[serial]
    fn both_flags_drain_queued_rows_after_both_repair_rows() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-both-outbox", dir.path(), 2);
        record_binding("bind-both-outbox", &old);
        let old_anchor = anchor_coordinates(&old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");
        write_anchored(&new, 2);
        roll_back(&new);
        let superseded = anchor_coordinates(&new);
        let before = log_rows(&new);
        for id in ["queued-1", "queued-2"] {
            AuditOutbox::for_log(&new.audit_log_path)
                .append(&queued_consent(id))
                .expect("queue");
        }

        let data = run_reanchor(&args_with("bind-both-outbox", true, true), &new)
            .expect("both flags accept");
        assert_eq!(data.outbox_drained, Some(2));
        assert!(data.warnings.is_empty(), "{:?}", data.warnings);
        assert_eq!(data.acknowledged, vec!["rollback", "binding_change"]);
        assert_eq!(data.recorded_binding, "changed");
        assert_eq!(data.previous_anchor, Some(superseded));
        assert_eq!(
            data.previous_binding_anchor.as_deref(),
            Some(old_anchor.as_str())
        );
        let rows = log_rows(&new);
        assert_eq!(rows.len(), before.len() + 4, "{rows:?}");
        assert_eq!(&rows[..before.len()], before.as_slice());
        let tail = &rows[before.len()..];
        assert_eq!(tail[0]["reason"], "rollback_acknowledged");
        assert_eq!(tail[1]["reason"], "binding_changed");
        assert_eq!(tail[2]["request_id"], "queued-1");
        assert_eq!(tail[3]["request_id"], "queued-2");
        assert_eq!(inspect_outbox(&new.audit_log_path).unwrap().pending, 0);
        assert!(outbox_file(&new).is_empty());
        assert_eq!(
            anchor_coordinates(&new),
            data.current_anchor,
            "the reported anchor covers the drained rows"
        );
        assert_eq!(counter(&new), Some(1));
        assert_eq!(
            raw_binding("bind-both-outbox"),
            Some(AuditBinding::for_profile(&new).to_keyring_value())
        );
        let json = serde_json::to_value(&data).expect("JSON");
        assert_eq!(json["outbox_drained"], 2);
        assert!(json.get("warnings").is_none(), "{json}");
    }

    /// On a binding change a refused drain is a warning, and the new binding
    /// is stored with either set of required acknowledgements.
    #[test]
    #[serial]
    fn a_refused_drain_on_a_binding_change_is_a_warning_and_the_binding_is_stored() {
        for rollback in [false, true] {
            keyring_mock::install().expect("mock keyring store");
            let dir = tempfile::tempdir().expect("tmp dir");
            let old = anchored_profile("bind-outbox-unusable", dir.path(), 2);
            record_binding("bind-outbox-unusable", &old);
            let old_anchor = anchor_coordinates(&old);
            let mut new = old.clone();
            new.audit_log_path = dir.path().join("new.jsonl");
            if rollback {
                write_anchored(&new, 2);
                roll_back(&new);
            }
            let before = log_rows(&new);
            let outbox = AuditOutbox::for_log(&new.audit_log_path);
            outbox.append(&queued_consent("queued-1")).expect("queue");
            let mut bytes = std::fs::read(outbox.path()).expect("outbox");
            bytes.extend_from_slice(b"not an audit entry\n");
            std::fs::write(outbox.path(), &bytes).expect("corrupt the outbox");

            let data = run_reanchor(&args_with("bind-outbox-unusable", rollback, true), &new)
                .expect("the repair stands");
            let (acknowledged, reasons) = if rollback {
                (
                    vec!["rollback", "binding_change"],
                    vec!["rollback_acknowledged", "binding_changed"],
                )
            } else {
                (vec!["binding_change"], vec!["binding_changed"])
            };
            assert_eq!(data.acknowledged, acknowledged);
            assert_eq!(data.recorded_binding, "changed");
            assert_eq!(
                data.previous_binding_anchor.as_deref(),
                Some(old_anchor.as_str())
            );
            assert_eq!(data.outbox_drained, None);
            assert_eq!(data.warnings.len(), 1);
            assert!(
                data.warnings[0].starts_with("audit.outbox_unusable"),
                "{:?}",
                data.warnings
            );
            assert_eq!(outbox_file(&new), bytes, "the outbox is left as it was");
            let rows = log_rows(&new);
            assert_eq!(rows.len(), before.len() + reasons.len(), "{rows:?}");
            assert_eq!(&rows[..before.len()], before.as_slice());
            for (row, reason) in rows[before.len()..].iter().zip(reasons) {
                assert_eq!(row["reason"], reason);
            }
            assert_eq!(anchor_coordinates(&new), data.current_anchor);
            assert_eq!(counter(&new), Some(1));
            assert!(
                raw_binding("bind-outbox-unusable")
                    == Some(AuditBinding::for_profile(&new).to_keyring_value()),
                "the binding is stored after a refused drain"
            );
            let json = serde_json::to_value(&data).expect("JSON");
            assert_eq!(json["warnings"][0], data.warnings[0]);
            assert!(json.get("outbox_drained").is_none(), "{json}");
        }
    }

    #[test]
    #[serial]
    fn an_unusable_stored_anchor_counts_as_disagreeing() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let old = anchored_profile("bind-unusable", dir.path(), 2);
        record_binding("bind-unusable", &old);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");
        stellar_agent_network::keyring::write_keyring_string(
            TestAnchorStore::new(&new.audit_log_hash_chain_key_id, &new.audit_log_path)
                .anchor_entry_ref(),
            "not-an-anchor",
        )
        .expect("plant");

        let err = run_reanchor(&args_with("bind-unusable", false, true), &new)
            .expect_err("an unusable anchor needs the rollback flag");
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AuditBindingChangeNotAcknowledged {
                    missing: "--acknowledge-rollback",
                    ..
                })
            ),
            "{err:?}"
        );
        let data =
            run_reanchor(&args_with("bind-unusable", true, true), &new).expect("both flags accept");
        assert_eq!(data.acknowledged, vec!["rollback", "binding_change"]);
    }

    #[test]
    #[serial]
    fn an_unparseable_record_gives_previous_anchor_none() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = anchored_profile("bind-garbage", dir.path(), 2);
        stellar_agent_network::keyring::write_keyring_string(
            TestBindingStore::for_profile("bind-garbage").entry_ref(),
            "garbage",
        )
        .expect("plant");

        let data = run_reanchor(&args_with("bind-garbage", false, true), &profile)
            .expect("the binding flag accepts an unreadable record");
        assert_eq!(data.recorded_binding, "unreadable");
        assert_eq!(data.previous_binding_anchor, None);
        let rows = tip_rows(&profile);
        let last = rows.last().expect("a row");
        assert_eq!(last["reason"], "binding_changed");
        assert!(last["previous_anchor"].is_null(), "{last}");
        assert!(
            raw_binding("bind-garbage")
                == Some(AuditBinding::for_profile(&profile).to_keyring_value()),
            "the new binding replaces the unreadable record"
        );
    }

    /// A run that stops before the binding write leaves the refusal in place,
    /// and a rerun appends its rows again.
    #[test]
    #[serial]
    fn a_failed_binding_write_leaves_the_refusal_and_a_rerun_appends_again() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let coordinate =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_audit_binding(
                "bind-rerun",
            );
        let mut old = Profile::builder_testnet("bind-rerun", "acct", "n-svc", "n-acct")
            .with_profile_name("bind-rerun")
            .build();
        old.audit_log_path = dir.path().join("old.jsonl");
        keyring_mock::install_with_write_error(
            &coordinate.service,
            &coordinate.account,
            Some(&AuditBinding::for_profile(&old).to_keyring_value()),
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("planted"))),
        )
        .expect("mock keyring store");
        let coord = old.audit_log_hash_chain_key_id.clone();
        stellar_agent_network::keyring::rotate_keyring_secret_32(&coord.service, &coord.account)
            .expect("seed audit key");
        write_anchored(&old, 2);
        let mut new = old.clone();
        new.audit_log_path = dir.path().join("new.jsonl");

        AuditOutbox::for_log(&new.audit_log_path)
            .append(&queued_consent("queued-before-binding-failure"))
            .expect("queue");

        let err = run_reanchor(&args_with("bind-rerun", false, true), &new)
            .expect_err("the binding write fails");
        assert_eq!(
            err.category(),
            stellar_agent_core::error::ErrorCategory::Auth
        );
        assert_eq!(tip_rows(&new).len(), 1, "the rows were appended");
        let rows = log_rows(&new);
        assert_eq!(
            rows.len(),
            2,
            "the queued row drained before the binding write failed"
        );
        assert_eq!(rows[0]["reason"], "binding_changed");
        assert_eq!(rows[1]["request_id"], "queued-before-binding-failure");
        assert!(outbox_file(&new).is_empty());
        assert_eq!(inspect_outbox(&new.audit_log_path).unwrap().pending, 0);
        assert_eq!(
            raw_binding("bind-rerun"),
            Some(AuditBinding::for_profile(&old).to_keyring_value())
        );
        let refusal = stellar_agent_network::keyring::keyed_audit_access(
            &new,
            "bind-rerun",
            BindingCheck::Enforce,
        )
        .expect_err("the refusal stays in place");
        assert_eq!(refusal.code(), "audit.log_binding_changed");

        run_reanchor(&args_with("bind-rerun", false, true), &new).expect("the rerun succeeds");
        assert_eq!(tip_rows(&new).len(), 2, "the rerun appends its rows again");
        stellar_agent_network::keyring::keyed_audit_access(
            &new,
            "bind-rerun",
            BindingCheck::Enforce,
        )
        .expect("the binding is accepted");
    }

    // ── Repair with queued consent rows ──────────────────────────────────────

    use stellar_agent_core::audit_log::{AuditOutbox, inspect_outbox};

    fn queued_consent(request_id: &str) -> AuditEntry {
        AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            request_id,
        )
    }

    fn log_rows(profile: &Profile) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&profile.audit_log_path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON row"))
            .collect()
    }

    fn outbox_file(profile: &Profile) -> Vec<u8> {
        std::fs::read(AuditOutbox::for_log(&profile.audit_log_path).path()).unwrap_or_default()
    }

    #[tokio::test]
    #[serial]
    async fn without_the_acknowledgement_the_log_the_anchor_and_the_outbox_are_unchanged() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = rolled_back_profile("reanchor-outbox-gate", dir.path());
        AuditOutbox::for_log(&profile.audit_log_path)
            .append(&queued_consent("queued-1"))
            .expect("queue");
        let store = TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        );
        let anchor_before = store.load_raw().expect("read anchor");
        let log_before = std::fs::read(&profile.audit_log_path).expect("read log");
        let outbox_before = outbox_file(&profile);

        let args = ReanchorArgs {
            profile: "reanchor-outbox-gate".to_owned(),
            acknowledge_rollback: false,
            acknowledge_binding_change: false,
        };
        let cloned = profile.clone();
        let code = run_with_dependencies(&args, move |_| Ok(cloned.clone()), || Ok(())).await;

        assert_eq!(code, 1);
        assert_eq!(store.load_raw().expect("read anchor"), anchor_before);
        assert_eq!(
            std::fs::read(&profile.audit_log_path).expect("read log"),
            log_before
        );
        assert_eq!(
            outbox_file(&profile),
            outbox_before,
            "the outbox is left as it was"
        );
    }

    #[tokio::test]
    #[serial]
    async fn with_the_acknowledgement_queued_rows_follow_the_repair_row() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = rolled_back_profile("reanchor-outbox-drain", dir.path());
        let store = TestAnchorStore::new(
            &profile.audit_log_hash_chain_key_id,
            &profile.audit_log_path,
        );
        let mismatching = store
            .load_anchor()
            .expect("read anchor")
            .expect("anchored")
            .coordinates();
        for id in ["queued-1", "queued-2"] {
            AuditOutbox::for_log(&profile.audit_log_path)
                .append(&queued_consent(id))
                .expect("queue");
        }

        let args = ReanchorArgs {
            profile: "reanchor-outbox-drain".to_owned(),
            acknowledge_rollback: true,
            acknowledge_binding_change: false,
        };
        let cloned = profile.clone();
        let code = run_with_dependencies(&args, move |_| Ok(cloned.clone()), || Ok(())).await;
        assert_eq!(code, 0);

        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .expect("read log")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("JSON row"))
            .collect();
        let repair_at = rows
            .iter()
            .position(|row| row["kind"] == "audit_tip_anchored")
            .expect("the repair row");
        assert_eq!(rows[repair_at]["previous_anchor"], mismatching);
        let tail: Vec<&str> = rows[repair_at + 1..]
            .iter()
            .map(|row| row["request_id"].as_str().expect("request id"))
            .collect();
        assert_eq!(
            tail,
            vec!["queued-1", "queued-2"],
            "queued rows follow the repair"
        );
        assert_eq!(inspect_outbox(&profile.audit_log_path).unwrap().pending, 0);
    }

    #[tokio::test]
    #[serial]
    async fn a_drain_refusal_after_the_repair_is_a_warning_and_the_repair_stands() {
        keyring_mock::install().expect("mock keyring store");
        let dir = tempfile::tempdir().expect("tmp dir");
        let profile = rolled_back_profile("reanchor-outbox-unusable", dir.path());
        let outbox = AuditOutbox::for_log(&profile.audit_log_path);
        outbox.append(&queued_consent("queued-1")).expect("queue");
        let mut bytes = std::fs::read(outbox.path()).expect("outbox");
        bytes.extend_from_slice(b"not an audit entry\n");
        std::fs::write(outbox.path(), &bytes).expect("corrupt the outbox");

        let mut writer = open_repair_writer(&profile, "reanchor-outbox-unusable").expect("open");
        let report = writer.reanchor().expect("the repair succeeds");
        drop(writer);
        let refusal = report.outbox_refusal.clone().expect("the drain refused");
        assert!(refusal.starts_with("audit.outbox_unusable"), "{refusal}");
        assert_eq!(report.outbox_drained, None);
        assert_eq!(outbox_file(&profile), bytes, "the outbox is left as it was");

        let data = serde_json::to_value(reanchor_data(
            "reanchor-outbox-unusable",
            report,
            vec!["rollback"],
            "absent",
            None,
        ))
        .expect("JSON");
        assert_eq!(data["warnings"][0], serde_json::json!(refusal));
        assert!(
            data.get("outbox_drained").is_none(),
            "a refused drain reports no count: {data}"
        );

        // The repair stands: the log opens cleanly under the ordinary path once
        // the outbox is moved aside.
        std::fs::remove_file(outbox.path()).expect("move the outbox aside");
        let key = load_audit_hmac_key(&profile, "reanchor-outbox-unusable").expect("load key");
        AuditWriter::open_with_tip_anchor(
            profile.audit_log_path.clone(),
            Some(key),
            TestAnchorStore::shared(
                &profile.audit_log_hash_chain_key_id,
                &profile.audit_log_path,
            ),
        )
        .expect("the repaired log opens cleanly");
    }
}
