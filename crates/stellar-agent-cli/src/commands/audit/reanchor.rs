//! `stellar-agent audit reanchor --profile <name> --acknowledge-rollback` —
//! move the audit log's keyring-held tip anchor to the log's current tip.
//!
//! # When this is needed
//!
//! The tip anchor keeps the active log file's entry count, tip hash, and byte
//! offset in the platform keyring, where filesystem access alone cannot rewind
//! them. A log that no longer contains the anchored tip — restored from an older
//! copy, truncated, or replaced — makes every value-moving verb refuse with
//! `audit.tip_anchor_mismatch`, and makes `audit verify --profile` refuse the
//! same way. This verb is the only way out of that state.
//!
//! # Why the acknowledgement is required
//!
//! Moving the anchor forgives whatever caused the disagreement. That may have
//! been an operator restoring a backup; it may have been tampering. The verb
//! cannot tell the two apart, so it reports the two anchors and refuses until
//! the operator states that the log as it now stands is the one to trust.
//! Without the flag nothing is written and the exit code is 1.
//!
//! # What it does
//!
//! Replays the whole active file first, so a log whose own hash chain is broken
//! is refused rather than blessed. Then it writes the current tip as the anchor,
//! increments the path's monotonic re-anchor counter, and appends an
//! `audit_tip_anchored` row naming the superseded anchor — a permanent record,
//! inside the log, that a rollback was accepted here.
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
//! - 1 without `--acknowledge-rollback`, and on any failure.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::{
    audit_log::{AuditWriter, TipAnchor, WriterError},
    envelope::Envelope,
    error::{ValidationError, WalletError},
    profile::schema::Profile,
};
use stellar_agent_network::keyring::{KeyringTipAnchorStore, init_platform_keyring_store};

use crate::common::profile_access::load_profile_reconciled_by_requested_name;
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
    /// Required. Without it the verb reports the anchor it would replace and the
    /// one it would write, changes nothing, and exits 1.
    #[arg(long)]
    pub acknowledge_rollback: bool,
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
    /// The path's monotonic count of acknowledged rollbacks, after this one.
    reanchor_count: u64,
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
    let profile = match load_profile(&args.profile) {
        Ok(profile) => profile,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let mut writer = match open_repair_writer(&profile, &args.profile) {
        Ok(writer) => writer,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let previous = match writer.stored_tip_anchor() {
        Ok(previous) => previous,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&writer_error(&e, &args.profile)));
            return 1;
        }
    };
    let proposed = match writer.current_tip_anchor() {
        Ok(proposed) => proposed,
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&writer_error(&e, &args.profile)));
            return 1;
        }
    };

    if !args.acknowledge_rollback {
        let refusal = WalletError::Validation(ValidationError::AuditReanchorNotAcknowledged {
            profile: args.profile.clone(),
            current: previous.coordinates().unwrap_or_else(|| "none".to_owned()),
            proposed: proposed
                .as_ref()
                .map_or_else(|| "none".to_owned(), TipAnchor::coordinates),
        });
        render::render_json(&Envelope::<()>::err(&refusal));
        return 1;
    }

    match writer.reanchor() {
        Ok(report) => {
            render::render_json(&Envelope::ok(ReanchorData {
                profile: args.profile.clone(),
                previous_anchor: report.previous.coordinates(),
                current_anchor: report
                    .current
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), TipAnchor::coordinates),
                reanchor_count: report.reanchor_count,
            }));
            0
        }
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&writer_error(&e, &args.profile)));
            1
        }
    }
}

/// Loads the named profile, reconciled, mapping the failure into the CLI
/// envelope model.
fn load_profile(profile_name: &str) -> Result<Profile, WalletError> {
    load_profile_reconciled_by_requested_name(profile_name, None).map_err(|e| {
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
    let hmac_key = load_audit_hmac_key(profile).ok();
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
        let key = load_audit_hmac_key(&profile).expect("load key");
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
        let key = load_audit_hmac_key(&profile).expect("load key");
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
}
