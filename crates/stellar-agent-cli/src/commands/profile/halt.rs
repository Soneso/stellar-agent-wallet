//! `stellar-agent profile halt` and `stellar-agent profile resume`: the
//! per-profile emergency stop.
//!
//! `profile halt --profile <name> [--reason <text>]` writes the halt marker
//! `<data_root>/profiles/<name>.halt`. From the next call on, every agent
//! action on the profile refuses with `profile.halted`: every MCP tool that is
//! not read-only, on a server already running or started later, and every CLI
//! verb that signs or submits. The CLI verbs that only record or reconcile
//! local state (`mpp receipt record`, `mpp settlement reconcile`,
//! `mpp state prune`, `tx status`) stay usable for the operator. No restart,
//! key change, or policy change is needed. `profile resume --profile <name>`
//! removes the marker.
//!
//! The operator ceremonies stay usable while a profile is halted, so the
//! operator can change the rules before resuming: `profile sign-policy`, the
//! `profile enroll-*` and `profile rotate-*` commands, and the approval
//! surfaces. Read-only commands and tools keep working.
//!
//! # Audit rows
//!
//! `profile halt` writes the marker first and then a `profile_halted` row: a
//! stop never waits on the audit log. A row that cannot be written leaves the
//! halt in effect and reports `audit_row: "not_written"`.
//!
//! `profile resume` on a halted profile reads the marker, appends the
//! `profile_resumed` row, and only then removes the marker, so a resume that
//! took effect is always recorded:
//!
//! - a marker that cannot be read, such as a directory at its path, refuses
//!   with `profile.halt_unreadable` and writes no row;
//! - a row that cannot be appended refuses with its audit code and leaves the
//!   marker in place;
//! - a marker that cannot be removed after the row refuses with
//!   `io.halt_marker`; the profile stays halted until a later resume removes
//!   it.
//!
//! A `profile_resumed` row records that the command ran; the marker file
//! decides the state. While the row is appended the marker still exists, so
//! no agent action passes the halt check before the row is committed. An
//! append that fails after its bytes landed leaves the profile halted with a
//! row that records the attempt.
//!
//! A resume of a profile that is not halted removes nothing, so its row is
//! written when the log is available and the command exits `0` either way.
//!
//! While an MCP server holds the profile's audit log, both rows are queued in
//! the audit outbox, and the server appends them at its next audit write.
//!
//! # Output (JSON envelope)
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "halted": true,
//!     "halted_at": "2026-10-31T12:00:00Z",
//!     "reason": "suspected prompt injection",
//!     "audit_row": "written"
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! `profile resume` reports `halted: false`, no `halted_at` or `reason`, and
//! `was_halted`. `--output table` prints the same fields as `key  value`
//! lines.
//!
//! # Errors
//!
//! Exit code `1` when the profile cannot be loaded (no marker is written and
//! the reason is not examined), the reason is invalid, the marker cannot be
//! written, or a resume of a halted profile cannot read the marker, record its
//! row, or remove the marker. A resume that exits `1` leaves the marker in
//! place.

use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{IoSource, ValidationError, WalletError};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::profile::halt::{
    self, HaltError, HaltMarker, HaltState, validate_halt_reason,
};
use stellar_agent_core::profile::schema::{Profile, canonical_data_root};
use stellar_agent_network::keyring::init_platform_keyring_store;
use uuid::Uuid;

use crate::commands::value_audit::{
    OperatorRowSink, acquire_operator_row_sink, append_value_audit_row_strict,
    audit_writer_open_failed,
};
use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::{render_json, sanitize_for_table};

/// Arguments for `stellar-agent profile halt`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct HaltArgs {
    /// Profile to halt, positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile to halt, flag form; an alternative to the positional `NAME`.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Why the profile is halted, recorded in the marker and the audit row.
    ///
    /// At most 128 characters, no control characters. Every refusal while
    /// the profile is halted repeats it. Examined after the profile loads.
    #[arg(long)]
    pub(crate) reason: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub(crate) output: OutputFormat,
}

impl HaltArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields.
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// Arguments for `stellar-agent profile resume`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub(crate) struct ResumeArgs {
    /// Profile to resume, positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,

    /// Profile to resume, flag form; an alternative to the positional `NAME`.
    #[arg(long, value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub(crate) output: OutputFormat,
}

impl ResumeArgs {
    /// Returns the resolved profile name; see [`HaltArgs::profile_name`].
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// Where a command's audit row went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditRowOutcome {
    /// Appended to the audit log through this process's writer.
    Written,
    /// Queued in the audit outbox for the draining writer of another process.
    Queued,
    /// Not written; the reason is logged. Only `profile halt` and a resume of
    /// a profile that is not halted report this, because neither depends on
    /// the row.
    NotWritten,
}

impl AuditRowOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Queued => "queued",
            Self::NotWritten => "not_written",
        }
    }
}

/// Success payload of `profile halt` and `profile resume`.
#[derive(Debug, Serialize)]
struct HaltCommandData {
    /// The profile the command acted on.
    profile: String,
    /// Whether the profile is halted after the command.
    halted: bool,
    /// The marker's timestamp, after a halt.
    #[serde(skip_serializing_if = "Option::is_none")]
    halted_at: Option<String>,
    /// The marker's reason, after a halt that gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Whether a marker existed before a resume.
    #[serde(skip_serializing_if = "Option::is_none")]
    was_halted: Option<bool>,
    /// Where the command's audit row went.
    audit_row: AuditRowOutcome,
}

/// Halt state of a profile as `profile show` reports it.
#[derive(Debug, Serialize)]
pub(super) struct HaltStateView {
    /// Whether agent actions on the profile refuse: a marker exists, valid or
    /// not.
    pub(super) halted: bool,
    /// The marker's timestamp, when a valid marker exists.
    pub(super) halted_at: Option<String>,
    /// The marker's reason, when a valid marker carries one.
    pub(super) halt_reason: Option<String>,
    /// Why the marker cannot be read, when it exists and is not valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) halt_marker_error: Option<String>,
}

impl From<&HaltState> for HaltStateView {
    fn from(state: &HaltState) -> Self {
        Self {
            halted: state.is_halted(),
            halted_at: state.halted_at().map(str::to_owned),
            halt_reason: state.reason().map(str::to_owned),
            halt_marker_error: match state {
                HaltState::Unreadable(detail) => Some(detail.clone()),
                _ => None,
            },
        }
    }
}

/// Runs `stellar-agent profile halt`.
///
/// Returns `0` once the marker is written, `1` otherwise.
///
/// # Panics
///
/// Never panics.
pub(crate) async fn run_halt(args: &HaltArgs) -> i32 {
    let format = args.output;
    let name = args.profile_name();
    let profile = match load_profile_reconciled(&ResolvedProfileName::from_flag(name)) {
        Ok(profile) => profile,
        Err(e) => {
            tracing::debug!(profile = %name, error = %e, "profile access refused");
            print_error(&profile_access_envelope(&e, name), format);
            return 1;
        }
    };
    if let Some(reason) = &args.reason
        && let Err(refusal) = reason_refusal(reason)
    {
        print_error(&refusal, format);
        return 1;
    }
    let data_root = match data_root() {
        Ok(root) => root,
        Err(error) => {
            print_error(&Envelope::err(&error), format);
            return 1;
        }
    };
    let marker = match HaltMarker::now(args.reason.clone()) {
        Ok(marker) => marker,
        Err(error) => {
            print_error(&Envelope::err(&marker_io_error(&error)), format);
            return 1;
        }
    };
    if let Err(error) = halt::write_halt(&data_root, name, &marker) {
        print_error(&Envelope::err(&marker_io_error(&error)), format);
        return 1;
    }
    tracing::warn!(profile = %name, "profile halted; agent actions refuse until resumed");

    let entry = AuditEntry::new_profile_halted(
        name,
        marker.halted_at.clone(),
        marker.reason.as_deref(),
        Uuid::new_v4().to_string(),
    );
    let audit_row = match operator_row_sink(&profile, name)
        .and_then(|sink| append_operator_row(&sink, name, entry))
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(
                profile = %name,
                code = error.code(),
                error = %error,
                "profile halt: the halt is in effect; its audit row was NOT written"
            );
            AuditRowOutcome::NotWritten
        }
    };

    print_success(
        &Envelope::ok(HaltCommandData {
            profile: name.to_owned(),
            halted: true,
            halted_at: Some(marker.halted_at),
            reason: marker.reason,
            was_halted: None,
            audit_row,
        }),
        format,
    );
    0
}

/// Runs `stellar-agent profile resume`.
///
/// Returns `0` when the profile is not halted afterwards. Returns `1` when the
/// command refuses; a marker that existed then stays in place, so the profile
/// stays halted.
///
/// # Panics
///
/// Never panics.
pub(crate) async fn run_resume(args: &ResumeArgs) -> i32 {
    let format = args.output;
    let name = args.profile_name();
    let profile = match load_profile_reconciled(&ResolvedProfileName::from_flag(name)) {
        Ok(profile) => profile,
        Err(e) => {
            tracing::debug!(profile = %name, error = %e, "profile access refused");
            print_error(&profile_access_envelope(&e, name), format);
            return 1;
        }
    };
    let data_root = match data_root() {
        Ok(root) => root,
        Err(error) => {
            print_error(&Envelope::err(&error), format);
            return 1;
        }
    };
    let was_halted = match halt::read_halt(&data_root, name) {
        Ok(marker) => marker.is_some(),
        Err(error) => {
            let refusal = WalletError::Validation(ValidationError::ProfileHaltUnreadable {
                profile: name.to_owned(),
                detail: error.to_string(),
            });
            print_error(&Envelope::err(&refusal), format);
            return 1;
        }
    };
    let entry = AuditEntry::new_profile_resumed(name, was_halted, Uuid::new_v4().to_string());
    let recorded =
        operator_row_sink(&profile, name).and_then(|sink| append_operator_row(&sink, name, entry));
    if !was_halted {
        let audit_row = match recorded {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(
                    profile = %name,
                    code = error.code(),
                    error = %error,
                    "profile resume: the profile is not halted; its audit row was NOT written"
                );
                AuditRowOutcome::NotWritten
            }
        };
        print_resumed(name, false, audit_row, format);
        return 0;
    }

    // Halted: the row is committed while the marker still stops every agent
    // action, and the marker is removed only after it.
    let audit_row = match recorded {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(
                profile = %name,
                code = error.code(),
                error = %error,
                "profile resume: the audit row cannot be recorded; the halt stays in place"
            );
            print_error(&Envelope::err(&error), format);
            return 1;
        }
    };
    if let Err(error) = halt::clear_halt(&data_root, name) {
        tracing::error!(
            profile = %name,
            error = %error,
            "profile resume: the row is recorded and the halt marker cannot be removed; the profile stays halted"
        );
        print_error(&Envelope::err(&marker_removal_error(name, &error)), format);
        return 1;
    }
    tracing::warn!(profile = %name, "profile resumed; agent actions are no longer refused");
    print_resumed(name, true, audit_row, format);
    0
}

/// The refusal for a marker that cannot be removed after the resume row is
/// recorded: `io.halt_marker`, naming the repair and the rerun.
fn marker_removal_error(name: &str, error: &HaltError) -> WalletError {
    match marker_io_error(error) {
        WalletError::Io {
            source_kind,
            message,
        } => WalletError::Io {
            source_kind,
            message: format!(
                "{message}; the profile stays halted and the profile_resumed row records this attempt; \
                 fix the marker file or its directory, then run \"stellar-agent profile resume --profile {name}\" again"
            )
            .into(),
        },
        other => other,
    }
}

/// Prints the success envelope of `profile resume`.
fn print_resumed(name: &str, was_halted: bool, audit_row: AuditRowOutcome, format: OutputFormat) {
    print_success(
        &Envelope::ok(HaltCommandData {
            profile: name.to_owned(),
            halted: false,
            halted_at: None,
            reason: None,
            was_halted: Some(was_halted),
            audit_row,
        }),
        format,
    );
}
/// Acquires the profile's operator-row sink: the keyed writer of this
/// process, or the outbox of the draining writer that holds the log.
fn operator_row_sink(profile: &Profile, name: &str) -> Result<OperatorRowSink, WalletError> {
    init_platform_keyring_store()?;
    acquire_operator_row_sink(profile, name)
}

/// Appends `entry` through `sink`.
fn append_operator_row(
    sink: &OperatorRowSink,
    name: &str,
    entry: AuditEntry,
) -> Result<AuditRowOutcome, WalletError> {
    match sink {
        OperatorRowSink::Writer(writer) => {
            let mut guard = writer.lock().map_err(|_| audit_writer_open_failed(name))?;
            append_value_audit_row_strict(&mut guard, name, entry)?;
            Ok(AuditRowOutcome::Written)
        }
        OperatorRowSink::Outbox(outbox) => {
            outbox.append(&entry).map_err(|error| {
                stellar_agent_core::audit_log::audit_writer_refusal(name, &error)
            })?;
            Ok(AuditRowOutcome::Queued)
        }
    }
}

/// The data root the marker lives under.
fn data_root() -> Result<std::path::PathBuf, WalletError> {
    canonical_data_root().map_err(|_| marker_io_error(&HaltError::NoDataRoot))
}

/// The refusal for an operator reason that is empty, too long, or holds a
/// control character.
fn reason_refusal(reason: &str) -> Result<(), Envelope<()>> {
    if reason.trim().is_empty() {
        return Err(Envelope::<()>::err_raw(
            "validation.reason_empty",
            "--reason must contain non-whitespace text",
        ));
    }
    validate_halt_reason(reason).map_err(|error| {
        let detail = match error {
            HaltError::InvalidReason(detail) => detail,
            other => other.to_string(),
        };
        Envelope::<()>::err_raw("validation.reason_invalid", format!("--reason {detail}"))
    })
}

/// Maps a marker write or removal failure to `io.halt_marker`.
fn marker_io_error(error: &HaltError) -> WalletError {
    match error {
        HaltError::InvalidName { name, reason } => {
            WalletError::Validation(ValidationError::ConfigInvalid {
                component: "profile",
                reason: format!("profile name `{name}` {reason}"),
            })
        }
        other => WalletError::Io {
            source_kind: IoSource::HaltMarker,
            message: other.to_string().into(),
        },
    }
}

fn print_success(envelope: &Envelope<HaltCommandData>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            if let Some(data) = &envelope.data {
                #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
                {
                    println!("{}", render_table(data));
                }
            }
        }
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            if let Some(err) = &envelope.error {
                #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
                {
                    println!("Error: {}: {}", err.code, sanitize_for_table(&err.message));
                }
            }
        }
        _ => render_json(envelope),
    }
}

/// Renders the command's result as `key  value` lines.
fn render_table(data: &HaltCommandData) -> String {
    let mut rows = vec![
        ("profile", sanitize_for_table(&data.profile)),
        ("halted", data.halted.to_string()),
    ];
    if let Some(halted_at) = &data.halted_at {
        rows.push(("halted_at", sanitize_for_table(halted_at)));
    }
    if let Some(reason) = &data.reason {
        rows.push(("reason", sanitize_for_table(reason)));
    }
    if let Some(was_halted) = data.was_halted {
        rows.push(("was_halted", was_halted.to_string()));
    }
    rows.push(("audit_row", data.audit_row.label().to_owned()));
    rows.iter()
        .map(|(key, value)| format!("{key:<10}  {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reads the halt state of `name` for display.
pub(super) fn halt_state_view(name: &str) -> HaltStateView {
    HaltStateView::from(&halt::halt_state(name))
}

/// Reads the halt state of `name` under `data_root` for display.
#[cfg(test)]
fn halt_state_view_in(data_root: &std::path::Path, name: &str) -> HaltStateView {
    HaltStateView::from(&halt::halt_state_in(data_root, name))
}

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

    use super::*;

    #[derive(Debug, Parser)]
    struct WrapHalt {
        #[command(flatten)]
        args: HaltArgs,
    }

    #[derive(Debug, Parser)]
    struct WrapResume {
        #[command(flatten)]
        args: ResumeArgs,
    }

    #[test]
    fn halt_accepts_the_flag_and_the_positional_form() {
        let w = WrapHalt::try_parse_from(["prog", "--profile", "acme", "--reason", "r"]).unwrap();
        assert_eq!(w.args.profile_name(), "acme");
        assert_eq!(w.args.reason.as_deref(), Some("r"));
        let w = WrapHalt::try_parse_from(["prog", "acme"]).unwrap();
        assert_eq!(w.args.profile_name(), "acme");
        assert!(w.args.reason.is_none());
        let err = WrapHalt::try_parse_from(["prog"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        let err = WrapHalt::try_parse_from(["prog", "a", "--profile", "b"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn resume_accepts_the_flag_and_the_positional_form() {
        let w = WrapResume::try_parse_from(["prog", "--profile", "acme"]).unwrap();
        assert_eq!(w.args.profile_name(), "acme");
        let w = WrapResume::try_parse_from(["prog", "acme", "--output", "table"]).unwrap();
        assert_eq!(w.args.output, OutputFormat::Table);
        let err = WrapResume::try_parse_from(["prog"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn invalid_reasons_are_refused_with_their_codes() {
        let empty = reason_refusal("  ").unwrap_err();
        assert_eq!(empty.error.unwrap().code, "validation.reason_empty");
        for reason in ["x".repeat(129), "a\u{1b}[31mb".to_owned()] {
            let refused = reason_refusal(&reason).unwrap_err();
            assert_eq!(refused.error.unwrap().code, "validation.reason_invalid");
        }
        reason_refusal("incident").unwrap();
    }

    #[test]
    fn the_table_lists_the_state() {
        let table = render_table(&HaltCommandData {
            profile: "alice".to_owned(),
            halted: true,
            halted_at: Some("2026-10-31T12:00:00Z".to_owned()),
            reason: Some("incident".to_owned()),
            was_halted: None,
            audit_row: AuditRowOutcome::Queued,
        });
        assert_eq!(
            table,
            "profile     alice\nhalted      true\nhalted_at   2026-10-31T12:00:00Z\n\
             reason      incident\naudit_row   queued"
        );
        let table = render_table(&HaltCommandData {
            profile: "alice".to_owned(),
            halted: false,
            halted_at: None,
            reason: None,
            was_halted: Some(false),
            audit_row: AuditRowOutcome::NotWritten,
        });
        assert_eq!(
            table,
            "profile     alice\nhalted      false\nwas_halted  false\naudit_row   not_written"
        );
    }

    #[test]
    fn the_show_view_reports_each_state() {
        let root = tempfile::tempdir().unwrap();
        let view = halt_state_view_in(root.path(), "alice");
        assert!(!view.halted);
        assert!(view.halted_at.is_none() && view.halt_marker_error.is_none());

        let marker =
            HaltMarker::new("2026-10-31T12:00:00Z".to_owned(), Some("r".to_owned())).unwrap();
        halt::write_halt(root.path(), "alice", &marker).unwrap();
        let view = halt_state_view_in(root.path(), "alice");
        assert!(view.halted);
        assert_eq!(view.halted_at.as_deref(), Some("2026-10-31T12:00:00Z"));
        assert_eq!(view.halt_reason.as_deref(), Some("r"));

        halt::clear_halt(root.path(), "alice").unwrap();
        std::fs::create_dir_all(halt::halt_path(root.path(), "alice").unwrap()).unwrap();
        let view = halt_state_view_in(root.path(), "alice");
        assert!(view.halted, "an unreadable marker reads as halted");
        assert!(view.halt_marker_error.is_some());
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["halted"], true);
        assert!(json["halted_at"].is_null());
    }
}
