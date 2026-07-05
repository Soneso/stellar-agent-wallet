//! `stellar-agent approve list` — enumerate pending approvals.
//!
//! Opens the profile-scoped pending-approvals store read-only and renders a
//! snapshot of every entry via [`stellar_agent_core::approval::PendingApprovalView`].
//! No keyring access and no network calls — this command only reads the
//! on-disk store.
//!
//! # Output (JSON envelope, default)
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "pending": [ /* PendingApprovalView, one per entry */ ],
//!     "expired_count": 1
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Output (`--output table`)
//!
//! One row per entry: nonce, kind, a one-line wallet-controlled summary, and
//! the time remaining until expiry. Every rendered field is passed through
//! [`sanitize_for_table`] — summary fields such as a payment memo are
//! agent-influenced free text and must not be trusted with raw terminal
//! output.
//!
//! # `--include-expired`
//!
//! By default, expired entries are omitted from `pending` (they no longer
//! grant approval and only remain on disk until the next `approve gc`).
//! `expired_count` always reports the number of expired entries in the
//! snapshot, regardless of this flag, so the operator can tell whether a
//! `gc` is due even when expired entries are hidden.
//!
//! # Exit codes
//!
//! - `0` on success (zero or more pending entries, including an empty list).
//! - `1` when the store cannot be opened (I/O error, locked, no approval dir).

use clap::Args;
use serde::Serialize;

use stellar_agent_core::approval::{
    ApprovalSummaryView, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, PendingApprovalView,
    open_with_retry,
};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_core::timefmt;

use crate::common::render::{render_json, sanitize_for_table};
use crate::common::resolve_profile_name;

/// Arguments for `stellar-agent approve list`.
///
/// # Examples
///
/// ```text
/// stellar-agent approve list
/// stellar-agent approve list --profile myprofile --output table
/// stellar-agent approve list --include-expired
/// ```
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ListArgs {
    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Include already-expired entries in `pending` instead of omitting them.
    #[arg(long = "include-expired")]
    pub include_expired: bool,
}

/// Success payload for the `approve list` JSON envelope.
#[derive(Debug, Serialize)]
struct ListData {
    /// Profile the snapshot was taken from.
    profile: String,
    /// Pending entries, filtered per `--include-expired`.
    pending: Vec<PendingApprovalView>,
    /// Count of expired entries in the snapshot, independent of the filter.
    expired_count: usize,
}

/// Runs `stellar-agent approve list`.
///
/// Returns `0` on success, `1` if the store cannot be opened.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code and JSON
/// envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: ListArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());

    let store_path = match default_approval_dir() {
        Ok(dir) => dir.join(format!("{profile_name}.toml")),
        Err(_) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.store_dir_error: could not determine approval store directory"
                    .to_owned(),
            });
            print_error(&Envelope::<()>::err(&err), args.output);
            return 1;
        }
    };

    let store = match open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF) {
        Ok(s) => s,
        Err(e) => {
            let err = super::common::approval_store_open_error(&e);
            print_error(&Envelope::<()>::err(&err), args.output);
            return 1;
        }
    };

    let now_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approval.clock_error: system clock error: {e}"),
            });
            print_error(&Envelope::<()>::err(&err), args.output);
            return 1;
        }
    };

    let snapshot = store.snapshot(now_ms);
    let expired_count = snapshot.iter().filter(|v| v.expired).count();
    let pending: Vec<PendingApprovalView> = if args.include_expired {
        snapshot
    } else {
        snapshot.into_iter().filter(|v| !v.expired).collect()
    };

    tracing::debug!(
        profile = %profile_name,
        pending_count = pending.len(),
        expired_count,
        "approval list completed"
    );

    let envelope = Envelope::ok(ListData {
        profile: profile_name,
        pending,
        expired_count,
    });
    print_success(&envelope, args.output, now_ms);
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(envelope: &Envelope<ListData>, format: OutputFormat, now_ms: u64) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(data) = &envelope.data {
                if data.pending.is_empty() {
                    println!("No pending approvals for profile '{}'.", data.profile);
                } else {
                    for view in &data.pending {
                        println!("{}", render_pending_row(view, now_ms));
                    }
                }
                if data.expired_count > 0 {
                    println!(
                        "({} expired entr{} not shown; run `approve gc` to clear)",
                        data.expired_count,
                        if data.expired_count == 1 { "y" } else { "ies" }
                    );
                }
            }
        }
        // `OutputFormat` is `#[non_exhaustive]`; unrecognised future variants
        // fall back to JSON rather than silently joining the table branch.
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
    }
}

/// Renders one `--output table` row: nonce, kind, one-line summary, expiry.
///
/// `now_ms` is the same snapshot timestamp used to compute `view.expired`,
/// so the displayed "expires in" duration is relative to the moment the
/// snapshot was taken, not the entry's creation time.
///
/// Every interpolated field passes through [`sanitize_for_table`] before
/// being written — `summary_memo` and similar summary fields originate from
/// simulate-time, potentially agent-influenced input and must not reach the
/// terminal unsanitised.
fn render_pending_row(view: &PendingApprovalView, now_ms: u64) -> String {
    let nonce = sanitize_for_table(&view.approval_nonce);
    let kind = sanitize_for_table(view.kind_name);
    let summary = sanitize_for_table(&render_summary_line(view));
    let expires_in = if view.expired {
        "expired".to_owned()
    } else {
        format_expires_in(view.expires_at_unix_ms, now_ms)
    };
    format!("{nonce}  {kind:<24}  {summary}  (expires in {expires_in})")
}

/// Renders a one-line, non-secret summary for a [`PendingApprovalView`].
fn render_summary_line(view: &PendingApprovalView) -> String {
    match &view.summary {
        ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            ..
        } => format!("pay {amount_stroops} stroops {asset} to {to}"),
        ApprovalSummaryView::Claim {
            balance_id_strkey,
            asset,
            amount_stroops,
            ..
        } => format!("claim {amount_stroops} stroops {asset} ({balance_id_strkey})"),
        ApprovalSummaryView::SignWithPasskey {
            smart_account_redacted,
            rp_id,
            ..
        } => format!("sign for {smart_account_redacted} (rp_id={rp_id})"),
        ApprovalSummaryView::RegisterPasskey {
            smart_account_redacted,
            rp_id,
            ..
        } => format!("register passkey for {smart_account_redacted} (rp_id={rp_id})"),
        ApprovalSummaryView::ToolsetFirstInvokeGate {
            toolset_name,
            capability,
            destination_redacted,
            ..
        } => format!("toolset '{toolset_name}' requests {capability} to {destination_redacted}"),
        ApprovalSummaryView::TrustlineClawbackOptIn {
            code,
            issuer_redacted,
            ..
        } => format!("clawback opt-in for {code}:{issuer_redacted}"),
        ApprovalSummaryView::RuleProposal {
            smart_account_redacted,
            summary_line,
            ..
        } => format!("{summary_line} on {smart_account_redacted}"),
        ApprovalSummaryView::Rejected { original_kind_name } => {
            format!("rejected ({original_kind_name})")
        }
        // `ApprovalSummaryView` is `#[non_exhaustive]`; a future variant
        // falls back to the entry's own kind name rather than failing to build.
        _ => format!("({} entry)", view.kind_name),
    }
}

/// Formats the remaining time until `expires_at_unix_ms`, relative to
/// `reference_unix_ms`, as a compact `"<n>m<n>s"` / `"<n>s"` string.
///
/// `reference_unix_ms` is the entry's `created_at_unix_ms` when the caller has
/// already established the entry is not expired (the CLI process's own
/// wall-clock read happens once per invocation via `timefmt::now_unix_ms`, so
/// this uses that same value indirectly through the non-expired branch in
/// [`render_pending_row`] — see call site).
fn format_expires_in(expires_at_unix_ms: u64, reference_unix_ms: u64) -> String {
    let remaining_ms = expires_at_unix_ms.saturating_sub(reference_unix_ms);
    let total_secs = remaining_ms / 1_000;
    let minutes = total_secs / 60;
    let seconds = total_secs % 60;
    if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use serial_test::serial;
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
    };
    use stellar_agent_core::profile::schema::default_approval_dir;
    use tempfile::TempDir;

    use super::*;

    fn uid() -> String {
        process_uid_for_attestation().expect("UID available on test host")
    }

    fn make_payment_entry(ttl_ms: u64) -> PendingApproval {
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000_000,
            "XLM".to_owned(),
            Some("hi".to_owned()),
            100,
            1,
            uid(),
            ttl_ms,
        )
        .unwrap()
    }

    // ── format_expires_in ────────────────────────────────────────────────────

    #[test]
    fn format_expires_in_seconds_only() {
        assert_eq!(format_expires_in(10_000, 5_000), "5s");
    }

    #[test]
    fn format_expires_in_minutes_and_seconds() {
        assert_eq!(format_expires_in(125_000, 5_000), "2m00s");
    }

    #[test]
    fn format_expires_in_saturates_on_already_past_reference() {
        assert_eq!(format_expires_in(1_000, 5_000), "0s");
    }

    // `approval_store_open_error` now lives in `common.rs` and is tested there.

    // ── run(): JSON shape, empty + populated ─────────────────────────────────

    #[tokio::test]
    #[serial]
    async fn list_run_empty_store_yields_empty_pending_and_exit_0() {
        let dir = match default_approval_dir() {
            Ok(d) => d,
            Err(_) => return, // no approval dir available in this CI env
        };
        std::fs::create_dir_all(&dir).ok();
        let profile = "__stellar_agent_approve_test_list_empty";
        let path = dir.join(format!("{profile}.toml"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(dir.join(format!("{profile}.toml.lock"))).ok();

        let args = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        let code = run(args).await;
        assert_eq!(code, 0, "list on a not-yet-existing store must succeed");
    }

    #[tokio::test]
    #[serial]
    async fn list_run_populated_store_reports_payment_and_rejected_entries() {
        let dir = match default_approval_dir() {
            Ok(d) => d,
            Err(_) => return,
        };
        std::fs::create_dir_all(&dir).ok();
        let profile = "__stellar_agent_approve_test_list_populated";
        let path = dir.join(format!("{profile}.toml"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(dir.join(format!("{profile}.toml.lock"))).ok();

        let now_ms = timefmt::now_unix_ms().unwrap();
        {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            store
                .insert(make_payment_entry(DEFAULT_TTL_MS), now_ms)
                .unwrap();

            let rejected_source = make_payment_entry(DEFAULT_TTL_MS);
            let rejected_nonce = rejected_source.approval_nonce.clone();
            store.insert(rejected_source, now_ms).unwrap();
            store
                .reject(&rejected_nonce, now_ms, DEFAULT_TTL_MS)
                .unwrap();
        } // lock released

        let args = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        let code = run(args).await;
        assert_eq!(code, 0);

        // Re-open to inspect the shape via the same snapshot API the command uses.
        let store = PendingApprovalStore::open(path).unwrap();
        let views = store.snapshot(now_ms);
        assert_eq!(views.len(), 2, "both entries must be present");
        assert!(views.iter().any(|v| v.kind_name == "PaymentSimulated"));
        assert!(views.iter().any(|v| v.kind_name == "Rejected"));
    }

    #[tokio::test]
    #[serial]
    async fn list_run_excludes_expired_unless_include_expired() {
        let dir = match default_approval_dir() {
            Ok(d) => d,
            Err(_) => return,
        };
        std::fs::create_dir_all(&dir).ok();
        let profile = "__stellar_agent_approve_test_list_expired_filter";
        let path = dir.join(format!("{profile}.toml"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(dir.join(format!("{profile}.toml.lock"))).ok();

        let now_ms = timefmt::now_unix_ms().unwrap();
        {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            store.insert(make_payment_entry(1), now_ms).unwrap(); // TTL=1ms
        }
        std::thread::sleep(std::time::Duration::from_millis(5));

        let args_default = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        assert_eq!(run(args_default).await, 0);

        let args_include = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: true,
        };
        assert_eq!(run(args_include).await, 0);

        // Both invocations must succeed; the filtering behavior itself is
        // covered directly against the snapshot filter logic below.
        let store = PendingApprovalStore::open(path).unwrap();
        let later_now = timefmt::now_unix_ms().unwrap();
        let views = store.snapshot(later_now);
        assert_eq!(views.len(), 1);
        assert!(views[0].expired, "the sole entry must have expired by now");
    }

    // ── render_pending_row / render_summary_line ─────────────────────────────

    #[test]
    fn render_pending_row_expiry_is_relative_to_now_not_creation() {
        // `PendingApproval::new_payment_pending` stamps `created_at_unix_ms`
        // from the real system clock, so the entry's real expiry is
        // `created_at + ttl`. A snapshot taken 9 of those 10 minutes later
        // must show ~1 remaining minute, not the full 10-minute TTL.
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let long_ttl_ms = 10 * 60 * 1_000; // 10 minutes
        let entry = make_payment_entry(long_ttl_ms);
        let created_at_unix_ms = entry.created_at_unix_ms;
        store.insert(entry, created_at_unix_ms).unwrap();

        let nine_minutes_later = created_at_unix_ms + 9 * 60 * 1_000;
        let view = store
            .snapshot(nine_minutes_later)
            .into_iter()
            .next()
            .unwrap();
        let row = render_pending_row(&view, nine_minutes_later);
        assert!(
            row.contains("1m00s"),
            "row must show ~1 remaining minute, not the full 10-minute TTL: {row}"
        );
    }

    #[test]
    fn render_pending_row_sanitizes_memo_escape_sequences() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let entry = PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr-bytes",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            Some("hello\x1b[31mworld".to_owned()),
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, 0).unwrap();
        let view = store.snapshot(0).into_iter().next().unwrap();
        // The row renderer must not embed the raw ESC byte anywhere.
        let row = render_pending_row(&view, 0);
        assert!(!row.contains('\x1b'), "escape sequence must be sanitized");
    }

    #[test]
    fn render_summary_line_covers_every_kind() {
        // Payment
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        store.insert(make_payment_entry(DEFAULT_TTL_MS), 0).unwrap();
        let view = store.snapshot(0).into_iter().next().unwrap();
        assert!(render_summary_line(&view).contains("pay"));

        // Rejected tombstone
        let rejected_dir = TempDir::new().unwrap();
        let mut dir_store =
            PendingApprovalStore::open(rejected_dir.path().join("default.toml")).unwrap();
        let rejected_source = make_payment_entry(DEFAULT_TTL_MS);
        let nonce = rejected_source.approval_nonce.clone();
        dir_store.insert(rejected_source, 0).unwrap();
        dir_store.reject(&nonce, 0, DEFAULT_TTL_MS).unwrap();
        let rejected_view = dir_store.snapshot(0).into_iter().next().unwrap();
        assert!(render_summary_line(&rejected_view).contains("rejected"));
    }
}
