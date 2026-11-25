//! `stellar-agent approve list` — enumerate pending approvals.
//!
//! Opens the profile-scoped pending-approvals store read-only and renders a
//! snapshot of every entry via [`stellar_agent_core::approval::PendingApprovalView`].
//! No keyring access and no network calls — this command only reads the
//! on-disk store.
//!
//! # Output (JSON envelope, default)
//!
//! `data` carries `pending` (non-tombstone entries), `resolved` (`Consumed`
//! and `Rejected` tombstones, each keeping its `kind_name`), and
//! `expired_count` (expired entries in the snapshot), alongside `profile`
//! when a saved profile matches:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "pending": [ /* PendingApprovalView, non-tombstone entries */ ],
//!     "resolved": [ /* PendingApprovalView, Consumed and Rejected tombstones */ ],
//!     "expired_count": 1
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Output (`--output table`)
//!
//! One row per entry: nonce, kind, a one-line wallet-controlled summary, and
//! an expiry column showing `(expires in <duration>)` for live entries or
//! `(expired)` for expired entries. Tombstone entries appear in a separate
//! section headed `Resolved`. When expired entries are omitted, a trailing
//! note reports how many were hidden and points to `approve gc`. Every
//! rendered field is passed through [`escape_for_terminal`]: summary values
//! are decoded from an agent-built envelope and must not be trusted with raw
//! terminal output.
//!
//! # `--include-expired`
//!
//! By default, expired entries are omitted from `pending` and `resolved`
//! (they no longer grant approval and only remain on disk until the next
//! `approve gc`). `expired_count` always reports the number of expired entries
//! in the snapshot, regardless of this flag, so the operator can tell whether
//! a `gc` is due even when expired entries are hidden. With `--include-expired`,
//! `--output table` shows those entries as `(expired)` and omits the hidden
//! entries note.
//!
//! # Exit codes
//!
//! - `0` on success (zero or more pending entries, including an empty list).
//! - `1` when the store cannot be opened (I/O error, locked, no approval dir).

use clap::Args;
use serde::Serialize;

use stellar_agent_core::approval::view::format_trustline_limit;
use stellar_agent_core::approval::{
    ApprovalSummaryView, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, PendingApprovalView,
    open_with_retry,
};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{ApprovalFailure, ValidationError, WalletError};
use stellar_agent_core::timefmt;

use crate::common::render::{escape_for_terminal, render_json};
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

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

    /// Include already-expired entries in `pending` and `resolved` instead of omitting them.
    #[arg(long = "include-expired")]
    pub include_expired: bool,
}

/// Success payload for the `approve list` JSON envelope.
///
/// Carries `pending` (non-tombstone entries), `resolved` (`Consumed` and
/// `Rejected` tombstones, each keeping its `kind_name`), and `expired_count`
/// (expired entries in the snapshot), plus `profile` when a saved profile
/// matches.
#[derive(Debug, Serialize)]
struct ListData {
    /// Saved profile the snapshot was taken from; absent when the name
    /// resolves to no saved profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// Non-tombstone pending entries, filtered per `--include-expired`.
    pending: Vec<PendingApprovalView>,
    /// Tombstone entries (`Consumed` and `Rejected`), filtered per `--include-expired`.
    resolved: Vec<PendingApprovalView>,
    /// Count of expired entries in the snapshot, independent of the filter.
    expired_count: usize,
}

/// Returns `true` when `view` is a terminal tombstone rather than an entry
/// awaiting a decision.
fn is_tombstone(view: &PendingApprovalView) -> bool {
    matches!(
        view.summary,
        ApprovalSummaryView::Consumed { .. } | ApprovalSummaryView::Rejected { .. }
    )
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
    let profile_name = resolve_profile_name(args.profile.as_deref()).name;

    // The name becomes a path component below without passing through the
    // loader, so it is validated here: these two commands build the approval
    // path directly and would otherwise write outside the data root.
    if let Err(reason) = validate_path_component_ascii_safe(&profile_name) {
        let err = WalletError::Validation(ValidationError::ConfigInvalid {
            component: "profile",
            reason: format!("the profile name is not a valid profile name: {reason}"),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    let store_path = match super::common::approval_store_dir() {
        Ok(dir) => dir.join(format!("{profile_name}.toml")),
        Err(err) => {
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
            let err = WalletError::Approval(ApprovalFailure::ClockError {
                detail: format!("system clock error: {e}"),
            });
            print_error(&Envelope::<()>::err(&err), args.output);
            return 1;
        }
    };

    let snapshot = store.snapshot(now_ms);
    let expired_count = snapshot.iter().filter(|v| v.expired).count();
    let (resolved, pending): (Vec<PendingApprovalView>, Vec<PendingApprovalView>) = snapshot
        .into_iter()
        .filter(|v| args.include_expired || !v.expired)
        .partition(is_tombstone);

    tracing::debug!(
        pending_count = pending.len(),
        resolved_count = resolved.len(),
        expired_count,
        "approval list completed"
    );

    let envelope = Envelope::ok(ListData {
        profile: super::common::saved_profile_name(profile_name),
        pending,
        resolved,
        expired_count,
    });
    print_success(&envelope, args.output, now_ms, args.include_expired);
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendering
// ─────────────────────────────────────────────────────────────────────────────

fn render_table(data: &ListData, now_ms: u64, include_expired: bool) -> String {
    let mut lines = Vec::new();
    if data.pending.is_empty() {
        match &data.profile {
            Some(profile) => lines.push(format!("No pending approvals for profile '{profile}'.")),
            None => lines.push("No pending approvals.".to_owned()),
        }
    } else {
        for view in &data.pending {
            lines.push(render_pending_row(view, now_ms));
        }
    }
    if !data.resolved.is_empty() {
        lines.push(String::new());
        lines.push("Resolved".to_owned());
        for view in &data.resolved {
            lines.push(render_pending_row(view, now_ms));
        }
    }
    if !include_expired && data.expired_count > 0 {
        lines.push(format!(
            "({} expired entr{} not shown; run `approve gc` to clear)",
            data.expired_count,
            if data.expired_count == 1 { "y" } else { "ies" }
        ));
    }
    lines.join("\n")
}

fn print_success(
    envelope: &Envelope<ListData>,
    format: OutputFormat,
    now_ms: u64,
    include_expired: bool,
) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(data) = &envelope.data {
                let table = render_table(data, now_ms, include_expired);
                #[cfg(test)]
                RENDERED_TABLES.with(|tables| tables.borrow_mut().push(table.clone()));
                println!("{table}");
            }
        }
        // `OutputFormat` is `#[non_exhaustive]`; unrecognised future variants
        // fall back to JSON rather than silently joining the table branch.
        _ => render_json(envelope),
    }
}

#[cfg(test)]
thread_local! {
    /// Tables rendered by `print_success` on the calling thread, oldest first.
    static RENDERED_TABLES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                let safe_msg = escape_for_terminal(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
    }
}

/// Renders one `--output table` row: nonce, kind, one-line summary, expiry.
///
/// Live entries show `(expires in <duration>)` relative to `now_ms`, the same
/// snapshot timestamp used to compute `view.expired`. Expired entries show
/// `(expired)`.
///
/// Every interpolated field passes through [`escape_for_terminal`] before
/// being written: the summary values are decoded from an agent-built
/// envelope and the reason comes from the policy, so neither may reach the
/// terminal unsanitised.
fn render_pending_row(view: &PendingApprovalView, now_ms: u64) -> String {
    let nonce = escape_for_terminal(&view.approval_nonce);
    let kind = escape_for_terminal(view.kind_name);
    let summary = escape_for_terminal(&render_summary_line(view));
    let expiry = if view.expired {
        "(expired)".to_owned()
    } else {
        format!(
            "(expires in {})",
            format_expires_in(view.expires_at_unix_ms, now_ms)
        )
    };
    let reason = view
        .reason
        .as_deref()
        .map(|reason| format!("  reason: {}", escape_for_terminal(reason)))
        .unwrap_or_default();
    format!("{nonce}  {kind:<24}  {summary}{reason}  {expiry}")
}

/// The base-account note of a muxed destination, or nothing without one.
fn base_account_note(base: Option<&str>) -> String {
    base.map(|base| format!(" (base account {base})"))
        .unwrap_or_default()
}

/// Renders a one-line, non-secret summary for a [`PendingApprovalView`].
fn render_summary_line(view: &PendingApprovalView) -> String {
    match &view.summary {
        ApprovalSummaryView::Payment {
            to,
            to_base,
            amount_stroops,
            asset,
            dest_asset: Some(dest_asset),
            dest_amount_stroops: Some(dest_amount),
            memo,
            ..
        } => format!(
            "pay up to {amount_stroops} stroops {asset} to {to}{}, who receives at least \
             {dest_amount} stroops {dest_asset}, memo {}",
            base_account_note(to_base.as_deref()),
            memo.display()
        ),
        ApprovalSummaryView::Payment {
            to,
            to_base,
            amount_stroops,
            asset,
            memo,
            ..
        } => format!(
            "pay {amount_stroops} stroops {asset} to {to}{}, memo {}",
            base_account_note(to_base.as_deref()),
            memo.display()
        ),
        ApprovalSummaryView::Trustline {
            holder,
            asset_code,
            asset_issuer,
            limit_stroops,
            memo,
            ..
        } => {
            let issuer = stellar_agent_core::approval::store::redact_g_strkey(asset_issuer);
            let limit = format_trustline_limit(*limit_stroops);
            format!(
                "trustline {asset_code}:{issuer} limit {limit} for {holder}, memo {}",
                memo.display()
            )
        }
        ApprovalSummaryView::Claim {
            balance_id_strkey,
            memo,
            ..
        } => format!("claim {balance_id_strkey}, memo {}", memo.display()),
        ApprovalSummaryView::Inconsistent {
            original_kind_name, ..
        } => format!("inconsistent {original_kind_name}: cannot be approved"),
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
            install_id,
            package_version,
            package_shasum_short,
            capability,
            destination,
            destination_base,
            ..
        } => format!(
            "toolset '{toolset_name}' {package_version} ({package_shasum_short}, install {install_id}) requests {capability} to {destination}{}",
            base_account_note(destination_base.as_deref())
        ),
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
        ApprovalSummaryView::MppCharge {
            amount,
            currency,
            payer_redacted,
            recipient_redacted,
            ..
        } => format!(
            "authorize {amount} base units {currency} from {payer_redacted} to {recipient_redacted}"
        ),
        ApprovalSummaryView::Rejected { original_kind_name } => {
            format!("rejected ({original_kind_name})")
        }
        // An x402 tombstone identifies the payment with a network-specific digest.
        ApprovalSummaryView::Consumed {
            original_kind_name,
            tx_hash_redacted,
            outcome,
        } if original_kind_name == "X402Payment" => format!(
            "spent ({original_kind_name}), payment digest {tx_hash_redacted}, outcome {outcome}"
        ),
        // A rule-proposal tombstone holds the proposal digest the operator
        // attested, written before the install sends anything.
        ApprovalSummaryView::Consumed {
            original_kind_name,
            tx_hash_redacted,
            outcome,
        } if original_kind_name == "RuleProposalSimulated" => format!(
            "spent ({original_kind_name}), proposal digest {tx_hash_redacted}, outcome {outcome}"
        ),
        ApprovalSummaryView::Consumed {
            original_kind_name,
            tx_hash_redacted,
            outcome,
        } => format!("spent ({original_kind_name}) on {tx_hash_redacted}, outcome {outcome}"),
        // `ApprovalSummaryView` is `#[non_exhaustive]`; a future variant
        // falls back to the entry's own kind name rather than failing to build.
        _ => format!("({} entry)", view.kind_name),
    }
}

/// Formats the remaining time until `expires_at_unix_ms`, relative to
/// `reference_unix_ms`, as a compact `"<n>m<n>s"` / `"<n>s"` string.
///
/// `reference_unix_ms` is the snapshot timestamp passed by [`render_pending_row`].
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
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
    const USDC_ISSUER_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    use serial_test::serial;
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, fixtures,
        process_uid_for_attestation,
    };
    use stellar_agent_core::profile::schema::default_approval_dir;
    use stellar_agent_test_support::StellarAgentHomeGuard;
    use tempfile::TempDir;

    use super::*;

    fn uid() -> String {
        process_uid_for_attestation().expect("UID available on test host")
    }

    fn make_payment_entry(ttl_ms: u64) -> PendingApproval {
        fixtures::payment_pending(
            SOURCE_G,
            DEST_G,
            "XLM",
            1_000_000,
            Some("hi"),
            100,
            1,
            uid(),
            ttl_ms,
        )
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
        let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        assert!(
            home.path()
                .join(stellar_agent_test_support::sandbox::MARKER)
                .is_file(),
            "owned wallet root is marked before the home guard"
        );
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let dir = default_approval_dir().unwrap();
        assert_eq!(dir, home.path().join("approvals"));
        let profile = "__stellar_agent_approve_test_list_empty";
        let path = dir.join(format!("{profile}.toml"));
        assert!(!path.exists());

        let args = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        crate::common::render::take_rendered_for_test();
        let code = run(args).await;
        assert_eq!(code, 0, "list on a not-yet-existing store must succeed");
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0]["data"]["pending"], serde_json::json!([]));
        assert_eq!(rendered[0]["data"]["resolved"], serde_json::json!([]));
        assert_eq!(rendered[0]["data"]["expired_count"], 0);
    }

    #[tokio::test]
    #[serial]
    async fn list_run_populated_store_separates_pending_from_tombstones() {
        let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        assert!(
            home.path()
                .join(stellar_agent_test_support::sandbox::MARKER)
                .is_file(),
            "owned wallet root is marked before the home guard"
        );
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let dir = default_approval_dir().unwrap();
        assert_eq!(dir, home.path().join("approvals"));
        let profile = "__stellar_agent_approve_test_list_populated";
        let path = dir.join(format!("{profile}.toml"));

        let now_ms = timefmt::now_unix_ms().unwrap();
        let pending_nonce;
        let rejected_nonce;
        let consumed_nonce;
        {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            let pending_entry = make_payment_entry(DEFAULT_TTL_MS);
            pending_nonce = pending_entry.approval_nonce.clone();
            store.insert(pending_entry, now_ms).unwrap();

            let rejected_source = make_payment_entry(DEFAULT_TTL_MS);
            rejected_nonce = rejected_source.approval_nonce.clone();
            store.insert(rejected_source, now_ms).unwrap();
            store
                .reject(&rejected_nonce, now_ms, DEFAULT_TTL_MS)
                .unwrap();

            let consumed_source = make_payment_entry(DEFAULT_TTL_MS);
            consumed_nonce = consumed_source.approval_nonce.clone();
            store.insert(consumed_source, now_ms).unwrap();
            store
                .consume(
                    &consumed_nonce,
                    &"ab".repeat(32),
                    stellar_agent_core::approval::ConsumedOutcome::Confirmed,
                )
                .unwrap();
        } // lock released

        let args = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        crate::common::render::take_rendered_for_test();
        let code = run(args).await;
        assert_eq!(code, 0);

        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1);
        let data = &rendered[0]["data"];
        let pending = data["pending"].as_array().unwrap();
        assert!(
            data["resolved"].is_array(),
            "expected resolved array: {data}"
        );
        let resolved = data["resolved"].as_array().unwrap();
        assert_eq!(pending.len(), 1, "only non-tombstone in pending: {data}");
        assert_eq!(pending[0]["approval_nonce"], pending_nonce);
        assert_eq!(pending[0]["kind_name"], "PaymentSimulated");
        assert_eq!(resolved.len(), 2, "tombstones live in resolved: {data}");
        assert!(
            resolved
                .iter()
                .any(|v| v["approval_nonce"] == rejected_nonce && v["kind_name"] == "Rejected")
        );
        assert!(
            resolved
                .iter()
                .any(|v| v["approval_nonce"] == consumed_nonce && v["kind_name"] == "Consumed")
        );
        assert_eq!(data["expired_count"], 0);
    }

    #[tokio::test]
    #[serial]
    async fn list_run_excludes_expired_unless_include_expired() {
        let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        assert!(
            home.path()
                .join(stellar_agent_test_support::sandbox::MARKER)
                .is_file(),
            "owned wallet root is marked before the home guard"
        );
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let dir = default_approval_dir().unwrap();
        assert_eq!(dir, home.path().join("approvals"));
        let profile = "__stellar_agent_approve_test_list_expired_filter";
        let path = dir.join(format!("{profile}.toml"));

        let now_ms = timefmt::now_unix_ms().unwrap();
        {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            store.insert(make_payment_entry(1), now_ms).unwrap(); // TTL=1ms
            let consumed_entry = make_payment_entry(1);
            let consumed_nonce = consumed_entry.approval_nonce.clone();
            store.insert(consumed_entry, now_ms).unwrap();
            store
                .consume(
                    &consumed_nonce,
                    &"cd".repeat(32),
                    stellar_agent_core::approval::ConsumedOutcome::Confirmed,
                )
                .unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));

        crate::common::render::take_rendered_for_test();
        let args_default = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: false,
        };
        assert_eq!(run(args_default).await, 0);
        let default_rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(
            default_rendered[0]["data"]["pending"],
            serde_json::json!([])
        );
        assert_eq!(
            default_rendered[0]["data"]["resolved"],
            serde_json::json!([])
        );
        assert_eq!(default_rendered[0]["data"]["expired_count"], 2);

        let args_include = ListArgs {
            profile: Some(profile.to_owned()),
            output: OutputFormat::Json,
            include_expired: true,
        };
        assert_eq!(run(args_include).await, 0);
        let included_rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(
            included_rendered[0]["data"]["pending"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            included_rendered[0]["data"]["resolved"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(included_rendered[0]["data"]["expired_count"], 2);
    }

    #[tokio::test]
    #[serial]
    async fn list_run_table_forwards_include_expired() {
        let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let profile = "__stellar_agent_approve_test_list_table";
        let path = default_approval_dir()
            .unwrap()
            .join(format!("{profile}.toml"));
        const CREATED_MS: u64 = 1_700_000_000_000;
        const TTL_MS: u64 = 1_000;
        let pending_nonce;
        let rejected_nonce;
        {
            let mut store = PendingApprovalStore::open(path).unwrap();
            let pending = make_timed_payment(CREATED_MS, TTL_MS);
            pending_nonce = pending.approval_nonce.clone();
            store.insert(pending, CREATED_MS).unwrap();
            let rejected = make_timed_payment(CREATED_MS, TTL_MS);
            rejected_nonce = rejected.approval_nonce.clone();
            store.insert(rejected, CREATED_MS).unwrap();
            assert!(store.reject(&rejected_nonce, CREATED_MS, TTL_MS).unwrap());
        }

        for (include_expired, expected) in [
            (
                false,
                "No pending approvals.\n(2 expired entries not shown; run `approve gc` to clear)"
                    .to_owned(),
            ),
            (
                true,
                format!(
                    "{pending_nonce}  {:<24}  pay 1000000 stroops XLM to {DEST_G}, memo text \"hi\"  (expired)\n\nResolved\n{rejected_nonce}  {:<24}  rejected (PaymentSimulated)  (expired)",
                    "PaymentSimulated", "Rejected"
                ),
            ),
        ] {
            RENDERED_TABLES.with(|tables| tables.borrow_mut().clear());
            let code = run(ListArgs {
                profile: Some(profile.to_owned()),
                output: OutputFormat::Table,
                include_expired,
            })
            .await;
            assert_eq!(code, 0, "include_expired={include_expired}");
            let tables = RENDERED_TABLES.with(|tables| std::mem::take(&mut *tables.borrow_mut()));
            assert_eq!(tables, vec![expected], "include_expired={include_expired}");
        }
    }

    #[test]
    fn render_table_places_tombstones_under_resolved_heading() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let pending_entry = make_payment_entry(DEFAULT_TTL_MS);
        let now_ms = pending_entry.created_at_unix_ms;
        store.insert(pending_entry, now_ms).unwrap();
        let pending_view = store.snapshot(now_ms).remove(0);
        let (consumed_view, _) = consumed_view(make_payment_entry(DEFAULT_TTL_MS));
        let rejected_dir = TempDir::new().unwrap();
        let mut rejected_store =
            PendingApprovalStore::open(rejected_dir.path().join("default.toml")).unwrap();
        let rejected_entry = make_payment_entry(DEFAULT_TTL_MS);
        let rejected_nonce = rejected_entry.approval_nonce.clone();
        rejected_store.insert(rejected_entry, now_ms).unwrap();
        rejected_store
            .reject(&rejected_nonce, now_ms, DEFAULT_TTL_MS)
            .unwrap();
        let rejected_view = rejected_store.snapshot(now_ms).remove(0);

        let pending_only = render_table(
            &ListData {
                profile: Some("default".to_owned()),
                pending: vec![pending_view.clone()],
                resolved: vec![],
                expired_count: 0,
            },
            now_ms,
            false,
        );
        assert!(!pending_only.contains("Resolved"), "{pending_only}");

        let both = render_table(
            &ListData {
                profile: Some("default".to_owned()),
                pending: vec![pending_view],
                resolved: vec![consumed_view.clone(), rejected_view],
                expired_count: 0,
            },
            now_ms,
            false,
        );
        assert!(
            both.contains("\n\nResolved\n"),
            "expected Resolved section heading: {both}"
        );
        let (before, after) = both.split_once("\n\nResolved\n").unwrap();
        assert!(before.contains("PaymentSimulated"), "{before}");
        assert!(!before.contains("spent (PaymentSimulated)"), "{before}");
        assert!(!before.contains("rejected (PaymentSimulated)"), "{before}");
        assert!(after.contains("spent (PaymentSimulated)"), "{after}");
        assert!(after.contains("rejected (PaymentSimulated)"), "{after}");

        let resolved_only = render_table(
            &ListData {
                profile: Some("default".to_owned()),
                pending: vec![],
                resolved: vec![consumed_view],
                expired_count: 1,
            },
            now_ms,
            false,
        );
        assert!(
            resolved_only.starts_with("No pending approvals for profile 'default'."),
            "{resolved_only}"
        );
        assert!(resolved_only.contains("\n\nResolved\n"), "{resolved_only}");
        assert!(
            resolved_only.contains("(1 expired entry not shown; run `approve gc` to clear)"),
            "{resolved_only}"
        );

        let unsaved_plural = render_table(
            &ListData {
                profile: None,
                pending: vec![],
                resolved: vec![],
                expired_count: 2,
            },
            now_ms,
            false,
        );
        assert!(
            unsaved_plural.starts_with("No pending approvals.\n"),
            "{unsaved_plural}"
        );
        assert!(
            unsaved_plural.contains("(2 expired entries not shown; run `approve gc` to clear)"),
            "{unsaved_plural}"
        );
    }

    fn make_timed_payment(created_ms: u64, ttl_ms: u64) -> PendingApproval {
        let mut entry = make_payment_entry(ttl_ms);
        entry.created_at_unix_ms = created_ms;
        entry.expires_at_unix_ms = created_ms + ttl_ms;
        entry
    }

    #[test]
    fn render_table_and_rows_format_expired_and_live_expiry_cells() {
        const CREATED_MS: u64 = 1_700_000_000_000;
        const LIVE_TTL_MS: u64 = 10 * 60 * 1_000;
        const EXPIRED_TTL_MS: u64 = 60 * 1_000;
        const NOW_MS: u64 = CREATED_MS + 9 * 60 * 1_000;

        let pending_view = |ttl_ms: u64| -> PendingApprovalView {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
            store
                .insert(make_timed_payment(CREATED_MS, ttl_ms), CREATED_MS)
                .unwrap();
            store.snapshot(NOW_MS).remove(0)
        };
        let consumed_at = |ttl_ms: u64| -> (PendingApprovalView, String) {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
            let entry = make_timed_payment(CREATED_MS, ttl_ms);
            let nonce = entry.approval_nonce.clone();
            store.insert(entry, CREATED_MS).unwrap();
            assert!(
                store
                    .consume(
                        &nonce,
                        &"ab".repeat(32),
                        stellar_agent_core::approval::ConsumedOutcome::Confirmed,
                    )
                    .unwrap()
            );
            let view = store.snapshot(NOW_MS).remove(0);
            let ApprovalSummaryView::Consumed {
                tx_hash_redacted, ..
            } = &view.summary
            else {
                panic!("{:?}", view.summary);
            };
            let redacted = tx_hash_redacted.clone();
            (view, redacted)
        };
        let rejected_at = |ttl_ms: u64| -> PendingApprovalView {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
            let entry = make_timed_payment(CREATED_MS, ttl_ms);
            let nonce = entry.approval_nonce.clone();
            store.insert(entry, CREATED_MS).unwrap();
            assert!(store.reject(&nonce, CREATED_MS, ttl_ms).unwrap());
            store.snapshot(NOW_MS).remove(0)
        };

        let live_pending = pending_view(LIVE_TTL_MS);
        let expired_pending = pending_view(EXPIRED_TTL_MS);
        let (live_consumed, live_tx_redacted) = consumed_at(LIVE_TTL_MS);
        let (expired_consumed, expired_tx_redacted) = consumed_at(EXPIRED_TTL_MS);
        let live_rejected = rejected_at(LIVE_TTL_MS);
        let expired_rejected = rejected_at(EXPIRED_TTL_MS);

        assert!(!live_pending.expired);
        assert!(expired_pending.expired);
        assert!(!live_consumed.expired);
        assert!(expired_consumed.expired);
        assert!(!live_rejected.expired);
        assert!(expired_rejected.expired);

        let expected_live_pending = format!(
            "{}  {:<24}  pay 1000000 stroops XLM to {DEST_G}, memo text \"hi\"  (expires in 1m00s)",
            live_pending.approval_nonce, "PaymentSimulated"
        );
        let expected_expired_pending = format!(
            "{}  {:<24}  pay 1000000 stroops XLM to {DEST_G}, memo text \"hi\"  (expired)",
            expired_pending.approval_nonce, "PaymentSimulated"
        );
        let expected_live_consumed = format!(
            "{}  {:<24}  spent (PaymentSimulated) on {live_tx_redacted}, outcome confirmed  (expires in 1m00s)",
            live_consumed.approval_nonce, "Consumed"
        );
        let expected_expired_consumed = format!(
            "{}  {:<24}  spent (PaymentSimulated) on {expired_tx_redacted}, outcome confirmed  (expired)",
            expired_consumed.approval_nonce, "Consumed"
        );
        let expected_live_rejected = format!(
            "{}  {:<24}  rejected (PaymentSimulated)  (expires in 1m00s)",
            live_rejected.approval_nonce, "Rejected"
        );
        let expected_expired_rejected = format!(
            "{}  {:<24}  rejected (PaymentSimulated)  (expired)",
            expired_rejected.approval_nonce, "Rejected"
        );

        assert_eq!(
            render_pending_row(&live_pending, NOW_MS),
            expected_live_pending
        );
        assert_eq!(
            render_pending_row(&expired_pending, NOW_MS),
            expected_expired_pending
        );
        assert_eq!(
            render_pending_row(&live_consumed, NOW_MS),
            expected_live_consumed
        );
        assert_eq!(
            render_pending_row(&expired_consumed, NOW_MS),
            expected_expired_consumed
        );
        assert_eq!(
            render_pending_row(&live_rejected, NOW_MS),
            expected_live_rejected
        );
        assert_eq!(
            render_pending_row(&expired_rejected, NOW_MS),
            expected_expired_rejected
        );

        let table = render_table(
            &ListData {
                profile: Some("default".to_owned()),
                pending: vec![live_pending, expired_pending],
                resolved: vec![
                    live_consumed,
                    expired_consumed,
                    live_rejected,
                    expired_rejected,
                ],
                expired_count: 3,
            },
            NOW_MS,
            true,
        );
        assert_eq!(
            table,
            [
                expected_live_pending,
                expected_expired_pending,
                String::new(),
                "Resolved".to_owned(),
                expected_live_consumed,
                expected_expired_consumed,
                expected_live_rejected,
                expected_expired_rejected,
            ]
            .join("\n")
        );
    }

    #[test]
    fn render_table_hidden_expired_note_matches_omission_flag_and_count() {
        const NOW_MS: u64 = 1_700_000_000_000;

        for (include_expired, expired_count, expected) in [
            (false, 0, "No pending approvals for profile 'default'."),
            (
                false,
                1,
                "No pending approvals for profile 'default'.\n(1 expired entry not shown; run `approve gc` to clear)",
            ),
            (
                false,
                3,
                "No pending approvals for profile 'default'.\n(3 expired entries not shown; run `approve gc` to clear)",
            ),
            (true, 0, "No pending approvals for profile 'default'."),
            (true, 1, "No pending approvals for profile 'default'."),
            (true, 3, "No pending approvals for profile 'default'."),
        ] {
            let rendered = render_table(
                &ListData {
                    profile: Some("default".to_owned()),
                    pending: vec![],
                    resolved: vec![],
                    expired_count,
                },
                NOW_MS,
                include_expired,
            );
            assert_eq!(
                rendered, expected,
                "include_expired={include_expired}, expired_count={expired_count}"
            );
        }
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
        let envelope = fixtures::payment_envelope(
            SOURCE_G,
            DEST_G,
            "XLM",
            1_000,
            Some("hello\x1b[31mworld"),
            100,
            1,
        );
        let entry = PendingApproval::new_payment_pending(
            envelope.clone(),
            envelope.as_bytes(),
            DEST_G.to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
        .with_policy_request(
            &stellar_agent_core::policy::ApprovalRequest::new(String::new(), 60)
                .with_reason("review\x1b[2Kthis".to_owned()),
        );
        store.insert(entry, 0).unwrap();
        let view = store.snapshot(0).into_iter().next().unwrap();
        // The row renderer must not embed the raw ESC byte anywhere.
        let row = render_pending_row(&view, 0);
        assert!(!row.contains('\x1b'), "escape sequence must be escaped");
        assert!(row.contains("review\\u{1b}[2Kthis"), "{row}");
    }

    #[test]
    fn render_summary_line_covers_every_kind() {
        for (limit, shown) in [
            (None, "unlimited"),
            (Some(0), "0 stroops (removes the trustline)"),
            (Some(123456789), "123456789 stroops"),
        ] {
            let dir = TempDir::new().unwrap();
            let mut store = PendingApprovalStore::open(dir.path().join("trustline.toml")).unwrap();
            store
                .insert(
                    fixtures::trustline_pending(
                        SOURCE_G,
                        "USDC",
                        USDC_ISSUER_G,
                        limit,
                        100,
                        42,
                        "1000".to_owned(),
                        DEFAULT_TTL_MS,
                    ),
                    0,
                )
                .unwrap();
            let view = store.snapshot(0).remove(0);
            assert_eq!(
                render_summary_line(&view),
                format!("trustline USDC:GBBD4...LFLA5 limit {shown} for {SOURCE_G}, memo none")
            );
            let json = serde_json::to_value(&view).unwrap();
            assert_eq!(
                json["summary"]["asset_issuer"],
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
            );
        }

        // Payment
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        store.insert(make_payment_entry(DEFAULT_TTL_MS), 0).unwrap();
        let view = store.snapshot(0).into_iter().next().unwrap();
        assert_eq!(
            render_summary_line(&view),
            format!("pay 1000000 stroops XLM to {DEST_G}, memo text \"hi\"")
        );

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
    #[test]
    fn rule_approval_shape_reaches_cli_list() {
        use ed25519_dalek::{Signer, SigningKey};
        use stellar_agent_core::policy::{
            Decision,
            v1::{canonical::canonical_bytes, loader::load_signed_policy, signature::digest},
        };
        let dir = TempDir::new().unwrap();
        let key = SigningKey::from_bytes(&[61; 32]);
        let body = "version = 1\nscope = \"profile:shape\"\n[[rules]]\nmatch = { tool = \"*\", chain = \"*\" }\ncriteria = []\ndecision = \"require_approval\"\nttl_secs = 617\nreason = \"Treasury review\"\n";
        let sig = hex::encode(
            key.sign(&digest(&canonical_bytes(body).unwrap()))
                .to_bytes(),
        );
        let owner = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
        let policy_path = dir.path().join("policy.toml");
        std::fs::write(
            &policy_path,
            format!("{body}\n[signature]\nowner_id = \"{owner}\"\nsig = \"{sig}\"\n"),
        )
        .unwrap();
        let policy = load_signed_policy(
            &policy_path,
            "shape",
            &key.verifying_key().to_bytes(),
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
        )
        .unwrap();
        let request = match &policy.rules[0].decision {
            Decision::RequireApproval(request) => Some(request),
            _ => None,
        }
        .expect("approval rule");
        let entry = make_payment_entry(DEFAULT_TTL_MS).with_policy_request(request);
        let now = entry.created_at_unix_ms;
        let store_path = dir.path().join("pending.toml");
        {
            let mut store = PendingApprovalStore::open(store_path.clone()).unwrap();
            store.insert(entry, now).unwrap();
        }
        let store = PendingApprovalStore::open(store_path).unwrap();
        let views = store.snapshot(now);
        let view = &views[0];
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json["reason"], "Treasury review");
        assert_eq!(view.expires_at_unix_ms - view.created_at_unix_ms, 617_000);
        let row = render_pending_row(view, now);
        assert!(row.contains("reason: Treasury review"), "{row}");
        assert!(row.contains("10m17s"), "{row}");
    }

    /// The tombstone view of `entry` after it is consumed with a 64-hex value
    /// and a confirmed outcome.
    fn consumed_view(entry: PendingApproval) -> (PendingApprovalView, String) {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("default.toml")).unwrap();
        let now_ms = entry.created_at_unix_ms;
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, now_ms).unwrap();
        let value = "ab".repeat(32);
        assert!(
            store
                .consume(
                    &nonce,
                    &value,
                    stellar_agent_core::approval::ConsumedOutcome::Confirmed
                )
                .unwrap()
        );
        let view = store.snapshot(now_ms).pop().unwrap();
        let ApprovalSummaryView::Consumed {
            tx_hash_redacted, ..
        } = &view.summary
        else {
            panic!("{:?}", view.summary);
        };
        let redacted = tx_hash_redacted.clone();
        (view, redacted)
    }

    /// A consumed x402 payment approval names its value as the payment digest.
    #[test]
    fn a_consumed_x402_approval_names_the_payment_digest() {
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
        };
        let root = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([4; 32])),
                    ))),
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([5; 32])),
                    ))),
                    ScVal::from(123i128),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };
        let entry = PendingApproval::new_x402_pending(
            &[7; 32],
            &root,
            Some("pay.example.org".to_owned()),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let (view, redacted) = consumed_view(entry);
        assert_eq!(
            render_summary_line(&view),
            format!("spent (X402Payment), payment digest {redacted}, outcome confirmed")
        );
    }

    /// A consumed rule-proposal approval names its value as the proposal
    /// digest.
    #[test]
    fn consumed_rule_proposal_names_its_value_as_the_proposal_digest() {
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };
        let entry = PendingApproval::new_rule_proposal_pending(
            "CDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            ContextRuleProposalSnapshot::new(
                RuleProposalContextType::Default,
                "rule".to_owned(),
                None,
                vec![RuleProposalSigner::delegated(SOURCE_G.to_owned(), true)],
                vec![],
                vec![0],
                false,
                false,
            ),
            "rule".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let (view, redacted) = consumed_view(entry);
        assert_eq!(
            render_summary_line(&view),
            format!("spent (RuleProposalSimulated), proposal digest {redacted}, outcome confirmed")
        );
    }

    /// Every other consumed approval keeps the transaction wording.
    #[test]
    fn a_consumed_payment_approval_keeps_the_transaction_wording() {
        let (view, redacted) = consumed_view(make_payment_entry(DEFAULT_TTL_MS));
        assert_eq!(
            render_summary_line(&view),
            format!("spent (PaymentSimulated) on {redacted}, outcome confirmed")
        );
    }
    #[test]
    fn approve_list_preserves_unicode_and_escapes_bidi_rule_names() {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("list.toml")).unwrap();
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };
        let entry = PendingApproval::new_rule_proposal_pending(
            "CDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            "stellar:testnet".to_owned(),
            ContextRuleProposalSnapshot::new(
                RuleProposalContextType::Default,
                "rule".to_owned(),
                None,
                vec![RuleProposalSigner::delegated(SOURCE_G.to_owned(), true)],
                vec![],
                vec![0],
                false,
                false,
            ),
            "rule".to_owned(),
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        store.insert(entry, 0).unwrap();
        let mut view = store.snapshot(0).remove(0);
        for (name, shown) in [("café", "café"), ("rule\u{202e}", "rule\\u{202e}")] {
            if let ApprovalSummaryView::RuleProposal {
                summary_line,
                definition,
                ..
            } = &mut view.summary
            {
                *summary_line = name.to_owned();
                definition.name = name.to_owned();
            }
            view.reason = Some(name.to_owned());
            let row = render_pending_row(&view, 0);
            assert!(row.contains(&format!("{shown} on")), "{row}");
            assert!(!row.contains('\u{202e}'));
        }
    }

    #[test]
    fn the_gate_summary_shows_version_shasum_and_install_id() {
        let entry = PendingApproval::new_toolset_first_invoke_gate_pending(
            "my-toolset".to_owned(),
            "a".repeat(32),
            "1.2.3".to_owned(),
            "d".repeat(64),
            "sign-payment".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
            "XLM".to_owned(),
            0,
            10,
            stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
            60_000,
        )
        .unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let mut store =
            stellar_agent_core::approval::PendingApprovalStore::open(dir.path().join("test.toml"))
                .unwrap();
        let now = entry.created_at_unix_ms;
        store.insert(entry, now).unwrap();
        let view = store.snapshot(now).remove(0);
        let line = render_summary_line(&view);
        assert!(line.contains(&format!(
            "toolset 'my-toolset' 1.2.3 ({}, install {}) requests sign-payment",
            "d".repeat(12),
            "a".repeat(32)
        )));
        assert!(!line.contains(&"d".repeat(13)));
    }

    /// SHA-256 of each pending row and summary line from fixed inputs.
    fn rendered_list_outputs() -> Vec<String> {
        use sha2::{Digest as _, Sha256};
        const NOW: u64 = 1_700_000_000_000;
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("rows.toml")).unwrap();
        let entries = [
            fixtures::payment_pending(
                SOURCE_G,
                DEST_G,
                "XLM",
                1_000_000,
                Some("hi"),
                100,
                1,
                "1000".to_owned(),
                600_000,
            ),
            fixtures::trustline_pending(
                SOURCE_G,
                "USDC",
                USDC_ISSUER_G,
                Some(5),
                100,
                42,
                "1000".to_owned(),
                600_000,
            ),
        ];
        for (index, mut entry) in entries.into_iter().enumerate() {
            entry.approval_nonce = format!("{index}").repeat(22);
            entry.created_at_unix_ms = NOW;
            entry.expires_at_unix_ms = NOW + 600_000;
            store.insert(entry, NOW).unwrap();
        }
        store
            .snapshot(NOW)
            .iter()
            .flat_map(|view| {
                [
                    render_pending_row(view, NOW + 1_000),
                    render_summary_line(view),
                ]
            })
            .map(|text| stellar_agent_core::hex::encode(&Sha256::digest(text.as_bytes())))
            .collect()
    }

    /// The digests of [`rendered_list_outputs`] as the base tree renders them.
    const BASE_LIST_OUTPUTS: &[&str] = &[
        "187b3d08ab53185bbff73e3a0a7efd228db1acd34e48dbfceb787558b46b5778",
        "e1be7985f1ecc8301ee9de9a756558519304e597c3e484e2cac0926fa0d94919",
        "84709417b1bc89d97f0644226f85ad0b64b72fc6ad24735451468e0c0a24f36d",
        "5c369cfacd99f2d6e5757faed755e35a931e9d00858bd2a2eb5328687bd7b042",
    ];

    #[test]
    fn list_renderers_keep_base_bytes() {
        assert_eq!(rendered_list_outputs(), BASE_LIST_OUTPUTS);
    }

    /// The owner sees the base. For a payment and a toolset grant to
    /// M0 or M17, the approval UI, `approve list` and `approve run` show the
    /// full M and a base account row; G payments and grants render without
    /// one.
    #[test]
    #[serial_test::serial]
    fn muxed_approval_shows_base_account() {
        let guard_home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        assert!(
            guard_home
                .path()
                .join(stellar_agent_test_support::sandbox::MARKER)
                .is_file(),
            "owned wallet root is marked before the home guard"
        );
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        use stellar_agent_core::approval::view::ApprovalSummaryView;
        let key = [0xAE; 32];
        let g = format!("{}", stellar_strkey::ed25519::PublicKey(key));
        let m = |id: u64| {
            format!(
                "{}",
                stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
            )
        };
        let payment = |destination: &str| {
            let mut builder = stellar_agent_network::builder::ClassicOpBuilder::new(
                SOURCE_G,
                41,
                stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                100,
            );
            builder
                .payment(
                    destination,
                    stellar_agent_core::StellarAmount::from_stroops(2_500_000),
                    &stellar_agent_network::builder::Asset::Native,
                )
                .map(|_| ())
                .unwrap();
            let envelope = builder.build().unwrap();
            PendingApproval::new_payment_pending(
                envelope.clone(),
                envelope.as_bytes(),
                destination.to_owned(),
                2_500_000,
                "XLM".to_owned(),
                None,
                100,
                42,
                uid(),
                DEFAULT_TTL_MS,
            )
            .unwrap()
        };
        let gate = |destination: &str| {
            PendingApproval::new_toolset_first_invoke_gate_pending(
                "mux-tools".to_owned(),
                "a".repeat(32),
                "1.0.0".to_owned(),
                "d".repeat(64),
                "sign-payment".to_owned(),
                destination.to_owned(),
                "XLM".to_owned(),
                0,
                10,
                uid(),
                DEFAULT_TTL_MS,
            )
            .unwrap()
        };
        let context = {
            let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
                "svc", "default", "nonce", "default",
            )
            .build();
            stellar_agent_core::approval::ApprovalContext::from_profile("render-test", &profile)
        };
        let base_row = format!("Base account</div>\n      <div class=\"addr\">{g}</div>");
        for (destination, muxed) in [(g.clone(), false), (m(0), true), (m(17), true)] {
            for entry in [payment(&destination), gate(&destination)] {
                let dir = TempDir::new().unwrap();
                {
                    let mut store =
                        PendingApprovalStore::open(dir.path().join("mux.toml")).unwrap();
                    store.insert(entry.clone(), 0).unwrap();
                }
                // The entry survives a reload of the store file.
                let store = PendingApprovalStore::open(dir.path().join("mux.toml")).unwrap();
                let view = store.snapshot(0).remove(0);
                let base = match &view.summary {
                    ApprovalSummaryView::Payment { to, to_base, .. } => {
                        assert_eq!(to, &destination);
                        to_base.clone()
                    }
                    ApprovalSummaryView::ToolsetFirstInvokeGate {
                        destination: shown,
                        destination_base,
                        ..
                    } => {
                        assert_eq!(shown, &destination);
                        destination_base.clone()
                    }
                    other => panic!("{other:?}"),
                };
                assert_eq!(base, muxed.then(|| g.clone()), "{destination}");

                let html = stellar_agent_approval_ui::render_summary_html(&view);
                let line = render_summary_line(&view);
                let mut sink = Vec::new();
                crate::commands::approve::run::write_summary(&entry, &context, &mut sink).unwrap();
                let run = String::from_utf8(sink).unwrap();
                if muxed {
                    assert!(html.contains(&destination), "{html}");
                    assert!(html.contains(&base_row), "{html}");
                    assert!(line.contains(&destination), "{line}");
                    assert!(line.contains(&format!("(base account {g})")), "{line}");
                    assert!(run.contains(&destination), "{run}");
                    assert!(
                        run.contains(&format!("  Base account:      {g}\n")),
                        "{run}"
                    );
                } else {
                    assert!(!html.contains("Base account"), "{html}");
                    assert!(!line.contains("base account"), "{line}");
                    assert!(!run.contains("Base account"), "{run}");
                }
            }
        }
    }

    use stellar_agent_core::approval::store::ApprovalKind;

    /// The G account the consent cases name and its maximum-ID M address.
    const CONSENT_G: &str = "GDK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LCRG";
    const CONSENT_MMAX: &str =
        "MDK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5LVOV2XK5L7777777777774ZMO";

    fn consent_context() -> stellar_agent_core::approval::ApprovalContext {
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "svc", "default", "nonce", "default",
        )
        .build();
        stellar_agent_core::approval::ApprovalContext::from_profile("render-test", &profile)
    }

    fn gate_entry(toolset: &str, destination: &str) -> PendingApproval {
        PendingApproval::new_toolset_first_invoke_gate_pending(
            toolset.to_owned(),
            "a".repeat(32),
            "1.0.0".to_owned(),
            "d".repeat(64),
            "sign-payment".to_owned(),
            destination.to_owned(),
            "XLM".to_owned(),
            0,
            10,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    /// The stored view of `entry`, the page, the `approve list` line, and
    /// the `approve` prompt.
    fn rendered(entry: &PendingApproval) -> (PendingApprovalView, String, String, String) {
        let dir = TempDir::new().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("consent.toml")).unwrap();
        store.insert(entry.clone(), 0).unwrap();
        let view = store.snapshot(0).remove(0);
        let html = stellar_agent_approval_ui::render_summary_html(&view);
        let line = render_pending_row(&view, 0);
        let mut sink = Vec::new();
        crate::commands::approve::run::write_summary(entry, &consent_context(), &mut sink).unwrap();
        (view, html, line, String::from_utf8(sink).unwrap())
    }

    /// A toolset grant to G or to the maximum-ID M shows the complete
    /// address on the page, the list line, and the prompt; M shows its base
    /// row and G shows none.
    #[test]
    #[serial_test::serial]
    fn toolset_consent_shows_the_complete_destination() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let (_, html, line, run) = rendered(&gate_entry("pay-tools", CONSENT_G));
        assert!(
            html.contains(&format!(
                "Destination</div>\n      <div class=\"addr\">{CONSENT_G}</div>"
            )),
            "{html}"
        );
        assert!(!html.contains("GDK5L...5LCRG"), "{html}");
        assert!(!html.contains("Base account"), "{html}");
        assert!(
            line.contains(&format!("requests sign-payment to {CONSENT_G}")),
            "{line}"
        );
        assert!(!line.contains("base account"), "{line}");
        assert!(
            run.contains(&format!("  Destination:       {CONSENT_G}\n")),
            "{run}"
        );
        assert!(!run.contains("Base account"), "{run}");

        let (_, html, line, run) = rendered(&gate_entry("pay-tools", CONSENT_MMAX));
        assert!(
            html.contains(&format!(
                "Destination</div>\n      <div class=\"addr\">{CONSENT_MMAX}</div>"
            )),
            "{html}"
        );
        assert!(
            html.contains(&format!(
                "Base account</div>\n      <div class=\"addr\">{CONSENT_G}</div>"
            )),
            "{html}"
        );
        assert!(
            line.contains(&format!("to {CONSENT_MMAX} (base account {CONSENT_G})")),
            "{line}"
        );
        assert!(
            run.contains(&format!("  Destination:       {CONSENT_MMAX}\n")),
            "{run}"
        );
        assert!(
            run.contains(&format!("  Base account:      {CONSENT_G}\n")),
            "{run}"
        );
    }

    /// Contract payments retain their full destination in the list and JSON.
    #[test]
    #[serial_test::serial]
    fn contract_list_shows_the_complete_destination() {
        let entry = fixtures::sac_payment_pending(
            stellar_agent_core::profile::caip2::Caip2::Testnet,
            stellar_agent_core::approval::IntentAsset::Native,
        );
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = stellar_agent_core::approval::PendingApprovalStore::open(
            dir.path().join("contract.toml"),
        )
        .unwrap();
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let view = store.snapshot(entry.created_at_unix_ms).remove(0);
        let line = render_pending_row(&view, entry.created_at_unix_ms);
        assert!(
            line.contains("CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ"),
            "full contract destination"
        );
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["summary"]["fee_stroops"], "500100");
    }

    /// A payment to the maximum-ID M shows its complete `to` and its base
    /// row on the page, the list line, and the prompt.
    #[test]
    #[serial_test::serial]
    fn payment_consent_shows_the_complete_destination() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let entry = fixtures::payment_pending(
            SOURCE_G,
            CONSENT_MMAX,
            "XLM",
            2_500_000,
            None,
            100,
            42,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        );
        let (view, html, line, run) = rendered(&entry);
        let ApprovalSummaryView::Payment { to, to_base, .. } = &view.summary else {
            panic!("{:?}", view.summary)
        };
        assert_eq!(to, CONSENT_MMAX);
        assert_eq!(to_base.as_deref(), Some(CONSENT_G));
        assert!(html.contains(CONSENT_MMAX), "{html}");
        assert!(
            html.contains(&format!(
                "Base account</div>\n      <div class=\"addr\">{CONSENT_G}</div>"
            )),
            "{html}"
        );
        assert!(line.contains(CONSENT_MMAX), "{line}");
        assert!(
            line.contains(&format!("(base account {CONSENT_G})")),
            "{line}"
        );
        assert!(run.contains(CONSENT_MMAX), "{run}");
        assert!(
            run.contains(&format!("  Base account:      {CONSENT_G}\n")),
            "{run}"
        );
    }

    /// A toolset request whose stored `destination` has a bad checksum, with
    /// control and multibyte text, renders as inconsistent and escaped, stays
    /// listable and rejectable, and refuses approval with
    /// `approval.entry_inconsistent`. A payment whose stored `summary_to`
    /// has a bad checksum shows the envelope's destination, never the stored
    /// text, and refuses approval with the same code.
    #[test]
    #[serial_test::serial]
    fn malformed_consent_terms_render_escaped() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        // Stores `entry`, replaces its one `from` with `to` in the stored
        // file, and reopens the store.
        fn stored_with(
            dir: &TempDir,
            entry: &PendingApproval,
            from: &str,
            to: &str,
        ) -> PendingApprovalStore {
            let path = dir.path().join("malformed.toml");
            PendingApprovalStore::open(path.clone())
                .unwrap()
                .insert(entry.clone(), 0)
                .unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text.matches(from).count(), 1, "{text}");
            std::fs::write(&path, text.replace(from, to)).unwrap();
            PendingApprovalStore::open(path).unwrap()
        }

        // The toolset `destination` with a bad checksum.
        let bad_g = format!("{}A", &CONSENT_G[..CONSENT_G.len() - 1]);
        let gate = gate_entry("tools", CONSENT_G);
        let dir = TempDir::new().unwrap();
        let mut store = stored_with(&dir, &gate, CONSENT_G, &bad_g);
        let loaded = store.get(&gate.approval_nonce).unwrap().clone();
        let view = store.snapshot(0).remove(0);
        assert!(
            matches!(view.summary, ApprovalSummaryView::Inconsistent { .. }),
            "{:?}",
            view.summary
        );
        let html = stellar_agent_approval_ui::render_summary_html(&view);
        assert!(!html.contains(&bad_g), "{html}");
        let mut sink = Vec::new();
        crate::commands::approve::run::write_summary(&loaded, &consent_context(), &mut sink)
            .unwrap();
        let run = String::from_utf8(sink).unwrap();
        assert!(run.contains("INCONSISTENT"), "{run}");
        assert_eq!(
            stellar_agent_core::approval::verify_entry_terms(&loaded.kind)
                .unwrap_err()
                .code(),
            "approval.entry_inconsistent"
        );
        assert!(
            store
                .reject(&gate.approval_nonce, 0, DEFAULT_TTL_MS)
                .unwrap()
        );
        assert!(matches!(
            store.snapshot(0).remove(0).summary,
            ApprovalSummaryView::Rejected { .. }
        ));

        // The payment `summary_to` with a bad checksum.
        let bad_m = format!("{}A", &CONSENT_MMAX[..CONSENT_MMAX.len() - 1]);
        let payment = fixtures::payment_pending(
            SOURCE_G,
            CONSENT_MMAX,
            "XLM",
            2_500_000,
            None,
            100,
            42,
            process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        );
        let dir = TempDir::new().unwrap();
        let mut store = stored_with(&dir, &payment, CONSENT_MMAX, &bad_m);
        let loaded = store.get(&payment.approval_nonce).unwrap().clone();
        let view = store.snapshot(0).remove(0);
        let ApprovalSummaryView::Payment { to, .. } = &view.summary else {
            panic!("{:?}", view.summary)
        };
        assert_eq!(to, CONSENT_MMAX, "the view decodes the envelope");
        let html = stellar_agent_approval_ui::render_summary_html(&view);
        assert!(html.contains(CONSENT_MMAX), "{html}");
        assert!(!html.contains(&bad_m), "{html}");
        assert!(render_pending_row(&view, 0).contains(CONSENT_MMAX));
        assert_eq!(
            stellar_agent_core::approval::verify_stored_destination(&loaded.kind)
                .unwrap_err()
                .code(),
            "approval.entry_inconsistent"
        );
        assert!(
            store
                .reject(&payment.approval_nonce, 0, DEFAULT_TTL_MS)
                .unwrap()
        );

        // Control and multibyte text renders escaped on the page, the list
        // line, and the prompt.
        let hostile = "t<b>\u{e9}\u{1b}[31m\u{202e}";
        let mut entry = gate_entry("tools", CONSENT_MMAX);
        let (mut view, _, _, _) = rendered(&entry);
        if let ApprovalSummaryView::ToolsetFirstInvokeGate { toolset_name, .. } = &mut view.summary
        {
            hostile.clone_into(toolset_name);
        }
        let html = stellar_agent_approval_ui::render_summary_html(&view);
        assert!(html.contains("t&lt;b&gt;\u{e9}"), "{html}");
        assert!(!html.contains("<b>"), "{html}");
        assert!(html.contains(CONSENT_MMAX), "{html}");
        let line = render_pending_row(&view, 0);
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{202e}'),
            "{line:?}"
        );
        assert!(line.contains(CONSENT_MMAX), "{line}");
        if let ApprovalKind::ToolsetFirstInvokeGate { toolset_name, .. } = &mut entry.kind {
            hostile.clone_into(toolset_name);
        }
        let mut sink = Vec::new();
        crate::commands::approve::run::write_summary(&entry, &consent_context(), &mut sink)
            .unwrap();
        let run = String::from_utf8(sink).unwrap();
        assert!(
            !run.contains('\u{1b}') && !run.contains('\u{202e}'),
            "{run:?}"
        );
        assert!(run.contains(CONSENT_MMAX), "{run}");
    }
}
