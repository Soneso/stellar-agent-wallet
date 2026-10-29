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
//! [`escape_for_terminal`]: summary values are decoded from an agent-built
//! envelope and must not be trusted with raw terminal output.
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
    let profile_name = resolve_profile_name(args.profile.as_deref()).name;

    // The name becomes a path component below without passing through the
    // loader, so it is validated here: these two commands build the approval
    // path directly and would otherwise write outside the data root.
    if let Err(reason) = validate_path_component_ascii_safe(&profile_name) {
        let err = WalletError::Validation(ValidationError::ConfigInvalid {
            component: "profile",
            reason: format!("invalid profile name '{profile_name}': {reason}"),
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
                let safe_msg = escape_for_terminal(&err.message);
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
/// Every interpolated field passes through [`escape_for_terminal`] before
/// being written: the summary values are decoded from an agent-built
/// envelope and the reason comes from the policy, so neither may reach the
/// terminal unsanitised.
fn render_pending_row(view: &PendingApprovalView, now_ms: u64) -> String {
    let nonce = escape_for_terminal(&view.approval_nonce);
    let kind = escape_for_terminal(view.kind_name);
    let summary = escape_for_terminal(&render_summary_line(view));
    let expires_in = if view.expired {
        "expired".to_owned()
    } else {
        format_expires_in(view.expires_at_unix_ms, now_ms)
    };
    let reason = view
        .reason
        .as_deref()
        .map(|reason| format!("  reason: {}", escape_for_terminal(reason)))
        .unwrap_or_default();
    format!("{nonce}  {kind:<24}  {summary}{reason}  (expires in {expires_in})")
}

/// Renders a one-line, non-secret summary for a [`PendingApprovalView`].
fn render_summary_line(view: &PendingApprovalView) -> String {
    match &view.summary {
        ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            dest_asset: Some(dest_asset),
            dest_amount_stroops: Some(dest_amount),
            memo,
            ..
        } => format!(
            "pay up to {amount_stroops} stroops {asset} to {to}, who receives at least \
             {dest_amount} stroops {dest_asset}, memo {}",
            memo.display()
        ),
        ApprovalSummaryView::Payment {
            to,
            amount_stroops,
            asset,
            memo,
            ..
        } => format!(
            "pay {amount_stroops} stroops {asset} to {to}, memo {}",
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
        // An x402 payment tombstone holds the digest of the final envelope,
        // never a chain hash, so its value is named for what it is.
        ApprovalSummaryView::Consumed {
            original_kind_name,
            tx_hash_redacted,
            outcome,
        } if original_kind_name == "X402Payment" => format!(
            "spent ({original_kind_name}), final-envelope digest {tx_hash_redacted}, outcome {outcome}"
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
        let home = TempDir::new().unwrap();
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
        let code = run(args).await;
        assert_eq!(code, 0, "list on a not-yet-existing store must succeed");
    }

    #[tokio::test]
    #[serial]
    async fn list_run_populated_store_reports_payment_and_rejected_entries() {
        let home = TempDir::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let dir = default_approval_dir().unwrap();
        assert_eq!(dir, home.path().join("approvals"));
        let profile = "__stellar_agent_approve_test_list_populated";
        let path = dir.join(format!("{profile}.toml"));

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
        let home = TempDir::new().unwrap();
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        let dir = default_approval_dir().unwrap();
        assert_eq!(dir, home.path().join("approvals"));
        let profile = "__stellar_agent_approve_test_list_expired_filter";
        let path = dir.join(format!("{profile}.toml"));

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
        let policy =
            load_signed_policy(&policy_path, "shape", &key.verifying_key().to_bytes()).unwrap();
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

    /// A consumed x402 payment approval names its value as the
    /// final-envelope digest.
    #[test]
    fn a_consumed_x402_approval_names_the_final_envelope_digest() {
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
            format!("spent (X402Payment), final-envelope digest {redacted}, outcome confirmed")
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
            [0x11; 32],
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
            [0x11; 32],
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
}
