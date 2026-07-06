//! `stellar-agent approve operator` — operator-approval credential
//! enrollment.
//!
//! Manages the dedicated operator-approval credential store
//! (`stellar_agent_core::approval::operator_credentials`) that authenticates
//! an operator for the remote-approval HTTP surface
//! (`stellar-agent-approval-remote`). This is a DIFFERENT trust role from a
//! smart-account signer passkey (`stellar-agent credentials add-passkey`):
//! enrolling here only ever grants the ability to consent to pending
//! wallet-controlled approvals, never on-chain signing authority.
//!
//! # Two enrollment modes
//!
//! `enroll` never runs over the network — it either drives a loopback
//! ceremony itself or imports the result of one that already ran elsewhere.
//! A WebAuthn credential is bound to its `rp.id` at creation, and a loopback
//! HTTP origin can only claim `"localhost"` as an effective domain, so which
//! mode applies depends on where the remote-approval listener is bound:
//!
//! - `--interactive`: for a loopback or SSH-tunnelled listener. Starts a
//!   one-shot local server (`stellar_agent_approval_ui::operator_enroll`),
//!   prints (and optionally opens) its enrollment URL, and persists the
//!   result automatically once the ceremony completes. Always produces a
//!   `rp_id: "localhost"` credential.
//! - `--credential-id` / `--public-key` / `--rp-id` / `--label` (all four
//!   together): for a domain-configured remote listener. Imports the id and
//!   public key produced by a WebAuthn ceremony run elsewhere — normally the
//!   remote listener's own `GET /enroll` page, which has to serve the
//!   ceremony from `https://<rp_id>` for the resulting credential to bind to
//!   that domain. This command's job in that mode is only to validate and
//!   persist the result.
//!
//! Either way, enrollment alone grants nothing — the profile's
//! `[remote_approval] allowed_credentials` list is the separate,
//! operator-controlled authorization step.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::{ArgGroup, Args, Subcommand};

use stellar_agent_approval_ui::operator_enroll::{
    OperatorEnrollAwaitError, start_operator_enroll_server,
};
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
    default_operator_approval_credentials_path,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::timefmt;

use crate::common::display_available;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Reminder attached to every successful enrollment, in both modes:
/// enrollment writes to the credential store only — it never touches the
/// profile's authorization allowlist.
const ALLOWLIST_NOTE: &str = "Enrollment does not by itself authorize this credential. Add its id \
     to this profile's [remote_approval] allowed_credentials list to permit it \
     to consent to remote approvals.";

/// Arguments for `stellar-agent approve operator`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct OperatorArgs {
    /// Nested subcommand (`enroll`).
    #[command(subcommand)]
    pub subcommand: OperatorSubcommand,
}

/// Subcommands of `stellar-agent approve operator`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum OperatorSubcommand {
    /// Enroll an operator-approval passkey credential.
    ///
    /// Validates and writes the credential to the profile's dedicated
    /// operator-approval credential store. Does NOT authorize the credential
    /// by itself — add its id to the profile's
    /// `[remote_approval] allowed_credentials` list separately.
    Enroll(EnrollArgs),
}

/// Arguments for `stellar-agent approve operator enroll`.
///
/// Exactly one of `--interactive` or the argument-import flags
/// (`--credential-id` / `--public-key` / `--rp-id` / `--label`) must be
/// given; the import flags are all-or-nothing together. `--sign-count` is
/// only meaningful alongside the import flags — interactive mode extracts
/// the sign count automatically.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(
    ArgGroup::new("enroll_mode")
        .args(["interactive", "credential_id_b64url"])
        .required(true)
        .multiple(false)
))]
pub struct EnrollArgs {
    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Start the interactive loopback enrollment ceremony: a one-shot local
    /// server serves a registration page, your authenticator creates the
    /// credential in place, and it is persisted automatically. Produces a
    /// credential bound to `rp_id: "localhost"` — correct for a local or
    /// SSH-tunnelled remote-approval listener. Mutually exclusive with the
    /// argument-import flags below.
    #[arg(long = "interactive")]
    pub interactive: bool,

    /// Do not open the enrollment URL in a browser; only print it.
    /// Interactive mode only — ignored (harmlessly) in argument-import mode,
    /// which never opens a browser.
    #[arg(long = "no-open")]
    pub no_open: bool,

    /// Interactive-ceremony timeout in seconds. Interactive mode only.
    #[arg(long = "timeout-seconds", value_name = "SECS", default_value_t = 300)]
    pub timeout_seconds: u64,

    /// Base64url WebAuthn credential id (16-64 raw bytes), from the
    /// registration ceremony's `PublicKeyCredential.id`.
    ///
    /// Import mode: use this to enroll a credential created on the
    /// operator's own device via the remote listener's `/enroll` page
    /// (domain-bound, for a remote-domain listener) — for a local or
    /// SSH-tunnelled listener, use `--interactive` instead. Requires
    /// `--public-key`, `--rp-id`, and `--label` together.
    #[arg(
        long = "credential-id",
        value_name = "B64URL",
        requires_all = ["public_key_sec1_b64", "rp_id", "label"]
    )]
    pub credential_id_b64url: Option<String>,

    /// Base64url-encoded 65-byte uncompressed SEC1 P-256 public key
    /// (`0x04 || X || Y`) extracted from the registration ceremony's
    /// attestation. Import mode only.
    #[arg(
        long = "public-key",
        value_name = "B64URL",
        conflicts_with = "interactive"
    )]
    pub public_key_sec1_b64: Option<String>,

    /// WebAuthn Relying Party ID this credential was registered against.
    /// Import mode only.
    #[arg(
        long = "rp-id",
        value_name = "HOSTNAME",
        conflicts_with = "interactive"
    )]
    pub rp_id: Option<String>,

    /// Operator-chosen human-readable label (e.g. `"laptop"`, `"phone"`).
    ///
    /// Import mode: required, alongside `--credential-id`. Interactive
    /// mode: optional pre-fill for the enrollment page's label field — if
    /// omitted, type it into the page.
    #[arg(long = "label", value_name = "LABEL")]
    pub label: Option<String>,

    /// Best-effort WebAuthn signature counter to seed at enrollment, read
    /// from the registration ceremony (the remote `/enroll` page displays
    /// it). Import mode only — interactive mode extracts this
    /// automatically, client-side. Advisory only: it seeds the
    /// clone-detection baseline and never affects authorization; see
    /// `OperatorApprovalCredential::sign_count`.
    #[arg(
        long = "sign-count",
        value_name = "U32",
        requires = "credential_id_b64url"
    )]
    pub sign_count: Option<u32>,
}

/// Runs `stellar-agent approve operator`.
///
/// Returns `0` on success, `1` on any error, user cancel, or timeout.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(args: OperatorArgs) -> i32 {
    match args.subcommand {
        OperatorSubcommand::Enroll(enroll_args) => run_enroll(enroll_args).await,
    }
}

async fn run_enroll(args: EnrollArgs) -> i32 {
    let profile_name = resolve_profile_name(args.profile.as_deref());
    if args.interactive {
        run_enroll_interactive(profile_name, args).await
    } else {
        run_enroll_args(profile_name, args).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument-import mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_enroll_args(profile_name: String, args: EnrollArgs) -> i32 {
    let store_path = match default_operator_approval_credentials_path(&profile_name) {
        Ok(p) => p,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_store_unavailable: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let registered_at_unix_ms = match timefmt::now_unix_ms() {
        Ok(n) => n,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.clock_error: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // The `enroll_mode` ArgGroup plus `credential_id_b64url`'s `requires_all`
    // guarantee all four are present together at parse time whenever this
    // branch runs. Handled defensively (not via `unreachable!()`) so this
    // function's "never panics" contract holds even if that clap wiring is
    // ever loosened by mistake.
    let (Some(credential_id_b64url), Some(public_key_sec1_b64), Some(rp_id), Some(label)) = (
        args.credential_id_b64url,
        args.public_key_sec1_b64,
        args.rp_id,
        args.label,
    ) else {
        let err = WalletError::Internal(InternalError::UnexpectedState {
            detail: "approve.operator_enroll_args_incomplete: credential-id, public-key, rp-id, \
                     and label must all be supplied together"
                .to_owned(),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    };

    let store = OperatorApprovalCredentialStore::new(store_path);
    let credential = OperatorApprovalCredential {
        credential_id_b64url: credential_id_b64url.clone(),
        public_key_sec1_b64,
        rp_id,
        label,
        registered_at_unix_ms,
        sign_count: args.sign_count,
    };

    match store.enroll(credential) {
        Ok(()) => {
            render_json(&Envelope::ok(EnrollResult {
                credential_id_b64url,
                enrolled: true,
                note: ALLOWLIST_NOTE.to_owned(),
            }));
            0
        }
        Err(ApprovalError::DuplicateCredentialId { .. }) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approve.operator_credential_already_enrolled: a credential with this id \
                         is already enrolled for this profile"
                    .to_owned(),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
        Err(ApprovalError::Invalid { reason }) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_credential_invalid: {reason}"),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_enroll_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
    }
}

/// JSON success payload for argument-import `approve operator enroll`.
#[derive(Debug, serde::Serialize)]
struct EnrollResult {
    credential_id_b64url: String,
    enrolled: bool,
    note: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Interactive mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_enroll_interactive(profile_name: String, args: EnrollArgs) -> i32 {
    let store_path = match default_operator_approval_credentials_path(&profile_name) {
        Ok(p) => p,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_store_unavailable: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // Snapshot the store's credential ids before the ceremony starts, so the
    // credential the ceremony persists can be identified afterward without
    // widening the completion signal's payload type.
    let store = OperatorApprovalCredentialStore::new(store_path.clone());
    let before_ids: HashSet<String> = match store.list() {
        Ok(list) => list.into_iter().map(|c| c.credential_id_b64url).collect(),
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_store_unavailable: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut handle =
        match start_operator_enroll_server(store_path, profile_name, bind_addr, args.label.clone())
            .await
        {
            Ok(h) => h,
            Err(e) => {
                let err = WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("approve.operator_enroll_interactive_start_failed: {e}"),
                });
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        };

    let url = handle.enroll_url();
    print_interactive_startup(&url);

    if !args.no_open && display_available() {
        let _ = webbrowser::open(&url);
    }

    let timeout = Duration::from_secs(args.timeout_seconds);
    let completion_result = handle.await_completion(timeout).await;

    if let Err(e) = handle.shutdown().await {
        // Non-fatal: the ceremony has already completed, timed out, or
        // errored — shutdown failing here does not change the outcome.
        tracing::debug!(
            error = %e,
            "approve operator enroll --interactive: shutdown did not complete cleanly"
        );
    }

    match completion_result {
        Ok(()) => report_interactive_success(&store, &before_ids),
        Err(OperatorEnrollAwaitError::Timeout) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approve.operator_enroll_interactive_timeout: no enrollment completed \
                         within the timeout"
                    .to_owned(),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_enroll_interactive_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
    }
}

/// Prints the interactive-ceremony startup guidance to stderr, keeping
/// stdout reserved for the terminal JSON envelope.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional interim guidance; stdout stays JSON-only"
)]
fn print_interactive_startup(url: &str) {
    eprintln!("stellar-agent: interactive operator enrollment ready.");
    eprintln!("  Open this URL and create a passkey: {url}");
    eprintln!(
        "  Remote host? Forward the port over SSH first: ssh -L <port>:127.0.0.1:<port> <user>@<host>"
    );
}

/// Diffs the store's credential ids against the pre-ceremony snapshot to
/// find the credential the ceremony just persisted, and renders the
/// success envelope.
///
/// # Errors
///
/// Returns exit code `1` (with an error envelope) if the store cannot be
/// read back, or if completion fired but no new credential is found — the
/// latter is unreachable given the server's single-use completion latch, and
/// is treated as a failure rather than reported as a success so a violated
/// invariant can never surface as a fabricated `enrolled` result.
fn report_interactive_success(
    store: &OperatorApprovalCredentialStore,
    before_ids: &HashSet<String>,
) -> i32 {
    let after = match store.list() {
        Ok(l) => l,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_store_unavailable: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    match after
        .into_iter()
        .find(|c| !before_ids.contains(&c.credential_id_b64url))
    {
        Some(cred) => {
            render_json(&Envelope::ok(InteractiveEnrollResult {
                status: "enrolled",
                credential_id_preview: credential_id_preview(&cred.credential_id_b64url),
                label: cred.label,
                rp_id: cred.rp_id,
                sign_count: cred.sign_count,
                note: ALLOWLIST_NOTE.to_owned(),
            }));
            0
        }
        None => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approve.operator_enroll_interactive_no_new_credential: the ceremony \
                         reported completion but no new credential is present in the store"
                    .to_owned(),
            });
            render_json(&Envelope::<()>::err(&err));
            1
        }
    }
}

/// Returns the first 8 characters of `id` (or the whole string if shorter)
/// followed by an ellipsis marker — a short, non-secret preview for the
/// interactive-enrollment summary. Distinct from the first-5-last-5
/// redaction used elsewhere in this crate: a preview for a one-shot success
/// summary has no tamper-evidence requirement to satisfy.
fn credential_id_preview(id: &str) -> String {
    let prefix: String = id.chars().take(8).collect();
    format!("{prefix}...")
}

/// JSON success payload for interactive `approve operator enroll`.
#[derive(Debug, serde::Serialize)]
struct InteractiveEnrollResult {
    status: &'static str,
    credential_id_preview: String,
    label: String,
    rp_id: String,
    sign_count: Option<u32>,
    note: String,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: EnrollArgs,
    }

    #[test]
    fn parses_required_flags() {
        let w = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
        ])
        .expect("flags parse");
        assert_eq!(
            w.args.credential_id_b64url.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAA")
        );
        assert_eq!(w.args.public_key_sec1_b64.as_deref(), Some("BBBBBBBB"));
        assert_eq!(w.args.rp_id.as_deref(), Some("wallet.internal"));
        assert_eq!(w.args.label.as_deref(), Some("laptop"));
        assert!(!w.args.interactive);
        assert_eq!(w.args.sign_count, None);
    }

    #[test]
    fn missing_required_flag_fails() {
        let result = Wrap::try_parse_from(["prog", "--credential-id", "AAAA"]);
        assert!(result.is_err());
    }

    #[test]
    fn neither_interactive_nor_credential_id_fails() {
        let result = Wrap::try_parse_from(["prog"]);
        assert!(result.is_err());
    }

    #[test]
    fn interactive_alone_parses() {
        let w = Wrap::try_parse_from(["prog", "--interactive"]).expect("flags parse");
        assert!(w.args.interactive);
        assert_eq!(w.args.credential_id_b64url, None);
    }

    #[test]
    fn interactive_with_credential_id_fails() {
        let result = Wrap::try_parse_from([
            "prog",
            "--interactive",
            "--credential-id",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn interactive_with_public_key_fails() {
        let result = Wrap::try_parse_from(["prog", "--interactive", "--public-key", "BBBBBBBB"]);
        assert!(result.is_err());
    }

    #[test]
    fn interactive_with_rp_id_fails() {
        let result = Wrap::try_parse_from(["prog", "--interactive", "--rp-id", "wallet.internal"]);
        assert!(result.is_err());
    }

    #[test]
    fn interactive_with_label_succeeds() {
        let w = Wrap::try_parse_from(["prog", "--interactive", "--label", "laptop"])
            .expect("flags parse");
        assert!(w.args.interactive);
        assert_eq!(w.args.label.as_deref(), Some("laptop"));
    }

    #[test]
    fn interactive_with_no_open_succeeds() {
        let w = Wrap::try_parse_from(["prog", "--interactive", "--no-open"]).expect("flags parse");
        assert!(w.args.interactive);
        assert!(w.args.no_open);
    }

    #[test]
    fn no_open_in_argument_mode_parses_but_is_unused() {
        let w = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
            "--no-open",
        ])
        .expect("flags parse");
        assert!(w.args.no_open);
        assert!(!w.args.interactive);
    }

    #[test]
    fn sign_count_with_args_parses() {
        let w = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
            "--sign-count",
            "42",
        ])
        .expect("flags parse");
        assert_eq!(w.args.sign_count, Some(42));
    }

    #[test]
    fn sign_count_without_credential_id_fails() {
        let result = Wrap::try_parse_from(["prog", "--interactive", "--sign-count", "42"]);
        assert!(result.is_err());
    }

    #[test]
    fn credential_id_preview_truncates_to_eight_chars() {
        assert_eq!(
            credential_id_preview("AAAAAAAAAAAAAAAAAAAAAA"),
            "AAAAAAAA..."
        );
    }

    #[test]
    fn credential_id_preview_handles_short_ids() {
        assert_eq!(credential_id_preview("AB"), "AB...");
    }
}
