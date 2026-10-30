//! `stellar-agent approve operator` — operator-approval credential
//! enrollment and removal.
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
//! - `--interactive`: for a loopback or SSH-tunnelled listener. Needs a
//!   terminal on stdin and stderr. Starts a one-shot local server
//!   (`stellar_agent_approval_ui::operator_enroll`), prints its enrollment
//!   URL, and opens it through a private redirect file unless `--no-open` is
//!   passed (the launcher never receives the URL itself). The server verifies
//!   the registration over its own challenge and stages it; the page then
//!   shows a confirmation code, and the command persists the credential only
//!   after the operator types that code at the terminal before the timeout.
//!   Always produces a `rp_id: "localhost"` credential.
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
//!
//! # Removal
//!
//! `remove --credential-id <B64URL>` deletes the enrollment record under the
//! credential store's write lock and reports whether one was removed. It
//! never edits the profile. Revoking a credential means removing its ID from
//! `allowed_credentials` and then removing its enrollment: a running
//! listener refuses it as soon as either is gone, and its uncommitted
//! approvals refuse at mainnet commit.
//!
//! # Profile name
//!
//! Both subcommands resolve the profile from `--profile`, then
//! `STELLAR_AGENT_PROFILE`, then `"default"`, and refuse a name that is not
//! a safe path component with `validation.config_invalid` before any
//! filesystem work: the name becomes the credential store's file name.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use clap::{ArgGroup, Args, Subcommand};

use stellar_agent_approval_ui::operator_enroll::{
    ConfirmedOperatorEnrollment, OperatorEnrollAwaitError, OperatorEnrollHandle,
    OperatorEnrollmentConfirmationError, PendingOperatorEnrollment, start_operator_enroll_server,
};
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
    default_operator_approval_credentials_path,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::timefmt;
use stellar_agent_loopback_http::brand::PageIdentity;

use crate::common::private_open;
use crate::common::profile_access::load_profile_reconciled;
use crate::common::render::{escape_for_terminal, render_json};
use crate::common::served_pages::page_identity_for;
use crate::common::tty::{read_line_from_terminal, stdin_and_stderr_are_terminals};
use crate::common::{display_available, interrupted};
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

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
    /// Remove an enrolled operator-approval credential.
    ///
    /// Deletes the credential's enrollment record and prints whether one was
    /// removed; removing an absent credential succeeds with `false`. Does
    /// not edit the profile: remove the id from
    /// `[remote_approval] allowed_credentials` first, then the enrollment.
    Remove(RemoveArgs),
}

/// Arguments for `stellar-agent approve operator remove`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct RemoveArgs {
    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Base64url WebAuthn credential id of the enrollment to remove.
    #[arg(
        long = "credential-id",
        value_name = "B64URL",
        allow_hyphen_values = true
    )]
    pub credential_id_b64url: String,
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
    /// credential over the server's challenge, and the page shows a
    /// confirmation code. The credential is persisted only after you type
    /// that code here, before the timeout. Needs a terminal. Produces a
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

    /// Interactive-ceremony timeout in seconds, covering both the browser
    /// registration and the terminal confirmation. Interactive mode only.
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
        allow_hyphen_values = true,
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
    /// it). Import mode only; interactive mode reads it from the verified
    /// authenticator data. Advisory only: it seeds the
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
        OperatorSubcommand::Remove(remove_args) => run_remove(&remove_args),
    }
}

async fn run_enroll(args: EnrollArgs) -> i32 {
    let resolved = match resolve_store_profile(args.profile.as_deref()) {
        Ok(resolved) => resolved,
        Err(code) => return code,
    };
    let profile_name = resolved.name.clone();
    if args.interactive {
        run_enroll_interactive(resolved, args).await
    } else {
        run_enroll_args(profile_name, args).await
    }
}

/// Resolves the profile whose operator-credential store a subcommand uses.
///
/// The name becomes the store's file name, so a name that is not a safe
/// path component (an absolute path, a separator, a `..` component) is
/// refused here, before any filesystem work, whether it came from
/// `--profile` or from `STELLAR_AGENT_PROFILE`.
///
/// # Errors
///
/// Renders `validation.config_invalid` and returns exit code `1`.
fn resolve_store_profile(flag: Option<&str>) -> Result<ResolvedProfileName, i32> {
    let resolved = resolve_profile_name(flag);
    if let Err(reason) = validate_path_component_ascii_safe(&resolved.name) {
        let err = WalletError::Validation(ValidationError::ConfigInvalid {
            component: "profile",
            reason: format!("invalid profile name '{}': {reason}", resolved.name),
        });
        render_json(&Envelope::<()>::err(&err));
        return Err(1);
    }
    Ok(resolved)
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

async fn run_enroll_interactive(resolved: ResolvedProfileName, args: EnrollArgs) -> i32 {
    // The confirmation code is typed at this terminal; without one the
    // ceremony could never be confirmed, so nothing starts.
    if !stdin_and_stderr_are_terminals() {
        render_json(&Envelope::<()>::err_raw(
            "approve.operator_enroll_tty_required",
            "interactive enrollment needs a terminal on stdin and stderr to type the \
             confirmation code the enrollment page shows",
        ));
        return 1;
    }

    let profile_name = resolved.name.clone();
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
    let store = OperatorApprovalCredentialStore::new(store_path.clone());

    // A protected refusal or a name mismatch blocks the ceremony.
    // Any other load failure yields the neutral identity.
    let page_identity = match page_identity_from_profile(load_profile_reconciled(&resolved)) {
        Ok(identity) => identity,
        Err(error) => {
            render_json(&Envelope::<()>::err(&error.to_wallet_error(&profile_name)));
            return 1;
        }
    };

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let handle = match start_operator_enroll_server(
        store_path,
        profile_name,
        bind_addr,
        args.label.clone(),
        page_identity,
    )
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

    let end = enroll_until_done(
        handle,
        &url,
        !args.no_open && display_available(),
        private_open::browser_opener,
        Duration::from_secs(args.timeout_seconds),
        tokio::signal::ctrl_c(),
        || read_line_from_terminal("operator-enroll-code"),
    )
    .await;
    report_enrollment_end(end, &store)
}

/// How the browser phase of the ceremony ended.
#[derive(Debug)]
enum CeremonyEnd {
    /// The server staged a verified registration, or the wait timed out or
    /// its server failed.
    Finished(Result<PendingOperatorEnrollment, OperatorEnrollAwaitError>),
    /// The operator interrupted the wait (Ctrl-C).
    Interrupted,
}

/// How the whole interactive enrollment ended.
#[derive(Debug)]
enum EnrollmentEnd {
    /// The operator typed the page's code before the deadline.
    Confirmed(ConfirmedOperatorEnrollment),
    /// No verified registration arrived before the deadline.
    TimedOut,
    /// The enrollment server failed before a registration arrived.
    Failed(OperatorEnrollAwaitError),
    /// The operator interrupted the browser phase.
    Interrupted,
    /// The typed code was malformed or not the page's.
    Mismatch,
    /// The deadline passed at the prompt.
    Expired,
    /// The prompt ended without a code: end of input, a read failure, or
    /// Ctrl-C.
    Canceled,
}

/// Runs the started enrollment server until the ceremony ends, then asks for
/// the confirmation code.
///
/// When `open_browser` is set, opens the enrollment URL through a private
/// redirect file first; `opener` receives only the file's URL. One deadline,
/// `timeout` after the open returns, bounds both the wait for a verified
/// registration and the prompt. The server stops and the redirect file and
/// its directory are removed as soon as the browser phase ends, an interrupt
/// included; when the open fails, the URL printed at startup is the handoff.
///
/// `interrupt` is watched across both phases. `read_code` reads the typed
/// line, `Ok(None)` at end of input; it runs only once a registration is
/// staged, and its future is dropped at the deadline or an interrupt, so a
/// line it reads after that confirms nothing.
async fn enroll_until_done<Code>(
    mut handle: OperatorEnrollHandle,
    url: &str,
    open_browser: bool,
    opener: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> EnrollmentEnd
where
    Code: Future<Output = io::Result<Option<String>>>,
{
    let browser_handoff = if open_browser {
        private_open::open_or_point_to_handoff(url, opener, "the enrollment URL printed above")
    } else {
        None
    };
    let deadline = Instant::now() + timeout;
    let interrupt = interrupted(interrupt);
    tokio::pin!(interrupt);

    let ceremony = tokio::select! {
        result = handle.await_completion_until(deadline) => CeremonyEnd::Finished(result),
        () = &mut interrupt => CeremonyEnd::Interrupted,
    };

    if let Err(e) = handle.shutdown().await {
        // Non-fatal: the browser phase has already ended; shutdown failing
        // here does not change the outcome, and the server can write nothing.
        tracing::debug!(
            error = %e,
            "approve operator enroll --interactive: shutdown did not complete cleanly"
        );
    }
    if let Some(handoff) = browser_handoff
        && let Err(e) = handoff.close()
    {
        tracing::debug!(
            error.kind = ?e.kind(),
            "approve operator enroll --interactive: redirect file cleanup failed"
        );
    }

    let pending = match ceremony {
        CeremonyEnd::Finished(Ok(pending)) => pending,
        CeremonyEnd::Finished(Err(OperatorEnrollAwaitError::Timeout)) => {
            return EnrollmentEnd::TimedOut;
        }
        CeremonyEnd::Finished(Err(error)) => return EnrollmentEnd::Failed(error),
        CeremonyEnd::Interrupted => return EnrollmentEnd::Interrupted,
    };

    print_confirmation_prompt(pending.label());
    let typed = tokio::select! {
        typed = tokio::time::timeout_at(tokio::time::Instant::from_std(pending.deadline()), read_code()) => typed,
        () = &mut interrupt => return EnrollmentEnd::Canceled,
    };
    let line = match typed {
        Ok(Ok(Some(line))) => line,
        Ok(Ok(None)) => return EnrollmentEnd::Canceled,
        Ok(Err(error)) => {
            tracing::debug!(
                error.kind = ?error.kind(),
                "approve operator enroll --interactive: reading the confirmation code failed"
            );
            return EnrollmentEnd::Canceled;
        }
        Err(_elapsed) => return EnrollmentEnd::Expired,
    };
    match pending.confirm(&line, Instant::now()) {
        Ok(confirmed) => EnrollmentEnd::Confirmed(confirmed),
        // The confirmation refuses only with a mismatch or the deadline; the
        // export refusals belong to the mainnet approval export and refuse
        // like a mismatch if they arise.
        Err(
            OperatorEnrollmentConfirmationError::Mismatch
            | OperatorEnrollmentConfirmationError::WrongPurpose
            | OperatorEnrollmentConfirmationError::CredentialInvalid,
        ) => EnrollmentEnd::Mismatch,
        Err(OperatorEnrollmentConfirmationError::Expired) => EnrollmentEnd::Expired,
    }
}

/// Renders the envelope for how the enrollment ended and returns the exit
/// code: `0` for a persisted credential, `1` otherwise. Only a confirmed
/// enrollment writes the store.
fn report_enrollment_end(end: EnrollmentEnd, store: &OperatorApprovalCredentialStore) -> i32 {
    let (code, message) = match end {
        EnrollmentEnd::Confirmed(confirmed) => return persist_confirmed(confirmed, store),
        EnrollmentEnd::TimedOut => (
            "approve.operator_enroll_interactive_timeout",
            "no enrollment completed within the timeout",
        ),
        EnrollmentEnd::Failed(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_enroll_interactive_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        EnrollmentEnd::Interrupted => (
            "approve.operator_enroll_interactive_interrupted",
            "the ceremony was interrupted before an enrollment completed",
        ),
        EnrollmentEnd::Mismatch => (
            "approve.operator_enroll_confirmation_mismatch",
            "the code typed is not the one the enrollment page shows; nothing was enrolled",
        ),
        EnrollmentEnd::Expired => (
            "approve.operator_enroll_confirmation_expired",
            "the timeout passed before the confirmation code was typed; nothing was enrolled",
        ),
        EnrollmentEnd::Canceled => (
            "approve.operator_enroll_confirmation_canceled",
            "no confirmation code was typed; nothing was enrolled",
        ),
    };
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

/// Persists the confirmed credential and renders the success envelope from
/// the record written.
fn persist_confirmed(
    confirmed: ConfirmedOperatorEnrollment,
    store: &OperatorApprovalCredentialStore,
) -> i32 {
    match confirmed.persist(store) {
        Ok(cred) => {
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
        Err(ApprovalError::WriterLocked) => {
            render_json(&Envelope::<()>::err_raw(
                "approval.writer_locked",
                "another process is writing the operator-credential store; nothing was enrolled",
            ));
            1
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
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.operator_enroll_failed: {e}"),
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

/// Asks for the code the page shows, on stderr.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional prompt; stdout stays JSON-only"
)]
pub(super) fn print_confirmation_prompt(label: &str) {
    eprint!("{}", confirmation_prompt(label));
}

/// The confirmation prompt for a staged credential labelled `label`.
///
/// The label comes from the browser, so it is shown through
/// [`escape_for_terminal`]: a control or format character appears as a
/// visible escape and cannot move the cursor, erase the prompt or reach the
/// terminal's clipboard. The expected code is never part of the prompt.
pub(super) fn confirmation_prompt(label: &str) -> String {
    format!(
        "stellar-agent: a passkey labelled \"{}\" was registered.\n  \
         Type the confirmation code the enrollment page shows, then press Enter: ",
        escape_for_terminal(label)
    )
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

// ─────────────────────────────────────────────────────────────────────────────
// Removal
// ─────────────────────────────────────────────────────────────────────────────

/// JSON success payload for `approve operator remove`. Carries no credential
/// id.
#[derive(Debug, serde::Serialize)]
struct RemoveResult {
    removed: bool,
}

fn run_remove(args: &RemoveArgs) -> i32 {
    let profile_name = match resolve_store_profile(args.profile.as_deref()) {
        Ok(resolved) => resolved.name,
        Err(code) => return code,
    };
    match default_operator_approval_credentials_path(&profile_name) {
        Ok(path) => remove_from(
            &OperatorApprovalCredentialStore::new(path),
            &args.credential_id_b64url,
        ),
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "approve.operator_remove_failed",
                format!("the operator-credential store is unavailable: {e}"),
            ));
            1
        }
    }
}

/// Removes `credential_id_b64url` from `store` and renders the result.
fn remove_from(store: &OperatorApprovalCredentialStore, credential_id_b64url: &str) -> i32 {
    match store.remove(credential_id_b64url) {
        Ok(removed) => {
            render_json(&Envelope::ok(RemoveResult { removed }));
            0
        }
        Err(ApprovalError::WriterLocked) => {
            render_json(&Envelope::<()>::err_raw(
                "approval.writer_locked",
                "another process is writing the operator-credential store; nothing was removed",
            ));
            1
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "approve.operator_remove_failed",
                format!("the operator-credential store could not be updated: {e}"),
            ));
            1
        }
    }
}

impl OperatorArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`] falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            OperatorSubcommand::Enroll(a) => a.profile.as_deref(),
            OperatorSubcommand::Remove(a) => a.profile.as_deref(),
        }
    }
}

fn page_identity_from_profile(
    loaded: Result<
        stellar_agent_core::profile::schema::Profile,
        crate::common::profile_access::ProfileAccessError,
    >,
) -> Result<PageIdentity, crate::common::profile_access::ProfileAccessError> {
    match loaded {
        Ok(profile) => Ok(page_identity_for(&profile)),
        Err(error) if error.requires_refusal() => Err(error),
        Err(_) => Ok(PageIdentity::neutral()),
    }
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

    #[test]
    fn operator_page_identity_preserves_protected_refusals() {
        for error in crate::common::profile_access::protected_load_errors_for_test() {
            let expected = error.code();
            let result = page_identity_from_profile(Err(error));
            let error = result.expect_err("protected refusal was swallowed");
            assert_eq!(error.code(), expected);
        }
    }

    /// A started enrollment server on a temporary store, with its URL and
    /// bootstrap token.
    async fn start_test_enrollment(
        dir: &tempfile::TempDir,
    ) -> (OperatorEnrollHandle, String, String) {
        let handle = start_operator_enroll_server(
            dir.path().join("enroll-test.toml"),
            "enroll-test".to_owned(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            None,
            PageIdentity::neutral(),
        )
        .await
        .unwrap();
        let url = handle.enroll_url();
        let token = handle.bootstrap_token_hex().to_owned();
        (handle, url, token)
    }

    /// The enrollment phase hands the browser only the private redirect
    /// file's URL and keeps the file while the ceremony waits. An interrupt
    /// ends the wait; the server stops, the file and its directory are
    /// removed, and the command exits `1`. A failed open makes one attempt
    /// with the file URL and leaves nothing behind; `--no-open` opens nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn operator_enroll_uses_private_open() {
        use crate::common::private_open::handoff_probe::HandoffProbe;
        // Far beyond the test's bound: only the interrupt can end the wait.
        let ceremony = Duration::from_secs(3600);
        let bound = Duration::from_secs(30);
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("enroll-test.toml"));

        let (handle, url, token) = start_test_enrollment(&dir).await;
        let addr = handle.local_addr();
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            bound,
            enroll_until_done(
                handle,
                &url,
                true,
                probe.opener(Ok(())),
                ceremony,
                probe.interrupt(),
                never_typed,
            ),
        )
        .await
        .expect("the interrupt ends the enrollment wait");
        assert!(matches!(end, EnrollmentEnd::Interrupted), "{end:?}");
        probe.assert_private_handoff(&url, &token);
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped"
        );
        crate::common::render::take_rendered_for_test();
        assert_eq!(report_enrollment_end(end, &store), 1);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0]["ok"], false, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"], "approve.operator_enroll_interactive_interrupted",
            "{rendered:?}"
        );
        assert_eq!(
            rendered[0]["error"]["message"],
            "the ceremony was interrupted before an enrollment completed",
            "{rendered:?}"
        );

        let (handle, url, token) = start_test_enrollment(&dir).await;
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            bound,
            enroll_until_done(
                handle,
                &url,
                true,
                probe.opener(Err(io::Error::other("no browser"))),
                ceremony,
                probe.interrupt(),
                never_typed,
            ),
        )
        .await
        .expect("the interrupt ends the enrollment wait");
        assert!(matches!(end, EnrollmentEnd::Interrupted), "{end:?}");
        probe.assert_failed_open_left_nothing(&token);

        let (handle, url, _token) = start_test_enrollment(&dir).await;
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            bound,
            enroll_until_done(
                handle,
                &url,
                false,
                probe.opener(Ok(())),
                ceremony,
                probe.interrupt(),
                never_typed,
            ),
        )
        .await
        .expect("the interrupt ends the enrollment wait");
        assert!(matches!(end, EnrollmentEnd::Interrupted), "{end:?}");
        assert!(probe.launched().is_empty());
    }

    /// A code reader the test never answers.
    fn never_typed() -> impl Future<Output = io::Result<Option<String>>> {
        std::future::pending()
    }

    /// What the operator does at the prompt in one interactive case.
    enum Typing {
        /// Types the page's code, in upper case with spaces for separators.
        PageCode,
        /// Types a well-formed code that is not the page's.
        OtherCode,
        /// Types something that is not a code.
        Garbage,
        /// Closes stdin.
        EndOfInput,
        /// The terminal read fails.
        ReadError,
        /// Presses Ctrl-C at the prompt, once the ceremony has asked for the
        /// code.
        Interrupt,
        /// Types nothing until the deadline passes.
        Nothing,
    }

    /// Runs one interactive ceremony against a real enrollment server: a
    /// software authenticator registers over the server's challenge through
    /// the page's HTTP calls, then `typing` happens at the prompt. A typed
    /// value waits in a channel until the ceremony reads it; Ctrl-C is sent
    /// only after the ceremony has called the code reader, so it lands at
    /// the prompt and not in the browser phase. Returns the end, the store,
    /// and the registrar.
    async fn interactive_case(
        dir: &tempfile::TempDir,
        typing: Typing,
        timeout: Duration,
    ) -> (
        EnrollmentEnd,
        OperatorApprovalCredentialStore,
        stellar_agent_approval_ui::operator_enroll::test_support::SoftwareRegistrar,
    ) {
        use stellar_agent_approval_ui::operator_enroll::test_support::{
            EnrollmentClient, SoftwareRegistrar,
        };
        let store = OperatorApprovalCredentialStore::new(dir.path().join("enroll-test.toml"));
        let (handle, url, token) = start_test_enrollment(dir).await;
        let addr = handle.local_addr();
        let registrar = SoftwareRegistrar::new([0x21; 32], vec![0x5a; 20]);
        let (typed_tx, typed_rx) = tokio::sync::oneshot::channel::<io::Result<Option<String>>>();
        let (interrupt_tx, interrupt_rx) = tokio::sync::oneshot::channel::<()>();
        let interrupt = async move {
            if interrupt_rx.await.is_ok() {
                Ok(())
            } else {
                std::future::pending().await
            }
        };
        let (prompt_tx, prompt_rx) = tokio::sync::oneshot::channel::<()>();
        // The ceremony calls the reader once it shows the prompt; the call
        // tells the driver the prompt is up. A dropped typing sender means
        // the operator types nothing.
        let read_code = move || {
            let _ = prompt_tx.send(());
            async move {
                match typed_rx.await {
                    Ok(typed) => typed,
                    Err(_) => std::future::pending().await,
                }
            }
        };
        let driver = {
            let store = OperatorApprovalCredentialStore::new(dir.path().join("enroll-test.toml"));
            let registrar = &registrar;
            async move {
                let client = EnrollmentClient::connect(addr, &token).await.unwrap();
                let (reply, code) = client.register(registrar, "laptop").await.unwrap();
                assert_eq!(reply.status, 200, "{reply:?}");
                assert_eq!(reply.json()["status"], "awaiting_confirmation");
                assert!(store.list().unwrap().is_empty(), "staged, not stored");
                let typed = match typing {
                    Typing::PageCode => Some(Ok(Some(code.to_uppercase().replace('-', " ")))),
                    Typing::OtherCode => {
                        let mut other = code.into_bytes();
                        other[0] = if other[0] == b'0' { b'1' } else { b'0' };
                        Some(Ok(Some(String::from_utf8(other).unwrap())))
                    }
                    Typing::Garbage => Some(Ok(Some("yes".to_owned()))),
                    Typing::EndOfInput => Some(Ok(None)),
                    Typing::ReadError => Some(Err(io::Error::other("terminal gone"))),
                    Typing::Interrupt => {
                        prompt_rx.await.expect("the ceremony reaches the prompt");
                        interrupt_tx.send(()).unwrap();
                        None
                    }
                    Typing::Nothing => None,
                };
                if let Some(typed) = typed {
                    let _ = typed_tx.send(typed);
                }
            }
        };
        let ceremony = enroll_until_done(
            handle,
            &url,
            false,
            |_| Ok(()),
            timeout,
            interrupt,
            read_code,
        );
        let (end, ()) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(ceremony, driver)
        })
        .await
        .expect("the ceremony ends");
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped before the prompt"
        );
        (end, store, registrar)
    }

    /// Only the page's code, typed before the deadline, persists the exact
    /// candidate, once. A different or malformed code, end of input, a
    /// read failure, Ctrl-C at the prompt, and the deadline each write
    /// nothing and exit `1` with their own code.
    #[tokio::test(flavor = "current_thread")]
    async fn interactive_enrollment_requires_matching_terminal_code() {
        for (typing, expected) in [
            (
                Typing::OtherCode,
                "approve.operator_enroll_confirmation_mismatch",
            ),
            (
                Typing::Garbage,
                "approve.operator_enroll_confirmation_mismatch",
            ),
            (
                Typing::EndOfInput,
                "approve.operator_enroll_confirmation_canceled",
            ),
            (
                Typing::ReadError,
                "approve.operator_enroll_confirmation_canceled",
            ),
            (
                Typing::Interrupt,
                "approve.operator_enroll_confirmation_canceled",
            ),
            (
                Typing::Nothing,
                "approve.operator_enroll_confirmation_expired",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let timeout = if matches!(typing, Typing::Nothing) {
                Duration::from_secs(3)
            } else {
                Duration::from_secs(30)
            };
            let (end, store, _) = interactive_case(&dir, typing, timeout).await;
            crate::common::render::take_rendered_for_test();
            assert_eq!(report_enrollment_end(end, &store), 1, "{expected}");
            let rendered = crate::common::render::take_rendered_for_test();
            assert_eq!(rendered.len(), 1, "{rendered:?}");
            assert_eq!(rendered[0]["error"]["code"], expected, "{rendered:?}");
            assert!(store.list().unwrap().is_empty(), "{expected}");
        }

        let dir = tempfile::tempdir().unwrap();
        let (end, store, registrar) =
            interactive_case(&dir, Typing::PageCode, Duration::from_secs(30)).await;
        assert!(matches!(end, EnrollmentEnd::Confirmed(_)), "{end:?}");
        crate::common::render::take_rendered_for_test();
        assert_eq!(report_enrollment_end(end, &store), 0);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered[0]["ok"], true, "{rendered:?}");
        assert_eq!(rendered[0]["data"]["status"], "enrolled");
        assert_eq!(rendered[0]["data"]["rp_id"], "localhost");
        assert_eq!(rendered[0]["data"]["label"], "laptop");
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].credential_id_b64url,
            registrar.credential_id_b64url()
        );
        assert_eq!(
            listed[0].public_key_sec1_b64,
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                registrar.public_key_sec1()
            )
        );
        assert_eq!(listed[0].rp_id, "localhost");
        assert_eq!(listed[0].label, "laptop");
        assert_eq!(listed[0].sign_count, Some(0));
        assert!(
            !rendered[0]
                .to_string()
                .contains(&registrar.credential_id_b64url()),
            "the summary carries only a preview of the id"
        );
    }

    /// Without a terminal on stdin and stderr the command refuses before it
    /// resolves a store or starts a server.
    #[tokio::test(flavor = "current_thread")]
    async fn interactive_enrollment_requires_a_terminal() {
        for streams in [(false, true), (true, false), (false, false)] {
            let _tty = crate::common::tty::tests::test_tty(streams.0, streams.1);
            // A one-second timeout keeps a ceremony that wrongly starts short.
            let args = Wrap::try_parse_from([
                "prog",
                "--interactive",
                "--no-open",
                "--timeout-seconds",
                "1",
            ])
            .unwrap()
            .args;
            crate::common::render::take_rendered_for_test();
            let resolved = resolve_profile_name(Some("enroll-tty-test"));
            assert_eq!(run_enroll_interactive(resolved, args).await, 1);
            let rendered = crate::common::render::take_rendered_for_test();
            assert_eq!(rendered.len(), 1, "{rendered:?}");
            assert_eq!(
                rendered[0]["error"]["code"], "approve.operator_enroll_tty_required",
                "{streams:?}"
            );
        }
    }

    #[derive(Debug, Parser)]
    struct WrapRemove {
        #[command(flatten)]
        args: RemoveArgs,
    }

    /// `remove` parses its exact flags, removes only from the named store,
    /// reports `false` for an absent id, and writes nothing while another
    /// writer holds the store's lock.
    #[test]
    fn operator_remove_is_idempotent_and_profile_scoped() {
        let parsed = WrapRemove::try_parse_from([
            "prog",
            "--credential-id",
            "-AbCdEfGhIjKlMnOpQrStU",
            "--profile",
            "laptop",
        ])
        .unwrap();
        assert_eq!(parsed.args.credential_id_b64url, "-AbCdEfGhIjKlMnOpQrStU");
        assert_eq!(parsed.args.profile.as_deref(), Some("laptop"));
        assert!(WrapRemove::try_parse_from(["prog"]).is_err());
        assert!(WrapRemove::try_parse_from(["prog", "--credential-id", "A", "--force"]).is_err());
        let operator = OperatorArgs {
            subcommand: OperatorSubcommand::Remove(parsed.args),
        };
        assert_eq!(operator.profile_flag(), Some("laptop"));

        let dir = tempfile::tempdir().unwrap();
        let credential = |seed: u8| OperatorApprovalCredential {
            credential_id_b64url: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                [seed; 16],
            ),
            public_key_sec1_b64: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                {
                    let mut key = [seed; 65];
                    key[0] = 0x04;
                    key
                },
            ),
            rp_id: "localhost".to_owned(),
            label: "laptop".to_owned(),
            registered_at_unix_ms: 1,
            sign_count: None,
        };
        let first = OperatorApprovalCredentialStore::new(dir.path().join("first.toml"));
        let second = OperatorApprovalCredentialStore::new(dir.path().join("second.toml"));
        first.enroll(credential(1)).unwrap();
        first.enroll(credential(2)).unwrap();
        second.enroll(credential(1)).unwrap();
        let id = credential(1).credential_id_b64url;

        crate::common::render::take_rendered_for_test();
        assert_eq!(remove_from(&first, &id), 0);
        assert_eq!(remove_from(&first, &id), 0);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered[0]["data"], serde_json::json!({"removed": true}));
        assert_eq!(rendered[1]["data"], serde_json::json!({"removed": false}));
        assert!(!rendered[0].to_string().contains(&id));
        assert_eq!(first.list().unwrap(), vec![credential(2)]);
        assert_eq!(
            second.list().unwrap(),
            vec![credential(1)],
            "another profile is untouched"
        );

        let before = std::fs::read(dir.path().join("second.toml")).unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.path().join("second.toml.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        assert_eq!(remove_from(&second, &id), 1);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered[0]["error"]["code"], "approval.writer_locked");
        assert_eq!(
            std::fs::read(dir.path().join("second.toml")).unwrap(),
            before
        );
        drop(lock);
        assert_eq!(remove_from(&second, &id), 0);
        assert!(second.list().unwrap().is_empty());
    }

    /// A credential record for the `run_remove` tests.
    fn remove_test_credential(seed: u8) -> OperatorApprovalCredential {
        let mut key = [seed; 65];
        key[0] = 0x04;
        OperatorApprovalCredential {
            credential_id_b64url: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                [seed; 16],
            ),
            public_key_sec1_b64: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                key,
            ),
            rp_id: "localhost".to_owned(),
            label: "laptop".to_owned(),
            registered_at_unix_ms: 1,
            sign_count: None,
        }
    }

    /// Every file under `root` with its bytes, by path relative to `root`.
    fn tree_snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    found.push((path.strip_prefix(root).unwrap().to_path_buf(), bytes));
                }
            }
        }
        found.sort();
        found
    }

    /// Sets `STELLAR_AGENT_PROFILE`; the caller holds a
    /// `ProfileEnvVarGuard`, which restores the variable, and is `#[serial]`.
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; serialised by #[serial]"
    )]
    fn set_profile_env(name: &str) {
        // SAFETY: serialised by #[serial]; the caller's guard restores the
        // variable when it drops.
        unsafe {
            std::env::set_var("STELLAR_AGENT_PROFILE", name);
        }
    }

    /// A profile name that is not a safe path component refuses with
    /// `validation.config_invalid`, by flag and by `STELLAR_AGENT_PROFILE`,
    /// and nothing anywhere is created, changed or removed: not the store
    /// the name points at outside the credential directory, not its lock
    /// sidecar, not the credential directory itself.
    #[test]
    #[serial_test::serial]
    fn operator_remove_refuses_an_unsafe_profile_name() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let outside = home.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let victim = OperatorApprovalCredentialStore::new(outside.join("victim.toml"));
        victim.enroll(remove_test_credential(1)).unwrap();
        let id = remove_test_credential(1).credential_id_b64url;
        let before = tree_snapshot(home.path());

        let absolute = outside.join("victim").to_str().unwrap().to_owned();
        let names = [
            "../outside/victim".to_owned(),
            absolute,
            "nested/victim".to_owned(),
            "..".to_owned(),
        ];
        for name in &names {
            for by_env in [false, true] {
                let args = if by_env {
                    set_profile_env(name);
                    RemoveArgs {
                        profile: None,
                        credential_id_b64url: id.clone(),
                    }
                } else {
                    RemoveArgs {
                        profile: Some(name.clone()),
                        credential_id_b64url: id.clone(),
                    }
                };
                crate::common::render::take_rendered_for_test();
                assert_eq!(run_remove(&args), 1, "{name} by_env={by_env}");
                let rendered = crate::common::render::take_rendered_for_test();
                assert_eq!(rendered.len(), 1, "{rendered:?}");
                assert_eq!(
                    rendered[0]["error"]["code"], "validation.config_invalid",
                    "{name} by_env={by_env}: {rendered:?}"
                );
            }
        }
        assert_eq!(tree_snapshot(home.path()), before, "nothing was touched");
        assert!(!home.path().join("operator-approval-credentials").exists());
        assert_eq!(victim.list().unwrap(), vec![remove_test_credential(1)]);
    }

    /// `enroll` applies the same profile-name rule as `remove`, by flag and
    /// by `STELLAR_AGENT_PROFILE`, in both modes, and creates nothing.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn operator_enroll_refuses_an_unsafe_profile_name() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let credential = remove_test_credential(3);
        for by_env in [false, true] {
            for interactive in [false, true] {
                let mut argv = vec!["prog".to_owned()];
                if by_env {
                    set_profile_env("../escape");
                } else {
                    argv.extend(["--profile".to_owned(), "../escape".to_owned()]);
                }
                if interactive {
                    argv.extend(["--interactive".to_owned(), "--no-open".to_owned()]);
                } else {
                    argv.extend([
                        "--credential-id".to_owned(),
                        credential.credential_id_b64url.clone(),
                        "--public-key".to_owned(),
                        credential.public_key_sec1_b64.clone(),
                        "--rp-id".to_owned(),
                        "localhost".to_owned(),
                        "--label".to_owned(),
                        "laptop".to_owned(),
                    ]);
                }
                let args = Wrap::try_parse_from(argv).unwrap().args;
                crate::common::render::take_rendered_for_test();
                assert_eq!(run_enroll(args).await, 1);
                let rendered = crate::common::render::take_rendered_for_test();
                assert_eq!(rendered.len(), 1, "{rendered:?}");
                assert_eq!(
                    rendered[0]["error"]["code"], "validation.config_invalid",
                    "by_env={by_env} interactive={interactive}: {rendered:?}"
                );
            }
        }
        assert!(tree_snapshot(home.path()).is_empty(), "nothing was created");
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    /// Argument import refuses a label that holds a control character
    /// through the store's own check and creates no store file.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn operator_import_refuses_a_label_with_a_control_character() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let credential = remove_test_credential(4);
        let args = Wrap::try_parse_from([
            "prog",
            "--profile",
            "import-label",
            "--credential-id",
            &credential.credential_id_b64url,
            "--public-key",
            &credential.public_key_sec1_b64,
            "--rp-id",
            "localhost",
            "--label",
            "lap\u{1b}[2Ktop",
        ])
        .unwrap()
        .args;
        crate::common::render::take_rendered_for_test();
        assert_eq!(run_enroll(args).await, 1);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"], "internal.unexpected_state",
            "{rendered:?}"
        );
        assert!(
            rendered[0]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("approve.operator_credential_invalid"),
            "{rendered:?}"
        );
        assert!(
            !default_operator_approval_credentials_path("import-label")
                .unwrap()
                .exists()
        );
        assert_eq!(
            std::fs::read_dir(home.path()).unwrap().count(),
            0,
            "nothing was created"
        );
    }

    /// `run_remove` edits the store of the profile it resolves: `--profile`
    /// first, then `STELLAR_AGENT_PROFILE`, and the flag wins over the
    /// variable. The stores of the other profiles keep their record.
    #[test]
    #[serial_test::serial]
    fn operator_remove_selects_the_resolved_profile_store() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let store = |name: &str| {
            OperatorApprovalCredentialStore::new(
                default_operator_approval_credentials_path(name).unwrap(),
            )
        };
        assert!(
            store("alpha")
                .path()
                .starts_with(home.path().join("operator-approval-credentials"))
        );
        for name in ["alpha", "beta", "default"] {
            store(name).enroll(remove_test_credential(1)).unwrap();
        }
        let id = remove_test_credential(1).credential_id_b64url;
        let holds = |name: &str| !store(name).list().unwrap().is_empty();

        let remove = |profile: Option<&str>| {
            crate::common::render::take_rendered_for_test();
            let code = run_remove(&RemoveArgs {
                profile: profile.map(str::to_owned),
                credential_id_b64url: id.clone(),
            });
            let rendered = crate::common::render::take_rendered_for_test();
            (code, rendered[0]["data"]["removed"].clone())
        };

        assert_eq!(remove(Some("alpha")), (0, serde_json::json!(true)));
        assert!(!holds("alpha"));
        assert!(holds("beta") && holds("default"));

        set_profile_env("beta");
        assert_eq!(remove(None), (0, serde_json::json!(true)));
        assert!(!holds("beta"));
        assert!(holds("default"));

        assert_eq!(remove(Some("default")), (0, serde_json::json!(true)));
        assert!(!holds("default"));
    }

    /// A browser-supplied label reaches the terminal only escaped: ANSI and
    /// OSC sequences, carriage return, bell and C1 controls appear as
    /// visible escapes, and the prompt holds no control character other than
    /// its own line break.
    #[test]
    fn confirmation_prompt_escapes_a_hostile_label() {
        let hostile = "laptop\u{1b}[2K\u{1b}[1A\rok\u{07}\u{1b}]52;c;ZXZpbA==\u{07}\u{9b}2J";
        let prompt = confirmation_prompt(hostile);
        assert_eq!(
            prompt,
            "stellar-agent: a passkey labelled \
             \"laptop\\u{1b}[2K\\u{1b}[1A\\rok\\u{7}\\u{1b}]52;c;ZXZpbA==\\u{7}\\u{9b}2J\" \
             was registered.\n  Type the confirmation code the enrollment page shows, then \
             press Enter: "
        );
        assert!(
            prompt.chars().all(|c| c == '\n' || !c.is_control()),
            "{prompt:?}"
        );
        assert_eq!(
            confirmation_prompt("laptop"),
            "stellar-agent: a passkey labelled \"laptop\" was registered.\n  Type the \
             confirmation code the enrollment page shows, then press Enter: "
        );
    }

    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: EnrollArgs,
    }

    #[test]
    fn parses_hyphen_prefixed_credential_id() {
        let credential_id = "-AbCdEfGhIjKlMnOpQrStU";
        let parsed = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            credential_id,
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
        ])
        .expect("hyphen-prefixed credential id parses");
        assert_eq!(
            parsed.args.credential_id_b64url.as_deref(),
            Some(credential_id)
        );

        let error = Wrap::try_parse_from([
            "prog",
            "--credential-id",
            "--public-key",
            "BBBBBBBB",
            "--rp-id",
            "wallet.internal",
            "--label",
            "laptop",
        ])
        .expect_err("a consumed public-key flag leaves an unexpected value");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
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
