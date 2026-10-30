//! `stellar-agent credentials add-passkey <name>` — register a WebAuthn passkey.
//!
//! Registration path:
//! 1. Validate the profile name and load the reconciled profile; every load
//!    error refuses.
//! 2. Require a terminal on stdin and stderr, where the operator types the
//!    confirmation code; without one the command refuses
//!    (`credentials.registration_tty_required`).
//! 3. Acquire the profile's keyed audit writer; without it the command
//!    refuses with the `audit.*` codes before any ceremony starts.
//! 4. Open `PendingApprovalStore` exactly once; wrap in `Arc<Mutex<>>`.
//! 5. Construct `CredentialsManager::new` with the shared store Arc.
//! 6. First-registration RP-ID binding prompt (if no prior passkeys).
//! 7. Start the WebAuthn bridge with the same shared store Arc.
//! 8. Insert `PendingApproval { kind: RegisterPasskey }`, which carries a
//!    fresh registration challenge, via `CredentialsManager`.
//! 9. Print the registration URL to stderr and open the browser through a
//!    private redirect file, so the launcher never receives the URL itself.
//!    A failed launch is reported and polling continues.
//! 10. Poll the shared store until the bridge records a response it verified
//!     against the entry's challenge, the deadline expires, or the operator
//!     presses Ctrl-C.
//! 11. Shut down the bridge, then remove the redirect file.
//! 12. Ask at the terminal for the confirmation code the registration page
//!     shows, until the same deadline or Ctrl-C.
//! 13. A matching code writes the `registered` audit row and then the
//!     credential metadata to the passkeys registry; any other end registers
//!     nothing.
//! 14. Print the JSON result envelope; an interrupt during the ceremony ends
//!     with `credentials.registration_user_canceled`, a wrong code with
//!     `credentials.registration_confirmation_mismatch`, and exit code `1`.
//!
//! # Shared store design
//!
//! The `PendingApprovalStore` is opened exactly once per invocation. The same
//! `Arc<tokio::sync::Mutex<PendingApprovalStore>>` is handed to both
//! `start_bridge_register_only` and `CredentialsManager::new`. All store interactions use the
//! tokio mutex — no re-opening, no OS-level file-lock contention.
//!
//! # Output envelope (registered)
//!
//! ```json
//! {"ok":true,"data":{"credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","registered_at_unix_ms":0},"request_id":"..."}
//! ```
//!
//! # Output envelope (timeout)
//!
//! ```json
//! {"ok":false,"error":{"code":"credentials.registration_timeout","message":"..."},"request_id":"..."}
//! ```
//!
//! # First-registration RP-ID binding warning
//!
//! If no credentials exist for the profile, a warning banner is printed
//! explaining the RP-ID binding risk. The operator must confirm `[y/N]`
//! before the ceremony begins. Declining prints a pointer to
//! `docs/remote-approval.md#making-rp_id-resolve` and exits with code 1.

use std::{
    io::{self, BufRead as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Args;
use serde::Serialize;
use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::redact_first5_last5;
use stellar_agent_smart_account::managers::credentials::{
    AddPasskeyOutcome, CredentialsError, CredentialsManager, PendingPasskeyRegistration,
    UnconfirmedEnd,
};
use stellar_agent_webauthn_bridge::{BridgeHandle, start_bridge_register_only};
use tokio::sync::Mutex;

use crate::commands::credentials::credentials_error_code;
use crate::commands::value_audit::{audit_writer_open_failed, require_value_audit_writer};
use crate::common::private_open;
use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::{escape_for_terminal, render_json};
use crate::common::served_pages::page_identity_for;
use crate::common::tty::{read_line_from_terminal, stdin_and_stderr_are_terminals};
use crate::common::{interrupted, resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Successful registration payload, carried under the envelope `data` field.
#[derive(Debug, Serialize)]
struct RegisteredSuccess {
    credential_id: String,
    credential_name: String,
    rp_id: String,
    registered_at_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `credentials add-passkey`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct AddPasskeyArgs {
    /// A human-readable name for this passkey credential.
    ///
    /// Must be 1–64 printable ASCII characters, no `/`, `\`, or `:`.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Profile name override. Defaults to `STELLAR_AGENT_PROFILE` env var,
    /// then `"default"`.
    #[arg(long = "profile", value_name = "PROFILE")]
    pub profile: Option<String>,

    /// RP-ID for the passkey.
    ///
    /// Must be a valid DNS domain string per WebAuthn Level 2 §5.1.2 — IP
    /// literals (e.g. `"127.0.0.1"`) are NOT valid RP-IDs and will be rejected
    /// by Chromium's WebAuthn implementation with a `SecurityError`.
    ///
    /// The default `"localhost"` is the correct loopback value for local wallets
    /// (WebAuthn-2 §6.1 explicitly exempts `localhost` from the HTTPS
    /// requirement).  For self-hosted deployments, set this to the deployment
    /// domain (e.g. `"wallet.example.com"`).
    ///
    /// WARNING: changing the RP-ID after registration renders existing
    /// passkeys unusable. Read `docs/remote-approval.md#making-rp_id-resolve`
    /// before proceeding.
    #[arg(long = "rp-id", value_name = "DOMAIN", default_value = "localhost")]
    pub rp_id: String,

    /// Registration timeout in seconds (default: 300).
    #[arg(long = "timeout-seconds", value_name = "SECS", default_value_t = 300)]
    pub timeout_seconds: u64,

    /// Skip the first-registration RP-ID binding warning prompt.
    ///
    /// DANGER: only set this flag if you understand the RP-ID binding risks
    /// documented in `docs/remote-approval.md#making-rp_id-resolve`.
    #[arg(long = "accept-rp-id-binding-risk")]
    pub accept_rp_id_binding_risk: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `credentials add-passkey`.
///
/// Returns `0` on success, `1` on any error, user cancel, or timeout.
#[expect(
    clippy::await_holding_lock,
    reason = "the audit writer guard spans the ceremony, whose poll and confirmation write \
              through it; no other task in this process locks the profile's writer meanwhile, \
              since the bridge records into the approval store and writes no audit row"
)]
pub async fn run(args: &AddPasskeyArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile = resolved.name.clone();

    // Validate the profile name as a path component before it is used to
    // construct filesystem paths.
    if let Err(reason) = validate_path_component_ascii_safe(&profile) {
        return emit_error(
            "credentials.invalid_profile_name",
            format!("invalid profile name '{profile}': {reason}"),
        );
    }

    // ── Reconcile the profile BEFORE any side effect ─────────────────────────
    // This runs ahead of the approval-store open, the bridge listener, the
    // PendingApproval write, and the browser launch, because a profile file
    // that names another profile must not leave any of them behind: the
    // approval store and the passkey registry are keyed on the REQUESTED name
    // while the audit rows follow the FILE, so a registration under a
    // mismatched profile would split the credential from its own trail.
    //
    // The registration writes its audit row through the profile's keyed
    // writer, so every load failure refuses.
    let loaded_profile = match load_profile_reconciled(&resolved) {
        Ok(loaded) => loaded,
        Err(e) => {
            render_json(&profile_access_envelope(&e, &profile));
            return 1;
        }
    };

    // ── Require a terminal for the confirmation code ─────────────────────────
    // The passkey is registered only once the operator types the code the
    // registration page shows, so without a terminal on stdin and stderr the
    // command refuses before any store, bridge or browser.
    if !stdin_and_stderr_are_terminals() {
        return emit_error(
            "credentials.registration_tty_required",
            "passkey registration needs a terminal on stdin and stderr to type the \
             confirmation code the registration page shows"
                .to_owned(),
        );
    }

    // ── Acquire the keyed audit writer (fail-closed) ─────────────────────────
    // The `registered` row precedes the registry write, so a registration
    // that cannot write its row cannot start.
    let audit_writer = match require_value_audit_writer(&loaded_profile, &profile) {
        Ok(writer) => writer,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    // The guard is held across the whole ceremony, because the poll and the
    // confirmation write their rows through it.
    let Ok(mut audit_guard) = audit_writer.lock() else {
        render_json(&Envelope::<()>::err(&audit_writer_open_failed(&profile)));
        return 1;
    };

    // ── Open the approval store ONCE; wrap in Arc<Mutex<>> ───────────────────
    // This single Arc is shared between the bridge and the manager.
    // The bridge holds an Arc clone; the manager holds an Arc clone.
    // No re-opening of the store occurs anywhere in this flow.
    let approval_store_path = match stellar_agent_core::profile::schema::default_approval_dir() {
        Ok(dir) => dir.join(format!("{profile}.toml")),
        Err(_) => {
            return emit_error(
                "credentials.approval_store_dir_unavailable",
                "could not determine approval store directory for this platform".to_owned(),
            );
        }
    };

    let shared_store = match open_with_retry(
        &approval_store_path,
        DEFAULT_RETRY_ATTEMPTS,
        DEFAULT_RETRY_BACKOFF,
    ) {
        Ok(s) => Arc::new(Mutex::new(s)),
        Err(e) => {
            return emit_error(
                "credentials.approval_store_open_failed",
                format!("approval store open failed: {e}"),
            );
        }
    };

    // ── Construct the manager with the shared store Arc ───────────────────────
    let passkeys_dir = match stellar_agent_core::profile::schema::default_passkeys_dir() {
        Ok(d) => d,
        Err(_) => {
            return emit_error(
                "credentials.state_dir_unavailable",
                "could not determine passkeys directory for this platform".to_owned(),
            );
        }
    };
    let mgr = CredentialsManager::new(
        passkeys_dir,
        &profile,
        &args.rp_id,
        Some(Arc::clone(&shared_store)),
    );

    // ── First-registration RP-ID binding warning ──────────────────────────
    if !args.accept_rp_id_binding_risk {
        match mgr.is_empty() {
            Ok(true) => {
                if !show_rp_id_binding_warning(&args.rp_id) {
                    return emit_rp_id_binding_warning_declined();
                }
            }
            Ok(false) => {}
            Err(e) => return emit_error(credentials_error_code(&e), e.to_string()),
        }
    }

    // ── Start the bridge with the shared store Arc ─────────────────────────
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let bridge = match start_bridge_register_only(
        Arc::clone(&shared_store),
        bind_addr,
        page_identity_for(&loaded_profile),
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            return emit_error(
                "credentials.bridge_start_failed",
                format!("bridge start failed: {e}"),
            );
        }
    };
    let bridge_addr = bridge.local_addr();

    // ── Prepare registration (insert PendingApproval, build URL) ──────────
    // The manager uses the shared store mutex — no re-opening occurs.
    let handle = match mgr
        .prepare_registration(&args.name, bridge_addr, None)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            let _ = bridge.shutdown().await;
            return emit_error(credentials_error_code(&e), e.to_string());
        }
    };

    // ── Print the manual handoff ───────────────────────────────────────────
    // The URL goes to stderr first: it is the manual handoff when the launch
    // fails and when a sandboxed browser cannot read the redirect file.
    print_registration_handoff(&handle.url);

    // ── Open the browser, poll, shut down, then ask for the code ──────────
    // The browser opens through a private redirect file. Polling continues
    // whether or not the launch succeeds, and the launch outcome is not
    // surfaced through `AddPasskeyOutcome`. The registration timeout counts
    // from the end of the launch and also bounds the confirmation prompt.
    let writer: &mut AuditWriter = &mut audit_guard;
    let end = register_until_done(
        bridge,
        &handle.url,
        private_open::browser_opener,
        Duration::from_secs(args.timeout_seconds),
        |deadline| mgr.poll_registration(&args.name, &handle.nonce, deadline, &mut *writer),
        tokio::signal::ctrl_c(),
        || read_line_from_terminal("add-passkey-code"),
    )
    .await;

    finish_registration(end, &mgr, writer, &args.name)
}

/// A browser phase that ends without a staged credential.
enum BrowserCompletion {
    Timeout,
    UserCanceled,
    EntryMissing,
    Unknown,
}

/// How the registration ended.
enum RegistrationEnd {
    /// Polling returned an outcome other than a recorded registration, or an
    /// error.
    Finished(Result<BrowserCompletion, CredentialsError>),
    /// The operator interrupted the wait for the browser (Ctrl-C).
    Interrupted,
    /// The bridge recorded a verified registration and the operator typed
    /// `line` at the prompt.
    Typed {
        /// The recorded registration.
        pending: PendingPasskeyRegistration,
        /// The line typed at the prompt.
        line: String,
    },
    /// The bridge recorded a verified registration and the prompt ended
    /// without a code.
    Unconfirmed {
        /// The recorded registration.
        pending: PendingPasskeyRegistration,
        /// Why the prompt ended.
        end: UnconfirmedEnd,
    },
}

impl std::fmt::Debug for RegistrationEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Finished(_) => "Finished",
            Self::Interrupted => "Interrupted",
            Self::Typed { .. } => "Typed",
            Self::Unconfirmed { .. } => "Unconfirmed",
        })
    }
}

/// Runs the registration ceremony on the started bridge, then asks for the
/// confirmation code.
///
/// Opens the registration URL through a private redirect file first;
/// `opener` receives only the file's URL, never the registration URL with
/// its nonce. The polling deadline is `timeout` after the opener returns, so
/// a slow launcher never shortens the operator's window; `registration`
/// builds the polling loop for that deadline. The file stays while polling
/// runs. Every end of the browser phase, an interrupt included, then shuts
/// the bridge down and removes the file and its directory. When the open
/// fails, the URL printed by [`print_registration_handoff`] is the handoff.
///
/// `interrupt` is watched across both phases. `read_code` reads the typed
/// line, `Ok(None)` at end of input; it runs only once the bridge recorded a
/// registration, under that registration's deadline, and its future is
/// dropped at the deadline or an interrupt, so a line it reads after that
/// confirms nothing.
async fn register_until_done<F, Code>(
    bridge: BridgeHandle,
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    registration: impl FnOnce(Instant) -> F,
    interrupt: impl Future<Output = io::Result<()>>,
    read_code: impl FnOnce() -> Code,
) -> RegistrationEnd
where
    F: Future<Output = Result<AddPasskeyOutcome, CredentialsError>>,
    Code: Future<Output = io::Result<Option<String>>>,
{
    let browser_handoff =
        private_open::open_or_point_to_handoff(url, opener, "the registration URL printed above");
    let polling = registration(Instant::now() + timeout);
    let interrupt = interrupted(interrupt);
    tokio::pin!(interrupt);

    let browser_end = tokio::select! {
        outcome = polling => Some(outcome),
        () = &mut interrupt => None,
    };

    if let Err(e) = bridge.shutdown().await {
        // Non-fatal: the ceremony has already completed, timed out or been
        // interrupted.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("stellar-agent: bridge shutdown warning: {e}");
        }
    }
    if let Some(handoff) = browser_handoff
        && let Err(e) = handoff.close()
    {
        tracing::debug!(
            error.kind = ?e.kind(),
            "credentials add-passkey: redirect file cleanup failed"
        );
    }

    let pending = match browser_end {
        Some(Ok(AddPasskeyOutcome::AwaitingConfirmation { pending })) => pending,
        Some(Ok(AddPasskeyOutcome::Timeout)) => {
            return RegistrationEnd::Finished(Ok(BrowserCompletion::Timeout));
        }
        Some(Ok(AddPasskeyOutcome::UserCanceled)) => {
            return RegistrationEnd::Finished(Ok(BrowserCompletion::UserCanceled));
        }
        Some(Ok(AddPasskeyOutcome::EntryMissing)) => {
            return RegistrationEnd::Finished(Ok(BrowserCompletion::EntryMissing));
        }
        Some(Ok(_)) => return RegistrationEnd::Finished(Ok(BrowserCompletion::Unknown)),
        Some(Err(error)) => return RegistrationEnd::Finished(Err(error)),
        None => return RegistrationEnd::Interrupted,
    };

    print_confirmation_prompt(pending.credential_name());
    let deadline = tokio::time::Instant::from_std(pending.deadline());
    let typed = tokio::select! {
        typed = tokio::time::timeout_at(deadline, read_code()) => typed,
        () = &mut interrupt => {
            return RegistrationEnd::Unconfirmed {
                pending,
                end: UnconfirmedEnd::Canceled,
            };
        }
    };
    let end = match typed {
        Ok(Ok(Some(line))) => return RegistrationEnd::Typed { pending, line },
        Ok(Ok(None)) => UnconfirmedEnd::Canceled,
        Ok(Err(error)) => {
            tracing::debug!(
                error.kind = ?error.kind(),
                "credentials add-passkey: reading the confirmation code failed"
            );
            UnconfirmedEnd::Canceled
        }
        Err(_elapsed) => UnconfirmedEnd::Expired,
    };
    RegistrationEnd::Unconfirmed { pending, end }
}

/// Asks for the code the registration page shows, on stderr.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional prompt; stdout stays JSON-only"
)]
fn print_confirmation_prompt(name: &str) {
    eprint!("{}", confirmation_prompt(name));
}

/// The confirmation prompt for the passkey named `name`. The expected code is
/// never part of the prompt.
fn confirmation_prompt(name: &str) -> String {
    format!(
        "stellar-agent: the passkey '{}' was created in the browser.\n  \
         Type the confirmation code the registration page shows, then press Enter: ",
        escape_for_terminal(name)
    )
}

/// Completes the registration for how the ceremony ended, renders the result
/// envelope and returns the exit code: `0` for a registered credential, `1`
/// otherwise.
///
/// A typed line goes to [`CredentialsManager::confirm_registration`], which
/// writes the `registered` row to `audit_writer` and then the registry; a
/// prompt that ended without a code goes to
/// [`CredentialsManager::abandon_registration`]. Nothing else registers.
fn finish_registration(
    end: RegistrationEnd,
    mgr: &CredentialsManager,
    audit_writer: &mut AuditWriter,
    name: &str,
) -> i32 {
    let outcome = match end {
        RegistrationEnd::Typed { pending, line } => {
            return match mgr.confirm_registration(pending, &line, Instant::now(), audit_writer) {
                Ok(metadata) => {
                    render_json(&Envelope::ok(RegisteredSuccess {
                        credential_id: redact_first5_last5(&metadata.credential_id_b64url),
                        credential_name: metadata.credential_name,
                        rp_id: metadata.rp_id,
                        registered_at_unix_ms: metadata.registered_at_unix_ms,
                    }));
                    0
                }
                Err(e) => emit_error(credentials_error_code(&e), e.to_string()),
            };
        }
        RegistrationEnd::Unconfirmed { pending, end } => {
            mgr.abandon_registration(pending, end, audit_writer);
            return emit_unconfirmed(end);
        }
        RegistrationEnd::Finished(outcome) => outcome,
        RegistrationEnd::Interrupted => {
            return emit_error(
                "credentials.registration_user_canceled",
                format!("registration of '{name}' was interrupted before the ceremony completed"),
            );
        }
    };
    match outcome {
        Ok(BrowserCompletion::Timeout) => emit_error(
            "credentials.registration_timeout",
            format!("registration of '{name}' timed out before the ceremony completed"),
        ),
        Ok(BrowserCompletion::UserCanceled) => emit_error(
            "credentials.registration_user_canceled",
            format!("registration of '{name}' was canceled by the user"),
        ),
        Ok(BrowserCompletion::EntryMissing) => emit_error(
            "credentials.registration_entry_missing",
            format!(
                "registration of '{name}' failed: the approval-store entry was not found (TTL-expired or never persisted)"
            ),
        ),
        Err(e) => emit_error(credentials_error_code(&e), e.to_string()),
        Ok(BrowserCompletion::Unknown) => emit_error(
            "credentials.unknown_registration_outcome",
            "unknown registration outcome".to_owned(),
        ),
    }
}

/// Renders the refusal for a registration whose prompt ended without a code.
fn emit_unconfirmed(end: UnconfirmedEnd) -> i32 {
    match end {
        UnconfirmedEnd::Expired => emit_error(
            "credentials.registration_confirmation_expired",
            "the timeout passed before the confirmation code was typed; nothing was registered"
                .to_owned(),
        ),
        // `Canceled`, and any other end without a typed code.
        _ => emit_error(
            "credentials.registration_confirmation_canceled",
            "no confirmation code was typed; nothing was registered".to_owned(),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// First-registration RP-ID binding warning
// ─────────────────────────────────────────────────────────────────────────────

/// Shows the first-registration RP-ID binding warning and returns
/// `true` if the operator confirmed.
///
/// This prompt is shown when `credentials list` is empty (no prior passkeys)
/// and `--accept-rp-id-binding-risk` is NOT set.
fn show_rp_id_binding_warning(rp_id: &str) -> bool {
    #[allow(clippy::print_stdout, reason = "CLI binary intentional warning output")]
    {
        println!();
        println!("WARNING: Passkey RP-ID binding.");
        println!();
        println!("  This passkey will be bound to RP-ID: {rp_id}");
        println!();
        println!("  The RP-ID is the domain or IP that the authenticator cryptographically binds");
        println!("  to this credential. If you ever lose control of this RP-ID, this passkey");
        println!("  becomes permanently unusable with this wallet.");
        println!();
        println!("  Recommendation: ensure you have a Delegated-fallback signer configured");
        println!(
            "  so you can still sign transactions if this passkey is ever lost or inaccessible."
        );
        println!("  See: docs/remote-approval.md#making-rp_id-resolve for recovery options.");
        println!();
        println!("  Do you have a Delegated-fallback signer, or understand the RP-ID binding");
        print!("  risk and wish to proceed? [y/N]: ");
    }
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            let trimmed = line.trim().to_ascii_lowercase();
            trimmed == "y" || trimmed == "yes"
        }
    }
}

/// Emits the refusal result (operator declined the RP-ID binding warning) and
/// returns exit code `1`.
fn emit_rp_id_binding_warning_declined() -> i32 {
    emit_error(
        "credentials.rp_id_binding_warning_declined",
        "operator declined the RP-ID binding warning; set up a Delegated-fallback signer first \
         (stellar-agent accounts add-signer-delegated) — see \
         docs/remote-approval.md#making-rp_id-resolve"
            .to_owned(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Prints the registration URL to stderr, keeping stdout reserved for the
/// JSON envelope.
#[allow(
    clippy::print_stderr,
    reason = "CLI binary intentional user output: manual registration handoff"
)]
fn print_registration_handoff(url: &str) {
    eprintln!(
        "stellar-agent: if the browser does not show the registration page, open this URL:\n  {url}"
    );
}

fn emit_error(code: &'static str, message: String) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use stellar_agent_approval_ui::operator_enroll::test_support::SoftwareRegistrar;
    use stellar_agent_core::approval::ApprovalKind;
    use stellar_agent_core::approval::webauthn_registration::{
        ConfirmationCode, PASSKEY_REGISTRATION_CODE_DOMAIN,
    };
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_core::audit_log::test_helpers::verified_audit_entries_from_path;
    use stellar_agent_loopback_http::brand::PageIdentity;
    use stellar_agent_smart_account::managers::credentials::CredentialMetadata;

    use super::*;

    type SharedStore = Arc<Mutex<stellar_agent_core::approval::store::PendingApprovalStore>>;

    /// A started register-only bridge on a temporary approval store, a
    /// manager sharing that store with its passkeys registry in `dir`, and
    /// the store.
    async fn start_test_registration(
        dir: &tempfile::TempDir,
        tag: &str,
    ) -> (BridgeHandle, CredentialsManager, SharedStore) {
        let store = stellar_agent_core::approval::store::PendingApprovalStore::open(
            dir.path().join(format!("{tag}.toml")),
        )
        .unwrap();
        let store = Arc::new(Mutex::new(store));
        let bridge = start_bridge_register_only(
            Arc::clone(&store),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            PageIdentity::neutral(),
        )
        .await
        .unwrap();
        let mgr = CredentialsManager::new(
            dir.path().join(format!("{tag}-passkeys")),
            tag,
            "localhost",
            Some(Arc::clone(&store)),
        );
        (bridge, mgr, store)
    }

    /// The software authenticator the browser side of the tests uses.
    fn registrar() -> SoftwareRegistrar {
        SoftwareRegistrar::new([0x11; 32], vec![0xa5; 16])
    }

    /// An unkeyed audit writer over `dir/<tag>-audit.jsonl`, and its path.
    fn test_writer(dir: &tempfile::TempDir, tag: &str) -> (AuditWriter, std::path::PathBuf) {
        let path = dir.path().join(format!("{tag}-audit.jsonl"));
        (AuditWriter::open(path.clone(), None).unwrap(), path)
    }

    /// Completes the browser side of the registration for `nonce`: POSTs a
    /// [`registrar`] response over the entry's challenge to the bridge with
    /// the entry's CSRF value, as the registration page does, and returns
    /// the confirmation code the page then shows.
    async fn complete_registration_in_browser(
        bridge_addr: SocketAddr,
        store: &SharedStore,
        nonce: &str,
    ) -> String {
        let (csrf, challenge) = {
            let guard = store.lock().await;
            match &guard.get(nonce).expect("the pending registration").kind {
                ApprovalKind::RegisterPasskey {
                    csrf_token,
                    registration_challenge: Some(challenge),
                    ..
                } => (hex::encode(csrf_token), *challenge),
                _ => panic!("the pending entry is a registration with a challenge"),
            }
        };
        let registrar = registrar();
        let response = registrar.builder(
            &challenge,
            &format!("http://localhost:{}", bridge_addr.port()),
        );
        let credential_id = registrar.credential_id_b64url();
        let public_key = registrar.public_key_sec1();
        let payload = serde_json::json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(response.client_data_json()),
                "attestationObject": URL_SAFE_NO_PAD.encode(response.attestation_object()),
                "publicKeySec1B64": STANDARD.encode(public_key),
                "transports": ["internal"]
            }
        });
        let reply = reqwest::Client::new()
            .post(format!("http://{bridge_addr}/register/{nonce}/credential"))
            .header("Origin", format!("http://{bridge_addr}"))
            .header("X-Stellar-Approval-CSRF", csrf)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status().as_u16(), 200);
        ConfirmationCode::compute(
            PASSKEY_REGISTRATION_CODE_DOMAIN,
            &challenge,
            registrar.credential_id(),
            &public_key,
        )
        .display()
    }

    /// The registration timeout counts from the end of the browser launch: a
    /// launcher slower than the whole timeout does not turn a registration
    /// the browser already completed into a timeout.
    #[tokio::test(flavor = "current_thread")]
    async fn registration_deadline_starts_after_the_launch() {
        use crate::common::private_open::handoff_probe::HandoffProbe;
        let dir = tempfile::tempdir().unwrap();
        let (bridge, mgr, store) = start_test_registration(&dir, "slow-launch").await;
        let bridge_addr = bridge.local_addr();
        let handle = mgr
            .prepare_registration("laptop", bridge_addr, None)
            .await
            .unwrap();
        let code = complete_registration_in_browser(bridge_addr, &store, &handle.nonce).await;
        let (mut writer, _path) = test_writer(&dir, "slow-launch");

        let timeout = Duration::from_millis(100);
        let probe = HandoffProbe::default();
        let launch = probe.opener(Ok(()));
        let slow_launch = move |url: &str| {
            std::thread::sleep(timeout * 4);
            launch(url)
        };
        let end = tokio::time::timeout(
            Duration::from_secs(30),
            register_until_done(
                bridge,
                &handle.url,
                slow_launch,
                timeout,
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, &mut writer),
                std::future::pending(),
                move || async move { Ok(Some(code)) },
            ),
        )
        .await
        .expect("polling returns");
        assert!(matches!(end, RegistrationEnd::Typed { .. }), "{end:?}");
        assert_eq!(probe.launched().len(), 1);
    }

    /// The registration phase hands the browser only the private redirect
    /// file's URL and keeps the file while polling runs. An interrupt ends
    /// polling; the bridge stops, the file and its directory are removed,
    /// and the command exits `1`. A failed open makes one attempt with the
    /// file URL, leaves nothing behind, and polling still runs.
    #[tokio::test(flavor = "current_thread")]
    async fn add_passkey_uses_private_open() {
        use crate::common::private_open::handoff_probe::HandoffProbe;
        // Far beyond the test's bound: only the interrupt can end polling.
        let patience = Duration::from_secs(3600);
        let bound = Duration::from_secs(30);
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, _path) = test_writer(&dir, "opened");

        let (bridge, mgr, _store) = start_test_registration(&dir, "opened").await;
        let bridge_addr = bridge.local_addr();
        let handle = mgr
            .prepare_registration("laptop", bridge_addr, None)
            .await
            .unwrap();
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            bound,
            register_until_done(
                bridge,
                &handle.url,
                probe.opener(Ok(())),
                patience,
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, &mut writer),
                probe.interrupt(),
                std::future::pending,
            ),
        )
        .await
        .expect("the interrupt ends the registration wait");
        assert!(matches!(end, RegistrationEnd::Interrupted), "{end:?}");
        probe.assert_private_handoff(&handle.url, &handle.nonce);
        assert!(
            std::net::TcpStream::connect(bridge_addr).is_err(),
            "the bridge stopped"
        );
        crate::common::render::take_rendered_for_test();
        assert_eq!(finish_registration(end, &mgr, &mut writer, "laptop"), 1);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0]["ok"], false, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"], "credentials.registration_user_canceled",
            "{rendered:?}"
        );
        assert_eq!(
            rendered[0]["error"]["message"],
            "registration of 'laptop' was interrupted before the ceremony completed",
            "{rendered:?}"
        );

        let (bridge, mgr, _store) = start_test_registration(&dir, "failed").await;
        let handle = mgr
            .prepare_registration("laptop", bridge.local_addr(), None)
            .await
            .unwrap();
        let probe = HandoffProbe::default();
        let end = tokio::time::timeout(
            bound,
            register_until_done(
                bridge,
                &handle.url,
                probe.opener(Err(io::Error::other("no browser"))),
                patience,
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, &mut writer),
                probe.interrupt(),
                std::future::pending,
            ),
        )
        .await
        .expect("the interrupt ends the registration wait");
        assert!(matches!(end, RegistrationEnd::Interrupted), "{end:?}");
        assert!(probe.waited());
        probe.assert_failed_open_left_nothing(&handle.nonce);
    }

    /// What the operator does at the confirmation prompt.
    #[derive(Debug, Clone, Copy)]
    enum Typing {
        /// Types the code the registration page shows.
        PageCode,
        /// Types a code that differs in its last digit.
        OtherCode,
        /// Presses Ctrl-C once the prompt is up.
        InterruptAtPrompt,
        /// Types nothing.
        Nothing,
    }

    /// How a registration whose browser side completed ended at the prompt.
    struct PromptCase {
        exit: i32,
        envelope: serde_json::Value,
        registered: Vec<CredentialMetadata>,
        statuses: Vec<String>,
    }

    /// Runs a registration whose browser side completes, with `typing` at
    /// the prompt under `timeout`, and finishes it.
    async fn prompt_case(tag: &str, typing: Typing, timeout: Duration) -> PromptCase {
        let dir = tempfile::tempdir().unwrap();
        let (bridge, mgr, store) = start_test_registration(&dir, tag).await;
        let bridge_addr = bridge.local_addr();
        let handle = mgr
            .prepare_registration("laptop", bridge_addr, None)
            .await
            .unwrap();
        let code = complete_registration_in_browser(bridge_addr, &store, &handle.nonce).await;
        let (mut writer, audit_path) = test_writer(&dir, tag);

        let line = match typing {
            Typing::PageCode => Some(code),
            Typing::OtherCode => {
                let mut other = code;
                let last = if other.ends_with('0') { "1" } else { "0" };
                other.replace_range(other.len() - 1.., last);
                Some(other)
            }
            Typing::InterruptAtPrompt | Typing::Nothing => None,
        };
        let (interrupt_tx, interrupt_rx) = tokio::sync::oneshot::channel::<()>();
        // A dropped sender is no interrupt: the watch never resolves.
        let interrupt = async move {
            interrupt_rx
                .await
                .map_err(|_| io::Error::other("no interrupt"))
        };
        // The ceremony calls the reader once the prompt is up.
        let read_code = move || {
            if matches!(typing, Typing::InterruptAtPrompt) {
                interrupt_tx.send(()).unwrap();
            }
            async move {
                match line {
                    Some(line) => Ok(Some(line)),
                    None => std::future::pending().await,
                }
            }
        };
        let end = tokio::time::timeout(
            Duration::from_secs(60),
            register_until_done(
                bridge,
                &handle.url,
                |_| Ok(()),
                timeout,
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, &mut writer),
                interrupt,
                read_code,
            ),
        )
        .await
        .expect("the registration ends");
        assert!(
            std::net::TcpStream::connect(bridge_addr).is_err(),
            "the bridge stopped before the prompt"
        );

        crate::common::render::take_rendered_for_test();
        let exit = finish_registration(end, &mgr, &mut writer, "laptop");
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        drop(writer);
        let statuses = verified_audit_entries_from_path(&audit_path)
            .into_iter()
            .filter_map(|entry| match entry.event_kind {
                EventKind::PasskeyRegistered { status, .. } => Some(status),
                _ => None,
            })
            .collect();
        PromptCase {
            exit,
            envelope: rendered.into_iter().next().unwrap(),
            registered: mgr.list().unwrap(),
            statuses,
        }
    }

    /// The code the page shows registers the passkey: the envelope carries
    /// the redacted ID, the registry holds the key, and the log holds one
    /// `registered` row.
    #[tokio::test(flavor = "current_thread")]
    async fn a_matching_code_registers_the_passkey() {
        let case = prompt_case("matching", Typing::PageCode, Duration::from_secs(30)).await;
        assert_eq!(case.exit, 0, "{}", case.envelope);
        assert_eq!(case.envelope["ok"], true, "{}", case.envelope);
        let registrar = registrar();
        assert_eq!(
            case.envelope["data"]["credential_id"],
            redact_first5_last5(&registrar.credential_id_b64url())
        );
        let [registered] = case.registered.as_slice() else {
            panic!("expected one registered passkey: {:?}", case.registered)
        };
        assert_eq!(registered.credential_name, "laptop");
        assert_eq!(
            registered.credential_id_b64url,
            registrar.credential_id_b64url()
        );
        assert_eq!(
            registered.public_key_sec1_b64,
            URL_SAFE_NO_PAD.encode(registrar.public_key_sec1())
        );
        assert_eq!(case.statuses, ["registered"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_wrong_code_registers_nothing() {
        let case = prompt_case("wrong", Typing::OtherCode, Duration::from_secs(30)).await;
        assert_eq!(case.exit, 1, "{}", case.envelope);
        assert_eq!(
            case.envelope["error"]["code"], "credentials.registration_confirmation_mismatch",
            "{}",
            case.envelope
        );
        assert!(case.registered.is_empty(), "{:?}", case.registered);
        assert_eq!(case.statuses, ["confirmation_mismatch"]);
    }

    /// An interrupt once the prompt is up ends the registration with nothing
    /// registered.
    #[tokio::test(flavor = "current_thread")]
    async fn an_interrupt_at_the_prompt_registers_nothing() {
        let case = prompt_case(
            "interrupt",
            Typing::InterruptAtPrompt,
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(case.exit, 1, "{}", case.envelope);
        assert_eq!(
            case.envelope["error"]["code"], "credentials.registration_confirmation_canceled",
            "{}",
            case.envelope
        );
        assert_eq!(
            case.envelope["error"]["message"],
            "no confirmation code was typed; nothing was registered"
        );
        assert!(case.registered.is_empty(), "{:?}", case.registered);
        assert_eq!(case.statuses, ["confirmation_canceled"]);
    }

    /// A prompt nobody answers ends at the registration deadline.
    #[tokio::test(flavor = "current_thread")]
    async fn the_prompt_ends_at_the_deadline() {
        let case = prompt_case("deadline", Typing::Nothing, Duration::from_secs(2)).await;
        assert_eq!(case.exit, 1, "{}", case.envelope);
        assert_eq!(
            case.envelope["error"]["code"], "credentials.registration_confirmation_expired",
            "{}",
            case.envelope
        );
        assert_eq!(
            case.envelope["error"]["message"],
            "the timeout passed before the confirmation code was typed; nothing was registered"
        );
        assert!(case.registered.is_empty(), "{:?}", case.registered);
        assert_eq!(case.statuses, ["confirmation_expired"]);
    }

    async fn audit_prerequisite_case(name: &str, mismatch: bool, expected: &str) {
        use stellar_agent_core::audit_log::AuditBinding;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _tty = crate::common::tty::tests::test_tty(true, true);
        let (bridge, _, _) = start_test_registration(&home, "audit-prerequisite").await;
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            name,
            &format!("stellar-agent-signer-{name}"),
            "default",
            &format!("stellar-agent-nonce-{name}"),
            "default",
        )
        .build();
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        if mismatch {
            stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
                .store(&AuditBinding::for_profile(&profile))
                .unwrap();
            profile.audit_log_path = home.path().join("other-audit.jsonl");
        }
        stellar_agent_core::profile::loader::save_to_dir(
            name,
            &profile,
            &home.path().join("profiles"),
        )
        .unwrap();
        let args = AddPasskeyArgs {
            name: "laptop".to_owned(),
            profile: Some(name.to_owned()),
            rp_id: "localhost".to_owned(),
            timeout_seconds: 1,
            accept_rp_id_binding_risk: true,
        };
        crate::common::render::take_rendered_for_test();
        assert_eq!(run(&args).await, 1);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0]["error"]["code"], expected);
        assert!(
            !home
                .path()
                .join("approvals")
                .join(format!("{name}.toml"))
                .exists(),
            "no approval store is opened"
        );
        assert!(
            !home
                .path()
                .join("approvals")
                .join(format!("{name}.toml.lock"))
                .exists(),
            "no approval store lock file is created"
        );
        assert!(
            !home.path().join("passkeys").exists(),
            "nothing is registered"
        );
        bridge.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn add_passkey_requires_the_audit_chain_key() {
        audit_prerequisite_case("passkey-audit-key", false, "audit.chain_key_unavailable").await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn add_passkey_requires_the_audit_binding() {
        audit_prerequisite_case("passkey-audit-binding", true, "audit.log_binding_changed").await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_registration_debug_omits_the_line() {
        let dir = tempfile::tempdir().unwrap();
        let store = stellar_agent_core::approval::store::PendingApprovalStore::open(
            dir.path().join("approval.toml"),
        )
        .unwrap();
        let store = Arc::new(Mutex::new(store));
        let mgr = CredentialsManager::new(
            dir.path().join("passkeys"),
            "debug",
            "localhost",
            Some(Arc::clone(&store)),
        );
        let handle = mgr
            .prepare_registration("laptop", "127.0.0.1:9999".parse().unwrap(), None)
            .await
            .unwrap();
        let input = stellar_agent_core::approval::RegistrationInput::new(
            vec![0xa5; 16],
            registrar().public_key_sec1().to_vec(),
            None,
            vec![],
        )
        .unwrap();
        store
            .lock()
            .await
            .record_passkey_registration(&handle.nonce, input)
            .unwrap();
        let (mut writer, _) = test_writer(&dir, "debug");
        let AddPasskeyOutcome::AwaitingConfirmation { pending } = mgr
            .poll_registration(
                "laptop",
                &handle.nonce,
                Instant::now() + Duration::from_secs(5),
                &mut writer,
            )
            .await
            .unwrap()
        else {
            panic!("the credential awaits confirmation")
        };
        let line = "0123-4567-89ab-cdef";
        let end = RegistrationEnd::Typed {
            pending,
            line: line.to_owned(),
        };
        let debug = format!("{end:?}");
        assert_eq!(debug, "Typed");
        assert!(!debug.contains(line));
    }

    /// Without a terminal on stdin and stderr the command refuses after the
    /// profile load and before it opens a store, starts a bridge or opens a
    /// browser.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn add_passkey_requires_a_terminal() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let name = "passkey-tty";
        let mut profile = stellar_agent_core::profile::schema::Profile::builder_testnet_named(
            name,
            "stellar-agent-signer-passkey-tty",
            "default",
            "stellar-agent-nonce-passkey-tty",
            "default",
        )
        .build();
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        stellar_agent_core::profile::loader::save_to_dir(
            name,
            &profile,
            &home.path().join("profiles"),
        )
        .unwrap();

        for streams in [(false, true), (true, false), (false, false)] {
            let _tty = crate::common::tty::tests::test_tty(streams.0, streams.1);
            let args = AddPasskeyArgs {
                name: "laptop".to_owned(),
                profile: Some(name.to_owned()),
                rp_id: "localhost".to_owned(),
                timeout_seconds: 1,
                accept_rp_id_binding_risk: true,
            };
            crate::common::render::take_rendered_for_test();
            assert_eq!(run(&args).await, 1, "{streams:?}");
            let rendered = crate::common::render::take_rendered_for_test();
            assert_eq!(rendered.len(), 1, "{rendered:?}");
            assert_eq!(
                rendered[0]["error"]["code"], "credentials.registration_tty_required",
                "{streams:?}"
            );
            assert_eq!(
                rendered[0]["error"]["message"],
                "passkey registration needs a terminal on stdin and stderr to type the \
                 confirmation code the registration page shows"
            );
            assert!(
                !home
                    .path()
                    .join("approvals")
                    .join(format!("{name}.toml"))
                    .exists(),
                "no approval store is opened"
            );
            assert!(
                !home.path().join("passkeys").exists(),
                "no passkeys registry is touched"
            );
        }
    }
}
