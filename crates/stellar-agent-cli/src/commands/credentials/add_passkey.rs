//! `stellar-agent credentials add-passkey <name>` — register a WebAuthn passkey.
//!
//! Registration path:
//! 1. First-registration RP-ID binding prompt (if no prior passkeys).
//! 2. Open `PendingApprovalStore` exactly once; wrap in `Arc<Mutex<>>`.
//! 3. Construct `CredentialsManager::new` with the shared store Arc.
//! 4. Start the WebAuthn bridge with the same shared store Arc.
//! 5. Insert `PendingApproval { kind: RegisterPasskey }` via `CredentialsManager`.
//! 6. Print the registration URL to stderr and open the browser through a
//!    private redirect file, so the launcher never receives the URL itself.
//!    A failed launch is reported and polling continues.
//! 7. Poll the shared store until the ceremony completes, the deadline
//!    expires, or the operator presses Ctrl-C.
//! 8. Shut down the bridge, then remove the redirect file.
//! 9. Write the credential metadata to the passkeys registry.
//! 10. Print the JSON result envelope; an interrupt ends with
//!     `credentials.registration_user_canceled` and exit code `1`.
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
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use clap::Args;
use serde::Serialize;
use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_core::redact_first5_last5;
use stellar_agent_smart_account::managers::credentials::{
    AddPasskeyOutcome, CredentialsError, CredentialsManager,
};
use stellar_agent_webauthn_bridge::{BridgeHandle, start_bridge_register_only};
use tokio::sync::Mutex;
use tracing::warn;

use crate::commands::credentials::credentials_error_code;
use crate::common::private_open;
use crate::common::profile_access::{
    ProfileAccessError, load_profile_reconciled, profile_access_envelope,
};
use crate::common::render::render_json;
use crate::common::served_pages::page_identity_for;
use crate::common::{interrupted, resolve_profile_name, validate_path_component_ascii_safe};
use stellar_agent_loopback_http::brand::PageIdentity;

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
    // Protected refusals are not tolerated. Other load failures yield the
    // neutral identity for registration with an unconfigured profile, and
    // the audit-writer open below also tolerates those failures.
    let loaded_profile = match optional_registration_profile(load_profile_reconciled(&resolved)) {
        Ok(loaded) => loaded,
        Err(e) => {
            render_json(&profile_access_envelope(&e, &profile));
            return 1;
        }
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
        loaded_profile
            .as_ref()
            .map_or_else(PageIdentity::neutral, page_identity_for),
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

    // ── Open audit writer (non-fatal: warn on failure, continue) ──────────
    // Wire a real AuditWriter so PasskeyRegistered events are emitted. If the
    // profile is not yet configured with an HMAC key, the writer cannot be
    // opened — this is expected for early-lifecycle wallets. Continue with
    // None; the audit entry is silently skipped under the non-fatal audit
    // posture.
    //
    // Use AuditWriterRegistry::get_or_open instead of AuditWriter::open
    // directly so the single-writer invariant is enforced.
    let audit_writer_arc: Option<Arc<StdMutex<AuditWriter>>> =
        open_profile_audit_writer_non_fatal(&resolved).await;

    // Lock the Arc<StdMutex<AuditWriter>> for the duration of poll_registration
    // so we can pass `Option<&mut AuditWriter>` to the manager.
    let mut guard = audit_writer_arc.as_ref().map(|arc| arc.lock());
    let audit_writer_ref: Option<&mut AuditWriter> = match guard.as_mut() {
        Some(Ok(g)) => Some(&mut **g),
        Some(Err(_poison)) => {
            warn!(
                profile = %profile,
                "credentials add-passkey: audit writer mutex poisoned before poll; audit entry will be skipped"
            );
            None
        }
        None => None,
    };

    // ── Open the browser, poll for completion, shut down ──────────────────
    // The browser opens through a private redirect file. Polling continues
    // whether or not the launch succeeds, and the launch outcome is not
    // surfaced through `AddPasskeyOutcome`. The registration timeout counts
    // from the end of the launch.
    let end = register_until_done(
        bridge,
        &handle.url,
        private_open::browser_opener,
        Duration::from_secs(args.timeout_seconds),
        |deadline| mgr.poll_registration(&args.name, &handle.nonce, deadline, audit_writer_ref),
        tokio::signal::ctrl_c(),
    )
    .await;

    report_registration_end(end, &args.name)
}

/// How the registration phase ended.
#[derive(Debug)]
enum RegistrationEnd {
    /// Polling returned an outcome or an error.
    Finished(Result<AddPasskeyOutcome, CredentialsError>),
    /// The operator interrupted the wait (Ctrl-C).
    Interrupted,
}

/// Runs the registration ceremony on the started bridge until the polling
/// loop returns or `interrupt` resolves.
///
/// Opens the registration URL through a private redirect file first;
/// `opener` receives only the file's URL, never the registration URL with
/// its nonce. The polling deadline is `timeout` after the opener returns, so
/// a slow launcher never shortens the operator's window; `registration`
/// builds the polling loop for that deadline. The file stays while polling
/// runs. Every end, an interrupt included, then shuts the bridge down and
/// removes the file and its directory. When the open fails, the URL printed
/// by [`print_registration_handoff`] is the handoff.
async fn register_until_done<F>(
    bridge: BridgeHandle,
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
    timeout: Duration,
    registration: impl FnOnce(Instant) -> F,
    interrupt: impl Future<Output = io::Result<()>>,
) -> RegistrationEnd
where
    F: Future<Output = Result<AddPasskeyOutcome, CredentialsError>>,
{
    let browser_handoff =
        private_open::open_or_point_to_handoff(url, opener, "the registration URL printed above");
    let polling = registration(Instant::now() + timeout);

    let end = tokio::select! {
        outcome = polling => RegistrationEnd::Finished(outcome),
        () = interrupted(interrupt) => RegistrationEnd::Interrupted,
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
    end
}

/// Renders the result envelope for how the registration phase ended and
/// returns the exit code: `0` for a registered credential, `1` otherwise.
fn report_registration_end(end: RegistrationEnd, name: &str) -> i32 {
    let outcome = match end {
        RegistrationEnd::Finished(outcome) => outcome,
        RegistrationEnd::Interrupted => {
            return emit_error(
                "credentials.registration_user_canceled",
                format!("registration of '{name}' was interrupted before the ceremony completed"),
            );
        }
    };
    match outcome {
        Ok(AddPasskeyOutcome::Registered { metadata }) => {
            render_json(&Envelope::ok(RegisteredSuccess {
                credential_id: redact_first5_last5(&metadata.credential_id_b64url),
                credential_name: metadata.credential_name,
                rp_id: metadata.rp_id,
                registered_at_unix_ms: metadata.registered_at_unix_ms,
            }));
            0
        }
        Ok(AddPasskeyOutcome::Timeout) => emit_error(
            "credentials.registration_timeout",
            format!("registration of '{name}' timed out before the ceremony completed"),
        ),
        Ok(AddPasskeyOutcome::UserCanceled) => emit_error(
            "credentials.registration_user_canceled",
            format!("registration of '{name}' was canceled by the user"),
        ),
        Ok(AddPasskeyOutcome::EntryMissing) => emit_error(
            "credentials.registration_entry_missing",
            format!(
                "registration of '{name}' failed: the approval-store entry was not found (TTL-expired or never persisted)"
            ),
        ),
        Err(e) => emit_error(credentials_error_code(&e), e.to_string()),
        // Non-exhaustive: future variants are non-success.
        Ok(_) => emit_error(
            "credentials.unknown_registration_outcome",
            "unknown registration outcome".to_owned(),
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

/// Opens or retrieves the cached `Arc<StdMutex<AuditWriter>>` for the passkey
/// registration event via [`AuditWriterRegistry`].
///
/// Non-fatal wrapper. If the profile cannot be loaded (not yet configured,
/// keyring miss, IO error), warns via `tracing::warn!` and returns `None`. The
/// registration flow continues without an audit entry.
///
/// A name mismatch cannot reach here: [`run`] reconciles before it opens the
/// approval store, so this helper only ever sees a profile that already
/// belongs to the requested name.
///
/// Uses [`AuditWriterRegistry::get_or_open_keyed`] instead of `AuditWriter::open`
/// directly so the single-writer invariant is enforced — if another call site
/// in the same process holds the writer for this profile the same `Arc` is
/// returned rather than a second open attempt that would receive `FileLocked`.
///
/// Steps: (1) reconciled profile load, (2) `keyed_audit_access`, the one helper
/// that pairs the chain-root key with the log's tip-anchor store, (3)
/// `AuditWriterRegistry::get_or_open_keyed`. Each step is non-fatal — returns
/// `None` on the first failure.
async fn open_profile_audit_writer_non_fatal(
    resolved: &ResolvedProfileName,
) -> Option<Arc<StdMutex<AuditWriter>>> {
    let profile_name = &resolved.name;
    let profile = match load_profile_reconciled(resolved) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                profile = %profile_name,
                error = %e,
                "credentials add-passkey: profile not found; audit entry will be skipped"
            );
            return None;
        }
    };

    let access = match stellar_agent_network::keyring::keyed_audit_access(
        &profile,
        profile_name,
        stellar_agent_core::audit_log::BindingCheck::Enforce,
    ) {
        Ok(access) => access,
        Err(e) if crate::commands::value_audit::is_binding_refusal(&e) => {
            warn!(
                profile = %profile_name,
                code = %e.code(),
                "credentials add-passkey: audit binding changed; audit entry will be skipped"
            );
            return None;
        }
        Err(e) => {
            warn!(
                profile = %profile_name,
                error = %e,
                "credentials add-passkey: audit chain key unavailable; audit entry will be skipped"
            );
            return None;
        }
    };

    match AuditWriterRegistry::get_or_open_keyed(profile_name, &profile.audit_log_path, access) {
        Ok(arc) => Some(arc),
        Err(e) => {
            warn!(
                path = %profile.audit_log_path.display(),
                error = %e,
                "credentials add-passkey: keyed audit writer open failed; audit entry will be skipped"
            );
            None
        }
    }
}

fn emit_error(code: &'static str, message: String) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

fn optional_registration_profile(
    loaded: Result<stellar_agent_core::profile::schema::Profile, ProfileAccessError>,
) -> Result<Option<stellar_agent_core::profile::schema::Profile>, ProfileAccessError> {
    match loaded {
        Ok(profile) => Ok(Some(profile)),
        Err(error) if error.requires_refusal() => Err(error),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn passkey_registration_preserves_protected_refusals() {
        for error in crate::common::profile_access::protected_load_errors_for_test() {
            let expected = error.code();
            let result = optional_registration_profile(Err(error));
            let error = result.expect_err("protected refusal was swallowed");
            assert_eq!(error.code(), expected);
        }
    }

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

    /// Completes the browser side of the registration for `nonce`: POSTs a
    /// structurally valid credential to the bridge with the entry's CSRF
    /// value, as the registration page does.
    async fn complete_registration_in_browser(
        bridge_addr: SocketAddr,
        store: &SharedStore,
        nonce: &str,
    ) {
        use base64::Engine as _;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use stellar_agent_core::approval::ApprovalKind;

        let csrf = {
            let guard = store.lock().await;
            match &guard.get(nonce).expect("the pending registration").kind {
                ApprovalKind::RegisterPasskey { csrf_token, .. } => hex::encode(csrf_token),
                _ => panic!("the pending entry is a registration"),
            }
        };
        let credential_id = URL_SAFE_NO_PAD.encode([0x42_u8; 16]);
        let mut public_key = [0x01_u8; 65];
        public_key[0] = 0x04;
        let payload = serde_json::json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": "ZHVtbXk",
                "attestationObject": "ZHVtbXk",
                "publicKeySec1B64": STANDARD.encode(public_key),
                "transports": ["internal"]
            }
        });
        let response = reqwest::Client::new()
            .post(format!("http://{bridge_addr}/register/{nonce}/credential"))
            .header("Origin", format!("http://{bridge_addr}"))
            .header("X-Stellar-Approval-CSRF", csrf)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
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
        complete_registration_in_browser(bridge_addr, &store, &handle.nonce).await;

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
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, None),
                std::future::pending(),
            ),
        )
        .await
        .expect("polling returns");
        assert!(
            matches!(
                end,
                RegistrationEnd::Finished(Ok(AddPasskeyOutcome::Registered { .. }))
            ),
            "{end:?}"
        );
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
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, None),
                probe.interrupt(),
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
        assert_eq!(report_registration_end(end, "laptop"), 1);
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
                |deadline| mgr.poll_registration("laptop", &handle.nonce, deadline, None),
                probe.interrupt(),
            ),
        )
        .await
        .expect("the interrupt ends the registration wait");
        assert!(matches!(end, RegistrationEnd::Interrupted), "{end:?}");
        assert!(probe.waited());
        probe.assert_failed_open_left_nothing(&handle.nonce);
    }

    /// Audit writer failure must not prevent registration.
    ///
    /// Simulated by calling `open_profile_audit_writer_non_fatal` with a
    /// profile name that does not exist in the system keyring. The function
    /// must return `None` without panicking.
    #[tokio::test]
    async fn audit_writer_failure_returns_none_not_panic() {
        // A profile that is almost certainly not configured on any test machine.
        let result = open_profile_audit_writer_non_fatal(&ResolvedProfileName::from_flag(
            "test-nonexistent-profile-xyz123",
        ))
        .await;
        // Must return None, not panic.
        assert!(
            result.is_none(),
            "audit writer must return None for an unconfigured profile"
        );
    }
}
