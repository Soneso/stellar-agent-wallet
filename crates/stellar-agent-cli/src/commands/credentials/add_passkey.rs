//! `stellar-agent credentials add-passkey <name>` — register a WebAuthn passkey.
//!
//! Registration path:
//! 1. First-registration RP-ID binding prompt (if no prior passkeys).
//! 2. Open `PendingApprovalStore` exactly once; wrap in `Arc<Mutex<>>`.
//! 3. Construct `CredentialsManager::new` with the shared store Arc.
//! 4. Start the WebAuthn bridge with the same shared store Arc.
//! 5. Insert `PendingApproval { kind: RegisterPasskey }` via `CredentialsManager`.
//! 6. Launch the browser (fallback: print URL to stderr and continue polling).
//! 7. Poll the shared store until ceremony completes or deadline expires.
//! 8. Shut down the bridge.
//! 9. Write the credential metadata to the passkeys registry.
//! 10. Print the JSON result envelope.
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
//! `docs/runbooks/passkey-rp-id-recovery.md` and exits with code 1.

use std::{
    io::{self, BufRead as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Instant,
};

use clap::Args;
use serde::Serialize;
use stellar_agent_core::approval::retry::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::profile::loader;
use stellar_agent_core::redact_first5_last5;
use stellar_agent_smart_account::managers::credentials::{AddPasskeyOutcome, CredentialsManager};
use stellar_agent_webauthn_bridge::start_bridge_register_only;
use tokio::sync::Mutex;
use tracing::warn;

use crate::commands::credentials::credentials_error_code;
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

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
    /// passkeys unusable. Read `docs/runbooks/passkey-rp-id-recovery.md`
    /// before proceeding.
    #[arg(long = "rp-id", value_name = "DOMAIN", default_value = "localhost")]
    pub rp_id: String,

    /// Registration timeout in seconds (default: 300).
    #[arg(long = "timeout-seconds", value_name = "SECS", default_value_t = 300)]
    pub timeout_seconds: u64,

    /// Skip the first-registration RP-ID binding warning prompt.
    ///
    /// DANGER: only set this flag if you understand the RP-ID binding risks
    /// documented in `docs/runbooks/passkey-rp-id-recovery.md`.
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
    let profile = resolve_profile_name(args.profile.as_deref());

    // Validate the profile name as a path component before it is used to
    // construct filesystem paths.
    if let Err(reason) = validate_path_component_ascii_safe(&profile) {
        return emit_error(
            "credentials.invalid_profile_name",
            format!("invalid profile name '{profile}': {reason}"),
        );
    }

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
    let bridge = match start_bridge_register_only(Arc::clone(&shared_store), bind_addr).await {
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

    // ── Launch browser (fallback: print URL to stderr, continue polling) ───
    // Browser-launch failure is non-fatal: the operator can open the URL
    // manually. The polling loop continues regardless. The launch outcome is
    // NOT surfaced through `AddPasskeyOutcome`.
    let browser_launched = launch_browser(&handle.url);
    if !browser_launched {
        #[allow(clippy::print_stderr)]
        {
            eprintln!(
                "stellar-agent: browser launch failed. Open the following URL to complete registration:\n  {}",
                handle.url
            );
        }
    }

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
        open_profile_audit_writer_non_fatal(&profile).await;

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

    // ── Poll for registration completion ───────────────────────────────────
    let deadline = Instant::now() + std::time::Duration::from_secs(args.timeout_seconds);

    let outcome = mgr
        .poll_registration(&args.name, &handle.nonce, deadline, audit_writer_ref)
        .await;

    // ── Shut down the bridge ───────────────────────────────────────────────
    if let Err(e) = bridge.shutdown().await {
        // Non-fatal: the ceremony has already completed or timed out.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("stellar-agent: bridge shutdown warning: {e}");
        }
    }

    // ── Emit result JSON ───────────────────────────────────────────────────
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
            format!(
                "registration of '{}' timed out before the ceremony completed",
                args.name
            ),
        ),
        Ok(AddPasskeyOutcome::UserCanceled) => emit_error(
            "credentials.registration_user_canceled",
            format!("registration of '{}' was canceled by the user", args.name),
        ),
        Ok(AddPasskeyOutcome::EntryMissing) => emit_error(
            "credentials.registration_entry_missing",
            format!(
                "registration of '{}' failed: the approval-store entry was not found (TTL-expired or never persisted)",
                args.name
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
        println!("  See: docs/runbooks/passkey-rp-id-recovery.md for recovery options.");
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
         docs/runbooks/passkey-rp-id-recovery.md"
            .to_owned(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Attempts to open the given URL in the OS default browser.
///
/// Returns `true` if `webbrowser::open` succeeded, `false` otherwise.
///
/// Shell-injection defence: the URL is passed as a `&str` argument to
/// `webbrowser::open`, which on macOS calls `open(1)` with the URL as a
/// direct `Command::arg` — not via shell interpolation. Shell metacharacters
/// in the URL cannot escape into a shell command.
fn launch_browser(url: &str) -> bool {
    webbrowser::open(url).is_ok()
}

/// Opens or retrieves the cached `Arc<StdMutex<AuditWriter>>` for the passkey
/// registration event via [`AuditWriterRegistry`].
///
/// Non-fatal wrapper. If the profile cannot be loaded (not yet configured,
/// keyring miss, IO error), warns via `tracing::warn!` and returns `None`. The
/// registration flow continues without an audit entry.
///
/// Uses [`AuditWriterRegistry::get_or_open`] instead of `AuditWriter::open`
/// directly so the single-writer invariant is enforced — if another call site
/// in the same process holds the writer for this profile the same `Arc` is
/// returned rather than a second open attempt that would receive `FileLocked`.
///
/// Steps: (1) `loader::load(profile_name)`, (2) load HMAC key from keyring,
/// (3) `AuditWriterRegistry::get_or_open(profile_name, path, key)`.
/// Each step is non-fatal — returns `None` on the first failure.
async fn open_profile_audit_writer_non_fatal(
    profile_name: &str,
) -> Option<Arc<StdMutex<AuditWriter>>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use zeroize::Zeroizing;

    let profile = match loader::load(profile_name, None) {
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

    let entry_ref = &profile.audit_log_hash_chain_key_id;
    let keyring_entry = match KeyringEntry::new(&entry_ref.service, &entry_ref.account) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                service = %entry_ref.service,
                error = %e,
                "credentials add-passkey: keyring Entry::new failed for audit HMAC key; audit entry will be skipped"
            );
            return None;
        }
    };

    let secret_b64 = match keyring_entry.get_password() {
        Ok(s) => Zeroizing::new(s),
        Err(e) => {
            warn!(
                service = %entry_ref.service,
                error = %e,
                "credentials add-passkey: keyring get_password failed; audit entry will be skipped"
            );
            return None;
        }
    };

    let decoded = match URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()) {
        Ok(b) => Zeroizing::new(b),
        Err(e) => {
            warn!(
                error = %e,
                "credentials add-passkey: audit HMAC key is not valid base64; audit entry will be skipped"
            );
            return None;
        }
    };

    if decoded.len() != 32 {
        warn!(
            len = decoded.len(),
            "credentials add-passkey: audit HMAC key has wrong length (expected 32); audit entry will be skipped"
        );
        return None;
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(decoded.as_slice());

    match AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, Some(key)) {
        Ok(arc) => Some(arc),
        Err(e) => {
            warn!(
                path = %profile.audit_log_path.display(),
                error = %e,
                "credentials add-passkey: AuditWriterRegistry::get_or_open failed; audit entry will be skipped"
            );
            None
        }
    }
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    /// Audit writer failure must not prevent registration.
    ///
    /// Simulated by calling `open_profile_audit_writer_non_fatal` with a
    /// profile name that does not exist in the system keyring. The function
    /// must return `None` without panicking.
    #[tokio::test]
    async fn audit_writer_failure_returns_none_not_panic() {
        // A profile that is almost certainly not configured on any test machine.
        let result = open_profile_audit_writer_non_fatal("test-nonexistent-profile-xyz123").await;
        // Must return None, not panic.
        assert!(
            result.is_none(),
            "audit writer must return None for unconfigured profile"
        );
    }
}
