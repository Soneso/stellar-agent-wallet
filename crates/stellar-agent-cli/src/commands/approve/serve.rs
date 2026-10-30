//! `stellar-agent approve serve` — local web UI for the pending-approval queue.
//!
//! Starts a loopback HTTP server (crate `stellar-agent-approval-ui`) that lets
//! the operator review and approve/reject pending approvals in a browser
//! instead of running `approve --id <nonce> --profile <name>` per entry on a terminal. The server
//! drives the exact same wallet-controlled attest/reject spine as the CLI, with
//! `Surface::Serve`.
//!
//! # Flow
//!
//! On start the server mints a single-use bootstrap token and prints the
//! `http://127.0.0.1:<port>/bootstrap/<token>` URL. Opening it exchanges the
//! token for an `HttpOnly` session cookie and a session proof the page keeps
//! in the tab, then shows the inbox; every other route requires the cookie,
//! and approve and reject also require the proof. The session ends after 15
//! minutes without operator activity or 8 hours after the exchange; restart
//! the command for a new one. The server runs until Ctrl-C.
//!
//! Unless `--no-open` is passed, the browser is opened through a private
//! redirect file (see `crate::common::private_open`): the launcher receives
//! only the file's URL, never the bootstrap URL. The file stays until the
//! server stops. If the browser cannot be opened, the printed URL is the
//! handoff.
//!
//! # Security notes
//!
//! - Loopback-only bind; never reachable off-host. For a remote host, forward
//!   the port over SSH (`ssh -L`) rather than binding a public interface.
//! - The attestation key is read from the platform keyring only inside the
//!   decision seam; it never passes through the HTTP layer.
//! - The server must run as the same OS user as the wallet's MCP server
//!   process — the attestation binds that user's id, so a different user cannot
//!   attest.
//!
//! # Exit codes
//!
//! - `0` — clean shutdown after Ctrl-C.
//! - `1` — failure to start (profile not found, keyring init, port in use).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::{Args, ValueEnum};

use stellar_agent_approval_ui::{
    DecisionContext, ServeConfig, ServeHandle, ServeStartError, start_serve,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::commands::smart_account::common::open_audit_writer;
use crate::common::private_open;
use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;
use crate::common::served_pages::page_identity_for;
use stellar_agent_loopback_http::brand::PageIdentity;

/// Whether the server attempts a best-effort OS toast when the queue grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NotifyMode {
    /// Attempt an OS toast (rate-limited) on a count increase.
    On,
    /// Never attempt an OS toast.
    Off,
}

/// Arguments for `stellar-agent approve serve`.
///
/// # Examples
///
/// ```text
/// stellar-agent approve serve
/// stellar-agent approve serve --profile myprofile --port 7823 --bell
/// stellar-agent approve serve --no-open --notify off
/// ```
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ServeArgs {
    /// Profile name (default: `"default"` or `STELLAR_AGENT_PROFILE` env var).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// TCP port to bind on `127.0.0.1` (default: `0`, an OS-assigned port).
    #[arg(long = "port", default_value_t = 0, value_name = "PORT")]
    pub port: u16,

    /// Do not open the bootstrap URL in a browser; only print it.
    #[arg(long = "no-open")]
    pub no_open: bool,

    /// OS toast notifications on queue growth: `on` (default) or `off`.
    #[arg(long = "notify", value_enum, default_value_t = NotifyMode::On)]
    pub notify: NotifyMode,

    /// Emit a terminal bell with each queue-growth notice.
    #[arg(long = "bell")]
    pub bell: bool,

    /// Load the inbox with expired entries shown by default.
    #[arg(long = "include-expired")]
    pub include_expired: bool,

    /// Bind the network-exposed, TLS-protected remote-approval surface
    /// instead of the loopback approval-inbox server.
    ///
    /// Refuses to start unless the profile has a `[remote_approval]` block
    /// with `enabled = true` AND `--confirm-remote-exposure` is also passed.
    /// `--port` / `--no-open` / `--notify` / `--bell` / `--include-expired`
    /// are ignored in this mode (the remote surface has its own bind address
    /// from the profile config and no browser auto-launch).
    #[arg(long = "remote")]
    pub remote: bool,

    /// Explicit consent to expose the approve/reject surface beyond
    /// loopback. Required (together with the profile's `[remote_approval]`
    /// block) for `--remote` to take effect; matches the `--confirm-*`
    /// consent-flag pattern used for other risky-write exceptions elsewhere
    /// in this CLI.
    #[arg(long = "confirm-remote-exposure")]
    pub confirm_remote_exposure: bool,
}

/// Runs `stellar-agent approve serve`.
///
/// Returns `1` on any failure to start; once the server is running it awaits
/// Ctrl-C and returns `0` on clean shutdown.
///
/// # Errors
///
/// Never returns `Err` — start failures are captured into the exit code and a
/// JSON error envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: ServeArgs) -> i32 {
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();

    // Resolve the profile for the attestation-key reference.
    // Reconciled: the attestation-key reference and the approval-store path
    // below both come from this file, so a file that names another profile is
    // refused here rather than used to serve approvals under this name.
    let profile = match load_profile_reconciled(&resolved_profile) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };

    let mainnet = profile.chain_id.is_mainnet();
    if mainnet && (args.remote || args.no_open || !crate::common::display_available()) {
        let failure = if args.remote {
            stellar_agent_core::ApprovalFailure::MainnetRemoteUnsupported
        } else {
            stellar_agent_core::ApprovalFailure::PresenceBrowserRequired
        };
        render_json(&Envelope::<()>::err(&WalletError::Approval(failure)));
        return 1;
    }
    let store_path = match super::common::approval_store_dir() {
        Ok(dir) => dir.join(format!("{profile_name}.toml")),
        Err(err) => {
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // One-time keyring bootstrap for the whole server run.
    if let Err(e) = init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let (audit_writer, _audit_path) = match open_audit_writer(
        &profile,
        crate::common::profile_access::ProfileOrigin::Persisted,
        &resolved_profile.name,
    ) {
        Ok(opened) => opened,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let mut context = DecisionContext::new(
        stellar_agent_core::approval::ApprovalContext::from_profile(&profile_name, &profile),
        store_path,
        profile.attestation_key_id.clone(),
        stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
            &profile_name,
            &profile,
        ),
        audit_writer,
        None,
    );

    if mainnet {
        let authority =
            stellar_agent_core::approval::MainnetApprovalAuthority::for_profile(&profile_name)
                .and_then(|authority| {
                    authority.load_current()?;
                    Ok(authority)
                });
        match authority {
            Ok(authority) => context = context.with_mainnet_authority(authority),
            Err(error) => {
                render_json(&Envelope::<()>::err(&error));
                return 1;
            }
        }
    }
    let page_identity = page_identity_for(&profile);

    if args.remote {
        return run_remote(
            &args,
            &profile_name,
            profile.remote_approval.as_ref(),
            context,
            page_identity,
        )
        .await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let notify_enabled = matches!(args.notify, NotifyMode::On);
    let config =
        ServeConfig::new(bind_addr, context, tx, notify_enabled).with_page_identity(page_identity);

    let handle = match start_serve(config).await {
        Ok(h) => h,
        Err(e) => {
            render_json(&Envelope::<()>::err(&start_error_to_wallet_error(&e)));
            return 1;
        }
    };

    let bootstrap_url = handle.bootstrap_url();
    let port = handle.local_addr().port();
    let port_was_explicit = args.port != 0;

    if mainnet {
        return serve_mainnet(handle, &bootstrap_url, port).await;
    }
    print_startup(&bootstrap_url, port, port_was_explicit);

    // CLI-side notice printer: reads the watcher's count-increase events.
    let bell = args.bell;
    let notice_task = tokio::spawn(async move {
        while let Some(count) = rx.recv().await {
            print_pending_notice(count, bell);
        }
    });

    // Open the browser only on a host with a display, and only when the URL is
    // not being handed to another process for a headless/tunnelled session.
    let open_browser = !args.no_open && crate::common::display_available();
    serve_until_shutdown(
        handle,
        &bootstrap_url,
        open_browser,
        private_open::browser_opener,
        tokio::signal::ctrl_c(),
    )
    .await;

    notice_task.abort();
    0
}

async fn serve_mainnet(handle: ServeHandle, url: &str, port: u16) -> i32 {
    let handoff = match private_open::open_private(url, private_open::browser_opener) {
        Ok(handoff) => handoff,
        Err(_) => {
            let _ = handle.shutdown().await;
            render_json(&Envelope::<()>::err(&WalletError::Approval(
                stellar_agent_core::ApprovalFailure::PresenceBrowserRequired,
            )));
            return 1;
        }
    };
    #[allow(
        clippy::print_stderr,
        reason = "CLI startup notice excludes bearer material"
    )]
    {
        eprintln!("Mainnet approval inbox listens on localhost port {port}.");
    }
    let _ = tokio::signal::ctrl_c().await;
    let stopped = handle.shutdown().await;
    let closed = handoff.close();
    if stopped.is_err() || closed.is_err() {
        return 1;
    }
    0
}

/// Runs the started inbox server until `shutdown_signal` resolves (Ctrl-C).
///
/// When `open_browser` is set, opens the bootstrap URL through a private
/// redirect file first; `opener` receives only the file's URL. The file stays
/// while the server runs. After the signal the server stops and the file and
/// its directory are removed. When the open fails, the URL printed at startup
/// is the handoff.
async fn serve_until_shutdown(
    handle: ServeHandle,
    bootstrap_url: &str,
    open_browser: bool,
    opener: impl FnOnce(&str) -> io::Result<()>,
    shutdown_signal: impl Future<Output = io::Result<()>>,
) {
    let browser_handoff = if open_browser {
        private_open::open_or_point_to_handoff(
            bootstrap_url,
            opener,
            "the approval inbox URL printed above",
        )
    } else {
        None
    };

    if let Err(e) = shutdown_signal.await {
        tracing::debug!(error = %e, "approve serve: ctrl-c wait failed; shutting down");
    }

    if let Err(e) = handle.shutdown().await {
        tracing::debug!(error = %e, "approve serve: shutdown did not complete cleanly");
    }
    if let Some(handoff) = browser_handoff
        && let Err(e) = handoff.close()
    {
        tracing::debug!(error.kind = ?e.kind(), "approve serve: redirect file cleanup failed");
    }
}

/// Runs `stellar-agent approve serve --remote`.
///
/// Refuses to start (exit `1`) unless BOTH the profile carries a
/// `[remote_approval]` block with `enabled = true` AND
/// `--confirm-remote-exposure` was passed — the profile block alone can
/// never silently turn on network exposure. Validates `bind` and `rp_id`
/// fail-closed before touching TLS or the network: `rp_id` must be a DNS
/// hostname, never an IP literal; `bind` must parse as a `SocketAddr`.
///
/// # Panics
///
/// Never panics.
async fn run_remote(
    args: &ServeArgs,
    profile_name: &str,
    remote_config: Option<&stellar_agent_core::profile::schema::RemoteApprovalConfig>,
    context: DecisionContext,
    page_identity: PageIdentity,
) -> i32 {
    let Some(remote_config) = remote_config.filter(|c| c.enabled) else {
        let err = WalletError::Internal(InternalError::UnexpectedState {
            detail: "approve.remote_not_configured: profile has no enabled [remote_approval] \
                     block; add one before passing --remote"
                .to_owned(),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    };

    if !args.confirm_remote_exposure {
        let err = WalletError::Internal(InternalError::UnexpectedState {
            detail: "approve.remote_exposure_not_confirmed: --remote requires \
                     --confirm-remote-exposure as an explicit, separate consent flag"
                .to_owned(),
        });
        render_json(&Envelope::<()>::err(&err));
        return 1;
    }

    let bind_addr = match stellar_agent_approval_remote::validate_remote_config(
        &remote_config.bind,
        &remote_config.rp_id,
    ) {
        Ok(addr) => addr,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.remote_config_invalid: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let tls = match stellar_agent_approval_remote::provision_or_load(
        profile_name,
        &remote_config.rp_id,
    ) {
        Ok(tls) => tls,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.remote_tls_provision_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // The listener reads the profile's allowlist and the operator-credential
    // store from these locations at every check; the `[remote_approval]`
    // block loaded above only configures the bind address and RP ID.
    let authority =
        match stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(profile_name) {
            Ok(authority) => authority,
            Err(e) => {
                let err = WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("approve.remote_operator_store_unavailable: {e}"),
                });
                render_json(&Envelope::<()>::err(&err));
                return 1;
            }
        };

    let fingerprint = tls.fingerprint_sha256_hex.clone();
    let config = stellar_agent_approval_remote::RemoteServeConfig::new(
        bind_addr,
        remote_config.rp_id.clone(),
        authority,
        context,
        tls,
    )
    .with_page_identity(page_identity);

    let handle = match stellar_agent_approval_remote::start_remote_serve(config).await {
        Ok(h) => h,
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("approve.remote_serve_start_failed: {e}"),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    print_remote_startup(
        &remote_config.rp_id,
        handle.local_addr().port(),
        &fingerprint,
    );

    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::debug!(error = %e, "approve serve --remote: ctrl-c wait failed; shutting down");
    }

    if let Err(e) = handle.shutdown().await {
        tracing::debug!(error = %e, "approve serve --remote: shutdown did not complete cleanly");
    }
    0
}

/// Prints the remote-approval startup banner: the HTTPS URL and the
/// certificate fingerprint for out-of-band verification on the approving
/// device.
fn print_remote_startup(rp_id: &str, port: u16, fingerprint_sha256_hex: &str) {
    #[allow(
        clippy::print_stdout,
        reason = "CLI binary intentional user output — remote-approval startup"
    )]
    {
        println!("Remote approval inbox: https://{rp_id}:{port}/");
        println!(
            "Certificate SHA-256 fingerprint (verify out-of-band before trusting): {fingerprint_sha256_hex}"
        );
        println!(
            "\"{rp_id}\" must resolve to this host from the approving device (internal DNS or a \
             hosts-file entry) — WebAuthn requires a DNS Relying Party ID, never an IP address."
        );
    }
}

/// Maps a [`ServeStartError`] to a wallet error for the JSON envelope.
///
/// A mainnet presence refusal keeps its approval code and fixed message.
fn start_error_to_wallet_error(e: &ServeStartError) -> WalletError {
    if let Some(failure) = e.presence_failure() {
        return WalletError::Approval(failure);
    }
    let detail = match e {
        ServeStartError::NonLoopbackBind { .. } => {
            format!("approve.serve_bind: {e}")
        }
        ServeStartError::Bind { .. } => {
            format!("approve.serve_bind: could not bind the requested port ({e})")
        }
        // `ServeStartError` is `#[non_exhaustive]`; a future variant maps to the
        // same generic serve-start error code.
        _ => format!("approve.serve_start: {e}"),
    };
    WalletError::Internal(InternalError::UnexpectedState { detail })
}

/// Prints the bootstrap URL plus at most two lines of startup guidance.
fn print_startup(bootstrap_url: &str, port: u16, port_was_explicit: bool) {
    #[allow(
        clippy::print_stdout,
        reason = "CLI binary intentional user output — approval-inbox startup"
    )]
    {
        println!("Approval inbox: {bootstrap_url}");
        println!(
            "Run this as the same OS user as the wallet's MCP server process, \
             or approvals will not attest."
        );
        if port_was_explicit {
            println!("Remote host? Forward the port: ssh -L {port}:127.0.0.1:{port} <user>@<host>");
        }
    }
}

/// Prints a content-free pending-count notice to stderr, optionally with a bell.
fn print_pending_notice(count: usize, bell: bool) {
    #[allow(
        clippy::print_stderr,
        reason = "CLI binary intentional user output — pending-approval notice"
    )]
    {
        if bell {
            eprint!("\x07");
        }
        eprintln!("approvals pending: {count}");
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

    /// Each presence start refusal surfaces with its approval code and the
    /// fixed message of that code, never as a generic serve-start error.
    #[test]
    fn presence_start_refusals_keep_their_codes() {
        use stellar_agent_approval_ui::PresenceStartRefusal;
        for (refusal, code, message) in [
            (
                PresenceStartRefusal::PolicyUnavailable,
                "approval.presence_policy_unavailable",
                "The current owner-signed mainnet approval policy cannot be verified; restore a \
                 valid policy and start a new approval ceremony.",
            ),
            (
                PresenceStartRefusal::Changed,
                "approval.presence_changed",
                "The consent details have changed; reload the approval page and review them again.",
            ),
            (
                PresenceStartRefusal::Unavailable,
                "approval.presence_unavailable",
                "The mainnet presence ceremony cannot start or complete; no approval is recorded.",
            ),
        ] {
            let error = start_error_to_wallet_error(&ServeStartError::Presence(refusal));
            assert_eq!(error.code(), code, "{refusal:?}");
            assert_eq!(error.to_string(), message, "{refusal:?}");
        }
        let bind = start_error_to_wallet_error(&ServeStartError::Bind {
            kind: std::io::ErrorKind::AddrInUse,
            source: std::io::Error::from(std::io::ErrorKind::AddrInUse),
        });
        assert!(bind.to_string().contains("approve.serve_bind"), "{bind}");
    }

    /// Minimal parser wrapper so `ServeArgs` can be exercised through clap.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ServeArgs,
    }

    /// A started inbox server on a temporary store, with its bootstrap URL
    /// and token.
    async fn start_test_inbox(dir: &tempfile::TempDir) -> (ServeHandle, String, String) {
        use std::sync::{Arc, Mutex};

        use stellar_agent_core::audit_log::writer::AuditWriter;
        use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

        let profile = Profile::builder_testnet("svc", "default", "nonce", "default").build();
        let context = DecisionContext::new(
            stellar_agent_core::approval::ApprovalContext::from_profile("serve-test", &profile),
            dir.path().join("serve-test.toml"),
            KeyringEntryRef::new("svc", "default"),
            stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile_name("serve-test"),
            Arc::new(Mutex::new(
                AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
            )),
            None,
        );
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let config = ServeConfig::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            context,
            tx,
            false,
        );
        let handle = start_serve(config).await.unwrap();
        let url = handle.bootstrap_url();
        let token = handle.bootstrap_token_hex().to_owned();
        (handle, url, token)
    }

    /// The serve phase hands the browser only the private redirect file's
    /// URL, keeps the file while the server runs, and removes it once the
    /// shutdown signal stops the server. A failed open makes one attempt with
    /// the file URL and leaves nothing behind; `--no-open` opens nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn serve_uses_private_open() {
        use crate::common::private_open::handoff_probe::HandoffProbe;
        let bound = std::time::Duration::from_secs(30);
        let dir = tempfile::tempdir().unwrap();

        let (handle, url, token) = start_test_inbox(&dir).await;
        let addr = handle.local_addr();
        let probe = HandoffProbe::default();
        tokio::time::timeout(
            bound,
            serve_until_shutdown(handle, &url, true, probe.opener(Ok(())), probe.interrupt()),
        )
        .await
        .expect("the shutdown signal ends the serve phase");
        probe.assert_private_handoff(&url, &token);
        assert!(
            std::net::TcpStream::connect(addr).is_err(),
            "the server stopped"
        );

        let (handle, url, token) = start_test_inbox(&dir).await;
        let probe = HandoffProbe::default();
        tokio::time::timeout(
            bound,
            serve_until_shutdown(
                handle,
                &url,
                true,
                probe.opener(Err(io::Error::other("no browser"))),
                probe.interrupt(),
            ),
        )
        .await
        .expect("the shutdown signal ends the serve phase");
        assert!(probe.waited());
        probe.assert_failed_open_left_nothing(&token);

        let (handle, url, _token) = start_test_inbox(&dir).await;
        let probe = HandoffProbe::default();
        tokio::time::timeout(
            bound,
            serve_until_shutdown(handle, &url, false, probe.opener(Ok(())), probe.interrupt()),
        )
        .await
        .expect("the shutdown signal ends the serve phase");
        assert!(probe.waited());
        assert!(probe.launched().is_empty());
    }

    #[test]
    fn parses_all_flags() {
        let w = Wrap::try_parse_from([
            "prog",
            "--profile",
            "myprofile",
            "--port",
            "7823",
            "--no-open",
            "--notify",
            "off",
            "--bell",
            "--include-expired",
            "--remote",
            "--confirm-remote-exposure",
        ])
        .expect("flags parse");
        assert_eq!(w.args.profile.as_deref(), Some("myprofile"));
        assert_eq!(w.args.port, 7823);
        assert!(w.args.no_open);
        assert_eq!(w.args.notify, NotifyMode::Off);
        assert!(w.args.bell);
        assert!(w.args.include_expired);
        assert!(w.args.remote);
        assert!(w.args.confirm_remote_exposure);
    }

    #[test]
    fn defaults_are_sane() {
        let w = Wrap::try_parse_from(["prog"]).expect("defaults parse");
        assert!(w.args.profile.is_none());
        assert_eq!(w.args.port, 0);
        assert!(!w.args.no_open);
        assert_eq!(w.args.notify, NotifyMode::On);
        assert!(!w.args.bell);
        assert!(!w.args.include_expired);
        assert!(
            !w.args.remote,
            "--remote must default to false (loopback default)"
        );
        assert!(!w.args.confirm_remote_exposure);
    }

    /// `serve::run` with an explicit already-bound port must fail cleanly with
    /// exit 1 rather than panicking. The profile is absent, so the command
    /// exits 1 at profile resolution without reaching the bind; either way the
    /// contract is a clean non-panicking exit-1. The bind-conflict path itself
    /// is covered at the library level in `stellar-agent-approval-ui`.
    #[tokio::test]
    async fn run_with_bound_port_and_absent_profile_exits_1_without_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let args = ServeArgs {
            profile: Some("__stellar_agent_serve_test_absent_profile".to_owned()),
            port,
            no_open: true,
            notify: NotifyMode::Off,
            bell: false,
            include_expired: false,
            remote: false,
            confirm_remote_exposure: false,
        };
        let code = run(args).await;
        assert_eq!(code, 1);
    }

    /// `--remote` without a `[remote_approval]` profile block must exit `1`
    /// cleanly (fail-closed) rather than attempting to bind or provision TLS.
    #[tokio::test]
    async fn run_remote_without_profile_block_exits_1_without_panic() {
        let args = ServeArgs {
            profile: Some("__stellar_agent_serve_test_absent_profile_remote".to_owned()),
            port: 0,
            no_open: true,
            notify: NotifyMode::Off,
            bell: false,
            include_expired: false,
            remote: true,
            confirm_remote_exposure: true,
        };
        let code = run(args).await;
        assert_eq!(code, 1);
    }
}
