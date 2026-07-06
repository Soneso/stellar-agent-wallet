//! `stellar-agent approve serve` — local web UI for the pending-approval queue.
//!
//! Starts a loopback HTTP server (crate `stellar-agent-approval-ui`) that lets
//! the operator review and approve/reject pending approvals in a browser
//! instead of running `approve --id <nonce>` per entry on a terminal. The server
//! drives the exact same wallet-controlled attest/reject spine as the CLI, with
//! `Surface::Serve`.
//!
//! # Flow
//!
//! On start the server mints a single-use bootstrap token and prints the
//! `http://127.0.0.1:<port>/bootstrap/<token>` URL. Opening it exchanges the
//! token for an `HttpOnly` session cookie and redirects to the inbox; every
//! other route requires the cookie. The server runs until Ctrl-C.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::{Args, ValueEnum};

use stellar_agent_approval_ui::{DecisionContext, ServeConfig, ServeStartError, start_serve};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::default_approval_dir;
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::commands::smart_account::common::open_audit_writer;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

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
    let profile_name = resolve_profile_name(args.profile.as_deref());

    // Resolve the profile for the attestation-key reference.
    let profile = match loader::load(&profile_name, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: profile_name.clone(),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let store_path = match default_approval_dir() {
        Ok(dir) => dir.join(format!("{profile_name}.toml")),
        Err(_) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: "approval.store_dir_error: could not determine approval store directory"
                    .to_owned(),
            });
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    // One-time keyring bootstrap for the whole server run.
    if let Err(e) = init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let (audit_writer, _audit_path) = match open_audit_writer(&profile_name) {
        Ok(pair) => pair,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let context = DecisionContext::new(
        profile_name.clone(),
        store_path,
        profile.attestation_key_id.clone(),
        audit_writer,
        None,
    );

    if args.remote {
        return run_remote(
            &args,
            &profile_name,
            profile.remote_approval.as_ref(),
            context,
        )
        .await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let notify_enabled = matches!(args.notify, NotifyMode::On);
    let config = ServeConfig::new(bind_addr, context, tx, notify_enabled);

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

    print_startup(&bootstrap_url, port, port_was_explicit);

    // Open the browser only on a host with a display, and only when the URL is
    // not being handed to another process for a headless/tunnelled session.
    if !args.no_open
        && crate::common::display_available()
        && webbrowser::open(&bootstrap_url).is_err()
    {
        tracing::debug!("approve serve: browser open failed; use the printed URL");
    }

    // CLI-side notice printer: reads the watcher's count-increase events.
    let bell = args.bell;
    let notice_task = tokio::spawn(async move {
        while let Some(count) = rx.recv().await {
            print_pending_notice(count, bell);
        }
    });

    // Run until Ctrl-C.
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::debug!(error = %e, "approve serve: ctrl-c wait failed; shutting down");
    }

    notice_task.abort();
    if let Err(e) = handle.shutdown().await {
        tracing::debug!(error = %e, "approve serve: shutdown did not complete cleanly");
    }
    0
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

    let operator_credentials_path =
        match stellar_agent_core::approval::default_operator_approval_credentials_path(profile_name)
        {
            Ok(p) => p,
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
        remote_config.allowed_credentials.clone(),
        context,
        operator_credentials_path,
        tls,
    );

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
fn start_error_to_wallet_error(e: &ServeStartError) -> WalletError {
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

    /// Minimal parser wrapper so `ServeArgs` can be exercised through clap.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ServeArgs,
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
