//! Bounded stdio transport for the MCP JSON-RPC protocol.
//!
//! Provides `BoundedStdioTransport`, a wallet-owned `Transport<RoleServer>`
//! implementation that enforces the 1 MiB max-line bound, and the startup
//! functions that wire a `WalletServer` to it as separate steps:
//! [`crate::transport::build_selected_server`] for the binary's startup,
//! [`crate::transport::build_server`], and [`crate::transport::serve`], with
//! [`crate::transport::run`] composing the latter two.
//!
//! It also holds the startup refusals that are decided from the loaded profile
//! alone: [`crate::transport::mcp_disabled_refusal`] for the per-profile kill-switch and
//! [`crate::transport::profile_name_mismatch_refusal`] for a profile file whose owner-key
//! coordinate names a different profile than the one selected. The latter is
//! re-exported from `stellar-agent-core`, where it is shared with the CLI so
//! both surfaces reconcile a profile against its own name identically.

use futures::{SinkExt, StreamExt};
use rmcp::{
    RoleServer, ServiceExt,
    service::{RxJsonRpcMessage, ServerInitializeError, TxJsonRpcMessage},
    transport::{
        Transport,
        async_rw::{JsonRpcMessageCodec, JsonRpcMessageCodecError},
    },
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use crate::STELLAR_AGENT_MCP_MAX_LINE_BYTES;
use crate::server::WalletServer;
use stellar_agent_core::policy::BuildRegistryError;
use stellar_agent_core::profile::schema::Profile;

/// The selected-name reconciliation both binaries apply, re-exported from
/// `stellar-agent-core`.
///
/// The implementation is shared so the MCP server and the CLI cannot reach
/// different verdicts on the same profile file. This module keeps the names
/// exported because they are part of this crate's published surface, and
/// because the startup refusal below is the server's only caller.
///
/// Render [`ProfileNameMismatch`] with
/// [`ProfileNameMismatch::message`] and [`ProfileStateLayout::DerivedThroughout`]:
/// this server keys every per-profile store — signed policy, approval store,
/// window state, audit log, counterparty cache — on the derived name.
pub use stellar_agent_core::profile::name::{
    ProfileNameMismatch, ProfileStateLayout, profile_name_mismatch_refusal,
};

/// Loads the profile the operator selected.
///
/// A profile named through `--profile` or `STELLAR_AGENT_PROFILE` is loaded
/// with no fallback. The synthesized first-run profile is a **testnet**,
/// **Noop-engine** configuration, and it never stands in for a named profile.
/// The fallback applies only when no name was given at all, which is the
/// first-run case it exists for.
///
/// The branch keys on the resolved name's source, never on the name itself:
/// `--profile default` on a host with no `default.toml` is a named profile that
/// must refuse, not a first run.
///
/// The returned origin is
/// [`ProfileOrigin::Persisted`](stellar_agent_core::profile::loader::ProfileOrigin::Persisted)
/// for every profile read from a file, the unnamed `default.toml` included;
/// only the synthesized fallback is
/// [`ProfileOrigin::Synthesized`](stellar_agent_core::profile::loader::ProfileOrigin::Synthesized).
/// [`build_selected_server`] and [`build_server`] take the binding check the
/// origin implies.
///
/// # Errors
///
/// The [`ProfileLoadError`](stellar_agent_core::profile::loader::ProfileLoadError)
/// of the load, or the refusal of an implicitly selected mainnet profile.
pub fn load_selected_profile(
    resolved: &stellar_agent_core::profile::name::ResolvedProfileName,
) -> Result<
    (Profile, stellar_agent_core::profile::loader::ProfileOrigin),
    stellar_agent_core::profile::loader::ProfileLoadError,
> {
    use stellar_agent_core::profile::loader;
    let (profile, origin) = if resolved.source.is_explicit() {
        (
            loader::load(&resolved.name, None)?,
            loader::ProfileOrigin::Persisted,
        )
    } else {
        loader::load_default_or_testnet_fallback()?
    };
    stellar_agent_core::profile::check_mainnet_selection(&profile, resolved)?;
    Ok((profile, origin))
}

// ─────────────────────────────────────────────────────────────────────────────
// Type aliases for BoundedTransport internals
// ─────────────────────────────────────────────────────────────────────────────

/// Codec-framed writer of the bounded transport.
type BoundedWriter<W> = FramedWrite<W, JsonRpcMessageCodec<TxJsonRpcMessage<RoleServer>>>;

/// Codec-framed reader of the bounded transport.
type BoundedReader<R> = FramedRead<R, JsonRpcMessageCodec<RxJsonRpcMessage<RoleServer>>>;

// ─────────────────────────────────────────────────────────────────────────────
// BoundedTransport: max-line mitigation
// ─────────────────────────────────────────────────────────────────────────────

/// A custom `Transport` implementation that enforces the 1 MiB max-line bound.
///
/// This type wraps `FramedRead<R, JsonRpcMessageCodec>` and
/// `FramedWrite<W, JsonRpcMessageCodec>` constructed with
/// `JsonRpcMessageCodec::new_with_max_length(STELLAR_AGENT_MCP_MAX_LINE_BYTES)`,
/// bypassing the default `usize::MAX` codec that `AsyncRwTransport::new` uses.
///
/// # Implements
///
/// `rmcp::transport::Transport<RoleServer>` — the trait required by
/// `ServiceExt::serve` to drive the MCP JSON-RPC loop.
pub struct BoundedTransport<R, W> {
    read: BoundedReader<R>,
    write: Arc<TokioMutex<Option<BoundedWriter<W>>>>,
}

/// The bounded transport over the process's standard streams.
pub type BoundedStdioTransport = BoundedTransport<tokio::io::Stdin, tokio::io::Stdout>;

impl Default for BoundedStdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedStdioTransport {
    /// Constructs a `BoundedStdioTransport` with the 1 MiB max-line codec.
    ///
    /// # Panics
    ///
    /// Never panics — `tokio::io::stdin()` and `tokio::io::stdout()` are
    /// infallible on all supported platforms.
    #[must_use]
    pub fn new() -> Self {
        Self::over(tokio::io::stdin(), tokio::io::stdout())
    }
}

impl<R: AsyncRead, W: AsyncWrite> BoundedTransport<R, W> {
    /// Constructs the transport over `read` and `write` with the 1 MiB
    /// max-line codec on both directions.
    #[must_use]
    pub fn over(read: R, write: W) -> Self {
        let codec_rx = JsonRpcMessageCodec::<RxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        let codec_tx = JsonRpcMessageCodec::<TxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        Self {
            read: FramedRead::new(read, codec_rx),
            write: Arc::new(TokioMutex::new(Some(FramedWrite::new(write, codec_tx)))),
        }
    }
}

/// Logs a refused client frame.
///
/// The codec's own error text quotes the frame, so the event states the
/// refusal with its position or I/O kind and holds no text of the frame.
fn log_frame_error(err: &JsonRpcMessageCodecError) {
    match err {
        JsonRpcMessageCodecError::MaxLineLengthExceeded => {
            tracing::error!("the frame exceeds the line limit");
        }
        JsonRpcMessageCodecError::Serde(parse) => {
            tracing::error!(
                line = parse.line(),
                column = parse.column(),
                "the frame is not a valid JSON-RPC message"
            );
        }
        JsonRpcMessageCodecError::Io(io) => {
            tracing::error!(kind = %io.kind(), "the frame could not be read");
        }
        _ => tracing::error!("the frame could not be read"),
    }
}

impl<R, W> Transport<RoleServer> for BoundedTransport<R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let lock = self.write.clone();
        async move {
            let mut guard = lock.lock().await;
            if let Some(ref mut writer) = *guard {
                writer.send(item).await.map_err(Into::into)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "transport closed",
                ))
            }
        }
    }

    fn receive(
        &mut self,
    ) -> impl std::future::Future<Output = Option<RxJsonRpcMessage<RoleServer>>> {
        let next = self.read.next();
        async move {
            next.await.and_then(
                |result: Result<RxJsonRpcMessage<RoleServer>, JsonRpcMessageCodecError>| {
                    result.inspect_err(log_frame_error).ok()
                },
            )
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        let mut guard = self.write.lock().await;
        drop(guard.take());
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server startup
// ─────────────────────────────────────────────────────────────────────────────

/// Starts the MCP stdio server and runs until the client disconnects.
///
/// Constructs the bounded transport (max-line mitigation) and calls
/// `rmcp::ServiceExt::serve` with the `WalletServer` handler. `binding` is
/// passed to [`build_server`].
///
/// # Errors
///
/// Returns a boxed error if the rmcp service encounters a fatal error during
/// initialisation or operation.
pub async fn run(
    profile: Profile,
    binding: stellar_agent_core::audit_log::BindingCheck,
) -> Result<(), Box<dyn std::error::Error>> {
    serve(build_server(profile, binding)?).await
}

/// Constructs the [`WalletServer`] for `profile` without starting the MCP loop
/// and without a profile selection, so installation verification does not
/// run. The binary's startup uses [`build_selected_server`].
///
/// `WalletServer::new` is fail-closed: a duplicate `McpToolRegistration` name
/// causes [`BuildRegistryError::DuplicateRegistration`], and a V1 profile whose
/// owner key, signed policy, or window state is not yet in place fails here
/// rather than serving with a degraded engine.
///
/// `binding` is the audit binding check the profile's origin implies; the
/// server stores it and every keyed audit acquisition applies it.
///
/// # Errors
///
/// Returns the [`BuildRegistryError`] produced by `WalletServer::new`.
pub fn build_server(
    profile: Profile,
    binding: stellar_agent_core::audit_log::BindingCheck,
) -> Result<WalletServer, BuildRegistryError> {
    Ok(WalletServer::new(profile)?.with_audit_binding_check(binding))
}

/// Constructs the [`WalletServer`] for the startup's profile selection without
/// starting the MCP loop. `source` is how the profile name was selected; the
/// profile file is read from the OS-conventional profile directory, which
/// installation verification binds to.
///
/// Returns typed startup errors so the binary can name the required recovery
/// step before serving.
///
/// `binding` is the audit binding check the profile's origin implies; the
/// server stores it and every keyed audit acquisition applies it.
///
/// # Errors
///
/// Returns [`BuildRegistryError::PolicyDirResolutionFailed`] when the profile
/// directory cannot be resolved, and otherwise the [`BuildRegistryError`]
/// produced by [`WalletServer::new_with_selection`].
pub fn build_selected_server(
    profile: Profile,
    source: stellar_agent_core::profile::name::ProfileNameSource,
    binding: stellar_agent_core::audit_log::BindingCheck,
) -> Result<WalletServer, BuildRegistryError> {
    let profile_dir = stellar_agent_core::profile::schema::default_profile_dir()
        .map_err(|_| BuildRegistryError::PolicyDirResolutionFailed)?;
    Ok(
        WalletServer::new_with_selection(profile, source, &profile_dir)?
            .with_audit_binding_check(binding),
    )
}

/// Runs the MCP stdio loop for an already-constructed server until the client
/// disconnects.
///
/// # Errors
///
/// Returns a boxed error if the rmcp service encounters a fatal error during
/// initialisation or operation.
pub async fn serve(server: WalletServer) -> Result<(), Box<dyn std::error::Error>> {
    serve_until(server, std::future::pending::<()>()).await
}

/// Runs the MCP stdio loop for an already-constructed server until the client
/// disconnects or `shutdown` resolves.
///
/// `shutdown` is polled from before the session starts. When it resolves, the
/// service is cancelled and its session task is awaited for at most
/// [`SHUTDOWN_WAIT`]. Within that wait the task closes the transport before
/// this function returns. A tool call that runs past the session's own drain
/// timeout keeps running; it reaches the audit log only through the writer mutex.
///
/// # Errors
///
/// [`SessionStartError`] when the session does not start, or the join error of
/// the running service.
pub async fn serve_until<F>(
    server: WalletServer,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: std::future::Future<Output = ()>,
{
    // ── Max-line mitigation: BoundedStdioTransport with 1 MiB max-line bound ──
    // Do NOT use `.serve(rmcp::transport::stdio())` or `.serve((stdin, stdout))`
    // — those paths call `AsyncRwTransport::new` which internally uses
    // `JsonRpcMessageCodec::default()` (max_length = usize::MAX, a DoS surface).
    //
    // `BoundedTransport` is a wallet-owned `Transport<RoleServer>` impl
    // that constructs both codec instances with explicit
    // `JsonRpcMessageCodec::new_with_max_length(STELLAR_AGENT_MCP_MAX_LINE_BYTES)`.
    // It is passed directly to `.serve()`, which accepts any `T: IntoTransport`
    // and the blanket impl `T: Transport<Role> => T: IntoTransport` applies.
    //
    // Verification point: the codec construction is in
    // `BoundedTransport::over()` above in this file; the `default()`
    // constructor is never called.
    serve_on_until(server, BoundedStdioTransport::new(), shutdown).await
}

/// Runs `server` on `transport` until the client disconnects.
///
/// # Errors
///
/// [`SessionStartError`] when the session does not start, or the join error of
/// the running service.
pub async fn serve_on<R, W>(
    server: WalletServer,
    transport: BoundedTransport<R, W>,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    serve_on_until(server, transport, std::future::pending::<()>()).await
}

/// Bounds the session's stop after a shutdown signal, allowing more than
/// rmcp's two-second response drain.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Runs `server` on `transport` until the client disconnects or `shutdown`
/// resolves.
///
/// One cancellation token reaches rmcp for the whole session: the handshake
/// and the running service observe it. A `shutdown` that resolves during the
/// handshake cancels the token, lets the handshake return, and yields
/// `Ok(())`. A `shutdown` on a running session cancels the same token and
/// waits at most [`SHUTDOWN_WAIT`] for the session to stop.
///
/// # Errors
///
/// [`SessionStartError`] when the session does not start, or the join error of
/// the running service.
pub async fn serve_on_until<R, W, F>(
    server: WalletServer,
    transport: BoundedTransport<R, W>,
    shutdown: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    F: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    let cancellation = CancellationToken::new();
    let starting = server.serve_with_ct(transport, cancellation.clone());
    tokio::pin!(starting);
    let started = tokio::select! {
        result = &mut starting => Some(result),
        () = &mut shutdown => None,
    };
    let service = match started {
        Some(result) => result.map_err(SessionStartError::from)?,
        None => {
            tracing::info!(
                "stellar-agent-mcp: shutdown signal received before the session started"
            );
            cancellation.cancel();
            // The handshake observes the cancelled token and returns, so it
            // ends through rmcp's own cancellation path. Its outcome is the
            // shutdown's, not a startup failure.
            drop(starting.await);
            return Ok(());
        }
    };

    tracing::info!("stellar-agent-mcp: MCP server ready");
    let waiting = service.waiting();
    tokio::pin!(waiting);
    tokio::select! {
        result = &mut waiting => {
            result?;
        }
        () = &mut shutdown => {
            tracing::info!(
                "stellar-agent-mcp: shutdown signal received; stopping the MCP server"
            );
            cancellation.cancel();
            match tokio::time::timeout(SHUTDOWN_WAIT, &mut waiting).await {
                Ok(result) => {
                    result?;
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        wait_seconds = SHUTDOWN_WAIT.as_secs(),
                        "stellar-agent-mcp: the session did not stop within \
                         the shutdown wait; draining and exiting"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Why an MCP session did not start.
///
/// rmcp's own error holds the client's rejected message and renders it in
/// `Display` and `Debug`, so the conversion keeps the condition and drops the
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionStartError {
    /// The client's first message is not an initialize request.
    ExpectedInitializeRequest,
    /// The connection ended during the initialization handshake.
    ConnectionClosed,
    /// The initialization handshake failed for another reason.
    HandshakeFailed,
}

impl std::fmt::Display for SessionStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExpectedInitializeRequest => {
                "the MCP client must open the session with an initialize request"
            }
            Self::ConnectionClosed => "the MCP client must stay connected until the session starts",
            Self::HandshakeFailed => "the MCP session must complete the initialization handshake",
        })
    }
}

impl std::error::Error for SessionStartError {}

impl From<ServerInitializeError> for SessionStartError {
    fn from(err: ServerInitializeError) -> Self {
        match err {
            ServerInitializeError::ExpectedInitializeRequest(_) => Self::ExpectedInitializeRequest,
            ServerInitializeError::ConnectionClosed(_) => Self::ConnectionClosed,
            _ => Self::HandshakeFailed,
        }
    }
}

/// Returns the startup-refusal wire code when the active profile disables the
/// MCP surface, or `None` when the server may start.
///
/// A profile with `mcp_disabled = true` is an operator kill-switch: the MCP
/// server refuses to start so the surface cannot be used for that profile.
#[must_use]
pub fn mcp_disabled_refusal(profile: &Profile) -> Option<&'static str> {
    profile.mcp_disabled.then_some("mcp.disabled_per_profile")
}

/// The state layout a [`ProfileNameMismatch`] refusal must be rendered under on
/// this surface.
///
/// This server resolves every per-profile store through the name derived from
/// `policy_owner_key_id.service`: the signed policy file, the pending-approval
/// store (`server.rs` `profile_name_for_approval`), the policy-window state
/// (read and write), the audit log, and the counterparty cache. A refusal
/// rendered under any other layout would tell the operator something untrue
/// about their own files.
pub const STARTUP_STATE_LAYOUT: ProfileStateLayout = ProfileStateLayout::DerivedThroughout;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::{
        ProfileStateLayout, STARTUP_STATE_LAYOUT, mcp_disabled_refusal,
        profile_name_mismatch_refusal,
    };
    use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build()
    }

    /// Builds a profile whose per-profile keyring coordinates are derived from
    /// `name`, as `profile init --profile <name>` writes them.
    fn named_profile(name: &str) -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
            .with_profile_name(name)
            .build()
    }

    #[test]
    #[serial_test::serial]
    fn enabled_profile_allows_startup() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let profile = testnet_profile();
        assert!(!profile.mcp_disabled);
        assert_eq!(mcp_disabled_refusal(&profile), None);
    }

    #[test]
    #[serial_test::serial]
    fn disabled_profile_refuses_startup_with_wire_code() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut profile = testnet_profile();
        profile.mcp_disabled = true;
        assert_eq!(
            mcp_disabled_refusal(&profile),
            Some("mcp.disabled_per_profile")
        );
    }

    // ── D6: selected name vs. the name derived from the profile's contents ───

    #[test]
    #[serial_test::serial]
    fn matching_names_produce_no_refusal() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let profile = named_profile("alice");
        assert_eq!(profile_name_mismatch_refusal(&profile, "alice"), None);
    }

    #[test]
    #[serial_test::serial]
    fn copied_profile_file_refuses_without_naming_either_profile() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        // The realistic path: `default.toml` copied to `alice.toml` without
        // re-deriving its keyring coordinates.
        let profile = named_profile("default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a profile naming 'default' must not serve as 'alice'");
        let message = refusal.message(STARTUP_STATE_LAYOUT);
        assert!(
            message.contains("policy_owner_key_id.service names a different profile"),
            "refusal must name the offending field: {message}"
        );
        assert!(
            message.contains("profile init --profile <name>"),
            "refusal must name the recovery command: {message}"
        );
        assert!(
            !message.contains("alice")
                && !message.contains("'default'")
                && !message.contains("stellar-agent-owner-default"),
            "refusal must repeat neither profile name nor the stored service: {message}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn noop_engine_profile_is_checked_too() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        // The check must not be attached to the V1 policy-engine derivation:
        // Noop profiles never reach it, yet the approval-store derivation —
        // which resolves a mismatch to `default` — runs for every engine.
        let mut profile = named_profile("default");
        profile.policy.engine = PolicyEngineKind::Noop;
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a Noop-engine profile must be reconciled exactly like a V1 one");
        let message = refusal.message(STARTUP_STATE_LAYOUT);
        for rejected in ["alice", "default", "stellar-agent-owner-default"] {
            assert!(!message.contains(rejected));
        }
        assert!(
            message.contains("policy_owner_key_id.service names a different profile"),
            "refusal must name the offending field: {message}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn absent_owner_key_prefix_is_a_mismatch_not_a_default() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let mut profile = named_profile("alice");
        profile.policy_owner_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::new("hand-written", "default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a service field without the owner-key prefix must refuse");
        let message = refusal.message(STARTUP_STATE_LAYOUT);
        assert!(
            message.contains("does not carry the 'stellar-agent-owner-' prefix"),
            "refusal must explain the absent prefix: {message}"
        );
        assert!(
            !message.contains("names profile"),
            "no profile name can be derived, so none may be reported: {message}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn the_synthesised_first_run_profile_reconciles_as_default() {
        #[allow(clippy::unwrap_used, reason = "fixture sandbox setup must succeed")]
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        // The MCP server's no-name startup path loads or synthesises `default`;
        // that profile must pass the reconciliation check unchanged.
        let profile = named_profile("default");
        assert_eq!(profile_name_mismatch_refusal(&profile, "default"), None);
    }

    #[test]
    fn the_startup_layout_is_the_derived_throughout_one() {
        // This server keys signed policy, approval store, window state, audit
        // log, and counterparty cache on the derived name; a refusal rendered
        // under any other layout would misdescribe where the operator's state
        // lives.
        assert_eq!(STARTUP_STATE_LAYOUT, ProfileStateLayout::DerivedThroughout);
    }
}
