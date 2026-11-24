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

use futures::SinkExt;
use rmcp::{
    ErrorData, RoleServer, ServiceExt,
    service::{RxJsonRpcMessage, ServerInitializeError, TxJsonRpcMessage},
    transport::{
        Transport,
        async_rw::{JsonRpcMessageCodec, JsonRpcMessageCodecError},
    },
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, FramedWrite};
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

// ─────────────────────────────────────────────────────────────────────────────
// BoundedTransport: max-line mitigation
// ─────────────────────────────────────────────────────────────────────────────

/// A custom `Transport` implementation that enforces the 1 MiB max-line bound.
///
/// The reader reads one line at a time and holds at most
/// [`STELLAR_AGENT_MCP_MAX_LINE_BYTES`] of it. Each complete line is parsed by
/// a `JsonRpcMessageCodec` constructed with
/// `JsonRpcMessageCodec::new_with_max_length(STELLAR_AGENT_MCP_MAX_LINE_BYTES)`,
/// and the writer is a `FramedWrite<W, JsonRpcMessageCodec>` built the same
/// way, bypassing the default `usize::MAX` codec that `AsyncRwTransport::new`
/// uses. rmcp's encoder does not check `max_length`, so outbound frames are
/// not bounded.
///
/// A line that is empty or holds only `\r` is skipped. A line that is not a
/// JSON-RPC message, or one over the bound, is answered with a JSON-RPC
/// `-32700` error without an `id`, and the transport reads the next line. A
/// line that is not a JSON-RPC message and holds a `method` the server does
/// not know and no `id` is skipped without an answer, under rmcp's
/// compatibility parse. A line that is not a JSON-RPC message and holds an
/// `id` and a `notifications/` method the server does not know is skipped too.
/// A JSON-RPC notification with a method the server does not know is returned
/// as a message. The session ends at end of input, on a read error, or when an
/// answer cannot be written.
///
/// # Implements
///
/// `rmcp::transport::Transport<RoleServer>` — the trait required by
/// `ServiceExt::serve` to drive the MCP JSON-RPC loop.
pub struct BoundedTransport<R, W> {
    read: BufReader<R>,
    codec: JsonRpcMessageCodec<RxJsonRpcMessage<RoleServer>>,
    /// The bytes of the current line read so far, at most the bound.
    line: Vec<u8>,
    /// Whether the current line is over the bound and is being discarded up to
    /// its newline.
    discarding: bool,
    /// The answer to a refused line that is not yet handed to the writer.
    ///
    /// rmcp drops a pending `receive` when another event wins its select, so
    /// the answer stays here until the writer takes it, and the next `receive`
    /// writes it.
    answer: Option<TxJsonRpcMessage<RoleServer>>,
    /// Whether an answer is handed to the writer and its flush has not yet
    /// completed. A `receive` dropped during the flush leaves it set, and the
    /// next `receive` finishes the flush before it reads.
    flush_owed: bool,
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
    ///
    /// The bound applies to inbound lines. rmcp's encoder does not check
    /// `max_length`, so the server's own outbound frames are not bounded.
    #[must_use]
    pub fn over(read: R, write: W) -> Self {
        let codec_rx = JsonRpcMessageCodec::<RxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        let codec_tx = JsonRpcMessageCodec::<TxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        Self {
            read: BufReader::new(read),
            codec: codec_rx,
            line: Vec::new(),
            discarding: false,
            answer: None,
            flush_owed: false,
            write: Arc::new(TokioMutex::new(Some(FramedWrite::new(write, codec_tx)))),
        }
    }
}

/// The `-32700` answer, without an `id`, to a line that is not a JSON-RPC
/// message.
fn parse_error_answer() -> TxJsonRpcMessage<RoleServer> {
    TxJsonRpcMessage::<RoleServer>::error(ErrorData::parse_error("Parse error", None), None)
}

/// The `-32700` answer, without an `id`, to a line over the line limit.
fn line_limit_answer() -> TxJsonRpcMessage<RoleServer> {
    TxJsonRpcMessage::<RoleServer>::error(
        ErrorData::parse_error(
            format!("the frame exceeds the line limit of {STELLAR_AGENT_MCP_MAX_LINE_BYTES} bytes"),
            None,
        ),
        None,
    )
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> BoundedTransport<R, W> {
    /// Parses one complete line without its newline.
    ///
    /// Returns the message, or `None` for a line that is skipped or refused.
    /// A refused line leaves its answer in `self.answer`.
    fn parse_line(&mut self, line: &[u8]) -> Option<RxJsonRpcMessage<RoleServer>> {
        if line.is_empty() || line == b"\r" {
            return None;
        }
        let mut frame = BytesMut::with_capacity(line.len() + 1);
        frame.extend_from_slice(line);
        frame.extend_from_slice(b"\n");
        // The frame holds one complete line within the bound, so the codec
        // either parses it, skips it under rmcp's compatibility rule
        // (`Ok(None)`), or returns its `Serde` error.
        match self.codec.decode(&mut frame) {
            Ok(message) => message,
            Err(err) => {
                log_frame_error(&err);
                self.answer = Some(parse_error_answer());
                None
            }
        }
    }

    /// Hands the pending answer to the shared writer, under its lock, and
    /// flushes it, or finishes the owed flush of an answer handed over before.
    ///
    /// The answer leaves `self.answer` only once the writer is ready to take
    /// it, and `self.flush_owed` stays set from the hand-over until the flush
    /// completes, so a call dropped at any await leaves the rest to the next
    /// one. Returns `false` when the writer is closed or a write fails.
    async fn write_answer(&mut self) -> bool {
        let lock = Arc::clone(&self.write);
        let mut guard = lock.lock().await;
        let Some(writer) = guard.as_mut() else {
            return false;
        };
        if futures::future::poll_fn(|cx| writer.poll_ready_unpin(cx))
            .await
            .is_err()
        {
            return false;
        }
        // With no answer left, the call only finishes an owed flush.
        if let Some(answer) = self.answer.take() {
            if writer.start_send_unpin(answer).is_err() {
                return false;
            }
            self.flush_owed = true;
        }
        if writer.flush().await.is_err() {
            return false;
        }
        self.flush_owed = false;
        true
    }

    /// Reads the next message, skipping and answering refused lines.
    async fn next_message(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            if (self.answer.is_some() || self.flush_owed) && !self.write_answer().await {
                return None;
            }
            let chunk = match self.read.fill_buf().await {
                Ok(chunk) => chunk,
                Err(err) => {
                    log_frame_error(&JsonRpcMessageCodecError::Io(err));
                    return None;
                }
            };
            if chunk.is_empty() {
                // End of input. A last line without its newline is still a
                // line; once it is parsed, the next pass ends the session. A
                // discarded line holds no bytes.
                if self.line.is_empty() {
                    return None;
                }
                let line = std::mem::take(&mut self.line);
                if let Some(message) = self.parse_line(&line) {
                    return Some(message);
                }
                continue;
            }
            let newline = chunk.iter().position(|byte| *byte == b'\n');
            let taken = newline.unwrap_or(chunk.len());
            let over_limit =
                !self.discarding && self.line.len() + taken > STELLAR_AGENT_MCP_MAX_LINE_BYTES;
            if !self.discarding && !over_limit {
                self.line.extend_from_slice(&chunk[..taken]);
            }
            self.read
                .consume(newline.map_or(taken, |offset| offset + 1));
            if over_limit {
                self.line = Vec::new();
                self.discarding = true;
                log_frame_error(&JsonRpcMessageCodecError::MaxLineLengthExceeded);
                self.answer = Some(line_limit_answer());
            }
            // The newline ends a discarded line without parsing it.
            if newline.is_some() && !std::mem::replace(&mut self.discarding, false) {
                let line = std::mem::take(&mut self.line);
                if let Some(message) = self.parse_line(&line) {
                    return Some(message);
                }
            }
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

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        self.next_message().await
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
    /// The client's first message other than a `ping` request is not an
    /// initialize request.
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
mod receive_tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::BoundedTransport;
    use crate::STELLAR_AGENT_MCP_MAX_LINE_BYTES;
    use rmcp::transport::Transport;
    use serde_json::{Value, json};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{
        AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader, DuplexStream, ReadHalf,
        WriteHalf,
    };

    type Peer = (BufReader<ReadHalf<DuplexStream>>, WriteHalf<DuplexStream>);

    /// A transport over an in-memory stream and the peer's two halves.
    fn transport() -> (
        BoundedTransport<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>,
        Peer,
    ) {
        let (server, client) = tokio::io::duplex(4 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let (client_read, client_write) = tokio::io::split(client);
        (
            BoundedTransport::over(server_read, server_write),
            (BufReader::new(client_read), client_write),
        )
    }

    fn ping(id: u64) -> String {
        json!({ "jsonrpc": "2.0", "id": id, "method": "ping" }).to_string()
    }

    async fn received_id(
        transport: &mut BoundedTransport<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>,
    ) -> Option<Value> {
        transport
            .receive()
            .await
            .map(|message| serde_json::to_value(message).unwrap()["id"].clone())
    }

    /// Every line the transport wrote, read after the transport is dropped.
    async fn written(peer: &mut Peer) -> Vec<Value> {
        let mut written = String::new();
        peer.0.read_to_string(&mut written).await.unwrap();
        written
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn line_limit_error() -> Value {
        json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message":
            format!("the frame exceeds the line limit of {STELLAR_AGENT_MCP_MAX_LINE_BYTES} bytes") } })
    }

    /// A line of exactly the bound is read; one byte more is refused with the
    /// line limit and the next line is read.
    #[tokio::test]
    async fn the_bound_admits_a_line_of_its_length_alone() {
        let (mut transport, mut peer) = transport();
        let mut exact = ping(1);
        exact.push_str(&" ".repeat(STELLAR_AGENT_MCP_MAX_LINE_BYTES - exact.len()));
        let mut over = ping(2);
        over.push_str(&" ".repeat(STELLAR_AGENT_MCP_MAX_LINE_BYTES + 1 - over.len()));
        let input = format!("{exact}\n{over}\n{}\n", ping(3));
        peer.1.write_all(input.as_bytes()).await.unwrap();

        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        assert_eq!(received_id(&mut transport).await, Some(json!(3)));
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(written(&mut peer).await, [line_limit_error()]);
    }

    /// A last line without its newline is read at end of input, and the next
    /// receive ends the session.
    #[tokio::test]
    async fn a_last_line_without_its_newline_is_read() {
        let (mut transport, mut peer) = transport();
        peer.1.write_all(ping(1).as_bytes()).await.unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        assert_eq!(received_id(&mut transport).await, None);
    }

    /// A malformed last line without its newline is answered before the
    /// session ends.
    #[tokio::test]
    async fn a_malformed_last_line_is_answered_before_the_end() {
        let (mut transport, mut peer) = transport();
        peer.1.write_all(b"{").await.unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(
            written(&mut peer).await,
            [json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "Parse error" } })]
        );
    }

    /// Input that ends inside a line over the bound is answered once and ends
    /// the session. The line runs three read chunks past the bound, so bytes
    /// arrive after the refusal.
    #[tokio::test]
    async fn input_that_ends_inside_an_oversized_line_ends_the_session() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(&vec![b'x'; STELLAR_AGENT_MCP_MAX_LINE_BYTES + 3 * 8192])
            .await
            .unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(written(&mut peer).await, [line_limit_error()]);
    }

    /// An empty line and a line that holds only `\r` get no answer.
    #[tokio::test]
    async fn an_empty_or_carriage_return_line_gets_no_answer() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(format!("\n\r\n{}\n", ping(1)).as_bytes())
            .await
            .unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(written(&mut peer).await, Vec::<Value>::new());
    }

    /// A frame that rmcp's compatibility parse skips gets no answer.
    #[tokio::test]
    async fn a_skipped_notification_gets_no_answer() {
        let (mut transport, mut peer) = transport();
        // rmcp's model parses a custom notification, so the skipped frame is
        // a notification of another protocol that the model refuses.
        let input = format!(
            "{}\n{}\n",
            json!({ "method": "textDocument/didOpen", "params": {} }),
            ping(1)
        );
        peer.1.write_all(input.as_bytes()).await.unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(written(&mut peer).await, Vec::<Value>::new());
    }

    /// An answer that waits for the writer survives a dropped receive and is
    /// written once by the next one.
    #[tokio::test]
    async fn a_dropped_receive_keeps_its_answer() {
        let (mut transport, mut peer) = transport();
        peer.1.write_all(b"{\n").await.unwrap();
        let lock = std::sync::Arc::clone(&transport.write);
        let guard = lock.lock().await;
        let waiting = tokio::time::timeout(Duration::from_millis(50), transport.receive()).await;
        assert!(waiting.is_err(), "the receive waits for the writer");
        drop(guard);
        drop(lock);
        peer.1
            .write_all(format!("{}\n", ping(1)).as_bytes())
            .await
            .unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        peer.1.shutdown().await.unwrap();
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(
            written(&mut peer).await,
            [json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "Parse error" } })]
        );
    }

    /// A valid message and a refused line that end in `\r\n` are served and
    /// answered like their `\n` forms.
    #[tokio::test]
    async fn lines_that_end_in_crlf_are_served_and_answered() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(format!("{{\r\n{}\r\n", ping(1)).as_bytes())
            .await
            .unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(
            written(&mut peer).await,
            [json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "Parse error" } })]
        );
    }

    /// A line whose newline arrives many reads after it crossed the bound is
    /// answered once, and the valid line after it is read.
    #[tokio::test]
    async fn a_late_newline_after_the_bound_ends_the_discarded_line() {
        let (mut transport, mut peer) = transport();
        let mut input = vec![b'x'; STELLAR_AGENT_MCP_MAX_LINE_BYTES + 50_000];
        input.push(b'\n');
        input.extend_from_slice(format!("{}\n", ping(3)).as_bytes());
        peer.1.write_all(&input).await.unwrap();
        peer.1.shutdown().await.unwrap();

        assert_eq!(received_id(&mut transport).await, Some(json!(3)));
        assert_eq!(received_id(&mut transport).await, None);
        drop(transport);
        assert_eq!(written(&mut peer).await, [line_limit_error()]);
    }

    /// The shared state of a [`GatedWriter`].
    #[derive(Default)]
    struct Gate {
        open: bool,
        written: Vec<u8>,
        waker: Option<std::task::Waker>,
    }

    /// A writer that is pending on every write and flush while its gate is
    /// closed.
    struct GatedWriter(std::sync::Arc<std::sync::Mutex<Gate>>);

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut gate = self.0.lock().unwrap();
            if !gate.open {
                gate.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            gate.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let mut gate = self.0.lock().unwrap();
            if !gate.open {
                gate.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// An answer whose flush is pending when the receive is dropped is
    /// written by the next receive before it returns the next message.
    #[tokio::test]
    async fn a_receive_dropped_during_the_flush_leaves_the_flush_owed() {
        let (server, client) = tokio::io::duplex(1 << 10);
        let (_client_read, mut client_write) = tokio::io::split(client);
        let gate = std::sync::Arc::new(std::sync::Mutex::new(Gate::default()));
        let mut transport =
            BoundedTransport::over(server, GatedWriter(std::sync::Arc::clone(&gate)));
        client_write
            .write_all(format!("{{\n{}\n", ping(1)).as_bytes())
            .await
            .unwrap();

        let waiting = tokio::time::timeout(Duration::from_millis(50), transport.receive()).await;
        assert!(waiting.is_err(), "the receive waits for the flush");
        assert!(gate.lock().unwrap().written.is_empty());
        {
            let mut open = gate.lock().unwrap();
            open.open = true;
            if let Some(waker) = open.waker.take() {
                waker.wake();
            }
        }

        let id = transport
            .receive()
            .await
            .map(|message| serde_json::to_value(message).unwrap()["id"].clone());
        let written: Vec<Value> = String::from_utf8(gate.lock().unwrap().written.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            written,
            [json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "Parse error" } })]
        );
        assert_eq!(id, Some(json!(1)));
    }

    /// Once an answer is flushed, no flush is owed: a later valid line is read
    /// while the writer is held by a send.
    #[tokio::test]
    async fn a_flushed_answer_leaves_no_flush_owed() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(format!("{{\n{}\n{}\n", ping(1), ping(2)).as_bytes())
            .await
            .unwrap();
        assert_eq!(received_id(&mut transport).await, Some(json!(1)));
        let lock = std::sync::Arc::clone(&transport.write);
        let _guard = lock.lock().await;

        let read = tokio::time::timeout(Duration::from_secs(5), received_id(&mut transport)).await;
        assert_eq!(read.ok(), Some(Some(json!(2))));
    }

    /// With no answer pending, a valid line is read while the writer is held
    /// by a send.
    #[tokio::test]
    async fn a_valid_line_is_read_while_the_writer_is_busy() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(format!("{}\n", ping(1)).as_bytes())
            .await
            .unwrap();
        let lock = std::sync::Arc::clone(&transport.write);
        let _guard = lock.lock().await;

        let read = tokio::time::timeout(Duration::from_secs(5), received_id(&mut transport)).await;
        assert_eq!(read.ok(), Some(Some(json!(1))));
    }

    /// A writer that fails every write.
    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::other("write refused")))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("flush refused")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// An answer that cannot be written ends the session.
    #[tokio::test]
    async fn an_answer_that_cannot_be_written_ends_the_session() {
        let (server, client) = tokio::io::duplex(1 << 10);
        let (_client_read, mut client_write) = tokio::io::split(client);
        let mut transport = BoundedTransport::over(server, FailingWriter);
        client_write
            .write_all(format!("{{\n{}\n", ping(1)).as_bytes())
            .await
            .unwrap();

        assert!(transport.receive().await.is_none());
    }

    /// An answer after the transport is closed ends the session.
    #[tokio::test]
    async fn an_answer_after_close_ends_the_session() {
        let (mut transport, mut peer) = transport();
        peer.1
            .write_all(format!("{{\n{}\n", ping(1)).as_bytes())
            .await
            .unwrap();
        transport.close().await.unwrap();

        assert_eq!(received_id(&mut transport).await, None);
    }
}

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
