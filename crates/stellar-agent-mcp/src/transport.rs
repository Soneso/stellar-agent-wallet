//! Bounded stdio transport for the MCP JSON-RPC protocol.
//!
//! Provides `BoundedStdioTransport`, a wallet-owned `Transport<RoleServer>`
//! implementation that enforces the 1 MiB max-line bound, and the `run` async
//! function that wires a `WalletServer` to the transport and runs the MCP loop.

use futures::{SinkExt, StreamExt};
use rmcp::{
    RoleServer, ServiceExt,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{
        Transport,
        async_rw::{JsonRpcMessageCodec, JsonRpcMessageCodecError},
    },
};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::STELLAR_AGENT_MCP_MAX_LINE_BYTES;
use crate::server::WalletServer;
use stellar_agent_core::profile::schema::Profile;

// ─────────────────────────────────────────────────────────────────────────────
// Type aliases for BoundedStdioTransport internals
// ─────────────────────────────────────────────────────────────────────────────

/// Codec-framed writer for the bounded stdio transport.
type BoundedWriter =
    FramedWrite<tokio::io::Stdout, JsonRpcMessageCodec<TxJsonRpcMessage<RoleServer>>>;

/// Codec-framed reader for the bounded stdio transport.
type BoundedReader =
    FramedRead<tokio::io::Stdin, JsonRpcMessageCodec<RxJsonRpcMessage<RoleServer>>>;

// ─────────────────────────────────────────────────────────────────────────────
// BoundedStdioTransport — max-line mitigation
// ─────────────────────────────────────────────────────────────────────────────

/// A custom `Transport` implementation that enforces the 1 MiB max-line bound.
///
/// This type wraps `FramedRead<Stdin, JsonRpcMessageCodec>` and
/// `FramedWrite<Stdout, JsonRpcMessageCodec>` constructed with
/// `JsonRpcMessageCodec::new_with_max_length(STELLAR_AGENT_MCP_MAX_LINE_BYTES)`,
/// bypassing the default `usize::MAX` codec that `AsyncRwTransport::new` uses.
///
/// # Implements
///
/// `rmcp::transport::Transport<RoleServer>` — the trait required by
/// `ServiceExt::serve` to drive the MCP JSON-RPC loop.
pub struct BoundedStdioTransport {
    read: BoundedReader,
    write: Arc<TokioMutex<Option<BoundedWriter>>>,
}

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
        let codec_rx = JsonRpcMessageCodec::<RxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        let codec_tx = JsonRpcMessageCodec::<TxJsonRpcMessage<RoleServer>>::new_with_max_length(
            STELLAR_AGENT_MCP_MAX_LINE_BYTES,
        );
        Self {
            read: FramedRead::new(tokio::io::stdin(), codec_rx),
            write: Arc::new(TokioMutex::new(Some(FramedWrite::new(
                tokio::io::stdout(),
                codec_tx,
            )))),
        }
    }
}

impl Transport<RoleServer> for BoundedStdioTransport {
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
                    result
                        .inspect_err(|err| {
                            tracing::error!(
                                error = %err,
                                "stellar-agent-mcp: JSON-RPC frame error \
                                 (max-line bound or parse failure)"
                            );
                        })
                        .ok()
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
/// `rmcp::ServiceExt::serve` with the `WalletServer` handler.
///
/// # Errors
///
/// Returns a boxed error if the rmcp service encounters a fatal error during
/// initialisation or operation.
pub async fn run(profile: Profile) -> Result<(), Box<dyn std::error::Error>> {
    // ── Max-line mitigation: BoundedStdioTransport with 1 MiB max-line bound ──
    // Do NOT use `.serve(rmcp::transport::stdio())` or `.serve((stdin, stdout))`
    // — those paths call `AsyncRwTransport::new` which internally uses
    // `JsonRpcMessageCodec::default()` (max_length = usize::MAX, a DoS surface).
    //
    // `BoundedStdioTransport` is a wallet-owned `Transport<RoleServer>` impl
    // that constructs both codec instances with explicit
    // `JsonRpcMessageCodec::new_with_max_length(STELLAR_AGENT_MCP_MAX_LINE_BYTES)`.
    // It is passed directly to `.serve()`, which accepts any `T: IntoTransport`
    // and the blanket impl `T: Transport<Role> => T: IntoTransport` applies.
    //
    // Verification point: the codec construction is in
    // `BoundedStdioTransport::new()` above in this file; the `default()`
    // constructor is never called.
    let transport = BoundedStdioTransport::new();
    // WalletServer::new is fallible (fail-closed): a duplicate
    // McpToolRegistration name causes Err(BuildRegistryError::DuplicateRegistration).
    let server = WalletServer::new(profile)?;

    let service = server.serve(transport).await?;

    tracing::info!("stellar-agent-mcp: MCP server ready");
    service.waiting().await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::mcp_disabled_refusal;
    use stellar_agent_core::profile::schema::Profile;

    fn testnet_profile() -> Profile {
        Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct").build()
    }

    #[test]
    fn enabled_profile_allows_startup() {
        let profile = testnet_profile();
        assert!(!profile.mcp_disabled);
        assert_eq!(mcp_disabled_refusal(&profile), None);
    }

    #[test]
    fn disabled_profile_refuses_startup_with_wire_code() {
        let mut profile = testnet_profile();
        profile.mcp_disabled = true;
        assert_eq!(
            mcp_disabled_refusal(&profile),
            Some("mcp.disabled_per_profile")
        );
    }
}
