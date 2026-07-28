//! Bounded stdio transport for the MCP JSON-RPC protocol.
//!
//! Provides `BoundedStdioTransport`, a wallet-owned `Transport<RoleServer>`
//! implementation that enforces the 1 MiB max-line bound, and the startup
//! functions that wire a `WalletServer` to it: [`build_server`] and [`serve`]
//! as separate steps, with [`run`] composing them.
//!
//! It also holds the startup refusals that are decided from the loaded profile
//! alone: [`mcp_disabled_refusal`] for the per-profile kill-switch and
//! [`profile_name_mismatch_refusal`] for a profile file whose owner-key
//! coordinate names a different profile than the one selected. The latter is
//! re-exported from `stellar-agent-core`, where it is shared with the CLI so
//! both surfaces reconcile a profile against its own name identically.

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
    serve(build_server(profile)?).await
}

/// Constructs the [`WalletServer`] for `profile` without starting the MCP loop.
///
/// Split out from [`run`] so a caller can match the typed
/// [`BuildRegistryError`] and translate it into an operator-facing recovery
/// message. `run` erases the error into `Box<dyn Error>`, and the refusal class
/// this seam exists for — an incomplete V1 ceremony — is a startup condition
/// that is only actionable when the caller can name the missing step. Matching
/// on the `Display` text instead would couple the binary to error wording.
///
/// `WalletServer::new` is fail-closed: a duplicate `McpToolRegistration` name
/// causes [`BuildRegistryError::DuplicateRegistration`], and a V1 profile whose
/// owner key, signed policy, or window state is not yet in place fails here
/// rather than serving with a degraded engine.
///
/// # Errors
///
/// Returns the [`BuildRegistryError`] produced by `WalletServer::new`.
pub fn build_server(profile: Profile) -> Result<WalletServer, BuildRegistryError> {
    WalletServer::new(profile)
}

/// Runs the MCP stdio loop for an already-constructed server until the client
/// disconnects.
///
/// # Errors
///
/// Returns a boxed error if the rmcp service encounters a fatal error during
/// initialisation or operation.
pub async fn serve(server: WalletServer) -> Result<(), Box<dyn std::error::Error>> {
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

    // ── D6: selected name vs. the name derived from the profile's contents ───

    #[test]
    fn matching_names_produce_no_refusal() {
        let profile = named_profile("alice");
        assert_eq!(profile_name_mismatch_refusal(&profile, "alice"), None);
    }

    #[test]
    fn copied_profile_file_refuses_and_names_both_profiles() {
        // The realistic path: `default.toml` copied to `alice.toml` without
        // re-deriving its keyring coordinates.
        let profile = named_profile("default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a profile naming 'default' must not serve as 'alice'");
        let message = refusal.message(STARTUP_STATE_LAYOUT);
        assert!(
            message.contains("'alice'") && message.contains("'default'"),
            "refusal must name both profiles: {message}"
        );
        assert!(
            message.contains("stellar-agent-owner-default"),
            "refusal must quote the offending policy_owner_key_id.service: {message}"
        );
        assert!(
            message.contains("profile init --profile alice"),
            "refusal must name the recovery command: {message}"
        );
    }

    #[test]
    fn noop_engine_profile_is_checked_too() {
        // The check must not be attached to the V1 policy-engine derivation:
        // Noop profiles never reach it, yet the approval-store derivation —
        // which resolves a mismatch to `default` — runs for every engine.
        let mut profile = named_profile("default");
        profile.policy.engine = PolicyEngineKind::Noop;
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a Noop-engine profile must be reconciled exactly like a V1 one");
        assert!(refusal.message(STARTUP_STATE_LAYOUT).contains("'alice'"));
    }

    #[test]
    fn absent_owner_key_prefix_is_a_mismatch_not_a_default() {
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
    fn the_synthesised_first_run_profile_reconciles_as_default() {
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
