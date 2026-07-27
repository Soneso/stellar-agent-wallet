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
//! coordinate names a different profile than the one selected.

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
use crate::server::{OWNER_KEY_SERVICE_PREFIX, WalletServer};
use stellar_agent_core::policy::BuildRegistryError;
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

/// A loaded profile whose owner-key coordinate names a different profile than
/// the one the operator selected.
///
/// Carries both names and the offending field so the refusal can be acted on
/// without opening the TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileNameMismatch {
    /// The profile name the operator selected.
    requested: String,
    /// The name derived from `policy_owner_key_id.service`, or `None` when the
    /// field does not carry the expected prefix at all.
    derived: Option<String>,
    /// The `policy_owner_key_id.service` value as stored in the profile.
    service: String,
}

impl std::fmt::Display for ProfileNameMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            requested,
            derived,
            service,
        } = self;
        match derived {
            Some(derived) => write!(
                f,
                "profile '{requested}' was selected, but its \
                 policy_owner_key_id.service is '{service}', which names profile \
                 '{derived}'"
            )?,
            None => write!(
                f,
                "profile '{requested}' was selected, but its \
                 policy_owner_key_id.service is '{service}', which does not carry \
                 the '{OWNER_KEY_SERVICE_PREFIX}' prefix a profile name is derived \
                 from"
            )?,
        }
        write!(
            f,
            "; the signed policy file, pending-approval store, and policy-window \
             state would be read and written under the derived name, not \
             '{requested}'. A profile file renamed or copied from another profile \
             must be re-created with `stellar-agent profile init --profile \
             {requested}`, or its policy_owner_key_id.service corrected to \
             '{OWNER_KEY_SERVICE_PREFIX}{requested}'"
        )
    }
}

/// Returns a refusal when the selected profile name disagrees with the name
/// derived from the loaded profile's `policy_owner_key_id.service`, or `None`
/// when the two agree.
///
/// The server derives the name it uses for per-profile state — the signed
/// policy file, the pending-approval store, the policy-window state — from the
/// profile's *contents* rather than from the name it was loaded under. When
/// those two disagree, a profile loaded as `alice` silently reads `default`'s
/// signed policy and writes `default`'s approvals. Reconciling them at startup
/// is what keeps the selected name and the state it governs the same profile.
///
/// An absent prefix is a mismatch, not a fallback: the approval-store derivation
/// resolves a prefix-less `service` to the literal `"default"`, which is the
/// same silent cross-profile write under a different guise.
///
/// The check is independent of `profile.policy.engine`. The name derivation it
/// guards runs for every engine kind, so attaching it to the V1 policy-engine
/// path would skip Noop profiles — the zero-ceremony configuration the
/// getting-started flow recommends, and precisely the case that reaches the
/// approval-store derivation with no other guard in front of it.
#[must_use]
pub fn profile_name_mismatch_refusal(
    profile: &Profile,
    requested_name: &str,
) -> Option<ProfileNameMismatch> {
    let service = &profile.policy_owner_key_id.service;
    let derived = service.strip_prefix(OWNER_KEY_SERVICE_PREFIX);
    if derived == Some(requested_name) {
        return None;
    }
    Some(ProfileNameMismatch {
        requested: requested_name.to_owned(),
        derived: derived.map(ToOwned::to_owned),
        service: service.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::{mcp_disabled_refusal, profile_name_mismatch_refusal};
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
        let message = refusal.to_string();
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
        assert!(refusal.to_string().contains("'alice'"));
    }

    #[test]
    fn absent_owner_key_prefix_is_a_mismatch_not_a_default() {
        let mut profile = named_profile("alice");
        profile.policy_owner_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::new("hand-written", "default");
        let refusal = profile_name_mismatch_refusal(&profile, "alice")
            .expect("a service field without the owner-key prefix must refuse");
        let message = refusal.to_string();
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
}
