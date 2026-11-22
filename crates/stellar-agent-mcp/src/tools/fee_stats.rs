//! `stellar_fee_stats` MCP tool: fetches Stellar RPC fee statistics.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;

use crate::server::WalletServer;
use stellar_agent_network::fetch_fee_stats;

/// Arguments for the `stellar_fee_stats` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarFeeStatsArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Optional Stellar RPC URL override matching an endpoint configured on the
    /// active profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
}

#[mcp_tool_router]
#[tool_router(router = fee_stats_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Fetches Stellar RPC `getFeeStats`.
    #[mcp_tool_item(
        name = "stellar_fee_stats",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_fee_stats",
        description = "Fetch Stellar RPC getFeeStats. Returns classic inclusion_fee and \
                       soroban_inclusion_fee percentile distributions. read_only_hint=true; \
                       destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_fee_stats(
        &self,
        Parameters(args): Parameters<StellarFeeStatsArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "rpc_url_override": args.rpc_url.is_some(),
        });
        // Read-only tool: RequireApproval produces no signing material; proceed.
        if let Err(e) = self
            .dispatch_gate("stellar_fee_stats", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        let client = match self.fee_stats_client(args.rpc_url.as_deref()) {
            Ok(client) => client,
            Err(refusal) => return refusal.into_tool_outcome(),
        };

        match fetch_fee_stats(&client).await {
            Ok(view) => {
                let envelope = stellar_agent_core::envelope::Envelope::ok(view);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(err) => {
                let wallet_err = stellar_agent_core::WalletError::Network(err);
                let envelope = stellar_agent_core::envelope::Envelope::<()>::err(&wallet_err);
                let json = envelope
                    .to_json_pretty()
                    .unwrap_or_else(|_| String::from("{}"));
                let mut result = CallToolResult::success(vec![Content::text(json)]);
                result.is_error = Some(true);
                Ok(result)
            }
        }
    }
}

impl WalletServer {
    /// Builds the client `stellar_fee_stats` reads through: the profile's
    /// primary endpoint, or an `input` URL whose scheme, host, and port equal
    /// an endpoint configured on the active profile.
    ///
    /// The primary credential goes only to the profile's own `rpc_url`, so an
    /// input URL that differs from it gets a client without a credential and
    /// opens no keyring entry.
    ///
    /// # Errors
    ///
    /// Returns [`FeeStatsClientError::InvalidInput`] when `input` is invalid,
    /// carries credentials, or does not match an endpoint configured on the
    /// active profile, and [`FeeStatsClientError::Construction`] when the
    /// client cannot be built.
    fn fee_stats_client(
        &self,
        input: Option<&str>,
    ) -> Result<stellar_agent_network::StellarRpcClient, FeeStatsClientError> {
        let rpc_url = match input {
            Some(url) => {
                validate_rpc_url_for_mcp(url, &self.profile)
                    .map_err(FeeStatsClientError::InvalidInput)?;
                url
            }
            None => self.context.rpc_url.as_str(),
        };
        stellar_agent_network::profile_rpc_client(
            &self.profile,
            stellar_agent_core::profile::schema::ProviderRole::Primary,
            rpc_url,
        )
        .map_err(FeeStatsClientError::Construction)
    }
}

/// Why `stellar_fee_stats` has no client to read through.
#[derive(Debug)]
enum FeeStatsClientError {
    /// The `rpc_url` input is invalid, carries credentials, or does not match
    /// an endpoint configured on the active profile.
    InvalidInput(rmcp::ErrorData),
    /// The client could not be built: a credential failure or a transport
    /// refusal of the URL.
    Construction(stellar_agent_core::WalletError),
}

impl FeeStatsClientError {
    /// The tool outcome of the refusal: the protocol-level `invalid_params`
    /// error for an input URL, and the outcome of
    /// [`crate::tools::common::rpc_client_failure`] for a construction
    /// failure.
    fn into_tool_outcome(self) -> Result<CallToolResult, rmcp::ErrorData> {
        match self {
            Self::InvalidInput(error) => Err(error),
            Self::Construction(error) => crate::tools::common::rpc_client_failure(&error),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_fee_stats` directly for integration tests.
    #[doc(hidden)]
    pub async fn call_stellar_fee_stats(
        &self,
        args: StellarFeeStatsArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_fee_stats(Parameters(args)).await
    }
}

fn validate_rpc_url_for_mcp(
    url: &str,
    profile: &stellar_agent_core::profile::schema::Profile,
) -> Result<(), rmcp::ErrorData> {
    stellar_agent_network::validate_profile_rpc_url(url, profile)
        .map_err(|err| rmcp::ErrorData::invalid_params(format!("invalid rpc_url: {err}"), None))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stellar_agent_core::profile::schema::{
        KeyringEntryRef, PrimaryProviderRecord, Profile, Providers, RpcCredentialPlacement,
    };
    use stellar_agent_test_support::keyring_mock;

    use crate::server::WalletServer;

    const PROFILE_RPC: &str = "https://rpc.profile.example/v1";

    /// Configured profile endpoints whose URL differs from `profile.rpc_url`
    /// build a client without the primary credential and read no keyring entry;
    /// an exact match to `profile.rpc_url` (or `None`) reads the credential
    /// once. Unconfigured or credentialed inputs refuse with `INVALID_PARAMS`
    /// naming the failed rule and never the URL. Only construction runs.
    #[test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    fn fee_stats_input_url_gets_no_credential() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let entry = KeyringEntryRef::new("stellar-agent-rpc-fee-stats", "primary");
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
            &entry.service,
            &entry.account,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )])
        .unwrap();
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password("fee-stats-credential")
            .unwrap();
        let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .rpc_url(PROFILE_RPC)
            .oracle_provider_url(url::Url::parse("https://oracle.profile.example:8443/v1").unwrap())
            .with_noop_engine()
            .build();
        profile.secondary_rpc_url = Some("https://secondary.profile.example/v2".to_owned());
        let mut providers = Providers::default();
        providers.primary = Some(
            PrimaryProviderRecord::new("Primary", "rpc.profile.example").with_credential(
                entry,
                RpcCredentialPlacement::Header {
                    name: "X-API-Key".to_owned(),
                },
            ),
        );
        profile.providers = Some(providers);
        let server = WalletServer::new(profile).unwrap();

        for input in [
            "https://rpc.profile.example",
            "https://secondary.profile.example",
            "https://oracle.profile.example:8443",
        ] {
            let client = server.fee_stats_client(Some(input)).unwrap();
            assert_eq!(client.url(), input);
        }
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "no keyring read for configured endpoints that differ from profile.rpc_url"
        );

        let client = server.fee_stats_client(None).unwrap();
        assert_eq!(client.url(), PROFILE_RPC);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "the default profile endpoint reads the credential"
        );

        let client = server.fee_stats_client(Some(PROFILE_RPC)).unwrap();
        assert_eq!(client.url(), PROFILE_RPC);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "an exact match to profile.rpc_url reads the credential"
        );

        for (rejected, expected_rule) in [
            ("https://untrusted.example.com", "configured endpoint"),
            ("https://soroban-testnet.stellar.org", "configured endpoint"),
            (
                "https://user:secret@rpc.profile.example",
                "embedded credentials",
            ),
        ] {
            let err = match server.fee_stats_client(Some(rejected)) {
                Err(super::FeeStatsClientError::InvalidInput(err)) => err,
                Err(super::FeeStatsClientError::Construction(err)) => {
                    panic!("expected InvalidInput for {rejected}, got Construction({err})")
                }
                Ok(_) => panic!("expected InvalidInput for {rejected}, got Ok"),
            };
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            let msg = err.to_string();
            assert!(msg.contains(expected_rule), "{rejected}: {msg}");
            assert!(!msg.contains("allow-list"), "{rejected}: {msg}");
            assert!(!msg.contains("secret"), "{rejected}: {msg}");
            assert!(!msg.contains(rejected), "{rejected}: {msg}");
        }
    }
}
