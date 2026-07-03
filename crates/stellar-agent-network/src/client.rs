//! Typed wrapper around `stellar-rpc-client::Client` that maps upstream errors
//! into the `WalletError` taxonomy.
//!
//! `StellarRpcClient` is the single network boundary for all account queries
//! and transaction submissions.  Horizon REST is not used; all data access
//! routes through Stellar RPC.

use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_rpc_client::{Client, GetHealthResponse, GetLedgerEntriesResponse};
use stellar_xdr::LedgerKey;

use crate::fees::FeeStatsView;
use crate::redact::redact_url_authority;

/// A typed wrapper around the `stellar-rpc-client` JSON-RPC transport.
///
/// Wraps `stellar_rpc_client::Client` and converts upstream errors into
/// [`WalletError`] variants, providing a single stable error surface for all
/// network operations in this workspace.
///
/// # Construction
///
/// Use [`StellarRpcClient::new`] with the full RPC URL (e.g.
/// `"https://soroban-testnet.stellar.org"`). The URL is validated at
/// construction time.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::StellarRpcClient;
///
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")
///     .expect("valid URL");
/// ```
#[non_exhaustive]
pub struct StellarRpcClient {
    pub(crate) inner: Client,
    pub(crate) url: String,
}

impl StellarRpcClient {
    /// Constructs a new `StellarRpcClient` connected to `url`.
    ///
    /// The URL is validated by the underlying JSON-RPC transport.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::Network`] wrapping
    /// [`NetworkError::RpcUnreachable`] if `url` fails to parse as a valid
    /// HTTP/HTTPS URI.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::StellarRpcClient;
    ///
    /// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org");
    /// assert!(client.is_ok());
    /// ```
    pub fn new(url: &str) -> Result<Self, WalletError> {
        let inner = Client::new(url).map_err(|e| {
            // Redact the URL to authority-only so credentials embedded in a URL
            // (e.g. `https://user:token@rpc.example.com`) are not emitted into
            // logs or error messages.  The `NetworkError::RpcUnreachable.url`
            // field carries the redacted authority form (scheme://host\[:port\]).
            WalletError::Network(NetworkError::RpcUnreachable {
                url: redact_url_authority(url),
                reason: e.to_string(),
            })
        })?;
        Ok(Self {
            inner,
            url: url.to_owned(),
        })
    }

    /// Returns the RPC endpoint URL this client is connected to.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::StellarRpcClient;
    ///
    /// // The rpc-client normalises the URL to include the explicit port.
    /// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();
    /// assert!(client.url().contains("soroban-testnet.stellar.org"));
    /// ```
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches one or more ledger entries by key via `getLedgerEntries`.
    ///
    /// A thin public wrapper around `stellar_rpc_client::Client::get_ledger_entries`
    /// so callers outside `stellar-agent-network` do not need access to the
    /// private `inner` field.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::RpcUnreachable`] when the RPC request fails.
    /// The `url` field in the error is authority-only (scheme://host\[:port\]) to
    /// prevent credential leakage from URLs of the form `user:token@host`.
    pub async fn get_ledger_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<GetLedgerEntriesResponse, NetworkError> {
        self.inner
            .get_ledger_entries(keys)
            .await
            .map_err(|e| NetworkError::RpcUnreachable {
                url: self.redacted_url(),
                reason: format!("getLedgerEntries failed: {e}"),
            })
    }

    /// Fetches Stellar RPC `getFeeStats` and maps it to [`FeeStatsView`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] when the RPC request fails or the response
    /// cannot be mapped.  The `url` field in the error is authority-only
    /// (scheme://host\[:port\]).
    pub async fn get_fee_stats(&self) -> Result<FeeStatsView, NetworkError> {
        let response =
            self.inner
                .get_fee_stats()
                .await
                .map_err(|e| NetworkError::RpcUnreachable {
                    url: self.redacted_url(),
                    reason: e.to_string(),
                })?;
        FeeStatsView::from_rpc(&response)
    }

    /// Fetches Stellar RPC `getHealth` and returns the raw [`GetHealthResponse`].
    ///
    /// The response includes `oldest_ledger` (the retention floor) and
    /// `ledger_retention_window`. The retention-aware polling logic in
    /// `idempotent_submit` uses `oldest_ledger` to detect when a transaction
    /// has fallen outside the RPC retention window.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::RpcUnreachable`] when the RPC request fails.
    /// The `url` field in the error is authority-only (scheme://host\[:port\]).
    pub async fn get_health(&self) -> Result<GetHealthResponse, NetworkError> {
        self.inner
            .get_health()
            .await
            .map_err(|e| NetworkError::RpcUnreachable {
                url: self.redacted_url(),
                reason: format!("getHealth failed: {e}"),
            })
    }

    /// Returns the RPC endpoint URL redacted to authority-only form
    /// (scheme://host\[:port\]).
    ///
    /// Used internally to populate `NetworkError::RpcUnreachable.url` without
    /// leaking credentials that may be embedded in the full URL
    /// (e.g. `https://user:token@rpc.example.com`).
    fn redacted_url(&self) -> String {
        redact_url_authority(&self.url)
    }
}
