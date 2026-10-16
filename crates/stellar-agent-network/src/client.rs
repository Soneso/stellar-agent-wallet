//! Typed wrapper around `stellar-rpc-client::Client` that maps upstream errors
//! into the `WalletError` taxonomy.
//!
//! `StellarRpcClient` is the single network boundary for all account queries
//! and transaction submissions.  Horizon REST is not used; all data access
//! routes through Stellar RPC.

use jsonrpsee_core::ClientError;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::params::ObjectParams;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_rpc_client::{
    Client, GetHealthResponse, GetLedgerEntriesResponse, GetTransactionResponseRaw,
};
use stellar_xdr::LedgerKey;
use tokio::time::Instant;

use crate::endpoint_identity::{EndpointIdentity, check_protocol_version};
use crate::fees::FeeStatsView;
use crate::redact::{redact_rpc_error, redact_rpc_error_display, redact_url_authority};
use crate::retry::{RetryPolicy, is_retryable_identity_error, retry_with_backoff};
use crate::submit::MAINNET_PASSPHRASE;
use crate::transaction_record::TransactionRecord;

/// What the endpoint reports about one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionStatusView {
    /// The `getTransaction` status string: `SUCCESS`, `FAILED` or
    /// `NOT_FOUND`. A `NOT_FOUND` from an endpoint whose retention window no
    /// longer covers the submission proves nothing about the transaction.
    pub status: String,
    /// The ledger the transaction confirmed in, when it did.
    pub ledger: Option<u32>,
}

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
        #[cfg(feature = "test-hooks")]
        CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        let inner = Client::new(url).map_err(|e| construction_failure(url, &e))?;
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
            .map_err(|e| rpc_unreachable(&self.url, GET_LEDGER_ENTRIES_FAILED, &e))
    }

    /// Fetches Stellar RPC `getFeeStats` and maps it to [`FeeStatsView`].
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] when the RPC request fails or the response
    /// cannot be mapped.  The `url` field in the error is authority-only
    /// (scheme://host\[:port\]).
    pub async fn get_fee_stats(&self) -> Result<FeeStatsView, NetworkError> {
        let response = self
            .inner
            .get_fee_stats()
            .await
            .map_err(|e| rpc_unreachable(&self.url, "", &e))?;
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
            .map_err(|e| rpc_unreachable(&self.url, GET_HEALTH_FAILED, &e))
    }

    /// Asks the endpoint what became of one transaction.
    ///
    /// Returns the `getTransaction` status string (`SUCCESS`, `FAILED`,
    /// `NOT_FOUND`) and the ledger it confirmed in, when there is one, both
    /// read as received through [`Self::get_transaction_raw`]. No XDR field
    /// of the response is decoded, so the answer does not depend on the
    /// endpoint's result or meta encoding. This is the read a reconciliation
    /// surface makes on a transaction hash it holds.
    ///
    /// # Errors
    ///
    /// - [`NetworkError::RpcUnreachable`] when the request fails, or when
    ///   `tx_hash_hex` is not 32 hex-encoded bytes. The `url` field is
    ///   authority-only.
    pub async fn get_transaction_status(
        &self,
        tx_hash_hex: &str,
    ) -> Result<TransactionStatusView, NetworkError> {
        let bytes = stellar_agent_core::hex::decode_hex32(tx_hash_hex).map_err(|e| {
            NetworkError::RpcUnreachable {
                url: self.redacted_url(),
                reason: format!("transaction hash is not 32 hex-encoded bytes: {e}"),
            }
        })?;
        let record = self.get_transaction_raw(&stellar_xdr::Hash(bytes)).await?;
        Ok(TransactionStatusView {
            status: record.status().to_owned(),
            ledger: record.ledger(),
        })
    }

    /// Fetches one transaction via `getTransaction` without decoding any XDR.
    ///
    /// The response is read into a [`TransactionRecord`]: status, ledger,
    /// created-at and transaction hash as received, and the XDR fields decoded
    /// only by the accessor that needs them, under the wallet's untrusted
    /// decode limits.
    ///
    /// # Errors
    ///
    /// [`NetworkError::RpcUnreachable`] when the request fails or the response
    /// body is not a `getTransaction` result. The `url` field is
    /// authority-only.
    pub async fn get_transaction_raw(
        &self,
        hash: &stellar_xdr::Hash,
    ) -> Result<TransactionRecord, NetworkError> {
        self.get_transaction_record(hash)
            .await
            .map_err(|e| rpc_unreachable(&self.url, GET_TRANSACTION_FAILED, &e))
    }

    /// Issues `getTransaction` through the RPC client's JSON-RPC transport
    /// and deserializes the raw response, decoding no XDR.
    ///
    /// The `hash` parameter is inserted the way `stellar-rpc-client` inserts
    /// it (64 lowercase hex). Every failure is a jsonrpsee
    /// [`ClientError`](jsonrpsee_core::ClientError) wrapped as
    /// [`stellar_rpc_client::Error::JsonRpc`]: a transport failure, a JSON-RPC
    /// error object, or a body that does not deserialize (`ParseError`). The
    /// poll loops classify errors with
    /// [`crate::retry::is_retryable_poll_error`], which treats every
    /// `JsonRpc` error as retryable.
    #[allow(
        clippy::result_large_err,
        reason = "the poll loops classify this error with is_retryable_poll_error, which takes the RPC client's own error type"
    )]
    pub(crate) async fn get_transaction_record(
        &self,
        hash: &stellar_xdr::Hash,
    ) -> Result<TransactionRecord, stellar_rpc_client::Error> {
        let mut params = ObjectParams::new();
        params
            .insert("hash", hash)
            .map_err(|e| stellar_rpc_client::Error::JsonRpc(ClientError::ParseError(e)))?;
        let raw: GetTransactionResponseRaw = self
            .inner
            .client()
            .request("getTransaction", params)
            .await
            .map_err(stellar_rpc_client::Error::JsonRpc)?;
        Ok(TransactionRecord::from_raw(raw))
    }

    /// Asks the endpoint which network it serves and which protocol it runs,
    /// and returns that identity once it passes every check.
    ///
    /// This serves the paths that sign or send: the target network is a
    /// property of the endpoint, not of the caller's declaration, so the two
    /// must be shown to agree first. The submit layer runs it on the client
    /// instance that sends, so no second connection can answer for a
    /// different endpoint.
    ///
    /// One `getNetwork` request answers both questions. Transport failures
    /// are retried with bounded exponential backoff under `deadline`, the
    /// caller's own deadline, using the classification of `sendTransaction`
    /// ([`is_retryable_send_error`](crate::retry::is_retryable_send_error))
    /// with one exception: an answer whose body does not deserialize, for
    /// example one without `protocolVersion`, is not retried. A passphrase
    /// mismatch is not retried either.
    ///
    /// The checks run in this order: an endpoint reporting the mainnet
    /// passphrase is refused whatever `expected_passphrase` is, then a
    /// passphrase other than `expected_passphrase` is refused, then the
    /// protocol rule of [`check_protocol_version`] applies. While mainnet
    /// writes are refused, a mainnet endpoint never reaches the protocol rule,
    /// so its mainnet branch is not reachable through this method.
    ///
    /// The check is fail-closed: an endpoint whose identity cannot be
    /// established is refused rather than replaced by the caller's
    /// declaration.
    ///
    /// # Errors
    ///
    /// - [`NetworkError::EndpointIdentityUnavailable`] if the request does not
    ///   complete within `deadline`, fails for any reason other than a
    ///   passphrase verdict, or returns a body that does not deserialize.
    /// - [`NetworkError::MainnetWriteForbidden`] if the endpoint reports the
    ///   mainnet passphrase, whatever `expected_passphrase` is.
    /// - [`NetworkError::EndpointNetworkMismatch`] if the endpoint reports any
    ///   other passphrase that differs from `expected_passphrase`.
    /// - [`NetworkError::UnsupportedProtocolVersion`] if
    ///   [`check_protocol_version`] refuses the reported version.
    pub async fn endpoint_identity(
        &self,
        expected_passphrase: &str,
        deadline: Instant,
    ) -> Result<EndpointIdentity, WalletError> {
        let policy = RetryPolicy::default();
        let network =
            retry_with_backoff(&policy, deadline, is_retryable_identity_error, || async {
                self.inner.get_network().await
            })
            .await
            .map_err(|_| {
                WalletError::Network(NetworkError::EndpointIdentityUnavailable {
                    url: self.redacted_url(),
                })
            })?;

        // Agreement with a mainnet declaration is still a mainnet write.
        if network.passphrase == MAINNET_PASSPHRASE {
            return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
        }
        if network.passphrase != expected_passphrase {
            return Err(WalletError::Network(
                NetworkError::EndpointNetworkMismatch {
                    expected: expected_passphrase.to_owned(),
                    server: network.passphrase,
                },
            ));
        }

        let chain_id = Caip2::from_passphrase(&network.passphrase);
        check_protocol_version(chain_id, network.protocol_version).map_err(WalletError::Network)?;
        Ok(EndpointIdentity::checked(
            chain_id,
            network.protocol_version,
            self.redacted_url(),
        ))
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

#[cfg(feature = "test-hooks")]
thread_local! {
    /// Calls to [`StellarRpcClient::new`] on this thread, failed ones included.
    static CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Returns how many times [`StellarRpcClient::new`] has run on the calling
/// thread, failed constructions included.
///
/// A test reads it before and after one command or tool call on a
/// current-thread runtime. The difference is the number of clients that call
/// built, which shows whether its reads and its send shared one instance. The
/// count is per thread, so tests running in parallel do not disturb each other.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
#[must_use]
pub fn constructions_on_this_thread() -> usize {
    CONSTRUCTIONS.with(std::cell::Cell::get)
}

/// Builds the error for a transport that refuses to construct for `url`.
///
/// The `url` field carries the authority form (scheme://host\[:port\]). Credentials
/// embedded in a URL, for example `https://user:token@rpc.example.com`, therefore
/// reach no log or error message. The reason goes through the same scrub as
/// every other RPC failure.
fn construction_failure(url: &str, e: &stellar_rpc_client::Error) -> WalletError {
    WalletError::Network(rpc_unreachable(url, "", e))
}

/// The reason prefix of a failed `getLedgerEntries` call.
pub(crate) const GET_LEDGER_ENTRIES_FAILED: &str = "getLedgerEntries failed: ";

/// The reason prefix of a failed `getHealth` call.
const GET_HEALTH_FAILED: &str = "getHealth failed: ";

/// The reason prefix of a failed `getTransaction` call.
const GET_TRANSACTION_FAILED: &str = "getTransaction failed: ";

/// The reason prefix of an unexpected status met while recovering a stale
/// pending receipt.
pub(crate) const STALE_PENDING_RECOVERY: &str = "stale-Pending recovery: ";

/// Builds [`NetworkError::RpcUnreachable`] for a failed call to the RPC
/// endpoint at `url`.
///
/// The `url` field holds only the endpoint's scheme, host, and port. The
/// reason is `prefix` followed by the display of `e`, scrubbed with
/// [`redact_rpc_error_display`]. That display carries the server's JSON-RPC
/// error `message` and raw `data`. A server or proxy can echo the
/// credential-bearing request URL there.
pub(crate) fn rpc_unreachable(
    url: &str,
    prefix: &str,
    e: &stellar_rpc_client::Error,
) -> NetworkError {
    NetworkError::RpcUnreachable {
        url: redact_url_authority(url),
        reason: format!("{prefix}{}", redact_rpc_error_display(e)),
    }
}

/// Builds [`NetworkError::RpcUnreachable`] for a `getTransaction` answer from
/// the endpoint at `url` whose status is none of `SUCCESS`, `FAILED`, and
/// `NOT_FOUND`.
///
/// The status is the endpoint's own text, so it enters the reason scrubbed
/// with [`redact_rpc_error`], after `prefix`.
pub(crate) fn unexpected_status(url: &str, prefix: &str, status: &str) -> NetworkError {
    NetworkError::RpcUnreachable {
        url: redact_url_authority(url),
        reason: format!(
            "{prefix}unexpected getTransaction status: {}",
            redact_rpc_error(status)
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;
    use crate::redact::rpc_error_fixtures::{
        ECHOED_URL, ENDPOINT, ENDPOINT_AUTHORITY, ERROR_OBJECTS, assert_scrubbed, call_error,
    };

    fn unreachable_parts(err: NetworkError) -> (String, String) {
        match err {
            NetworkError::RpcUnreachable { url, reason } => (url, reason),
            other => panic!("expected RpcUnreachable, got {other:?}"),
        }
    }

    /// Every prefix the client's call sites pass keeps its place, and the
    /// server text after it keeps only the echoed host and port.
    #[test]
    fn rpc_unreachable_scrubs_the_server_text_after_each_prefix() {
        let prefixes = [
            "",
            GET_LEDGER_ENTRIES_FAILED,
            GET_HEALTH_FAILED,
            GET_TRANSACTION_FAILED,
        ];
        for prefix in prefixes {
            for (case, raw) in ERROR_OBJECTS {
                let (url, reason) =
                    unreachable_parts(rpc_unreachable(ENDPOINT, prefix, &call_error(raw)));
                assert_eq!(
                    url, ENDPOINT_AUTHORITY,
                    "{case}: the endpoint keeps its authority"
                );
                assert!(
                    reason.starts_with(prefix),
                    "{case}: the prefix stays: {reason}"
                );
                assert!(
                    reason.contains("ErrorObject"),
                    "{case}: the reason still names the error object: {reason}"
                );
                assert_scrubbed(case, &reason);
            }
        }
    }

    /// A construction failure whose error text holds a URL keeps only that
    /// URL's host and port in the reason, and the endpoint keeps only its
    /// authority. The error is synthetic: the mapping is the same for every
    /// error the transport returns.
    #[test]
    fn construction_failure_scrubs_its_reason() {
        let e = stellar_rpc_client::Error::InvalidUrl(format!("refused {ECHOED_URL}"));
        let WalletError::Network(err) = construction_failure(ENDPOINT, &e) else {
            panic!("a construction failure is a network error");
        };
        let (url, reason) = unreachable_parts(err);
        assert_eq!(url, ENDPOINT_AUTHORITY);
        assert_scrubbed("construction", &reason);
    }

    /// Every call to the constructor counts on the calling thread, a refused
    /// URL included, and on no other thread.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn every_construction_counts_on_the_calling_thread_only() {
        let before = constructions_on_this_thread();
        let _built = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
        let _refused = StellarRpcClient::new("https://archive example.com/rpc");
        assert_eq!(constructions_on_this_thread() - before, 2);

        let elsewhere = std::thread::spawn(|| {
            let before = constructions_on_this_thread();
            let _built = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
            constructions_on_this_thread() - before
        })
        .join()
        .unwrap();
        assert_eq!(elsewhere, 1);
        assert_eq!(
            constructions_on_this_thread() - before,
            2,
            "another thread's construction does not count here"
        );
    }

    /// A URL the transport refuses to parse fails construction with the
    /// stable code, and the credentials it carried reach neither field.
    #[test]
    fn new_with_an_unparseable_credentialed_url_reports_rpc_unreachable() {
        let err = StellarRpcClient::new("https://user:SECRET@archive example.com/rpc?token=SECRET")
            .err()
            .expect("a URL with a space in its host must not construct");
        assert_eq!(err.code(), "network.rpc_unreachable");
        let rendered = err.to_string();
        for leaked in ["SECRET", "token=", "user:"] {
            assert!(
                !rendered.contains(leaked),
                "{leaked} reached the error: {rendered}"
            );
        }
    }

    /// A status the endpoint invented enters the reason scrubbed, after the
    /// prefix and the fixed wording.
    #[test]
    fn unexpected_status_scrubs_the_status_text() {
        for prefix in ["", STALE_PENDING_RECOVERY] {
            let (url, reason) = unreachable_parts(unexpected_status(
                ENDPOINT,
                prefix,
                &format!("PENDING {ECHOED_URL}"),
            ));
            assert_eq!(url, ENDPOINT_AUTHORITY);
            assert_eq!(
                reason,
                format!(
                    "{prefix}unexpected getTransaction status: PENDING archive.example.com:8443"
                )
            );
        }
    }
}
