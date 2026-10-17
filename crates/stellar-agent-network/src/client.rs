//! Typed wrapper around `stellar-rpc-client::Client` that maps upstream errors
//! into the `WalletError` taxonomy.
//!
//! `StellarRpcClient` is the single network boundary for all account queries
//! and transaction submissions.  Horizon REST is not used; all data access
//! routes through Stellar RPC.

use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee_core::ClientError;
use jsonrpsee_core::client::ClientT;
use jsonrpsee_core::params::ObjectParams;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::{
    RpcCredentialDefect, RpcCredentialPlacement, check_rpc_credential_placement,
    check_rpc_credential_value,
};
use stellar_rpc_client::{
    Client, GetHealthResponse, GetLedgerEntriesResponse, GetTransactionResponseRaw,
    SimulateTransactionResponse,
};
use stellar_xdr::{LedgerKey, TransactionEnvelope};
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

use crate::endpoint_identity::{EndpointIdentity, check_protocol_version};
use crate::fees::FeeStatsView;
use crate::redact::{redact_rpc_error, redact_url_authority};
use crate::retry::{RetryPolicy, is_retryable_identity_error, rejected_status, retry_with_backoff};
use crate::submit::MAINNET_PASSPHRASE;
use crate::transaction_record::TransactionRecord;

/// The text that replaces a credential in an error or log text.
const REDACTED_CREDENTIAL: &str = "[redacted]";

/// The shortest token after a header value's scheme prefix that the scrub
/// removes on its own. Shorter tokens are common words that would garble
/// unrelated text.
const MIN_SCRUBBED_HEADER_TOKEN_BYTES: usize = 8;

/// The endpoint a client sends to: the configured URL, which never holds the
/// keyring credential, and the forms of that credential that the client's
/// error texts must not carry.
///
/// Every error the client builds from transport or server text passes
/// [`RpcEndpoint::scrub`]: each credential form is replaced first, then every
/// URL keeps only its host and port. The forms are the stored value, the
/// form-urlencoded value of a query placement, the percent-encoded segment of
/// a path placement, and for a header value with a scheme prefix the token
/// after the first space when it holds at least
/// [`MIN_SCRUBBED_HEADER_TOKEN_BYTES`] bytes. Each form lives in a
/// [`Zeroizing`] holder.
pub(crate) struct RpcEndpoint {
    url: String,
    secrets: Vec<Zeroizing<String>>,
}

impl RpcEndpoint {
    /// An endpoint without a credential.
    pub(crate) fn plain(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            secrets: Vec::new(),
        }
    }

    /// An endpoint whose requests carry `value` at `placement`. The value
    /// itself is kept as one of the credential forms.
    pub(crate) fn credentialed(
        url: &str,
        value: Zeroizing<String>,
        placement: &RpcCredentialPlacement,
    ) -> Self {
        let mut secrets = Vec::with_capacity(2);
        match placement {
            RpcCredentialPlacement::Query { .. } => secrets.push(Zeroizing::new(
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect(),
            )),
            RpcCredentialPlacement::Path {} => {
                if let Some(segment) = encoded_path_segment(&value) {
                    secrets.push(segment);
                }
            }
            RpcCredentialPlacement::Header { .. } => {
                if let Some((_, token)) = value.split_once(' ')
                    && token.len() >= MIN_SCRUBBED_HEADER_TOKEN_BYTES
                {
                    secrets.push(Zeroizing::new(token.to_owned()));
                }
            }
            // A placement kind this client does not build refuses in
            // `with_credential`, so only the stored value applies.
            _ => {}
        }
        secrets.push(value);
        // Longer forms first, so a shorter form inside a longer one never
        // leaves a fragment of the longer one behind.
        secrets.sort_by_key(|form| std::cmp::Reverse(form.len()));
        secrets.dedup();
        Self {
            url: url.to_owned(),
            secrets,
        }
    }

    /// The configured endpoint URL, without the keyring credential.
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }

    /// The configured URL redacted to scheme, host, and port.
    pub(crate) fn authority(&self) -> String {
        redact_url_authority(&self.url)
    }

    /// Replaces every credential form in `text`, leaving URLs as they are.
    pub(crate) fn redact_credential(&self, text: &str) -> String {
        let mut out = Zeroizing::new(text.to_owned());
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = Zeroizing::new(out.replace(secret.as_str(), REDACTED_CREDENTIAL));
            }
        }
        out.as_str().to_owned()
    }

    /// Replaces every credential form in `text`, then keeps only host and
    /// port of every URL in it.
    pub(crate) fn scrub(&self, text: &str) -> String {
        redact_rpc_error(&self.redact_credential(text))
    }

    /// [`Self::scrub`] applied to the display of `error`.
    pub(crate) fn scrub_display(&self, error: &impl std::fmt::Display) -> String {
        self.scrub(&Zeroizing::new(error.to_string()))
    }
}

/// The percent-encoded form the URL path takes for `value` as one segment.
fn encoded_path_segment(value: &str) -> Option<Zeroizing<String>> {
    let mut probe = Url::parse("http://segment.invalid/").ok()?;
    probe.path_segments_mut().ok()?.clear().push(value);
    let encoded = Zeroizing::new(String::from(probe));
    encoded
        .strip_prefix("http://segment.invalid/")
        .map(|segment| Zeroizing::new(segment.to_owned()))
}

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
/// `"https://soroban-testnet.stellar.org"`), or
/// [`StellarRpcClient::with_credential`] for an endpoint that requires a
/// provider credential. The URL is validated at construction time.
///
/// The type implements neither `Debug` nor `Clone`: the inner transport
/// prints its target URL, which holds a query or path credential, and a
/// credential is never copied out of the client.
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
    pub(crate) url: RpcEndpoint,
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
        let endpoint = RpcEndpoint::plain(url);
        let inner = Client::new(url).map_err(|e| construction_failure(&endpoint, &e))?;
        Ok(Self {
            inner,
            url: endpoint,
        })
    }

    /// Constructs a client whose every request carries the provider
    /// credential `value` at `placement`.
    ///
    /// The value and the placement are checked again here: the value with
    /// [`check_rpc_credential_value`], the placement with
    /// [`check_rpc_credential_placement`]. The transport sends a URL password
    /// as Basic authentication, so a URL with a username or password is
    /// refused.
    ///
    /// - A header placement sends `value` as the value of the named header,
    ///   marked sensitive so that its `Debug` form hides it, on the URL as
    ///   given.
    /// - A query placement appends `name=value` to the query, form-urlencoded.
    /// - A path placement appends `value` to the path as one percent-encoded
    ///   segment. A configured path ending in `/`, a bare host included,
    ///   keeps a trailing slash after the segment: `https://h/` becomes
    ///   `https://h/KEY/` and `https://h/v2` becomes `https://h/v2/KEY`.
    ///
    /// [`Self::url`] returns `url` as given, never the URL with the
    /// credential. Every error the client returns has the credential forms
    /// replaced before URLs are redacted (see the type's error contract).
    ///
    /// # Errors
    ///
    /// - [`NetworkError::RpcCredentialUnusable`] when the value or the
    ///   placement breaks its rules, or `url` carries a username or password.
    /// - [`NetworkError::RpcUnreachable`] when `url` does not parse as an
    ///   HTTP or HTTPS URL. The error carries only the URL's authority.
    pub fn with_credential(
        url: &str,
        placement: &RpcCredentialPlacement,
        value: Zeroizing<String>,
    ) -> Result<Self, WalletError> {
        #[cfg(feature = "test-hooks")]
        CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        let unusable =
            |reason| WalletError::Network(NetworkError::RpcCredentialUnusable { reason });
        check_rpc_credential_value(&value).map_err(unusable)?;
        check_rpc_credential_placement(placement)
            .map_err(|_| unusable(RpcCredentialDefect::Placement))?;
        let invalid_url = |reason: String| {
            WalletError::Network(NetworkError::RpcUnreachable {
                url: redact_url_authority(url),
                reason,
            })
        };
        let parsed = Url::parse(url).map_err(|e| invalid_url(format!("invalid URL: {e}")))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(unusable(RpcCredentialDefect::Userinfo));
        }
        let built = match placement {
            RpcCredentialPlacement::Header { name } => {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| unusable(RpcCredentialDefect::Placement))?;
                let mut header = HeaderValue::from_str(&value)
                    .map_err(|_| unusable(RpcCredentialDefect::ControlCharacter))?;
                header.set_sensitive(true);
                let mut headers = HeaderMap::new();
                headers.insert(name, header);
                Client::new_with_headers(url, headers)
            }
            RpcCredentialPlacement::Query { name } => {
                let mut target = parsed;
                target.query_pairs_mut().append_pair(name, &value);
                let target = Zeroizing::new(String::from(target));
                Client::new(&target)
            }
            RpcCredentialPlacement::Path {} => {
                let trailing_slash = parsed.path().ends_with('/');
                let mut target = parsed;
                {
                    let mut segments = target.path_segments_mut().map_err(|()| {
                        invalid_url("the URL has no path to carry the credential".to_owned())
                    })?;
                    segments.pop_if_empty().push(&value);
                    if trailing_slash {
                        segments.push("");
                    }
                }
                let target = Zeroizing::new(String::from(target));
                Client::new(&target)
            }
            _ => return Err(unusable(RpcCredentialDefect::Placement)),
        };
        let endpoint = RpcEndpoint::credentialed(url, value, placement);
        let inner = built.map_err(|e| construction_failure(&endpoint, &e))?;
        Ok(Self {
            inner,
            url: endpoint,
        })
    }

    /// Returns the configured RPC endpoint URL of this client.
    ///
    /// This is the URL passed to the constructor, never a URL with a keyring
    /// credential interpolated into its query or path.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_network::StellarRpcClient;
    ///
    /// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();
    /// assert_eq!(client.url(), "https://soroban-testnet.stellar.org");
    /// ```
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
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

    /// Fetches Stellar RPC `getHealth`, retrying transport failures until
    /// `deadline`.
    ///
    /// The retries follow the classification of
    /// [`Self::endpoint_identity`]: a transport failure or a JSON-RPC error
    /// object is retried with bounded exponential backoff under `deadline`,
    /// the caller's own deadline. An answer whose body does not deserialize,
    /// for example one without `ledgerRetentionWindow`, is not retried, and
    /// neither is an HTTP 401 or 403 answer. The answer is returned as
    /// received; judging its `status` is the caller's part.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::RpcUnreachable`] when no attempt succeeds before
    /// `deadline` or the retries run out, or when the answer does not
    /// deserialize. The `url` field is authority-only and the reason is
    /// scrubbed of credential-bearing URLs.
    pub async fn get_health_within(
        &self,
        deadline: Instant,
    ) -> Result<GetHealthResponse, NetworkError> {
        let policy = RetryPolicy::default();
        retry_with_backoff(&policy, deadline, is_retryable_identity_error, || async {
            self.inner.get_health().await
        })
        .await
        .map_err(|e| rpc_unreachable(&self.url, GET_HEALTH_FAILED, &e))
    }

    /// Simulates `envelope` through Stellar RPC `simulateTransaction`.
    ///
    /// The request carries the envelope as given and no `authMode` field, so
    /// the endpoint applies its own default mode. The answer is returned as
    /// received; every check of its content is the caller's part.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::RpcUnreachable`] when the envelope does not
    /// encode, the request fails, or the answer does not deserialize. The
    /// `url` field is authority-only and the reason is scrubbed of
    /// credential-bearing URLs.
    pub async fn simulate_transaction_envelope(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, NetworkError> {
        let mut response = self
            .inner
            .simulate_transaction_envelope(envelope, None)
            .await
            .map_err(|e| rpc_unreachable(&self.url, SIMULATE_TRANSACTION_FAILED, &e))?;
        // The answer's `error` is the endpoint's own text and reaches callers
        // as received apart from the credential.
        if let Some(error) = response.error.as_mut() {
            *error = self.url.redact_credential(error);
        }
        Ok(response)
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
    /// with two exceptions: an answer whose body does not deserialize, for
    /// example one without `protocolVersion`, is not retried, and neither is
    /// an HTTP 401 or 403 answer, which no retry changes. A passphrase
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
    /// - [`NetworkError::RpcCredentialRejected`] if the endpoint answers
    ///   HTTP 401 or 403, with that status and the endpoint's authority.
    /// - [`NetworkError::EndpointIdentityUnavailable`] if the request does not
    ///   complete within `deadline`, fails for any reason other than a
    ///   passphrase verdict or a 401 or 403 answer, or returns a body that
    ///   does not deserialize.
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
            .map_err(|e| {
                WalletError::Network(match rejected_status(&e) {
                    Some(status @ (401 | 403)) => NetworkError::RpcCredentialRejected {
                        url: self.redacted_url(),
                        status,
                    },
                    _ => NetworkError::EndpointIdentityUnavailable {
                        url: self.redacted_url(),
                    },
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
        self.url.authority()
    }
}

#[cfg(feature = "test-hooks")]
thread_local! {
    /// Calls to [`StellarRpcClient::new`] and [`StellarRpcClient::with_credential`]
    /// on this thread, failed ones included.
    static CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Returns how many times [`StellarRpcClient::new`] or
/// [`StellarRpcClient::with_credential`] has run on the calling thread, failed
/// constructions included.
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

/// Builds the error for a transport that refuses to construct for `endpoint`.
///
/// The `url` field carries the authority form (scheme://host\[:port\]). Credentials
/// embedded in a URL, for example `https://user:token@rpc.example.com`, therefore
/// reach no log or error message. The reason goes through the same scrub as
/// every other RPC failure.
fn construction_failure(endpoint: &RpcEndpoint, e: &stellar_rpc_client::Error) -> WalletError {
    WalletError::Network(rpc_unreachable(endpoint, "", e))
}

/// The reason prefix of a failed `getLedgerEntries` call.
pub(crate) const GET_LEDGER_ENTRIES_FAILED: &str = "getLedgerEntries failed: ";

/// The reason prefix of a failed `getHealth` call.
const GET_HEALTH_FAILED: &str = "getHealth failed: ";

/// The reason prefix of a failed `getTransaction` call.
const GET_TRANSACTION_FAILED: &str = "getTransaction failed: ";

/// The reason prefix of a failed `simulateTransaction` call.
const SIMULATE_TRANSACTION_FAILED: &str = "simulateTransaction failed: ";

/// The reason prefix of an unexpected status met while recovering a stale
/// pending receipt.
pub(crate) const STALE_PENDING_RECOVERY: &str = "stale-Pending recovery: ";

/// Builds [`NetworkError::RpcUnreachable`] for a failed call to `endpoint`.
///
/// The `url` field holds only the endpoint's scheme, host, and port. The
/// reason is `prefix` followed by the display of `e`, scrubbed with
/// [`RpcEndpoint::scrub`]. That display carries the server's JSON-RPC error
/// `message` and raw `data`. A server or proxy can echo the credential or the
/// credential-bearing request URL there.
pub(crate) fn rpc_unreachable(
    endpoint: &RpcEndpoint,
    prefix: &str,
    e: &stellar_rpc_client::Error,
) -> NetworkError {
    NetworkError::RpcUnreachable {
        url: endpoint.authority(),
        reason: format!("{prefix}{}", endpoint.scrub_display(e)),
    }
}

/// Builds [`NetworkError::RpcUnreachable`] for a `getTransaction` answer from
/// `endpoint` whose status is none of `SUCCESS`, `FAILED`, and `NOT_FOUND`.
///
/// The status is the endpoint's own text, so it enters the reason scrubbed
/// with [`RpcEndpoint::scrub`], after `prefix`.
pub(crate) fn unexpected_status(
    endpoint: &RpcEndpoint,
    prefix: &str,
    status: &str,
) -> NetworkError {
    NetworkError::RpcUnreachable {
        url: endpoint.authority(),
        reason: format!(
            "{prefix}unexpected getTransaction status: {}",
            endpoint.scrub(status)
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
            SIMULATE_TRANSACTION_FAILED,
        ];
        for prefix in prefixes {
            for (case, raw) in ERROR_OBJECTS {
                let (url, reason) = unreachable_parts(rpc_unreachable(
                    &RpcEndpoint::plain(ENDPOINT),
                    prefix,
                    &call_error(raw),
                ));
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
        let WalletError::Network(err) = construction_failure(&RpcEndpoint::plain(ENDPOINT), &e)
        else {
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

    /// A value with a space, `+`, `/`, and `%`, so that its query and path
    /// forms differ from the raw one.
    const VALUE: &str = "k3y +/%2F v4lue";

    fn header() -> RpcCredentialPlacement {
        RpcCredentialPlacement::Header {
            name: "X-API-Key".to_owned(),
        }
    }

    fn query() -> RpcCredentialPlacement {
        RpcCredentialPlacement::Query {
            name: "apikey".to_owned(),
        }
    }

    fn secret(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    fn credentialed(url: &str, placement: &RpcCredentialPlacement) -> StellarRpcClient {
        StellarRpcClient::with_credential(url, placement, Zeroizing::new(VALUE.to_owned())).unwrap()
    }

    /// `url()` and every authority the client reports are the configured
    /// URL's, for each placement; the credential reaches only the transport
    /// target of a query or path placement.
    #[test]
    fn with_credential_keeps_url_credential_free() {
        for url in [
            "https://rpc.example.com/v1/",
            "http://127.0.0.1:9",
            "https://h",
        ] {
            for placement in [header(), query(), RpcCredentialPlacement::Path {}] {
                let client = credentialed(url, &placement);
                assert_eq!(client.url(), url);
                assert_eq!(client.url.authority(), redact_url_authority(url));
                let target = client.inner.base_url();
                match placement {
                    RpcCredentialPlacement::Header { .. } => {
                        assert!(!target.contains("k3y"), "{target}");
                    }
                    RpcCredentialPlacement::Query { .. } => {
                        assert!(
                            target.ends_with("?apikey=k3y+%2B%2F%252F+v4lue"),
                            "{target}"
                        );
                    }
                    _ => assert!(target.contains("/k3y%20+%2F%252F%20v4lue"), "{target}"),
                }
            }
        }
    }

    /// A URL with a username or a password refuses before anything is built.
    #[test]
    fn with_credential_refuses_a_userinfo_url() {
        for url in [
            "https://user:pass@rpc.example.com",
            "https://user@rpc.example.com/rpc",
            "https://:pass@rpc.example.com",
        ] {
            for placement in [header(), query(), RpcCredentialPlacement::Path {}] {
                let err = StellarRpcClient::with_credential(
                    url,
                    &placement,
                    Zeroizing::new(VALUE.to_owned()),
                )
                .err()
                .unwrap();
                assert!(
                    matches!(
                        err,
                        WalletError::Network(NetworkError::RpcCredentialUnusable {
                            reason: RpcCredentialDefect::Userinfo
                        })
                    ),
                    "{url}: {err:?}"
                );
                assert_eq!(err.code(), "network.rpc_credential_refused");
            }
        }
    }

    /// The value and the placement are checked again at construction.
    #[test]
    fn with_credential_refuses_a_bad_value_or_placement() {
        for (value, defect) in [
            (String::new(), RpcCredentialDefect::Empty),
            ("a".repeat(1025), RpcCredentialDefect::TooLong),
            ("a\nb".to_owned(), RpcCredentialDefect::ControlCharacter),
        ] {
            let err = StellarRpcClient::with_credential(
                "https://rpc.example.com",
                &header(),
                Zeroizing::new(value),
            )
            .err()
            .unwrap();
            assert!(
                matches!(
                    err,
                    WalletError::Network(NetworkError::RpcCredentialUnusable { reason })
                        if reason == defect
                ),
                "{err:?}"
            );
        }
        for placement in [
            RpcCredentialPlacement::Header {
                name: "Host".to_owned(),
            },
            RpcCredentialPlacement::Header {
                name: "X Key".to_owned(),
            },
            RpcCredentialPlacement::Query {
                name: "a&b".to_owned(),
            },
            RpcCredentialPlacement::Query {
                name: String::new(),
            },
        ] {
            let err = StellarRpcClient::with_credential(
                "https://rpc.example.com",
                &placement,
                Zeroizing::new(VALUE.to_owned()),
            )
            .err()
            .unwrap();
            assert!(
                matches!(
                    err,
                    WalletError::Network(NetworkError::RpcCredentialUnusable {
                        reason: RpcCredentialDefect::Placement
                    })
                ),
                "{placement:?}: {err:?}"
            );
        }
    }

    /// A URL that does not parse refuses with the stable transport code and
    /// carries neither the credential nor the URL's secret parts.
    #[test]
    fn with_credential_reports_an_unparseable_url_without_its_parts() {
        let err = StellarRpcClient::with_credential(
            "https://archive example.com/rpc?token=SECRET",
            &header(),
            Zeroizing::new(VALUE.to_owned()),
        )
        .err()
        .unwrap();
        assert_eq!(err.code(), "network.rpc_unreachable");
        let rendered = format!("{err} {err:?}");
        for leaked in ["SECRET", "token=", "k3y"] {
            assert!(!rendered.contains(leaked), "{leaked}: {rendered}");
        }
    }

    /// Each credential form, placed bare in a server text and inside an
    /// echoed URL, is gone from every error the mapping helpers build, and
    /// the URL scrub still runs after it.
    #[test]
    fn credential_value_is_scrubbed_from_every_mapped_error() {
        let query_form = "k3y+%2B%2F%252F+v4lue";
        let path_form = "k3y%20+%2F%252F%20v4lue";
        for (placement, wire) in [
            (header(), VALUE),
            (query(), query_form),
            (RpcCredentialPlacement::Path {}, path_form),
        ] {
            let endpoint = RpcEndpoint::credentialed(ENDPOINT, secret(VALUE), &placement);
            let text = format!(
                "bad key {VALUE} sent as {wire} via \
                 https://user:SECRET@archive.example.com:8443/rpc/{wire}"
            );
            let raw = serde_json::json!({"code": -32000, "message": text}).to_string();
            for prefix in ["", GET_LEDGER_ENTRIES_FAILED, SIMULATE_TRANSACTION_FAILED] {
                let (url, reason) =
                    unreachable_parts(rpc_unreachable(&endpoint, prefix, &call_error(&raw)));
                assert_eq!(url, ENDPOINT_AUTHORITY);
                assert!(
                    reason.contains("bad key [redacted] sent as [redacted] via"),
                    "{reason}"
                );
                assert_scrubbed(&format!("{placement:?}"), &reason);
                for form in [VALUE, query_form, path_form, "k3y"] {
                    assert!(!reason.contains(form), "{form}: {reason}");
                }
            }
            let (_, reason) = unreachable_parts(unexpected_status(&endpoint, "", &text));
            assert!(!reason.contains("k3y"), "{reason}");
            assert_eq!(
                endpoint.redact_credential(&format!("simulation refused {wire}")),
                "simulation refused [redacted]"
            );
        }
    }

    /// A construction failure whose text holds the credential loses it.
    #[test]
    fn construction_failure_scrubs_the_credential() {
        for placement in [header(), query(), RpcCredentialPlacement::Path {}] {
            let endpoint = RpcEndpoint::credentialed(ENDPOINT, secret(VALUE), &placement);
            let e =
                stellar_rpc_client::Error::InvalidUrl(format!("refused {VALUE} at {ECHOED_URL}"));
            let WalletError::Network(err) = construction_failure(&endpoint, &e) else {
                panic!("a construction failure is a network error");
            };
            let (url, reason) = unreachable_parts(err);
            assert_eq!(url, ENDPOINT_AUTHORITY);
            assert!(!reason.contains("k3y"), "{reason}");
            assert_scrubbed("construction", &reason);
        }
    }

    /// The token after a header value's scheme is scrubbed on its own from
    /// eight bytes on; a shorter one stays, the full value never does.
    #[test]
    fn header_scheme_token_is_scrubbed_from_eight_bytes() {
        for (value, token, scrubbed) in [
            ("Bearer abcdefg", "abcdefg", false),
            ("Bearer abcdefgh", "abcdefgh", true),
            ("Api-Key 0123456789abcdef", "0123456789abcdef", true),
        ] {
            let endpoint = RpcEndpoint::credentialed(ENDPOINT, secret(value), &header());
            let echoed = endpoint.redact_credential(&format!("token {token}; full {value}"));
            assert!(echoed.ends_with("full [redacted]"), "{echoed}");
            assert_eq!(
                echoed.starts_with("token [redacted]"),
                scrubbed,
                "{value}: {echoed}"
            );
        }
        let query_endpoint =
            RpcEndpoint::credentialed(ENDPOINT, secret("Bearer abcdefgh"), &query());
        assert_eq!(
            query_endpoint.redact_credential("token abcdefgh"),
            "token abcdefgh"
        );
    }

    /// A status the endpoint invented enters the reason scrubbed, after the
    /// prefix and the fixed wording.
    #[test]
    fn unexpected_status_scrubs_the_status_text() {
        for prefix in ["", STALE_PENDING_RECOVERY] {
            let (url, reason) = unreachable_parts(unexpected_status(
                &RpcEndpoint::plain(ENDPOINT),
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
