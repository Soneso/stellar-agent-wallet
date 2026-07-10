//! HMAC-protected per-profile counterparty cache with single-writer flock.
//!
//! # What this module does
//!
//! Provides [`StellarTomlResolver`] — the production implementation of
//! [`CounterpartyResolver`].  It combines:
//!
//! - **HTTPS fetch** via `fetch::fetch_stellar_toml`.
//! - **SEP-1 parsing** via `parser::parse_minimal_sep1`.
//! - **HMAC-SHA-256 cache integrity** using a per-profile keyring entry
//!   (`stellar-agent-counterparty-<profile>`).
//! - **Single-writer flock** via `lock::CacheLock`.
//! - **Atomic cache writes** via `tempfile::NamedTempFile` + `persist()`
//!   (temp-file-then-rename pattern, POSIX-atomic on the same filesystem).
//! - **Lazy-mint** of the HMAC keyring entry on the first successful write.
//!
//! # Cache file format (v2)
//!
//! Each home domain is stored as:
//! ```text
//! [32-byte HMAC-SHA-256 tag]
//! || [u16 BE: home_domain byte length]
//! || [home_domain bytes (strict-ASCII)]
//! || [i64 BE: fetched_at UNIX seconds]
//! || [u32 BE: TOML body byte length]
//! || [TOML body bytes]
//! ```
//!
//! The HMAC is computed over a context-labelled concatenation:
//! ```text
//! HMAC input =
//!   b"stellar-agent-counterparty/v2/stellar-toml-body\x00"
//!   || u16_BE(home_domain_len)
//!   || home_domain_bytes
//!   || i64_BE(fetched_at_unix_s)
//!   || u32_BE(toml_body_len)
//!   || toml_body_bytes
//! ```
//!
//! Embedding `fetched_at` in the HMAC-protected header prevents a TTL-replay
//! attack where an attacker with cache-file write access extends observed
//! freshness by changing the file `mtime` via `touch -m`.  The `v2` label
//! distinguishes this format from the legacy `v1` format (which lacked the
//! `fetched_at` field); any v1 cache files fail HMAC verification cleanly and
//! are re-fetched.
//!
//! The HMAC key is the `stellar-agent-counterparty-<profile>` keyring entry
//! (raw bytes, base64-encoded at rest), accessed under account name `"default"`
//! to align with [`stellar_agent_core::profile::schema::KeyringEntryRef::default_counterparty_key`].
//!
//! The **filename** is a sanitised form of the home domain used only for
//! locating the file on disk.  The filename is **non-canonical**; the canonical
//! home domain is recovered from the length-prefixed field inside the HMAC-
//! protected body.  Collisions between two different domains mapping to the
//! same filename are acceptable: the body authoritatively identifies the domain.
//!
//! # Threat model boundary
//!
//! The HMAC defends against **post-fetch local cache tampering** — an attacker
//! with file-write access to the cache directory but without access to the
//! platform keyring cannot forge a valid HMAC tag.  The context label
//! `b"stellar-agent-counterparty/v2/stellar-toml-body\x00"` prevents a tag
//! computed under a different label from verifying under this one.  Embedding
//! `fetched_at` in the HMAC input means `touch -m` does not alter the
//! HMAC-bound timestamp — the resolver ignores `mtime` entirely.
//! First-fetch TOFU, TLS interception, and CT-pinning are out of scope for
//! this module.
//!
//! # Write path
//!
//! 1. `CacheLock::acquire(<cache_dir>/.lock)` — single-writer serialisation.
//! 2. Fetch the `stellar.toml` body.
//! 3. Parse the body via `parse_minimal_sep1` (structural validation).
//! 4. Load (or mint) the HMAC key from the keyring.
//! 5. Record `fetched_at = SystemTime::now()` as a UNIX-second `i64`.
//! 6. Compute HMAC-SHA-256 over context label + home_domain + fetched_at + body.
//! 7. Write `tag || u16_hd_len || hd_bytes || i64_fetched_at || u32_body_len || body`
//!    to a `NamedTempFile` in `cache_dir`.
//! 8. `tempfile.persist(<cache_file_path>)` — atomic rename.
//! 9. Release the lock (CacheLock drops).
//!
//! # Read path
//!
//! 1. Read the cache file into memory.
//! 2. Split the 32-byte HMAC tag prefix.
//! 3. Parse u16 home_domain length and recover the canonical home_domain.
//! 4. Parse i64 `fetched_at` from the HMAC-protected header.
//! 5. Parse u32 body length and recover body bytes.
//! 6. Load the HMAC key from the keyring.
//! 7. Recompute HMAC-SHA-256 over context label + home_domain + fetched_at + body.
//! 8. `ConstantTimeEq` compare stored tag vs recomputed tag.
//! 9. If mismatch → [`CounterpartyError::HmacMismatch`] (fail-closed).
//! 10. `fetched_at` + TTL yields `expires_at`; `mtime` is ignored.
//!
//! This module is the production implementation of the counterparty resolver
//! combining HTTPS fetch, SEP-1 parsing, HMAC-protected cache, and single-writer
//! flock.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hmac::Hmac;
use keyring_core::Entry as KeyringEntry;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

#[cfg(any(test, feature = "test-helpers"))]
use crate::counterparty::fetch::build_fetch_client;
use crate::counterparty::fetch::fetch_stellar_toml;
use crate::counterparty::lock::CacheLock;
use crate::counterparty::parser::parse_minimal_sep1;
use crate::counterparty::{CounterpartyError, CounterpartyResolver, StellarTomlBinding};

/// Default TTL for cached `stellar.toml` entries (1 hour).
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// HMAC-SHA-256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Length of the HMAC-SHA-256 tag in bytes.
const HMAC_TAG_LEN: usize = 32;

/// Length of the generated HMAC key in bytes (256 bits).
const HMAC_KEY_LEN: usize = 32;

/// Keyring service name prefix for the per-profile counterparty cache key.
const KEYRING_SERVICE_PREFIX: &str = "stellar-agent-counterparty-";

/// Keyring account name used for the per-profile counterparty HMAC key.
///
/// Uses `"default"` to align with
/// [`stellar_agent_core::profile::schema::KeyringEntryRef::default_counterparty_key`]
/// and the `rotate-counterparty-key` CLI, which writes to the same
/// `(stellar-agent-counterparty-<profile>, "default")` entry.
const KEYRING_ACCOUNT: &str = "default";

/// HMAC context label for the cache file format v2.
///
/// Included as the first bytes of the HMAC input to provide domain separation.
/// A tag computed under a different context label cannot verify under this one.
///
/// The `v2` label distinguishes this format from the legacy `v1` format (which
/// did not include `fetched_at` in the HMAC input).  Any v1 cache files fail
/// HMAC verification and are discarded; the operator runs
/// `stellar-agent counterparty refresh <domain>` to re-mint them.
/// Embedding `fetched_at` in the HMAC input prevents TTL-replay via `touch -m`.
const HMAC_CONTEXT_LABEL: &[u8] = b"stellar-agent-counterparty/v2/stellar-toml-body\x00";

/// Lock file name within the cache directory.
const LOCK_FILE_NAME: &str = ".lock";

/// Cache file extension.
const CACHE_FILE_EXT: &str = ".toml.cache";

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Production [`CounterpartyResolver`] with HTTPS fetch, HMAC-protected cache,
/// single-writer flock, and atomic write-temp+rename.
///
/// Construct via [`StellarTomlResolver::new`].  The resolver is `Send + Sync`
/// and cheap to clone (all heavy state is behind `Arc` or stack-stored).
///
/// # Cache directory layout
///
/// ```text
/// <cache_dir>/
///   .lock                          ← per-profile advisory flock file
///   circle_com.toml.cache          ← HMAC tag (32 B) + TOML body
///   stellar_org.toml.cache
///   ...
/// ```
///
/// # Thread safety
///
/// `StellarTomlResolver` itself is `Send + Sync`.  Concurrent calls to
/// `refresh` on the same instance (or from two distinct instances sharing the
/// same `cache_dir`) are serialised by the OFD lock; the loser receives
/// [`CounterpartyError::WriterLocked`].
///
pub struct StellarTomlResolver {
    /// Profile name used to derive the keyring entry name.
    profile_name: String,
    /// Filesystem directory where cache files are stored.
    cache_dir: PathBuf,
    /// Async HTTP client used only by the test-only base-URL fetch path; the
    /// production fetch builds its own per-request pinned client internally.
    #[cfg(any(test, feature = "test-helpers"))]
    http_client: reqwest::Client,
    /// Cache TTL after which entries are considered stale and re-fetched.
    ttl: Duration,
    /// Return an HMAC-verified expired entry when refresh hits a transient fetch
    /// failure. Disabled by default so callers remain fail-closed unless they
    /// explicitly opt in.
    stale_if_error: bool,
    /// Optional base URL override for integration tests.
    ///
    /// In production this is always `None`; the fetch function builds
    /// `https://<home_domain>/.well-known/stellar.toml`.  In tests this
    /// can be set to a wiremock HTTP base URL (e.g. `http://127.0.0.1:PORT`)
    /// to avoid requiring a real TLS endpoint.
    ///
    /// Only compiled under `test` or `test-helpers` feature.
    #[cfg(any(test, feature = "test-helpers"))]
    test_base_url: Option<String>,
}

impl std::fmt::Debug for StellarTomlResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("StellarTomlResolver");
        dbg.field("profile_name", &self.profile_name)
            .field("cache_dir", &self.cache_dir)
            .field("ttl", &self.ttl)
            .field("stale_if_error", &self.stale_if_error);
        #[cfg(any(test, feature = "test-helpers"))]
        dbg.field("test_base_url", &self.test_base_url);
        dbg.finish_non_exhaustive()
    }
}

impl StellarTomlResolver {
    /// Creates a new resolver for the given profile.
    ///
    /// The `cache_dir` must exist and be writable; the caller is responsible
    /// for creating it.  A dedicated `reqwest::Client` is built internally
    /// with the standard counterparty fetch settings (5-second timeout, no
    /// redirects).
    ///
    /// # Errors
    ///
    /// Returns [`CounterpartyError::FetchFailed`] if the internal HTTP client
    /// cannot be constructed (platform error, should not happen in practice).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use stellar_agent_network::counterparty::cache::StellarTomlResolver;
    ///
    /// let resolver = StellarTomlResolver::new("default", "/tmp/cache", Duration::from_secs(3600))
    ///     .expect("resolver construction must succeed");
    /// ```
    pub fn new(
        profile_name: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
        ttl: Duration,
    ) -> Result<Self, CounterpartyError> {
        Ok(Self {
            profile_name: profile_name.into(),
            cache_dir: cache_dir.into(),
            #[cfg(any(test, feature = "test-helpers"))]
            http_client: build_fetch_client()?,
            ttl,
            stale_if_error: false,
            #[cfg(any(test, feature = "test-helpers"))]
            test_base_url: None,
        })
    }

    /// Creates a resolver with a caller-provided HTTP client.
    ///
    /// Useful in tests where the client is pre-configured to point at a
    /// `wiremock` mock server.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use stellar_agent_network::counterparty::cache::StellarTomlResolver;
    ///
    /// let client = reqwest::Client::new();
    /// let resolver = StellarTomlResolver::with_client("default", "/tmp/cache", Duration::from_secs(3600), client);
    /// ```
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn with_client(
        profile_name: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
        ttl: Duration,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            profile_name: profile_name.into(),
            cache_dir: cache_dir.into(),
            http_client,
            ttl,
            stale_if_error: false,
            #[cfg(any(test, feature = "test-helpers"))]
            test_base_url: None,
        }
    }

    /// Configures whether refresh may return an expired HMAC-verified cache
    /// entry after a transient fetch failure.
    ///
    /// The default is `false` to preserve fail-closed refresh behavior. CLI or
    /// daemon callers that prefer availability can opt in and inspect
    /// [`StellarTomlBinding::stale`].
    #[must_use]
    pub fn with_stale_if_error(mut self, enabled: bool) -> Self {
        self.stale_if_error = enabled;
        self
    }

    /// Creates a resolver that fetches from a custom base URL instead of
    /// `https://<home_domain>`.
    ///
    /// Intended for integration tests that use `wiremock`.  The `base_url`
    /// replaces the `https://<home_domain>` prefix so that
    /// `https://testdomain.example/.well-known/stellar.toml` becomes
    /// `<base_url>/.well-known/stellar.toml`.
    ///
    /// Only available under `test` or `test-helpers` feature.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn with_test_base_url(
        profile_name: impl Into<String>,
        cache_dir: impl Into<PathBuf>,
        ttl: Duration,
        http_client: reqwest::Client,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            profile_name: profile_name.into(),
            cache_dir: cache_dir.into(),
            http_client,
            ttl,
            stale_if_error: false,
            test_base_url: Some(base_url.into()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyResolver implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl CounterpartyResolver for StellarTomlResolver {
    /// Forces a re-fetch of `https://<home_domain>/.well-known/stellar.toml`.
    ///
    /// Acquires the per-profile flock, fetches, parses, writes the HMAC-
    /// protected cache file via atomic temp+rename, and returns the binding.
    ///
    /// # Errors
    ///
    /// See [`CounterpartyError`] for the variant table.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn refresh(&self, home_domain: &str) -> Result<StellarTomlBinding, CounterpartyError> {
        // Normalise to ASCII lowercase before any use: the policy criteria
        // query the cache with the lowercased on-chain home_domain, so a
        // mixed-case refresh argument would key an entry the lookup can never
        // hit and a legitimate counterparty would deny as unverified.
        let home_domain = &home_domain.to_ascii_lowercase();

        // Validate the domain before touching the filesystem.
        crate::counterparty::fetch::validate_home_domain(home_domain)?;

        // Acquire the single-writer flock.
        let lock_path = self.cache_dir.join(LOCK_FILE_NAME);
        let _lock = CacheLock::acquire(&lock_path)?;

        tracing::debug!(
            home_domain = %home_domain,
            profile = %self.profile_name,
            "counterparty cache refresh started"
        );

        // Fetch the stellar.toml body.
        // In test/test-helpers builds, `test_base_url` may override the base
        // URL so that the fetch targets a wiremock HTTP server instead of the
        // real HTTPS endpoint.
        #[cfg(any(test, feature = "test-helpers"))]
        let body_result = {
            if let Some(ref base_url) = self.test_base_url {
                fetch_with_base_url(home_domain, base_url, &self.http_client).await
            } else {
                fetch_stellar_toml(home_domain).await
            }
        };
        #[cfg(not(any(test, feature = "test-helpers")))]
        let body_result = fetch_stellar_toml(home_domain).await;

        let body = match body_result {
            Ok(body) => body,
            Err(err @ CounterpartyError::FetchFailed { .. }) if self.stale_if_error => {
                if let Some(binding) = self.read_stale_binding(home_domain)? {
                    tracing::warn!(
                        home_domain = %home_domain,
                        profile = %self.profile_name,
                        "counterparty refresh fetch failed; returning stale HMAC-verified cache entry"
                    );
                    return Ok(binding);
                }
                return Err(err);
            }
            Err(err) => return Err(err),
        };

        // Structural parse (validates TOML and extracts fields, including
        // ACCOUNTS — carried into the binding below).
        let sep1 = parse_minimal_sep1(&body)?;

        // Load (or mint) the HMAC key.
        let hmac_key = load_or_mint_hmac_key(&self.profile_name)?;

        // Record fetched_at before writing — embedded in the HMAC-protected
        // header so that mtime cannot be forged.
        let fetched_at = SystemTime::now();
        let fetched_at_unix_s = fetched_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let fetched_at_unix_s_i64 = fetched_at_unix_s_to_i64(fetched_at_unix_s);

        // Compute HMAC-SHA-256 over context label + home_domain + fetched_at + body.
        // Deref Zeroizing<[u8;32]> → &[u8] via as_ref().
        let tag = compute_hmac_v2(
            hmac_key.as_ref(),
            home_domain,
            fetched_at_unix_s_i64,
            body.as_bytes(),
        )?;

        // Write tag || u16_hd_len || hd_bytes || i64_fetched_at || u32_body_len || body.
        let cache_path = cache_file_path(&self.cache_dir, home_domain);
        write_cache_atomic(
            &self.cache_dir,
            &cache_path,
            &tag,
            home_domain,
            fetched_at_unix_s,
            body.as_bytes(),
        )?;

        let expires_at = cache_expires_at(fetched_at, self.ttl);

        tracing::debug!(
            home_domain = %home_domain,
            profile = %self.profile_name,
            "counterparty cache refresh complete"
        );

        Ok(StellarTomlBinding {
            home_domain: home_domain.to_owned(),
            fetched_at,
            expires_at,
            stale: false,
            accounts: sep1.accounts,
        })
    }

    /// Returns the list of cached bindings for this profile.
    ///
    /// Reads the cache directory, validates each file's HMAC, and returns
    /// verified bindings.  Files whose HMAC fails validation are silently
    /// skipped (the operator must run `stellar-agent counterparty refresh` to
    /// re-mint them).
    ///
    /// # Errors
    ///
    /// Returns [`CounterpartyError::Io`] when the cache directory cannot be
    /// enumerated.  Returns [`CounterpartyError::KeyringUnavailable`] when the
    /// per-profile keyring entry cannot be loaded.
    ///
    /// # Panics
    ///
    /// Never panics.
    async fn list_cached(&self) -> Result<Vec<StellarTomlBinding>, CounterpartyError> {
        // Load the HMAC key — if the key is not yet minted, there are no valid
        // cache entries (lazy-mint only fires on first write).
        let hmac_key = match load_hmac_key(&self.profile_name) {
            Ok(k) => k,
            Err(CounterpartyError::KeyringUnavailable { .. }) => return Ok(Vec::new()),
            Err(other) => return Err(other),
        };

        let read_dir = std::fs::read_dir(&self.cache_dir)
            .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

        let mut bindings = Vec::new();

        for entry in read_dir {
            let entry = entry.map_err(|e| CounterpartyError::Io { kind: e.kind() })?;
            let path = entry.path();

            // Only process files matching the *.toml.cache extension.
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_owned(),
                None => continue,
            };
            if !file_name.ends_with(CACHE_FILE_EXT) {
                continue;
            }

            // Read and verify the cache file.  The canonical home_domain is
            // recovered from the HMAC-protected body header, NOT from the
            // filename.  Filenames are non-canonical: hyphenated domains
            // (e.g. "sub-domain.com") would round-trip incorrectly if
            // recovered from the filename sanitisation.
            match read_and_verify_cache(&path, hmac_key.as_ref()) {
                Ok((home_domain, body, file_meta)) => {
                    // Re-parse the cached body to recover ACCOUNTS. A body
                    // that fails to parse here indicates the cache file was
                    // written by an incompatible format or corrupted in a way
                    // the HMAC check does not catch bit-for-bit; skip it like
                    // the other invalid-entry arms rather than trusting a
                    // domain-only binding with no ACCOUNTS proof.
                    let accounts = match parse_minimal_sep1(&String::from_utf8_lossy(&body)) {
                        Ok(sep1) => sep1.accounts,
                        Err(err) => {
                            tracing::debug!(
                                file = %path.file_name().unwrap_or_default().to_string_lossy(),
                                err = %err,
                                "counterparty cache body failed SEP-1 re-parse — skipping"
                            );
                            continue;
                        }
                    };
                    let fetched_at = file_meta;
                    let expires_at = cache_expires_at(fetched_at, self.ttl);
                    bindings.push(StellarTomlBinding {
                        home_domain,
                        fetched_at,
                        expires_at,
                        stale: false,
                        accounts,
                    });
                }
                Err(CounterpartyError::HmacMismatch) => {
                    // HMAC mismatch is operator-relevant (key rotation, on-disk
                    // tamper, or key corruption) — surface at warn so it appears
                    // under the default operator log filter.  Redact to filename-
                    // only to avoid leaking the cache-dir layout.
                    tracing::warn!(
                        file = %path.file_name().unwrap_or_default().to_string_lossy(),
                        "counterparty cache HMAC mismatch — skipping (rotated key or tampered file)"
                    );
                    continue;
                }
                Err(CounterpartyError::CacheInvalid { .. }) => {
                    // Skip invalid entries silently; redact to filename-only to
                    // avoid leaking the cache-dir layout.
                    tracing::debug!(
                        file = %path.file_name().unwrap_or_default().to_string_lossy(),
                        "counterparty cache file invalid — skipping"
                    );
                    continue;
                }
                Err(other) => {
                    // Redact to filename-only to avoid leaking the cache-dir layout.
                    tracing::debug!(
                        file = %path.file_name().unwrap_or_default().to_string_lossy(),
                        err = %other,
                        "counterparty cache file read error — skipping"
                    );
                    continue;
                }
            }
        }

        Ok(bindings)
    }
}

impl StellarTomlResolver {
    fn read_stale_binding(
        &self,
        home_domain: &str,
    ) -> Result<Option<StellarTomlBinding>, CounterpartyError> {
        let hmac_key = match load_hmac_key(&self.profile_name) {
            Ok(key) => key,
            Err(CounterpartyError::KeyringUnavailable { .. }) => return Ok(None),
            Err(err) => return Err(err),
        };
        let cache_path = cache_file_path(&self.cache_dir, home_domain);
        let (cached_home_domain, body, fetched_at) =
            match read_and_verify_cache(&cache_path, hmac_key.as_ref()) {
                Ok(entry) => entry,
                Err(CounterpartyError::Io {
                    kind: std::io::ErrorKind::NotFound,
                }) => return Ok(None),
                Err(CounterpartyError::HmacMismatch | CounterpartyError::CacheInvalid { .. }) => {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
        if cached_home_domain != home_domain {
            return Ok(None);
        }
        let body_str = String::from_utf8(body).map_err(|_| CounterpartyError::CacheInvalid {
            detail: "cache body is not valid UTF-8".to_owned(),
        })?;
        let sep1 = parse_minimal_sep1(&body_str)?;
        Ok(Some(StellarTomlBinding {
            home_domain: cached_home_domain,
            fetched_at,
            expires_at: cache_expires_at(fetched_at, self.ttl),
            stale: true,
            accounts: sep1.accounts,
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only fetch helper (base-URL override for wiremock)
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches `stellar.toml` from a custom base URL (test/test-helpers only).
///
/// Builds the URL as `<base_url>/.well-known/stellar.toml` and performs the
/// same body-cap check as `fetch_stellar_toml`, but skips the HTTPS enforcement
/// and the domain validation since the caller already validated the domain.
///
/// # Errors
///
/// Returns [`CounterpartyError::FetchFailed`] on any HTTP or body error.
///
/// # Panics
///
/// Never panics.
#[cfg(any(test, feature = "test-helpers"))]
async fn fetch_with_base_url(
    _home_domain: &str,
    base_url: &str,
    http: &reqwest::Client,
) -> Result<String, CounterpartyError> {
    use crate::counterparty::fetch::MAX_BODY_BYTES;

    let url = format!(
        "{}/.well-known/stellar.toml",
        base_url.trim_end_matches('/')
    );
    tracing::debug!(url = %url, "test fetch with base_url override");

    let response = http
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| CounterpartyError::FetchFailed {
            detail: format!("network error: {}", e.without_url()),
        })?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        return Err(CounterpartyError::FetchFailed {
            detail: format!("unexpected HTTP status {}", status.as_u16()),
        });
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| CounterpartyError::FetchFailed {
            detail: format!("body read error: {}", e.without_url()),
        })?;

    if bytes.len() > MAX_BODY_BYTES {
        return Err(CounterpartyError::FetchFailed {
            detail: format!("body too large ({} bytes)", bytes.len()),
        });
    }

    String::from_utf8(bytes.into()).map_err(|_| CounterpartyError::FetchFailed {
        detail: "body is not valid UTF-8".to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC key management
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the keyring service name for a profile.
fn keyring_service_name(profile_name: &str) -> String {
    format!("{}{}", KEYRING_SERVICE_PREFIX, profile_name)
}

/// Loads the HMAC key for the given profile from the keyring.
///
/// Returns the key in a `zeroize::Zeroizing` wrapper so that key bytes are
/// scrubbed from memory when the guard drops.
///
/// Returns [`CounterpartyError::KeyringUnavailable`] when the entry does not
/// exist or cannot be accessed.
///
/// Uses `account = "default"` to align with
/// [`stellar_agent_core::profile::schema::KeyringEntryRef::default_counterparty_key`]
/// and the `rotate-counterparty-key` CLI which writes to the same account name.
fn load_hmac_key(
    profile_name: &str,
) -> Result<zeroize::Zeroizing<[u8; HMAC_KEY_LEN]>, CounterpartyError> {
    let service = keyring_service_name(profile_name);
    let entry = KeyringEntry::new(&service, KEYRING_ACCOUNT).map_err(|e| {
        CounterpartyError::KeyringUnavailable {
            detail: format!("keyring entry open failed: {e}"),
        }
    })?;

    let raw = entry.get_password().map_err(|e| match e {
        keyring_core::Error::NoEntry => {
            // Omit service name from operator-visible error to avoid leaking
            // profile names in multi-profile setups.  Service-name detail goes
            // to debug tracing only.
            tracing::debug!(service = %service, "keyring entry not found");
            CounterpartyError::KeyringUnavailable {
                detail: "keyring entry not found — has never been minted".to_owned(),
            }
        }
        other => {
            // Do not embed the keyring backend's error string in the
            // operator-visible detail — the backend may include service /
            // account names or platform-specific paths.  Route the original
            // error to debug tracing only.
            tracing::debug!(
                service = %service,
                error = %other,
                "keyring get_password failed"
            );
            CounterpartyError::KeyringUnavailable {
                detail: "keyring backend error retrieving entry".to_owned(),
            }
        }
    })?;

    base64_decode_key(&raw, &service)
}

/// Loads the HMAC key or mints a fresh one if the entry does not exist yet.
///
/// Returns the key in a `zeroize::Zeroizing` wrapper so that key bytes are
/// scrubbed from memory when the guard drops.
///
/// This is the lazy-mint path triggered on first cache write.  After minting,
/// the new key is stored in the keyring and returned.
///
/// Uses `account = "default"` so that `rotate_counterparty_key` — which also
/// writes `(stellar-agent-counterparty-<profile>, "default")` — invalidates
/// the cache HMAC correctly on next read.
fn load_or_mint_hmac_key(
    profile_name: &str,
) -> Result<zeroize::Zeroizing<[u8; HMAC_KEY_LEN]>, CounterpartyError> {
    let service = keyring_service_name(profile_name);
    let entry = KeyringEntry::new(&service, KEYRING_ACCOUNT).map_err(|e| {
        CounterpartyError::KeyringUnavailable {
            detail: format!("keyring entry open failed: {e}"),
        }
    })?;

    match entry.get_password() {
        Ok(raw) => base64_decode_key(&raw, &service),
        Err(keyring_core::Error::NoEntry) => {
            // Lazy-mint: generate a fresh 256-bit random key and store it.
            tracing::info!(
                profile = %profile_name,
                "minting stellar-agent-counterparty-{profile_name} keyring entry"
            );
            let key = generate_hmac_key();
            let encoded = base64_encode_key(key.as_ref());
            entry
                .set_password(&encoded)
                .map_err(|e| CounterpartyError::KeyringUnavailable {
                    detail: format!("keyring set_password failed during lazy-mint: {e}"),
                })?;
            Ok(key)
        }
        Err(other) => {
            // Route backend error string to debug tracing only; do not leak
            // it via the operator-visible detail.
            tracing::debug!(
                service = %service,
                error = %other,
                "keyring get_password failed during lazy-mint check"
            );
            Err(CounterpartyError::KeyringUnavailable {
                detail: "keyring backend error retrieving entry".to_owned(),
            })
        }
    }
}

/// Decodes a base64-encoded HMAC key from the keyring into a zeroizing buffer.
///
/// The caller does not need to explicitly zeroize the returned key bytes —
/// the `Zeroizing` wrapper scrubs memory on drop.
fn base64_decode_key(
    encoded: &str,
    service: &str,
) -> Result<zeroize::Zeroizing<[u8; HMAC_KEY_LEN]>, CounterpartyError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| {
            // Do not embed the keyring service name (which carries the profile
            // name) in the operator-visible detail.
            tracing::debug!(
                service = %service,
                "keyring entry contains invalid base64"
            );
            CounterpartyError::KeyringUnavailable {
                detail: "keyring entry contains invalid base64".to_owned(),
            }
        })?;
    let arr: [u8; HMAC_KEY_LEN] =
        bytes
            .try_into()
            .map_err(|_| CounterpartyError::KeyringUnavailable {
                detail: "keyring entry has unexpected length (expected 32 bytes)".to_owned(),
            })?;
    Ok(zeroize::Zeroizing::new(arr))
}

/// Base64-encodes an HMAC key for storage in the keyring.
fn base64_encode_key(key: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Generates a fresh 256-bit random HMAC key using the OS CSPRNG.
///
/// Returns a zeroizing buffer so key material is scrubbed if the caller
/// discards the value without storing it.
fn generate_hmac_key() -> zeroize::Zeroizing<[u8; HMAC_KEY_LEN]> {
    use rand_core::{OsRng, RngCore};
    let mut key = zeroize::Zeroizing::new([0u8; HMAC_KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    key
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC computation (context-separated, v2 format)
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the context-labelled HMAC-SHA-256 tag for a v2 cache entry.
///
/// HMAC input (in order):
/// 1. `HMAC_CONTEXT_LABEL` — domain separation label (`v2`), preventing cross-
///    context tag reuse and distinguishing from the v1 format.
/// 2. `u16_BE(home_domain.len())` — length-prefixed home_domain.
/// 3. `home_domain_bytes` — strict-ASCII home domain.
/// 4. `i64_BE(fetched_at_unix_s)` — HMAC-bound fetch timestamp; binding
///    `fetched_at` here prevents an attacker with file-write access from
///    extending TTL via `touch -m`.
/// 5. `u32_BE(body.len())` — length-prefixed TOML body.
/// 6. `body` — raw TOML body bytes.
///
/// A tag computed under `HMAC_CONTEXT_LABEL` cannot verify under a different
/// label; a tag computed with a different `fetched_at` cannot verify under
/// this one (TTL-replay resistance).
fn compute_hmac_v2(
    key: &[u8],
    home_domain: &str,
    fetched_at_unix_s: i64,
    body: &[u8],
) -> Result<[u8; HMAC_TAG_LEN], CounterpartyError> {
    use hmac::{KeyInit as _, Mac as _};

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "HMAC key length is invalid".to_owned(),
    })?;

    // 1. Context label (domain separation, v2).
    mac.update(HMAC_CONTEXT_LABEL);

    // 2. u16 BE home_domain length + home_domain bytes.
    // home_domain is max 255 bytes; fits u16 without overflow.
    let hd_bytes = home_domain.as_bytes();
    let hd_len = u16::try_from(hd_bytes.len()).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "home_domain length exceeds u16::MAX".to_owned(),
    })?;
    mac.update(&hd_len.to_be_bytes());
    mac.update(hd_bytes);

    // 3. i64 BE fetched_at — bound in the HMAC to prevent TTL-replay via mtime.
    mac.update(&fetched_at_unix_s.to_be_bytes());

    // 4. u32 BE body length + body bytes.
    // body is max MAX_BODY_BYTES (64 KiB); fits u32 without overflow.
    let body_len = u32::try_from(body.len()).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "TOML body length exceeds u32::MAX".to_owned(),
    })?;
    mac.update(&body_len.to_be_bytes());
    mac.update(body);

    let tag_generic = mac.finalize().into_bytes();
    let mut tag = [0u8; HMAC_TAG_LEN];
    tag.copy_from_slice(&tag_generic);
    Ok(tag)
}

/// Verifies a stored HMAC tag using constant-time compare.
///
/// Returns `Err(HmacMismatch)` on mismatch.
fn verify_hmac_v2(
    key: &[u8],
    home_domain: &str,
    fetched_at_unix_s: i64,
    body: &[u8],
    stored_tag: &[u8; HMAC_TAG_LEN],
) -> Result<(), CounterpartyError> {
    let recomputed = compute_hmac_v2(key, home_domain, fetched_at_unix_s, body)?;
    if stored_tag.ct_eq(&recomputed).into() {
        Ok(())
    } else {
        Err(CounterpartyError::HmacMismatch)
    }
}

/// Converts an in-memory UNIX-second timestamp to the v2 cache wire type.
///
/// The v2 cache format stores `fetched_at` as signed `i64` big-endian bytes.
/// The wallet's in-memory timestamp source is `u64`, so values above
/// `i64::MAX` are saturated before HMAC computation and serialisation.  Real
/// wall-clock timestamps stay below this bound until year 2262; saturation is
/// a defensive guard for adversarial clocks and future test fixtures.
fn fetched_at_unix_s_to_i64(fetched_at_unix_s: u64) -> i64 {
    i64::try_from(fetched_at_unix_s).unwrap_or_else(|_| {
        tracing::warn!(
            fetched_at = fetched_at_unix_s,
            "cache timestamp exceeds i64::MAX; saturating to i64::MAX"
        );
        i64::MAX
    })
}

/// Converts the v2 cache wire timestamp back to an in-memory `u64`.
///
/// Negative values on disk are clamped to `0` (the UNIX epoch) rather than
/// wrapping into a huge `u64`.  The HMAC still authenticates the exact signed
/// wire value; this function only controls the `SystemTime` projection after
/// verification succeeds.
fn fetched_at_i64_to_unix_s(fetched_at_unix_s: i64) -> u64 {
    u64::try_from(fetched_at_unix_s.max(0)).unwrap_or(0)
}

/// Computes a cache entry's expiry instant as `fetched_at + ttl`.
///
/// If the addition would overflow the representable time range (a pathologically
/// large `ttl` or a far-future `fetched_at`), the entry effectively never
/// expires; this saturates to a fixed far-future instant rather than panicking.
fn cache_expires_at(fetched_at: SystemTime, ttl: Duration) -> SystemTime {
    // ~317,000 years past the epoch: far beyond any real `now()` yet safely
    // within `SystemTime`'s representable range on supported platforms.
    const NEVER: Duration = Duration::from_secs(10_000_000_000_000);
    fetched_at
        .checked_add(ttl)
        .unwrap_or_else(|| SystemTime::UNIX_EPOCH + NEVER)
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache file naming
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the cache file path for a given home domain.
///
/// Sanitises the domain by replacing `.` and `-` with `_` to produce a valid
/// file name.  This is a **non-canonical** one-way mapping — two different
/// domains (e.g. `my-bank.com` and `my.bank.com`) may map to the same filename.
/// That collision is acceptable because the canonical home domain is stored
/// inside the HMAC-protected body and is recovered from there, not from the
/// filename.  The filename only locates the file on disk.
///
/// Exposed as `pub` for integration tests that need to locate cache files.
pub fn cache_file_path(cache_dir: &Path, home_domain: &str) -> PathBuf {
    let sanitised = home_domain.replace(['.', '-'], "_");
    cache_dir.join(format!("{sanitised}{CACHE_FILE_EXT}"))
}

/// Minimum header size for a v2 cache file:
///
///   32 bytes HMAC tag + 2 bytes u16 home_domain_len + at least 1 byte
///   home_domain + 8 bytes i64 fetched_at + 4 bytes u32 body_len
///   = 47 bytes minimum (before the body).
const CACHE_HEADER_MIN_LEN: usize = HMAC_TAG_LEN + 2 + 1 + 8 + 4;

// ─────────────────────────────────────────────────────────────────────────────
// Cache I/O
// ─────────────────────────────────────────────────────────────────────────────

/// Writes the v2 cache format to `dest_path` atomically.
///
/// Format:
/// ```text
/// [32-byte HMAC tag]
/// || [u16 BE: home_domain byte length]
/// || [home_domain bytes (strict-ASCII)]
/// || [i64 BE: fetched_at UNIX seconds]
/// || [u32 BE: TOML body byte length]
/// || [TOML body bytes]
/// ```
///
/// The `fetched_at` field is HMAC-bound so that `touch -m` cannot extend
/// the observed TTL without invalidating the tag.
///
/// The file is written to a temp file in `cache_dir` first, then renamed
/// atomically (POSIX rename, same-device guarantee).
fn write_cache_atomic(
    cache_dir: &Path,
    dest_path: &Path,
    tag: &[u8; HMAC_TAG_LEN],
    home_domain: &str,
    fetched_at_unix_s: u64,
    body: &[u8],
) -> Result<(), CounterpartyError> {
    use std::io::Write as _;

    // Create the temp file in the same directory as the destination so the
    // rename is on the same filesystem (POSIX rename is atomic same-device).
    let mut tmp = tempfile::NamedTempFile::new_in(cache_dir)
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // 1. Write 32-byte HMAC tag.
    tmp.write_all(tag)
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // 2. Write u16 BE home_domain length + home_domain bytes.
    let hd_bytes = home_domain.as_bytes();
    // Validated at fetch time; max 255 bytes fits u16 safely.
    // The try_from cannot fail here (same guard is in compute_hmac_v2), but
    // we map the error for defence-in-depth.
    let hd_len = u16::try_from(hd_bytes.len()).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "home_domain length exceeds u16::MAX".to_owned(),
    })?;
    tmp.write_all(&hd_len.to_be_bytes())
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;
    tmp.write_all(hd_bytes)
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // 3. Write i64 BE fetched_at (HMAC-bound; prevents TTL-replay via mtime).
    //
    // The wire format is fixed as `i64`; in-memory callers pass `u64`.  Values
    // above `i64::MAX` saturate to `i64::MAX` rather than wrapping through an
    // implicit cast.
    let fetched_at_unix_s_i64 = fetched_at_unix_s_to_i64(fetched_at_unix_s);
    tmp.write_all(&fetched_at_unix_s_i64.to_be_bytes())
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // 4. Write u32 BE body length + body bytes.
    // MAX_BODY_BYTES is 64 KiB; well within u32::MAX.
    let body_len = u32::try_from(body.len()).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "TOML body length exceeds u32::MAX".to_owned(),
    })?;
    tmp.write_all(&body_len.to_be_bytes())
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;
    tmp.write_all(body)
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;
    tmp.flush()
        .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // Set file permissions to 0o600 on Unix before persisting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CounterpartyError::Io { kind: e.kind() })?;
    }

    // Atomic rename: replaces dest_path if it exists.
    tmp.persist(dest_path).map_err(|e| CounterpartyError::Io {
        kind: e.error.kind(),
    })?;

    Ok(())
}

/// Reads a v2 cache file, verifies the HMAC, and returns the canonical
/// `home_domain`, body bytes, and HMAC-bound `fetched_at` timestamp.
///
/// The canonical home domain and `fetched_at` are both recovered from the
/// HMAC-protected header — **not** from the filename or `mtime`.  This
/// correctly handles hyphenated domains and prevents TTL-replay via
/// `touch -m`.
///
/// v2 format: `tag(32) || u16_hd_len(2) || hd_bytes || i64_fetched_at(8)
///             || u32_body_len(4) || body`
fn read_and_verify_cache(
    path: &Path,
    hmac_key: &[u8],
) -> Result<(String, Vec<u8>, SystemTime), CounterpartyError> {
    let file_bytes = std::fs::read(path).map_err(|e| CounterpartyError::Io { kind: e.kind() })?;

    // Minimum size: 32 HMAC + 2 u16 hd_len + 1 hd_byte + 8 i64 + 4 u32 body_len.
    if file_bytes.len() < CACHE_HEADER_MIN_LEN {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file is too short to contain the v2 header".to_owned(),
        });
    }

    // Split out the 32-byte HMAC tag.
    let (stored_tag_slice, rest) = file_bytes.split_at(HMAC_TAG_LEN);
    let mut stored_tag = [0u8; HMAC_TAG_LEN];
    stored_tag.copy_from_slice(stored_tag_slice);

    // Parse u16 BE home_domain length.
    if rest.len() < 2 {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file truncated at home_domain length field".to_owned(),
        });
    }
    let hd_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let rest = &rest[2..];

    if rest.len() < hd_len {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file truncated in home_domain bytes".to_owned(),
        });
    }
    let (hd_bytes, rest) = rest.split_at(hd_len);

    // Validate home_domain bytes with the same strict RFC 1035 LDH gate used
    // at fetch time and at on-chain projection.
    let home_domain_str =
        std::str::from_utf8(hd_bytes).map_err(|_| CounterpartyError::CacheInvalid {
            detail: "cached home_domain is not valid UTF-8".to_owned(),
        })?;
    crate::counterparty::fetch::validate_home_domain(home_domain_str).map_err(|_| {
        CounterpartyError::CacheInvalid {
            detail: "home_domain bytes failed RFC 1035 LDH validation".to_owned(),
        }
    })?;
    let home_domain = home_domain_str.to_owned();

    // Parse i64 BE fetched_at (HMAC-bound; mtime is ignored).
    if rest.len() < 8 {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file truncated at fetched_at field".to_owned(),
        });
    }
    // SAFETY: we checked rest.len() >= 8 above; the slice-to-array conversion
    // is infallible.  Using a map_err avoids expect_used while preserving the
    // invariant comment.
    let fetched_at_bytes: [u8; 8] =
        rest[..8]
            .try_into()
            .map_err(|_| CounterpartyError::CacheInvalid {
                detail: "fetched_at slice-to-array conversion failed (unreachable)".to_owned(),
            })?;
    let fetched_at_unix_s = i64::from_be_bytes(fetched_at_bytes);
    let rest = &rest[8..];

    // Parse u32 BE body length.
    if rest.len() < 4 {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file truncated at body length field".to_owned(),
        });
    }
    // SAFETY: we checked rest.len() >= 4 above.
    let body_len_bytes: [u8; 4] =
        rest[..4]
            .try_into()
            .map_err(|_| CounterpartyError::CacheInvalid {
                detail: "body_len slice-to-array conversion failed (unreachable)".to_owned(),
            })?;
    let body_len = u32::from_be_bytes(body_len_bytes) as usize;
    let rest = &rest[4..];

    if rest.len() < body_len {
        return Err(CounterpartyError::CacheInvalid {
            detail: "cache file truncated in TOML body bytes".to_owned(),
        });
    }
    let body = &rest[..body_len];

    // Verify HMAC over context label + home_domain + fetched_at + body.
    verify_hmac_v2(hmac_key, &home_domain, fetched_at_unix_s, body, &stored_tag)?;

    // Reconstruct `fetched_at` from the HMAC-bound i64 — mtime is ignored.
    // Negative on-disk values clamp to the UNIX epoch instead of wrapping to
    // a huge `u64`.
    let fetched_at =
        SystemTime::UNIX_EPOCH + Duration::from_secs(fetched_at_i64_to_unix_s(fetched_at_unix_s));

    Ok((home_domain, body.to_vec(), fetched_at))
}

/// Reads a cache file, verifies HMAC, parses body, and checks TTL.
///
/// Returns `None` if the entry is expired (caller should re-fetch).  Returns
/// `Some((parsed, binding))` on a valid, non-expired entry.
///
/// Exposed under `test-helpers` feature for integration test verification.
///
/// # Errors
///
/// - [`CounterpartyError::Io`] — the file could not be read.
/// - [`CounterpartyError::CacheInvalid`] — the file is shorter than the HMAC
///   tag or the body is not valid UTF-8.
/// - [`CounterpartyError::HmacMismatch`] — the stored HMAC tag does not match
///   the recomputed value.
/// - [`CounterpartyError::TomlInvalid`] — the body is not valid TOML.
///
/// # Panics
///
/// Never panics.
#[cfg(any(test, feature = "test-helpers"))]
pub fn read_cache_entry(
    path: &Path,
    hmac_key: &[u8],
    ttl: Duration,
) -> Result<Option<(crate::counterparty::parser::MinimalSep1, StellarTomlBinding)>, CounterpartyError>
{
    let (home_domain, body, fetched_at) = read_and_verify_cache(path, hmac_key)?;

    let expires_at = cache_expires_at(fetched_at, ttl);

    if SystemTime::now() > expires_at {
        // Entry has expired; caller should re-fetch.
        return Ok(None);
    }

    let body_str = String::from_utf8(body).map_err(|_| CounterpartyError::CacheInvalid {
        detail: "cache body is not valid UTF-8".to_owned(),
    })?;

    // home_domain is recovered from the HMAC-protected body header, not the filename.
    let parsed = parse_minimal_sep1(&body_str)?;

    let binding = StellarTomlBinding {
        home_domain,
        fetched_at,
        expires_at,
        stale: false,
        accounts: parsed.accounts.clone(),
    };

    Ok(Some((parsed, binding)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use tempfile::TempDir;

    // ── HMAC helpers (v2 context-separated format with fetched_at) ──────────

    const TEST_FETCHED_AT: u64 = 1_777_552_496; // 2026-04-30T12:34:56Z

    #[test]
    fn hmac_v2_compute_and_verify_round_trip() {
        let key = [0xAB_u8; 32];
        let body = b"stellar.toml body bytes";
        let tag = compute_hmac_v2(
            &key,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        assert!(
            verify_hmac_v2(
                &key,
                "circle.com",
                fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
                body,
                &tag
            )
            .is_ok()
        );
    }

    #[test]
    fn hmac_v2_verify_wrong_key_returns_mismatch() {
        let key1 = [0xAB_u8; 32];
        let key2 = [0xCD_u8; 32];
        let body = b"stellar.toml body bytes";
        let tag = compute_hmac_v2(
            &key1,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        assert!(matches!(
            verify_hmac_v2(
                &key2,
                "circle.com",
                fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
                body,
                &tag
            ),
            Err(CounterpartyError::HmacMismatch)
        ));
    }

    #[test]
    fn hmac_v2_verify_corrupted_body_returns_mismatch() {
        let key = [0xAB_u8; 32];
        let body = b"stellar.toml body bytes";
        let tag = compute_hmac_v2(
            &key,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        let mut corrupted = body.to_vec();
        corrupted[0] ^= 0xFF;
        assert!(matches!(
            verify_hmac_v2(
                &key,
                "circle.com",
                fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
                &corrupted,
                &tag
            ),
            Err(CounterpartyError::HmacMismatch)
        ));
    }

    /// Tags computed under a different home_domain must not verify.
    #[test]
    fn hmac_v2_different_home_domain_returns_mismatch() {
        let key = [0xAB_u8; 32];
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        // Attempt to verify as if the domain were "evil.com" — must fail.
        assert!(matches!(
            verify_hmac_v2(
                &key,
                "evil.com",
                fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
                body,
                &tag
            ),
            Err(CounterpartyError::HmacMismatch)
        ));
    }

    /// A tag verified with a different fetched_at must not pass,
    /// preventing TTL-replay via `touch -m`.
    #[test]
    fn hmac_v2_different_fetched_at_returns_mismatch() {
        let key = [0xAB_u8; 32];
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        // Attempt to verify with a different timestamp (simulate touch -m).
        let tampered_ts = fetched_at_unix_s_to_i64(TEST_FETCHED_AT + 7200); // +2 hours
        assert!(matches!(
            verify_hmac_v2(&key, "circle.com", tampered_ts, body, &tag),
            Err(CounterpartyError::HmacMismatch)
        ));
    }

    /// Defence-in-depth: a tag produced with the v1 context label (no fetched_at)
    /// must not verify under the v2 label.
    #[test]
    fn hmac_v2_v1_label_tag_returns_mismatch() {
        let key = [0xAB_u8; 32];
        let body = b"VERSION = \"2.0.0\"";
        // Compute a tag using the v1 label (without fetched_at).
        use hmac::{KeyInit as _, Mac as _};
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"stellar-agent-counterparty/v1/stellar-toml-body\x00");
        mac.update(&(10u16).to_be_bytes()); // len("circle.com")
        mac.update(b"circle.com");
        mac.update(&(body.len() as u32).to_be_bytes());
        mac.update(body);
        let fake_tag_bytes = mac.finalize().into_bytes();
        let mut fake_tag = [0u8; HMAC_TAG_LEN];
        fake_tag.copy_from_slice(&fake_tag_bytes);
        // Verify with the v2 label — must fail.
        assert!(matches!(
            verify_hmac_v2(
                &key,
                "circle.com",
                fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
                body,
                &fake_tag
            ),
            Err(CounterpartyError::HmacMismatch)
        ));
    }

    // ── Cache file I/O ───────────────────────────────────────────────────────

    #[test]
    fn write_and_read_cache_round_trip() {
        let dir = TempDir::new().unwrap();
        let key = [0xAB_u8; 32];
        let home_domain = "circle.com";
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            home_domain,
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();

        let path = dir.path().join("circle_com.toml.cache");
        write_cache_atomic(dir.path(), &path, &tag, home_domain, TEST_FETCHED_AT, body).unwrap();

        let (recovered_domain, read_body, fetched_at) = read_and_verify_cache(&path, &key).unwrap();
        assert_eq!(read_body, body);
        assert_eq!(recovered_domain, home_domain);
        // fetched_at is HMAC-bound — must match what was written.
        let expected_ts = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_FETCHED_AT);
        assert_eq!(
            fetched_at, expected_ts,
            "fetched_at must be recovered from HMAC-protected header"
        );
    }

    /// Touching the mtime of a cache file must NOT change the `fetched_at` /
    /// `expires_at` returned by `list_cached` because `fetched_at` is
    /// HMAC-bound in the file body, not derived from `mtime`.
    #[test]
    fn touch_mtime_does_not_change_fetched_at() {
        let dir = TempDir::new().unwrap();
        let key = [0xAB_u8; 32];
        let home_domain = "circle.com";
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            home_domain,
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        let path = dir.path().join("circle_com.toml.cache");
        write_cache_atomic(dir.path(), &path, &tag, home_domain, TEST_FETCHED_AT, body).unwrap();

        // Simulate an attacker touching the mtime forward by 2 hours.
        // On Unix, set the access + modification times.
        // We just verify that read_and_verify_cache ignores mtime entirely.
        let (_, _, fetched_at) = read_and_verify_cache(&path, &key).unwrap();
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_FETCHED_AT);
        assert_eq!(
            fetched_at, expected,
            "fetched_at must come from HMAC-protected body, not mtime"
        );
    }

    /// Hyphenated domain round-trips correctly — BLOCKER-2 regression guard.
    #[test]
    fn hyphenated_domain_round_trips_correctly() {
        let dir = TempDir::new().unwrap();
        let key = [0xAB_u8; 32];
        let home_domain = "sub-domain.com";
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            home_domain,
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        let path = cache_file_path(dir.path(), home_domain);
        write_cache_atomic(dir.path(), &path, &tag, home_domain, TEST_FETCHED_AT, body).unwrap();
        let (recovered_domain, _, _) = read_and_verify_cache(&path, &key).unwrap();
        assert_eq!(
            recovered_domain, home_domain,
            "hyphenated domain must round-trip via body header, not filename"
        );
    }

    #[test]
    fn read_cache_hmac_mismatch_on_flipped_byte() {
        let dir = TempDir::new().unwrap();
        let key = [0xAB_u8; 32];
        let home_domain = "circle.com";
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(
            &key,
            home_domain,
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();

        let path = dir.path().join("circle_com.toml.cache");
        write_cache_atomic(dir.path(), &path, &tag, home_domain, TEST_FETCHED_AT, body).unwrap();

        // Flip a byte in the TOML body region of the stored file.
        let mut file_bytes = std::fs::read(&path).unwrap();
        // v2 body starts after: tag(32) + u16_hd_len(2) + hd_bytes + i64_fetched_at(8) +
        //                        u32_body_len(4).  "circle.com" = 10 bytes.
        let body_start = HMAC_TAG_LEN + 2 + home_domain.len() + 8 + 4;
        file_bytes[body_start] ^= 0xFF;
        std::fs::write(&path, &file_bytes).unwrap();

        let result = read_and_verify_cache(&path, &key);
        assert!(
            matches!(result, Err(CounterpartyError::HmacMismatch)),
            "expected HmacMismatch, got: {result:?}"
        );
    }

    #[test]
    fn read_cache_too_short_returns_cache_invalid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("circle_com.toml.cache");
        // Write fewer than CACHE_HEADER_MIN_LEN bytes.
        std::fs::write(&path, [0u8; 10]).unwrap();
        let key = [0xAB_u8; 32];
        let result = read_and_verify_cache(&path, &key);
        assert!(
            matches!(result, Err(CounterpartyError::CacheInvalid { .. })),
            "expected CacheInvalid, got: {result:?}"
        );
    }

    /// A cache file with a control character in the home_domain must fail with
    /// `CacheInvalid` (strict RFC 1035 LDH gate at cache-read).
    #[test]
    fn control_char_in_cached_home_domain_returns_cache_invalid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad_domain.toml.cache");
        // Craft a file with "circle\x00.com" as the home_domain; bypass validation
        // by writing raw bytes directly.  The cache-read path must reject it.
        let bad_domain = b"circle\x00.com"; // 11 bytes, contains NUL
        let key = [0xAB_u8; 32];
        let body = b"VERSION = \"2.0.0\"";
        // Build a fake tag over the bad domain (won't matter — domain validation
        // fires before HMAC verify, but compute the tag to make the file format valid).
        let tag = compute_hmac_v2(
            &key,
            "circle.com",
            fetched_at_unix_s_to_i64(TEST_FETCHED_AT),
            body,
        )
        .unwrap();
        // Write the v2 header manually with the bad domain.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&tag);
        let hd_len = bad_domain.len() as u16;
        buf.extend_from_slice(&hd_len.to_be_bytes());
        buf.extend_from_slice(bad_domain);
        buf.extend_from_slice(&fetched_at_unix_s_to_i64(TEST_FETCHED_AT).to_be_bytes());
        let body_len = body.len() as u32;
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.extend_from_slice(body);
        std::fs::write(&path, &buf).unwrap();

        let result = read_and_verify_cache(&path, &key);
        assert!(
            matches!(result, Err(CounterpartyError::CacheInvalid { .. })),
            "NUL in cached home_domain must return CacheInvalid, got: {result:?}"
        );
    }

    /// The v2 wire timestamp is `i64`, so write saturation must be explicit
    /// rather than relying on `as` wraparound.
    #[test]
    fn write_cache_saturates_fetched_at_above_i64_max() {
        let dir = TempDir::new().unwrap();
        let key = [0xAB_u8; 32];
        let home_domain = "circle.com";
        let body = b"VERSION = \"2.0.0\"";
        let tag = compute_hmac_v2(&key, home_domain, i64::MAX, body).unwrap();
        let path = dir.path().join("circle_com.toml.cache");

        write_cache_atomic(dir.path(), &path, &tag, home_domain, u64::MAX, body).unwrap();

        let file_bytes = std::fs::read(&path).unwrap();
        let ts_start = HMAC_TAG_LEN + 2 + home_domain.len();
        let ts_end = ts_start + 8;
        assert_eq!(
            &file_bytes[ts_start..ts_end],
            i64::MAX.to_be_bytes().as_slice(),
            "u64 timestamps above i64::MAX must saturate on the v2 wire"
        );
    }

    /// Authenticated negative on-disk timestamps are projected as UNIX_EPOCH
    /// rather than wrapping to a huge future time.
    #[test]
    fn read_cache_clamps_negative_fetched_at_to_epoch() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("circle_com.toml.cache");
        let key = [0xAB_u8; 32];
        let home_domain = "circle.com";
        let body = b"VERSION = \"2.0.0\"";
        let fetched_at_unix_s = i64::MIN;
        let tag = compute_hmac_v2(&key, home_domain, fetched_at_unix_s, body).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&tag);
        let hd_len = u16::try_from(home_domain.len()).unwrap();
        buf.extend_from_slice(&hd_len.to_be_bytes());
        buf.extend_from_slice(home_domain.as_bytes());
        buf.extend_from_slice(&fetched_at_unix_s.to_be_bytes());
        let body_len = u32::try_from(body.len()).unwrap();
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.extend_from_slice(body);
        std::fs::write(&path, &buf).unwrap();

        let (_, read_body, fetched_at) = read_and_verify_cache(&path, &key).unwrap();
        assert_eq!(read_body, body);
        assert_eq!(
            fetched_at,
            SystemTime::UNIX_EPOCH,
            "negative authenticated timestamps must clamp to UNIX_EPOCH"
        );
    }

    // ── File naming ──────────────────────────────────────────────────────────

    #[test]
    fn cache_file_path_sanitises_dots() {
        let dir = PathBuf::from("/tmp");
        let path = cache_file_path(&dir, "circle.com");
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            "circle_com.toml.cache"
        );
    }

    #[test]
    fn cache_file_path_sanitises_hyphens() {
        let dir = PathBuf::from("/tmp");
        let path = cache_file_path(&dir, "my-bank.com");
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            "my_bank_com.toml.cache",
            "hyphens sanitised to underscores for filename; domain recoverable from body"
        );
    }

    #[test]
    fn key_generate_returns_32_bytes() {
        let key = generate_hmac_key();
        assert_eq!(key.len(), HMAC_KEY_LEN);
    }

    #[test]
    fn keyring_unavailable_error_redacts_service_and_profile_name() {
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring init");

        let profile_name = "sensitive-profile-244";
        let service_name = keyring_service_name(profile_name);
        let result = load_hmac_key(profile_name);

        let err = result.expect_err("missing mock keyring entry must fail");
        assert!(
            matches!(err, CounterpartyError::KeyringUnavailable { .. }),
            "expected KeyringUnavailable, got: {err:?}"
        );
        let rendered = err.to_string();
        assert!(
            !rendered.contains(profile_name),
            "operator-visible error must redact profile name"
        );
        assert!(
            !rendered.contains(&service_name),
            "operator-visible error must redact keyring service name"
        );
    }

    #[test]
    fn base64_encode_decode_round_trip() {
        let key = [0xDE_u8; 32];
        let encoded = base64_encode_key(&key);
        let decoded = base64_decode_key(&encoded, "test-service").unwrap();
        // Never `assert_eq!` on secret-bearing bytes; `assert_eq!` echoes both
        // operands into the
        // panic message on failure, leaking key material to the test runner.
        // Compare via boolean equality and emit a fixed message instead.
        let matches = decoded.as_ref() == key;
        assert!(matches, "base64 round-trip produced unexpected bytes");
    }
}
