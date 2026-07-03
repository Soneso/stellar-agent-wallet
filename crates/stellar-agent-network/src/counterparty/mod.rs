//! Counterparty resolution substrate — `stellar.toml` (SEP-1) fetch + cache +
//! HMAC-protected integrity.
//!
//! # Module layout
//!
//! | Submodule | Responsibility |
//! |-----------|----------------|
//! | [`fetch`]  | HTTPS-only `stellar.toml` retrieval with 5 s timeout, 64 KiB cap, redirect rejection |
//! | [`parser`] | `toml_edit`-based extraction of SEP-1 fields into [`parser::MinimalSep1`] |
//! | [`cache`]  | HMAC-protected per-profile cache; [`cache::StellarTomlResolver`] implements the trait |
//! | [`validation`] | Shared lowercase LDH `home_domain` validation façade |
//! | [`lock`]   | OFD-advisory single-writer flock (`std::fs::File::try_lock`) |
//!
//! # Threat model boundary
//!
//! The cache HMAC defends against post-fetch local cache tampering only.
//! First-fetch TOFU, TLS-strip-at-refresh, and CT pinning are out of scope
//! for this module.
//!
//! # CounterpartyCacheSnapshot
//!
//! [`CounterpartyCacheSnapshot`] is a frozen, synchronous view of the
//! resolved counterparty cache built from
//! [`CounterpartyResolver::list_cached`] at dispatch time.  It implements
//! [`stellar_agent_core::policy::v1::CounterpartyCacheView`] so the
//! `home_domain_resolved` policy criterion can query cache state
//! synchronously during criterion evaluation without blocking on async I/O.
//!
//! Build one snapshot per dispatch call:
//!
//! ```ignore
//! let snapshot = CounterpartyCacheSnapshot::from_resolver(&*resolver).await?;
//! let ctx = EvalContext::new(...)
//!     .with_counterparty_cache(&snapshot);
//! ```

use std::time::SystemTime;

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Submodules
// ─────────────────────────────────────────────────────────────────────────────

pub mod cache;
pub mod fetch;
pub mod parser;
pub mod validation;

// `lock` is public under `test` or `test-helpers` so integration tests can
// call `CacheLock::acquire` to simulate the WriterLocked race scenario.
// Production callers outside this crate do not access `lock` directly —
// the public API is `StellarTomlResolver`, which acquires the lock internally.
// Test-only public items are feature-gated to avoid exposing internals in
// production builds.
#[cfg(any(test, feature = "test-helpers"))]
pub mod lock;
#[cfg(not(any(test, feature = "test-helpers")))]
pub(crate) mod lock;

pub use cache::StellarTomlResolver;
pub use parser::{MinimalCurrency, MinimalSep1, parse_minimal_sep1};
pub use validation::is_valid_ldh_home_domain;

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyKindParseError — structured parser failures for kind fields
// ─────────────────────────────────────────────────────────────────────────────

/// Structured failures for counterparty kind-field parsing.
///
/// Callers can match these variants directly instead of inspecting
/// free-form parser detail strings.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterpartyKindParseError {
    /// The TOML kind field contained an unrecognised discriminator string.
    #[error("unknown counterparty kind: {kind}")]
    UnknownKind {
        /// Unknown kind string from the TOML input.
        kind: String,
    },

    /// A recognised kind omitted a field required to interpret that kind.
    #[error("missing required field for kind '{kind}': {field}")]
    MissingField {
        /// Recognised kind whose required field is absent.
        kind: String,
        /// Missing TOML field name.
        field: String,
    },

    /// A kind-related TOML field was present but had an invalid value.
    #[error("invalid field value for {field}: {value}")]
    InvalidValue {
        /// TOML field name.
        field: String,
        /// Sanitised representation of the offending value.  Control characters
        /// are replaced with `?` and the rendered length is capped at 64 chars
        /// (with a trailing `...` truncation marker if capped).  Safe to embed
        /// in `tracing` text-formatter output and other operator-facing sinks
        /// (prevents terminal-injection / log-spoofing via crafted TOML scalars).
        /// Sanitisation is applied at the `parser.rs` construction sites via
        /// `sanitize_invalid_value`.
        value: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyError — typed error variants exposed by the resolver substrate
// ─────────────────────────────────────────────────────────────────────────────

/// Typed errors returned by the counterparty resolver and cache substrate.
///
/// Each variant maps to a wire-stable JSON-RPC error code so that an agent
/// observer can react deterministically.  The wire codes are:
///
/// | Variant | Wire code |
/// |---|---|
/// | [`CounterpartyError::WriterLocked`] | `counterparty.writer_locked` |
/// | [`CounterpartyError::CacheInvalid`] | `counterparty.cache_invalid` |
/// | [`CounterpartyError::HmacMismatch`] | `counterparty.hmac_mismatch` |
/// | [`CounterpartyError::FetchFailed`] | `counterparty.fetch_failed` |
/// | [`CounterpartyError::TomlInvalid`] | `counterparty.toml_invalid` |
/// | [`CounterpartyError::KindParseError`] | `counterparty.kind_parse.unknown`, `counterparty.kind_parse.missing_field`, or `counterparty.kind_parse.invalid_value` |
/// | [`CounterpartyError::HomeDomainInvalid`] | `counterparty.home_domain_invalid` |
/// | [`CounterpartyError::KeyringUnavailable`] | `counterparty.keyring_unavailable` |
/// | [`CounterpartyError::Io`] | `counterparty.io` |
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CounterpartyError {
    /// Single-writer flock invariant violated — another wallet process is
    /// holding the per-profile counterparty cache lock.
    #[error("counterparty cache writer is locked by another process")]
    WriterLocked,

    /// Cache file is structurally invalid (truncated, malformed, or missing
    /// the expected HMAC prefix).
    #[error("counterparty cache file is invalid: {detail}")]
    CacheInvalid {
        /// Operator-facing detail. MUST NOT include key material.
        detail: String,
    },

    /// Cache file's HMAC does not match the recomputed value — indicates
    /// tampering or key-rotation drift.  Treated as fail-closed (cache is
    /// discarded; next fetch re-mints).
    #[error("counterparty cache HMAC mismatch — possible tampering or rotation")]
    HmacMismatch,

    /// HTTPS fetch of `stellar.toml` failed (network error, non-200 status,
    /// body too large, redirect loop).
    #[error("counterparty stellar.toml fetch failed: {detail}")]
    FetchFailed {
        /// Operator-facing detail.
        detail: String,
    },

    /// `stellar.toml` parse failed — invalid TOML or missing required
    /// SEP-1 fields.
    #[error("counterparty stellar.toml parse failed: {detail}")]
    TomlInvalid {
        /// Operator-facing detail.
        detail: String,
    },

    /// A counterparty kind field was present but could not be interpreted.
    #[error(transparent)]
    KindParseError(#[from] CounterpartyKindParseError),

    /// Home-domain string is invalid (not strict ASCII, contains control
    /// chars, exceeds the SEP-1 length cap, or is not a valid hostname).
    /// Strict ASCII enforcement defends against IDN homoglyph attacks.
    #[error("counterparty home_domain is invalid: {detail}")]
    HomeDomainInvalid {
        /// Operator-facing detail.  MUST NOT echo the entire home_domain
        /// when it could leak sensitive information.
        detail: String,
    },

    /// Keyring access for `stellar-agent-counterparty-<profile>` failed.
    #[error("counterparty keyring entry unavailable: {detail}")]
    KeyringUnavailable {
        /// Operator-facing detail.
        detail: String,
    },

    /// Underlying I/O failure during cache read or write.
    #[error("counterparty cache I/O failed: {kind}")]
    Io {
        /// `io::ErrorKind` rendered at construction.  The full path is
        /// deliberately omitted to avoid leaking the cache-dir layout.
        kind: std::io::ErrorKind,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// StellarTomlBinding — resolved + verified `stellar.toml` snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved `stellar.toml` snapshot bound to a specific home domain.
///
/// Represents the result of a successful SEP-1 fetch-and-verify cycle:
///
/// 1. Wallet fetches `https://<home_domain>/.well-known/stellar.toml` over TLS.
/// 2. Wallet HMAC-protects the canonical TOML body using the per-profile
///    `stellar-agent-counterparty-<profile>` keyring entry.
/// 3. The HMAC is verified on every subsequent cache read.
///
/// The `stellar.toml` body is retained in the cache for forensic correlation
/// and for the SEP-10 server-key binding step; the binding struct carries only
/// the metadata fields needed for TTL tracking and cache enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StellarTomlBinding {
    /// The strict-ASCII home domain (e.g. `"circle.com"`).  Validated at
    /// construction to reject Unicode homoglyphs and control characters.
    pub home_domain: String,

    /// UNIX timestamp (seconds since epoch) when the binding was established
    /// (resolver wrote the cache file).  Used by the resolver's TTL check.
    pub fetched_at: SystemTime,

    /// UNIX timestamp when the binding becomes stale.  Equal to
    /// `fetched_at + ttl`.  Resolver re-fetches on access if `now > expires_at`.
    pub expires_at: SystemTime,

    /// `true` when the resolver returned an expired HMAC-verified cache entry
    /// because an opt-in stale-if-error fallback handled a transient fetch
    /// failure.
    pub stale: bool,
}

impl StellarTomlBinding {
    /// Constructs a resolved `stellar.toml` binding.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn new(
        home_domain: String,
        fetched_at: SystemTime,
        expires_at: SystemTime,
        stale: bool,
    ) -> Self {
        Self {
            home_domain,
            fetched_at,
            expires_at,
            stale,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a destination's home domain and persists an HMAC-protected
/// `stellar.toml` cache binding.
///
/// [`StellarTomlResolver`] is the production implementation (HTTPS fetch +
/// parser + cache + flock).  The CLI commands `stellar-agent counterparty list`
/// and `refresh` consume this trait.
///
/// # Async vs sync
///
/// The trait is async because `refresh` performs an HTTPS fetch and the cache
/// write performs file I/O.  `list_cached` is async to allow async-locked
/// directory enumeration on platforms where blocking I/O on the dispatch
/// thread is forbidden.
///
/// # Single-writer invariant
///
/// `refresh` acquires the per-profile flock (`<cache_dir>/.lock`) before
/// reading or writing the cache.  Concurrent calls from the same process or
/// from another wallet process competing on the same profile receive
/// [`CounterpartyError::WriterLocked`].
#[async_trait::async_trait]
pub trait CounterpartyResolver: Send + Sync {
    /// Forces a re-fetch of `https://<home_domain>/.well-known/stellar.toml`
    /// and writes the HMAC-protected binding to the per-profile cache.
    ///
    /// On success returns the resolved binding.  On failure returns a typed
    /// [`CounterpartyError`] without writing the cache file.
    ///
    /// # Errors
    ///
    /// See [`CounterpartyError`] for the variant table.
    async fn refresh(&self, home_domain: &str) -> Result<StellarTomlBinding, CounterpartyError>;

    /// Returns the list of currently-cached bindings for this profile.
    ///
    /// Reads the per-profile cache directory, validates each cache file's
    /// HMAC against the keyring entry, and returns the resolved bindings in
    /// arbitrary order (callers sort if needed).  Bindings whose HMAC fails
    /// validation are silently skipped (the resolver does NOT delete invalid
    /// files; the operator must run `stellar-agent counterparty refresh
    /// <home_domain>` to mint a fresh entry).
    ///
    /// # Errors
    ///
    /// Returns [`CounterpartyError::Io`] when the cache directory cannot be
    /// enumerated.  Returns [`CounterpartyError::KeyringUnavailable`] when
    /// the per-profile keyring entry cannot be loaded.
    async fn list_cached(&self) -> Result<Vec<StellarTomlBinding>, CounterpartyError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopCounterpartyResolver — test/default fallback
// ─────────────────────────────────────────────────────────────────────────────

/// A resolver that performs no fetches and reports an empty cache.
///
/// Used as the default at process start when the operator has not yet
/// configured a profile with a counterparty cache key.  CLI / criterion paths
/// that consult the resolver receive empty results and degrade gracefully —
/// the criterion's HOME_DOMAIN match falls back to the on-chain
/// `AccountEntry.home_domain` field surfaced via `AccountReservesView`.
///
/// Useful in tests and as a permissions-degraded fallback.
#[derive(Debug, Default)]
pub struct NoopCounterpartyResolver;

#[async_trait::async_trait]
impl CounterpartyResolver for NoopCounterpartyResolver {
    async fn refresh(&self, _home_domain: &str) -> Result<StellarTomlBinding, CounterpartyError> {
        Err(CounterpartyError::FetchFailed {
            detail: "NoopCounterpartyResolver does not perform fetches".to_owned(),
        })
    }

    async fn list_cached(&self) -> Result<Vec<StellarTomlBinding>, CounterpartyError> {
        Ok(Vec::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CounterpartyCacheSnapshot — synchronous frozen view of the resolved cache
// ─────────────────────────────────────────────────────────────────────────────

/// A frozen, synchronous snapshot of the resolved counterparty cache.
///
/// Built once per dispatch call from [`CounterpartyResolver::list_cached`] and
/// implements [`stellar_agent_core::policy::v1::CounterpartyCacheView`] so
/// the `home_domain_resolved` policy criterion can query cache state
/// synchronously during criterion evaluation without blocking on async I/O.
///
/// # Build once, query many times
///
/// Construct one snapshot before entering the policy-evaluation loop, then pass
/// a reference to `EvalContext::with_counterparty_cache`:
///
/// ```ignore
/// let snapshot = CounterpartyCacheSnapshot::from_resolver(&*resolver).await?;
/// let ctx = EvalContext::new(...)
///     .with_counterparty_cache(&snapshot);
/// ```
///
/// # Snapshot semantics
///
/// The snapshot reflects cache state at construction time.  Bindings added or
/// expired between snapshot construction and criterion evaluation are not
/// visible.  This is intentional — criterion evaluation must be deterministic
/// within a single dispatch cycle.
///
/// # Async-vs-sync boundary
///
/// The snapshot is built from `resolver.list_cached()` at dispatch time rather
/// than querying the resolver directly in the synchronous criterion path.  This
/// keeps the async resolver unchanged and confines the `CounterpartyCacheView`
/// impl entirely to this synchronous snapshot.
#[derive(Debug, Clone)]
pub struct CounterpartyCacheSnapshot {
    resolved: std::collections::HashSet<String>,
}

impl CounterpartyCacheSnapshot {
    /// Builds a snapshot from the current cache state of a
    /// [`CounterpartyResolver`].
    ///
    /// Calls `resolver.list_cached()` once and collects the `home_domain`
    /// keys of all returned bindings.  Bindings whose `home_domain` is absent
    /// are ignored (should never occur given the resolver's validation, but
    /// defensive-ness is warranted).
    ///
    /// # Errors
    ///
    /// Returns [`CounterpartyError`] when `resolver.list_cached()` fails —
    /// typically [`CounterpartyError::Io`] (cache directory unreadable) or
    /// [`CounterpartyError::KeyringUnavailable`] (no HMAC key).  The caller
    /// should log the error and pass `None` as `counterparty_cache` to
    /// `EvalContext` when the resolver is unavailable, rather than hard-
    /// failing the dispatch.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use stellar_agent_network::counterparty::{
    ///     CounterpartyCacheSnapshot, NoopCounterpartyResolver,
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let resolver = NoopCounterpartyResolver;
    /// let snapshot = CounterpartyCacheSnapshot::from_resolver(&resolver)
    ///     .await
    ///     .unwrap();
    /// assert!(!snapshot.has_resolved("example.com"));
    /// # });
    /// ```
    pub async fn from_resolver(
        resolver: &dyn CounterpartyResolver,
    ) -> Result<Self, CounterpartyError> {
        let bindings = resolver.list_cached().await?;
        let resolved = bindings
            .into_iter()
            .map(|b| b.home_domain)
            .collect::<std::collections::HashSet<_>>();
        Ok(Self { resolved })
    }

    /// Returns `true` if the given `home_domain` is present in the snapshot.
    ///
    /// Equivalent to `CounterpartyCacheView::has_resolved` — exposed here so
    /// callers that hold a concrete `CounterpartyCacheSnapshot` reference
    /// (rather than a `&dyn CounterpartyCacheView` trait object) can query
    /// the snapshot directly.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use stellar_agent_network::counterparty::{
    ///     CounterpartyCacheSnapshot, NoopCounterpartyResolver,
    /// };
    ///
    /// # tokio_test::block_on(async {
    /// let resolver = NoopCounterpartyResolver;
    /// let snapshot = CounterpartyCacheSnapshot::from_resolver(&resolver)
    ///     .await
    ///     .unwrap();
    /// assert!(!snapshot.has_resolved("example.com"));
    /// # });
    /// ```
    #[must_use]
    pub fn has_resolved(&self, home_domain: &str) -> bool {
        self.resolved.contains(home_domain)
    }
}

impl stellar_agent_core::policy::v1::CounterpartyCacheView for CounterpartyCacheSnapshot {
    /// Returns `true` if the snapshot contains a resolved binding for
    /// `home_domain`.
    ///
    /// Case-sensitive byte equality — same posture as the counterparty
    /// allowlist criterion for IDN homoglyph defence.
    fn has_resolved(&self, home_domain: &str) -> bool {
        self.resolved.contains(home_domain)
    }
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

    #[tokio::test]
    async fn noop_resolver_refresh_returns_fetch_failed() {
        let resolver = NoopCounterpartyResolver;
        let err = resolver
            .refresh("example.com")
            .await
            .expect_err("NoopCounterpartyResolver::refresh must always fail with FetchFailed");
        assert!(
            matches!(err, CounterpartyError::FetchFailed { .. }),
            "expected FetchFailed, got {err:?}",
        );
    }

    #[tokio::test]
    async fn noop_resolver_list_cached_is_empty() {
        let resolver = NoopCounterpartyResolver;
        let entries = resolver
            .list_cached()
            .await
            .expect("list_cached cannot fail");
        assert!(entries.is_empty(), "Noop resolver must report empty cache");
    }

    // ── CounterpartyCacheSnapshot ─────────────────────────────────────────────

    /// Snapshot built from a noop resolver is empty.
    #[tokio::test]
    async fn snapshot_from_noop_resolver_is_empty() {
        let resolver = NoopCounterpartyResolver;
        let snapshot = CounterpartyCacheSnapshot::from_resolver(&resolver)
            .await
            .expect("noop resolver must not fail list_cached");
        assert!(
            !snapshot.has_resolved("example.com"),
            "empty snapshot must not report any domain as resolved"
        );
    }

    /// Snapshot correctly identifies a domain populated by a stub resolver.
    #[tokio::test]
    async fn snapshot_has_resolved_matches_stub_bindings() {
        use std::time::{Duration, SystemTime};

        // Inline stub resolver that returns a fixed set of bindings.
        struct StubResolver {
            domains: Vec<String>,
        }

        #[async_trait::async_trait]
        impl CounterpartyResolver for StubResolver {
            async fn refresh(
                &self,
                _home_domain: &str,
            ) -> Result<StellarTomlBinding, CounterpartyError> {
                Err(CounterpartyError::FetchFailed {
                    detail: "stub".to_owned(),
                })
            }

            async fn list_cached(&self) -> Result<Vec<StellarTomlBinding>, CounterpartyError> {
                let now = SystemTime::now();
                Ok(self
                    .domains
                    .iter()
                    .map(|d| StellarTomlBinding {
                        home_domain: d.clone(),
                        fetched_at: now,
                        expires_at: now + Duration::from_secs(3600),
                        stale: false,
                    })
                    .collect())
            }
        }

        let resolver = StubResolver {
            domains: vec!["circle.com".to_owned(), "anchor.stellar.org".to_owned()],
        };
        let snapshot = CounterpartyCacheSnapshot::from_resolver(&resolver)
            .await
            .expect("stub resolver must not fail");

        assert!(
            snapshot.has_resolved("circle.com"),
            "circle.com must be reported as resolved"
        );
        assert!(
            snapshot.has_resolved("anchor.stellar.org"),
            "anchor.stellar.org must be reported as resolved"
        );
        assert!(
            !snapshot.has_resolved("unknown.example"),
            "unknown.example must not be reported as resolved"
        );
        // Case-sensitive: uppercase variant must not match.
        assert!(
            !snapshot.has_resolved("Circle.com"),
            "case-sensitive check: Circle.com must not match circle.com"
        );
    }

    /// The `CounterpartyCacheView` trait impl delegates correctly.
    #[tokio::test]
    async fn snapshot_cache_view_trait_delegates() {
        use stellar_agent_core::policy::v1::CounterpartyCacheView;

        let resolver = NoopCounterpartyResolver;
        let snapshot = CounterpartyCacheSnapshot::from_resolver(&resolver)
            .await
            .expect("noop resolver must not fail");
        let view: &dyn CounterpartyCacheView = &snapshot;
        assert!(
            !view.has_resolved("example.com"),
            "trait object delegation must report empty snapshot"
        );
    }
}
