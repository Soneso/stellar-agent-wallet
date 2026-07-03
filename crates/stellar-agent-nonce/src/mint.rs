//! Nonce minting, encoding, and verification.
//!
//! Provides [`Nonce`] (the 48-byte opaque value), [`NonceMint`] (the per-profile
//! minter / verifier), and [`ToolCatalogue`] (the tool-validation interface).
//!
//! # Wire format
//!
//! `Nonce` is 48 bytes transmitted as URL-safe base64 (no padding):
//!
//! ```text
//! bytes[0..16]  = 16-byte random salt (OsRng)
//! bytes[16..48] = 32-byte HMAC-SHA256 tag
//! ```
//!
//! The salt is NOT an HMAC input; it serves only as the HashMap key in the
//! replay window and as nonce uniqueness across concurrent calls.
//!
//! # HMAC input order (canonical form)
//!
//! ```text
//! mac.update(boot_nonce)              // 16 bytes — process-scoped; zeroed on restart
//! mac.update(envelope_hash)           // 32 bytes — SHA-256(envelope_xdr)
//! mac.update(expiry_unix_ms BE)       // 8 bytes big-endian u64
//! mac.update(tool_name.len() as BE4)  // 4 bytes — length prefix (boundary-collision defence)
//! mac.update(tool_name UTF-8)         // variable-length
//! mac.update(chain_id.len() as BE4)   // 4 bytes — length prefix (boundary-collision defence)
//! mac.update(chain_id UTF-8)          // variable-length
//! ```
//!
//! ## Length-prefix rationale
//!
//! Without length prefixes, two different `(tool_name, chain_id)` pairs can
//! produce identical HMAC inputs: `("ab", "cd")` and `("abc", "d")` both
//! concatenate to `"abcd"`.  Length-prefixing each variable-length field with
//! its `u32` byte-count in big-endian order eliminates all such boundary
//! collisions.  The 4 bytes per field are negligible overhead.
//!
//! Three alternatives were considered for fail-closed-on-restart:
//!
//! 1. **HashMap-only replay** — rejected: pre-restart nonces accepted on empty window.
//! 2. **`boot_nonce` as HMAC input** (adopted) — process-restart fails closed.
//! 3. **Persistent monotonic counter** — rejected: operator could opt out of
//!    fail-closed-on-restart by persisting the counter.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use stellar_agent_core::{
    error::AuthError,
    profile::schema::{KeyringEntryRef, Profile},
};

use crate::{ReplayWindow, error::NonceError};

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// ToolCatalogue
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract interface for the registered MCP tool catalogue.
///
/// [`NonceMint::mint`] validates `tool_name` against this trait BEFORE engaging
/// key state.  This trait keeps the nonce crate runtime-free; the MCP tool
/// registry provides a concrete implementation.
///
/// # Examples
///
/// ```
/// use stellar_agent_nonce::ToolCatalogue;
///
/// struct StaticCatalogue;
/// impl ToolCatalogue for StaticCatalogue {
///     fn is_registered(&self, tool_name: &str) -> bool {
///         matches!(tool_name, "stellar_balances" | "stellar_friendbot")
///     }
/// }
///
/// let c = StaticCatalogue;
/// assert!(c.is_registered("stellar_balances"));
/// assert!(!c.is_registered("unknown_tool"));
/// ```
pub trait ToolCatalogue {
    /// Returns `true` if `tool_name` is a registered MCP tool.
    ///
    /// # Panics
    ///
    /// Implementors MUST NOT panic.
    fn is_registered(&self, tool_name: &str) -> bool;
}

// -----------------------------------------------------------------------------
// Verification requests
// -----------------------------------------------------------------------------

/// Request parameters for [`NonceMint::verify`].
///
/// Groups the replay-window state, nonce identity, envelope binding, tool
/// binding, chain binding, and verification clock into one call-site object.
pub struct NonceVerifyRequest<'a> {
    /// Replay window that records the nonce after HMAC verification succeeds.
    pub replay_window: &'a mut ReplayWindow,
    /// Wallet-issued nonce supplied by the MCP commit request.
    pub nonce: &'a Nonce,
    /// Canonical transaction envelope XDR bytes from the MCP commit envelope.
    pub envelope_xdr: &'a [u8],
    /// Expiry timestamp bound into the nonce, in Unix milliseconds.
    pub expiry_unix_ms: u64,
    /// Registered MCP tool name bound into the nonce.
    pub tool_name: &'a str,
    /// CAIP-2 chain id from the active profile and MCP commit request.
    pub chain_id: &'a str,
    /// Verification clock value in Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Request parameters for [`NonceMint::verify_hmac_only`].
///
/// This carries the same nonce binding fields as [`NonceVerifyRequest`] but
/// omits the replay window because the caller records replay state after the
/// blocking HMAC phase completes.
#[derive(Clone, Copy)]
pub struct NonceVerifyHmacOnlyRequest<'a> {
    /// Wallet-issued nonce supplied by the MCP commit request.
    pub nonce: &'a Nonce,
    /// Canonical transaction envelope XDR bytes from the MCP commit envelope.
    pub envelope_xdr: &'a [u8],
    /// Expiry timestamp bound into the nonce, in Unix milliseconds.
    pub expiry_unix_ms: u64,
    /// Registered MCP tool name bound into the nonce.
    pub tool_name: &'a str,
    /// CAIP-2 chain id from the active profile and MCP commit request.
    pub chain_id: &'a str,
    /// Verification clock value in Unix milliseconds.
    pub now_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Nonce
// ─────────────────────────────────────────────────────────────────────────────

/// A 48-byte single-use nonce: 16-byte random salt + 32-byte HMAC-SHA256 tag.
///
/// Opaque value; inspect only via [`to_base64`] / [`from_base64`].
/// The internal layout is stable and documented in the crate `//!` header.
///
/// Transmitted to the MCP agent as a URL-safe base64 string (no padding).
///
/// # Trait derive policy
///
/// This type intentionally does not derive or implement `PartialEq` or `Hash`.
/// Equality on nonce values is a timing-attack surface unless performed with a
/// constant-time comparison such as `subtle::ConstantTimeEq`. [`ReplayWindow`]
/// already keys on the raw 48-byte inner array (`[u8; 48]`), so no caller needs
/// `PartialEq` on `Nonce`. If a future consumer requires equality, implement it
/// with `subtle::ConstantTimeEq` rather than `#[derive]`.
///
/// [`to_base64`]: Nonce::to_base64
/// [`from_base64`]: Nonce::from_base64
#[derive(Clone)]
pub struct Nonce {
    /// `[salt(16) || hmac_tag(32)]`
    inner: [u8; 48],
}

impl Nonce {
    /// Returns the 16-byte random salt portion of this nonce.
    ///
    /// Used as the HashMap key in the [`ReplayWindow`].
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// **Test-helpers gate:** only available when the `test-helpers` Cargo
    /// feature is enabled (or in `#[cfg(test)]` contexts).  Do not use in
    /// production code.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn salt(&self) -> [u8; 16] {
        // `inner` is [u8; 48]; copy the first 16 bytes as a stack array.
        let mut s = [0u8; 16];
        s.copy_from_slice(&self.inner[..16]);
        s
    }

    /// Returns the 32-byte HMAC-SHA256 tag portion of this nonce.
    ///
    /// **Do not log this value.** The HMAC tag is derived from the nonce key;
    /// while it does not directly reveal the key, logging it creates an oracle
    /// for offline pre-image attacks.
    ///
    /// **Test-helpers gate:** only available when the `test-helpers` Cargo
    /// feature is enabled (or in `#[cfg(test)]` contexts).
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn tag(&self) -> [u8; 32] {
        // `inner` is [u8; 48]; copy bytes 16..48 as a stack array.
        let mut t = [0u8; 32];
        t.copy_from_slice(&self.inner[16..]);
        t
    }

    /// Returns the full 48-byte `[salt || tag]` array.
    ///
    /// Used by the MCP commit handler to record the nonce in the replay window
    /// after a successful `verify_hmac_only` call (HMAC runs in
    /// `spawn_blocking`; replay record runs under lock with no I/O).
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn inner_bytes(&self) -> [u8; 48] {
        self.inner
    }

    /// Encodes this nonce as URL-safe base64 (no padding).
    ///
    /// The output is 64 characters long (48 bytes × 4/3, rounded up to 64).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(any(test, feature = "test-helpers"))]
    /// # {
    /// # use stellar_agent_nonce::mint::Nonce;
    /// let n = Nonce::from_raw([0u8; 48]);
    /// let b64 = n.to_base64();
    /// assert_eq!(b64.len(), 64);
    /// # }
    /// ```
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.inner)
    }

    /// Decodes a nonce from URL-safe base64 (no padding).
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::SerialiseFailed`] if the string is not valid
    /// base64 or does not decode to exactly 48 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(any(test, feature = "test-helpers"))]
    /// # {
    /// # use stellar_agent_nonce::mint::Nonce;
    /// let n = Nonce::from_raw([0u8; 48]);
    /// let b64 = n.to_base64();
    /// let decoded = Nonce::from_base64(&b64).expect("valid base64");
    /// assert_eq!(n.to_base64(), decoded.to_base64());
    /// # }
    /// ```
    pub fn from_base64(s: &str) -> Result<Self, NonceError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| NonceError::SerialiseFailed {
                detail: "base64 decode error".to_owned(),
            })?;
        if bytes.len() != 48 {
            return Err(NonceError::SerialiseFailed {
                detail: format!("expected 48 bytes, got {}", bytes.len()),
            });
        }
        let mut inner = [0u8; 48];
        inner.copy_from_slice(&bytes);
        Ok(Self { inner })
    }

    /// Constructs a `Nonce` directly from a 48-byte array.
    ///
    /// **Test-helpers gate:** only available when the `test-helpers` Cargo
    /// feature is enabled (or in `#[cfg(test)]` contexts).  The production
    /// path is [`NonceMint::mint`].
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn from_raw(bytes: [u8; 48]) -> Self {
        Self { inner: bytes }
    }
}

impl std::fmt::Debug for Nonce {
    /// Shows the first 4 bytes of the 16-byte salt as hex for tracing
    /// correlation (`salt=aabbccdd...`).
    ///
    /// The full 32-byte HMAC-SHA256 tag is **redacted entirely**.  Rationale:
    /// although the tag alone does not reveal the key, logging it creates an
    /// oracle for offline pre-image attacks; a 4-byte salt prefix is
    /// sufficient to correlate log lines across mint and verify calls.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Nonce(salt={:02x}{:02x}{:02x}{:02x}..., tag=[REDACTED])",
            self.inner[0], self.inner[1], self.inner[2], self.inner[3]
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NonceMint
// ─────────────────────────────────────────────────────────────────────────────

/// Process-scoped boot nonce: lazily initialised on first `NonceMint` construction.
///
/// All `NonceMint` instances in the same process share the same `boot_nonce`.
/// A process restart generates a new `boot_nonce`, so all pre-restart nonces
/// fail HMAC verification — this is the fail-closed-on-restart property.
///
/// `OnceLock` guarantees exactly-once initialisation across threads without
/// locking after the first write.
static PROCESS_BOOT_NONCE: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();

/// Returns the process-scoped `boot_nonce`, initialising it from `OsRng` on
/// first call.
fn process_boot_nonce() -> &'static [u8; 16] {
    PROCESS_BOOT_NONCE.get_or_init(|| {
        let mut boot_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut boot_nonce);
        boot_nonce
    })
}

/// Per-profile HMAC-SHA256 nonce minter and verifier.
///
/// Holds no key bytes.  The HMAC key is lazy-loaded from the platform keyring
/// on every [`mint`] or [`verify`] call and zeroised immediately after.
///
/// # Key residency
///
/// The nonce key exists only within a single `load_key` call's stack frame —
/// a `Zeroizing<[u8; 32]>` that is dropped before the function returns.  The
/// `NonceMint` itself is safe to hold in an `Arc` across async tasks.
///
/// # Fail-closed-on-restart
///
/// The process-scoped `PROCESS_BOOT_NONCE` is a 16-byte value generated from
/// `OsRng` once per process and never persisted.  It is included in the HMAC
/// input so any nonce minted before a process restart fails HMAC verification
/// after the restart (the new process generates a fresh `boot_nonce`).
/// Callers SHOULD map such failures to `nonce.expired`.
///
/// All `NonceMint` instances within the same process share the same
/// `boot_nonce`.  Callers MUST hold a single `Arc<NonceMint>` per profile
/// across mint and verify calls — constructing separate `NonceMint` instances
/// in the same process is valid (they share `boot_nonce`) but wastes the
/// keyring load on every call.
///
/// # Self-custodial key residency
///
/// The HMAC nonce key never leaves the user's host.  The `mcp_nonce_key_alias`
/// reference stored here is the non-secret keyring coordinate pair; it does not
/// contain the key itself.
///
/// [`mint`]: NonceMint::mint
/// [`verify`]: NonceMint::verify
pub struct NonceMint {
    /// Non-secret keyring reference for the HMAC nonce key.
    entry_ref: KeyringEntryRef,
    /// CAIP-2 chain identifier from the profile (non-secret).
    ///
    /// Validated at every `mint` and `verify` call: the caller-supplied
    /// `chain_id` must match this value (chain binding).
    chain_id: String,
    /// Maximum nonce TTL in milliseconds.
    ///
    /// Validated at `mint` time: `expiry_unix_ms - now_unix_ms` must not
    /// exceed this value, and must not be below `MIN_TTL_MS`.
    max_ttl_ms: u64,
}

impl NonceMint {
    /// Maximum configurable TTL: 5 minutes.
    pub const MAX_TTL_MS: u64 = 300_000;
    /// Minimum configurable TTL: 30 seconds.
    pub const MIN_TTL_MS: u64 = 30_000;

    /// Constructs a `NonceMint` from a loaded profile.
    ///
    /// Triggers lazy initialisation of the process-scoped `PROCESS_BOOT_NONCE`
    /// on first call.  Does NOT load the HMAC key at construction time
    /// (lazy-load only at `mint`/`verify`).
    ///
    /// The `max_ttl_ms` is clamped to `[MIN_TTL_MS, MAX_TTL_MS]`.
    ///
    /// # Errors
    ///
    /// Never errors in the current implementation.  The return type is `Result`
    /// for forward compatibility with future validation (e.g. reachability probe).
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::profile::schema::Profile;
    /// use stellar_agent_nonce::NonceMint;
    ///
    /// # fn make_profile() -> Profile {
    /// #     Profile::builder_testnet(
    /// #         "stellar-agent-signer",
    /// #         "alice-testnet",
    /// #         "stellar-agent-nonce",
    /// #         "alice-nonce",
    /// #     ).build()
    /// # }
    /// let profile = make_profile();
    /// let mint = NonceMint::from_profile(&profile)?;
    /// # Ok::<_, stellar_agent_nonce::NonceError>(())
    /// ```
    pub fn from_profile(profile: &Profile) -> Result<Self, NonceError> {
        // Ensure the process-scoped boot_nonce is initialised.
        let _ = process_boot_nonce();
        Ok(Self {
            entry_ref: profile.mcp_nonce_key_alias.clone(),
            chain_id: profile.chain_id.to_string(),
            max_ttl_ms: Self::MAX_TTL_MS,
        })
    }

    /// Returns the process-scoped `boot_nonce`.
    ///
    /// All `NonceMint` instances in this process return the same value.
    /// Non-secret in isolation (random bytes without the HMAC key); exposed for
    /// testing only.
    ///
    /// **Test-helpers gate:** only available when the `test-helpers` Cargo
    /// feature is enabled (or in `#[cfg(test)]` contexts).
    ///
    /// # Panics
    ///
    /// Never panics.
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    #[must_use]
    pub fn boot_nonce(&self) -> &'static [u8; 16] {
        process_boot_nonce()
    }

    /// Mints a new nonce binding for the given tool call parameters.
    ///
    /// Validation order (tool validation runs before key state is engaged):
    ///
    /// 1. Validate `tool_name` against `registered_tools`.
    /// 2. Validate `envelope_xdr` is non-empty.
    /// 3. Validate `chain_id` matches the profile's chain (`ChainMismatch`).
    /// 4. Validate TTL range: `expiry_unix_ms - now_unix_ms` must be in
    ///    `[MIN_TTL_MS, max_ttl_ms]` (`TtlTooShort` / `TtlExceeded`).
    /// 5. Load the HMAC key from the keyring (lazy).
    /// 6. Compute `SHA-256(envelope_xdr)`.
    /// 7. Generate 16-byte `OsRng` salt.
    /// 8. Compute HMAC-SHA256 tag (with length-prefix separators).
    /// 9. Zeroise the key.
    /// 10. Return `Nonce(salt || tag)`.
    ///
    /// # Async
    ///
    /// This method is synchronous and performs blocking platform-keyring I/O
    /// at step 5 (macOS Keychain / D-Bus / Windows Credential Store depending on
    /// the platform).  On Linux with a D-Bus keyring the call can take tens to
    /// hundreds of milliseconds.  Callers running inside a Tokio async context
    /// MUST wrap this call in `tokio::task::spawn_blocking` to avoid blocking
    /// the async executor.  The MCP simulate handlers call `mint` directly because
    /// the simulate tools are not on the Tokio hot path; the documented contract
    /// (caller wraps when on a hot path) is the decided resolution — the internal
    /// implementation stays synchronous because keyring backends are synchronous.
    ///
    /// # Errors
    ///
    /// - [`NonceError::InvalidTool`] if `tool_name` is not in `registered_tools`
    ///   (no key state engaged).
    /// - [`NonceError::InvalidEnvelope`] if `envelope_xdr` is empty.
    /// - [`NonceError::ChainMismatch`] if `chain_id` differs from the profile's.
    /// - [`NonceError::TtlExceeded`] if `expiry - now > max_ttl_ms`.
    /// - [`NonceError::TtlTooShort`] if `expiry - now < MIN_TTL_MS`.
    /// - [`NonceError::Expired`] if `expiry_unix_ms <= now_unix_ms`
    ///   (i.e. already expired at mint time).
    /// - [`NonceError::KeyringError`] if the HMAC key cannot be loaded.
    /// - [`NonceError::KeyTooShort`] if the decoded key is fewer than 32 bytes.
    /// - [`NonceError::SerialiseFailed`] if the keyring entry is not valid base64.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn mint(
        &self,
        registered_tools: &dyn ToolCatalogue,
        envelope_xdr: &[u8],
        now_unix_ms: u64,
        expiry_unix_ms: u64,
        tool_name: &str,
        chain_id: &str,
    ) -> Result<Nonce, NonceError> {
        // 1. Validate tool BEFORE any key state.
        if !registered_tools.is_registered(tool_name) {
            return Err(NonceError::InvalidTool {
                tool: tool_name.to_owned(),
            });
        }

        // 2. Envelope non-empty check.
        if envelope_xdr.is_empty() {
            return Err(NonceError::InvalidEnvelope);
        }

        // 3. Chain binding: caller-supplied chain_id must match the profile.
        if chain_id != self.chain_id {
            return Err(NonceError::ChainMismatch {
                expected: self.chain_id.clone(),
                got: chain_id.to_owned(),
            });
        }

        // 4. TTL range enforcement.
        let ttl = expiry_unix_ms
            .checked_sub(now_unix_ms)
            .ok_or(NonceError::Expired)?;
        if ttl > self.max_ttl_ms {
            return Err(NonceError::TtlExceeded {
                max_ms: self.max_ttl_ms,
                requested_ms: ttl,
            });
        }
        if ttl < Self::MIN_TTL_MS {
            return Err(NonceError::TtlTooShort {
                min_ms: Self::MIN_TTL_MS,
                requested_ms: ttl,
            });
        }

        // 5. Load key — zeroised on all exit paths by Zeroizing<T> Drop.
        let key = self.load_key()?;

        // 6-8. Generate tag with length-prefix separators (boundary-collision defence).
        let tag = compute_tag(
            &key,
            process_boot_nonce(),
            envelope_xdr,
            expiry_unix_ms,
            tool_name,
            chain_id,
        )?;

        // 7. Generate 16-byte random salt (uniqueness + replay window key).
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut inner = [0u8; 48];
        inner[..16].copy_from_slice(&salt);
        inner[16..].copy_from_slice(tag.as_ref());

        tracing::debug!(
            tool = tool_name,
            chain = chain_id,
            expiry_ms = expiry_unix_ms,
            "nonce minted"
        );

        Ok(Nonce { inner })
    }

    /// Verifies a nonce binding.
    ///
    /// Checks (in order):
    ///
    /// 1. Not expired (`expiry_unix_ms > now_unix_ms`).
    /// 2. `chain_id` matches the profile's chain.
    /// 3. Salt not in `replay_window` (not yet consumed).
    /// 4. HMAC tag matches (constant-time comparison via `subtle::ConstantTimeEq`).
    /// 5. Records the nonce (full 48 bytes) in `replay_window`.
    ///
    /// The replay window MUST be checked and MUST record the nonce on success.
    /// The caller owns the `ReplayWindow` and is responsible for calling
    /// [`ReplayWindow::evict_expired`] periodically.
    ///
    /// # Async
    ///
    /// This method is synchronous and performs blocking platform-keyring I/O
    /// (same as [`NonceMint::mint`]).  MCP commit handlers use the split
    /// [`NonceMint::verify_hmac_only`] + [`NonceMint::record_verified_nonce`]
    /// approach where `verify_hmac_only` runs inside `tokio::task::spawn_blocking`
    /// (see `tools/common.rs::commit_envelope_and_verify_nonce`).  Callers that
    /// do NOT need the split behaviour MUST wrap this method in
    /// `tokio::task::spawn_blocking` when called from an async context.
    ///
    /// # Errors
    ///
    /// - [`NonceError::Expired`] if `now_unix_ms >= expiry_unix_ms`.
    /// - [`NonceError::ChainMismatch`] if `chain_id` differs from the profile's.
    /// - [`NonceError::Replayed`] if the nonce is already in the replay window.
    /// - [`NonceError::HmacMismatch`] if the HMAC tag does not match.
    /// - [`NonceError::KeyringError`] / [`NonceError::KeyTooShort`] /
    ///   [`NonceError::SerialiseFailed`] on key-load failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stellar_agent_nonce::{NonceMint, NonceVerifyRequest, ToolCatalogue, ReplayWindow};
    /// # use std::time::Duration;
    /// # struct AllTools;
    /// # impl ToolCatalogue for AllTools { fn is_registered(&self, _: &str) -> bool { true } }
    /// # async fn example() -> Result<(), stellar_agent_nonce::NonceError> {
    /// # use stellar_agent_core::profile::schema::Profile;
    /// # let p = Profile::builder_testnet(
    /// #     "stellar-agent-signer",
    /// #     "alice-testnet",
    /// #     "stellar-agent-nonce",
    /// #     "alice-nonce",
    /// # ).build();
    /// let mint = NonceMint::from_profile(&p)?;
    /// let now = now_ms();
    /// let expiry = now + 300_000;
    /// let nonce = mint.mint(&AllTools, b"xdr", now, expiry, "stellar_balances", "stellar:testnet")?;
    /// let mut window = ReplayWindow::new();
    /// mint.verify(NonceVerifyRequest {
    ///     replay_window: &mut window,
    ///     nonce: &nonce,
    ///     envelope_xdr: b"xdr",
    ///     expiry_unix_ms: expiry,
    ///     tool_name: "stellar_balances",
    ///     chain_id: "stellar:testnet",
    ///     now_unix_ms: now,
    /// })?;
    /// # fn now_ms() -> u64 { 0 }
    /// # Ok(()) }
    /// ```
    pub fn verify(&self, req: NonceVerifyRequest<'_>) -> Result<(), NonceError> {
        let NonceVerifyRequest {
            replay_window,
            nonce,
            envelope_xdr,
            expiry_unix_ms,
            tool_name,
            chain_id,
            now_unix_ms,
        } = req;

        // 1. Expiry check.
        if now_unix_ms >= expiry_unix_ms {
            return Err(NonceError::Expired);
        }

        // 2. Chain binding check — same invariant as mint.
        if chain_id != self.chain_id {
            return Err(NonceError::ChainMismatch {
                expected: self.chain_id.clone(),
                got: chain_id.to_owned(),
            });
        }

        // 3. Replay check (before key load; lookup is cheap).
        //    Key is the full 48-byte nonce (salt + tag) for defence-in-depth.
        let full_nonce: [u8; 48] = nonce.inner;
        replay_window.check_not_replayed(&full_nonce)?;

        // 4. Load key — zeroised on all exit paths.
        let key = self.load_key()?;

        // 5. Recompute HMAC tag.
        let recomputed = compute_tag(
            &key,
            process_boot_nonce(),
            envelope_xdr,
            expiry_unix_ms,
            tool_name,
            chain_id,
        )?;

        // 6. Constant-time comparison (subtle::ConstantTimeEq).
        let stored: [u8; 32] = {
            let mut t = [0u8; 32];
            t.copy_from_slice(&nonce.inner[16..]);
            t
        };
        let tags_match: bool = recomputed.ct_eq(&stored).into();
        if !tags_match {
            return Err(NonceError::HmacMismatch);
        }

        // 7. Record in replay window (only after successful HMAC check).
        replay_window.record(full_nonce, expiry_unix_ms)?;

        tracing::debug!(
            tool = tool_name,
            chain = chain_id,
            "nonce verified and consumed"
        );

        Ok(())
    }

    /// Verifies expiry, chain binding, and HMAC tag without touching the replay window.
    ///
    /// Intended for async callers that must run keyring/HMAC work outside the
    /// replay-window lock.  The caller is responsible for:
    ///
    /// 1. Calling this method (with keyring I/O) OUTSIDE the replay-window lock
    ///    and INSIDE `tokio::task::spawn_blocking` to avoid blocking the executor.
    /// 2. On `Ok`, acquiring the replay window lock and calling
    ///    [`ReplayWindow::evict_expired`] then
    ///    [`NonceMint::record_verified_nonce`] to complete the TOCTOU-bounded
    ///    replay check.
    ///
    /// # TOCTOU note
    ///
    /// There is a narrow window between this call and the subsequent `record`
    /// where a concurrent request could complete with the same nonce.  That
    /// concurrent request would also pass `verify_hmac_only` but fail `record`
    /// with `Replayed`.  The overall nonce correctness guarantee is maintained
    /// because a replayed nonce never produces two committed transactions.
    ///
    /// # Security
    ///
    /// **Residual timing channel.** This function returns early on `Expired`
    /// (no keyring I/O or HMAC computation), while a tampered nonce that passes
    /// the expiry check executes the full keyring load + tag computation +
    /// constant-time compare path.  The wall-clock latency delta (typically tens
    /// to hundreds of milliseconds on D-Bus keyrings on Linux) is observable
    /// from outside the wallet binary and provides a side-channel that can
    /// distinguish `Expired` from `HmacMismatch` at the transport layer.
    ///
    /// This does **NOT** enable HMAC-key recovery: the constant-time comparison
    /// via `subtle::ConstantTimeEq` is preserved for the HMAC path.  The
    /// indistinguishability invariant is `SHOULD` (not `MUST`); the agent-visible
    /// JSON response is byte-identical for both variants (both map to the
    /// `nonce.expired` wire code and the same human-readable message).
    ///
    /// Fixed-latency padding (e.g. a `tokio::time::sleep` for a minimum total
    /// duration) may be added if the threat model evolves to require
    /// transport-layer indistinguishability.
    ///
    /// # Errors
    ///
    /// - [`NonceError::Expired`] if `now_unix_ms >= expiry_unix_ms`.
    /// - [`NonceError::ChainMismatch`] if `chain_id` differs from the profile's.
    /// - [`NonceError::HmacMismatch`] if the recomputed HMAC tag does not match.
    /// - [`NonceError::KeyringError`] / [`NonceError::KeyTooShort`] /
    ///   [`NonceError::SerialiseFailed`] on key-load failure.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn verify_hmac_only(&self, req: NonceVerifyHmacOnlyRequest<'_>) -> Result<(), NonceError> {
        let NonceVerifyHmacOnlyRequest {
            nonce,
            envelope_xdr,
            expiry_unix_ms,
            tool_name,
            chain_id,
            now_unix_ms,
        } = req;

        // 1. Expiry check.
        if now_unix_ms >= expiry_unix_ms {
            return Err(NonceError::Expired);
        }

        // 2. Chain binding check.
        if chain_id != self.chain_id {
            return Err(NonceError::ChainMismatch {
                expected: self.chain_id.clone(),
                got: chain_id.to_owned(),
            });
        }

        // 3. Load key (this is the blocking keyring IPC call).
        let key = self.load_key()?;

        // 4. Recompute HMAC tag.
        let recomputed = compute_tag(
            &key,
            process_boot_nonce(),
            envelope_xdr,
            expiry_unix_ms,
            tool_name,
            chain_id,
        )?;

        // 5. Constant-time tag comparison.
        let stored: [u8; 32] = {
            let mut t = [0u8; 32];
            t.copy_from_slice(&nonce.inner[16..]);
            t
        };
        let tags_match: bool = recomputed.ct_eq(&stored).into();
        if !tags_match {
            return Err(NonceError::HmacMismatch);
        }

        tracing::debug!(
            tool = tool_name,
            chain = chain_id,
            "nonce HMAC verified (replay check deferred to caller)"
        );

        Ok(())
    }

    /// Records a nonce in the replay window after [`NonceMint::verify_hmac_only`] succeeds.
    ///
    /// For async callers that run keyring/HMAC work outside the replay-window
    /// lock. Callers must invoke this only after `verify_hmac_only` returns
    /// `Ok(())` for the same `nonce`, envelope, expiry, tool, chain, and
    /// timestamp tuple.
    ///
    /// # Errors
    ///
    /// Returns [`NonceError::Replayed`] if `nonce` is already present in the
    /// replay window.
    pub fn record_verified_nonce(
        &self,
        replay_window: &mut ReplayWindow,
        nonce: &Nonce,
        expiry_unix_ms: u64,
    ) -> Result<(), NonceError> {
        replay_window.record(nonce.inner, expiry_unix_ms)
    }

    /// Loads the 32-byte HMAC key from the platform keyring.
    ///
    /// The returned `Zeroizing<[u8; 32]>` is zeroed when it drops.  The caller
    /// MUST NOT store the array beyond the scope of a single HMAC operation.
    ///
    /// # Key encoding
    ///
    /// The keyring entry stores the key as URL-safe base64 (no padding).
    /// See crate `//!` header for the encoding rationale.
    ///
    /// # Errors
    ///
    /// - [`NonceError::KeyringError`] if the platform keyring is unavailable,
    ///   the entry does not exist, or the keyring is locked.
    /// - [`NonceError::SerialiseFailed`] if the stored value is not valid base64.
    /// - [`NonceError::KeyTooShort`] if fewer than 32 bytes decode.
    ///
    /// # Panics
    ///
    /// Never panics.
    fn load_key(&self) -> Result<Zeroizing<[u8; 32]>, NonceError> {
        // Open the keyring entry (cheap: one Arc clone).
        let entry =
            KeyringEntry::new(&self.entry_ref.service, &self.entry_ref.account).map_err(|e| {
                tracing::debug!(error = %e, "nonce keyring entry construction failed");
                NonceError::KeyringError(AuthError::KeyringNotFound {
                    name: "nonce key entry construction failed".to_owned(),
                })
            })?;

        // Retrieve the password as a Zeroizing<String> to clear it on drop.
        let raw: Zeroizing<String> = Zeroizing::new(entry.get_password().map_err(|e| {
            tracing::debug!(error = %e, "nonce keyring get_password failed");
            NonceError::KeyringError(AuthError::KeyringNotFound {
                name: "nonce key not found in keyring".to_owned(),
            })
        })?);

        // Base64-decode into a Zeroizing<Vec<u8>>.
        let decoded: Zeroizing<Vec<u8>> =
            Zeroizing::new(URL_SAFE_NO_PAD.decode(raw.as_bytes()).map_err(|_| {
                NonceError::SerialiseFailed {
                    detail: "nonce key base64 decode error".to_owned(),
                }
            })?);

        if decoded.len() < 32 {
            return Err(NonceError::KeyTooShort {
                actual: decoded.len(),
            });
        }

        // Copy first 32 bytes into a Zeroizing<[u8; 32]>.
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded[..32]);
        let key_z: Zeroizing<[u8; 32]> = Zeroizing::new(key);

        // Panic-injection hook — only compiled when `test-hooks` feature is enabled.
        // Placed AFTER the secret-bearing `Zeroizing<T>` wrappers (raw, decoded,
        // key_z) are constructed and live on the stack, so that the integration
        // test verifies Drop fires on the unwind path with actual secret-bearing
        // wrappers in scope.
        //
        // SAFETY: the panic immediately precedes a successful return; the
        // wrappers' `Drop::drop` runs as part of the unwind, zeroising heap +
        // stack copies of the loaded key.
        #[cfg(feature = "test-hooks")]
        #[allow(
            clippy::panic,
            reason = "test-only panic injection hook gated on test-hooks feature"
        )]
        if PANIC_AFTER_LOAD.load(std::sync::atomic::Ordering::SeqCst) {
            DROP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("panic-injection test — PANIC_AFTER_LOAD triggered in nonce::load_key");
        }

        // raw and decoded are dropped here; their Zeroizing wrappers fire.
        Ok(key_z)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only hooks (panic-injection for zeroisation panic-safety)
// ─────────────────────────────────────────────────────────────────────────────

/// Toggle set to `true` by the panic-injection integration test before calling
/// `NonceMint::mint` (which calls `load_key`).  When armed, `load_key` panics
/// after opening the keyring entry but before returning the key, proving that
/// `Zeroizing::Drop` fires during stack unwind.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static PANIC_AFTER_LOAD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Counter incremented by the panic-injection hook and by the `DropSentinel`
/// in the panic-injection integration test.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static DROP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the HMAC-SHA256 tag for the canonical input domain.
///
/// Input order with length-prefix boundary separators:
///
/// ```text
/// boot_nonce        (16 bytes, fixed)
/// SHA-256(envelope) (32 bytes, fixed)
/// expiry_unix_ms    (8 bytes, big-endian u64)
/// tool_name.len()   (4 bytes, big-endian u32) — boundary separator
/// tool_name         (variable UTF-8)
/// chain_id.len()    (4 bytes, big-endian u32) — boundary separator
/// chain_id          (variable UTF-8)
/// ```
///
/// Length prefixes prevent boundary-collision attacks: without them,
/// `(tool="ab", chain="cd")` and `(tool="abc", chain="d")` both yield the
/// concatenation `"abcd"` and produce identical HMAC tags.
///
/// Returns a 32-byte `Zeroizing<[u8; 32]>` that is zeroed on drop.
///
/// # Errors
///
/// Returns:
/// - [`NonceError::KeyTooShort`] if the key slice is empty (i.e. `key` is a
///   zero-length slice). In practice `key` is always `&[u8; 32]` (32 bytes),
///   so this path is unreachable; the typed error is returned rather than
///   panicking.
/// - [`NonceError::InputTooLong`] if `tool_name.len()` or `chain_id.len()`
///   exceeds `u32::MAX`, which cannot be represented by the canonical length
///   prefix.
///
/// # Panics
///
/// Never panics.
fn compute_tag(
    key: &[u8; 32],
    boot_nonce: &[u8; 16],
    envelope_xdr: &[u8],
    expiry_unix_ms: u64,
    tool_name: &str,
    chain_id: &str,
) -> Result<Zeroizing<[u8; 32]>, NonceError> {
    // SHA-256(envelope_xdr) per the canonical HMAC input domain.
    let envelope_hash = Sha256::digest(envelope_xdr);

    // `new_from_slice` fails only if the key is zero-length.  `key` is `&[u8; 32]`
    // so this is unreachable in practice; return a typed error instead of panicking.
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|_| NonceError::KeyTooShort { actual: key.len() })?;

    mac.update(boot_nonce);
    mac.update(&envelope_hash);
    mac.update(&expiry_unix_ms.to_be_bytes());
    // Length-prefix each variable-length field to prevent boundary collisions.
    mac.update(&length_prefix_u32("tool_name", tool_name.len())?.to_be_bytes());
    mac.update(tool_name.as_bytes());
    mac.update(&length_prefix_u32("chain_id", chain_id.len())?.to_be_bytes());
    mac.update(chain_id.as_bytes());

    // Wrap in Zeroizing<T> immediately so the GenericArray window
    // between `into_bytes()` and the copy is bounded by Zeroizing::Drop.
    let mut tag = Zeroizing::new([0u8; 32]);
    tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    Ok(tag)
}

fn length_prefix_u32(field: &'static str, len: usize) -> Result<u32, NonceError> {
    u32::try_from(len).map_err(|_| NonceError::InputTooLong { field, len })
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

    /// A simple test catalogue that accepts any tool.
    struct AnyTool;
    impl ToolCatalogue for AnyTool {
        fn is_registered(&self, _: &str) -> bool {
            true
        }
    }

    /// A catalogue that rejects all tools.
    struct NoTool;
    impl ToolCatalogue for NoTool {
        fn is_registered(&self, _: &str) -> bool {
            false
        }
    }

    #[test]
    fn nonce_base64_round_trip() {
        let n = Nonce::from_raw([42u8; 48]);
        let b64 = n.to_base64();
        let decoded = Nonce::from_base64(&b64).unwrap();
        assert_eq!(n.to_base64(), decoded.to_base64());
    }

    #[test]
    fn nonce_from_base64_wrong_length() {
        let short = URL_SAFE_NO_PAD.encode([0u8; 20]);
        let err = Nonce::from_base64(&short).unwrap_err();
        assert!(matches!(err, NonceError::SerialiseFailed { .. }));
    }

    #[test]
    fn nonce_from_base64_invalid_chars() {
        let err = Nonce::from_base64("not-valid-base64-!!").unwrap_err();
        assert!(matches!(err, NonceError::SerialiseFailed { .. }));
    }

    #[test]
    fn nonce_salt_and_tag_lengths() {
        let mut inner = [0u8; 48];
        for i in 0..16u8 {
            inner[i as usize] = i;
        }
        for i in 0..32u8 {
            inner[16 + i as usize] = i + 100;
        }
        let n = Nonce::from_raw(inner);
        assert_eq!(n.salt().len(), 16);
        assert_eq!(n.tag().len(), 32);
        assert_eq!(n.salt()[0], 0);
        assert_eq!(n.tag()[0], 100);
    }

    #[test]
    fn compute_tag_is_deterministic() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        let tag1 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        let tag2 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        assert_eq!(*tag1, *tag2);
    }

    #[test]
    fn compute_tag_differs_on_envelope() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        let tag1 = compute_tag(
            &key,
            &boot,
            b"xdr1",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        let tag2 = compute_tag(
            &key,
            &boot,
            b"xdr2",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        assert_ne!(*tag1, *tag2);
    }

    #[test]
    fn compute_tag_differs_on_tool() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        let tag1 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        let tag2 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_balances",
            "stellar:testnet",
        )
        .unwrap();
        assert_ne!(*tag1, *tag2);
    }

    #[test]
    fn compute_tag_differs_on_chain() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        let tag1 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        let tag2 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:mainnet",
        )
        .unwrap();
        assert_ne!(*tag1, *tag2);
    }

    #[test]
    fn compute_tag_differs_on_boot_nonce() {
        let key = [1u8; 32];
        let tag1 = compute_tag(&key, &[0u8; 16], b"xdr", 99_000, "t", "c").unwrap();
        let tag2 = compute_tag(&key, &[1u8; 16], b"xdr", 99_000, "t", "c").unwrap();
        assert_ne!(*tag1, *tag2);
    }

    // Boundary-collision guard: ("ab", "cd") vs ("abc", "d") must differ.
    #[test]
    fn compute_tag_no_boundary_collision() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        // Without length prefixes, both produce the concatenation "abcd" and
        // would yield the same HMAC.  With length prefixes they are distinct.
        let tag_ab_cd = compute_tag(&key, &boot, b"xdr", 99_000, "ab", "cd").unwrap();
        let tag_abc_d = compute_tag(&key, &boot, b"xdr", 99_000, "abc", "d").unwrap();
        assert_ne!(
            *tag_ab_cd, *tag_abc_d,
            "length-prefix separators must prevent boundary collision \
             between (tool='ab', chain='cd') and (tool='abc', chain='d')"
        );
    }

    #[test]
    fn length_prefix_u32_rejects_oversized_inputs() {
        let err = length_prefix_u32("tool_name", usize::MAX).unwrap_err();

        assert!(matches!(
            err,
            NonceError::InputTooLong {
                field: "tool_name",
                len: usize::MAX,
            }
        ));
    }

    // Tag must differ when only expiry changes.
    #[test]
    fn compute_tag_differs_on_expiry() {
        let key = [1u8; 32];
        let boot = [2u8; 16];
        let tag1 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_000,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        let tag2 = compute_tag(
            &key,
            &boot,
            b"xdr",
            99_001,
            "stellar_pay",
            "stellar:testnet",
        )
        .unwrap();
        assert_ne!(*tag1, *tag2, "different expiry must produce different tag");
    }

    #[test]
    fn tool_catalogue_trait_object() {
        let cat: &dyn ToolCatalogue = &AnyTool;
        assert!(cat.is_registered("anything"));
        let cat2: &dyn ToolCatalogue = &NoTool;
        assert!(!cat2.is_registered("anything"));
    }

    #[test]
    fn nonce_debug_redacts_tag_on_all_platforms() {
        let mut raw = [0u8; 48];
        raw[..16].copy_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        raw[16..].fill(0xab);

        let n = Nonce::from_raw(raw);
        let debug = format!("{n:?}");
        assert!(debug.contains("Nonce(salt=01020304..."));
        assert!(debug.contains("tag=[REDACTED]"));
        assert!(!debug.contains("05060708090a0b0c0d0e0f10"));
        assert!(!debug.contains("abababababababab"));
    }

    /// `inner_bytes` returns the full 48-byte `[salt || tag]` array, preserving
    /// every byte exactly as constructed via `from_raw`.
    #[test]
    fn inner_bytes_returns_full_48_byte_array() {
        let mut raw = [0u8; 48];
        // Salt (bytes 0..16): sequential values 0x00–0x0F.
        for i in 0u8..16 {
            raw[i as usize] = i;
        }
        // Tag (bytes 16..48): sequential values 0x10–0x2F.
        for i in 0u8..32 {
            raw[16 + i as usize] = i + 0x10;
        }

        let n = Nonce::from_raw(raw);
        let bytes = n.inner_bytes();

        assert_eq!(bytes.len(), 48, "inner_bytes must return exactly 48 bytes");
        assert_eq!(
            bytes, raw,
            "inner_bytes must match the constructed raw array"
        );
        // Spot-check salt and tag boundaries.
        assert_eq!(bytes[0], 0x00, "salt byte 0 must be 0x00");
        assert_eq!(bytes[15], 0x0F, "salt byte 15 must be 0x0F");
        assert_eq!(bytes[16], 0x10, "tag byte 0 must be 0x10");
        assert_eq!(bytes[47], 0x2F, "tag byte 31 must be 0x2F");
    }

    /// `inner_bytes` returns a copy, not a reference.  Mutating the returned
    /// array does not affect the original `Nonce`.
    #[test]
    fn inner_bytes_is_a_copy_not_a_reference() {
        let raw = [0xFFu8; 48];
        let n = Nonce::from_raw(raw);
        let mut copy = n.inner_bytes();
        copy[0] = 0x00;
        assert_eq!(copy[0], 0x00, "the local copy must reflect the mutation");
        // The original nonce must not be affected.
        assert_eq!(
            n.inner_bytes()[0],
            0xFF,
            "mutating the returned copy must not modify the Nonce"
        );
    }

    /// `mint` returns `InvalidEnvelope` when `envelope_xdr` is empty.
    ///
    /// Validation order in `mint`:
    /// 1. Tool check — passes (`AnyTool` accepts everything).
    /// 2. Envelope non-empty check — fires here, returns `InvalidEnvelope`.
    ///
    /// Key state is never engaged, so no keyring setup is required.
    #[test]
    fn mint_rejects_empty_envelope_xdr() {
        let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
            "stellar-agent-signer",
            "empty-env-inline",
            "stellar-agent-nonce-empty-env-inline",
            "empty-env-inline",
        )
        .build();

        let mint = NonceMint::from_profile(&profile).expect("from_profile");

        // now and expiry produce a valid TTL so the failure is definitely from
        // the envelope guard, not from a TTL guard.
        let now: u64 = 1_893_456_000_000;
        let expiry: u64 = 1_893_456_300_000; // TTL = 300_000 ms == MAX_TTL_MS

        let err = mint
            .mint(
                &AnyTool,
                &[], // empty envelope — must be rejected
                now,
                expiry,
                "any_tool",
                "stellar:testnet",
            )
            .expect_err("empty envelope must return InvalidEnvelope");

        assert!(
            matches!(err, NonceError::InvalidEnvelope),
            "expected InvalidEnvelope, got: {err:?}"
        );
    }
}
