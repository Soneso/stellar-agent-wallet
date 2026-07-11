//! Platform keyring signing handle — per-call secret load with zeroisation.
//!
//! # What this module does
//!
//! Provides [`KeyringSignHandle`] and [`signer_from_keyring`] — the keyring
//! analogue of [`super::signing::source::signer_from_env`].  Unlike the
//! environment-variable path, the keyring path RE-LOADS the secret on every
//! call to [`KeyringSignHandle::sign_tx_payload`], limiting the secret's
//! residency to a single stack frame.  The handle itself holds only the
//! [`KeyringEntryRef`] lookup coordinates and the cached public key — no
//! secret material.
//!
//! # N1 (self-custodial) conformance
//!
//! Secrets retrieved from the keyring never leave the user's host.  Every
//! `get_password` call goes directly to the platform keyring (macOS Keychain,
//! Linux Secret Service, Windows Credential Manager) and the resulting bytes
//! exist only within a single stack frame before being zeroised by
//! `Zeroizing<T>` drop semantics.  No secret is transmitted over a network,
//! written to a file, or returned via a public API.
//!
//! # Zeroisation discipline
//!
//! `sign_tx_payload` applies the same canonical six-step zeroisation sequence
//! as `signing::source::signer_from_s_strkey` (see
//! `signing/source.rs`'s module-level doc):
//!
//! 1. `get_password()` result wrapped in `Zeroizing<String>`.
//! 2. `stellar_strkey::ed25519::PrivateKey::from_string` parses the S-strkey.
//! 3. Seed bytes copied into `Zeroizing<[u8; 32]>`.
//! 4. `zeroize::Zeroize::zeroize(&mut private_key.0)` — explicit zeroisation
//!    of the `Copy` residue (stellar-strkey's `PrivateKey` is `Copy` with no
//!    `Drop`/`Zeroize`, so the residue is zeroized explicitly here).
//! 5. `Zeroizing<String>` dropped before the signing key is constructed.
//! 6. `SoftwareSigningKey::new_from_zeroizing` moves seed into a `SecretBox`
//!    whose `Drop` zeroes the heap allocation.  The signer is dropped at the
//!    end of `sign_tx_payload` so zeroisation fires on every exit path including
//!    panic.
//!
//! # stellar-strkey upstream gap
//!
//! `stellar_strkey::ed25519::PrivateKey` is `Copy` and has no `Drop`/`Zeroize`
//! impl.  Step 4 above patches the gap explicitly — same as `signer_from_env`
//! does.  When upstream adds `Drop+Zeroize`, remove the explicit call.
//!
//! # Secret-leak-in-errors discipline
//!
//! Error messages produced by this module MUST NOT echo the keyring service
//! name, account name, or any retrieved secret material.  The service name is
//! used only to construct the diagnostic label in `KeyringNotFound`; the label
//! is the service name (non-secret keyring coordinate) — never the password.
//! Platform-store `Display` strings are never forwarded to typed error payloads;
//! they are emitted at `tracing::debug!` level only,
//! where the wallet's `RedactingLayer` scrubs known-secret patterns.
//!
//! # Platform initialisation
//!
//! Before any `KeyringEntry::new` call succeeds, the platform keyring store
//! must be registered as the default store via
//! [`init_platform_keyring_store`].  Call this once at process startup (before
//! spawning worker tasks) from the binary's `main` function.  Tests must call
//! `stellar_agent_test_support::keyring_mock::install` instead (each test
//! sets its own isolated store).
//!
//! Supported target platforms: `macos`, `linux`, `windows`.  On any other
//! target, `init_platform_keyring_store` returns
//! [`AuthError::KeyringNotFound`] immediately with a diagnostic naming the
//! unsupported OS — see [`init_platform_keyring_store`] for details.
//!
//! # Headless deployments
//!
//! [`init_platform_keyring_store`] checks
//! `stellar_agent_headless_keyring::requested_backend()` FIRST: if the
//! `STELLAR_AGENT_KEYRING_BACKEND` environment variable is set (to
//! `"headless-env"` or `"headless-dpapi"`), it registers the opt-in
//! file-backed store from [`stellar_agent_headless_keyring`] instead of the
//! platform store, and never falls back to the platform store on any
//! failure. Every existing `init_platform_keyring_store()` call site across
//! the CLI and MCP server picks this up automatically, unchanged — see that
//! crate's module docs for the activation surface, protection modes, and
//! trust model.
//!
//! # Related
//!
//! - [`super::signing::source`] — `signer_from_env` / `signer_from_ledger`
//!   (the same zeroisation discipline; `signer_from_s_strkey` in that module
//!   is the canonical reference implementation reused by `signer_from_keyring`
//!   and `sign_payload_from_s_strkey`).
//! - [`super::signing::software::SoftwareSigningKey`] — the signing backend
//!   consumed by the lazy-load path in `sign_tx_payload`.
//! - [`stellar_agent_core::profile::schema::KeyringEntryRef`] — the
//!   service-name + account-name reference stored in the profile TOML.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use stellar_agent_core::{
    error::{AuthError, InternalError, WalletError},
    observability::redact_strkey_first5_last5,
    profile::schema::KeyringEntryRef,
};
use zeroize::Zeroizing;

use crate::signing::source::signer_from_s_strkey;
use crate::signing::{Signer, WebAuthnAssertion, software::SoftwareSigningKey};

// ─────────────────────────────────────────────────────────────────────────────
// Platform store initialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Initialises the default platform keyring store for this process.
///
/// Must be called once at process startup before any [`signer_from_keyring`]
/// call.  Repeated calls replace the registered store (last-writer wins).
///
/// # Supported platforms
///
/// - **macOS** — macOS legacy Keychain via `apple-native-keyring-store`
///   (`Security.framework`; available to all non-sandboxed applications).
/// - **Linux** — D-Bus Secret Service (GNOME Keyring / KWallet) via
///   `dbus-secret-service-keyring-store` (crypto-rust, vendored).
/// - **Windows** — Windows Credential Manager via
///   `windows-native-keyring-store`.
/// - **Other** — returns [`AuthError::KeyringNotFound`] immediately with a
///   diagnostic naming the unsupported OS (fail-fast; does not silently
///   continue with no store registered).
///
/// # Errors
///
/// Returns [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if:
/// - The platform store cannot be instantiated (store library construction
///   error; emitted at `tracing::debug!` level).
/// - The target OS is not `macos`, `linux`, or `windows` (fail-fast with OS
///   name in the diagnostic label).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::keyring::init_platform_keyring_store;
///
/// init_platform_keyring_store().expect("platform keyring unavailable");
/// ```
pub fn init_platform_keyring_store() -> Result<(), WalletError> {
    if let Some(backend) = stellar_agent_headless_keyring::requested_backend() {
        return stellar_agent_headless_keyring::init_headless_store(&backend).map_err(|e| {
            tracing::debug!(error = %e, backend = %backend, "headless keyring store init failure");
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!("headless keyring backend '{backend}' failed to initialise: {e}"),
            })
        });
    }

    #[cfg(target_os = "macos")]
    {
        use apple_native_keyring_store::keychain::Store;
        // Store::new() returns Result<Arc<Store>>; coerce to Arc<dyn trait>.
        // Upstream Display strings are not forwarded to typed errors; emit at debug only.
        let store: Arc<keyring_core::CredentialStore> = Store::new().map_err(|e| {
            tracing::debug!(error = %e, "macOS Keychain store init failure");
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "macOS Keychain store init failed".to_owned(),
            })
        })?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        use dbus_secret_service_keyring_store::Store;
        // Upstream Display strings are not forwarded to typed errors; emit at debug only.
        let store: Arc<keyring_core::CredentialStore> = Store::new().map_err(|e| {
            tracing::debug!(error = %e, "Linux Secret Service store init failure");
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "Linux Secret Service store init failed".to_owned(),
            })
        })?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        use windows_native_keyring_store::Store;
        // Upstream Display strings are not forwarded to typed errors; emit at debug only.
        let store: Arc<keyring_core::CredentialStore> = Store::new().map_err(|e| {
            tracing::debug!(error = %e, "Windows Credential Manager store init failure");
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "Windows Credential Manager store init failed".to_owned(),
            })
        })?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    // Unsupported platform: fail fast with the OS name so the operator can
    // diagnose the configuration error immediately rather than receiving a
    // mysterious NoDefaultStore error on the first keyring lookup.
    #[allow(unreachable_code)]
    Err(WalletError::Auth(AuthError::KeyringNotFound {
        name: format!(
            "platform keyring not supported on this target_os ({})",
            std::env::consts::OS
        ),
    }))
}

/// Generates 32 fresh CSPRNG bytes, base64-URL-safe-no-pad encodes them, and
/// writes the encoded secret to the keyring entry `service`/`entry_name`.
///
/// Used by `stellar_agent_nonce::rotate_nonce_key` and the CLI profile HMAC
/// key rotators to share a single CSPRNG-and-base64-encoding primitive.
/// This helper is for HMAC-like 32-byte secrets; do not use it for ed25519
/// owner seeds.
///
/// # Errors
///
/// Returns [`WalletError`] when the keyring entry cannot be opened or updated.
/// Operator-visible errors are mapped through the same secret-safe keyring
/// error discipline as signing-key lookups.
pub fn rotate_keyring_secret_32(service: &str, entry_name: &str) -> Result<(), WalletError> {
    let mut raw = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(raw.as_mut());

    let encoded: Zeroizing<String> = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_ref()));

    let entry_ref = KeyringEntryRef::new(service, entry_name);
    let entry = open_entry(&entry_ref)?;
    entry
        .set_password(&encoded)
        .map_err(|e| map_keyring_error(&e, service))?;

    Ok(())
}

/// Loads a 32-byte HMAC-like secret from the keyring entry `entry_ref`,
/// base64-URL-safe-no-pad decoding it and validating the 32-byte length.
///
/// The READ counterpart of [`rotate_keyring_secret_32`]: chain-root HMAC keys
/// (audit log, nonce, attestation, counterparty cache) are stored as
/// `URL_SAFE_NO_PAD`-encoded 32-byte secrets. The decoded key is returned inside
/// a [`Zeroizing`] wrapper so it is wiped on drop; the residency discipline is
/// the caller's from there. This is the single source for chain-root HMAC key
/// loading — the MCP tools and CLI commands adapt it with a profile-field
/// lookup rather than re-implementing the keyring read.
///
/// Do NOT use this for ed25519 owner seeds: those are stored as S-strkeys and
/// loaded through [`signer_from_keyring`], which applies the full parse-verify
/// zeroise sequence and host-swap defence.
///
/// # Errors
///
/// - [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if the entry
///   is unavailable, following the same secret-safe keyring error discipline as
///   [`signer_from_keyring`] (the service name is the only coordinate echoed).
/// - [`WalletError::Internal`] if the stored value is not valid base64 or does
///   not decode to exactly 32 bytes.
///
/// # Panics
///
/// Never panics.
pub fn load_hmac_key_32(entry_ref: &KeyringEntryRef) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let entry = open_entry(entry_ref)?;
    let secret_b64 = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| map_keyring_error(&e, &entry_ref.service))?,
    );

    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        // Upstream Display strings are not forwarded to typed errors; debug only.
        tracing::debug!(error = %e, "chain-root HMAC key base64 decode failed");
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "audit.key_decode_failed: keyring HMAC key is not valid base64".to_owned(),
        })
    })?);

    if decoded.len() != 32 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "audit.key_length_error: keyring HMAC key must be 32 bytes, got {}",
                decoded.len()
            ),
        }));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(decoded.as_slice());
    Ok(key)
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyringSignHandle
// ─────────────────────────────────────────────────────────────────────────────

/// An opaque signing handle backed by a platform keyring entry.
///
/// Holds only the [`KeyringEntryRef`] lookup coordinates and a cached
/// ed25519 public key.  No secret material is held between signing calls.
///
/// # Secret residency
///
/// The signing secret is loaded from the keyring on every [`Self::sign_tx_payload`]
/// call and is held only within that call's stack frame.  The `KeyringEntry`
/// is reconstructed on each call so the OS-level keyring handle is not held
/// open between calls (minimising the cross-call attack surface).
/// All signing methods are async and may yield while the keyring I/O or
/// signing backend completes.
///
/// [`Self::public_key`] returns the cached public key WITHOUT touching the keyring.
///
/// # N1 conformance
///
/// The cached public key is not secret material; it is derived from the
/// secret seed at handle construction time and is retained so callers can
/// perform pre-RPC key-match checks without re-loading the secret.
///
/// # Design note: `KeyringEntry` omitted from the struct
///
/// `keyring_core::Entry` is cheap to construct (a single `Arc` clone and a
/// credential build call).  Reconstructing it on every signing call avoids
/// holding a long-lived OS handle while the wallet is waiting between calls
/// (agents may call `sign_tx_payload` infrequently).  This is the
/// per-call-handle discipline: the OS-level keyring handle is never held open
/// between calls.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_core::profile::schema::KeyringEntryRef;
/// use stellar_agent_network::keyring::signer_from_keyring;
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// # stellar_agent_test_support::keyring_mock::install().ok();
/// let entry_ref = KeyringEntryRef::new("stellar-agent-signer", "my-profile");
/// // (in production, the entry is populated at profile-creation time)
/// let handle = signer_from_keyring(&entry_ref, "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY").await?;
/// let pk = handle.public_key();
/// # Ok(()) }
/// ```
#[non_exhaustive]
pub struct KeyringSignHandle {
    /// Non-secret lookup reference stored in the profile TOML.
    entry_ref: KeyringEntryRef,
    /// Cached ed25519 public key derived at handle construction time.
    ///
    /// Stored as the 32-byte raw representation to avoid holding a
    /// `stellar_strkey` stack-allocated type between async await points.
    cached_pubkey_bytes: [u8; 32],
}

impl KeyringSignHandle {
    /// Returns the cached ed25519 public key without accessing the keyring.
    ///
    /// Use this for pre-RPC key-match checks where re-loading the secret would
    /// be wasteful.  The public key was derived from the secret at handle
    /// construction time and is stable for the handle's lifetime.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    /// use stellar_agent_network::keyring::signer_from_keyring;
    ///
    /// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
    /// # stellar_agent_test_support::keyring_mock::install().ok();
    /// let entry_ref = KeyringEntryRef::new("stellar-agent-signer", "my-profile");
    /// let handle = signer_from_keyring(&entry_ref, "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY").await?;
    /// let pk: stellar_strkey::ed25519::PublicKey = handle.public_key();
    /// # Ok(()) }
    /// ```
    #[must_use]
    pub fn public_key(&self) -> stellar_strkey::ed25519::PublicKey {
        stellar_strkey::ed25519::PublicKey(self.cached_pubkey_bytes)
    }

    /// Returns the keyring entry reference stored in this handle.
    ///
    /// Non-secret: this is the service-name + account-name pair used to look
    /// up the keyring entry.  It does not contain the secret itself.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[must_use]
    pub fn entry_ref(&self) -> &KeyringEntryRef {
        &self.entry_ref
    }

    /// Signs a 32-byte transaction hash payload.
    ///
    /// RE-LOADS the secret from the keyring on every call.  The secret exists
    /// only within this function's stack frame and is zeroised before the
    /// function returns (or unwinds).
    ///
    /// # Zeroisation sequence
    ///
    /// 1. `get_password()` result immediately wrapped in
    ///    `Zeroizing<String>`.
    /// 2. `stellar_strkey::ed25519::PrivateKey::from_string` parses the
    ///    S-strkey.
    /// 3. Seed bytes copied into `Zeroizing<[u8; 32]>`.
    /// 4. `zeroize::Zeroize::zeroize(&mut private_key.0)` — explicit
    ///    zeroisation of the `Copy` residue in the `PrivateKey` stack local.
    /// 5. `Zeroizing<String>` holding the S-strkey dropped before
    ///    `SoftwareSigningKey` is constructed.
    /// 6. `SoftwareSigningKey::new_from_zeroizing` moves the seed into a
    ///    `SecretBox`, whose `Drop` impl zeroes the heap allocation.
    ///
    /// Signing happens after step 6; the per-call signer is dropped before
    /// `sign_tx_payload` returns, so `SecretBox::drop` fires on every exit
    /// path.
    ///
    /// All `Zeroizing<T>` wrappers fire their `Drop` on every exit path
    /// including panic.
    ///
    /// # Host-swap defence
    ///
    /// After loading the fresh seed, the public key derived from it is
    /// compared against the `cached_pubkey_bytes` that were recorded at
    /// handle construction time.  A mismatch returns
    /// [`AuthError::SignerKeyMismatch`] without signing.  This detects a class
    /// of attacks where an adversary replaces the keyring entry value between
    /// handle construction and signing.  The comparison is one ed25519
    /// scalar-multiply (~50 µs) and is defence-in-depth, not the primary trust
    /// root.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if the
    ///   keyring entry does not exist or the platform keyring is locked.
    /// - [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if the
    ///   stored value is not a valid S-strkey (the entry's content is corrupt).
    /// - [`WalletError::Auth`] wrapping [`AuthError::SignerKeyMismatch`] if the
    ///   public key derived from the freshly-loaded seed does not match the
    ///   cached public key from handle construction (host-swap defence).
    ///
    /// # Panics
    ///
    /// Never panics (all `unwrap`-free; panic-injection in tests uses a
    /// production-side hook gated on the `test-hooks` feature).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_core::profile::schema::KeyringEntryRef;
    /// use stellar_agent_network::keyring::signer_from_keyring;
    ///
    /// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
    /// # stellar_agent_test_support::keyring_mock::install().ok();
    /// let entry_ref = KeyringEntryRef::new("stellar-agent-signer-test", "test");
    /// let handle = signer_from_keyring(&entry_ref, "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY").await?;
    /// let sig = handle.sign_tx_payload(&[0u8; 32]).await?;
    /// assert_eq!(sig.len(), 64);
    /// # Ok(()) }
    /// ```
    pub async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        let result = self.sign_tx_payload_inner(payload).await;
        let service = redact_keyring_coord(&self.entry_ref.service);
        let public_key = redact_strkey_first5_last5(self.public_key().to_string().as_ref());
        match &result {
            Ok(_) => tracing::info!(
                target: "keyring",
                event = "keyring.sign.success",
                service = %service,
                account = %self.entry_ref.account,
                public_key = %public_key,
                "keyring signing operation succeeded"
            ),
            Err(err) => tracing::error!(
                target: "keyring",
                event = "keyring.sign.failure",
                service = %service,
                account = %self.entry_ref.account,
                public_key = %public_key,
                error_kind = wallet_error_kind(err),
                error_code = err.code(),
                "keyring signing operation failed"
            ),
        }
        result
    }

    async fn sign_tx_payload_inner(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        // Step 1: load the secret from the keyring into a Zeroizing<String>.
        // The String's heap allocation is zeroed when `s_strkey` drops.
        // The `KeyringEntry` is constructed fresh on every call (per-call
        // handle discipline).
        let entry = open_entry(&self.entry_ref)?;
        let s_strkey: Zeroizing<String> = Zeroizing::new(
            entry
                .get_password()
                .map_err(|e| map_keyring_error(&e, &self.entry_ref.service))?,
        );

        // Delegate to the inner helper which verifies the freshly-loaded seed's
        // public key against the cached bytes before signing. The panic-injection
        // hook (test-hooks feature) is placed there to verify that Zeroizing::Drop
        // fires during unwind.
        sign_payload_verifying_pubkey(
            s_strkey,
            payload,
            &self.cached_pubkey_bytes,
            &self.entry_ref.service,
        )
        .await
    }

    /// Signs a 32-byte smart-account auth-digest using the keyring-stored seed.
    ///
    /// Cryptographically identical to [`KeyringSignHandle::sign_tx_payload`]
    /// (same zeroise sequence, host-swap pubkey-verification, and ed25519
    /// primitive). The split is a call-site-discipline guard: smart-account
    /// auth-entry assembly invokes `sign_auth_digest`, classic transaction
    /// signing invokes `sign_tx_payload`.
    ///
    /// # Errors
    ///
    /// Same variants as [`KeyringSignHandle::sign_tx_payload`].
    pub async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        // Same zeroisation + host-swap check as sign_tx_payload. The two methods
        // diverge only at the call site (which payload class is being signed).
        let entry = open_entry(&self.entry_ref)?;
        let s_strkey: Zeroizing<String> = Zeroizing::new(
            entry
                .get_password()
                .map_err(|e| map_keyring_error(&e, &self.entry_ref.service))?,
        );

        sign_payload_verifying_pubkey(
            s_strkey,
            digest,
            &self.cached_pubkey_bytes,
            &self.entry_ref.service,
        )
        .await
    }

    /// Signs a 32-byte Soroban address-credentials auth-entry signature_payload
    /// using the keyring-stored seed.
    ///
    /// Cryptographically identical to [`KeyringSignHandle::sign_tx_payload`]
    /// and [`KeyringSignHandle::sign_auth_digest`] (same zeroise sequence,
    /// host-swap pubkey-verification, and ed25519 primitive). Used exclusively
    /// for the secondary "Delegated G-key" auth entry that OZ smart accounts
    /// require. See [`Signer::sign_soroban_address_auth_payload`] for the
    /// call-site-discipline rationale.
    ///
    /// # Errors
    ///
    /// Same variants as [`KeyringSignHandle::sign_tx_payload`].
    pub async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        let entry = open_entry(&self.entry_ref)?;
        let s_strkey: Zeroizing<String> = Zeroizing::new(
            entry
                .get_password()
                .map_err(|e| map_keyring_error(&e, &self.entry_ref.service))?,
        );

        sign_payload_verifying_pubkey(
            s_strkey,
            payload,
            &self.cached_pubkey_bytes,
            &self.entry_ref.service,
        )
        .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer impl for KeyringSignHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Allows `KeyringSignHandle` to be used at the single SEP-23 signing call site
/// (`attach_signature`) which takes `&dyn Signer`.
///
/// `sign_tx_payload` delegates to `sign_payload_verifying_pubkey` (the same
/// code that `KeyringSignHandle::sign_tx_payload` calls), so the full
/// zeroisation sequence and host-swap defence apply.
///
/// `public_key` returns the cached public key without a keyring lookup,
/// matching the Signer contract (fast, no I/O).
#[async_trait]
impl Signer for KeyringSignHandle {
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        KeyringSignHandle::sign_tx_payload(self, payload).await
    }

    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        KeyringSignHandle::sign_auth_digest(self, digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        KeyringSignHandle::sign_soroban_address_auth_payload(self, payload).await
    }

    /// Keyring-stored ed25519 seeds cannot produce WebAuthn assertions;
    /// passkey signing requires a dedicated `PasskeySignHandle`.
    ///
    /// Always returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "keyring"`. The `_auth_digest` and `_credential_id`
    /// parameters are unused; the underscore prefix silences the unused-variable
    /// lint without requiring `#[allow]`.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] wrapping [`AuthError::SignerKindMismatch`] —
    ///   always, on every call.
    async fn sign_webauthn_assertion(
        &self,
        _auth_digest: &[u8; 32],
        _credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "keyring",
            requested_primitive: "sign_webauthn_assertion",
        }))
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        Ok(KeyringSignHandle::public_key(self))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// signer_from_keyring
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a keyring signing handle from a [`KeyringEntryRef`].
///
/// Looks up the keyring entry identified by `entry_ref`, reads the secret as
/// a `Zeroizing<String>`, delegates to
/// `signing::source::signer_from_s_strkey` for the full parse-verify-zeroise
/// sequence (steps 2-6 from the module-level doc), derives the cached public
/// key bytes from the returned signer, then drops the signer immediately so
/// `SecretBox::drop` fires.  Returns a [`KeyringSignHandle`] carrying only the
/// lookup-ref and the cached public key — no secret material.
///
/// The G-strkey comparison inside `signer_from_s_strkey` ensures no RPC or
/// network call proceeds if the key doesn't match the claimed source, matching
/// the same discipline as `signer_from_env` and `signer_from_ledger`.
///
/// # Errors
///
/// - [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if the
///   entry does not exist, the platform keyring is locked, or the stored
///   value is not a valid S-strkey.
/// - [`WalletError::Auth`] wrapping [`AuthError::SignerKeyMismatch`] if the
///   derived public key does not match `expected_source_g`.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_core::profile::schema::KeyringEntryRef;
/// use stellar_agent_network::keyring::signer_from_keyring;
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// # stellar_agent_test_support::keyring_mock::install().ok();
/// let entry_ref = KeyringEntryRef::new("stellar-agent-signer", "my-profile");
/// let handle = signer_from_keyring(
///     &entry_ref,
///     "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
/// ).await?;
/// # Ok(()) }
/// ```
pub async fn signer_from_keyring(
    entry_ref: &KeyringEntryRef,
    expected_source_g: &str,
) -> Result<KeyringSignHandle, WalletError> {
    // Load the secret into a Zeroizing<String>; dropped inside
    // signer_from_s_strkey after the seed bytes are captured.
    let entry = open_entry(entry_ref)?;
    let s_strkey: Zeroizing<String> = Zeroizing::new(
        entry
            .get_password()
            .map_err(|e| map_keyring_error(&e, &entry_ref.service))?,
    );

    // Delegate to the canonical parse-verify-zeroise helper in signing::source.
    // It applies the full zeroisation sequence (PrivateKey residue,
    // Zeroizing<String> drop, SecretBox heap) and verifies the G-strkey before
    // returning. Map the generic "invalid S-strkey" error to name the keyring
    // service.
    let signer = signer_from_s_strkey(s_strkey, expected_source_g)
        .await
        .map_err(|e| match e {
            WalletError::Auth(AuthError::KeyringNotFound { ref name })
                if name == "invalid S-strkey" =>
            {
                WalletError::Auth(AuthError::KeyringNotFound {
                    name: format!(
                        "keyring entry '{}' contains an invalid S-strkey",
                        entry_ref.service
                    ),
                })
            }
            other => other,
        })?;

    // Derive cached public key from the signer; vk holds no secret material.
    let pk: stellar_strkey::ed25519::PublicKey = signer.public_key().await?;
    let cached_pubkey_bytes = pk.0;
    // Explicit drop: SecretBox inside the signer zeroes the heap allocation.
    drop(signer);

    tracing::info!(
        target: "keyring",
        event = "keyring.handle.constructed",
        service = %redact_keyring_coord(&entry_ref.service),
        account = %entry_ref.account,
        public_key = %redact_strkey_first5_last5(pk.to_string().as_ref()),
        "keyring signing handle constructed"
    );

    Ok(KeyringSignHandle {
        entry_ref: entry_ref.clone(),
        cached_pubkey_bytes,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Opens a `keyring_core::Entry` for the given [`KeyringEntryRef`].
///
/// Returns [`AuthError::KeyringNotFound`] if the default store has not been
/// set (process forgot to call `init_platform_keyring_store`) or if the
/// entry coordinates are rejected by the store.
fn open_entry(entry_ref: &KeyringEntryRef) -> Result<KeyringEntry, WalletError> {
    KeyringEntry::new(&entry_ref.service, &entry_ref.account)
        .map_err(|e| map_keyring_error(&e, &entry_ref.service))
}

/// Maps a `keyring_core::Error` to a `WalletError`.
///
/// The service name is included (non-secret keyring coordinate used in
/// diagnostics); the password, account name, and any secret content are
/// NEVER included in the error message.
fn map_keyring_error(e: &keyring_core::Error, service: &str) -> WalletError {
    match e {
        keyring_core::Error::NoEntry => WalletError::Auth(AuthError::KeyringNotFound {
            name: service.to_owned(),
        }),
        keyring_core::Error::NoDefaultStore => WalletError::Auth(AuthError::KeyringNotFound {
            name: format!(
                "{service} (no OS credential store is available for this session; ensure the platform keychain — macOS Keychain, GNOME Keyring / KWallet, or Windows Credential Manager — is running and unlocked)"
            ),
        }),
        keyring_core::Error::NoStorageAccess(inner) if is_windows_no_logon_session(inner) => {
            WalletError::Auth(AuthError::KeyringInteractiveSessionRequired)
        }
        keyring_core::Error::PlatformFailure(_) | keyring_core::Error::NoStorageAccess(_) => {
            WalletError::Auth(AuthError::KeyringPlatformError)
        }
        // All other variants (BadEncoding, Ambiguous, TooLong, Invalid, etc.)
        // are reported as KeyringNotFound with the service name only.
        _ => WalletError::Auth(AuthError::KeyringNotFound {
            name: service.to_owned(),
        }),
    }
}

/// Detects whether a `keyring_core::Error::NoStorageAccess` inner error is the
/// Windows `ERROR_NO_SUCH_LOGON_SESSION` (1312) case.
///
/// `windows-native-keyring-store` v1.1.0 maps that Win32 error to
/// `NoStorageAccess(Box<PlatformError(1312)>)` (`utils.rs::decode_error`),
/// where `PlatformError`'s `Display` renders the fixed text
/// `"Windows ERROR_NO_SUCH_LOGON_SESSION"` (`utils.rs::PlatformError::fmt`).
/// The concrete `PlatformError` type is private to that crate (`mod utils;`,
/// not `pub mod utils;`), so a string match on the `Display` text is the only
/// signal available across the crate boundary — there is no numeric error
/// code or public type to downcast to.
fn is_windows_no_logon_session(inner: &keyring_core::error::PlatformError) -> bool {
    inner.to_string().contains("ERROR_NO_SUCH_LOGON_SESSION")
}

fn redact_keyring_coord(value: &str) -> String {
    if value.len() > 10 {
        format!("{}...{}", &value[..5], &value[value.len() - 5..])
    } else {
        value.to_owned()
    }
}

fn wallet_error_kind(err: &WalletError) -> &'static str {
    match err {
        WalletError::Auth(AuthError::KeyringLocked) => "AuthError::KeyringLocked",
        WalletError::Auth(AuthError::KeyringPlatformError) => "AuthError::KeyringPlatformError",
        WalletError::Auth(AuthError::KeyringInteractiveSessionRequired) => {
            "AuthError::KeyringInteractiveSessionRequired"
        }
        WalletError::Auth(AuthError::KeyringNotFound { .. }) => "AuthError::KeyringNotFound",
        WalletError::Auth(AuthError::HardwareUserRefused) => "AuthError::HardwareUserRefused",
        WalletError::Auth(AuthError::SignerKeyMismatch { .. }) => "AuthError::SignerKeyMismatch",
        WalletError::Auth(AuthError::SignerKindMismatch { .. }) => "AuthError::SignerKindMismatch",
        WalletError::Validation(_) => "WalletError::Validation",
        WalletError::Network(_) => "WalletError::Network",
        WalletError::WalletState(_) => "WalletError::WalletState",
        WalletError::Protocol(_) => "WalletError::Protocol",
        WalletError::Ledger(_) => "WalletError::Ledger",
        WalletError::Submission(_) => "WalletError::Submission",
        WalletError::Internal(_) => "WalletError::Internal",
        WalletError::SmartAccount { .. } => "WalletError::SmartAccount",
        _ => "WalletError::Unknown",
    }
}

/// Inner helper: parse, verify public key against cached bytes, then sign.
///
/// Owns steps 2-6 of the zeroisation sequence from the module-level doc,
/// with an added host-swap check before constructing the per-call signer.
/// Called from `KeyringSignHandle::sign_tx_payload` ONLY — that caller
/// owns step 1 (loading the secret into `Zeroizing<String>`).
///
/// All `Zeroizing<T>` wrappers fire their `Drop` on every exit path including
/// panic.
async fn sign_payload_verifying_pubkey(
    s_strkey: Zeroizing<String>,
    payload: &[u8; 32],
    expected_pubkey_bytes: &[u8; 32],
    service: &str,
) -> Result<[u8; 64], WalletError> {
    // Step 2: parse the S-strkey.  Parse-error message names the keyring
    // service for operator diagnosis (service name is a non-secret alias, not
    // the secret material).
    let mut private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!("keyring entry '{service}' contains an invalid S-strkey"),
            })
        })?;
    // Step 3: copy seed bytes into Zeroizing.
    let seed_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    // Step 4: explicit zeroize of Copy residue.
    // stellar-strkey's PrivateKey is Copy with no Drop/Zeroize, so the residue is zeroized explicitly here.
    zeroize::Zeroize::zeroize(&mut private_key.0);
    // Step 5: release the heap String holding the raw S-strkey.
    drop(s_strkey);

    // Panic-injection hook — only compiled when `test-hooks` feature is enabled.
    // When armed, panics here (after drop(s_strkey) and with seed_bytes still
    // live on the stack) to prove that Zeroizing::Drop fires during unwind.
    // The test arms PANIC_AFTER_LOAD, constructs a Drop-instrumented sentinel,
    // calls sign_tx_payload inside catch_unwind, and asserts DROP_COUNTER
    // incremented — proving the sentinel's Drop ran across the unwind path.
    #[cfg(feature = "test-hooks")]
    #[allow(
        clippy::panic,
        reason = "test-only panic injection hook gated on test-hooks feature"
    )]
    if PANIC_AFTER_LOAD.load(std::sync::atomic::Ordering::SeqCst) {
        DROP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("panic-injection test — PANIC_AFTER_LOAD triggered");
    }

    // Host-swap defence: derive the public key from the freshly-loaded seed
    // and compare to the cached bytes from handle construction.
    // Mismatch → SignerKeyMismatch (no secret echo).  One ed25519 scalar-mult
    // (~50 µs).
    let derived_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let derived_pubkey_bytes = derived_signing_key.verifying_key().to_bytes();
    // Explicit drop: signing key holds no further purpose, clear it now.
    drop(derived_signing_key);
    if &derived_pubkey_bytes != expected_pubkey_bytes {
        // stellar-strkey's PublicKey::to_string() returns a heapless String; the second
        // .to_string() (Display) converts to std::String. Removing either call breaks the build.
        let expected_g = stellar_strkey::ed25519::PublicKey(*expected_pubkey_bytes)
            .to_string()
            .to_string();
        let got_g = stellar_strkey::ed25519::PublicKey(derived_pubkey_bytes)
            .to_string()
            .to_string();
        return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
            expected: expected_g,
            got: got_g,
        }));
    }

    // Step 6: construct the signing key (SecretBox on the heap).
    let signer = SoftwareSigningKey::new_from_zeroizing(seed_bytes);

    // Step 7: sign; `signer` drops at end of scope.
    let sig = signer.sign_tx_payload(payload).await?;
    // `signer` drops here; SecretBox::drop zeroes the heap allocation.
    Ok(sig)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-only hooks for panic-injection
// ─────────────────────────────────────────────────────────────────────────────

/// Toggle set to `true` by the panic-injection integration test before calling
/// `KeyringSignHandle::sign_tx_payload`.  When armed, `sign_payload_verifying_pubkey`
/// panics after `drop(s_strkey)` and with `seed_bytes` live on the stack,
/// proving that `Zeroizing::drop` fires during unwind.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled.  Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static PANIC_AFTER_LOAD: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Counter incremented by the panic-injection hook and by the `DropSentinel`
/// in the panic-injection integration test.
///
/// The test arms `PANIC_AFTER_LOAD`, places a `DropSentinel` (whose `Drop`
/// increments this counter) on the call stack alongside `seed_bytes`, then
/// calls `sign_tx_payload` inside `catch_unwind`.  After `catch_unwind` the
/// counter reflects the number of `Drop` calls that fired during unwind,
/// confirming that the sentinel's `Drop` (and thus `Zeroizing::drop` on the
/// same unwind path) fired correctly.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static DROP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in unit tests"
)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use stellar_agent_core::error::ErrorCategory;
    use stellar_agent_test_support::{CaptureWriter, keyring_mock};

    fn gstrkey_for_seed(seed: [u8; 32]) -> String {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
            .to_string()
            .to_string()
    }

    fn sstrkey_for_seed(seed: [u8; 32]) -> String {
        stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string()
    }

    fn store_sstrkey(entry_ref: &KeyringEntryRef, sstrkey: &str) {
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        entry.set_password(sstrkey).unwrap();
    }

    fn json_capture_subscriber(
        writer: CaptureWriter,
    ) -> impl tracing::Subscriber + Send + Sync + 'static {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_ansi(false)
            .with_writer(writer)
            .with_max_level(tracing::Level::TRACE)
            .finish()
    }

    #[test]
    #[serial_test::serial]
    fn rotate_keyring_secret_32_creates_base64_32_byte_secret() {
        keyring_mock::install().expect("mock store");
        let service = "stellar-agent-network-rotate-secret-test";
        let entry_name = "default";

        rotate_keyring_secret_32(service, entry_name).expect("rotation ok");

        let entry = KeyringEntry::new(service, entry_name).unwrap();
        let stored = entry.get_password().expect("secret stored");
        let decoded = URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    #[serial_test::serial]
    fn load_hmac_key_32_round_trips_rotate_keyring_secret_32() {
        keyring_mock::install().expect("mock store");
        let service = "stellar-agent-network-load-hmac-test";
        let entry_name = "default";

        rotate_keyring_secret_32(service, entry_name).expect("rotation ok");

        let entry_ref = KeyringEntryRef::new(service, entry_name);
        let loaded = load_hmac_key_32(&entry_ref).expect("load ok");
        assert_eq!(loaded.len(), 32, "loaded key must be exactly 32 bytes");
        // Loading the same entry twice yields the identical key. Compared with a
        // bare `assert!` (not `assert_eq!`) so a failure never prints the key.
        let reloaded = load_hmac_key_32(&entry_ref).expect("reload ok");
        assert!(*loaded == *reloaded, "same entry must load the same key");
    }

    #[test]
    #[serial_test::serial]
    fn load_hmac_key_32_rejects_non_32_byte_secret() {
        keyring_mock::install().expect("mock store");
        let entry_ref = KeyringEntryRef::new("stellar-agent-network-load-hmac-bad-len", "default");
        // A base64 secret that decodes to 16 bytes must be rejected as an
        // internal invariant violation, not silently truncated or padded.
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        entry
            .set_password(&URL_SAFE_NO_PAD.encode([0u8; 16]))
            .unwrap();

        let err = load_hmac_key_32(&entry_ref).unwrap_err();
        assert_eq!(err.category(), ErrorCategory::Internal);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn signer_from_keyring_emits_handle_construction_event() {
        keyring_mock::install().expect("mock store");
        let seed = [0xAA_u8; 32];
        let entry_ref = KeyringEntryRef::new("stellar-agent-keyring-handle-event", "default");
        let expected_g = gstrkey_for_seed(seed);
        store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));
        let redacted_service = redact_keyring_coord(&entry_ref.service);
        let redacted_public_key = redact_strkey_first5_last5(&expected_g);

        let writer = CaptureWriter::new();
        let subscriber = json_capture_subscriber(writer.clone());
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let _handle = signer_from_keyring(&entry_ref, &expected_g).await.unwrap();
        drop(_guard);

        let logs = writer.captured_str();
        assert!(logs.contains("keyring.handle.constructed"), "{logs}");
        assert!(logs.contains("\"target\":\"keyring\""), "{logs}");
        assert!(logs.contains(&redacted_service), "{logs}");
        assert!(logs.contains("\"account\":\"default\""), "{logs}");
        assert!(logs.contains(&redacted_public_key), "{logs}");
        assert!(!logs.contains(&entry_ref.service), "{logs}");
        assert!(!logs.contains(&expected_g), "{logs}");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sign_tx_payload_emits_success_event() {
        keyring_mock::install().expect("mock store");
        let seed = [0xBB_u8; 32];
        let entry_ref = KeyringEntryRef::new("stellar-agent-keyring-sign-success", "default");
        let expected_g = gstrkey_for_seed(seed);
        store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));
        let handle = signer_from_keyring(&entry_ref, &expected_g).await.unwrap();

        let writer = CaptureWriter::new();
        let subscriber = json_capture_subscriber(writer.clone());
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let sig = handle.sign_tx_payload(&[0x01_u8; 32]).await.unwrap();
        drop(_guard);

        assert_eq!(sig.len(), 64);
        let logs = writer.captured_str();
        assert!(logs.contains("keyring.sign.success"), "{logs}");
        assert!(logs.contains("\"target\":\"keyring\""), "{logs}");
        assert!(
            logs.contains(&redact_keyring_coord(&entry_ref.service)),
            "{logs}"
        );
        assert!(
            logs.contains(&redact_strkey_first5_last5(&expected_g)),
            "{logs}"
        );
        assert!(!logs.contains(&entry_ref.service), "{logs}");
        assert!(!logs.contains(&expected_g), "{logs}");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sign_tx_payload_emits_failure_event() {
        keyring_mock::install().expect("mock store");
        let seed = [0xCC_u8; 32];
        let entry_ref = KeyringEntryRef::new("stellar-agent-keyring-sign-failure", "default");
        let expected_g = gstrkey_for_seed(seed);
        store_sstrkey(&entry_ref, &sstrkey_for_seed(seed));
        let handle = signer_from_keyring(&entry_ref, &expected_g).await.unwrap();
        store_sstrkey(&entry_ref, &sstrkey_for_seed([0xDD_u8; 32]));

        let writer = CaptureWriter::new();
        let subscriber = json_capture_subscriber(writer.clone());
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let err = handle.sign_tx_payload(&[0x02_u8; 32]).await.unwrap_err();
        drop(_guard);

        assert_eq!(err.code(), "auth.signer_key_mismatch");
        let logs = writer.captured_str();
        assert!(logs.contains("keyring.sign.failure"), "{logs}");
        assert!(logs.contains("\"target\":\"keyring\""), "{logs}");
        assert!(logs.contains("AuthError::SignerKeyMismatch"), "{logs}");
        assert!(logs.contains("auth.signer_key_mismatch"), "{logs}");
        assert!(
            logs.contains(&redact_keyring_coord(&entry_ref.service)),
            "{logs}"
        );
        assert!(
            logs.contains(&redact_strkey_first5_last5(&expected_g)),
            "{logs}"
        );
        assert!(!logs.contains(&entry_ref.service), "{logs}");
        assert!(!logs.contains(&expected_g), "{logs}");
    }

    // ── map_keyring_error tests ───────────────────────────────────────────────

    #[test]
    fn no_entry_maps_to_keyring_not_found() {
        let err = map_keyring_error(&keyring_core::Error::NoEntry, "my-svc");
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
    }

    #[test]
    fn no_default_store_maps_to_keyring_not_found() {
        let err = map_keyring_error(&keyring_core::Error::NoDefaultStore, "my-svc");
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
        // The message mentions the service name (non-secret) and stays
        // operator-actionable: it must not expose the password / account and
        // must not leak the internal `init_platform_keyring_store` API name.
        assert!(err.message().contains("my-svc"), "service name in message");
        assert!(
            !err.message().contains("init_platform_keyring_store"),
            "operator-facing message must not name the internal init API"
        );
    }

    #[test]
    fn platform_failure_maps_to_keyring_platform_error() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::PlatformFailure(Box::new(io::Error::other("os error"))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    /// `windows-native-keyring-store` v1.1.0 maps Win32
    /// `ERROR_NO_SUCH_LOGON_SESSION` (1312) to
    /// `NoStorageAccess(Box<PlatformError(1312)>)` whose `Display` is the
    /// fixed text `"Windows ERROR_NO_SUCH_LOGON_SESSION"` (the concrete
    /// `PlatformError` type is private to that crate, so a string match on
    /// this exact text is the only signal available across the crate
    /// boundary). This test constructs that text directly rather than
    /// depending on the Windows-only backend, so it runs on every platform.
    #[test]
    fn no_storage_access_with_no_logon_session_text_maps_to_interactive_session_required() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::NoStorageAccess(Box::new(io::Error::other(
                "Windows ERROR_NO_SUCH_LOGON_SESSION",
            ))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
        assert!(
            err.message().contains("interactive logon session"),
            "message must state the interactive-session cause: {}",
            err.message()
        );
    }

    /// A `NoStorageAccess` failure NOT caused by the logon-session case (e.g.
    /// a locked/unavailable credential store for another reason) must keep
    /// mapping to the pre-existing `auth.keyring_platform_error` code, not the
    /// new interactive-session-specific one.
    #[test]
    fn no_storage_access_other_reason_still_maps_to_keyring_platform_error() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::NoStorageAccess(Box::new(io::Error::other("keychain is locked"))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    // ── open_entry with no default store ─────────────────────────────────────

    /// Asserts that `KeyringSignHandle::sign_webauthn_assertion` (via the
    /// `Signer` trait impl) returns `AuthError::SignerKindMismatch` with
    /// `signer_kind = "keyring"`.
    ///
    /// The `KeyringSignHandle` wraps an ed25519 seed stored in the platform
    /// keyring; it cannot produce secp256r1 / WebAuthn assertions. The refusal
    /// must be immediate and must not trigger a keyring read.
    ///
    /// This test constructs a `KeyringSignHandle` directly rather than going
    /// through `signer_from_keyring`, since the latter requires a populated
    /// keyring entry; the refusal fires before any field on the handle is read.
    #[tokio::test]
    async fn keyring_signer_refuses_webauthn_assertion_with_kind_mismatch() {
        use stellar_agent_core::error::AuthError;

        // Construct a handle with a fixed pubkey — the refusal fires before
        // any keyring lookup, so the entry coordinates need not exist.
        let handle = KeyringSignHandle {
            entry_ref: KeyringEntryRef::new("test-service", "test-account"),
            cached_pubkey_bytes: [0u8; 32],
        };
        let auth_digest = [0xAB_u8; 32];
        let credential_id = b"test-credential-id";

        let err = (<KeyringSignHandle as Signer>::sign_webauthn_assertion(
            &handle,
            &auth_digest,
            credential_id,
        ))
        .await
        .unwrap_err();

        assert_eq!(err.code(), "auth.signer_kind_mismatch");
        match err {
            WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind,
                requested_primitive,
            }) => {
                assert_eq!(signer_kind, "keyring");
                assert_eq!(requested_primitive, "sign_webauthn_assertion");
            }
            other => panic!("expected SignerKindMismatch, got: {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn open_entry_without_store_returns_keyring_not_found() {
        // `#[serial]` alongside the store-installing tests: this test unsets the
        // process-global keyring store and then asserts a lookup fails, so a
        // sibling test re-installing the default store between those two steps
        // would race it. Serialising against the store mutators removes the race
        // without weakening the assertion.
        // Explicitly unset the store so the test is not order-dependent.
        keyring_core::unset_default_store();

        let entry_ref = KeyringEntryRef::new("stellar-agent-test-no-store", "x");
        let result = open_entry(&entry_ref);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
    }
}
