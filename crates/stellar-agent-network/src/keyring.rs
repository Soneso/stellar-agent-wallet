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
//! Credential-store Display and Debug strings never enter diagnostics.
//! Classified failures contain fixed labels and extracted numeric codes.
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
//! [`AuthError::KeyringPlatformError`] immediately with a fixed
//! unsupported-platform diagnostic. See [`init_platform_keyring_store`] for details.
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

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use stellar_agent_core::profile::owner_key;
use stellar_agent_core::{
    audit_log::binding::{AuditBinding, BindingCheck, RecordedBinding},
    audit_log::tip_anchor::{
        KeyedAuditAccess, TipAnchor, TipAnchorStore, TipAnchorStoreError,
        reanchor_count_account_for_digest, tip_anchor_account_for_digest,
    },
    error::{AuthError, InternalError, ValidationError, WalletError},
    observability::redact_strkey_first5_last5,
    profile::schema::{KeyringEntryRef, Profile},
};
use zeroize::Zeroizing;

use crate::signing::source::{SecretStrkeySource, signer_from_s_strkey};
use crate::signing::{Signer, WebAuthnAssertion, software::SoftwareSigningKey};

#[allow(deprecated)]
pub use stellar_agent_core::keyring_errors::classify_keyring_error;
use stellar_agent_core::keyring_errors::keyring_store_label;
pub use stellar_agent_core::keyring_errors::{KeyringOperation, classify_keyring_operation_error};

/// Classifies a read failure, including typed headless DPAPI failures.
#[must_use]
#[deprecated(note = "use the operation-aware function")]
pub fn map_keyring_error(e: &keyring_core::Error, service: &str) -> WalletError {
    map_keyring_operation_error(e, KeyringOperation::Read, service)
}

/// Classifies an operation failure with safe platform diagnostics.
///
/// DPAPI protect errors contribute only their numeric code. Other errors use
/// core's classifier; upstream Display and Debug never enter the detail.
#[must_use]
pub fn map_keyring_operation_error(
    e: &keyring_core::Error,
    operation: KeyringOperation,
    service: &str,
) -> WalletError {
    use stellar_agent_headless_keyring::crypto::CryptoError;
    if let keyring_core::Error::PlatformFailure(inner) = e {
        let cause = match inner.downcast_ref::<CryptoError>() {
            Some(CryptoError::DpapiProtectFailed { code }) => Some(format!(
                "DPAPI CryptProtectData failed (error {code}) while writing headless-dpapi; if this session cannot access the user's DPAPI master key, try an interactive desktop logon, or configure STELLAR_AGENT_KEYRING_BACKEND=headless-env and STELLAR_AGENT_HEADLESS_KEYRING_KEY"
            )),
            Some(CryptoError::DpapiProtectInternalFailure) => {
                Some("headless-dpapi could not protect the value".to_owned())
            }
            _ => None,
        };
        if let Some(cause) = cause {
            return WalletError::Auth(AuthError::KeyringPlatformError {
                detail: format!("{} {}: {cause}", operation.label(), keyring_store_label()),
            });
        }
    }
    WalletError::Auth(classify_keyring_operation_error(e, operation, service))
}

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
/// - **Other**: returns [`AuthError::KeyringPlatformError`] immediately with
///   a fixed unsupported-platform diagnostic.
///
/// # Errors
///
/// Returns [`WalletError::Auth`] wrapping [`AuthError::KeyringConfigInvalid`]
/// if `STELLAR_AGENT_KEYRING_BACKEND` selects a headless backend that cannot
/// be set up. The causes are an unrecognized backend value, a missing or
/// malformed `STELLAR_AGENT_HEADLESS_KEYRING_KEY`, a backend the platform does
/// not support, and an undeterminable state directory. The detail names the
/// variable or condition at fault.
///
/// Returns [`WalletError::Auth`] wrapping [`AuthError::KeyringPlatformError`]
/// with a fixed diagnostic if the platform store cannot be initialized or
/// the target OS is unsupported.
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
    // A headless backend that cannot be set up is a configuration fault the
    // operator fixes in the environment, so it reports the configuration
    // code, with the variable or condition at fault, and no keyring entry.
    if let Some(backend) = stellar_agent_headless_keyring::requested_backend() {
        return stellar_agent_headless_keyring::init_headless_store(&backend).map_err(|e| {
            tracing::debug!(error = %e, backend = %backend, "headless keyring store init failure");
            WalletError::Auth(AuthError::KeyringConfigInvalid {
                detail: e.to_string(),
            })
        });
    }

    #[cfg(target_os = "macos")]
    {
        use apple_native_keyring_store::keychain::Store;
        return install_platform_store(
            Store::new().map(|store| store as Arc<keyring_core::CredentialStore>),
        );
    }
    #[cfg(target_os = "linux")]
    {
        use dbus_secret_service_keyring_store::Store;
        return install_platform_store(
            Store::new().map(|store| store as Arc<keyring_core::CredentialStore>),
        );
    }
    #[cfg(target_os = "windows")]
    {
        use windows_native_keyring_store::Store;
        return install_platform_store(
            Store::new().map(|store| store as Arc<keyring_core::CredentialStore>),
        );
    }
    #[allow(unreachable_code)]
    Err(platform_store_init_failure(
        "unsupported-platform credential store initialization failed",
    ))
}

fn platform_store_init_failure(label: &str) -> WalletError {
    WalletError::Auth(AuthError::KeyringPlatformError {
        detail: label.to_owned(),
    })
}

fn install_platform_store(
    store: keyring_core::Result<Arc<keyring_core::CredentialStore>>,
) -> Result<(), WalletError> {
    let store = store.map_err(|error| {
        let label = if cfg!(target_os = "macos") {
            "macOS Keychain store initialization failed"
        } else if cfg!(target_os = "linux") {
            "Linux Secret Service store initialization failed"
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager store initialization failed"
        } else {
            "unsupported-platform credential store initialization failed"
        };
        let classified = classify_keyring_operation_error(&error, KeyringOperation::Construct, "");
        let cause = match &classified {
            AuthError::KeyringPlatformError { detail } => {
                // Core separates its fixed operation/store labels from the safe cause.
                detail
                    .split_once(": ")
                    .map_or(detail.as_str(), |(_, cause)| cause)
            }
            AuthError::KeyringInteractiveSessionRequired => {
                "credential store requires an interactive logon session"
            }
            _ => "credential store operation failed",
        };
        platform_store_init_failure(&format!("{label}: {cause}"))
    })?;
    keyring_core::set_default_store(store);
    Ok(())
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
        .map_err(|e| map_keyring_operation_error(&e, KeyringOperation::Write, service))?;

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
    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
    })?);

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
// Audit-log tip anchor
// ─────────────────────────────────────────────────────────────────────────────

/// Writes `value` to the keyring entry `entry_ref`, replacing any current
/// value.
///
/// The caller-supplied counterpart to [`rotate_keyring_secret_32`], which only
/// ever writes fresh random bytes. Used for the non-secret bookkeeping the
/// wallet keeps in the keyring, outside the log file: the audit-log tip
/// anchor, its re-anchor counter, and the audit binding. Anyone who can restore
/// the keyring's own storage together with the log can restore an older state.
/// With a headless keyring backend these entries are kept in a file on the
/// same host, and anyone who can write that file can restore older entries or
/// delete one.
///
/// Do NOT route secret material through this helper. Secrets are minted by
/// [`rotate_keyring_secret_32`] and read by [`load_hmac_key_32`], both of which
/// carry the base64 and zeroisation discipline this one deliberately does not.
///
/// # Errors
///
/// Returns [`WalletError`] when the keyring entry cannot be opened or written,
/// mapped through the same secret-safe keyring error discipline as signing-key
/// lookups.
pub fn write_keyring_string(entry_ref: &KeyringEntryRef, value: &str) -> Result<(), WalletError> {
    let entry = open_entry(entry_ref)?;
    entry
        .set_password(value)
        .map_err(|e| map_keyring_operation_error(&e, KeyringOperation::Write, &entry_ref.service))
}

/// Reads the keyring entry `entry_ref` as a plain string.
///
/// `Ok(None)` means the entry has never been written — the first-run signal the
/// tip anchor's adoption path needs, distinct from a backend failure.
///
/// # Errors
///
/// Returns [`WalletError`] when the keyring entry cannot be opened or read for
/// any reason other than its absence.
pub fn read_keyring_string(entry_ref: &KeyringEntryRef) -> Result<Option<String>, WalletError> {
    let entry = open_entry(entry_ref)?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(map_keyring_operation_error(
            &e,
            KeyringOperation::Read,
            &entry_ref.service,
        )),
    }
}

/// Checks the profile's audit binding, then loads its audit chain-root key and
/// pairs it with the anchor store for that profile's log path.
///
/// The single way a keyed audit writer is opened. Both halves come from the same
/// keyring coordinate — the key from the entry itself, the anchor from an
/// account derived from it and the log path — so producing them together removes
/// the shape where a caller loads the key and forgets the anchor. A keyed writer
/// whose appends do not advance the anchor writes rows the rollback guard never
/// covers, which is precisely the class of rows an attacker wants to remove.
///
/// `profile_name` is the selected, reconciled profile name; the binding
/// coordinate derives from it alone. The key's coordinate is refused first
/// when it sits in the owner key namespace, so no binding records an owner
/// coordinate. [`check_audit_binding`] then runs under `binding` before the
/// key loads, so a changed binding refuses without a key read. The loaded key
/// is refused when it equals the profile's owner public key.
///
/// # Errors
///
/// - [`WalletError::Validation`] wrapping
///   [`ValidationError::AuditLogBindingChanged`] when the recorded binding
///   differs from the profile's or does not parse.
/// - [`WalletError::Validation`] wrapping
///   [`ValidationError::KeyMatchesOwnerPublicKey`] for an owner-namespace
///   coordinate or a key equal to the owner public key.
/// - [`WalletError::Auth`] if the binding cannot be read or recorded, or if
///   the key's keyring entry is unavailable.
/// - [`WalletError::Internal`] if the stored key is not valid base64 or not
///   exactly 32 bytes.
pub fn keyed_audit_access(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
) -> Result<KeyedAuditAccess, WalletError> {
    owner_key::refuse_owner_key_coordinate(&profile.audit_log_hash_chain_key_id, AUDIT_KEY_FIELD)?;
    check_audit_binding(profile, profile_name, binding)?;
    let hmac_key = load_hmac_key_32(&profile.audit_log_hash_chain_key_id)?;
    owner_key::refuse_owner_public_key(
        hmac_key.as_ref(),
        &owner_key::OwnerKeyContext::for_profile(profile_name, profile),
        AUDIT_KEY_FIELD,
    )?;
    let tip_anchor = KeyringTipAnchorStore::shared(
        &profile.audit_log_hash_chain_key_id,
        &profile.audit_log_path,
    );
    Ok(KeyedAuditAccess::new(hmac_key, tip_anchor))
}

/// The profile field an audit-key owner refusal names.
pub const AUDIT_KEY_FIELD: &str = "audit_log_hash_chain_key_id";

/// Compares the profile's audit binding with the record at
/// [`KeyringEntryRef::default_audit_binding`] for `profile_name`.
///
/// - An equal record continues.
/// - An absent record is stored under [`BindingCheck::Enforce`] and left
///   absent under [`BindingCheck::CheckOnly`].
/// - A record that differs or does not parse refuses.
///
/// # Errors
///
/// - [`WalletError::Validation`] wrapping
///   [`ValidationError::AuditLogBindingChanged`] for a record that differs or
///   does not parse. The message names the profile and the remedy, never a
///   path, a coordinate, or the record.
/// - The keyring error when the record cannot be read, which writes nothing,
///   or cannot be stored.
pub fn check_audit_binding(
    profile: &Profile,
    profile_name: &str,
    binding: BindingCheck,
) -> Result<(), WalletError> {
    let store = KeyringAuditBindingStore::for_profile(profile_name);
    let expected = AuditBinding::for_profile(profile);
    match store.classify(&expected)? {
        RecordedBinding::Equal => Ok(()),
        RecordedBinding::Absent => match binding {
            BindingCheck::Enforce => store.store(&expected),
            BindingCheck::CheckOnly => Ok(()),
        },
        RecordedBinding::Changed(_) | RecordedBinding::Unparseable => Err(WalletError::Validation(
            ValidationError::AuditLogBindingChanged {
                profile: profile_name.to_owned(),
            },
        )),
    }
}

/// The platform-keyring store of one profile's audit binding.
///
/// Reads and writes the record at [`KeyringEntryRef::default_audit_binding`]
/// through [`read_keyring_string`] and [`write_keyring_string`]. An entry the
/// backend reports as absent reads as `None`; any other read failure is an
/// error, so a backend that cannot answer never reads as "nothing recorded".
#[derive(Debug, Clone)]
pub struct KeyringAuditBindingStore {
    entry_ref: KeyringEntryRef,
}

impl KeyringAuditBindingStore {
    /// The store for the profile selected as `profile_name`.
    #[must_use]
    pub fn for_profile(profile_name: &str) -> Self {
        Self {
            entry_ref: KeyringEntryRef::default_audit_binding(profile_name),
        }
    }

    /// The keyring coordinate holding the record.
    #[must_use]
    pub fn entry_ref(&self) -> &KeyringEntryRef {
        &self.entry_ref
    }

    /// Reads the record without parsing it. `Ok(None)` when nothing is
    /// recorded.
    ///
    /// # Errors
    ///
    /// The keyring error for any read failure other than an absent entry.
    pub fn load_raw(&self) -> Result<Option<String>, WalletError> {
        read_keyring_string(&self.entry_ref)
    }

    /// Reads the record and compares it with `expected`.
    ///
    /// # Errors
    ///
    /// The keyring error for any read failure other than an absent entry.
    pub fn classify(&self, expected: &AuditBinding) -> Result<RecordedBinding, WalletError> {
        let raw = self.load_raw()?;
        Ok(RecordedBinding::classify(raw.as_deref(), expected))
    }

    /// Records `binding`, replacing any current record.
    ///
    /// # Errors
    ///
    /// The keyring error when the write fails.
    pub fn store(&self, binding: &AuditBinding) -> Result<(), WalletError> {
        write_keyring_string(&self.entry_ref, &binding.to_keyring_value())
    }
}

/// The platform-keyring implementation of the audit log's tip anchor.
///
/// Holds the two keyring coordinates the anchor for one log PATH occupies: the
/// anchor value itself, and the monotonic counter of operator-acknowledged
/// re-anchors beside it. Both are derived from the profile's audit-key
/// coordinate plus the lexically normalized log path, so a repointed
/// `audit_log_path` has coordinates of its own and never carries the old
/// file's tip onto a new file. The audit binding refuses the repointed path
/// until the operator acknowledges it.
///
/// Neither value is secret: the anchor is a count, a public chain hash, and a
/// byte offset. The anchor, the re-anchor counter, and the audit binding live
/// in the keyring, outside the log file. Anyone who can restore the keyring's
/// own storage together with the log can restore an older state. With a
/// headless keyring backend these entries are kept in a file on the same host.
/// Anyone who can write that file can restore older entries or delete one,
/// which needs no key material.
#[derive(Debug, Clone)]
pub struct KeyringTipAnchorStore {
    anchor_ref: KeyringEntryRef,
    counter_ref: KeyringEntryRef,
}

impl KeyringTipAnchorStore {
    /// Derives the anchor coordinates for `log_path` from the profile's
    /// audit-key entry reference.
    ///
    /// The service is the audit key's own service, so an operator-overridden
    /// audit coordinate keeps its anchor associated with it; the account is the
    /// audit key's account suffixed with the path digest.
    #[must_use]
    pub fn new(audit_key_ref: &KeyringEntryRef, log_path: &Path) -> Self {
        Self::for_path_digest(
            audit_key_ref,
            &stellar_agent_core::audit_log::tip_anchor::log_path_sha256(log_path),
        )
    }

    /// [`KeyringTipAnchorStore::new`] for a path known only by its digest, as
    /// an [`AuditBinding`] records it.
    #[must_use]
    pub fn for_path_digest(audit_key_ref: &KeyringEntryRef, path_sha256: &[u8; 32]) -> Self {
        Self {
            anchor_ref: KeyringEntryRef::new(
                audit_key_ref.service.clone(),
                tip_anchor_account_for_digest(&audit_key_ref.account, path_sha256),
            ),
            counter_ref: KeyringEntryRef::new(
                audit_key_ref.service.clone(),
                reanchor_count_account_for_digest(&audit_key_ref.account, path_sha256),
            ),
        }
    }

    /// Returns the anchor store for `log_path` as a shared trait object, ready
    /// to hand to [`stellar_agent_core::audit_log::AuditWriter`].
    #[must_use]
    pub fn shared(audit_key_ref: &KeyringEntryRef, log_path: &Path) -> Arc<dyn TipAnchorStore> {
        Arc::new(Self::new(audit_key_ref, log_path))
    }

    /// The keyring coordinate holding the anchor value.
    #[must_use]
    pub fn anchor_entry_ref(&self) -> &KeyringEntryRef {
        &self.anchor_ref
    }
}

/// Maps a keyring failure into the anchor store's error type.
///
/// The wallet error's `Display` already carries only non-secret coordinates and
/// fixed labels, and the anchor itself is not secret, so the text is forwarded
/// as the detail.
fn anchor_store_error(op: &str, e: &WalletError) -> TipAnchorStoreError {
    TipAnchorStoreError::new(format!("{op}: {e}"))
}

impl TipAnchorStore for KeyringTipAnchorStore {
    fn load_anchor(&self) -> Result<Option<TipAnchor>, TipAnchorStoreError> {
        let raw = read_keyring_string(&self.anchor_ref)
            .map_err(|e| anchor_store_error("anchor read failed", &e))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        TipAnchor::parse(raw.trim())
            .map(Some)
            .map_err(|e| TipAnchorStoreError::new(format!("anchor value is unusable: {e}")))
    }

    fn load_raw(&self) -> Result<Option<String>, TipAnchorStoreError> {
        read_keyring_string(&self.anchor_ref)
            .map_err(|e| anchor_store_error("anchor read failed", &e))
    }

    fn store_anchor(&self, anchor: &TipAnchor) -> Result<(), TipAnchorStoreError> {
        write_keyring_string(&self.anchor_ref, &anchor.to_keyring_value())
            .map_err(|e| anchor_store_error("anchor write failed", &e))
    }

    fn bump_reanchor_count(&self) -> Result<u64, TipAnchorStoreError> {
        let current = self.reanchor_count()?.unwrap_or(0);
        let next = current.checked_add(1).ok_or_else(|| {
            TipAnchorStoreError::new("audit re-anchor counter overflow".to_owned())
        })?;
        write_keyring_string(&self.counter_ref, &next.to_string())
            .map_err(|e| anchor_store_error("re-anchor counter write failed", &e))?;
        Ok(next)
    }

    fn reanchor_count(&self) -> Result<Option<u64>, TipAnchorStoreError> {
        let raw = read_keyring_string(&self.counter_ref)
            .map_err(|e| anchor_store_error("re-anchor counter read failed", &e))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        raw.trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|e| TipAnchorStoreError::new(format!("re-anchor counter is unusable: {e}")))
    }
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
    ///   keyring entry does not exist.
    /// - [`WalletError::Auth`] wrapping [`AuthError::KeyringPlatformError`] if
    ///   the credential store operation fails.
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
        let s_strkey: Zeroizing<String> = Zeroizing::new(entry.get_password().map_err(|e| {
            map_keyring_operation_error(&e, KeyringOperation::Read, &self.entry_ref.service)
        })?);

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
        let s_strkey: Zeroizing<String> = Zeroizing::new(entry.get_password().map_err(|e| {
            map_keyring_operation_error(&e, KeyringOperation::Read, &self.entry_ref.service)
        })?);

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
        let s_strkey: Zeroizing<String> = Zeroizing::new(entry.get_password().map_err(|e| {
            map_keyring_operation_error(&e, KeyringOperation::Read, &self.entry_ref.service)
        })?);

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

/// Constructs a lazy keyring signing handle from the profile's expected
/// public account without opening or reading the keyring entry.
///
/// The first signing call loads the seed and verifies that its derived public
/// key matches `expected_source_g` before producing a signature. This is useful
/// for flows that must durably claim an operation before any secret-key access.
///
/// # Errors
///
/// Returns a signer-key mismatch error when `expected_source_g` is not a
/// canonical ed25519 public-key strkey.
pub fn lazy_signer_from_keyring(
    entry_ref: &KeyringEntryRef,
    expected_source_g: &str,
) -> Result<KeyringSignHandle, WalletError> {
    let public_key =
        stellar_strkey::ed25519::PublicKey::from_string(expected_source_g).map_err(|_error| {
            WalletError::Auth(AuthError::SignerKeyMismatch {
                expected: redact_strkey_first5_last5(expected_source_g),
                got: "invalid public account".to_owned(),
            })
        })?;
    Ok(KeyringSignHandle {
        entry_ref: entry_ref.clone(),
        cached_pubkey_bytes: public_key.0,
    })
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
///   entry does not exist or the stored value is not a valid S-strkey.
/// - [`WalletError::Auth`] wrapping [`AuthError::KeyringPlatformError`] if the
///   credential store operation fails.
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
    let s_strkey: Zeroizing<String> = Zeroizing::new(entry.get_password().map_err(|e| {
        map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
    })?);

    // Delegate to the canonical parse-verify-zeroise helper in signing::source.
    // It applies the full zeroisation sequence (PrivateKey residue,
    // Zeroizing<String> drop, SecretBox heap) and verifies the G-strkey before
    // returning. The keyring-entry source classifies a parse failure as a
    // keyring-content condition naming the service alias.
    let signer = signer_from_s_strkey(
        s_strkey,
        expected_source_g,
        SecretStrkeySource::KeyringEntry(&entry_ref.service),
    )
    .await?;

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

/// The profile's enrolled keyring signer; on mainnet the pin must be valid and the stored key must derive to it.
///
/// # Errors
/// Refuses invalid enrollment, a different stored key, or a keyring load failure.
pub async fn enrolled_keyring_signer(
    profile_name: &str,
    profile: &stellar_agent_core::profile::Profile,
    expected_source_g: &str,
) -> Result<KeyringSignHandle, WalletError> {
    use stellar_agent_core::profile::enrolled_signer_pin;
    let pin = enrolled_signer_pin(profile_name, profile)?;
    let result = signer_from_keyring(&profile.mcp_signer_default, expected_source_g).await;
    if let Some(enrolled) = pin {
        let derived = match &result {
            Ok(handle) => Some(handle.public_key().to_string().to_string()),
            Err(WalletError::Auth(AuthError::SignerKeyMismatch { got, .. })) => Some(got.clone()),
            _ => None,
        };
        if let Some(derived) = derived
            && derived != enrolled
        {
            return Err(AuthError::EnrolledSignerMismatch {
                profile: profile_name.to_owned(),
                enrolled,
                derived,
            }
            .into());
        }
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Opens a `keyring_core::Entry` for the given [`KeyringEntryRef`].
///
/// Classifies construction failures with their operation and safe cause.
/// A missing default store or rejected coordinate is a platform failure.
fn open_entry(entry_ref: &KeyringEntryRef) -> Result<KeyringEntry, WalletError> {
    KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        map_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service)
    })
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
        WalletError::Auth(AuthError::KeyringPlatformError { .. }) => {
            "AuthError::KeyringPlatformError"
        }
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
        WalletError::Approval(_) => "WalletError::Approval",
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

    struct RestoreStore(Option<Arc<keyring_core::CredentialStore>>);
    impl RestoreStore {
        fn new() -> Self {
            Self(keyring_core::unset_default_store())
        }
    }
    impl Drop for RestoreStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }

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

    fn enrolled_profile(mainnet: bool, pin: &str) -> stellar_agent_core::profile::Profile {
        if mainnet {
            stellar_agent_core::profile::Profile::builder_mainnet_named(
                "enrolled",
                "https://rpc.example.invalid",
                "identity-test",
                pin,
                "n",
                "a",
            )
            .build()
        } else {
            stellar_agent_core::profile::Profile::builder_testnet_named(
                "enrolled",
                "identity-test",
                pin,
                "n",
                "a",
            )
            .build()
        }
    }

    #[test]
    #[serial_test::serial]
    fn dpapi_typed_diagnostics_preserve_only_protect_codes() {
        use stellar_agent_headless_keyring::crypto::{CryptoError, ProtectionMode};
        use stellar_agent_headless_keyring::store::HeadlessStore;
        let dir = tempfile::tempdir().unwrap();
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(std::sync::Arc::new(HeadlessStore::new(
            dir.path().join("keyring.json"),
            ProtectionMode::Dpapi,
        )));
        for (inner, expected) in [
            (
                CryptoError::DpapiProtectFailed { code: 2148073483 },
                "DPAPI CryptProtectData failed (error 2148073483) while writing headless-dpapi; if this session cannot access the user's DPAPI master key, try an interactive desktop logon, or configure STELLAR_AGENT_KEYRING_BACKEND=headless-env and STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            ),
            (
                CryptoError::DpapiProtectInternalFailure,
                "headless-dpapi could not protect the value",
            ),
            (CryptoError::SealFailed, "credential store operation failed"),
        ] {
            let error = keyring_core::Error::PlatformFailure(Box::new(inner));
            let classified =
                map_keyring_operation_error(&error, KeyringOperation::Write, "service-sentinel");
            assert_eq!(classified.code(), "auth.keyring_platform_error");
            assert_eq!(
                classified.message(),
                format!("keyring operation failed: write headless-dpapi: {expected}")
            );
            assert!(!format!("{classified:?}").contains("service-sentinel"));
        }
        let nested = keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(
            CryptoError::DpapiProtectFailed { code: 2148073483 },
        )));
        assert_eq!(
            map_keyring_operation_error(&nested, KeyringOperation::Write, "service").message(),
            "keyring operation failed: write headless-dpapi: credential store operation failed"
        );
    }

    #[test]
    #[serial_test::serial]
    fn platform_store_initialization_failure_is_platform_error() {
        let _restore = RestoreStore::new();
        let expected = if cfg!(target_os = "macos") {
            "keyring operation failed: macOS Keychain store initialization failed"
        } else if cfg!(target_os = "linux") {
            "keyring operation failed: Linux Secret Service store initialization failed"
        } else if cfg!(target_os = "windows") {
            "keyring operation failed: Windows Credential Manager store initialization failed"
        } else {
            "keyring operation failed: unsupported-platform credential store initialization failed"
        };
        for (error, cause) in [
            (
                keyring_core::Error::BadStoreFormat("secret-sentinel".to_owned()),
                "credential store is not readable",
            ),
            (
                keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::from_raw_os_error(
                    13,
                ))),
                "credential store access denied (OS error 13)",
            ),
        ] {
            let error = install_platform_store(Err(error)).unwrap_err();
            assert_eq!(error.code(), "auth.keyring_platform_error");
            assert_eq!(error.message(), format!("{expected}: {cause}"));
            assert!(!format!("{error:?}").contains("secret-sentinel"));
        }
    }

    #[test]
    #[serial_test::serial]
    #[cfg(target_os = "windows")]
    fn dpapi_protect_failure_reaches_wallet_error() {
        use stellar_agent_headless_keyring::crypto::{
            DpapiError, ProtectionMode, with_dpapi_protect_result,
        };
        use stellar_agent_headless_keyring::store::HeadlessStore;
        let dir = tempfile::tempdir().unwrap();
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(std::sync::Arc::new(HeadlessStore::new(
            dir.path().join("keyring.json"),
            ProtectionMode::Dpapi,
        )));
        let entry = keyring_core::Entry::new("service-sentinel", "account-sentinel").unwrap();
        with_dpapi_protect_result(
            Err(DpapiError::Win32 {
                api: "hostile-api-label",
                code: 2148073483,
            }),
            || {
                let error = entry.set_secret(b"secret-sentinel").unwrap_err();
                let classified = super::map_keyring_operation_error(
                    &error,
                    super::KeyringOperation::Write,
                    "service-sentinel",
                );
                assert_eq!(classified.code(), "auth.keyring_platform_error");
                assert_eq!(
                    classified.message(),
                    "keyring operation failed: write headless-dpapi: DPAPI CryptProtectData failed (error 2148073483) while writing headless-dpapi; if this session cannot access the user's DPAPI master key, try an interactive desktop logon, or configure STELLAR_AGENT_KEYRING_BACKEND=headless-env and STELLAR_AGENT_HEADLESS_KEYRING_KEY"
                );
                for sentinel in [
                    "service-sentinel",
                    "account-sentinel",
                    "secret-sentinel",
                    "hostile-api-label",
                ] {
                    assert!(!format!("{classified:?}").contains(sentinel));
                }
            },
        );
        with_dpapi_protect_result(Err(DpapiError::InputTooLarge), || {
            let error = entry.set_secret(b"secret-sentinel").unwrap_err();
            let classified = super::map_keyring_operation_error(
                &error,
                super::KeyringOperation::Write,
                "service-sentinel",
            );
            assert_eq!(classified.code(), "auth.keyring_platform_error");
            assert_eq!(
                classified.message(),
                "keyring operation failed: write headless-dpapi: headless-dpapi could not protect the value"
            );
        });
    }

    #[test]
    #[serial_test::serial]
    fn dpapi_protect_diagnostic_matches_crypto_display() {
        use stellar_agent_headless_keyring::crypto::CryptoError;
        let _restore = RestoreStore::new();
        let inner = CryptoError::DpapiProtectFailed { code: 2148073483 };
        let expected = inner.to_string();
        let error = keyring_core::Error::PlatformFailure(Box::new(inner));
        let classified = map_keyring_operation_error(&error, KeyringOperation::Write, "service");
        assert_eq!(
            classified.message(),
            format!("keyring operation failed: write no default store: {expected}")
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_mainnet_placeholder_refuses_before_store_read() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, "default");
        let entry = &profile.mcp_signer_default;
        store_sstrkey(entry, &sstrkey_for_seed([1; 32]));
        keyring_mock::inject_error(&entry.service, &entry.account, keyring_core::Error::NoEntry)
            .unwrap();
        let error = enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([1; 32]))
            .await
            .err()
            .expect("refusal");
        assert_eq!(error.code(), "auth.enrolled_signer_unpinned");
        let stored = KeyringEntry::new(&entry.service, &entry.account).unwrap();
        assert!(
            matches!(stored.get_password(), Err(keyring_core::Error::NoEntry)),
            "the injected store error must remain unread"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_mainnet_malformed_refuses_before_store_read() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, "malformed");
        let entry = &profile.mcp_signer_default;
        store_sstrkey(entry, &sstrkey_for_seed([1; 32]));
        keyring_mock::inject_error(&entry.service, &entry.account, keyring_core::Error::NoEntry)
            .unwrap();
        let error = enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([1; 32]))
            .await
            .err()
            .expect("refusal");
        assert_eq!(error.code(), "auth.enrolled_signer_unpinned");
        let stored = KeyringEntry::new(&entry.service, &entry.account).unwrap();
        assert!(
            matches!(stored.get_password(), Err(keyring_core::Error::NoEntry)),
            "the injected store error must remain unread"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_stored_b_expected_a() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, &gstrkey_for_seed([1; 32]));
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([2; 32]));
        let result =
            enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([1; 32])).await;
        assert_eq!(
            result.err().expect("refusal").code(),
            "auth.enrolled_signer_mismatch"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_stored_b_expected_b() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, &gstrkey_for_seed([1; 32]));
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([2; 32]));
        let result =
            enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([2; 32])).await;
        assert_eq!(
            result.err().expect("refusal").code(),
            "auth.enrolled_signer_mismatch"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_stored_a_expected_b() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, &gstrkey_for_seed([1; 32]));
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([1; 32]));
        let result =
            enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([2; 32])).await;
        assert_eq!(
            result.err().expect("refusal").code(),
            "auth.signer_key_mismatch"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_stored_a_expected_a() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(true, &gstrkey_for_seed([1; 32]));
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([1; 32]));
        let result =
            enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([1; 32])).await;
        assert_eq!(
            result.expect("handle").public_key().to_string().to_string(),
            gstrkey_for_seed([1; 32])
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_testnet_stored_a_expected_a() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(false, &gstrkey_for_seed([1; 32]));
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([1; 32]));
        let result =
            enrolled_keyring_signer("enrolled", &profile, &gstrkey_for_seed([1; 32])).await;
        assert_eq!(
            result.expect("handle").public_key().to_string().to_string(),
            gstrkey_for_seed([1; 32])
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_testnet_placeholder_preserves_keyring_errors() {
        keyring_mock::install().unwrap();
        let profile = enrolled_profile(false, "default");
        let result = enrolled_keyring_signer("enrolled", &profile, "default").await;
        assert_eq!(
            result.err().expect("absent key").code(),
            "auth.keyring_not_found"
        );
        store_sstrkey(&profile.mcp_signer_default, &sstrkey_for_seed([1; 32]));
        let result = enrolled_keyring_signer("enrolled", &profile, "default").await;
        assert_eq!(
            result.err().expect("source mismatch").code(),
            "auth.signer_key_mismatch"
        );
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
    fn open_entry_without_store_returns_platform_error() {
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
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn lazy_signer_construction_does_not_open_the_keyring() {
        keyring_core::unset_default_store();
        let expected_g = gstrkey_for_seed([0x42; 32]);
        let entry_ref = KeyringEntryRef::new("stellar-agent-lazy-signer-test", "default");

        let handle = lazy_signer_from_keyring(&entry_ref, &expected_g)
            .expect("public identity alone constructs the handle");
        assert_eq!(handle.public_key().to_string(), expected_g.as_str());

        let error = handle
            .sign_tx_payload(&[0x11; 32])
            .await
            .expect_err("first signature call must open the missing keyring");
        assert_eq!(error.code(), "auth.keyring_platform_error");
        assert!(lazy_signer_from_keyring(&entry_ref, "not-a-g-strkey").is_err());
    }

    // ── Audit-log tip anchor ─────────────────────────────────────────────────

    fn audit_ref() -> KeyringEntryRef {
        KeyringEntryRef::new("stellar-agent-audit-anchor-test", "default")
    }

    #[test]
    #[serial_test::serial]
    fn tip_anchor_round_trips_through_the_keyring() {
        keyring_mock::install().expect("mock keyring store");
        let store = KeyringTipAnchorStore::new(&audit_ref(), Path::new("/data/audit/one.jsonl"));

        assert_eq!(
            store.load_anchor().unwrap(),
            None,
            "an unwritten anchor reads as absent, which is the adoption signal"
        );

        let anchor = TipAnchor::new(4, format!("sha256:{}", "ab".repeat(32)), 900);
        store.store_anchor(&anchor).unwrap();
        assert_eq!(store.load_anchor().unwrap(), Some(anchor.clone()));

        // The raw keyring value is the documented wire form, not a debug dump.
        let raw = read_keyring_string(store.anchor_entry_ref())
            .unwrap()
            .unwrap();
        assert_eq!(raw, anchor.to_keyring_value());
    }

    #[test]
    #[serial_test::serial]
    fn tip_anchor_follows_the_log_path_not_the_profile() {
        keyring_mock::install().expect("mock keyring store");
        let audit_ref = audit_ref();
        let first = KeyringTipAnchorStore::new(&audit_ref, Path::new("/data/audit/one.jsonl"));
        let second = KeyringTipAnchorStore::new(&audit_ref, Path::new("/data/audit/two.jsonl"));

        let anchor = TipAnchor::new(2, format!("sha256:{}", "cd".repeat(32)), 400);
        first.store_anchor(&anchor).unwrap();

        assert_eq!(first.load_anchor().unwrap(), Some(anchor));
        assert_eq!(
            second.load_anchor().unwrap(),
            None,
            "a repointed log path has an anchor coordinate of its own"
        );
        assert_ne!(
            first.anchor_entry_ref().account,
            second.anchor_entry_ref().account
        );
        assert_eq!(
            first.anchor_entry_ref().service,
            audit_ref.service,
            "the anchor stays on the profile's own audit service"
        );
    }

    #[test]
    #[serial_test::serial]
    fn tip_anchor_lexically_equal_paths_share_one_anchor() {
        keyring_mock::install().expect("mock keyring store");
        let audit_ref = audit_ref();
        let plain = KeyringTipAnchorStore::new(&audit_ref, Path::new("/data/audit/one.jsonl"));
        let dotted =
            KeyringTipAnchorStore::new(&audit_ref, Path::new("/data/audit/x/../one.jsonl"));

        let anchor = TipAnchor::new(1, format!("sha256:{}", "ef".repeat(32)), 120);
        plain.store_anchor(&anchor).unwrap();
        assert_eq!(dotted.load_anchor().unwrap(), Some(anchor));
    }

    #[test]
    #[serial_test::serial]
    fn reanchor_counter_is_monotonic_and_starts_absent() {
        keyring_mock::install().expect("mock keyring store");
        let store = KeyringTipAnchorStore::new(&audit_ref(), Path::new("/data/audit/one.jsonl"));

        assert_eq!(store.reanchor_count().unwrap(), None);
        assert_eq!(store.bump_reanchor_count().unwrap(), 1);
        assert_eq!(store.bump_reanchor_count().unwrap(), 2);
        assert_eq!(store.reanchor_count().unwrap(), Some(2));
    }

    #[test]
    #[serial_test::serial]
    fn an_unparseable_anchor_is_an_error_not_an_adoption() {
        keyring_mock::install().expect("mock keyring store");
        let store = KeyringTipAnchorStore::new(&audit_ref(), Path::new("/data/audit/one.jsonl"));
        write_keyring_string(store.anchor_entry_ref(), "not-an-anchor").unwrap();

        assert!(
            store.load_anchor().is_err(),
            "a corrupted anchor must refuse, not read as never-written: \
             adopting over it would erase the rollback guard"
        );
    }

    // ── Audit binding ────────────────────────────────────────────────────────

    /// A profile named `name` whose audit key is minted in the mock keyring.
    fn bound_profile(name: &str, log_path: &str) -> Profile {
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        profile.audit_log_path = std::path::PathBuf::from(log_path);
        let coordinate = &profile.audit_log_hash_chain_key_id;
        rotate_keyring_secret_32(&coordinate.service, &coordinate.account).expect("mint audit key");
        profile
    }

    fn recorded_binding(name: &str) -> Option<String> {
        read_keyring_string(&KeyringEntryRef::default_audit_binding(name)).expect("read binding")
    }

    fn assert_binding_refusal(result: Result<KeyedAuditAccess, WalletError>, name: &str) {
        let err = result.expect_err("a changed binding must refuse");
        assert_eq!(err.code(), "audit.log_binding_changed", "{err}");
        let message = err.to_string();
        assert!(message.contains(name), "{message}");
        assert!(
            message.contains("--acknowledge-binding-change"),
            "{message}"
        );
        assert!(!message.contains("/data/"), "no path: {message}");
        assert!(
            !message.contains("auditbinding"),
            "no coordinate: {message}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn an_absent_binding_is_recorded_under_enforce_and_a_changed_path_then_refuses() {
        keyring_mock::install().expect("mock keyring store");
        let mut profile = bound_profile("bind-enforce", "/data/audit/one.jsonl");
        assert!(
            recorded_binding("bind-enforce").is_none(),
            "nothing recorded yet"
        );

        keyed_audit_access(&profile, "bind-enforce", BindingCheck::Enforce)
            .expect("an absent binding is recorded and the acquisition continues");
        assert!(
            recorded_binding("bind-enforce")
                == Some(AuditBinding::for_profile(&profile).to_keyring_value()),
            "the stored record is the profile's binding"
        );
        keyed_audit_access(&profile, "bind-enforce", BindingCheck::Enforce)
            .expect("an equal binding continues");

        profile.audit_log_path = std::path::PathBuf::from("/data/audit/two.jsonl");
        assert_binding_refusal(
            keyed_audit_access(&profile, "bind-enforce", BindingCheck::Enforce),
            "bind-enforce",
        );
    }

    #[test]
    #[serial_test::serial]
    fn check_only_records_nothing_and_refuses_a_changed_record() {
        keyring_mock::install().expect("mock keyring store");
        let mut profile = bound_profile("bind-check", "/data/audit/one.jsonl");

        keyed_audit_access(&profile, "bind-check", BindingCheck::CheckOnly)
            .expect("an absent binding continues under CheckOnly");
        assert!(
            recorded_binding("bind-check").is_none(),
            "CheckOnly never records a binding"
        );

        let recorded = AuditBinding::for_profile(&profile);
        KeyringAuditBindingStore::for_profile("bind-check")
            .store(&recorded)
            .expect("record a binding");
        keyed_audit_access(&profile, "bind-check", BindingCheck::CheckOnly)
            .expect("an equal binding continues under CheckOnly");

        profile.audit_log_path = std::path::PathBuf::from("/data/audit/two.jsonl");
        assert_binding_refusal(
            keyed_audit_access(&profile, "bind-check", BindingCheck::CheckOnly),
            "bind-check",
        );
        assert!(
            recorded_binding("bind-check") == Some(recorded.to_keyring_value()),
            "a refusal leaves the record"
        );
    }

    /// The binding refusal comes before any read of the audit key: an error
    /// planted at the key's coordinate is still pending afterwards.
    #[test]
    #[serial_test::serial]
    fn a_changed_path_refuses_before_the_hmac_key_load() {
        keyring_mock::install().expect("mock keyring store");
        let mut profile = bound_profile("bind-order", "/data/audit/one.jsonl");
        keyed_audit_access(&profile, "bind-order", BindingCheck::Enforce).expect("record");

        profile.audit_log_path = std::path::PathBuf::from("/data/audit/two.jsonl");
        let key = profile.audit_log_hash_chain_key_id.clone();
        keyring_mock::inject_error(
            &key.service,
            &key.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("planted"))),
        )
        .expect("inject");
        assert_binding_refusal(
            keyed_audit_access(&profile, "bind-order", BindingCheck::Enforce),
            "bind-order",
        );
        assert!(
            load_hmac_key_32(&key).is_err(),
            "the planted key error is still pending, so the key was never read"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_changed_audit_key_coordinate_refuses() {
        keyring_mock::install().expect("mock keyring store");
        let mut profile = bound_profile("bind-key", "/data/audit/one.jsonl");
        keyed_audit_access(&profile, "bind-key", BindingCheck::Enforce).expect("record");

        profile.audit_log_hash_chain_key_id =
            KeyringEntryRef::new("stellar-agent-audit-other", "x");
        rotate_keyring_secret_32("stellar-agent-audit-other", "x").expect("mint other key");
        assert_binding_refusal(
            keyed_audit_access(&profile, "bind-key", BindingCheck::Enforce),
            "bind-key",
        );
    }

    #[test]
    #[serial_test::serial]
    fn an_unparseable_record_refuses_under_both_checks() {
        keyring_mock::install().expect("mock keyring store");
        let profile = bound_profile("bind-garbage", "/data/audit/one.jsonl");
        write_keyring_string(
            &KeyringEntryRef::default_audit_binding("bind-garbage"),
            "not a binding",
        )
        .expect("plant");
        for check in [BindingCheck::Enforce, BindingCheck::CheckOnly] {
            assert_binding_refusal(
                keyed_audit_access(&profile, "bind-garbage", check),
                "bind-garbage",
            );
        }
        assert!(
            recorded_binding("bind-garbage").as_deref() == Some("not a binding"),
            "a refusal never overwrites the record"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_binding_write_error_fails_the_acquisition_with_the_keyring_code() {
        let coordinate = KeyringEntryRef::default_audit_binding("bind-write");
        keyring_mock::install_with_write_error(
            &coordinate.service,
            &coordinate.account,
            None,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("planted"))),
        )
        .expect("mock keyring store");
        let profile = bound_profile("bind-write", "/data/audit/one.jsonl");

        let err = keyed_audit_access(&profile, "bind-write", BindingCheck::Enforce)
            .expect_err("a failed binding write fails the acquisition");
        assert_eq!(err.category(), ErrorCategory::Auth, "{err}");
        assert_ne!(err.code(), "audit.log_binding_changed");
        assert!(
            recorded_binding("bind-write").is_none(),
            "a failed write records nothing"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_binding_read_error_fails_closed_and_writes_nothing() {
        keyring_mock::install().expect("mock keyring store");
        let profile = bound_profile("bind-read", "/data/audit/one.jsonl");
        let coordinate = KeyringEntryRef::default_audit_binding("bind-read");
        keyring_mock::inject_error(
            &coordinate.service,
            &coordinate.account,
            keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("planted"))),
        )
        .expect("inject");

        let err = keyed_audit_access(&profile, "bind-read", BindingCheck::Enforce)
            .expect_err("a binding read error fails closed");
        assert_eq!(err.category(), ErrorCategory::Auth, "{err}");
        assert!(
            recorded_binding("bind-read").is_none(),
            "a read error records nothing"
        );
    }

    #[test]
    #[serial_test::serial]
    fn keyed_audit_access_refuses_the_owner_public_key() {
        keyring_mock::install().expect("mock keyring store");
        let profile = bound_profile("owner-audit", "/data/audit/owner.jsonl");
        let older_form = URL_SAFE_NO_PAD.encode([0x4d; 32]);
        for coordinate in [
            &KeyringEntryRef::default_owner_key("owner-audit"),
            &profile.audit_log_hash_chain_key_id,
        ] {
            write_keyring_string(coordinate, &older_form).expect("plant");
        }
        let err = keyed_audit_access(&profile, "owner-audit", BindingCheck::Enforce)
            .expect_err("an audit key equal to the owner key refuses");
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(err.to_string().contains(AUDIT_KEY_FIELD), "{err}");
    }

    #[test]
    #[serial_test::serial]
    fn keyed_audit_access_refuses_a_g_strkey_owner_value() {
        keyring_mock::install().expect("mock keyring store");
        let profile = bound_profile("owner-audit-strkey", "/data/audit/strkey.jsonl");
        write_keyring_string(
            &profile.audit_log_hash_chain_key_id,
            &gstrkey_for_seed([0x4e; 32]),
        )
        .expect("plant");
        let err = keyed_audit_access(&profile, "owner-audit-strkey", BindingCheck::Enforce)
            .expect_err("a G-strkey is not a 32-byte key");
        assert!(
            err.to_string().contains("must be 32 bytes, got 42"),
            "{err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn keyed_audit_access_refuses_an_owner_coordinate_without_a_read() {
        keyring_mock::install().expect("mock keyring store");
        let mut profile = bound_profile("owner-audit-coord", "/data/audit/coord.jsonl");
        profile.audit_log_hash_chain_key_id =
            KeyringEntryRef::new("stellar-agent-owner-B", "default");
        keyring_mock::inject_error(
            "stellar-agent-owner-B",
            "default",
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .expect("inject");
        assert!(
            recorded_binding("owner-audit-coord").is_none(),
            "nothing recorded yet"
        );
        let err = keyed_audit_access(&profile, "owner-audit-coord", BindingCheck::Enforce)
            .expect_err("an owner-namespace coordinate refuses");
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(
            recorded_binding("owner-audit-coord").is_none(),
            "an absent binding is not recorded for an owner-namespace coordinate"
        );
        let pending = KeyringEntry::new("stellar-agent-owner-B", "default")
            .and_then(|e| e.get_password())
            .expect_err("the planted error is still pending");
        assert!(
            matches!(pending, keyring_core::Error::PlatformFailure(_)),
            "no read happened: {pending:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_binding_digest_names_the_same_anchor_as_the_path() {
        keyring_mock::install().expect("mock keyring store");
        let path = Path::new("/data/audit/x/../one.jsonl");
        let by_path = KeyringTipAnchorStore::new(&audit_ref(), path);
        let by_digest = KeyringTipAnchorStore::for_path_digest(
            &audit_ref(),
            &stellar_agent_core::audit_log::tip_anchor::log_path_sha256(Path::new(
                "/data/audit/one.jsonl",
            )),
        );
        assert_eq!(by_path.anchor_entry_ref(), by_digest.anchor_entry_ref());
    }
}
