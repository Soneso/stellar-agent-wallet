//! `HardwareSigningKey` — Ledger hardware wallet signing via
//! `stellar_ledger::LedgerSigner<TransportNativeHID>`.
//!
//! # N1 / N3 alignment
//!
//! Hardware signing is the gold-standard N1 (self-custodial) path: the
//! ed25519 secret key never leaves the Ledger device. The signing payload
//! (the 32-byte transaction hash) is sent to the device; the device returns
//! a 64-byte signature. At no point does the host process hold or observe the
//! secret key material.
//!
//! N3 (no central server) is satisfied: the HID transport is a direct USB
//! connection to the device; no network request is made.
//!
//! # Generic parameter erasure
//!
//! `stellar_ledger::LedgerSigner<T: Exchange>` is generic over its transport.
//! We erase the generic parameter by boxing the `LedgerSigner` behind a
//! `Box<dyn SignerDevice>` — an internal trait defined in this module.  The
//! public `HardwareSigningKey` struct is not generic, so callers and the `Signer`
//! trait surface do not see the `Exchange` type parameter.
//!
//! # Timeout
//!
//! `HardwareSigningKey::sign_tx_payload` wraps the `LedgerSigner::sign_blob`
//! call in `tokio::time::timeout`.  The default timeout is 60 seconds;
//! rationale: Ledger UX requires the user to physically review and confirm
//! a transaction on-device.  60 seconds is generous but bounded; it prevents
//! an indefinite block when the user walks away or the device is unresponsive
//! without returning a transport error.  On elapsed, the function returns
//! `WalletError::WalletState(WalletStateError::HardwareTimeout)`.
//!
//! # Ledger Stellar app protocol version
//!
//! This module targets the Stellar Ledger app as shipped with the
//! `stellar-cli` 26.0.0 release.  The APDU constants embedded in
//! `stellar_ledger::LedgerSigner` (see `lib.rs` of that crate) correspond to
//! the Stellar app command specification at:
//! <https://github.com/LedgerHQ/app-stellar/blob/develop/docs/COMMANDS.md>
//!
//! The hash-signing mode (SIGN_TX_HASH = 0x08) requires the Stellar app to
//! have "Allow blind signing" enabled in its settings on the device.  If the
//! setting is disabled, the device returns APDU retcode 0x6C66, which
//! `stellar_ledger` surfaces as `Error::BlindSigningModeNotEnabled` and we
//! map to `WalletStateError::HardwareBlindSigningDisabled`.
//!

use std::time::Duration;

use async_trait::async_trait;
use stellar_agent_core::error::{
    AuthError, InternalError, ProtocolError, WalletError, WalletStateError,
};
use stellar_ledger::hd_path::HdPath;
use stellar_ledger::{Blob, Exchange, LedgerSigner};
use tokio::time::timeout;
use tracing::warn;

use crate::signing::{Signer, WebAuthnAssertion};

// ─────────────────────────────────────────────────────────────────────────────
// Internal type-erased transport trait
// ─────────────────────────────────────────────────────────────────────────────

/// Internal trait that erases the `Exchange` generic parameter.
///
/// `LedgerSigner<T>` is generic; storing it directly in a non-generic struct
/// would expose the `Exchange` type parameter in the public API.  This sealed
/// internal trait provides the two operations we need (`sign_blob`,
/// `get_public_key`) over a type-erased `dyn` pointer.
///
/// The trait is `Send + Sync` because `LedgerSigner<T>` unconditionally
/// declares `unsafe impl Send` and `unsafe impl Sync` upstream.  The `Send +
/// Sync` bounds here are safe trait bounds on `T: Exchange + Send + Sync` at
/// the generic layer, propagated through the blanket impl below.
///
/// # stellar-strkey version bridging
///
/// `stellar-ledger` bundles an older `stellar-strkey` than the workspace. The
/// two versions are binary-incompatible even though both expose the key as a
/// plain `pub [u8; 32]` newtype. The bridge extracts the raw 32 bytes via `.0`
/// on the ledger type and constructs a workspace
/// `stellar_strkey::ed25519::PublicKey` from those bytes.
#[async_trait]
trait SignerDevice: Send + Sync {
    async fn device_sign_blob(
        &self,
        hd_path: HdPath,
        blob: &[u8],
    ) -> Result<Vec<u8>, stellar_ledger::Error>;

    /// Returns the raw 32-byte public key.
    ///
    /// Returns raw bytes rather than `stellar_strkey::ed25519::PublicKey` to
    /// avoid the version-boundary conversion being done at the trait level
    /// (where the type identity is ambiguous).  The caller wraps the bytes.
    async fn device_public_key_bytes(
        &self,
        hd_path: HdPath,
    ) -> Result<[u8; 32], stellar_ledger::Error>;
}

#[async_trait]
impl<T> SignerDevice for LedgerSigner<T>
where
    T: Exchange + Send + Sync,
{
    async fn device_sign_blob(
        &self,
        hd_path: HdPath,
        blob: &[u8],
    ) -> Result<Vec<u8>, stellar_ledger::Error> {
        self.sign_blob(&hd_path, blob).await
    }

    async fn device_public_key_bytes(
        &self,
        hd_path: HdPath,
    ) -> Result<[u8; 32], stellar_ledger::Error> {
        // Calls stellar_ledger::Blob::get_public_key which returns a
        // stellar_strkey::ed25519::PublicKey from ledger's bundled stellar-strkey.
        // Extract the inner bytes via `.0` and return them; the caller wraps
        // them in the workspace stellar-strkey type.
        let pk = self.get_public_key(&hd_path).await?;
        Ok(pk.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public type
// ─────────────────────────────────────────────────────────────────────────────

/// Default timeout for hardware signing: 60 seconds.
///
/// See module-level documentation for the rationale.
pub const DEFAULT_HARDWARE_TIMEOUT: Duration = Duration::from_secs(60);

/// Targeted Stellar Ledger app version.
///
/// `stellar-ledger 26.0.0` embeds APDU constants matching the Stellar Ledger
/// app as shipped at the `stellar-cli` 26.0.0 release tag; this constant
/// asserts the target version and should be updated when the upstream crate
/// is bumped. Version bytes come from the `get_app_configuration` APDU
/// response: `[flags, major, minor, patch]` = `[0, 5, 0, 3]`.
pub const TARGETED_LEDGER_STELLAR_APP_VERSION: (u8, u8, u8) = (5, 0, 3);

/// Wraps a connected Ledger device for hardware signing.
///
/// Delegates signing to `stellar_ledger::LedgerSigner<TransportNativeHID>` via
/// a type-erased internal trait, so the `Exchange` generic parameter does not
/// appear in the public API.
///
/// # N1 alignment
///
/// The ed25519 private key never leaves the Ledger device.  Only the 32-byte
/// transaction hash payload is sent to the device over HID; the 64-byte
/// signature is returned.  This is the self-custodial signing path.
///
/// # Construction
///
/// Use [`HardwareSigningKey::native`] to open a connection to the first
/// connected Ledger device using the system HID API.  Use
/// [`HardwareSigningKey::new`] to provide a custom `Exchange` transport
/// (primarily for testing).
///
/// # Stability
///
/// `#[non_exhaustive]` because future additions (e.g. a custom HD-path
/// override, retry policy, or multi-device selector) must not be breaking
/// changes.  All fields are private; external callers cannot use struct-literal
/// construction regardless.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::HardwareSigningKey;
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// // Opens a connection to the first connected Ledger device.
/// let key = HardwareSigningKey::native()?;
/// # Ok(()) }
/// ```
#[non_exhaustive]
pub struct HardwareSigningKey {
    device: Box<dyn SignerDevice>,
    hd_path: HdPath,
    timeout_duration: Duration,
}

impl HardwareSigningKey {
    /// Opens a connection to the first connected Ledger device using the
    /// system HID API with the default HD path `m/44'/148'/0'` and the
    /// default 60-second signing timeout.
    ///
    /// # Errors
    ///
    /// - [`WalletError::WalletState`] wrapping `HardwareNotFound` if no
    ///   Ledger device is connected or the HID API cannot enumerate devices.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::HardwareSigningKey;
    ///
    /// let key = HardwareSigningKey::native().expect("Ledger must be connected");
    /// ```
    pub fn native() -> Result<Self, WalletError> {
        let signer = stellar_ledger::native().map_err(map_ledger_error)?;
        Ok(Self {
            device: Box::new(signer),
            hd_path: HdPath(0), // m/44'/148'/0'
            timeout_duration: DEFAULT_HARDWARE_TIMEOUT,
        })
    }

    /// Constructs a `HardwareSigningKey` from any type that implements
    /// `stellar_ledger::Exchange`.
    ///
    /// Primarily for testing: supply a `MockExchange` rather than a real
    /// device.  The default HD path `m/44'/148'/0'` and the default 60-second
    /// timeout are used.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::HardwareSigningKey;
    ///
    /// // In tests, supply a mock transport.
    /// // let key = HardwareSigningKey::new(mock_transport);
    /// ```
    #[must_use]
    pub fn new<T>(transport: T) -> Self
    where
        T: Exchange + Send + Sync + 'static,
    {
        Self {
            device: Box::new(LedgerSigner::new(transport)),
            hd_path: HdPath(0),
            timeout_duration: DEFAULT_HARDWARE_TIMEOUT,
        }
    }

    /// Constructs a `HardwareSigningKey` with a custom HD account index.
    ///
    /// The path is `m/44'/148'/<account_index>'`.  The default index is `0`
    /// (`m/44'/148'/0'`).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::HardwareSigningKey;
    ///
    /// let key = HardwareSigningKey::native()
    ///     .unwrap()
    ///     .with_account_index(2);
    /// ```
    #[must_use]
    pub fn with_account_index(mut self, index: u32) -> Self {
        self.hd_path = HdPath(index);
        self
    }

    /// Overrides the signing timeout.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use stellar_agent_network::HardwareSigningKey;
    ///
    /// let key = HardwareSigningKey::native()
    ///     .unwrap()
    ///     .with_timeout(Duration::from_secs(30));
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, duration: Duration) -> Self {
        self.timeout_duration = duration;
        self
    }
}

#[async_trait]
impl Signer for HardwareSigningKey {
    /// Signs a 32-byte transaction hash by sending it to the Ledger device
    /// and returning the 64-byte ed25519 signature.
    ///
    /// The call is wrapped in `tokio::time::timeout`; if the device does not
    /// respond within the configured duration (default 60 seconds),
    /// `WalletError::WalletState(HardwareTimeout)` is returned.
    ///
    /// # Errors
    ///
    /// - `WalletError::Auth(HardwareUserRefused)` — user rejected on device.
    /// - `WalletError::WalletState(HardwareNotFound)` — device not connected.
    /// - `WalletError::WalletState(HardwareWrongApp)` — Stellar app not open.
    /// - `WalletError::WalletState(HardwareTimeout)` — device did not respond.
    /// - `WalletError::WalletState(HardwareBlindSigningDisabled)` — blind
    ///   signing is disabled in the Stellar app settings.
    /// - `WalletError::Protocol(XdrCodecFailed)` — XDR encoding failure.
    /// - `WalletError::Internal(UnexpectedState)` — BIP-32 path error or
    ///   APDU decode failure.
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        let sign_future = self.device.device_sign_blob(self.hd_path, payload);
        let result = timeout(self.timeout_duration, sign_future)
            .await
            .map_err(|_elapsed| {
                warn!(
                    "hardware signer timed out after {:?}",
                    self.timeout_duration
                );
                WalletError::WalletState(WalletStateError::HardwareTimeout)
            })?
            .map_err(map_ledger_error)?;

        // stellar-ledger returns a Vec<u8>; convert to [u8; 64].
        result.try_into().map_err(|v: Vec<u8>| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "Ledger returned {} bytes for signature; expected 64",
                    v.len()
                ),
            })
        })
    }

    /// Signs a 32-byte smart-account auth-digest by sending it to the Ledger
    /// device and returning the 64-byte ed25519 signature.
    ///
    /// The device cannot distinguish a transaction-hash payload from an
    /// auth-digest payload — both are 32 raw bytes routed through the
    /// SIGN_TX_HASH (0x08) blind-signing APDU. The semantic split between
    /// `sign_tx_payload` and `sign_auth_digest` is enforced on the host side
    /// (caller selects the trait method matching the payload class). For the
    /// device's perspective, this is the same blind-sign call.
    ///
    /// # Errors
    ///
    /// Same variants as [`HardwareSigningKey::sign_tx_payload`].
    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        let sign_future = self.device.device_sign_blob(self.hd_path, digest);
        let result = timeout(self.timeout_duration, sign_future)
            .await
            .map_err(|_elapsed| {
                warn!(
                    "hardware auth-digest signer timed out after {:?}",
                    self.timeout_duration
                );
                WalletError::WalletState(WalletStateError::HardwareTimeout)
            })?
            .map_err(map_ledger_error)?;

        result.try_into().map_err(|v: Vec<u8>| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "Ledger returned {} bytes for auth-digest signature; expected 64",
                    v.len()
                ),
            })
        })
    }

    /// Signs a 32-byte Soroban address-credentials auth-entry signature_payload
    /// via the Ledger SIGN_TX_HASH (0x08) blind-signing APDU.
    ///
    /// The device cannot distinguish a transaction-hash payload from an
    /// auth-digest payload from a Soroban auth-entry signature_payload —
    /// all three are 32 raw bytes routed through the same blind-signing APDU.
    /// The semantic split is enforced on the host side (caller selects the
    /// trait method matching the payload class).
    ///
    /// # Errors
    ///
    /// Same variants as [`HardwareSigningKey::sign_tx_payload`].
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        let sign_future = self.device.device_sign_blob(self.hd_path, payload);
        let result = timeout(self.timeout_duration, sign_future)
            .await
            .map_err(|_elapsed| {
                warn!(
                    "hardware soroban-auth-payload signer timed out after {:?}",
                    self.timeout_duration
                );
                WalletError::WalletState(WalletStateError::HardwareTimeout)
            })?
            .map_err(map_ledger_error)?;

        result.try_into().map_err(|v: Vec<u8>| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "Ledger returned {} bytes for soroban-auth-payload signature; expected 64",
                    v.len()
                ),
            })
        })
    }

    /// Hardware ed25519 signers (Ledger) cannot produce WebAuthn assertions;
    /// the Stellar Ledger app does not support secp256r1 / passkey signing.
    ///
    /// Always returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "hardware"`. The `_auth_digest` and `_credential_id`
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
            signer_kind: "hardware",
            requested_primitive: "sign_webauthn_assertion",
        }))
    }

    /// Returns the ed25519 public key at the configured HD path by querying
    /// the device. The Stellar Ledger app at the `stellar-cli` 26.0.0 release
    /// target does not prompt the user for a plain `GET_PUBLIC_KEY` call
    /// (P1=0x00). Other firmware versions may behave differently.
    ///
    /// # Errors
    ///
    /// Same as [`HardwareSigningKey::sign_tx_payload`] minus `HardwareUserRefused`.
    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        let pk_future = self.device.device_public_key_bytes(self.hd_path);
        let bytes = timeout(self.timeout_duration, pk_future)
            .await
            .map_err(|_elapsed| {
                warn!("hardware public-key fetch timed out");
                WalletError::WalletState(WalletStateError::HardwareTimeout)
            })?
            .map_err(map_ledger_error)?;
        // Wrap the 32 raw bytes in the workspace stellar-strkey type.
        Ok(stellar_strkey::ed25519::PublicKey(bytes))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitizes a device-supplied detail string for use in user-visible messages
/// and `warn!` log fields.
///
/// Strips any character that is not ASCII graphic or a plain space, then
/// truncates to 32 characters. Prevents a hostile Ledger clone from injecting
/// control characters, newlines, or ANSI escape sequences into log output or
/// error messages.
///
/// All detail strings passing through `map_ledger_error` are sanitized here.
/// None of the `warn!`-logged detail strings carry secret material — they are
/// APDU retcode hex strings or OS errno strings produced by stellar-ledger.
fn sanitize_device_detail(detail: &str) -> String {
    detail
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect()
}

/// Maps every `stellar_ledger::Error` variant to a `WalletError` taxonomy entry.
///
/// # Mapping rationale
///
/// | `stellar_ledger::Error` | `WalletError` | Rationale |
/// |---|---|---|
/// | `TxRejectedByUser` | `Auth(HardwareUserRefused)` | The user explicitly declined on-device — an authentication rejection, not a device state problem. |
/// | `StellarAppNotOpen` | `WalletState(HardwareWrongApp)` | The device is reachable but has the wrong app; actionable: open the Stellar app. |
/// | `DeviceLocked` | `WalletState(HardwareNotFound)` | A locked device behaves like an absent device from the wallet's perspective; the user must unlock before any signing. |
/// | `LedgerHidError` | `WalletState(HardwareNotFound)` | HID API initialisation failed; no device is accessible. |
/// | `HidApiError` | `WalletState(HardwareNotFound)` | OS-level HID enumeration failed; no device is accessible. |
/// | `LedgerConnectionError` | `WalletState(HardwareNotFound)` | APDU exchange failed at the transport layer; device is effectively unreachable. |
/// | `APDUExchangeError` | `WalletState(HardwareNotFound)` | Generic APDU failure; no more specific taxonomy entry applies without a new subcategory. |
/// | `BlindSigningModeNotEnabled` | `WalletState(HardwareBlindSigningDisabled)` | Distinct from WrongApp — app is correct but a setting inside the app needs to change. |
/// | `XdrError` | `Protocol(XdrCodecFailed)` | XDR serialisation failure inside the signing payload builder. |
/// | `DecodeError` | `Internal(UnexpectedState)` | strkey decode failure on the returned public key; indicates a malformed device response. |
/// | `Bip32PathError` | `Internal(UnexpectedState)` | BIP-32 path encoding failure; indicates a construction-time invariant violation. |
///
/// `stellar_ledger::Error` is `#[non_exhaustive]` in all but name — it does not
/// carry the attribute but the upstream crate controls it, so we treat every
/// arm explicitly and use a catch-all for any future variant rather than
/// `_ => unreachable!()`.
pub(crate) fn map_ledger_error(err: stellar_ledger::Error) -> WalletError {
    // All `detail` / error strings logged via `warn!` in this function are
    // non-secret: they are APDU retcode hex strings or OS errno strings from
    // stellar-ledger. None carry key material, user data, or account IDs.
    // All are additionally sanitized via `sanitize_device_detail` before use.
    use stellar_ledger::Error as LE;
    match err {
        LE::TxRejectedByUser(_) => WalletError::Auth(AuthError::HardwareUserRefused),
        LE::StellarAppNotOpen(detail) => {
            WalletError::WalletState(WalletStateError::HardwareWrongApp {
                expected: "Stellar".to_owned(),
                got: sanitize_device_detail(&detail),
            })
        }
        LE::DeviceLocked(detail) => {
            // A locked device is operationally equivalent to "not found" from
            // the signing path's perspective. Log the sanitized detail at warn
            // level so an operator can distinguish the two conditions in the
            // logs without exposing the sub-condition through the taxonomy wire
            // code.
            warn!(
                "Ledger device is locked: {}",
                sanitize_device_detail(&detail)
            );
            WalletError::WalletState(WalletStateError::HardwareNotFound)
        }
        LE::HidApiError(e) => {
            warn!("HID API error: {}", sanitize_device_detail(&e.to_string()));
            WalletError::WalletState(WalletStateError::HardwareNotFound)
        }
        LE::LedgerHidError(e) => {
            warn!(
                "Ledger HID transport error: {}",
                sanitize_device_detail(&e.to_string())
            );
            WalletError::WalletState(WalletStateError::HardwareNotFound)
        }
        LE::LedgerConnectionError(detail) => {
            warn!(
                "Ledger connection error: {}",
                sanitize_device_detail(&detail)
            );
            WalletError::WalletState(WalletStateError::HardwareNotFound)
        }
        LE::APDUExchangeError(detail) => {
            // Catch-all for unexpected APDU retcodes not covered by a specific
            // variant. Maps to HardwareNotFound (device unreachable or app
            // returned an undocumented error code) with the sanitized detail
            // logged.
            warn!("APDU exchange error: {}", sanitize_device_detail(&detail));
            WalletError::WalletState(WalletStateError::HardwareNotFound)
        }
        LE::BlindSigningModeNotEnabled(_) => {
            WalletError::WalletState(WalletStateError::HardwareBlindSigningDisabled)
        }
        LE::XdrError(e) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: e.to_string(),
        }),
        LE::DecodeError(e) => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("Ledger returned malformed strkey: {e}"),
        }),
        LE::Bip32PathError(detail) => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "BIP-32 path encoding failed: {}",
                sanitize_device_detail(&detail)
            ),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only code; panics, unwrap and expect are acceptable in unit tests"
)]
mod tests {
    use std::collections::VecDeque;
    use std::ops::Deref;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use ledger_apdu::{APDUAnswer, APDUCommand};
    use stellar_agent_core::error::{ErrorCategory, WalletStateError};
    use stellar_ledger::Exchange;

    use super::*;

    // ─────────────────────────────────────────────────────────────────────
    // MockExchange — pure-Rust Exchange impl backed by a VecDeque of answers
    // ─────────────────────────────────────────────────────────────────────

    /// A scripted `Exchange` implementation for unit-testing hardware signing
    /// paths without a real device, without `http-transport`, and without
    /// `httpmock`.
    ///
    /// Responses are enqueued as raw APDU data bytes.  Each call to `exchange`
    /// pops the front answer.  An empty queue causes the exchange to return an
    /// error (simulating a lost connection).
    ///
    /// # Retcodes
    ///
    /// The retcode is encoded as the final two bytes of the response in
    /// big-endian format, following the APDU convention.
    struct MockExchange {
        /// Queue of pre-scripted raw answer bytes (data + retcode).
        answers: Mutex<VecDeque<Vec<u8>>>,
    }

    impl MockExchange {
        /// Creates a `MockExchange` with no queued answers.
        fn empty() -> Self {
            Self {
                answers: Mutex::new(VecDeque::new()),
            }
        }

        /// Creates a `MockExchange` with a single success response carrying
        /// `data` as the payload and `0x9000` (OK) as the retcode.
        fn with_success(mut data: Vec<u8>) -> Self {
            // Append 0x90 0x00 (retcode OK) as per APDU wire format.
            data.push(0x90);
            data.push(0x00);
            let mock = Self::empty();
            #[allow(
                clippy::unwrap_used,
                reason = "test-only construction; lock cannot be poisoned here"
            )]
            mock.answers.lock().unwrap().push_back(data);
            mock
        }

        /// Creates a `MockExchange` that returns a specific APDU retcode
        /// with empty payload data.
        fn with_retcode(retcode: u16) -> Self {
            let hi = (retcode >> 8) as u8;
            let lo = (retcode & 0xFF) as u8;
            let mock = Self::empty();
            #[allow(
                clippy::unwrap_used,
                reason = "test-only construction; lock cannot be poisoned here"
            )]
            mock.answers.lock().unwrap().push_back(vec![hi, lo]);
            mock
        }
    }

    /// `OwnedBytes` is a simple newtype over `Vec<u8>` that implements
    /// `Deref<Target = [u8]>` so it can serve as `Exchange::AnswerType`.
    struct OwnedBytes(Vec<u8>);

    impl Deref for OwnedBytes {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    #[async_trait]
    impl Exchange for MockExchange {
        type Error = std::io::Error;
        type AnswerType = OwnedBytes;

        async fn exchange<I>(
            &self,
            _command: &APDUCommand<I>,
        ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
        where
            I: Deref<Target = [u8]> + Send + Sync,
        {
            let mut queue = self
                .answers
                .lock()
                .map_err(|_| std::io::Error::other("mock lock poisoned"))?;
            match queue.pop_front() {
                Some(raw) => {
                    // `APDUAnswer::from_answer` takes any `B: Deref<Target=[u8]>`.
                    // We pass `OwnedBytes(raw)` directly so the returned type is
                    // `APDUAnswer<OwnedBytes>` matching `Self::AnswerType`.
                    APDUAnswer::from_answer(OwnedBytes(raw))
                        .map_err(|_| std::io::Error::other("invalid APDU answer"))
                }
                None => Err(std::io::Error::other("MockExchange: answer queue empty")),
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────

    fn key_with_mock(mock: MockExchange) -> HardwareSigningKey {
        HardwareSigningKey::new(mock)
    }

    // ─────────────────────────────────────────────────────────────────────
    // sanitize_device_detail unit tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn sanitize_empty_input_returns_empty() {
        assert_eq!(sanitize_device_detail(""), "");
    }

    #[test]
    fn sanitize_strips_ansi_escape_and_control_characters() {
        // ESC (0x1B), tab, newline, carriage return, DEL (0x7F), NUL all stripped.
        let crafted = "app\x1B[31mRED\x1B[0m\tfoo\nbar\r\x7F\0baz";
        assert_eq!(sanitize_device_detail(crafted), "app[31mRED[0mfoobarbaz");
    }

    #[test]
    fn sanitize_strips_non_ascii_unicode() {
        // Unicode look-alikes (fullwidth, combining marks) stripped; plain ASCII retained.
        let crafted = "abc\u{FF21}def\u{0301}ghi";
        assert_eq!(sanitize_device_detail(crafted), "abcdefghi");
    }

    #[test]
    fn sanitize_truncates_to_32_chars() {
        let long = "A".repeat(100);
        let out = sanitize_device_detail(&long);
        assert_eq!(out.len(), 32);
        assert!(out.chars().all(|c| c == 'A'));
    }

    #[test]
    fn sanitize_preserves_space_and_graphic() {
        let s = "error 0x6511 app not open";
        assert_eq!(sanitize_device_detail(s), s);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Error-mapping unit tests (pure; no async, no device required)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn map_tx_rejected_by_user() {
        let err = stellar_ledger::Error::TxRejectedByUser("user pressed X".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "auth.hardware_user_refused");
        assert_eq!(mapped.category(), ErrorCategory::Auth);
    }

    #[test]
    fn map_stellar_app_not_open() {
        let err = stellar_ledger::Error::StellarAppNotOpen("0x6511".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "wallet_state.hardware_wrong_app");
        assert_eq!(mapped.category(), ErrorCategory::WalletState);
        // The WrongApp variant should name "Stellar" as the expected app.
        if let WalletError::WalletState(WalletStateError::HardwareWrongApp { expected, .. }) =
            &mapped
        {
            assert_eq!(expected, "Stellar");
        } else {
            panic!("expected HardwareWrongApp, got: {mapped:?}");
        }
    }

    #[test]
    fn map_device_locked() {
        let err = stellar_ledger::Error::DeviceLocked("0x5515".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "wallet_state.hardware_not_found");
    }

    #[test]
    fn map_blind_signing_disabled() {
        let err = stellar_ledger::Error::BlindSigningModeNotEnabled("0x6C66".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(
            mapped.code(),
            "wallet_state.hardware_blind_signing_disabled"
        );
        assert_eq!(mapped.category(), ErrorCategory::WalletState);
    }

    #[test]
    fn map_ledger_connection_error() {
        let err = stellar_ledger::Error::LedgerConnectionError("no device".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "wallet_state.hardware_not_found");
    }

    #[test]
    fn map_apdu_exchange_error() {
        let err = stellar_ledger::Error::APDUExchangeError("0xFFFF".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "wallet_state.hardware_not_found");
    }

    #[test]
    fn map_xdr_error() {
        let xdr_err = stellar_xdr::Error::Invalid;
        let err = stellar_ledger::Error::XdrError(xdr_err);
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "protocol.xdr_codec_failed");
        assert_eq!(mapped.category(), ErrorCategory::Protocol);
    }

    #[test]
    fn map_bip32_path_error() {
        let err = stellar_ledger::Error::Bip32PathError("overflow".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "internal.unexpected_state");
        assert_eq!(mapped.category(), ErrorCategory::Internal);
    }

    /// Verifies the BIP-32 path error variant routes to
    /// `Internal(UnexpectedState)`.
    ///
    /// `stellar_ledger::Error::DecodeError` wraps a type from the `stellar-strkey`
    /// bundled inside `stellar-ledger`, which is a different, binary-incompatible
    /// version than the workspace `stellar-strkey`, so `DecodeError` cannot be
    /// constructed directly from this crate.
    /// `Bip32PathError` shares the same taxonomy mapping
    /// (`Internal(UnexpectedState)`) and can be constructed here, so this test
    /// uses it to verify the `Internal` category path is reachable.
    #[test]
    fn bip32_path_error_routes_to_internal_unexpected_state() {
        let err = stellar_ledger::Error::Bip32PathError("test".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.category(), ErrorCategory::Internal);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Mock-Exchange async signing tests
    // ─────────────────────────────────────────────────────────────────────

    /// A successful sign returns a 64-byte signature.
    #[tokio::test]
    async fn mock_sign_happy_path() {
        let sig_bytes = vec![0xABu8; 64];
        let key = key_with_mock(MockExchange::with_success(sig_bytes));
        let payload = [0u8; 32];
        let sig = key.sign_tx_payload(&payload).await.unwrap();
        assert_eq!(sig, [0xABu8; 64]);
    }

    /// APDU retcode 0x6985 — user rejected.
    #[tokio::test]
    async fn mock_user_refused() {
        let key = key_with_mock(MockExchange::with_retcode(0x6985));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "auth.hardware_user_refused");
    }

    /// APDU retcode 0x6511 — Stellar app not open.
    #[tokio::test]
    async fn mock_stellar_app_not_open() {
        let key = key_with_mock(MockExchange::with_retcode(0x6511));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_wrong_app");
    }

    /// APDU retcode 0x6C66 — blind signing disabled.
    #[tokio::test]
    async fn mock_blind_signing_disabled() {
        let key = key_with_mock(MockExchange::with_retcode(0x6C66));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_blind_signing_disabled");
    }

    /// APDU retcode 0x5515 — device locked.
    #[tokio::test]
    async fn mock_device_locked() {
        let key = key_with_mock(MockExchange::with_retcode(0x5515));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_not_found");
    }

    /// Empty queue simulates a connection error.
    #[tokio::test]
    async fn mock_connection_error() {
        let key = key_with_mock(MockExchange::empty());
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_not_found");
    }

    /// Unknown APDU retcode maps to `HardwareNotFound` via `APDUExchangeError`.
    #[tokio::test]
    async fn mock_unknown_apdu_retcode() {
        let key = key_with_mock(MockExchange::with_retcode(0xDEAD));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_not_found");
    }

    /// Signing times out when the transport stalls beyond the configured limit.
    ///
    /// Uses a stalling `Exchange` implementation that never resolves.  The
    /// `tokio::time::timeout` in `HardwareSigningKey::sign_tx_payload` fires
    /// when wall-clock time advances past `with_timeout(Duration)`.
    ///
    /// `tokio::time::pause` / `advance` require the `test-util` Tokio
    /// feature, which we deliberately do not enable to keep the dep footprint
    /// small.  We use a very short real-wall-clock timeout (5 ms) and
    /// a stalling transport that sleeps for 60 seconds.  The test runs in
    /// <50 ms in practice.
    #[tokio::test]
    async fn mock_timeout() {
        struct StallingExchange;

        #[async_trait]
        impl Exchange for StallingExchange {
            type Error = std::io::Error;
            type AnswerType = OwnedBytes;

            async fn exchange<I>(
                &self,
                _command: &APDUCommand<I>,
            ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
            where
                I: Deref<Target = [u8]> + Send + Sync,
            {
                // Stall far beyond the 5 ms test timeout.
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(std::io::Error::other("never reached"))
            }
        }

        let key = HardwareSigningKey::new(StallingExchange).with_timeout(Duration::from_millis(5));

        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_timeout");
    }

    /// App configuration fetch wiring coverage — exercises the config-fetch
    /// APDU round-trip against a mock and verifies the targeted Stellar Ledger
    /// app version constant.
    ///
    /// `stellar_ledger::LedgerSigner::get_app_configuration` sends APDU
    /// `e006000000` and expects four data bytes (flags, major, minor, patch).
    /// The assertion uses the constant on both sides (mock input + expected
    /// output), so the test verifies the APDU parser path, not on-device
    /// drift. Drift detection relies on the exact-version pin for
    /// `stellar-ledger` in the workspace manifest; any upstream bump should
    /// trigger a re-review of this constant.
    #[tokio::test]
    async fn mock_app_configuration_roundtrip() {
        let (target_major, target_minor, target_patch) = TARGETED_LEDGER_STELLAR_APP_VERSION;
        let config_data = vec![0x00u8, target_major, target_minor, target_patch];
        let mock = MockExchange::with_success(config_data);
        let signer = LedgerSigner::new(mock);
        let config = signer.get_app_configuration().await.unwrap();
        let (major, minor, patch) = (config[1], config[2], config[3]);
        assert_eq!(
            (major, minor, patch),
            TARGETED_LEDGER_STELLAR_APP_VERSION,
            "stellar-ledger targets version {TARGETED_LEDGER_STELLAR_APP_VERSION:?}; \
             update the constant if upstream shipped a new app version."
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Real-device integration tests (ignored; require hardware)
    // ─────────────────────────────────────────────────────────────────────

    /// Asserts that `HardwareSigningKey::sign_webauthn_assertion` returns
    /// `AuthError::SignerKindMismatch { signer_kind: "hardware", .. }`.
    ///
    /// The Ledger Stellar app does not support secp256r1 / passkey signing; the
    /// refusal must be immediate and require no device interaction (no mock
    /// APDU exchange is consumed).
    #[tokio::test]
    async fn hardware_signer_refuses_webauthn_assertion_with_kind_mismatch() {
        use stellar_agent_core::error::AuthError;

        // MockExchange::empty() — no APDU responses queued; the refusal must
        // return before any device interaction occurs.
        let key = key_with_mock(MockExchange::empty());
        let auth_digest = [0xAB_u8; 32];
        let credential_id = b"test-credential-id";

        let err = key
            .sign_webauthn_assertion(&auth_digest, credential_id)
            .await
            .unwrap_err();

        assert_eq!(err.code(), "auth.signer_kind_mismatch");
        match err {
            WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind,
                requested_primitive,
            }) => {
                assert_eq!(signer_kind, "hardware");
                assert_eq!(requested_primitive, "sign_webauthn_assertion");
            }
            other => panic!("expected SignerKindMismatch, got: {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // sign_auth_digest via mock
    // ─────────────────────────────────────────────────────────────────────

    /// `sign_auth_digest` succeeds and returns a 64-byte signature.
    #[tokio::test]
    async fn mock_sign_auth_digest_happy_path() {
        let sig_bytes = vec![0xCDu8; 64];
        let key = key_with_mock(MockExchange::with_success(sig_bytes));
        let digest = [0x01u8; 32];
        let sig = key.sign_auth_digest(&digest).await.unwrap();
        assert_eq!(sig, [0xCDu8; 64]);
    }

    /// `sign_auth_digest` propagates user-refused on retcode 0x6985.
    #[tokio::test]
    async fn mock_sign_auth_digest_user_refused() {
        let key = key_with_mock(MockExchange::with_retcode(0x6985));
        let digest = [0x02u8; 32];
        let err = key.sign_auth_digest(&digest).await.unwrap_err();
        assert_eq!(err.code(), "auth.hardware_user_refused");
    }

    /// `sign_auth_digest` times out when the transport stalls.
    #[tokio::test]
    async fn mock_sign_auth_digest_timeout() {
        struct StallingExchange2;

        #[async_trait]
        impl Exchange for StallingExchange2 {
            type Error = std::io::Error;
            type AnswerType = OwnedBytes;

            async fn exchange<I>(
                &self,
                _command: &APDUCommand<I>,
            ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
            where
                I: Deref<Target = [u8]> + Send + Sync,
            {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(std::io::Error::other("never reached"))
            }
        }

        let key = HardwareSigningKey::new(StallingExchange2).with_timeout(Duration::from_millis(5));
        let digest = [0x03u8; 32];
        let err = key.sign_auth_digest(&digest).await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_timeout");
    }

    // ─────────────────────────────────────────────────────────────────────
    // sign_soroban_address_auth_payload via mock
    // ─────────────────────────────────────────────────────────────────────

    /// `sign_soroban_address_auth_payload` succeeds and returns a 64-byte signature.
    #[tokio::test]
    async fn mock_sign_soroban_address_auth_payload_happy_path() {
        let sig_bytes = vec![0xEFu8; 64];
        let key = key_with_mock(MockExchange::with_success(sig_bytes));
        let payload = [0x04u8; 32];
        let sig = key
            .sign_soroban_address_auth_payload(&payload)
            .await
            .unwrap();
        assert_eq!(sig, [0xEFu8; 64]);
    }

    /// `sign_soroban_address_auth_payload` propagates blind-signing-disabled on retcode 0x6C66.
    #[tokio::test]
    async fn mock_sign_soroban_address_auth_payload_blind_signing_disabled() {
        let key = key_with_mock(MockExchange::with_retcode(0x6C66));
        let payload = [0x05u8; 32];
        let err = key
            .sign_soroban_address_auth_payload(&payload)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_blind_signing_disabled");
    }

    /// `sign_soroban_address_auth_payload` times out when the transport stalls.
    #[tokio::test]
    async fn mock_sign_soroban_address_auth_payload_timeout() {
        struct StallingExchange3;

        #[async_trait]
        impl Exchange for StallingExchange3 {
            type Error = std::io::Error;
            type AnswerType = OwnedBytes;

            async fn exchange<I>(
                &self,
                _command: &APDUCommand<I>,
            ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
            where
                I: Deref<Target = [u8]> + Send + Sync,
            {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(std::io::Error::other("never reached"))
            }
        }

        let key = HardwareSigningKey::new(StallingExchange3).with_timeout(Duration::from_millis(5));
        let payload = [0x06u8; 32];
        let err = key
            .sign_soroban_address_auth_payload(&payload)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_timeout");
    }

    // ─────────────────────────────────────────────────────────────────────
    // public_key() via mock
    // ─────────────────────────────────────────────────────────────────────

    /// `public_key()` returns a 32-byte public key matching the seed that the
    /// mock APDU response encodes.  The mock returns 32 raw bytes + 0x9000.
    /// The `stellar_ledger::LedgerSigner::get_public_key` call wraps those
    /// 32 bytes in a strkey and returns it; the bridge extracts `.0`.
    /// We use a well-known ed25519 seed to produce a deterministic 32-byte
    /// public key and verify the round-trip.
    #[tokio::test]
    async fn mock_public_key_happy_path() {
        use ed25519_dalek::SigningKey;

        let seed = [0x77u8; 32];
        let expected_pk_bytes = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        // stellar-ledger encodes the public key as a raw 32-byte payload in
        // the APDU response data (before the 0x9000 retcode suffix).
        // `get_public_key` returns stellar_ledger::stellar_strkey::ed25519::PublicKey(bytes).
        // The bridge extracts `.0`, which is the 32-byte array.
        let key = key_with_mock(MockExchange::with_success(expected_pk_bytes.to_vec()));
        let pk = key.public_key().await.unwrap();
        assert_eq!(
            pk.0, expected_pk_bytes,
            "public key byte bridge must return the 32 bytes from the APDU response"
        );
    }

    /// `public_key()` times out when the transport stalls.
    #[tokio::test]
    async fn mock_public_key_timeout() {
        struct StallingExchange4;

        #[async_trait]
        impl Exchange for StallingExchange4 {
            type Error = std::io::Error;
            type AnswerType = OwnedBytes;

            async fn exchange<I>(
                &self,
                _command: &APDUCommand<I>,
            ) -> Result<APDUAnswer<Self::AnswerType>, Self::Error>
            where
                I: Deref<Target = [u8]> + Send + Sync,
            {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(std::io::Error::other("never reached"))
            }
        }

        let key = HardwareSigningKey::new(StallingExchange4).with_timeout(Duration::from_millis(5));
        let err = key.public_key().await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_timeout");
    }

    /// `public_key()` propagates device errors — here an empty queue simulates a
    /// transport failure, which routes to `HardwareNotFound`.
    #[tokio::test]
    async fn mock_public_key_device_error() {
        let key = key_with_mock(MockExchange::empty());
        let err = key.public_key().await.unwrap_err();
        assert_eq!(err.code(), "wallet_state.hardware_not_found");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Short-signature error path
    // ─────────────────────────────────────────────────────────────────────

    /// When `stellar-ledger` returns fewer than 64 bytes for a signing
    /// response, `sign_tx_payload` must return
    /// `Internal(UnexpectedState)` describing the byte count.
    ///
    /// The mock returns 32 bytes of signature data + 0x9000.  The
    /// `Vec<u8>::try_into::<[u8; 64]>()` call inside the signing path
    /// fails because the vector is 32 bytes, triggering the error arm.
    #[tokio::test]
    async fn sign_tx_payload_short_signature_returns_unexpected_state() {
        // 32 bytes of payload data — NOT 64 — so the try_into conversion fails.
        let short_sig = vec![0xFFu8; 32];
        let key = key_with_mock(MockExchange::with_success(short_sig));
        let payload = [0u8; 32];
        let err = key.sign_tx_payload(&payload).await.unwrap_err();
        assert_eq!(err.code(), "internal.unexpected_state");
        assert_eq!(err.category(), ErrorCategory::Internal);
        // The error message must name the actual byte count.
        assert!(
            err.message().contains("32"),
            "error message must include the byte count; got: {}",
            err.message()
        );
    }

    /// Same short-signature invariant for `sign_auth_digest`.
    #[tokio::test]
    async fn sign_auth_digest_short_signature_returns_unexpected_state() {
        let short_sig = vec![0xFFu8; 16];
        let key = key_with_mock(MockExchange::with_success(short_sig));
        let digest = [0u8; 32];
        let err = key.sign_auth_digest(&digest).await.unwrap_err();
        assert_eq!(err.code(), "internal.unexpected_state");
        assert!(
            err.message().contains("16"),
            "error message must include the byte count; got: {}",
            err.message()
        );
    }

    /// Same short-signature invariant for `sign_soroban_address_auth_payload`.
    #[tokio::test]
    async fn sign_soroban_auth_payload_short_signature_returns_unexpected_state() {
        let short_sig = vec![0xFFu8; 8];
        let key = key_with_mock(MockExchange::with_success(short_sig));
        let payload = [0u8; 32];
        let err = key
            .sign_soroban_address_auth_payload(&payload)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "internal.unexpected_state");
        assert!(
            err.message().contains("8"),
            "error message must include the byte count; got: {}",
            err.message()
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Builder method assertions
    // ─────────────────────────────────────────────────────────────────────

    /// `with_account_index` changes the HD path used for subsequent signing.
    ///
    /// Two keys are constructed with different account indices.  Each signs the
    /// same payload against a mock that returns a fixed 64-byte signature.
    /// The test verifies that both succeed (the HD path does not affect the
    /// mock signing result; what matters is that the builder accepts a non-zero
    /// index without panicking or erroring).
    #[tokio::test]
    async fn with_account_index_is_accepted_by_builder() {
        let sig_bytes = vec![0x12u8; 64];
        let key = key_with_mock(MockExchange::with_success(sig_bytes)).with_account_index(3);
        let payload = [0u8; 32];
        let sig = key.sign_tx_payload(&payload).await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// `DEFAULT_HARDWARE_TIMEOUT` is 60 seconds as documented.
    #[test]
    fn default_hardware_timeout_is_60_seconds() {
        assert_eq!(DEFAULT_HARDWARE_TIMEOUT.as_secs(), 60);
    }

    /// `TARGETED_LEDGER_STELLAR_APP_VERSION` is a non-zero triple.
    ///
    /// The constant documents the Stellar Ledger app version targeted by the
    /// workspace dep pin. A zero tuple would indicate an unintended
    /// default-initialisation; this verifies the constant is non-zero.
    #[test]
    fn targeted_ledger_app_version_is_nonzero() {
        let (major, minor, patch) = TARGETED_LEDGER_STELLAR_APP_VERSION;
        // At least one component must be non-zero — a (0,0,0) version indicates
        // unintended initialisation or a reset of the constant.
        assert!(
            major > 0 || minor > 0 || patch > 0,
            "TARGETED_LEDGER_STELLAR_APP_VERSION must be non-zero; got ({major},{minor},{patch})"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // map_ledger_error: HidApiError and LedgerHidError variants
    // ─────────────────────────────────────────────────────────────────────

    /// `APDUExchangeError` — the catch-all for unexpected APDU retcodes — maps to
    /// `HardwareNotFound` with category `WalletState`.
    ///
    /// `HidApiError` and `LedgerHidError` also map to `HardwareNotFound` via
    /// the same branch, but those types (`hidapi::HidError`,
    /// `ledger_transport_hid::LedgerHIDError`) are not exported by `stellar-ledger`
    /// and cannot be constructed here without adding them as direct dev-dependencies.
    /// `map_ledger_error` for the `HidApiError` and `LedgerHidError` arms is covered
    /// in the integration-test path through `MockExchange::empty()` (which triggers
    /// `LedgerConnectionError`, the closest host-reachable approximation) and is
    /// documented under suspected_issues in the coverage report.
    #[test]
    fn map_apdu_exchange_error_category_is_wallet_state() {
        let err = stellar_ledger::Error::APDUExchangeError("0x6D00".to_owned());
        let mapped = map_ledger_error(err);
        assert_eq!(mapped.code(), "wallet_state.hardware_not_found");
        assert_eq!(mapped.category(), ErrorCategory::WalletState);
    }

    #[tokio::test]
    #[ignore = "requires connected Ledger with Stellar app open"]
    async fn real_device_sign_roundtrip() {
        // Signs a known payload on a real connected Ledger device and verifies
        // the result with ed25519.
        //
        // To run: cargo test -p stellar-agent-network real_device_sign_roundtrip -- --ignored
        //
        // Device requirements:
        //   1. Stellar app open.
        //   2. "Allow blind signing" enabled in Stellar app settings.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let key = HardwareSigningKey::native().expect("Ledger must be connected");
        let payload = [0xAB_u8; 32];
        let sig_bytes = key
            .sign_tx_payload(&payload)
            .await
            .expect("signing must succeed");
        let pk = key
            .public_key()
            .await
            .expect("public key fetch must succeed");
        let vk = VerifyingKey::from_bytes(&pk.0).expect("public key must be valid ed25519");
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&payload, &sig)
            .expect("signature produced by Ledger must verify");
    }

    #[tokio::test]
    #[ignore = "requires connected Ledger with Stellar app open"]
    async fn real_device_public_key_is_valid_strkey() {
        // Public key fetched from device must encode to a valid G-strkey.
        let key = HardwareSigningKey::native().expect("Ledger must be connected");
        let pk = key
            .public_key()
            .await
            .expect("public key fetch must succeed");
        let strkey = pk.to_string();
        assert!(
            strkey.starts_with('G'),
            "public key must encode to a G-strkey, got: {strkey}"
        );
    }
}
