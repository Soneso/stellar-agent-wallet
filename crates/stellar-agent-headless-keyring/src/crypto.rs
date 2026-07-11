//! Protection-mode seal/open primitives.
//!
//! Two independent protection modes, selected once at store construction and
//! held for the store's lifetime — never mixed within one file:
//!
//! - [`ProtectionMode::EnvKey`] — XChaCha20-Poly1305 AEAD with a 32-byte key
//!   supplied by the operator via environment variable. The env var is the
//!   root of trust: anyone who can read it can decrypt every entry. Works on
//!   every platform; the intended target is Linux services and CI.
//! - [`ProtectionMode::Dpapi`] (Windows only) — `CryptProtectData` /
//!   `CryptUnprotectData`, CurrentUser scope, via
//!   `stellar_agent_windows_identity::dpapi_protect` /
//!   `dpapi_unprotect`. Any process running as the same Windows user can
//!   decrypt the result — the SAME trust boundary as Windows Credential
//!   Manager, minus the interactive-logon-session requirement DPAPI
//!   CurrentUser scope does not have.
//!
//! Both modes are tamper-evident: [`open`] returns [`CryptoError::SealFailed`]
//! for a corrupted or tampered ciphertext rather than silently returning
//! altered plaintext. XChaCha20-Poly1305 carries its own Poly1305 tag; DPAPI
//! blobs are self-authenticating (`CryptUnprotectData` fails on a modified
//! blob).

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 nonce length in bytes.
pub(crate) const NONCE_LEN: usize = 24;

/// Errors from the seal/open primitives.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Encryption or decryption failed. For `open`, this is the fail-closed
    /// outcome for a corrupted or tampered ciphertext — deliberately carries
    /// no further detail (an AEAD/DPAPI failure reason is not
    /// operator-actionable and must never hint at how close an attacker's
    /// forgery came).
    #[error("seal/open operation failed (corrupt or tampered data, or a key mismatch)")]
    SealFailed,
    /// [`ProtectionMode::Dpapi`] was selected on a non-Windows target.
    #[error("DPAPI protection mode is only available on Windows")]
    DpapiUnsupportedPlatform,
    /// The `env-key` protection mode's environment variable was missing,
    /// not valid base64, or did not decode to exactly 32 bytes.
    #[error("headless keyring env-key: {0}")]
    InvalidEnvKey(&'static str),
}

/// Selected protection mode, held for a [`crate::store::HeadlessStore`]'s
/// lifetime.
#[derive(Clone)]
pub enum ProtectionMode {
    /// XChaCha20-Poly1305 with a 32-byte key from an operator-supplied
    /// environment variable. Shared (`Arc`) rather than duplicated per
    /// credential instance; still `Zeroizing` so the key is wiped when the
    /// last reference drops.
    EnvKey(Arc<Zeroizing<[u8; 32]>>),
    /// DPAPI CurrentUser scope. Windows-only; selecting this on any other
    /// target fails every seal/open call with
    /// [`CryptoError::DpapiUnsupportedPlatform`].
    Dpapi,
}

impl std::fmt::Debug for ProtectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvKey(_) => write!(f, "ProtectionMode::EnvKey(<redacted>)"),
            Self::Dpapi => write!(f, "ProtectionMode::Dpapi"),
        }
    }
}

impl ProtectionMode {
    /// The backend-kind label recorded in the wire file and emitted on the
    /// tracing log line — never the key material.
    #[must_use]
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::EnvKey(_) => "headless-env",
            Self::Dpapi => "headless-dpapi",
        }
    }
}

/// A sealed (encrypted + authenticated) entry value.
pub(crate) struct Sealed {
    /// Present for [`ProtectionMode::EnvKey`] (the AEAD nonce); `None` for
    /// [`ProtectionMode::Dpapi`] (DPAPI manages its own IV internally).
    pub nonce: Option<[u8; NONCE_LEN]>,
    pub ciphertext: Vec<u8>,
}

/// Seals `plaintext` under `mode`. `aad` (associated authenticated data —
/// the `service`/`account` coordinate) is bound into the XChaCha20-Poly1305
/// tag for [`ProtectionMode::EnvKey`] so a ciphertext cannot be silently
/// relocated to a different entry; DPAPI has no AAD concept, so `aad` is
/// unused for [`ProtectionMode::Dpapi`] (documented scope limitation — same
/// trust boundary as Windows Credential Manager, which has none either).
pub(crate) fn seal(
    mode: &ProtectionMode,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, CryptoError> {
    match mode {
        ProtectionMode::EnvKey(key) => {
            // Borrow the key straight from its zeroizing buffer: an owned
            // [u8; 32] copy would be dropped un-wiped on every call.
            let cipher = XChaCha20Poly1305::new((&***key).into());
            let mut nonce_bytes = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = XNonce::from(nonce_bytes);
            let ciphertext = cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::SealFailed)?;
            Ok(Sealed {
                nonce: Some(nonce_bytes),
                ciphertext,
            })
        }
        ProtectionMode::Dpapi => dpapi_seal(plaintext),
    }
}

/// Opens a value sealed by [`seal`]. See [`seal`]'s docs for the `aad`
/// binding.
///
/// # Errors
///
/// Returns [`CryptoError::SealFailed`] for a corrupted/tampered ciphertext, a
/// key mismatch, or a missing nonce on the `env-key` path.
pub(crate) fn open(
    mode: &ProtectionMode,
    aad: &[u8],
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match mode {
        ProtectionMode::EnvKey(key) => {
            let nonce_bytes = sealed.nonce.ok_or(CryptoError::SealFailed)?;
            // Borrow the key straight from its zeroizing buffer: an owned
            // [u8; 32] copy would be dropped un-wiped on every call.
            let cipher = XChaCha20Poly1305::new((&***key).into());
            let nonce = XNonce::from(nonce_bytes);
            let plaintext = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &sealed.ciphertext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::SealFailed)?;
            Ok(Zeroizing::new(plaintext))
        }
        ProtectionMode::Dpapi => dpapi_open(&sealed.ciphertext),
    }
}

#[cfg(target_os = "windows")]
fn dpapi_seal(plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    let ciphertext = stellar_agent_windows_identity::dpapi_protect(plaintext)
        .map_err(|_| CryptoError::SealFailed)?;
    Ok(Sealed {
        nonce: None,
        ciphertext,
    })
}

#[cfg(not(target_os = "windows"))]
fn dpapi_seal(_plaintext: &[u8]) -> Result<Sealed, CryptoError> {
    Err(CryptoError::DpapiUnsupportedPlatform)
}

#[cfg(target_os = "windows")]
fn dpapi_open(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    stellar_agent_windows_identity::dpapi_unprotect(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::SealFailed)
}

#[cfg(not(target_os = "windows"))]
fn dpapi_open(_ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    Err(CryptoError::DpapiUnsupportedPlatform)
}

/// Parses the `env-key` protection mode's 32-byte key from `raw` (expected:
/// URL-safe base64, no padding — the same encoding convention every other
/// 32-byte secret in this codebase uses, e.g.
/// `stellar_agent_network::keyring::rotate_keyring_secret_32`).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidEnvKey`] if `raw` is not valid base64 or
/// does not decode to exactly 32 bytes.
pub(crate) fn parse_env_key(raw: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(raw.trim())
            .map_err(|_| CryptoError::InvalidEnvKey("value is not valid URL-safe base64"))?,
    );
    if decoded.len() != 32 {
        return Err(CryptoError::InvalidEnvKey(
            "decoded value must be exactly 32 bytes",
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
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

    fn env_key_mode() -> ProtectionMode {
        ProtectionMode::EnvKey(Arc::new(Zeroizing::new([0x42u8; 32])))
    }

    #[test]
    fn env_key_seal_open_round_trips() {
        let mode = env_key_mode();
        let aad = b"svc\x00acct";
        let plaintext = b"top secret owner seed material";
        let sealed = seal(&mode, aad, plaintext).expect("seal");
        assert_ne!(
            sealed.ciphertext, plaintext,
            "ciphertext must not equal plaintext"
        );
        let opened = open(&mode, aad, &sealed).expect("open");
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn env_key_open_rejects_tampered_ciphertext() {
        let mode = env_key_mode();
        let aad = b"svc\x00acct";
        let mut sealed = seal(&mode, aad, b"payload").expect("seal");
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0xFF;
        assert!(matches!(
            open(&mode, aad, &sealed),
            Err(CryptoError::SealFailed)
        ));
    }

    #[test]
    fn env_key_open_rejects_mismatched_aad() {
        let mode = env_key_mode();
        let sealed = seal(&mode, b"svc\x00acct-a", b"payload").expect("seal");
        assert!(
            matches!(
                open(&mode, b"svc\x00acct-b", &sealed),
                Err(CryptoError::SealFailed)
            ),
            "a ciphertext relocated to a different entry coordinate must fail to open"
        );
    }

    #[test]
    fn env_key_open_rejects_wrong_key() {
        let sealed = seal(&env_key_mode(), b"aad", b"payload").expect("seal");
        let other_mode = ProtectionMode::EnvKey(Arc::new(Zeroizing::new([0x99u8; 32])));
        assert!(matches!(
            open(&other_mode, b"aad", &sealed),
            Err(CryptoError::SealFailed)
        ));
    }

    #[test]
    fn env_key_open_rejects_missing_nonce() {
        let mode = env_key_mode();
        let sealed = Sealed {
            nonce: None,
            ciphertext: vec![1, 2, 3],
        };
        assert!(matches!(
            open(&mode, b"aad", &sealed),
            Err(CryptoError::SealFailed)
        ));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn dpapi_mode_fails_closed_on_non_windows() {
        assert!(matches!(
            seal(&ProtectionMode::Dpapi, b"aad", b"x"),
            Err(CryptoError::DpapiUnsupportedPlatform)
        ));
        let sealed = Sealed {
            nonce: None,
            ciphertext: vec![1, 2, 3],
        };
        assert!(matches!(
            open(&ProtectionMode::Dpapi, b"aad", &sealed),
            Err(CryptoError::DpapiUnsupportedPlatform)
        ));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn dpapi_mode_round_trips() {
        let mode = ProtectionMode::Dpapi;
        let plaintext = b"headless keyring DPAPI mode round-trip";
        let sealed = seal(&mode, b"unused-aad", plaintext).expect("seal");
        assert!(sealed.nonce.is_none());
        let opened = open(&mode, b"unused-aad", &sealed).expect("open");
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn parse_env_key_accepts_32_bytes() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let encoded = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        let key = parse_env_key(&encoded).expect("valid key");
        assert_eq!(key.as_ref(), &[0x11u8; 32]);
    }

    #[test]
    fn parse_env_key_rejects_wrong_length() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let encoded = URL_SAFE_NO_PAD.encode([0x11u8; 16]);
        assert!(matches!(
            parse_env_key(&encoded),
            Err(CryptoError::InvalidEnvKey(_))
        ));
    }

    #[test]
    fn parse_env_key_rejects_invalid_base64() {
        assert!(matches!(
            parse_env_key("not valid base64!!"),
            Err(CryptoError::InvalidEnvKey(_))
        ));
    }
}
