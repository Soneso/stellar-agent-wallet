//! [`RegistrationInput`] — the byte bundle produced by a WebAuthn registration ceremony.
//!
//! Sibling of [`super::assertion_input::AssertionInput`] (which carries signing
//! ceremony output).  `RegistrationInput` carries the credential data produced
//! when a new passkey is registered: the credential identifier, the public key,
//! an optional attestation blob, and the authenticator transport hints.
//!
//! # Security
//!
//! The `Debug` impl redacts every byte field to its length.  A stray
//! `tracing::debug!(?registration_input)` therefore emits only integer lengths
//! and counts, not raw credential or public-key bytes.

use serde::{Deserialize, Serialize};

use super::error::ApprovalError;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum credential-ID length in bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
pub(crate) const CREDENTIAL_ID_MIN_BYTES: usize = 16;

/// Maximum credential-ID length in bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
pub(crate) const CREDENTIAL_ID_MAX_BYTES: usize = 64;

/// Expected length of an uncompressed SEC1 P-256 public key in bytes.
///
/// Encoding: `0x04 || X (32 bytes) || Y (32 bytes)` per ANSI X9.62 / SEC1
/// §2.3.3. The OZ `__check_auth` webauthn-verifier accepts exactly this form.
/// The constant is `pub(crate)` so the validator and the test surface share a
/// single source.
///
/// Serde's built-in array support only covers `[T; 0..=32]`, so the field is
/// stored as `Vec<u8>` and length-checked at construction + deserialisation.
pub(crate) const PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN: usize = 65;

/// Maximum number of CTAP transport strings per credential record.
pub(crate) const TRANSPORTS_MAX_COUNT: usize = 4;

/// Valid CTAP2 transport strings per W3C WebAuthn Level 2 §5.4.4.
pub(crate) const VALID_TRANSPORTS: &[&str] = &["usb", "internal", "ble", "nfc", "hybrid"];

// ─────────────────────────────────────────────────────────────────────────────
// RegistrationInput
// ─────────────────────────────────────────────────────────────────────────────

/// Bytes produced by a successful WebAuthn registration ceremony, consumed by
/// the passkey-registration flow wired at `ApprovalKind::RegisterPasskey`.
///
/// The bridge crate populates this from a browser-driven ceremony and writes
/// it into the approval store as part of `ApprovalKind::RegisterPasskey`.
/// The registration manager reads it back and stores the public key on-chain
/// in the Stellar smart account.
///
/// # Fields
///
/// - `credential_id`: the credential identifier returned by the platform
///   authenticator, confirming which stored credential was created.
///   Must be 16–64 bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
/// - `public_key_uncompressed_sec1`: uncompressed SEC1 P-256 public key,
///   stored as `Vec<u8>` (serde arrays only support up to `[T; 32]`).
///   Must be exactly 65 bytes with `[0] == 0x04`.
/// - `attestation_blob_b64`: optional base64-encoded CBOR attestation object.
///   When `Some`, must contain only valid base64 characters.
/// - `transports`: list of authenticator transport hints per W3C WebAuthn
///   Level 2 §5.4.4.  At most 4 entries; each must be one of
///   `"usb" | "internal" | "ble" | "nfc" | "hybrid"`.
///
/// # Security
///
/// `public_key_uncompressed_sec1` and `credential_id` MUST NOT be interpolated
/// into any `tracing::*!` macro.  The `Debug` impl below redacts to
/// length-only.  Any caller that logs a `RegistrationInput` value will see
/// only field-length integers and counts in the output.
///
/// # Serialisation
///
/// `Serialize` / `Deserialize` are derived so the approval store can persist a
/// `RegisterPasskey` entry with `registration_input: Some(RegistrationInput)` to
/// TOML.  Byte fields use serde's default `Vec<u8>` TOML representation
/// (array of integers).
///
/// # Future fields
///
/// `#[non_exhaustive]` permits adding future WebAuthn registration fields
/// (e.g. `user_id`, `backup_eligible`) without breaking downstream
/// struct-literal construction sites.
///
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegistrationInput {
    /// The credential identifier returned by the authenticator.  Typically
    /// 16–64 bytes (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
    ///
    /// Security: MUST NOT be interpolated into tracing events.
    pub credential_id: Vec<u8>,

    /// Uncompressed SEC1 P-256 public key: `0x04 || X (32 bytes) || Y (32 bytes)`.
    ///
    /// Stored as `Vec<u8>` (exactly 65 bytes) because serde's built-in const-
    /// array support only covers `[T; 0..=32]`.  Validated at construction time
    /// and on deserialisation: must be exactly 65 bytes with `[0] == 0x04`.
    ///
    /// The on-chain OZ webauthn-verifier expects the uncompressed form.
    ///
    /// Security: MUST NOT be interpolated into tracing events.
    pub public_key_uncompressed_sec1: Vec<u8>,

    /// Optional CBOR attestation object, base64-encoded.
    ///
    /// `None` when attestation is not requested or not supported by the
    /// authenticator.  When `Some`, must contain only valid base64 characters.
    pub attestation_blob_b64: Option<String>,

    /// CTAP2 transport hints per W3C WebAuthn Level 2 §5.4.4.
    ///
    /// At most 4 entries; each must be one of
    /// `"usb" | "internal" | "ble" | "nfc" | "hybrid"`.
    /// May be empty (`[]`) when the authenticator does not report transports.
    pub transports: Vec<String>,
}

impl RegistrationInput {
    /// Constructs a `RegistrationInput` from the four fields produced by the
    /// browser-handoff bridge after a successful WebAuthn registration ceremony.
    ///
    /// # Validation
    ///
    /// - `credential_id.len()` must be in `[16, 64]` (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
    /// - `public_key_uncompressed_sec1.len()` must be exactly 65 bytes and
    ///   `public_key_uncompressed_sec1[0]` must be `0x04` (uncompressed SEC1 marker).
    /// - `transports.len()` must be `≤ 4`.
    /// - Each transport string must be one of `"usb" | "internal" | "ble" | "nfc" | "hybrid"`.
    /// - `attestation_blob_b64`: when `Some`, must contain only characters
    ///   from the standard base64 alphabet `[A-Za-z0-9+/=]` per RFC 4648 §4.
    ///   The browser-facing bridge handler normalises any URL-safe input from
    ///   the WebAuthn client to standard before constructing the
    ///   `RegistrationInput`; structural CBOR validity is verified at
    ///   ceremony-completion time by the OZ `__check_auth` verifier.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalError::Invalid`] if any validation check fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::approval::RegistrationInput;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::ApprovalError> {
    /// let mut pubkey = vec![0u8; 65];
    /// pubkey[0] = 0x04;
    /// let input = RegistrationInput::new(
    ///     vec![0u8; 32],
    ///     pubkey,
    ///     None,
    ///     vec!["internal".to_owned()],
    /// )?;
    /// assert_eq!(input.credential_id().len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        credential_id: Vec<u8>,
        public_key_uncompressed_sec1: Vec<u8>,
        attestation_blob_b64: Option<String>,
        transports: Vec<String>,
    ) -> Result<Self, ApprovalError> {
        validate_registration_input_invariants(
            &credential_id,
            &public_key_uncompressed_sec1,
            attestation_blob_b64.as_deref(),
            &transports,
        )
        .map_err(|reason| ApprovalError::Invalid { reason })?;

        Ok(Self {
            credential_id,
            public_key_uncompressed_sec1,
            attestation_blob_b64,
            transports,
        })
    }

    /// Returns the credential identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::approval::RegistrationInput;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::ApprovalError> {
    /// let mut pubkey = vec![0u8; 65];
    /// pubkey[0] = 0x04;
    /// let input = RegistrationInput::new(vec![0u8; 32], pubkey, None, vec![])?;
    /// assert_eq!(input.credential_id().len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Returns the uncompressed SEC1 P-256 public key (exactly 65 bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::approval::RegistrationInput;
    ///
    /// # fn example() -> Result<(), stellar_agent_core::approval::ApprovalError> {
    /// let mut pubkey = vec![0u8; 65];
    /// pubkey[0] = 0x04;
    /// let input = RegistrationInput::new(vec![0u8; 32], pubkey, None, vec![])?;
    /// assert_eq!(input.public_key_uncompressed_sec1()[0], 0x04);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn public_key_uncompressed_sec1(&self) -> &[u8] {
        &self.public_key_uncompressed_sec1
    }

    /// Returns the optional base64-encoded CBOR attestation object.
    #[must_use]
    pub fn attestation_blob_b64(&self) -> Option<&str> {
        self.attestation_blob_b64.as_deref()
    }

    /// Returns the list of CTAP2 transport hints.
    #[must_use]
    pub fn transports(&self) -> &[String] {
        &self.transports
    }
}

impl std::fmt::Debug for RegistrationInput {
    /// Redacted `Debug` impl: shows byte-length fields and counts only.
    ///
    /// A stray `tracing::debug!(?registration_input)` would otherwise emit the
    /// full byte arrays (no credential / public-key bytes in tracing events).
    /// Field lengths are sufficient for operator diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationInput")
            .field("credential_id_len", &self.credential_id.len())
            .field(
                "public_key_uncompressed_sec1_len",
                &self.public_key_uncompressed_sec1.len(),
            )
            .field(
                "attestation_blob_b64_len",
                &self.attestation_blob_b64.as_ref().map(|s| s.len()),
            )
            .field("transports_count", &self.transports.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Invariant validator (shared by ctor + Deserialize path in store.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Runs all `RegistrationInput` field invariants and returns the first failing
/// reason.
///
/// Invoked from both `RegistrationInput::new` and the custom
/// `Deserialize<PendingApproval>` impl for `RegisterPasskey` entries, so
/// construction-time defences also apply to on-disk reload.
pub(crate) fn validate_registration_input_invariants(
    credential_id: &[u8],
    public_key_uncompressed_sec1: &[u8],
    attestation_blob_b64: Option<&str>,
    transports: &[String],
) -> Result<(), String> {
    // credential_id length (CTAP2 §4.2 / WebAuthn-2 §5.4.7).
    if credential_id.len() < CREDENTIAL_ID_MIN_BYTES
        || credential_id.len() > CREDENTIAL_ID_MAX_BYTES
    {
        return Err(format!(
            "credential_id must be {CREDENTIAL_ID_MIN_BYTES}–{CREDENTIAL_ID_MAX_BYTES} bytes \
             (CTAP2 §4.2 / WebAuthn-2 §5.4.7), got {} bytes",
            credential_id.len()
        ));
    }

    // Public key: must be exactly PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN bytes.
    if public_key_uncompressed_sec1.len() != PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN {
        return Err(format!(
            "public_key_uncompressed_sec1 must be exactly {PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN} bytes \
             (uncompressed SEC1 P-256: 0x04 || X || Y), got {} bytes",
            public_key_uncompressed_sec1.len()
        ));
    }

    // First byte must be 0x04 (uncompressed SEC1 marker).
    if public_key_uncompressed_sec1[0] != 0x04 {
        return Err(format!(
            "public_key_uncompressed_sec1[0] must be 0x04 (uncompressed SEC1 P-256 marker), \
             got 0x{:02x}",
            public_key_uncompressed_sec1[0]
        ));
    }

    // transports: at most TRANSPORTS_MAX_COUNT entries, each a known string.
    if transports.len() > TRANSPORTS_MAX_COUNT {
        return Err(format!(
            "transports must have at most {TRANSPORTS_MAX_COUNT} entries \
             (CTAP2 transport hints), got {}",
            transports.len()
        ));
    }
    for t in transports {
        if !VALID_TRANSPORTS.contains(&t.as_str()) {
            return Err(format!(
                "transport {t:?} is not a valid CTAP2 transport \
                 (must be one of {VALID_TRANSPORTS:?})"
            ));
        }
    }

    // attestation_blob_b64: when present, must contain only characters from
    // the STANDARD base64 alphabet (RFC 4648 §4). URL-safe variants `_-` are
    // rejected to prevent mixed-alphabet inputs that would parse-fail later;
    // the bridge POST handler normalises any URL-safe input from the browser
    // to standard at receive time. This is a character-set check only;
    // structural CBOR validity is verified at ceremony-completion time by the
    // OZ `__check_auth` verifier.
    if let Some(blob) = attestation_blob_b64
        && !blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return Err(
            "attestation_blob_b64 contains characters outside the standard \
             base64 alphabet ([A-Za-z0-9+/=]) per RFC 4648 §4"
                .to_owned(),
        );
    }

    Ok(())
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

    fn valid_pubkey() -> Vec<u8> {
        let mut k = vec![0u8; 65];
        k[0] = 0x04;
        k
    }

    fn valid_credential_id() -> Vec<u8> {
        vec![0xABu8; 32]
    }

    // 1. Happy path ─────────────────────────────────────────────────────────

    #[test]
    fn new_happy_path() {
        let input = RegistrationInput::new(
            valid_credential_id(),
            valid_pubkey(),
            None,
            vec!["internal".to_owned()],
        )
        .unwrap();
        assert_eq!(input.credential_id().len(), 32);
        assert_eq!(input.public_key_uncompressed_sec1()[0], 0x04);
        assert_eq!(input.public_key_uncompressed_sec1().len(), 65);
        assert!(input.attestation_blob_b64().is_none());
        assert_eq!(input.transports().len(), 1);
    }

    // 2. credential_id length boundary ─────────────────────────────────────

    #[test]
    fn new_rejects_credential_id_len_15() {
        let err = RegistrationInput::new(
            vec![0u8; 15], // one byte below minimum
            valid_pubkey(),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "15-byte credential_id must be rejected: {err:?}"
        );
    }

    #[test]
    fn new_rejects_credential_id_len_65() {
        let err = RegistrationInput::new(
            vec![0u8; 65], // one byte above maximum
            valid_pubkey(),
            None,
            vec![],
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "65-byte credential_id must be rejected: {err:?}"
        );
    }

    #[test]
    fn new_accepts_credential_id_len_16() {
        RegistrationInput::new(vec![0u8; 16], valid_pubkey(), None, vec![]).unwrap();
    }

    #[test]
    fn new_accepts_credential_id_len_64() {
        RegistrationInput::new(vec![0u8; 64], valid_pubkey(), None, vec![]).unwrap();
    }

    // 3. Public key: first byte != 0x04 ────────────────────────────────────

    #[test]
    fn new_rejects_pubkey_first_byte_not_04() {
        let mut bad_key = valid_pubkey();
        bad_key[0] = 0x02; // compressed form marker
        let err = RegistrationInput::new(valid_credential_id(), bad_key, None, vec![]).unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "pubkey[0] != 0x04 must be rejected: {err:?}"
        );
    }

    #[test]
    fn new_rejects_pubkey_wrong_length() {
        let short_key = vec![0x04u8; 64]; // 64 bytes, not 65
        let err =
            RegistrationInput::new(valid_credential_id(), short_key, None, vec![]).unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "64-byte pubkey must be rejected: {err:?}"
        );
    }

    // 4. transports.len() > 4 ──────────────────────────────────────────────

    #[test]
    fn new_rejects_transports_len_5() {
        let err = RegistrationInput::new(
            valid_credential_id(),
            valid_pubkey(),
            None,
            vec![
                "usb".to_owned(),
                "internal".to_owned(),
                "ble".to_owned(),
                "nfc".to_owned(),
                "hybrid".to_owned(), // 5th entry
            ],
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "5 transports must be rejected: {err:?}"
        );
    }

    // 5. Unknown transport string ───────────────────────────────────────────

    #[test]
    fn new_rejects_unknown_transport_string() {
        let err = RegistrationInput::new(
            valid_credential_id(),
            valid_pubkey(),
            None,
            vec!["wifi".to_owned()], // not in VALID_TRANSPORTS
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Invalid { .. }),
            "unknown transport must be rejected: {err:?}"
        );
    }

    #[test]
    fn new_accepts_all_four_valid_transports() {
        RegistrationInput::new(
            valid_credential_id(),
            valid_pubkey(),
            None,
            vec![
                "usb".to_owned(),
                "internal".to_owned(),
                "ble".to_owned(),
                "nfc".to_owned(),
            ],
        )
        .unwrap();
    }

    // 6. Debug is redacted ─────────────────────────────────────────────────

    #[test]
    fn debug_is_redacted_length_only() {
        let input = RegistrationInput::new(
            vec![0xABu8; 32],
            {
                let mut k = vec![0u8; 65];
                k[0] = 0x04;
                k.iter_mut().skip(1).for_each(|b| *b = 0xCD);
                k
            },
            Some("dGVzdA==".to_owned()),
            vec!["internal".to_owned()],
        )
        .unwrap();

        let debug_str = format!("{input:?}");

        // Length fields must appear.
        assert!(
            debug_str.contains("credential_id_len: 32"),
            "credential_id_len must appear: {debug_str}"
        );
        assert!(
            debug_str.contains("public_key_uncompressed_sec1_len: 65"),
            "public_key_len must appear: {debug_str}"
        );
        assert!(
            debug_str.contains("transports_count: 1"),
            "transports_count must appear: {debug_str}"
        );

        // Raw bytes must NOT appear.
        assert!(
            !debug_str.contains("credential_id: ["),
            "raw credential_id bytes must not appear: {debug_str}"
        );
        assert!(
            !debug_str.contains("public_key_uncompressed_sec1: ["),
            "raw public key bytes must not appear: {debug_str}"
        );
        // 0xAB = 171 decimal; must not appear as numeric in arrays.
        assert!(
            !debug_str.contains("171,"),
            "raw credential byte 0xAB must not appear: {debug_str}"
        );
    }

    // Serde round-trip ─────────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip_toml() {
        let input = RegistrationInput::new(
            vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            {
                let mut k = vec![0u8; 65];
                k[0] = 0x04;
                k
            },
            Some("dGVzdA==".to_owned()),
            vec!["usb".to_owned()],
        )
        .unwrap();

        let serialised = toml::to_string(&input).expect("serialise");
        let deserialised: RegistrationInput = toml::from_str(&serialised).expect("deserialise");

        assert_eq!(input.credential_id, deserialised.credential_id);
        assert_eq!(
            input.public_key_uncompressed_sec1,
            deserialised.public_key_uncompressed_sec1
        );
        assert_eq!(
            input.attestation_blob_b64,
            deserialised.attestation_blob_b64
        );
        assert_eq!(input.transports, deserialised.transports);
    }
}
