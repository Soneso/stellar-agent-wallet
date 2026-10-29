//! The stored form of a profile's owner public key, and the checks that keep
//! it from serving as a symmetric key.
//!
//! `profile enroll-owner-key` stores the owner public key at
//! [`KeyringEntryRef::default_owner_key`] as its G-strkey. A G-strkey decodes
//! as URL-safe base64 to 42 bytes, so no 32-byte symmetric-key loader accepts
//! it. Owner readers accept only the G-strkey. An older base64 entry is refused
//! until the owner public key is enrolled again. Symmetric-key loaders compare
//! both forms.
//!
//! Every symmetric-key loader refuses a coordinate in the owner namespace
//! before any keyring read ([`refuse_owner_key_coordinate`]) and a loaded key
//! equal to the profile's own owner public key
//! ([`refuse_owner_public_key`]).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::error::{ValidationError, WalletError};
use crate::keyring_errors::{KeyringOperation, map_keyring_operation_error};
use crate::profile::name::OWNER_KEY_SERVICE_PREFIX;
use crate::profile::schema::{KeyringEntryRef, Profile};

/// Why an owner entry cannot supply a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnerKeyDecodeError {
    /// The entry holds ambiguous 32-byte URL-safe base64.
    #[error("owner key is in the older base64 form; enroll the owner public key again")]
    OlderForm,
    /// The entry is neither a G-strkey nor the older form.
    #[error("owner key is neither a G-strkey nor the older form")]
    Undecodable,
}

/// Decodes only a G-strkey owner entry.
///
/// # Errors
/// Returns [`OwnerKeyDecodeError::OlderForm`] for 32-byte URL-safe base64,
/// or [`OwnerKeyDecodeError::Undecodable`] for any other value.
pub fn decode_owner_public_key(raw: &str) -> Result<[u8; 32], OwnerKeyDecodeError> {
    let trimmed = raw.trim();
    if let Ok(strkey) = stellar_strkey::ed25519::PublicKey::from_string(trimmed) {
        return Ok(strkey.0);
    }
    let bytes = zeroize::Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(trimmed)
            .map_err(|_| OwnerKeyDecodeError::Undecodable)?,
    );
    if bytes.len() == 32 {
        return Err(OwnerKeyDecodeError::OlderForm);
    }
    Err(OwnerKeyDecodeError::Undecodable)
}

/// Reads either form for symmetric-key comparisons.
fn owner_key_bytes_in_either_form(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if let Ok(strkey) = stellar_strkey::ed25519::PublicKey::from_string(trimmed) {
        return Some(strkey.0);
    }
    let bytes = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.decode(trimmed).ok()?);
    bytes.as_slice().try_into().ok()
}

/// Identifies stored owner bytes without rendering a reversible encoding.
#[must_use]
pub fn owner_key_fingerprint(key: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent-owner-key-fingerprint:v1");
    hash.update(key);
    format!("sha256:{}", crate::hex::encode(&hash.finalize()[..16]))
}

/// Renders the stored form of an owner public key: its G-strkey.
#[must_use]
pub fn encode_owner_public_key(key: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*key)
        .to_string()
        .to_string()
}

/// Refuses a symmetric-key coordinate in the owner key namespace.
///
/// Runs before any keyring read: every real owner entry lives under
/// [`OWNER_KEY_SERVICE_PREFIX`], so a symmetric key never does.
///
/// # Errors
///
/// [`ValidationError::KeyMatchesOwnerPublicKey`] naming `field`.
pub fn refuse_owner_key_coordinate(
    entry_ref: &KeyringEntryRef,
    field: &'static str,
) -> Result<(), WalletError> {
    if entry_ref.service.starts_with(OWNER_KEY_SERVICE_PREFIX) {
        return Err(WalletError::Validation(
            ValidationError::KeyMatchesOwnerPublicKey { field },
        ));
    }
    Ok(())
}

/// Refuses a profile field in the installation's toolset pin-key namespace.
///
/// Callers check this before opening the keyring, on every chain.
/// The service comparison follows the case-insensitive key-scope classifier.
///
/// # Errors
///
/// Returns [`ValidationError::InstallationKeyCoordinate`] naming `field` and
/// the reserved service.
pub fn refuse_installation_key_coordinate(
    entry_ref: &KeyringEntryRef,
    field: &'static str,
) -> Result<(), WalletError> {
    if entry_ref
        .service
        .eq_ignore_ascii_case(super::schema::TOOLSET_PIN_KEY_SERVICE)
    {
        return Err(WalletError::Validation(
            ValidationError::InstallationKeyCoordinate { field },
        ));
    }
    Ok(())
}

/// The owner coordinates a symmetric-key loader compares a loaded key with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyContext {
    coordinates: Vec<KeyringEntryRef>,
}

impl OwnerKeyContext {
    /// The owner coordinates of `profile` selected as `profile_name`:
    /// [`KeyringEntryRef::default_owner_key`] of the name, and
    /// `policy_owner_key_id` when it differs.
    #[must_use]
    pub fn for_profile(profile_name: &str, profile: &Profile) -> Self {
        let mut context = Self::for_profile_name(profile_name);
        if !context.coordinates.contains(&profile.policy_owner_key_id) {
            context
                .coordinates
                .push(profile.policy_owner_key_id.clone());
        }
        context
    }

    /// The owner coordinates of a loader that holds the profile and not the
    /// name it was selected under.
    ///
    /// The name is the one the profile's own owner coordinate names, which
    /// both binaries reconcile with the selected name before any key loads.
    #[must_use]
    pub fn for_loaded_profile(profile: &Profile) -> Self {
        Self::for_profile(
            &crate::profile::name::profile_name_for_approval(profile),
            profile,
        )
    }

    /// The owner coordinate of a loader that holds only the profile name:
    /// [`KeyringEntryRef::default_owner_key`] of the name.
    #[must_use]
    pub fn for_profile_name(profile_name: &str) -> Self {
        Self {
            coordinates: vec![KeyringEntryRef::default_owner_key(profile_name)],
        }
    }

    /// The coordinates compared, in order.
    #[must_use]
    pub fn coordinates(&self) -> &[KeyringEntryRef] {
        &self.coordinates
    }
}

/// Refuses loaded symmetric-key bytes equal to the profile's own owner public
/// key.
///
/// Reads each coordinate of `owner`, decodes the value in either stored form,
/// and compares it with `key` in constant time. An absent owner entry, and a
/// value in neither form, skip the comparison. The error never carries key
/// material.
///
/// # Errors
///
/// - [`ValidationError::KeyMatchesOwnerPublicKey`] naming `field` when `key`
///   equals an owner public key.
/// - The classified keyring error when an owner entry cannot be read for a
///   reason other than its absence.
pub fn refuse_owner_public_key(
    key: &[u8],
    owner: &OwnerKeyContext,
    field: &'static str,
) -> Result<(), WalletError> {
    for coordinate in owner.coordinates() {
        let entry = KeyringEntry::new(&coordinate.service, &coordinate.account).map_err(|e| {
            map_keyring_operation_error(&e, KeyringOperation::Construct, &coordinate.service)
        })?;
        let raw = match entry.get_password() {
            Ok(raw) => zeroize::Zeroizing::new(raw),
            Err(keyring_core::Error::NoEntry) => continue,
            Err(e) => {
                return Err(map_keyring_operation_error(
                    &e,
                    KeyringOperation::Read,
                    &coordinate.service,
                ));
            }
        };
        let Some(owner_key) = owner_key_bytes_in_either_form(&raw) else {
            continue;
        };
        if key.len() == owner_key.len() && bool::from(key.ct_eq(&owner_key)) {
            return Err(WalletError::Validation(
                ValidationError::KeyMatchesOwnerPublicKey { field },
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

    use serial_test::serial;

    use super::*;

    const OWNER: [u8; 32] = [0x5a; 32];

    fn install() {
        let store: std::sync::Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().expect("mock store");
        keyring_core::set_default_store(store);
    }

    fn put(entry_ref: &KeyringEntryRef, value: &str) {
        KeyringEntry::new(&entry_ref.service, &entry_ref.account)
            .unwrap()
            .set_password(value)
            .unwrap();
    }

    fn get(entry_ref: &KeyringEntryRef) -> Option<String> {
        KeyringEntry::new(&entry_ref.service, &entry_ref.account)
            .unwrap()
            .get_password()
            .ok()
    }

    #[test]
    fn only_the_strkey_form_decodes() {
        assert_eq!(
            decode_owner_public_key(&encode_owner_public_key(&OWNER)),
            Ok(OWNER)
        );
        assert_eq!(
            decode_owner_public_key(&URL_SAFE_NO_PAD.encode(OWNER)),
            Err(OwnerKeyDecodeError::OlderForm)
        );
        for raw in [URL_SAFE_NO_PAD.encode([0x5a; 31]), "not a key".to_owned()] {
            assert_eq!(
                decode_owner_public_key(&raw),
                Err(OwnerKeyDecodeError::Undecodable)
            );
        }
    }

    /// The 39-character length excludes every full G-strkey, S-strkey, hex,
    /// and base64 encoding of the 32-byte key.
    #[test]
    fn the_fingerprint_is_one_way_and_domain_separated() {
        let fingerprint = owner_key_fingerprint(&OWNER);
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), 39);
        assert!(
            fingerprint[7..]
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_eq!(fingerprint, owner_key_fingerprint(&OWNER));
        assert_ne!(fingerprint, owner_key_fingerprint(&[0x11; 32]));
        assert_ne!(
            fingerprint[7..],
            crate::hex::encode(&Sha256::digest(OWNER)[..16])
        );
    }

    #[test]
    fn an_owner_namespace_coordinate_is_refused() {
        let err = refuse_owner_key_coordinate(
            &KeyringEntryRef::new("stellar-agent-owner-b", "default"),
            "attestation_key_id",
        )
        .unwrap_err();
        assert_eq!(err.code(), "validation.key_matches_owner_public_key");
        assert!(
            refuse_owner_key_coordinate(
                &KeyringEntryRef::new("stellar-agent-attestation-b", "default"),
                "attestation_key_id",
            )
            .is_ok()
        );
    }

    #[test]
    #[serial]
    fn a_key_equal_to_the_owner_key_is_refused_in_either_form() {
        install();
        let owner = OwnerKeyContext::for_profile_name("owner-compare");
        let coordinate = KeyringEntryRef::default_owner_key("owner-compare");
        assert!(
            refuse_owner_public_key(&OWNER, &owner, "nonce_key").is_ok(),
            "an absent owner entry skips the comparison"
        );
        for stored in [
            URL_SAFE_NO_PAD.encode(OWNER),
            encode_owner_public_key(&OWNER),
        ] {
            put(&coordinate, &stored);
            let err = refuse_owner_public_key(&OWNER, &owner, "nonce_key").unwrap_err();
            assert_eq!(err.code(), "validation.key_matches_owner_public_key");
            assert!(err.to_string().contains("nonce_key"));
            assert!(!err.to_string().contains(&stored), "no key material");
            assert!(refuse_owner_public_key(&[0x11; 32], &owner, "nonce_key").is_ok());
        }
    }

    #[test]
    #[serial]
    fn the_profile_coordinate_is_compared_when_it_differs() {
        install();
        let mut profile = Profile::builder_testnet_named("owner-two", "s", "a", "n", "a").build();
        profile.policy_owner_key_id = KeyringEntryRef::new("stellar-agent-owner-owner-two", "x");
        let owner = OwnerKeyContext::for_profile("owner-two", &profile);
        assert_eq!(owner.coordinates().len(), 2);
        put(&profile.policy_owner_key_id, &URL_SAFE_NO_PAD.encode(OWNER));
        assert!(
            get(&KeyringEntryRef::default_owner_key("owner-two")).is_none(),
            "only the second coordinate holds the key"
        );
        assert!(refuse_owner_public_key(&OWNER, &owner, "attestation_key_id").is_err());
        assert_eq!(
            OwnerKeyContext::for_profile(
                "owner-two",
                &Profile::builder_testnet_named("owner-two", "s", "a", "n", "a").build()
            )
            .coordinates()
            .len(),
            1
        );
    }

    #[test]
    #[serial]
    fn an_owner_read_error_refuses() {
        install();
        let coordinate = KeyringEntryRef::default_owner_key("owner-read-error");
        let entry = KeyringEntry::new(&coordinate.service, &coordinate.account).unwrap();
        let cred = entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .expect("mock credential");
        cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
            std::io::Error::other("planted"),
        )));
        let err = refuse_owner_public_key(
            &OWNER,
            &OwnerKeyContext::for_profile_name("owner-read-error"),
            "nonce_key",
        )
        .unwrap_err();
        assert_ne!(err.code(), "validation.key_matches_owner_public_key");
        assert_eq!(err.category(), crate::error::ErrorCategory::Auth);
    }

    /// The installation namespace is case-insensitive and covers every account.
    #[test]
    fn installation_coordinate_refusal_names_the_field_and_reserved_key() {
        for service in ["stellar-agent-toolsets", "StElLaR-AgEnT-ToOlSeTs"] {
            for account in ["pin-key", "another-account"] {
                let error = refuse_installation_key_coordinate(
                    &KeyringEntryRef::new(service, account),
                    "attestation_key_id",
                )
                .unwrap_err();
                assert_eq!(error.code(), "validation.installation_key_coordinate");
                assert!(error.to_string().contains("attestation_key_id"));
                assert!(
                    error
                        .to_string()
                        .contains("reserved service `stellar-agent-toolsets`")
                );
            }
        }
        refuse_installation_key_coordinate(
            &KeyringEntryRef::default_owner_key("test"),
            "policy_owner_key_id",
        )
        .unwrap();
    }
}
