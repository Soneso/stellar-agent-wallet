//! The stored form of a profile's owner public key, and the checks that keep
//! it from serving as a symmetric key.
//!
//! `profile enroll-owner-key` stores the owner public key at
//! [`KeyringEntryRef::default_owner_key`] as its G-strkey. A G-strkey decodes
//! as URL-safe base64 to 42 bytes, so no 32-byte symmetric-key loader accepts
//! it. Entries written in the older form, URL-safe base64 of the 32 key bytes,
//! are read by every owner reader and rewritten as the G-strkey, best effort.
//!
//! Every symmetric-key loader refuses a coordinate in the owner namespace
//! before any keyring read ([`refuse_owner_key_coordinate`]) and a loaded key
//! equal to the profile's own owner public key
//! ([`refuse_owner_public_key`]). Under `headless-dpapi` an owner entry still
//! in the older form can be moved to another coordinate until a V1 verb or
//! `enroll-owner-key` rewrites it.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use subtle::ConstantTimeEq as _;

use crate::error::{ValidationError, WalletError};
use crate::keyring_errors::{KeyringOperation, map_keyring_operation_error};
use crate::profile::name::OWNER_KEY_SERVICE_PREFIX;
use crate::profile::schema::{KeyringEntryRef, Profile};

/// The form an owner entry's value is stored in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerKeyForm {
    /// The G-strkey `enroll-owner-key` writes.
    Strkey,
    /// URL-safe base64 of the 32 key bytes, the older form.
    OlderBase64,
}

/// Decodes an owner entry value in either stored form.
///
/// Returns `None` for a value that is neither a G-strkey nor URL-safe base64
/// of exactly 32 bytes.
#[must_use]
pub fn decode_owner_public_key(raw: &str) -> Option<([u8; 32], OwnerKeyForm)> {
    let trimmed = raw.trim();
    if let Ok(strkey) = stellar_strkey::ed25519::PublicKey::from_string(trimmed) {
        return Some((strkey.0, OwnerKeyForm::Strkey));
    }
    let bytes = URL_SAFE_NO_PAD.decode(trimmed).ok()?;
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some((key, OwnerKeyForm::OlderBase64))
}

/// Renders the stored form of an owner public key: its G-strkey.
#[must_use]
pub fn encode_owner_public_key(key: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*key)
        .to_string()
        .to_string()
}

/// What [`rewrite_older_form_owner_entry`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerEntryRewrite {
    /// The entry is already a G-strkey; nothing was written.
    AlreadyStrkey,
    /// The older-form entry was rewritten as its G-strkey.
    Rewritten,
    /// No entry exists at the coordinate.
    Absent,
    /// The value is in neither form; nothing was written.
    Undecodable,
    /// The entry could not be read; carries the keyring code.
    Unreadable {
        /// The wire code of the classified keyring error.
        code: &'static str,
    },
    /// The rewrite failed; carries the keyring code. The entry keeps its older
    /// form and the next attempt retries.
    WriteFailed {
        /// The wire code of the classified keyring error.
        code: &'static str,
    },
}

/// Rewrites an older-form owner entry as its G-strkey, best effort.
///
/// A G-strkey entry, an absent entry, and a value in neither form are left
/// as they are. Never fails: every outcome is reported in the return value,
/// and the caller decides how to log it. The value is never logged.
#[must_use]
pub fn rewrite_older_form_owner_entry(entry_ref: &KeyringEntryRef) -> OwnerEntryRewrite {
    let entry = match KeyringEntry::new(&entry_ref.service, &entry_ref.account) {
        Ok(entry) => entry,
        Err(e) => {
            return OwnerEntryRewrite::Unreadable {
                code: map_keyring_operation_error(
                    &e,
                    KeyringOperation::Construct,
                    &entry_ref.service,
                )
                .code(),
            };
        }
    };
    let raw = match entry.get_password() {
        Ok(raw) => zeroize::Zeroizing::new(raw),
        Err(keyring_core::Error::NoEntry) => return OwnerEntryRewrite::Absent,
        Err(e) => {
            return OwnerEntryRewrite::Unreadable {
                code: map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
                    .code(),
            };
        }
    };
    rewrite_value(&entry, &entry_ref.service, &raw)
}

/// Rewrites an owner entry the caller already read, so an owner reader does
/// not read the entry twice.
#[must_use]
pub fn rewrite_owner_value_if_older(entry_ref: &KeyringEntryRef, raw: &str) -> OwnerEntryRewrite {
    match KeyringEntry::new(&entry_ref.service, &entry_ref.account) {
        Ok(entry) => rewrite_value(&entry, &entry_ref.service, raw),
        Err(e) => OwnerEntryRewrite::WriteFailed {
            code: map_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service)
                .code(),
        },
    }
}

fn rewrite_value(entry: &KeyringEntry, service: &str, raw: &str) -> OwnerEntryRewrite {
    match decode_owner_public_key(raw) {
        None => OwnerEntryRewrite::Undecodable,
        Some((_, OwnerKeyForm::Strkey)) => OwnerEntryRewrite::AlreadyStrkey,
        Some((key, OwnerKeyForm::OlderBase64)) => {
            match entry.set_password(&encode_owner_public_key(&key)) {
                Ok(()) => OwnerEntryRewrite::Rewritten,
                Err(e) => OwnerEntryRewrite::WriteFailed {
                    code: map_keyring_operation_error(&e, KeyringOperation::Write, service).code(),
                },
            }
        }
    }
}

/// Logs an owner-entry rewrite outcome at `warn` when it needs attention.
///
/// A failed or skipped rewrite is logged with the keyring code and the
/// profile name, never the value. The other outcomes are silent.
pub fn log_owner_entry_rewrite(profile_name: &str, outcome: &OwnerEntryRewrite) {
    match outcome {
        OwnerEntryRewrite::WriteFailed { code } => tracing::warn!(
            profile = %profile_name,
            code = %code,
            "owner key entry kept its older form; the rewrite as a G-strkey failed and the next \
             engine build retries"
        ),
        OwnerEntryRewrite::Unreadable { code } => tracing::warn!(
            profile = %profile_name,
            code = %code,
            "owner key entry could not be read; its rewrite as a G-strkey was skipped"
        ),
        OwnerEntryRewrite::Absent => tracing::warn!(
            profile = %profile_name,
            "no owner key entry; its rewrite as a G-strkey was skipped"
        ),
        OwnerEntryRewrite::Undecodable => tracing::warn!(
            profile = %profile_name,
            "owner key entry is in neither stored form; its rewrite was skipped"
        ),
        OwnerEntryRewrite::AlreadyStrkey | OwnerEntryRewrite::Rewritten => {}
    }
}

/// Rewrites the older-form owner entry of every profile in `profile_dir`
/// except `skip`, best effort.
///
/// Reads [`KeyringEntryRef::default_owner_key`] of each profile listed by
/// [`crate::profile::loader::list_profiles_in_dir`]. A missing or unreadable
/// entry is skipped with a `warn`, and nothing here fails the caller.
pub fn rewrite_older_form_owner_entries_in_dir(profile_dir: &Path, skip: Option<&str>) {
    let names = match crate::profile::loader::list_profiles_in_dir(profile_dir) {
        Ok(names) => names,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "owner key rewrite: the profile directory could not be listed; skipped"
            );
            return;
        }
    };
    for name in names.iter().filter(|name| Some(name.as_str()) != skip) {
        let outcome = rewrite_older_form_owner_entry(&KeyringEntryRef::default_owner_key(name));
        log_owner_entry_rewrite(name, &outcome);
    }
}

/// Runs [`rewrite_older_form_owner_entries_in_dir`] over the default profile
/// directory once per process.
///
/// The first V1 engine build in a process calls this; later builds return at
/// once. A directory that cannot be resolved is skipped with a `warn`.
pub fn rewrite_older_form_owner_entries_once(skip: Option<&str>) {
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| match crate::profile::schema::default_profile_dir() {
        Ok(dir) => rewrite_older_form_owner_entries_in_dir(&dir, skip),
        Err(e) => tracing::warn!(
            error = %e,
            "owner key rewrite: no profile directory; skipped"
        ),
    });
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
        let Some((owner_key, _)) = decode_owner_public_key(&raw) else {
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
    fn both_forms_decode_to_the_same_key() {
        let strkey = encode_owner_public_key(&OWNER);
        assert!(strkey.starts_with('G'));
        assert_eq!(
            decode_owner_public_key(&strkey),
            Some((OWNER, OwnerKeyForm::Strkey))
        );
        assert_eq!(
            decode_owner_public_key(&URL_SAFE_NO_PAD.encode(OWNER)),
            Some((OWNER, OwnerKeyForm::OlderBase64))
        );
        assert_eq!(decode_owner_public_key("not a key"), None);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&strkey).map(|b| b.len()).ok(),
            Some(42),
            "a G-strkey decodes as URL-safe base64 to 42 bytes"
        );
    }

    #[test]
    #[serial]
    fn an_older_form_entry_is_rewritten_and_a_strkey_entry_is_left() {
        install();
        let coordinate = KeyringEntryRef::default_owner_key("owner-rewrite");
        put(&coordinate, &URL_SAFE_NO_PAD.encode(OWNER));
        assert_eq!(
            rewrite_older_form_owner_entry(&coordinate),
            OwnerEntryRewrite::Rewritten
        );
        assert!(
            get(&coordinate) == Some(encode_owner_public_key(&OWNER)),
            "rewritten as the G-strkey"
        );
        assert_eq!(
            rewrite_older_form_owner_entry(&coordinate),
            OwnerEntryRewrite::AlreadyStrkey
        );
        assert_eq!(
            rewrite_older_form_owner_entry(&KeyringEntryRef::default_owner_key("absent")),
            OwnerEntryRewrite::Absent
        );
    }

    #[test]
    #[serial]
    fn a_directory_sweep_rewrites_every_other_profile() {
        install();
        let dir = tempfile::tempdir().unwrap();
        for name in ["sweep-a", "sweep-b", "sweep-c"] {
            std::fs::write(dir.path().join(format!("{name}.toml")), "").unwrap();
            put(
                &KeyringEntryRef::default_owner_key(name),
                &URL_SAFE_NO_PAD.encode(OWNER),
            );
        }
        rewrite_older_form_owner_entries_in_dir(dir.path(), Some("sweep-a"));
        assert!(
            get(&KeyringEntryRef::default_owner_key("sweep-a"))
                == Some(URL_SAFE_NO_PAD.encode(OWNER)),
            "the skipped profile is left to its own reader"
        );
        for name in ["sweep-b", "sweep-c"] {
            assert!(
                get(&KeyringEntryRef::default_owner_key(name))
                    == Some(encode_owner_public_key(&OWNER)),
                "every other profile is rewritten"
            );
        }
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
}
