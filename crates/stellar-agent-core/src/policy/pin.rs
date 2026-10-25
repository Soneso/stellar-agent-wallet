//! The policy pin: the sequence, digest, and owner of the signed policy a
//! mainnet profile last verified.
//!
//! The pin lives in the platform keyring beside the window-state key, at
//! [`policy_pin_entry_ref`](crate::profile::schema::policy_pin_entry_ref): the
//! window-state key's service and its account
//! suffixed `-policy-pin`. Its value is one strict JSON object,
//!
//! ```text
//! {"v":1,"sequence":N,"digest":"<64 lowercase hex>","owner":"G..."}
//! ```
//!
//! where `sequence` is the signed policy's sequence (non-negative), `digest`
//! the BLAKE3 digest of its canonical bytes, and `owner` the owner key that
//! signed it.
//!
//! # The guard
//!
//! [`read`](crate::policy::pin::read), [`write`](crate::policy::pin::write),
//! and [`compare`](crate::policy::pin::compare) take the window-state store's
//! [`WindowStoreLock`](crate::policy::state_lock::WindowStoreLock) and a
//! [`PinScope`](crate::policy::pin::PinScope) naming the store and its key
//! coordinate. Each checks that the guard was acquired for exactly that
//! scope and never takes the lock itself, so a caller holds one guard across
//! a read, a comparison, and a write, and the store's authorization
//! transitions read the pin under the guard they already hold.
//!
//! # Absent versus malformed
//!
//! [`read`](crate::policy::pin::read) reports an absent pin as
//! [`PinState::Absent`](crate::policy::pin::PinState::Absent), which the first
//! pin advance accepts. A value that does not parse as the object above is
//! [`PinError::Malformed`](crate::policy::pin::PinError::Malformed), never
//! absence. [`compare`](crate::policy::pin::compare) refuses both: an
//! authorization transition requires a pin that is present and equal.

use std::path::Path;

use keyring_core::Entry as KeyringEntry;
use serde::{Deserialize, Serialize};

use crate::keyring_errors::{KeyringOperation, map_keyring_operation_error};
use crate::policy::state_lock::WindowStoreLock;
use crate::profile::schema::{KeyringEntryRef, Profile, policy_pin_entry_ref};

/// The only pin value version this build reads and writes.
pub const POLICY_PIN_VERSION: u32 = 1;

/// The window-state store a pin operation acts on.
#[derive(Debug, Clone, Copy)]
pub struct PinScope<'a> {
    window_path: &'a Path,
    window_key: &'a KeyringEntryRef,
}

impl<'a> PinScope<'a> {
    /// The scope of the store at `window_path` whose HMAC key lives at
    /// `window_key`.
    #[must_use]
    pub fn new(window_path: &'a Path, window_key: &'a KeyringEntryRef) -> Self {
        Self {
            window_path,
            window_key,
        }
    }

    /// The scope of `profile`'s store at `window_path`, keyed by its
    /// configured `policy_window_state_key_id`.
    #[must_use]
    pub fn for_profile(window_path: &'a Path, profile: &'a Profile) -> Self {
        Self::new(window_path, &profile.policy_window_state_key_id)
    }

    /// The keyring coordinate of this scope's pin.
    #[must_use]
    pub fn pin_entry_ref(&self) -> KeyringEntryRef {
        policy_pin_entry_ref(self.window_key)
    }
}

/// One recorded policy pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    sequence: i64,
    digest: [u8; 32],
    owner: [u8; 32],
}

impl Pin {
    /// A pin for the policy at `sequence` with BLAKE3 `digest`, signed by
    /// the owner key `owner`.
    ///
    /// # Errors
    ///
    /// [`PinError::Malformed`] for a negative sequence.
    pub fn new(sequence: i64, digest: [u8; 32], owner: [u8; 32]) -> Result<Self, PinError> {
        if sequence < 0 {
            return Err(PinError::Malformed {
                detail: "the policy sequence is negative".to_owned(),
            });
        }
        Ok(Self {
            sequence,
            digest,
            owner,
        })
    }

    /// The pinned policy sequence.
    #[must_use]
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The pinned policy's BLAKE3 digest of its canonical bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The owner public key that signed the pinned policy.
    #[must_use]
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }
}

/// What the keyring holds at a scope's pin coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// No pin has been written.
    Absent,
    /// A well-formed pin.
    Present(Pin),
}

/// Why a pin operation refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PinError {
    /// The guard was not acquired for the scope the operation names.
    #[error("the policy pin operation holds a lock that does not guard this window-state store")]
    WrongGuard,
    /// No pin is recorded for the scope.
    #[error("no policy pin is recorded for this profile")]
    Absent,
    /// The recorded value is not a well-formed pin.
    #[error("the recorded policy pin is malformed: {detail}")]
    Malformed {
        /// Which rule the value breaks. Never the value itself.
        detail: String,
    },
    /// The recorded pin differs from the presented policy.
    #[error("the recorded policy pin does not match the presented policy's {field}")]
    Mismatch {
        /// `sequence` or `digest`.
        field: &'static str,
    },
    /// The keyring entry could not be read or written.
    #[error("the policy pin keyring entry could not be used: {detail}")]
    Keyring {
        /// The classified keyring error's text.
        detail: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinWire {
    v: u32,
    sequence: i64,
    digest: String,
    owner: String,
}

fn check_guard(lock: &WindowStoreLock, scope: &PinScope<'_>) -> Result<(), PinError> {
    if lock.guards(scope.window_path, scope.window_key) {
        Ok(())
    } else {
        Err(PinError::WrongGuard)
    }
}

fn open(entry_ref: &KeyringEntryRef) -> Result<KeyringEntry, PinError> {
    KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| PinError::Keyring {
        detail: map_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service)
            .to_string(),
    })
}

fn parse(raw: &str) -> Result<Pin, PinError> {
    let malformed = |detail: &str| PinError::Malformed {
        detail: detail.to_owned(),
    };
    let wire: PinWire = serde_json::from_str(raw)
        .map_err(|_| malformed("the value is not the pin object of version 1"))?;
    if wire.v != POLICY_PIN_VERSION {
        return Err(malformed("the pin version is not 1"));
    }
    if wire.digest.len() != 64
        || !wire
            .digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed("the digest is not 64 lowercase hex characters"));
    }
    let digest = crate::hex::decode_hex32(&wire.digest)
        .map_err(|_| malformed("the digest is not 64 lowercase hex characters"))?;
    let owner = stellar_strkey::ed25519::PublicKey::from_string(&wire.owner)
        .map_err(|_| malformed("the owner is not a G-strkey"))?
        .0;
    Pin::new(wire.sequence, digest, owner)
}

fn render(pin: &Pin) -> Result<String, PinError> {
    serde_json::to_string(&PinWire {
        v: POLICY_PIN_VERSION,
        sequence: pin.sequence,
        digest: crate::hex::encode(&pin.digest),
        owner: stellar_strkey::ed25519::PublicKey(pin.owner)
            .to_string()
            .to_string(),
    })
    .map_err(|e| PinError::Malformed {
        detail: format!("the pin could not be serialized: {e}"),
    })
}

/// Reads the pin of `scope` under `lock`.
///
/// # Errors
///
/// - [`PinError::WrongGuard`] when `lock` does not guard `scope`.
/// - [`PinError::Malformed`] when the recorded value is not a well-formed pin.
/// - [`PinError::Keyring`] when the entry cannot be read.
pub fn read(lock: &WindowStoreLock, scope: &PinScope<'_>) -> Result<PinState, PinError> {
    check_guard(lock, scope)?;
    let entry_ref = scope.pin_entry_ref();
    let entry = open(&entry_ref)?;
    match entry.get_password() {
        Ok(raw) => parse(raw.trim()).map(PinState::Present),
        Err(keyring_core::Error::NoEntry) => Ok(PinState::Absent),
        Err(e) => Err(PinError::Keyring {
            detail: map_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service)
                .to_string(),
        }),
    }
}

/// Writes `pin` as the pin of `scope` under `lock`, replacing any value.
///
/// # Errors
///
/// - [`PinError::WrongGuard`] when `lock` does not guard `scope`.
/// - [`PinError::Keyring`] when the entry cannot be written.
pub fn write(lock: &WindowStoreLock, scope: &PinScope<'_>, pin: &Pin) -> Result<(), PinError> {
    check_guard(lock, scope)?;
    let value = render(pin)?;
    let entry_ref = scope.pin_entry_ref();
    open(&entry_ref)?
        .set_password(&value)
        .map_err(|e| PinError::Keyring {
            detail: map_keyring_operation_error(&e, KeyringOperation::Write, &entry_ref.service)
                .to_string(),
        })
}

/// Requires the pin of `scope` to be present and to name the policy at
/// `sequence` with `digest`, and returns it.
///
/// # Errors
///
/// - [`PinError::WrongGuard`] when `lock` does not guard `scope`.
/// - [`PinError::Absent`] when no pin is recorded.
/// - [`PinError::Malformed`] when the recorded value is not a well-formed pin.
/// - [`PinError::Mismatch`] naming the first component that differs.
/// - [`PinError::Keyring`] when the entry cannot be read.
pub fn compare(
    lock: &WindowStoreLock,
    scope: &PinScope<'_>,
    sequence: i64,
    digest: &[u8; 32],
) -> Result<Pin, PinError> {
    let pin = match read(lock, scope)? {
        PinState::Absent => return Err(PinError::Absent),
        PinState::Present(pin) => pin,
    };
    if pin.sequence != sequence {
        return Err(PinError::Mismatch { field: "sequence" });
    }
    if &pin.digest != digest {
        return Err(PinError::Mismatch { field: "digest" });
    }
    Ok(pin)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    const OWNER: [u8; 32] = [7; 32];

    fn window_key() -> KeyringEntryRef {
        KeyringEntryRef::default_policy_window_state_key("pin-test")
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

    /// An absent pin reads as absent; a written pin reads back, has the
    /// documented wire form, and compares equal on both components.
    #[test]
    #[serial]
    fn a_written_pin_reads_back_in_its_wire_form() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let window = dir.path().join("pin.window");
        let key = window_key();
        let scope = PinScope::new(&window, &key);
        let lock = WindowStoreLock::acquire_for(&window, &key).unwrap();
        assert_eq!(read(&lock, &scope).unwrap(), PinState::Absent);
        assert_eq!(compare(&lock, &scope, 3, &[1; 32]), Err(PinError::Absent));
        let pin = Pin::new(3, [1; 32], OWNER).unwrap();
        write(&lock, &scope, &pin).unwrap();
        assert_eq!(read(&lock, &scope).unwrap(), PinState::Present(pin.clone()));
        assert_eq!(compare(&lock, &scope, 3, &[1; 32]).unwrap(), pin);
        let owner = stellar_strkey::ed25519::PublicKey(OWNER).to_string();
        assert_eq!(
            get(&scope.pin_entry_ref()).unwrap(),
            format!(
                "{{\"v\":1,\"sequence\":3,\"digest\":\"{}\",\"owner\":\"{owner}\"}}",
                "01".repeat(32)
            )
        );
        assert_eq!(
            scope.pin_entry_ref(),
            KeyringEntryRef::new(key.service.clone(), "default-policy-pin")
        );
    }

    /// The comparison refuses each component on its own.
    #[test]
    #[serial]
    fn compare_refuses_each_component() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let window = dir.path().join("pin.window");
        let key = window_key();
        let scope = PinScope::new(&window, &key);
        let lock = WindowStoreLock::acquire_for(&window, &key).unwrap();
        write(&lock, &scope, &Pin::new(3, [1; 32], OWNER).unwrap()).unwrap();
        assert_eq!(
            compare(&lock, &scope, 4, &[1; 32]),
            Err(PinError::Mismatch { field: "sequence" })
        );
        assert_eq!(
            compare(&lock, &scope, 3, &[2; 32]),
            Err(PinError::Mismatch { field: "digest" })
        );
    }

    /// Every malformed value refuses as malformed, never as absent.
    #[test]
    #[serial]
    fn malformed_values_refuse_as_malformed() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let window = dir.path().join("pin.window");
        let key = window_key();
        let scope = PinScope::new(&window, &key);
        let lock = WindowStoreLock::acquire_for(&window, &key).unwrap();
        let owner = stellar_strkey::ed25519::PublicKey(OWNER).to_string();
        let digest = "01".repeat(32);
        for value in [
            "not json".to_owned(),
            format!("{{\"v\":2,\"sequence\":1,\"digest\":\"{digest}\",\"owner\":\"{owner}\"}}"),
            format!("{{\"v\":1,\"sequence\":-1,\"digest\":\"{digest}\",\"owner\":\"{owner}\"}}"),
            format!(
                "{{\"v\":1,\"sequence\":1,\"digest\":\"{}\",\"owner\":\"{owner}\"}}",
                "AB".repeat(32)
            ),
            format!("{{\"v\":1,\"sequence\":1,\"digest\":\"01\",\"owner\":\"{owner}\"}}"),
            format!("{{\"v\":1,\"sequence\":1,\"digest\":\"{digest}\",\"owner\":\"GBAD\"}}"),
            format!(
                "{{\"v\":1,\"sequence\":1,\"digest\":\"{digest}\",\"owner\":\"{owner}\",\"x\":1}}"
            ),
        ] {
            put(&scope.pin_entry_ref(), &value);
            assert!(
                matches!(read(&lock, &scope), Err(PinError::Malformed { .. })),
                "{value}"
            );
            assert!(
                matches!(
                    compare(&lock, &scope, 1, &[1; 32]),
                    Err(PinError::Malformed { .. })
                ),
                "{value}"
            );
        }
    }

    /// A guard over another store, another coordinate, or a bare lock path is
    /// refused before the keyring is touched, and the operations never take
    /// the lock themselves.
    #[test]
    #[serial]
    fn operations_require_the_guard_of_their_scope() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let window = dir.path().join("pin.window");
        let other = dir.path().join("other.window");
        let key = window_key();
        let other_key = KeyringEntryRef::default_policy_window_state_key("other");
        let scope = PinScope::new(&window, &key);
        let pin = Pin::new(1, [1; 32], OWNER).unwrap();

        let foreign = WindowStoreLock::acquire_for(&other, &key).unwrap();
        assert_eq!(read(&foreign, &scope), Err(PinError::WrongGuard));
        let wrong_key = WindowStoreLock::acquire_for(&window, &other_key).unwrap();
        assert_eq!(write(&wrong_key, &scope, &pin), Err(PinError::WrongGuard));
        drop(wrong_key);
        let bare = WindowStoreLock::acquire(&crate::policy::state_lock::window_lock_path(&window))
            .unwrap();
        assert_eq!(
            compare(&bare, &scope, 1, &[1; 32]),
            Err(PinError::WrongGuard)
        );
        drop(bare);
        assert!(get(&scope.pin_entry_ref()).is_none(), "nothing was written");

        let held = WindowStoreLock::acquire_for(&window, &key).unwrap();
        write(&held, &scope, &pin).unwrap();
        assert_eq!(compare(&held, &scope, 1, &[1; 32]).unwrap(), pin);
        assert!(matches!(
            WindowStoreLock::acquire_for(&window, &key),
            Err(crate::policy::state_lock::StateLockError::WriterLocked)
        ));
    }
}
