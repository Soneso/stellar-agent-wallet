//! Verifies a signed policy and compares its pin under the window-state lock.

use super::{
    PolicyDocument, PolicyEngineV1, PolicyStateStore,
    canonical::canonical_bytes,
    loader::{load_signed_policy_text, read_policy_file},
    mainnet_minimum,
};
use crate::{
    mainnet::verified_policy::{MainnetBody, VerifiedPolicy},
    policy::{
        PolicyError,
        pin::{self, Pin, PinScope, PinState},
        state_lock::{StateLockError, WindowStoreLock},
    },
    profile::{
        loader::{ThresholdIdentityConflict, threshold_identity_conflict},
        schema::{MINIMUM_FLOOR, Profile},
    },
};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use toml_edit::{DocumentMut, Item};

/// Whether a verified load may advance the installation's policy pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// Persist a first or newer v2 policy after all body checks pass.
    ///
    /// The load creates the store's lock file when it is absent, in a
    /// directory that must exist, and holds the lock across the pin read, the
    /// comparison, and the write.
    Advance,
    /// Compare freshness without changing the pin or creating any file.
    ///
    /// An existing lock is held across the pin read and the comparison. An
    /// absent lock file or window-state directory reads as an absent pin.
    /// A pin left behind after its lock file was removed is therefore not
    /// compared until a load in [`PinMode::Advance`] recreates the lock.
    CompareOnly,
}

/// Where the owner public key that verifies a policy was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeySource {
    /// The profile's owner entry in the keyring.
    Keyring,
    /// The test-only owner public-key file of a test build. A load refuses
    /// this source for a policy that enables mainnet writes in this build.
    TestFile,
}

/// The bindings of one verified policy load.
#[derive(Debug, Clone, Copy)]
pub struct PolicyLoad<'a> {
    /// The signed policy file.
    pub path: &'a Path,
    /// The profile the policy governs.
    pub profile: &'a Profile,
    /// The profile name the policy scope must name.
    pub profile_name: &'a str,
    /// The owner public key the signature must verify under.
    pub owner_pubkey: &'a [u8; 32],
    /// Where `owner_pubkey` was read from.
    pub owner_source: OwnerKeySource,
    /// The window-state store whose lock guards the pin.
    pub window_path: &'a Path,
}

/// What a compare-only inspection of a policy file found.
pub struct PolicyInspection {
    /// The signed body, parsed from the bytes whose signature verified, or
    /// `None` when the file could not be read or verified.
    pub document: Option<DocumentMut>,
    /// The pin the freshness comparison read, or `None` when the load stopped
    /// before it. An absent lock file reads as [`PinState::Absent`].
    pub pin: Option<PinState>,
    /// The outcome of the compare-only verified load.
    pub verified: Result<VerifiedPolicy, PolicyError>,
}

fn parse_error(detail: impl Into<String>) -> PolicyError {
    PolicyError::PolicyFileParseFailed {
        detail: detail.into(),
    }
}

/// Reads the strictly positive TOML integer sequence of a v2 body.
///
/// # Errors
/// Refuses an absent, noninteger, or nonpositive sequence.
pub fn sequence(doc: &DocumentMut) -> Result<i64, PolicyError> {
    doc.get("sequence")
        .and_then(Item::as_integer)
        .filter(|n| *n >= 1)
        .ok_or_else(|| parse_error("v2 sequence must be an integer in 1..=i64::MAX"))
}

pub(crate) fn parse_thresholds(
    item: Option<&Item>,
    passphrase: &str,
) -> Result<Option<BTreeMap<String, i128>>, PolicyError> {
    let Some(item) = item else {
        return Ok(None);
    };
    let table = item
        .as_table_like()
        .ok_or_else(|| parse_error("mainnet.cross_check_thresholds must be a table"))?;
    let mut result = BTreeMap::new();
    let mut identities = Vec::new();
    for (key, value) in table.iter() {
        let asset = super::asset_equivalence::pinned_asset(key)
            .map_err(|_| parse_error("threshold key must be native or a pinned asset"))?;
        let threshold = value
            .as_str()
            .and_then(|s| s.parse::<i128>().ok())
            .or_else(|| value.as_integer().map(i128::from))
            .filter(|v| *v > 0)
            .ok_or_else(|| parse_error("threshold must be a positive i128 decimal"))?;
        if key == "native" && threshold < i128::from(MINIMUM_FLOOR) {
            return Err(parse_error("native threshold is below MINIMUM_FLOOR"));
        }
        identities.push(asset);
        result.insert(key.to_owned(), threshold);
    }
    if let Some(conflict) = threshold_identity_conflict(&identities, passphrase) {
        return Err(parse_error(match conflict {
            ThresholdIdentityConflict::NativeContract { asset } => format!(
                "mainnet.cross_check_thresholds: key `{asset}` names the native asset's \
                 contract; set the `native` key instead"
            ),
            ThresholdIdentityConflict::SameAsset { asset, other } => format!(
                "mainnet.cross_check_thresholds: key `{asset}` names the same asset as key \
                 `{other}`"
            ),
        }));
    }
    Ok(Some(result))
}

fn parse_mainnet(doc: &DocumentMut, profile: &Profile) -> Result<Option<MainnetBody>, PolicyError> {
    let Some(item) = doc.get("mainnet") else {
        return Ok(None);
    };
    if !profile.chain_id.is_mainnet() {
        return Err(PolicyError::MainnetTableOnTestnet);
    }
    let table = item
        .as_table_like()
        .ok_or_else(|| parse_error("mainnet must be a table"))?;
    let text = |key| {
        table
            .get(key)
            .and_then(Item::as_str)
            .map(str::to_owned)
            .ok_or_else(|| parse_error(format!("mainnet.{key} must be a string")))
    };
    let integer = |key| {
        table
            .get(key)
            .and_then(Item::as_integer)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| parse_error(format!("mainnet.{key} must be a u32")))
    };
    let nonce = text("installation_nonce_sha256")?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(parse_error(
            "installation_nonce_sha256 must be 64 lowercase hex characters",
        ));
    }
    let installation_nonce_sha256 =
        crate::hex::decode_hex32(&nonce).map_err(|_| parse_error("invalid nonce digest"))?;
    Ok(Some(MainnetBody {
        profile: text("profile")?,
        endpoint_host: text("endpoint_host")?,
        installation_nonce_sha256,
        classic_max_fee_per_op_stroops: integer("classic_max_fee_per_op_stroops")?,
        authorization_ttl_seconds: table
            .get("authorization_ttl_seconds")
            .map(|_| integer("authorization_ttl_seconds"))
            .transpose()?,
        cross_check_thresholds: parse_thresholds(
            table.get("cross_check_thresholds"),
            &profile.network_passphrase,
        )?,
    }))
}

/// Validates profile-dependent fields before a policy is signed.
///
/// # Errors
/// Refuses malformed mainnet fields or a mainnet table on testnet.
pub fn validate_profile_body(doc: &DocumentMut, profile: &Profile) -> Result<(), PolicyError> {
    parse_mainnet(doc, profile).map(|_| ())
}

/// Acquires the policy-state lock, retrying contention as
/// [`WindowStoreLock::acquire_for_with_retry`] does. The lock file is created
/// when absent; its directory must exist.
///
/// # Errors
/// Distinguishes contention from the classified lock-file I/O error.
pub fn acquire_state_lock(
    window_path: &Path,
    profile: &Profile,
) -> Result<WindowStoreLock, PolicyError> {
    WindowStoreLock::acquire_for_with_retry(window_path, &profile.policy_window_state_key_id)
        .map_err(state_lock_error)
}

fn state_lock_error(error: StateLockError) -> PolicyError {
    match error {
        StateLockError::WriterLocked => PolicyError::StateLockBusy,
        StateLockError::Io { kind } => PolicyError::StateLockIo { kind },
    }
}

/// Reads the pin without creating the lock file or its directory. It runs
/// `compare` on the pin while the lock it was read under is still held, so no
/// writer can change the pin between the read and the comparison. An absent
/// lock file passes an absent pin and holds no lock.
///
/// # Errors
/// Refuses lock contention, lock-file I/O other than absence, and an
/// unreadable or malformed pin.
pub fn with_pin_without_creating<T>(
    window_path: &Path,
    profile: &Profile,
    compare: impl FnOnce(PinState) -> T,
) -> Result<T, PolicyError> {
    let lock = WindowStoreLock::acquire_existing_for_with_retry(
        window_path,
        &profile.policy_window_state_key_id,
    )
    .map_err(state_lock_error)?;
    match lock {
        Some(lock) => {
            let state = pin::read(&lock, &PinScope::for_profile(window_path, profile))
                .map_err(PolicyError::from)?;
            let outcome = compare(state);
            drop(lock);
            Ok(outcome)
        }
        None => Ok(compare(PinState::Absent)),
    }
}

/// Reads the pin without creating the lock file or its directory: an absent
/// lock file reads as an absent pin.
///
/// # Errors
/// The errors of [`with_pin_without_creating`].
pub fn read_pin_without_creating(
    window_path: &Path,
    profile: &Profile,
) -> Result<PinState, PolicyError> {
    with_pin_without_creating(window_path, profile, |state| state)
}

/// Applies the pin transition rules to a policy at `sequence` with `digest`,
/// signed by `owner`, and reports whether it advances the pin.
///
/// An absent pin advances for any v2 policy and stays absent for v1. A
/// present pin refuses v1 and every lower sequence as a rollback, and an
/// equal sequence with another digest or owner as a fork.
fn advances(
    state: &PinState,
    sequence: i64,
    digest: [u8; 32],
    owner: [u8; 32],
) -> Result<bool, PolicyError> {
    match state {
        PinState::Absent => Ok(sequence > 0),
        PinState::Present(pin) => {
            if sequence == 0 || sequence < pin.sequence() {
                return Err(PolicyError::SequenceRollback);
            }
            if sequence == pin.sequence() && (digest != pin.digest() || owner != pin.owner()) {
                return Err(PolicyError::SequenceFork);
            }
            Ok(sequence > pin.sequence())
        }
    }
}

/// A policy file whose signature verified, before its body checks.
struct SignedPolicy {
    raw: String,
    document: PolicyDocument,
    doc: DocumentMut,
}

/// The body facts the freshness comparison and the proof consume.
struct CheckedBody {
    sequence: i64,
    canonical: Vec<u8>,
    digest: [u8; 32],
    mainnet: Option<MainnetBody>,
}

/// Reads the file once and verifies its signature. Every later check runs on
/// the document parsed from these bytes.
fn read_signed(load: &PolicyLoad<'_>) -> Result<SignedPolicy, PolicyError> {
    let raw = read_policy_file(load.path)?;
    let document = load_signed_policy_text(&raw, load.profile_name, load.owner_pubkey)?;
    let doc = raw
        .parse::<DocumentMut>()
        .map_err(|e| parse_error(e.to_string()))?;
    Ok(SignedPolicy { raw, document, doc })
}

/// Applies the owner-source refusal and the minimum restrictions under the
/// mainnet condition, then parses the mainnet table and the sequence.
fn check_body(load: &PolicyLoad<'_>, signed: &SignedPolicy) -> Result<CheckedBody, PolicyError> {
    if mainnet_minimum::required(&signed.doc, load.profile) {
        if load.owner_source == OwnerKeySource::TestFile {
            return Err(PolicyError::TestOwnerKeyRefused);
        }
        mainnet_minimum::validate(&signed.doc, load.profile, load.profile_name)?;
    }
    let mainnet = parse_mainnet(&signed.doc, load.profile)?;
    let sequence = if signed.document.version == 2 {
        sequence(&signed.doc)?
    } else {
        0
    };
    let canonical = canonical_bytes(&signed.raw)?;
    let digest = *blake3::hash(&canonical).as_bytes();
    Ok(CheckedBody {
        sequence,
        canonical,
        digest,
        mainnet,
    })
}

/// Builds the engine and the proof once every check has passed and the pin
/// lock is released.
fn into_verified(
    load: &PolicyLoad<'_>,
    document: PolicyDocument,
    body: CheckedBody,
    window_state: PolicyStateStore,
) -> VerifiedPolicy {
    let engine = Arc::new(PolicyEngineV1::new_with_store(
        document,
        load.profile_name.to_owned(),
        window_state,
    ));
    VerifiedPolicy::from_verified(
        body.sequence,
        &body.canonical,
        *load.owner_pubkey,
        engine,
        body.mainnet,
    )
}

/// Verifies a policy, checks mainnet restrictions when enabled, and guards
/// its pin. The hydrated store moves into the engine after the pin lock is
/// released.
///
/// The file is read once; the signature, the owner-source refusal, the
/// minimum restrictions, and the pin comparison all apply to those bytes.
///
/// # Errors
/// Refuses invalid signatures or bodies, a test owner-key source for an
/// enabled mainnet policy, rollback, forks, lock failures, and an unusable
/// pin.
pub fn load_verified_policy(
    load: &PolicyLoad<'_>,
    window_state: PolicyStateStore,
    pin_mode: PinMode,
) -> Result<VerifiedPolicy, PolicyError> {
    let signed = read_signed(load)?;
    let body = check_body(load, &signed)?;
    let owner = *load.owner_pubkey;
    match pin_mode {
        PinMode::Advance => {
            let lock = acquire_state_lock(load.window_path, load.profile)?;
            let scope = PinScope::for_profile(load.window_path, load.profile);
            let state = pin::read(&lock, &scope).map_err(PolicyError::from)?;
            if advances(&state, body.sequence, body.digest, owner)? {
                let pin = Pin::new(body.sequence, body.digest, owner).map_err(PolicyError::from)?;
                pin::write(&lock, &scope, &pin).map_err(PolicyError::from)?;
            }
        }
        PinMode::CompareOnly => {
            with_pin_without_creating(load.window_path, load.profile, |state| {
                advances(&state, body.sequence, body.digest, owner)
            })??;
        }
    }
    Ok(into_verified(load, signed.document, body, window_state))
}

/// Runs a compare-only verified load and reports what it read: the verified
/// document for a minimum report, the pin it compared against, and the
/// outcome.
///
/// Writes nothing: neither the pin nor the lock file nor its directory.
#[must_use]
pub fn inspect_verified_policy(
    load: &PolicyLoad<'_>,
    window_state: PolicyStateStore,
) -> PolicyInspection {
    let signed = match read_signed(load) {
        Ok(signed) => signed,
        Err(error) => {
            return PolicyInspection {
                document: None,
                pin: None,
                verified: Err(error),
            };
        }
    };
    let mut pin = None;
    let verified = check_body(load, &signed).and_then(|body| {
        let (state, checked) =
            with_pin_without_creating(load.window_path, load.profile, |state| {
                let checked = advances(&state, body.sequence, body.digest, *load.owner_pubkey);
                (state, checked)
            })?;
        pin = Some(state);
        checked?;
        Ok(body)
    });
    let SignedPolicy { document, doc, .. } = signed;
    PolicyInspection {
        document: Some(doc),
        pin,
        verified: verified.map(|body| into_verified(load, document, body, window_state)),
    }
}
