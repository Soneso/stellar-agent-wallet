//! `stellar-agent profile sign-policy` — sign a V1 policy file with the owner
//! key so the policy engine accepts it.
//!
//! The V1 engine loads `<state_dir>/policies/<profile>.toml`, recomputes the
//! canonical form (the `[signature]` table excluded), and verifies the
//! `[signature]` against the owner PUBLIC key enrolled in the keyring.  This
//! command produces that `[signature]` table: it reads the owner seed from an
//! environment variable, computes the same canonical digest the loader
//! computes, signs it, and writes `owner_id` + `sig` back into the file.
//!
//! # Signing pre-image
//!
//! The signed bytes are exactly what the loader verifies:
//! `sig = ed25519_sign(seed, blake3(canonical_bytes(policy_toml)))`, where
//! `canonical_bytes` excludes the `[signature]` table.  See
//! `stellar_agent_core::policy::v1::{canonical, signature}`.
//!
//! # Body checks
//!
//! The command signs only a body the V1 loader accepts. Before canonicalising,
//! it refuses a key outside the policy schema
//! (`sign_policy.canonicalization_failed`, naming the key and its location).
//! It reads the installation's policy pin, without creating any state file,
//! and assigns a version 2 body the next sequence. Before signing, it runs the
//! loader's body checks for the engine's profile name and refuses a body the
//! loader would refuse (`sign_policy.policy_body_invalid`, with the loader's
//! detail). It then applies the minimum mainnet policy when this build
//! enforces it and checks the profile-dependent `[mainnet]` fields. The existing
//! `[signature]` table is not checked: signing replaces it whole, so a stale or
//! malformed signature is repaired by signing again. The key and body
//! refusals name the policy file and state that no file was written. A pin
//! that cannot be read refuses with its state code: `policy.pin_unusable` for
//! an unreadable or malformed pin entry, and `policy.state_lock_busy` or
//! `policy.state_lock_io` for the state lock.
//!
//! # Owner-key cross-check
//!
//! Before writing, the derived public key is compared against the owner public
//! key enrolled at the profile's owner coordinate (the key the engine will
//! verify against).  A seed that does not match the enrolled owner key would
//! produce a file the engine rejects, so signing refuses on a mismatch and
//! points the operator at `enroll-owner-key`.
//!
//! # Owner rotation
//!
//! With `--previous-owner-secret-env`, the seed in `--secret-env` is the new
//! owner's. The previous seed must derive to the owner the installation's
//! policy pin names, or to the enrolled owner when no pin exists, because a
//! verified load checks the statement against the pin. That seed signs the
//! `[owner_rotation]` statement for the new owner, and the new seed then
//! signs the policy including the table. Both seeds go through the same
//! mlock-protected ceremony.
//!
//! # Secret handling
//!
//! The owner seed is held only in `Zeroizing` wrappers and the
//! `ed25519_dalek::SigningKey` (which zeroizes on drop).  It is never printed,
//! logged, returned, or written to disk.  The policy digest and signature are
//! derived from the non-secret policy document and are safe to report.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "signed": true,
//!     "owner_address": "G...",
//!     "policy_path": "/.../policies/default.toml",
//!     "digest": "<hex>",
//!     "replaced": false
//!   },
//!   "request_id": "..."
//! }
//! ```

use std::path::PathBuf;

use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;

use super::owner_seed::{OwnerSeedError, with_owner_seed};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::signature::{digest, sign};
use stellar_agent_core::policy::v1::{validate_policy_keys, validate_unsigned_policy};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::owner_key::{OwnerKeyDecodeError, owner_key_fingerprint};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, default_policy_dir};
use stellar_agent_core::wallet::MlockRequired;
use stellar_agent_network::keyring::{KeyringOperation, map_keyring_operation_error};

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::{render, resolve_profile_name};
use stellar_agent_core::profile::name::{
    OWNER_KEY_SERVICE_PREFIX, derive_profile_name_from_owner_key,
};

/// Arguments for `stellar-agent profile sign-policy`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct SignPolicyArgs {
    /// Profile whose policy file should be signed.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Name of the environment variable that holds the owner `S...` strkey.
    ///
    /// The flag takes the variable NAME, never the secret itself.
    #[arg(long, value_name = "VAR")]
    pub(crate) secret_env: String,

    /// Name of the environment variable that holds the previous owner's
    /// `S...` strkey. Signs an `[owner_rotation]` statement that hands the
    /// policy to the owner in `--secret-env`.
    #[arg(long, value_name = "VAR")]
    pub(crate) previous_owner_secret_env: Option<String>,

    /// Path to the policy file to sign.
    ///
    /// Defaults to the engine's expected location
    /// `<state_dir>/policies/<profile>.toml`.  Use this to sign a policy file
    /// at a non-default path while authoring; the engine only loads the default
    /// location.
    #[arg(long, value_name = "PATH")]
    pub(crate) file: Option<PathBuf>,
}

/// Success payload for the `sign-policy` envelope.
#[derive(Debug, Serialize)]
struct SignPolicyData {
    /// Name of the profile whose policy file was signed.
    profile: String,
    /// Always `true` on success.
    signed: bool,
    /// The G-strkey of the owner key that signs the policy.
    owner_address: String,
    /// Absolute path of the signed policy file.
    policy_path: String,
    /// Hex-encoded BLAKE3 digest of the canonical policy bytes that was signed.
    digest: String,
    /// Hex-encoded 64-byte ed25519 signature written to the `[signature]` table.
    signature: String,
    /// `true` when an existing `[signature]` table was replaced (re-signing).
    replaced: bool,
    /// The `owner_id` of the replaced `[signature]` table, when one existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_owner_id: Option<String>,
    /// Assigned v2 sequence; absent for v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<i64>,
    /// Maximum of the input sequence and the installed pin.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_sequence: Option<i64>,
    /// Actions needed before mainnet writes or the next policy load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// Runs `stellar-agent profile sign-policy`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub(crate) async fn run(args: &SignPolicyArgs) -> i32 {
    run_with_dependencies(
        args,
        injected_profile_load,
        stellar_agent_network::keyring::init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and platform-keyring
/// initialiser injected.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &SignPolicyArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();

    // ── Load profile first, then initialise the keyring store ─────────────────
    // Reconciled in the CALLER of the injected loader: several test closures
    // ignore the name they are handed, so a check placed inside one would be
    // bypassed by every test that supplies it.
    let profile = match reconcile_loaded_profile(load_profile(&profile_name), &resolved) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };
    if let Err(e) = stellar_agent_core::profile::owner_key::refuse_installation_key_coordinate(
        &profile.policy_window_state_key_id,
        "policy_window_state_key_id",
    ) {
        render::render_json(&Envelope::<()>::err(&e));
        return 1;
    }
    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    // ── Resolve the profile name + owner coordinate the engine uses ───────────
    let engine_profile_name = match engine_profile_name(&profile) {
        Ok(n) => n,
        Err(msg) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.invalid_owner_service",
                msg,
            ));
            return 1;
        }
    };
    let owner_coord = KeyringEntryRef::default_owner_key(&engine_profile_name);

    // ── Read the enrolled owner PUBLIC key (the engine's verification key) ────
    let enrolled_pubkey = match read_owner_pubkey(&owner_coord) {
        Ok(pk) => pk,
        Err(error) => {
            let code = match &error {
                OwnerReadError::OlderForm => "sign_policy.owner_key_older_form",
                OwnerReadError::Unavailable(_) => "sign_policy.owner_key_unavailable",
            };
            render::render_json(&Envelope::<()>::err_raw(code, error.message()));
            return 1;
        }
    };

    // ── Resolve the policy file path ──────────────────────────────────────────
    // Binding: the default path mirrors the engine's own construction —
    // `default_policy_dir().join("<profile>.toml")` in
    // `commands::policy_engine::build_v1_policy_engine` (policy_engine.rs:132)
    // and `build_policy_engine` in `stellar-agent-mcp/src/server.rs:478`. Signing
    // any other file has no effect unless the operator moves it there.
    let policy_path = match args.file.clone() {
        Some(p) => p,
        None => match default_policy_dir() {
            Ok(dir) => dir.join(format!("{engine_profile_name}.toml")),
            Err(e) => {
                render::render_json(&Envelope::<()>::err_raw(
                    "sign_policy.policy_dir_unavailable",
                    format!("the OS policy state directory is unavailable ({e})"),
                ));
                return 1;
            }
        },
    };

    // ── Read the policy TOML ──────────────────────────────────────────────────
    let raw = match std::fs::read_to_string(&policy_path) {
        Ok(s) => s,
        Err(e) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.policy_file_unreadable",
                format!("could not read policy file {}: {e}", policy_path.display()),
            ));
            return 1;
        }
    };

    let prepared = match prepare_policy(
        &raw,
        &profile,
        &engine_profile_name,
        &policy_path,
        &stellar_agent_core::profile::schema::default_policy_window_state_path_for(&profile_name),
    ) {
        Ok(prepared) => prepared,
        Err((code, detail)) => {
            render::render_json(&Envelope::<()>::err_raw(code, detail));
            return 1;
        }
    };
    let raw = prepared.raw;

    // ── Sign the digest inside an mlock-protected window ──────────────────────
    // The policy signature is a raw ed25519 signature over the BLAKE3 digest, a
    // pre-image class distinct from every `Signer` trait method (Stellar tx/auth
    // payloads, which MUST NOT be substituted). The owner seed is pinned via
    // `Wallet::unlock` (matching `enroll-owner-key`'s mlock ceremony posture:
    // `Wallet::unlock` emits the same `tracing::warn!` on degradation) and the
    // dalek key is built from the pinned bytes only for this one signature.
    let (raw, derived_pubkey, sig, d) = match sign_policy_with_owner_seeds(
        &args.secret_env,
        profile.wallet.mlock_required,
        profile.wallet.unlock_ttl_seconds,
        &enrolled_pubkey,
        &raw,
        args.previous_owner_secret_env
            .as_deref()
            .map(|var_name| PreviousOwner {
                var_name,
                expected: prepared.pinned_owner.unwrap_or(enrolled_pubkey),
            }),
    )
    .await
    {
        Ok(pair) => pair,
        Err(OwnerSignError::Policy(error)) => {
            render::render_json(&Envelope::<()>::err_raw(
                error.wire_code(),
                error.to_string(),
            ));
            return 1;
        }
        Err(OwnerSignError::Env(msg)) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.invalid_owner_seed",
                msg,
            ));
            return 1;
        }
        Err(OwnerSignError::Unlock(msg)) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.owner_seed_unlock_failed",
                msg,
            ));
            return 1;
        }
        Err(OwnerSignError::Mismatch { derived }) => {
            let derived_address = stellar_strkey::ed25519::PublicKey(derived)
                .to_string()
                .to_string();
            let enrolled_fingerprint = owner_key_fingerprint(&enrolled_pubkey);
            let derived_fingerprint = owner_key_fingerprint(&derived);
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.owner_key_mismatch",
                format!(
                    "the seed in '{}' derives to owner key {derived_address} (fingerprint {derived_fingerprint}), \
                     but the profile's enrolled owner key has fingerprint {enrolled_fingerprint}; \
                     a policy signed with this seed would be rejected by the engine. Supply the \
                     enrolled owner's seed, or enroll the owner public key again with \
                     `stellar-agent profile enroll-owner-key --force`. No file was written.",
                    args.secret_env
                ),
            ));
            return 1;
        }
        Err(OwnerSignError::PreviousMismatch { derived, expected }) => {
            let derived_address = stellar_strkey::ed25519::PublicKey(derived)
                .to_string()
                .to_string();
            let expected_identity = if prepared.pinned_owner.is_some() {
                stellar_strkey::ed25519::PublicKey(expected)
                    .to_string()
                    .to_string()
            } else {
                format!("fingerprint {}", owner_key_fingerprint(&expected))
            };
            let source = if prepared.pinned_owner.is_some() {
                "the owner the installation's policy pin names"
            } else {
                "the enrolled owner, as no policy pin exists"
            };
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.owner_key_mismatch",
                format!(
                    "the seed in '{}' derives to owner key {derived_address}, but the previous \
                     owner of this rotation is {expected_identity}, {source}. Supply that \
                     owner's seed. No file was written.",
                    args.previous_owner_secret_env
                        .as_deref()
                        .unwrap_or_default()
                ),
            ));
            return 1;
        }
    };
    let owner_address = stellar_strkey::ed25519::PublicKey(derived_pubkey)
        .to_string()
        .to_string();
    let sig_hex = to_hex(&sig);
    let digest_hex = to_hex(&d);

    // ── Render + atomically write the `[signature]` table ─────────────────────
    let (rendered, replaced, previous_owner_id) =
        match render_with_signature(&raw, &owner_address, &sig_hex) {
            Ok(r) => r,
            Err(msg) => {
                render::render_json(&Envelope::<()>::err_raw(
                    "sign_policy.policy_file_invalid",
                    msg,
                ));
                return 1;
            }
        };
    if let Err(e) = atomic_write_string(&policy_path, &rendered) {
        render::render_json(&Envelope::<()>::err_raw(
            "sign_policy.policy_file_write_failed",
            format!(
                "could not write signed policy file {}: {e}",
                policy_path.display()
            ),
        ));
        return 1;
    }

    tracing::info!("policy file signed for profile '{profile_name}'");
    render::render_json(&Envelope::ok(SignPolicyData {
        profile: profile_name.clone(),
        signed: true,
        owner_address,
        policy_path: policy_path.display().to_string(),
        digest: digest_hex,
        signature: sig_hex,
        replaced,
        previous_owner_id,
        sequence: prepared.sequence,
        previous_sequence: prepared.previous_sequence,
        warnings: prepared.warnings,
    }));
    0
}

/// A policy body that passed every check signing applies, with its assigned
/// sequence and canonical bytes.
struct PreparedPolicy {
    raw: String,
    /// The owner the installation's pin names, when a pin exists.
    pinned_owner: Option<[u8; 32]>,
    sequence: Option<i64>,
    previous_sequence: Option<i64>,
    warnings: Vec<String>,
}

/// Checks the policy text at `policy_path` in the order the loader applies
/// them and assigns a v2 sequence, so every refusal happens before the owner
/// seed is read.
///
/// The checks run in this order: a key outside the policy schema, the
/// installation's pin, the v2 sequence, and canonicalization. The loader's
/// body checks for the engine's profile `name` follow, then the minimum
/// mainnet policy when this build enforces it, then the profile-dependent
/// `[mainnet]` fields. The `[signature]` table is not checked: signing
/// replaces it whole.
///
/// The pin is read without creating the window-state directory or its lock
/// file, and never written: an absent lock file reads as no pin.
///
/// # Errors
///
/// Returns the wire code and a message naming the policy file:
///
/// - A body that does not parse as TOML or cannot be canonicalized refuses
///   with `sign_policy.canonicalization_failed`.
/// - A key outside the schema refuses with
///   `sign_policy.canonicalization_failed`.
/// - A body the loader refuses refuses with `sign_policy.policy_body_invalid`.
/// - An exhausted sequence refuses with `sign_policy.sequence_exhausted`.
/// - The minimum and the `[mainnet]` fields keep their policy codes.
/// - A pin entry that cannot be read or is malformed refuses with
///   `policy.pin_unusable`.
/// - A state lock that cannot be taken refuses with `policy.state_lock_busy`
///   or `policy.state_lock_io`.
///
/// Every refusal except the parse and canonicalization failures states that
/// no file was written.
fn prepare_policy(
    raw: &str,
    profile: &Profile,
    name: &str,
    policy_path: &std::path::Path,
    window_path: &std::path::Path,
) -> Result<PreparedPolicy, (&'static str, String)> {
    use stellar_agent_core::policy::{
        PolicyError,
        pin::PinState,
        v1::{mainnet_minimum, verified::read_pin_without_creating},
    };
    let path = policy_path.display();
    let not_canonical = |e: PolicyError| {
        (
            "sign_policy.canonicalization_failed",
            format!("policy file {path} could not be canonicalised for signing ({e})"),
        )
    };
    let body_invalid = |detail: &dyn std::fmt::Display| {
        (
            "sign_policy.policy_body_invalid",
            format!(
                "the V1 policy loader refuses the body of policy file {path} ({detail}); correct \
                 the policy, then sign again. No file was written."
            ),
        )
    };
    let mut body = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
        not_canonical(PolicyError::PolicyFileParseFailed {
            detail: e.to_string(),
        })
    })?;

    // The loader refuses a key outside the schema before it verifies the
    // signature, so a file signed with one is never accepted.
    let mut unsigned = body.clone();
    unsigned.remove("signature");
    validate_policy_keys(&unsigned).map_err(|e| {
        (
            "sign_policy.canonicalization_failed",
            format!(
                "policy file {path} holds a key outside the V1 policy schema ({e}); correct the \
                 key, then sign again. No file was written."
            ),
        )
    })?;

    let pin = match read_pin_without_creating(window_path, profile) {
        Ok(PinState::Absent) => None,
        Ok(PinState::Present(pin)) => Some(pin),
        Err(e) => {
            return Err((
                e.wire_code(),
                format!(
                    "could not read the installation's policy pin for policy file {path} ({e}). \
                     No file was written."
                ),
            ));
        }
    };
    let pinned_owner = pin
        .as_ref()
        .map(stellar_agent_core::policy::pin::Pin::owner);
    let pin = pin.map(|pin| pin.sequence());
    let mut result = PreparedPolicy {
        raw: raw.to_owned(),
        pinned_owner,
        sequence: None,
        previous_sequence: None,
        warnings: Vec::new(),
    };
    if body.get("version").and_then(toml_edit::Item::as_integer) == Some(2) {
        let previous_body = match body.get("sequence") {
            None => 0,
            Some(value) => value
                .as_integer()
                .filter(|n| *n >= 1)
                .ok_or_else(|| body_invalid(&"sequence must be in 1..=i64::MAX"))?,
        };
        let previous = pin.unwrap_or(0).max(previous_body);
        let sequence = previous.checked_add(1).ok_or_else(|| {
            (
                "sign_policy.sequence_exhausted",
                format!(
                    "the sequence of policy file {path} cannot advance past i64::MAX. No file \
                     was written."
                ),
            )
        })?;
        body["sequence"] = toml_edit::value(sequence);
        result.sequence = Some(sequence);
        result.previous_sequence = Some(previous);
        result.raw = body.to_string();
    } else {
        if profile.chain_id.is_mainnet() {
            result
                .warnings
                .push("Mainnet writes require a v2 policy body with [mainnet].".into());
        }
        if pin.is_some() {
            result
                .warnings
                .push("The next load refuses this v1 body with policy.sequence_rollback.".into());
        }
    }
    canonical_bytes(&result.raw).map_err(not_canonical)?;
    validate_unsigned_policy(&result.raw, name).map_err(|e| body_invalid(&e))?;
    if mainnet_minimum::required(&body, profile) {
        mainnet_minimum::validate(&body, profile, name).map_err(|e| {
            (
                e.wire_code(),
                format!(
                    "policy file {path} does not meet the minimum mainnet policy ({e}); correct \
                     the policy, then sign again. No file was written."
                ),
            )
        })?;
    }
    stellar_agent_core::policy::v1::verified::validate_profile_body(&body, profile).map_err(
        |e| {
            (
                e.wire_code(),
                format!(
                    "the [mainnet] table of policy file {path} does not fit this profile ({e}); \
                     correct the policy, then sign again. No file was written."
                ),
            )
        },
    )?;
    Ok(result)
}

/// Derives the engine's profile name from `policy_owner_key_id.service`,
/// matching the engine's own derivation.
///
/// Binding: [`derive_profile_name_from_owner_key`] is the single implementation
/// of this strip, shared with `build_v1_policy_engine` and with
/// `stellar-agent-mcp`. Signing must derive the same name so it targets the
/// owner coordinate and policy path the engine will read.
///
/// The profile reaching this point has already been reconciled against the
/// requested name, so the derived name equals the name the operator selected.
fn engine_profile_name(profile: &Profile) -> Result<String, String> {
    let service = &profile.policy_owner_key_id.service;
    derive_profile_name_from_owner_key(profile)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            format!(
                "the profile's owner-key service '{service}' does not start with the expected \
                 prefix '{OWNER_KEY_SERVICE_PREFIX}'; the profile was not constructed with the \
                 standard owner coordinate"
            )
        })
}

/// A value-free failure to read the enrolled owner.
#[derive(Debug)]
enum OwnerReadError {
    OlderForm,
    Unavailable(String),
}

impl From<String> for OwnerReadError {
    fn from(message: String) -> Self {
        Self::Unavailable(message)
    }
}

impl OwnerReadError {
    fn message(self) -> String {
        match self {
            Self::OlderForm => "the owner key entry is in the older base64 form; \
                enroll the owner public key again with \
                `stellar-agent profile enroll-owner-key --force`"
                .to_owned(),
            Self::Unavailable(message) => message,
        }
    }
}

/// Reads the enrolled owner public key (32 bytes) from the keyring coordinate.
///
/// Accepts only the stored G-strkey; the older form requires enrollment again.
fn read_owner_pubkey(coord: &KeyringEntryRef) -> Result<[u8; 32], OwnerReadError> {
    let entry = KeyringEntry::new(&coord.service, &coord.account).map_err(|e| {
        let classified =
            map_keyring_operation_error(&e, KeyringOperation::Construct, &coord.service);
        format!(
            "owner keyring entry '{}:{}' could not be opened ({classified})",
            coord.service, coord.account
        )
    })?;
    let raw = entry
        .get_password()
        .map(zeroize::Zeroizing::new)
        .map_err(|e| match &e {
            // Absence keeps the outward not-enrolled contract; any other cause is
            // classified and surfaced, so a non-interactive Windows session is not
            // misreported as a missing enrolment.
            keyring_core::Error::NoEntry => format!(
                "no owner key is enrolled at keyring service '{}' account '{}'; run \
                 `stellar-agent profile enroll-owner-key` first",
                coord.service, coord.account
            ),
            other => {
                let classified =
                    map_keyring_operation_error(other, KeyringOperation::Read, &coord.service);
                format!(
                    "the owner key at keyring service '{}' account '{}' could not be read ({}): {}",
                    coord.service,
                    coord.account,
                    classified.code(),
                    classified.message()
                )
            }
        })?;
    stellar_agent_core::profile::owner_key::decode_owner_public_key(&raw).map_err(|error| {
        match error {
            OwnerKeyDecodeError::OlderForm => OwnerReadError::OlderForm,
            _ => OwnerReadError::Unavailable(
                "the enrolled owner key is neither a G-strkey nor the older form; \
                 enroll the owner public key again with \
                 `stellar-agent profile enroll-owner-key --force`"
                    .to_owned(),
            ),
        }
    })
}

/// Failure modes of the owner signing ceremony.
enum OwnerSignError {
    /// The policy cannot be canonicalized.
    Policy(stellar_agent_core::policy::PolicyError),
    /// The env var is unset or does not hold a valid `S...` strkey.
    Env(String),
    /// `Wallet::unlock` (mlock pinning) or seed access failed.
    Unlock(String),
    /// The seed derives to `derived`, which is not the enrolled owner key.
    Mismatch {
        /// The public key the supplied seed derives to.
        derived: [u8; 32],
    },
    /// The previous seed derives to `derived`, which is not the previous
    /// owner the statement must name.
    PreviousMismatch {
        /// The public key the previous seed derives to.
        derived: [u8; 32],
        /// The pin's owner, or the enrolled owner when no pin exists.
        expected: [u8; 32],
    },
}

impl From<OwnerSeedError> for OwnerSignError {
    fn from(error: OwnerSeedError) -> Self {
        match error {
            OwnerSeedError::NotSet { var } => {
                Self::Env(format!("environment variable '{var}' not set"))
            }
            OwnerSeedError::Invalid { var } => Self::Env(format!(
                "environment variable '{var}' contains an invalid S-strkey"
            )),
            OwnerSeedError::Unlock(message) => Self::Unlock(message),
        }
    }
}

/// The previous owner a rotation statement must name.
#[derive(Clone, Copy)]
struct PreviousOwner<'a> {
    /// Environment variable holding the previous owner's seed.
    var_name: &'a str,
    /// The pin's owner, or the enrolled owner when no pin exists.
    expected: [u8; 32],
}

/// Signs a policy with the seed in `var_name`.
///
/// Without `previous`, that seed must derive to `enrolled_pubkey`. With it,
/// the previous seed must derive to `previous.expected`; it signs the
/// `[owner_rotation]` statement for the new owner first, and the new seed
/// then signs the policy including that table. Both seeds run through
/// [`with_owner_seed`].
async fn sign_policy_with_owner_seeds(
    var_name: &str,
    mlock_required: MlockRequired,
    ttl_seconds: u32,
    enrolled_pubkey: &[u8; 32],
    raw: &str,
    previous: Option<PreviousOwner<'_>>,
) -> Result<(String, [u8; 32], [u8; 64], [u8; 32]), OwnerSignError> {
    with_owner_seed(
        var_name,
        "profile-sign-policy",
        mlock_required,
        ttl_seconds,
        async |key| {
            let derived = key.verifying_key().to_bytes();
            let mut raw = raw.to_owned();
            match previous {
                Some(previous) => {
                    let table = with_owner_seed(
                        previous.var_name,
                        "profile-sign-policy",
                        mlock_required,
                        ttl_seconds,
                        async |previous_key| {
                            let previous_owner = previous_key.verifying_key().to_bytes();
                            if previous_owner != previous.expected {
                                return Err(OwnerSignError::PreviousMismatch {
                                    derived: previous_owner,
                                    expected: previous.expected,
                                });
                            }
                            stellar_agent_core::policy::v1::signature::build_owner_rotation(
                                &raw,
                                previous_key,
                                &derived,
                            )
                            .map_err(OwnerSignError::Policy)
                        },
                    )
                    .await?;
                    let mut doc = raw.parse::<toml_edit::DocumentMut>().map_err(|e| {
                        OwnerSignError::Policy(
                            stellar_agent_core::policy::PolicyError::PolicyFileParseFailed {
                                detail: e.to_string(),
                            },
                        )
                    })?;
                    doc["owner_rotation"] = toml_edit::Item::Table(table);
                    raw = doc.to_string();
                }
                None if derived != *enrolled_pubkey => {
                    return Err(OwnerSignError::Mismatch { derived });
                }
                None => {}
            }
            let canonical = canonical_bytes(&raw).map_err(OwnerSignError::Policy)?;
            let digest = digest(&canonical);
            Ok((raw, derived, sign(&digest, key), digest))
        },
    )
    .await
}

/// Atomically writes `contents` to `path`: writes a temp file in the same
/// directory, fsyncs it, then renames it over the target.
///
/// The policy file is the root-of-trust document; a mid-write crash must not
/// truncate or corrupt the operator's body. `rename(2)` is atomic on a single
/// host, mirroring the profile writer's approach
/// (`stellar-agent-core::profile::migrate`).
pub(crate) fn atomic_write_string(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(contents.as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Parses `raw`, replaces (or inserts) the `[signature]` table with `owner_id`
/// + `sig`, and returns `(rendered_toml, replaced, previous_owner_id)`.
///
/// The body (`version`, `scope`, `[[rules]]`) is preserved verbatim; only the
/// `[signature]` table is written.  Because
/// [`canonical_bytes`] excludes the `[signature]` table, replacing it never
/// changes the signed pre-image.
fn render_with_signature(
    raw: &str,
    owner_id: &str,
    sig_hex: &str,
) -> Result<(String, bool, Option<String>), String> {
    let mut doc = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("policy file is not valid TOML ({e})"))?;

    let previous_owner_id = doc
        .get("signature")
        .and_then(toml_edit::Item::as_table)
        .and_then(|t| t.get("owner_id"))
        .and_then(toml_edit::Item::as_str)
        .map(ToOwned::to_owned);
    let replaced = doc.contains_key("signature");

    let mut sig_table = toml_edit::Table::new();
    sig_table.insert("owner_id", toml_edit::value(owner_id));
    sig_table.insert("sig", toml_edit::value(sig_hex));
    doc.insert("signature", toml_edit::Item::Table(sig_table));

    Ok((doc.to_string(), replaced, previous_owner_id))
}

/// Lower-case hex-encodes `bytes` (the encoding the loader hex-decodes).
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use serial_test::serial;
    use stellar_agent_core::policy::PolicyError;
    use stellar_agent_core::policy::v1::loader::load_signed_policy;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    use super::*;

    const PROFILE_NAME: &str = "sign-policy-test";

    /// `(S-strkey, pubkey bytes, G-strkey)` for a fixed 32-byte seed.
    fn seed_material(seed: [u8; 32]) -> (String, [u8; 32], String) {
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let g = stellar_strkey::ed25519::PublicKey(pk)
            .to_string()
            .to_string();
        (s_strkey, pk, g)
    }

    fn profile_for(name: &str) -> Profile {
        let mut profile = Profile::builder_testnet(
            "stellar-agent-signer",
            "default",
            "stellar-agent-nonce",
            "default",
        )
        .with_profile_name(name)
        .build();
        // These tests exercise the sign/verify round trip, not mlock. The
        // platform default posture is `True` (fail-closed) on Linux/macOS, which
        // would make `Wallet::unlock` fail wherever mlock is unavailable (e.g.
        // sandboxed CI). `Warn` still attempts the lock but tolerates its
        // absence, keeping the crypto assertions deterministic — the same
        // fallback the signer ceremony applies to profiles it cannot load.
        profile.wallet.mlock_required = MlockRequired::Warn;
        profile
    }

    fn enroll_owner_pubkey(name: &str, pk: &[u8; 32]) {
        let coord = KeyringEntryRef::default_owner_key(name);
        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        entry
            .set_password(&stellar_agent_core::profile::owner_key::encode_owner_public_key(pk))
            .unwrap();
    }

    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; serialised by #[serial]"
        )]
        fn set(var: String, value: &str) -> Self {
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    fn unique_var(tag: &str) -> String {
        format!("SIGN_POLICY_TEST_{tag}_{}", std::process::id())
    }

    fn policy_body(name: &str) -> String {
        format!(
            "version = 1\nscope = \"profile:{name}\"\n\n[[rules]]\nmatch = {{ tool = \"stellar_balances\", chain = \"*\" }}\ncriteria = []\ndecision = \"allow\"\n"
        )
    }

    fn args(file: &std::path::Path, var: &str) -> SignPolicyArgs {
        SignPolicyArgs {
            profile: Some(PROFILE_NAME.to_owned()),
            secret_env: var.to_owned(),
            previous_owner_secret_env: None,
            file: Some(file.to_path_buf()),
        }
    }

    /// Owner-key absence keeps the outward not-enrolled contract.
    #[test]
    #[serial]
    fn read_owner_pubkey_reports_not_enrolled_on_absence() {
        keyring_mock::install().expect("mock store");
        let coord = KeyringEntryRef::default_owner_key("sign-policy-owner-absent-test");
        let err = read_owner_pubkey(&coord).unwrap_err().message();
        assert!(
            err.contains("no owner key is enrolled"),
            "absence must keep the not-enrolled message, got: {err}"
        );
    }

    /// A non-interactive Windows session is NOT misreported as a missing
    /// enrolment: the classified `auth.keyring_interactive_session_required`
    /// code is surfaced in the refusal message.
    #[test]
    #[serial]
    fn read_owner_pubkey_surfaces_interactive_session_required() {
        keyring_mock::install().expect("mock store");
        let coord = KeyringEntryRef::default_owner_key("sign-policy-owner-no-logon-test");
        keyring_mock::inject_no_logon_session(&coord.service, &coord.account).unwrap();
        let err = read_owner_pubkey(&coord).unwrap_err().message();
        assert!(
            err.contains("auth.keyring_interactive_session_required"),
            "a non-interactive session must surface the classified code, got: {err}"
        );
        assert!(
            !err.contains("no owner key is enrolled"),
            "an environmental failure must not be misreported as not-enrolled, got: {err}"
        );
    }

    /// The acceptance law: real sign-policy → the REAL v1 loader accepts the
    /// signed file under the enrolled owner key; tampering the body is rejected.
    #[tokio::test]
    #[serial]
    async fn sign_produces_a_file_the_real_loader_accepts_and_tamper_is_rejected() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, pk, owner_g) = seed_material([0x11u8; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &pk);

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, policy_body(PROFILE_NAME)).unwrap();

        let var = unique_var("HAPPY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        assert_eq!(
            code, 0,
            "sign-policy must succeed with the enrolled owner seed"
        );

        // (d) The REAL loader accepts the signed file under the enrolled key.
        let doc = load_signed_policy(&path, PROFILE_NAME, &pk)
            .expect("the signed policy must load and verify");
        assert_eq!(doc.version, 1);
        let sig = doc.signature.expect("signature must be populated");
        assert_eq!(sig.owner_id, owner_g, "owner_id must be the owner G-strkey");

        // (e) Tamper one byte of the signed body → the loader rejects it.
        let signed = std::fs::read_to_string(&path).unwrap();
        let tampered = signed.replace("stellar_balances", "stellar_pay");
        assert_ne!(signed, tampered, "tamper must actually change the body");
        let tpath = dir.path().join("tampered.toml");
        std::fs::write(&tpath, tampered).unwrap();
        let err = load_signed_policy(&tpath, PROFILE_NAME, &pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { .. }),
            "a tampered body must fail signature verification, got: {err:?}"
        );
    }

    /// (f) A signed file does not verify under a DIFFERENT owner public key.
    #[tokio::test]
    #[serial]
    async fn signed_file_rejected_under_a_wrong_owner_key() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, pk, _g) = seed_material([0x22u8; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &pk);

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, policy_body(PROFILE_NAME)).unwrap();

        let var = unique_var("WRONGLOAD");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        assert_eq!(code, 0);

        let (_other_s, other_pk, _other_g) = seed_material([0x33u8; 32]);
        let err = load_signed_policy(&path, PROFILE_NAME, &other_pk).unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { .. }),
            "verification under a different owner key must fail, got: {err:?}"
        );
    }

    /// A seed that does not match the enrolled owner key is refused before any
    /// write (the cross-check), so the file stays unsigned.
    #[tokio::test]
    #[serial]
    async fn wrong_seed_is_refused_and_file_is_not_written() {
        keyring_mock::install().expect("mock store");
        let (_enrolled_s, enrolled_pk, _enrolled_g) = seed_material([0x44u8; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &enrolled_pk);

        // A DIFFERENT seed than the one enrolled.
        let (wrong_s, _wrong_pk, _wrong_g) = seed_material([0x55u8; 32]);

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        let body = policy_body(PROFILE_NAME);
        std::fs::write(&path, &body).unwrap();

        let var = unique_var("WRONGSEED");
        let _guard = EnvGuard::set(var.clone(), &wrong_s);
        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        assert_eq!(
            code, 1,
            "a seed not matching the enrolled owner key must refuse"
        );

        // The file was left untouched — no [signature] table added.
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, body, "no file must be written on owner-key mismatch");
        assert!(!after.contains("[signature]"));
    }

    async fn owner_refusal(stored: &str, previous: bool) -> serde_json::Value {
        keyring_mock::install().unwrap();
        let coord = KeyringEntryRef::default_owner_key(PROFILE_NAME);
        KeyringEntry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(stored)
            .unwrap();
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        let body = policy_body(PROFILE_NAME);
        std::fs::write(&path, &body).unwrap();
        let (secret, _, _) = seed_material([0x55; 32]);
        let var = unique_var("OWNER_HYGIENE");
        let _guard = EnvGuard::set(var.clone(), &secret);
        let mut arguments = args(&path, &var);
        if previous {
            arguments.previous_owner_secret_env = Some(var);
        }
        render::take_rendered_for_test();
        let profile = profile_for(PROFILE_NAME);
        assert_eq!(
            run_with_dependencies(&arguments, |_| Ok(profile.clone()), || Ok(())).await,
            1
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), body);
        let mut output = render::take_rendered_for_test();
        assert_eq!(output.len(), 1);
        output.remove(0)
    }

    #[tokio::test]
    #[serial]
    async fn an_older_form_owner_entry_refuses_sign_policy() {
        use base64::Engine as _;
        let bytes = [0x44; 32];
        let older = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let output = owner_refusal(&older, false).await;
        assert_eq!(output["error"]["code"], "sign_policy.owner_key_older_form");
        let rendered = output.to_string();
        for value in [
            older,
            stellar_agent_core::profile::owner_key::encode_owner_public_key(&bytes),
            seed_material(bytes).0,
        ] {
            assert!(!rendered.contains(&value));
        }
    }

    #[tokio::test]
    #[serial]
    async fn the_mismatch_error_names_fingerprints_and_no_enrolled_key() {
        let bytes = [0x44; 32];
        let stored = stellar_agent_core::profile::owner_key::encode_owner_public_key(&bytes);
        let output = owner_refusal(&stored, false).await;
        assert_eq!(output["error"]["code"], "sign_policy.owner_key_mismatch");
        let rendered = output.to_string();
        let (_, derived, address) = seed_material([0x55; 32]);
        assert!(rendered.contains(&owner_key_fingerprint(&bytes)));
        assert!(rendered.contains(&owner_key_fingerprint(&derived)));
        assert!(rendered.contains(&address));
        assert!(!rendered.contains(&stored));
        assert!(!rendered.contains(&seed_material(bytes).0));
    }

    #[tokio::test]
    #[serial]
    async fn a_previous_owner_mismatch_without_a_pin_names_a_fingerprint() {
        let bytes = [0x44; 32];
        let stored = stellar_agent_core::profile::owner_key::encode_owner_public_key(&bytes);
        let output = owner_refusal(&stored, true).await;
        assert_eq!(output["error"]["code"], "sign_policy.owner_key_mismatch");
        let rendered = output.to_string();
        assert!(rendered.contains(&owner_key_fingerprint(&bytes)));
        assert!(!rendered.contains(&stored));
        assert!(!rendered.contains(&seed_material(bytes).0));
    }

    /// Re-signing an already-signed file succeeds without a force flag,
    /// replaces the `[signature]` table in place (no duplication), and the
    /// result still verifies. The `replaced` / `previous_owner_id` envelope
    /// fields are asserted directly in `render_with_signature_reports_replaced`.
    #[tokio::test]
    #[serial]
    async fn resign_replaces_signature_table_in_place_and_still_verifies() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, pk, owner_g) = seed_material([0x11u8; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &pk);

        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, policy_body(PROFILE_NAME)).unwrap();

        let var = unique_var("RESIGN");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // First signing.
        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        assert_eq!(code, 0);
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains(&owner_g));

        // Second signing of the same file re-signs in place.
        let profile2 = profile_for(PROFILE_NAME);
        let code = run_with_dependencies(
            &args(&path, &var),
            move |_n| Ok(profile2.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "re-signing must succeed without a force flag");

        // Still exactly one signature table, and it still verifies.
        let resigned = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            resigned.matches("[signature]").count(),
            1,
            "re-signing must not duplicate the [signature] table"
        );
        load_signed_policy(&path, PROFILE_NAME, &pk).expect("re-signed file must verify");
    }

    /// Runs `sign-policy` with the enrolled owner seed on `policy.toml`
    /// holding `body`. Returns the exit code, the one rendered envelope, the
    /// file contents afterwards, the enrolled owner public key, and the
    /// directory that holds the file.
    async fn sign_file_holding(
        tag: &str,
        body: &str,
    ) -> (i32, serde_json::Value, String, [u8; 32], TempDir) {
        keyring_mock::install().expect("mock store");
        let (s_strkey, pk, _g) = seed_material([0x66u8; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &pk);
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, body).unwrap();
        let var = unique_var(tag);
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        crate::common::render::take_rendered_for_test();
        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        let mut rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "one envelope per run: {rendered:?}");
        let after = std::fs::read_to_string(&path).unwrap();
        (code, rendered.remove(0), after, pk, dir)
    }

    /// A key outside the policy schema is refused before signing with the
    /// canonicalisation code, naming the key and its location, and the file is
    /// left byte-identical. The canonical form drops an unknown rule key, so
    /// this check is what refuses it.
    #[tokio::test]
    #[serial]
    async fn unknown_policy_key_is_refused_and_the_file_is_unchanged() {
        let body = format!(
            "{}decision_override = \"deny\"\n",
            policy_body(PROFILE_NAME)
        );
        let (code, envelope, after, _pk, dir) = sign_file_holding("UNKNOWNKEY", &body).await;
        assert_eq!(code, 1, "an unknown key must refuse: {envelope}");
        assert_eq!(
            envelope["error"]["code"], "sign_policy.canonicalization_failed",
            "{envelope}"
        );
        let path = dir.path().join("policy.toml");
        assert_eq!(
            envelope["error"]["message"],
            format!(
                "policy file {} holds a key outside the V1 policy schema (policy file parse \
                 failed: rule[0]: unknown key `decision_override`; a rule accepts match, \
                 criteria, decision, reason, ttl_secs, allow_opaque_signing); correct the key, \
                 then sign again. No file was written.",
                path.display()
            ),
            "the refusal must name the file, the key, and its location"
        );
        assert_eq!(after, body, "a refused file must be left byte-identical");
    }

    /// A body the loader refuses, but that canonicalises, is refused with
    /// `sign_policy.policy_body_invalid` carrying the loader's detail, and the
    /// file is left byte-identical: an approval `ttl_secs` out of range, and a
    /// scope for another profile.
    #[tokio::test]
    #[serial]
    async fn body_the_loader_refuses_is_refused_and_the_file_is_unchanged() {
        let out_of_range_ttl = format!(
            "{}\n[[rules]]\nmatch = {{ tool = \"*\", chain = \"*\" }}\ncriteria = []\n\
             decision = \"require_approval\"\nttl_secs = 0\n",
            policy_body(PROFILE_NAME)
        );
        let other_scope = policy_body("another-profile");
        for (body, detail) in [
            (
                out_of_range_ttl.as_str(),
                "rule[1] `ttl_secs` must be between 1 and 604800",
            ),
            (
                other_scope.as_str(),
                "policy scope does not match profile `sign-policy-test`",
            ),
        ] {
            canonical_bytes(body).expect("the body must canonicalise");
            let (code, envelope, after, _pk, dir) = sign_file_holding("BODYINVALID", body).await;
            assert_eq!(code, 1, "{detail}: {envelope}");
            assert_eq!(
                envelope["error"]["code"], "sign_policy.policy_body_invalid",
                "{envelope}"
            );
            assert_eq!(
                envelope["error"]["message"],
                format!(
                    "the V1 policy loader refuses the body of policy file {} (policy file parse \
                     failed: {detail}); correct the policy, then sign again. No file was written.",
                    dir.path().join("policy.toml").display()
                ),
                "the refusal must name the file and carry the loader's detail"
            );
            assert_eq!(after, body, "a refused file must be left byte-identical");
        }
    }

    /// Signing does not require a valid previous signature: a signature made
    /// over an earlier body, and a malformed `[signature]` table with a bad
    /// `sig` and an extra key, are both replaced, and the result loads.
    #[tokio::test]
    #[serial]
    async fn resign_repairs_a_stale_or_malformed_previous_signature() {
        let body = policy_body(PROFILE_NAME);
        let (code, envelope, signed, pk, dir) = sign_file_holding("STALE", &body).await;
        assert_eq!(code, 0, "{envelope}");
        let edited = signed.replace("stellar_balances", "stellar_pay");
        assert_ne!(edited, signed, "the body edit must apply");
        let stale_path = dir.path().join("stale.toml");
        std::fs::write(&stale_path, &edited).unwrap();
        assert!(
            matches!(
                load_signed_policy(&stale_path, PROFILE_NAME, &pk),
                Err(PolicyError::OwnerSignatureInvalid { .. })
            ),
            "the edited body must not verify under the old signature"
        );

        let malformed = format!(
            "{body}\n[signature]\nowner_id = \"GOLD\"\nsig = \"not-hex\"\nnote = \"stale\"\n"
        );
        let mut failures = Vec::new();
        for (case, previous) in [("stale", edited), ("malformed", malformed)] {
            let (code, envelope, resigned, pk, dir) =
                sign_file_holding("RESIGNOLD", &previous).await;
            if code != 0 {
                failures.push(format!("{case}: re-signing must succeed: {envelope}"));
                continue;
            }
            assert_eq!(envelope["data"]["replaced"], true, "{case}: {envelope}");
            assert!(
                !resigned.contains("note"),
                "{case}: the old table must be replaced"
            );
            let path = dir.path().join("policy.toml");
            let loaded = load_signed_policy(&path, PROFILE_NAME, &pk);
            assert!(
                loaded.is_ok(),
                "{case}: the re-signed file must load: {:?}",
                loaded.err()
            );
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[tokio::test]
    #[serial]
    async fn missing_owner_key_points_at_enroll() {
        keyring_mock::install().expect("mock store");
        // No owner key enrolled.
        let (s_strkey, _pk, _g) = seed_material([0x11u8; 32]);
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, policy_body(PROFILE_NAME)).unwrap();
        let var = unique_var("NOOWNER");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_for(PROFILE_NAME);
        let code =
            run_with_dependencies(&args(&path, &var), move |_n| Ok(profile.clone()), || Ok(()))
                .await;
        assert_eq!(code, 1, "missing enrolled owner key must refuse");
        // File not signed.
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("[signature]")
        );
    }

    #[tokio::test]
    #[serial]
    async fn nonexistent_profile_returns_exit_1() {
        let args = SignPolicyArgs {
            profile: Some("__nonexistent_sign_policy__".to_owned()),
            secret_env: "__UNSET_SIGN_POLICY_VAR__".to_owned(),
            previous_owner_secret_env: None,
            file: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    // ── render_with_signature (the replaced / previous_owner_id reporting) ─────

    /// An unsigned body reports `replaced = false` and no previous owner, and
    /// the emitted TOML carries the new `[signature]` table.
    #[test]
    fn render_with_signature_on_unsigned_body_reports_not_replaced() {
        let body = "version = 1\nscope = \"profile:x\"\n";
        let (rendered, replaced, previous) =
            render_with_signature(body, "GNEW", "aa").expect("render must succeed");
        assert!(!replaced, "an unsigned body must not report replaced");
        assert_eq!(previous, None, "an unsigned body has no previous owner");
        assert!(rendered.contains("[signature]"));
        assert!(rendered.contains("owner_id = \"GNEW\""));
        assert!(rendered.contains("sig = \"aa\""));
    }

    /// Re-rendering an already-signed body reports `replaced = true` and returns
    /// the PRIOR `owner_id` (read from the file's `[signature]` string — never
    /// derived from stored key bytes), and the new signature replaces the old.
    #[test]
    fn render_with_signature_reports_replaced() {
        let signed = "version = 1\nscope = \"profile:x\"\n\n[signature]\nowner_id = \"GOLD\"\nsig = \"dead\"\n";
        let (rendered, replaced, previous) =
            render_with_signature(signed, "GNEW", "beef").expect("render must succeed");
        assert!(replaced, "an already-signed body must report replaced");
        assert_eq!(
            previous.as_deref(),
            Some("GOLD"),
            "must report the prior owner_id"
        );
        assert!(rendered.contains("owner_id = \"GNEW\""));
        assert!(rendered.contains("sig = \"beef\""));
        assert!(
            !rendered.contains("dead"),
            "the old signature must be replaced"
        );
        assert_eq!(
            rendered.matches("[signature]").count(),
            1,
            "re-rendering must not duplicate the [signature] table"
        );
    }

    #[test]
    #[serial]
    fn sequence_assignment_uses_pin_and_body_without_writing_pin() {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope, PinState},
            state_lock::WindowStoreLock,
        };
        keyring_mock::install().unwrap();
        let directory = TempDir::new().unwrap();
        let window = directory.path().join("state.window");
        let policy = directory.path().join("policy.toml");
        let profile = profile_for("operator");
        let body = "version = 2\nscope = \"profile:operator\"\nsequence = 7\n[[rules]]\n\
            match = {tool = \"stellar_balances\", chain = \"*\"}\ncriteria = []\n\
            decision = \"allow\"\n";
        let prepared = prepare_policy(body, &profile, "operator", &policy, &window).unwrap();
        assert_eq!(prepared.sequence, Some(8));
        assert_eq!(prepared.previous_sequence, Some(7));
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .next()
                .is_none(),
            "preparing writes no state file"
        );
        let absent = directory.path().join("absent").join("state.window");
        assert_eq!(
            prepare_policy(body, &profile, "operator", &policy, &absent)
                .unwrap()
                .sequence,
            Some(8)
        );
        assert!(
            !directory.path().join("absent").exists(),
            "preparing creates no window-state directory"
        );
        let lock =
            WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id).unwrap();
        let scope = PinScope::for_profile(&window, &profile);
        assert_eq!(pin::read(&lock, &scope).unwrap(), PinState::Absent);
        pin::write(&lock, &scope, &Pin::new(10, [0; 32], [0; 32]).unwrap()).unwrap();
        drop(lock);
        let prepared = prepare_policy(body, &profile, "operator", &policy, &window).unwrap();
        assert_eq!(prepared.sequence, Some(11));
        assert_eq!(prepared.previous_sequence, Some(10));
        let lock =
            WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id).unwrap();
        assert!(matches!(
            pin::read(&lock, &scope).unwrap(),
            PinState::Present(pin) if pin.sequence() == 10
        ));
    }

    #[test]
    #[serial]
    fn sequence_missing_and_exhaustion_boundaries() {
        keyring_mock::install().unwrap();
        let directory = TempDir::new().unwrap();
        let window = directory.path().join("state.window");
        let policy = directory.path().join("policy.toml");
        let profile = profile_for("operator");
        let body = "version = 2\nscope = \"profile:operator\"\n[[rules]]\n\
            match = {tool = \"stellar_balances\", chain = \"*\"}\ncriteria = []\n\
            decision = \"allow\"\n";
        let prepared = prepare_policy(body, &profile, "operator", &policy, &window).unwrap();
        assert_eq!(prepared.sequence, Some(1));
        assert_eq!(prepared.previous_sequence, Some(0));
        let body = body.replace("version = 2", "version = 2\nsequence = 9223372036854775806");
        let prepared = prepare_policy(&body, &profile, "operator", &policy, &window).unwrap();
        assert_eq!(prepared.sequence, Some(i64::MAX));
        assert_eq!(prepared.previous_sequence, Some(i64::MAX - 1));
        let error = prepare_policy(&prepared.raw, &profile, "operator", &policy, &window)
            .err()
            .unwrap();
        assert_eq!(
            error,
            (
                "sign_policy.sequence_exhausted",
                format!(
                    "the sequence of policy file {} cannot advance past i64::MAX. No file was \
                     written.",
                    policy.display()
                )
            )
        );
    }

    #[test]
    #[serial]
    fn v1_warning_and_pin_rollback_warning() {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
        };
        keyring_mock::install().unwrap();
        let directory = TempDir::new().unwrap();
        let window = directory.path().join("state.window");
        let policy = directory.path().join("policy.toml");
        let profile = Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        let raw = policy_body("operator");
        let prepared = prepare_policy(&raw, &profile, "operator", &policy, &window).unwrap();
        assert_eq!(prepared.raw, raw);
        assert_eq!(prepared.sequence, None);
        assert!(prepared.warnings.iter().any(|w| w.contains("v2")));
        let lock =
            WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id).unwrap();
        pin::write(
            &lock,
            &PinScope::for_profile(&window, &profile),
            &Pin::new(1, [0; 32], [0; 32]).unwrap(),
        )
        .unwrap();
        drop(lock);
        let prepared = prepare_policy(&raw, &profile, "operator", &policy, &window).unwrap();
        assert!(
            prepared
                .warnings
                .iter()
                .any(|w| w.contains("policy.sequence_rollback"))
        );
    }

    #[test]
    #[serial]
    fn unsigned_and_minimum_validation_precede_signing() {
        keyring_mock::install().unwrap();
        let directory = TempDir::new().unwrap();
        let window = directory.path().join("state.window");
        let policy = directory.path().join("policy.toml");
        let profile = Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .build();
        let full = include_str!("../../../../stellar-agent-core/tests/fixtures/policy-v2.toml");
        let invalid = full.replace("max_calls = 10", "max_calls = -1");
        let (code, message) = prepare_policy(&invalid, &profile, "operator", &policy, &window)
            .err()
            .unwrap();
        assert_eq!(code, "sign_policy.policy_body_invalid");
        let framing = format!(
            "the V1 policy loader refuses the body of policy file {} (",
            policy.display()
        );
        let ending = "); correct the policy, then sign again. No file was written.";
        assert!(
            message.starts_with(&framing) && message.ends_with(ending),
            "{message}"
        );
        let unmet = full.replace("ttl_secs = 3600", "ttl_secs = 3601");
        let result = prepare_policy(&unmet, &profile, "operator", &policy, &window);
        assert_eq!(result.is_err(), cfg!(feature = "mainnet-write"));
        if let Err(error) = result {
            assert_eq!(
                error,
                (
                    "policy.mainnet_minimum_unmet",
                    format!(
                        "policy file {} does not meet the minimum mainnet policy \
                         (policy.mainnet_minimum_unmet: requirement=rule_ttl, rule=Some(0)); \
                         correct the policy, then sign again. No file was written.",
                        policy.display()
                    )
                )
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn rendered_sequence_fields_and_mainnet_warning_follow_the_signed_body() {
        use stellar_agent_core::policy::pin::PinState;
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let (secret, pk, _) = seed_material([11; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &pk);
        let var = unique_var("SEQUENCE");
        let _secret = EnvGuard::set(var.clone(), &secret);
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            policy_body(PROFILE_NAME).replace("version = 1", "version = 2"),
        )
        .unwrap();
        let mut profile = profile_for(PROFILE_NAME);
        for expected in [1, 2] {
            render::take_rendered_for_test();
            assert_eq!(
                run_with_dependencies(&args(&path, &var), |_| Ok(profile.clone()), || Ok(())).await,
                0
            );
            let output = render::take_rendered_for_test();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0]["data"]["sequence"], expected);
            assert_eq!(output[0]["data"]["previous_sequence"], expected - 1);
            assert_eq!(
                load_signed_policy(&path, PROFILE_NAME, &pk)
                    .unwrap()
                    .version,
                2
            );
        }
        let window =
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(PROFILE_NAME);
        assert!(
            !window.parent().unwrap().exists(),
            "signing creates no window-state directory"
        );
        assert_eq!(
            stellar_agent_core::policy::v1::verified::read_pin_without_creating(&window, &profile)
                .unwrap(),
            PinState::Absent
        );
        std::fs::write(&path, policy_body(PROFILE_NAME)).unwrap();
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Mainnet;
        profile.network_passphrase = profile.chain_id.network_passphrase().into();
        profile.rpc_url = "https://rpc.example.invalid".into();
        render::take_rendered_for_test();
        assert_eq!(
            run_with_dependencies(&args(&path, &var), |_| Ok(profile.clone()), || Ok(())).await,
            0
        );
        let output = render::take_rendered_for_test();
        assert!(
            output[0]["data"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains("v2"))
        );
        assert!(output[0]["data"].get("sequence").is_none());
    }
    /// A pin that cannot be read refuses with its state code and the rendered
    /// error, naming the policy file.
    #[test]
    #[serial]
    fn unreadable_pin_keeps_its_state_code() {
        keyring_mock::install().unwrap();
        let directory = TempDir::new().unwrap();
        let window = directory.path().join("state.window");
        let policy = directory.path().join("policy.toml");
        let profile = profile_for("operator");
        drop(
            stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
                &window,
                &profile.policy_window_state_key_id,
            )
            .unwrap(),
        );
        let coordinate = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &profile.policy_window_state_key_id,
        );
        keyring_mock::inject_no_logon_session(&coordinate.service, &coordinate.account).unwrap();
        let (code, message) = prepare_policy(
            &policy_body("operator"),
            &profile,
            "operator",
            &policy,
            &window,
        )
        .err()
        .unwrap();
        assert_eq!(code, "policy.pin_unusable");
        let framing = format!(
            "could not read the installation's policy pin for policy file {} \
             (policy.pin_unusable: the policy pin keyring entry could not be used: ",
            policy.display()
        );
        assert!(
            message.starts_with(&framing) && message.ends_with("). No file was written."),
            "{message}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn previous_owner_seed_signs_a_loadable_rotation_without_secret_output() {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
            v1::{
                PolicyStateStore,
                verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
            },
        };
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let (previous_secret, previous_public, _) = seed_material([41; 32]);
        let (new_secret, new_public, _) = seed_material([42; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &previous_public);
        let previous_var = unique_var("PREVIOUS");
        let new_var = unique_var("NEW");
        let _previous = EnvGuard::set(previous_var.clone(), &previous_secret);
        let _new = EnvGuard::set(new_var.clone(), &new_secret);
        let profile = profile_for(PROFILE_NAME);
        let window =
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(PROFILE_NAME);
        std::fs::create_dir_all(window.parent().unwrap()).unwrap();
        let lock =
            WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id).unwrap();
        pin::write(
            &lock,
            &PinScope::for_profile(&window, &profile),
            &Pin::new(1, [0; 32], previous_public).unwrap(),
        )
        .unwrap();
        drop(lock);
        let path = dir.path().join("policy.toml");
        let body = policy_body(PROFILE_NAME).replace("version = 1", "version = 2\nsequence = 1");
        std::fs::write(&path, &body).unwrap();
        let mut arguments = args(&path, &new_var);
        arguments.previous_owner_secret_env = Some(previous_var);
        render::take_rendered_for_test();
        assert_eq!(
            run_with_dependencies(&arguments, |_| Ok(profile.clone()), || Ok(())).await,
            0
        );
        let output = render::take_rendered_for_test();
        let text = serde_json::to_string(&output).unwrap();
        assert!(!text.contains(&previous_secret));
        assert!(!text.contains(&new_secret));
        let signed = std::fs::read_to_string(&path).unwrap();
        assert!(!signed.contains(&previous_secret));
        assert!(!signed.contains(&new_secret));
        assert!(signed.contains("[owner_rotation]"));
        let verified = load_verified_policy(
            &PolicyLoad {
                path: &path,
                profile: &profile,
                profile_name: PROFILE_NAME,
                owner_pubkey: &new_public,
                owner_source: OwnerKeySource::Keyring,
                window_path: &window,
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        assert_eq!(verified.sequence(), 2);
        assert_eq!(verified.owner(), new_public);
        let coord = KeyringEntryRef::default_owner_key(PROFILE_NAME);
        assert_eq!(read_owner_pubkey(&coord).unwrap(), previous_public);

        // A previous seed that is not the pinned owner's leaves the file intact.
        let (other_secret, _, _) = seed_material([40; 32]);
        let other_var = unique_var("OTHER");
        let _other = EnvGuard::set(other_var.clone(), &other_secret);
        arguments.previous_owner_secret_env = Some(other_var);
        render::take_rendered_for_test();
        assert_eq!(
            run_with_dependencies(&arguments, |_| Ok(profile.clone()), || Ok(())).await,
            1
        );
        let output = render::take_rendered_for_test();
        assert_eq!(output[0]["error"]["code"], "sign_policy.owner_key_mismatch");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), signed);
        let text = serde_json::to_string(&output).unwrap();
        assert!(!text.contains(&previous_secret));
        assert!(!text.contains(&new_secret));
        assert!(!text.contains(&other_secret));
    }

    /// The statement must name the pin's owner, so the previous seed is
    /// checked against the pin when one exists, also after the enrolled
    /// owner entry was replaced.
    #[tokio::test]
    #[serial]
    async fn previous_owner_seed_must_match_the_pinned_owner() {
        use stellar_agent_core::policy::{
            pin::{self, Pin, PinScope},
            state_lock::WindowStoreLock,
            v1::{
                PolicyStateStore,
                verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
            },
        };
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let (pinned_secret, pinned_public, _) = seed_material([43; 32]);
        let (enrolled_secret, enrolled_public, _) = seed_material([44; 32]);
        let (new_secret, new_public, _) = seed_material([45; 32]);
        enroll_owner_pubkey(PROFILE_NAME, &enrolled_public);
        let pinned_var = unique_var("PINNED");
        let enrolled_var = unique_var("ENROLLED");
        let new_var = unique_var("NEW_OWNER");
        let _pinned = EnvGuard::set(pinned_var.clone(), &pinned_secret);
        let _enrolled = EnvGuard::set(enrolled_var.clone(), &enrolled_secret);
        let _new = EnvGuard::set(new_var.clone(), &new_secret);
        let profile = profile_for(PROFILE_NAME);
        let window =
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(PROFILE_NAME);
        std::fs::create_dir_all(window.parent().unwrap()).unwrap();
        let lock =
            WindowStoreLock::acquire_for(&window, &profile.policy_window_state_key_id).unwrap();
        pin::write(
            &lock,
            &PinScope::for_profile(&window, &profile),
            &Pin::new(1, [0; 32], pinned_public).unwrap(),
        )
        .unwrap();
        drop(lock);
        let path = dir.path().join("policy.toml");
        let body = policy_body(PROFILE_NAME).replace("version = 1", "version = 2\nsequence = 1");
        std::fs::write(&path, &body).unwrap();
        let mut arguments = args(&path, &new_var);
        arguments.previous_owner_secret_env = Some(enrolled_var);
        render::take_rendered_for_test();
        assert_eq!(
            run_with_dependencies(&arguments, |_| Ok(profile.clone()), || Ok(())).await,
            1
        );
        let output = render::take_rendered_for_test();
        assert_eq!(output[0]["error"]["code"], "sign_policy.owner_key_mismatch");
        let message = output[0]["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(
                &stellar_strkey::ed25519::PublicKey(pinned_public)
                    .to_string()
                    .to_string()
            ),
            "{message}"
        );
        assert!(message.contains("policy pin"), "{message}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);

        arguments.previous_owner_secret_env = Some(pinned_var);
        render::take_rendered_for_test();
        assert_eq!(
            run_with_dependencies(&arguments, |_| Ok(profile.clone()), || Ok(())).await,
            0
        );
        let verified = load_verified_policy(
            &PolicyLoad {
                path: &path,
                profile: &profile,
                profile_name: PROFILE_NAME,
                owner_pubkey: &new_public,
                owner_source: OwnerKeySource::Keyring,
                window_path: &window,
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        assert_eq!(verified.owner(), new_public);
        assert_eq!(verified.sequence(), 2);
    }

    #[tokio::test]
    #[serial]
    async fn installation_coordinate_refuses_without_writing() {
        crate::common::installation_key_fixture::assert_installation_profile_refusal(
            |profile| &mut profile.policy_window_state_key_id,
            async |fixture, profile, name| {
                let args = SignPolicyArgs {
                    profile: Some(name.to_owned()),
                    secret_env: "UNUSED_PIN_SEED".to_owned(),
                    previous_owner_secret_env: None,
                    file: None,
                };
                run_with_dependencies(&args, |_| Ok(profile.clone()), || fixture.init()).await
            },
        )
        .await;
    }
}
