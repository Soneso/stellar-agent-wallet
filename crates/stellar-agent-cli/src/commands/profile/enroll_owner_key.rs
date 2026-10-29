//! `stellar-agent profile enroll-owner-key` — enroll the policy-file owner
//! ed25519 PUBLIC key into the profile's owner keyring entry.
//!
//! The V1 policy engine verifies every policy file against the owner public key
//! it reads from the keyring entry `stellar-agent-owner-<profile>` / `"default"`
//! (see `fetch_owner_pubkey_from_keyring` in `stellar-agent-mcp` and
//! `build_v1_policy_engine` in this crate).  The stored value is the public
//! key's G-strkey. A G-strkey decodes as URL-safe base64 to 42 bytes, so no
//! 32-byte symmetric-key loader accepts it. Owner readers refuse older base64
//! entries until the owner public key is enrolled again.
//!
//! # Why the online agent holds only the public key
//!
//! The owner key is the root of trust for policy: a party that can sign a
//! policy file can authorise any action the policy permits.  The always-online
//! agent therefore holds ONLY the public key (enough to verify), never the
//! seed.  The operator keeps the seed offline and signs policy files with
//! `stellar-agent profile sign-policy`, which reads the seed from an
//! environment variable at sign time and never persists it.
//!
//! This command reads the operator's owner `S...` strkey from a named
//! environment variable through the shared mlock-protected ceremony, derives
//! the public address, and stores the PUBLIC key at the profile's owner
//! coordinate.  The seed is never printed, logged, returned, or written to the
//! keyring.
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
//!     "enrolled": true,
//!     "owner_address": "G...",
//!     "keyring_service": "stellar-agent-owner-default",
//!     "keyring_account": "default",
//!     "replaced": false
//!   },
//!   "request_id": "..."
//! }
//! ```

use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::Signer as _;
use stellar_agent_network::keyring::{KeyringOperation, init_platform_keyring_store};
use uuid::Uuid;

use crate::common::profile_access::{
    injected_profile_load, profile_access_envelope, reconcile_loaded_profile,
};
use crate::common::signer_ceremony::resolve_software_signer_from_env;
use crate::common::{render, resolve_profile_name};
use stellar_agent_core::profile::name::{
    OWNER_KEY_SERVICE_PREFIX, derive_profile_name_from_owner_key,
};

use super::audit_emit::emit_keyring_key_written;

/// Arguments for `stellar-agent profile enroll-owner-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct EnrollOwnerKeyArgs {
    /// Profile whose owner public key should be enrolled.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Name of the environment variable that holds the owner `S...` strkey.
    ///
    /// The flag takes the variable NAME, never the secret itself.
    #[arg(long, value_name = "VAR")]
    pub(crate) secret_env: String,

    /// Expected owner public address (G-strkey).
    ///
    /// When set, enrollment refuses unless the seed derives to this address —
    /// a guard against enrolling the wrong owner key.
    #[arg(long, value_name = "G_STRKEY")]
    pub(crate) expected_address: Option<String>,

    /// Replace an already-enrolled owner key.
    ///
    /// Without this flag, enrollment refuses when the owner coordinate already
    /// holds a value.
    #[arg(long, default_value_t = false)]
    pub(crate) force: bool,
}

/// Success payload for the `enroll-owner-key` envelope.
#[derive(Debug, Serialize)]
struct EnrollOwnerKeyData {
    /// Name of the profile whose owner key was enrolled.
    profile: String,
    /// Always `true` on success.
    enrolled: bool,
    /// The G-strkey the enrolled owner key derives to.
    owner_address: String,
    /// Keyring service coordinate the public key was written to.
    keyring_service: String,
    /// Keyring account coordinate the public key was written to (the literal
    /// `"default"`; the owner coordinate is not account-as-identity).
    keyring_account: String,
    /// `true` when an existing owner key was replaced (`--force`).
    ///
    /// The replaced value is deliberately NOT decoded or reported: the legacy
    /// `rotate-owner-key` stored the owner SEED at this coordinate in the same
    /// base64 encoding, so rendering the stored bytes as an address could print
    /// the private key. `replaced` alone conveys that a prior entry existed.
    replaced: bool,
}

/// Runs `stellar-agent profile enroll-owner-key`.
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
pub(crate) async fn run(args: &EnrollOwnerKeyArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`]; tests substitute an in-memory profile and a
/// spy initialiser so the enrollment path can be exercised against a mock
/// keyring store without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &EnrollOwnerKeyArgs,
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
    if let Err(e) = init_keyring() {
        render::render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    // ── Resolve the owner coordinate the engine reads ─────────────────────────
    // The engine derives the profile name by stripping OWNER_KEY_SERVICE_PREFIX
    // from `policy_owner_key_id.service` and reads
    // `default_owner_key(profile_name)` (account forced to "default").  Mirror
    // that exactly so the key we write is the key the engine reads.
    let owner_coord = match owner_coordinate(&profile) {
        Ok(c) => c,
        Err(msg) => {
            render::render_json(&Envelope::<()>::err_raw(
                "enroll_owner_key.invalid_owner_service",
                msg,
            ));
            return 1;
        }
    };

    // ── Derive the owner public key from the env S-strkey ─────────────────────
    // Reuses the shared mlock-protected env-seed ceremony; the seed never leaves
    // the ceremony's Zeroizing wrappers and only the derived public key is kept.
    let owner_pubkey = match resolve_software_signer_from_env(
        &args.secret_env,
        "profile-enroll-owner-key",
        &profile,
    )
    .await
    {
        Ok(outcome) => match outcome.signer.public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                render::render_json(&Envelope::<()>::err(&e));
                return 1;
            }
        },
        Err(e) => {
            render::render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };
    let owner_address = owner_pubkey.to_string().to_string();

    // ── Optional --expected-address guard (no write on mismatch) ──────────────
    if let Some(expected) = args.expected_address.as_deref() {
        if stellar_strkey::ed25519::PublicKey::from_string(expected).is_err() {
            render::render_json(&Envelope::<()>::err_raw(
                "enroll_owner_key.expected_address_invalid",
                format!("--expected-address is not a valid G-strkey: {expected}"),
            ));
            return 1;
        }
        if expected != owner_address {
            render::render_json(&Envelope::<()>::err_raw(
                "enroll_owner_key.expected_address_mismatch",
                format!(
                    "the seed in '{}' derives to {owner_address}, which does not match \
                     --expected-address {expected}; no entry was written",
                    args.secret_env
                ),
            ));
            return 1;
        }
    }

    // ── Overwrite protection ──────────────────────────────────────────────────
    let entry = match KeyringEntry::new(&owner_coord.service, &owner_coord.account) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("enroll-owner-key: keyring entry construction failed");
            render::render_json(&Envelope::<()>::err(
                &stellar_agent_network::keyring::map_keyring_operation_error(
                    &e,
                    KeyringOperation::Construct,
                    &owner_coord.service,
                ),
            ));
            return 1;
        }
    };

    let existing_present = match entry.get_password() {
        // Probe for existence only. The stored value is NOT decoded or rendered:
        // the legacy rotate-owner-key wrote the owner SEED here in the same
        // base64 encoding, and a curve-point check cannot distinguish a seed
        // from a public key (~half of random seeds are valid points), so
        // decoding could leak the private key. `--force` gating needs only the
        // boolean.
        Ok(_existing) => true,
        Err(keyring_core::Error::NoEntry) => false,
        Err(e) => {
            tracing::debug!("enroll-owner-key: existence probe failed");
            render::render_json(&Envelope::<()>::err(
                &stellar_agent_network::keyring::map_keyring_operation_error(
                    &e,
                    KeyringOperation::Read,
                    &owner_coord.service,
                ),
            ));
            return 1;
        }
    };

    if existing_present && !args.force {
        render::render_json(&Envelope::<()>::err_raw(
            "enroll_owner_key.entry_exists",
            format!(
                "an owner key is already enrolled at keyring service '{}' account '{}'; \
                 pass --force to replace it (this invalidates every policy file signed by \
                 the previous owner key)",
                owner_coord.service, owner_coord.account
            ),
        ));
        return 1;
    }

    // Hold the pin lock through the owner write so a concurrent load cannot
    // change the owner that authorizes this enrollment.
    let rotation_lock = match authorize_owner_write(&profile, &profile_name, &owner_pubkey.0) {
        Ok(lock) => lock,
        Err(refusal) => {
            render::render_json(&refusal);
            return 1;
        }
    };

    // ── Write the PUBLIC key to the owner coordinate as its G-strkey ──────────
    // A G-strkey decodes as URL-safe base64 to 42 bytes, so no 32-byte
    // symmetric-key loader accepts this entry. Every owner reader decodes it.
    // Wrap in Zeroizing for uniformity though the public key is non-secret.
    let encoded: Zeroizing<String> = Zeroizing::new(
        stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner_pubkey.0),
    );
    if let Err(e) = entry.set_password(&encoded) {
        tracing::debug!("enroll-owner-key: set_password failed");
        // Classify the write failure: a non-interactive Windows session must
        // surface as auth.keyring_interactive_session_required, not "not
        // found".
        render::render_json(&Envelope::<()>::err(
            &stellar_agent_network::keyring::map_keyring_operation_error(
                &e,
                KeyringOperation::Write,
                &owner_coord.service,
            ),
        ));
        return 1;
    }

    drop(rotation_lock);

    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &profile_name,
        "profile_enroll_owner_key",
        KeyPurpose::OwnerPublicKey,
        &owner_coord,
        Some(RedactedStrkey::from_full(&owner_address)),
        &request_id,
    );

    // Info-level log omits the address and coordinate to avoid leaking operator
    // topology; the JSON envelope carries the full detail.
    tracing::info!("owner key enrolled for profile '{profile_name}'");
    render::render_json(&Envelope::ok(EnrollOwnerKeyData {
        profile: profile_name.clone(),
        enrolled: true,
        owner_address,
        keyring_service: owner_coord.service,
        keyring_account: owner_coord.account,
        replaced: existing_present,
    }));
    0
}

/// Authorizes the owner entry write of an installation that holds owner
/// continuity records and returns the pin lock to hold across it; `None` when
/// it holds none.
///
/// The records are the mainnet enablement nonce and the policy pin. The
/// profile's configured window-state entry is checked when it holds either
/// one. Its default entry `stellar-agent-policy-window-<profile>` / `default`,
/// when it differs, is checked when it holds a nonce, whatever chain the
/// profile file names: a nonce exists only after `profile enable-mainnet`, and
/// a mainnet profile cannot move its window-state entry, so an edit of the
/// chain or of the window-state entry in the profile file does not hide the
/// records of an enabled installation. A pin alone at that default entry is
/// left to the pin rule of the next load there. Each checked coordinate must
/// hold a present pin. The pinned owner may always be written back; any other key
/// needs the installed policy signed by that key with a valid statement from
/// the pinned owner. A missing owner entry is no exception.
///
/// # Errors
///
/// The refusal envelope: `enroll_owner_key.rotation_statement_required` for
/// an absent or invalid statement or a policy the key does not sign,
/// `policy.pin_absent` naming a missing lock file or a missing pin, and the
/// own code of every other cause, such as `policy.state_lock_busy`,
/// `policy.state_lock_io`, `policy.pin_unusable`,
/// `profile.mainnet_enablement_invalid` for an unreadable nonce entry, or
/// `policy.sequence_rollback`.
fn authorize_owner_write(
    profile: &Profile,
    profile_name: &str,
    new_owner: &[u8; 32],
) -> Result<Option<stellar_agent_core::policy::state_lock::WindowStoreLock>, Envelope<()>> {
    use stellar_agent_core::{
        mainnet::enablement::has_enablement_nonce,
        policy::{PolicyError, pin},
    };
    let configured = profile.policy_window_state_key_id.clone();
    let default = KeyringEntryRef::default_policy_window_state_key(profile_name);
    let mut coordinates = vec![(configured, true)];
    if coordinates[0].0 != default {
        coordinates.push((default, false));
    }
    let mut held = None;
    for (coordinate, is_configured) in coordinates {
        let mut scoped = profile.clone();
        scoped.policy_window_state_key_id = coordinate;
        let nonce = has_enablement_nonce(&scoped)
            .map_err(|error| Envelope::<()>::err(&WalletError::from(error)))?;
        // A pin alone selects only the configured coordinate: the pin rule
        // guards it on the next load there. At a distinct default coordinate
        // only a nonce selects, and its pin entry is read only then.
        let pin = if is_configured || nonce {
            pin::entry_present(&scoped.policy_window_state_key_id)
                .map_err(|e| policy_refusal(PolicyError::from(e)))?
        } else {
            false
        };
        if nonce || pin {
            // Every coordinate shares the store's one lock file: release the
            // previous guard before taking the next.
            drop(held.take());
            held = Some(authorize_at(&scoped, profile_name, new_owner, nonce, pin)?);
        }
    }
    Ok(held)
}

/// The refusal envelope of a policy error in [`authorize_owner_write`]: the
/// statement and signature causes as
/// `enroll_owner_key.rotation_statement_required`, every other cause with its
/// own code.
fn policy_refusal(error: stellar_agent_core::policy::PolicyError) -> Envelope<()> {
    use stellar_agent_core::policy::PolicyError;
    match error {
        PolicyError::OwnerRotationRequired
        | PolicyError::OwnerRotationInvalid
        | PolicyError::OwnerSignatureInvalid { .. } => Envelope::<()>::err_raw(
            "enroll_owner_key.rotation_statement_required",
            format!(
                "install a policy signed by the new owner with a valid owner_rotation statement \
                 from the pinned owner before enrollment ({}); no entry was written",
                error.wire_code()
            ),
        ),
        other => {
            Envelope::<()>::err_raw(other.wire_code(), format!("{other}; no entry was written"))
        }
    }
}

/// Applies the enabled-installation rules at the window-state coordinate of
/// `scoped`, which holds an enablement nonce (`nonce`) or a pin entry
/// (`pin`), and returns the lock the pin was read under.
fn authorize_at(
    scoped: &Profile,
    profile_name: &str,
    new_owner: &[u8; 32],
    nonce: bool,
    pin: bool,
) -> Result<stellar_agent_core::policy::state_lock::WindowStoreLock, Envelope<()>> {
    use stellar_agent_core::{
        policy::{
            PolicyError,
            pin::{self, PinScope, PinState},
            v1::verified::{
                OwnerKeySource, PolicyLoad, acquire_existing_state_lock, check_owner_enrollment,
            },
        },
        profile::schema::{
            default_policy_dir, default_policy_window_state_path_for, mainnet_enablement_entry_ref,
            policy_pin_entry_ref,
        },
    };
    let window_key = &scoped.policy_window_state_key_id;
    let pin_absent = || {
        let pin_entry = policy_pin_entry_ref(window_key);
        let detail = if nonce {
            let nonce_entry = mainnet_enablement_entry_ref(window_key);
            format!(
                "profile '{profile_name}' holds a mainnet enablement nonce at keyring service \
                 '{}' account '{}' but stores no policy pin at account '{}'; remove the nonce \
                 entry with the platform keyring tool, run `stellar-agent profile \
                 enable-mainnet --profile {profile_name}`, and sign the rebound policy",
                nonce_entry.service, nonce_entry.account, pin_entry.account
            )
        } else {
            format!(
                "profile '{profile_name}' stores no policy pin at keyring service '{}' account \
                 '{}' any more",
                pin_entry.service, pin_entry.account
            )
        };
        Envelope::<()>::err_raw(
            PolicyError::PinAbsent.wire_code(),
            format!("{detail}; no entry was written"),
        )
    };
    if !pin {
        return Err(pin_absent());
    }
    let window = default_policy_window_state_path_for(profile_name);
    let Some(lock) = acquire_existing_state_lock(&window, scoped).map_err(policy_refusal)? else {
        return Err(Envelope::<()>::err_raw(
            PolicyError::PinAbsent.wire_code(),
            format!(
                "the policy-state lock file of profile '{profile_name}' is missing, so its \
                 policy pin cannot be read; a command that builds the V1 policy engine \
                 recreates the lock file; no entry was written"
            ),
        ));
    };
    let PinState::Present(pinned) = pin::read(&lock, &PinScope::for_profile(&window, scoped))
        .map_err(|e| policy_refusal(PolicyError::from(e)))?
    else {
        return Err(pin_absent());
    };
    let path = default_policy_dir()
        .map_err(|e| {
            policy_refusal(PolicyError::PolicyFileLoadFailed {
                detail: format!("policy directory: {e}"),
            })
        })?
        .join(format!("{profile_name}.toml"));
    check_owner_enrollment(
        &PolicyLoad {
            path: &path,
            profile: scoped,
            profile_name,
            owner_pubkey: new_owner,
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        },
        &pinned,
    )
    .map_err(policy_refusal)?;
    Ok(lock)
}

/// Resolves the owner keyring coordinate the V1 engine reads for `profile`.
///
/// Mirrors the engine: recover the profile name from
/// `policy_owner_key_id.service`, then rebuild
/// `default_owner_key(profile_name)` so the account is the literal `"default"`
/// the engine uses.
///
/// Binding: [`derive_profile_name_from_owner_key`] is the single
/// implementation of the strip, and `default_owner_key` is the single
/// implementation of its inverse. Enrolment must target the exact coordinate
/// the engine reads.
///
/// The profile reaching this point has already been reconciled against the
/// requested name, so the key is enrolled under the name the operator
/// selected — never under another profile's trust anchor.
fn owner_coordinate(profile: &Profile) -> Result<KeyringEntryRef, String> {
    let service = &profile.policy_owner_key_id.service;
    let profile_name = derive_profile_name_from_owner_key(profile).ok_or_else(|| {
        format!(
            "the profile's owner-key service '{service}' does not start with the expected \
             prefix '{OWNER_KEY_SERVICE_PREFIX}'; the profile was not constructed with the \
             standard owner coordinate and cannot be enrolled"
        )
    })?;
    Ok(KeyringEntryRef::default_owner_key(profile_name))
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

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    /// Deterministic `(S-strkey, derived G-strkey, pubkey bytes)` for a fixed
    /// 32-byte seed.
    fn seed_material(seed: [u8; 32]) -> (String, String, [u8; 32]) {
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let pk_bytes = verifying.to_bytes();
        let g = stellar_strkey::ed25519::PublicKey(pk_bytes)
            .to_string()
            .to_string();
        (s_strkey, g, pk_bytes)
    }

    /// Builds an in-memory testnet profile whose owner coordinate service is
    /// `stellar-agent-owner-<profile_name>` (the standard form), disjoint per
    /// test via the profile name.
    fn profile_for(profile_name: &str) -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer",
            "default",
            "stellar-agent-nonce",
            "default",
        )
        .with_profile_name(profile_name)
        .build()
    }

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        var: String,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(var: String, value: &str) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(&var, value);
            }
            Self { var }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(&self.var);
            }
        }
    }

    fn args(
        profile: &str,
        secret_env: &str,
        expected: Option<&str>,
        force: bool,
    ) -> EnrollOwnerKeyArgs {
        EnrollOwnerKeyArgs {
            profile: Some(profile.to_owned()),
            secret_env: secret_env.to_owned(),
            expected_address: expected.map(str::to_owned),
            force,
        }
    }

    fn unique_var(tag: &str) -> String {
        format!("ENROLL_OWNER_KEY_TEST_{tag}_{}", std::process::id())
    }

    #[tokio::test]
    #[serial]
    async fn enroll_happy_path_stores_pubkey_the_engine_can_read() {
        keyring_mock::install().expect("mock store");
        let profile_name = "enroll-owner-happy";
        let (s_strkey, derived_g, pk_bytes) = seed_material([0x11u8; 32]);
        let var = unique_var("HAPPY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_for(profile_name);
        let coord = KeyringEntryRef::default_owner_key(profile_name);

        let code = run_with_dependencies(
            &args(profile_name, &var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed on a clean owner coordinate");

        // The stored value is the PUBLIC key's G-strkey, which the engine
        // decodes and no 32-byte symmetric loader accepts.
        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        let stored = entry.get_password().expect("owner key must be present");
        assert!(
            stored == derived_g,
            "the stored value is the owner G-strkey"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.decode(stored.trim()).map(|b| b.len()).ok(),
            Some(42),
            "a G-strkey decodes as URL-safe base64 to 42 bytes"
        );
        let decoded = stellar_agent_core::profile::owner_key::decode_owner_public_key(&stored)
            .expect("the engine decodes the stored form");
        assert!(decoded == pk_bytes, "stored value must be the public key");
        assert!(
            decoded != [0x11u8; 32],
            "stored value must be the public key, never the seed"
        );
    }

    /// Enrollment leaves every sibling owner entry byte-identical.
    #[tokio::test]
    #[serial]
    async fn enroll_preserves_other_profiles_older_form_entries() {
        keyring_mock::install().expect("mock store");
        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let profile_dir =
            stellar_agent_core::profile::schema::default_profile_dir().expect("profile dir");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let (_s_b, _g_b, pk_b) = seed_material([0x51u8; 32]);
        let (_s_c, g_c, _pk_c) = seed_material([0x52u8; 32]);
        for (name, value) in [
            ("enroll-other-b", URL_SAFE_NO_PAD.encode(pk_b)),
            ("enroll-other-c", g_c.clone()),
        ] {
            std::fs::write(profile_dir.join(format!("{name}.toml")), "").unwrap();
            let coord = KeyringEntryRef::default_owner_key(name);
            KeyringEntry::new(&coord.service, &coord.account)
                .unwrap()
                .set_password(&value)
                .unwrap();
        }

        let profile_name = "enroll-owner-siblings";
        let (s_strkey, _g, _pk) = seed_material([0x53u8; 32]);
        let var = unique_var("SIBLINGS");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let profile = profile_for(profile_name);
        let code = run_with_dependencies(
            &args(profile_name, &var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0);

        let read = |name: &str| {
            let coord = KeyringEntryRef::default_owner_key(name);
            KeyringEntry::new(&coord.service, &coord.account)
                .unwrap()
                .get_password()
                .unwrap()
        };
        assert_eq!(read("enroll-other-b"), URL_SAFE_NO_PAD.encode(pk_b));
        assert!(read("enroll-other-c") == g_c, "the stored form is left");
    }

    #[tokio::test]
    #[serial]
    async fn expected_address_mismatch_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let profile_name = "enroll-owner-expected";
        let (s_strkey, _derived_g, _pk) = seed_material([0x22u8; 32]);
        let var = unique_var("EXPECTED");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_for(profile_name);
        let coord = KeyringEntryRef::default_owner_key(profile_name);

        let (_other_s, other_g, _other_pk) = seed_material([0x33u8; 32]);

        let code = run_with_dependencies(
            &args(profile_name, &var, Some(&other_g), false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "a mismatched --expected-address must refuse");

        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no entry must be written on expected-address mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn overwrite_without_force_is_refused() {
        keyring_mock::install().expect("mock store");
        let profile_name = "enroll-owner-noforce";
        let (s_strkey, _g, _pk) = seed_material([0x44u8; 32]);
        let var = unique_var("NOFORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_for(profile_name);
        let coord = KeyringEntryRef::default_owner_key(profile_name);

        let pre = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        pre.set_password("preexisting-sentinel").unwrap();

        let code = run_with_dependencies(
            &args(profile_name, &var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "enroll must refuse to overwrite without --force");

        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        assert!(
            entry.get_password().unwrap() == "preexisting-sentinel",
            "the existing entry must be left untouched"
        );
    }

    #[tokio::test]
    #[serial]
    async fn force_replaces_existing_entry() {
        keyring_mock::install().expect("mock store");
        let profile_name = "enroll-owner-force";
        let (s_strkey, derived_g, pk_bytes) = seed_material([0x11u8; 32]);
        let var = unique_var("FORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_for(profile_name);
        let coord = KeyringEntryRef::default_owner_key(profile_name);

        // Pre-seed with a different valid public key.
        let (_other_s, other_g, _other_pk) = seed_material([0x66u8; 32]);
        let pre = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        pre.set_password(&other_g).unwrap();
        assert_ne!(derived_g, other_g);

        let code = run_with_dependencies(
            &args(profile_name, &var, None, true),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "--force must replace the existing entry");

        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        let stored = entry.get_password().unwrap();
        assert!(
            stored == derived_g,
            "coordinate must hold the new public key"
        );
        let decoded =
            stellar_agent_core::profile::owner_key::decode_owner_public_key(&stored).unwrap();
        assert!(
            decoded == pk_bytes,
            "coordinate must hold the new public key"
        );
    }

    #[tokio::test]
    #[serial]
    async fn enroll_nonexistent_profile_returns_exit_1() {
        let args = EnrollOwnerKeyArgs {
            profile: Some("__nonexistent_enroll_owner_key__".to_owned()),
            secret_env: "__UNSET_ENROLL_OWNER_KEY_VAR__".to_owned(),
            expected_address: None,
            force: false,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
    /// An enabled mainnet installation of profile `operator` under a fresh
    /// data root: the owner `[31; 32]` enrolled, its signed v2 policy at
    /// sequence 7 pinned, then the enablement nonce stored, in the order
    /// `profile enable-mainnet` keeps. `var` holds the seed `[32; 32]` of the
    /// candidate owner and `previous_var` the enrolled owner's seed.
    struct Enabled {
        _dir: tempfile::TempDir,
        _home: stellar_agent_test_support::StellarAgentHomeGuard,
        profile: Profile,
        owner_entry: KeyringEntry,
        nonce_entry: KeyringEntry,
        path: std::path::PathBuf,
        window: std::path::PathBuf,
        body: String,
        old: ed25519_dalek::SigningKey,
        new: ed25519_dalek::SigningKey,
        old_value: String,
        var: String,
        previous_var: String,
        _secrets: [EnvGuard; 2],
    }
    const NONCE: &str = "test-enablement-nonce";
    impl Enabled {
        fn new() -> Self {
            use sha2::Digest as _;
            use stellar_agent_core::{
                mainnet::enablement::{read_enablement_nonce, verify_enablement},
                policy::v1::{
                    PolicyStateStore,
                    verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
                },
                profile::{
                    name::ProfileNameSource,
                    schema::{
                        default_policy_dir, default_policy_window_state_path_for,
                        default_profile_dir, mainnet_enablement_entry_ref,
                    },
                },
            };
            keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
            let signer = stellar_strkey::ed25519::PublicKey([2; 32])
                .to_string()
                .to_string();
            let mut profile = Profile::builder_mainnet_named(
                "operator",
                "https://rpc.example.invalid",
                "stellar-agent-signer-operator",
                &signer,
                "stellar-agent-nonce-operator",
                "default",
            )
            .primary_provider(
                stellar_agent_core::profile::schema::PrimaryProviderRecord::new(
                    "Primary operator",
                    "rpc.example.invalid",
                ),
            )
            .oracle_provider_url(url::Url::parse("https://oracle.example.invalid").unwrap())
            .oracle_provider(stellar_agent_core::profile::schema::ProviderRecord::new(
                "Oracle operator",
                "oracle.example.invalid",
                true,
            ))
            .build();
            profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
            let identity = stellar_agent_core::profile::schema::signer_identity_entry_ref(
                &profile.mcp_signer_default,
            );
            KeyringEntry::new(&identity.service, &identity.account)
                .unwrap()
                .set_password(
                    &stellar_agent_core::profile::signer_identity::SignerIdentityRecord::agent(
                        [2; 32],
                    )
                    .render(),
                )
                .unwrap();
            let profiles = default_profile_dir().unwrap();
            loader::save_to_dir("operator", &profile, &profiles).unwrap();
            let path = default_policy_dir().unwrap().join("operator.toml");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let window = default_policy_window_state_path_for("operator");
            std::fs::create_dir_all(window.parent().unwrap()).unwrap();
            let old = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
            let new = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
            let owner_coord = KeyringEntryRef::default_owner_key("operator");
            let owner_entry =
                KeyringEntry::new(&owner_coord.service, &owner_coord.account).unwrap();
            let old_value = stellar_strkey::ed25519::PublicKey(old.verifying_key().to_bytes())
                .to_string()
                .to_string();
            owner_entry.set_password(&old_value).unwrap();
            let body = include_str!("../../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
                .replace(
                    &"0".repeat(64),
                    &stellar_agent_core::hex::encode(&sha2::Sha256::digest(NONCE.as_bytes())),
                );
            std::fs::write(&path, signed(&body, &old)).unwrap();
            let verified = load_verified_policy(
                &PolicyLoad {
                    path: &path,
                    profile: &profile,
                    profile_name: "operator",
                    owner_pubkey: &old.verifying_key().to_bytes(),
                    owner_source: OwnerKeySource::Keyring,
                    window_path: &window,
                },
                PolicyStateStore::new(),
                PinMode::Advance,
            )
            .unwrap();
            let coord = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
            let nonce_entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
            nonce_entry.set_password(NONCE).unwrap();
            verify_enablement(
                &verified,
                "operator",
                ProfileNameSource::Flag,
                &profile,
                &profiles,
                &read_enablement_nonce,
            )
            .unwrap();
            let var = unique_var("ROTATION");
            let previous_var = unique_var("PREVIOUS");
            let secrets = [
                EnvGuard::set(var.clone(), &seed_material([32; 32]).0),
                EnvGuard::set(previous_var.clone(), &seed_material([31; 32]).0),
            ];
            Self {
                _dir: dir,
                _home: home,
                profile,
                owner_entry,
                nonce_entry,
                path,
                window,
                body,
                old,
                new,
                old_value,
                var,
                previous_var,
                _secrets: secrets,
            }
        }
        /// The policy at `sequence` with a statement from the pinned owner
        /// to the candidate owner, before its `[signature]`.
        fn rotation(&self, sequence: i64) -> String {
            let body = self
                .body
                .replace("sequence = 7", &format!("sequence = {sequence}"));
            let mut doc = body.parse::<toml_edit::DocumentMut>().unwrap();
            doc["owner_rotation"] = toml_edit::Item::Table(
                stellar_agent_core::policy::v1::signature::build_owner_rotation(
                    &body,
                    &self.old,
                    &self.new.verifying_key().to_bytes(),
                )
                .unwrap(),
            );
            doc.to_string()
        }
        fn pin(&self) -> stellar_agent_core::policy::pin::PinState {
            stellar_agent_core::policy::v1::verified::read_pin_without_creating(
                &self.window,
                &self.profile,
            )
            .unwrap()
        }
        /// Runs the enrollment against the stored profile file.
        async fn enroll(&self, var: &str, force: bool) -> (i32, Vec<serde_json::Value>) {
            enroll_stored(var, force).await
        }
    }
    /// Runs the enrollment of profile `operator` against its stored profile
    /// file and returns the exit code and the rendered envelopes.
    async fn enroll_stored(var: &str, force: bool) -> (i32, Vec<serde_json::Value>) {
        render::take_rendered_for_test();
        let code = run_with_dependencies(
            &args("operator", var, None, force),
            |name| {
                loader::load_from_dir(
                    name,
                    &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
                    None,
                )
            },
            || Ok(()),
        )
        .await;
        (code, render::take_rendered_for_test())
    }
    /// A testnet v2 policy body of profile `operator` at `sequence`, before
    /// its `[signature]`.
    fn testnet_body(sequence: i64) -> String {
        format!(
            "version = 2\nscope = \"profile:operator\"\nsequence = {sequence}\n\
             [[rules]]\nmatch = {{tool = \"stellar_balances\", chain = \"*\"}}\n\
             criteria = []\ndecision = \"allow\"\n"
        )
    }
    /// The testnet profile `operator` with the window-state key `window`.
    fn testnet_operator(window: Option<KeyringEntryRef>) -> Profile {
        let signer = stellar_strkey::ed25519::PublicKey([2; 32])
            .to_string()
            .to_string();
        let mut profile = Profile::builder_testnet_named(
            "operator",
            "stellar-agent-signer-operator",
            &signer,
            "stellar-agent-nonce-operator",
            "default",
        )
        .build();
        profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
        if let Some(window) = window {
            profile.policy_window_state_key_id = window;
        }
        profile
    }
    /// Loads the policy at `path` for `profile` under `key` in
    /// `PinMode::Advance`.
    fn advance(
        path: &std::path::Path,
        window: &std::path::Path,
        profile: &Profile,
        key: &ed25519_dalek::SigningKey,
    ) {
        use stellar_agent_core::policy::v1::{
            PolicyStateStore,
            verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
        };
        load_verified_policy(
            &PolicyLoad {
                path,
                profile,
                profile_name: "operator",
                owner_pubkey: &key.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: window,
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
    }
    fn signed(raw: &str, key: &ed25519_dalek::SigningKey) -> String {
        use stellar_agent_core::policy::v1::{
            canonical::canonical_bytes,
            signature::{digest, sign},
        };
        format!(
            "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()),
            stellar_agent_core::hex::encode(&sign(&digest(&canonical_bytes(raw).unwrap()), key))
        )
    }

    #[tokio::test]
    #[serial]
    async fn enabled_owner_enrollment_requires_an_installed_valid_rotation() {
        let f = Enabled::new();
        let before = f.pin();
        assert!(matches!(
            before,
            stellar_agent_core::policy::pin::PinState::Present(_)
        ));
        let valid = f.rotation(8);
        for defect in [
            "absent",
            "forged",
            "wrong_owner",
            "changed_body",
            "outer_signature",
            "valid",
        ] {
            let mut doc = valid.parse::<toml_edit::DocumentMut>().unwrap();
            match defect {
                "absent" => {
                    doc.remove("owner_rotation");
                }
                "forged" => doc["owner_rotation"]["sig"] = toml_edit::value("00".repeat(64)),
                "wrong_owner" => {
                    doc["owner_rotation"]["new_owner"] = toml_edit::value(f.old_value.clone())
                }
                "changed_body" => doc["sequence"] = toml_edit::value(9),
                _ => {}
            }
            let key = if defect == "outer_signature" {
                &f.old
            } else {
                &f.new
            };
            let installed = signed(&doc.to_string(), key);
            std::fs::write(&f.path, &installed).unwrap();
            let (code, output) = f.enroll(&f.var, true).await;
            if defect == "valid" {
                assert_eq!(code, 0, "{output:?}");
                assert_eq!(
                    f.owner_entry.get_password().unwrap(),
                    stellar_strkey::ed25519::PublicKey(f.new.verifying_key().to_bytes())
                        .to_string()
                        .to_string()
                );
            } else {
                assert_eq!(code, 1, "{defect}: {output:?}");
                assert_eq!(
                    output[0]["error"]["code"], "enroll_owner_key.rotation_statement_required",
                    "{defect}"
                );
                assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value);
            }
            assert_eq!(std::fs::read_to_string(&f.path).unwrap(), installed);
            assert_eq!(f.pin(), before);
            assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE);
        }
    }

    /// The pin authorizes its own owner: a lost owner entry of an enabled
    /// installation is restored by enrolling the pinned key, with or without
    /// `--force`, while another key without a statement stays refused.
    #[tokio::test]
    #[serial]
    async fn enrolling_the_pinned_owner_restores_a_lost_owner_entry() {
        let f = Enabled::new();
        let before = f.pin();
        f.owner_entry.delete_credential().unwrap();
        let (code, output) = f.enroll(&f.var, false).await;
        assert_eq!(code, 1, "{output:?}");
        assert_eq!(
            output[0]["error"]["code"],
            "enroll_owner_key.rotation_statement_required"
        );
        assert!(matches!(
            f.owner_entry.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        let (code, output) = f.enroll(&f.previous_var, false).await;
        assert_eq!(code, 0, "{output:?}");
        assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value);
        let (code, output) = f.enroll(&f.previous_var, true).await;
        assert_eq!(code, 0, "{output:?}");
        assert_eq!(output[0]["data"]["replaced"], true);
        assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value);
        assert_eq!(f.pin(), before);
        assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE);
    }

    /// Each cause other than the statement keeps its own code, and none
    /// writes the owner entry.
    #[tokio::test]
    #[serial]
    async fn enrollment_refusals_keep_their_causes() {
        use stellar_agent_core::policy::state_lock::{WindowStoreLock, window_lock_path};
        let f = Enabled::new();
        std::fs::write(&f.path, signed(&f.rotation(8), &f.new)).unwrap();
        let lock_path = window_lock_path(&f.window);
        let pin_coord = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &f.profile.policy_window_state_key_id,
        );
        let pin_entry = KeyringEntry::new(&pin_coord.service, &pin_coord.account).unwrap();
        let stored_pin = pin_entry.get_password().unwrap();
        let installed = std::fs::read_to_string(&f.path).unwrap();
        for (cause, code, text) in [
            (
                "nonce_unreadable",
                "profile.mainnet_enablement_invalid",
                "nonce",
            ),
            ("lock_busy", "policy.state_lock_busy", ""),
            ("lock_io", "policy.state_lock_io", ""),
            ("lock_missing", "policy.pin_absent", "lock file"),
            ("pin_missing", "policy.pin_absent", "stores no policy pin"),
            ("pin_unusable", "policy.pin_unusable", ""),
            ("pin_unreadable_without_nonce", "policy.pin_unusable", ""),
            (
                "policy_missing",
                "policy.policy_file_load_failed",
                "operator.toml",
            ),
            ("rollback", "policy.sequence_rollback", ""),
        ] {
            let mut held = None;
            match cause {
                "nonce_unreadable" => {
                    let coord = stellar_agent_core::profile::schema::mainnet_enablement_entry_ref(
                        &f.profile.policy_window_state_key_id,
                    );
                    keyring_mock::inject_error(
                        &coord.service,
                        &coord.account,
                        keyring_core::Error::BadStoreFormat("injected read failure".into()),
                    )
                    .unwrap();
                }
                "lock_busy" => {
                    held = Some(
                        WindowStoreLock::acquire_for(
                            &f.window,
                            &f.profile.policy_window_state_key_id,
                        )
                        .unwrap(),
                    );
                }
                "lock_io" => {
                    std::fs::remove_file(&lock_path).unwrap();
                    std::fs::create_dir(&lock_path).unwrap();
                }
                "lock_missing" => std::fs::remove_file(&lock_path).unwrap(),
                "pin_missing" => pin_entry.delete_credential().unwrap(),
                "pin_unusable" => pin_entry.set_password("not a pin").unwrap(),
                "pin_unreadable_without_nonce" => {
                    f.nonce_entry.delete_credential().unwrap();
                    keyring_mock::inject_error(
                        &pin_coord.service,
                        &pin_coord.account,
                        keyring_core::Error::BadStoreFormat("injected read failure".into()),
                    )
                    .unwrap();
                }
                "policy_missing" => std::fs::remove_file(&f.path).unwrap(),
                _ => std::fs::write(&f.path, signed(&f.rotation(6), &f.new)).unwrap(),
            }
            let (status, output) = f.enroll(&f.var, true).await;
            drop(held);
            assert_eq!(status, 1, "{cause}: {output:?}");
            assert_eq!(output[0]["error"]["code"], code, "{cause}: {output:?}");
            let message = output[0]["error"]["message"].as_str().unwrap();
            assert!(message.contains(text), "{cause}: {message}");
            assert_eq!(
                f.owner_entry.get_password().unwrap(),
                f.old_value,
                "{cause}"
            );
            if cause == "pin_unreadable_without_nonce" {
                assert_eq!(pin_entry.get_password().unwrap(), stored_pin, "{cause}");
                assert!(matches!(
                    f.nonce_entry.get_password(),
                    Err(keyring_core::Error::NoEntry)
                ));
                f.nonce_entry.set_password(NONCE).unwrap();
            }
            assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE, "{cause}");
            // Restore the installation for the next cause.
            if lock_path.is_dir() {
                std::fs::remove_dir(&lock_path).unwrap();
            }
            drop(
                WindowStoreLock::acquire_for(&f.window, &f.profile.policy_window_state_key_id)
                    .unwrap(),
            );
            pin_entry.set_password(&stored_pin).unwrap();
            std::fs::write(&f.path, &installed).unwrap();
        }
        let (status, output) = f.enroll(&f.var, true).await;
        assert_eq!(status, 0, "{output:?}");
    }

    /// A window-state key moved in the profile file would select an empty pin
    /// and nonce namespace. The mainnet key-scope check refuses that profile
    /// before enrollment, both forms of the enablement ceremony, a mainnet
    /// verb, and every other verb that reconciles it, so the owner cannot be
    /// re-rooted without a statement.
    #[tokio::test]
    #[serial]
    async fn a_moved_window_state_key_cannot_re_root_an_enabled_profile() {
        use stellar_agent_core::profile::schema::{
            default_profile_dir, mainnet_enablement_entry_ref, policy_pin_entry_ref,
        };
        let f = Enabled::new();
        let mut moved = f.profile.clone();
        moved.policy_window_state_key_id.account = "moved".to_owned();
        let profiles = default_profile_dir().unwrap();
        loader::save_to_dir("operator", &moved, &profiles).unwrap();
        let loaded = loader::load_from_dir("operator", &profiles, None).unwrap();
        assert_eq!(loaded.policy_window_state_key_id.account, "moved");
        let moved_nonce = mainnet_enablement_entry_ref(&loaded.policy_window_state_key_id);
        let moved_pin = policy_pin_entry_ref(&loaded.policy_window_state_key_id);
        let absent = |coord: &KeyringEntryRef| {
            matches!(
                KeyringEntry::new(&coord.service, &coord.account)
                    .unwrap()
                    .get_password(),
                Err(keyring_core::Error::NoEntry)
            )
        };

        // A new owner without a statement.
        let (code, output) = f.enroll(&f.var, true).await;
        assert_eq!(code, 1, "{output:?}");
        assert_eq!(output[0]["error"]["code"], "profile.key_scope_conflict");
        assert!(
            output[0]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("policy_window_state_key_id"),
            "{output:?}"
        );
        assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value);

        // Both forms of the enablement ceremony in the moved namespace.
        #[derive(clap::Parser)]
        struct Command {
            #[command(flatten)]
            args: super::super::enable_mainnet::EnableMainnetArgs,
        }
        let policy = std::fs::read_to_string(&f.path).unwrap();
        let pinned = f.pin();
        for form in [&[][..], &["--rotate"][..]] {
            let command = <Command as clap::Parser>::try_parse_from(
                ["enable-mainnet", "--profile", "operator"]
                    .iter()
                    .chain(form),
            )
            .unwrap();
            let mut audited = false;
            let (refused, detail) = super::super::enable_mainnet::execute(
                &command.args,
                "operator",
                &loaded,
                &profiles,
                &f.path,
                &f.window,
                |_| {
                    audited = true;
                    Ok(())
                },
                |_, _| Ok(()),
            )
            .unwrap_err();
            assert_eq!(refused, "profile.enable_mainnet_precondition", "{form:?}");
            assert!(detail.contains("key_scope"), "{form:?}: {detail}");
            assert!(
                detail.contains("policy_window_state_key_id"),
                "{form:?}: {detail}"
            );
            assert!(!audited, "{form:?}");
            assert!(absent(&moved_nonce), "{form:?}");
            assert!(absent(&moved_pin), "{form:?}");
            assert_eq!(std::fs::read_to_string(&f.path).unwrap(), policy);
            assert_eq!(f.pin(), pinned, "{form:?}");
            assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE, "{form:?}");
        }

        // A mainnet verb of the V1 engine.
        #[derive(clap::Parser)]
        struct Pay {
            #[command(flatten)]
            args: crate::commands::pay::PayArgs,
        }
        let destination = stellar_strkey::ed25519::PublicKey([9; 32])
            .to_string()
            .to_string();
        let pay = <Pay as clap::Parser>::try_parse_from([
            "pay",
            "--profile",
            "operator",
            destination.as_str(),
            "1",
        ])
        .unwrap();
        render::take_rendered_for_test();
        assert_eq!(crate::commands::pay::run(&pay.args).await, 1);
        let output = render::take_rendered_for_test();
        assert_eq!(
            output[0]["error"]["code"], "profile.key_scope_conflict",
            "{output:?}"
        );
        assert!(
            output[0]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("policy_window_state_key_id"),
            "{output:?}"
        );
        assert!(absent(&moved_nonce));
        assert!(absent(&moved_pin));
        assert_eq!(std::fs::read_to_string(&f.path).unwrap(), policy);
        assert_eq!(f.pin(), pinned);

        // Every CLI verb reconciles the loaded profile before it runs.
        let refusal = crate::common::profile_access::reconcile_loaded_profile(
            Ok(loaded),
            &stellar_agent_core::profile::ResolvedProfileName::from_flag("operator"),
        )
        .unwrap_err();
        assert!(
            matches!(
                &refusal,
                crate::common::profile_access::ProfileAccessError::KeyScopeConflict(conflict)
                    if conflict.kind == "window_state_key_override"
            ),
            "{refusal:?}"
        );
        assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value);
        assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE);
    }

    /// An enabled installation whose profile file is edited to testnet with
    /// a moved window-state entry: the edited profile loads, and enrollment
    /// still finds the nonce and the pin at the default entry and applies
    /// the enabled-installation rules. Without a pin it refuses with
    /// `policy.pin_absent`; with one, a key without a statement refuses. The
    /// owner entry, the nonce, and the pin stay unchanged, and nothing is
    /// written at the moved entry.
    #[tokio::test]
    #[serial]
    async fn a_testnet_detour_cannot_re_root_an_enabled_profile() {
        use stellar_agent_core::profile::schema::{
            default_profile_dir, mainnet_enablement_entry_ref, policy_pin_entry_ref,
        };
        for (pin, code) in [
            (false, "policy.pin_absent"),
            (true, "enroll_owner_key.rotation_statement_required"),
        ] {
            let f = Enabled::new();
            if !pin {
                let coord = policy_pin_entry_ref(&f.profile.policy_window_state_key_id);
                KeyringEntry::new(&coord.service, &coord.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            let before = f.pin();
            let signer = stellar_strkey::ed25519::PublicKey([2; 32])
                .to_string()
                .to_string();
            let mut detour = Profile::builder_testnet_named(
                "operator",
                "stellar-agent-signer-operator",
                &signer,
                "stellar-agent-nonce-operator",
                "default",
            )
            .build();
            detour.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
            assert_eq!(
                detour.policy_window_state_key_id,
                KeyringEntryRef::default_policy_window_state_key("operator")
            );
            detour.policy_window_state_key_id.account = "moved".to_owned();
            let profiles = default_profile_dir().unwrap();
            loader::save_to_dir("operator", &detour, &profiles).unwrap();
            let loaded = loader::load_from_dir("operator", &profiles, None).unwrap();
            assert!(!loaded.chain_id.is_mainnet());
            assert_eq!(loaded.policy_window_state_key_id.account, "moved");

            let (status, output) = f.enroll(&f.var, true).await;
            assert_eq!(status, 1, "{pin}: {output:?}");
            assert_eq!(output[0]["error"]["code"], code, "{pin}: {output:?}");
            assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value, "{pin}");
            assert_eq!(f.nonce_entry.get_password().unwrap(), NONCE, "{pin}");
            assert_eq!(f.pin(), before, "{pin}");
            for coord in [
                mainnet_enablement_entry_ref(&loaded.policy_window_state_key_id),
                policy_pin_entry_ref(&loaded.policy_window_state_key_id),
            ] {
                assert!(
                    matches!(
                        KeyringEntry::new(&coord.service, &coord.account)
                            .unwrap()
                            .get_password(),
                        Err(keyring_core::Error::NoEntry)
                    ),
                    "{pin}: {coord:?}"
                );
            }
        }
    }

    /// A policy pin without an enablement nonce at the configured
    /// window-state entry is a continuity record too: on the mainnet profile,
    /// on the same profile edited to testnet, and on a testnet profile whose
    /// custom entry holds the pin while its default entry holds nothing, a
    /// key without a statement refuses and the owner entry and the pin stay
    /// unchanged.
    #[tokio::test]
    #[serial]
    async fn a_pin_without_a_nonce_still_requires_the_statement() {
        use stellar_agent_core::{
            policy::{pin::PinState, v1::verified::read_pin_without_creating},
            profile::schema::{default_profile_dir, policy_pin_entry_ref},
        };
        for case in ["mainnet", "testnet_default", "testnet_custom"] {
            let f = Enabled::new();
            f.nonce_entry.delete_credential().unwrap();
            let profile = match case {
                "mainnet" => f.profile.clone(),
                "testnet_default" => {
                    let testnet = testnet_operator(None);
                    assert_eq!(
                        testnet.policy_window_state_key_id,
                        f.profile.policy_window_state_key_id
                    );
                    testnet
                }
                _ => {
                    let default = policy_pin_entry_ref(&f.profile.policy_window_state_key_id);
                    KeyringEntry::new(&default.service, &default.account)
                        .unwrap()
                        .delete_credential()
                        .unwrap();
                    let testnet = testnet_operator(Some(KeyringEntryRef::new(
                        "stellar-agent-policy-window-operator",
                        "custom",
                    )));
                    std::fs::write(&f.path, signed(&testnet_body(3), &f.old)).unwrap();
                    advance(&f.path, &f.window, &testnet, &f.old);
                    assert_eq!(f.pin(), PinState::Absent);
                    testnet
                }
            };
            if case != "mainnet" {
                loader::save_to_dir("operator", &profile, &default_profile_dir().unwrap()).unwrap();
            }
            let before = read_pin_without_creating(&f.window, &profile).unwrap();
            assert!(matches!(before, PinState::Present(_)), "{case}");
            let (status, output) = f.enroll(&f.var, true).await;
            assert_eq!(status, 1, "{case}: {output:?}");
            assert_eq!(
                output[0]["error"]["code"], "enroll_owner_key.rotation_statement_required",
                "{case}: {output:?}"
            );
            assert_eq!(f.owner_entry.get_password().unwrap(), f.old_value, "{case}");
            assert_eq!(
                read_pin_without_creating(&f.window, &profile).unwrap(),
                before,
                "{case}"
            );
        }
    }

    /// Two successive owner rotations on a testnet profile whose window-state
    /// entry moved after its policy loaded at the default entry: each
    /// enrollment checks the configured pin, which the previous rotation's
    /// load advanced, and the pin left at the default entry does not refuse
    /// it.
    #[tokio::test]
    #[serial]
    async fn successive_testnet_rotations_after_a_window_move_enroll() {
        use stellar_agent_core::{
            policy::{pin::PinState, v1::verified::read_pin_without_creating},
            profile::schema::{
                default_policy_dir, default_policy_window_state_path_for, default_profile_dir,
            },
        };
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let keys = [41_u8, 42, 43].map(|seed| ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
        let address = |key: &ed25519_dalek::SigningKey| {
            stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
                .to_string()
                .to_string()
        };
        let vars = [unique_var("ROTATION_B"), unique_var("ROTATION_C")];
        let _secrets = [
            EnvGuard::set(vars[0].clone(), &seed_material([42; 32]).0),
            EnvGuard::set(vars[1].clone(), &seed_material([43; 32]).0),
        ];
        let profiles = default_profile_dir().unwrap();
        let path = default_policy_dir().unwrap().join("operator.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let window = default_policy_window_state_path_for("operator");
        std::fs::create_dir_all(window.parent().unwrap()).unwrap();
        let owner_coord = KeyringEntryRef::default_owner_key("operator");
        let owner_entry = KeyringEntry::new(&owner_coord.service, &owner_coord.account).unwrap();
        owner_entry.set_password(&address(&keys[0])).unwrap();

        let original = testnet_operator(None);
        loader::save_to_dir("operator", &original, &profiles).unwrap();
        std::fs::write(&path, signed(&testnet_body(1), &keys[0])).unwrap();
        advance(&path, &window, &original, &keys[0]);
        let moved = testnet_operator(Some(KeyringEntryRef::new(
            "stellar-agent-policy-window-operator",
            "moved",
        )));
        loader::save_to_dir("operator", &moved, &profiles).unwrap();
        advance(&path, &window, &moved, &keys[0]);
        let default_pin = read_pin_without_creating(&window, &original).unwrap();

        for (step, var) in vars.iter().enumerate() {
            let (previous, next) = (&keys[step], &keys[step + 1]);
            let sequence = i64::try_from(step).unwrap() + 2;
            let body = testnet_body(sequence);
            let mut doc = body.parse::<toml_edit::DocumentMut>().unwrap();
            doc["owner_rotation"] = toml_edit::Item::Table(
                stellar_agent_core::policy::v1::signature::build_owner_rotation(
                    &body,
                    previous,
                    &next.verifying_key().to_bytes(),
                )
                .unwrap(),
            );
            std::fs::write(&path, signed(&doc.to_string(), next)).unwrap();
            let (code, output) = enroll_stored(var, true).await;
            assert_eq!(code, 0, "step {step}: {output:?}");
            assert_eq!(owner_entry.get_password().unwrap(), address(next));
            advance(&path, &window, &moved, next);
            assert!(matches!(
                read_pin_without_creating(&window, &moved).unwrap(),
                PinState::Present(pin) if pin.sequence() == sequence
                    && pin.owner() == next.verifying_key().to_bytes()
            ));
        }
        assert_eq!(
            read_pin_without_creating(&window, &original).unwrap(),
            default_pin
        );
    }

    /// A testnet profile with a custom window-state entry and no record at
    /// its default entry or its configured one enrolls a new owner with
    /// `--force`.
    #[tokio::test]
    #[serial]
    async fn a_testnet_custom_window_key_without_records_enrolls() {
        keyring_mock::install().expect("mock store");
        let profile_name = "enroll-owner-custom-window";
        let (s_strkey, derived_g, _) = seed_material([0x11u8; 32]);
        let var = unique_var("CUSTOM_WINDOW");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);
        let mut profile = profile_for(profile_name);
        profile.policy_window_state_key_id =
            KeyringEntryRef::new("stellar-agent-policy-window-custom", "custom");
        let coord = KeyringEntryRef::default_owner_key(profile_name);
        let (_, other_g, _) = seed_material([0x66u8; 32]);
        KeyringEntry::new(&coord.service, &coord.account)
            .unwrap()
            .set_password(&other_g)
            .unwrap();

        let code = run_with_dependencies(
            &args(profile_name, &var, None, true),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0);
        assert_eq!(
            KeyringEntry::new(&coord.service, &coord.account)
                .unwrap()
                .get_password()
                .unwrap(),
            derived_g
        );
    }

    /// Profile-name reconciliation refuses an installation owner coordinate before keyring initialization.
    #[tokio::test]
    #[serial]
    async fn installation_coordinate_refuses_without_writing() {
        use crate::common::installation_key_fixture::InstallationKeyFixture;
        let fixture = InstallationKeyFixture::new("stellar-agent-toolsets");
        let name = "pin-coordinate-refusal";
        let mut profile = profile_for(name);
        profile.policy_owner_key_id = fixture.coordinate.clone();
        let code = run_with_dependencies(
            &args(name, "UNUSED_PIN_SEED", None, true),
            |_| Ok(profile.clone()),
            || fixture.init(),
        )
        .await;
        fixture.assert_refused(code);
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0]["error"]["code"], "profile.name_mismatch");
    }
}
