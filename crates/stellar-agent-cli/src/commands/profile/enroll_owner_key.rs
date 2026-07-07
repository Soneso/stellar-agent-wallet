//! `stellar-agent profile enroll-owner-key` — enroll the policy-file owner
//! ed25519 PUBLIC key into the profile's owner keyring entry.
//!
//! The V1 policy engine verifies every policy file against the owner public key
//! it reads from the keyring entry `stellar-agent-owner-<profile>` / `"default"`
//! (see `fetch_owner_pubkey_from_keyring` in `stellar-agent-mcp` and
//! `build_v1_policy_engine` in this crate).  The stored value is a URL-safe
//! base64 (no padding) encoding of the 32-byte ed25519 public key.
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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::Signer as _;
use stellar_agent_network::keyring::init_platform_keyring_store;

use crate::commands::policy_engine::OWNER_KEY_SERVICE_PREFIX;
use crate::common::render;
use crate::common::signer_ceremony::resolve_software_signer_from_env;

/// Arguments for `stellar-agent profile enroll-owner-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct EnrollOwnerKeyArgs {
    /// Profile whose owner public key should be enrolled.
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub(crate) profile: String,

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
    run_with_dependencies(
        args,
        |name| loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
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
    // ── Load profile first, then initialise the keyring store ─────────────────
    let profile = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("failed to load profile '{}': {e}", args.profile),
            });
            render::render_json(&Envelope::<()>::err(&err));
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
        Some(&args.profile),
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
            tracing::debug!(error = %e, "enroll-owner-key: keyring entry construction failed");
            render::render_json(&Envelope::<()>::err(&WalletError::Auth(
                AuthError::KeyringNotFound {
                    name: format!("{}:{}", owner_coord.service, owner_coord.account),
                },
            )));
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
            tracing::debug!(error = %e, "enroll-owner-key: existence probe failed");
            render::render_json(&Envelope::<()>::err(&WalletError::Auth(
                AuthError::KeyringNotFound {
                    name: format!("{}:{}", owner_coord.service, owner_coord.account),
                },
            )));
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

    // ── Write the base64-encoded PUBLIC key to the owner coordinate ───────────
    // The encoding matches `fetch_owner_pubkey_from_keyring` / the V1 engine
    // read path: URL-safe base64, no padding, over the raw 32 public-key bytes.
    // Wrap in Zeroizing for uniformity though the public key is non-secret.
    let encoded: Zeroizing<String> = Zeroizing::new(URL_SAFE_NO_PAD.encode(owner_pubkey.0));
    if let Err(e) = entry.set_password(&encoded) {
        tracing::debug!(error = %e, "enroll-owner-key: set_password failed");
        render::render_json(&Envelope::<()>::err(&WalletError::Auth(
            AuthError::KeyringNotFound {
                name: format!("{}:{}", owner_coord.service, owner_coord.account),
            },
        )));
        return 1;
    }

    // Info-level log omits the address and coordinate to avoid leaking operator
    // topology; the JSON envelope carries the full detail.
    tracing::info!("owner key enrolled for profile '{}'", args.profile);
    render::render_json(&Envelope::ok(EnrollOwnerKeyData {
        profile: args.profile.clone(),
        enrolled: true,
        owner_address,
        keyring_service: owner_coord.service,
        keyring_account: owner_coord.account,
        replaced: existing_present,
    }));
    0
}

/// Resolves the owner keyring coordinate the V1 engine reads for `profile`.
///
/// Mirrors the engine: strip [`OWNER_KEY_SERVICE_PREFIX`] from
/// `policy_owner_key_id.service` to recover the profile name, then rebuild
/// `default_owner_key(profile_name)` so the account is the literal `"default"`
/// the engine uses.
///
/// Binding: the same prefix-strip + `default_owner_key` reconstruction the
/// engine performs in `commands::policy_engine::build_v1_policy_engine`
/// (policy_engine.rs:74/86) and `fetch_owner_pubkey_from_keyring` in
/// `stellar-agent-mcp/src/server.rs:331`. The shared [`OWNER_KEY_SERVICE_PREFIX`]
/// constant is the single source of truth; enrolment must target the exact
/// coordinate the engine reads.
fn owner_coordinate(profile: &Profile) -> Result<KeyringEntryRef, String> {
    let service = &profile.policy_owner_key_id.service;
    let profile_name = service
        .strip_prefix(OWNER_KEY_SERVICE_PREFIX)
        .ok_or_else(|| {
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
            profile: profile.to_owned(),
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

        // The stored value is the base64 PUBLIC key the engine decodes.
        let entry = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        let stored = entry.get_password().expect("owner key must be present");
        let decoded = URL_SAFE_NO_PAD.decode(stored.trim()).expect("valid base64");
        assert_eq!(decoded, pk_bytes, "stored value must be the raw public key");
        assert_ne!(
            decoded, [0x11u8; 32],
            "stored value must be the public key, never the seed"
        );
        // The stored public-key bytes render to the derived owner address.
        let decoded_arr: [u8; 32] = decoded.try_into().expect("32 bytes");
        assert_eq!(
            stellar_strkey::ed25519::PublicKey(decoded_arr)
                .to_string()
                .to_string(),
            derived_g,
            "the stored public key must render to the derived owner address"
        );
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
        assert_eq!(
            entry.get_password().unwrap(),
            "preexisting-sentinel",
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
        let (_other_s, other_g, other_pk) = seed_material([0x66u8; 32]);
        let pre = KeyringEntry::new(&coord.service, &coord.account).unwrap();
        pre.set_password(&URL_SAFE_NO_PAD.encode(other_pk)).unwrap();
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
        let decoded = URL_SAFE_NO_PAD.decode(stored.trim()).unwrap();
        assert_eq!(decoded, pk_bytes, "coordinate must hold the new public key");
    }

    #[tokio::test]
    #[serial]
    async fn enroll_nonexistent_profile_returns_exit_1() {
        let args = EnrollOwnerKeyArgs {
            profile: "__nonexistent_enroll_owner_key__".to_owned(),
            secret_env: "__UNSET_ENROLL_OWNER_KEY_VAR__".to_owned(),
            expected_address: None,
            force: false,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
