//! `stellar-agent profile enroll-signer` — import an operator-held ed25519
//! seed into the profile's MCP signer keyring entry.
//!
//! Every MCP fund-movement tool and the keyring-signing CLI verbs resolve their
//! signer via `signer_from_keyring(&profile.mcp_signer_default, …)`.  That entry
//! stores the seed as an `S…` ed25519 secret-key strkey — the exact form
//! `signer_from_keyring` parses back with `PrivateKey::from_string`.  No other
//! shipped command writes it; on a clean install the entry is absent and all
//! MCP signing fails with `auth.keyring_not_found`.  This command closes that
//! gap: it reads the operator's S-strkey from a named environment variable,
//! derives the public address, and stores the S-strkey at the profile's
//! `mcp_signer_default` coordinate.
//!
//! # Account-as-identity
//!
//! The `mcp_signer_default` coordinate's `account` field is both the keyring
//! account name and the G-strkey identity that `signer_from_keyring` verifies
//! the loaded seed against.  A seed whose derived address does not equal that
//! `account` can never sign, so enrollment refuses when they differ and reports
//! the address the operator must set `account` to.  The operator's profile TOML
//! is never rewritten.
//!
//! # Secret handling
//!
//! The seed is read from the environment through the shared mlock-protected
//! ceremony (`resolve_software_signer_from_env`); the S-strkey string is held
//! only in `Zeroizing` wrappers and written verbatim to the platform keyring.
//! The seed is never returned, logged, or placed in the JSON envelope — only
//! the derived public address (G-strkey) and the keyring coordinate are
//! reported.
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
//!     "public_address": "G...",
//!     "keyring_service": "stellar-agent-signer-default",
//!     "keyring_account": "G...",
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
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::Signer as _;
use stellar_agent_network::keyring::{init_platform_keyring_store, signer_from_keyring};
use uuid::Uuid;

use crate::common::render;
use crate::common::signer_ceremony::resolve_software_signer_from_env;

use super::audit_emit::emit_keyring_key_written;

/// Arguments for `stellar-agent profile enroll-signer`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct EnrollSignerArgs {
    /// Profile whose MCP signer entry should be enrolled.
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub(crate) profile: String,

    /// Name of the environment variable that holds the signer S-strkey.
    ///
    /// The flag takes the variable NAME, never the secret itself.
    #[arg(long, value_name = "VAR")]
    pub(crate) secret_env: String,

    /// Expected signer public address (G-strkey).
    ///
    /// When set, enrollment refuses unless the seed derives to this address —
    /// a guard against enrolling the wrong secret.
    #[arg(long, value_name = "G_STRKEY")]
    pub(crate) expected_address: Option<String>,

    /// Replace an already-enrolled entry.
    ///
    /// Without this flag, enrollment refuses when the keyring coordinate
    /// already holds a value.
    #[arg(long, default_value_t = false)]
    pub(crate) force: bool,
}

/// Success payload for the `enroll-signer` envelope.
#[derive(Debug, Serialize)]
struct EnrollSignerData {
    /// Name of the profile whose signer was enrolled.
    profile: String,
    /// Always `true` on success.
    enrolled: bool,
    /// The G-strkey the enrolled seed derives to.
    public_address: String,
    /// Keyring service coordinate the seed was written to.
    keyring_service: String,
    /// Keyring account coordinate the seed was written to (equals
    /// `public_address`).
    keyring_account: String,
    /// `true` when an existing entry was replaced (`--force`).
    replaced: bool,
    /// The public address the replaced entry resolved to, when a prior entry
    /// existed and its stored value could be parsed.  Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_address: Option<String>,
}

/// Runs `stellar-agent profile enroll-signer`.
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
pub(crate) async fn run(args: &EnrollSignerArgs) -> i32 {
    run_with_dependencies(
        args,
        |name| loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and a
/// spy initialiser so the enrollment path can be exercised against a mock
/// keyring store without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &EnrollSignerArgs,
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

    let entry_ref = &profile.mcp_signer_default;

    // ── Derive the public address from the env S-strkey ───────────────────────
    // Reuses the shared mlock-protected env-seed ceremony; the seed never leaves
    // the ceremony's Zeroizing wrappers.
    let derived_g = match resolve_software_signer_from_env(
        &args.secret_env,
        "profile-enroll-signer",
        Some(&args.profile),
    )
    .await
    {
        Ok(outcome) => match outcome.signer.public_key().await {
            Ok(pk) => pk.to_string().to_string(),
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

    // ── Optional --expected-address guard (no write on mismatch) ──────────────
    if let Some(expected) = args.expected_address.as_deref() {
        if stellar_strkey::ed25519::PublicKey::from_string(expected).is_err() {
            render::render_json(&Envelope::<()>::err_raw(
                "enroll_signer.expected_address_invalid",
                format!("--expected-address is not a valid G-strkey: {expected}"),
            ));
            return 1;
        }
        if expected != derived_g {
            render::render_json(&Envelope::<()>::err_raw(
                "enroll_signer.expected_address_mismatch",
                format!(
                    "the seed in '{}' derives to {derived_g}, which does not match \
                     --expected-address {expected}; no entry was written",
                    args.secret_env
                ),
            ));
            return 1;
        }
    }

    // ── Account-as-identity guard (no write on mismatch) ──────────────────────
    // signer_from_keyring verifies the loaded seed derives to the coordinate's
    // `account`; a seed for a different address could never sign.
    if entry_ref.account != derived_g {
        render::render_json(&Envelope::<()>::err_raw(
            "enroll_signer.account_identity_mismatch",
            format!(
                "profile '{}' enrolls the MCP signer at account '{}', but the supplied seed \
                 derives to '{derived_g}'. Set the profile's mcp_signer_default account to \
                 '{derived_g}' (or supply the seed whose address is '{}') and re-run; no entry \
                 was written.",
                args.profile, entry_ref.account, entry_ref.account
            ),
        ));
        return 1;
    }

    // ── Overwrite protection ──────────────────────────────────────────────────
    let entry = match KeyringEntry::new(&entry_ref.service, &entry_ref.account) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(error = %e, "enroll-signer: keyring entry construction failed");
            render::render_json(&Envelope::<()>::err(&WalletError::Auth(
                AuthError::KeyringNotFound {
                    name: format!("{}:{}", entry_ref.service, entry_ref.account),
                },
            )));
            return 1;
        }
    };

    let existing_present = match entry.get_password() {
        // The probe retrieves the value to test for existence — for an
        // already-enrolled entry that is a live S-strkey. `keyring_core` 1.0.0
        // has no non-retrieving probe, so wrap the retrieved secret in
        // `Zeroizing` to clear the heap allocation instead of dropping a plain
        // `String`.
        Ok(existing) => {
            drop(Zeroizing::new(existing));
            true
        }
        Err(keyring_core::Error::NoEntry) => false,
        Err(e) => {
            tracing::debug!(error = %e, "enroll-signer: existence probe failed");
            render::render_json(&Envelope::<()>::err(&WalletError::Auth(
                AuthError::KeyringNotFound {
                    name: format!("{}:{}", entry_ref.service, entry_ref.account),
                },
            )));
            return 1;
        }
    };

    if existing_present && !args.force {
        render::render_json(&Envelope::<()>::err_raw(
            "enroll_signer.entry_exists",
            format!(
                "an entry is already enrolled at keyring service '{}' account '{}'; \
                 pass --force to replace it",
                entry_ref.service, entry_ref.account
            ),
        ));
        return 1;
    }

    // Derive the address the replaced entry resolves to for the envelope. Reuses
    // the real keyring consumer path; addresses only, never the seed.
    let previous_address: Option<String> = if existing_present {
        match signer_from_keyring(entry_ref, &entry_ref.account).await {
            // `KeyringSignHandle::public_key` returns the cached derived address
            // synchronously and infallibly.
            Ok(handle) => Some(handle.public_key().to_string().to_string()),
            Err(WalletError::Auth(AuthError::SignerKeyMismatch { got, .. })) => Some(got),
            Err(_) => None,
        }
    } else {
        None
    };

    // ── Write the S-strkey verbatim to the keyring coordinate ─────────────────
    let s_strkey: Zeroizing<String> = match std::env::var(&args.secret_env) {
        Ok(v) => Zeroizing::new(v),
        Err(_) => {
            render::render_json(&Envelope::<()>::err(&WalletError::Auth(
                AuthError::KeyringNotFound {
                    name: format!("environment variable '{}' not set", args.secret_env),
                },
            )));
            return 1;
        }
    };
    if let Err(e) = entry.set_password(&s_strkey) {
        tracing::debug!(error = %e, "enroll-signer: set_password failed");
        drop(s_strkey);
        render::render_json(&Envelope::<()>::err(&WalletError::Auth(
            AuthError::KeyringNotFound {
                name: format!("{}:{}", entry_ref.service, entry_ref.account),
            },
        )));
        return 1;
    }
    drop(s_strkey);

    let request_id = Uuid::new_v4().to_string();
    emit_keyring_key_written(
        &profile,
        &args.profile,
        "profile_enroll_signer",
        KeyPurpose::McpSignerSeed,
        entry_ref,
        Some(RedactedStrkey::from_full(&derived_g)),
        &request_id,
    );

    // Info-level log omits the address and coordinate to avoid leaking operator
    // topology; the JSON envelope carries the full detail.
    tracing::info!("MCP signer enrolled for profile '{}'", args.profile);
    render::render_json(&Envelope::ok(EnrollSignerData {
        profile: args.profile.clone(),
        enrolled: true,
        public_address: derived_g,
        keyring_service: entry_ref.service.clone(),
        keyring_account: entry_ref.account.clone(),
        replaced: existing_present,
        previous_address,
    }));
    0
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

    const SIGNER_SERVICE: &str = "stellar-agent-signer-enroll-test";

    /// Deterministic `(S-strkey, derived G-strkey)` for a fixed 32-byte seed.
    fn seed_material(seed: [u8; 32]) -> (String, String) {
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let verifying = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let g = stellar_strkey::ed25519::PublicKey(verifying.to_bytes())
            .to_string()
            .to_string();
        (s_strkey, g)
    }

    /// Builds an in-memory testnet profile whose `mcp_signer_default` account is
    /// `account`, under the test signer service.
    fn profile_with_signer_account(account: &str) -> Profile {
        Profile::builder_testnet_named(
            "enroll-signer-test",
            SIGNER_SERVICE,
            account,
            "stellar-agent-nonce-enroll-test",
            "enroll-signer-test",
        )
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

    fn args(secret_env: &str, expected: Option<&str>, force: bool) -> EnrollSignerArgs {
        EnrollSignerArgs {
            profile: "enroll-signer-test".to_owned(),
            secret_env: secret_env.to_owned(),
            expected_address: expected.map(str::to_owned),
            force,
        }
    }

    fn unique_var(tag: &str) -> String {
        format!("ENROLL_SIGNER_TEST_{tag}_{}", std::process::id())
    }

    #[tokio::test]
    #[serial]
    async fn enroll_happy_path_writes_entry_and_produces_working_signer() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("HAPPY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed on a clean coordinate");

        // The verbatim S-strkey is stored at the coordinate. Compare via a
        // boolean so a failure never prints the secret.
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().expect("entry must be present");
        assert!(
            stored == s_strkey,
            "the stored value must be the verbatim S-strkey"
        );

        // #25 acceptance: the real consumer path resolves a WORKING signer whose
        // derived address matches the enrolled account identity.
        let handle = signer_from_keyring(&entry_ref, &entry_ref.account)
            .await
            .expect("signer_from_keyring must succeed after enroll");
        assert_eq!(handle.public_key().to_string().to_string(), derived_g);
    }

    #[tokio::test]
    #[serial]
    async fn expected_address_mismatch_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x22u8; 32]);
        let var = unique_var("EXPECTED");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // A different, valid G-strkey as the wrong expectation.
        let (_other_s, other_g) = seed_material([0x33u8; 32]);

        let code = run_with_dependencies(
            &args(&var, Some(&other_g), false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "a mismatched --expected-address must refuse");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no entry must be written on expected-address mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn account_identity_mismatch_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, _derived_g) = seed_material([0x44u8; 32]);
        let var = unique_var("IDENTITY");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // Profile's signer account is a DIFFERENT address than the seed derives
        // to — the "account = default / placeholder" failure mode.
        let (_other_s, wrong_account) = seed_material([0x55u8; 32]);
        let profile = profile_with_signer_account(&wrong_account);
        let entry_ref = profile.mcp_signer_default.clone();

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "an account-identity mismatch must refuse");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no entry must be written on account-identity mismatch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn overwrite_without_force_is_refused() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("NOFORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // Pre-seed the coordinate.
        let pre = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        pre.set_password("preexisting-sentinel").unwrap();

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "enroll must refuse to overwrite without --force");

        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
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
        let (s_strkey, derived_g) = seed_material([0x11u8; 32]);
        let var = unique_var("FORCE");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        let profile = profile_with_signer_account(&derived_g);
        let entry_ref = profile.mcp_signer_default.clone();

        // Pre-seed with a different valid S-strkey (deriving to another address)
        // so the previous-address derivation exercises the mismatch branch.
        let (other_s, _other_g) = seed_material([0x66u8; 32]);
        let pre = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        pre.set_password(&other_s).unwrap();

        let code = run_with_dependencies(
            &args(&var, None, true),
            move |_n| Ok(profile.clone()),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "--force must replace the existing entry");

        // Compare via a boolean so a failure never prints the secret.
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().unwrap();
        assert!(
            stored == s_strkey,
            "the coordinate must now hold the newly enrolled S-strkey"
        );
    }

    // Real `run()`: a nonexistent profile bails at the profile-load arm (mapped
    // to `ProfileNotFound`, matching the sibling rotate commands) before any
    // keyring or environment access. Defensive `#[serial]`: even though `run()`
    // early-exits before `init_platform_keyring_store()`, the test binary
    // observes a flaky race (~1 in 30 runs) where an `Arc<CredentialStore>` swap
    // during parallel execution clobbers a sibling `#[serial]` test's mock
    // store, surfacing as `Auth(KeyringNotFound)` for the sibling. Serialising
    // defensively eliminates the cross-test interference at trivial cost.
    #[tokio::test]
    #[serial]
    async fn enroll_nonexistent_profile_returns_exit_1() {
        let args = EnrollSignerArgs {
            profile: "__nonexistent_enroll_signer__".to_owned(),
            secret_env: "__UNSET_ENROLL_SIGNER_VAR__".to_owned(),
            expected_address: None,
            force: false,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
