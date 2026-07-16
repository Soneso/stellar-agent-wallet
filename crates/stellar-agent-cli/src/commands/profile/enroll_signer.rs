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
//! the loaded seed against.  `stellar-agent profile init` mints new profiles
//! with the literal placeholder account `"default"` because the signer's
//! eventual G-strkey is not known until a seed is enrolled.  Enrollment
//! classifies the coordinate from its RAW ON-DISK value
//! (`loader::read_signer_ref`) — never from the environment-merged load, so a
//! transient `STELLAR_AGENT_*` overlay cannot influence what gets persisted
//! into the trust root — and resolves three cases:
//!
//! - **Placeholder** (`account` is exactly the literal `"default"`) — this is
//!   the coordinate's first enrollment.  `loader::pin_signer_account` patches
//!   ONLY `mcp_signer_default.account` in the on-disk document to the derived
//!   G-strkey (every other stored key survives verbatim), BEFORE the keyring
//!   write, so `signer_from_keyring` resolves correctly the moment the
//!   profile is next loaded.  Persisting the account first keeps the flow
//!   convergent: if the process dies between the two writes, the account
//!   already equals the derived address, so re-running enroll-signer takes
//!   the "pinned" branch below and simply retries the keyring write.  Every
//!   refusal path precedes the pin, so a refused run modifies nothing.
//! - **Pinned** (`account` parses as a G-strkey — set by a prior enrollment,
//!   or by an operator who hand-edited the TOML) — enrollment refuses unless
//!   the supplied seed derives to that exact address, printing the address to
//!   set `account` to.  A different secret can never silently redirect an
//!   already-established signer identity, and the profile TOML is never
//!   rewritten in this branch.
//! - **Malformed** (anything else — a typo'd or truncated strkey, an
//!   M-strkey, stray whitespace) — refused with
//!   `enroll_signer.account_malformed` rather than treated as a placeholder:
//!   a broken pin is surfaced to the operator, never silently replaced.
//!
//! `EnrollSignerData::account_populated` reports which branch a given run took.
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
//!     "replaced": false,
//!     "account_populated": true
//!   },
//!   "request_id": "..."
//! }
//! ```

use std::path::PathBuf;

use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::audit_log::KeyPurpose;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{AuthError, InternalError, ValidationError, WalletError};
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};
use stellar_agent_network::Signer as _;
use stellar_agent_network::keyring::{init_platform_keyring_store, signer_from_keyring};
use uuid::Uuid;

use crate::common::render;
use crate::common::signer_ceremony::resolve_software_signer_from_env;

use super::audit_emit::emit_keyring_key_written;

/// The literal placeholder account minted by `profile init` and the first-run
/// fallback. Only this exact value is populated at enrollment; any other
/// non-G-strkey value is refused as a malformed pin.
const PLACEHOLDER_ACCOUNT: &str = "default";

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
    /// `true` when the profile's on-disk `mcp_signer_default.account` was the
    /// literal placeholder `"default"` and this run pinned it to the derived
    /// public address (patching only that key in the profile file).  `false`
    /// when the account already pinned a G-strkey identity (see
    /// "Account-as-identity" in the module documentation).
    account_populated: bool,
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
        loader::read_signer_ref,
        loader::pin_signer_account,
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader, the raw on-disk
/// signer-ref reader, the single-field pin writer, and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real loader
/// ([`loader::load`], for the audit-emission context only),
/// [`loader::read_signer_ref`] (the raw on-disk read that classification is
/// built on — environment overlays never reach it), and
/// [`loader::pin_signer_account`] (the raw-document patch that writes only
/// `mcp_signer_default.account`). Tests substitute in-memory equivalents so
/// the enrollment path — including the placeholder-account pin, see
/// "Account-as-identity" in the module documentation — can be exercised
/// against a mock keyring store without touching the OS keychain or a
/// persisted profile file.
async fn run_with_dependencies<LoadProfile, ReadRawSignerRef, PinSigner, InitKeyring>(
    args: &EnrollSignerArgs,
    load_profile: LoadProfile,
    read_raw_signer_ref: ReadRawSignerRef,
    pin_signer: PinSigner,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, loader::ProfileLoadError>,
    ReadRawSignerRef: Fn(&str) -> Result<KeyringEntryRef, loader::ProfileLoadError>,
    PinSigner: Fn(&str, &str) -> Result<PathBuf, loader::ProfileSaveError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Load profile first, then initialise the keyring store ─────────────────
    // The env-merged load supplies the audit-emission context at the end of
    // the flow; every enrollment DECISION below uses the raw on-disk signer
    // reference instead, so environment overlays stay load-time-only.
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

    // ── Raw on-disk signer reference ───────────────────────────────────────────
    // Classification (placeholder vs pinned) and the pin itself operate on
    // the stored document alone: a `STELLAR_AGENT_MCP_SIGNER_DEFAULT`
    // environment overlay can redirect a load, but must never influence what
    // enrollment persists into the trust root.
    let signer_ref = match read_raw_signer_ref(&args.profile) {
        Ok(r) => r,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
        Err(e) => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "failed to read the on-disk signer reference for profile '{}': {e}",
                    args.profile
                ),
            });
            render::render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

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

    // ── Account-as-identity resolution ────────────────────────────────────────
    // See "Account-as-identity" in the module documentation, evaluated on the
    // RAW on-disk value: the literal placeholder `"default"` (the value
    // `profile init` and the first-run fallback mint) is populated; a valid
    // G-strkey is a pinned identity (refuse on mismatch, never rewrite); any
    // other value is a malformed pin and is refused rather than replaced.
    let account_is_pinned_identity =
        stellar_strkey::ed25519::PublicKey::from_string(&signer_ref.account).is_ok();

    if account_is_pinned_identity && signer_ref.account != derived_g {
        render::render_json(&Envelope::<()>::err_raw(
            "enroll_signer.account_identity_mismatch",
            format!(
                "profile '{}' enrolls the MCP signer at account '{}', but the supplied seed \
                 derives to '{derived_g}'. Set the profile's mcp_signer_default account to \
                 '{derived_g}' (or supply the seed whose address is '{}') and re-run; no entry \
                 was written.",
                args.profile, signer_ref.account, signer_ref.account
            ),
        ));
        return 1;
    }

    if !account_is_pinned_identity && signer_ref.account != PLACEHOLDER_ACCOUNT {
        render::render_json(&Envelope::<()>::err_raw(
            "enroll_signer.account_malformed",
            format!(
                "profile '{}' names signer account '{}', which is neither the placeholder \
                 '{PLACEHOLDER_ACCOUNT}' nor a valid G-strkey; a malformed pin is refused \
                 rather than replaced. Set the profile's mcp_signer_default account to \
                 '{PLACEHOLDER_ACCOUNT}' (to enroll fresh) or to the signer's G-strkey, then \
                 re-run; no entry was written and the profile was not modified.",
                args.profile, signer_ref.account
            ),
        ));
        return 1;
    }

    let account_populated = !account_is_pinned_identity;

    let entry_ref = KeyringEntryRef::new(signer_ref.service.clone(), derived_g.clone());

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
        match signer_from_keyring(&entry_ref, &entry_ref.account).await {
            // `KeyringSignHandle::public_key` returns the cached derived address
            // synchronously and infallibly.
            Ok(handle) => Some(handle.public_key().to_string().to_string()),
            Err(WalletError::Auth(AuthError::SignerKeyMismatch { got, .. })) => Some(got),
            Err(_) => None,
        }
    } else {
        None
    };

    // ── Placeholder pin: persist the derived address into the TOML ────────────
    // Every refusal path above is write-free; the pin runs only once the
    // enrollment is definitely proceeding, and BEFORE the keyring write. If
    // the process fails between the two writes, the on-disk account already
    // equals the derived address, so a re-run takes the "pinned" branch and
    // simply retries the keyring write — the flow always converges. The pin
    // patches only `mcp_signer_default.account` on the stored document;
    // nothing else in the file changes, and no environment overlay can leak
    // into it.
    if account_populated && let Err(e) = pin_signer(&args.profile, &derived_g) {
        render::render_json(&Envelope::<()>::err(&WalletError::Internal(
            InternalError::UnexpectedState {
                detail: format!(
                    "failed to persist the derived signer address into profile '{}': {e}",
                    args.profile
                ),
            },
        )));
        return 1;
    }

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
        &entry_ref,
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
        account_populated,
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

    /// A `pin_signer` stub that panics if invoked.
    ///
    /// Used by every fixture whose `mcp_signer_default.account` already pins a
    /// G-strkey identity (and by refusal fixtures), asserting those paths
    /// never write the profile TOML (see "Account-as-identity" in the module
    /// documentation).
    fn pin_signer_must_not_be_called(
        _name: &str,
        _account: &str,
    ) -> Result<PathBuf, loader::ProfileSaveError> {
        panic!(
            "pin_signer must not be called when the account already pins a \
             G-strkey identity or the run refuses"
        );
    }

    /// Builds the raw-signer-ref injection for a profile fixture: the raw
    /// on-disk view in these unit tests is the fixture's own signer ref.
    fn raw_ref_of(
        profile: &Profile,
    ) -> impl Fn(&str) -> Result<KeyringEntryRef, loader::ProfileLoadError> + 'static {
        let r = profile.mcp_signer_default.clone();
        move |_n| Ok(r.clone())
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

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
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

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, Some(&other_g), false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
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

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
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

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
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

        let raw = raw_ref_of(&profile);
        let code = run_with_dependencies(
            &args(&var, None, true),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
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

    /// The completeness round trip a `profile init`-minted profile requires:
    /// the on-disk `mcp_signer_default.account` starts as the literal
    /// placeholder `"default"`, so enrollment must pin it to the derived
    /// G-strkey BEFORE writing the keyring secret, and the keyring write
    /// itself must land at the DERIVED coordinate, not the placeholder one.
    /// The pin closure asserts the ordering: when it runs, the keyring
    /// coordinate must still be empty. Without this flow, an `init`-created
    /// profile could never enroll a working signer (see "Account-as-identity"
    /// in the module documentation).
    #[tokio::test]
    #[serial]
    async fn enroll_on_placeholder_account_populates_profile_before_keyring_write() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x77u8; 32]);
        let var = unique_var("PLACEHOLDER");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // The literal placeholder `profile init` mints.
        let profile = profile_with_signer_account("default");
        let signer_service = profile.mcp_signer_default.service.clone();
        let raw = raw_ref_of(&profile);

        let pinned: std::sync::Arc<std::sync::Mutex<Option<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let pinned_for_closure = pinned.clone();
        let service_for_closure = signer_service.clone();

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            move |name, account| {
                // Ordering pin: the keyring write must not have happened yet
                // when the profile pin runs (TOML-before-keyring convergence).
                let probe = KeyringEntry::new(&service_for_closure, account).unwrap();
                assert!(
                    probe.get_password().is_err(),
                    "the keyring coordinate must still be empty when the pin runs"
                );
                *pinned_for_closure.lock().unwrap() = Some((name.to_owned(), account.to_owned()));
                Ok(PathBuf::from("/unused-in-test/default.toml"))
            },
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed against a placeholder account");

        let (pinned_name, pinned_account) = pinned
            .lock()
            .unwrap()
            .clone()
            .expect("pin_signer must have been called for a placeholder account");
        assert_eq!(pinned_name, "enroll-signer-test");
        assert_eq!(
            pinned_account, derived_g,
            "the pin must carry the derived G-strkey"
        );

        // The keyring secret itself lands at the DERIVED coordinate, not the
        // placeholder — the exact coordinate a subsequent profile load (which
        // now carries the derived account) resolves via `signer_from_keyring`.
        let entry = KeyringEntry::new(&signer_service, &derived_g).unwrap();
        let stored = entry
            .get_password()
            .expect("entry must be present at the derived coordinate");
        assert!(
            stored == s_strkey,
            "the stored value must be the verbatim S-strkey"
        );

        let entry_ref = KeyringEntryRef::new(signer_service, derived_g.clone());
        let handle = signer_from_keyring(&entry_ref, &derived_g)
            .await
            .expect("signer_from_keyring must succeed after enroll");
        assert_eq!(handle.public_key().to_string().to_string(), derived_g);
    }

    /// An on-disk account that is neither the literal placeholder nor a valid
    /// G-strkey (a typo'd pin) is refused: nothing is pinned and no keyring
    /// entry is written. A broken pin must be surfaced, never replaced.
    #[tokio::test]
    #[serial]
    async fn malformed_account_pin_refuses_without_writing() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x88u8; 32]);
        let var = unique_var("MALFORMED");
        let _guard = EnvGuard::set(var.clone(), &s_strkey);

        // A truncated G-strkey: not the placeholder, not a valid strkey.
        let profile = profile_with_signer_account("GAQAA5L65LSYH7CQ3VTJ7F3HHLG");
        let signer_service = profile.mcp_signer_default.service.clone();
        let raw = raw_ref_of(&profile);

        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile.clone()),
            raw,
            pin_signer_must_not_be_called,
            || Ok(()),
        )
        .await;
        assert_eq!(code, 1, "a malformed account pin must refuse");

        let entry = KeyringEntry::new(&signer_service, &derived_g).unwrap();
        assert!(
            entry.get_password().is_err(),
            "no keyring entry must be written on a malformed-pin refusal"
        );
    }

    /// End-to-end environment immunity through the PRODUCTION loader
    /// functions: a `STELLAR_AGENT_MCP_SIGNER_DEFAULT` overlay must neither
    /// influence the enrollment classification nor leak into the pinned
    /// on-disk document. The profile lives in a real temp dir; the raw read
    /// and the pin are the production `read_signer_ref_on_disk` /
    /// `pin_signer_account_on_disk` over that dir.
    #[tokio::test]
    #[serial]
    async fn env_overlay_never_reaches_the_on_disk_pin() {
        keyring_mock::install().expect("mock store");
        let (s_strkey, derived_g) = seed_material([0x99u8; 32]);
        let var = unique_var("ENVIMMUNE");
        let _seed_guard = EnvGuard::set(var.clone(), &s_strkey);
        // An overlay that would redirect the signer ref on an env-merged load.
        let _overlay_guard = EnvGuard::set(
            "STELLAR_AGENT_MCP_SIGNER_DEFAULT".to_owned(),
            r#"{service="env-injected-svc",account="default"}"#,
        );

        let dir = tempfile::tempdir().unwrap();
        let profile = profile_with_signer_account("default");
        loader::save_to_dir("enroll-signer-test", &profile, dir.path()).unwrap();

        let dir_for_read = dir.path().to_path_buf();
        let dir_for_pin = dir.path().to_path_buf();
        let profile_for_load = profile.clone();
        let code = run_with_dependencies(
            &args(&var, None, false),
            move |_n| Ok(profile_for_load.clone()),
            move |n| loader::read_signer_ref_on_disk(n, &dir_for_read),
            move |n, g| loader::pin_signer_account_on_disk(n, &dir_for_pin, g),
            || Ok(()),
        )
        .await;
        assert_eq!(code, 0, "enroll must succeed with the overlay set");

        let written = std::fs::read_to_string(dir.path().join("enroll-signer-test.toml")).unwrap();
        assert!(
            written.contains(&format!("account = \"{derived_g}\"")),
            "the on-disk pin must carry the derived G-strkey; got:\n{written}"
        );
        assert!(
            written.contains(&format!("service = \"{SIGNER_SERVICE}\"")),
            "the on-disk service must be the stored one; got:\n{written}"
        );
        assert!(
            !written.contains("env-injected-svc"),
            "no environment overlay value may leak into the stored document; got:\n{written}"
        );

        // The keyring write landed at the ON-DISK service, not the env one.
        let entry = KeyringEntry::new(SIGNER_SERVICE, &derived_g).unwrap();
        assert!(
            entry.get_password().is_ok(),
            "the secret must be stored at the on-disk service coordinate"
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
