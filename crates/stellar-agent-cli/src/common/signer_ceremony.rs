//! Shared secret-env signer ceremony for CLI write commands.
//!
//! Every subcommand that accepts a `--*-secret-env <VAR>` flag derives a
//! `SoftwareSigningKey` from an `S...` ed25519 strkey stored in an
//! environment variable through the same mlock-protected unlock window:
//!
//! 1. Read the S-strkey from the named env var into a `Zeroizing<String>`.
//! 2. Parse it into a 32-byte seed; wrap the seed in `Zeroizing<[u8; 32]>`.
//! 3. Explicitly zeroize the `Copy` residue left in `PrivateKey.0` (until
//!    `stellar-strkey` gains its own `Drop`/`Zeroize` impl for the type).
//! 4. Move the seed into `Wallet::unlock`, mlock-pinning the page for the
//!    resolved profile's `[wallet]` posture and TTL.
//! 5. Derive the `SoftwareSigningKey` via `signer_from_wallet`.
//! 6. Dispose the wallet (munlock + zeroize the `LockedSeed`) before
//!    returning the signer.
//!
//! [`resolve_software_signer_from_env`] is the single call site for this
//! ceremony. Every CLI verb that resolves a signer from an env var routes
//! through it, so the `[wallet]` profile controls and the zeroization
//! discipline cannot drift between call sites.
//!
//! # `WalletMlockFailed` audit recording
//!
//! When `Wallet::unlock` degrades under `MlockRequired::Warn` (mlock
//! unavailable), [`resolve_software_signer_from_env`] returns the details in
//! [`SignerCeremonyOutcome::mlock_degradation`]. A caller that holds an open
//! audit writer when it resolves the signer writes the `WalletMlockFailed`
//! entry through [`record_mlock_degradation`]: the smart-account handler
//! context, `execute`, `multicall`, the timelock verbs, and `accounts
//! deploy-c` with `--profile`. Every other caller relies on the
//! `tracing::warn!` that `Wallet::unlock` emits.
//!
//! # Enrolled signer identity
//!
//! Every function that resolves a seed or Ledger signer calls
//! [`require_enrolled_signer`] once on the resolved signer, so on a mainnet
//! profile the signer must be the profile's enrolled identity. The enrollment
//! ceremonies are exempt because they establish that identity.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::{ValidationError, WalletError, WalletStateError};
use stellar_agent_core::profile::Profile;
#[cfg(test)]
use stellar_agent_core::wallet::{DEFAULT_TTL_SECONDS, MlockRequired};
use stellar_agent_core::wallet::{MlockDegradation, Wallet};
use stellar_agent_network::signing::hardware::HardwareSigningKey;
use stellar_agent_network::signing::wallet::signer_from_wallet;
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::deployment::DeployerKeypair;
use zeroize::Zeroizing;

/// Outcome of [`resolve_software_signer_from_env`]: the derived signer plus
/// whether the mlock-protected unlock window degraded to unprotected memory.
///
/// `#[must_use]`: a call site that derives a signer without inspecting
/// `mlock_degradation` silently drops the information needed to record a
/// `WalletMlockFailed` audit-log entry via [`record_mlock_degradation`].
#[must_use]
pub(crate) struct SignerCeremonyOutcome {
    /// The derived signing key.
    pub(crate) signer: SoftwareSigningKey,
    /// `Some` when `Wallet::unlock` degraded under `MlockRequired::Warn`.
    pub(crate) mlock_degradation: Option<MlockDegradation>,
}

/// Derives a software signer using the loaded profile's wallet controls.
///
/// # Errors
/// Refuses an absent or invalid seed, an invalid TTL, or an unsuccessful unlock.
pub(crate) async fn resolve_software_signer_from_env(
    var_name: &str,
    wallet_label: &str,
    profile: &Profile,
) -> Result<SignerCeremonyOutcome, WalletError> {
    let mlock_required = profile.wallet.mlock_required;
    let ttl_seconds = profile.wallet.unlock_ttl_seconds;

    let s_strkey: Zeroizing<String> = Zeroizing::new(std::env::var(var_name).map_err(|_| {
        WalletError::Validation(ValidationError::SecretEnvNotSet {
            var: var_name.to_owned(),
        })
    })?);

    let mut private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            WalletError::Validation(ValidationError::SecretEnvInvalid {
                var: var_name.to_owned(),
            })
        })?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    zeroize::Zeroize::zeroize(&mut private_key.0);
    drop(s_strkey);

    let mut wallet = Wallet::unlock(wallet_label.to_owned(), seed, ttl_seconds, mlock_required)
        .await
        .map_err(|e| {
            WalletError::WalletState(WalletStateError::UnlockFailed {
                detail: e.to_string(),
            })
        })?;
    let mlock_degradation = wallet.mlock_degradation().cloned();

    let signer = match signer_from_wallet(&wallet) {
        Ok(s) => s,
        Err(e) => {
            wallet.dispose();
            return Err(e);
        }
    };
    wallet.dispose();
    Ok(SignerCeremonyOutcome {
        signer,
        mlock_degradation,
    })
}

/// Checks the resolved signer's identity on a mainnet profile.
///
/// On a testnet profile it returns `Ok` without touching the signer, so a
/// Ledger signer makes no device round trip. On a mainnet profile it fetches
/// the signer's public key and compares it with the profile's enrolled pin.
///
/// # Errors
///
/// - The signer's own error when its public key cannot be fetched.
/// - `auth.enrolled_signer_unpinned` when the profile's
///   `mcp_signer_default.account` is the placeholder or malformed.
/// - `auth.enrolled_signer_mismatch` when the signer is not the enrolled
///   identity.
pub(crate) async fn require_enrolled_signer(
    profile_name: &str,
    profile: &Profile,
    signer: &dyn Signer,
) -> Result<(), WalletError> {
    if !profile.chain_id.is_mainnet() {
        return Ok(());
    }
    let derived = signer.public_key().await?.to_string().to_string();
    stellar_agent_core::profile::check_enrolled_signer(profile_name, profile, &derived)?;
    Ok(())
}

/// Resolves a deployer from `--deployer-secret-env` or `--sign-with-ledger`
/// and holds it to the profile's enrolled identity.
///
/// Returns the deployer with any `mlock` degradation the seed ceremony
/// reported. The Ledger arm reports none.
///
/// # Errors
///
/// - `validation.signer_source_required` when neither flag is supplied.
/// - `validation.secret_env_not_set` or `validation.secret_env_invalid` for an
///   absent or invalid seed, and `wallet_state.unlock_failed` when the unlock
///   fails.
/// - The Ledger device errors (`wallet_state.hardware_not_found`, or the
///   timeout and wrong-app variants).
/// - The enrolled-signer refusals of [`require_enrolled_signer`].
pub(crate) async fn resolve_deployer_keypair(
    deployer_secret_env: Option<&str>,
    sign_with_ledger: bool,
    account_index: u32,
    wallet_label: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<(DeployerKeypair, Option<MlockDegradation>), WalletError> {
    let (signer, var_name, degradation): (Box<dyn Signer + Send + Sync>, _, _) = if sign_with_ledger
    {
        let signer = HardwareSigningKey::native()?.with_account_index(account_index);
        (Box::new(signer), None, None)
    } else {
        let var_name = deployer_secret_env.ok_or_else(|| {
            WalletError::Validation(ValidationError::SignerSourceRequired {
                detail: "no deployer signer flag specified; pass --deployer-secret-env <VAR> \
                             or --sign-with-ledger"
                    .to_owned(),
            })
        })?;
        let SignerCeremonyOutcome {
            signer,
            mlock_degradation,
        } = resolve_software_signer_from_env(var_name, wallet_label, profile).await?;
        (Box::new(signer), Some(var_name), mlock_degradation)
    };
    require_enrolled_signer(profile_name, profile, signer.as_ref()).await?;
    let deployer = match var_name {
        Some(var_name) => DeployerKeypair::SecretEnv {
            var_name: var_name.to_owned(),
            signer,
        },
        None => DeployerKeypair::Ledger {
            account_index,
            signer,
        },
    };
    Ok((deployer, degradation))
}

/// Records a `WalletMlockFailed` audit-log entry when `degradation` is
/// `Some`, using the caller's already-open audit writer.
///
/// No-op when `degradation` is `None`. Best-effort: an audit-writer lock
/// failure is swallowed rather than failing the signing operation over an
/// audit-log write, matching the `write_success_audit_rows` /
/// `write_failure_audit_row` convention used elsewhere in the CLI.
pub(crate) fn record_mlock_degradation(
    audit_writer: &Arc<Mutex<AuditWriter>>,
    degradation: Option<&MlockDegradation>,
    profile_name: &str,
    request_id: &str,
) {
    let Some(degradation) = degradation else {
        return;
    };
    let Ok(mut writer) = audit_writer.lock() else {
        return;
    };
    let entry = AuditEntry::new_mlock_failed(
        profile_name.to_owned(),
        degradation.reason.clone(),
        degradation.errno,
        request_id.to_owned(),
    );
    let _ = writer.write_entry(entry);
}

/// Enrolled-identity fixtures shared by the signing tests of the CLI verbs.
#[cfg(test)]
pub(crate) mod test_fixtures {
    #![allow(clippy::expect_used, reason = "test fixture assertions")]

    use stellar_agent_core::error::WalletError;
    use stellar_agent_core::profile::Profile;

    /// The seed every enrolled-identity test signs with.
    const ENROLLED_TEST_SEED: [u8; 32] = [42; 32];

    /// How a mainnet profile's enrolled pin relates to the key the test seed
    /// derives.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum EnrolledPin {
        /// The pin is the derived key.
        Derived,
        /// The pin is the placeholder.
        Placeholder,
        /// The pin is another valid key.
        Other,
    }

    impl EnrolledPin {
        /// The refusal code a signer derived from the test seed meets, or
        /// `None` when it passes.
        fn expected_refusal(self) -> Option<&'static str> {
            match self {
                Self::Derived => None,
                Self::Placeholder => Some("auth.enrolled_signer_unpinned"),
                Self::Other => Some("auth.enrolled_signer_mismatch"),
            }
        }

        fn account(self) -> String {
            match self {
                Self::Derived => enrolled_test_g(),
                Self::Placeholder => "default".to_owned(),
                Self::Other => stellar_strkey::ed25519::PublicKey([7; 32])
                    .to_string()
                    .to_string(),
            }
        }
    }

    /// The G-strkey the test seed derives.
    pub(crate) fn enrolled_test_g() -> String {
        let verifying_key =
            ed25519_dalek::SigningKey::from_bytes(&ENROLLED_TEST_SEED).verifying_key();
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
            .to_string()
            .to_string()
    }

    /// The S-strkey of the test seed.
    pub(crate) fn enrolled_test_secret() -> String {
        stellar_strkey::ed25519::PrivateKey(ENROLLED_TEST_SEED)
            .as_unredacted()
            .to_string()
            .to_string()
    }

    /// A mainnet profile named `enrolled` whose pin follows `pin`. The
    /// `[wallet]` posture skips mlock so the ceremony runs on any host.
    pub(crate) fn enrolled_mainnet_profile(pin: EnrolledPin) -> Profile {
        let mut profile = Profile::builder_mainnet_named(
            "enrolled",
            "https://rpc.example.invalid",
            "s",
            &pin.account(),
            "n",
            "a",
        )
        .build();
        profile.wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::False;
        profile
    }

    /// Asserts the outcome `pin` predicts for a signer derived from the test
    /// seed.
    pub(crate) fn assert_enrolled_outcome<T: std::fmt::Debug>(
        pin: EnrolledPin,
        result: Result<T, WalletError>,
    ) {
        match pin.expected_refusal() {
            None => {
                result.expect("the enrolled signer must pass");
            }
            Some(code) => assert_eq!(
                result
                    .expect_err("a signer that is not enrolled must be refused")
                    .code(),
                code
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use stellar_agent_core::error::AuthError;
    use stellar_agent_network::WebAuthnAssertion;

    use super::*;

    fn test_profile() -> Profile {
        let mut profile = Profile::builder_testnet_named("ceremony", "s", "a", "n", "a").build();
        profile.wallet.mlock_required = MlockRequired::Warn;
        profile
    }

    fn unique_var(tag: &str) -> String {
        format!("SIGNER_CEREMONY_TEST_{tag}_{}", std::process::id())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; the variable name is unique to this test"
    )]
    async fn derives_the_expected_public_key_with_testnet_profile() {
        let seed = [0x11u8; 32];
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let expected_g = {
            let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            stellar_strkey::ed25519::PublicKey(vk.to_bytes())
                .to_string()
                .to_string()
        };
        let var = unique_var("NO_PROFILE");
        unsafe {
            std::env::set_var(&var, &s_strkey);
        }
        let outcome = resolve_software_signer_from_env(&var, "unit-test", &test_profile())
            .await
            .expect("resolve must succeed");
        assert!(
            outcome.mlock_degradation.is_none(),
            "a real mlock success/opt-out must not report degradation"
        );
        let derived = outcome
            .signer
            .public_key()
            .await
            .expect("public key must derive");
        assert_eq!(derived.to_string().to_string(), expected_g);
        unsafe {
            std::env::remove_var(&var);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unset_env_var_is_refused() {
        let var = unique_var("UNSET");
        let err = match resolve_software_signer_from_env(&var, "unit-test", &test_profile()).await {
            Ok(_) => panic!("unset env var must refuse"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "validation.secret_env_not_set");
        assert!(
            err.message().contains(&var),
            "error must name the variable: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    #[allow(unsafe_code, reason = "test-only process environment mutation")]
    async fn invalid_s_strkey_is_refused() {
        let var = unique_var("INVALID");
        unsafe {
            std::env::set_var(&var, "not-an-s-strkey");
        }
        let err = match resolve_software_signer_from_env(&var, "unit-test", &test_profile()).await {
            Ok(_) => panic!("invalid S-strkey must refuse"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "validation.secret_env_invalid");
        assert!(
            err.message().contains(&var),
            "error must name the variable: {err}"
        );
        assert!(
            !err.message().contains("not-an-s-strkey"),
            "error must not echo the malformed value: {err}"
        );
        unsafe {
            std::env::remove_var(&var);
        }
    }

    /// An out-of-range profile `unlock_ttl_seconds` is refused by
    /// `Wallet::unlock` inside the ceremony and surfaces as
    /// `wallet_state.unlock_failed`, not a keyring error. Profile load does
    /// not range-check the TTL (enforcement lives in `Wallet::unlock`), so the
    /// ceremony is the boundary that refuses it.
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; the S-strkey variable name is unique to this test"
    )]
    async fn over_max_ttl_profile_surfaces_unlock_failed() {
        use stellar_agent_core::wallet::MAX_TTL_SECONDS;

        let mut profile = test_profile();
        // Above the permitted (0, MAX_TTL_SECONDS] range; refused at unlock, not
        // clamped, and not range-checked at profile load.
        profile.wallet.unlock_ttl_seconds = MAX_TTL_SECONDS + 1;

        let seed = [0x55u8; 32];
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let var = unique_var("OVER_MAX_TTL");
        unsafe {
            std::env::set_var(&var, &s_strkey);
        }

        let err = match resolve_software_signer_from_env(&var, "unit-test", &profile).await {
            Ok(_) => panic!("an over-maximum TTL must be refused at unlock"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "wallet_state.unlock_failed");

        unsafe {
            std::env::remove_var(&var);
        }
    }

    /// A persisted profile with `mlock_required = false` and a non-default
    /// TTL loads with those `[wallet]` values, and the ceremony derives the
    /// expected key under them through [`resolve_software_signer_from_env`].
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; the variable name is unique to this test"
    )]
    async fn wires_mlock_false_and_custom_ttl_from_a_persisted_profile() {
        use stellar_agent_core::profile::schema::Profile;

        let dir = tempfile::tempdir().expect("tempdir");
        let profile_name = "signer-ceremony-test-mlock-false";
        let mut profile = Profile::builder_testnet(
            "signer-ceremony-svc",
            "signer-ceremony-acct",
            "signer-ceremony-nonce-svc",
            "signer-ceremony-nonce-acct",
        )
        .audit_log_path(dir.path().join("audit.log"))
        .build();
        profile.wallet.mlock_required = MlockRequired::False;
        profile.wallet.unlock_ttl_seconds = 45;
        let toml_bytes = toml::to_string_pretty(&profile).expect("serialize profile");
        std::fs::write(dir.path().join(format!("{profile_name}.toml")), toml_bytes)
            .expect("write profile");

        let loaded =
            stellar_agent_core::profile::loader::load_from_dir(profile_name, dir.path(), None)
                .expect("profile must load");
        assert_eq!(loaded.wallet.mlock_required, MlockRequired::False);
        assert_eq!(loaded.wallet.unlock_ttl_seconds, 45);

        let seed = [0x22u8; 32];
        let s_strkey = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        let expected_g = {
            let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            stellar_strkey::ed25519::PublicKey(vk.to_bytes())
                .to_string()
                .to_string()
        };
        let var = unique_var("MLOCK_FALSE_PROFILE");
        unsafe {
            std::env::set_var(&var, &s_strkey);
        }

        let outcome = resolve_software_signer_from_env(&var, "unit-test-mlock-false", &loaded)
            .await
            .expect("ceremony");
        let signer = outcome.signer;
        let derived = signer.public_key().await.expect("public key must derive");
        assert_eq!(derived.to_string().to_string(), expected_g);
        unsafe {
            std::env::remove_var(&var);
        }
    }

    /// An out-of-range TTL — as a profile's `unlock_ttl_seconds` could carry
    /// if misconfigured — is refused by `Wallet::unlock` rather than
    /// silently clamped.
    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_range_ttl_is_refused_not_clamped() {
        let seed = [0x33u8; 32];
        let over_max = stellar_agent_core::wallet::MAX_TTL_SECONDS + 1;
        let seed_bytes = Zeroizing::new(seed);
        let result = Wallet::unlock(
            "unit-test".to_owned(),
            seed_bytes,
            over_max,
            MlockRequired::Warn,
        )
        .await;
        assert!(result.is_err(), "TTL above MAX_TTL_SECONDS must be refused");
    }

    // ── mlock-degradation detection ─────────────────────────────────────────
    //
    // There is no test-only hook to force `region::lock` to fail
    // deterministically (mlock.rs's own tests probe real mlock behaviour and
    // accept either outcome, e.g. `warn_mode_succeeds_or_falls_back`).
    // These tests instead pin the detection accessor's behaviour on the
    // paths that ARE deterministic (opt-out via `MlockRequired::False`), and
    // exercise `record_mlock_degradation` directly against a constructed
    // `MlockDegradation` value for the recording half.

    /// `Wallet::mlock_degradation` returns `None` under `MlockRequired::False`
    /// (locking never attempted, not a degradation).
    #[tokio::test(flavor = "multi_thread")]
    async fn mlock_degradation_is_none_when_locking_is_opted_out() {
        let seed_bytes = Zeroizing::new([0x44u8; 32]);
        let mut wallet = Wallet::unlock(
            "unit-test-mlock-false".to_owned(),
            seed_bytes,
            DEFAULT_TTL_SECONDS,
            MlockRequired::False,
        )
        .await
        .expect("unlock under MlockRequired::False must always succeed");
        assert!(
            wallet.mlock_degradation().is_none(),
            "MlockRequired::False must never report degradation"
        );
        wallet.dispose();
        // The accessor is a snapshot taken at construction time: it remains
        // queryable (and still None) after dispose.
        assert!(wallet.mlock_degradation().is_none());
    }

    /// `record_mlock_degradation` writes a `WalletMlockFailed` audit-log
    /// entry carrying the supplied reason and errno when `degradation` is
    /// `Some`.
    #[test]
    fn record_mlock_degradation_writes_the_expected_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit").join("test.jsonl");
        let writer = AuditWriter::open(path.clone(), None).expect("open audit writer");
        let audit_writer = Arc::new(Mutex::new(writer));

        let degradation = MlockDegradation {
            reason: "ENOMEM".to_owned(),
            errno: Some(12),
        };
        record_mlock_degradation(
            &audit_writer,
            Some(&degradation),
            "test-profile",
            "req-mlock-degraded",
        );

        let contents = std::fs::read_to_string(&path).expect("read audit log");
        assert_eq!(
            contents.lines().count(),
            1,
            "exactly one audit row must be written; got: {contents}"
        );
        assert!(
            contents.contains("\"wallet_mlock_failed\""),
            "row must carry the WalletMlockFailed event-kind tag; got: {contents}"
        );
        assert!(
            contents.contains("ENOMEM") && contents.contains("test-profile"),
            "row must carry the reason and profile fields; got: {contents}"
        );
        assert!(
            contents.contains("req-mlock-degraded"),
            "row must carry the request_id; got: {contents}"
        );
    }

    /// `record_mlock_degradation` is a no-op when `degradation` is `None` —
    /// the common case (no mlock failure to report).
    #[test]
    fn record_mlock_degradation_is_a_noop_when_not_degraded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit").join("test.jsonl");
        let writer = AuditWriter::open(path.clone(), None).expect("open audit writer");
        let audit_writer = Arc::new(Mutex::new(writer));

        record_mlock_degradation(&audit_writer, None, "test-profile", "req-not-degraded");

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            contents.is_empty(),
            "no row must be written when degradation is None; got: {contents}"
        );
    }

    // ── resolve_deployer_keypair ────────────────────────────────────────────

    /// With neither `--deployer-secret-env` nor `--sign-with-ledger`, the
    /// resolver refuses with `validation.signer_source_required` before any
    /// key access.
    #[tokio::test]
    async fn resolve_deployer_keypair_without_a_source_flag_refuses() {
        let error = match resolve_deployer_keypair(
            None,
            false,
            0,
            "unit-test",
            &test_profile(),
            "ceremony",
        )
        .await
        {
            Ok(_) => panic!("a missing signer-source flag must be refused"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "validation.signer_source_required");
    }

    // ── require_enrolled_signer ─────────────────────────────────────────────

    /// A signer whose key fetch counts its calls and fails, standing in for a
    /// Ledger device whose key fetch is a round trip.
    #[derive(Default)]
    struct CountingKeyFetchSigner {
        key_fetches: AtomicUsize,
    }

    fn counting_signer_error() -> WalletError {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: "counting-key-fetch-sentinel".to_owned(),
        })
    }

    #[async_trait::async_trait]
    impl Signer for CountingKeyFetchSigner {
        async fn sign_tx_payload(&self, _payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            Err(counting_signer_error())
        }

        async fn sign_auth_digest(&self, _digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
            Err(counting_signer_error())
        }

        async fn sign_soroban_address_auth_payload(
            &self,
            _payload: &[u8; 32],
        ) -> Result<[u8; 64], WalletError> {
            Err(counting_signer_error())
        }

        async fn sign_webauthn_assertion(
            &self,
            _auth_digest: &[u8; 32],
            _credential_id: &[u8],
        ) -> Result<WebAuthnAssertion, WalletError> {
            Err(counting_signer_error())
        }

        async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
            self.key_fetches.fetch_add(1, Ordering::SeqCst);
            Err(counting_signer_error())
        }
    }

    /// A pinned mainnet profile: the enrolled account is a valid G-strkey.
    fn pinned_mainnet_profile() -> Profile {
        let pin = stellar_strkey::ed25519::PublicKey([0x66u8; 32])
            .to_string()
            .to_string();
        Profile::builder_mainnet_named(
            "enrolled",
            "https://rpc.example.invalid",
            "s",
            &pin,
            "n",
            "a",
        )
        .build()
    }

    #[tokio::test]
    async fn require_enrolled_signer_leaves_the_signer_untouched_on_testnet() {
        let signer = CountingKeyFetchSigner::default();
        let result = require_enrolled_signer("ceremony", &test_profile(), &signer).await;
        assert_eq!(
            signer.key_fetches.load(Ordering::SeqCst),
            0,
            "a testnet profile must not fetch the signer's key"
        );
        result.expect("a testnet profile admits any signer");
    }

    #[tokio::test]
    async fn require_enrolled_signer_fetches_the_key_once_on_mainnet() {
        let signer = CountingKeyFetchSigner::default();
        let error = require_enrolled_signer("enrolled", &pinned_mainnet_profile(), &signer)
            .await
            .expect_err("the failing key fetch must surface on mainnet");
        assert_eq!(error.code(), counting_signer_error().code());
        assert!(
            error.message().contains("counting-key-fetch-sentinel"),
            "the signer's own error must surface: {error}"
        );
        assert_eq!(signer.key_fetches.load(Ordering::SeqCst), 1);
    }
}
