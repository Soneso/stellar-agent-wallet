//! The owner ceremony for an enrolled mainnet signer. The agent seed is never read.

use super::{
    audit_emit::emit_signer_identity_enrolled,
    owner_seed::{OwnerSeedError, with_owner_seed},
};
use crate::common::{
    profile_access::{load_profile_reconciled, profile_access_envelope},
    render, resolve_profile_name,
};
use clap::Args;
use ed25519_dalek::SigningKey;
use std::path::Path;
use stellar_agent_core::{
    envelope::Envelope,
    error::{AuthError, InternalError, WalletError},
    observability::RedactedStrkey,
    policy::{
        pin::{self, PinScope, PinState},
        state_lock::WindowStoreLock,
    },
    profile::{
        owner_key::decode_owner_public_key,
        schema::{
            KeyringEntryRef, Profile, default_policy_window_state_path_for,
            signer_identity_entry_ref,
        },
        signer_identity::SignerIdentityRecord,
    },
};
use stellar_agent_network::keyring::{
    init_platform_keyring_store, read_keyring_string, write_keyring_string,
};

/// Arguments for the owner-signed signer binding ceremony.
#[derive(Debug, Args)]
pub(crate) struct BindSignerArgs {
    /// The mainnet profile whose signer serves this owner.
    #[arg(long, value_name = "NAME")]
    pub(super) profile: String,
    /// Environment variable containing the owner's S-strkey.
    #[arg(long, value_name = "VAR")]
    owner_secret_env: String,
}

/// Why the ceremony refused: a refusal of the verb itself, or a classified
/// wallet error such as a keyring failure, which keeps its own code.
#[derive(Debug)]
enum Failure {
    Refused(&'static str, String),
    Wallet(WalletError),
}
impl From<OwnerSeedError> for Failure {
    fn from(error: OwnerSeedError) -> Self {
        let detail = match error {
            // The flag value names no set variable, so the text names the flag.
            OwnerSeedError::NotSet => {
                "--owner-secret-env names an environment variable that is not set".to_owned()
            }
            OwnerSeedError::Invalid => {
                "--owner-secret-env names an environment variable that does not hold a valid \
                 S-strkey"
                    .to_owned()
            }
            OwnerSeedError::Unlock(detail) => detail,
        };
        Self::Refused("profile.bind_signer_owner_seed", detail)
    }
}
impl From<WalletError> for Failure {
    fn from(error: WalletError) -> Self {
        Self::Wallet(error)
    }
}
fn conflict() -> Failure {
    Failure::Refused(
        "profile.bind_signer_record_conflict",
        "the identity record does not name this profile, chain and pinned agent key".into(),
    )
}
/// A lock, pin or owner-entry content failure.
fn storage(error: impl std::fmt::Display) -> Failure {
    Failure::Refused("profile.bind_signer_storage", error.to_string())
}

/// The owner public key enrolled at `coordinate`.
fn enrolled_owner_key(coordinate: &KeyringEntryRef) -> Result<[u8; 32], Failure> {
    let raw = read_keyring_string(coordinate)?.ok_or_else(|| {
        WalletError::from(AuthError::KeyringNotFound {
            cause: stellar_agent_core::error::KeyringMissingCause::MissingEntry,
        })
    })?;
    decode_owner_public_key(&raw).map_err(|_| {
        storage("the enrolled owner key is not a G-strkey; enroll the owner key again")
    })
}

pub(crate) async fn run(args: &BindSignerArgs) -> i32 {
    let resolved = resolve_profile_name(Some(&args.profile));
    let profile = match load_profile_reconciled(&resolved) {
        Ok(profile) => profile,
        Err(error) => {
            return render::write_envelope(
                &mut std::io::stdout(),
                &profile_access_envelope(&error),
                1,
            );
        }
    };
    let result = async {
        init_platform_keyring_store()?;
        let window = default_policy_window_state_path_for(&resolved.name);
        with_owner_seed(
            &args.owner_secret_env,
            "profile-bind-signer",
            profile.wallet.mlock_required,
            profile.wallet.unlock_ttl_seconds,
            async |key| bind_with_key(&resolved.name, &profile, &window, key),
        )
        .await
    }
    .await;
    match result {
        Ok(bound) => render::write_envelope(
            &mut std::io::stdout(),
            &Envelope::ok(serde_json::json!({"profile": resolved.name, "bound": bound})),
            0,
        ),
        Err(Failure::Refused(code, detail)) => render::write_envelope(
            &mut std::io::stdout(),
            &Envelope::<()>::err_raw(code, detail),
            1,
        ),
        Err(Failure::Wallet(error)) => {
            render::write_envelope(&mut std::io::stdout(), &Envelope::<()>::err(&error), 1)
        }
    }
}

fn bind_with_key(
    name: &str,
    profile: &Profile,
    window: &Path,
    key: &SigningKey,
) -> Result<bool, Failure> {
    if !profile.chain_id.is_mainnet() {
        return Err(Failure::Refused(
            "profile.bind_signer_mainnet_required",
            "binding requires a mainnet profile".into(),
        ));
    }
    if profile.mcp_signer_default.service != KeyringEntryRef::default_signer(name).service {
        return Err(Failure::Refused(
            "profile.bind_signer_coordinate_not_canonical",
            "binding requires the profile's canonical signer service".into(),
        ));
    }
    let agent =
        stellar_strkey::ed25519::PublicKey::from_string(&profile.mcp_signer_default.account)
            .map_err(|_| conflict())?
            .0;
    let identity = signer_identity_entry_ref(&profile.mcp_signer_default);
    let raw = read_keyring_string(&identity)?.ok_or_else(conflict)?;
    let record = SignerIdentityRecord::parse(&raw).map_err(|_| conflict())?;
    if record.public_key() != agent
        || record
            .binding
            .as_ref()
            .is_some_and(|binding| binding.profile != name || binding.chain != profile.chain_id)
    {
        return Err(conflict());
    }
    if let Some(parent) = window.parent() {
        std::fs::create_dir_all(parent).map_err(storage)?;
    }
    let lock = WindowStoreLock::acquire_for(window, &profile.policy_window_state_key_id)
        .map_err(storage)?;
    let pin = pin::read(&lock, &PinScope::for_profile(window, profile)).map_err(storage)?;
    let expected_owner = match pin {
        PinState::Present(pin) => pin.owner(),
        PinState::Absent => enrolled_owner_key(&KeyringEntryRef::default_owner_key(name))?,
    };
    let owner = key.verifying_key().to_bytes();
    if owner != expected_owner {
        return Err(Failure::Refused(
            "profile.bind_signer_owner_mismatch",
            "the supplied owner seed does not match the established owner".into(),
        ));
    }
    if owner == agent {
        return Err(Failure::Refused(
            "profile.bind_signer_owner_is_signer",
            "the agent key cannot prove its owner binding".into(),
        ));
    }
    if record
        .binding
        .as_ref()
        .and_then(|b| b.owner)
        .is_some_and(|(bound_owner, _)| bound_owner == owner)
        && record
            .verify_owner_signature(&profile.mcp_signer_default)
            .is_ok()
    {
        return Ok(false);
    }
    let mut record = SignerIdentityRecord::agent(agent, name, profile.chain_id);
    let rendered = record
        .bind_owner(key, &profile.mcp_signer_default)
        .and_then(|()| record.render())
        .map_err(|error| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("the bound signer identity record cannot be rendered: {error}"),
            })
        })?;
    write_keyring_string(&identity, &rendered)?;
    emit_signer_identity_enrolled(
        profile,
        name,
        "profile_bind_signer",
        &identity,
        RedactedStrkey::from_full(&record.public_key_strkey()),
        &uuid::Uuid::new_v4().to_string(),
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures fail loudly"
    )]
    use super::*;
    use serial_test::serial;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use stellar_agent_core::policy::pin::Pin;
    use stellar_agent_test_support::keyring_mock;

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

    struct Fixture {
        dir: tempfile::TempDir,
        profile: Profile,
        owner: SigningKey,
        reads: Arc<AtomicUsize>,
    }
    impl Fixture {
        fn new() -> Self {
            let agent = SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes();
            let profile = Profile::builder_mainnet_named(
                "v",
                "https://rpc.example.invalid",
                "stellar-agent-signer-v",
                &stellar_strkey::ed25519::PublicKey(agent).to_string(),
                "stellar-agent-nonce-v",
                "default",
            )
            .build();
            let reads = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&reads);
            keyring_mock::install_with_read_hooks(vec![keyring_mock::ReadHook::new(
                &profile.mcp_signer_default.service,
                &profile.mcp_signer_default.account,
                Arc::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            )])
            .unwrap();
            let owner = SigningKey::from_bytes(&[11; 32]);
            write_keyring_string(
                &KeyringEntryRef::default_owner_key("v"),
                &stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string(),
            )
            .unwrap();
            let fixture = Self {
                dir: tempfile::tempdir().unwrap(),
                profile,
                owner,
                reads,
            };
            let legacy = format!(
                r#"{{"v":1,"public_key":"{}","role":"agent"}}"#,
                fixture.profile.mcp_signer_default.account
            );
            fixture.put(&legacy);
            fixture.pin(&fixture.owner, 1);
            fixture
        }
        fn window(&self) -> std::path::PathBuf {
            self.dir.path().join("state.window")
        }
        fn pin(&self, key: &SigningKey, sequence: i64) {
            let window = self.window();
            let lock =
                WindowStoreLock::acquire_for(&window, &self.profile.policy_window_state_key_id)
                    .unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(&window, &self.profile),
                &Pin::new(
                    sequence,
                    [sequence as u8; 32],
                    key.verifying_key().to_bytes(),
                )
                .unwrap(),
            )
            .unwrap();
        }
        fn put(&self, raw: &str) {
            write_keyring_string(
                &signer_identity_entry_ref(&self.profile.mcp_signer_default),
                raw,
            )
            .unwrap();
        }
        fn raw(&self) -> String {
            read_keyring_string(&signer_identity_entry_ref(&self.profile.mcp_signer_default))
                .unwrap()
                .unwrap()
        }
        fn bind(&self, key: &SigningKey) -> Result<bool, Failure> {
            bind_with_key("v", &self.profile, &self.window(), key)
        }
    }
    impl Failure {
        fn code(&self) -> &str {
            match self {
                Self::Refused(code, _) => code,
                Self::Wallet(error) => error.code(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert_eq!(
                self.reads.load(Ordering::SeqCst),
                0,
                "the agent seed is never read"
            );
        }
    }

    /// An `--owner-secret-env` value that names no set variable, or a variable
    /// without a valid S-strkey, refuses by the flag, without the variable
    /// name.
    #[tokio::test]
    #[serial]
    async fn owner_seed_variable_marker_is_not_echoed() {
        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker_in_text,
        };

        let unset_var = format!("{CREDENTIAL_MARKER}_{}", std::process::id());
        let failure = with_owner_seed(
            &unset_var,
            "profile-bind-signer",
            stellar_agent_core::wallet::MlockRequired::Warn,
            60,
            async |_key| -> Result<bool, Failure> { panic!("an unset variable yields no key") },
        )
        .await
        .unwrap_err();
        let Failure::Refused(code, detail) = failure else {
            panic!("an unset variable is a refusal of the verb");
        };
        assert_eq!(code, "profile.bind_signer_owner_seed");
        assert_eq!(
            detail,
            "--owner-secret-env names an environment variable that is not set"
        );
        assert_no_marker_in_text(&detail, CREDENTIAL_MARKER);

        let invalid_var = format!("{CREDENTIAL_MARKER}_INVALID_{}", std::process::id());
        let _invalid = EnvGuard::set(invalid_var.clone(), CREDENTIAL_MARKER);
        let failure = with_owner_seed(
            &invalid_var,
            "profile-bind-signer",
            stellar_agent_core::wallet::MlockRequired::Warn,
            60,
            async |_key| -> Result<bool, Failure> { panic!("an invalid seed yields no key") },
        )
        .await
        .unwrap_err();
        assert_no_marker_in_text(&format!("{failure:?}"), CREDENTIAL_MARKER);
        let Failure::Refused(code, detail) = failure else {
            panic!("an invalid seed is a refusal of the verb");
        };
        assert_eq!(code, "profile.bind_signer_owner_seed");
        assert_eq!(
            detail,
            "--owner-secret-env names an environment variable that does not hold a valid S-strkey"
        );
        assert_no_marker_in_text(&detail, CREDENTIAL_MARKER);
        let error = with_owner_seed(
            &invalid_var,
            "profile-bind-signer",
            stellar_agent_core::wallet::MlockRequired::Warn,
            60,
            async |_key| -> Result<bool, OwnerSeedError> {
                panic!("an invalid seed yields no key")
            },
        )
        .await
        .unwrap_err();
        assert_no_marker_in_text(&format!("{error:?}"), CREDENTIAL_MARKER);
    }

    #[test]
    #[serial]
    fn binding_needs_the_pinned_owner_seed() {
        let f = Fixture::new();
        let before = f.raw();
        assert_eq!(
            f.bind(&SigningKey::from_bytes(&[12; 32]))
                .unwrap_err()
                .code(),
            "profile.bind_signer_owner_mismatch"
        );
        assert_eq!(f.raw(), before);
        assert!(f.bind(&f.owner).unwrap());
        let record = SignerIdentityRecord::parse(&f.raw()).unwrap();
        assert!(
            record
                .verify_owner_signature(&f.profile.mcp_signer_default)
                .is_ok()
        );
        let before = f.raw();
        assert!(!f.bind(&f.owner).unwrap());
        assert_eq!(f.raw(), before);
    }

    #[test]
    #[serial]
    fn a_binding_writes_the_bind_signer_audit_row() {
        let mut f = Fixture::new();
        f.profile.audit_log_path = f.dir.path().join("audit.jsonl");
        stellar_agent_core::audit_log::AuditWriterRegistry::remove_for_test("v");
        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &f.profile.audit_log_hash_chain_key_id.service,
            &f.profile.audit_log_hash_chain_key_id.account,
        )
        .unwrap();
        assert!(f.bind(&f.owner).unwrap());
        let log = std::fs::read_to_string(&f.profile.audit_log_path).unwrap();
        let rows: Vec<serde_json::Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|row: &serde_json::Value| row["kind"] == "signer_identity_enrolled")
            .collect();
        assert_eq!(rows.len(), 1, "{log}");
        assert_eq!(rows[0]["tool"], "profile_bind_signer", "{log}");
    }

    #[test]
    #[serial]
    fn a_keyring_failure_keeps_its_wallet_code() {
        let f = Fixture::new();
        let before = f.raw();
        let identity = signer_identity_entry_ref(&f.profile.mcp_signer_default);
        keyring_mock::inject_error(
            &identity.service,
            &identity.account,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other("planted"))),
        )
        .unwrap();
        let failure = bind_with_key("v", &f.profile, &f.window(), &f.owner).unwrap_err();
        assert!(matches!(failure, Failure::Wallet(_)), "{failure:?}");
        assert_eq!(failure.code(), "auth.keyring_platform_error");
        assert_eq!(f.raw(), before);
    }

    #[test]
    #[serial]
    fn a_foreign_coordinate_cannot_be_bound() {
        let f = Fixture::new();
        let before = f.raw();
        let evil = Profile::builder_mainnet_named(
            "evil",
            "https://rpc.example.invalid",
            "stellar-agent-signer-v",
            &f.profile.mcp_signer_default.account,
            "stellar-agent-nonce-evil",
            "default",
        )
        .build();
        let attacker = SigningKey::from_bytes(&[12; 32]);
        let window = f.dir.path().join("evil.window");
        {
            let lock =
                WindowStoreLock::acquire_for(&window, &evil.policy_window_state_key_id).unwrap();
            pin::write_for_test(
                &lock,
                &PinScope::for_profile(&window, &evil),
                &Pin::new(1, [1; 32], attacker.verifying_key().to_bytes()).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            bind_with_key("evil", &evil, &window, &attacker)
                .unwrap_err()
                .code(),
            "profile.bind_signer_coordinate_not_canonical"
        );
        assert_eq!(f.raw(), before);
    }

    #[test]
    #[serial]
    fn a_record_of_another_profile_is_never_rebound() {
        let f = Fixture::new();
        let key =
            stellar_strkey::ed25519::PublicKey::from_string(&f.profile.mcp_signer_default.account)
                .unwrap()
                .0;
        for (name, chain) in [
            ("elsewhere", f.profile.chain_id),
            ("v", stellar_agent_core::profile::caip2::Caip2::Testnet),
        ] {
            f.put(
                &SignerIdentityRecord::agent(key, name, chain)
                    .render()
                    .unwrap(),
            );
            let before = f.raw();
            assert_eq!(
                f.bind(&f.owner).unwrap_err().code(),
                "profile.bind_signer_record_conflict"
            );
            assert_eq!(f.raw(), before);
        }
    }

    #[test]
    #[serial]
    fn the_agent_key_is_no_owner_proof() {
        let f = Fixture::new();
        let agent = SigningKey::from_bytes(&[21; 32]);
        f.pin(&agent, 2);
        let before = f.raw();
        assert_eq!(
            f.bind(&agent).unwrap_err().code(),
            "profile.bind_signer_owner_is_signer"
        );
        assert_eq!(f.raw(), before);
    }

    #[test]
    #[serial]
    fn rebinding_follows_the_rotated_pin() {
        let f = Fixture::new();
        assert!(f.bind(&f.owner).unwrap());
        let next = SigningKey::from_bytes(&[12; 32]);
        use stellar_agent_core::policy::v1::{
            PolicyStateStore,
            canonical::canonical_bytes,
            signature::{build_owner_rotation, digest, sign},
            verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
        };
        let mut doc = include_str!("../../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
            .replace("operator", "v")
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        doc.remove("mainnet");
        doc["sequence"] = toml_edit::value(2);
        let body = doc.to_string();
        doc["owner_rotation"] = toml_edit::Item::Table(
            build_owner_rotation(&body, &f.owner, &next.verifying_key().to_bytes()).unwrap(),
        );
        let body = doc.to_string();
        let signature = sign(&digest(&canonical_bytes(&body).unwrap()), &next);
        let path = f.dir.path().join("policy.toml");
        std::fs::write(
            &path,
            format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(next.verifying_key().to_bytes()),
                stellar_agent_core::hex::encode(&signature)
            ),
        )
        .unwrap();
        let policy = load_verified_policy(
            &PolicyLoad {
                path: &path,
                profile: &f.profile,
                profile_name: "v",
                owner_pubkey: &next.verifying_key().to_bytes(),
                owner_source: OwnerKeySource::Keyring,
                window_path: &f.window(),
            },
            PolicyStateStore::new(),
            PinMode::Advance,
        )
        .unwrap();
        assert_eq!(policy.owner(), next.verifying_key().to_bytes());
        let before = f.raw();
        assert_eq!(
            f.bind(&f.owner).unwrap_err().code(),
            "profile.bind_signer_owner_mismatch"
        );
        assert_eq!(f.raw(), before);
        assert!(f.bind(&next).unwrap());
        let record = SignerIdentityRecord::parse(&f.raw()).unwrap();
        assert_eq!(
            record.binding.as_ref().unwrap().owner.unwrap().0,
            next.verifying_key().to_bytes()
        );
        assert!(
            record
                .verify_owner_signature(&f.profile.mcp_signer_default)
                .is_ok()
        );
    }
}
