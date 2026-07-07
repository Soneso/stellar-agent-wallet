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
//! # Owner-key cross-check
//!
//! Before writing, the derived public key is compared against the owner public
//! key enrolled at the profile's owner coordinate (the key the engine will
//! verify against).  A seed that does not match the enrolled owner key would
//! produce a file the engine rejects, so signing refuses on a mismatch and
//! points the operator at `enroll-owner-key`.
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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde::Serialize;
use zeroize::Zeroizing;

use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::policy::v1::canonical::canonical_bytes;
use stellar_agent_core::policy::v1::signature::{digest, sign};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, default_policy_dir};
use stellar_agent_core::wallet::{MlockRequired, Wallet};

use crate::commands::policy_engine::OWNER_KEY_SERVICE_PREFIX;
use crate::common::render;

/// Arguments for `stellar-agent profile sign-policy`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct SignPolicyArgs {
    /// Profile whose policy file should be signed.
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub(crate) profile: String,

    /// Name of the environment variable that holds the owner `S...` strkey.
    ///
    /// The flag takes the variable NAME, never the secret itself.
    #[arg(long, value_name = "VAR")]
    pub(crate) secret_env: String,

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
    /// The G-strkey of the owner key that signed (equals the enrolled owner).
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
        |name| loader::load(name, None),
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
        Err(msg) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.owner_key_unavailable",
                msg,
            ));
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

    // ── Canonicalise the policy body (excludes the [signature] table) ─────────
    let canon = match canonical_bytes(&raw) {
        Ok(c) => c,
        Err(e) => {
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.canonicalization_failed",
                format!(
                    "policy file {} could not be canonicalised for signing ({e})",
                    policy_path.display()
                ),
            ));
            return 1;
        }
    };
    let d = digest(&canon);
    let digest_hex = to_hex(&d);

    // ── Sign the digest inside an mlock-protected window ──────────────────────
    // The policy signature is a raw ed25519 signature over the BLAKE3 digest — a
    // pre-image class distinct from every `Signer` trait method (Stellar tx/auth
    // payloads, which MUST NOT be substituted). The owner seed is pinned via
    // `Wallet::unlock` (matching `enroll-owner-key`'s mlock ceremony posture:
    // `Wallet::unlock` emits the same `tracing::warn!` on degradation) and the
    // dalek key is built from the pinned bytes only for this one signature.
    let (derived_pubkey, sig) = match sign_digest_with_owner_seed(
        &args.secret_env,
        profile.wallet.mlock_required,
        profile.wallet.unlock_ttl_seconds,
        &enrolled_pubkey,
        &d,
    )
    .await
    {
        Ok(pair) => pair,
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
            let enrolled_address = stellar_strkey::ed25519::PublicKey(enrolled_pubkey)
                .to_string()
                .to_string();
            render::render_json(&Envelope::<()>::err_raw(
                "sign_policy.owner_key_mismatch",
                format!(
                    "the seed in '{}' derives to owner key {derived_address}, but the profile's \
                     enrolled owner key is {enrolled_address}; a policy signed with this seed \
                     would be rejected by the engine. Supply the enrolled owner's seed, or \
                     re-enroll with `stellar-agent profile enroll-owner-key`. No file was written.",
                    args.secret_env
                ),
            ));
            return 1;
        }
    };
    let owner_address = stellar_strkey::ed25519::PublicKey(derived_pubkey)
        .to_string()
        .to_string();
    let sig_hex = to_hex(&sig);

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

    tracing::info!("policy file signed for profile '{}'", args.profile);
    render::render_json(&Envelope::ok(SignPolicyData {
        profile: args.profile.clone(),
        signed: true,
        owner_address,
        policy_path: policy_path.display().to_string(),
        digest: digest_hex,
        signature: sig_hex,
        replaced,
        previous_owner_id,
    }));
    0
}

/// Derives the engine's profile name by stripping [`OWNER_KEY_SERVICE_PREFIX`]
/// from `policy_owner_key_id.service`, matching the engine's own derivation.
///
/// Binding: this is the same prefix-strip the engine performs in
/// `commands::policy_engine::build_v1_policy_engine` (policy_engine.rs:74) and
/// `profile_name_from_key_ref` in `stellar-agent-mcp/src/server.rs:386`. The
/// shared [`OWNER_KEY_SERVICE_PREFIX`] constant is the single source of truth;
/// signing must derive the same name so it targets the owner coordinate and
/// policy path the engine will read.
fn engine_profile_name(profile: &Profile) -> Result<String, String> {
    let service = &profile.policy_owner_key_id.service;
    service
        .strip_prefix(OWNER_KEY_SERVICE_PREFIX)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            format!(
                "the profile's owner-key service '{service}' does not start with the expected \
                 prefix '{OWNER_KEY_SERVICE_PREFIX}'; the profile was not constructed with the \
                 standard owner coordinate"
            )
        })
}

/// Reads the enrolled owner public key (32 bytes) from the keyring coordinate.
fn read_owner_pubkey(coord: &KeyringEntryRef) -> Result<[u8; 32], String> {
    let entry = KeyringEntry::new(&coord.service, &coord.account).map_err(|e| {
        format!(
            "owner keyring entry '{}:{}' could not be opened ({e})",
            coord.service, coord.account
        )
    })?;
    let raw = entry.get_password().map_err(|_| {
        format!(
            "no owner key is enrolled at keyring service '{}' account '{}'; run \
             `stellar-agent profile enroll-owner-key` first",
            coord.service, coord.account
        )
    })?;
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).map_err(|e| {
        format!(
            "the enrolled owner key at '{}:{}' is not valid base64 ({e}); re-enroll with \
             `stellar-agent profile enroll-owner-key`",
            coord.service, coord.account
        )
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "the enrolled owner key at '{}:{}' decoded to {} bytes (expected 32); re-enroll with \
             `stellar-agent profile enroll-owner-key`",
            coord.service,
            coord.account,
            v.len()
        )
    })
}

/// Failure modes of [`sign_digest_with_owner_seed`].
enum OwnerSignError {
    /// The env var is unset or does not hold a valid `S...` strkey.
    Env(String),
    /// `Wallet::unlock` (mlock pinning) or seed access failed.
    Unlock(String),
    /// The seed derives to `derived`, which is not the enrolled owner key.
    Mismatch {
        /// The public key the supplied seed derives to.
        derived: [u8; 32],
    },
}

/// Reads the owner `S...` strkey from `var_name` into a zeroizing 32-byte seed.
///
/// The `Copy` residue `stellar_strkey` leaves in `PrivateKey.0` is explicitly
/// zeroized (the type has no `Drop`/`Zeroize` impl of its own).
fn seed_from_env(var_name: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let s_strkey: Zeroizing<String> = Zeroizing::new(
        std::env::var(var_name)
            .map_err(|_| format!("environment variable '{var_name}' not set"))?,
    );
    let mut private_key = stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey)
        .map_err(|_| format!("environment variable '{var_name}' contains an invalid S-strkey"))?;
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    zeroize::Zeroize::zeroize(&mut private_key.0);
    Ok(seed)
}

/// Signs `digest_bytes` with the owner seed from `var_name` inside an
/// mlock-protected window, refusing when the seed does not derive to
/// `enrolled_pubkey`.
///
/// The seed is pinned in RAM via `Wallet::unlock` for the derive-and-sign
/// window, matching `enroll-owner-key`'s posture: the same `mlock_required` /
/// `unlock_ttl_seconds` profile controls apply, and `Wallet::unlock` emits the
/// `wallet.mlock_failed` `tracing::warn!` on degradation. The wallet is
/// disposed (munlock + zeroize) before returning on every path.
async fn sign_digest_with_owner_seed(
    var_name: &str,
    mlock_required: MlockRequired,
    ttl_seconds: u32,
    enrolled_pubkey: &[u8; 32],
    digest_bytes: &[u8; 32],
) -> Result<([u8; 32], [u8; 64]), OwnerSignError> {
    let seed = seed_from_env(var_name).map_err(OwnerSignError::Env)?;
    let mut wallet = Wallet::unlock(
        "profile-sign-policy".to_owned(),
        seed,
        ttl_seconds,
        mlock_required,
    )
    .await
    .map_err(|e| OwnerSignError::Unlock(e.to_string()))?;

    let outcome = derive_and_sign(&wallet, enrolled_pubkey, digest_bytes);
    wallet.dispose();
    outcome
}

/// Builds the dalek key from the pinned seed, cross-checks the derived public
/// key against `enrolled_pubkey`, and signs `digest_bytes`.
///
/// The dalek `SigningKey` lives only for this call and zeroizes on drop.
fn derive_and_sign(
    wallet: &Wallet,
    enrolled_pubkey: &[u8; 32],
    digest_bytes: &[u8; 32],
) -> Result<([u8; 32], [u8; 64]), OwnerSignError> {
    let seed_ref = wallet
        .seed()
        .map_err(|e| OwnerSignError::Unlock(e.to_string()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed_ref);
    let derived = signing_key.verifying_key().to_bytes();
    if &derived != enrolled_pubkey {
        return Err(OwnerSignError::Mismatch { derived });
    }
    Ok((derived, sign(digest_bytes, &signing_key)))
}

/// Atomically writes `contents` to `path`: writes a temp file in the same
/// directory, fsyncs it, then renames it over the target.
///
/// The policy file is the root-of-trust document; a mid-write crash must not
/// truncate or corrupt the operator's body. `rename(2)` is atomic on a single
/// host, mirroring the profile writer's approach
/// (`stellar-agent-core::profile::migrate`).
fn atomic_write_string(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
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
        entry.set_password(&URL_SAFE_NO_PAD.encode(pk)).unwrap();
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
            profile: PROFILE_NAME.to_owned(),
            secret_env: var.to_owned(),
            file: Some(file.to_path_buf()),
        }
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

    #[tokio::test]
    #[serial]
    async fn missing_owner_key_points_at_enroll() {
        keyring_mock::install().expect("mock store");
        // No owner key enrolled.
        let (s_strkey, _pk, _g) = seed_material([0x11u8; 32]);
        let dir = TempDir::new().unwrap();
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
            profile: "__nonexistent_sign_policy__".to_owned(),
            secret_env: "__UNSET_SIGN_POLICY_VAR__".to_owned(),
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
}
