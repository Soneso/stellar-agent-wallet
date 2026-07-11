//! Opt-in, file-backed keyring store for headless deployments.
//!
//! # Why
//!
//! Windows Credential Manager requires an interactive logon session; a
//! Windows service, an SSH/WinRM session, or a "run whether user is logged
//! on or not" scheduled task cannot use it — `stellar-agent`'s keyring reads
//! and writes fail closed with `auth.keyring_interactive_session_required`.
//! This crate provides an alternative store an operator can opt into for
//! exactly those deployment shapes.
//!
//! # Activation — opt-in, fail-closed default
//!
//! The platform keyring (macOS Keychain / Linux Secret Service / Windows
//! Credential Manager) remains the default in every case. This store
//! activates ONLY when the environment variable
//! `STELLAR_AGENT_KEYRING_BACKEND` is set on the process, to one of:
//!
//! - `headless-env` — [`crypto::ProtectionMode::EnvKey`] (every platform).
//! - `headless-dpapi` — [`crypto::ProtectionMode::Dpapi`] (Windows only).
//!
//! `stellar_agent_network::keyring::init_platform_keyring_store` (called at
//! every existing keyring-consuming call site, unchanged) checks this env
//! var FIRST and, when set, calls [`init_headless_store`] instead of
//! registering the platform store — no call-site changes anywhere in the CLI
//! or MCP server were needed to wire this in. There is no profile-file
//! `[keyring] backend = ...` surface in this iteration: the mechanical cost
//! of threading a `Profile` reference through every one of the ~25
//! `init_platform_keyring_store()` call sites (most of which do not have a
//! loaded profile in scope at that point) was judged not worth it against an
//! env var that already fully serves the deployment shape this feature
//! targets (an operator provisioning a headless host sets one process-wide
//! environment variable, not per-profile TOML edits across every profile on
//! that host).
//!
//! Selecting `headless-dpapi` on a non-Windows target, or `headless-env`
//! without `STELLAR_AGENT_HEADLESS_KEYRING_KEY` set to a valid 32-byte
//! URL-safe-base64 key, fails [`init_headless_store`] immediately — this
//! store NEVER silently falls back to the platform keyring or to an
//! unprotected store.
//!
//! # Protection modes and trust model
//!
//! - **`headless-env`** — every entry is sealed with XChaCha20-Poly1305
//!   (crate `chacha20poly1305` 0.11.0) under a 32-byte key read from
//!   `STELLAR_AGENT_HEADLESS_KEYRING_KEY` (URL-safe base64, no padding — the
//!   same 32-byte-secret encoding convention this codebase uses everywhere
//!   else, e.g. `stellar_agent_network::keyring::rotate_keyring_secret_32`).
//!   **The environment variable is the root of trust**: anyone who can read
//!   it (or who can read the process environment of a process that has it
//!   set) can decrypt every entry in the store. Intended for Linux services
//!   and CI where a secret manager or orchestrator already injects
//!   environment variables under access control the operator trusts.
//! - **`headless-dpapi`** (Windows only) — every entry is sealed with
//!   `CryptProtectData` / `CryptUnprotectData`, CurrentUser scope, via
//!   `stellar_agent_windows_identity::dpapi_protect` /
//!   `dpapi_unprotect` (`CRYPTPROTECT_UI_FORBIDDEN`, so a headless session
//!   can never block on a UI prompt). **Any process running as the same
//!   Windows user can decrypt the result — the SAME trust boundary as
//!   Windows Credential Manager**, minus the interactive-logon-session
//!   requirement DPAPI CurrentUser scope does not have. This is the mode the
//!   tester's `stellar-win-vm` acceptance evidence targets (an SSH / network
//!   logon session).
//!
//! Both modes fail closed on a corrupted or tampered entry — see
//! [`crypto`]'s module docs.
//!
//! # Storage
//!
//! One JSON file for the whole host/user at
//! `<state>/stellar-agent/headless-keyring/store.keyring`
//! (`0600` on Unix; parent-directory-inherited ACL on Windows), written
//! atomically (temp-file + `sync_data` + rename + parent-directory fsync —
//! the `PersistedWindowStore` / `stellar_agent_core::audit_log` sidecar-write
//! precedent). One file (not one per profile) mirrors the platform
//! keyring's own single-shared-store shape; see [`init_headless_store`]'s
//! docs for why this is safe. See [`store`]'s module docs for the wire
//! format and the single-process-writer scope limitation.
//!
//! # Coordinate compatibility
//!
//! [`store::HeadlessStore`] implements `keyring_core::api::CredentialStoreApi`
//! and slots in behind the exact SAME `KeyringEntryRef` (service, account)
//! coordinates every existing enroll/rotate/sign call site already uses —
//! `keyring_core::Entry::new(service, account)` is unchanged at every call
//! site; only which concrete store answers it differs. Every existing
//! keyring-consuming code path (owner-key enrollment, signer enrollment,
//! HMAC-key rotation, signing) therefore works unchanged once this store is
//! registered as the process default.
//!
//! # Audit
//!
//! Enrollments/rotations through this store emit the SAME
//! `KeyringKeyWritten` audit row every existing profile command already
//! emits — that emission is keyed off the `keyring_core::Entry::set_password`
//! call succeeding, which is backend-agnostic. This store additionally emits
//! a `headless_keyring.write` tracing log line naming the active protection
//! mode (`backend = "headless-env" | "headless-dpapi"`), so the backend kind
//! is visible in logs without a hash-chained audit-schema change.

pub mod crypto;
pub mod store;

use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroizing;

use crypto::ProtectionMode;
use store::HeadlessStore;

/// Name of the environment variable that opts a process into the headless
/// keyring store. Values: `"headless-env"` or `"headless-dpapi"`. Unset (the
/// default): the platform keyring is used, unchanged.
pub const BACKEND_ENV_VAR: &str = "STELLAR_AGENT_KEYRING_BACKEND";

/// Name of the environment variable holding the `headless-env` protection
/// mode's 32-byte AEAD key (URL-safe base64, no padding). Required when
/// [`BACKEND_ENV_VAR`] is `"headless-env"`; ignored otherwise.
pub const ENV_KEY_VAR: &str = "STELLAR_AGENT_HEADLESS_KEYRING_KEY";

/// Errors from [`init_headless_store`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HeadlessKeyringInitError {
    /// `STELLAR_AGENT_KEYRING_BACKEND` was set to a value other than
    /// `"headless-env"` or `"headless-dpapi"`.
    #[error(
        "{var} is set to an unrecognised value {value:?}; expected \"headless-env\" or \"headless-dpapi\""
    , var = BACKEND_ENV_VAR)]
    UnknownBackend {
        /// The unrecognised value.
        value: String,
    },
    /// `headless-dpapi` was selected on a non-Windows target.
    #[error("headless-dpapi is only available on Windows")]
    DpapiUnsupportedPlatform,
    /// `headless-env` was selected but `STELLAR_AGENT_HEADLESS_KEYRING_KEY`
    /// was missing, not valid base64, or not exactly 32 bytes.
    #[error("{ENV_KEY_VAR}: {0}")]
    InvalidEnvKey(&'static str),
    /// The OS-conventional state directory could not be determined.
    #[error(
        "could not determine the OS-conventional state directory for the headless keyring store"
    )]
    StateDirUnavailable,
}

/// Returns the value of [`BACKEND_ENV_VAR`] if set, or `None` (the platform
/// keyring applies, unchanged).
#[must_use]
pub fn requested_backend() -> Option<String> {
    std::env::var(BACKEND_ENV_VAR).ok()
}

/// Registers the headless keyring store as the process default, per
/// [`BACKEND_ENV_VAR`]'s value.
///
/// One store, one file, for the whole process — mirroring the platform
/// keyring's own shape (one Keychain / one Secret Service collection / one
/// Credential Manager vault shared by every profile on the host). This is
/// safe because the `(service, account)` coordinate space is ALREADY
/// profile-scoped by convention throughout this codebase (e.g.
/// `stellar-agent-owner-<profile>`, `stellar-agent-signer-<profile>`) — the
/// SAME disambiguation the platform keyring already relies on, not a new
/// property this store introduces.
///
/// Called by `stellar_agent_network::keyring::init_platform_keyring_store`
/// when [`requested_backend`] returns `Some`, in place of registering the
/// platform store. Never falls back to the platform store or to an
/// unprotected store on any failure — the caller MUST propagate `Err` and
/// refuse the operation (fail-closed).
///
/// # Errors
///
/// Returns [`HeadlessKeyringInitError`] if `backend` is not a recognised
/// value, `headless-dpapi` is selected on a non-Windows target,
/// `headless-env`'s key env var is missing/invalid, or the state directory
/// cannot be determined.
pub fn init_headless_store(backend: &str) -> Result<(), HeadlessKeyringInitError> {
    let mode = match backend {
        "headless-env" => {
            let raw = std::env::var(ENV_KEY_VAR).map_err(|_| {
                HeadlessKeyringInitError::InvalidEnvKey("environment variable is not set")
            })?;
            let key = crypto::parse_env_key(&raw).map_err(|e| match e {
                crypto::CryptoError::InvalidEnvKey(detail) => {
                    HeadlessKeyringInitError::InvalidEnvKey(detail)
                }
                _ => HeadlessKeyringInitError::InvalidEnvKey("key parse failed"),
            })?;
            ProtectionMode::EnvKey(Arc::new(Zeroizing::new(*key)))
        }
        "headless-dpapi" => {
            if cfg!(not(target_os = "windows")) {
                return Err(HeadlessKeyringInitError::DpapiUnsupportedPlatform);
            }
            ProtectionMode::Dpapi
        }
        other => {
            return Err(HeadlessKeyringInitError::UnknownBackend {
                value: other.to_owned(),
            });
        }
    };

    let path = headless_keyring_path()?;
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(HeadlessStore::new(path, mode.clone()));
    keyring_core::set_default_store(store);

    tracing::info!(
        target: "headless_keyring",
        event = "headless_keyring.store_registered",
        backend = mode.label(),
        "headless keyring store registered as process default"
    );
    Ok(())
}

/// Returns the OS-conventional headless-keyring file path:
/// `<canonical_data_root>/headless-keyring/store.keyring`.
///
/// One file for the whole host/user — see [`init_headless_store`]'s docs for
/// why this is safe (the coordinate space inside the file is already
/// profile-scoped, mirroring the platform keyring's own single-shared-store
/// shape).
///
/// Tests and the CI acceptance harness may set `STELLAR_AGENT_HOME` to
/// redirect the directory to `$STELLAR_AGENT_HOME/headless-keyring`,
/// mirroring the profile-loader's own override — gated behind `#[cfg(any(test,
/// feature = "test-helpers"))]` so production release builds never honour it.
///
/// # Canonical-root replication, not reuse
///
/// This crate cannot depend on `stellar-agent-core` (it is a low-level,
/// minimal-dependency store meant for headless/service deployments; pulling
/// in core's XDR/signing/tokio dependency closure here would be a layering
/// violation with no functional benefit — see the "prefer separate crates"
/// project convention). It therefore replicates
/// `stellar_agent_core::profile::schema::canonical_data_root`'s derivation
/// byte-for-byte instead of importing it: `directories::ProjectDirs::from("",
/// "Soneso", "stellar-agent").data_local_dir()`. The
/// `canonical_data_root_matches_stellar_agent_core` test below pins
/// byte-equality between the two crates' derivations (as a dev-dependency
/// only — this does not add `stellar-agent-core` to the crate's production
/// dependency graph) so the two cannot silently drift.
fn headless_keyring_path() -> Result<PathBuf, HeadlessKeyringInitError> {
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(home) = std::env::var_os("STELLAR_AGENT_HOME") {
        return Ok(PathBuf::from(home)
            .join("headless-keyring")
            .join("store.keyring"));
    }

    Ok(canonical_data_root()?
        .join("headless-keyring")
        .join("store.keyring"))
}

/// Replicates
/// `stellar_agent_core::profile::schema::canonical_data_root`'s derivation.
/// See `headless_keyring_path`'s rustdoc for why this crate cannot import
/// that function directly.
fn canonical_data_root() -> Result<PathBuf, HeadlessKeyringInitError> {
    directories::ProjectDirs::from("", "Soneso", "stellar-agent")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
        .ok_or(HeadlessKeyringInitError::StateDirUnavailable)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serial_test::serial;

    use super::*;

    /// RAII env-var guard; `#[serial]` on every test using it prevents
    /// concurrent env access.
    struct EnvGuard {
        vars: Vec<String>,
    }
    impl EnvGuard {
        #[allow(
            unsafe_code,
            reason = "test-only env mutation; #[serial] prevents concurrent access"
        )]
        fn set(pairs: &[(&str, &str)]) -> Self {
            let vars = pairs.iter().map(|(k, _)| (*k).to_owned()).collect();
            for (k, v) in pairs {
                // SAFETY: serialised by #[serial]; no concurrent env access.
                unsafe {
                    std::env::set_var(k, v);
                }
            }
            Self { vars }
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code, reason = "test-only env cleanup")]
        fn drop(&mut self) {
            for v in &self.vars {
                // SAFETY: same as set(); serialised by #[serial].
                unsafe {
                    std::env::remove_var(v);
                }
            }
        }
    }

    #[test]
    #[serial]
    fn requested_backend_is_none_when_unset() {
        // Ensure a clean slate regardless of test execution order within
        // this process (no #[serial]-guarded setter has run yet in this
        // test body).
        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] applies")]
        unsafe {
            std::env::remove_var(BACKEND_ENV_VAR);
        }
        assert_eq!(requested_backend(), None);
    }

    #[test]
    #[serial]
    fn requested_backend_reads_the_env_var() {
        let _guard = EnvGuard::set(&[(BACKEND_ENV_VAR, "headless-env")]);
        assert_eq!(requested_backend().as_deref(), Some("headless-env"));
    }

    #[test]
    #[serial]
    fn init_headless_store_rejects_unknown_backend() {
        let err = init_headless_store("not-a-real-backend").unwrap_err();
        assert!(matches!(
            err,
            HeadlessKeyringInitError::UnknownBackend { .. }
        ));
    }

    #[test]
    #[serial]
    fn init_headless_store_rejects_missing_env_key() {
        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] applies")]
        unsafe {
            std::env::remove_var(ENV_KEY_VAR);
        }
        let err = init_headless_store("headless-env").unwrap_err();
        assert!(matches!(err, HeadlessKeyringInitError::InvalidEnvKey(_)));
    }

    #[test]
    #[serial]
    fn init_headless_store_env_mode_round_trips() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let key = URL_SAFE_NO_PAD.encode([0x55u8; 32]);
        let _guard = EnvGuard::set(&[
            (ENV_KEY_VAR, key.as_str()),
            (
                "STELLAR_AGENT_HOME",
                dir.path().to_str().expect("utf8 path"),
            ),
        ]);

        init_headless_store("headless-env").expect("init must succeed");

        let entry = keyring_core::Entry::new("stellar-agent-signer-init-roundtrip", "default")
            .expect("entry construction");
        entry.set_password("s3cr3t").expect("set");
        assert_eq!(entry.get_password().expect("get"), "s3cr3t");
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    #[serial]
    fn init_headless_store_rejects_dpapi_on_non_windows() {
        let err = init_headless_store("headless-dpapi").unwrap_err();
        assert!(matches!(
            err,
            HeadlessKeyringInitError::DpapiUnsupportedPlatform
        ));
    }

    #[test]
    #[serial]
    fn headless_keyring_path_uses_stellar_agent_home_override() {
        let dir = tempfile::tempdir().expect("tmp dir");
        let _guard = EnvGuard::set(&[(
            "STELLAR_AGENT_HOME",
            dir.path().to_str().expect("utf8 path"),
        )]);
        let path = headless_keyring_path().expect("path resolution");
        assert_eq!(
            path,
            dir.path().join("headless-keyring").join("store.keyring")
        );
    }

    /// Pins byte-equality between this crate's replicated canonical-root
    /// derivation and `stellar_agent_core::profile::schema::canonical_data_root`.
    /// Guards against the two independently-maintained derivations silently
    /// drifting apart (see `headless_keyring_path`'s rustdoc).
    #[test]
    fn canonical_data_root_matches_stellar_agent_core() {
        let local = canonical_data_root().expect("local derivation must resolve");
        let core = stellar_agent_core::profile::schema::canonical_data_root()
            .expect("stellar-agent-core derivation must resolve");
        assert_eq!(
            local, core,
            "headless-keyring's replicated canonical root must byte-match \
             stellar-agent-core::profile::schema::canonical_data_root"
        );
    }
}
