//! `init_platform_keyring_store` headless-backend dispatch.
//!
//! An integration test (not a `src/keyring.rs` unit test) because
//! `stellar-agent-network`'s crate root carries `#![forbid(unsafe_code)]`,
//! which cannot be locally overridden even for test-only `std::env::set_var`
//! — this file is its own compilation unit and is not subject to that
//! crate-level attribute.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in unit tests"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;
use stellar_agent_core::error::ErrorCategory;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_network::init_platform_keyring_store;

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

/// `init_platform_keyring_store` dispatches to the headless store — not the
/// platform store — when `STELLAR_AGENT_KEYRING_BACKEND` is set, proven by a
/// real write+read round trip against the SAME `KeyringEntryRef` coordinate
/// every existing enroll/rotate/sign call site uses (`keyring_core::Entry::new`
/// unchanged).
#[test]
#[serial]
fn init_platform_keyring_store_dispatches_to_headless_env_backend() {
    let dir = tempfile::tempdir().expect("tmp dir");
    let key = URL_SAFE_NO_PAD.encode([0x33u8; 32]);
    let _guard = EnvGuard::set(&[
        (
            stellar_agent_headless_keyring::BACKEND_ENV_VAR,
            "headless-env",
        ),
        (stellar_agent_headless_keyring::ENV_KEY_VAR, key.as_str()),
        (
            "STELLAR_AGENT_HOME",
            dir.path().to_str().expect("utf8 path"),
        ),
    ]);

    init_platform_keyring_store().expect("headless dispatch must succeed");

    let entry_ref = KeyringEntryRef::new("stellar-agent-headless-dispatch-test", "default");
    let entry = keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .expect("entry construction");
    entry.set_password("dispatch-test-value").expect("set");
    assert_eq!(entry.get_password().expect("get"), "dispatch-test-value");

    // The write landed in the headless store's file, not any platform
    // credential store — proof the dispatch actually happened rather than
    // the platform store coincidentally being registered already.
    let on_disk =
        std::fs::read_to_string(dir.path().join("headless-keyring").join("store.keyring"))
            .expect("headless keyring file must exist on disk");
    assert!(on_disk.contains("headless-env"));
}

/// An unrecognised `STELLAR_AGENT_KEYRING_BACKEND` value refuses — never
/// silently falls back to the platform keyring.
#[test]
#[serial]
fn init_platform_keyring_store_refuses_unknown_backend_without_fallback() {
    let _guard = EnvGuard::set(&[(
        stellar_agent_headless_keyring::BACKEND_ENV_VAR,
        "not-a-real-backend",
    )]);

    let err = init_platform_keyring_store().unwrap_err();
    assert_eq!(err.category(), ErrorCategory::Auth);
    assert_eq!(err.code(), "auth.keyring_not_found");
}
