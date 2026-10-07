//! Safe, operation-aware classification of credential store failures.
//!
//! Diagnostics use fixed labels and numeric OS codes. Upstream error and
//! credential formatting can contain secrets and must never reach the detail.

use crate::error::{AuthError, WalletError};

/// The credential operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyringOperation {
    /// Construct an entry handle.
    Construct,
    /// Read a credential.
    Read,
    /// Write a credential.
    Write,
    /// Delete a credential.
    Delete,
}

impl KeyringOperation {
    /// Fixed label used in safe diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Construct => "construct",
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }
}

/// Returns a fixed label for the currently registered credential store.
///
/// Vendor values match the pinned platform backends exactly. Unknown metadata
/// is never rendered, since a store can include credentials in those strings.
#[must_use]
pub fn keyring_store_label() -> &'static str {
    let Some(store) = keyring_core::get_default_store() else {
        return "no default store";
    };
    match store.vendor().as_str() {
        "macOS Keychain Store, https://crates.io/crates/apple-native-keyring-store" => {
            "macOS Keychain"
        }
        "Secret Service store, https://crates.io/crates/dbus-secret-service-keyring-store" => {
            "Linux Secret Service"
        }
        "Windows Credential Manager, https://crates.io/crates/windows-native-keyring-store" => {
            "Windows Credential Manager"
        }
        "stellar-agent-headless-keyring" => match store.id().as_str() {
            "stellar-agent-headless-keyring/headless-env" => "headless-env",
            "stellar-agent-headless-keyring/headless-dpapi" => "headless-dpapi",
            _ => "unknown credential store",
        },
        _ => "unknown credential store",
    }
}

/// Classifies a read failure as a [`WalletError`].
#[must_use]
#[deprecated(note = "use the operation-aware function")]
pub fn map_keyring_error(e: &keyring_core::Error, service: &str) -> WalletError {
    map_keyring_operation_error(e, KeyringOperation::Read, service)
}

/// Classifies a credential operation failure as a [`WalletError`].
#[must_use]
pub fn map_keyring_operation_error(
    e: &keyring_core::Error,
    operation: KeyringOperation,
    service: &str,
) -> WalletError {
    WalletError::Auth(classify_keyring_operation_error(e, operation, service))
}

/// Classifies a read failure as an [`AuthError`].
#[must_use]
#[deprecated(note = "use the operation-aware function")]
pub fn classify_keyring_error(e: &keyring_core::Error, service: &str) -> AuthError {
    classify_keyring_operation_error(e, KeyringOperation::Read, service)
}

/// Classifies a credential operation failure without exposing upstream data.
///
/// Only missing reads use [`AuthError::KeyringNotFound`]. Windows no-logon
/// failures keep their interactive-session guidance for every operation.
/// The service appears only in missing-read diagnostics.
#[must_use]
pub fn classify_keyring_operation_error(
    e: &keyring_core::Error,
    operation: KeyringOperation,
    service: &str,
) -> AuthError {
    use keyring_core::Error;
    let cause = match e {
        Error::NoEntry if operation == KeyringOperation::Read => {
            return AuthError::KeyringNotFound {
                name: service.to_owned(),
            };
        }
        Error::NoDefaultStore if operation == KeyringOperation::Read => {
            return AuthError::KeyringNotFound {
                name: format!(
                    "{service} (no OS credential store is available for this session; ensure the platform keychain — macOS Keychain, GNOME Keyring / KWallet, or Windows Credential Manager — is running and unlocked)"
                ),
            };
        }
        Error::NoStorageAccess(inner) if is_windows_no_logon_session(inner) => {
            return AuthError::KeyringInteractiveSessionRequired;
        }
        Error::PlatformFailure(inner) => os_cause("credential store operation failed", inner),
        Error::NoStorageAccess(inner) => os_cause("credential store access denied", inner),
        Error::NoEntry => "no matching credential".to_owned(),
        Error::NoDefaultStore => "no default credential store is configured".to_owned(),
        Error::BadEncoding(_) => "stored password is not valid UTF-8".to_owned(),
        Error::BadDataFormat(_, _) => "stored value could not be decoded".to_owned(),
        Error::BadStoreFormat(_) => "credential store is not readable".to_owned(),
        Error::TooLong(_, _) => "credential attribute exceeds the store limit".to_owned(),
        Error::Invalid(_, _) => "invalid credential parameter".to_owned(),
        Error::Ambiguous(entries) => format!("multiple matching credentials ({})", entries.len()),
        Error::NotSupportedByStore(_) => {
            "operation is not supported by the credential store".to_owned()
        }
        _ => "unclassified keyring error".to_owned(),
    };
    AuthError::KeyringPlatformError {
        detail: format!("{} {}: {cause}", operation.label(), keyring_store_label()),
    }
}

fn os_cause(cause: &str, inner: &keyring_core::error::PlatformError) -> String {
    match inner
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
    {
        Some(code) => format!("{cause} (OS error {code})"),
        None => cause.to_owned(),
    }
}

/// Detects whether a `keyring_core::Error::NoStorageAccess` inner error is the
/// Windows `ERROR_NO_SUCH_LOGON_SESSION` (1312) case.
///
/// `windows-native-keyring-store` v1.1.0 maps that Win32 error to
/// `NoStorageAccess(Box<PlatformError(1312)>)` (`utils.rs::decode_error`),
/// where `PlatformError`'s `Display` renders the fixed text
/// `"Windows ERROR_NO_SUCH_LOGON_SESSION"` (`utils.rs::PlatformError::fmt`).
/// The concrete `PlatformError` type is private to that crate (`mod utils;`,
/// not `pub mod utils;`), so a string match on the `Display` text is the only
/// signal available across the crate boundary — there is no numeric error
/// code or public type to downcast to.
fn is_windows_no_logon_session(inner: &keyring_core::error::PlatformError) -> bool {
    inner.to_string().contains("ERROR_NO_SUCH_LOGON_SESSION")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]
    use super::*;
    use crate::error::ErrorCategory;
    use keyring_core::api::{CredentialApi, CredentialStoreApi};
    use keyring_core::{Entry, Error};
    use serial_test::serial;
    use std::sync::Arc;

    const ACCOUNT: &str = "account-sentinel-never-render";
    const SECRET: &str = "secret-sentinel-never-render";
    const RAW: &[u8] = &[219, 237, 191, 241, 203];
    const HOSTILE: &str = "inner-error-sentinel-never-render";

    struct RestoreStore(Option<Arc<keyring_core::CredentialStore>>);
    impl RestoreStore {
        fn new() -> Self {
            Self(keyring_core::unset_default_store())
        }
    }
    impl Drop for RestoreStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(store) = self.0.take() {
                keyring_core::set_default_store(store);
            }
        }
    }

    #[derive(Debug)]
    struct MetadataStore {
        vendor: String,
        id: String,
    }
    impl CredentialStoreApi for MetadataStore {
        fn vendor(&self) -> String {
            self.vendor.clone()
        }
        fn id(&self) -> String {
            self.id.clone()
        }
        fn build(
            &self,
            _: &str,
            _: &str,
            _: Option<&std::collections::HashMap<&str, &str>>,
        ) -> keyring_core::Result<Entry> {
            Err(Error::NoEntry)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct HostileCredential;
    impl CredentialApi for HostileCredential {
        fn set_secret(&self, _: &[u8]) -> keyring_core::Result<()> {
            Err(Error::NoEntry)
        }
        fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
            Err(Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring_core::Result<()> {
            Err(Error::NoEntry)
        }
        fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::Credential>>> {
            Ok(None)
        }
        fn get_specifiers(&self) -> Option<(String, String)> {
            Some((SECRET.to_owned(), ACCOUNT.to_owned()))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{ACCOUNT} {SECRET} {RAW:?} {HOSTILE}")
        }
    }

    fn hostile_text() -> String {
        format!("{ACCOUNT} {SECRET} {RAW:?} {HOSTILE}")
    }
    struct HostileInner;
    impl std::fmt::Display for HostileInner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&hostile_text())
        }
    }
    impl std::fmt::Debug for HostileInner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&hostile_text())
        }
    }
    impl std::error::Error for HostileInner {}
    fn hostile_inner() -> keyring_core::error::PlatformError {
        Box::new(HostileInner)
    }
    fn assert_safe(error: &AuthError) {
        for rendered in [error.to_string(), format!("{error:?}")] {
            for forbidden in [
                ACCOUNT.to_owned(),
                SECRET.to_owned(),
                format!("{RAW:?}").trim_matches(['[', ']']).to_owned(),
                HOSTILE.to_owned(),
            ] {
                assert!(
                    !rendered.contains(&forbidden),
                    "classified error exposes sentinel: {rendered}"
                );
            }
        }
    }

    fn assert_platform(error: &Error, cause: &str) {
        let _restore = RestoreStore::new();
        for (operation, label) in [
            (KeyringOperation::Construct, "construct"),
            (KeyringOperation::Read, "read"),
            (KeyringOperation::Write, "write"),
            (KeyringOperation::Delete, "delete"),
        ] {
            if operation == KeyringOperation::Read
                && matches!(error, Error::NoEntry | Error::NoDefaultStore)
            {
                continue;
            }
            let classified = classify_keyring_operation_error(error, operation, SECRET);
            assert_safe(&classified);
            assert_eq!(classified.code(), "auth.keyring_platform_error");
            assert_eq!(
                classified.to_string(),
                format!("keyring operation failed: {label} no default store: {cause}")
            );
        }
    }

    #[test]
    #[serial]
    fn platform_failure_has_safe_operation_detail() {
        assert_platform(
            &Error::PlatformFailure(hostile_inner()),
            "credential store operation failed",
        );
    }

    #[test]
    #[serial]
    fn no_storage_access_has_safe_operation_detail() {
        assert_platform(
            &Error::NoStorageAccess(hostile_inner()),
            "credential store access denied",
        );
    }

    #[test]
    #[serial]
    fn no_entry_has_safe_operation_detail() {
        assert_platform(&Error::NoEntry, "no matching credential");
    }

    #[test]
    #[serial]
    fn no_default_store_has_safe_operation_detail() {
        assert_platform(
            &Error::NoDefaultStore,
            "no default credential store is configured",
        );
    }

    #[test]
    #[serial]
    fn bad_encoding_has_safe_operation_detail() {
        assert_platform(
            &Error::BadEncoding([hostile_text().as_bytes(), RAW].concat()),
            "stored password is not valid UTF-8",
        );
    }

    #[test]
    #[serial]
    fn bad_data_format_has_safe_operation_detail() {
        assert_platform(
            &Error::BadDataFormat([hostile_text().as_bytes(), RAW].concat(), hostile_inner()),
            "stored value could not be decoded",
        );
    }

    #[test]
    #[serial]
    fn bad_store_format_has_safe_operation_detail() {
        assert_platform(
            &Error::BadStoreFormat(hostile_text()),
            "credential store is not readable",
        );
    }

    #[test]
    #[serial]
    fn too_long_has_safe_operation_detail() {
        assert_platform(
            &Error::TooLong(hostile_text(), 123),
            "credential attribute exceeds the store limit",
        );
    }

    #[test]
    #[serial]
    fn invalid_has_safe_operation_detail() {
        assert_platform(
            &Error::Invalid(hostile_text(), hostile_text()),
            "invalid credential parameter",
        );
    }

    #[test]
    #[serial]
    fn ambiguous_has_safe_operation_detail() {
        assert_platform(
            &Error::Ambiguous(vec![
                Entry::new_with_credential(Arc::new(HostileCredential)),
                Entry::new_with_credential(Arc::new(HostileCredential)),
            ]),
            "multiple matching credentials (2)",
        );
    }

    #[test]
    #[serial]
    fn not_supported_has_safe_operation_detail() {
        assert_platform(
            &Error::NotSupportedByStore(hostile_text()),
            "operation is not supported by the credential store",
        );
    }

    #[test]
    #[serial]
    fn platform_failure_preserves_only_os_code() {
        assert_platform(
            &Error::PlatformFailure(Box::new(std::io::Error::from_raw_os_error(123))),
            "credential store operation failed (OS error 123)",
        );
    }

    #[test]
    #[serial]
    fn access_failure_preserves_only_os_code() {
        assert_platform(
            &Error::NoStorageAccess(Box::new(std::io::Error::from_raw_os_error(123))),
            "credential store access denied (OS error 123)",
        );
    }

    #[test]
    #[serial]
    fn macos_store_has_fixed_label() {
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(Arc::new(MetadataStore {
            vendor: "macOS Keychain Store, https://crates.io/crates/apple-native-keyring-store"
                .to_owned(),
            id: "unused".to_owned(),
        }));
        assert_eq!(keyring_store_label(), "macOS Keychain");
        let err =
            classify_keyring_operation_error(&Error::NoEntry, KeyringOperation::Write, SECRET);
        assert_eq!(
            err.to_string(),
            "keyring operation failed: write macOS Keychain: no matching credential"
        );
    }

    #[test]
    #[serial]
    fn linux_store_has_fixed_label() {
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(Arc::new(MetadataStore {
            vendor:
                "Secret Service store, https://crates.io/crates/dbus-secret-service-keyring-store"
                    .to_owned(),
            id: "unused".to_owned(),
        }));
        assert_eq!(keyring_store_label(), "Linux Secret Service");
        let err =
            classify_keyring_operation_error(&Error::NoEntry, KeyringOperation::Write, SECRET);
        assert_eq!(
            err.to_string(),
            "keyring operation failed: write Linux Secret Service: no matching credential"
        );
    }

    #[test]
    #[serial]
    fn windows_store_has_fixed_label() {
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(Arc::new(MetadataStore {
            vendor:
                "Windows Credential Manager, https://crates.io/crates/windows-native-keyring-store"
                    .to_owned(),
            id: "unused".to_owned(),
        }));
        assert_eq!(keyring_store_label(), "Windows Credential Manager");
        let err =
            classify_keyring_operation_error(&Error::NoEntry, KeyringOperation::Write, SECRET);
        assert_eq!(
            err.to_string(),
            "keyring operation failed: write Windows Credential Manager: no matching credential"
        );
    }

    #[test]
    #[serial]
    fn headless_env_store_has_fixed_label() {
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(Arc::new(MetadataStore {
            vendor: "stellar-agent-headless-keyring".to_owned(),
            id: "stellar-agent-headless-keyring/headless-env".to_owned(),
        }));
        assert_eq!(keyring_store_label(), "headless-env");
        let err =
            classify_keyring_operation_error(&Error::NoEntry, KeyringOperation::Write, SECRET);
        assert_eq!(
            err.to_string(),
            "keyring operation failed: write headless-env: no matching credential"
        );
    }

    #[test]
    #[serial]
    fn headless_dpapi_store_has_fixed_label() {
        let _restore = RestoreStore::new();
        keyring_core::set_default_store(Arc::new(MetadataStore {
            vendor: "stellar-agent-headless-keyring".to_owned(),
            id: "stellar-agent-headless-keyring/headless-dpapi".to_owned(),
        }));
        assert_eq!(keyring_store_label(), "headless-dpapi");
        let err =
            classify_keyring_operation_error(&Error::NoEntry, KeyringOperation::Write, SECRET);
        assert_eq!(
            err.to_string(),
            "keyring operation failed: write headless-dpapi: no matching credential"
        );
    }

    #[test]
    #[serial]
    fn unknown_store_metadata_is_not_rendered() {
        let _restore = RestoreStore::new();
        for vendor in [
            hostile_text(),
            "stellar-agent-headless-keyring".to_owned(),
            "macOS Keychain Store".to_owned(),
        ] {
            keyring_core::set_default_store(Arc::new(MetadataStore {
                vendor,
                id: hostile_text(),
            }));
            let error = classify_keyring_operation_error(
                &Error::NoEntry,
                KeyringOperation::Construct,
                SECRET,
            );
            assert_eq!(
                error.to_string(),
                "keyring operation failed: construct unknown credential store: no matching credential"
            );
            assert_safe(&error);
        }
    }

    #[test]
    #[serial]
    fn missing_store_construction_is_platform_failure() {
        let _restore = RestoreStore::new();
        assert_eq!(keyring_store_label(), "no default store");
        let error = Entry::new("service", ACCOUNT).unwrap_err();
        let classified =
            map_keyring_operation_error(&error, KeyringOperation::Construct, "service");
        assert_eq!(classified.code(), "auth.keyring_platform_error");
        assert_eq!(
            classified.message(),
            "keyring operation failed: construct no default store: no default credential store is configured"
        );
    }

    #[test]
    #[serial]
    fn injected_write_no_entry_is_platform_failure() {
        let _restore = RestoreStore::new();
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let entry = Entry::new("service", ACCOUNT).unwrap();
        entry
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .unwrap()
            .set_error(Error::NoEntry);
        let error = entry.set_password(SECRET).unwrap_err();
        let classified = map_keyring_operation_error(&error, KeyringOperation::Write, "service");
        assert_eq!(classified.code(), "auth.keyring_platform_error");
        assert_eq!(
            classified.message(),
            "keyring operation failed: write unknown credential store: no matching credential"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn missing_read_and_legacy_wrappers_keep_guidance() {
        for (error, expected) in [
            (Error::NoEntry, "keyring entry 'service' was not found"),
            (
                Error::NoDefaultStore,
                "keyring entry 'service (no OS credential store is available for this session; ensure the platform keychain — macOS Keychain, GNOME Keyring / KWallet, or Windows Credential Manager — is running and unlocked)' was not found",
            ),
        ] {
            for classified in [
                map_keyring_error(&error, "service"),
                WalletError::Auth(classify_keyring_error(&error, "service")),
            ] {
                assert_eq!(classified.code(), "auth.keyring_not_found");
                assert_eq!(classified.message(), expected);
                assert_eq!(classified.category(), ErrorCategory::Auth);
            }
        }
    }

    #[test]
    fn no_logon_session_keeps_guidance_for_every_operation() {
        for operation in [
            KeyringOperation::Construct,
            KeyringOperation::Read,
            KeyringOperation::Write,
            KeyringOperation::Delete,
        ] {
            let error = Error::NoStorageAccess(Box::new(std::io::Error::other(
                "Windows ERROR_NO_SUCH_LOGON_SESSION",
            )));
            let classified = map_keyring_operation_error(&error, operation, "service");
            assert_eq!(
                classified.code(),
                "auth.keyring_interactive_session_required"
            );
            assert!(classified.message().contains("interactive logon session"));
        }
    }
}
