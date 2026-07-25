//! Single classification point for platform-keyring failures.
//!
//! Every keyring operation — entry construction (`Entry::new`), reads
//! (`get_password`), and writes (`set_password`) — routes its
//! `keyring_core::Error` through [`classify_keyring_error`] (or its
//! `WalletError`-returning wrapper [`map_keyring_error`]) so that
//! environmental causes are reported precisely. Hand-rolling
//! [`AuthError::KeyringNotFound`] around a failed keyring op misreports those
//! causes — most notably a non-interactive Windows session, which must surface
//! as [`AuthError::KeyringInteractiveSessionRequired`], not "not found".
//!
//! `stellar-agent-network` re-exports [`classify_keyring_error`] and
//! [`map_keyring_error`] from `stellar_agent_network::keyring`, so existing
//! callers on that path are unaffected by the classifier living in core.

use crate::error::{AuthError, WalletError};

/// Maps a `keyring_core::Error` to a `WalletError`.
///
/// Wire-level wrapper over [`classify_keyring_error`]; see there for the
/// classification contract. Callers that render a `WalletError` envelope use
/// this form; callers with their own error domain wrap the [`AuthError`]
/// from [`classify_keyring_error`] instead.
#[must_use]
pub fn map_keyring_error(e: &keyring_core::Error, service: &str) -> WalletError {
    WalletError::Auth(classify_keyring_error(e, service))
}

/// Classifies a `keyring_core::Error` into a typed [`AuthError`].
///
/// This is the single classification point for EVERY keyring operation —
/// entry construction (`Entry::new`), reads (`get_password`), and writes
/// (`set_password`). Write paths must route through it too: hand-rolling
/// `KeyringNotFound` around a failed write misreports environmental causes
/// (most notably a non-interactive Windows session, which must surface as
/// [`AuthError::KeyringInteractiveSessionRequired`], not "not found").
///
/// The service name is included (non-secret keyring coordinate used in
/// diagnostics); the password, account name, and any secret content are
/// NEVER included in the error message.
#[must_use]
pub fn classify_keyring_error(e: &keyring_core::Error, service: &str) -> AuthError {
    match e {
        keyring_core::Error::NoEntry => AuthError::KeyringNotFound {
            name: service.to_owned(),
        },
        keyring_core::Error::NoDefaultStore => AuthError::KeyringNotFound {
            name: format!(
                "{service} (no OS credential store is available for this session; ensure the platform keychain — macOS Keychain, GNOME Keyring / KWallet, or Windows Credential Manager — is running and unlocked)"
            ),
        },
        keyring_core::Error::NoStorageAccess(inner) if is_windows_no_logon_session(inner) => {
            AuthError::KeyringInteractiveSessionRequired
        }
        keyring_core::Error::PlatformFailure(_) | keyring_core::Error::NoStorageAccess(_) => {
            AuthError::KeyringPlatformError
        }
        // All other variants (BadEncoding, Ambiguous, TooLong, Invalid, etc.)
        // are reported as KeyringNotFound with the service name only.
        _ => AuthError::KeyringNotFound {
            name: service.to_owned(),
        },
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
    use super::*;
    use crate::error::ErrorCategory;

    #[test]
    fn no_entry_maps_to_keyring_not_found() {
        let err = map_keyring_error(&keyring_core::Error::NoEntry, "my-svc");
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
    }

    #[test]
    fn no_default_store_maps_to_keyring_not_found() {
        let err = map_keyring_error(&keyring_core::Error::NoDefaultStore, "my-svc");
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
        // The message mentions the service name (non-secret) and stays
        // operator-actionable: it must not expose the password / account and
        // must not leak the internal `init_platform_keyring_store` API name.
        assert!(err.message().contains("my-svc"), "service name in message");
        assert!(
            !err.message().contains("init_platform_keyring_store"),
            "operator-facing message must not name the internal init API"
        );
    }

    #[test]
    fn platform_failure_maps_to_keyring_platform_error() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::PlatformFailure(Box::new(io::Error::other("os error"))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }

    /// `windows-native-keyring-store` v1.1.0 maps Win32
    /// `ERROR_NO_SUCH_LOGON_SESSION` (1312) to
    /// `NoStorageAccess(Box<PlatformError(1312)>)` whose `Display` is the
    /// fixed text `"Windows ERROR_NO_SUCH_LOGON_SESSION"` (the concrete
    /// `PlatformError` type is private to that crate, so a string match on
    /// this exact text is the only signal available across the crate
    /// boundary). This test constructs that text directly rather than
    /// depending on the Windows-only backend, so it runs on every platform.
    #[test]
    fn no_storage_access_with_no_logon_session_text_maps_to_interactive_session_required() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::NoStorageAccess(Box::new(io::Error::other(
                "Windows ERROR_NO_SUCH_LOGON_SESSION",
            ))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
        assert!(
            err.message().contains("interactive logon session"),
            "message must state the interactive-session cause: {}",
            err.message()
        );
    }

    /// A `NoStorageAccess` failure NOT caused by the logon-session case (e.g.
    /// a locked/unavailable credential store for another reason) must keep
    /// mapping to the pre-existing `auth.keyring_platform_error` code, not the
    /// new interactive-session-specific one.
    #[test]
    fn no_storage_access_other_reason_still_maps_to_keyring_platform_error() {
        use std::io;
        let err = map_keyring_error(
            &keyring_core::Error::NoStorageAccess(Box::new(io::Error::other("keychain is locked"))),
            "my-svc",
        );
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_platform_error");
    }
}
