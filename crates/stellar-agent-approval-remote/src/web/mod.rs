//! Static browser-side JS assets baked into the binary.
//!
//! Three same-origin, no-build-step vanilla JS files, split by
//! authentication state: [`LOGIN_JS`] runs the passkey login ceremony and is
//! served ungated at `GET /static/login.js` — the login ceremony itself IS
//! the authentication step, so no session exists yet for it to run behind.
//! [`ENROLL_JS`] runs the passkey-creation ceremony and is served ungated at
//! `GET /static/enroll.js`, for the same reason: enrollment must happen
//! before any session exists. [`APP_JS`] covers the inbox listing, the
//! per-approval detail rendering, and the per-action WebAuthn ceremony, and
//! is served behind the session cookie at `GET /static/app.js`, mirroring
//! the defence-in-depth posture of the loopback approval-inbox server's own
//! `/static/app.js` (also session-gated there, because that flow's
//! bootstrap step needs no client-side script to run before a session
//! exists).

/// Pre-authentication login-page browser glue served ungated at
/// `GET /static/login.js`. Source-of-truth: `src/web/login.js`.
pub(crate) const LOGIN_JS: &[u8] = include_bytes!("login.js");

/// Pre-authentication enrollment-page browser glue served ungated at
/// `GET /static/enroll.js`. Source-of-truth: `src/web/enroll.js`.
pub(crate) const ENROLL_JS: &[u8] = include_bytes!("enroll.js");

/// Post-authentication inbox / detail / per-action-ceremony browser glue,
/// served behind the session cookie at `GET /static/app.js`.
/// Source-of-truth: `src/web/app.js`.
pub(crate) const APP_JS: &[u8] = include_bytes!("app.js");

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    fn login_js_is_valid_utf8() {
        std::str::from_utf8(LOGIN_JS).expect("login.js must be valid UTF-8");
    }

    #[test]
    fn app_js_is_valid_utf8() {
        std::str::from_utf8(APP_JS).expect("app.js must be valid UTF-8");
    }

    #[test]
    fn enroll_js_is_valid_utf8() {
        std::str::from_utf8(ENROLL_JS).expect("enroll.js must be valid UTF-8");
    }

    #[test]
    fn login_js_wires_login_endpoints() {
        let body = std::str::from_utf8(LOGIN_JS).unwrap();
        assert!(body.contains("/login/challenge"));
        assert!(body.contains("/login/assertion"));
    }

    #[test]
    fn enroll_js_runs_credentials_create_and_reads_rp_id_island() {
        let body = std::str::from_utf8(ENROLL_JS).unwrap();
        assert!(body.contains("credentials"));
        assert!(body.contains(".create("));
        assert!(body.contains("enroll-data"));
        assert!(
            !body.contains("fetch("),
            "enroll.js must never call a write endpoint"
        );
    }

    #[test]
    fn enroll_js_extracts_sign_count_via_get_authenticator_data() {
        let body = std::str::from_utf8(ENROLL_JS).unwrap();
        assert!(body.contains("getAuthenticatorData"));
    }

    #[test]
    fn enroll_js_never_reads_attestation_object_bytes_directly() {
        let body = std::str::from_utf8(ENROLL_JS).unwrap();
        assert!(!body.contains("response.attestationObject"));
    }

    #[test]
    fn enroll_js_copy_paste_command_includes_sign_count_flag() {
        let body = std::str::from_utf8(ENROLL_JS).unwrap();
        assert!(body.contains("--sign-count"));
    }

    #[test]
    fn app_js_wires_ceremony_endpoints_and_csrf_header() {
        let body = std::str::from_utf8(APP_JS).unwrap();
        assert!(body.contains("x-stellar-remote-approval-csrf"));
        assert!(body.contains("/pending.json"));
        assert!(body.contains("/challenge"));
        assert!(body.contains("/decision"));
    }
}
