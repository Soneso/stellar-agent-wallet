//! Static browser-side JS assets baked into the binary.
//!
//! Three same-origin, no-build-step vanilla JS files owned by this crate,
//! plus a fourth this crate serves but does not own — see [`APP_JS`]. Split by
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
///
/// Loaded after `/static/app-shared.js`, whose `stellarAgentApproval`
/// namespace it consumes. That file is NOT in this crate: it is
/// `stellar_agent_approval_ui::APP_SHARED_JS`, served verbatim by
/// [`crate::routes`], so an approval renders identically on both surfaces.
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

    /// The remote glue is the page half of a two-file program; the shared half
    /// publishes the namespace it reads.
    #[test]
    fn app_js_consumes_the_shared_namespace() {
        let app = std::str::from_utf8(APP_JS).unwrap();
        let shared = std::str::from_utf8(stellar_agent_approval_ui::APP_SHARED_JS).unwrap();
        assert!(
            app.contains("var shared = stellarAgentApproval;"),
            "app.js must consume the namespace"
        );
        assert!(
            shared.contains("var stellarAgentApproval = (function ()"),
            "app_shared.js must publish the namespace"
        );
    }

    /// Every helper this crate's glue calls has to exist on the namespace the
    /// shared file returns. A missing one is a runtime `TypeError` that only
    /// the browser sees, and the inbox poll's `catch` would swallow it: the
    /// operator would sit on a page that never lists an approval.
    #[test]
    fn every_shared_helper_the_page_calls_is_exported() {
        let app = std::str::from_utf8(APP_JS).unwrap();
        let shared = std::str::from_utf8(stellar_agent_approval_ui::APP_SHARED_JS).unwrap();
        let exports = shared
            .rsplit_once("  return {")
            .expect("app_shared.js must end with its export table")
            .1;

        let bytes: Vec<char> = app.chars().collect();
        let needle: Vec<char> = "shared.".chars().collect();
        let mut calls = 0usize;
        for start in 0..bytes.len().saturating_sub(needle.len()) {
            if bytes[start..start + needle.len()] != needle[..] {
                continue;
            }
            // Only a member access on the namespace binding itself, so the
            // literal "/static/app-shared.js" in a comment is not a match.
            if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == '-') {
                continue;
            }
            let name: String = bytes[start + needle.len()..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            calls += 1;
            assert!(
                exports.contains(&format!("{name}: {name},")),
                "app.js calls shared.{name}, which app_shared.js does not export"
            );
        }
        assert!(
            calls > 0,
            "the scan must find the namespace calls it checks"
        );
    }
}
