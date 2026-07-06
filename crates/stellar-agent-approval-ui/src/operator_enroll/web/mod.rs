//! Static web assets for the interactive operator-enrollment server.
//!
//! Holds the wallet-authored, same-origin `operator-enroll.js` served at
//! `GET /static/operator-enroll.js`. Vanilla JS, no build step, no external
//! dependency — it reads the server-rendered data island, runs the WebAuthn
//! registration ceremony, and POSTs the result to `POST /enroll/credential`.

/// Wallet-authored operator-enrollment browser glue served at
/// `GET /static/operator-enroll.js`.
///
/// Source-of-truth: `src/operator_enroll/web/operator-enroll.js`.
pub(crate) const OPERATOR_ENROLL_JS: &[u8] = include_bytes!("operator-enroll.js");

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
    fn operator_enroll_js_is_valid_utf8() {
        std::str::from_utf8(OPERATOR_ENROLL_JS).expect("operator-enroll.js must be valid UTF-8");
    }

    #[test]
    fn operator_enroll_js_runs_create_with_none_attestation() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("navigator.credentials"));
        assert!(body.contains(".create("));
        assert!(body.contains(r#"attestation: "none""#));
    }

    #[test]
    fn operator_enroll_js_reads_data_island_and_posts_credential() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("enroll-data"));
        assert!(body.contains("/enroll/credential"));
        assert!(body.contains("x-stellar-approval-csrf"));
    }

    #[test]
    fn operator_enroll_js_extracts_sign_count_via_get_authenticator_data() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("getAuthenticatorData"));
    }

    #[test]
    fn operator_enroll_js_never_reads_attestation_object_bytes_directly() {
        // The counter extraction goes only through `getAuthenticatorData()`;
        // the file must never touch `response.attestationObject` (doing so
        // would require a CBOR decoder this ceremony deliberately omits —
        // the comment above `extractSignCount` documents that omission,
        // which is why this check targets the property access, not the
        // word "CBOR" itself).
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(!body.contains("response.attestationObject"));
        assert!(!body.contains("credential.response.attestationObject"));
    }
}
