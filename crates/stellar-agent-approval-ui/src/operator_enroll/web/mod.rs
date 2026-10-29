//! Static web assets for the interactive operator-enrollment server.
//!
//! Holds the wallet-authored, same-origin `operator-enroll.js` served at
//! `GET /static/operator-enroll.js`. Vanilla JS, no build step, no external
//! dependency. It reads the server-rendered data island, requests the
//! server's challenge at `POST /enroll/challenge`, runs the WebAuthn
//! registration ceremony over it, POSTs the response to
//! `POST /enroll/credential`, and shows the confirmation code of the
//! credential it created.

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

    /// The ceremony registers with the options the server's challenge
    /// response names, and never generates a challenge itself.
    #[test]
    fn operator_enroll_js_registers_over_the_server_challenge() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("navigator.credentials"));
        assert!(body.contains(".create("));
        assert!(body.contains("/enroll/challenge"));
        assert!(body.contains("challenge: ceremony.challenge"));
        assert!(body.contains("attestation: options.attestation"));
        assert!(!body.contains("getRandomValues(new Uint8Array(32))"));
    }

    #[test]
    fn operator_enroll_js_reads_data_island_and_posts_credential() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("enroll-data"));
        assert!(body.contains("/enroll/credential"));
        assert!(body.contains("x-stellar-approval-csrf"));
    }

    /// The posted body carries the authenticator's own response and no
    /// client-chosen counter.
    #[test]
    fn operator_enroll_js_posts_the_authenticator_response_and_no_counter() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains("client_data_json: b64urlFromBytes(response.clientDataJSON)"));
        assert!(body.contains("attestation_object: b64urlFromBytes(response.attestationObject)"));
        assert!(!body.contains("sign_count"));
        assert!(!body.contains("getAuthenticatorData"));
    }

    /// The code domain is the one the server derives the expected code
    /// under.
    #[test]
    fn operator_enroll_js_derives_the_code_under_the_server_domain() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains(r#""stellar-agent-operator-enrollment-confirmation:v1""#));
        assert!(body.contains(r#"crypto.subtle.digest("SHA-256""#));
    }

    /// The ceremony reads the proof from the key the bootstrap page stores it
    /// under and sends it in the header the server checks.
    #[test]
    fn operator_enroll_js_reads_the_enrollment_proof_key_and_sends_the_proof_header() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        assert!(body.contains(&format!(
            "\"{}\"",
            crate::auth::SessionPurpose::OperatorEnroll.proof_storage_key()
        )));
        assert!(body.contains(&format!(
            "\"{}\": proof",
            crate::auth::SESSION_PROOF_HEADER_NAME
        )));
    }
}
