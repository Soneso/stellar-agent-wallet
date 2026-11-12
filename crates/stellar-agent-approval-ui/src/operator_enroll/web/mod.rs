//! Static web assets for the interactive enrollment server.
//!
//! Holds the wallet-authored, same-origin `operator-enroll.js` served at
//! `GET /static/operator-enroll.js`. Vanilla JS, no build step, no external
//! dependency. It reads the server-rendered data island, requests the
//! server's challenge at `POST /enroll/challenge`, runs the WebAuthn
//! registration ceremony over it, POSTs the response to
//! `POST /enroll/credential`, and shows the confirmation code of the
//! credential it created.
//!
//! A signed-origin listener also serves `operator-enroll-code.js` before a
//! session exists. It posts the terminal's enrollment code to
//! `POST /enroll/code`, stores the session proof of the reply and opens
//! `/enroll`.

/// Wallet-authored operator-enrollment browser glue served at
/// `GET /static/operator-enroll.js`.
///
/// Source-of-truth: `src/operator_enroll/web/operator-enroll.js`.
pub(crate) const OPERATOR_ENROLL_JS: &[u8] = include_bytes!("operator-enroll.js");

/// The enrollment code form's script, served at
/// `GET /static/operator-enroll-code.js` by a signed-origin listener only.
///
/// Source-of-truth: `src/operator_enroll/web/operator-enroll-code.js`.
pub(crate) const OPERATOR_ENROLL_CODE_JS: &[u8] = include_bytes!("operator-enroll-code.js");

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    /// The loopback ceremony script keeps its base bytes.
    #[test]
    fn loopback_enroll_asset_keeps_base_bytes() {
        use sha2::{Digest as _, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(OPERATOR_ENROLL_JS)),
            "15166ed844f390b525c6582adce8d2432258d484d9a899eea302337d35d3395f"
        );
    }

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

    /// Each purpose's code domain is the one the server derives that
    /// purpose's expected code under, keyed by the value the server renders.
    #[test]
    fn operator_enroll_js_derives_the_code_under_the_server_domain() {
        use super::super::EnrollmentPurpose;
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        for purpose in [
            EnrollmentPurpose::RemoteOperator,
            EnrollmentPurpose::MainnetApproval,
        ] {
            let domain = std::str::from_utf8(purpose.code_domain()).unwrap();
            let entry = body
                .find(&format!("\"{}\": {{", purpose.page_value()))
                .unwrap_or_else(|| panic!("no entry for {purpose:?}"));
            let next = body[entry..].find("},").unwrap();
            assert!(
                body[entry..entry + next].contains(&format!("codeDomain: \"{domain}\"")),
                "{purpose:?}"
            );
        }
        assert!(body.contains(r#"crypto.subtle.digest("SHA-256""#));
        assert!(body.contains(r#"getAttribute("data-purpose")"#));
    }

    /// The ceremony reads the proof from the key the bootstrap page stores it
    /// under for the page's purpose and sends it in the header the server
    /// checks.
    #[test]
    fn operator_enroll_js_reads_the_enrollment_proof_key_and_sends_the_proof_header() {
        let body = std::str::from_utf8(OPERATOR_ENROLL_JS).unwrap();
        for purpose in [
            crate::auth::SessionPurpose::OperatorEnroll,
            crate::auth::SessionPurpose::MainnetApprovalEnroll,
        ] {
            assert!(body.contains(&format!("proofKey: \"{}\"", purpose.proof_storage_key())));
        }
        assert!(body.contains(&format!(
            "\"{}\": proof",
            crate::auth::SESSION_PROOF_HEADER_NAME
        )));
    }
}
