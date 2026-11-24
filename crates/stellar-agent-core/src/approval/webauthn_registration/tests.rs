#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;

use super::*;

const ORIGIN: &str = "http://localhost:9999";
const CHALLENGE: [u8; 32] = [0x42; 32];

/// The confirmation-code domain of an operator credential enrollment, the
/// value the enrollment page and its server use.
const OPERATOR_ENROLLMENT_DOMAIN: &[u8] = b"stellar-agent-operator-enrollment-confirmation:v1";

/// Appends a CBOR head of `major` with the shortest encoding of `value`.
fn head(out: &mut Vec<u8>, major: u8, value: usize) {
    let major = major << 5;
    match u8::try_from(value) {
        Ok(small) if small < 24 => out.push(major | small),
        Ok(byte) => out.extend_from_slice(&[major | 24, byte]),
        Err(_) => {
            out.push(major | 25);
            out.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
        }
    }
}

fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len());
    out.extend_from_slice(value);
}

/// A software credential: a P-256 key from a fixed seed and a 16-byte ID.
struct Credential {
    id: Vec<u8>,
    key: [u8; 65],
}

fn credential() -> Credential {
    let secret = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let point = secret.public_key().to_encoded_point(false);
    Credential {
        id: vec![0xa5; 16],
        key: point.as_bytes().try_into().unwrap(),
    }
}

/// The `none` attestation object of `credential` whose authenticator data
/// names SHA-256 of `rp_id`.
fn attestation_object(credential: &Credential, rp_id: &str) -> Vec<u8> {
    attestation_with(credential, rp_id, 3, None)
}

fn attestation_with(
    credential: &Credential,
    rp_id: &str,
    counter: u32,
    extension: Option<&[u8]>,
) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(FLAG_UP | FLAG_UV | FLAG_AT | if extension.is_some() { FLAG_ED } else { 0 });
    auth_data.extend_from_slice(&counter.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]);
    auth_data.extend_from_slice(&u16::try_from(credential.id.len()).unwrap().to_be_bytes());
    auth_data.extend_from_slice(&credential.id);
    // COSE_Key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    head(&mut auth_data, 5, 5);
    auth_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
    bytes(&mut auth_data, &credential.key[1..33]);
    auth_data.push(0x22);
    bytes(&mut auth_data, &credential.key[33..]);

    if let Some(extension) = extension {
        auth_data.extend_from_slice(extension);
    }
    let mut out = Vec::new();
    head(&mut out, 5, 3);
    text(&mut out, "fmt");
    text(&mut out, "none");
    text(&mut out, "attStmt");
    head(&mut out, 5, 0);
    text(&mut out, "authData");
    bytes(&mut out, &auth_data);
    out
}

fn client_data(challenge: &[u8; 32], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{origin}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes()
}

fn verify(
    credential: &Credential,
    client_data_json: &[u8],
    attestation_object: &[u8],
    rp_id: &str,
) -> Result<VerifiedRegistration, RegistrationVerifyError> {
    verify_registration_response(
        &RegistrationResponse {
            credential_id: &credential.id,
            public_key_sec1: &credential.key,
            client_data_json,
            attestation_object,
        },
        &RegistrationExpectation {
            challenge: &CHALLENGE,
            origin: ORIGIN,
            rp_id,
        },
    )
}

/// The RP ID hash in the authenticator data is compared with SHA-256 of the
/// caller's relying-party ID, whichever it is.
#[test]
fn a_response_verifies_against_its_relying_party() {
    let credential = credential();
    let client_data_json = client_data(&CHALLENGE, ORIGIN);

    let for_domain = attestation_object(&credential, "wallet.example.com");
    let verified = verify(
        &credential,
        &client_data_json,
        &for_domain,
        "wallet.example.com",
    )
    .unwrap();
    assert_eq!(verified.credential_id(), credential.id.as_slice());
    assert_eq!(verified.public_key_sec1(), &credential.key);
    assert_eq!(verified.sign_count(), 3);
    assert_eq!(
        verify(&credential, &client_data_json, &for_domain, "localhost").unwrap_err(),
        RegistrationVerifyError::Invalid
    );

    let for_localhost = attestation_object(&credential, "localhost");
    assert!(verify(&credential, &client_data_json, &for_localhost, "localhost").is_ok());
    assert_eq!(
        verify(
            &credential,
            &client_data_json,
            &for_localhost,
            "wallet.example.com"
        )
        .unwrap_err(),
        RegistrationVerifyError::Invalid
    );
}

/// The challenge, the origin and the posted credential are each bound: a
/// response over another challenge, from another origin, or posted with
/// another ID or key refuses.
#[test]
fn a_response_is_bound_to_its_challenge_origin_and_credential() {
    let credential = credential();
    let attestation = attestation_object(&credential, "localhost");
    assert!(
        verify(
            &credential,
            &client_data(&CHALLENGE, ORIGIN),
            &attestation,
            "localhost"
        )
        .is_ok()
    );

    for client_data_json in [
        client_data(&[0x43; 32], ORIGIN),
        client_data(&CHALLENGE, "http://127.0.0.1:9999"),
        client_data(&CHALLENGE, "http://localhost:9998"),
    ] {
        assert_eq!(
            verify(&credential, &client_data_json, &attestation, "localhost").unwrap_err(),
            RegistrationVerifyError::Invalid
        );
    }

    let other_secret = p256::SecretKey::from_slice(&[0x22; 32]).unwrap();
    let other_key: [u8; 65] = other_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    for posted in [
        Credential {
            id: vec![0xa6; 16],
            key: credential.key,
        },
        Credential {
            id: credential.id.clone(),
            key: other_key,
        },
    ] {
        assert_eq!(
            verify(
                &posted,
                &client_data(&CHALLENGE, ORIGIN),
                &attestation,
                "localhost"
            )
            .unwrap_err(),
            RegistrationVerifyError::Invalid
        );
    }

    let mut off_curve = credential.key;
    off_curve[64] ^= 0x01;
    let posted = Credential {
        id: credential.id.clone(),
        key: off_curve,
    };
    assert_eq!(
        verify(
            &posted,
            &client_data(&CHALLENGE, ORIGIN),
            &attestation,
            "localhost"
        )
        .unwrap_err(),
        RegistrationVerifyError::Invalid
    );
}

#[test]
fn a_verified_registration_and_its_inputs_debug_without_bytes() {
    let credential = credential();
    let verified = verify(
        &credential,
        &client_data(&CHALLENGE, ORIGIN),
        &attestation_object(&credential, "localhost"),
        "localhost",
    )
    .unwrap();
    assert_eq!(format!("{verified:?}"), "VerifiedRegistration { .. }");
    let expectation = RegistrationExpectation {
        challenge: &CHALLENGE,
        origin: ORIGIN,
        rp_id: "localhost",
    };
    assert!(!format!("{expectation:?}").contains("66"));
    assert_eq!(
        RegistrationVerifyError::Invalid.to_string(),
        "the registration response does not verify"
    );
}

/// The code vectors the browser tests share: challenge `0x00..=0x1f`,
/// credential ID sixteen `0xa5` bytes, key `0x04` followed by `0x01..=0x40`.
#[test]
fn confirmation_codes_match_the_browser_vectors() {
    let mut challenge = [0u8; 32];
    for (index, byte) in challenge.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    let mut key = [0u8; 65];
    key[0] = 0x04;
    for (index, byte) in key.iter_mut().enumerate().skip(1) {
        *byte = u8::try_from(index).unwrap();
    }
    let id = [0xa5; 16];

    let operator = ConfirmationCode::compute(OPERATOR_ENROLLMENT_DOMAIN, &challenge, &id, &key);
    assert_eq!(operator.display(), "305b-4244-62ef-fd53");
    let passkey =
        ConfirmationCode::compute(PASSKEY_REGISTRATION_CODE_DOMAIN, &challenge, &id, &key);
    assert_eq!(passkey.display(), "2235-dd14-e097-75ce");
    assert!(!passkey.matches(&operator.display()));
    assert_eq!(format!("{passkey:?}"), "ConfirmationCode { .. }");
}

#[test]
fn a_typed_code_matches_in_every_accepted_form() {
    let code = ConfirmationCode::compute(
        PASSKEY_REGISTRATION_CODE_DOMAIN,
        &CHALLENGE,
        &[0xa5; 16],
        &credential().key,
    );
    let shown = code.display();
    let digits = shown.replace('-', "");
    for accepted in [
        shown.clone(),
        shown.to_uppercase(),
        digits.clone(),
        shown.replace('-', " "),
        format!("  {shown}\n"),
        format!("\t{}\r\n", digits.to_uppercase()),
    ] {
        assert!(code.matches(&accepted), "{accepted:?}");
    }
    let mut non_hex = digits.clone();
    non_hex.replace_range(15.., "g");
    for refused in [
        digits[..15].to_owned(),
        format!("{digits}0"),
        non_hex,
        String::new(),
        "\n".to_owned(),
    ] {
        assert!(!code.matches(&refused), "{refused:?}");
    }
}

#[test]
fn submitted_codes_normalize_case_and_separators_only() {
    let expected = *b"305b424462effd53";
    for accepted in [
        "305b-4244-62ef-fd53",
        "305B-4244-62EF-FD53",
        "305b424462effd53",
        "305b 4244 62ef fd53",
        "  305b-4244-62ef-fd53\n",
    ] {
        assert_eq!(
            normalize_submitted_code(accepted),
            Some(expected),
            "{accepted}"
        );
    }
    for refused in [
        "",
        "305b-4244-62ef-fd5",
        "305b-4244-62ef-fd533",
        "305b_4244_62ef_fd53",
        "305b-4244-62ef-fd5g",
        "305b-4244-62ef-fd53x",
        "305b\t4244\t62ef\tfd53",
        "３０５b-4244-62ef-fd53",
    ] {
        assert_eq!(normalize_submitted_code(refused), None, "{refused:?}");
    }
}

#[test]
fn the_capped_decoder_refuses_empty_oversized_and_non_canonical_text() {
    assert_eq!(decode_b64url_capped("", 32), None);
    assert_eq!(
        decode_b64url_capped(&URL_SAFE_NO_PAD.encode([7u8; 33]), 32),
        None
    );
    assert_eq!(decode_b64url_capped(&"A".repeat(1000), 32), None);
    assert_eq!(decode_b64url_capped("AQ==", 2), None);
    assert_eq!(decode_b64url_capped("AR", 2), None);
    assert_eq!(
        decode_b64url_capped(&URL_SAFE_NO_PAD.encode([7u8; 32]), 32),
        Some(vec![7u8; 32])
    );
}

#[test]
fn client_data_security_members_are_typed_unique_and_same_origin() {
    let credential = credential();
    let attestation = attestation_object(&credential, "localhost");
    let base = String::from_utf8(client_data(&CHALLENGE, ORIGIN)).unwrap();
    for member in [
        r#""topOrigin":"http://localhost:9999""#,
        r#""topOrigin":null"#,
        r#""crossOrigin":true"#,
        r#""crossOrigin":null"#,
        r#""crossOrigin":"false""#,
        r#""origin":"http://localhost:9999""#,
        r#""crossOrigin":false,"crossOrigin":false"#,
        r#""type":"webauthn.create""#,
    ] {
        let json = format!("{},{} }}", &base[..base.len() - 1], member);
        assert_eq!(
            verify(&credential, json.as_bytes(), &attestation, "localhost").unwrap_err(),
            RegistrationVerifyError::Invalid,
            "{member}"
        );
    }
    let json = format!(
        "{},\"crossOrigin\":false,\"unknown\":[1,{{\"x\":null}}]}}",
        &base[..base.len() - 1]
    );
    assert!(verify(&credential, json.as_bytes(), &attestation, "localhost").is_ok());
}

#[test]
fn extensions_require_a_map() {
    let credential = credential();
    let client = client_data(&CHALLENGE, ORIGIN);
    for extension in [&[0x80][..], &[0x01][..]] {
        let attestation = attestation_with(&credential, "localhost", 3, Some(extension));
        assert_eq!(
            verify(&credential, &client, &attestation, "localhost").unwrap_err(),
            RegistrationVerifyError::Invalid
        );
    }
    let attestation = attestation_with(&credential, "localhost", 3, Some(&[0xa0]));
    assert!(verify(&credential, &client, &attestation, "localhost").is_ok());
}

#[test]
fn the_signature_counter_uses_all_four_bytes() {
    let credential = credential();
    let attestation = attestation_with(&credential, "localhost", 0x01020304, None);
    let verified = verify(
        &credential,
        &client_data(&CHALLENGE, ORIGIN),
        &attestation,
        "localhost",
    )
    .unwrap();
    assert_eq!(verified.sign_count(), 16_909_060);
}

#[test]
fn matching_credential_ids_obey_the_core_bounds() {
    let mut credential = credential();
    let client = client_data(&CHALLENGE, ORIGIN);
    for length in [15, 16, 64, 65] {
        credential.id = vec![0xa5; length];
        let attestation = attestation_object(&credential, "localhost");
        let result = verify(&credential, &client, &attestation, "localhost");
        if matches!(length, 16 | 64) {
            assert!(result.is_ok(), "length {length}");
        } else {
            assert_eq!(
                result.unwrap_err(),
                RegistrationVerifyError::Invalid,
                "length {length}"
            );
        }
    }
}

#[test]
fn oversized_client_data_refuses_in_core() {
    let credential = credential();
    let attestation = attestation_object(&credential, "localhost");
    let mut client = client_data(&CHALLENGE, ORIGIN);
    client.resize(MAX_CLIENT_DATA_JSON_BYTES, b' ');
    assert!(verify(&credential, &client, &attestation, "localhost").is_ok());
    client.push(b' ');
    assert_eq!(
        verify(&credential, &client, &attestation, "localhost").unwrap_err(),
        RegistrationVerifyError::Invalid
    );
}

#[test]
fn oversized_attestation_refuses_in_core() {
    let credential = credential();
    let client = client_data(&CHALLENGE, ORIGIN);
    for padding in [1024, MAX_ATTESTATION_OBJECT_BYTES] {
        let mut extension = vec![0xa1, 0x01];
        bytes(&mut extension, &vec![0; padding]);
        let attestation = attestation_with(&credential, "localhost", 3, Some(&extension));
        let result = verify(&credential, &client, &attestation, "localhost");
        if padding == 1024 {
            assert!(attestation.len() < MAX_ATTESTATION_OBJECT_BYTES);
            assert!(result.is_ok());
        } else {
            assert!(attestation.len() > MAX_ATTESTATION_OBJECT_BYTES);
            assert_eq!(result.unwrap_err(), RegistrationVerifyError::Invalid);
        }
    }
}
