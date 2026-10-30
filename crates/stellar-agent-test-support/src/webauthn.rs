//! A software WebAuthn authenticator that signs real ES256 assertions.
//!
//! [`TestAuthenticator`] holds a fixed P-256 key and credential ID and
//! answers `navigator.credentials.get` the way a platform authenticator
//! does: it builds the authenticator data and `clientDataJSON`, then signs
//! `authenticator_data || SHA-256(clientDataJSON)` with ES256. Tests verify
//! its output with the production verifier; nothing here produces a verified
//! value directly.
//!
//! Every key derives from a fixed nonzero test scalar; no OS randomness and
//! no real credential is involved.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Backed up.
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub const FLAG_ED: u8 = 0x80;

/// The private scalar of the fixture approval credential that
/// `crates/stellar-agent-core/tests/fixtures/policy-v2.toml` lists.
pub const FIXTURE_SEED: [u8; 32] = [0x21; 32];

/// The credential ID of the fixture approval credential.
pub const FIXTURE_CREDENTIAL_ID: [u8; 16] = [0x5a; 16];

/// The fixture credential ID in unpadded base64url, as the policy fixture
/// spells it.
pub const FIXTURE_CREDENTIAL_ID_B64URL: &str = "WlpaWlpaWlpaWlpaWlpaWg";

/// The fixture public key in unpadded base64url, as the policy fixture
/// spells it.
pub const FIXTURE_PUBLIC_KEY_B64URL: &str =
    "BEYtuhrk_BqWi02s8gzdbb4frjSqlxUUpj00BcPRz9ODtYu7CMEzg0KMWFPHHEyFHhNLBWgh5Gj-Cpd6v0MT3eE";

/// The fixture approval credential's authenticator.
#[must_use]
pub fn fixture_authenticator() -> TestAuthenticator {
    TestAuthenticator::from_seed(FIXTURE_SEED, FIXTURE_CREDENTIAL_ID.to_vec())
}

/// The bytes of one assertion, as a browser returns them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAssertion {
    /// The raw credential ID.
    pub credential_id: Vec<u8>,
    /// `rpIdHash || flags || signCount` and any extra bytes.
    pub authenticator_data: Vec<u8>,
    /// The exact `clientDataJSON` bytes that were signed.
    pub client_data_json: Vec<u8>,
    /// The ASN.1 DER ECDSA signature.
    pub signature_der: Vec<u8>,
    /// The same signature as 64-byte `r || s` with low S.
    pub signature_compact: Vec<u8>,
}

/// A software authenticator with one P-256 credential.
pub struct TestAuthenticator {
    signing_key: SigningKey,
    credential_id: Vec<u8>,
}

impl std::fmt::Debug for TestAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthenticator")
            .field("credential_id_len", &self.credential_id.len())
            .finish_non_exhaustive()
    }
}

impl TestAuthenticator {
    /// An authenticator whose private scalar is `seed` and whose credential
    /// ID is `credential_id`.
    ///
    /// # Panics
    ///
    /// Panics when `seed` is not a valid nonzero P-256 scalar or the ID is
    /// not 16 to 64 bytes; every fixture passes a fixed valid value.
    #[must_use]
    pub fn from_seed(seed: [u8; 32], credential_id: Vec<u8>) -> Self {
        assert!(
            (16..=64).contains(&credential_id.len()),
            "a WebAuthn test credential ID is 16 to 64 bytes"
        );
        #[allow(
            clippy::expect_used,
            reason = "test support; a fixed nonzero seed below the curve order is a valid scalar"
        )]
        let signing_key = SigningKey::from_bytes(&seed.into()).expect("valid P-256 seed");
        Self {
            signing_key,
            credential_id,
        }
    }

    /// The SEC1 uncompressed public key `0x04 || x || y`.
    #[must_use]
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The raw credential ID.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The credential ID in unpadded base64url.
    #[must_use]
    pub fn credential_id_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// The public key in unpadded base64url.
    #[must_use]
    pub fn public_key_sec1_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key_sec1())
    }

    /// An assertion over `challenge` for `origin` and `rp_id`, with the
    /// given authenticator flags and signature counter.
    ///
    /// The authenticator data is `SHA-256(rp_id) || flags || u32be(count)`
    /// and the client data is
    /// `{"type":"webauthn.get","challenge":"<b64url>","origin":"<origin>","crossOrigin":false}`.
    #[must_use]
    pub fn assert(
        &self,
        challenge: [u8; 32],
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
    ) -> TestAssertion {
        let authenticator_data = authenticator_data(rp_id, flags, sign_count);
        let client_data_json = client_data_json("webauthn.get", &challenge, origin);
        self.sign_raw(authenticator_data, client_data_json)
    }

    /// Signs arbitrary authenticator data and client data bytes, for
    /// adversarial cases whose bytes the standard builder does not produce.
    #[must_use]
    pub fn sign_raw(
        &self,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> TestAssertion {
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: Signature = self.signing_key.sign(&signed);
        let signature = signature.normalize_s().unwrap_or(signature);
        TestAssertion {
            credential_id: self.credential_id.clone(),
            authenticator_data,
            client_data_json,
            signature_der: signature.to_der().as_bytes().to_vec(),
            signature_compact: signature.to_bytes().to_vec(),
        }
    }
}

/// `SHA-256(rp_id) || flags || u32be(sign_count)`.
#[must_use]
pub fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

/// The `clientDataJSON` a browser produces for `kind` (`webauthn.get` or
/// `webauthn.create`), `challenge` and `origin`, with `crossOrigin` false.
#[must_use]
pub fn client_data_json(kind: &str, challenge: &[u8; 32], origin: &str) -> Vec<u8> {
    serde_json::json!({
        "type": kind,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    const SEED: [u8; 32] = [0x21; 32];

    fn authenticator() -> TestAuthenticator {
        TestAuthenticator::from_seed(SEED, vec![0x5a; 16])
    }

    fn verifies(public_key: &[u8; 65], assertion: &TestAssertion) -> bool {
        let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(&assertion.signature_der) else {
            return false;
        };
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&assertion.client_data_json));
        key.verify(&signed, &signature).is_ok()
    }

    #[test]
    fn assertion_fixture_verifies_and_mutation_fails() {
        let authenticator = authenticator();
        let assertion = authenticator.assert(
            [7; 32],
            "http://localhost:4100",
            "localhost",
            FLAG_UP | FLAG_UV,
            3,
        );
        assert!(verifies(&authenticator.public_key_sec1(), &assertion));
        assert_eq!(assertion.signature_compact.len(), 64);
        let compact = Signature::from_slice(&assertion.signature_compact).expect("compact");
        assert!(
            compact.normalize_s().is_none(),
            "the compact form has low S"
        );
        assert_eq!(assertion.authenticator_data.len(), 37);
        assert_eq!(assertion.authenticator_data[32], FLAG_UP | FLAG_UV);
        assert_eq!(&assertion.authenticator_data[33..37], &3u32.to_be_bytes());

        let mut flipped = assertion.clone();
        flipped.authenticator_data[32] ^= FLAG_UV;
        assert!(!verifies(&authenticator.public_key_sec1(), &flipped));

        let mut changed_json = assertion.clone();
        changed_json.client_data_json.push(b' ');
        assert!(!verifies(&authenticator.public_key_sec1(), &changed_json));

        let other = TestAuthenticator::from_seed([0x22; 32], vec![0x5a; 16]);
        assert!(!verifies(&other.public_key_sec1(), &assertion));
    }

    #[test]
    fn fixture_signs_the_original_client_data_bytes() {
        let authenticator = authenticator();
        let raw = b"{ \"type\" : \"webauthn.get\", \"challenge\":\"AA\", \"origin\":\"http://localhost:1\" }"
            .to_vec();
        let assertion =
            authenticator.sign_raw(authenticator_data("localhost", FLAG_UP, 0), raw.clone());
        assert_eq!(assertion.client_data_json, raw);
        assert!(verifies(&authenticator.public_key_sec1(), &assertion));

        let reserialized: serde_json::Value =
            serde_json::from_slice(&raw).expect("fixture JSON parses");
        let mut rebuilt = assertion.clone();
        rebuilt.client_data_json = reserialized.to_string().into_bytes();
        assert_ne!(rebuilt.client_data_json, raw);
        assert!(!verifies(&authenticator.public_key_sec1(), &rebuilt));
    }

    #[test]
    fn fixture_credential_matches_its_policy_spelling() {
        let fixture = fixture_authenticator();
        assert_eq!(fixture.credential_id_b64url(), FIXTURE_CREDENTIAL_ID_B64URL);
        assert_eq!(fixture.public_key_sec1_b64url(), FIXTURE_PUBLIC_KEY_B64URL);
    }

    #[test]
    #[should_panic(expected = "16 to 64 bytes")]
    fn credential_ids_outside_the_webauthn_bounds_panic() {
        let _ = TestAuthenticator::from_seed(SEED, vec![0; 15]);
    }
}
