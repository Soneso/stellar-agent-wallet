//! Wire-to-verified-assertion glue: decodes an [`AssertionWire`], normalises
//! its signature, and runs it through
//! `stellar_agent_smart_account::webauthn::pre_verify_assertion`.
//!
//! # Origin binding
//!
//! `pre_verify_assertion` deliberately does not check `clientDataJSON.origin`
//! — it mirrors the on-chain OZ verifier, which binds only `type`,
//! `challenge`, and `rp_id_hash` (see its module docs). That omission is
//! correct on-chain: a signed authorization entry never leaves the
//! transaction it is embedded in, so there is no separate "origin" to
//! confuse. A remote-approval assertion is different — it is a purely
//! network-facing authentication proof, submitted from a browser to an HTTP
//! endpoint, where a foreign page could otherwise relay a same-RP-ID
//! assertion it tricked the operator into signing. This module therefore
//! checks `clientDataJSON.origin` itself, against the exact expected origin
//! string the caller supplies (constructed once at server startup — see
//! `crate::remote_origin::expected_https_origin` — never derived from a
//! request header).
//!
//! # Error indistinguishability
//!
//! Every failure mode here (malformed base64, wrong-length fields, wrong
//! origin, and every `pre_verify_assertion` sub-code) collapses to the
//! single [`VerifyAssertionError`] type — it carries no discriminating
//! variant or field. Mirrors the `stellar-agent-webauthn-bridge` convention
//! documented at `handlers/approve.rs`: branching the wire response on WHY an
//! assertion failed (malformed vs. wrong challenge vs. signature-invalid)
//! would let a network-exposed caller distinguish states that must not be
//! distinguishable (e.g. probing whether a credential id is enrolled at
//! all).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use stellar_agent_smart_account::webauthn::{normalize_der_to_compact_low_s, pre_verify_assertion};

use crate::wire::AssertionWire;

/// Minimum length of `authenticator_data` carrying a 4-byte big-endian sign
/// counter (bytes 33..37): 32 (rp_id_hash) + 1 (flags) + 4 (counter).
const AUTH_DATA_COUNTER_END: usize = 37;

/// A verified WebAuthn assertion's decoded, caller-relevant fields.
#[derive(Debug, Clone)]
pub struct VerifiedAssertion {
    /// Base64url credential id from the wire payload (the value the
    /// verifier's public key was matched against).
    pub credential_id_b64url: String,
    /// The 4-byte big-endian sign counter from `authenticator_data[33..37]`.
    /// `0` means the authenticator does not report counters (WebAuthn L2).
    pub sign_count: u32,
}

/// Every failure mode collapses to this single, non-discriminating variant —
/// see the module docs on error indistinguishability.
#[derive(Debug, thiserror::Error)]
#[error("webauthn assertion invalid")]
pub struct VerifyAssertionError;

/// The `origin` field of a `clientDataJSON` object — the only field this
/// module reads out of it beyond what `pre_verify_assertion` already parses.
#[derive(serde::Deserialize)]
struct ClientDataOrigin {
    /// The origin the browser embedded in `clientDataJSON` when producing
    /// this assertion.
    origin: String,
}

/// Decodes, normalises, and verifies `wire` against `challenge`, `rp_id`,
/// `pubkey_uncompressed`, and `expected_origin`.
///
/// `expected_origin` must be the exact `https://<rp_id>[:<port>]` string
/// constructed once at server startup (see
/// `crate::remote_origin::expected_https_origin`) — never recomputed
/// per-request from a request header, which an attacker controls.
///
/// # Errors
///
/// Returns [`VerifyAssertionError`] on any decode or verification failure —
/// see the module-level error-indistinguishability note.
pub fn verify_wire_assertion(
    wire: &AssertionWire,
    challenge: &[u8; 32],
    rp_id: &str,
    pubkey_uncompressed: &[u8; 65],
    expected_origin: &str,
) -> Result<VerifiedAssertion, VerifyAssertionError> {
    let credential_id_b64url = wire.id.clone();

    let authenticator_data = URL_SAFE_NO_PAD
        .decode(&wire.response.authenticator_data)
        .map_err(|_| VerifyAssertionError)?;
    let client_data_json = URL_SAFE_NO_PAD
        .decode(&wire.response.client_data_json)
        .map_err(|_| VerifyAssertionError)?;
    let signature_der = URL_SAFE_NO_PAD
        .decode(&wire.response.signature)
        .map_err(|_| VerifyAssertionError)?;

    let client_data: ClientDataOrigin =
        serde_json::from_slice(&client_data_json).map_err(|_| VerifyAssertionError)?;
    if client_data.origin != expected_origin {
        return Err(VerifyAssertionError);
    }

    let (normalised_sig, _was_high_s) =
        normalize_der_to_compact_low_s(&signature_der).map_err(|_| VerifyAssertionError)?;

    let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();

    pre_verify_assertion(
        challenge,
        pubkey_uncompressed,
        &authenticator_data,
        &client_data_json,
        normalised_sig.as_bytes(),
        &rp_id_hash,
    )
    .map_err(|_| VerifyAssertionError)?;

    let sign_count = if authenticator_data.len() >= AUTH_DATA_COUNTER_END {
        u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ])
    } else {
        // `pre_verify_assertion` already requires >= 37 bytes (step 3), so
        // this arm is unreachable in practice; treated as "unsupported" (0)
        // defensively rather than panicking on a slice index.
        0
    };

    Ok(VerifiedAssertion {
        credential_id_b64url,
        sign_count,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only")]
    use super::*;

    #[test]
    fn malformed_base64_is_refused() {
        let wire = AssertionWireForTest::malformed().into_wire();
        let err = verify_wire_assertion(
            &wire,
            &[0u8; 32],
            "wallet.internal",
            &[0x04u8; 65],
            "https://wallet.internal",
        );
        assert!(err.is_err());
    }

    /// Minimal local builder so this unit test does not depend on the
    /// crate's `test-helpers`-gated software authenticator (that helper is
    /// exercised end-to-end in `tests/` integration tests instead).
    struct AssertionWireForTest;
    impl AssertionWireForTest {
        fn malformed() -> Self {
            Self
        }
        fn into_wire(self) -> crate::wire::AssertionWire {
            crate::wire::AssertionWire {
                id: "not-valid-base64url!!".to_owned(),
                response: crate::wire::AssertionResponseWire {
                    authenticator_data: "***".to_owned(),
                    client_data_json: "***".to_owned(),
                    signature: "***".to_owned(),
                },
            }
        }
    }
}
