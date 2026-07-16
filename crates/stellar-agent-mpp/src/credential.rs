//! Sponsored transaction credential construction.

use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_strkey::Strkey;

use crate::{
    TESTNET_NETWORK,
    challenge::{ChallengeEcho, SelectedChallenge},
    context::RequestContext,
    error::{MppError, MppErrorCode},
    limits::{MAX_CREDENTIAL_BYTES, MAX_XDR_BYTES},
};

/// Transport-ready credential returned to a trusted host.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum CredentialOutput {
    /// HTTP `Authorization` field value, excluding the field name.
    Http {
        /// Value beginning with the `Payment` authentication scheme.
        authorization: String,
    },
    /// Native MCP credential object for `org.paymentauth/credential`.
    Mcp {
        /// Complete native credential object.
        credential: Value,
    },
}

impl fmt::Debug for CredentialOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { .. } => formatter.write_str("CredentialOutput::Http([redacted])"),
            Self::Mcp { .. } => formatter.write_str("CredentialOutput::Mcp([redacted])"),
        }
    }
}

#[derive(Serialize)]
struct CredentialWire<'a> {
    challenge: &'a ChallengeEcho,
    payload: TransactionPayload<'a>,
    source: String,
}

#[derive(Serialize)]
struct TransactionPayload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    transaction: &'a str,
}

/// Builds the one-shot transport credential for a signed sponsored transaction.
///
/// `payer` must be the classic account that signed the Soroban authorization
/// entry. `transaction_xdr` is the base64 Stellar transaction envelope; this
/// function validates its encoding and bounded decoded size but transaction
/// semantics must already have been inspected by the sponsored orchestrator.
///
/// # Errors
///
/// Returns a stable credential or challenge error for an invalid payer, XDR,
/// serialization failure, or size violation.
pub fn build_credential(
    selected: &SelectedChallenge,
    payer: &str,
    transaction_xdr: &str,
) -> Result<CredentialOutput, MppError> {
    if !matches!(Strkey::from_string(payer), Ok(Strkey::PublicKeyEd25519(_))) {
        return Err(MppError::new(
            MppErrorCode::ChallengeInvalid,
            "credential payer must be a classic account",
        ));
    }
    if transaction_xdr.len() > MAX_XDR_BYTES.saturating_mul(2) {
        return Err(credential_too_large());
    }
    let decoded = STANDARD.decode(transaction_xdr).map_err(|_error| {
        MppError::new(
            MppErrorCode::ChallengeInvalid,
            "transaction credential contains invalid XDR encoding",
        )
    })?;
    if decoded.len() > MAX_XDR_BYTES {
        return Err(credential_too_large());
    }

    let wire = CredentialWire {
        challenge: selected.echo(),
        payload: TransactionPayload {
            kind: "transaction",
            transaction: transaction_xdr,
        },
        source: format!("did:pkh:{TESTNET_NETWORK}:{payer}"),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_error| {
        MppError::new(
            MppErrorCode::ChallengeInvalid,
            "credential serialization failed",
        )
    })?;
    if bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(credential_too_large());
    }
    match selected.context() {
        RequestContext::Http(_) => Ok(CredentialOutput::Http {
            authorization: format!("Payment {}", URL_SAFE_NO_PAD.encode(bytes)),
        }),
        RequestContext::Mcp(_) => {
            let credential = serde_json::to_value(wire).map_err(|_error| {
                MppError::new(
                    MppErrorCode::ChallengeInvalid,
                    "credential serialization failed",
                )
            })?;
            Ok(CredentialOutput::Mcp { credential })
        }
    }
}

const fn credential_too_large() -> MppError {
    MppError::new(
        MppErrorCode::CredentialTooLarge,
        "MPP credential exceeds the size limit",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures use expect for concise setup"
    )]

    use super::*;
    use crate::{
        ChallengeInput, HttpRequestContext, McpOperationKind, McpRequestContext,
        json::canonical_json, select_and_validate,
    };

    const CONTRACT: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn selected() -> SelectedChallenge {
        let request = serde_json::json!({
            "amount": "1",
            "currency": CONTRACT,
            "methodDetails": { "feePayer": true, "network": "stellar:testnet" },
            "recipient": ACCOUNT
        });
        let encoded = URL_SAFE_NO_PAD.encode(canonical_json(&request).expect("canonical request"));
        let input = ChallengeInput::Http {
            www_authenticate: vec![format!(
                "Payment id=one, realm=api.example, method=stellar, intent=charge, request={encoded}"
            )],
            selected_challenge_id: None,
            context: HttpRequestContext::new(
                "https://api.example",
                "GET",
                "https://api.example/paid",
                None,
                None,
            )
            .expect("valid context"),
        };
        select_and_validate(&input, 1_700_000_000).expect("valid challenge")
    }

    fn selected_mcp() -> SelectedChallenge {
        let input = ChallengeInput::Mcp {
            challenges: vec![serde_json::json!({
                "id": "one",
                "realm": "server.example",
                "method": "stellar",
                "intent": "charge",
                "request": {
                    "amount": "1",
                    "currency": CONTRACT,
                    "methodDetails": { "feePayer": true, "network": "stellar:testnet" },
                    "recipient": ACCOUNT
                }
            })],
            selected_challenge_id: None,
            context: McpRequestContext::from_params(
                "server.example",
                McpOperationKind::Tool,
                "paid_tool",
                None,
            )
            .expect("valid MCP context"),
        };
        select_and_validate(&input, 1_700_000_000).expect("valid MCP challenge")
    }

    #[test]
    fn builds_sdk_compatible_http_shape() {
        let xdr = STANDARD.encode([0_u8; 32]);
        let output = build_credential(&selected(), ACCOUNT, &xdr).expect("valid credential");
        let CredentialOutput::Http { authorization } = output else {
            unreachable!("HTTP input returns HTTP credential")
        };
        let token = authorization
            .strip_prefix("Payment ")
            .expect("Payment scheme");
        let value: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token)
                .expect("valid base64url credential"),
        )
        .expect("valid credential JSON");
        assert_eq!(value["payload"]["type"], "transaction");
        assert_eq!(
            value["source"],
            format!("did:pkh:stellar:testnet:{ACCOUNT}")
        );
        assert!(value["challenge"]["request"].is_string());
    }

    #[test]
    fn debug_never_contains_credential() {
        let xdr = STANDARD.encode([0_u8; 32]);
        let output = build_credential(&selected(), ACCOUNT, &xdr).expect("valid credential");
        assert_eq!(format!("{output:?}"), "CredentialOutput::Http([redacted])");
    }

    #[test]
    fn builds_native_mcp_credential_without_transport_translation() {
        let xdr = STANDARD.encode([0_u8; 32]);
        let output = build_credential(&selected_mcp(), ACCOUNT, &xdr).expect("valid credential");
        let CredentialOutput::Mcp { credential } = &output else {
            panic!("MCP challenge returns a native credential")
        };
        assert_eq!(credential["challenge"]["request"]["amount"], "1");
        assert_eq!(credential["payload"]["type"], "transaction");
        assert_eq!(format!("{output:?}"), "CredentialOutput::Mcp([redacted])");
    }

    #[test]
    fn rejects_invalid_payer_xdr_and_credential_size() {
        let xdr = STANDARD.encode([0_u8; 32]);
        assert_eq!(
            build_credential(&selected(), "not-a-payer", &xdr)
                .expect_err("invalid payer")
                .code(),
            "mpp.challenge_invalid"
        );
        assert_eq!(
            build_credential(&selected(), ACCOUNT, &"A".repeat(MAX_XDR_BYTES * 2 + 1))
                .expect_err("encoded XDR bound")
                .code(),
            "mpp.credential_too_large"
        );
        assert_eq!(
            build_credential(&selected(), ACCOUNT, "!!!!")
                .expect_err("base64 XDR")
                .code(),
            "mpp.challenge_invalid"
        );
        let decoded_too_large = STANDARD.encode(vec![0_u8; MAX_XDR_BYTES + 1]);
        assert_eq!(
            build_credential(&selected(), ACCOUNT, &decoded_too_large)
                .expect_err("decoded XDR bound")
                .code(),
            "mpp.credential_too_large"
        );
        let credential_too_large = STANDARD.encode(vec![0_u8; MAX_XDR_BYTES]);
        assert_eq!(
            build_credential(&selected(), ACCOUNT, &credential_too_large)
                .expect_err("serialized credential bound")
                .code(),
            "mpp.credential_too_large"
        );
    }
}
