//! Plain `AccountId` fields of classic operations.
//!
//! Operation fields that the protocol types as `MuxedAccount` take a G account
//! or an M address through [`crate::payment_accounts::PaymentAccount`]. Fields
//! that the protocol types as `AccountId` go through
//! [`crate::classic_address::require_account_id`], which refuses a muxed input
//! by name, because an `AccountId` cannot encode a mux ID.
//!
//! The parsed form, never a prefix, a length or the ID value, decides whether
//! an address is muxed. A refusal names the field and never echoes the
//! rejected input.

use stellar_xdr::AccountId;

use crate::error::ValidationError;
use crate::payment_accounts::PaymentAccount;

/// The reason an asset issuer refuses a muxed `M...` address. An issuer is an
/// `AccountId`, the base account, so a mux ID has no place in it.
pub const MUXED_ISSUER_REASON: &str =
    "issuer requires AccountId; a muxed ID cannot be encoded; an issuer is a base account";

/// The refusal for a muxed address in a field that the protocol types as
/// `AccountId`.
#[must_use]
pub fn plain_account_refusal(field: &str) -> ValidationError {
    ValidationError::address_check(format!(
        "{field} requires AccountId; a muxed ID cannot be encoded"
    ))
}

/// Parses a plain `G...` account for a field that the protocol types as
/// `AccountId`.
///
/// # Errors
///
/// Returns [`plain_account_refusal`] for a valid `M...` input and
/// [`ValidationError::AddressInvalid`] naming `field` for every other input.
pub fn require_account_id(input: &str, field: &'static str) -> Result<AccountId, ValidationError> {
    let address =
        PaymentAccount::parse(input).map_err(|_| ValidationError::address_argument(field))?;
    if address.muxed_id().is_some() {
        return Err(plain_account_refusal(field));
    }
    Ok(address.base_account_id())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; unwraps are acceptable in unit tests"
    )]

    use super::*;
    use stellar_xdr::{PublicKey, Uint256};

    fn g(key: [u8; 32]) -> String {
        format!("{}", stellar_strkey::ed25519::PublicKey(key))
    }

    fn m(key: [u8; 32], id: u64) -> String {
        format!(
            "{}",
            stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
        )
    }

    /// Inputs that are neither G nor M: contract, muxed contract, secret
    /// key, checksum-corrupt and malformed strings.
    fn refused(key: [u8; 32]) -> Vec<String> {
        let mut corrupt = m(key, 17);
        let last = corrupt.pop().unwrap();
        corrupt.push(if last == 'A' { 'B' } else { 'A' });
        vec![
            format!("{}", stellar_strkey::Contract(key)),
            format!(
                "{}",
                stellar_strkey::MuxedContract {
                    contract_id: key,
                    id: 17
                }
            ),
            stellar_strkey::ed25519::PrivateKey(key)
                .as_unredacted()
                .to_string()
                .as_str()
                .to_owned(),
            corrupt,
            "not-an-address".to_owned(),
        ]
    }

    /// The `AccountId` guard takes a G and refuses M0 and M17
    /// with the field name and reason, under the existing error code, and
    /// never echoes malformed or secret-key input.
    #[test]
    fn destination_plain_field_reason() {
        let key = [0xA4; 32];
        assert_eq!(
            require_account_id(&g(key), "destination").unwrap(),
            AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key)))
        );
        for field in ["destination", "issuer"] {
            for id in [0, 17] {
                let error = require_account_id(&m(key, id), field).unwrap_err();
                assert_eq!(error.code(), "validation.address_invalid");
                assert_eq!(
                    error.to_string(),
                    format!("{field} requires AccountId; a muxed ID cannot be encoded"),
                    "M{id}"
                );
            }
        }
        for input in refused(key) {
            let error = require_account_id(&input, "destination").unwrap_err();
            assert_eq!(error.code(), "validation.address_invalid");
            assert!(!error.to_string().contains(&input));
            assert!(!error.to_string().contains("muxed ID"));
        }
    }
}
