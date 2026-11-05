//! Structural decoding of smart account authorization payloads.

use stellar_xdr::{AccountId, PublicKey, ScAddress, ScVal};

/// The authority named by an authorization payload signer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPayloadSigner {
    /// An account delegated by the smart account.
    Delegated([u8; 32]),
    /// An external verifier and its encoded key data.
    External {
        /// The verifier contract address.
        verifier: [u8; 32],
        /// The verifier's key data bytes.
        key_data: Vec<u8>,
    },
}

/// Authorization facts decoded from the contract payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPayloadFacts {
    /// Context rule identifiers in payload order.
    pub context_rule_ids: Vec<u32>,
    /// Signer keys in payload order.
    pub signers: Vec<AuthPayloadSigner>,
}

/// An authorization payload does not have the required structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the authorization payload has an unsupported structure")]
pub struct AuthPayloadDecodeError;

fn symbol(value: &ScVal, name: &[u8]) -> bool {
    matches!(value, ScVal::Symbol(symbol) if symbol.0.as_slice() == name)
}

/// Decodes the contract's rule identifiers and signer descriptors.
///
/// # Errors
/// Refuses unknown fields, malformed signer keys, or unsupported address kinds.
pub fn decode_auth_payload(value: &ScVal) -> Result<AuthPayloadFacts, AuthPayloadDecodeError> {
    let ScVal::Map(Some(map)) = value else {
        return Err(AuthPayloadDecodeError);
    };
    if map.len() != 2
        || !symbol(&map[0].key, b"context_rule_ids")
        || !symbol(&map[1].key, b"signers")
    {
        return Err(AuthPayloadDecodeError);
    }
    let ScVal::Vec(Some(ids)) = &map[0].val else {
        return Err(AuthPayloadDecodeError);
    };
    let context_rule_ids = ids
        .iter()
        .map(|id| match id {
            ScVal::U32(id) => Ok(*id),
            _ => Err(AuthPayloadDecodeError),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ScVal::Map(Some(keys)) = &map[1].val else {
        return Err(AuthPayloadDecodeError);
    };
    let signers = keys
        .iter()
        .map(|entry| {
            if !matches!(entry.val, ScVal::Bytes(_)) {
                return Err(AuthPayloadDecodeError);
            }
            let ScVal::Vec(Some(key)) = &entry.key else {
                return Err(AuthPayloadDecodeError);
            };
            match key.as_slice() {
                [
                    tag,
                    ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                        key,
                    )))),
                ] if symbol(tag, b"Delegated") => Ok(AuthPayloadSigner::Delegated(key.0)),
                [
                    tag,
                    ScVal::Address(ScAddress::Contract(verifier)),
                    ScVal::Bytes(key_data),
                ] if symbol(tag, b"External") => Ok(AuthPayloadSigner::External {
                    verifier: verifier.0.0,
                    key_data: key_data.0.to_vec(),
                }),
                _ => Err(AuthPayloadDecodeError),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthPayloadFacts {
        context_rule_ids,
        signers,
    })
}
