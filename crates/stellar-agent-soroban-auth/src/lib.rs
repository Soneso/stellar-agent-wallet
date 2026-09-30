//! Soroban authorization-entry preimages and signature payloads (CAP-71).
//!
//! An address-credentialled `SorobanAuthorizationEntry` is signed over
//! `SHA-256(HashIdPreimage.to_xdr())`. The preimage case depends on the entry's
//! credential arm:
//!
//! | Credential arm | Version | Preimage case | Envelope type |
//! |---|---|---|---|
//! | `SorobanCredentials::Address` | [`AuthCredentialsVersion::V1`] | `HashIdPreimage::SorobanAuthorization` | 9 |
//! | `SorobanCredentials::AddressV2` | [`AuthCredentialsVersion::V2`] | `HashIdPreimage::SorobanAuthorizationWithAddress` | 10 |
//!
//! Both arms carry the same `SorobanAddressCredentials` payload. The type 10
//! preimage adds the credential's `address`, so a type 10 signature is bound to
//! the address it authorizes and cannot be replayed for another address that
//! shares the key (CAP-71). `SorobanCredentials::SourceAccount` carries no
//! signature and `SorobanCredentials::AddressWithDelegates` (CAP-71-01 delegate
//! trees) is refused by every caller that sees the entry; both map to `None`.
//!
//! The crate depends on `stellar-xdr`, `sha2` and `thiserror` only, so every
//! signing crate in the workspace can build its preimage here without taking a
//! network, keyring or RPC dependency.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    EnvelopeType, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScAddress, SorobanAddressCredentials,
    SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};

/// The signature-payload version of an address-credentialled authorization
/// entry.
///
/// The version selects the `HashIdPreimage` case the entry is signed over; the
/// credential payload (`SorobanAddressCredentials`) is identical for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthCredentialsVersion {
    /// `SorobanCredentials::Address`, signed over the envelope type 9
    /// `HashIdPreimage::SorobanAuthorization` preimage.
    V1,
    /// `SorobanCredentials::AddressV2`, signed over the envelope type 10
    /// `HashIdPreimage::SorobanAuthorizationWithAddress` preimage, which binds
    /// the credential's address.
    V2,
}

impl AuthCredentialsVersion {
    /// Returns the XDR envelope type of the preimage this version is signed
    /// over.
    #[must_use]
    pub const fn envelope_type(self) -> EnvelopeType {
        match self {
            Self::V1 => EnvelopeType::SorobanAuthorization,
            Self::V2 => EnvelopeType::SorobanAuthorizationWithAddress,
        }
    }

    /// Returns the numeric envelope type (9 for V1, 10 for V2) for trace and
    /// log records.
    #[must_use]
    pub const fn envelope_type_number(self) -> u32 {
        match self {
            Self::V1 => 9,
            Self::V2 => 10,
        }
    }
}

/// Error returned when a preimage cannot be turned into a signature payload.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthPreimageError {
    /// XDR encoding of the preimage failed.
    #[error("failed to encode the authorization preimage: {detail}")]
    Encode {
        /// The encoder's error text. It describes the XDR structure only and
        /// carries no key material.
        detail: String,
    },
}

/// Returns the version and the address credentials of an address-credentialled
/// `SorobanCredentials` value.
///
/// `Address` is [`AuthCredentialsVersion::V1`] and `AddressV2` is
/// [`AuthCredentialsVersion::V2`]. `SourceAccount` and `AddressWithDelegates`
/// return `None`: the first carries no signature, and callers that see the
/// entry refuse the second, a CAP-71-01 delegate tree.
#[must_use]
pub fn credentials_version(
    credentials: &SorobanCredentials,
) -> Option<(AuthCredentialsVersion, &SorobanAddressCredentials)> {
    match credentials {
        SorobanCredentials::Address(address) => Some((AuthCredentialsVersion::V1, address)),
        SorobanCredentials::AddressV2(address) => Some((AuthCredentialsVersion::V2, address)),
        SorobanCredentials::SourceAccount | SorobanCredentials::AddressWithDelegates(_) => None,
    }
}

/// Mutable form of [`credentials_version`], for embedding a signature or
/// updating the expiration ledger in place while the credential arm stays
/// unchanged.
#[must_use]
pub fn credentials_version_mut(
    credentials: &mut SorobanCredentials,
) -> Option<(AuthCredentialsVersion, &mut SorobanAddressCredentials)> {
    match credentials {
        SorobanCredentials::Address(address) => Some((AuthCredentialsVersion::V1, address)),
        SorobanCredentials::AddressV2(address) => Some((AuthCredentialsVersion::V2, address)),
        SorobanCredentials::SourceAccount | SorobanCredentials::AddressWithDelegates(_) => None,
    }
}

/// Builds the `HashIdPreimage` an address-credentialled entry of `version` is
/// signed over.
///
/// - [`AuthCredentialsVersion::V1`] builds
///   `HashIdPreimage::SorobanAuthorization { network_id, nonce,
///   signature_expiration_ledger, invocation }` (envelope type 9). `address`
///   is not part of this preimage.
/// - [`AuthCredentialsVersion::V2`] builds
///   `HashIdPreimage::SorobanAuthorizationWithAddress { network_id, nonce,
///   signature_expiration_ledger, address, invocation }` (envelope type 10), as
///   CAP-71 specifies for `SOROBAN_CREDENTIALS_ADDRESS_V2`.
///
/// `network_id` is `SHA-256(network passphrase)`; `nonce`,
/// `signature_expiration_ledger` and `address` are the entry's
/// `SorobanAddressCredentials` fields and `invocation` is its
/// `root_invocation`.
#[must_use]
pub fn build_auth_preimage(
    version: AuthCredentialsVersion,
    network_id: [u8; 32],
    nonce: i64,
    signature_expiration_ledger: u32,
    address: &ScAddress,
    invocation: SorobanAuthorizedInvocation,
) -> HashIdPreimage {
    match version {
        AuthCredentialsVersion::V1 => {
            HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                network_id: Hash(network_id),
                nonce,
                signature_expiration_ledger,
                invocation,
            })
        }
        AuthCredentialsVersion::V2 => HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id: Hash(network_id),
                nonce,
                signature_expiration_ledger,
                address: address.clone(),
                invocation,
            },
        ),
    }
}

/// Returns the 32-byte signature payload `SHA-256(preimage.to_xdr())`.
///
/// The preimage is an in-memory value built by the caller, so it is encoded
/// without limits.
///
/// # Errors
///
/// [`AuthPreimageError::Encode`] when XDR encoding fails.
pub fn auth_signature_payload(preimage: &HashIdPreimage) -> Result<[u8; 32], AuthPreimageError> {
    let bytes = preimage
        .to_xdr(Limits::none())
        .map_err(|e| AuthPreimageError::Encode {
            detail: e.to_string(),
        })?;
    Ok(Sha256::digest(&bytes).into())
}

/// Returns the parts of a Soroban authorization preimage a verifier checks:
/// its version, its `network_id` and, for [`AuthCredentialsVersion::V2`], the
/// address it is bound to.
///
/// `SorobanAuthorization` is `(V1, network_id, None)` and
/// `SorobanAuthorizationWithAddress` is `(V2, network_id, Some(address))`.
/// Every other `HashIdPreimage` case returns `None`. A verifier compares the
/// `network_id` with `SHA-256(network passphrase)` of the network it signs for.
#[must_use]
pub fn preimage_parts(
    preimage: &HashIdPreimage,
) -> Option<(AuthCredentialsVersion, [u8; 32], Option<&ScAddress>)> {
    match preimage {
        HashIdPreimage::SorobanAuthorization(v1) => {
            Some((AuthCredentialsVersion::V1, v1.network_id.0, None))
        }
        HashIdPreimage::SorobanAuthorizationWithAddress(v2) => Some((
            AuthCredentialsVersion::V2,
            v2.network_id.0,
            Some(&v2.address),
        )),
        HashIdPreimage::OpId(_)
        | HashIdPreimage::PoolRevokeOpId(_)
        | HashIdPreimage::ContractId(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use stellar_xdr::{
        AccountId, ContractId, ContractIdPreimage, ContractIdPreimageFromAddress,
        HashIdPreimageContractId, HashIdPreimageOperationId, HashIdPreimageRevokeId,
        InvokeContractArgs, PoolId, PublicKey, ScVal, SequenceNumber,
        SorobanAddressCredentialsWithDelegates, SorobanAuthorizedFunction, Uint256,
    };

    use super::*;

    const NONCE: i64 = 0x1234_5678;
    const EXPIRATION: u32 = 9999;

    fn network_id() -> [u8; 32] {
        Sha256::digest(b"Test SDF Network ; September 2015").into()
    }

    fn account(byte: u8) -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [byte; 32],
        ))))
    }

    fn invocation() -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xA0; 32]))),
                function_name: "test_invoke".try_into().unwrap(),
                args: vec![].try_into().unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        }
    }

    fn address_credentials(byte: u8) -> SorobanAddressCredentials {
        SorobanAddressCredentials {
            address: account(byte),
            nonce: NONCE,
            signature_expiration_ledger: EXPIRATION,
            signature: ScVal::Void,
        }
    }

    fn with_delegates() -> SorobanCredentials {
        SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
            address_credentials: address_credentials(0x33),
            delegates: vec![].try_into().unwrap(),
        })
    }

    /// The three `HashIdPreimage` cases that are not Soroban authorization
    /// preimages.
    fn other_preimage_cases() -> [HashIdPreimage; 3] {
        let source_account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([0; 32])));
        [
            HashIdPreimage::OpId(HashIdPreimageOperationId {
                source_account: source_account.clone(),
                seq_num: SequenceNumber(1),
                op_num: 0,
            }),
            HashIdPreimage::PoolRevokeOpId(HashIdPreimageRevokeId {
                source_account,
                seq_num: SequenceNumber(1),
                op_num: 0,
                liquidity_pool_id: PoolId(Hash([0; 32])),
                asset: stellar_xdr::Asset::Native,
            }),
            HashIdPreimage::ContractId(HashIdPreimageContractId {
                network_id: Hash(network_id()),
                contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                    address: account(0x44),
                    salt: Uint256([0; 32]),
                }),
            }),
        ]
    }

    #[test]
    fn envelope_type_maps_each_version() {
        assert_eq!(
            AuthCredentialsVersion::V1.envelope_type(),
            EnvelopeType::SorobanAuthorization
        );
        assert_eq!(
            AuthCredentialsVersion::V2.envelope_type(),
            EnvelopeType::SorobanAuthorizationWithAddress
        );
        assert_eq!(AuthCredentialsVersion::V1.envelope_type_number(), 9);
        assert_eq!(AuthCredentialsVersion::V2.envelope_type_number(), 10);
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            assert_eq!(
                i64::from(i32::from(version.envelope_type())),
                i64::from(version.envelope_type_number()),
                "the number must be the XDR discriminant of the envelope type"
            );
        }
    }

    #[test]
    fn credentials_version_maps_all_four_arms() {
        let v1 = SorobanCredentials::Address(address_credentials(0x11));
        let (version, creds) = credentials_version(&v1).unwrap();
        assert_eq!(version, AuthCredentialsVersion::V1);
        assert_eq!(creds, &address_credentials(0x11));

        let v2 = SorobanCredentials::AddressV2(address_credentials(0x22));
        let (version, creds) = credentials_version(&v2).unwrap();
        assert_eq!(version, AuthCredentialsVersion::V2);
        assert_eq!(creds, &address_credentials(0x22));

        assert!(credentials_version(&SorobanCredentials::SourceAccount).is_none());
        assert!(credentials_version(&with_delegates()).is_none());
    }

    #[test]
    fn credentials_version_mut_maps_all_four_arms_and_keeps_the_arm() {
        let mut v1 = SorobanCredentials::Address(address_credentials(0x11));
        let (version, creds) = credentials_version_mut(&mut v1).unwrap();
        assert_eq!(version, AuthCredentialsVersion::V1);
        creds.signature_expiration_ledger = 42;
        let SorobanCredentials::Address(after) = &v1 else {
            panic!("the V1 arm must be kept, got {v1:?}");
        };
        assert_eq!(after.signature_expiration_ledger, 42);

        let mut v2 = SorobanCredentials::AddressV2(address_credentials(0x22));
        let (version, creds) = credentials_version_mut(&mut v2).unwrap();
        assert_eq!(version, AuthCredentialsVersion::V2);
        creds.signature_expiration_ledger = 43;
        let SorobanCredentials::AddressV2(after) = &v2 else {
            panic!("the V2 arm must be kept, got {v2:?}");
        };
        assert_eq!(after.signature_expiration_ledger, 43);

        assert!(credentials_version_mut(&mut SorobanCredentials::SourceAccount).is_none());
        assert!(credentials_version_mut(&mut with_delegates()).is_none());
    }

    #[test]
    fn build_auth_preimage_v1_equals_hand_built_case_9() {
        let built = build_auth_preimage(
            AuthCredentialsVersion::V1,
            network_id(),
            NONCE,
            EXPIRATION,
            &account(0x44),
            invocation(),
        );
        let expected = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(network_id()),
            nonce: NONCE,
            signature_expiration_ledger: EXPIRATION,
            invocation: invocation(),
        });
        assert_eq!(built, expected);
        assert_eq!(built.discriminant(), EnvelopeType::SorobanAuthorization);
    }

    #[test]
    fn build_auth_preimage_v2_equals_hand_built_case_10() {
        let built = build_auth_preimage(
            AuthCredentialsVersion::V2,
            network_id(),
            NONCE,
            EXPIRATION,
            &account(0x44),
            invocation(),
        );
        let expected = HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id: Hash(network_id()),
                nonce: NONCE,
                signature_expiration_ledger: EXPIRATION,
                address: account(0x44),
                invocation: invocation(),
            },
        );
        assert_eq!(built, expected);
        assert_eq!(
            built.discriminant(),
            EnvelopeType::SorobanAuthorizationWithAddress
        );
    }

    #[test]
    fn auth_signature_payload_is_sha256_of_the_xdr() {
        for version in [AuthCredentialsVersion::V1, AuthCredentialsVersion::V2] {
            let preimage = build_auth_preimage(
                version,
                network_id(),
                NONCE,
                EXPIRATION,
                &account(0x44),
                invocation(),
            );
            let expected: [u8; 32] =
                Sha256::digest(preimage.to_xdr(Limits::none()).unwrap()).into();
            assert_eq!(auth_signature_payload(&preimage).unwrap(), expected);
        }
    }

    #[test]
    fn case_9_and_case_10_payloads_of_the_same_inputs_differ() {
        let payload = |version| {
            auth_signature_payload(&build_auth_preimage(
                version,
                network_id(),
                NONCE,
                EXPIRATION,
                &account(0x44),
                invocation(),
            ))
            .unwrap()
        };
        assert_ne!(
            payload(AuthCredentialsVersion::V1),
            payload(AuthCredentialsVersion::V2)
        );
    }

    #[test]
    fn case_10_payload_depends_on_the_address() {
        let payload = |byte| {
            auth_signature_payload(&build_auth_preimage(
                AuthCredentialsVersion::V2,
                network_id(),
                NONCE,
                EXPIRATION,
                &account(byte),
                invocation(),
            ))
            .unwrap()
        };
        assert_ne!(payload(0x44), payload(0x45));
    }

    #[test]
    fn preimage_parts_maps_all_five_cases() {
        let other_network: [u8; 32] = Sha256::digest(b"another network").into();
        for id in [network_id(), other_network] {
            let v1 = build_auth_preimage(
                AuthCredentialsVersion::V1,
                id,
                NONCE,
                EXPIRATION,
                &account(0x44),
                invocation(),
            );
            assert_eq!(
                preimage_parts(&v1),
                Some((AuthCredentialsVersion::V1, id, None))
            );

            let v2 = build_auth_preimage(
                AuthCredentialsVersion::V2,
                id,
                NONCE,
                EXPIRATION,
                &account(0x44),
                invocation(),
            );
            assert_eq!(
                preimage_parts(&v2),
                Some((AuthCredentialsVersion::V2, id, Some(&account(0x44))))
            );
        }

        // The ContractId case carries a network_id too; it is not an
        // authorization preimage and returns None.
        for other in other_preimage_cases() {
            assert_eq!(preimage_parts(&other), None, "{other:?}");
        }
    }
}
