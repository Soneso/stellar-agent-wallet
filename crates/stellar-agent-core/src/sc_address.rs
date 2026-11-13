//! Strkey rendering for XDR [`stellar_xdr::ScAddress`] values.
//!
//! Account (`G...`) and contract (`C...`) addresses have a canonical strkey
//! form that every wallet surface renders. The remaining `ScAddress` variants
//! (muxed account, muxed contract, claimable balance, liquidity pool) are never valid
//! principals on the wallet's signing, pinning or storage-inspection paths,
//! so [`crate::sc_address::scaddress_to_strkey`] returns a typed
//! [`crate::sc_address::ScAddressStrkeyError`] for them and callers that only
//! display the address render
//! [`crate::sc_address::UNSUPPORTED_ADDRESS_PLACEHOLDER`] instead.
//! The multicall bundle decoder renders destinations with
//! [`crate::sc_address::scaddress_destination_strkey`], which keeps M and W ids.
//!
//! The module also builds the ledger key of a CAP-85 executable-tag entry
//! ([`crate::sc_address::executable_tag_ledger_key`]) and its SHA-256 digest
//! ([`crate::sc_address::executable_tag_key_digest`]), which identifies one
//! owner and tag pair across the network fetch, the smart-account pin and the
//! audit log.

use sha2::{Digest as _, Sha256};
use stellar_xdr::{
    AccountId, ContractDataDurability, ContractExecutable, ContractId, ContractIdPreimage,
    FeeBumpTransactionInnerTx, Hash, HashIdPreimage, HostFunction, InvokeContractArgs, LedgerKey,
    LedgerKeyContractData, Limits, Operation, OperationBody, PublicKey, RevokeSponsorshipOp,
    ScAddress, ScMap, ScString, ScVal, SorobanAddressCredentials, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, TransactionEnvelope,
    TransactionExt, Uint256, WriteXdr,
};

/// Fixed display text for an [`ScAddress`] that has no account or contract
/// strkey form.
///
/// Display-only callers render this placeholder so a ledger-supplied address
/// of an unexpected variant never reaches a message as its `Debug` form.
pub const UNSUPPORTED_ADDRESS_PLACEHOLDER: &str = "<unsupported address>";

/// Refusal detail for a muxed contract address on a path that cannot execute it.
pub const MUXED_CONTRACT_REFUSAL: &str =
    "a muxed contract address (W) is not accepted on this path";

/// Error returned by [`scaddress_to_strkey`] for an address variant that has
/// no account or contract strkey form.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("address variant {variant} has no account or contract strkey form")]
pub struct ScAddressStrkeyError {
    /// XDR variant name of the rejected address (for example `MuxedAccount`).
    pub variant: &'static str,
}

/// Renders an account or contract [`ScAddress`] as its canonical strkey.
///
/// `stellar_strkey` returns a fixed-capacity `heapless::String` from its
/// inherent `to_string`; the result is converted through `as_str()` so the
/// returned value is an owned `std::string::String`.
///
/// # Errors
///
/// Returns [`ScAddressStrkeyError`] for every variant other than
/// `ScAddress::Account` and `ScAddress::Contract`.
pub fn scaddress_to_strkey(addr: &ScAddress) -> Result<String, ScAddressStrkeyError> {
    match addr {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))) => {
            Ok(stellar_strkey::ed25519::PublicKey(*bytes)
                .to_string()
                .as_str()
                .to_owned())
        }
        ScAddress::Contract(ContractId(Hash(bytes))) => Ok(stellar_strkey::Contract(*bytes)
            .to_string()
            .as_str()
            .to_owned()),
        // Every other variant, including feature-gated ones, shares the same
        // typed refusal: none of them is a wallet principal.
        other => Err(ScAddressStrkeyError {
            variant: other.name(),
        }),
    }
}

/// Renders a destination as a full G, C, M or W strkey, including its mux id.
///
/// # Errors
///
/// Returns [`ScAddressStrkeyError`] for claimable balances and liquidity pools.
pub fn scaddress_destination_strkey(addr: &ScAddress) -> Result<String, ScAddressStrkeyError> {
    match addr {
        ScAddress::MuxedAccount(m) => Ok(stellar_strkey::ed25519::MuxedAccount {
            ed25519: m.ed25519.0,
            id: m.id,
        }
        .to_string()
        .as_str()
        .to_owned()),
        ScAddress::MuxedContract(w) => Ok(stellar_strkey::MuxedContract {
            contract_id: w.contract_id.0.0,
            id: w.id,
        }
        .to_string()
        .as_str()
        .to_owned()),
        other => scaddress_to_strkey(other),
    }
}

fn address_has_muxed_contract(address: &ScAddress) -> bool {
    matches!(address, ScAddress::MuxedContract(_))
}

fn map_has_muxed_contract(map: &ScMap) -> bool {
    map.iter()
        .any(|entry| scval_has_muxed_contract(&entry.key) || scval_has_muxed_contract(&entry.val))
}

fn executable_has_muxed_contract(executable: &ContractExecutable) -> bool {
    matches!(executable, ContractExecutable::ExternalRef(reference)
        if address_has_muxed_contract(&reference.executable_owner))
}

/// Detects CAP-84 W addresses in a value, including collections and storage.
#[must_use]
pub fn scval_has_muxed_contract(value: &ScVal) -> bool {
    match value {
        ScVal::Address(address) => address_has_muxed_contract(address),
        ScVal::Vec(Some(values)) => values.iter().any(scval_has_muxed_contract),
        ScVal::Map(Some(map)) => map_has_muxed_contract(map),
        ScVal::ContractInstance(instance) => {
            executable_has_muxed_contract(&instance.executable)
                || instance
                    .storage
                    .as_ref()
                    .is_some_and(map_has_muxed_contract)
        }
        _ => false,
    }
}

fn contract_id_has_muxed_contract(preimage: &ContractIdPreimage) -> bool {
    matches!(preimage, ContractIdPreimage::Address(from)
        if address_has_muxed_contract(&from.address))
}

fn call_has_muxed_contract(call: &InvokeContractArgs) -> bool {
    address_has_muxed_contract(&call.contract_address)
        || call.args.iter().any(scval_has_muxed_contract)
}

fn invocation_has_muxed_contract(invocation: &SorobanAuthorizedInvocation) -> bool {
    let found = match &invocation.function {
        SorobanAuthorizedFunction::ContractFn(call) => call_has_muxed_contract(call),
        SorobanAuthorizedFunction::CreateContractHostFn(create) => {
            contract_id_has_muxed_contract(&create.contract_id_preimage)
                || executable_has_muxed_contract(&create.executable)
        }
        SorobanAuthorizedFunction::CreateContractV2HostFn(create) => {
            contract_id_has_muxed_contract(&create.contract_id_preimage)
                || executable_has_muxed_contract(&create.executable)
                || create.constructor_args.iter().any(scval_has_muxed_contract)
        }
    };
    found
        || invocation
            .sub_invocations
            .iter()
            .any(invocation_has_muxed_contract)
}

/// Detects CAP-84 W addresses in a hash preimage and its authorization tree.
#[must_use]
pub fn preimage_has_muxed_contract(preimage: &HashIdPreimage) -> bool {
    use stellar_agent_soroban_auth::{preimage_invocation, preimage_parts};
    matches!(preimage, HashIdPreimage::ContractId(p)
        if contract_id_has_muxed_contract(&p.contract_id_preimage))
        || preimage_parts(preimage)
            .and_then(|(_, _, address)| address)
            .is_some_and(address_has_muxed_contract)
        || preimage_invocation(preimage).is_some_and(invocation_has_muxed_contract)
}

fn credential_has_muxed_contract(credential: &SorobanAddressCredentials) -> bool {
    address_has_muxed_contract(&credential.address)
        || scval_has_muxed_contract(&credential.signature)
}

fn delegate_has_muxed_contract(delegate: &SorobanDelegateSignature) -> bool {
    address_has_muxed_contract(&delegate.address)
        || scval_has_muxed_contract(&delegate.signature)
        || delegate
            .nested_delegates
            .iter()
            .any(delegate_has_muxed_contract)
}

fn ledger_key_has_muxed_contract(key: &LedgerKey) -> bool {
    matches!(key, LedgerKey::ContractData(data)
        if address_has_muxed_contract(&data.contract) || scval_has_muxed_contract(&data.key))
}

fn operation_has_muxed_contract(operation: &Operation) -> bool {
    match &operation.body {
        OperationBody::InvokeHostFunction(op) => {
            let found = match &op.host_function {
                HostFunction::InvokeContract(call) => call_has_muxed_contract(call),
                HostFunction::CreateContract(create) => {
                    contract_id_has_muxed_contract(&create.contract_id_preimage)
                        || executable_has_muxed_contract(&create.executable)
                }
                HostFunction::CreateContractV2(create) => {
                    contract_id_has_muxed_contract(&create.contract_id_preimage)
                        || executable_has_muxed_contract(&create.executable)
                        || create.constructor_args.iter().any(scval_has_muxed_contract)
                }
                HostFunction::UploadContractWasm(_) => false,
            };
            found
                || op.auth.iter().any(|auth| {
                    let credentials = match &auth.credentials {
                        SorobanCredentials::SourceAccount => false,
                        SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
                            credential_has_muxed_contract(c)
                        }
                        SorobanCredentials::AddressWithDelegates(c) => {
                            credential_has_muxed_contract(&c.address_credentials)
                                || c.delegates.iter().any(delegate_has_muxed_contract)
                        }
                    };
                    credentials || invocation_has_muxed_contract(&auth.root_invocation)
                })
        }
        OperationBody::RevokeSponsorship(RevokeSponsorshipOp::LedgerEntry(key)) => {
            ledger_key_has_muxed_contract(key)
        }
        _ => false,
    }
}

/// Detects CAP-84 W addresses in operations, authorization and the footprint.
/// A fee bump checks its inner transaction; V0 checks its operations.
#[must_use]
pub fn envelope_has_muxed_contract(envelope: &TransactionEnvelope) -> bool {
    let tx = match envelope {
        TransactionEnvelope::Tx(tx) => &tx.tx,
        TransactionEnvelope::TxFeeBump(fee_bump) => {
            let FeeBumpTransactionInnerTx::Tx(tx) = &fee_bump.tx.inner_tx;
            &tx.tx
        }
        TransactionEnvelope::TxV0(tx) => {
            return tx.tx.operations.iter().any(operation_has_muxed_contract);
        }
    };
    tx.operations.iter().any(operation_has_muxed_contract)
        || match &tx.ext {
            TransactionExt::V0 => false,
            TransactionExt::V1(data) => data
                .resources
                .footprint
                .read_only
                .iter()
                .chain(data.resources.footprint.read_write.iter())
                .any(ledger_key_has_muxed_contract),
        }
}

/// Renders an [`ScAddress`] for a log line or error string: the
/// first-5-last-5 redacted strkey of an account or contract address, or
/// [`UNSUPPORTED_ADDRESS_PLACEHOLDER`] for any other variant.
#[must_use]
pub fn scaddress_redacted(addr: &ScAddress) -> String {
    scaddress_to_strkey(addr).map_or_else(
        |_| UNSUPPORTED_ADDRESS_PLACEHOLDER.to_owned(),
        |strkey| crate::observability::redact_strkey_first5_last5(&strkey),
    )
}

/// Returns the ledger key of the persistent `ContractData` entry in which
/// `owner` stores the Wasm hash for an external-reference `tag`
/// (`ScVal::ExecutableTag(tag)`, persistent durability).
///
/// A CAP-85 instance whose executable is
/// `ContractExecutable::ExternalRef { executable_owner, tag }` runs the Wasm
/// whose hash this entry holds.
#[must_use]
pub fn executable_tag_ledger_key(owner: &ScAddress, tag: &ScString) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: owner.clone(),
        key: ScVal::ExecutableTag(tag.clone()),
        durability: ContractDataDurability::Persistent,
    })
}

/// Returns the SHA-256 digest of the XDR encoding of
/// [`executable_tag_ledger_key`] for `owner` and `tag`.
///
/// Two external references name the same owner-managed code slot exactly when
/// their digests are equal, so the digest is the identity a pin records and a
/// later observation is compared against. The owner and the tag are
/// ledger-supplied; the digest carries neither in readable form.
///
/// # Errors
///
/// Returns the XDR encoder's error when the key cannot be encoded. The key is
/// built from values that already passed XDR length checks and is encoded
/// without depth or length limits, so no current input produces an error.
pub fn executable_tag_key_digest(
    owner: &ScAddress,
    tag: &ScString,
) -> Result<[u8; 32], stellar_xdr::Error> {
    let key_xdr = executable_tag_ledger_key(owner, tag).to_xdr(Limits::none())?;
    Ok(Sha256::digest(key_xdr).into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only assertions")]

    use super::*;
    use stellar_xdr::{ClaimableBalanceId, MuxedEd25519Account, PoolId};

    fn tag(bytes: &[u8]) -> ScString {
        ScString(bytes.to_vec().try_into().unwrap())
    }

    fn w() -> ScAddress {
        ScAddress::MuxedContract(stellar_xdr::MuxedContract {
            contract_id: ContractId(Hash([0; 32])),
            id: 7,
        })
    }

    #[test]
    fn muxed_contract_destination_strkeys() {
        let contract_id = [
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ];
        for (id, expected) in [
            (
                0,
                "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC",
            ),
            (
                1 << 63,
                "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY",
            ),
        ] {
            let address = ScAddress::MuxedContract(stellar_xdr::MuxedContract {
                contract_id: ContractId(Hash(contract_id)),
                id,
            });
            assert_eq!(scaddress_destination_strkey(&address).unwrap(), expected);
        }
        let m = ScAddress::MuxedAccount(MuxedEd25519Account {
            id: 7,
            ed25519: Uint256([1; 32]),
        });
        let expected = stellar_strkey::ed25519::MuxedAccount {
            id: 7,
            ed25519: [1; 32],
        }
        .to_string();
        assert_eq!(scaddress_destination_strkey(&m).unwrap(), expected.as_str());
        for address in [
            ScAddress::ClaimableBalance(ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                [2; 32],
            ))),
            ScAddress::LiquidityPool(PoolId(Hash([3; 32]))),
        ] {
            assert_eq!(
                scaddress_destination_strkey(&address),
                scaddress_to_strkey(&address)
            );
            assert!(scaddress_destination_strkey(&address).is_err());
        }
    }

    #[test]
    fn muxed_contract_walkers_cover_address_positions() {
        use stellar_xdr::*;
        let address = ScVal::Address(w());
        let map = |key, val| ScMap(vec![ScMapEntry { key, val }].try_into().unwrap());
        let external = ContractExecutable::ExternalRef(ContractExecutableExternalRef {
            executable_owner: w(),
            tag: tag(b"v1"),
        });
        for value in [
            address.clone(),
            ScVal::Vec(Some(ScVec(vec![address.clone()].try_into().unwrap()))),
            ScVal::Map(Some(map(address.clone(), ScVal::Void))),
            ScVal::Map(Some(map(ScVal::Void, address.clone()))),
            ScVal::ContractInstance(ScContractInstance {
                executable: external.clone(),
                storage: None,
            }),
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                storage: Some(map(address.clone(), ScVal::Void)),
            }),
        ] {
            assert!(scval_has_muxed_contract(&value), "{value:?}");
        }
        let call = InvokeContractArgs {
            contract_address: w(),
            ..Default::default()
        };
        let from = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: w(),
            salt: Uint256([0; 32]),
        });
        let create = CreateContractArgs {
            contract_id_preimage: from.clone(),
            executable: ContractExecutable::StellarAsset,
        };
        let create_external = CreateContractArgs {
            executable: external.clone(),
            ..Default::default()
        };
        let create_args = CreateContractArgsV2 {
            constructor_args: vec![address.clone()].try_into().unwrap(),
            ..Default::default()
        };
        let functions = [
            HostFunction::InvokeContract(call.clone()),
            HostFunction::InvokeContract(InvokeContractArgs {
                args: vec![address.clone()].try_into().unwrap(),
                ..Default::default()
            }),
            HostFunction::CreateContract(create.clone()),
            HostFunction::CreateContract(create_external.clone()),
            HostFunction::CreateContractV2(create_args.clone()),
            HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage: from.clone(),
                ..Default::default()
            }),
            HostFunction::CreateContractV2(CreateContractArgsV2 {
                executable: external,
                ..Default::default()
            }),
        ];
        let envelope = |op: InvokeHostFunctionOp| {
            TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: Transaction {
                    operations: vec![Operation {
                        source_account: None,
                        body: OperationBody::InvokeHostFunction(op),
                    }]
                    .try_into()
                    .unwrap(),
                    ..Default::default()
                },
                signatures: Default::default(),
            })
        };
        for function in functions {
            assert!(envelope_has_muxed_contract(&envelope(
                InvokeHostFunctionOp {
                    host_function: function,
                    auth: Default::default()
                }
            )));
        }
        let invocations: Vec<_> = [
            SorobanAuthorizedFunction::ContractFn(call),
            SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                args: vec![address.clone()].try_into().unwrap(),
                ..Default::default()
            }),
            SorobanAuthorizedFunction::CreateContractHostFn(create),
            SorobanAuthorizedFunction::CreateContractHostFn(create_external),
            SorobanAuthorizedFunction::CreateContractV2HostFn(create_args),
        ]
        .into_iter()
        .map(|function| SorobanAuthorizedInvocation {
            function,
            sub_invocations: Default::default(),
        })
        .collect();
        for invocation in invocations {
            for root in [
                invocation.clone(),
                SorobanAuthorizedInvocation {
                    sub_invocations: vec![invocation].try_into().unwrap(),
                    ..Default::default()
                },
            ] {
                assert!(preimage_has_muxed_contract(
                    &HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                        invocation: root.clone(),
                        ..Default::default()
                    })
                ));
                assert!(preimage_has_muxed_contract(
                    &HashIdPreimage::SorobanAuthorizationWithAddress(
                        HashIdPreimageSorobanAuthorizationWithAddress {
                            invocation: root.clone(),
                            ..Default::default()
                        }
                    )
                ));
                assert!(envelope_has_muxed_contract(&envelope(
                    InvokeHostFunctionOp {
                        auth: vec![SorobanAuthorizationEntry {
                            credentials: SorobanCredentials::SourceAccount,
                            root_invocation: root
                        }]
                        .try_into()
                        .unwrap(),
                        ..Default::default()
                    }
                )));
            }
        }
        assert!(preimage_has_muxed_contract(&HashIdPreimage::ContractId(
            HashIdPreimageContractId {
                contract_id_preimage: from,
                ..Default::default()
            }
        )));
        assert!(preimage_has_muxed_contract(
            &HashIdPreimage::SorobanAuthorizationWithAddress(
                HashIdPreimageSorobanAuthorizationWithAddress {
                    address: w(),
                    ..Default::default()
                }
            )
        ));
        for credential in [
            SorobanAddressCredentials {
                address: w(),
                ..Default::default()
            },
            SorobanAddressCredentials {
                signature: address.clone(),
                ..Default::default()
            },
        ] {
            for credentials in [
                SorobanCredentials::Address(credential.clone()),
                SorobanCredentials::AddressV2(credential.clone()),
                SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                    address_credentials: credential,
                    delegates: Default::default(),
                }),
            ] {
                assert!(envelope_has_muxed_contract(&envelope(
                    InvokeHostFunctionOp {
                        auth: vec![SorobanAuthorizationEntry {
                            credentials,
                            ..Default::default()
                        }]
                        .try_into()
                        .unwrap(),
                        ..Default::default()
                    }
                )));
            }
        }
        for delegate in [
            SorobanDelegateSignature {
                address: w(),
                ..Default::default()
            },
            SorobanDelegateSignature {
                signature: address.clone(),
                ..Default::default()
            },
        ] {
            for delegate in [
                delegate.clone(),
                SorobanDelegateSignature {
                    nested_delegates: vec![delegate].try_into().unwrap(),
                    ..Default::default()
                },
            ] {
                assert!(envelope_has_muxed_contract(&envelope(
                    InvokeHostFunctionOp {
                        auth: vec![SorobanAuthorizationEntry {
                            credentials: SorobanCredentials::AddressWithDelegates(
                                SorobanAddressCredentialsWithDelegates {
                                    delegates: vec![delegate].try_into().unwrap(),
                                    ..Default::default()
                                }
                            ),
                            ..Default::default()
                        }]
                        .try_into()
                        .unwrap(),
                        ..Default::default()
                    }
                )));
            }
        }
        for key in [
            LedgerKeyContractData {
                contract: w(),
                ..Default::default()
            },
            LedgerKeyContractData {
                key: address,
                ..Default::default()
            },
        ] {
            let key = LedgerKey::ContractData(key);
            for read_only in [true, false] {
                let mut data = SorobanTransactionData::default();
                if read_only {
                    data.resources.footprint.read_only = vec![key.clone()].try_into().unwrap();
                } else {
                    data.resources.footprint.read_write = vec![key.clone()].try_into().unwrap();
                }
                let tx = TransactionV1Envelope {
                    tx: Transaction {
                        ext: TransactionExt::V1(data),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                assert!(envelope_has_muxed_contract(&TransactionEnvelope::Tx(
                    tx.clone()
                )));
                assert!(envelope_has_muxed_contract(
                    &TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
                        tx: FeeBumpTransaction {
                            inner_tx: FeeBumpTransactionInnerTx::Tx(tx),
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                ));
            }
        }
        for safe in [
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1; 32])))),
            ScAddress::Contract(ContractId(Hash([1; 32]))),
            ScAddress::MuxedAccount(MuxedEd25519Account {
                id: 7,
                ed25519: Uint256([1; 32]),
            }),
        ] {
            assert!(!envelope_has_muxed_contract(&envelope(
                InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(InvokeContractArgs {
                        contract_address: safe.clone(),
                        args: vec![ScVal::Address(safe)].try_into().unwrap(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            )));
        }
    }

    #[test]
    fn executable_tag_ledger_key_is_the_owner_persistent_executable_tag_key() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let LedgerKey::ContractData(key) = executable_tag_ledger_key(&owner, &tag(b"v1")) else {
            panic!("executable tag key must be a contract-data key");
        };
        assert_eq!(key.contract, owner);
        assert_eq!(key.key, ScVal::ExecutableTag(tag(b"v1")));
        assert_eq!(key.durability, ContractDataDurability::Persistent);
    }

    #[test]
    fn executable_tag_key_digest_is_the_sha256_of_the_key_xdr() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let key_xdr = executable_tag_ledger_key(&owner, &tag(b"v1"))
            .to_xdr(Limits::none())
            .unwrap();
        let expected: [u8; 32] = Sha256::digest(key_xdr).into();
        assert_eq!(
            executable_tag_key_digest(&owner, &tag(b"v1")).unwrap(),
            expected
        );
    }

    #[test]
    fn executable_tag_key_digest_separates_owner_and_tag() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let other_owner = ScAddress::Contract(ContractId(Hash([8u8; 32])));
        let base = executable_tag_key_digest(&owner, &tag(b"v1")).unwrap();
        assert_eq!(
            base,
            executable_tag_key_digest(&owner, &tag(b"v1")).unwrap()
        );
        assert_ne!(
            base,
            executable_tag_key_digest(&owner, &tag(b"v2")).unwrap()
        );
        assert_ne!(
            base,
            executable_tag_key_digest(&other_owner, &tag(b"v1")).unwrap()
        );
    }

    #[test]
    fn account_address_renders_g_strkey() {
        let addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0u8; 32],
        ))));
        assert_eq!(
            scaddress_to_strkey(&addr).unwrap(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
    }

    #[test]
    fn contract_address_renders_c_strkey() {
        let addr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        assert_eq!(
            scaddress_to_strkey(&addr).unwrap(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
    }

    #[test]
    fn scaddress_redacted_renders_first5_last5_or_placeholder() {
        let contract = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        assert_eq!(scaddress_redacted(&contract), "CAAAA...ABSC4");
        let pool = ScAddress::LiquidityPool(PoolId(Hash([3u8; 32])));
        assert_eq!(scaddress_redacted(&pool), UNSUPPORTED_ADDRESS_PLACEHOLDER);
    }

    #[test]
    fn non_principal_variants_return_typed_error_naming_the_variant() {
        let cases = [
            (
                ScAddress::MuxedAccount(MuxedEd25519Account {
                    id: 7,
                    ed25519: Uint256([1u8; 32]),
                }),
                "MuxedAccount",
            ),
            (
                ScAddress::ClaimableBalance(ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                    [2u8; 32],
                ))),
                "ClaimableBalance",
            ),
            (
                ScAddress::LiquidityPool(PoolId(Hash([3u8; 32]))),
                "LiquidityPool",
            ),
        ];
        for (addr, variant) in cases {
            assert_eq!(
                scaddress_to_strkey(&addr),
                Err(ScAddressStrkeyError { variant }),
                "variant {variant}"
            );
        }
    }
}
