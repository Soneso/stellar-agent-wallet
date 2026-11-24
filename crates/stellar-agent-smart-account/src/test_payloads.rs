//! Typed signing payloads for this crate's signer tests, built through the
//! public testnet constructors of the network crate.
//!
//! Each builder takes a `tag` that varies the signed value, so two tags give
//! two different payloads of the same domain.

#![allow(
    clippy::expect_used,
    reason = "test fixtures; a failed build fails the test"
)]

use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_network::signing::{
    SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
};
use stellar_xdr::{
    ContractId, Hash, HashIdPreimage, InvokeContractArgs, Memo, MuxedAccount, Preconditions,
    ScAddress, SequenceNumber, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
};

use crate::managers::auth_entry::{network_id_of, soroban_authorization_preimage};

/// The SEP-23 payload of an empty V1 testnet transaction at sequence `tag`.
pub(crate) fn tx_payload(tag: u8) -> TxSigningPayload {
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0x11; 32])),
            fee: 100,
            seq_num: SequenceNumber(i64::from(tag)),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    });
    TxSigningPayload::for_envelope(&envelope, TESTNET_PASSPHRASE)
        .expect("a testnet V1 payload builds")
}

/// A testnet envelope type 9 authorization preimage under nonce `tag`.
fn preimage(tag: u8) -> HashIdPreimage {
    soroban_authorization_preimage(
        network_id_of(TESTNET_PASSPHRASE),
        i64::from(tag),
        1_000,
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
                function_name: "transfer".try_into().expect("a short symbol"),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        },
    )
}

/// The Soroban authorization payload of the preimage under nonce `tag`.
pub(crate) fn soroban_payload(tag: u8) -> SorobanAuthPayload {
    SorobanAuthPayload::from_preimage(&preimage(tag)).expect("a testnet preimage builds")
}

/// The smart-account digest of the preimage under nonce `tag` with no rule
/// ids bound.
pub(crate) fn auth_digest(tag: u8) -> SmartAccountAuthDigest {
    SmartAccountAuthDigest::new(&preimage(tag), &[]).expect("a testnet digest builds")
}
