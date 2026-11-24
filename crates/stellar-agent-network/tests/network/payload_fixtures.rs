//! Typed signing payloads for the signer tests, built through the public
//! testnet constructors.
//!
//! Each builder takes a `tag` that varies the signed value, so two tags give
//! two different payloads of the same domain.

#![allow(
    clippy::expect_used,
    reason = "test fixtures; a failed build fails the test"
)]

use sha2::{Digest as _, Sha256};
use stellar_agent_network::signing::{
    SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
};
use stellar_xdr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Memo,
    MuxedAccount, Preconditions, ScAddress, SequenceNumber, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM,
};

/// The testnet passphrase every fixture payload commits to.
pub(crate) const TESTNET: &str = "Test SDF Network ; September 2015";

/// The SEP-23 payload of an empty V1 transaction at sequence `tag`.
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
    TxSigningPayload::for_envelope(&envelope, TESTNET).expect("a testnet V1 payload builds")
}

/// A testnet envelope type 9 authorization preimage under nonce `tag`.
fn preimage(tag: u8) -> HashIdPreimage {
    HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(TESTNET.as_bytes()).into()),
        nonce: i64::from(tag),
        signature_expiration_ledger: 1_000,
        invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0xc4; 32]))),
                function_name: "transfer".try_into().expect("a short symbol"),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        },
    })
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
