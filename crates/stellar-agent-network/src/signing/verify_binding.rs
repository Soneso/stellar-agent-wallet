//! Signature-network binding verification.
//!
//! A Stellar signature commits to a network: the SEP-23
//! `TransactionSignaturePayload` hashed by the signer carries
//! `network_id = SHA-256(passphrase)`, so the same transaction signed for two
//! networks produces two different signatures. Nothing in the wire format
//! records which network a signature was made for — it can only be recovered
//! by re-deriving the payload under a candidate network id and checking the
//! signature against it.
//!
//! [`verify_signature_network_binding`] performs that check for every
//! decorated signature on an envelope, against the ed25519 signers of the
//! accounts whose authority the transaction actually invokes. It is the
//! reason an envelope signed for one network cannot be submitted under
//! another's passphrase.
//!
//! # What is checked
//!
//! - Every decorated signature must verify under the network the endpoint
//!   serves, against some ed25519 signer of the relevant source accounts.
//! - A signature that instead verifies under the mainnet network id is a
//!   mainnet authorisation and is refused, whatever endpoint it was relayed to.
//! - A signature that verifies under neither is refused: an envelope carrying
//!   a signature this layer cannot account for is not submitted.
//! - A signature set with no signatures at all is refused before the round
//!   trip, per set: a fee-bump's outer and inner transactions each need one.
//!
//! # Which accounts are relevant
//!
//! For a `Tx` envelope, the transaction's own source account and every
//! distinct operation-level source account: an operation-level source
//! contributes its own authority and is signed for separately. For a
//! `TxFeeBump` envelope, the outer signatures answer to the fee source and the
//! inner signatures to the inner transaction's sources. Muxed accounts resolve
//! to the underlying G-account, which is where the signer set lives.
//!
//! An operation source that an earlier operation of the same transaction
//! creates is absent from the ledger when the envelope is submitted and
//! present when the operation applies. Its signer set at apply time is exactly
//! its own master key, which is the account id, so it is derived locally
//! rather than read. The CAP-33 sponsored-creation sandwich is built this way:
//! the new account signs the `EndSponsoringFutureReserves` operation that
//! names it as source, in the same transaction that creates it.
//!
//! Legacy `TxV0` envelopes are refused, matching the signing path.

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_agent_core::error::{NetworkError, ProtocolError, WalletError};
use stellar_xdr::{
    DecoratedSignature, FeeBumpTransactionInnerTx, Hash, Limits, MuxedAccount, Transaction,
    TransactionEnvelope, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    WriteXdr,
};
use tokio::time::Instant;

use crate::account::fetch_account_signers;
use crate::client::StellarRpcClient;
use crate::submit::{MAINNET_PASSPHRASE, bytes_to_hex};

/// The `Display` detail used when a legacy V0 envelope reaches a path that
/// only handles the SEP-23 tagged-transaction variants.
///
/// Identical to the signing path's rejection: V0 is not part of the SEP-23
/// tagged-transaction set, so neither signing nor binding verification can
/// construct a payload for it.
const V0_UNSUPPORTED: &str = "legacy V0 transaction envelopes are not supported; \
                              use a V1 Tx or TxFeeBump envelope";

/// One set of decorated signatures, the SEP-23 tagged transaction they cover,
/// and the accounts whose signers may have produced them.
struct SignatureGroup<'a> {
    signatures: &'a [DecoratedSignature],
    tagged: TransactionSignaturePayloadTaggedTransaction,
    accounts: Vec<AccountRef>,
}

/// One account whose authority a signature group may invoke.
struct AccountRef {
    /// The G-strkey, used to key the fetched signer sets.
    id: String,
    /// The account's own ed25519 key, which is also its master key.
    key: [u8; 32],
    /// Set when an earlier operation of the same transaction creates this
    /// account. Such an account has no ledger entry to read and, once created,
    /// exactly one signer: its master key.
    created_in_transaction: bool,
}

/// Verifies that every signature on `envelope` was produced under
/// `endpoint_passphrase`.
///
/// `endpoint_passphrase` must be the passphrase the RPC endpoint itself
/// reported, established by [`StellarRpcClient::verify_network_passphrase`]
/// before this call. Passing a caller-declared value that the endpoint has not
/// confirmed would verify the binding against the wrong network and defeat the
/// check.
///
/// Signer sets are fetched in a single bounded, retried `getLedgerEntries`
/// under `deadline`.
///
/// # Errors
///
/// - [`NetworkError::EnvelopeUnsigned`] if any signature set on the envelope
///   is empty.
/// - [`NetworkError::EnvelopeSignedForMainnet`] if a signature verifies under
///   the mainnet network id.
/// - [`NetworkError::EnvelopeSignatureUnverifiable`] if a signature verifies
///   under neither network id for any gathered signer, including when no
///   gathered ed25519 signer matches its hint.
/// - [`NetworkError::AccountNotFound`] if a source account is absent from the
///   ledger and is not created by the transaction itself.
/// - [`WalletError::Protocol`] for a legacy V0 envelope or an XDR encode
///   failure.
pub(crate) async fn verify_signature_network_binding(
    client: &StellarRpcClient,
    envelope: &TransactionEnvelope,
    endpoint_passphrase: &str,
    deadline: Instant,
) -> Result<(), WalletError> {
    let groups = signature_groups(envelope)?;

    // An unsigned envelope is the natural mistake after a build-only stage.
    // It carries no hint to report, so it gets its own refusal rather than
    // being reported as an unverifiable signature.
    //
    // Each group is checked on its own: a fee-bump whose outer transaction is
    // signed and whose inner transaction is not carries no authority for the
    // inner operations, and counting across groups would let the outer
    // signature stand in for the missing inner one.
    if groups.iter().any(|g| g.signatures.is_empty()) {
        return Err(WalletError::Network(NetworkError::EnvelopeUnsigned));
    }

    // One round trip covers every account that already exists. Accounts the
    // transaction creates have no entry to read; their master key is derived
    // below. Every group names at least one account that is not created here
    // (a transaction source, or a fee source), so this list is never empty.
    let mut accounts_to_fetch: Vec<String> = Vec::new();
    for group in &groups {
        for account in &group.accounts {
            if !account.created_in_transaction {
                accounts_to_fetch.push(account.id.clone());
            }
        }
    }
    let signers_by_account = fetch_account_signers(client, &accounts_to_fetch, deadline).await?;

    let endpoint_network_id = network_id(endpoint_passphrase);
    let mainnet_network_id = network_id(MAINNET_PASSPHRASE);

    for group in &groups {
        // The candidate pool for a group is the union of its accounts' signer
        // sets: any of them could have produced any of the group's signatures,
        // and the hint narrows it further per signature.
        let mut candidate_keys: Vec<[u8; 32]> = Vec::new();
        for account in &group.accounts {
            if account.created_in_transaction {
                candidate_keys.push(account.key);
            } else if let Some(keys) = signers_by_account.get(&account.id) {
                candidate_keys.extend_from_slice(keys);
            }
        }

        let endpoint_hash = payload_hash(&endpoint_network_id, &group.tagged)?;
        let mainnet_hash = payload_hash(&mainnet_network_id, &group.tagged)?;

        for signature in group.signatures {
            verify_one_signature(signature, &candidate_keys, &endpoint_hash, &mainnet_hash)?;
        }
    }

    Ok(())
}

/// Splits an envelope into the signature groups that must be verified, each
/// carrying the payload its signatures cover and the accounts that may have
/// signed it.
fn signature_groups(
    envelope: &TransactionEnvelope,
) -> Result<Vec<SignatureGroup<'_>>, WalletError> {
    match envelope {
        TransactionEnvelope::Tx(v1) => Ok(vec![SignatureGroup {
            signatures: v1.signatures.as_slice(),
            tagged: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone()),
            accounts: transaction_source_accounts(&v1.tx),
        }]),
        TransactionEnvelope::TxFeeBump(fb) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            Ok(vec![
                SignatureGroup {
                    signatures: fb.signatures.as_slice(),
                    tagged: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone()),
                    accounts: vec![account_ref(&fb.tx.fee_source, false)],
                },
                SignatureGroup {
                    signatures: inner.signatures.as_slice(),
                    tagged: TransactionSignaturePayloadTaggedTransaction::Tx(inner.tx.clone()),
                    accounts: transaction_source_accounts(&inner.tx),
                },
            ])
        }
        TransactionEnvelope::TxV0(_) => Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: V0_UNSUPPORTED.to_owned(),
        })),
    }
}

/// Returns the transaction's source account followed by every distinct
/// operation-level source account.
///
/// The transaction source always exists before the transaction applies — it
/// supplies the sequence number — so it is never marked as created here.
fn transaction_source_accounts(tx: &Transaction) -> Vec<AccountRef> {
    let mut accounts = vec![account_ref(&tx.source_account, false)];
    for (index, op) in tx.operations.iter().enumerate() {
        let Some(source) = &op.source_account else {
            continue;
        };
        let key = muxed_account_key(source);
        if accounts.iter().any(|existing| existing.key == key) {
            continue;
        }
        accounts.push(account_ref(source, created_before_index(tx, index, &key)));
    }
    accounts
}

/// Returns true when an operation before `index` creates the account `key`.
///
/// Operations apply in order, so only a creation at a strictly earlier index
/// leaves the account present when the operation at `index` applies.
fn created_before_index(tx: &Transaction, index: usize, key: &[u8; 32]) -> bool {
    tx.operations.iter().take(index).any(|op| {
        let stellar_xdr::OperationBody::CreateAccount(create) = &op.body else {
            return false;
        };
        let stellar_xdr::PublicKey::PublicKeyTypeEd25519(destination) = &create.destination.0;
        destination.0 == *key
    })
}

/// Builds an [`AccountRef`] for the account a `MuxedAccount` resolves to.
fn account_ref(muxed: &MuxedAccount, created_in_transaction: bool) -> AccountRef {
    let key = muxed_account_key(muxed);
    AccountRef {
        id: format!("{}", stellar_strkey::ed25519::PublicKey(key)),
        key,
        created_in_transaction,
    }
}

/// Resolves a `MuxedAccount` to the 32 key bytes of the underlying account.
///
/// The mux id selects a sub-account for memo purposes; the signer set and the
/// ledger entry belong to the underlying G-account.
fn muxed_account_key(muxed: &MuxedAccount) -> [u8; 32] {
    match muxed {
        MuxedAccount::Ed25519(uint256) => uint256.0,
        MuxedAccount::MuxedEd25519(med) => med.ed25519.0,
    }
}

/// Returns `SHA-256(passphrase)`, the SEP-23 network id.
fn network_id(passphrase: &str) -> Hash {
    Hash(Sha256::digest(passphrase.as_bytes()).into())
}

/// Rebuilds the SEP-23 signing payload under `network_id` and returns its
/// SHA-256 hash — the exact bytes an ed25519 signature covers.
fn payload_hash(
    network_id: &Hash,
    tagged: &TransactionSignaturePayloadTaggedTransaction,
) -> Result<[u8; 32], WalletError> {
    let payload = TransactionSignaturePayload {
        network_id: network_id.clone(),
        tagged_transaction: tagged.clone(),
    };
    let bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("TransactionSignaturePayload XDR encode failed: {e}"),
        })
    })?;
    Ok(Sha256::digest(&bytes).into())
}

/// Classifies one decorated signature against the candidate signer keys.
///
/// The hint narrows the candidates to keys whose last four bytes match; a hint
/// collision is resolved by trying every match, so a colliding wrong key does
/// not shadow the right one. `verify_strict` rejects small-order and
/// non-canonical points, so a signature cannot be made to verify under an
/// attacker-chosen key.
fn verify_one_signature(
    signature: &DecoratedSignature,
    candidate_keys: &[[u8; 32]],
    endpoint_hash: &[u8; 32],
    mainnet_hash: &[u8; 32],
) -> Result<(), WalletError> {
    let hint = signature.hint.0;
    let unverifiable = || {
        WalletError::Network(NetworkError::EnvelopeSignatureUnverifiable {
            hint: bytes_to_hex(&hint),
        })
    };

    let candidates: Vec<&[u8; 32]> = candidate_keys
        .iter()
        .filter(|key| key[28..32] == hint)
        .collect();
    if candidates.is_empty() {
        return Err(unverifiable());
    }

    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature.signature.0.as_slice()) else {
        return Err(unverifiable());
    };
    let dalek_signature = DalekSignature::from_bytes(&sig_bytes);

    for key in &candidates {
        if let Ok(verifying_key) = VerifyingKey::from_bytes(key)
            && verifying_key
                .verify_strict(endpoint_hash, &dalek_signature)
                .is_ok()
        {
            return Ok(());
        }
    }

    // Not made for this network. Distinguish a mainnet authorisation, which is
    // structurally refused, from a signature this layer cannot place at all.
    for key in &candidates {
        if let Ok(verifying_key) = VerifyingKey::from_bytes(key)
            && verifying_key
                .verify_strict(mainnet_hash, &dalek_signature)
                .is_ok()
        {
            return Err(WalletError::Network(NetworkError::EnvelopeSignedForMainnet));
        }
    }

    Err(unverifiable())
}

/// Refuses a legacy V0 envelope with the same error the signing path uses.
///
/// Called before the endpoint identity probe so a V0 envelope costs no round
/// trip.
pub(crate) fn reject_v0_envelope(envelope: &TransactionEnvelope) -> Result<(), WalletError> {
    if matches!(envelope, TransactionEnvelope::TxV0(_)) {
        return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: V0_UNSUPPORTED.to_owned(),
        }));
    }
    Ok(())
}
