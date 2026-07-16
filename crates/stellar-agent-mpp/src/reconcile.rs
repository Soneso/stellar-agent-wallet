//! Sponsored transaction ledger reconciliation.

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_rpc_client::Client;
use stellar_xdr::{
    FeeBumpTransactionInnerTx, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HostFunction, Limits, Memo, MuxedAccount, OperationBody, Preconditions, PublicKey, ScVal,
    SorobanCredentials, TimePoint, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::{AuthorizationRecord, LedgerOutcome, MppAuthorizationStore, MppError, MppErrorCode};

/// Closed RPC transaction status used by reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStatus {
    /// Transaction succeeded in a final ledger.
    Success,
    /// Transaction failed in a final ledger.
    Failed,
    /// RPC has no final transaction result.
    NotFound,
}

/// Bounded transaction observation returned by an injected RPC.
#[derive(Clone, Debug)]
pub struct TransactionObservation {
    /// Closed status.
    pub status: TransactionStatus,
    /// Final ledger when available.
    pub ledger: Option<u32>,
    /// Exact transaction hash returned by RPC.
    pub transaction_hash: Option<String>,
    /// Direct or fee-bump envelope when final.
    pub envelope: Option<TransactionEnvelope>,
}

/// RPC boundary for deterministic reconciliation tests.
#[async_trait]
pub trait ReconciliationRpc: Send + Sync {
    /// Looks up a lowercase transaction hash.
    async fn transaction(
        &self,
        transaction_hash: &[u8; 32],
    ) -> Result<TransactionObservation, MppError>;
}

/// Production reconciliation RPC backed by `stellar-rpc-client`.
pub struct StellarReconciliationRpc {
    client: Client,
}

impl StellarReconciliationRpc {
    /// Constructs a client for an operator-configured RPC URL.
    ///
    /// # Errors
    ///
    /// Returns `mpp.reconciliation_unavailable` when the URL is invalid.
    pub fn new(rpc_url: &str) -> Result<Self, MppError> {
        Ok(Self {
            client: Client::new(rpc_url).map_err(|_error| unavailable())?,
        })
    }
}

#[async_trait]
impl ReconciliationRpc for StellarReconciliationRpc {
    async fn transaction(
        &self,
        transaction_hash: &[u8; 32],
    ) -> Result<TransactionObservation, MppError> {
        let response = self
            .client
            .get_transaction(&stellar_xdr::Hash(*transaction_hash))
            .await
            .map_err(|_error| unavailable())?;
        let status = match response.status.as_str() {
            "SUCCESS" => TransactionStatus::Success,
            "FAILED" => TransactionStatus::Failed,
            "NOT_FOUND" => TransactionStatus::NotFound,
            _ => return Err(unavailable()),
        };
        Ok(TransactionObservation {
            status,
            ledger: response.ledger,
            transaction_hash: response.tx_hash,
            envelope: response.envelope,
        })
    }
}

/// Redacted reconciliation result.
#[derive(Clone, Debug, Serialize)]
pub struct ReconciliationResult {
    /// Durable authorization identifier.
    pub authorization_id: String,
    /// Verified outcome (`settled` or `failed`).
    pub outcome: String,
    /// Final ledger sequence.
    pub ledger: u32,
    /// First-eight/last-eight transaction hash rendering.
    pub transaction_reference_redacted: String,
}

/// Verifies that a final direct or fee-bump transaction is the exact prepared
/// sponsored charge, then records its independent ledger outcome.
///
/// # Errors
///
/// Returns `mpp.reconciliation_unavailable` for malformed hashes, not-found or
/// incomplete RPC observations, receipt-reference mismatch, or transaction
/// semantic mismatch.
pub async fn reconcile_transaction(
    state_store: &MppAuthorizationStore,
    authorization_id: &str,
    transaction_hash: &str,
    now_unix: i64,
    rpc: &(dyn ReconciliationRpc + Send + Sync),
) -> Result<ReconciliationResult, MppError> {
    let hash = parse_hash(transaction_hash)?;
    let record = state_store.load(authorization_id)?;
    validate_receipt_reference(&record, transaction_hash)?;
    let observation = rpc.transaction(&hash).await?;
    if observation.status == TransactionStatus::NotFound
        || observation.transaction_hash.as_deref() != Some(transaction_hash)
    {
        return Err(unavailable());
    }
    let ledger = observation.ledger.ok_or_else(unavailable)?;
    let envelope = observation.envelope.as_ref().ok_or_else(unavailable)?;
    inspect_observed_envelope(&record, envelope)?;
    let (outcome, outcome_name) = match observation.status {
        TransactionStatus::Success => (
            LedgerOutcome::Settled {
                ledger,
                reconciled_at: now_unix,
            },
            "settled",
        ),
        TransactionStatus::Failed => (
            LedgerOutcome::Failed {
                ledger,
                reconciled_at: now_unix,
            },
            "failed",
        ),
        TransactionStatus::NotFound => return Err(unavailable()),
    };
    state_store.record_ledger_outcome(authorization_id, outcome, now_unix)?;
    Ok(ReconciliationResult {
        authorization_id: authorization_id.to_owned(),
        outcome: outcome_name.to_owned(),
        ledger,
        transaction_reference_redacted: redact_reference(transaction_hash),
    })
}

fn inspect_observed_envelope(
    record: &AuthorizationRecord,
    envelope: &TransactionEnvelope,
) -> Result<(), MppError> {
    let inner = match envelope {
        TransactionEnvelope::Tx(inner) => inner,
        TransactionEnvelope::TxFeeBump(fee_bump) => match &fee_bump.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(inner) => inner,
        },
        TransactionEnvelope::TxV0(_) => return Err(unavailable()),
    };
    inspect_inner(record, inner)
}

fn inspect_inner(
    record: &AuthorizationRecord,
    envelope: &TransactionV1Envelope,
) -> Result<(), MppError> {
    let prepared = record.prepared_charge()?;
    let expected_expiry = u64::try_from(record.expires_at()).map_err(|_error| unavailable())?;
    let time_bounds = match &envelope.tx.cond {
        Preconditions::Time(bounds) => Some(bounds),
        Preconditions::V2(value) => value.time_bounds.as_ref(),
        Preconditions::None => None,
    };
    let Some(time_bounds) = time_bounds else {
        return Err(unavailable());
    };
    if envelope.tx.seq_num.0 <= 0
        || !matches!(envelope.tx.memo, Memo::None)
        || time_bounds.min_time != TimePoint(0)
        || time_bounds.max_time != TimePoint(expected_expiry)
        || envelope.tx.operations.len() != 1
        || !matches!(envelope.tx.ext, TransactionExt::V1(_))
    {
        return Err(unavailable());
    }
    verify_server_envelope_signature(envelope)?;
    let operation = envelope.tx.operations.first().ok_or_else(unavailable)?;
    let OperationBody::InvokeHostFunction(host) = &operation.body else {
        return Err(unavailable());
    };
    if operation.source_account.is_some()
        || host.host_function != HostFunction::InvokeContract(prepared.invoke.clone())
        || host.auth.len() != 1
    {
        return Err(unavailable());
    }
    let auth = host.auth.first().ok_or_else(unavailable)?;
    let SorobanCredentials::Address(credentials) = &auth.credentials else {
        return Err(unavailable());
    };
    let SorobanCredentials::Address(expected) = &prepared.auth_entry.credentials else {
        return Err(unavailable());
    };
    if credentials.address != expected.address
        || credentials.signature_expiration_ledger == 0
        || matches!(credentials.signature, stellar_xdr::ScVal::Void)
        || auth.root_invocation != prepared.auth_entry.root_invocation
    {
        return Err(unavailable());
    }
    verify_address_signature(credentials, auth)
}

fn verify_server_envelope_signature(envelope: &TransactionV1Envelope) -> Result<(), MppError> {
    let MuxedAccount::Ed25519(Uint256(public_key)) = &envelope.tx.source_account else {
        return Err(unavailable());
    };
    if *public_key == [0; 32] || envelope.signatures.len() != 1 {
        return Err(unavailable());
    }
    let signature = envelope.signatures.first().ok_or_else(unavailable)?;
    if signature.hint.0 != public_key[28..] {
        return Err(unavailable());
    }
    let signature_bytes: [u8; 64] = signature
        .signature
        .as_slice()
        .try_into()
        .map_err(|_error| unavailable())?;
    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(envelope.tx.clone()),
    };
    let payload = payload
        .to_xdr(Limits::none())
        .map_err(|_error| unavailable())?;
    let digest: [u8; 32] = Sha256::digest(payload).into();
    VerifyingKey::from_bytes(public_key)
        .map_err(|_error| unavailable())?
        .verify_strict(&digest, &Signature::from_bytes(&signature_bytes))
        .map_err(|_error| unavailable())
}

fn verify_address_signature(
    credentials: &stellar_xdr::SorobanAddressCredentials,
    auth: &stellar_xdr::SorobanAuthorizationEntry,
) -> Result<(), MppError> {
    let ScVal::Vec(Some(signers)) = &credentials.signature else {
        return Err(unavailable());
    };
    if signers.len() != 1 {
        return Err(unavailable());
    }
    let ScVal::Map(Some(fields)) = &signers[0] else {
        return Err(unavailable());
    };
    if fields.len() != 2 {
        return Err(unavailable());
    }
    let mut public_key = None;
    let mut signature = None;
    for field in fields.iter() {
        let ScVal::Symbol(name) = &field.key else {
            return Err(unavailable());
        };
        match name.0.to_utf8_string_lossy().as_str() {
            "public_key" => {
                let ScVal::Bytes(value) = &field.val else {
                    return Err(unavailable());
                };
                public_key =
                    Some(<[u8; 32]>::try_from(value.0.as_slice()).map_err(|_error| unavailable())?);
            }
            "signature" => {
                let ScVal::Bytes(value) = &field.val else {
                    return Err(unavailable());
                };
                signature =
                    Some(<[u8; 64]>::try_from(value.0.as_slice()).map_err(|_error| unavailable())?);
            }
            _ => return Err(unavailable()),
        }
    }
    let public_key = public_key.ok_or_else(unavailable)?;
    let signature = signature.ok_or_else(unavailable)?;
    let stellar_xdr::ScAddress::Account(account) = &credentials.address else {
        return Err(unavailable());
    };
    let PublicKey::PublicKeyTypeEd25519(Uint256(account_key)) = &account.0;
    if public_key != *account_key {
        return Err(unavailable());
    }
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
        nonce: credentials.nonce,
        signature_expiration_ledger: credentials.signature_expiration_ledger,
        invocation: auth.root_invocation.clone(),
    });
    let preimage = preimage
        .to_xdr(Limits::none())
        .map_err(|_error| unavailable())?;
    let digest: [u8; 32] = Sha256::digest(preimage).into();
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_error| unavailable())?
        .verify_strict(&digest, &Signature::from_bytes(&signature))
        .map_err(|_error| unavailable())
}

fn validate_receipt_reference(
    record: &AuthorizationRecord,
    transaction_hash: &str,
) -> Result<(), MppError> {
    if let Some(receipt) = record.host_observation()
        && receipt.reference_digest != Sha256::digest(transaction_hash.as_bytes()).as_slice()
    {
        return Err(unavailable());
    }
    Ok(())
}

fn parse_hash(value: &str) -> Result<[u8; 32], MppError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unavailable());
    }
    hex::decode(value)
        .map_err(|_error| unavailable())?
        .try_into()
        .map_err(|_bytes: Vec<u8>| unavailable())
}

fn redact_reference(value: &str) -> String {
    format!("{}...{}", &value[..8], &value[value.len() - 8..])
}

const fn unavailable() -> MppError {
    MppError::new(
        MppErrorCode::ReconciliationUnavailable,
        "ledger reconciliation could not verify the MPP transaction",
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "test fixtures use concise assertions"
    )]

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer as _, SigningKey};
    use stellar_xdr::{
        DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        ReadXdr, ScBytes, ScMap, ScVec, SequenceNumber, Signature as XdrSignature, SignatureHint,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        ApprovalDisposition, AuthorizationStatus, CredentialOutput, persist_prepared_authorization,
        service::commit_authorization, sponsored::tests::prepared_fixture,
    };

    const NOW: i64 = 1_700_000_000;
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone)]
    struct StaticRpc(TransactionObservation);

    struct FailingRpc;

    #[async_trait]
    impl ReconciliationRpc for StaticRpc {
        async fn transaction(
            &self,
            _transaction_hash: &[u8; 32],
        ) -> Result<TransactionObservation, MppError> {
            Ok(self.0.clone())
        }
    }

    #[async_trait]
    impl ReconciliationRpc for FailingRpc {
        async fn transaction(
            &self,
            _transaction_hash: &[u8; 32],
        ) -> Result<TransactionObservation, MppError> {
            Err(unavailable())
        }
    }

    async fn authorized_fixture(
        profile: &str,
    ) -> (TempDir, MppAuthorizationStore, String, TransactionEnvelope) {
        let directory = TempDir::new().expect("tempdir");
        let state = MppAuthorizationStore::at_path(directory.path().join("state"), [9; 32]);
        let (prepared, signer, rpc) = prepared_fixture(NOW).await;
        let preview = persist_prepared_authorization(
            profile,
            TESTNET_PASSPHRASE,
            &prepared,
            ApprovalDisposition::Allow,
            "424242",
            NOW,
            &state,
            None,
        )
        .expect("persist");
        let credential = commit_authorization(
            &state,
            None,
            None,
            &preview.authorization_id,
            NOW + 1,
            TESTNET_PASSPHRASE,
            &signer,
            &rpc,
            |_record, _prepared, _effects| Ok(()),
            |_authorized| Ok(()),
            |_withheld| {},
        )
        .await
        .expect("commit");
        let CredentialOutput::Http { authorization } = credential else {
            panic!("fixture must be HTTP")
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(authorization.strip_prefix("Payment ").expect("scheme"))
            .expect("credential base64");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("credential JSON");
        let transaction = value["payload"]["transaction"]
            .as_str()
            .expect("transaction");
        let envelope = TransactionEnvelope::from_xdr_base64(transaction, Limits::none())
            .expect("transaction XDR");
        (
            directory,
            state,
            preview.authorization_id,
            sign_as_observed(envelope),
        )
    }

    fn sign_as_observed(mut envelope: TransactionEnvelope) -> TransactionEnvelope {
        let TransactionEnvelope::Tx(inner) = &mut envelope else {
            panic!("fixture must be v1")
        };
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        inner.tx.source_account = MuxedAccount::Ed25519(Uint256(public_key));
        inner.tx.seq_num = SequenceNumber(2);
        let payload = TransactionSignaturePayload {
            network_id: Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(inner.tx.clone()),
        }
        .to_xdr(Limits::none())
        .expect("signature payload");
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let signature = signing_key.sign(&digest).to_bytes();
        inner.signatures = vec![DecoratedSignature {
            hint: SignatureHint(public_key[28..].try_into().expect("signature hint")),
            signature: XdrSignature(signature.to_vec().try_into().expect("signature bytes")),
        }]
        .try_into()
        .expect("bounded signatures");
        envelope
    }

    fn observation(status: TransactionStatus, envelope: TransactionEnvelope) -> StaticRpc {
        StaticRpc(TransactionObservation {
            status,
            ledger: Some(1_234),
            transaction_hash: Some(HASH.to_owned()),
            envelope: Some(envelope),
        })
    }

    #[tokio::test]
    async fn direct_reconciliation_is_idempotent_across_timestamps() {
        let (_directory, state, id, envelope) = authorized_fixture("direct").await;
        let rpc = observation(TransactionStatus::Success, envelope);
        let first = reconcile_transaction(&state, &id, HASH, NOW + 2, &rpc)
            .await
            .expect("first reconciliation");
        let second = reconcile_transaction(&state, &id, HASH, NOW + 20, &rpc)
            .await
            .expect("idempotent reconciliation");
        assert_eq!(first.outcome, "settled");
        assert_eq!(second.ledger, 1_234);
        assert_eq!(
            state.load(&id).expect("state").status(),
            AuthorizationStatus::Settled
        );
    }

    #[tokio::test]
    async fn fee_bump_inner_transaction_is_verified() {
        let (_directory, state, id, envelope) = authorized_fixture("fee-bump").await;
        let TransactionEnvelope::Tx(inner) = envelope else {
            panic!("fixture must be v1")
        };
        let outer = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([3; 32])),
                fee: 10_000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Vec::new().try_into().expect("empty signatures"),
        });
        let result = reconcile_transaction(
            &state,
            &id,
            HASH,
            NOW + 2,
            &observation(TransactionStatus::Success, outer),
        )
        .await
        .expect("fee bump reconciliation");
        assert_eq!(result.outcome, "settled");
    }

    #[tokio::test]
    async fn final_failure_is_recorded_independently_of_a_receipt() {
        let (_directory, state, id, envelope) = authorized_fixture("failed").await;
        let result = reconcile_transaction(
            &state,
            &id,
            HASH,
            NOW + 2,
            &observation(TransactionStatus::Failed, envelope),
        )
        .await
        .expect("failed transaction is still a final observation");

        assert_eq!(result.outcome, "failed");
        let record = state.load(&id).expect("state");
        assert_eq!(record.status(), AuthorizationStatus::Failed);
        assert!(matches!(
            record.ledger_outcome(),
            LedgerOutcome::Failed { ledger: 1_234, .. }
        ));
    }

    #[tokio::test]
    async fn not_found_does_not_mutate_authorization_state() {
        let (_directory, state, id, _envelope) = authorized_fixture("not-found").await;
        let rpc = StaticRpc(TransactionObservation {
            status: TransactionStatus::NotFound,
            ledger: None,
            transaction_hash: None,
            envelope: None,
        });
        let error = reconcile_transaction(&state, &id, HASH, NOW + 2, &rpc)
            .await
            .expect_err("not found is not final proof");

        assert_eq!(error.code(), "mpp.reconciliation_unavailable");
        let record = state.load(&id).expect("state");
        assert_eq!(record.status(), AuthorizationStatus::Authorized);
        assert!(matches!(record.ledger_outcome(), LedgerOutcome::Unknown));
    }

    #[tokio::test]
    async fn rpc_failure_does_not_mutate_authorization_state() {
        let (_directory, state, id, _envelope) = authorized_fixture("rpc-failure").await;
        let error = reconcile_transaction(&state, &id, HASH, NOW + 2, &FailingRpc)
            .await
            .expect_err("RPC failure must stay retryable");

        assert_eq!(error.code(), "mpp.reconciliation_unavailable");
        assert_eq!(
            state.load(&id).expect("state").status(),
            AuthorizationStatus::Authorized
        );
    }

    #[tokio::test]
    async fn mutated_authorization_signature_is_rejected() {
        let (_directory, state, id, mut envelope) = authorized_fixture("mutated-signature").await;
        let TransactionEnvelope::Tx(inner) = &mut envelope else {
            panic!("fixture must be v1")
        };
        let mut operations = inner.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(host) = &mut operations[0].body else {
            panic!("fixture must invoke")
        };
        let mut auth = host.auth.to_vec();
        let SorobanCredentials::Address(credentials) = &mut auth[0].credentials else {
            panic!("fixture must use address credentials")
        };
        let ScVal::Vec(Some(signers)) = &credentials.signature else {
            panic!("signature vector")
        };
        let mut signer_values = signers.to_vec();
        let ScVal::Map(Some(fields)) = &signer_values[0] else {
            panic!("signature map")
        };
        let mut fields = fields.0.to_vec();
        let signature = fields
            .iter_mut()
            .find(|field| {
                matches!(&field.key, ScVal::Symbol(name) if name.0.to_utf8_string_lossy() == "signature")
            })
            .expect("signature field");
        let ScVal::Bytes(bytes) = &signature.val else {
            panic!("signature bytes")
        };
        let mut mutated = bytes.0.to_vec();
        mutated[0] ^= 1;
        signature.val = ScVal::Bytes(ScBytes(mutated.try_into().expect("bounded bytes")));
        signer_values[0] = ScVal::Map(Some(ScMap(fields.try_into().expect("bounded map"))));
        credentials.signature = ScVal::Vec(Some(ScVec(
            signer_values.try_into().expect("bounded signer vector"),
        )));
        host.auth = auth.try_into().expect("bounded auth");
        inner.tx.operations = operations.try_into().expect("bounded operations");

        let error = reconcile_transaction(
            &state,
            &id,
            HASH,
            NOW + 2,
            &observation(TransactionStatus::Success, envelope),
        )
        .await
        .expect_err("mutated signature must fail");
        assert_eq!(error.code(), "mpp.reconciliation_unavailable");
        assert_eq!(
            state.load(&id).expect("state").status(),
            AuthorizationStatus::Authorized
        );
    }

    #[tokio::test]
    async fn mutated_server_source_without_a_matching_signature_is_rejected() {
        let (_directory, state, id, mut envelope) = authorized_fixture("mutated-server").await;
        let TransactionEnvelope::Tx(inner) = &mut envelope else {
            panic!("fixture must be v1")
        };
        inner.tx.source_account = MuxedAccount::Ed25519(Uint256([4; 32]));

        let error = reconcile_transaction(
            &state,
            &id,
            HASH,
            NOW + 2,
            &observation(TransactionStatus::Success, envelope),
        )
        .await
        .expect_err("server source and signature are one verified unit");
        assert_eq!(error.code(), "mpp.reconciliation_unavailable");
        assert_eq!(
            state.load(&id).expect("state").status(),
            AuthorizationStatus::Authorized
        );
    }
}
