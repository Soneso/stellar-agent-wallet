#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixtures")]
use super::*;
use stellar_xdr::*;

pub(crate) async fn recorded_send(
    recorder: &dyn SubmissionRecorder,
    intent: &SubmissionIntent,
    sends: &std::sync::atomic::AtomicUsize,
) -> Result<SubmissionResult, WalletError> {
    let envelope = differing_envelope();
    budgeted_submission(
        None,
        std::time::Duration::from_secs(10),
        |_| async { recorder.pre_send(intent).await.map_err(SentByError::from) },
        |(), deadline| async move {
            send_and_confirm_through(
                |_| {
                    sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::future::ready(Ok(stellar_rpc_client::SendTransactionResponse {
                        hash: intent.tx_hash.clone(),
                        status: "PENDING".to_owned(),
                        error_result_xdr: None,
                        latest_ledger: 1000,
                        latest_ledger_close_time: 1000,
                    }))
                },
                || std::future::ready(Ok(crate::poll_test_support::answer("SUCCESS"))),
                &RpcEndpoint::plain(crate::redact::rpc_error_fixtures::ENDPOINT),
                SendPhase {
                    envelope: &envelope,
                    intent,
                    send_by: None,
                    send_deadline: deadline,
                    timeout: std::time::Duration::from_secs(10),
                    recorder: Some(recorder),
                    signer_kind: None,
                    witness: FailureWitness::Primary,
                },
            )
            .await
        },
    )
    .await
    .map_err(|error| match error {
        SentByError::Failed(error) => error,
        other => panic!("unexpected deadline: {other:?}"),
    })
}

pub(crate) fn muxed_destination(id: u64) -> String {
    format!(
        "{}",
        stellar_strkey::ed25519::MuxedAccount {
            ed25519: [7; 32],
            id
        }
    )
}

pub(crate) fn plain_destination() -> String {
    format!("{}", stellar_strkey::ed25519::PublicKey([8; 32]))
}

pub(crate) fn payment(to: &str) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: stellar_agent_core::payment_accounts::PaymentAccount::parse(to)
                .unwrap()
                .to_muxed_account(),
            asset: Asset::Native,
            amount: 1,
        }),
    }
}

pub(crate) fn envelope_for_destinations(operations: Vec<Operation>) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([9; 32])),
            fee: 100,
            seq_num: SequenceNumber(7),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    })
}

pub(crate) fn differing_envelope() -> TransactionEnvelope {
    envelope_for_destinations(vec![
        payment(&plain_destination()),
        nonpayment(),
        payment(&muxed_destination(u64::MAX)),
    ])
}

fn nonpayment() -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::ManageData(ManageDataOp {
            data_name: String64("display".try_into().unwrap()),
            data_value: None,
        }),
    }
}

pub(crate) fn destination_provenance() -> PaymentDestinations {
    PaymentDestinations::PerOperation(vec![
        OperationDestination {
            operation: 0,
            destination: plain_destination(),
        },
        OperationDestination {
            operation: 2,
            destination: muxed_destination(u64::MAX),
        },
    ])
}

#[test]
fn receipt_destinations_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store =
        stellar_agent_core::profile::receipt::ReceiptStore::open_at(dir.path(), "destinations")
            .unwrap();
    let destinations = payment_destinations(&envelope_for_destinations(vec![payment(
        &plain_destination(),
    )]));
    store
        .try_begin_to(
            &"ab".repeat(32),
            &"cd".repeat(32),
            "source",
            1,
            0,
            100,
            &destinations,
        )
        .unwrap();
    let wire: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.file_path().unwrap()).unwrap()).unwrap();
    assert_eq!(wire[&"ab".repeat(32)].get("destination"), None);
    assert_eq!(wire[&"ab".repeat(32)].get("destinations"), None);
}

#[test]
fn payment_destinations_follow_the_operations() {
    let plain = plain_destination();
    let zero = muxed_destination(0);
    let maximum = muxed_destination(u64::MAX);
    for (operations, expected) in [
        (vec![], PaymentDestinations::None),
        (vec![nonpayment()], PaymentDestinations::None),
        (vec![payment(&plain)], PaymentDestinations::None),
        (
            vec![payment(&zero)],
            PaymentDestinations::Single(zero.clone()),
        ),
        (
            vec![payment(&maximum), payment(&maximum)],
            PaymentDestinations::Single(maximum.clone()),
        ),
        (
            vec![payment(&maximum), nonpayment()],
            PaymentDestinations::Single(maximum.clone()),
        ),
        (
            vec![payment(&plain), nonpayment(), payment(&maximum)],
            destination_provenance(),
        ),
        (
            vec![
                payment(&plain),
                payment(&format!("{}", stellar_strkey::ed25519::PublicKey([9; 32]))),
            ],
            PaymentDestinations::None,
        ),
    ] {
        assert_eq!(
            payment_destinations(&envelope_for_destinations(operations)),
            expected
        );
    }
    let shared_base = format!("{}", stellar_strkey::ed25519::PublicKey([7; 32]));
    for pair in [
        [&shared_base, &zero],
        [&shared_base, &maximum],
        [&zero, &maximum],
    ] {
        assert_eq!(
            payment_destinations(&envelope_for_destinations(
                pair.iter().map(|to| payment(to)).collect()
            )),
            PaymentDestinations::PerOperation(vec![
                OperationDestination {
                    operation: 0,
                    destination: pair[0].clone()
                },
                OperationDestination {
                    operation: 1,
                    destination: pair[1].clone()
                },
            ]),
        );
    }
    let destination = stellar_agent_core::payment_accounts::PaymentAccount::parse(&maximum)
        .unwrap()
        .to_muxed_account();
    let receive = Operation {
        source_account: None,
        body: OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
            send_asset: Asset::Native,
            send_max: 3,
            destination: destination.clone(),
            dest_asset: Asset::Native,
            dest_amount: 1,
            path: Default::default(),
        }),
    };
    let send = Operation {
        source_account: None,
        body: OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
            send_asset: Asset::Native,
            send_amount: 1,
            destination,
            dest_asset: Asset::Native,
            dest_min: 1,
            path: Default::default(),
        }),
    };
    for operation in [receive, send] {
        assert_eq!(
            payment_destinations(&envelope_for_destinations(vec![operation])),
            PaymentDestinations::Single(maximum.clone())
        );
    }
    let inner = differing_envelope();
    assert_eq!(
        payment_operation_destinations(&inner),
        match destination_provenance() {
            PaymentDestinations::PerOperation(entries) => entries,
            _ => unreachable!(),
        }
    );
    let TransactionEnvelope::Tx(inner) = inner else {
        unreachable!()
    };
    let outer = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256([10; 32])),
            fee: 1000,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner.clone()),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: Default::default(),
    });
    assert_eq!(payment_destinations(&outer), destination_provenance());
    let legacy = TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256([9; 32]),
            fee: 100,
            seq_num: SequenceNumber(7),
            time_bounds: None,
            memo: Memo::None,
            operations: inner.tx.operations,
            ext: TransactionV0Ext::V0,
        },
        signatures: Default::default(),
    });
    assert_eq!(payment_destinations(&legacy), PaymentDestinations::None);
    assert!(payment_operation_destinations(&legacy).is_empty());
}
