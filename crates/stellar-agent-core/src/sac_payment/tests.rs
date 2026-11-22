#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures and assertions"
)]

use super::*;

const INVALID: &str = "validation.contract_payment_invalid";
const FOOTPRINT: &str = "validation.contract_payment_footprint";

fn account(byte: u8) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])))
}

fn issued(code: &str, issuer: u8) -> IntentAsset {
    IntentAsset::Issued {
        code: code.to_owned(),
        issuer: stellar_strkey::ed25519::PublicKey([issuer; 32])
            .to_string()
            .to_string(),
    }
}

fn context(asset: IntentAsset) -> SacPaymentContext {
    SacPaymentContext::new(Caip2::Testnet, asset).unwrap()
}

fn fixture(context: &SacPaymentContext) -> TransactionV1Envelope {
    crate::approval::fixtures::sac_transfer(context)
}

fn host(envelope: &mut TransactionV1Envelope) -> &mut InvokeHostFunctionOp {
    let OperationBody::InvokeHostFunction(host) = &mut at(&mut envelope.tx.operations, 0).body
    else {
        panic!("fixture operation");
    };
    host
}

fn at<T, const N: u32>(values: &mut VecM<T, N>, index: usize) -> &mut T {
    values.iter_mut().nth(index).unwrap()
}

fn auth(envelope: &mut TransactionV1Envelope) -> &mut SorobanAuthorizationEntry {
    at(&mut host(envelope).auth, 0)
}

fn edit_invoke(envelope: &mut TransactionV1Envelope, edit: impl FnOnce(&mut InvokeContractArgs)) {
    let host = host(envelope);
    let HostFunction::InvokeContract(invoke) = &mut host.host_function else {
        panic!("fixture invocation");
    };
    edit(invoke);
    at(&mut host.auth, 0).root_invocation.function =
        SorobanAuthorizedFunction::ContractFn(invoke.clone());
}

fn data(envelope: &mut TransactionV1Envelope) -> &mut SorobanTransactionData {
    let TransactionExt::V1(data) = &mut envelope.tx.ext else {
        panic!("fixture data")
    };
    data
}

fn verify(
    envelope: &TransactionV1Envelope,
    context: &SacPaymentContext,
) -> Result<VerifiedSacPayment, WalletError> {
    verify_sac_payment(
        &TransactionEnvelope::Tx(envelope.clone())
            .to_xdr_base64(Limits::none())
            .unwrap(),
        context,
    )
}

fn invalid(envelope: &TransactionV1Envelope, context: &SacPaymentContext, case: &str) {
    assert_eq!(
        verify(envelope, context).err().map(|e| e.code()),
        Some(INVALID),
        "{case}"
    );
}

fn validate(
    envelope: &TransactionV1Envelope,
    context: &SacPaymentContext,
    bid: Option<u32>,
    cap: u32,
) -> Result<SacTransferFee, WalletError> {
    validate_sac_payment_data(
        &verify(envelope, context).unwrap(),
        bid,
        ContractTransferFeeLimits {
            total: ContractTransferFeeCap {
                stroops: cap,
                signed: false,
            },
        },
    )
}

fn bad_data(envelope: &TransactionV1Envelope, context: &SacPaymentContext, case: &str) {
    assert_eq!(
        validate(envelope, context, None, u32::MAX)
            .err()
            .map(|e| e.code()),
        Some(FOOTPRINT),
        "{case}"
    );
}

#[test]
fn b1_context_and_closed_errors() {
    for asset in [
        IntentAsset::Native,
        issued("USD", 3),
        issued("LongCode1234", 3),
        issued("usd", 3),
    ] {
        let ctx = context(asset.clone());
        assert_eq!(ctx.asset(), &asset);
        assert_eq!(
            serde_json::from_str::<SacPaymentContext>(&serde_json::to_string(&ctx).unwrap())
                .unwrap(),
            ctx
        );
    }
    let issuer = stellar_strkey::ed25519::PublicKey([3; 32])
        .to_string()
        .to_string();
    for issuer in [
        "Ginvalid".to_owned(),
        issuer.to_lowercase(),
        format!(" {issuer}"),
        stellar_strkey::Contract([3; 32]).to_string().to_string(),
        "\n\u{1b}[31m雪".to_owned(),
    ] {
        let asset = IntentAsset::Issued {
            code: "USD".into(),
            issuer,
        };
        assert_eq!(
            SacPaymentContext::new(Caip2::Testnet, asset.clone())
                .err()
                .map(|e| e.code()),
            Some(INVALID),
            "invalid issuer"
        );
        let raw = serde_json::json!({"chain": "stellar:testnet", "asset": asset});
        assert!(
            serde_json::from_value::<SacPaymentContext>(raw).is_err(),
            "invalid deserialized issuer"
        );
    }
    for code in ["", "USD_", "USD ", "0123456789012", "雪"] {
        assert!(
            SacPaymentContext::new(Caip2::Testnet, issued(code, 3)).is_err(),
            "invalid code"
        );
        assert!(
            serde_json::from_value::<SacPaymentContext>(
                serde_json::json!({"chain":"stellar:testnet", "asset":issued(code, 3)})
            )
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<SacPaymentContext>(
            serde_json::json!({"chain":"stellar:unknown", "asset":"native"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<SacPaymentContext>(
            serde_json::json!({"chain":"stellar:testnet","asset":"native","extra":1})
        )
        .is_err(),
        "unknown context field"
    );
    let cases = [
        (
            SacPaymentError::Unavailable,
            "validation.contract_payment_unavailable",
        ),
        (
            SacPaymentError::WitnessUnavailable,
            "validation.contract_payment_witness_unavailable",
        ),
        (
            SacPaymentError::AssetContractNotDeployed {
                context: context(issued("USD", 3)),
            },
            "validation.asset_contract_not_deployed",
        ),
        (
            SacPaymentError::ArchivedEntry {
                key_sha256: [4; 32],
            },
            "validation.contract_payment_archived_entry",
        ),
        (
            SacPaymentError::MemoUnsupported,
            "validation.contract_payment_memo_unsupported",
        ),
        (
            SacPaymentError::FeeConsentRequired,
            "validation.contract_transfer_fee_cap_required",
        ),
        (
            SacPaymentError::FeeExceeded,
            "validation.contract_transfer_fee_exceeded",
        ),
        (SacPaymentError::Footprint, FOOTPRINT),
        (SacPaymentError::Invalid, INVALID),
        (
            SacPaymentError::SimulationInvalid,
            "validation.contract_payment_simulation_invalid",
        ),
    ];
    for (reason, code) in cases {
        let error = WalletError::from(reason);
        assert_eq!(error.code(), code, "closed code");
        assert!(!error.message().contains('\n'));
        if code == "validation.asset_contract_not_deployed" {
            assert!(error.message().contains(&format!("USD:{issuer}")));
            assert!(error.message().contains("never have been deployed"));
            assert!(error.message().contains("not be restorable"));
            assert!(error.message().contains("not a diagnosis"));
        }
    }
}

#[test]
fn b1_transfer_shape() {
    let ctx = context(IntentAsset::Native);
    let good = fixture(&ctx);
    let mut oversized = good.clone();
    data(&mut oversized).resources.footprint.read_only =
        vec![account_key(1); 60_000].try_into().unwrap();
    invalid(&oversized, &ctx, "bounded valid XDR");
    for signed in [false, true] {
        let mut e = good.clone();
        if signed {
            e.signatures = vec![DecoratedSignature {
                hint: SignatureHint([0; 4]),
                signature: vec![7; 64].try_into().unwrap(),
            }]
            .try_into()
            .unwrap();
        }
        let p = verify(&e, &ctx).unwrap();
        assert_eq!(p.transaction(), &good.tx);
        assert_eq!(p.context(), &ctx);
        assert_eq!(p.invoke().args.len(), 3);
    }
    for text in ["not base64".to_owned(), "A".repeat(2_000_000)] {
        assert_eq!(verify_sac_payment(&text, &ctx).unwrap_err().code(), INVALID);
    }
    for outer in [
        TransactionEnvelope::TxV0(Default::default()),
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: good.tx.source_account.clone(),
                fee: 1,
                inner_tx: FeeBumpTransactionInnerTx::Tx(good.clone()),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        }),
    ] {
        assert_eq!(
            verify_sac_payment(&outer.to_xdr_base64(Limits::none()).unwrap(), &ctx)
                .unwrap_err()
                .code(),
            INVALID
        );
    }
    let mut e = good.clone();
    e.tx.operations = vec![e.tx.operations[0].clone(); 2].try_into().unwrap();
    invalid(&e, &ctx, "two operations");
    e.tx.operations = Default::default();
    invalid(&e, &ctx, "zero operations");
    let mut e = good.clone();
    edit_invoke(&mut e, |i| {
        i.function_name = ScSymbol("approve".try_into().unwrap())
    });
    invalid(&e, &ctx, "wrong function");
    for function in [
        HostFunction::UploadContractWasm(Default::default()),
        HostFunction::CreateContract(Default::default()),
        HostFunction::CreateContractV2(Default::default()),
    ] {
        let mut e = good.clone();
        host(&mut e).host_function = function;
        invalid(&e, &ctx, "not an invocation");
    }
    let mut e = good.clone();
    at(&mut e.tx.operations, 0).body = OperationBody::BumpSequence(BumpSequenceOp {
        bump_to: SequenceNumber(1),
    });
    invalid(&e, &ctx, "not a host function");
    for n in [0, 2, 4] {
        let mut e = good.clone();
        edit_invoke(&mut e, |i| {
            let mut args = i.args.to_vec();
            args.resize(n, ScVal::Void);
            i.args = args.try_into().unwrap();
        });
        invalid(&e, &ctx, "arity");
    }
    for (index, val) in [
        (
            0,
            ScVal::Address(ScAddress::Contract(ContractId(Hash([1; 32])))),
        ),
        (1, ScVal::Address(ScAddress::Account(account(2)))),
        (2, ScVal::I64(1)),
        (1, ScVal::Void),
    ] {
        let mut e = good.clone();
        edit_invoke(&mut e, |i| *at(&mut i.args, index) = val);
        invalid(&e, &ctx, "argument type");
    }
}

#[test]
fn b1_source_binding() {
    let ctx = context(IntentAsset::Native);
    let good = fixture(&ctx);
    let mut e = good.clone();
    e.tx.source_account = MuxedAccount::Ed25519(Uint256([9; 32]));
    invalid(&e, &ctx, "payer mismatch");
    e.tx.source_account = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 0,
        ed25519: Uint256([1; 32]),
    });
    invalid(&e, &ctx, "muxed transaction source");
    for source in [
        MuxedAccount::Ed25519(Uint256([9; 32])),
        MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: 1,
            ed25519: Uint256([1; 32]),
        }),
    ] {
        let mut e = good.clone();
        at(&mut e.tx.operations, 0).source_account = Some(source);
        invalid(&e, &ctx, "operation source mismatch");
    }
    for source in [None, Some(good.tx.source_account.clone())] {
        let mut e = good.clone();
        at(&mut e.tx.operations, 0).source_account = source;
        assert!(verify(&e, &ctx).is_ok());
    }
}

#[test]
fn b1_amount_bounds() {
    let ctx = context(IntentAsset::Native);
    for amount in [1, i128::from(i64::MAX)] {
        let mut e = fixture(&ctx);
        edit_invoke(&mut e, |i| *at(&mut i.args, 2) = ScVal::from(amount));
        assert!(verify(&e, &ctx).is_ok(), "amount {amount}");
    }
    for amount in [0, -1, i128::from(i64::MAX) + 1, i128::MAX, i128::MIN] {
        let mut e = fixture(&ctx);
        edit_invoke(&mut e, |i| *at(&mut i.args, 2) = ScVal::from(amount));
        invalid(&e, &ctx, &format!("amount {amount}"));
    }
}

#[test]
fn b1_asset_and_network_proof() {
    for chain in [Caip2::Testnet, Caip2::Mainnet] {
        for asset in [
            IntentAsset::Native,
            issued("USD", 3),
            issued("LongCode1234", 3),
        ] {
            let ctx = SacPaymentContext::new(chain, asset).unwrap();
            let good = fixture(&ctx);
            let first = verify(&good, &ctx).unwrap();
            assert_eq!(
                verify(&good, &ctx).unwrap().transaction(),
                first.transaction(),
                "repeat success"
            );
            let other_chain = if chain == Caip2::Testnet {
                Caip2::Mainnet
            } else {
                Caip2::Testnet
            };
            invalid(
                &good,
                &SacPaymentContext::new(other_chain, ctx.asset().clone()).unwrap(),
                "wrong network",
            );
            for wrong in [issued("usd", 3), issued("USD", 4)] {
                invalid(
                    &good,
                    &SacPaymentContext::new(chain, wrong).unwrap(),
                    "wrong asset",
                );
            }
            let mut e = good.clone();
            edit_invoke(&mut e, |i| {
                i.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])))
            });
            invalid(&e, &ctx, "custom contract");
            invalid(&e, &ctx, "repeat refusal");
            assert!(verify(&good, &ctx).is_ok(), "success after refusal");
        }
    }
    let ctx = context(IntentAsset::Native);
    assert_eq!(
        crate::sc_address::scaddress_to_strkey(
            &verify(&fixture(&ctx), &ctx)
                .unwrap()
                .invoke()
                .contract_address
        )
        .unwrap(),
        "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"
    );
}

#[test]
fn b1_exact_source_authorization() {
    let ctx = context(IntentAsset::Native);
    let good = fixture(&ctx);
    for n in [0, 2] {
        let mut e = good.clone();
        let auth = host(&mut e).auth[0].clone();
        host(&mut e).auth = vec![auth; n].try_into().unwrap();
        invalid(&e, &ctx, "auth cardinality");
    }
    let mut e = good.clone();
    auth(&mut e).credentials = SorobanCredentials::Address(SorobanAddressCredentials {
        address: ScAddress::Account(account(1)),
        nonce: 0,
        signature_expiration_ledger: 0,
        signature: ScVal::Void,
    });
    invalid(&e, &ctx, "address credentials");
    for field in 0..3 {
        let mut e = good.clone();
        let SorobanAuthorizedFunction::ContractFn(root) =
            &mut auth(&mut e).root_invocation.function
        else {
            panic!("root")
        };
        match field {
            0 => root.contract_address = ScAddress::Contract(ContractId(Hash([9; 32]))),
            1 => {
                *at(&mut root.args, 1) =
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([9; 32]))))
            }
            _ => *at(&mut root.args, 2) = ScVal::from(2_i128),
        }
        invalid(&e, &ctx, "root mismatch");
    }
    let mut e = good.clone();
    let child = host(&mut e).auth[0].root_invocation.clone();
    auth(&mut e).root_invocation.sub_invocations = vec![child].try_into().unwrap();
    invalid(&e, &ctx, "child invocation");
    assert!(verify(&good, &ctx).is_ok());
}

#[test]
fn b1_memo_refusal() {
    let ctx = context(IntentAsset::Native);
    assert!(verify(&fixture(&ctx), &ctx).is_ok());
    for memo in [
        Memo::Text("invoice".try_into().unwrap()),
        Memo::Id(7),
        Memo::Hash(Hash([3; 32])),
        Memo::Return(Hash([4; 32])),
    ] {
        let mut e = fixture(&ctx);
        e.tx.memo = memo;
        let error = verify(&e, &ctx).err();
        assert_eq!(
            error.as_ref().map(WalletError::code),
            Some("validation.contract_payment_memo_unsupported"),
            "memo code"
        );
        assert_eq!(
            error.unwrap().message(),
            "The network rejects a memo on a contract invocation. Use a W address to carry an id on a network at protocol 30 or later. W payments are not available in this implementation."
        );
    }
}

fn account_key(byte: u8) -> LedgerKey {
    LedgerKey::Account(LedgerKeyAccount {
        account_id: account(byte),
    })
}

fn contract_keys(envelope: &mut TransactionV1Envelope) -> (LedgerKey, LedgerKey) {
    let HostFunction::InvokeContract(i) = &host(envelope).host_function else {
        panic!("invoke")
    };
    let contract = i.contract_address.clone();
    let make = |key| {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: contract.clone(),
            key,
            durability: ContractDataDurability::Persistent,
        })
    };
    (
        make(ScVal::LedgerKeyContractInstance),
        make(ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Balance".try_into().unwrap())),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([2; 32])))),
            ]
            .try_into()
            .unwrap(),
        )))),
    )
}

fn trustline(code: &str, issuer: u8, payer: u8) -> LedgerKey {
    let asset = if code.len() <= 4 {
        let mut bytes = [0; 4];
        bytes[..code.len()].copy_from_slice(code.as_bytes());
        TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(bytes),
            issuer: account(issuer),
        })
    } else {
        let mut bytes = [0; 12];
        bytes[..code.len()].copy_from_slice(code.as_bytes());
        TrustLineAsset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(bytes),
            issuer: account(issuer),
        })
    };
    LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: account(payer),
        asset,
    })
}

/// The payer's (key `[1; 32]`) trustline for an asset of issuer `[3; 32]`,
/// as literal `LedgerKey` XDR computed outside this crate.
fn pinned_trustline(code: &str) -> LedgerKey {
    let xdr = match code {
        "USD" => {
            "AAAAAQAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAFVU0QAAAAAAAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD"
        }
        "LongCode1234" => {
            "AAAAAQAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAJMb25nQ29kZTEyMzQAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
        }
        other => panic!("no pinned trustline for {other}"),
    };
    LedgerKey::from_xdr_base64(xdr, Limits::none()).unwrap()
}

fn footprint(envelope: &mut TransactionV1Envelope, ro: Vec<LedgerKey>, rw: Vec<LedgerKey>) {
    data(envelope).resources.footprint = LedgerFootprint {
        read_only: ro.try_into().unwrap(),
        read_write: rw.try_into().unwrap(),
    };
}

#[test]
fn b1_forward_footprint() {
    for asset in [
        IntentAsset::Native,
        issued("USD", 3),
        issued("LongCode1234", 3),
        issued("USD", 1),
    ] {
        let ctx = context(asset.clone());
        let mut good = fixture(&ctx);
        let (instance, balance) = contract_keys(&mut good);
        assert!(
            validate(&good, &ctx, None, u32::MAX).is_ok(),
            "optional empty footprint"
        );
        let mut ro = vec![instance.clone()];
        let mut rw = vec![account_key(1), balance.clone()];
        if let IntentAsset::Issued { code, issuer } = &asset {
            if issuer
                == &stellar_strkey::ed25519::PublicKey([1; 32])
                    .to_string()
                    .to_string()
            {
                let mut e = good.clone();
                footprint(
                    &mut e,
                    vec![instance.clone(), account_key(1)],
                    vec![balance.clone()],
                );
                assert!(
                    validate(&e, &ctx, None, u32::MAX).is_ok(),
                    "issuer payer RO"
                );
                footprint(
                    &mut e,
                    vec![instance.clone()],
                    vec![account_key(1), balance.clone()],
                );
                assert!(
                    validate(&e, &ctx, None, u32::MAX).is_ok(),
                    "issuer payer RW"
                );
                footprint(&mut e, vec![], vec![trustline(code, 1, 1)]);
                bad_data(&e, &ctx, "issuer trustline");
            } else {
                ro.push(account_key(3));
                rw.push(pinned_trustline(code));
            }
        }
        footprint(&mut good, ro.clone(), rw.clone());
        assert!(
            validate(&good, &ctx, None, u32::MAX).is_ok(),
            "valid forward keys"
        );
        for key in ro.iter().chain(&rw) {
            let mut e = good.clone();
            let mut duplicate = ro.clone();
            duplicate.push(key.clone());
            footprint(&mut e, duplicate, rw.clone());
            bad_data(&e, &ctx, "duplicate or cross-list key");
            let mut e = good.clone();
            let mut duplicate = rw.clone();
            duplicate.push(key.clone());
            footprint(&mut e, ro.clone(), duplicate);
            bad_data(&e, &ctx, "RW duplicate or cross-list key");
        }
        let mut foreign = vec![
            account_key(9),
            trustline("EUR", 3, 1),
            trustline("USD", 9, 1),
            trustline("USD", 3, 9),
            LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: Hash([9; 32]),
            }),
        ];
        for key in [&instance, &balance] {
            let LedgerKey::ContractData(original) = key else {
                panic!("contract data")
            };
            let mut changed = original.clone();
            changed.contract = ScAddress::Contract(ContractId(Hash([9; 32])));
            foreign.push(LedgerKey::ContractData(changed));
            let mut changed = original.clone();
            changed.durability = ContractDataDurability::Temporary;
            foreign.push(LedgerKey::ContractData(changed));
        }
        let LedgerKey::ContractData(mut changed) = balance.clone() else {
            panic!("balance")
        };
        changed.key = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol("Balance".try_into().unwrap())),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([9; 32])))),
            ]
            .try_into()
            .unwrap(),
        )));
        foreign.push(LedgerKey::ContractData(changed));
        for key in foreign {
            for read_only in [true, false] {
                let mut e = fixture(&ctx);
                footprint(
                    &mut e,
                    if read_only { vec![key.clone()] } else { vec![] },
                    if read_only { vec![] } else { vec![key.clone()] },
                );
                bad_data(
                    &e,
                    &ctx,
                    if read_only {
                        "foreign RO"
                    } else {
                        "foreign RW"
                    },
                );
            }
        }
        let mut e = fixture(&ctx);
        footprint(&mut e, vec![balance], vec![]);
        bad_data(&e, &ctx, "balance RO");
        if asset != issued("USD", 1) {
            footprint(&mut e, vec![account_key(1)], vec![]);
            bad_data(&e, &ctx, "payer RO");
        }
        if asset == issued("USD", 3) {
            footprint(&mut e, vec![], vec![account_key(3)]);
            bad_data(&e, &ctx, "issuer RW");
        }
    }
}

fn indices(envelope: &mut TransactionV1Envelope, values: &[u32]) {
    data(envelope).ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: values.to_vec().try_into().unwrap(),
    });
}

#[test]
fn b1_atomic_restoration_indices() {
    for asset in [IntentAsset::Native, issued("USD", 3)] {
        let ctx = context(asset);
        let mut e = fixture(&ctx);
        let (instance, balance) = contract_keys(&mut e);
        for (rw, restored) in [
            (vec![balance.clone()], vec![0]),
            (vec![instance.clone()], vec![0]),
            (vec![balance.clone(), instance.clone()], vec![0, 1]),
            (vec![instance.clone(), balance.clone()], vec![0, 1]),
        ] {
            footprint(&mut e, vec![], rw);
            indices(&mut e, &restored);
            let before = e.clone();
            let payment = verify(&e, &ctx).unwrap();
            assert!(
                validate_sac_payment_data(
                    &payment,
                    None,
                    ContractTransferFeeLimits {
                        total: ContractTransferFeeCap {
                            stroops: u32::MAX,
                            signed: true
                        }
                    }
                )
                .is_ok(),
                "valid restoration"
            );
            assert_eq!(payment.transaction(), &before.tx, "order preserved");
        }
        footprint(&mut e, vec![], vec![instance.clone(), balance.clone()]);
        for restored in [
            vec![1, 0],
            vec![0, 0],
            vec![0, 2],
            vec![0, u32::MAX],
            vec![1],
            vec![],
        ] {
            indices(&mut e, &restored);
            bad_data(&e, &ctx, &format!("indices {restored:?}"));
        }
        data(&mut e).ext = SorobanTransactionDataExt::V0;
        bad_data(&e, &ctx, "unindexed RW instance V0");
        for key in [account_key(1), trustline("USD", 3, 1), account_key(9)] {
            footprint(&mut e, vec![], vec![key]);
            indices(&mut e, &[0]);
            bad_data(&e, &ctx, "nonrestorable key index");
        }
        footprint(&mut e, vec![instance], vec![balance]);
        indices(&mut e, &[]);
        assert!(
            validate(&e, &ctx, None, u32::MAX).is_ok(),
            "live balance needs no index"
        );
    }
}

#[test]
fn b1_total_fee_and_inclusion() {
    let ctx = context(IntentAsset::Native);
    let good = fixture(&ctx);
    assert!(
        validate(&good, &ctx, Some(100), 500_100).is_ok(),
        "high resource fee inside total cap"
    );
    assert_eq!(
        validate(&good, &ctx, Some(100), 500_100).unwrap(),
        SacTransferFee {
            total_stroops: 500_100,
            inclusion_bid_stroops: 100,
            resource_stroops: 500_000
        },
        "high resource fee inside total cap"
    );
    for resource in [-1, i64::from(u32::MAX) + 1, 500_101] {
        let mut e = good.clone();
        data(&mut e).resource_fee = resource;
        assert_eq!(
            validate(&e, &ctx, None, u32::MAX).err().map(|e| e.code()),
            Some(INVALID),
            "resource {resource}"
        );
    }
    assert_eq!(
        validate(&good, &ctx, Some(99), u32::MAX)
            .err()
            .map(|e| e.code()),
        Some(INVALID),
        "explicit inclusion mismatch"
    );
    assert_eq!(
        validate(&good, &ctx, None, 500_099).err().map(|e| e.code()),
        Some("validation.contract_transfer_fee_exceeded"),
        "total cap plus one"
    );
    assert_eq!(
        validate(&good, &ctx, None, 0).unwrap_err().code(),
        "validation.contract_transfer_fee_exceeded"
    );
    for (total, resource, inclusion) in [
        (0, 0, 0),
        (u32::MAX, i64::from(u32::MAX), 0),
        (u32::MAX, 0, u32::MAX),
    ] {
        let mut e = good.clone();
        e.tx.fee = total;
        data(&mut e).resource_fee = resource;
        assert_eq!(
            validate(&e, &ctx, Some(inclusion), total).unwrap(),
            SacTransferFee {
                total_stroops: total,
                inclusion_bid_stroops: inclusion,
                resource_stroops: resource as u32
            }
        );
    }
    let mut e = good;
    e.tx.ext = TransactionExt::V0;
    assert_eq!(
        validate(&e, &ctx, None, u32::MAX).unwrap_err().code(),
        INVALID
    );
}

fn b64(envelope: &TransactionV1Envelope) -> String {
    TransactionEnvelope::Tx(envelope.clone())
        .to_xdr_base64(Limits::none())
        .unwrap()
}

/// A classic envelope from payer `[1; 32]` with the single operation `body`.
fn classic(body: OperationBody) -> String {
    let mut envelope = fixture(&context(IntentAsset::Native));
    envelope.tx.operations = vec![Operation {
        source_account: None,
        body,
    }]
    .try_into()
    .unwrap();
    envelope.tx.ext = TransactionExt::V0;
    b64(&envelope)
}

const PAYER: &str = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
const RECIPIENT: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";

#[test]
fn b1_contextual_policy_facts() {
    use crate::envelope_decode::{
        ClassicMemo, ClassicOperation, decode_authoritative_args, decode_pay_args_with_context,
    };
    let native = context(IntentAsset::Native);
    let good = fixture(&native);
    let args = decode_pay_args_with_context(&b64(&good), Some(&native)).unwrap();
    assert_eq!(
        args,
        serde_json::json!({
            "source": PAYER,
            "total_fee_stroops": 500_100,
            "destination": RECIPIENT,
            "amount_stroops": "1",
            "asset": "XLM",
            "sequence_number": 77,
            "memo_kind": "none",
            "memo": null,
        }),
        "authoritative facts"
    );
    let payment = verify(&good, &native).unwrap();
    assert_eq!(payment.policy_args(), args);
    let summary = payment.summary();
    assert_eq!(
        (
            summary.source.as_str(),
            summary.fee_stroops,
            summary.seq_num
        ),
        (PAYER, 500_100, 77)
    );
    assert_eq!(summary.memo, ClassicMemo::None);
    assert_eq!(
        summary.operation,
        ClassicOperation::SacTransfer {
            destination: RECIPIENT.to_owned(),
            asset: "XLM".to_owned(),
            amount_stroops: 1,
            inclusion_fee_stroops: Some(100),
            resource_fee_stroops: Some(500_000),
        },
        "summary"
    );
    let usd = context(issued("USD", 3));
    let issued_args = decode_pay_args_with_context(&b64(&fixture(&usd)), Some(&usd)).unwrap();
    assert_eq!(
        issued_args["asset"],
        format!(
            "USD:{}",
            "GABQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQHGPC"
        )
    );
    assert_eq!(
        verify(&good, &native).unwrap().intent_payload(Some(7)),
        crate::approval::IntentPayload::ContractPay {
            destination: RECIPIENT.to_owned(),
            asset: IntentAsset::Native,
            amount_stroops: 1,
            explicit_inclusion_bid_stroops: Some(7),
        },
        "intent payload"
    );

    let mut custom = good.clone();
    edit_invoke(&mut custom, |i| {
        i.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])))
    });
    for (envelope, context, case) in [
        (&good, Some(&usd), "wrong asset context"),
        (&good, None, "missing context"),
        (&custom, Some(&native), "custom token"),
        (&custom, None, "custom token without context"),
    ] {
        assert_eq!(
            decode_pay_args_with_context(&b64(envelope), context)
                .unwrap_err()
                .code(),
            INVALID,
            "{case}"
        );
    }
    let mut memo = good.clone();
    memo.tx.memo = Memo::Id(7);
    assert_eq!(
        decode_pay_args_with_context(&b64(&memo), None)
            .unwrap_err()
            .code(),
        INVALID,
        "memo transfer without context"
    );

    let payment_op = OperationBody::Payment(PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256([2; 32])),
        asset: Asset::Native,
        amount: 5,
    });
    let classic_payment = classic(payment_op);
    assert_eq!(
        decode_pay_args_with_context(&classic_payment, None).unwrap(),
        decode_authoritative_args(&classic_payment, "stellar_pay_commit").unwrap(),
        "classic decoding without context"
    );
    assert_eq!(
        decode_pay_args_with_context(&classic_payment, Some(&native))
            .unwrap_err()
            .code(),
        INVALID,
        "classic payment with context"
    );
    let create = classic(OperationBody::CreateAccount(CreateAccountOp {
        destination: account(2),
        starting_balance: 5,
    }));
    assert_eq!(
        decode_pay_args_with_context(&create, None)
            .unwrap_err()
            .code(),
        "protocol.xdr_codec_failed",
        "other operations stay classic decode failures"
    );
}

const POLICY_NOW_MS: u64 = 1_700_000_000_000;

#[test]
fn contract_summary_wire_facts() {
    use crate::approval::{ClassicIntent, IntentBase, IntentView, MemoFact};
    let entry = crate::approval::fixtures::sac_payment_pending(Caip2::Testnet, IntentAsset::Native);
    let dir = tempfile::TempDir::new().unwrap();
    let mut store =
        crate::approval::PendingApprovalStore::open(dir.path().join("contract.toml")).unwrap();
    store
        .insert(entry.clone(), entry.created_at_unix_ms)
        .unwrap();
    let view = store.snapshot(entry.created_at_unix_ms).remove(0);
    let wire = serde_json::to_value(&view.summary).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({
            "kind": "payment", "source": PAYER, "to": RECIPIENT, "amount_stroops": "1",
            "asset": "XLM", "memo": {"kind": "none"}, "fee_stroops": "500100", "seq_num": 77,
            "inclusion_fee_stroops": "100", "resource_fee_stroops": "500000"
        }),
        "contract summary JSON"
    );
    let native = context(IntentAsset::Native);
    let payment = verify(&fixture(&native), &native).unwrap();
    let base = IntentBase::new(
        "stellar:testnet".into(),
        PAYER.into(),
        [0x11; 32],
        1_000_000,
        MemoFact::None,
    )
    .unwrap();
    let intent = ClassicIntent::new(base, payment.intent_payload(Some(100))).unwrap();
    let wire = serde_json::to_value(IntentView::new(&intent)).unwrap();
    assert_eq!(wire["fee_at_most_stroops"], "1000000", "intent cap");
    assert_eq!(wire["kind"], "contract_pay");
    assert_eq!(wire["destination"], RECIPIENT);
    assert_eq!(wire["explicit_inclusion_bid_stroops"], "100");
    for fee in [-1, 500_101, i64::MAX, i64::from(u32::MAX) + 1] {
        let mut envelope = fixture(&native);
        data(&mut envelope).resource_fee = fee;
        let summary = verify(&envelope, &native).unwrap().summary();
        assert!(
            matches!(
                summary.operation,
                crate::envelope_decode::ClassicOperation::SacTransfer {
                    inclusion_fee_stroops: None,
                    resource_fee_stroops: None,
                    ..
                }
            ),
            "invalid fee split {fee}"
        );
    }
    let mut missing = fixture(&native);
    missing.tx.ext = TransactionExt::V0;
    assert!(
        matches!(
            verify(&missing, &native).unwrap().summary().operation,
            crate::envelope_decode::ClassicOperation::SacTransfer {
                inclusion_fee_stroops: None,
                resource_fee_stroops: None,
                ..
            }
        ),
        "missing resource data supplies no split"
    );
}

struct ObservedBalance(i64);

impl crate::policy::v1::AccountReservesView for ObservedBalance {
    fn reserves_stroops(&self, base_reserve_stroops: i64) -> i64 {
        2 * base_reserve_stroops
    }

    fn balance_stroops(&self) -> Result<i64, crate::policy::v1::AccountReserveLookupError> {
        Ok(self.0)
    }

    fn observation(&self) -> Option<crate::policy::v1::AccountObservation> {
        Some(crate::policy::v1::AccountObservation {
            ledger_sequence: 1,
            observed_at_ms: POLICY_NOW_MS,
            close_time_floor_ms: POLICY_NOW_MS,
        })
    }

    fn effective_native_reservations_stroops(&self) -> Option<u64> {
        Some(0)
    }
}

/// The decision of a signed testnet `stellar_pay_commit` rule with one
/// criterion over `args`, for a payer with `balance` stroops.
fn decide(criterion: &str, args: &serde_json::Value, balance: i64) -> crate::policy::Decision {
    use crate::policy::v1::{
        PolicyEngineV1, canonical::canonical_bytes, loader::load_signed_policy_text, signature,
        value::derive_value_class,
    };
    use crate::policy::{PolicyEngine, ToolDescriptor, ToolValueKind};
    let body = format!(
        "version = 2\nsequence = 1\nscope = \"profile:sac-test\"\n[[rules]]\nmatch = {{ tool = \"stellar_pay_commit\", chain = \"stellar:testnet\" }}\ncriteria = [{criterion}]\ndecision = \"allow\"\n"
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let digest = signature::digest(&canonical_bytes(&body).unwrap());
    let sig = crate::hex::encode(&signature::sign(&digest, &key));
    let signed = format!("{body}\n[signature]\nowner_id = \"sac-test\"\nsig = \"{sig}\"\n");
    let doc = load_signed_policy_text(
        &signed,
        "sac-test",
        &key.verifying_key().to_bytes(),
        crate::profile::caip2::TESTNET_PASSPHRASE,
    )
    .unwrap();
    let tool = ToolDescriptor {
        name: "stellar_pay_commit".into(),
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        chain_id: "stellar:testnet".into(),
        value_kind: ToolValueKind::MovesValue,
    };
    let profile =
        crate::profile::schema::Profile::builder_testnet("sac-test", "acct", "n-svc", "n-acct")
            .build();
    PolicyEngineV1::new(doc, "sac-test".into())
        .evaluate_with_value_full(
            &tool,
            args,
            &profile,
            derive_value_class("stellar_pay_commit", args),
            Some(&ObservedBalance(balance)),
            None,
            None,
            None,
            None,
            POLICY_NOW_MS,
        )
        .unwrap()
        .decision
}

/// Verified contract payment facts reach the existing payment criteria: the
/// C recipient is an address alternative, carries no home domain, and the
/// whole transaction fee counts against the floor.
#[test]
#[serial_test::serial]
fn b1_contextual_policy_decisions() {
    use crate::policy::Decision;
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let native = context(IntentAsset::Native);
    let args = verify(&fixture(&native), &native).unwrap().policy_args();
    let rich = 1_000_000_000;
    let g_only = format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\"], allowlist = [\"{PAYER}\"] }}"
    );
    assert!(
        matches!(decide(&g_only, &args, rich), Decision::Deny(_)),
        "G-only list"
    );
    let mixed = format!(
        "{{ kind = \"counterparty_allowlist\", kinds = [\"G_ACCOUNT\", \"C_ACCOUNT\"], allowlist = [\"{PAYER}\", \"{RECIPIENT}\"] }}"
    );
    assert_eq!(decide(&mixed, &args, rich), Decision::Allow, "mixed list");
    let home = "{ kind = \"counterparty_allowlist\", kinds = [\"HOME_DOMAIN\"], allowlist = [\"example.com\"] }";
    assert!(
        matches!(decide(home, &args, rich), Decision::Deny(_)),
        "home domain"
    );
    // Amount 1 plus the whole 500,100 stroop fee leaves exactly the floor.
    let floor = "{ kind = \"balance_floor\", min_stroops = \"10000000\" }";
    let exact = 10_000_000 + 1 + 500_100;
    assert_eq!(
        decide(floor, &args, exact),
        Decision::Allow,
        "floor equality"
    );
    assert!(
        matches!(decide(floor, &args, exact - 1), Decision::Deny(_)),
        "full fee crosses the floor"
    );
    let reserve = "{ kind = \"minimum_reserve\", margin_stroops = 0 }";
    assert_eq!(
        decide(reserve, &args, exact),
        Decision::Allow,
        "reserve equality"
    );
    assert!(
        matches!(decide(reserve, &args, exact - 1), Decision::Deny(_)),
        "full fee crosses reserve"
    );
}

/// A contract payment record shows only its verified envelope facts: any
/// stored fact, context, digest or envelope that disagrees refuses.
#[test]
fn b1_contextual_reopen_refuses_tampering() {
    use crate::approval::{ApprovalKind, attest::classic_entry_summary};
    let native = context(IntentAsset::Native);
    let entry = crate::approval::fixtures::sac_payment_pending(Caip2::Testnet, IntentAsset::Native);
    assert_eq!(
        classic_entry_summary(&entry.kind).unwrap().unwrap(),
        verify(&fixture(&native), &native).unwrap().summary(),
        "valid reopen"
    );
    let mut bounded = fixture(&native);
    bounded.tx.cond = Preconditions::Time(TimeBounds {
        min_time: TimePoint(0),
        max_time: TimePoint(1),
    });
    for case in [
        "context",
        "context chain",
        "digest",
        "envelope",
        "destination",
        "amount",
        "asset",
        "memo",
        "fee",
        "sequence",
    ] {
        let mut kind = entry.kind.clone();
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            summary_to,
            summary_amount_stroops,
            summary_asset,
            summary_memo,
            summary_simulated_fee_stroops,
            summary_simulated_seq_num,
            sac_payment_context,
        } = &mut kind
        else {
            panic!("payment fixture")
        };
        match case {
            "context" => *sac_payment_context = Some(context(issued("USD", 3))),
            "context chain" => {
                *sac_payment_context =
                    Some(SacPaymentContext::new(Caip2::Mainnet, IntentAsset::Native).unwrap())
            }
            "digest" => *envelope_sha256_hex = "00".repeat(32),
            "envelope" => *envelope_xdr_b64 = b64(&bounded),
            "destination" => *summary_to = format!("{}", stellar_strkey::Contract([5; 32])),
            "amount" => *summary_amount_stroops = 2,
            "asset" => *summary_asset = format!("USD:{PAYER}"),
            "memo" => *summary_memo = Some("note".to_owned()),
            "fee" => *summary_simulated_fee_stroops = 100,
            _ => *summary_simulated_seq_num = 78,
        }
        assert_eq!(
            classic_entry_summary(&kind)
                .unwrap()
                .err()
                .map(|error| error.code()),
            Some("approval.entry_inconsistent"),
            "{case}"
        );
    }
}

#[test]
fn payment_surfaces_refuse_contract_payments() {
    const UNAVAILABLE: &str = "validation.contract_payment_unavailable";
    const MEMO: &str = "validation.contract_payment_memo_unsupported";
    let destination = |text: &str, memo| refuse_contract_destination(text, memo).err();
    assert_eq!(
        destination(RECIPIENT, false),
        Some(SacPaymentError::Unavailable),
        "C"
    );
    assert_eq!(
        destination(RECIPIENT, true),
        Some(SacPaymentError::MemoUnsupported),
        "C memo"
    );
    for other in [PAYER, &RECIPIENT.to_lowercase(), "", "W"] {
        assert_eq!(
            destination(other, true),
            None,
            "{other:?} keeps its own checks"
        );
    }
    let transfer = |envelope: &str, context: Option<&SacPaymentContext>| {
        refuse_contract_transfer(envelope, context)
            .err()
            .map(|reason| reason.code())
    };
    for asset in [IntentAsset::Native, issued("USD", 7)] {
        let ctx = context(asset);
        assert_eq!(
            transfer(&b64(&fixture(&ctx)), Some(&ctx)),
            Some(UNAVAILABLE),
            "verified"
        );
        assert_eq!(
            transfer(&b64(&fixture(&ctx)), None),
            Some(INVALID),
            "no context"
        );
        let mut memo = fixture(&ctx);
        memo.tx.memo = Memo::Id(1);
        assert_eq!(transfer(&b64(&memo), Some(&ctx)), Some(MEMO), "memo");
    }
    let native = context(IntentAsset::Native);
    let usd = context(issued("USD", 7));
    assert_eq!(
        transfer(&b64(&fixture(&native)), Some(&usd)),
        Some(INVALID),
        "wrong asset"
    );
    let mut custom = fixture(&native);
    edit_invoke(&mut custom, |invoke| {
        invoke.contract_address = ScAddress::Contract(ContractId(Hash([9; 32])));
    });
    assert_eq!(
        transfer(&b64(&custom), Some(&native)),
        Some(INVALID),
        "custom token"
    );
    let payment = classic(OperationBody::Payment(PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256([2; 32])),
        asset: Asset::Native,
        amount: 5,
    }));
    assert_eq!(
        transfer(&payment, Some(&native)),
        None,
        "classic payment passes"
    );
    assert_eq!(
        transfer("not xdr", None),
        None,
        "undecodable keeps its classic error"
    );
}

#[test]
fn muxed_contract_destination_is_refused() {
    let zero = format!(
        "{}",
        stellar_strkey::MuxedContract {
            contract_id: [2; 32],
            id: 0,
        }
    );
    let max = format!(
        "{}",
        stellar_strkey::MuxedContract {
            contract_id: [2; 32],
            id: u64::MAX,
        }
    );
    for address in [&zero, &max] {
        assert_eq!(
            refuse_contract_destination(address, false),
            Err(SacPaymentError::Unavailable),
            "{address} without memo"
        );
        assert_eq!(
            refuse_contract_destination(address, true),
            Err(SacPaymentError::MemoUnsupported),
            "{address} with memo"
        );
    }
    let mut bad_checksum = zero.clone();
    let replacement = if bad_checksum.ends_with('A') {
        'B'
    } else {
        'A'
    };
    bad_checksum.pop();
    bad_checksum.push(replacement);
    for other in [zero.to_lowercase(), bad_checksum, "W".to_owned()] {
        assert_eq!(
            refuse_contract_destination(&other, true),
            Ok(()),
            "{other:?} keeps its own checks"
        );
    }
}
