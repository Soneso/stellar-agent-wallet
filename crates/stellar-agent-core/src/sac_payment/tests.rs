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
    let asset = match context.asset() {
        IntentAsset::Native => CanonicalAsset::Native,
        IntentAsset::Issued { code, issuer } => CanonicalAsset::classic(code, issuer).unwrap(),
    };
    let contract = stellar_strkey::Contract::from_string(
        &asset
            .sac_contract_id(context.chain().network_passphrase())
            .unwrap(),
    )
    .unwrap();
    let invoke = InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
        function_name: ScSymbol("transfer".try_into().unwrap()),
        args: vec![
            ScVal::Address(ScAddress::Account(account(1))),
            ScVal::Address(ScAddress::Contract(ContractId(Hash([2; 32])))),
            ScVal::from(1_i128),
        ]
        .try_into()
        .unwrap(),
    };
    let auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
            sub_invocations: Default::default(),
        },
    };
    TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([1; 32])),
            fee: 500_100,
            seq_num: SequenceNumber(77),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(invoke),
                    auth: vec![auth].try_into().unwrap(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V1(SorobanTransactionData {
                resource_fee: 500_000,
                ..Default::default()
            }),
        },
        signatures: Default::default(),
    }
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
                rw.push(trustline(code, 3, 1));
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
