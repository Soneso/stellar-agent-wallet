#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures and assertions"
)]

use super::*;
use crate::fees::{FeeDistribution, FeePercentile};
use serde_json::{Value, json};
use std::cell::RefCell;
use stellar_agent_core::approval::{IntentBase, fixtures::sac_transfer};
use stellar_agent_core::profile::caip2::Caip2;

const INVALID: &str = "validation.contract_payment_invalid";
const SIMULATION: &str = "validation.contract_payment_simulation_invalid";
const FOOTPRINT: &str = "validation.contract_payment_footprint";
const CAP: &str = "validation.contract_transfer_fee_exceeded";

fn xdr(value: &impl WriteXdr) -> String {
    value.to_xdr_base64(Limits::none()).unwrap()
}

fn issued(issuer: u8) -> IntentAsset {
    IntentAsset::Issued {
        code: "USD".into(),
        issuer: stellar_strkey::ed25519::PublicKey([issuer; 32])
            .to_string()
            .to_string(),
    }
}

fn long_asset() -> IntentAsset {
    IntentAsset::Issued {
        code: "LongCode1234".into(),
        issuer: stellar_strkey::ed25519::PublicKey([3; 32])
            .to_string()
            .to_string(),
    }
}

struct Fixture {
    context: SacPaymentContext,
    intent: ClassicIntent,
    invoke: InvokeContractArgs,
    auth: SorobanAuthorizationEntry,
    data: SorobanTransactionData,
}

impl Fixture {
    fn new(asset: IntentAsset, bid: Option<u32>, cap: u32) -> Self {
        let context = SacPaymentContext::new(Caip2::Testnet, asset).unwrap();
        let env = sac_transfer(&context);
        let payment =
            verify_sac_payment(&xdr(&TransactionEnvelope::Tx(env.clone())), &context).unwrap();
        let base = crate::operation_entry::contract_pay_base(
            Caip2::Testnet,
            &stellar_strkey::ed25519::PublicKey([1; 32]).to_string(),
            [7; 32],
            MemoFact::None,
            stellar_agent_core::sac_payment::ContractTransferFeeCap {
                stroops: cap,
                signed: false,
            },
        )
        .unwrap();
        let intent = ClassicIntent::new(base, payment.intent_payload(bid)).unwrap();
        let OperationBody::InvokeHostFunction(host) = &env.tx.operations[0].body else {
            panic!("host")
        };
        let TransactionExt::V1(data) = env.tx.ext else {
            panic!("data")
        };
        Self {
            context,
            intent,
            invoke: payment.invoke().clone(),
            auth: host.auth[0].clone(),
            data,
        }
    }

    fn request(&self) -> SacPaymentBuildRequest<'_> {
        let IntentPayload::ContractPay {
            explicit_inclusion_bid_stroops,
            ..
        } = self.intent.payload()
        else {
            panic!("intent")
        };
        SacPaymentBuildRequest {
            intent: &self.intent,
            context: &self.context,
            sequence: 77,
            conditions: Preconditions::None,
            fee_choice: explicit_inclusion_bid_stroops
                .map_or(ClassicFeeChoice::ProfileDefault, ClassicFeeChoice::Explicit),
            default_inclusion_bid: 100,
            policy: None,
        }
    }

    fn response(&self) -> Value {
        json!({"latestLedger": 1000, "minResourceFee": self.data.resource_fee.max(0).to_string(),
            "transactionData": xdr(&self.data), "results": [{"xdr": xdr(&ScVal::Void), "auth": [xdr(&self.auth)]}]})
    }

    fn instance(&self) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: self.invoke.contract_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        })
    }

    fn balance(&self) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: self.invoke.contract_address.clone(),
            key: ScVal::Vec(Some(ScVec(
                vec![
                    ScVal::Symbol(ScSymbol("Balance".try_into().unwrap())),
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([2; 32])))),
                ]
                .try_into()
                .unwrap(),
            ))),
            durability: ContractDataDurability::Persistent,
        })
    }

    fn entries(&self) -> Value {
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: self.invoke.contract_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                storage: None,
            }),
        });
        json!({"latestLedger": 1000, "entries": [{"key": xdr(&self.instance()), "xdr": xdr(&data), "lastModifiedLedgerSeq": 999, "liveUntilLedgerSeq": 2000}]})
    }

    fn rpc(&self) -> FakeRpc {
        FakeRpc {
            entries: self.entries(),
            response: self.response(),
            fail: "",
            calls: RefCell::new(vec![]),
            envelopes: RefCell::new(vec![]),
            keys: RefCell::new(vec![]),
            soroban: 777,
        }
    }
}

struct FakeRpc {
    entries: Value,
    response: Value,
    fail: &'static str,
    calls: RefCell<Vec<&'static str>>,
    envelopes: RefCell<Vec<TransactionEnvelope>>,
    keys: RefCell<Vec<LedgerKey>>,
    soroban: u64,
}

impl FakeRpc {
    fn call(&self, name: &'static str) -> Result<(), NetworkError> {
        self.calls.borrow_mut().push(name);
        if self.fail == name {
            return Err(NetworkError::RpcUnreachable {
                url: "https://rpc.example".into(),
                reason: name.into(),
            });
        }
        Ok(())
    }
}

impl SacRpc for FakeRpc {
    async fn entries(&self, keys: &[LedgerKey]) -> Result<GetLedgerEntriesResponse, NetworkError> {
        self.call("entries")?;
        self.keys.borrow_mut().extend_from_slice(keys);
        Ok(serde_json::from_value(self.entries.clone()).unwrap())
    }
    async fn stats(&self) -> Result<FeeStatsView, NetworkError> {
        self.call("stats")?;
        let distribution = |n| FeeDistribution {
            max: n,
            min: n,
            mode: n,
            p10: n + 10,
            p20: n + 20,
            p30: n + 30,
            p40: n + 40,
            p50: n + 50,
            p60: n + 60,
            p70: n + 70,
            p80: n + 80,
            p90: n + 90,
            p95: n + 95,
            p99: n + 99,
            transaction_count: 1,
            ledger_count: 1,
        };
        Ok(FeeStatsView {
            inclusion_fee: distribution(123),
            soroban_inclusion_fee: distribution(self.soroban),
            latest_ledger: 1000,
        })
    }
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, NetworkError> {
        self.call("simulate")?;
        self.envelopes.borrow_mut().push(envelope.clone());
        let mut response = self.response.clone();
        let TransactionEnvelope::Tx(tx) = envelope else {
            panic!("simulation envelope")
        };
        let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
            panic!("simulation operation")
        };
        if !op.auth.is_empty() {
            response["results"][0]["auth"] = json!([]);
        }
        Ok(serde_json::from_value(response).unwrap())
    }
}

#[tokio::test]
async fn sac_build_terms_and_local_authorization() {
    for asset in [IntentAsset::Native, issued(3), issued(1), long_asset()] {
        let f = Fixture::new(asset, Some(100), 500_100);
        let rpc = f.rpc();
        let prepared = prepare_with(&rpc, &f.request()).await.unwrap();
        assert_eq!(
            prepared.envelope_xdr,
            xdr(&TransactionEnvelope::Tx(sac_transfer(&f.context)))
        );
        assert_eq!(prepared.payment.transaction().seq_num.0, 77);
        assert_eq!(prepared.payment.invoke(), &f.invoke);
        assert_eq!(prepared.intent, f.intent);
        assert_eq!(
            prepared.fee,
            SacTransferFee {
                total_stroops: 500_100,
                inclusion_bid_stroops: 100,
                resource_stroops: 500_000
            }
        );
        assert_eq!(*rpc.calls.borrow(), ["entries", "simulate"]);
        assert_eq!(*rpc.keys.borrow(), [f.instance()]);
        let OperationBody::InvokeHostFunction(host) =
            &prepared.payment.transaction().operations[0].body
        else {
            panic!("host")
        };
        assert_eq!(host.auth[0], f.auth);
        let TransactionEnvelope::Tx(simulated) = rpc.envelopes.borrow()[0].clone() else {
            panic!("tx")
        };
        assert_eq!(simulated.tx.fee, 100);
        assert_eq!(simulated.tx.ext, TransactionExt::V0);
        assert_eq!(simulated.tx.seq_num.0, 77);
        let mut request = f.request();
        request.conditions = Preconditions::Time(TimeBounds {
            min_time: TimePoint(12),
            max_time: TimePoint(99),
        });
        let prepared = prepare_with(&f.rpc(), &request).await.unwrap();
        assert_eq!(prepared.payment.transaction().cond, request.conditions);
    }
}

#[tokio::test]
async fn sac_simulation_records_without_authorization() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let rpc = f.rpc();
    let prepared = prepare_with(&rpc, &f.request()).await.unwrap();
    let TransactionEnvelope::Tx(tx) = rpc.envelopes.borrow()[0].clone() else {
        panic!("tx")
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!("host")
    };
    assert!(op.auth.is_empty());
    let OperationBody::InvokeHostFunction(op) = &prepared.payment.transaction().operations[0].body
    else {
        panic!("host")
    };
    assert_eq!(op.auth.as_slice(), &[f.auth]);
}

#[tokio::test]
async fn sac_absent_instance_requires_its_index() {
    for case in 0..4 {
        let mut f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
        f.data.resources.footprint.read_only = VecM::default();
        f.data.resources.footprint.read_write = vec![f.balance(), f.instance()].try_into().unwrap();
        let indices = if case == 1 { vec![] } else { vec![0] };
        if case >= 1 {
            f.data.resources.footprint.read_write = vec![f.balance()].try_into().unwrap();
            if case <= 2 {
                f.data.resources.footprint.read_only = vec![f.instance()].try_into().unwrap();
            }
        }
        f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: indices.try_into().unwrap(),
        });
        let mut rpc = f.rpc();
        rpc.entries["entries"] = json!([]);
        let result = prepare_with(&rpc, &f.request()).await;
        assert!(result.is_err(), "case {case}");
        assert_eq!(result.unwrap_err().code(), FOOTPRINT, "case {case}");
    }
}

#[tokio::test]
async fn sac_prepare_rebuild_refusal_precedence() {
    let mut f = Fixture::new(IntentAsset::Native, Some(100), 1);
    f.data.resources.footprint.read_only = vec![account_key(9)].try_into().unwrap();
    f.data.resource_fee = 1_000_000;
    let presented = xdr(&envelope(
        &f.request(),
        &f.invoke,
        1_000_100,
        TransactionExt::V1(f.data.clone()),
    )
    .unwrap());
    assert_eq!(
        prepare_with(&f.rpc(), &f.request())
            .await
            .unwrap_err()
            .code(),
        FOOTPRINT
    );
    assert_eq!(
        rebuild_sac_payment(&f.request(), &presented, &caller(&f))
            .unwrap_err()
            .code(),
        FOOTPRINT
    );

    let classic = ClassicIntent::new(
        IntentBase::new(
            "stellar:testnet".into(),
            f.intent.base().source().into(),
            [7; 32],
            1,
            MemoFact::Id(1),
        )
        .unwrap(),
        IntentPayload::Pay {
            destination: f.intent.base().source().into(),
            asset: IntentAsset::Native,
            amount_stroops: 1,
        },
    )
    .unwrap();
    let mut request = f.request();
    request.intent = &classic;
    assert_eq!(
        prepare_with(&f.rpc(), &request).await.unwrap_err().code(),
        INVALID
    );
    assert_eq!(
        rebuild_sac_payment(&request, &presented, &caller(&f))
            .unwrap_err()
            .code(),
        INVALID
    );
}

#[tokio::test]
async fn sac_restoration_index_precedes_archived_key() {
    for indices in [vec![1, 0], vec![0, 0], vec![0, 99]] {
        let mut f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
        f.data.resources.footprint.read_only = VecM::default();
        f.data.resources.footprint.read_write =
            vec![account_key(1), f.instance()].try_into().unwrap();
        f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: indices.try_into().unwrap(),
        });
        let presented = xdr(&envelope(
            &f.request(),
            &f.invoke,
            500_100,
            TransactionExt::V1(f.data.clone()),
        )
        .unwrap());
        assert_eq!(
            prepare_with(&f.rpc(), &f.request())
                .await
                .unwrap_err()
                .code(),
            FOOTPRINT
        );
        assert_eq!(
            rebuild_sac_payment(&f.request(), &presented, &caller(&f))
                .unwrap_err()
                .code(),
            FOOTPRINT
        );
    }
}

#[tokio::test]
async fn sac_absent_bid_disagrees_with_explicit_zero() {
    for (bid, choice) in [
        (None, ClassicFeeChoice::Explicit(0)),
        (Some(0), ClassicFeeChoice::ProfileDefault),
    ] {
        let f = Fixture::new(IntentAsset::Native, bid, 500_100);
        let mut request = f.request();
        request.fee_choice = choice;
        assert_eq!(
            prepare_with(&f.rpc(), &request).await.unwrap_err().code(),
            INVALID
        );
        let prepared = prepare_with(&f.rpc(), &f.request()).await.unwrap();
        assert_eq!(
            rebuild_sac_payment(&request, &prepared.envelope_xdr, &caller(&f))
                .unwrap_err()
                .code(),
            INVALID
        );
        let mut args = caller(&f);
        args.explicit_inclusion_bid_stroops = if bid.is_none() { Some(0) } else { None };
        assert_eq!(
            rebuild_sac_payment(&f.request(), &prepared.envelope_xdr, &args)
                .unwrap_err()
                .code(),
            INVALID
        );
    }
}

#[test]
fn sac_simulation_allocation_accessors() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let mut response = f.response();
    response["minResourceFee"] = json!("600000");
    let checked =
        check_sac_simulation(&serde_json::from_value(response).unwrap(), &f.invoke).unwrap();
    let mut expected = f.data.clone();
    expected.resource_fee = 600_000;
    assert_eq!(checked.transaction_data(), &expected);
    assert_eq!(checked.resource_stroops(), 600_000);
}

#[tokio::test]
async fn sac_context_and_intent_disagreement() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    for context in [
        SacPaymentContext::new(Caip2::Mainnet, IntentAsset::Native).unwrap(),
        SacPaymentContext::new(Caip2::Testnet, issued(3)).unwrap(),
    ] {
        let mut request = f.request();
        request.context = &context;
        let rpc = f.rpc();
        assert_eq!(
            prepare_with(&rpc, &request).await.unwrap_err().code(),
            INVALID
        );
        assert!(rpc.calls.borrow().is_empty());
    }
    for choice in [
        ClassicFeeChoice::Explicit(99),
        ClassicFeeChoice::ProfileDefault,
        ClassicFeeChoice::Auto(FeePercentile::P95),
    ] {
        let mut request = f.request();
        request.fee_choice = choice;
        assert_eq!(
            prepare_with(&f.rpc(), &request).await.unwrap_err().code(),
            INVALID
        );
    }
    for memo in [
        MemoFact::Text("memo".into()),
        MemoFact::Id(1),
        MemoFact::Hash([1; 32]),
        MemoFact::Return([1; 32]),
    ] {
        let base = IntentBase::new(
            "stellar:testnet".into(),
            f.intent.base().source().into(),
            [7; 32],
            500_100,
            memo,
        )
        .unwrap();
        let intent = ClassicIntent::new(base, f.intent.payload().clone()).unwrap();
        let mut request = f.request();
        request.intent = &intent;
        assert_eq!(
            prepare_with(&f.rpc(), &request).await.unwrap_err().code(),
            "validation.contract_payment_memo_unsupported"
        );
    }
    let classic = ClassicIntent::new(
        f.intent.base().clone(),
        IntentPayload::Pay {
            destination: f.intent.base().source().into(),
            asset: IntentAsset::Native,
            amount_stroops: 1,
        },
    )
    .unwrap();
    let mut request = f.request();
    request.intent = &classic;
    assert_eq!(
        prepare_with(&f.rpc(), &request).await.unwrap_err().code(),
        INVALID
    );
}

#[tokio::test]
async fn sac_fee_selection_and_arithmetic() {
    for bid in [None, Some(0), Some(100)] {
        let f = Fixture::new(IntentAsset::Native, bid, 1_000_000);
        let prepared = prepare_with(&f.rpc(), &f.request()).await.unwrap();
        assert_eq!(prepared.fee.inclusion_bid_stroops, bid.unwrap_or(100));
        assert_eq!(prepared.fee.total_stroops, 500_000 + bid.unwrap_or(100));
    }
    let f = Fixture::new(IntentAsset::Native, None, 1_000_000);
    for (percentile, expected) in [
        (FeePercentile::P10, 787),
        (FeePercentile::P20, 797),
        (FeePercentile::P30, 807),
        (FeePercentile::P40, 817),
        (FeePercentile::P50, 827),
        (FeePercentile::P60, 837),
        (FeePercentile::P70, 847),
        (FeePercentile::P80, 857),
        (FeePercentile::P90, 867),
        (FeePercentile::P95, 872),
        (FeePercentile::P99, 876),
    ] {
        let mut request = f.request();
        request.fee_choice = ClassicFeeChoice::Auto(percentile);
        let rpc = f.rpc();
        assert_eq!(
            prepare_with(&rpc, &request)
                .await
                .unwrap()
                .fee
                .inclusion_bid_stroops,
            expected
        );
        assert_eq!(*rpc.calls.borrow(), ["stats", "entries", "simulate"]);
        let mut rpc = f.rpc();
        rpc.soroban = u64::from(u32::MAX) + 1;
        assert_eq!(
            prepare_with(&rpc, &request).await.unwrap_err().code(),
            INVALID
        );
    }
    for (resource, bid, cap, expected) in [
        (500_000, 100, 500_100, None),
        (500_000, 101, 500_100, Some(CAP)),
        (1_000_000, 1, u32::MAX, Some(CAP)),
        (u32::MAX as i64, 1, u32::MAX, Some(INVALID)),
        (u32::MAX as i64 + 1, 0, u32::MAX, Some(INVALID)),
        (-1, 0, u32::MAX, Some(INVALID)),
        (0, 0, 0, None),
        (0, 1, 0, Some(CAP)),
    ] {
        let mut f = Fixture::new(IntentAsset::Native, Some(bid), cap);
        f.data.resource_fee = resource;
        let result = prepare_with(&f.rpc(), &f.request()).await;
        assert_eq!(
            result.err().map(|e| e.code()),
            expected,
            "resource={resource} bid={bid} cap={cap}"
        );
    }
    for (encoded, minimum, expected) in [(300_000, 500_000, 500_000), (500_000, 300_000, 500_000)] {
        let mut f = Fixture::new(IntentAsset::Native, Some(100), 600_000);
        f.data.resource_fee = encoded;
        let mut rpc = f.rpc();
        rpc.response["minResourceFee"] = json!(minimum.to_string());
        assert_eq!(
            prepare_with(&rpc, &f.request())
                .await
                .unwrap()
                .fee
                .resource_stroops,
            expected
        );
    }
    let mut rpc = f.rpc();
    rpc.response["minResourceFee"] = json!(u64::MAX.to_string());
    assert_eq!(
        prepare_with(&rpc, &f.request()).await.unwrap_err().code(),
        INVALID
    );
    rpc.response["minResourceFee"] = json!((u64::from(u32::MAX) + 1).to_string());
    assert_eq!(
        prepare_with(&rpc, &f.request())
            .await
            .err()
            .map(|e| e.code()),
        Some(INVALID)
    );
}

#[test]
fn sac_decode_and_encode_bounds() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let mut data = f.data.clone();
    data.resources.footprint.read_only = vec![account_key(1); 1300].try_into().unwrap();
    let mut response = f.response();
    response["transactionData"] = json!(xdr(&data));
    assert_eq!(
        check_sac_simulation(&serde_json::from_value(response).unwrap(), &f.invoke)
            .err()
            .map(|e| e.code()),
        Some(SIMULATION)
    );
    let mut nested = ScVal::Void;
    for _ in 0..70 {
        nested = ScVal::Vec(Some(ScVec(vec![nested].try_into().unwrap())));
    }
    let mut deep_data = f.data.clone();
    let LedgerKey::ContractData(mut key) = f.instance() else {
        panic!("instance")
    };
    key.key = nested;
    deep_data.resources.footprint.read_only =
        vec![LedgerKey::ContractData(key)].try_into().unwrap();
    let mut response = f.response();
    response["transactionData"] = json!(xdr(&deep_data));
    assert_eq!(
        check_sac_simulation(&serde_json::from_value(response).unwrap(), &f.invoke)
            .err()
            .map(|e| e.code()),
        Some(SIMULATION)
    );
    assert_eq!(
        assemble_sac_payment(&f.request(), &deep_data, 500_100)
            .unwrap_err()
            .code(),
        INVALID
    );
    data.resources.footprint.read_only = vec![account_key(1); 2000].try_into().unwrap();
    assert_eq!(
        assemble_sac_payment(&f.request(), &data, 500_100)
            .err()
            .map(|e| e.code()),
        Some(INVALID)
    );
}

#[tokio::test]
async fn sac_mainnet_requires_signed_consent_before_rpc() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let context = SacPaymentContext::new(Caip2::Mainnet, IntentAsset::Native).unwrap();
    let base = IntentBase::new(
        Caip2::Mainnet.caip2_str().into(),
        f.intent.base().source().into(),
        [7; 32],
        500_100,
        MemoFact::None,
    )
    .unwrap();
    let intent = ClassicIntent::new(base, f.intent.payload().clone()).unwrap();
    let mut request = f.request();
    request.context = &context;
    request.intent = &intent;
    let rpc = f.rpc();
    assert_eq!(
        prepare_with(&rpc, &request).await.err().map(|e| e.code()),
        Some("validation.contract_transfer_fee_cap_required")
    );
    assert!(rpc.calls.borrow().is_empty());
}

async fn transport_failure(method: &'static str) {
    let f = Fixture::new(IntentAsset::Native, None, 1_000_000);
    let mut rpc = f.rpc();
    rpc.fail = method;
    let mut request = f.request();
    request.fee_choice = ClassicFeeChoice::Auto(FeePercentile::P95);
    let error = prepare_with(&rpc, &request).await.unwrap_err();
    assert_eq!(error.code(), "network.rpc_unreachable");
    assert!(error.to_string().contains(method));
}

#[tokio::test]
async fn sac_read_transport_error() {
    transport_failure("entries").await;
}

#[tokio::test]
async fn sac_stats_transport_error() {
    transport_failure("stats").await;
}

#[tokio::test]
async fn sac_simulate_transport_error() {
    transport_failure("simulate").await;
}

#[test]
fn sac_rebuild_requires_contract_intent() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let classic = ClassicIntent::new(
        f.intent.base().clone(),
        IntentPayload::Pay {
            destination: f.intent.base().source().into(),
            asset: IntentAsset::Native,
            amount_stroops: 1,
        },
    )
    .unwrap();
    let mut request = f.request();
    request.intent = &classic;
    assert_eq!(
        rebuild_sac_payment(
            &request,
            &xdr(&TransactionEnvelope::Tx(sac_transfer(&f.context))),
            &caller(&f)
        )
        .err()
        .map(|e| e.code()),
        Some(INVALID)
    );
}

#[tokio::test]
async fn sac_instance_state_and_transport() {
    let mut f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let mut rpc = f.rpc();
    rpc.entries["entries"] = json!([]);
    assert_eq!(
        prepare_with(&rpc, &f.request()).await.unwrap_err().code(),
        FOOTPRINT
    );
    f.data.resources.footprint.read_write = vec![f.balance(), f.instance()].try_into().unwrap();
    f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: vec![0, 1].try_into().unwrap(),
    });
    for entries in [json!([]), Value::Null] {
        let mut rpc = f.rpc();
        rpc.entries["entries"] = entries;
        let prepared = prepare_with(&rpc, &f.request()).await.unwrap();
        assert_eq!(
            prepared.payment.transaction().ext,
            TransactionExt::V1(f.data.clone())
        );
        assert_eq!(*rpc.calls.borrow(), ["entries", "simulate"]);
        rpc.response["error"] = json!("secret untrusted diagnostic \u{1b}[31m");
        let error = prepare_with(&rpc, &f.request()).await.unwrap_err();
        assert_eq!(error.code(), "validation.asset_contract_not_deployed");
        assert!(error.to_string().contains("never have been deployed"));
        assert!(error.to_string().contains("not be restorable"));
        assert!(error.to_string().contains("native on stellar:testnet"));
        assert!(!error.to_string().contains("secret"));
    }
    let mut rpc = f.rpc();
    rpc.response["error"] = json!("untrusted");
    assert_eq!(
        prepare_with(&rpc, &f.request()).await.unwrap_err().code(),
        SIMULATION
    );
    for fail in ["entries", "simulate", "stats"] {
        transport_failure(fail).await;
    }
}

#[tokio::test]
async fn sac_instance_response_validation() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let good = f.entries()["entries"][0].clone();
    let mut cases = vec![json!([good.clone(), good.clone()])];
    for key in ["bad".to_owned(), xdr(&f.balance()), "A".repeat(MAX_XDR + 1)] {
        let mut entry = good.clone();
        entry["key"] = json!(key);
        cases.push(json!([entry]));
    }
    for data in [
        "bad".to_owned(),
        xdr(&LedgerEntryData::ContractCode(ContractCodeEntry::default())),
    ] {
        let mut entry = good.clone();
        entry["xdr"] = json!(data);
        cases.push(json!([entry]));
    }
    let LedgerEntryData::ContractData(original) =
        LedgerEntryData::from_xdr_base64(good["xdr"].as_str().unwrap(), Limits::none()).unwrap()
    else {
        panic!("instance")
    };
    for change in 0..5 {
        let mut data = original.clone();
        match change {
            0 => data.contract = ScAddress::Contract(ContractId(Hash([8; 32]))),
            1 => data.key = ScVal::Void,
            2 => data.durability = ContractDataDurability::Temporary,
            3 => data.val = ScVal::Void,
            _ => {
                data.val = ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash([9; 32])),
                    storage: None,
                })
            }
        }
        let mut entry = good.clone();
        entry["xdr"] = json!(xdr(&LedgerEntryData::ContractData(data)));
        cases.push(json!([entry]));
    }
    for entries in cases {
        let mut rpc = f.rpc();
        rpc.entries["entries"] = entries;
        assert_eq!(
            prepare_with(&rpc, &f.request()).await.unwrap_err().code(),
            SIMULATION
        );
        assert_eq!(*rpc.calls.borrow(), ["entries"]);
    }
}

#[test]
fn sac_simulation_response_validation() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let good = f.response();
    let check = |value| check_sac_simulation(&serde_json::from_value(value).unwrap(), &f.invoke);
    assert_eq!(check(good.clone()).unwrap().data, f.data);
    let mut cases = vec![];
    for error in [json!(""), json!("untrusted")] {
        let mut r = good.clone();
        r["error"] = error;
        cases.push(r);
    }
    for results in [
        json!([]),
        json!([good["results"][0].clone(), good["results"][0].clone()]),
    ] {
        let mut r = good.clone();
        r["results"] = results;
        cases.push(r);
    }
    for field in ["xdr", "transactionData", "auth"] {
        for bad in ["?".into(), "A".repeat(MAX_XDR + 1), xdr(&ScVal::U32(5))] {
            let mut r = good.clone();
            match field {
                "xdr" => r["results"][0][field] = json!(bad),
                "auth" => r["results"][0][field][0] = json!(bad),
                _ => r[field] = json!(bad),
            }
            cases.push(r);
        }
    }
    for auth in [json!([]), json!([xdr(&f.auth), xdr(&f.auth)])] {
        let mut r = good.clone();
        r["results"][0]["auth"] = auth;
        cases.push(r);
    }
    for only in [false, true] {
        let mut r = good.clone();
        r["restorePreamble"] = json!({"transactionData": xdr(&f.data), "minResourceFee": "10"});
        if only {
            r["results"] = json!([]);
            r["transactionData"] = json!("");
        }
        cases.push(r);
    }
    for (index, r) in cases.into_iter().enumerate() {
        assert_eq!(check(r).unwrap_err().code(), SIMULATION, "case {index}");
    }
    let mut nested = ScVal::Void;
    for _ in 0..70 {
        nested = ScVal::Vec(Some(ScVec(vec![nested].try_into().unwrap())));
    }
    let mut r = good;
    r["results"][0]["xdr"] = json!(xdr(&nested));
    assert_eq!(check(r).unwrap_err().code(), SIMULATION);
}

#[tokio::test]
async fn sac_simulation_authorization_origin() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    for change in 0..5 {
        let mut auth = f.auth.clone();
        let SorobanAuthorizedFunction::ContractFn(invoke) = &mut auth.root_invocation.function
        else {
            panic!("root")
        };
        match change {
            0 => {
                invoke.args = vec![
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([8; 32])),
                    ))),
                    f.invoke.args[1].clone(),
                    ScVal::from(1_i128),
                ]
                .try_into()
                .unwrap()
            }
            1 => invoke.contract_address = ScAddress::Contract(ContractId(Hash([8; 32]))),
            2 => invoke.function_name = ScSymbol("burn".try_into().unwrap()),
            3 => {
                auth.root_invocation.sub_invocations =
                    vec![f.auth.root_invocation.clone()].try_into().unwrap()
            }
            _ => {
                auth.credentials = SorobanCredentials::Address(SorobanAddressCredentials {
                    address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                        Uint256([1; 32]),
                    ))),
                    nonce: 1,
                    signature_expiration_ledger: 1001,
                    signature: ScVal::Void,
                })
            }
        }
        let mut rpc = f.rpc();
        rpc.response["results"][0]["auth"] = json!([xdr(&auth)]);
        assert_eq!(
            prepare_with(&rpc, &f.request()).await.unwrap_err().code(),
            SIMULATION,
            "case {change}"
        );
    }
}

fn account_key(byte: u8) -> LedgerKey {
    LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32]))),
    })
}

fn caller(f: &Fixture) -> SacPaymentCaller<'_> {
    let IntentPayload::ContractPay {
        destination,
        asset,
        amount_stroops,
        explicit_inclusion_bid_stroops,
    } = f.intent.payload()
    else {
        panic!("intent")
    };
    SacPaymentCaller {
        source: f.intent.base().source(),
        destination,
        asset,
        amount_stroops: *amount_stroops,
        explicit_inclusion_bid_stroops: *explicit_inclusion_bid_stroops,
        memo: &MemoFact::None,
    }
}

#[test]
fn sac_nonce_subject_vectors() {
    use hmac::{Hmac, KeyInit, Mac};
    let mut subjects = vec![];
    for bid in [None, Some(0), Some(100)] {
        let f = Fixture::new(IntentAsset::Native, bid, 500_100);
        let envelope = xdr(&TransactionEnvelope::Tx(sac_transfer(&f.context)));
        let subject = sac_payment_nonce_subject(Some(&f.intent), &envelope).unwrap();
        assert_eq!(&subject[..35], b"stellar-agent:sac-payment:nonce:v1\0");
        let canonical = f.intent.canonical_bytes();
        let length = u64::from_be_bytes(subject[35..43].try_into().unwrap());
        assert_eq!(length, canonical.len() as u64);
        assert_eq!(&subject[43..43 + canonical.len()], canonical.as_slice());
        assert_eq!(&subject[51 + canonical.len()..], envelope.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(b"public deterministic test key").unwrap();
        mac.update(&subject);
        let tag = mac.finalize().into_bytes();
        for changed in [format!("{envelope}x"), String::new()] {
            let other = sac_payment_nonce_subject(Some(&f.intent), &changed).unwrap();
            let mut mac = Hmac::<Sha256>::new_from_slice(b"public deterministic test key").unwrap();
            mac.update(&other);
            assert!(mac.verify_slice(&tag).is_err());
        }
        subjects.push((subject, tag));
    }
    for i in 0..subjects.len() {
        for j in 0..subjects.len() {
            if i != j {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(b"public deterministic test key").unwrap();
                mac.update(&subjects[j].0);
                assert!(
                    mac.verify_slice(&subjects[i].1).is_err(),
                    "bid option is nonce-bound"
                );
            }
        }
    }
    assert_eq!(
        sac_payment_nonce_subject(None, "envelope")
            .unwrap_err()
            .code(),
        INVALID
    );
    let f = Fixture::new(IntentAsset::Native, None, 500_100);
    let classic = ClassicIntent::new(
        f.intent.base().clone(),
        IntentPayload::Pay {
            destination: f.intent.base().source().into(),
            asset: IntentAsset::Native,
            amount_stroops: 1,
        },
    )
    .unwrap();
    assert_eq!(
        sac_payment_nonce_subject(Some(&classic), "envelope")
            .unwrap_err()
            .code(),
        INVALID
    );
}

#[test]
fn sac_literal_vectors() {
    let mut vectors = vec![];
    for asset in [IntentAsset::Native, issued(3), issued(1)] {
        let f = Fixture::new(asset, Some(100), 500_100);
        let prepared = assemble_sac_payment(&f.request(), &f.data, 500_100).unwrap();
        vectors.push(stellar_agent_core::hex::encode(&Sha256::digest(
            prepared.envelope_xdr.as_bytes(),
        )));
    }
    for bid in [None, Some(0), Some(100)] {
        let f = Fixture::new(IntentAsset::Native, bid, 500_100);
        let subject = sac_payment_nonce_subject(Some(&f.intent), "envelope").unwrap();
        vectors.push(stellar_agent_core::hex::encode(&Sha256::digest(subject)));
    }
    vectors.push(stellar_agent_core::hex::encode(&Sha256::digest(
        account_key(1).to_xdr(Limits::none()).unwrap(),
    )));
    assert_eq!(
        vectors,
        [
            "726555a25dc4a69d453c4768d8fe2e1444c1ba28f94b34b1c57fb2ea58b6a827",
            "a82c312b3bbca4bee2b2a408c40c62e8fa833a0778abcaf64e6feeb0982e8171",
            "030abd89bf837a2d3bd03b7275ae1dc15c83914346835426b24752c82dab4ac1",
            "d654bd5b1fa932b2fcc278e05deae6da6961c68834332db8410d7e994ff7b8c2",
            "d7ec9a3400cbc7a958e0b81a32c79bc49536c33d2982deb4d4ed22ccd45b2f0e",
            "c199c53669d0d0aa446945c44be95fdbcfd34508e0ee3e45d5e824fee13d8fc5",
            "9f8b3c76e9062af32c1ab2caf0d1aac6770820265475ed7fb0b7b32685a641ea",
        ]
    );
}

#[test]
fn sac_nonce_changed_intent_hmac() {
    use hmac::{Hmac, KeyInit, Mac};
    let f = Fixture::new(IntentAsset::Native, None, 500_100);
    let original = sac_payment_nonce_subject(Some(&f.intent), "unchanged envelope").unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"public deterministic test key").unwrap();
    mac.update(&original);
    let tag = mac.finalize().into_bytes();
    let mut payload = f.intent.payload().clone();
    let IntentPayload::ContractPay { amount_stroops, .. } = &mut payload else {
        panic!("intent")
    };
    *amount_stroops = 2;
    let changed = ClassicIntent::new(f.intent.base().clone(), payload).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"public deterministic test key").unwrap();
    mac.update(&sac_payment_nonce_subject(Some(&changed), "unchanged envelope").unwrap());
    assert!(
        mac.verify_slice(&tag).is_err(),
        "an unchanged envelope cannot authenticate another intent"
    );
}

#[tokio::test]
async fn sac_archived_instance_preparation() {
    let mut f = Fixture::new(issued(3), Some(100), 500_100);
    f.data.resources.footprint.read_write = vec![f.instance()].try_into().unwrap();
    f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: vec![0].try_into().unwrap(),
    });
    let mut rpc = f.rpc();
    rpc.entries["entries"] = json!([]);
    let result = prepare_with(&rpc, &f.request()).await;
    assert!(
        result.is_ok(),
        "indexed absent instance restores: {result:?}"
    );
    assert_eq!(result.unwrap().fee.total_stroops, 500_100);
    assert_eq!(*rpc.calls.borrow(), ["entries", "simulate"]);
}

#[tokio::test]
#[serial_test::serial]
async fn sac_signed_cap_maximum() {
    use stellar_agent_core::policy::v1::{
        canonical::canonical_bytes,
        criteria::state_store::PolicyStateStore,
        signature::{digest, sign},
        verified::{OwnerKeySource, PinMode, PolicyLoad, load_verified_policy},
    };
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    let window = dir.path().join("state.window");
    let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let public = key.verifying_key().to_bytes();
    let body =
        "version = 1\nscope = \"profile:fees\"\ncontract_transfer_max_fee_stroops = 4294967295\n";
    let signed = format!(
        "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
        stellar_strkey::ed25519::PublicKey(public),
        stellar_agent_core::hex::encode(&sign(&digest(&canonical_bytes(body).unwrap()), &key))
    );
    std::fs::write(&path, signed).unwrap();
    let profile = stellar_agent_core::profile::schema::Profile::builder_testnet(
        "signer", "owner", "nonce", "test",
    )
    .build();
    let policy = load_verified_policy(
        &PolicyLoad {
            path: &path,
            profile: &profile,
            profile_name: "fees",
            owner_pubkey: &public,
            owner_source: OwnerKeySource::Keyring,
            window_path: &window,
        },
        PolicyStateStore::new(),
        PinMode::CompareOnly,
    )
    .unwrap();
    for (resource, bid) in [(u32::MAX, 0), (0, u32::MAX)] {
        let mut f = Fixture::new(IntentAsset::Native, Some(bid), u32::MAX);
        f.data.resource_fee = i64::from(resource);
        let mut request = f.request();
        request.policy = Some(&policy);
        let prepared = prepare_with(&f.rpc(), &request).await.unwrap();
        assert_eq!(
            prepared.fee,
            SacTransferFee {
                total_stroops: u32::MAX,
                resource_stroops: resource,
                inclusion_bid_stroops: bid
            }
        );
        assert_eq!(
            rebuild_sac_payment(&request, &prepared.envelope_xdr, &caller(&f))
                .unwrap()
                .fee,
            prepared.fee
        );
    }
}

#[tokio::test]
async fn sac_rebuild_independent_caller_agreement() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let rpc = f.rpc();
    let prepared = prepare_with(&rpc, &f.request()).await.unwrap();
    let subject = sac_payment_nonce_subject(Some(&f.intent), &prepared.envelope_xdr).unwrap();
    let other_source = stellar_strkey::ed25519::PublicKey([9; 32])
        .to_string()
        .to_string();
    let other_destination = stellar_strkey::Contract([9; 32]).to_string().to_string();
    let same_payload_g = stellar_strkey::ed25519::PublicKey([2; 32])
        .to_string()
        .to_string();
    let other_asset = issued(3);
    for change in 0..8 {
        let mut args = caller(&f);
        match change {
            0 => args.source = &other_source,
            1 => args.destination = &other_destination,
            2 => args.asset = &other_asset,
            3 => args.amount_stroops = 2,
            4 => args.explicit_inclusion_bid_stroops = Some(99),
            5 => args.memo = &MemoFact::Id(1),
            6 => args.destination = &same_payload_g,
            _ => args.explicit_inclusion_bid_stroops = None,
        }
        assert_eq!(
            rebuild_sac_payment(&f.request(), &prepared.envelope_xdr, &args)
                .unwrap_err()
                .code(),
            INVALID,
            "caller field {change}"
        );
        assert_eq!(
            sac_payment_nonce_subject(Some(&f.intent), &prepared.envelope_xdr).unwrap(),
            subject
        );
    }
    let rebuilt = rebuild_sac_payment(&f.request(), &prepared.envelope_xdr, &caller(&f)).unwrap();
    assert_eq!(rebuilt.envelope_xdr, prepared.envelope_xdr);
    assert_eq!(rebuilt.fee.resource_stroops, 500_000);
    assert_eq!(*rpc.calls.borrow(), ["entries", "simulate"]);
    let mut request = f.request();
    request.sequence = 78;
    assert_eq!(
        rebuild_sac_payment(&request, &prepared.envelope_xdr, &caller(&f))
            .unwrap_err()
            .code(),
        INVALID
    );
    request = f.request();
    request.conditions = Preconditions::Time(TimeBounds {
        min_time: TimePoint(1),
        max_time: TimePoint(2),
    });
    assert_eq!(
        rebuild_sac_payment(&request, &prepared.envelope_xdr, &caller(&f))
            .unwrap_err()
            .code(),
        INVALID
    );
}

#[test]
fn sac_rebuild_envelope_equality() {
    let f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    let good = sac_transfer(&f.context);
    let original = xdr(&TransactionEnvelope::Tx(good.clone()));
    assert_eq!(
        rebuild_sac_payment(&f.request(), &original, &caller(&f))
            .unwrap()
            .envelope_xdr,
        original
    );
    for change in 0..11 {
        let mut e = good.clone();
        match change {
            0 => e.tx.source_account = MuxedAccount::Ed25519(Uint256([8; 32])),
            1 => e.tx.seq_num.0 += 1,
            2 => e.tx.memo = Memo::Id(1),
            3 => e.tx.ext = TransactionExt::V0,
            4 => e.tx.operations = VecM::default(),
            5 => {
                e.signatures = vec![DecoratedSignature {
                    hint: SignatureHint([0; 4]),
                    signature: Signature(vec![0; 64].try_into().unwrap()),
                }]
                .try_into()
                .unwrap()
            }
            6 => e.tx.fee += 1,
            7 => {
                let TransactionExt::V1(data) = &mut e.tx.ext else {
                    panic!("data")
                };
                data.resources.footprint.read_only = vec![account_key(9)].try_into().unwrap();
            }
            8 => {
                let OperationBody::InvokeHostFunction(host) =
                    &mut e.tx.operations.iter_mut().next().unwrap().body
                else {
                    panic!("host")
                };
                host.auth = VecM::default();
            }
            9 => {
                e.tx.operations.iter_mut().next().unwrap().source_account =
                    Some(e.tx.source_account.clone())
            }
            _ => {
                let OperationBody::InvokeHostFunction(host) =
                    &mut e.tx.operations.iter_mut().next().unwrap().body
                else {
                    panic!("host")
                };
                let HostFunction::InvokeContract(invoke) = &mut host.host_function else {
                    panic!("invoke")
                };
                invoke.args = vec![
                    f.invoke.args[0].clone(),
                    f.invoke.args[1].clone(),
                    ScVal::from(2_i128),
                ]
                .try_into()
                .unwrap();
            }
        }
        let expected = if change == 7 { FOOTPRINT } else { INVALID };
        assert_eq!(
            rebuild_sac_payment(&f.request(), &xdr(&TransactionEnvelope::Tx(e)), &caller(&f))
                .unwrap_err()
                .code(),
            expected,
            "envelope change {change}"
        );
    }
    for encoded in [
        "bad".to_owned(),
        "A".repeat(MAX_XDR + 1),
        xdr(&TransactionEnvelope::TxV0(TransactionV0Envelope::default())),
    ] {
        assert_eq!(
            rebuild_sac_payment(&f.request(), &encoded, &caller(&f))
                .unwrap_err()
                .code(),
            INVALID
        );
    }
}

#[tokio::test]
async fn sac_data_adapters_footprint_and_restoration() {
    for asset in [IntentAsset::Native, issued(3), issued(1), long_asset()] {
        let mut f = Fixture::new(asset.clone(), Some(100), 500_100);
        let instance = f.instance();
        let balance = f.balance();
        let mut good = vec![
            (
                vec![instance.clone()],
                vec![account_key(1), balance.clone()],
                vec![],
            ),
            (vec![], vec![instance.clone(), balance.clone()], vec![0, 1]),
            (vec![], vec![balance.clone(), instance.clone()], vec![0, 1]),
        ];
        if asset == issued(1) {
            good.push((
                vec![instance.clone(), account_key(1)],
                vec![balance.clone()],
                vec![],
            ));
        }
        if asset == issued(3) {
            good.push((
                vec![instance.clone(), account_key(3)],
                vec![account_key(1), balance.clone()],
                vec![],
            ));
        }
        let trustline = |code: [u8; 4], issuer: u8, payer: u8| {
            LedgerKey::Trustline(LedgerKeyTrustLine {
                account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([payer; 32]))),
                asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code),
                    issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([issuer; 32]))),
                }),
            })
        };
        if asset == issued(3) {
            good.push((
                vec![instance.clone(), account_key(3)],
                vec![trustline(*b"USD\0", 3, 1), balance.clone()],
                vec![],
            ));
        }
        if asset == long_asset() {
            let key = LedgerKey::from_xdr_base64(
                "AAAAAQAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAAAJMb25nQ29kZTEyMzQAAAAAAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
                Limits::none(),
            ).unwrap();
            good.push((
                vec![instance.clone(), account_key(3)],
                vec![key, balance.clone()],
                vec![],
            ));
        }
        for (ro, rw, indices) in &good {
            f.data.resources.footprint = LedgerFootprint {
                read_only: ro.clone().try_into().unwrap(),
                read_write: rw.clone().try_into().unwrap(),
            };
            f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                archived_soroban_entries: indices.clone().try_into().unwrap(),
            });
            let a = prepare_with(&f.rpc(), &f.request()).await.unwrap();
            let b = assemble_sac_payment(&f.request(), &f.data, 500_100).unwrap();
            assert_eq!(a.envelope_xdr, b.envelope_xdr);
            assert_eq!(
                rebuild_sac_payment(&f.request(), &a.envelope_xdr, &caller(&f))
                    .unwrap()
                    .envelope_xdr,
                a.envelope_xdr
            );
            assert_eq!(
                a.payment.transaction().ext,
                TransactionExt::V1(f.data.clone())
            );
        }
        let mut bad = vec![(vec![balance.clone()], vec![], vec![])];
        let mut foreign = vec![
            trustline(*b"EUR\0", 3, 1),
            trustline(*b"USD\0", 9, 1),
            trustline(*b"USD\0", 3, 9),
        ];
        if asset == issued(1) {
            foreign.push(trustline(*b"USD\0", 1, 1));
        }
        for key in [&instance, &balance] {
            let LedgerKey::ContractData(data) = key else {
                panic!("contract data")
            };
            let mut other = data.clone();
            other.contract = ScAddress::Contract(ContractId(Hash([9; 32])));
            foreign.push(LedgerKey::ContractData(other));
            let mut other = data.clone();
            other.durability = ContractDataDurability::Temporary;
            foreign.push(LedgerKey::ContractData(other));
        }
        let LedgerKey::ContractData(mut other) = balance.clone() else {
            panic!("balance")
        };
        other.key = ScVal::Void;
        foreign.push(LedgerKey::ContractData(other));
        for key in foreign {
            bad.push((vec![key.clone()], vec![], vec![]));
            bad.push((vec![], vec![key], vec![]));
        }
        for key in [
            account_key(9),
            LedgerKey::ContractCode(LedgerKeyContractCode {
                hash: Hash([9; 32]),
            }),
        ] {
            bad.push((vec![key.clone()], vec![], vec![]));
            bad.push((vec![], vec![key], vec![]));
        }
        for key in [&instance, &balance, &account_key(1)] {
            bad.push((vec![key.clone()], vec![key.clone()], vec![]));
            bad.push((vec![], vec![key.clone(), key.clone()], vec![]));
        }
        for indices in [
            vec![1, 0],
            vec![0, 0],
            vec![0, 2],
            vec![0, u32::MAX],
            vec![1],
            vec![],
        ] {
            bad.push((vec![], vec![instance.clone(), balance.clone()], indices));
        }
        for (ro, rw, indices) in bad {
            f.data.resources.footprint = LedgerFootprint {
                read_only: ro.try_into().unwrap(),
                read_write: rw.try_into().unwrap(),
            };
            f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
                archived_soroban_entries: indices.try_into().unwrap(),
            });
            assert_eq!(
                prepare_with(&f.rpc(), &f.request())
                    .await
                    .unwrap_err()
                    .code(),
                FOOTPRINT
            );
            assert_eq!(
                assemble_sac_payment(&f.request(), &f.data, 500_100)
                    .unwrap_err()
                    .code(),
                FOOTPRINT
            );
            let mut presented = sac_transfer(&f.context);
            presented.tx.ext = TransactionExt::V1(f.data.clone());
            assert_eq!(
                rebuild_sac_payment(
                    &f.request(),
                    &xdr(&TransactionEnvelope::Tx(presented)),
                    &caller(&f)
                )
                .unwrap_err()
                .code(),
                FOOTPRINT
            );
        }
    }
}

#[tokio::test]
async fn sac_archived_key_digest_and_retained_fees() {
    let mut f = Fixture::new(IntentAsset::Native, Some(100), 500_100);
    f.data.resources.footprint.read_write = vec![account_key(1)].try_into().unwrap();
    f.data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: vec![0].try_into().unwrap(),
    });
    let presented = xdr(&envelope(
        &f.request(),
        &f.invoke,
        500_100,
        TransactionExt::V1(f.data.clone()),
    )
    .unwrap());
    for error in [
        prepare_with(&f.rpc(), &f.request()).await.unwrap_err(),
        rebuild_sac_payment(&f.request(), &presented, &caller(&f)).unwrap_err(),
    ] {
        assert_eq!(error.code(), "validation.contract_payment_archived_entry");
        let WalletError::Validation(stellar_agent_core::error::ValidationError::SacPayment(
            Refusal::ArchivedEntry { key_sha256 },
        )) = error
        else {
            panic!("typed archived error")
        };
        assert_eq!(
            stellar_agent_core::hex::encode(&key_sha256),
            "9f8b3c76e9062af32c1ab2caf0d1aac6770820265475ed7fb0b7b32685a641ea"
        );
    }
    f.data.resources.footprint = LedgerFootprint::default();
    f.data.ext = SorobanTransactionDataExt::V0;
    for (resource, total, expected) in [
        (-1, 500_100, INVALID),
        (u32::MAX as i64 + 1, 500_100, INVALID),
        (500_101, 500_100, INVALID),
        (500_000, 500_099, INVALID),
        (500_001, 500_101, CAP),
    ] {
        f.data.resource_fee = resource;
        let presented = xdr(&envelope(
            &f.request(),
            &f.invoke,
            total,
            TransactionExt::V1(f.data.clone()),
        )
        .unwrap());
        assert_eq!(
            rebuild_sac_payment(&f.request(), &presented, &caller(&f))
                .unwrap_err()
                .code(),
            expected
        );
    }
}
