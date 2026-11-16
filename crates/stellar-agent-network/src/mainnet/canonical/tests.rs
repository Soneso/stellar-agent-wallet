#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::*;
use crate::fees::ClassicFeeChoice;
use crate::operation_entry::{IntentBaseFacts, classic_intent, intent_envelope};
use stellar_agent_core::amount::StellarAmount;
use stellar_agent_core::approval::subject::approval_subject_classic;
use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;
use stellar_xdr::{
    ClaimPredicate, ClaimableBalanceEntryExt, Claimant, ClaimantV0, DecoratedSignature,
    FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, Hash, Limits, MuxedAccountMed25519, Preconditions, PreconditionsV2,
    SorobanResources, SorobanTransactionData, SorobanTransactionDataExt, TimeBounds, TimePoint,
    TransactionV0, TransactionV0Envelope, TransactionV0Ext, Uint256, WriteXdr as _,
};

const SOURCE: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const DESTINATION: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const ISSUER: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
const BALANCE: [u8; 32] = [0xcd; 32];
/// The check time; a deadline 90 seconds later passes every deadline rule.
const NOW_MS: u64 = 1_800_000_000_000;
const MAX_TIME: u64 = NOW_MS / 1000 + 90;
const BOUND: u32 = 500;
const CAP: u32 = 1_000;

fn intent_with(
    payload: IntentPayload,
    memo: MemoFact,
    fee_choice: ClassicFeeChoice,
) -> ClassicIntent {
    classic_intent(
        IntentBaseFacts {
            chain_id: "stellar:mainnet",
            source: SOURCE,
            policy_digest: [0x11; 32],
            signed_fee_cap: Some(CAP),
            profile_fee_cap: Some(BOUND),
            fee_choice,
            memo,
        },
        payload,
    )
    .unwrap()
}

fn intent(payload: IntentPayload, memo: MemoFact) -> ClassicIntent {
    intent_with(payload, memo, ClassicFeeChoice::ProfileDefault)
}

fn pay_payload(destination: &str, asset: IntentAsset, amount: i64) -> IntentPayload {
    IntentPayload::Pay {
        destination: destination.to_owned(),
        asset,
        amount_stroops: amount,
    }
}

fn usdc() -> crate::Asset {
    crate::Asset::Credit {
        code: "USDC".to_owned(),
        issuer: ISSUER.to_owned(),
    }
}

fn issued(code: &str) -> IntentAsset {
    IntentAsset::Issued {
        code: code.to_owned(),
        issuer: ISSUER.to_owned(),
    }
}

/// An unsigned envelope from the public builder at `sequence` and `fee`,
/// with operations `ops` adds and `memo`.
fn built(
    sequence: i64,
    fee: u32,
    max_time: u64,
    memo: Option<Memo>,
    ops: impl FnOnce(&mut crate::ClassicOpBuilder),
) -> String {
    let mut builder = crate::ClassicOpBuilder::new(SOURCE, sequence, MAINNET_PASSPHRASE, fee);
    ops(&mut builder);
    if let Some(memo) = memo {
        builder.memo(&memo).unwrap();
    }
    builder.with_time_bounds(0, max_time);
    builder.build().unwrap()
}

fn pay_envelope(
    destination: &str,
    asset: &crate::Asset,
    amount: i64,
    memo: Option<Memo>,
) -> String {
    built(41, 100, MAX_TIME, memo, |b| {
        b.payment(destination, StellarAmount::from_stroops(amount), asset)
            .unwrap();
    })
}

/// `envelope` with `change` applied to its decoded XDR.
fn edited(envelope: &str, change: impl FnOnce(&mut TransactionEnvelope)) -> String {
    let mut decoded = TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap();
    change(&mut decoded);
    decoded.to_xdr_base64(Limits::none()).unwrap()
}

fn tx_of(envelope: &mut TransactionEnvelope) -> &mut stellar_xdr::Transaction {
    let TransactionEnvelope::Tx(inner) = envelope else {
        panic!("a V1 envelope")
    };
    &mut inner.tx
}

/// `envelope` with `change` applied to its first operation.
fn op_edited(envelope: &str, change: impl FnOnce(&mut stellar_xdr::Operation)) -> String {
    edited(envelope, |envelope| {
        let tx = tx_of(envelope);
        let mut operations = tx.operations.to_vec();
        change(&mut operations[0]);
        tx.operations = operations.try_into().unwrap();
    })
}

fn check(intent: &ClassicIntent) -> CanonicalCheck<'_> {
    CanonicalCheck {
        intent,
        fee_cap_stroops: CAP,
        now_ms: NOW_MS,
        claim_entry: None,
    }
}

fn refusal(envelope: &str, intent: &ClassicIntent) -> CanonicalRefusal {
    match_envelope(envelope, &check(intent)).unwrap_err()
}

fn account(seed: u8) -> stellar_xdr::AccountId {
    stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(
        [seed; 32],
    )))
}

fn source_key() -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(SOURCE)
        .unwrap()
        .0
}

/// Every envelope shape outside an unsigned V1 transaction with one
/// operation on the intent's G source refuses, each naming its own guard.
/// An explicit operation source equal to the transaction source passes.
#[test]
fn canonical_shape_and_source_matrix() {
    use CanonicalPart as Part;
    let stored = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::None,
    );
    let valid = pay_envelope(DESTINATION, &crate::Asset::Native, 10, None);
    assert!(match_envelope(&valid, &check(&stored)).is_ok());
    let same_source = op_edited(&valid, |op| {
        op.source_account = Some(MuxedAccount::Ed25519(Uint256(source_key())));
    });
    assert!(match_envelope(&same_source, &check(&stored)).is_ok());

    let TransactionEnvelope::Tx(inner) =
        TransactionEnvelope::from_xdr_base64(&valid, Limits::none()).unwrap()
    else {
        unreachable!()
    };
    let fee_bump = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256(source_key())),
            fee: 1_000,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner.clone()),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let v0 = TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256(source_key()),
            fee: inner.tx.fee,
            seq_num: inner.tx.seq_num.clone(),
            time_bounds: Some(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(MAX_TIME),
            }),
            memo: Memo::None,
            operations: inner.tx.operations.clone(),
            ext: TransactionV0Ext::V0,
        },
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap();
    let signed = edited(&valid, |envelope| {
        let TransactionEnvelope::Tx(inner) = envelope else {
            unreachable!()
        };
        inner.signatures = vec![DecoratedSignature {
            hint: stellar_xdr::SignatureHint([1; 4]),
            signature: vec![2; 64].try_into().unwrap(),
        }]
        .try_into()
        .unwrap();
    });
    let two_operations = edited(&valid, |envelope| {
        let tx = tx_of(envelope);
        let op = tx.operations[0].clone();
        tx.operations = vec![op.clone(), op].try_into().unwrap();
    });
    let create = built(41, 100, MAX_TIME, None, |b| {
        b.create_account(DESTINATION, StellarAmount::from_stroops(10))
            .unwrap();
    });
    let muxed_source = edited(&valid, |envelope| {
        tx_of(envelope).source_account = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: 0,
            ed25519: Uint256(source_key()),
        });
    });
    let foreign_source = edited(&valid, |envelope| {
        tx_of(envelope).source_account = MuxedAccount::Ed25519(Uint256([9; 32]));
    });
    let foreign_operation_source = op_edited(&valid, |op| {
        op.source_account = Some(MuxedAccount::Ed25519(Uint256([9; 32])));
    });
    let muxed_operation_source = op_edited(&valid, |op| {
        op.source_account = Some(MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: 3,
            ed25519: Uint256(source_key()),
        }));
    });
    let extension = edited(&valid, |envelope| {
        tx_of(envelope).ext = TransactionExt::V1(SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: stellar_xdr::LedgerFootprint {
                    read_only: Default::default(),
                    read_write: Default::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        });
    });
    for (name, envelope, expected) in [
        ("undecodable", "not an envelope".to_owned(), Part::Envelope),
        ("fee bump", fee_bump, Part::FeeBump),
        ("v0", v0, Part::Version),
        ("signed", signed, Part::Signatures),
        ("extension", extension, Part::Extension),
        ("muxed source", muxed_source, Part::Source),
        ("foreign source", foreign_source, Part::Source),
        ("two operations", two_operations, Part::OperationCount),
        (
            "foreign operation source",
            foreign_operation_source,
            Part::OperationSource,
        ),
        (
            "muxed operation source",
            muxed_operation_source,
            Part::OperationSource,
        ),
        ("wrong variant", create, Part::Operation),
    ] {
        assert_eq!(
            refusal(&envelope, &stored),
            CanonicalRefusal::Mismatch(expected),
            "{name}"
        );
    }
}

/// One intent matches two envelopes that differ in sequence, fee and
/// deadline. The returned digest is the stored intent's digest, not the
/// envelope subject, and the facts are each envelope's own.
#[test]
fn one_intent_matches_two_fresh_envelopes() {
    let stored = intent(
        pay_payload(DESTINATION, issued("USDC"), 25_000_000),
        MemoFact::Id(7),
    );
    let first = built(41, 100, MAX_TIME, Some(Memo::Id(7)), |b| {
        b.payment(
            DESTINATION,
            StellarAmount::from_stroops(25_000_000),
            &usdc(),
        )
        .unwrap();
    });
    let second = built(57, BOUND, MAX_TIME + 29, Some(Memo::Id(7)), |b| {
        b.payment(
            DESTINATION,
            StellarAmount::from_stroops(25_000_000),
            &usdc(),
        )
        .unwrap();
    });
    assert_ne!(first, second);
    let a = match_envelope(&first, &check(&stored)).unwrap();
    let b = match_envelope(&second, &check(&stored)).unwrap();
    assert_eq!(a.digest, stored.digest());
    assert_eq!(b.digest, stored.digest());
    assert_ne!(a.digest.as_bytes(), &approval_subject_classic(&first));
    assert_eq!(
        (a.sequence, a.fee_stroops, a.max_time_s),
        (42, 100, MAX_TIME)
    );
    assert_eq!(
        (b.sequence, b.fee_stroops, b.max_time_s),
        (58, BOUND, MAX_TIME + 29)
    );
}

/// Each lasting field changed alone refuses and names that field, for all
/// four operation types.
#[test]
fn canonical_payload_changes_refuse() {
    use CanonicalPart as Part;
    let pay = intent(pay_payload(DESTINATION, issued("USDC"), 10), MemoFact::None);
    let usdc_other_issuer = crate::Asset::Credit {
        code: "USDC".to_owned(),
        issuer: SOURCE.to_owned(),
    };
    for (name, envelope, expected) in [
        (
            "destination",
            pay_envelope(ISSUER, &usdc(), 10, None),
            Part::Destination,
        ),
        (
            "native asset",
            pay_envelope(DESTINATION, &crate::Asset::Native, 10, None),
            Part::Asset,
        ),
        (
            "issuer",
            pay_envelope(DESTINATION, &usdc_other_issuer, 10, None),
            Part::Asset,
        ),
        (
            "amount",
            pay_envelope(DESTINATION, &usdc(), 11, None),
            Part::Amount,
        ),
        (
            "zero amount",
            pay_envelope(DESTINATION, &usdc(), 0, None),
            Part::Amount,
        ),
    ] {
        assert_eq!(
            refusal(&envelope, &pay),
            CanonicalRefusal::Mismatch(expected),
            "{name}"
        );
    }

    let create = intent(
        IntentPayload::CreateAccount {
            destination: DESTINATION.to_owned(),
            starting_balance_stroops: 10_000_000,
        },
        MemoFact::None,
    );
    let create_envelope = |destination: &str, balance: i64| {
        built(41, 100, MAX_TIME, None, |b| {
            b.create_account(destination, StellarAmount::from_stroops(balance))
                .unwrap();
        })
    };
    assert!(match_envelope(&create_envelope(DESTINATION, 10_000_000), &check(&create)).is_ok());
    assert_eq!(
        refusal(&create_envelope(ISSUER, 10_000_000), &create),
        CanonicalRefusal::Mismatch(Part::Destination)
    );
    assert_eq!(
        refusal(&create_envelope(DESTINATION, 10_000_001), &create),
        CanonicalRefusal::Mismatch(Part::Amount)
    );

    let trust = intent(
        IntentPayload::Trustline {
            issuer: ISSUER.to_owned(),
            code: "USDC".to_owned(),
            limit_stroops: 0,
        },
        MemoFact::None,
    );
    let trust_envelope = |asset: &crate::Asset, limit: i64| {
        built(41, 100, MAX_TIME, None, |b| {
            b.change_trust(asset, Some(limit)).unwrap();
        })
    };
    assert!(match_envelope(&trust_envelope(&usdc(), 0), &check(&trust)).is_ok());
    let eurc = crate::Asset::Credit {
        code: "EURC".to_owned(),
        issuer: ISSUER.to_owned(),
    };
    assert_eq!(
        refusal(&trust_envelope(&eurc, 0), &trust),
        CanonicalRefusal::Mismatch(Part::Asset)
    );
    assert_eq!(
        refusal(&trust_envelope(&usdc_other_issuer, 0), &trust),
        CanonicalRefusal::Mismatch(Part::Asset)
    );
    assert_eq!(
        refusal(&trust_envelope(&usdc(), 1), &trust),
        CanonicalRefusal::Mismatch(Part::Amount)
    );
}

/// The balance entry of `BALANCE` holding `asset` and `amount`, claimable by
/// `claimants` in order.
fn balance_entry(
    asset: Asset,
    amount: i64,
    claimants: Vec<(stellar_xdr::AccountId, ClaimPredicate)>,
) -> ClaimableBalanceEntry {
    ClaimableBalanceEntry {
        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(BALANCE)),
        claimants: claimants
            .into_iter()
            .map(|(destination, predicate)| {
                Claimant::ClaimantTypeV0(ClaimantV0 {
                    destination,
                    predicate,
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        asset,
        amount,
        ext: ClaimableBalanceEntryExt::V0,
    }
}

/// A claim matches only with a fresh entry of its balance holding its asset
/// and amount; the asset and amount enter the reconstructed intent from
/// that entry.
#[test]
fn canonical_claim_requires_its_fresh_facts() {
    use CanonicalPart as Part;
    let balance_id = format!("00000000{}", stellar_agent_core::hex::encode(&BALANCE));
    let stored = intent(
        IntentPayload::Claim {
            balance_id: balance_id.clone(),
            asset: IntentAsset::Native,
            amount_stroops: 70,
            claimant: SOURCE.to_owned(),
        },
        MemoFact::None,
    );
    let claim_of = |hash: [u8; 32]| {
        built(41, 100, MAX_TIME, None, |b| {
            b.claim_claimable_balance(&stellar_agent_core::hex::encode(&hash))
                .unwrap();
        })
    };
    let envelope = claim_of(BALANCE);
    let fresh = balance_entry(Asset::Native, 70, vec![]);
    let stored = &stored;
    let with = |entry| CanonicalCheck {
        claim_entry: entry,
        ..check(stored)
    };
    assert_eq!(
        match_envelope(&envelope, &with(Some(&fresh)))
            .unwrap()
            .digest,
        stored.digest()
    );
    let mut usdc = fresh.clone();
    usdc.asset = Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
        asset_code: stellar_xdr::AssetCode4(*b"USDC"),
        issuer: account(3),
    });
    let mut more = fresh.clone();
    more.amount = 71;
    let mut other = fresh.clone();
    other.balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
    for (name, entry, expected) in [
        ("no entry", None, Part::ClaimFacts),
        ("asset", Some(&usdc), Part::ClaimFacts),
        ("amount", Some(&more), Part::ClaimFacts),
        ("entry of another balance", Some(&other), Part::ClaimFacts),
    ] {
        assert_eq!(
            match_envelope(&envelope, &with(entry)).unwrap_err(),
            CanonicalRefusal::Mismatch(expected),
            "{name}"
        );
    }
    let mut other_fresh = fresh.clone();
    other_fresh.balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
    assert_eq!(
        match_envelope(&claim_of([0xab; 32]), &with(Some(&other_fresh))).unwrap_err(),
        CanonicalRefusal::Mismatch(Part::BalanceId)
    );
}

/// A payment to an M address keeps its ID through the builder and the
/// matcher. G and M spellings of one base account are distinct intents, an
/// envelope with another ID refuses, and recipient classification keeps the
/// one base account.
#[test]
fn canonical_muxed_payment_keeps_id() {
    use stellar_agent_core::payment_accounts::PaymentAccount;
    let key = stellar_strkey::ed25519::PublicKey::from_string(DESTINATION)
        .unwrap()
        .0;
    let muxed = |id: u64| {
        stellar_strkey::ed25519::MuxedAccount { ed25519: key, id }
            .to_string()
            .as_str()
            .to_owned()
    };
    let g = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::None,
    );
    for id in [0, 1, u64::MAX] {
        let m = intent(
            pay_payload(&muxed(id), IntentAsset::Native, 10),
            MemoFact::None,
        );
        assert_ne!(m.digest(), g.digest(), "{id}");
        let envelope = intent_envelope(&m, MAINNET_PASSPHRASE, 41, 100, MAX_TIME).unwrap();
        let decoded = TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(inner) = &decoded else {
            unreachable!()
        };
        let OperationBody::Payment(payment) = &inner.tx.operations[0].body else {
            panic!("a payment")
        };
        assert_eq!(
            payment.destination,
            MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id,
                ed25519: Uint256(key)
            }),
            "{id}"
        );
        assert_eq!(
            match_envelope(&envelope, &check(&m)).unwrap().digest,
            m.digest()
        );
        assert_eq!(
            refusal(&envelope, &g),
            CanonicalRefusal::Mismatch(CanonicalPart::Destination)
        );
        let other_id = pay_envelope(&muxed(id ^ 1), &crate::Asset::Native, 10, None);
        assert_eq!(
            refusal(&other_id, &m),
            CanonicalRefusal::Mismatch(CanonicalPart::Destination),
            "{id}"
        );
        assert_eq!(
            PaymentAccount::parse(&muxed(id)).unwrap().base_account(),
            PaymentAccount::parse(DESTINATION).unwrap().base_account()
        );
    }
}

/// Every memo kind matches itself only: an ID memo differs from the next
/// ID and from no memo, and text that is not UTF-8 matches no intent.
#[test]
fn canonical_memos_keep_kind_and_value() {
    let memos = [
        (MemoFact::None, None),
        (
            MemoFact::Text("order 7 ✓".to_owned()),
            Some(Memo::Text(
                "order 7 ✓".as_bytes().to_vec().try_into().unwrap(),
            )),
        ),
        (MemoFact::Id(7), Some(Memo::Id(7))),
        (MemoFact::Id(8), Some(Memo::Id(8))),
        (MemoFact::Id(u64::MAX), Some(Memo::Id(u64::MAX))),
        (MemoFact::Hash([3; 32]), Some(Memo::Hash(Hash([3; 32])))),
        (MemoFact::Return([3; 32]), Some(Memo::Return(Hash([3; 32])))),
    ];
    for (i, (fact, _)) in memos.iter().enumerate() {
        let stored = intent(
            pay_payload(DESTINATION, IntentAsset::Native, 10),
            fact.clone(),
        );
        for (j, (_, memo)) in memos.iter().enumerate() {
            let envelope = pay_envelope(DESTINATION, &crate::Asset::Native, 10, memo.clone());
            let result = match_envelope(&envelope, &check(&stored));
            if i == j {
                assert_eq!(result.unwrap().digest, stored.digest(), "{fact:?}");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    CanonicalRefusal::Mismatch(CanonicalPart::Memo),
                    "{fact:?} against {memo:?}"
                );
            }
        }
    }
    let stored = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::Text("\u{fffd}".to_owned()),
    );
    let invalid = edited(
        &pay_envelope(DESTINATION, &crate::Asset::Native, 10, None),
        |envelope| tx_of(envelope).memo = Memo::Text(vec![0xff].try_into().unwrap()),
    );
    assert_eq!(
        refusal(&invalid, &stored),
        CanonicalRefusal::Mismatch(CanonicalPart::Memo)
    );
}

/// The fee may equal the intent's bound and the current cap; one stroop more
/// than either refuses. An explicit fee choice is its own bound.
#[test]
fn canonical_fee_bound_is_inclusive() {
    let payload = pay_payload(DESTINATION, IntentAsset::Native, 10);
    let default = intent(payload.clone(), MemoFact::None);
    let explicit = intent_with(payload, MemoFact::None, ClassicFeeChoice::Explicit(800));
    assert_eq!(default.base().fee_bound_stroops(), BOUND);
    assert_eq!(explicit.base().fee_bound_stroops(), 800);
    let at = |fee: u32| {
        built(41, fee, MAX_TIME, None, |b| {
            b.payment(
                DESTINATION,
                StellarAmount::from_stroops(10),
                &crate::Asset::Native,
            )
            .unwrap();
        })
    };
    let fee = CanonicalRefusal::Mismatch(CanonicalPart::Fee);
    assert_eq!(
        match_envelope(&at(BOUND), &check(&default))
            .unwrap()
            .fee_stroops,
        BOUND
    );
    assert_eq!(refusal(&at(BOUND + 1), &default), fee);
    assert!(match_envelope(&at(800), &check(&explicit)).is_ok());
    assert_eq!(refusal(&at(801), &explicit), fee);
    let tighter = CanonicalCheck {
        fee_cap_stroops: 799,
        ..check(&explicit)
    };
    assert_eq!(match_envelope(&at(800), &tighter).unwrap_err(), fee);
    assert!(match_envelope(&at(799), &tighter).is_ok());
}

/// The deadline follows the mainnet deadline check at the check time: a
/// deadline 120 seconds out passes, one second more refuses, as do a V2
/// precondition, a nonzero minimum and a deadline inside the send margin.
#[test]
fn canonical_deadline_uses_check_time() {
    use MainnetPrecondition as P;
    let stored = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::None,
    );
    let now_s = NOW_MS / 1000;
    let with_cond = |cond: Preconditions| {
        edited(
            &pay_envelope(DESTINATION, &crate::Asset::Native, 10, None),
            |envelope| {
                tx_of(envelope).cond = cond;
            },
        )
    };
    let bounds = |min: u64, max: u64| {
        Preconditions::Time(TimeBounds {
            min_time: TimePoint(min),
            max_time: TimePoint(max),
        })
    };
    assert_eq!(
        match_envelope(&with_cond(bounds(0, now_s + 120)), &check(&stored))
            .unwrap()
            .max_time_s,
        now_s + 120
    );
    let v2 = Preconditions::V2(PreconditionsV2 {
        time_bounds: Some(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(now_s + 90),
        }),
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: stellar_xdr::Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: Default::default(),
    });
    for (name, cond, expected) in [
        (
            "over the ceiling",
            bounds(0, now_s + 121),
            P::DeadlineTooFar,
        ),
        ("far future", bounds(0, u64::MAX), P::DeadlineTooFar),
        ("v2", v2, P::DeadlineMissing),
        ("no bounds", Preconditions::None, P::DeadlineMissing),
        ("nonzero minimum", bounds(1, now_s + 90), P::DeadlineMissing),
        (
            "inside the margin",
            bounds(0, now_s + 30),
            P::DeadlineWithinMargin,
        ),
        ("elapsed", bounds(0, now_s), P::DeadlineElapsed),
    ] {
        assert_eq!(
            refusal(&with_cond(cond), &stored),
            CanonicalRefusal::Deadline(expected),
            "{name}"
        );
    }
    assert!(match_envelope(&with_cond(bounds(0, now_s + 31)), &check(&stored)).is_ok());
}

/// Limits of each numeric field: the fee bound at `u32::MAX`, a trustline
/// limit of zero and `i64::MAX`, the largest sequence, and negative amounts
/// and limits, which no intent holds.
#[test]
fn canonical_numeric_edges() {
    use CanonicalPart as Part;
    let payload = pay_payload(DESTINATION, IntentAsset::Native, i64::MAX);
    let widest = intent_with(
        payload,
        MemoFact::Id(u64::MAX),
        ClassicFeeChoice::Explicit(u32::MAX),
    );
    let full = CanonicalCheck {
        fee_cap_stroops: u32::MAX,
        ..check(&widest)
    };
    let envelope = |sequence: i64, amount: i64| {
        built(
            sequence,
            u32::MAX,
            MAX_TIME,
            Some(Memo::Id(u64::MAX)),
            |b| {
                b.payment(
                    DESTINATION,
                    StellarAmount::from_stroops(amount),
                    &crate::Asset::Native,
                )
                .unwrap();
            },
        )
    };
    let at_max = edited(&envelope(41, i64::MAX), |envelope| {
        tx_of(envelope).seq_num = stellar_xdr::SequenceNumber(i64::MAX);
    });
    let matched = match_envelope(&at_max, &full).unwrap();
    assert_eq!(
        (matched.sequence, matched.fee_stroops),
        (i64::MAX, u32::MAX)
    );
    let negative = op_edited(&envelope(41, i64::MAX), |op| {
        let OperationBody::Payment(payment) = &mut op.body else {
            unreachable!()
        };
        payment.amount = -1;
    });
    assert_eq!(
        match_envelope(&negative, &full).unwrap_err(),
        CanonicalRefusal::Mismatch(Part::Amount)
    );

    for limit in [0, i64::MAX] {
        let trust = intent(
            IntentPayload::Trustline {
                issuer: ISSUER.to_owned(),
                code: "USDC".to_owned(),
                limit_stroops: limit,
            },
            MemoFact::None,
        );
        let envelope = intent_envelope(&trust, MAINNET_PASSPHRASE, 41, 100, MAX_TIME).unwrap();
        assert!(match_envelope(&envelope, &check(&trust)).is_ok(), "{limit}");
        let negative = op_edited(&envelope, |op| {
            let OperationBody::ChangeTrust(change) = &mut op.body else {
                unreachable!()
            };
            change.limit = -1;
        });
        assert_eq!(
            refusal(&negative, &trust),
            CanonicalRefusal::Mismatch(Part::Amount)
        );
    }
    let before_max = intent_envelope(&widest, MAINNET_PASSPHRASE, i64::MAX - 1, 100, MAX_TIME);
    assert!(before_max.is_ok());
    let at_max = std::panic::catch_unwind(|| {
        intent_envelope(&widest, MAINNET_PASSPHRASE, i64::MAX, 100, MAX_TIME)
    });
    assert!(
        matches!(&at_max, Ok(Err(error)) if error.code() == "protocol.xdr_codec_failed"),
        "{at_max:?}"
    );
}

/// The envelope of one claimable balance creation whose claimant predicate
/// nests `depth` `Not` predicates around an unconditional one.
fn nested_predicate_envelope(depth: usize) -> String {
    use base64::Engine as _;
    let flat = op_edited(&pay_envelope(DESTINATION, &usdc(), 1, None), |op| {
        op.body = OperationBody::CreateClaimableBalance(stellar_xdr::CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 1,
            claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                destination: account(1),
                predicate: ClaimPredicate::Unconditional,
            })]
            .try_into()
            .unwrap(),
        });
    });
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(flat)
        .unwrap();
    // The last twelve bytes are the unconditional predicate, the V0
    // extension and the empty signature list, each a zero word.
    let tail = bytes.split_off(bytes.len() - 12);
    assert_eq!(tail, [0; 12]);
    for _ in 0..depth {
        bytes.extend_from_slice(&[0, 0, 0, 3, 0, 0, 0, 1]);
    }
    bytes.extend_from_slice(&tail);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// An envelope nested past the decode depth bound refuses as an envelope
/// that does not decode, and a nesting that exhausts an unbounded decoder's
/// stack refuses the same way instead of aborting the process. A matching
/// envelope padded with base64 whitespace passes at the input length limit
/// and refuses one byte over it.
#[test]
fn canonical_deep_envelope_refuses_typed() {
    let stored = intent(pay_payload(DESTINATION, issued("USDC"), 1), MemoFact::None);
    for depth in [500, 4_000] {
        assert_eq!(
            refusal(&nested_predicate_envelope(depth), &stored),
            CanonicalRefusal::Mismatch(CanonicalPart::Envelope),
            "{depth}"
        );
    }
    let mut at_cap = pay_envelope(DESTINATION, &usdc(), 1, None);
    at_cap.push_str(&" ".repeat(MAX_ENVELOPE_BASE64_LEN - at_cap.len()));
    assert!(match_envelope(&at_cap, &check(&stored)).is_ok());
    at_cap.push(' ');
    assert_eq!(
        refusal(&at_cap, &stored),
        CanonicalRefusal::Mismatch(CanonicalPart::Envelope)
    );
}

/// One identity has one spelling: an asset code in another case, a short
/// code in the twelve-byte form, and an issued asset coded `XLM` are each
/// another asset than the intent's.
#[test]
fn canonical_identity_spelling_matrix() {
    use CanonicalPart as Part;
    let stored = intent(pay_payload(DESTINATION, issued("USDC"), 10), MemoFact::None);
    let valid = pay_envelope(DESTINATION, &usdc(), 10, None);
    assert!(match_envelope(&valid, &check(&stored)).is_ok());
    let lower = crate::Asset::Credit {
        code: "usdc".to_owned(),
        issuer: ISSUER.to_owned(),
    };
    let wide = op_edited(&valid, |op| {
        let OperationBody::Payment(payment) = &mut op.body else {
            unreachable!()
        };
        let mut code = [0; 12];
        code[..4].copy_from_slice(b"USDC");
        payment.asset = Asset::CreditAlphanum12(stellar_xdr::AlphaNum12 {
            asset_code: stellar_xdr::AssetCode12(code),
            issuer: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(ISSUER)
                    .unwrap()
                    .0,
            ))),
        });
    });
    for (name, envelope) in [
        ("lowercase", pay_envelope(DESTINATION, &lower, 10, None)),
        ("twelve-byte form", wide),
        (
            "native",
            pay_envelope(DESTINATION, &crate::Asset::Native, 10, None),
        ),
    ] {
        assert_eq!(
            refusal(&envelope, &stored),
            CanonicalRefusal::Mismatch(Part::Asset),
            "{name}"
        );
    }
    let xlm = intent(pay_payload(DESTINATION, issued("XLM"), 10), MemoFact::None);
    let native = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::None,
    );
    assert_ne!(xlm.digest(), native.digest());
    assert_eq!(
        refusal(
            &pay_envelope(DESTINATION, &crate::Asset::Native, 10, None),
            &xlm
        ),
        CanonicalRefusal::Mismatch(Part::Asset)
    );
}

/// The builder of a stored intent emits an envelope its matcher admits, for
/// every operation type and memo kind.
#[test]
fn intent_envelopes_match_their_intent() {
    let balance_id = format!("00000000{}", stellar_agent_core::hex::encode(&BALANCE));
    let claim = intent(
        IntentPayload::Claim {
            balance_id,
            asset: issued("USDC"),
            amount_stroops: 5,
            claimant: SOURCE.to_owned(),
        },
        MemoFact::Return([4; 32]),
    );
    let entry = balance_entry(
        Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
            asset_code: stellar_xdr::AssetCode4(*b"USDC"),
            issuer: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(ISSUER)
                    .unwrap()
                    .0,
            ))),
        }),
        5,
        vec![],
    );
    let cases = [
        intent(
            pay_payload(DESTINATION, issued("LONGCODE12AB"), 3),
            MemoFact::Text("hi".to_owned()),
        ),
        intent(
            IntentPayload::CreateAccount {
                destination: DESTINATION.to_owned(),
                starting_balance_stroops: 0,
            },
            MemoFact::Hash([5; 32]),
        ),
        intent(
            IntentPayload::Trustline {
                issuer: ISSUER.to_owned(),
                code: "USDC".to_owned(),
                limit_stroops: 9,
            },
            MemoFact::Id(0),
        ),
        claim,
    ];
    for stored in &cases {
        let envelope = intent_envelope(stored, MAINNET_PASSPHRASE, 41, 100, MAX_TIME).unwrap();
        let matched = match_envelope(
            &envelope,
            &CanonicalCheck {
                claim_entry: Some(&entry),
                ..check(stored)
            },
        )
        .unwrap();
        assert_eq!(matched.digest, stored.digest(), "{stored:?}");
        assert_eq!((matched.sequence, matched.max_time_s), (42, MAX_TIME));
    }
}

/// Refusal messages name the refused part and carry no envelope or intent
/// text, so any UTF-8 input renders safely.
#[test]
fn canonical_refusal_messages_carry_no_input() {
    let stored = intent(
        pay_payload(DESTINATION, IntentAsset::Native, 10),
        MemoFact::Text("ünï ✓ 名".to_owned()),
    );
    let envelope = pay_envelope(
        DESTINATION,
        &crate::Asset::Native,
        10,
        Some(Memo::Text(
            "ünï ✓ 名前".as_bytes().to_vec().try_into().unwrap(),
        )),
    );
    let message = refusal(&envelope, &stored).to_string();
    assert_eq!(message, "the memo differs from the stored canonical intent");
    for text in ["ünï", DESTINATION, SOURCE, &envelope] {
        assert!(!message.contains(text));
    }
}
