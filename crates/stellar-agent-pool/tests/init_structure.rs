//! Sandwich structure unit tests — XDR inspection pre-submit.
//!
//! Verifies that the CAP-33 sponsored-reserve sandwich builder produces:
//! - Exactly N × (Begin, Create, End) operation triples.
//! - Correct per-operation source accounts (funder for Begin/Create, channel
//!   for End).
//! - Zero starting balance on CreateAccount ops.
//!
//! Uses `assert_sandwich_structure` from `stellar_agent_pool::init`, gated
//! behind `#[cfg(any(test, feature = "test-helpers"))]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use stellar_agent_network::{ClassicOpBuilder, SoftwareSigningKey};
use stellar_agent_pool::init::assert_sandwich_structure;

// Known-valid G-strkeys verified against stellar-agent-network builder.rs tests.
// seed=[1u8;32] → GAQAA5...; seed=[2u8;32] → GBPXXOA5...
// Channel 2 uses a G-strkey from the SEP-5 test vectors (account 0, Test 1).
const FUNDER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"; // seed=[1u8;32]
const CHANNEL_1: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL"; // seed=[2u8;32]
// Different valid G-strkey for channel 2 (SEP-5 Test 1 account 0).
const CHANNEL_2: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"; // SEP-5 vector

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Build a CAP-33 sandwich for N channels and assert its XDR structure.
///
/// This helper:
/// 1. Constructs a `ClassicOpBuilder` with N × (Begin, CreateAccount, End)
///    triples.
/// 2. Signs with the funder key + one key per channel.
/// 3. Decodes the resulting envelope and calls `assert_sandwich_structure`.
async fn build_and_assert_sandwich(funder_strkey: &str, channel_strkeys: &[&str], funder_seq: i64) {
    let n = channel_strkeys.len();
    let fee_per_op: u32 = 100;
    let total_fee = fee_per_op * (n as u32 * 3);

    let mut builder =
        ClassicOpBuilder::new(funder_strkey, funder_seq, TESTNET_PASSPHRASE, total_fee);

    for channel_strkey in channel_strkeys {
        builder
            .begin_sponsoring_future_reserves(funder_strkey, channel_strkey)
            .unwrap();
        builder
            .create_account_sponsored(funder_strkey, channel_strkey)
            .unwrap();
        builder
            .end_sponsoring_future_reserves(channel_strkey)
            .unwrap();
    }

    // Sign with funder + each channel key (ephemeral; test-only).
    // Key seeds: funder=[1u8;32], channels=[2u8;32], [3u8;32], etc.
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let channel_keys: Vec<SoftwareSigningKey> = (2u8..=(n as u8 + 1))
        .map(|seed_byte| {
            let mut seed = [0u8; 32];
            seed[0] = seed_byte;
            SoftwareSigningKey::new_from_bytes(seed)
        })
        .collect();

    let mut signer_refs: Vec<&dyn stellar_agent_network::signing::Signer> =
        Vec::with_capacity(1 + n);
    signer_refs.push(&funder_key);
    for ck in &channel_keys {
        signer_refs.push(ck);
    }

    let signed_xdr = builder
        .build_and_sign_multi(&signer_refs)
        .await
        .expect("build_and_sign_multi should succeed");

    let channel_strings: Vec<String> = channel_strkeys.iter().map(|s| s.to_string()).collect();

    assert_sandwich_structure(&signed_xdr, funder_strkey, &channel_strings)
        .expect("sandwich structure must be valid");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Single-channel sandwich: 1 × (Begin, Create, End).
#[tokio::test]
async fn sandwich_single_channel_structure_valid() {
    build_and_assert_sandwich(FUNDER, &[CHANNEL_1], 100).await;
}

/// Two-channel sandwich: 2 × (Begin, Create, End) = 6 ops.
#[tokio::test]
async fn sandwich_two_channels_structure_valid() {
    build_and_assert_sandwich(FUNDER, &[CHANNEL_1, CHANNEL_2], 200).await;
}

/// Operation count for N=2 must be exactly 6.
#[tokio::test]
async fn sandwich_op_count_is_n_times_3() {
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    let n: usize = 2;
    let channels = &[CHANNEL_1, CHANNEL_2];
    let mut builder = ClassicOpBuilder::new(FUNDER, 300, TESTNET_PASSPHRASE, 100 * 6);

    for ch in channels {
        builder
            .begin_sponsoring_future_reserves(FUNDER, ch)
            .unwrap();
        builder.create_account_sponsored(FUNDER, ch).unwrap();
        builder.end_sponsoring_future_reserves(ch).unwrap();
    }

    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let ch2_key = SoftwareSigningKey::new_from_bytes([3u8; 32]);
    let signers: Vec<&dyn stellar_agent_network::signing::Signer> =
        vec![&funder_key, &ch1_key, &ch2_key];

    let xdr = builder.build_and_sign_multi(&signers).await.unwrap();

    let envelope = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).unwrap();
    let ops = match &envelope {
        TransactionEnvelope::Tx(v1) => v1.tx.operations.len(),
        _ => panic!("expected Tx envelope"),
    };
    assert_eq!(ops, n * 3, "op count should be {}×3={}", n, n * 3);
}

/// `build_and_sign_multi` with zero signers returns an error.
#[tokio::test]
async fn build_and_sign_multi_no_signers_returns_error() {
    let mut builder = ClassicOpBuilder::new(FUNDER, 100, TESTNET_PASSPHRASE, 100);
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_1)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_1).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_1).unwrap();

    let result = builder.build_and_sign_multi(&[]).await;
    assert!(result.is_err(), "zero signers should return an error");
}

// ─────────────────────────────────────────────────────────────────────────────
// assert_sandwich_structure — error path coverage
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err for non-base64 input.
#[test]
fn assert_sandwich_structure_invalid_xdr_returns_err() {
    let result = assert_sandwich_structure("!!not-valid-base64!!", FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "invalid base64 must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("failed to decode envelope"),
        "error must mention decode failure; got: {msg}"
    );
}

/// `assert_sandwich_structure` returns Err when the op count does not match N×3.
///
/// Build a 1-channel sandwich (3 ops) but claim N=2 (expects 6 ops).
#[tokio::test]
async fn assert_sandwich_structure_wrong_op_count_returns_err() {
    // Build a 1-channel sandwich.
    let mut builder = ClassicOpBuilder::new(FUNDER, 100, TESTNET_PASSPHRASE, 300);
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_1)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_1).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_1).unwrap();
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let xdr = builder
        .build_and_sign_multi(&[
            &funder_key as &dyn stellar_agent_network::signing::Signer,
            &ch1_key,
        ])
        .await
        .unwrap();

    // Claim N=2, but the envelope has only 3 ops (N=1).
    let result =
        assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned(), CHANNEL_2.to_owned()]);
    assert!(result.is_err(), "wrong op count must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("expected 6 ops") || msg.contains("ops"),
        "error must mention op count mismatch; got: {msg}"
    );
}

/// `assert_sandwich_structure` returns Err when the Begin op source is wrong.
///
/// Build a 1-channel sandwich then claim the funder is a different key.
#[tokio::test]
async fn assert_sandwich_structure_wrong_begin_source_returns_err() {
    let mut builder = ClassicOpBuilder::new(FUNDER, 100, TESTNET_PASSPHRASE, 300);
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_1)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_1).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_1).unwrap();
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let xdr = builder
        .build_and_sign_multi(&[
            &funder_key as &dyn stellar_agent_network::signing::Signer,
            &ch1_key,
        ])
        .await
        .unwrap();

    // Claim the funder is CHANNEL_2 (wrong source for Begin op).
    let result = assert_sandwich_structure(&xdr, CHANNEL_2, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong Begin source must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("Begin") || msg.contains("source"),
        "error must mention Begin/source mismatch; got: {msg}"
    );
}

/// `assert_sandwich_structure` returns Err when the sponsoredID in Begin is wrong.
///
/// Build a sandwich with CHANNEL_1 as the sponsored account, then assert with
/// CHANNEL_2 as the expected sponsored account.
#[tokio::test]
async fn assert_sandwich_structure_wrong_sponsored_id_returns_err() {
    let mut builder = ClassicOpBuilder::new(FUNDER, 100, TESTNET_PASSPHRASE, 300);
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_1)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_1).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_1).unwrap();
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let xdr = builder
        .build_and_sign_multi(&[
            &funder_key as &dyn stellar_agent_network::signing::Signer,
            &ch1_key,
        ])
        .await
        .unwrap();

    // The envelope has CHANNEL_1 as sponsored; claim CHANNEL_2 as expected.
    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_2.to_owned()]);
    assert!(result.is_err(), "wrong sponsoredID must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("sponsoredID") || msg.contains("Begin"),
        "error must mention sponsoredID mismatch; got: {msg}"
    );
}

/// `assert_sandwich_structure` returns Err when the channel list is supplied in
/// the wrong order (swapped channels).
///
/// Providing channels in reversed order trips the Begin sponsoredID check on the
/// first triple: the envelope has CHANNEL_1 as the sponsored account but the
/// assertion expects CHANNEL_2.
#[tokio::test]
async fn assert_sandwich_structure_swapped_channels_returns_err() {
    let mut builder = ClassicOpBuilder::new(FUNDER, 100, TESTNET_PASSPHRASE, 600);
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_1)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_1).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_1).unwrap();
    builder
        .begin_sponsoring_future_reserves(FUNDER, CHANNEL_2)
        .unwrap();
    builder.create_account_sponsored(FUNDER, CHANNEL_2).unwrap();
    builder.end_sponsoring_future_reserves(CHANNEL_2).unwrap();

    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let ch2_key = SoftwareSigningKey::new_from_bytes([3u8; 32]);
    let xdr = builder
        .build_and_sign_multi(&[
            &funder_key as &dyn stellar_agent_network::signing::Signer,
            &ch1_key,
            &ch2_key,
        ])
        .await
        .unwrap();

    // Assert with channels reversed: channel 1 expects CHANNEL_2, channel 2 expects CHANNEL_1.
    let result =
        assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_2.to_owned(), CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "swapped channel strkeys must return Err");
    // The error fires on the sponsoredID check of the Begin op (channel 0).
    let msg = result.unwrap_err();
    assert!(
        msg.contains("sponsoredID") || msg.contains("Begin"),
        "error must describe the mismatch; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw XDR construction helpers for branch coverage of assert_sandwich_structure
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a G-strkey into a raw 32-byte public-key array.
fn pk_bytes(strkey: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(strkey)
        .expect("valid G-strkey")
        .0
}

/// Build a `MuxedAccount::Ed25519` from a G-strkey.
fn muxed_from_str(strkey: &str) -> stellar_xdr::MuxedAccount {
    stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(pk_bytes(strkey)))
}

/// Build an `AccountId` from a G-strkey.
fn account_id_from_str(strkey: &str) -> stellar_xdr::AccountId {
    stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
        stellar_xdr::Uint256(pk_bytes(strkey)),
    ))
}

/// Encode a `TransactionEnvelope::Tx` with `ops` as a base64 XDR string.
///
/// `source` is the transaction source account (the funder).
fn make_v1_envelope_with_ops(source: &str, ops: Vec<stellar_xdr::Operation>) -> String {
    use stellar_xdr::{
        Limits, Memo, Preconditions, SequenceNumber, Transaction, TransactionEnvelope,
        TransactionExt, TransactionV1Envelope, WriteXdr,
    };

    let tx = Transaction {
        source_account: muxed_from_str(source),
        fee: (ops.len() as u32) * 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: ops.try_into().expect("ops within VecM cap"),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().expect("empty sigs"),
    });
    env.to_xdr_base64(Limits::none())
        .expect("XDR encode must succeed")
}

/// Build a correct Begin op with the given source and sponsored ID.
fn op_begin(source: &str, sponsored_id: &str) -> stellar_xdr::Operation {
    use stellar_xdr::{AccountId, BeginSponsoringFutureReservesOp, Operation, OperationBody};
    Operation {
        source_account: Some(muxed_from_str(source)),
        body: OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
            sponsored_id: AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::Uint256(pk_bytes(sponsored_id)),
            )),
        }),
    }
}

/// Build a correct CreateAccount op with the given source, destination, and balance.
fn op_create(source: &str, destination: &str, balance: i64) -> stellar_xdr::Operation {
    use stellar_xdr::{CreateAccountOp, Operation, OperationBody};
    Operation {
        source_account: Some(muxed_from_str(source)),
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: account_id_from_str(destination),
            starting_balance: balance,
        }),
    }
}

/// Build a correct End op with the given source.
fn op_end(source: &str) -> stellar_xdr::Operation {
    use stellar_xdr::{Operation, OperationBody};
    Operation {
        source_account: Some(muxed_from_str(source)),
        body: OperationBody::EndSponsoringFutureReserves,
    }
}

/// Build an Inflation op (wrong body; simplest op with no operands).
fn op_inflation(source: Option<&str>) -> stellar_xdr::Operation {
    use stellar_xdr::{Operation, OperationBody};
    Operation {
        source_account: source.map(muxed_from_str),
        body: OperationBody::Inflation,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TxV0 envelope
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when passed a `TxV0` (non-Tx) envelope.
///
/// The function pattern-matches on `TransactionEnvelope::Tx(v1)` and falls through
/// to the `other =>` branch for any other variant (TxV0, TxFeeBump).
#[test]
fn assert_sandwich_structure_txv0_envelope_returns_err() {
    use stellar_xdr::{
        Limits, Memo, SequenceNumber, TransactionEnvelope, TransactionV0, TransactionV0Envelope,
        TransactionV0Ext, Uint256, WriteXdr,
    };

    let env = TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256([1u8; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: vec![].try_into().expect("empty ops"),
            ext: TransactionV0Ext::V0,
        },
        signatures: vec![].try_into().expect("empty sigs"),
    });
    let xdr = env.to_xdr_base64(Limits::none()).expect("encode TxV0");

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "TxV0 envelope must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("expected Tx envelope"),
        "error must mention 'expected Tx envelope'; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Missing source_account
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[0] has no source account.
///
/// `source_strkey` returns `None` for `source_account: None`, triggering the
/// `ok_or_else` "missing source" error.
#[test]
fn assert_sandwich_structure_missing_source_returns_err() {
    use stellar_xdr::{BeginSponsoringFutureReservesOp, Operation, OperationBody};

    // op[0] has no source_account (None) — triggers the `_ => None` branch.
    let op0 = Operation {
        source_account: None,
        body: OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
            sponsored_id: account_id_from_str(CHANNEL_1),
        }),
    };
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![op0, op_create(FUNDER, CHANNEL_1, 0), op_end(CHANNEL_1)],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "missing source_account must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("missing source"),
        "error must mention 'missing source'; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong op[0] body
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[0] body is not
/// `BeginSponsoringFutureReserves`.
///
/// The source-account check for op[0] passes (source=FUNDER), but the body
/// is `Inflation`, triggering the `other =>` arm in the Begin body match.
#[test]
fn assert_sandwich_structure_wrong_begin_op_type_returns_err() {
    // op[0]: source=FUNDER (ok), body=Inflation (wrong Begin body)
    // op[1]: CreateAccount (correct — error fires before this)
    // op[2]: End (correct — error fires before this)
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_inflation(Some(FUNDER)),
            op_create(FUNDER, CHANNEL_1, 0),
            op_end(CHANNEL_1),
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong Begin op type must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("expected BeginSponsoringFutureReserves"),
        "error must mention expected op type; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong op[1] (Create) source
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[1] source is not the funder.
///
/// op[0] (Begin) passes all checks.  op[1] has source=CHANNEL_1 (wrong;
/// should be FUNDER), triggering the Create-source mismatch error.
#[test]
fn assert_sandwich_structure_wrong_create_source_returns_err() {
    // op[0]: correct Begin (source=FUNDER, sponsoredId=CHANNEL_1)
    // op[1]: wrong source — source=CHANNEL_1 instead of FUNDER
    // op[2]: not reached
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_create(CHANNEL_1, CHANNEL_1, 0), // wrong source
            op_end(CHANNEL_1),
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong Create source must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("Create") && msg.contains("source"),
        "error must mention Create/source mismatch; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong CreateAccount destination
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when the CreateAccount destination
/// does not match the expected channel strkey.
///
/// op[0] (Begin) passes.  op[1] source passes (FUNDER).  The destination is
/// CHANNEL_2 but the expected channel is CHANNEL_1.
#[test]
fn assert_sandwich_structure_wrong_create_destination_xdr_returns_err() {
    // op[1]: source=FUNDER (ok), destination=CHANNEL_2 (wrong; expected CHANNEL_1)
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_create(FUNDER, CHANNEL_2, 0), // wrong destination
            op_end(CHANNEL_1),
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong Create destination must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("Create") && msg.contains("destination"),
        "error must mention Create/destination mismatch; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-zero starting_balance
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when the CreateAccount starting_balance
/// is not zero.
///
/// op[0] and op[1] source pass; destination passes; only the balance check fails.
#[test]
fn assert_sandwich_structure_nonzero_starting_balance_returns_err() {
    // op[1]: source=FUNDER (ok), destination=CHANNEL_1 (ok), starting_balance=1_000_000 (wrong)
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_create(FUNDER, CHANNEL_1, 1_000_000), // non-zero balance
            op_end(CHANNEL_1),
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "non-zero starting_balance must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("starting_balance"),
        "error must mention starting_balance; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong op[1] body
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[1] body is not `CreateAccount`.
///
/// op[0] (Begin) passes.  op[1] has source=FUNDER (passes) but wrong body
/// (Inflation), triggering the `other =>` arm in the Create body match.
#[test]
fn assert_sandwich_structure_wrong_create_op_type_returns_err() {
    // op[1]: source=FUNDER (ok), body=Inflation (wrong CreateAccount body)
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_inflation(Some(FUNDER)), // wrong body
            op_end(CHANNEL_1),
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong Create op type must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("expected CreateAccount"),
        "error must mention expected CreateAccount; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong End source
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[2] source is not the channel.
///
/// op[0] (Begin) and op[1] (Create) pass all checks.  op[2] has source=FUNDER
/// instead of CHANNEL_1, triggering the End-source mismatch error.
#[test]
fn assert_sandwich_structure_wrong_end_source_returns_err() {
    // op[2]: source=FUNDER (wrong; should be CHANNEL_1), body=End
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_create(FUNDER, CHANNEL_1, 0),
            op_end(FUNDER), // wrong source — should be CHANNEL_1
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong End source must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("End") && msg.contains("source"),
        "error must mention End/source mismatch; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrong op[2] body
// ─────────────────────────────────────────────────────────────────────────────

/// `assert_sandwich_structure` returns Err when op[2] body is not
/// `EndSponsoringFutureReserves`.
///
/// op[0] (Begin) and op[1] (Create) pass.  op[2] has source=CHANNEL_1 (ok) but
/// wrong body (Inflation), triggering the `other =>` arm in the End body match.
#[test]
fn assert_sandwich_structure_wrong_end_op_type_returns_err() {
    // op[2]: source=CHANNEL_1 (ok), body=Inflation (wrong EndSponsoringFutureReserves body)
    let xdr = make_v1_envelope_with_ops(
        FUNDER,
        vec![
            op_begin(FUNDER, CHANNEL_1),
            op_create(FUNDER, CHANNEL_1, 0),
            op_inflation(Some(CHANNEL_1)), // wrong body
        ],
    );

    let result = assert_sandwich_structure(&xdr, FUNDER, &[CHANNEL_1.to_owned()]);
    assert!(result.is_err(), "wrong End op type must return Err");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("expected EndSponsoringFutureReserves"),
        "error must mention expected EndSponsoringFutureReserves; got: {msg}"
    );
}
