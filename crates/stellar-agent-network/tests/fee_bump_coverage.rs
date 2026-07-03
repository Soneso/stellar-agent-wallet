//! Coverage tests for `fee_bump.rs` — `FeeBumpError` code/From mappings,
//! zero-op degenerate inner tx handling, exact CAP-15 fee boundary cases,
//! signed outer tx hash via build_and_sign_fee_bump, and error codes.
//!
//! All tests exercise public API surface: `build_and_sign_fee_bump`,
//! `build_fee_bump` (pub(crate) not reachable here — exercised via the public
//! wrapper), `FeeBumpError::code()`, and `From<FeeBumpError> for WalletError`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::err_expect,
    reason = "test-only"
)]

use stellar_agent_core::error::{ProtocolError, SubmissionError, ValidationError, WalletError};
use stellar_agent_network::fee_bump::{FeeBumpError, build_and_sign_fee_bump};
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_xdr::{
    FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, Preconditions, SequenceNumber,
    TransactionEnvelope, TransactionV1Envelope, Uint256, WriteXdr,
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared test fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

// Public test keys — deterministic, NOT production keys.
const FEE_PAYER_SEED: [u8; 32] = [0x10u8; 32];
const INNER_SOURCE_SEED: [u8; 32] = [0x11u8; 32];

fn fee_payer_gstrkey() -> String {
    use stellar_strkey::ed25519::PublicKey as StrPk;
    let sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
    StrPk(sk.verifying_key().to_bytes()).to_string().to_string()
}

/// Builds a `TransactionEnvelope::Tx(v1)` XDR string with `op_count` payment
/// operations, inner fee = `per_op_fee * op_count`.
fn make_v1_xdr(op_count: u32, per_op_fee: u32) -> String {
    use stellar_xdr::{Asset, Operation, OperationBody, PaymentOp, Transaction, TransactionExt};

    let inner_pk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED)
        .verifying_key()
        .to_bytes();
    let dst_pk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED)
        .verifying_key()
        .to_bytes();

    let ops: Vec<Operation> = (0..op_count)
        .map(|_| Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dst_pk)),
                asset: Asset::Native,
                amount: 1_000_000,
            }),
        })
        .collect();

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(inner_pk)),
        fee: per_op_fee * op_count,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: ops.try_into().expect("op count within VecM cap"),
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().expect("empty sigs"),
    });
    envelope
        .to_xdr_base64(Limits::none())
        .expect("encode inner v1")
}

/// Builds a zero-op `TransactionEnvelope::Tx(v1)` XDR string.
///
/// The inner tx has zero operations (degenerate; stellar-core rejects with
/// txMISSING_OPERATION, but `validate_fee` must handle it without panicking
/// by treating effective_op_count as 1).
fn make_zero_op_v1_xdr() -> String {
    use stellar_xdr::{Transaction, TransactionExt};

    let inner_pk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED)
        .verifying_key()
        .to_bytes();

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(inner_pk)),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![].try_into().expect("empty ops"),
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![].try_into().expect("empty sigs"),
    });
    envelope
        .to_xdr_base64(Limits::none())
        .expect("encode zero-op v1")
}

/// Builds a `TransactionEnvelope::TxV0` XDR string.
fn make_v0_xdr() -> String {
    use stellar_xdr::{TransactionV0, TransactionV0Envelope, TransactionV0Ext};
    let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
        tx: TransactionV0 {
            source_account_ed25519: Uint256([0u8; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: vec![].try_into().expect("empty ops"),
            ext: TransactionV0Ext::V0,
        },
        signatures: vec![].try_into().expect("empty sigs"),
    });
    envelope.to_xdr_base64(Limits::none()).expect("encode v0")
}

/// Builds a `TransactionEnvelope::TxFeeBump` XDR string.
fn make_fee_bump_outer_xdr() -> String {
    use stellar_xdr::TransactionExt;

    let inner_pk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED)
        .verifying_key()
        .to_bytes();

    let v1_inner = TransactionV1Envelope {
        tx: stellar_xdr::Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(inner_pk)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![].try_into().expect("empty ops"),
            ext: TransactionExt::V0,
        },
        signatures: vec![].try_into().expect("empty sigs"),
    };

    let fee_payer_pk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED)
        .verifying_key()
        .to_bytes();

    let fb_env = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256(fee_payer_pk)),
            fee: 300,
            inner_tx: FeeBumpTransactionInnerTx::Tx(v1_inner),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: vec![].try_into().expect("empty sigs"),
    });
    fb_env
        .to_xdr_base64(Limits::none())
        .expect("encode fee_bump outer")
}

// ─────────────────────────────────────────────────────────────────────────────
// FeeBumpError::code() — stable codes for all variants
// ─────────────────────────────────────────────────────────────────────────────

/// Every `FeeBumpError` variant returns the correct stable wire code.
///
/// The codes are part of the public contract (`FeeBumpError::code()`);
/// callers use them for structured logging, API responses, and receipt storage.
#[test]
fn fee_bump_error_code_all_variants() {
    let cases: Vec<(&str, FeeBumpError)> = vec![
        (
            "feebump.inner_not_v1",
            FeeBumpError::InnerNotV1 {
                found: "TxV0".to_owned(),
            },
        ),
        (
            "feebump.inner_decode_failed",
            FeeBumpError::InnerDecodeFailed {
                detail: "some detail".to_owned(),
            },
        ),
        (
            "feebump.fee_below_cap15_minimum",
            FeeBumpError::FeeBelowCap15Minimum {
                supplied: 100,
                minimum: 200,
                inner_op_count: 1,
                inner_fee: 100,
            },
        ),
        (
            "feebump.fee_exceeds_policy_cap",
            FeeBumpError::FeeExceedsPolicyCap {
                supplied: 5000,
                cap: 1000,
            },
        ),
        (
            "feebump.invalid_fee_source",
            FeeBumpError::InvalidFeeSource {
                detail: "bad strkey".to_owned(),
            },
        ),
        (
            "feebump.fee_source_signer_mismatch",
            FeeBumpError::FeeSourceSignerMismatch,
        ),
        (
            "feebump.envelope_encode_failed",
            FeeBumpError::EnvelopeEncodeFailed {
                detail: "encode failed".to_owned(),
            },
        ),
        (
            "feebump.signing_failed",
            FeeBumpError::SigningFailed(WalletError::Validation(ValidationError::AddressInvalid {
                input: "signing error".to_owned(),
            })),
        ),
    ];

    for (expected_code, err) in cases {
        assert_eq!(
            err.code(),
            expected_code,
            "FeeBumpError::{:?} must have code '{}'; got '{}'",
            std::mem::discriminant(&err),
            expected_code,
            err.code()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// From<FeeBumpError> for WalletError — all conversion arms
// ─────────────────────────────────────────────────────────────────────────────

/// `FeeBumpError::InnerDecodeFailed` converts to `WalletError::Protocol(XdrCodecFailed)`.
#[test]
fn from_inner_decode_failed_yields_protocol_xdr_codec_failed() {
    let err = FeeBumpError::InnerDecodeFailed {
        detail: "bad XDR".to_owned(),
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Protocol(ProtocolError::XdrCodecFailed { .. })
        ),
        "InnerDecodeFailed must convert to WalletError::Protocol(XdrCodecFailed); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "protocol.xdr_codec_failed");
}

/// `FeeBumpError::EnvelopeEncodeFailed` converts to `WalletError::Protocol(XdrCodecFailed)`.
#[test]
fn from_envelope_encode_failed_yields_protocol_xdr_codec_failed() {
    let err = FeeBumpError::EnvelopeEncodeFailed {
        detail: "encode failed".to_owned(),
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Protocol(ProtocolError::XdrCodecFailed { .. })
        ),
        "EnvelopeEncodeFailed must convert to WalletError::Protocol(XdrCodecFailed); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "protocol.xdr_codec_failed");
}

/// `FeeBumpError::InnerNotV1` converts to `WalletError::Validation(AddressInvalid)`.
#[test]
fn from_inner_not_v1_yields_validation_address_invalid() {
    let err = FeeBumpError::InnerNotV1 {
        found: "TxV0".to_owned(),
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Validation(ValidationError::AddressInvalid { .. })
        ),
        "InnerNotV1 must convert to WalletError::Validation(AddressInvalid); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "validation.address_invalid");
}

/// `FeeBumpError::InvalidFeeSource` converts to `WalletError::Validation(AddressInvalid)`.
#[test]
fn from_invalid_fee_source_yields_validation_address_invalid() {
    let err = FeeBumpError::InvalidFeeSource {
        detail: "bad strkey".to_owned(),
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Validation(ValidationError::AddressInvalid { .. })
        ),
        "InvalidFeeSource must convert to WalletError::Validation(AddressInvalid); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "validation.address_invalid");
}

/// `FeeBumpError::FeeBelowCap15Minimum` converts to `WalletError::Submission(TxMalformed)`.
#[test]
fn from_fee_below_cap15_minimum_yields_submission_tx_malformed() {
    let err = FeeBumpError::FeeBelowCap15Minimum {
        supplied: 100,
        minimum: 200,
        inner_op_count: 1,
        inner_fee: 100,
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Submission(SubmissionError::TxMalformed { .. })
        ),
        "FeeBelowCap15Minimum must convert to WalletError::Submission(TxMalformed); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "submission.tx_malformed");
    // The detail message must mention the exact supplied and minimum values.
    let detail = format!("{wallet_err:?}");
    assert!(
        detail.contains("100") && detail.contains("200"),
        "TxMalformed detail must mention supplied=100 and minimum=200; got: {detail}"
    );
}

/// `FeeBumpError::FeeExceedsPolicyCap` converts to `WalletError::Submission(TxMalformed)`.
#[test]
fn from_fee_exceeds_policy_cap_yields_submission_tx_malformed() {
    let err = FeeBumpError::FeeExceedsPolicyCap {
        supplied: 5000,
        cap: 1000,
    };
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Submission(SubmissionError::TxMalformed { .. })
        ),
        "FeeExceedsPolicyCap must convert to WalletError::Submission(TxMalformed); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "submission.tx_malformed");
}

/// `FeeBumpError::FeeSourceSignerMismatch` converts to `WalletError::Submission(TxMalformed)`.
#[test]
fn from_fee_source_signer_mismatch_yields_submission_tx_malformed() {
    let err = FeeBumpError::FeeSourceSignerMismatch;
    let wallet_err = WalletError::from(err);
    assert!(
        matches!(
            wallet_err,
            WalletError::Submission(SubmissionError::TxMalformed { .. })
        ),
        "FeeSourceSignerMismatch must convert to WalletError::Submission(TxMalformed); got: {wallet_err:?}"
    );
    assert_eq!(wallet_err.code(), "submission.tx_malformed");
}

/// `FeeBumpError::SigningFailed(WalletError)` unwraps and propagates the inner `WalletError`.
#[test]
fn from_signing_failed_propagates_inner_wallet_error() {
    let inner = WalletError::Validation(ValidationError::AddressInvalid {
        input: "signing error payload".to_owned(),
    });
    let err = FeeBumpError::SigningFailed(inner);
    let wallet_err = WalletError::from(err);
    // Must propagate the INNER error code, not wrap it in a new outer type.
    assert_eq!(
        wallet_err.code(),
        "validation.address_invalid",
        "SigningFailed must propagate the inner WalletError code; got: {}",
        wallet_err.code()
    );
    assert!(
        matches!(
            wallet_err,
            WalletError::Validation(ValidationError::AddressInvalid { .. })
        ),
        "SigningFailed must unwrap and propagate the inner WalletError; got: {wallet_err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Zero-op degenerate inner tx — validate_fee must not panic
// ─────────────────────────────────────────────────────────────────────────────

/// A zero-op inner tx (degenerate) is handled fail-closed: validate_fee uses
/// effective_op_count=1 to avoid division by zero.
///
/// CAP-15 minimum with zero_op (treated as 1): (1+1) * max(100, ceil(100/1)) = 200.
/// Supplying 200 must succeed (even though stellar-core would reject the inner
/// as txMISSING_OPERATION — the validator does not duplicate stellar-core checks).
#[tokio::test]
async fn zero_op_inner_tx_validate_fee_uses_effective_op_count_1() {
    let zero_op_xdr = make_zero_op_v1_xdr(); // inner fee=100, op_count=0
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    // CAP-15 minimum for 0 ops (effective=1): (1+1) * max(100, ceil(100/1)) = 200.
    // Supplying 200 must succeed.
    let result = build_and_sign_fee_bump(
        &zero_op_xdr,
        &fp_g,
        200,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    assert!(
        result.is_ok(),
        "zero-op inner tx with outer_fee=200 must not panic and must succeed; got: {result:?}"
    );

    // Supplying 199 must be rejected as FeeBelowCap15Minimum.
    let result_low = build_and_sign_fee_bump(
        &zero_op_xdr,
        &fp_g,
        199,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    let err = result_low
        .err()
        .expect("zero-op inner with outer_fee=199 must return Err");
    assert_eq!(
        err.code(),
        "feebump.fee_below_cap15_minimum",
        "zero-op inner with outer_fee=199 must return FeeBelowCap15Minimum; got code: {}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CAP-15 fee minimum — exact boundary at op_count=1, high inner fee rate
// ─────────────────────────────────────────────────────────────────────────────

/// For 1 op with inner_fee=300, rate=300 > 100, cap15_min = (1+1)*300 = 600.
/// Supplying 599 is rejected; 600 succeeds.
#[tokio::test]
async fn cap15_minimum_1op_high_fee_rate_boundary() {
    let inner_xdr = make_v1_xdr(1, 300); // 1 op, inner_fee = 300
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    // cap15_min = (1+1) * max(100, ceil(300/1)) = 2 * 300 = 600
    let result_low = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        599,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;
    let err = result_low.err().expect("599 must be rejected");
    assert_eq!(
        err.code(),
        "feebump.fee_below_cap15_minimum",
        "outer_fee=599 must be rejected (cap15_min=600); code: {}",
        err.code()
    );

    // Exact minimum passes.
    let result_ok = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        600,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;
    assert!(
        result_ok.is_ok(),
        "outer_fee=600 must satisfy cap15_min=600; got: {result_ok:?}"
    );
}

/// For 3 ops with inner_fee=900 (rate=300), cap15_min = (3+1)*300 = 1200.
/// Supplying 1199 is rejected; 1200 succeeds.
#[tokio::test]
async fn cap15_minimum_3op_rate_based_boundary() {
    let inner_xdr = make_v1_xdr(3, 300); // 3 ops, inner_fee = 900
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    // cap15_min = (3+1) * max(100, ceil(900/3)) = 4 * 300 = 1200
    let result_low = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        1199,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;
    let err = result_low.err().expect("1199 must be rejected");
    assert_eq!(
        err.code(),
        "feebump.fee_below_cap15_minimum",
        "outer_fee=1199 must be rejected (cap15_min=1200); code: {}",
        err.code()
    );

    let result_ok = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        1200,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;
    assert!(
        result_ok.is_ok(),
        "outer_fee=1200 must satisfy cap15_min=1200; got: {result_ok:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Outer hash changes when network passphrase changes
// ─────────────────────────────────────────────────────────────────────────────

/// The same inner envelope + fee produces a DIFFERENT signed outer tx under a
/// different network passphrase.
///
/// The outer `TransactionSignaturePayload` embeds `SHA-256(network_passphrase)`
/// as `network_id`.  Two calls with different passphrases sign different payloads
/// — the resulting signed envelopes differ.
#[tokio::test]
async fn outer_hash_differs_under_different_network_passphrase() {
    use stellar_xdr::ReadXdr;

    let inner_xdr = make_v1_xdr(1, 100);
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let testnet_xdr = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        300,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await
    .expect("testnet signing must succeed");

    let pubnet_xdr = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        300,
        100_000,
        PUBNET_PASSPHRASE,
        &fee_payer,
    )
    .await
    .expect("pubnet signing must succeed");

    // Different passphrases → different outer transaction signature payloads →
    // different signatures → different base64 XDR outputs.
    assert_ne!(
        testnet_xdr, pubnet_xdr,
        "different network passphrases must produce different signed outer envelopes"
    );

    // Both must decode as TxFeeBump and share the same inner tx body.
    let testnet_env = TransactionEnvelope::from_xdr_base64(&testnet_xdr, Limits::none())
        .expect("decode testnet outer");
    let pubnet_env = TransactionEnvelope::from_xdr_base64(&pubnet_xdr, Limits::none())
        .expect("decode pubnet outer");

    let testnet_inner = match testnet_env {
        TransactionEnvelope::TxFeeBump(ref fb) => match &fb.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(v1) => v1.tx.fee,
        },
        _ => panic!("expected TxFeeBump"),
    };
    let pubnet_inner = match pubnet_env {
        TransactionEnvelope::TxFeeBump(ref fb) => match &fb.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(v1) => v1.tx.fee,
        },
        _ => panic!("expected TxFeeBump"),
    };

    // The inner tx fee field is identical regardless of network passphrase.
    assert_eq!(
        testnet_inner, pubnet_inner,
        "inner tx fee must be equal regardless of passphrase (inner is not re-encoded)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid fee_source string rejected before signing
// ─────────────────────────────────────────────────────────────────────────────

/// An entirely invalid (non-strkey) `fee_source` string returns `InvalidFeeSource`
/// before the signer is called.
#[tokio::test]
async fn build_and_sign_rejects_invalid_fee_source_before_signing() {
    let inner_xdr = make_v1_xdr(1, 100);
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let result = build_and_sign_fee_bump(
        &inner_xdr,
        "NOTAVALIDSTRKEY!!!",
        300,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    let err = result.err().expect("invalid fee_source must return Err");
    assert_eq!(
        err.code(),
        "feebump.invalid_fee_source",
        "invalid fee_source must return InvalidFeeSource code; got: {}",
        err.code()
    );
    assert!(
        matches!(err, FeeBumpError::InvalidFeeSource { .. }),
        "invalid fee_source must return FeeBumpError::InvalidFeeSource; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy cap exactly equal to outer_fee — boundary condition
// ─────────────────────────────────────────────────────────────────────────────

/// When `outer_fee_stroops == policy_fee_cap_stroops` exactly, the fee is
/// accepted (the condition is `> cap`, not `>= cap`).
#[tokio::test]
async fn outer_fee_exactly_equal_to_policy_cap_is_accepted() {
    let inner_xdr = make_v1_xdr(1, 100); // cap15_min = 200
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    // outer_fee == policy_cap: must be accepted.
    let result = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        5000,
        5000, // cap == supplied
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    assert!(
        result.is_ok(),
        "outer_fee == policy_cap must be accepted (condition is >, not >=); got: {result:?}"
    );
}

/// When `outer_fee_stroops == policy_fee_cap_stroops + 1`, the fee is rejected.
#[tokio::test]
async fn outer_fee_one_above_policy_cap_is_rejected() {
    let inner_xdr = make_v1_xdr(1, 100);
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let result = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        5001,
        5000, // cap = 5000, supplied = 5001
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    let err = result.err().expect("fee one above cap must be rejected");
    assert_eq!(
        err.code(),
        "feebump.fee_exceeds_policy_cap",
        "fee one above cap must return FeeExceedsPolicyCap; got: {}",
        err.code()
    );
    assert!(
        matches!(
            err,
            FeeBumpError::FeeExceedsPolicyCap {
                supplied: 5001,
                cap: 5000,
            }
        ),
        "FeeExceedsPolicyCap fields must match supplied=5001, cap=5000; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// FeeBelowCap15Minimum carries exact inner_op_count and inner_fee fields
// ─────────────────────────────────────────────────────────────────────────────

/// `FeeBelowCap15Minimum` error carries the exact `inner_op_count` and
/// `inner_fee` values from the inner tx, for diagnostics.
#[tokio::test]
async fn fee_below_cap15_minimum_carries_exact_inner_metadata() {
    let inner_xdr = make_v1_xdr(3, 200); // 3 ops, inner_fee = 600
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    // cap15_min = (3+1) * max(100, ceil(600/3)) = 4 * 200 = 800
    let result = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        799,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    let err = result.err().expect("outer_fee=799 must be rejected");
    match err {
        FeeBumpError::FeeBelowCap15Minimum {
            supplied,
            minimum,
            inner_op_count,
            inner_fee,
        } => {
            assert_eq!(supplied, 799, "supplied must be 799; got: {supplied}");
            assert_eq!(minimum, 800, "minimum must be 800 (4*200); got: {minimum}");
            assert_eq!(
                inner_op_count, 3,
                "inner_op_count must be 3; got: {inner_op_count}"
            );
            assert_eq!(inner_fee, 600, "inner_fee must be 600; got: {inner_fee}");
        }
        other => panic!("expected FeeBelowCap15Minimum, got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TxFeeBump as inner is rejected via build_and_sign_fee_bump (CAP-15 guard)
// ─────────────────────────────────────────────────────────────────────────────

/// Passing a `TxFeeBump` envelope as `inner_envelope_xdr` to
/// `build_and_sign_fee_bump` is rejected with `InnerNotV1 { found: "TxFeeBump" }`.
#[tokio::test]
async fn build_and_sign_rejects_fee_bump_as_inner() {
    let outer_xdr = make_fee_bump_outer_xdr();
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let result = build_and_sign_fee_bump(
        &outer_xdr, // TxFeeBump, not Tx(V1)
        &fp_g,
        500,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await;

    let err = result.err().expect("TxFeeBump as inner must be rejected");
    assert_eq!(err.code(), "feebump.inner_not_v1");
    match err {
        FeeBumpError::InnerNotV1 { found } => {
            assert_eq!(
                found, "TxFeeBump",
                "InnerNotV1.found must be 'TxFeeBump'; got: {found}"
            );
        }
        other => panic!("expected InnerNotV1; got: {other:?}"),
    }
}

/// Passing a `TxV0` envelope as `inner_envelope_xdr` is rejected with
/// `InnerNotV1 { found: "TxV0" }`.
#[tokio::test]
async fn build_and_sign_rejects_v0_as_inner() {
    let v0_xdr = make_v0_xdr();
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let result =
        build_and_sign_fee_bump(&v0_xdr, &fp_g, 300, 100_000, TESTNET_PASSPHRASE, &fee_payer).await;

    let err = result.err().expect("TxV0 as inner must be rejected");
    assert_eq!(err.code(), "feebump.inner_not_v1");
    match err {
        FeeBumpError::InnerNotV1 { found } => {
            assert_eq!(
                found, "TxV0",
                "InnerNotV1.found must be 'TxV0'; got: {found}"
            );
        }
        other => panic!("expected InnerNotV1; got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signed fee-bump XDR round-trips to same outer fee
// ─────────────────────────────────────────────────────────────────────────────

/// The signed outer fee-bump envelope decodes to the exact `outer_fee_stroops`
/// supplied.  The fee field is stored verbatim in the `FeeBumpTransaction` body.
#[tokio::test]
async fn signed_outer_envelope_fee_field_matches_supplied() {
    use stellar_xdr::ReadXdr;

    let inner_xdr = make_v1_xdr(2, 100); // 2 ops, inner_fee=200, cap15_min=300
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);
    let supplied_fee: i64 = 750;

    let signed_xdr = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        supplied_fee,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await
    .expect("build_and_sign_fee_bump must succeed");

    let envelope =
        TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none()).expect("decode");
    let fb_env = match envelope {
        TransactionEnvelope::TxFeeBump(fb) => fb,
        _ => panic!("expected TxFeeBump"),
    };

    assert_eq!(
        fb_env.tx.fee, supplied_fee,
        "fee field in signed outer envelope must match supplied_fee={supplied_fee}; got: {}",
        fb_env.tx.fee
    );

    // The inner_tx must carry the same operation count as the original inner.
    let inner_op_count = match &fb_env.tx.inner_tx {
        FeeBumpTransactionInnerTx::Tx(v1) => v1.tx.operations.len(),
    };
    assert_eq!(
        inner_op_count, 2,
        "inner tx must have 2 operations; got: {inner_op_count}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Signed outer signature covers outer payload, not inner tx
// ─────────────────────────────────────────────────────────────────────────────

/// Changing only the outer_fee_stroops produces a DIFFERENT outer signature but
/// the SAME inner tx content.
///
/// The fee-payer signs the outer `FeeBumpTransaction` body (which includes the
/// fee field).  Two envelopes that differ only in `outer_fee_stroops` must have
/// different outer signatures.
#[tokio::test]
async fn different_fees_produce_different_outer_signatures() {
    use stellar_xdr::ReadXdr;

    let inner_xdr = make_v1_xdr(1, 100);
    let fp_g = fee_payer_gstrkey();
    let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let xdr_300 = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        300,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await
    .expect("fee=300 must succeed");

    let xdr_500 = build_and_sign_fee_bump(
        &inner_xdr,
        &fp_g,
        500,
        100_000,
        TESTNET_PASSPHRASE,
        &fee_payer,
    )
    .await
    .expect("fee=500 must succeed");

    assert_ne!(
        xdr_300, xdr_500,
        "different outer fees must produce different signed outer envelopes"
    );

    // Both outer envelopes carry exactly one outer signature.
    for (fee, xdr) in [(300, &xdr_300), (500, &xdr_500)] {
        let env = TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).expect("decode");
        let sigs = match env {
            TransactionEnvelope::TxFeeBump(ref fb) => fb.signatures.len(),
            _ => panic!("expected TxFeeBump"),
        };
        assert_eq!(
            sigs, 1,
            "outer envelope (fee={fee}) must have exactly 1 signature; got: {sigs}"
        );
    }
}
