//! Integration tests for [`stellar_agent_core::envelope_decode::decode_authoritative_args`].
//!
//! Tests verify the public API surface using XDR fixtures built entirely from
//! `stellar_xdr` types.  No external XDR builder crate is used so the
//! fixture provenance is deterministic and self-contained.
//!
//! # Fixture provenance
//!
//! All XDR envelopes are constructed with:
//! - `SOURCE_G` = canonical test G-strkey derived from seed `[1u8; 32]` via
//!   ed25519-dalek (same vector used across the workspace integration tests).
//! - `DEST_G` = second canonical test G-strkey.
//! - Memo bytes hard-coded to known UTF-8 strings.
//! - Amounts in stroops (integer, no floating-point).
//!
//! # Coverage matrix
//!
//! 1. Happy path: Payment (native XLM) with Memo::Text
//! 2. Happy path: Payment (USDC Alphanum4) with no memo
//! 3. Happy path: CreateAccount
//! 4. Source account derived from tx-level when op-level source is absent
//! 5. Source account derived from op-level when op-level source overrides tx-level
//! 6. MuxedEd25519 source resolves to G-strkey (mux-ID discarded)
//! 7. Mismatched tool → `OperationKindMismatch`
//! 8. Operation count ≠ 1 → `UnexpectedOperationCount`
//! 9. `Memo::Hash` → `MemoUnsupportedForReDerive`
//! 10. Unsupported tool name → `UnsupportedTool`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use stellar_agent_core::envelope_decode::{EnvelopeDecodeError, decode_authoritative_args};
use stellar_xdr::{
    AccountId, Asset, CreateAccountOp, Hash, Limits, Memo, MuxedAccount, MuxedAccountMed25519,
    Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, StringM,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
    WriteXdr,
};

// ─────────────────────────────────────────────────────────────────────────────
// Fixture constants
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const USDC_ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// ─────────────────────────────────────────────────────────────────────────────
// XDR fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

fn g_to_bytes(g: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g)
        .expect("valid G-strkey")
        .0
}

fn g_to_muxed(g: &str) -> MuxedAccount {
    MuxedAccount::Ed25519(Uint256(g_to_bytes(g)))
}

fn g_to_account_id(g: &str) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_to_bytes(g))))
}

fn build_tx1_envelope(tx_source: &str, op: Operation, memo: Memo) -> TransactionEnvelope {
    let tx = Transaction {
        source_account: g_to_muxed(tx_source),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo,
        operations: vec![op].try_into().expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
}

fn to_b64(env: &TransactionEnvelope) -> String {
    env.to_xdr_base64(Limits::none())
        .expect("XDR serialization must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Happy path — Payment (native XLM) with text memo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_decodes_payment_xlm_with_text_memo() {
    let op = Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: g_to_muxed(DEST_G),
            asset: Asset::Native,
            amount: 10_000_000, // 1 XLM
        }),
    };
    let memo_bytes: StringM<28> = b"hello-memo"
        .as_slice()
        .try_into()
        .expect("memo within 28 bytes");
    let env = build_tx1_envelope(SOURCE_G, op, Memo::Text(memo_bytes));
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();

    assert_eq!(result["source"].as_str().unwrap(), SOURCE_G);
    assert_eq!(result["destination"].as_str().unwrap(), DEST_G);
    assert_eq!(result["amount_stroops"].as_str().unwrap(), "10000000");
    assert_eq!(result["asset"].as_str().unwrap(), "XLM");
    assert_eq!(result["memo"].as_str().unwrap(), "hello-memo");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Happy path — Payment (USDC non-native) with no memo
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_decodes_payment_usdc_non_native() {
    use stellar_xdr::{AlphaNum4, AssetCode4};
    let mut code_bytes = [0u8; 4];
    code_bytes[..4].copy_from_slice(b"USDC");

    let op = Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: g_to_muxed(DEST_G),
            asset: Asset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(code_bytes),
                issuer: g_to_account_id(USDC_ISSUER_G),
            }),
            amount: 50_000_000, // 5 USDC
        }),
    };
    let env = build_tx1_envelope(SOURCE_G, op, Memo::None);
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();

    assert_eq!(result["source"].as_str().unwrap(), SOURCE_G);
    assert_eq!(result["destination"].as_str().unwrap(), DEST_G);
    assert_eq!(result["amount_stroops"].as_str().unwrap(), "50000000");
    let expected_asset = format!("USDC:{USDC_ISSUER_G}");
    assert_eq!(result["asset"].as_str().unwrap(), &expected_asset);
    assert!(
        result["memo"].is_null(),
        "memo should be null for Memo::None"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Happy path — CreateAccount
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_decodes_create_account() {
    let op = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: g_to_account_id(DEST_G),
            starting_balance: 20_000_000, // 2 XLM
        }),
    };
    let env = build_tx1_envelope(SOURCE_G, op, Memo::None);
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();

    assert_eq!(result["source"].as_str().unwrap(), SOURCE_G);
    assert_eq!(result["destination"].as_str().unwrap(), DEST_G);
    assert_eq!(
        result["starting_balance_stroops"].as_str().unwrap(),
        "20000000"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Source from tx-level when op-level absent
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_derives_source_from_tx_level_when_op_source_absent() {
    let op = Operation {
        source_account: None, // no op-level override
        body: OperationBody::Payment(PaymentOp {
            destination: g_to_muxed(DEST_G),
            asset: Asset::Native,
            amount: 1_000_000,
        }),
    };
    let env = build_tx1_envelope(SOURCE_G, op, Memo::None);
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
    assert_eq!(
        result["source"].as_str().unwrap(),
        SOURCE_G,
        "source must fall back to tx-level"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Op-level source overrides tx-level
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_derives_source_from_op_level_when_present() {
    let op = Operation {
        source_account: Some(g_to_muxed(DEST_G)), // op-level = DEST_G
        body: OperationBody::Payment(PaymentOp {
            destination: g_to_muxed(USDC_ISSUER_G),
            asset: Asset::Native,
            amount: 1_000_000,
        }),
    };
    // tx-level = SOURCE_G; op-level = DEST_G — op-level must win.
    let env = build_tx1_envelope(SOURCE_G, op, Memo::None);
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
    assert_eq!(
        result["source"].as_str().unwrap(),
        DEST_G,
        "op-level source must override tx-level"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: MuxedEd25519 → G-strkey (mux ID discarded)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_resolves_muxed_ed25519_source_to_g_strkey() {
    let muxed_src = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 99,
        ed25519: Uint256(g_to_bytes(SOURCE_G)),
    });
    let tx = Transaction {
        source_account: muxed_src,
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(DEST_G),
                starting_balance: 10_000_000,
            }),
        }]
        .try_into()
        .expect("single op"),
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let xdr_b64 = to_b64(&env);

    let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();
    assert_eq!(
        result["source"].as_str().unwrap(),
        SOURCE_G,
        "MuxedEd25519 must resolve to plain G-strkey; mux ID (99) must be discarded"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: Mismatched tool → OperationKindMismatch
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_returns_operation_kind_mismatch_for_wrong_tool() {
    // CreateAccount op passed as stellar_pay_commit.
    let op = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: g_to_account_id(DEST_G),
            starting_balance: 10_000_000,
        }),
    };
    let env = build_tx1_envelope(SOURCE_G, op, Memo::None);
    let xdr_b64 = to_b64(&env);

    let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
        .expect_err("must return an error");
    assert!(
        matches!(err, EnvelopeDecodeError::OperationKindMismatch { .. }),
        "expected OperationKindMismatch, got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: Operation count ≠ 1 → UnexpectedOperationCount
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_returns_unexpected_op_count_for_empty_tx() {
    let tx = Transaction {
        source_account: g_to_muxed(SOURCE_G),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::default(), // empty
        ext: TransactionExt::V0,
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let xdr_b64 = to_b64(&env);

    let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
        .expect_err("must return an error");
    assert!(
        matches!(
            err,
            EnvelopeDecodeError::UnexpectedOperationCount { count: 0 }
        ),
        "expected UnexpectedOperationCount(0), got: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: Memo::Hash → Ok(null memo)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_returns_null_memo_for_hash_memo() {
    let op = Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: g_to_muxed(DEST_G),
            asset: Asset::Native,
            amount: 10_000_000,
        }),
    };
    let env = build_tx1_envelope(SOURCE_G, op, Memo::Hash(Hash([0u8; 32])));
    let xdr_b64 = to_b64(&env);

    // Memo::Hash must return Ok with a null memo field, not an error.
    let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
        .expect("Memo::Hash must not cause a decode error");
    assert_eq!(
        result["memo"],
        serde_json::Value::Null,
        "Memo::Hash should produce null in args JSON"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: Unsupported tool name → UnsupportedTool
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn it_returns_unsupported_tool_for_unknown_tool() {
    // The XDR is irrelevant; the tool check fires before XDR decode.
    let err = decode_authoritative_args("AAAAAAAAAA==", "stellar_balances")
        .expect_err("must return UnsupportedTool");
    assert!(
        matches!(err, EnvelopeDecodeError::UnsupportedTool { .. }),
        "expected UnsupportedTool, got: {err}"
    );
}
