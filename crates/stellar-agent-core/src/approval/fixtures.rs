//! Test fixtures: classic pending approvals whose stored summary agrees with
//! their envelope.
//!
//! Compiled only under `#[cfg(test)]` or the `test-helpers` feature. Every
//! approval surface decodes a classic entry from its envelope and refuses an
//! entry whose stored digest is not the digest of that envelope, so a test
//! that attests or renders such an entry needs a real envelope. These
//! builders encode one: a single-operation `TransactionV1Envelope` whose
//! values are the arguments, and the matching pending entry.

#![allow(
    clippy::expect_used,
    clippy::too_many_arguments,
    reason = "test fixtures: a malformed argument is a bug in the calling test"
)]

use stellar_xdr::{
    AccountId, AlphaNum4, AlphaNum12, Asset, AssetCode4, AssetCode12, ChangeTrustAsset,
    ChangeTrustOp, ClaimClaimableBalanceOp, ClaimableBalanceId, Hash, Limits, Memo, MuxedAccount,
    Operation, OperationBody, PaymentOp, Preconditions, PublicKey, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

use super::store::PendingApproval;

fn account_bytes(g_strkey: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g_strkey)
        .expect("fixture account is a G-strkey")
        .0
}

fn account_id(g_strkey: &str) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_bytes(
        g_strkey,
    ))))
}

/// `"XLM"` or `"CODE:Gissuer"` as an XDR asset.
fn asset(asset: &str) -> Asset {
    if asset == "XLM" {
        return Asset::Native;
    }
    let (code, issuer) = asset.split_once(':').expect("asset is CODE:ISSUER");
    let issuer = account_id(issuer);
    if code.len() <= 4 {
        let mut bytes = [0u8; 4];
        bytes[..code.len()].copy_from_slice(code.as_bytes());
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(bytes),
            issuer,
        })
    } else {
        let mut bytes = [0u8; 12];
        bytes[..code.len()].copy_from_slice(code.as_bytes());
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(bytes),
            issuer,
        })
    }
}

fn memo(text: Option<&str>) -> Memo {
    text.map_or(Memo::None, |text| {
        Memo::Text(
            text.as_bytes()
                .to_vec()
                .try_into()
                .expect("memo text within 28 bytes"),
        )
    })
}

/// Encodes a single-operation v1 envelope with `source` as the transaction
/// source and no operation source.
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn envelope(source: &str, body: OperationBody, memo: Memo, fee: u32, seq_num: i64) -> String {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(account_bytes(source))),
            fee,
            seq_num: SequenceNumber(seq_num),
            cond: Preconditions::None,
            memo,
            operations: vec![Operation {
                source_account: None,
                body,
            }]
            .try_into()
            .expect("one operation"),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .expect("fixture envelope encodes")
}

/// A `Payment` envelope.
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn payment_envelope(
    source: &str,
    destination: &str,
    asset_id: &str,
    amount_stroops: i64,
    memo_text: Option<&str>,
    fee: u32,
    seq_num: i64,
) -> String {
    envelope(
        source,
        OperationBody::Payment(PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256(account_bytes(destination))),
            asset: asset(asset_id),
            amount: amount_stroops,
        }),
        memo(memo_text),
        fee,
        seq_num,
    )
}

/// A `ChangeTrust` envelope; `limit_stroops` `None` is the unlimited limit.
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn change_trust_envelope(
    holder: &str,
    asset_code: &str,
    asset_issuer: &str,
    limit_stroops: Option<i64>,
    fee: u32,
    seq_num: i64,
) -> String {
    let line = match asset(&format!("{asset_code}:{asset_issuer}")) {
        Asset::CreditAlphanum4(a) => ChangeTrustAsset::CreditAlphanum4(a),
        Asset::CreditAlphanum12(a) => ChangeTrustAsset::CreditAlphanum12(a),
        Asset::Native => unreachable!("a credit asset"),
    };
    envelope(
        holder,
        OperationBody::ChangeTrust(ChangeTrustOp {
            line,
            limit: limit_stroops.unwrap_or(i64::MAX),
        }),
        Memo::None,
        fee,
        seq_num,
    )
}

/// A `ClaimClaimableBalance` envelope for the balance whose 32-byte hash is
/// `balance_hash`.
///
/// # Panics
///
/// Panics when the source is not a G-strkey.
#[must_use]
pub fn claim_envelope(source: &str, balance_hash: [u8; 32], fee: u32, seq_num: i64) -> String {
    envelope(
        source,
        OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
            balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(balance_hash)),
        }),
        Memo::None,
        fee,
        seq_num,
    )
}

/// The canonical 72-hex id and the `B...` strkey of the balance whose hash is
/// `balance_hash`.
#[must_use]
pub fn balance_ids(balance_hash: [u8; 32]) -> (String, String) {
    (
        format!("00000000{}", crate::hex::encode(&balance_hash)),
        format!("{}", stellar_strkey::ClaimableBalance::V0(balance_hash)),
    )
}

/// A `PaymentSimulated` entry over [`payment_envelope`], its summary fields
/// equal to the envelope's values.
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn payment_pending(
    source: &str,
    destination: &str,
    asset_id: &str,
    amount_stroops: i64,
    memo_text: Option<&str>,
    fee: u32,
    seq_num: i64,
    process_uid: String,
    ttl_ms: u64,
) -> PendingApproval {
    let envelope = payment_envelope(
        source,
        destination,
        asset_id,
        amount_stroops,
        memo_text,
        fee,
        seq_num,
    );
    PendingApproval::new_payment_pending(
        envelope.clone(),
        envelope.as_bytes(),
        destination.to_owned(),
        amount_stroops,
        asset_id.to_owned(),
        memo_text.map(ToOwned::to_owned),
        fee,
        seq_num,
        process_uid,
        ttl_ms,
    )
    .expect("fixture payment entry")
}

/// A `TrustlineSimulated` entry over [`change_trust_envelope`].
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn trustline_pending(
    holder: &str,
    asset_code: &str,
    asset_issuer: &str,
    limit_stroops: Option<i64>,
    fee: u32,
    seq_num: i64,
    process_uid: String,
    ttl_ms: u64,
) -> PendingApproval {
    let envelope = change_trust_envelope(
        holder,
        asset_code,
        asset_issuer,
        limit_stroops,
        fee,
        seq_num,
    );
    PendingApproval::new_trustline_pending(
        envelope.clone(),
        envelope.as_bytes(),
        holder.to_owned(),
        asset_code.to_owned(),
        asset_issuer.to_owned(),
        limit_stroops,
        fee,
        seq_num,
        process_uid,
        ttl_ms,
    )
    .expect("fixture trustline entry")
}

/// A `ClaimSimulated` entry over [`claim_envelope`]; `value` is the stored
/// asset and amount, which the envelope does not carry.
///
/// # Panics
///
/// Panics when an account is not a G-strkey, an asset is not `"XLM"` or
/// `"CODE:Gissuer"`, or a memo exceeds 28 bytes.
#[must_use]
pub fn claim_pending(
    source: &str,
    balance_hash: [u8; 32],
    value: Option<(&str, i64)>,
    fee: u32,
    seq_num: i64,
    process_uid: String,
    ttl_ms: u64,
) -> PendingApproval {
    let envelope = claim_envelope(source, balance_hash, fee, seq_num);
    let (hex72, strkey) = balance_ids(balance_hash);
    match value {
        Some((asset_id, amount_stroops)) => PendingApproval::new_claim_pending(
            envelope.clone(),
            envelope.as_bytes(),
            hex72,
            strkey,
            asset_id.to_owned(),
            amount_stroops,
            source.to_owned(),
            fee,
            seq_num,
            process_uid,
            ttl_ms,
        ),
        None => PendingApproval::new_claim_pending_unvalued(
            envelope.clone(),
            envelope.as_bytes(),
            hex72,
            strkey,
            source.to_owned(),
            fee,
            seq_num,
            process_uid,
            ttl_ms,
        ),
    }
    .expect("fixture claim entry")
}

/// Binds the displayed terms of an MPP test entry to deterministic context
/// and challenge digests on testnet.
///
/// # Panics
///
/// Panics when the entry's challenge expiry exceeds `i64::MAX`.
#[must_use]
pub fn bind_mpp_entry(mut entry: PendingApproval) -> PendingApproval {
    use super::mpp::{MppAuthorizationContext, MppChargeTerms, authorization_fingerprint};
    use sha2::{Digest as _, Sha256};
    if let super::store::ApprovalKind::MppChargeSimulated {
        authorization_fingerprint: fingerprint,
        authorization_context,
        profile,
        payer,
        amount,
        currency,
        recipient,
        challenge_expires_at_unix,
        ..
    } = &mut entry.kind
    {
        let context = MppAuthorizationContext {
            context_digest: [0x31; 32],
            challenge_digest: [0x32; 32],
            network_passphrase_hash: Sha256::digest(
                crate::profile::caip2::TESTNET_PASSPHRASE.as_bytes(),
            )
            .into(),
        };
        *fingerprint = authorization_fingerprint(
            &MppChargeTerms {
                profile,
                payer,
                amount,
                currency,
                recipient,
                effective_expires_at_unix: i64::try_from(*challenge_expires_at_unix)
                    .expect("fixture expiry fits i64"),
            },
            &context,
        );
        *authorization_context = Some(context);
    }
    entry
}

/// An MPP entry whose displayed terms match its authorization fingerprint.
///
/// # Panics
///
/// Panics if the test clock or fixed terms are invalid.
#[must_use]
pub fn mpp_pending() -> PendingApproval {
    let now = crate::timefmt::now_unix_ms().expect("test clock");
    bind_mpp_entry(
        PendingApproval::new_mpp_charge_pending(
            [0; 32],
            [0x22; 32],
            "a".to_owned(),
            "stellar:testnet".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            "mcp".to_owned(),
            "merchant".to_owned(),
            "tools/charge".to_owned(),
            "1000000".to_owned(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            now / 1000 + 3600,
            1100,
            "1000".to_owned(),
            60_000,
        )
        .expect("valid MPP test entry"),
    )
}

/// Character ranges refused at input and escaped at display, including all Cf ranges.
pub const MEMO_CONTROL_RANGES: &[(u32, u32)] = &[
    (0, 0x1f),
    (0x7f, 0x9f),
    (0xad, 0xad),
    (0x600, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70f, 0x70f),
    (0x890, 0x891),
    (0x8e2, 0x8e2),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x2028, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
];

/// A resolved rule with distinct ordered signers, policies and authorization ids.
#[must_use]
pub fn rule_proposal_snapshot() -> super::ContextRuleProposalSnapshot {
    use super::{
        ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalPolicy,
        RuleProposalSigner,
    };
    let contract = stellar_strkey::Contract([0; 32]).to_string().to_string();
    ContextRuleProposalSnapshot::new(
        RuleProposalContextType::CallContract {
            contract: contract.clone(),
        },
        "fixture-rule".to_owned(),
        Some(100),
        vec![
            RuleProposalSigner::delegated(
                stellar_strkey::ed25519::PublicKey([1; 32])
                    .to_string()
                    .to_string(),
                true,
            ),
            RuleProposalSigner::external(contract.clone(), vec![1, 2, 3], false),
        ],
        vec![
            RuleProposalPolicy::new(contract, "AAAAAwAAAAE".to_owned()),
            RuleProposalPolicy::new(
                stellar_strkey::Contract([2; 32]).to_string().to_string(),
                "AAAAAwAAAAI".to_owned(),
            ),
        ],
        vec![1, 2],
        false,
        false,
    )
}

/// Independent mutations of every snapshot field, including optional values and order.
#[must_use]
pub fn rule_proposal_mutations() -> Vec<(&'static str, super::ContextRuleProposalSnapshot)> {
    use super::{ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSignerKind};
    type Mutation = (&'static str, fn(&mut ContextRuleProposalSnapshot));
    let mutations: &[Mutation] = &[
        ("version", |s| s.snapshot_version += 1),
        ("default context", |s| {
            s.context_type = RuleProposalContextType::Default
        }),
        ("call contract", |s| {
            s.context_type = RuleProposalContextType::CallContract {
                contract: stellar_strkey::Contract([3; 32]).to_string().to_string(),
            }
        }),
        ("create contract", |s| {
            s.context_type = RuleProposalContextType::CreateContract {
                wasm_hash_hex: "00".repeat(32),
            }
        }),
        ("wasm hash", |s| {
            s.context_type = RuleProposalContextType::CreateContract {
                wasm_hash_hex: "01".repeat(32),
            }
        }),
        ("name", |s| s.name.push('x')),
        ("expiry absent", |s| s.valid_until = None),
        ("expiry value", |s| s.valid_until = Some(101)),
        ("signer kind", |s| {
            s.signers[0].kind = RuleProposalSignerKind::External
        }),
        ("address", |s| {
            s.signers[0].address = Some(
                stellar_strkey::ed25519::PublicKey([3; 32])
                    .to_string()
                    .to_string(),
            )
        }),
        ("address absent", |s| s.signers[0].address = None),
        ("address empty", |s| {
            s.signers[1].address = Some(String::new())
        }),
        ("verifier", |s| {
            s.signers[1].verifier = Some(stellar_strkey::Contract([3; 32]).to_string().to_string())
        }),
        ("verifier absent", |s| s.signers[1].verifier = None),
        ("verifier empty", |s| {
            s.signers[0].verifier = Some(String::new())
        }),
        ("public key", |s| {
            s.signers[1].pubkey_data = Some(vec![4, 5, 6])
        }),
        ("public key absent", |s| s.signers[1].pubkey_data = None),
        ("public key empty", |s| {
            s.signers[0].pubkey_data = Some(vec![])
        }),
        ("proposer", |s| s.signers[0].is_proposer = false),
        ("signer order", |s| s.signers.swap(0, 1)),
        ("signer count", |s| {
            s.signers.pop();
        }),
        ("policy address", |s| {
            s.policies[0].policy_address = stellar_strkey::Contract([3; 32]).to_string().to_string()
        }),
        ("policy params", |s| {
            s.policies[0].params_xdr_b64 = "AAAAAwAAAAM".to_owned()
        }),
        ("policy order", |s| s.policies.swap(0, 1)),
        ("policy count", |s| {
            s.policies.pop();
        }),
        ("first id", |s| s.auth_rule_ids[0] = 3),
        ("second id", |s| s.auth_rule_ids[1] = 3),
        ("id order", |s| s.auth_rule_ids.swap(0, 1)),
        ("id count", |s| {
            s.auth_rule_ids.pop();
        }),
        ("mutable verifier", |s| s.accept_mutable_verifier = true),
        ("unknown verifier", |s| s.accept_unknown_verifier = true),
        ("both flags", |s| {
            s.accept_mutable_verifier = true;
            s.accept_unknown_verifier = true;
        }),
    ];
    mutations
        .iter()
        .map(|(name, mutate)| {
            let mut snapshot = rule_proposal_snapshot();
            mutate(&mut snapshot);
            (*name, snapshot)
        })
        .collect()
}

/// A pending rule whose digest agrees with its displayed terms.
///
/// # Panics
///
/// Panics if the fixture is invalid or the clock is unavailable.
#[must_use]
pub fn rule_proposal_pending() -> PendingApproval {
    PendingApproval::new_rule_proposal_pending(
        stellar_strkey::Contract([0; 32]).to_string().to_string(),
        crate::profile::caip2::TESTNET_PASSPHRASE.to_owned(),
        "stellar:testnet".to_owned(),
        rule_proposal_snapshot(),
        "fixture summary".to_owned(),
        "1000".to_owned(),
        60_000,
    )
    .expect("valid rule fixture")
}

/// A well-formed version 1 presence receipt with fixed bytes. It holds the
/// fixture credential's assertion over a fixed challenge at the loopback
/// origin. It is issued 5 s after `base_ms`, verified at 6 s and expires at
/// 65 s.
#[cfg(test)]
pub(crate) fn fixed_presence_receipt(base_ms: u64) -> super::presence::MainnetPresenceReceipt {
    use base64::Engine as _;
    use stellar_agent_test_support::webauthn::{FLAG_UP, FLAG_UV, fixture_authenticator};
    let origin = super::presence::mainnet_presence_origin(4100);
    let assertion = fixture_authenticator().assert(
        [7; 32],
        &origin,
        super::presence::MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "request_id": "00000000-0000-4000-8000-000000000001",
        "random_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32]),
        "policy_sequence": 7,
        "policy_digest_hex": "ab".repeat(32),
        "policy_owner_hex": "09".repeat(32),
        "expected_origin": origin,
        "issued_at_unix_ms": base_ms + 5_000,
        "expires_at_unix_ms": base_ms + 65_000,
        "verified_at_unix_ms": base_ms + 6_000,
        "assertion": {
            "credential_id": assertion.credential_id,
            "authenticator_data": assertion.authenticator_data,
            "client_data_json": assertion.client_data_json,
            "signature_compact": assertion.signature_compact,
        },
    }))
    .expect("fixed presence receipt")
}

#[cfg(test)]
pub(crate) mod intent {
    use super::super::intent::ClassicIntent;
    use serde::Deserialize;

    pub(crate) const VECTORS: [&str; 7] = [
        include_str!("intent/vectors/pay_native_memo_none.json"),
        include_str!("intent/vectors/pay_issued_muxed_memo_text.json"),
        include_str!("intent/vectors/create_account_memo_id.json"),
        include_str!("intent/vectors/trustline_removal_memo_hash.json"),
        include_str!("intent/vectors/trustline_unlimited_memo_return.json"),
        include_str!("intent/vectors/claim_native_memo_none.json"),
        include_str!("intent/vectors/claim_issued_memo_text.json"),
    ];

    #[derive(Deserialize)]
    pub(crate) struct Vector {
        pub(crate) name: String,
        pub(crate) intent: ClassicIntent,
        pub(crate) canonical_hex: String,
        pub(crate) digest_hex: String,
    }
    pub(crate) fn vectors() -> Vec<Vector> {
        VECTORS
            .iter()
            .map(|text| serde_json::from_str(text).expect("valid named intent vector"))
            .collect()
    }
    pub(crate) fn fixture(name: &str) -> ClassicIntent {
        vectors()
            .into_iter()
            .find(|v| v.name == name)
            .expect("valid named intent vector")
            .intent
    }
}
