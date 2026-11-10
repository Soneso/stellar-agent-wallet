//! Canonical lasting facts for classic approvals.
//!
//! [`ClassicIntent`] holds an [`IntentBase`] and an [`IntentPayload`]. The base
//! binds the CAIP-2 chain, effective source, BLAKE3 policy digest, fee bound,
//! and [`MemoFact`]. [`IntentAsset`] preserves native or issuer-pinned identity.
//!
//! # Canonical layout
//!
//! The base precedes the payload; fields follow declaration order. Enum tags
//! occupy one byte, starting at zero in declaration order. Payload tags are
//! Pay 0, CreateAccount 1, Trustline 2, Claim 3. Asset tags are Native 0 and
//! Issued 1. Memo tags are None 0, Text 1, Id 2, Hash 3, Return 4.
//! Integers occupy eight big-endian bytes, with signed values in two's
//! complement and the u32 fee bound zero-extended. UTF-8 strings and byte
//! arrays carry a four-byte big-endian byte length followed by their bytes.
//! An option carries tag 0 for absence or tag 1 followed by its value.
//!
//! [`IntentDigest`] is SHA-256 of [`CLASSIC_INTENT_DIGEST_LABEL`] followed by
//! the canonical bytes, with no length prefix on either part. JSON is a
//! transport representation; deserialization validates the complete intent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::{MuxedAccount, PublicKey};

use super::witness::ApprovedKind;
use crate::policy::v1::{ActionKind, ValueLeg};
use crate::profile::caip2::Caip2;

/// Domain label for the canonical classic intent digest.
pub const CLASSIC_INTENT_DIGEST_LABEL: &[u8] = b"stellar-agent-wallet/classic-intent/v1";

/// Validated lasting facts of one classic operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawClassicIntent")]
pub struct ClassicIntent {
    base: IntentBase,
    payload: IntentPayload,
}

/// Network, source, policy, fee bound, and memo shared by classic operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawIntentBase")]
pub struct IntentBase {
    chain_id: String,
    source: String,
    #[serde(with = "wire_hex32")]
    policy_digest: [u8; 32],
    #[serde(serialize_with = "crate::wire_stroops::u32::serialize")]
    fee_bound_stroops: u32,
    memo: MemoFact,
}

/// Operation facts, validated when constructing a [`ClassicIntent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentPayload {
    /// A classic payment to a G or M account.
    Pay {
        /// Destination in its supplied canonical form.
        destination: String,
        /// Asset being sent.
        asset: IntentAsset,
        /// Positive amount in stroops.
        #[serde(
            serialize_with = "crate::wire_stroops::i64::serialize",
            deserialize_with = "deserialize_decimal"
        )]
        amount_stroops: i64,
    },
    /// Creation of a G account with a native starting balance.
    CreateAccount {
        /// New G account.
        destination: String,
        /// Nonnegative starting balance in stroops.
        #[serde(
            serialize_with = "crate::wire_stroops::i64::serialize",
            deserialize_with = "deserialize_decimal"
        )]
        starting_balance_stroops: i64,
    },
    /// An issued-asset trustline change.
    Trustline {
        /// Issuer G account.
        issuer: String,
        /// One to twelve ASCII alphanumeric characters.
        code: String,
        /// Nonnegative limit; zero removes the line, i64::MAX is unlimited.
        #[serde(
            serialize_with = "crate::wire_stroops::i64::serialize",
            deserialize_with = "deserialize_decimal"
        )]
        limit_stroops: i64,
    },
    /// An inbound claim with its ledger asset and amount.
    Claim {
        /// Lowercase hexadecimal XDR ClaimableBalanceId, 72 characters.
        balance_id: String,
        /// Asset being claimed.
        asset: IntentAsset,
        /// Positive amount in stroops.
        #[serde(
            serialize_with = "crate::wire_stroops::i64::serialize",
            deserialize_with = "deserialize_decimal"
        )]
        amount_stroops: i64,
        /// Claimant G account, equal to the effective source.
        claimant: String,
    },
}

/// A native or issuer-pinned classic asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentAsset {
    /// Native XLM.
    Native,
    /// An issued asset.
    Issued {
        /// One to twelve ASCII alphanumeric characters.
        code: String,
        /// Issuer G account.
        issuer: String,
    },
}

/// Exact typed memo facts, validated by [`IntentBase::new`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoFact {
    /// No memo.
    None,
    /// At most 28 UTF-8 bytes.
    Text(String),
    /// Unsigned identifier.
    Id(
        #[serde(
            serialize_with = "crate::wire_stroops::u64::serialize",
            deserialize_with = "deserialize_decimal"
        )]
        u64,
    ),
    /// Hash memo bytes.
    Hash(#[serde(with = "wire_hex32")] [u8; 32]),
    /// Return memo bytes.
    Return(#[serde(with = "wire_hex32")] [u8; 32]),
}

/// SHA-256 digest of a canonical classic intent and its domain label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentDigest([u8; 32]);

impl IntentDigest {
    /// Returns the digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A malformed intent fact. Errors carry no input text or wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IntentError {
    /// The chain is not a supported CAIP-2 string.
    #[error("invalid CAIP-2 chain id")]
    InvalidChainId,
    /// The source is not a G strkey.
    #[error("source must be a G strkey")]
    InvalidSource,
    /// The claimant is not a G strkey.
    #[error("claimant must be a G strkey")]
    InvalidClaimant,
    /// An issuer is not a G strkey.
    #[error("issuer must be a G strkey")]
    InvalidIssuer,
    /// The account creation destination is not a G strkey.
    #[error("account creation destination must be a G strkey")]
    InvalidCreateAccountDestination,
    /// The payment destination is not a G or M strkey.
    #[error("payment destination must be a G or M strkey")]
    InvalidPayDestination,
    /// A decoded strkey re-encodes differently.
    #[error("strkey must re-encode to the same text")]
    NonCanonicalStrkey,
    /// The asset code violates its length or character rules.
    #[error("asset code must contain 1 to 12 ASCII alphanumerics")]
    InvalidAssetCode,
    /// The balance id is not canonical lowercase XDR hex.
    #[error("balance id must be 72 lowercase hexadecimal XDR characters")]
    InvalidBalanceId,
    /// The claimant differs from the effective source.
    #[error("claimant must equal source")]
    ClaimantMismatch,
    /// Payment or claim amount is not positive.
    #[error("payment and claim amounts must be positive")]
    NonPositiveAmount,
    /// The starting balance is negative.
    #[error("starting balance must be nonnegative")]
    NegativeStartingBalance,
    /// The trustline limit is negative.
    #[error("trustline limit must be nonnegative")]
    NegativeLimit,
    /// Text memo exceeds the protocol byte limit.
    #[error("memo text must be at most 28 bytes")]
    MemoTextTooLong,
}

#[derive(Deserialize)]
struct RawClassicIntent {
    base: IntentBase,
    payload: IntentPayload,
}
#[derive(Deserialize)]
struct RawIntentBase {
    chain_id: String,
    source: String,
    #[serde(with = "wire_hex32")]
    policy_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_decimal")]
    fee_bound_stroops: u32,
    memo: MemoFact,
}
impl TryFrom<RawClassicIntent> for ClassicIntent {
    type Error = IntentError;
    fn try_from(raw: RawClassicIntent) -> Result<Self, Self::Error> {
        Self::new(raw.base, raw.payload)
    }
}
impl TryFrom<RawIntentBase> for IntentBase {
    type Error = IntentError;
    fn try_from(raw: RawIntentBase) -> Result<Self, Self::Error> {
        Self::new(
            raw.chain_id,
            raw.source,
            raw.policy_digest,
            raw.fee_bound_stroops,
            raw.memo,
        )
    }
}

fn deserialize_decimal<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    let text = String::deserialize(deserializer)?;
    let value = text.parse::<T>().map_err(serde::de::Error::custom)?;
    if value.to_string() != text {
        return Err(serde::de::Error::custom(
            "expected a canonical decimal string",
        ));
    }
    Ok(value)
}

mod wire_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::hex::encode(value))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let bytes = crate::hex::decode_hex32(&text).map_err(serde::de::Error::custom)?;
        if crate::hex::encode(&bytes) != text {
            return Err(serde::de::Error::custom(
                "expected 64 lowercase hex characters",
            ));
        }
        Ok(bytes)
    }
}

impl IntentBase {
    /// Constructs validated shared facts.
    ///
    /// # Errors
    /// Refuses an unsupported chain, malformed source, or oversized text memo.
    pub fn new(
        chain_id: String,
        source: String,
        policy_digest: [u8; 32],
        fee_bound_stroops: u32,
        memo: MemoFact,
    ) -> Result<Self, IntentError> {
        chain_id
            .parse::<Caip2>()
            .map_err(|_| IntentError::InvalidChainId)?;
        check_g(&source, IntentError::InvalidSource)?;
        if matches!(&memo, MemoFact::Text(text) if text.len() > 28) {
            return Err(IntentError::MemoTextTooLong);
        }
        Ok(Self {
            chain_id,
            source,
            policy_digest,
            fee_bound_stroops,
            memo,
        })
    }
    /// Returns the CAIP-2 chain string.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Returns the effective source G strkey.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Returns the verified policy's BLAKE3 digest.
    #[must_use]
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }
    /// Returns the largest approved fee in stroops.
    #[must_use]
    pub fn fee_bound_stroops(&self) -> u32 {
        self.fee_bound_stroops
    }
    /// Returns the typed memo.
    #[must_use]
    pub fn memo(&self) -> &MemoFact {
        &self.memo
    }
}

impl IntentPayload {
    /// Derives the operation kind from its sole stored discriminator.
    #[must_use]
    pub fn kind(&self) -> ActionKind {
        match self {
            Self::Pay { .. } => ActionKind::Payment,
            Self::CreateAccount { .. } => ActionKind::AccountCreation,
            Self::Trustline { .. } => ActionKind::Trustline,
            Self::Claim { .. } => ActionKind::Claim,
        }
    }
}

impl ClassicIntent {
    /// Validates operation facts against their shared base.
    ///
    /// # Errors
    /// Refuses malformed addresses, assets, amounts, limits, or balance ids,
    /// and a claimant that differs from the effective source.
    pub fn new(base: IntentBase, payload: IntentPayload) -> Result<Self, IntentError> {
        match &payload {
            IntentPayload::Pay {
                destination,
                asset,
                amount_stroops,
            } => {
                let encoded = PublicKey::from_string(destination)
                    .map(|key| format!("{key}"))
                    .or_else(|_| MuxedAccount::from_string(destination).map(|key| format!("{key}")))
                    .map_err(|_| IntentError::InvalidPayDestination)?;
                check_canonical(destination, &encoded)?;
                check_asset(asset)?;
                check_amount(*amount_stroops)?;
            }
            IntentPayload::CreateAccount {
                destination,
                starting_balance_stroops,
            } => {
                check_g(destination, IntentError::InvalidCreateAccountDestination)?;
                if *starting_balance_stroops < 0 {
                    return Err(IntentError::NegativeStartingBalance);
                }
            }
            IntentPayload::Trustline {
                issuer,
                code,
                limit_stroops,
            } => {
                check_g(issuer, IntentError::InvalidIssuer)?;
                check_code(code)?;
                if *limit_stroops < 0 {
                    return Err(IntentError::NegativeLimit);
                }
            }
            IntentPayload::Claim {
                balance_id,
                asset,
                amount_stroops,
                claimant,
            } => {
                // The XDR union has discriminator zero and a 32-byte hash.
                if balance_id.len() != 72
                    || !balance_id.starts_with("00000000")
                    || !balance_id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(IntentError::InvalidBalanceId);
                }
                check_asset(asset)?;
                check_amount(*amount_stroops)?;
                check_g(claimant, IntentError::InvalidClaimant)?;
                if claimant != base.source() {
                    return Err(IntentError::ClaimantMismatch);
                }
            }
        }
        Ok(Self { base, payload })
    }
    /// Returns the shared facts.
    #[must_use]
    pub fn base(&self) -> &IntentBase {
        &self.base
    }
    /// Returns the operation facts.
    #[must_use]
    pub fn payload(&self) -> &IntentPayload {
        &self.payload
    }
    /// Maps classic facts to the approval record kind.
    #[must_use]
    pub fn approved_kind(&self) -> ApprovedKind {
        match self.payload {
            IntentPayload::Pay { .. } | IntentPayload::CreateAccount { .. } => {
                ApprovedKind::Payment
            }
            IntentPayload::Trustline { .. } => ApprovedKind::Trustline,
            IntentPayload::Claim { .. } => ApprovedKind::Claim,
        }
    }
    /// Encodes the canonical layout described by this module.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, self.base.chain_id.as_bytes());
        put_bytes(&mut out, self.base.source.as_bytes());
        put_bytes(&mut out, &self.base.policy_digest);
        out.extend_from_slice(&u64::from(self.base.fee_bound_stroops).to_be_bytes());
        match &self.base.memo {
            MemoFact::None => out.push(0),
            MemoFact::Text(text) => {
                out.push(1);
                put_bytes(&mut out, text.as_bytes());
            }
            MemoFact::Id(id) => {
                out.push(2);
                out.extend_from_slice(&id.to_be_bytes());
            }
            MemoFact::Hash(hash) => {
                out.push(3);
                put_bytes(&mut out, hash);
            }
            MemoFact::Return(hash) => {
                out.push(4);
                put_bytes(&mut out, hash);
            }
        }
        match &self.payload {
            IntentPayload::Pay {
                destination,
                asset,
                amount_stroops,
            } => {
                out.push(0);
                put_bytes(&mut out, destination.as_bytes());
                put_asset(&mut out, asset);
                out.extend_from_slice(&amount_stroops.to_be_bytes());
            }
            IntentPayload::CreateAccount {
                destination,
                starting_balance_stroops,
            } => {
                out.push(1);
                put_bytes(&mut out, destination.as_bytes());
                out.extend_from_slice(&starting_balance_stroops.to_be_bytes());
            }
            IntentPayload::Trustline {
                issuer,
                code,
                limit_stroops,
            } => {
                out.push(2);
                put_bytes(&mut out, issuer.as_bytes());
                put_bytes(&mut out, code.as_bytes());
                out.extend_from_slice(&limit_stroops.to_be_bytes());
            }
            IntentPayload::Claim {
                balance_id,
                asset,
                amount_stroops,
                claimant,
            } => {
                out.push(3);
                put_bytes(&mut out, balance_id.as_bytes());
                put_asset(&mut out, asset);
                out.extend_from_slice(&amount_stroops.to_be_bytes());
                put_bytes(&mut out, claimant.as_bytes());
            }
        }
        out
    }
    /// Hashes the domain label followed directly by the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> IntentDigest {
        let mut hash = Sha256::new();
        hash.update(CLASSIC_INTENT_DIGEST_LABEL);
        hash.update(self.canonical_bytes());
        IntentDigest(hash.finalize().into())
    }
    /// Returns the claim's inbound value leg, or `None` for other operations.
    /// Pass this leg to `evaluate_with_value_full` with the caller's tool and chain.
    #[must_use]
    pub fn claim_value_leg(&self) -> Option<ValueLeg> {
        let IntentPayload::Claim {
            asset,
            amount_stroops,
            ..
        } = &self.payload
        else {
            return None;
        };
        let id = match asset {
            IntentAsset::Native => "native".to_owned(),
            IntentAsset::Issued { code, issuer } => format!("{code}:{issuer}"),
        };
        Some(ValueLeg {
            kind: ActionKind::Claim,
            amount: Some(i128::from(*amount_stroops)),
            asset: Some(id),
            destination: None,
        })
    }
}

fn check_canonical(input: &str, encoded: &str) -> Result<(), IntentError> {
    // Re-encoding pins canonical text against a laxer strkey decoder.
    if input == encoded {
        Ok(())
    } else {
        Err(IntentError::NonCanonicalStrkey)
    }
}
fn check_g(input: &str, error: IntentError) -> Result<(), IntentError> {
    let key = PublicKey::from_string(input).map_err(|_| error)?;
    check_canonical(input, &key.to_string())
}
fn check_code(code: &str) -> Result<(), IntentError> {
    if code.is_empty() || code.len() > 12 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Err(IntentError::InvalidAssetCode)
    } else {
        Ok(())
    }
}
fn check_asset(asset: &IntentAsset) -> Result<(), IntentError> {
    if let IntentAsset::Issued { code, issuer } = asset {
        check_code(code)?;
        check_g(issuer, IntentError::InvalidIssuer)?;
    }
    Ok(())
}
fn check_amount(amount: i64) -> Result<(), IntentError> {
    if amount > 0 {
        Ok(())
    } else {
        Err(IntentError::NonPositiveAmount)
    }
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    // Validated strings are bounded by protocol limits, at most 72 bytes.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn put_asset(out: &mut Vec<u8>, asset: &IntentAsset) {
    match asset {
        IntentAsset::Native => out.push(0),
        IntentAsset::Issued { code, issuer } => {
            out.push(1);
            put_bytes(out, code.as_bytes());
            put_bytes(out, issuer.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
    use super::*;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;

    use super::super::fixtures::intent::{VECTORS, fixture, vectors};

    const OTHER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    fn wire(index: usize) -> Value {
        serde_json::from_str::<Value>(VECTORS[index]).unwrap()["intent"].clone()
    }
    fn build(value: &Value) -> Result<ClassicIntent, IntentError> {
        let base: RawIntentBase = serde_json::from_value(value["base"].clone()).unwrap();
        let payload = serde_json::from_value(value["payload"].clone()).unwrap();
        ClassicIntent::new(IntentBase::try_from(base)?, payload)
    }

    #[test]
    fn golden_vectors_match_bytes_and_digest() {
        let mismatches: Vec<_> = vectors()
            .into_iter()
            .filter_map(|v| {
                let bytes = crate::hex::encode(&v.intent.canonical_bytes());
                let digest = crate::hex::encode(v.intent.digest().as_bytes());
                (bytes != v.canonical_hex || digest != v.digest_hex)
                    .then_some((v.name, bytes, digest))
            })
            .collect();
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }

    #[test]
    fn golden_vectors_cover_every_kind() {
        let mut payloads = BTreeSet::new();
        let mut memos = BTreeSet::new();
        let mut assets = BTreeSet::new();
        let mut limits = BTreeSet::new();
        let mut muxed = false;
        for v in vectors() {
            memos.insert(match v.intent.base.memo {
                MemoFact::None => 0,
                MemoFact::Text(_) => 1,
                MemoFact::Id(_) => 2,
                MemoFact::Hash(_) => 3,
                MemoFact::Return(_) => 4,
            });
            payloads.insert(match v.intent.payload {
                IntentPayload::Pay {
                    destination, asset, ..
                } => {
                    muxed |= destination.starts_with('M');
                    assets.insert(matches!(asset, IntentAsset::Issued { .. }) as u8);
                    0
                }
                IntentPayload::CreateAccount { .. } => 1,
                IntentPayload::Trustline { limit_stroops, .. } => {
                    limits.insert(limit_stroops);
                    2
                }
                IntentPayload::Claim { asset, .. } => {
                    assets.insert(matches!(asset, IntentAsset::Issued { .. }) as u8);
                    3
                }
            });
        }
        assert_eq!(payloads, BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(memos, BTreeSet::from([0, 1, 2, 3, 4]));
        assert_eq!(assets, BTreeSet::from([0, 1]));
        assert_eq!(limits, BTreeSet::from([0, i64::MAX]));
        assert!(muxed);
    }

    #[test]
    fn digest_hashes_the_label_then_the_bytes() {
        for v in vectors() {
            let mut hash = Sha256::new();
            hash.update(b"stellar-agent-wallet/classic-intent/v1");
            hash.update(v.intent.canonical_bytes());
            assert_eq!(
                v.intent.digest().as_bytes().as_slice(),
                hash.finalize().as_slice()
            );
        }
    }

    #[test]
    fn tags_count_from_zero_in_declaration_order() {
        // Both chain strings have 15 bytes and each source has 56 bytes.
        const MEMO: usize = 4 + 15 + 4 + 56 + 4 + 32 + 8;
        let expected = [
            (0, 0, 1, Some((60, 0))),
            (0, 1, 15, Some((73, 1))),
            (1, 2, 9, None),
            (2, 3, 37, None),
            (2, 4, 37, None),
            (3, 0, 1, Some((76, 0))),
            (3, 1, 10, Some((76, 1))),
        ];
        for (v, (payload, memo, memo_len, asset)) in vectors().into_iter().zip(expected) {
            let bytes = v.intent.canonical_bytes();
            assert_eq!(bytes[MEMO], memo, "{} memo", v.name);
            assert_eq!(bytes[MEMO + memo_len], payload, "{} payload", v.name);
            if let Some((offset, tag)) = asset {
                assert_eq!(bytes[MEMO + memo_len + 1 + offset], tag, "{} asset", v.name);
            }
        }
    }

    #[test]
    fn fee_bound_takes_eight_bytes() {
        let bytes = fixture("pay_issued_muxed_memo_text").canonical_bytes();
        assert_eq!(crate::hex::encode(&bytes[115..123]), "00000000ffffffff");
    }

    #[test]
    fn every_field_changes_the_digest() {
        let edits = [
            (0, "/base/chain_id", json!("stellar:mainnet")),
            (0, "/base/source", json!(OTHER)),
            (
                0,
                "/base/policy_digest",
                json!(format!("12{}", "11".repeat(31))),
            ),
            (0, "/base/fee_bound_stroops", json!("101")),
            (0, "/base/memo", json!({"text":""})),
            (1, "/base/memo/text", json!("invoice 43")),
            (2, "/base/memo/id", json!("0")),
            (
                3,
                "/base/memo/hash",
                json!(format!("23{}", "22".repeat(31))),
            ),
            (
                4,
                "/base/memo/return",
                json!(format!("34{}", "33".repeat(31))),
            ),
            (0, "/payload/pay/destination", json!(OTHER)),
            (
                0,
                "/payload/pay/asset",
                json!({"issued":{"code":"USDC","issuer":OTHER}}),
            ),
            (0, "/payload/pay/amount_stroops", json!("1")),
            (1, "/payload/pay/asset/issued/code", json!("USD")),
            (1, "/payload/pay/asset/issued/issuer", json!(OTHER)),
            (2, "/payload/create_account/destination", json!(OTHER)),
            (
                2,
                "/payload/create_account/starting_balance_stroops",
                json!("0"),
            ),
            (
                3,
                "/payload/trustline/issuer",
                wire(0)["base"]["source"].clone(),
            ),
            (3, "/payload/trustline/code", json!("USD")),
            (3, "/payload/trustline/limit_stroops", json!("1")),
            (
                5,
                "/payload/claim/balance_id",
                json!(format!("00000000{}", "0c".repeat(32))),
            ),
            (
                5,
                "/payload/claim/asset",
                json!({"issued":{"code":"USDC","issuer":OTHER}}),
            ),
            (5, "/payload/claim/amount_stroops", json!("1")),
            (5, "/payload/claim/claimant", json!(OTHER)),
            (6, "/payload/claim/asset/issued/code", json!("USD")),
            (6, "/payload/claim/asset/issued/issuer", json!(OTHER)),
        ];
        for (index, path, value) in edits {
            let mut raw = wire(index);
            let original = build(&raw).unwrap().digest();
            *raw.pointer_mut(path).unwrap() = value;
            if path.ends_with("/claimant") {
                raw["base"]["source"] = json!(OTHER);
            }
            assert_ne!(build(&raw).unwrap().digest(), original, "{index} {path}");
        }
        let pay = build(&wire(0)).unwrap();
        let create = ClassicIntent::new(
            pay.base.clone(),
            IntentPayload::CreateAccount {
                destination: wire(0)["payload"]["pay"]["destination"]
                    .as_str()
                    .unwrap()
                    .into(),
                starting_balance_stroops: 10_000_000,
            },
        )
        .unwrap();
        assert_ne!(pay.digest(), create.digest());
        let hash = fixture("trustline_removal_memo_hash");
        let mut return_base = hash.base.clone();
        return_base.memo = MemoFact::Return([0x22; 32]);
        assert_ne!(
            hash.digest(),
            ClassicIntent::new(return_base, hash.payload.clone())
                .unwrap()
                .digest()
        );
    }

    fn malformed() -> Vec<(usize, &'static str, Value, IntentError)> {
        use IntentError::*;
        let muxed = wire(1)["payload"]["pay"]["destination"].clone();
        vec![
            (
                0,
                "/base/chain_id",
                json!("stellar:futurenet"),
                InvalidChainId,
            ),
            (0, "/base/source", json!("bad"), InvalidSource),
            (0, "/base/source", muxed.clone(), InvalidSource),
            (
                0,
                "/base/source",
                json!(OTHER.to_lowercase()),
                InvalidSource,
            ),
            (0, "/base/source", json!(format!("{OTHER}=")), InvalidSource),
            (
                0,
                "/payload/pay/destination",
                json!("bad"),
                InvalidPayDestination,
            ),
            (
                0,
                "/payload/pay/destination",
                json!(OTHER.to_lowercase()),
                InvalidPayDestination,
            ),
            (
                2,
                "/payload/create_account/destination",
                muxed.clone(),
                InvalidCreateAccountDestination,
            ),
            (
                2,
                "/payload/create_account/destination",
                json!("bad"),
                InvalidCreateAccountDestination,
            ),
            (
                1,
                "/payload/pay/asset/issued/issuer",
                muxed.clone(),
                InvalidIssuer,
            ),
            (3, "/payload/trustline/issuer", json!("bad"), InvalidIssuer),
            (
                6,
                "/payload/claim/asset/issued/issuer",
                json!("bad"),
                InvalidIssuer,
            ),
            (
                1,
                "/payload/pay/asset/issued/code",
                json!(""),
                InvalidAssetCode,
            ),
            (
                1,
                "/payload/pay/asset/issued/code",
                json!("ABCDEFGHIJ123"),
                InvalidAssetCode,
            ),
            (
                3,
                "/payload/trustline/code",
                json!("ABCDEFGHIJ123"),
                InvalidAssetCode,
            ),
            (
                6,
                "/payload/claim/asset/issued/code",
                json!("ABCDEFGHIJ123"),
                InvalidAssetCode,
            ),
            (
                3,
                "/payload/trustline/code",
                json!("US-C"),
                InvalidAssetCode,
            ),
            (
                6,
                "/payload/claim/asset/issued/code",
                json!("é"),
                InvalidAssetCode,
            ),
            (
                5,
                "/payload/claim/balance_id",
                json!("00"),
                InvalidBalanceId,
            ),
            (
                5,
                "/payload/claim/balance_id",
                json!(format!("00000000{}", "0A".repeat(32))),
                InvalidBalanceId,
            ),
            (
                5,
                "/payload/claim/balance_id",
                json!(format!("00000001{}", "0a".repeat(32))),
                InvalidBalanceId,
            ),
            (
                5,
                "/payload/claim/balance_id",
                json!(format!("00000000{}", "zz".repeat(32))),
                InvalidBalanceId,
            ),
            (5, "/payload/claim/claimant", muxed, InvalidClaimant),
            (5, "/payload/claim/claimant", json!(OTHER), ClaimantMismatch),
            (
                0,
                "/payload/pay/amount_stroops",
                json!("0"),
                NonPositiveAmount,
            ),
            (
                0,
                "/payload/pay/amount_stroops",
                json!("-1"),
                NonPositiveAmount,
            ),
            (
                5,
                "/payload/claim/amount_stroops",
                json!("0"),
                NonPositiveAmount,
            ),
            (
                5,
                "/payload/claim/amount_stroops",
                json!("-1"),
                NonPositiveAmount,
            ),
            (
                2,
                "/payload/create_account/starting_balance_stroops",
                json!("-1"),
                NegativeStartingBalance,
            ),
            (
                3,
                "/payload/trustline/limit_stroops",
                json!("-1"),
                NegativeLimit,
            ),
            (1, "/base/memo/text", json!("a".repeat(29)), MemoTextTooLong),
            (1, "/base/memo/text", json!("é".repeat(15)), MemoTextTooLong),
        ]
    }

    #[test]
    fn construction_refuses_each_malformed_field() {
        for (index, path, value, error) in malformed() {
            let mut raw = wire(index);
            *raw.pointer_mut(path).unwrap() = value;
            assert_eq!(build(&raw), Err(error), "{path}");
        }
        assert_eq!(
            check_canonical("noncanonical", OTHER),
            Err(IntentError::NonCanonicalStrkey)
        );
    }

    #[test]
    fn deserialization_refuses_each_malformed_field() {
        for (index, path, value, error) in malformed() {
            let mut raw = wire(index);
            *raw.pointer_mut(path).unwrap() = value;
            let result = serde_json::from_value::<ClassicIntent>(raw).unwrap_err();
            assert!(
                result.to_string().contains(&error.to_string()),
                "{path}: {result}"
            );
        }
    }

    #[test]
    fn json_round_trips_validated_intents() {
        for (index, v) in vectors().into_iter().enumerate() {
            let json = serde_json::to_string(&v.intent).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), wire(index));
            let restored: ClassicIntent = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, v.intent);
            assert_eq!(restored.digest(), v.intent.digest());
        }
        let mut raw = wire(1);
        raw["base"]["memo"] = json!({"text":"é".repeat(14)});
        raw["payload"]["pay"]["asset"]["issued"]["code"] = json!("a1");
        assert!(build(&raw).is_ok());
    }

    #[test]
    fn intent_json_uses_wire_forms() {
        let intent = fixture("pay_issued_muxed_memo_text");
        let expected = r#"{"base":{"chain_id":"stellar:mainnet","source":"GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY","policy_digest":"1111111111111111111111111111111111111111111111111111111111111111","fee_bound_stroops":"4294967295","memo":{"text":"invoice 42"}},"payload":{"pay":{"destination":"MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU","asset":{"issued":{"code":"USDC","issuer":"GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"}},"amount_stroops":"1"}}}"#;
        assert_eq!(serde_json::to_string(&intent).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<ClassicIntent>(expected).unwrap(),
            intent
        );

        let refusals = [
            (0, "/payload/pay/amount_stroops", json!(1)),
            (5, "/payload/claim/amount_stroops", json!(1)),
            (
                2,
                "/payload/create_account/starting_balance_stroops",
                json!(0),
            ),
            (3, "/payload/trustline/limit_stroops", json!(0)),
            (0, "/base/fee_bound_stroops", json!(100)),
            (2, "/base/memo/id", json!(u64::MAX)),
            (0, "/base/policy_digest", json!("AB".repeat(32))),
            (0, "/base/policy_digest", json!([17; 32].to_vec())),
            (3, "/base/memo/hash", json!("AB".repeat(32))),
            (4, "/base/memo/return", json!("AB".repeat(32))),
            (3, "/base/memo/hash", json!([34; 32].to_vec())),
            (4, "/base/memo/return", json!([51; 32].to_vec())),
            (0, "/payload", json!({"Pay": wire(0)["payload"]["pay"]})),
            (0, "/payload/pay/asset", json!("Native")),
            (0, "/base/memo", json!("None")),
            (0, "/payload/pay/amount_stroops", json!("+1")),
            (0, "/payload/pay/amount_stroops", json!("01")),
        ];
        for (index, path, value) in refusals {
            let mut raw = wire(index);
            *raw.pointer_mut(path).unwrap() = value;
            assert!(
                serde_json::from_value::<ClassicIntent>(raw).is_err(),
                "{path}"
            );
        }
        for (index, path) in [
            (0, "/base/policy_digest"),
            (3, "/base/memo/hash"),
            (4, "/base/memo/return"),
        ] {
            let mut raw = wire(index);
            *raw.pointer_mut(path).unwrap() = json!("ab".repeat(32));
            assert!(
                serde_json::from_value::<ClassicIntent>(raw).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn a_muxed_pay_destination_keeps_its_m_form() {
        let intent = fixture("pay_issued_muxed_memo_text");
        let IntentPayload::Pay { destination, .. } = intent.payload() else {
            unreachable!()
        };
        assert_eq!(
            destination,
            wire(1)["payload"]["pay"]["destination"].as_str().unwrap()
        );
        assert!(destination.starts_with('M'));
        assert!(
            intent
                .canonical_bytes()
                .windows(destination.len())
                .any(|bytes| bytes == destination.as_bytes())
        );
    }

    #[test]
    fn claim_leg_carries_asset_and_amount() {
        for name in ["claim_native_memo_none", "claim_issued_memo_text"] {
            let intent = fixture(name);
            let (amount, asset) = if name == "claim_native_memo_none" {
                (5_000_000, "native".to_owned())
            } else {
                (
                    1,
                    "USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_owned(),
                )
            };
            assert_eq!(
                intent.claim_value_leg(),
                Some(ValueLeg {
                    kind: ActionKind::Claim,
                    amount: Some(amount),
                    asset: Some(asset),
                    destination: None
                })
            );
        }
        for v in vectors().into_iter().take(5) {
            assert_eq!(v.intent.claim_value_leg(), None);
        }
    }

    fn evaluate_claim(intent: &ClassicIntent, criterion: &str) -> crate::policy::Decision {
        use crate::policy::v1::{
            PolicyEngineV1, ValueClass, ValueEffects, canonical::canonical_bytes,
            loader::load_signed_policy_text, signature,
        };
        use crate::policy::{PolicyEngine, ToolDescriptor, ToolValueKind};
        use crate::profile::{caip2::MAINNET_PASSPHRASE, schema::Profile};
        let body = format!(
            "version = 1\nscope = \"profile:intent-test\"\n[[rules]]\nmatch = {{ tool = \"stellar_claim_commit\", chain = \"stellar:mainnet\" }}\ncriteria = [{criterion}]\ndecision = \"allow\"\n"
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let digest = signature::digest(&canonical_bytes(&body).unwrap());
        let sig = crate::hex::encode(&signature::sign(&digest, &key));
        let signed = format!("{body}\n[signature]\nowner_id = \"intent-test\"\nsig = \"{sig}\"\n");
        let doc = load_signed_policy_text(
            &signed,
            "intent-test",
            &key.verifying_key().to_bytes(),
            MAINNET_PASSPHRASE,
        )
        .unwrap();
        let engine = PolicyEngineV1::new(doc, "intent-test".into());
        let tool = ToolDescriptor {
            name: "stellar_claim_commit".into(),
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            chain_id: "stellar:mainnet".into(),
            value_kind: ToolValueKind::MovesValue,
        };
        let profile = Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "n-svc",
            "n-acct",
        )
        .build();
        engine
            .evaluate_with_value_full(
                &tool,
                &json!({}),
                &profile,
                ValueClass::Value(ValueEffects::single(intent.claim_value_leg().unwrap())),
                None,
                None,
                None,
                None,
                None,
                1_700_000_000_000,
            )
            .unwrap()
            .decision
    }

    #[test]
    fn claim_leg_outside_the_asset_allowlist_is_a_criterion_denial() {
        use crate::policy::{Decision, DenyReason};
        let intent = fixture("claim_native_memo_none");
        assert_eq!(
            evaluate_claim(
                &intent,
                &format!("{{ kind = \"asset_allowlist\", assets = [\"USDC:{OTHER}\"] }}")
            ),
            Decision::Deny(DenyReason::AssetNotAllowlisted)
        );
        assert_eq!(
            evaluate_claim(
                &intent,
                "{ kind = \"asset_allowlist\", assets = [\"native\"] }"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn claim_leg_counts_toward_no_debit_cap() {
        let mut raw = wire(5);
        raw["payload"]["claim"]["amount_stroops"] = json!("1000000000");
        assert_eq!(
            evaluate_claim(
                &build(&raw).unwrap(),
                "{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1\" }"
            ),
            crate::policy::Decision::Allow
        );
    }

    #[test]
    fn operation_and_approval_kinds_follow_the_payload() {
        let expected = [
            (ActionKind::Payment, ApprovedKind::Payment),
            (ActionKind::Payment, ApprovedKind::Payment),
            (ActionKind::AccountCreation, ApprovedKind::Payment),
            (ActionKind::Trustline, ApprovedKind::Trustline),
            (ActionKind::Trustline, ApprovedKind::Trustline),
            (ActionKind::Claim, ApprovedKind::Claim),
            (ActionKind::Claim, ApprovedKind::Claim),
        ];
        for (v, (action, approved)) in vectors().into_iter().zip(expected) {
            assert_eq!(v.intent.payload().kind(), action);
            assert_eq!(v.intent.approved_kind(), approved);
        }
    }
}
