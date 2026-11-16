//! The match of a rebuilt classic envelope against its canonical intent.
//!
//! A canonical record binds lasting facts, not one envelope. An envelope
//! rebuilt for it carries a fresh sequence, a fee at most the intent's bound
//! and the current cap, and a deadline the mainnet deadline check admits.
//! [`match_envelope`] reconstructs the payload and memo from the decoded
//! XDR, takes the chain, policy digest and fee bound from the stored intent,
//! and requires the digest of the result to equal the stored intent's digest.
//! A claim's asset and amount come from the balance entry read after consent,
//! so a changed balance refuses.

use stellar_agent_core::approval::{
    ClassicIntent, IntentAsset, IntentBase, IntentDigest, IntentPayload, MemoFact,
};
use stellar_agent_core::envelope_decode::MAX_ENVELOPE_BASE64_LEN;
use stellar_xdr::{
    Asset, ChangeTrustAsset, ClaimableBalanceEntry, ClaimableBalanceId, Memo, MuxedAccount,
    OperationBody, ReadXdr as _, TransactionEnvelope, TransactionExt,
};

use super::MainnetPrecondition;
use super::resolve::check_classic_deadline;
use crate::operation_entry::{account_strkey, asset_code, memo_fact, muxed_strkey};

/// The fact a canonical use refuses on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPart {
    /// The CAIP-2 chain.
    Chain,
    /// The signed policy digest.
    Policy,
    /// The envelope text, which does not decode.
    Envelope,
    /// A transaction envelope other than V1.
    Version,
    /// A fee-bump envelope.
    FeeBump,
    /// Signatures on an envelope that must be unsigned.
    Signatures,
    /// A transaction extension other than V0.
    Extension,
    /// The transaction source.
    Source,
    /// An operation count other than one.
    OperationCount,
    /// An operation source other than the transaction source.
    OperationSource,
    /// An operation of another type.
    Operation,
    /// The payment or account creation destination.
    Destination,
    /// The asset or trustline asset.
    Asset,
    /// The payment amount, starting balance or trustline limit.
    Amount,
    /// The claimable balance id.
    BalanceId,
    /// The asset and amount of the balance read after consent.
    ClaimFacts,
    /// The memo.
    Memo,
    /// The fee per operation.
    Fee,
}

impl CanonicalPart {
    fn name(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Policy => "policy digest",
            Self::Envelope => "envelope encoding",
            Self::Version => "envelope version",
            Self::FeeBump => "fee bump",
            Self::Signatures => "signatures",
            Self::Extension => "transaction extension",
            Self::Source => "source account",
            Self::OperationCount => "operation count",
            Self::OperationSource => "operation source",
            Self::Operation => "operation type",
            Self::Destination => "destination",
            Self::Asset => "asset",
            Self::Amount => "amount",
            Self::BalanceId => "balance id",
            Self::ClaimFacts => "claimable balance facts",
            Self::Memo => "memo",
            Self::Fee => "fee",
        }
    }
}

/// A refused use of a canonical intent. Messages carry no input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalRefusal {
    /// The record binds no canonical intent.
    #[error("the operation record binds no canonical intent")]
    NotCanonical,
    /// The stored intent is not the canonical form of a valid intent.
    #[error("the stored canonical intent is malformed")]
    Malformed,
    /// The stored intent does not hash to the digest recorded beside it.
    #[error("the stored canonical intent does not hash to its recorded digest")]
    StoredDigest,
    /// A fact differs from the stored intent or is outside its bounds.
    #[error("the {} differs from the stored canonical intent", .0.name())]
    Mismatch(CanonicalPart),
    /// The deadline fails the mainnet deadline check.
    #[error("the envelope deadline is refused: {0}")]
    Deadline(MainnetPrecondition),
}

/// What [`match_envelope`] checks an envelope against.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalCheck<'a> {
    /// The stored intent, validated against its slot.
    pub intent: &'a ClassicIntent,
    /// The current effective classic fee cap per operation.
    pub fee_cap_stroops: u32,
    /// The check time in Unix milliseconds.
    pub now_ms: u64,
    /// The balance entry read after consent, for a claim.
    pub claim_entry: Option<&'a ClaimableBalanceEntry>,
}

/// The facts of an envelope that matches its canonical intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalMatch {
    /// The digest of the intent reconstructed from the envelope.
    pub digest: IntentDigest,
    /// The envelope's sequence number.
    pub sequence: i64,
    /// The fee per operation in stroops.
    pub fee_stroops: u32,
    /// The deadline in Unix seconds.
    pub max_time_s: u64,
}

/// Matches the unsigned envelope `unsigned_envelope_b64` against
/// `check.intent`.
///
/// The text is untrusted: it is read only within
/// [`MAX_ENVELOPE_BASE64_LEN`] and the
/// [`untrusted_decode_limits`](stellar_agent_xdr_limits::untrusted_decode_limits)
/// of its length.
///
/// The envelope is an unsigned V1 transaction with a V0 extension, the
/// intent's G source, and one operation on that source. Its fee is at most
/// the intent's bound and `check.fee_cap_stroops`, and its deadline passes
/// [`check_classic_deadline`] at `check.now_ms`. The intent reconstructed
/// from its memo and operation must hash to the stored intent's digest.
///
/// # Errors
///
/// [`CanonicalRefusal::Mismatch`] naming the first refused fact, and
/// [`CanonicalRefusal::Deadline`] with the deadline check's precondition.
pub fn match_envelope(
    unsigned_envelope_b64: &str,
    check: &CanonicalCheck<'_>,
) -> Result<CanonicalMatch, CanonicalRefusal> {
    use CanonicalPart as Part;
    let stored = check.intent;
    require(
        unsigned_envelope_b64.len() <= MAX_ENVELOPE_BASE64_LEN,
        Part::Envelope,
    )?;
    let envelope = TransactionEnvelope::from_xdr_base64(
        unsigned_envelope_b64,
        stellar_agent_xdr_limits::untrusted_decode_limits(unsigned_envelope_b64.len()),
    )
    .map_err(|_| mismatch(Part::Envelope))?;
    let envelope = match envelope {
        TransactionEnvelope::Tx(envelope) => envelope,
        TransactionEnvelope::TxFeeBump(_) => return Err(mismatch(Part::FeeBump)),
        TransactionEnvelope::TxV0(_) => return Err(mismatch(Part::Version)),
    };
    require(envelope.signatures.is_empty(), Part::Signatures)?;
    let tx = envelope.tx;
    require(matches!(tx.ext, TransactionExt::V0), Part::Extension)?;
    let MuxedAccount::Ed25519(source_key) = &tx.source_account else {
        return Err(mismatch(Part::Source));
    };
    let source = muxed_strkey(&tx.source_account);
    require(source == stored.base().source(), Part::Source)?;
    let [operation] = tx.operations.as_slice() else {
        return Err(mismatch(Part::OperationCount));
    };
    require(
        operation
            .source_account
            .as_ref()
            .is_none_or(|account| account == &MuxedAccount::Ed25519(source_key.clone())),
        Part::OperationSource,
    )?;
    require(tx.fee <= stored.base().fee_bound_stroops(), Part::Fee)?;
    require(tx.fee <= check.fee_cap_stroops, Part::Fee)?;
    let max_time_s =
        check_classic_deadline(&tx.cond, check.now_ms).map_err(CanonicalRefusal::Deadline)?;
    let memo = exact_memo(&tx.memo).ok_or(mismatch(Part::Memo))?;
    let payload = payload(
        stored.payload(),
        &operation.body,
        &source,
        check.claim_entry,
    )?;
    let rebuilt = IntentBase::new(
        stored.base().chain_id().to_owned(),
        source,
        *stored.base().policy_digest(),
        stored.base().fee_bound_stroops(),
        memo.clone(),
    )
    .and_then(|base| ClassicIntent::new(base, payload.clone()))
    .map(|intent| intent.digest());
    let Some(digest) = rebuilt.ok().filter(|digest| *digest == stored.digest()) else {
        return Err(mismatch(difference(stored, &memo, &payload)));
    };
    Ok(CanonicalMatch {
        digest,
        sequence: tx.seq_num.0,
        fee_stroops: tx.fee,
        max_time_s,
    })
}

fn mismatch(part: CanonicalPart) -> CanonicalRefusal {
    CanonicalRefusal::Mismatch(part)
}

fn require(holds: bool, part: CanonicalPart) -> Result<(), CanonicalRefusal> {
    if holds { Ok(()) } else { Err(mismatch(part)) }
}

/// The memo fact of `memo`; `None` for text that is not UTF-8, which no
/// intent memo encodes.
fn exact_memo(memo: &Memo) -> Option<MemoFact> {
    match memo {
        Memo::Text(text) => std::str::from_utf8(text.as_slice())
            .ok()
            .map(|text| MemoFact::Text(text.to_owned())),
        other => Some(memo_fact(other)),
    }
}

/// The issued asset of a code and issuer. A twelve-byte code shorter than
/// five characters names no asset the network accepts, so it gives `None`.
fn exact_issued(code: &[u8], issuer: &stellar_xdr::AccountId, wide: bool) -> Option<IntentAsset> {
    let code = asset_code(code);
    (!wide || code.len() > 4).then(|| IntentAsset::Issued {
        code,
        issuer: account_strkey(issuer),
    })
}

/// The intent asset of a ledger asset, in its canonical width only: `None`
/// for a code of at most four characters in the twelve-byte form.
#[must_use]
pub fn exact_asset(asset: &Asset) -> Option<IntentAsset> {
    match asset {
        Asset::Native => Some(IntentAsset::Native),
        Asset::CreditAlphanum4(credit) => exact_issued(&credit.asset_code.0, &credit.issuer, false),
        Asset::CreditAlphanum12(credit) => exact_issued(&credit.asset_code.0, &credit.issuer, true),
    }
}

/// The payload `body` carries for an intent of `stored`'s type, with a
/// claim's asset and amount from `claim_entry`.
fn payload(
    stored: &IntentPayload,
    body: &OperationBody,
    source: &str,
    claim_entry: Option<&ClaimableBalanceEntry>,
) -> Result<IntentPayload, CanonicalRefusal> {
    use CanonicalPart as Part;
    Ok(match (stored, body) {
        (IntentPayload::Pay { .. }, OperationBody::Payment(payment)) => IntentPayload::Pay {
            destination: muxed_strkey(&payment.destination),
            asset: exact_asset(&payment.asset).ok_or(mismatch(Part::Asset))?,
            amount_stroops: payment.amount,
        },
        (IntentPayload::CreateAccount { .. }, OperationBody::CreateAccount(create)) => {
            IntentPayload::CreateAccount {
                destination: account_strkey(&create.destination),
                starting_balance_stroops: create.starting_balance,
            }
        }
        (IntentPayload::Trustline { .. }, OperationBody::ChangeTrust(change)) => {
            let asset = match &change.line {
                ChangeTrustAsset::CreditAlphanum4(credit) => {
                    exact_issued(&credit.asset_code.0, &credit.issuer, false)
                }
                ChangeTrustAsset::CreditAlphanum12(credit) => {
                    exact_issued(&credit.asset_code.0, &credit.issuer, true)
                }
                ChangeTrustAsset::Native | ChangeTrustAsset::PoolShare(_) => None,
            };
            let Some(IntentAsset::Issued { code, issuer }) = asset else {
                return Err(mismatch(Part::Asset));
            };
            IntentPayload::Trustline {
                issuer,
                code,
                limit_stroops: change.limit,
            }
        }
        (IntentPayload::Claim { .. }, OperationBody::ClaimClaimableBalance(claim)) => {
            let entry = claim_entry
                .filter(|entry| entry.balance_id == claim.balance_id)
                .ok_or(mismatch(Part::ClaimFacts))?;
            let ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) = &claim.balance_id;
            IntentPayload::Claim {
                balance_id: format!("00000000{}", stellar_agent_core::hex::encode(&hash.0)),
                asset: exact_asset(&entry.asset).ok_or(mismatch(Part::ClaimFacts))?,
                amount_stroops: entry.amount,
                claimant: source.to_owned(),
            }
        }
        _ => return Err(mismatch(Part::Operation)),
    })
}

/// The first fact in which `memo` and `payload` differ from `stored`.
fn difference(stored: &ClassicIntent, memo: &MemoFact, payload: &IntentPayload) -> CanonicalPart {
    use CanonicalPart as Part;
    use IntentPayload as P;
    let checks = match (stored.payload(), payload) {
        (
            P::Pay {
                destination: d0,
                asset: a0,
                amount_stroops: n0,
            },
            P::Pay {
                destination,
                asset,
                amount_stroops,
            },
        ) => [
            (d0 != destination, Part::Destination),
            (a0 != asset, Part::Asset),
            (n0 != amount_stroops, Part::Amount),
        ],
        (
            P::CreateAccount {
                destination: d0,
                starting_balance_stroops: n0,
            },
            P::CreateAccount {
                destination,
                starting_balance_stroops,
            },
        ) => [
            (d0 != destination, Part::Destination),
            (n0 != starting_balance_stroops, Part::Amount),
            (false, Part::Operation),
        ],
        (
            P::Trustline {
                issuer: i0,
                code: c0,
                limit_stroops: n0,
            },
            P::Trustline {
                issuer,
                code,
                limit_stroops,
            },
        ) => [
            (i0 != issuer || c0 != code, Part::Asset),
            (n0 != limit_stroops, Part::Amount),
            (false, Part::Operation),
        ],
        (
            P::Claim {
                balance_id: b0,
                asset: a0,
                amount_stroops: n0,
                ..
            },
            P::Claim {
                balance_id,
                asset,
                amount_stroops,
                ..
            },
        ) => [
            (b0 != balance_id, Part::BalanceId),
            (a0 != asset || n0 != amount_stroops, Part::ClaimFacts),
            (false, Part::Operation),
        ],
        _ => return Part::Operation,
    };
    std::iter::once((memo != stored.base().memo(), Part::Memo))
        .chain(checks)
        .find_map(|(differs, part)| differs.then_some(part))
        .unwrap_or(Part::Operation)
}

#[cfg(test)]
mod tests;
