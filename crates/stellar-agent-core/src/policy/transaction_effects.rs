//! Decodes operations as valued on a payment route, unvalued, refused, or without a value effect.
//!
//! Account identity is the base ed25519 key, including for muxed accounts.
//! Without a wallet key, every source and fee payer counts as the wallet.
//! A fee bump carries only its outer fee effect.
//! Another source's payments and merges into the wallet, and its reserve sponsorship, carry no value effect.
//! Its claimable balances count only claimants other than that source and the wallet.
//! Its other operations retain their effective source and receive the same classification as the wallet's operations.

use stellar_xdr::{
    AccountId, ChangeTrustAsset, Claimant, ClawbackOp, CreateClaimableBalanceOp,
    FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, Operation, OperationBody, OperationType,
    PaymentOp, Preconditions, PublicKey, SetOptionsOp, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, WriteXdr,
};

use crate::envelope_decode::{
    ClassicMemo, ENVELOPE_INPUT_TOO_LONG, EnvelopeReadError, TRANSACTION_ENVELOPE_XDR_FORM,
    decode_authoritative_args, read_envelope,
};

/// A payment tool route that evaluates an operation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentRoute {
    /// A payment or path payment.
    Pay,
    /// An account's starting balance.
    CreateAccount,
    /// A trustline limit.
    Trustline,
    /// A claimable balance claim.
    Claim,
}

impl PaymentRoute {
    /// The commit tool whose rule decides an operation on this route.
    pub const fn commit_tool(self) -> &'static str {
        match self {
            Self::Pay => "stellar_pay_commit",
            Self::CreateAccount => "stellar_create_account_commit",
            Self::Trustline => "stellar_trustline_commit",
            Self::Claim => "stellar_claim_commit",
        }
    }
}

/// An operation that a payment rule evaluates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValuedOperation {
    /// The zero-based index in the signed transaction.
    pub operation_index: u32,
    /// The payment rule's route.
    pub route: PaymentRoute,
    /// The arguments `decode_authoritative_args` returns for the route's commit tool, without `chain_id`.
    pub policy_args: serde_json::Value,
    /// `None`: the engine derives the value from `policy_args`.
    pub value: Option<crate::policy::v1::value::ValueEffects>,
}

/// An effect whose amount the decoder cannot determine.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnvaluedEffect {
    /// An offer with a nonzero amount.
    Offer,
    /// A deposit into a liquidity pool.
    LiquidityPoolDeposit,
    /// Sponsorship of future reserves.
    ReserveSponsorship,
    /// A host function invocation.
    ContractInvocation,
    /// A clawback from the wallet account.
    Clawback,
}

impl UnvaluedEffect {
    /// The effect's snake_case name.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::LiquidityPoolDeposit => "liquidity_pool_deposit",
            Self::ReserveSponsorship => "reserve_sponsorship",
            Self::ContractInvocation => "contract_invocation",
            Self::Clawback => "clawback",
        }
    }
}

/// An operation with an effect whose amount remains unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnvaluedOperation {
    /// The zero-based index in the signed transaction.
    pub operation_index: u32,
    /// The effect that requires an explicit policy decision.
    pub effect: UnvaluedEffect,
}

/// An effect that no signed amount limit bounds.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedEffect {
    /// A transfer of the account's balance at execution time.
    AccountMerge,
    /// A change to signers, master weight, or thresholds.
    AuthorityChange,
}

impl RefusedEffect {
    /// The effect's snake_case name.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AccountMerge => "account_merge",
            Self::AuthorityChange => "authority_change",
        }
    }
}

/// The fee authorized by the wallet account's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeEffect {
    /// The total transaction fee in stroops.
    pub total_stroops: u64,
    /// The operation count, including the fee bump when present.
    pub operation_count: u32,
    /// The resource fee in the transaction extension, when present.
    pub resource_fee_stroops: Option<i64>,
}

/// The fee and operation effects a transaction signature authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionEffects {
    /// `Some` when the wallet account pays the fee.
    pub fee: Option<FeeEffect>,
    /// The operations evaluated through payment rules, in transaction order.
    pub valued: Vec<ValuedOperation>,
    /// The effects whose amounts remain unknown, in transaction order.
    pub unvalued: Vec<UnvaluedOperation>,
    /// The memo of a `Tx` envelope; `None` for a fee bump and for a text memo that is not UTF-8.
    pub memo: Option<ClassicMemo>,
}

impl TransactionEffects {
    /// Whether any operation has a valued or unvalued effect.
    pub fn has_value_effect(&self) -> bool {
        !self.valued.is_empty() || !self.unvalued.is_empty()
    }
}

/// A malformed envelope or an effect the decoder refuses.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionEffectsError {
    /// The envelope or its authoritative arguments cannot be decoded.
    #[error("{detail}")]
    Decode {
        /// A diagnostic that never quotes envelope bytes.
        detail: String,
    },
    /// The envelope uses the unsupported legacy format.
    #[error("legacy V0 transaction envelopes are not supported")]
    LegacyEnvelope,
    /// An operation contains a negative amount field.
    #[error("operation {operation_index} has a negative {operation_kind:?}.{field}")]
    NegativeAmount {
        /// The zero-based index of the refused operation.
        operation_index: u32,
        /// The kind of operation containing the field.
        operation_kind: OperationType,
        /// The amount field's XDR name.
        field: &'static str,
    },
    /// The first operation whose effect no signed amount limit bounds.
    #[error("operation {operation_index} has an effect no signed limit bounds: {}", effect.label())]
    Refused {
        /// The zero-based index of the refused operation.
        operation_index: u32,
        /// The effect that requires refusal.
        effect: RefusedEffect,
    },
}

fn decode_error(detail: impl Into<String>) -> TransactionEffectsError {
    TransactionEffectsError::Decode {
        detail: detail.into(),
    }
}

fn base_key(account: &MuxedAccount) -> &[u8; 32] {
    match account {
        MuxedAccount::Ed25519(key) => &key.0,
        MuxedAccount::MuxedEd25519(account) => &account.ed25519.0,
    }
}

fn account_key(account: &AccountId) -> &[u8; 32] {
    match &account.0 {
        PublicKey::PublicKeyTypeEd25519(key) => &key.0,
    }
}

fn is_wallet(account: &MuxedAccount, wallet: Option<&[u8; 32]>) -> bool {
    wallet.is_none_or(|key| base_key(account) == key)
}

fn fee_effect(
    tx: &Transaction,
    payer: &MuxedAccount,
    total_stroops: u64,
    fee_bump: bool,
    wallet: Option<&[u8; 32]>,
) -> Result<Option<FeeEffect>, TransactionEffectsError> {
    let resource_fee_stroops = match &tx.ext {
        TransactionExt::V0 => None,
        TransactionExt::V1(data) => {
            if data.resource_fee < 0 {
                return Err(decode_error("the resource fee is negative"));
            }
            Some(data.resource_fee)
        }
    };
    // The XDR vector holds at most 100 operations.
    let operation_count = tx.operations.len() as u32 + u32::from(fee_bump);
    Ok(is_wallet(payer, wallet).then_some(FeeEffect {
        total_stroops,
        operation_count,
        resource_fee_stroops,
    }))
}

fn valued_operation(
    tx: &Transaction,
    operation: &Operation,
    operation_index: u32,
    route: PaymentRoute,
) -> Result<ValuedOperation, TransactionEffectsError> {
    let single_tx = Transaction {
        source_account: tx.source_account.clone(),
        fee: tx.fee,
        seq_num: tx.seq_num.clone(),
        cond: Preconditions::None,
        memo: tx.memo.clone(),
        operations: vec![operation.clone()]
            .try_into()
            .map_err(|_| decode_error("the single operation cannot be encoded"))?,
        ext: TransactionExt::V0,
    };
    let single = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: single_tx,
        signatures: Default::default(),
    })
    .to_xdr_base64(Limits::none())
    .map_err(|_| decode_error("the single operation cannot be encoded"))?;
    #[cfg(test)]
    tests::record_derived_decode(single.len());
    let policy_args = decode_authoritative_args(&single, route.commit_tool())
        .map_err(|error| decode_error(error.to_string()))?;
    Ok(ValuedOperation {
        operation_index,
        route,
        policy_args,
        value: None,
    })
}

fn validate_amounts(tx: &Transaction) -> Result<(), TransactionEffectsError> {
    for (operation_index, operation) in (0u32..).zip(tx.operations.iter()) {
        let check = |amount: i64, field| {
            if amount < 0 {
                Err(TransactionEffectsError::NegativeAmount {
                    operation_index,
                    operation_kind: operation.body.discriminant(),
                    field,
                })
            } else {
                Ok(())
            }
        };
        match &operation.body {
            OperationBody::Payment(op) => check(op.amount, "amount")?,
            OperationBody::PathPaymentStrictReceive(op) => {
                check(op.send_max, "send_max")?;
                check(op.dest_amount, "dest_amount")?;
            }
            OperationBody::PathPaymentStrictSend(op) => {
                check(op.send_amount, "send_amount")?;
                check(op.dest_min, "dest_min")?;
            }
            OperationBody::CreateAccount(op) => check(op.starting_balance, "starting_balance")?,
            OperationBody::CreateClaimableBalance(op) => check(op.amount, "amount")?,
            OperationBody::Clawback(op) => check(op.amount, "amount")?,
            OperationBody::ManageSellOffer(op) => check(op.amount, "amount")?,
            OperationBody::ManageBuyOffer(op) => check(op.buy_amount, "buy_amount")?,
            OperationBody::CreatePassiveSellOffer(op) => check(op.amount, "amount")?,
            OperationBody::ChangeTrust(op) => check(op.limit, "limit")?,
            OperationBody::LiquidityPoolDeposit(op) => {
                check(op.max_amount_a, "max_amount_a")?;
                check(op.max_amount_b, "max_amount_b")?;
            }
            OperationBody::LiquidityPoolWithdraw(op) => {
                check(op.amount, "amount")?;
                check(op.min_amount_a, "min_amount_a")?;
                check(op.min_amount_b, "min_amount_b")?;
            }
            OperationBody::SetOptions(_)
            | OperationBody::AllowTrust(_)
            | OperationBody::AccountMerge(_)
            | OperationBody::Inflation
            | OperationBody::ManageData(_)
            | OperationBody::BumpSequence(_)
            | OperationBody::ClaimClaimableBalance(_)
            | OperationBody::BeginSponsoringFutureReserves(_)
            | OperationBody::EndSponsoringFutureReserves
            | OperationBody::RevokeSponsorship(_)
            | OperationBody::ClawbackClaimableBalance(_)
            | OperationBody::SetTrustLineFlags(_)
            | OperationBody::InvokeHostFunction(_)
            | OperationBody::ExtendFootprintTtl(_)
            | OperationBody::RestoreFootprint(_) => {}
        }
    }
    Ok(())
}

/// Decodes the fee and operation effects a caller-supplied transaction authorizes.
///
/// `wallet` identifies the profile's base account key; `None` counts every source as the wallet.
/// `network_passphrase` names the profile's network and has no effect on classic asset decoding.
///
/// # Errors
///
/// Returns an error for malformed or legacy envelopes, negative fees or amounts, empty transactions, and refused operations.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::transaction_effects::{transaction_effects, TransactionEffectsError};
///
/// let result = transaction_effects("invalid", None, "Test SDF Network ; September 2015");
/// assert!(matches!(result, Err(TransactionEffectsError::Decode { .. })));
/// ```
pub fn transaction_effects(
    envelope_xdr_b64: &str,
    wallet: Option<&[u8; 32]>,
    _network_passphrase: &str,
) -> Result<TransactionEffects, TransactionEffectsError> {
    let envelope = read_envelope(envelope_xdr_b64).map_err(|error| {
        decode_error(match error {
            EnvelopeReadError::InputTooLong => ENVELOPE_INPUT_TOO_LONG,
            EnvelopeReadError::Xdr(_) => TRANSACTION_ENVELOPE_XDR_FORM,
        })
    })?;
    let tx = match envelope {
        TransactionEnvelope::TxV0(_) => return Err(TransactionEffectsError::LegacyEnvelope),
        TransactionEnvelope::Tx(v1) => v1.tx,
        TransactionEnvelope::TxFeeBump(outer) => {
            let inner = match outer.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx,
            };
            let total = u64::try_from(outer.tx.fee)
                .map_err(|_| decode_error("the fee bump fee is negative"))?;
            if inner.operations.is_empty() {
                return Err(decode_error("the transaction holds no operation"));
            }
            let fee = fee_effect(&inner, &outer.tx.fee_source, total, true, wallet)?;
            validate_amounts(&inner)?;
            return Ok(TransactionEffects {
                fee,
                valued: Vec::new(),
                unvalued: Vec::new(),
                memo: None,
            });
        }
    };
    if tx.operations.is_empty() {
        return Err(decode_error("the transaction holds no operation"));
    }
    let memo = match &tx.memo {
        Memo::None => Some(ClassicMemo::None),
        Memo::Text(text) => std::str::from_utf8(text.as_slice())
            .ok()
            .map(|text| ClassicMemo::Text(text.to_owned())),
        Memo::Id(id) => Some(ClassicMemo::Id(*id)),
        Memo::Hash(hash) => Some(ClassicMemo::Hash(hash.0)),
        Memo::Return(hash) => Some(ClassicMemo::Return(hash.0)),
    };
    let mut effects = TransactionEffects {
        fee: fee_effect(&tx, &tx.source_account, u64::from(tx.fee), false, wallet)?,
        valued: Vec::new(),
        unvalued: Vec::new(),
        memo,
    };
    // Refuse the whole transaction before deriving any operation's value.
    validate_amounts(&tx)?;
    for (operation_index, operation) in (0u32..).zip(tx.operations.iter()) {
        decode_operation(&tx, operation, operation_index, wallet, &mut effects)?;
    }
    Ok(effects)
}

fn decode_operation(
    tx: &Transaction,
    operation: &Operation,
    operation_index: u32,
    wallet: Option<&[u8; 32]>,
    effects: &mut TransactionEffects,
) -> Result<(), TransactionEffectsError> {
    #[cfg(test)]
    tests::record_operation();
    let source = operation
        .source_account
        .as_ref()
        .unwrap_or(&tx.source_account);
    let other_source = !is_wallet(source, wallet);
    let incoming = |destination: &MuxedAccount| other_source && is_wallet(destination, wallet);
    let mut value = |route| -> Result<(), TransactionEffectsError> {
        effects
            .valued
            .push(valued_operation(tx, operation, operation_index, route)?);
        Ok(())
    };
    let mut unvalued = |effect| {
        effects.unvalued.push(UnvaluedOperation {
            operation_index,
            effect,
        });
    };
    let refuse = |effect| TransactionEffectsError::Refused {
        operation_index,
        effect,
    };
    match &operation.body {
        OperationBody::Payment(payment) => {
            if !incoming(&payment.destination) {
                value(PaymentRoute::Pay)?;
            }
        }
        OperationBody::PathPaymentStrictReceive(payment) => {
            if !incoming(&payment.destination) {
                value(PaymentRoute::Pay)?;
            }
        }
        OperationBody::PathPaymentStrictSend(payment) => {
            if !incoming(&payment.destination) {
                value(PaymentRoute::Pay)?;
            }
        }
        OperationBody::CreateAccount(_) => value(PaymentRoute::CreateAccount)?,
        OperationBody::ChangeTrust(trust) => match &trust.line {
            ChangeTrustAsset::Native
            | ChangeTrustAsset::CreditAlphanum4(_)
            | ChangeTrustAsset::CreditAlphanum12(_) => value(PaymentRoute::Trustline)?,
            ChangeTrustAsset::PoolShare(_) => {}
        },
        OperationBody::ClaimClaimableBalance(_) => value(PaymentRoute::Claim)?,
        OperationBody::CreateClaimableBalance(balance) => {
            let CreateClaimableBalanceOp {
                asset,
                amount,
                claimants,
            } = balance;
            let mut destinations: Vec<MuxedAccount> = claimants
                .iter()
                .filter_map(|claimant| {
                    let Claimant::ClaimantTypeV0(claimant) = claimant;
                    let key = account_key(&claimant.destination);
                    if key == base_key(source) || (other_source && wallet == Some(key)) {
                        None
                    } else {
                        Some(MuxedAccount::Ed25519(stellar_xdr::Uint256(*key)))
                    }
                })
                .collect();
            if destinations.is_empty() && !other_source {
                destinations.push(source.clone());
            }
            for destination in destinations {
                let payment = Operation {
                    source_account: operation.source_account.clone(),
                    body: OperationBody::Payment(PaymentOp {
                        destination,
                        asset: asset.clone(),
                        amount: *amount,
                    }),
                };
                effects.valued.push(valued_operation(
                    tx,
                    &payment,
                    operation_index,
                    PaymentRoute::Pay,
                )?);
            }
        }
        OperationBody::ManageSellOffer(offer) => {
            if offer.amount != 0 {
                unvalued(UnvaluedEffect::Offer);
            }
        }
        OperationBody::CreatePassiveSellOffer(offer) => {
            if offer.amount != 0 {
                unvalued(UnvaluedEffect::Offer);
            }
        }
        OperationBody::ManageBuyOffer(offer) => {
            if offer.buy_amount != 0 {
                unvalued(UnvaluedEffect::Offer);
            }
        }
        OperationBody::LiquidityPoolDeposit(_) => unvalued(UnvaluedEffect::LiquidityPoolDeposit),
        OperationBody::BeginSponsoringFutureReserves(_) => {
            if !other_source {
                unvalued(UnvaluedEffect::ReserveSponsorship);
            }
        }
        OperationBody::InvokeHostFunction(_) => unvalued(UnvaluedEffect::ContractInvocation),
        OperationBody::AccountMerge(destination) => {
            if !incoming(destination) {
                return Err(refuse(RefusedEffect::AccountMerge));
            }
        }
        OperationBody::SetOptions(options) => {
            let SetOptionsOp {
                inflation_dest: _,
                clear_flags: _,
                set_flags: _,
                master_weight,
                low_threshold,
                med_threshold,
                high_threshold,
                home_domain: _,
                signer,
            } = options;
            if signer.is_some()
                || master_weight.is_some()
                || low_threshold.is_some()
                || med_threshold.is_some()
                || high_threshold.is_some()
            {
                return Err(refuse(RefusedEffect::AuthorityChange));
            }
        }
        OperationBody::Clawback(clawback) => {
            let ClawbackOp {
                asset: _,
                from,
                amount: _,
            } = clawback;
            if is_wallet(from, wallet) {
                unvalued(UnvaluedEffect::Clawback);
            }
        }
        OperationBody::ManageData(_)
        | OperationBody::BumpSequence(_)
        | OperationBody::Inflation
        | OperationBody::AllowTrust(_)
        | OperationBody::SetTrustLineFlags(_)
        | OperationBody::ClawbackClaimableBalance(_)
        | OperationBody::EndSponsoringFutureReserves
        | OperationBody::RevokeSponsorship(_)
        | OperationBody::LiquidityPoolWithdraw(_)
        | OperationBody::ExtendFootprintTtl(_)
        | OperationBody::RestoreFootprint(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions and fixtures"
    )]

    use super::*;
    use stellar_xdr::*;

    const TESTNET: &str = "Test SDF Network ; September 2015";
    const WALLET: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];
    const THIRD: [u8; 32] = [3; 32];

    std::thread_local! {
        static WORK: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) };
    }

    pub(super) fn record_operation() {
        WORK.update(|(operations, calls, bytes)| (operations + 1, calls, bytes));
    }

    pub(super) fn record_derived_decode(len: usize) {
        WORK.update(|(operations, calls, bytes)| (operations, calls + 1, bytes + len));
    }

    fn account(key: [u8; 32]) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key)))
    }

    fn muxed(key: [u8; 32], id: Option<u64>) -> MuxedAccount {
        match id {
            Some(id) => MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id,
                ed25519: Uint256(key),
            }),
            None => MuxedAccount::Ed25519(Uint256(key)),
        }
    }

    fn strkey(key: [u8; 32]) -> String {
        stellar_strkey::ed25519::PublicKey(key)
            .to_string()
            .as_str()
            .to_owned()
    }

    fn operation(body: OperationBody) -> Operation {
        Operation {
            source_account: None,
            body,
        }
    }

    fn transaction(operations: Vec<Operation>) -> Transaction {
        Transaction {
            source_account: muxed(WALLET, None),
            fee: 1234,
            seq_num: SequenceNumber(7),
            operations: operations.try_into().unwrap(),
            ..Default::default()
        }
    }

    fn envelope(tx: &Transaction) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: Default::default(),
        })
    }

    fn fee_bump(tx: &Transaction, payer: MuxedAccount, fee: i64) -> TransactionEnvelope {
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: payer,
                fee,
                inner_tx: FeeBumpTransactionInnerTx::Tx(TransactionV1Envelope {
                    tx: tx.clone(),
                    signatures: Default::default(),
                }),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        })
    }

    fn encode(envelope: &TransactionEnvelope) -> String {
        envelope.to_xdr_base64(Limits::none()).unwrap()
    }

    fn decode(tx: &Transaction) -> TransactionEffects {
        let result = transaction_effects(&encode(&envelope(tx)), Some(&WALLET), TESTNET);
        assert!(result.is_ok(), "transaction decodes: {result:?}");
        result.unwrap()
    }

    fn empty(effects: &TransactionEffects) {
        assert!(effects.valued.is_empty(), "valued effects are empty");
        assert!(effects.unvalued.is_empty(), "unvalued effects are empty");
        assert!(!effects.has_value_effect());
    }

    fn payment(destination: MuxedAccount) -> OperationBody {
        OperationBody::Payment(PaymentOp {
            destination,
            asset: Asset::Native,
            amount: 900,
        })
    }

    fn balance(claimants: &[[u8; 32]]) -> OperationBody {
        OperationBody::CreateClaimableBalance(CreateClaimableBalanceOp {
            asset: Asset::Native,
            amount: 7654,
            claimants: claimants
                .iter()
                .map(|key| {
                    Claimant::ClaimantTypeV0(ClaimantV0 {
                        destination: account(*key),
                        predicate: ClaimPredicate::Unconditional,
                    })
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        })
    }

    fn footprint(keys: usize) -> TransactionExt {
        TransactionExt::V1(SorobanTransactionData {
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![
                        LedgerKey::Account(LedgerKeyAccount {
                            account_id: account(OTHER),
                        });
                        keys
                    ]
                    .try_into()
                    .unwrap(),
                    read_write: Default::default(),
                },
                ..Default::default()
            },
            ..Default::default()
        })
    }

    #[test]
    fn derived_payment_work_is_independent_of_the_envelope_footprint() {
        let claimants: Vec<_> = (10..20).map(|byte| [byte; 32]).collect();
        let mut tx = transaction(vec![operation(balance(&claimants)); 100]);
        let mut work = Vec::new();
        for keys in [0, 20_000] {
            tx.ext = if keys == 0 {
                TransactionExt::V0
            } else {
                footprint(keys)
            };
            let encoded = encode(&envelope(&tx));
            if keys != 0 {
                assert_eq!(encoded.len(), 1_128_672);
            }
            WORK.set((0, 0, 0));
            let effects = transaction_effects(&encoded, Some(&WALLET), TESTNET).unwrap();
            assert_eq!(effects.valued.len(), 1000);
            assert!(effects.unvalued.is_empty());
            let counts = WORK.get();
            assert_eq!(counts.0, 100);
            assert_eq!(counts.1, 1000);
            assert!(counts.2 <= 256_000, "derived decode bytes: {}", counts.2);
            work.push(counts);
        }
        assert_eq!(work[0], work[1]);
    }

    #[test]
    fn input_and_collection_bounds_refuse_before_operation_work() {
        use crate::envelope_decode::{EnvelopeReadError, MAX_ENVELOPE_BASE64_LEN};
        use base64::Engine as _;

        let tx = transaction(vec![operation(balance(&[OTHER]))]);
        let encoded = encode(&envelope(&tx));
        let mut at_cap = encoded.clone();
        at_cap.push_str(&" ".repeat(MAX_ENVELOPE_BASE64_LEN - encoded.len()));
        assert!(transaction_effects(&at_cap, Some(&WALLET), TESTNET).is_ok());
        for text in [
            format!("{at_cap} "),
            "!".repeat(MAX_ENVELOPE_BASE64_LEN + 1),
        ] {
            WORK.set((0, 0, 0));
            assert_eq!(
                transaction_effects(&text, Some(&WALLET), TESTNET),
                Err(decode_error(ENVELOPE_INPUT_TOO_LONG))
            );
            assert_eq!(WORK.get(), (0, 0, 0));
        }

        // The prefix ends before the operation count. The empty transaction
        // contributes the operation count, extension tag, and signature count.
        let prefix_len = envelope(&transaction(Vec::new()))
            .to_xdr(Limits::none())
            .unwrap()
            .len()
            - 12;
        let raw = envelope(&tx).to_xdr(Limits::none()).unwrap();
        // Operation source, body tag, asset tag, and amount precede the claimant count.
        let claimant_offset = prefix_len + 4 + 4 + 4 + 4 + 8;
        for (offset, count) in [(prefix_len, 101u32), (claimant_offset, 11u32)] {
            let mut forged = raw.clone();
            forged[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
            let encoded = base64::engine::general_purpose::STANDARD.encode(forged);
            assert!(matches!(
                read_envelope(&encoded),
                Err(EnvelopeReadError::Xdr(stellar_xdr::Error::LengthExceedsMax))
            ));
            WORK.set((0, 0, 0));
            assert_eq!(
                transaction_effects(&encoded, Some(&WALLET), TESTNET),
                Err(decode_error(TRANSACTION_ENVELOPE_XDR_FORM))
            );
            assert_eq!(WORK.get(), (0, 0, 0));
        }
    }

    #[test]
    fn signed_text_and_hash_memos_reach_payment_arguments() {
        for memo in [
            Memo::Text(b"inv-7".as_slice().try_into().unwrap()),
            Memo::Hash(Hash([9; 32])),
        ] {
            let mut tx = transaction(vec![operation(payment(muxed(OTHER, None)))]);
            tx.memo = memo.clone();
            let effects = decode(&tx);
            assert!(effects.unvalued.is_empty());
            assert_eq!(effects.valued.len(), 1);
            let args = &effects.valued[0].policy_args;
            match memo {
                Memo::Text(_) => assert_eq!(args["memo"], "inv-7"),
                Memo::Hash(_) => {
                    assert_eq!(args["memo"], serde_json::Value::Null);
                    assert_eq!(args["memo_hash"], "09".repeat(32));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn a_wallet_payment_to_its_own_muxed_account_is_valued() {
        for kind in [
            OperationType::Payment,
            OperationType::PathPaymentStrictReceive,
            OperationType::PathPaymentStrictSend,
        ] {
            let (mut body, _) = fixture(kind);
            let destination = muxed(WALLET, Some(1));
            match &mut body {
                OperationBody::Payment(p) => p.destination = destination,
                OperationBody::PathPaymentStrictReceive(p) => p.destination = destination,
                OperationBody::PathPaymentStrictSend(p) => p.destination = destination,
                _ => unreachable!(),
            }
            let effects = decode(&transaction(vec![operation(body)]));
            assert!(effects.unvalued.is_empty());
            assert_eq!(effects.valued.len(), 1, "{kind:?}");
            assert_eq!(effects.valued[0].route, PaymentRoute::Pay);
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Outcome {
        Valued(PaymentRoute),
        Unvalued(UnvaluedEffect),
        Refused(RefusedEffect),
        None,
    }

    fn fixture(kind: OperationType) -> (OperationBody, Outcome) {
        match kind {
            OperationType::CreateAccount => (
                OperationBody::CreateAccount(CreateAccountOp {
                    destination: account(OTHER),
                    starting_balance: 345,
                }),
                Outcome::Valued(PaymentRoute::CreateAccount),
            ),
            OperationType::Payment => (
                payment(muxed(OTHER, Some(42))),
                Outcome::Valued(PaymentRoute::Pay),
            ),
            OperationType::PathPaymentStrictReceive => (
                OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                    send_asset: Asset::Native,
                    send_max: 950,
                    destination: muxed(OTHER, None),
                    dest_asset: Asset::Native,
                    dest_amount: 800,
                    path: Default::default(),
                }),
                Outcome::Valued(PaymentRoute::Pay),
            ),
            OperationType::ManageSellOffer => (
                OperationBody::ManageSellOffer(ManageSellOfferOp {
                    amount: 50,
                    ..Default::default()
                }),
                Outcome::Unvalued(UnvaluedEffect::Offer),
            ),
            OperationType::CreatePassiveSellOffer => (
                OperationBody::CreatePassiveSellOffer(CreatePassiveSellOfferOp {
                    amount: 50,
                    ..Default::default()
                }),
                Outcome::Unvalued(UnvaluedEffect::Offer),
            ),
            OperationType::SetOptions => (
                OperationBody::SetOptions(SetOptionsOp {
                    high_threshold: Some(1),
                    ..Default::default()
                }),
                Outcome::Refused(RefusedEffect::AuthorityChange),
            ),
            OperationType::ChangeTrust => (
                OperationBody::ChangeTrust(ChangeTrustOp {
                    line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(*b"USD\0"),
                        issuer: account(THIRD),
                    }),
                    limit: 200,
                }),
                Outcome::Valued(PaymentRoute::Trustline),
            ),
            OperationType::AllowTrust => (
                OperationBody::AllowTrust(AllowTrustOp::default()),
                Outcome::None,
            ),
            OperationType::AccountMerge => (
                OperationBody::AccountMerge(muxed(OTHER, None)),
                Outcome::Refused(RefusedEffect::AccountMerge),
            ),
            OperationType::Inflation => (OperationBody::Inflation, Outcome::None),
            OperationType::ManageData => (
                OperationBody::ManageData(ManageDataOp::default()),
                Outcome::None,
            ),
            OperationType::BumpSequence => (
                OperationBody::BumpSequence(BumpSequenceOp::default()),
                Outcome::None,
            ),
            OperationType::ManageBuyOffer => (
                OperationBody::ManageBuyOffer(ManageBuyOfferOp {
                    buy_amount: 50,
                    ..Default::default()
                }),
                Outcome::Unvalued(UnvaluedEffect::Offer),
            ),
            OperationType::PathPaymentStrictSend => (
                OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                    send_asset: Asset::Native,
                    send_amount: 850,
                    destination: muxed(OTHER, None),
                    dest_asset: Asset::Native,
                    dest_min: 700,
                    path: Default::default(),
                }),
                Outcome::Valued(PaymentRoute::Pay),
            ),
            OperationType::CreateClaimableBalance => {
                (balance(&[OTHER]), Outcome::Valued(PaymentRoute::Pay))
            }
            OperationType::ClaimClaimableBalance => (
                OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp::default()),
                Outcome::Valued(PaymentRoute::Claim),
            ),
            OperationType::BeginSponsoringFutureReserves => (
                OperationBody::BeginSponsoringFutureReserves(BeginSponsoringFutureReservesOp {
                    sponsored_id: account(OTHER),
                }),
                Outcome::Unvalued(UnvaluedEffect::ReserveSponsorship),
            ),
            OperationType::EndSponsoringFutureReserves => {
                (OperationBody::EndSponsoringFutureReserves, Outcome::None)
            }
            OperationType::RevokeSponsorship => (
                OperationBody::RevokeSponsorship(RevokeSponsorshipOp::default()),
                Outcome::None,
            ),
            OperationType::Clawback => (
                OperationBody::Clawback(ClawbackOp {
                    from: muxed(WALLET, None),
                    amount: 500,
                    asset: Asset::Native,
                }),
                Outcome::Unvalued(UnvaluedEffect::Clawback),
            ),
            OperationType::ClawbackClaimableBalance => (
                OperationBody::ClawbackClaimableBalance(ClawbackClaimableBalanceOp::default()),
                Outcome::None,
            ),
            OperationType::SetTrustLineFlags => (
                OperationBody::SetTrustLineFlags(SetTrustLineFlagsOp::default()),
                Outcome::None,
            ),
            OperationType::LiquidityPoolDeposit => (
                OperationBody::LiquidityPoolDeposit(LiquidityPoolDepositOp::default()),
                Outcome::Unvalued(UnvaluedEffect::LiquidityPoolDeposit),
            ),
            OperationType::LiquidityPoolWithdraw => (
                OperationBody::LiquidityPoolWithdraw(LiquidityPoolWithdrawOp::default()),
                Outcome::None,
            ),
            OperationType::InvokeHostFunction => (
                OperationBody::InvokeHostFunction(InvokeHostFunctionOp::default()),
                Outcome::Unvalued(UnvaluedEffect::ContractInvocation),
            ),
            OperationType::ExtendFootprintTtl => (
                OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp::default()),
                Outcome::None,
            ),
            OperationType::RestoreFootprint => (
                OperationBody::RestoreFootprint(RestoreFootprintOp::default()),
                Outcome::None,
            ),
        }
    }

    const AMOUNT_FIELDS: [(OperationType, &str); 17] = [
        (OperationType::Payment, "amount"),
        (OperationType::PathPaymentStrictReceive, "send_max"),
        (OperationType::PathPaymentStrictReceive, "dest_amount"),
        (OperationType::PathPaymentStrictSend, "send_amount"),
        (OperationType::PathPaymentStrictSend, "dest_min"),
        (OperationType::CreateAccount, "starting_balance"),
        (OperationType::CreateClaimableBalance, "amount"),
        (OperationType::Clawback, "amount"),
        (OperationType::ManageSellOffer, "amount"),
        (OperationType::ManageBuyOffer, "buy_amount"),
        (OperationType::CreatePassiveSellOffer, "amount"),
        (OperationType::ChangeTrust, "limit"),
        (OperationType::LiquidityPoolDeposit, "max_amount_a"),
        (OperationType::LiquidityPoolDeposit, "max_amount_b"),
        (OperationType::LiquidityPoolWithdraw, "amount"),
        (OperationType::LiquidityPoolWithdraw, "min_amount_a"),
        (OperationType::LiquidityPoolWithdraw, "min_amount_b"),
    ];

    fn amount_fixture(kind: OperationType, field: &str, amount: i64) -> OperationBody {
        let (mut body, _) = fixture(kind);
        let target = match (&mut body, field) {
            (OperationBody::Payment(op), "amount") => &mut op.amount,
            (OperationBody::PathPaymentStrictReceive(op), "send_max") => &mut op.send_max,
            (OperationBody::PathPaymentStrictReceive(op), "dest_amount") => &mut op.dest_amount,
            (OperationBody::PathPaymentStrictSend(op), "send_amount") => &mut op.send_amount,
            (OperationBody::PathPaymentStrictSend(op), "dest_min") => &mut op.dest_min,
            (OperationBody::CreateAccount(op), "starting_balance") => &mut op.starting_balance,
            (OperationBody::CreateClaimableBalance(op), "amount") => &mut op.amount,
            (OperationBody::Clawback(op), "amount") => &mut op.amount,
            (OperationBody::ManageSellOffer(op), "amount") => &mut op.amount,
            (OperationBody::ManageBuyOffer(op), "buy_amount") => &mut op.buy_amount,
            (OperationBody::CreatePassiveSellOffer(op), "amount") => &mut op.amount,
            (OperationBody::ChangeTrust(op), "limit") => &mut op.limit,
            (OperationBody::LiquidityPoolDeposit(op), "max_amount_a") => &mut op.max_amount_a,
            (OperationBody::LiquidityPoolDeposit(op), "max_amount_b") => &mut op.max_amount_b,
            (OperationBody::LiquidityPoolWithdraw(op), "amount") => &mut op.amount,
            (OperationBody::LiquidityPoolWithdraw(op), "min_amount_a") => &mut op.min_amount_a,
            (OperationBody::LiquidityPoolWithdraw(op), "min_amount_b") => &mut op.min_amount_b,
            _ => panic!("unknown amount field: {kind:?}.{field}"),
        };
        *target = amount;
        body
    }

    #[test]
    fn nonnegative_amount_fields_keep_their_outcomes() {
        for (kind, field) in AMOUNT_FIELDS {
            for amount in [0, 42] {
                let body = amount_fixture(kind, field, amount);
                let tx = transaction(vec![operation(body.clone())]);
                let mut expected = TransactionEffects {
                    fee: Some(FeeEffect {
                        total_stroops: 1234,
                        operation_count: 1,
                        resource_fee_stroops: None,
                    }),
                    valued: Vec::new(),
                    unvalued: Vec::new(),
                    memo: Some(ClassicMemo::None),
                };
                match fixture(kind).1 {
                    Outcome::Valued(route) => {
                        let decoder_tx = match body {
                            OperationBody::CreateClaimableBalance(balance) => {
                                transaction(vec![operation(OperationBody::Payment(PaymentOp {
                                    destination: muxed(OTHER, None),
                                    asset: balance.asset,
                                    amount,
                                }))])
                            }
                            _ => tx.clone(),
                        };
                        expected.valued.push(ValuedOperation {
                            operation_index: 0,
                            route,
                            policy_args: decode_authoritative_args(
                                &encode(&envelope(&decoder_tx)),
                                route.commit_tool(),
                            )
                            .unwrap(),
                            value: None,
                        });
                    }
                    Outcome::Unvalued(UnvaluedEffect::Offer) if amount == 0 => {}
                    Outcome::Unvalued(effect) => expected.unvalued.push(UnvaluedOperation {
                        operation_index: 0,
                        effect,
                    }),
                    Outcome::None => {}
                    Outcome::Refused(_) => panic!("amount fixture has no refused effect"),
                }
                let actual = decode(&tx);
                assert_eq!(actual, expected, "{kind:?}.{field} = {amount}");
                for (actual, expected) in actual.valued.iter().zip(&expected.valued) {
                    assert_eq!(
                        serde_json::to_vec(&actual.policy_args).unwrap(),
                        serde_json::to_vec(&expected.policy_args).unwrap(),
                        "{kind:?}.{field} = {amount} argument bytes"
                    );
                }
                expected.fee.as_mut().unwrap().total_stroops = 2000;
                expected.fee.as_mut().unwrap().operation_count = 2;
                expected.valued.clear();
                expected.unvalued.clear();
                expected.memo = None;
                assert_eq!(
                    transaction_effects(
                        &encode(&fee_bump(&tx, muxed(WALLET, None), 2000)),
                        Some(&WALLET),
                        TESTNET,
                    ),
                    Ok(expected),
                    "fee bump: {kind:?}.{field} = {amount}"
                );
            }
        }
    }

    #[test]
    fn negative_amount_fields_are_typed_refusals() {
        for (kind, field) in AMOUNT_FIELDS {
            for amount in [-1, i64::MIN] {
                let tx = transaction(vec![
                    operation(OperationBody::Inflation),
                    operation(amount_fixture(kind, field, amount)),
                ]);
                for wallet in [None, Some(&WALLET), Some(&OTHER)] {
                    WORK.set((0, 0, 0));
                    assert_eq!(
                        transaction_effects(&encode(&envelope(&tx)), wallet, TESTNET),
                        Err(TransactionEffectsError::NegativeAmount {
                            operation_index: 1,
                            operation_kind: kind,
                            field,
                        }),
                        "{kind:?}.{field} = {amount}, wallet = {wallet:?}"
                    );
                    assert_eq!(
                        WORK.get(),
                        (0, 0, 0),
                        "negative amounts never reach valuation"
                    );
                }
            }
        }
    }

    #[test]
    fn fee_bumps_refuse_negative_amount_fields() {
        for (kind, field) in AMOUNT_FIELDS {
            for amount in [-1, i64::MIN] {
                let tx = transaction(vec![
                    operation(OperationBody::Inflation),
                    operation(amount_fixture(kind, field, amount)),
                ]);
                WORK.set((0, 0, 0));
                assert_eq!(
                    transaction_effects(
                        &encode(&fee_bump(&tx, muxed(WALLET, None), 2000)),
                        Some(&WALLET),
                        TESTNET,
                    ),
                    Err(TransactionEffectsError::NegativeAmount {
                        operation_index: 1,
                        operation_kind: kind,
                        field,
                    }),
                    "{kind:?}.{field} = {amount}"
                );
                assert_eq!(WORK.get(), (0, 0, 0));
            }
        }
    }

    #[test]
    fn a_negative_payment_refuses_the_transaction_before_any_valuation() {
        for amount in [-1, i64::MIN] {
            let tx = transaction(vec![
                fixture_op(OperationType::Payment),
                operation(amount_fixture(OperationType::Payment, "amount", amount)),
            ]);
            WORK.set((0, 0, 0));
            assert_eq!(
                transaction_effects(&encode(&envelope(&tx)), Some(&WALLET), TESTNET),
                Err(TransactionEffectsError::NegativeAmount {
                    operation_index: 1,
                    operation_kind: OperationType::Payment,
                    field: "amount",
                })
            );
            assert_eq!(WORK.get(), (0, 0, 0), "no operation reaches valuation");
        }
    }

    #[test]
    fn negative_amounts_are_refused_even_without_a_wallet_debit() {
        for amount in [-1, i64::MIN] {
            let mut incoming = operation(amount_fixture(OperationType::Payment, "amount", amount));
            incoming.source_account = Some(muxed(THIRD, Some(7)));
            let bodies = [
                (incoming, OperationType::Payment, "amount"),
                (
                    operation(OperationBody::ChangeTrust(ChangeTrustOp {
                        line: ChangeTrustAsset::PoolShare(LiquidityPoolParameters::default()),
                        limit: amount,
                    })),
                    OperationType::ChangeTrust,
                    "limit",
                ),
                (
                    operation(OperationBody::Clawback(ClawbackOp {
                        from: muxed(THIRD, None),
                        asset: Asset::Native,
                        amount,
                    })),
                    OperationType::Clawback,
                    "amount",
                ),
            ];
            for (op, operation_kind, field) in bodies {
                let tx = transaction(vec![op]);
                WORK.set((0, 0, 0));
                assert_eq!(
                    transaction_effects(&encode(&envelope(&tx)), Some(&OTHER), TESTNET),
                    Err(TransactionEffectsError::NegativeAmount {
                        operation_index: 0,
                        operation_kind,
                        field,
                    })
                );
                assert_eq!(WORK.get(), (0, 0, 0));
            }
        }
    }

    #[test]
    fn each_valued_kind_takes_its_route_and_the_payment_decoder_arguments() {
        let mut cases: Vec<_> = [
            OperationType::Payment,
            OperationType::PathPaymentStrictReceive,
            OperationType::PathPaymentStrictSend,
            OperationType::CreateAccount,
            OperationType::ChangeTrust,
            OperationType::ClaimClaimableBalance,
        ]
        .into_iter()
        .map(fixture)
        .collect();
        for line in [
            ChangeTrustAsset::Native,
            ChangeTrustAsset::CreditAlphanum12(AlphaNum12 {
                asset_code: AssetCode12(*b"LONGASSET123"),
                issuer: account(THIRD),
            }),
        ] {
            cases.push((
                OperationBody::ChangeTrust(ChangeTrustOp { line, limit: 99 }),
                Outcome::Valued(PaymentRoute::Trustline),
            ));
        }
        for (body, expected) in cases {
            let Outcome::Valued(route) = expected else {
                panic!("fixture has a valued route")
            };
            let mut tx = transaction(vec![operation(body)]);
            tx.cond = Preconditions::V2(PreconditionsV2 {
                min_seq_num: Some(SequenceNumber(6)),
                min_seq_age: Duration(7),
                min_seq_ledger_gap: 8,
                ..Default::default()
            });
            tx.ext = footprint(20);
            tx.memo = Memo::Text(b"inv-7".as_slice().try_into().unwrap());
            let effects = decode(&tx);
            assert!(effects.unvalued.is_empty());
            assert!(effects.has_value_effect());
            assert_eq!(effects.valued.len(), 1);
            let valued = &effects.valued[0];
            assert_eq!(valued.operation_index, 0);
            assert_eq!(valued.route, route);
            assert_eq!(valued.value, None);
            assert_eq!(
                serde_json::to_vec(&valued.policy_args).unwrap(),
                serde_json::to_vec(
                    &decode_authoritative_args(&encode(&envelope(&tx)), route.commit_tool())
                        .unwrap()
                )
                .unwrap()
            );
            assert!(valued.policy_args.get("chain_id").is_none());
            if matches!(tx.operations[0].body, OperationBody::Payment(_)) {
                assert!(
                    valued.policy_args["destination"]
                        .as_str()
                        .unwrap()
                        .starts_with('M')
                );
            }
        }
        let mut claim_tx = transaction(vec![operation(balance(&[OTHER]))]);
        claim_tx.memo = Memo::Hash(Hash([9; 32]));
        claim_tx.ext = footprint(20);
        let effects = decode(&claim_tx);
        let mut payment_tx = claim_tx.clone();
        payment_tx.operations = vec![operation(OperationBody::Payment(PaymentOp {
            destination: muxed(OTHER, None),
            asset: Asset::Native,
            amount: 7654,
        }))]
        .try_into()
        .unwrap();
        assert!(effects.unvalued.is_empty());
        assert_eq!(
            serde_json::to_vec(&effects.valued[0].policy_args).unwrap(),
            serde_json::to_vec(
                &decode_authoritative_args(&encode(&envelope(&payment_tx)), "stellar_pay_commit")
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            effects.valued,
            vec![ValuedOperation {
                operation_index: 0,
                route: PaymentRoute::Pay,
                policy_args: decode_authoritative_args(
                    &encode(&envelope(&payment_tx)),
                    "stellar_pay_commit"
                )
                .unwrap(),
                value: None,
            }]
        );
        assert_eq!(PaymentRoute::Pay.commit_tool(), "stellar_pay_commit");
        assert_eq!(
            PaymentRoute::CreateAccount.commit_tool(),
            "stellar_create_account_commit"
        );
        assert_eq!(
            PaymentRoute::Trustline.commit_tool(),
            "stellar_trustline_commit"
        );
        assert_eq!(PaymentRoute::Claim.commit_tool(), "stellar_claim_commit");
    }

    #[test]
    fn each_operation_is_decoded_alone_in_order() {
        let tx = transaction(vec![
            operation(OperationBody::CreateAccount(CreateAccountOp {
                destination: account(OTHER),
                starting_balance: 100,
            })),
            operation(OperationBody::CreateAccount(CreateAccountOp {
                destination: account(THIRD),
                starting_balance: 200,
            })),
        ]);
        let effects = decode(&tx);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 2);
        for (index, key, amount) in [(0, OTHER, "100"), (1, THIRD, "200")] {
            let valued = &effects.valued[index];
            assert_eq!(valued.operation_index, index as u32);
            assert_eq!(valued.policy_args["destination"], strkey(key));
            assert_eq!(valued.policy_args["starting_balance_stroops"], amount);
        }
    }

    #[test]
    fn a_claimable_balance_is_one_payment_per_other_claimant() {
        let mut claim = operation(balance(&[WALLET, OTHER, THIRD]));
        claim.source_account = Some(muxed(WALLET, Some(88)));
        let tx = transaction(vec![operation(OperationBody::Inflation), claim]);
        let effects = decode(&tx);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 2);
        for (valued, key) in effects.valued.iter().zip([OTHER, THIRD]) {
            assert_eq!(valued.operation_index, 1);
            assert_eq!(valued.route, PaymentRoute::Pay);
            assert_eq!(valued.value, None);
            assert_eq!(valued.policy_args["destination"], strkey(key));
            assert_eq!(valued.policy_args["source"], strkey(WALLET));
            assert_eq!(valued.policy_args["amount_stroops"], "7654");
        }
        for claimants in [vec![OTHER, WALLET, THIRD], vec![OTHER, WALLET]] {
            let mut op = operation(balance(&claimants));
            op.source_account = Some(muxed(OTHER, Some(7)));
            let effects = decode(&transaction(vec![op]));
            assert!(effects.unvalued.is_empty());
            assert_eq!(
                effects.valued.len(),
                usize::from(claimants.contains(&THIRD))
            );
            if let Some(valued) = effects.valued.first() {
                assert_eq!(valued.policy_args["destination"], strkey(THIRD));
                assert_eq!(valued.policy_args["source"], strkey(OTHER));
                assert_eq!(valued.policy_args["amount_stroops"], "7654");
            }
        }
    }

    #[test]
    fn a_claimable_balance_only_the_source_can_claim_pays_the_source() {
        let effects = decode(&transaction(vec![operation(balance(&[WALLET]))]));
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_eq!(effects.valued[0].route, PaymentRoute::Pay);
        assert_eq!(effects.valued[0].policy_args["destination"], strkey(WALLET));
        assert_eq!(effects.valued[0].policy_args["amount_stroops"], "7654");
    }

    #[test]
    fn another_sources_payment_to_the_wallet_carries_no_effect() {
        for id in [None, Some(99)] {
            for kind in [
                OperationType::Payment,
                OperationType::PathPaymentStrictReceive,
                OperationType::PathPaymentStrictSend,
            ] {
                let (mut body, _) = fixture(kind);
                let destination = muxed(WALLET, id);
                match &mut body {
                    OperationBody::Payment(p) => p.destination = destination,
                    OperationBody::PathPaymentStrictReceive(p) => p.destination = destination,
                    OperationBody::PathPaymentStrictSend(p) => p.destination = destination,
                    _ => unreachable!(),
                }
                for explicit_source in [false, true] {
                    let mut op = operation(body.clone());
                    let mut tx = transaction(Vec::new());
                    if explicit_source {
                        op.source_account = Some(muxed(OTHER, None));
                    } else {
                        tx.source_account = muxed(OTHER, None);
                    }
                    tx.operations = vec![op].try_into().unwrap();
                    empty(&decode(&tx));
                }
            }
        }
    }

    #[test]
    fn another_sources_payment_to_a_third_account_is_valued() {
        let mut op = operation(payment(muxed(THIRD, None)));
        op.source_account = Some(muxed(OTHER, Some(4)));
        let effects = decode(&transaction(vec![op]));
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_eq!(effects.valued[0].route, PaymentRoute::Pay);
        assert_eq!(effects.valued[0].policy_args["source"], strkey(OTHER));
        assert_eq!(effects.valued[0].policy_args["destination"], strkey(THIRD));
    }

    #[test]
    fn without_a_wallet_key_every_operation_and_the_fee_count() {
        let mut tx = transaction(vec![operation(payment(muxed(WALLET, None)))]);
        tx.source_account = muxed(OTHER, None);
        let effects = transaction_effects(&encode(&envelope(&tx)), None, TESTNET).unwrap();
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_eq!(effects.valued[0].policy_args["source"], strkey(OTHER));
        assert_eq!(
            effects.fee,
            Some(FeeEffect {
                total_stroops: 1234,
                operation_count: 1,
                resource_fee_stroops: None
            })
        );
        let clawback = operation(OperationBody::Clawback(ClawbackOp {
            from: muxed(THIRD, Some(5)),
            ..Default::default()
        }));
        let effects = transaction_effects(
            &encode(&envelope(&transaction(vec![clawback]))),
            None,
            TESTNET,
        )
        .unwrap();
        assert!(effects.valued.is_empty());
        assert_eq!(
            effects.unvalued,
            vec![UnvaluedOperation {
                operation_index: 0,
                effect: UnvaluedEffect::Clawback
            }]
        );
    }

    #[test]
    fn an_account_merge_refuses() {
        let tx = transaction(vec![
            operation(OperationBody::Inflation),
            operation(OperationBody::AccountMerge(muxed(THIRD, None))),
            fixture_op(OperationType::SetOptions),
        ]);
        assert_eq!(
            transaction_effects(&encode(&envelope(&tx)), Some(&WALLET), TESTNET),
            Err(TransactionEffectsError::Refused {
                operation_index: 1,
                effect: RefusedEffect::AccountMerge
            })
        );
        for id in [None, Some(44)] {
            let mut op = operation(OperationBody::AccountMerge(muxed(WALLET, id)));
            op.source_account = Some(muxed(OTHER, None));
            empty(&decode(&transaction(vec![op])));
        }
        let mut op = operation(OperationBody::AccountMerge(muxed(THIRD, None)));
        op.source_account = Some(muxed(OTHER, None));
        assert!(matches!(
            transaction_effects(
                &encode(&envelope(&transaction(vec![op]))),
                Some(&WALLET),
                TESTNET
            ),
            Err(TransactionEffectsError::Refused {
                effect: RefusedEffect::AccountMerge,
                ..
            })
        ));
        assert_eq!(RefusedEffect::AccountMerge.label(), "account_merge");
    }

    fn fixture_op(kind: OperationType) -> Operation {
        operation(fixture(kind).0)
    }

    #[test]
    fn set_options_refuses_exactly_the_authority_fields() {
        for options in [
            SetOptionsOp {
                signer: Some(Signer::default()),
                ..Default::default()
            },
            SetOptionsOp {
                master_weight: Some(0),
                ..Default::default()
            },
            SetOptionsOp {
                low_threshold: Some(0),
                ..Default::default()
            },
            SetOptionsOp {
                med_threshold: Some(0),
                ..Default::default()
            },
            SetOptionsOp {
                high_threshold: Some(0),
                ..Default::default()
            },
        ] {
            for key in [WALLET, OTHER] {
                let mut op = operation(OperationBody::SetOptions(options.clone()));
                op.source_account = Some(muxed(key, None));
                let tx = transaction(vec![operation(OperationBody::Inflation), op]);
                assert_eq!(
                    transaction_effects(&encode(&envelope(&tx)), Some(&WALLET), TESTNET),
                    Err(TransactionEffectsError::Refused {
                        operation_index: 1,
                        effect: RefusedEffect::AuthorityChange
                    })
                );
            }
        }
        for options in [
            SetOptionsOp::default(),
            SetOptionsOp {
                home_domain: Some(String32("example.org".try_into().unwrap())),
                ..Default::default()
            },
            SetOptionsOp {
                clear_flags: Some(1),
                set_flags: Some(2),
                ..Default::default()
            },
            SetOptionsOp {
                inflation_dest: Some(account(OTHER)),
                ..Default::default()
            },
        ] {
            empty(&decode(&transaction(vec![operation(
                OperationBody::SetOptions(options),
            )])));
        }
        assert_eq!(RefusedEffect::AuthorityChange.label(), "authority_change");
    }

    #[test]
    fn offers_pool_deposits_sponsorship_and_invocations_are_unvalued() {
        for (kind, effect, label) in [
            (
                OperationType::ManageSellOffer,
                UnvaluedEffect::Offer,
                "offer",
            ),
            (
                OperationType::CreatePassiveSellOffer,
                UnvaluedEffect::Offer,
                "offer",
            ),
            (
                OperationType::ManageBuyOffer,
                UnvaluedEffect::Offer,
                "offer",
            ),
            (
                OperationType::LiquidityPoolDeposit,
                UnvaluedEffect::LiquidityPoolDeposit,
                "liquidity_pool_deposit",
            ),
            (
                OperationType::BeginSponsoringFutureReserves,
                UnvaluedEffect::ReserveSponsorship,
                "reserve_sponsorship",
            ),
            (
                OperationType::InvokeHostFunction,
                UnvaluedEffect::ContractInvocation,
                "contract_invocation",
            ),
        ] {
            let effects = decode(&transaction(vec![
                operation(OperationBody::Inflation),
                fixture_op(kind),
            ]));
            assert!(effects.valued.is_empty());
            assert_eq!(
                effects.unvalued,
                vec![UnvaluedOperation {
                    operation_index: 1,
                    effect
                }]
            );
            assert!(effects.has_value_effect());
            assert_eq!(effect.label(), label);
        }
        let effects = decode(&transaction(vec![
            fixture_op(OperationType::InvokeHostFunction),
            fixture_op(OperationType::InvokeHostFunction),
        ]));
        assert!(effects.valued.is_empty());
        assert_eq!(
            effects.unvalued,
            vec![
                UnvaluedOperation {
                    operation_index: 0,
                    effect: UnvaluedEffect::ContractInvocation
                },
                UnvaluedOperation {
                    operation_index: 1,
                    effect: UnvaluedEffect::ContractInvocation
                },
            ]
        );
        let mut sponsorship = fixture_op(OperationType::BeginSponsoringFutureReserves);
        sponsorship.source_account = Some(muxed(OTHER, None));
        empty(&decode(&transaction(vec![sponsorship])));
    }

    #[test]
    fn an_offer_deletion_carries_no_effect() {
        for body in [
            OperationBody::ManageSellOffer(ManageSellOfferOp::default()),
            OperationBody::CreatePassiveSellOffer(CreatePassiveSellOfferOp::default()),
            OperationBody::ManageBuyOffer(ManageBuyOfferOp::default()),
        ] {
            empty(&decode(&transaction(vec![operation(body)])));
        }
    }

    #[test]
    fn operations_without_a_debit_carry_no_effect() {
        let mut operations: Vec<_> = OperationType::VARIANTS
            .into_iter()
            .filter_map(|kind| {
                let (body, outcome) = fixture(kind);
                matches!(outcome, Outcome::None).then_some(operation(body))
            })
            .collect();
        operations.push(operation(OperationBody::ChangeTrust(ChangeTrustOp {
            line: ChangeTrustAsset::PoolShare(LiquidityPoolParameters::default()),
            limit: 100,
        })));
        operations.push(operation(OperationBody::Clawback(ClawbackOp {
            from: muxed(THIRD, None),
            amount: 500,
            asset: Asset::Native,
        })));
        operations.push(operation(
            OperationBody::SetOptions(SetOptionsOp::default()),
        ));
        for op in &operations {
            empty(&decode(&transaction(vec![op.clone()])));
        }
        empty(&decode(&transaction(operations)));
    }

    #[test]
    fn a_clawback_from_the_wallet_is_unvalued() {
        for id in [None, Some(9)] {
            let op = Operation {
                source_account: Some(muxed(OTHER, None)),
                body: OperationBody::Clawback(ClawbackOp {
                    from: muxed(WALLET, id),
                    amount: 500,
                    asset: Asset::Native,
                }),
            };
            let effects = decode(&transaction(vec![operation(OperationBody::Inflation), op]));
            assert!(effects.valued.is_empty());
            assert_eq!(
                effects.unvalued,
                vec![UnvaluedOperation {
                    operation_index: 1,
                    effect: UnvaluedEffect::Clawback
                }]
            );
        }
        assert_eq!(UnvaluedEffect::Clawback.label(), "clawback");
    }

    #[test]
    fn every_operation_kind_of_the_xdr_has_one_outcome() {
        assert_eq!(OperationType::VARIANTS.len(), 27);
        for kind in OperationType::VARIANTS {
            let (body, expected) = fixture(kind);
            assert_eq!(body.discriminant(), kind);
            let result = transaction_effects(
                &encode(&envelope(&transaction(vec![operation(body)]))),
                Some(&WALLET),
                TESTNET,
            );
            match expected {
                Outcome::Valued(route) => {
                    let effects = result.unwrap();
                    assert!(effects.unvalued.is_empty(), "{kind:?}");
                    assert_eq!(effects.valued.len(), 1, "{kind:?}");
                    assert_eq!(effects.valued[0].route, route, "{kind:?}");
                }
                Outcome::Unvalued(effect) => {
                    let effects = result.unwrap();
                    assert!(effects.valued.is_empty(), "{kind:?}");
                    assert_eq!(
                        effects.unvalued,
                        vec![UnvaluedOperation {
                            operation_index: 0,
                            effect
                        }],
                        "{kind:?}"
                    );
                }
                Outcome::Refused(effect) => assert_eq!(
                    result,
                    Err(TransactionEffectsError::Refused {
                        operation_index: 0,
                        effect
                    }),
                    "{kind:?}"
                ),
                Outcome::None => empty(&result.unwrap()),
            }
        }
    }

    #[test]
    fn the_memo_is_the_signed_memo() {
        for (memo, expected) in [
            (Memo::None, Some(ClassicMemo::None)),
            (Memo::Id(u64::MAX), Some(ClassicMemo::Id(u64::MAX))),
            (Memo::Hash(Hash([4; 32])), Some(ClassicMemo::Hash([4; 32]))),
            (
                Memo::Return(Hash([5; 32])),
                Some(ClassicMemo::Return([5; 32])),
            ),
            (
                Memo::Text("hello".try_into().unwrap()),
                Some(ClassicMemo::Text("hello".to_owned())),
            ),
            (Memo::Text(vec![0xff].try_into().unwrap()), None),
        ] {
            let mut tx = transaction(vec![operation(OperationBody::Inflation)]);
            tx.memo = memo;
            let effects = decode(&tx);
            empty(&effects);
            assert_eq!(effects.memo, expected);
            let effects = transaction_effects(
                &encode(&fee_bump(&tx, muxed(WALLET, None), 2000)),
                Some(&WALLET),
                TESTNET,
            )
            .unwrap();
            empty(&effects);
            assert_eq!(effects.memo, None);
        }
    }

    #[test]
    fn the_fee_effect_names_total_count_and_resource_fee() {
        let mut tx = transaction(vec![operation(OperationBody::Inflation); 3]);
        let effects = decode(&tx);
        assert_eq!(
            effects.fee,
            Some(FeeEffect {
                total_stroops: 1234,
                operation_count: 3,
                resource_fee_stroops: None
            })
        );
        tx.ext = TransactionExt::V1(SorobanTransactionData {
            resource_fee: 432,
            ..Default::default()
        });
        assert_eq!(
            decode(&tx).fee,
            Some(FeeEffect {
                total_stroops: 1234,
                operation_count: 3,
                resource_fee_stroops: Some(432)
            })
        );
    }

    #[test]
    fn a_fee_another_account_pays_is_no_fee_effect() {
        let mut tx = transaction(vec![operation(OperationBody::Inflation)]);
        tx.source_account = muxed(OTHER, None);
        assert_eq!(decode(&tx).fee, None);
        tx.source_account = muxed(WALLET, Some(17));
        assert_eq!(
            decode(&tx).fee,
            Some(FeeEffect {
                total_stroops: 1234,
                operation_count: 1,
                resource_fee_stroops: None
            })
        );
    }

    #[test]
    fn a_fee_bump_carries_only_its_fee() {
        let mut tx = transaction(vec![
            fixture_op(OperationType::Payment),
            fixture_op(OperationType::SetOptions),
        ]);
        tx.ext = TransactionExt::V1(SorobanTransactionData {
            resource_fee: 333,
            ..Default::default()
        });
        for payer in [
            muxed(WALLET, None),
            muxed(WALLET, Some(6)),
            muxed(OTHER, None),
        ] {
            let effects = transaction_effects(
                &encode(&fee_bump(&tx, payer.clone(), 5000)),
                Some(&WALLET),
                TESTNET,
            )
            .unwrap();
            empty(&effects);
            assert_eq!(
                effects.fee,
                (base_key(&payer) == &WALLET).then_some(FeeEffect {
                    total_stroops: 5000,
                    operation_count: 3,
                    resource_fee_stroops: Some(333)
                })
            );
        }
    }

    #[test]
    fn a_legacy_or_undecodable_envelope_is_an_error() {
        let legacy = TransactionEnvelope::TxV0(TransactionV0Envelope::default());
        assert_eq!(
            transaction_effects(&encode(&legacy), Some(&WALLET), TESTNET),
            Err(TransactionEffectsError::LegacyEnvelope)
        );
        let tx = transaction(vec![operation(OperationBody::Inflation)]);
        empty(&decode(&tx));
        let mut negative_resource = tx.clone();
        negative_resource.ext = TransactionExt::V1(SorobanTransactionData {
            resource_fee: -1,
            ..Default::default()
        });
        let encoded = encode(&envelope(&tx));
        for (text, expected) in [
            (
                "private-invalid-envelope!".to_owned(),
                TRANSACTION_ENVELOPE_XDR_FORM,
            ),
            (
                encoded[..encoded.len() - 8].to_owned(),
                TRANSACTION_ENVELOPE_XDR_FORM,
            ),
            (
                encode(&fee_bump(&tx, muxed(WALLET, None), -1)),
                "the fee bump fee is negative",
            ),
            (
                encode(&envelope(&negative_resource)),
                "the resource fee is negative",
            ),
            (
                encode(&fee_bump(&negative_resource, muxed(OTHER, None), 2000)),
                "the resource fee is negative",
            ),
        ] {
            let error = transaction_effects(&text, Some(&WALLET), TESTNET).unwrap_err();
            assert_eq!(
                error,
                TransactionEffectsError::Decode {
                    detail: expected.to_owned()
                }
            );
            assert!(!error.to_string().contains(&text));
        }
    }

    #[test]
    fn a_transaction_without_operations_is_an_error() {
        let tx = transaction(Vec::new());
        for envelope in [envelope(&tx), fee_bump(&tx, muxed(WALLET, None), 500)] {
            assert_eq!(
                transaction_effects(&encode(&envelope), Some(&WALLET), TESTNET),
                Err(TransactionEffectsError::Decode {
                    detail: "the transaction holds no operation".to_owned()
                })
            );
        }
        empty(&decode(&transaction(vec![operation(
            OperationBody::Inflation,
        )])));
    }

    #[test]
    fn a_deeply_nested_envelope_refuses_under_the_untrusted_limits() {
        let mut invocation = SorobanAuthorizedInvocation::default();
        let mut previous: Option<String> = None;
        for _ in 0..=stellar_agent_xdr_limits::XDR_DECODE_MAX_DEPTH {
            let tx = transaction(vec![operation(OperationBody::InvokeHostFunction(
                InvokeHostFunctionOp {
                    auth: vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::SourceAccount,
                        root_invocation: invocation.clone(),
                    }]
                    .try_into()
                    .unwrap(),
                    ..Default::default()
                },
            ))]);
            let encoded = encode(&envelope(&tx));
            let limits = stellar_agent_xdr_limits::untrusted_decode_limits(encoded.len());
            if TransactionEnvelope::from_xdr_base64(&encoded, limits).is_err() {
                let admitted =
                    transaction_effects(&previous.unwrap(), Some(&WALLET), TESTNET).unwrap();
                assert!(admitted.valued.is_empty());
                assert_eq!(
                    admitted.unvalued,
                    vec![UnvaluedOperation {
                        operation_index: 0,
                        effect: UnvaluedEffect::ContractInvocation
                    }]
                );
                assert_eq!(
                    transaction_effects(&encoded, Some(&WALLET), TESTNET),
                    Err(TransactionEffectsError::Decode {
                        detail: TRANSACTION_ENVELOPE_XDR_FORM.to_owned()
                    })
                );
                return;
            }
            previous = Some(encoded);
            invocation = SorobanAuthorizedInvocation {
                sub_invocations: vec![invocation].try_into().unwrap(),
                ..Default::default()
            };
        }
        panic!("the invocation exceeds the decode depth limit");
    }
}
