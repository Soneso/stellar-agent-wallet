//! Decodes operations as valued on a payment route, unvalued, refused, or without a value effect.
//!
//! Account identity is the base ed25519 key, including for muxed accounts.
//! Without a wallet key, every source and fee payer counts as the wallet.
//! A fee bump carries only its outer fee effect.
//! Another source's payments and merges into the wallet, and its reserve sponsorship, carry no value effect.
//! Its claimable balances count only claimants other than that source and the wallet.
//! Its other operations retain their effective source and receive the same classification as the wallet's operations.
//!
//! A transaction signature authorizes `SourceAccount` entries for the operation's source account.
//! Address credentials carry their own signatures; the transaction signature adds no authorization to them.
//! A contract debits the source account's tokens through an authorized call, including calls in sub-invocations.
//! Other contract functions can move value held inside a contract without a decodable bound.
//! A native asset contract transfer debits XLM and retains its contract address in the leg.
//! An asset contract address hashes the network and asset; the address cannot reveal the asset.

use stellar_xdr::{
    AccountId, ChangeTrustAsset, Claimant, ClawbackOp, CreateClaimableBalanceOp,
    FeeBumpTransactionInnerTx, HostFunction, InvokeContractArgs, Limits, Memo, MuxedAccount,
    Operation, OperationBody, OperationType, PaymentOp, Preconditions, PublicKey, ScAddress, ScVal,
    SetOptionsOp, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, WriteXdr,
};

use crate::envelope_decode::{
    ClassicMemo, ENVELOPE_INPUT_TOO_LONG, EnvelopeReadError, TRANSACTION_ENVELOPE_XDR_FORM,
    decode_authoritative_args, read_envelope,
};
use crate::policy::v1::value::{ActionKind, ValueEffects, ValueLeg};
use crate::sc_address::{scaddress_destination_strkey, scaddress_to_strkey};

/// The token legs and unknown calls in an authorized invocation tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationEffects {
    /// One leg per valued token call, in tree order.
    pub legs: Vec<ValueLeg>,
    /// True when a node is a call the wallet cannot value.
    pub unvalued: bool,
}

/// Values SEP-41 calls authorized for `account`, in depth-first tree order.
///
/// Every leg retains its token contract address, including native asset contracts.
/// The envelope decoder bounds the tree depth before this function runs.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::transaction_effects::authorized_invocation_effects;
/// use stellar_xdr::{ScAddress, SorobanAuthorizedFunction, SorobanAuthorizedInvocation};
///
/// let root = SorobanAuthorizedInvocation {
///     function: SorobanAuthorizedFunction::CreateContractHostFn(Default::default()),
///     sub_invocations: Default::default(),
/// };
/// let effects = authorized_invocation_effects(&root, &ScAddress::default());
/// assert!(effects.legs.is_empty());
/// assert!(!effects.unvalued);
/// ```
pub fn authorized_invocation_effects(
    root: &SorobanAuthorizedInvocation,
    account: &ScAddress,
) -> InvocationEffects {
    let mut effects = InvocationEffects {
        legs: Vec::new(),
        unvalued: false,
    };
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        match &node.function {
            SorobanAuthorizedFunction::ContractFn(call) => match token_leg(call, account) {
                Ok(Some(leg)) => effects.legs.push(leg),
                Ok(None) => {}
                Err(()) => effects.unvalued = true,
            },
            SorobanAuthorizedFunction::CreateContractHostFn(_)
            | SorobanAuthorizedFunction::CreateContractV2HostFn(_) => {}
        }
        pending.extend(node.sub_invocations.iter().rev());
    }
    effects
}

fn token_leg(call: &InvokeContractArgs, account: &ScAddress) -> Result<Option<ValueLeg>, ()> {
    if !matches!(call.contract_address, ScAddress::Contract(_)) {
        return Err(());
    }
    let asset = scaddress_to_strkey(&call.contract_address).map_err(|_| ())?;
    let function = call.function_name.0.as_slice();
    let (authorizer, destination, amount) = match (function, call.args.as_slice()) {
        (
            b"transfer",
            [
                ScVal::Address(from),
                ScVal::Address(to),
                ScVal::I128(amount),
            ],
        ) => (from, Some(to), amount),
        (
            b"transfer_from",
            [
                ScVal::Address(spender),
                ScVal::Address(_from),
                ScVal::Address(to),
                ScVal::I128(amount),
            ],
        ) => (spender, Some(to), amount),
        (
            b"approve",
            [
                ScVal::Address(from),
                ScVal::Address(spender),
                ScVal::I128(amount),
                ScVal::U32(_),
            ],
        ) => (from, Some(spender), amount),
        (b"burn", [ScVal::Address(from), ScVal::I128(amount)]) => (from, None, amount),
        (
            b"burn_from",
            [
                ScVal::Address(spender),
                ScVal::Address(_from),
                ScVal::I128(amount),
            ],
        ) => (spender, None, amount),
        _ => return Err(()),
    };
    if authorizer != account {
        return Err(());
    }
    let amount = i128::from(amount);
    if amount < 0 {
        return Err(());
    }
    let destination = destination
        .map(scaddress_destination_strkey)
        .transpose()
        .map_err(|_| ())?;
    if function == b"approve" && amount == 0 {
        return Ok(None);
    }
    Ok(Some(ValueLeg {
        kind: ActionKind::Payment,
        amount: Some(amount),
        asset: Some(asset),
        destination,
    }))
}

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
    /// Token legs carry the signed memo in `memo`, `memo_id`, `memo_hash`, or `memo_return`.
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
    /// Valued legs of a mixed invocation, in entry and tree order.
    /// Empty for every other effect.
    pub valued_legs: Vec<ValuedOperation>,
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
    /// Every leg the payment rules decide, including retained legs of unvalued operations.
    /// Orders legs by operation index, then in stored order.
    /// Token legs carry the transaction's memo in their arguments and [`ValueEffects::memo`].
    pub fn payment_legs(&self) -> Vec<&ValuedOperation> {
        let mut legs: Vec<_> = self
            .valued
            .iter()
            .chain(self.unvalued.iter().flat_map(|op| &op.valued_legs))
            .collect();
        legs.sort_by_key(|leg| leg.operation_index);
        legs
    }

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
    /// A transaction with a payment leg has a text memo that is not UTF-8.
    #[error("the payment transaction's text memo is not UTF-8")]
    UnreadableMemo,
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
        // Classification precedes refusal of an unreadable payment memo.
        memo: match &tx.memo {
            Memo::Text(text) if std::str::from_utf8(text.as_slice()).is_err() => Memo::None,
            memo => memo.clone(),
        },
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
/// Every token leg carries the signed memo in its arguments and [`ValueEffects::memo`].
/// A transaction without a memo supplies [`ClassicMemo::None`].
///
/// # Errors
///
/// Returns an error for malformed or legacy envelopes, negative fees or amounts, empty transactions, and refused operations.
/// A payment leg with a text memo that is not UTF-8 returns [`TransactionEffectsError::UnreadableMemo`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::transaction_effects::{transaction_effects, TransactionEffectsError};
///
/// let result = transaction_effects("invalid", None, "Test SDF Network ; September 2015");
/// assert!(matches!(result, Err(TransactionEffectsError::Decode { .. })));
/// ```
///
/// A token transfer carries the transaction's text memo:
///
/// ```
/// use stellar_agent_core::envelope_decode::ClassicMemo;
/// use stellar_agent_core::policy::transaction_effects::transaction_effects;
/// use stellar_xdr::*;
///
/// let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1; 32])));
/// let call = InvokeContractArgs {
///     contract_address: ScAddress::Contract(ContractId(Hash([9; 32]))),
///     function_name: "transfer".try_into().unwrap(),
///     args: vec![ScVal::Address(ScAddress::Account(account.clone())),
///                ScVal::Address(ScAddress::Account(account)), ScVal::from(5i128)].try_into()?,
/// };
/// let operation = Operation {
///     source_account: None,
///     body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
///         host_function: HostFunction::InvokeContract(call.clone()),
///         auth: vec![SorobanAuthorizationEntry {
///             credentials: SorobanCredentials::SourceAccount,
///             root_invocation: SorobanAuthorizedInvocation {
///                 function: SorobanAuthorizedFunction::ContractFn(call),
///                 sub_invocations: Default::default(),
///             },
///         }].try_into()?,
///     }),
/// };
/// let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
///     tx: Transaction {
///         source_account: MuxedAccount::Ed25519(Uint256([1; 32])),
///         memo: Memo::Text("inv-7".try_into()?),
///         operations: vec![operation].try_into()?,
///         ..Default::default()
///     },
///     signatures: Default::default(),
/// });
/// let effects = transaction_effects(&envelope.to_xdr_base64(Limits::none())?, None, "")?;
/// let leg = effects.payment_legs()[0];
/// assert_eq!(leg.policy_args["memo"], "inv-7");
/// assert_eq!(leg.value.as_ref().unwrap().memo(), Some(&ClassicMemo::Text("inv-7".into())));
/// # Ok::<(), Box<dyn std::error::Error>>(())
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
    if effects.memo.is_none() && !effects.payment_legs().is_empty() {
        return Err(TransactionEffectsError::UnreadableMemo);
    }
    Ok(effects)
}

fn invocation_operation(
    tx: &Transaction,
    source: &MuxedAccount,
    operation_index: u32,
    leg: ValueLeg,
    memo: Option<&ClassicMemo>,
) -> ValuedOperation {
    let mut policy_args = serde_json::json!({
        "source": stellar_strkey::ed25519::PublicKey(*base_key(source)).to_string().as_str(),
        "total_fee_stroops": tx.fee,
        "amount_stroops": leg.amount.map(|amount| amount.to_string()),
        "asset": leg.asset,
        "memo": null,
    });
    match memo {
        Some(ClassicMemo::Text(text)) => policy_args["memo"] = text.clone().into(),
        Some(ClassicMemo::Id(id)) => policy_args["memo_id"] = id.to_string().into(),
        Some(ClassicMemo::Hash(hash)) => policy_args["memo_hash"] = crate::hex::encode(hash).into(),
        Some(ClassicMemo::Return(hash)) => {
            policy_args["memo_return"] = crate::hex::encode(hash).into()
        }
        Some(ClassicMemo::None) | None => {}
    }
    if let Some(destination) = &leg.destination {
        policy_args["destination"] = destination.clone().into();
    }
    ValuedOperation {
        operation_index,
        route: PaymentRoute::Pay,
        policy_args,
        value: Some(ValueEffects::single(leg).with_memo(memo.cloned())),
    }
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
            valued_legs: Vec::new(),
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
        OperationBody::InvokeHostFunction(op) => {
            match &op.host_function {
                HostFunction::InvokeContract(_)
                | HostFunction::CreateContract(_)
                | HostFunction::UploadContractWasm(_)
                | HostFunction::CreateContractV2(_) => {}
            }
            let account = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                stellar_xdr::Uint256(*base_key(source)),
            )));
            let mut valued_legs = Vec::new();
            let mut has_unvalued = false;
            for entry in &op.auth {
                match &entry.credentials {
                    SorobanCredentials::SourceAccount => {
                        let invocation =
                            authorized_invocation_effects(&entry.root_invocation, &account);
                        has_unvalued |= invocation.unvalued;
                        valued_legs.extend(invocation.legs.into_iter().map(|leg| {
                            invocation_operation(
                                tx,
                                source,
                                operation_index,
                                leg,
                                effects.memo.as_ref(),
                            )
                        }));
                    }
                    SorobanCredentials::Address(_)
                    | SorobanCredentials::AddressV2(_)
                    | SorobanCredentials::AddressWithDelegates(_) => {}
                }
            }
            if has_unvalued {
                effects.unvalued.push(UnvaluedOperation {
                    operation_index,
                    effect: UnvaluedEffect::ContractInvocation,
                    valued_legs,
                });
            } else {
                effects.valued.extend(valued_legs);
            }
        }
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

    fn address(key: [u8; 32]) -> ScAddress {
        ScAddress::Account(account(key))
    }

    fn contract() -> ScAddress {
        ScAddress::Contract(ContractId(Hash([9; 32])))
    }

    fn contract_strkey() -> String {
        stellar_strkey::Contract([9; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    fn call(name: &str, args: Vec<ScVal>) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract(),
                function_name: ScSymbol(name.try_into().unwrap()),
                args: args.try_into().unwrap(),
            }),
            sub_invocations: Default::default(),
        }
    }

    fn token_args(name: &str, authorizer: [u8; 32], amount: i128) -> Vec<ScVal> {
        let owner = ScVal::Address(address(authorizer));
        let other = ScVal::Address(address(OTHER));
        let amount = ScVal::from(amount);
        match name {
            "transfer" => vec![owner, other, amount],
            "transfer_from" => vec![owner, ScVal::Address(address(THIRD)), other, amount],
            "approve" => vec![owner, other, amount, ScVal::U32(100)],
            "burn" => vec![owner, amount],
            "burn_from" => vec![owner, other, amount],
            _ => panic!("the fixture names a token function"),
        }
    }

    fn token(name: &str, amount: i128) -> SorobanAuthorizedInvocation {
        call(name, token_args(name, WALLET, amount))
    }

    fn create_tree(children: Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::CreateContractHostFn(Default::default()),
            sub_invocations: children.try_into().unwrap(),
        }
    }

    fn invocation_body(roots: Vec<SorobanAuthorizedInvocation>) -> OperationBody {
        OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs::default()),
            auth: roots
                .into_iter()
                .map(|root_invocation| SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::SourceAccount,
                    root_invocation,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        })
    }

    fn invocation_effects(roots: Vec<SorobanAuthorizedInvocation>) -> TransactionEffects {
        decode(&transaction(vec![operation(invocation_body(roots))]))
    }

    fn assert_unknown(effects: &TransactionEffects) {
        assert!(
            effects.valued.is_empty(),
            "unknown calls have no separate valued operations"
        );
        assert_eq!(
            effects.unvalued,
            vec![UnvaluedOperation {
                operation_index: 0,
                effect: UnvaluedEffect::ContractInvocation,
                valued_legs: Vec::new(),
            }]
        );
    }

    fn assert_token_leg(
        op: &ValuedOperation,
        index: u32,
        source: [u8; 32],
        amount: i128,
        asset: &str,
        destination: Option<&str>,
    ) {
        assert_eq!(op.operation_index, index);
        assert_eq!(op.route, PaymentRoute::Pay);
        assert_eq!(
            op.value.as_ref().unwrap().legs(),
            &[ValueLeg {
                kind: ActionKind::Payment,
                amount: Some(amount),
                asset: Some(asset.to_owned()),
                destination: destination.map(str::to_owned),
            }]
        );
        let mut expected = serde_json::json!({
            "source": strkey(source),
            "total_fee_stroops": 1234,
            "amount_stroops": amount.to_string(),
            "asset": asset,
            "memo": null,
        });
        if let Some(destination) = destination {
            expected["destination"] = destination.into();
        }
        assert_eq!(op.policy_args, expected);
    }

    #[test]
    fn a_source_account_transfer_from_the_wallet_is_a_pay_route_payment() {
        let amount = i128::from(i64::MAX) + 1;
        for (to, expected) in [
            (address(OTHER), strkey(OTHER)),
            (contract(), contract_strkey()),
            (
                ScAddress::MuxedAccount(MuxedEd25519Account {
                    id: 17,
                    ed25519: Uint256(OTHER),
                }),
                stellar_strkey::ed25519::MuxedAccount {
                    ed25519: OTHER,
                    id: 17,
                }
                .to_string()
                .as_str()
                .to_owned(),
            ),
        ] {
            let root = call(
                "transfer",
                vec![
                    ScVal::Address(address(WALLET)),
                    ScVal::Address(to),
                    ScVal::from(amount),
                ],
            );
            let direct = authorized_invocation_effects(&root, &address(WALLET));
            assert!(!direct.unvalued);
            assert_eq!(direct.legs.len(), 1);
            let effects = invocation_effects(vec![root]);
            assert!(effects.unvalued.is_empty());
            assert_eq!(effects.valued.len(), 1);
            assert_token_leg(
                &effects.valued[0],
                0,
                WALLET,
                amount,
                &contract_strkey(),
                Some(&expected),
            );
            assert_eq!(
                direct.legs,
                effects.valued[0].value.as_ref().unwrap().legs()
            );
        }
    }

    #[test]
    fn a_native_contract_transfer_keeps_its_contract_address() {
        use crate::asset_id::CanonicalAsset;
        for network in [TESTNET, "Public Global Stellar Network ; September 2015"] {
            for asset in [
                CanonicalAsset::Native,
                CanonicalAsset::Classic {
                    code: "USD".into(),
                    issuer: strkey(THIRD),
                },
            ] {
                let asset = asset.sac_contract_id(network).unwrap();
                let mut root = token("transfer", 5);
                let SorobanAuthorizedFunction::ContractFn(call) = &mut root.function else {
                    unreachable!()
                };
                call.contract_address = ScAddress::Contract(ContractId(Hash(
                    stellar_strkey::Contract::from_string(&asset).unwrap().0,
                )));
                let tx = transaction(vec![operation(invocation_body(vec![root]))]);
                let effects =
                    transaction_effects(&encode(&envelope(&tx)), Some(&WALLET), network).unwrap();
                assert!(effects.unvalued.is_empty());
                assert_eq!(effects.valued.len(), 1);
                assert_token_leg(
                    &effects.valued[0],
                    0,
                    WALLET,
                    5,
                    &asset,
                    Some(&strkey(OTHER)),
                );
                assert!(!effects.valued[0].value.as_ref().unwrap().legs()[0].is_native_debit());
            }
        }
    }

    #[test]
    fn sub_invocation_transfers_are_valued() {
        let mut inner = create_tree(vec![token("transfer", 5)]);
        inner.function = SorobanAuthorizedFunction::CreateContractV2HostFn(Default::default());
        let effects = invocation_effects(vec![create_tree(vec![inner])]);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_token_leg(
            &effects.valued[0],
            0,
            WALLET,
            5,
            &contract_strkey(),
            Some(&strkey(OTHER)),
        );
        for function in [
            SorobanAuthorizedFunction::CreateContractHostFn(Default::default()),
            SorobanAuthorizedFunction::CreateContractV2HostFn(Default::default()),
        ] {
            empty(&invocation_effects(vec![SorobanAuthorizedInvocation {
                function,
                sub_invocations: Default::default(),
            }]));
        }
    }

    #[test]
    fn approve_is_valued_to_the_spender_and_a_zero_allowance_is_no_effect() {
        let effects = invocation_effects(vec![token("approve", 5)]);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_token_leg(
            &effects.valued[0],
            0,
            WALLET,
            5,
            &contract_strkey(),
            Some(&strkey(OTHER)),
        );
        empty(&invocation_effects(vec![token("approve", 0)]));
    }

    #[test]
    fn transfer_from_and_both_burns_are_valued() {
        let effects = invocation_effects(vec![
            token("transfer_from", 5),
            token("burn", 6),
            token("burn_from", 7),
        ]);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 3);
        for (index, op) in effects.valued.iter().enumerate() {
            let destination = (index == 0).then(|| strkey(OTHER));
            assert_token_leg(
                op,
                0,
                WALLET,
                5 + index as i128,
                &contract_strkey(),
                destination.as_deref(),
            );
            if index != 0 {
                assert!(op.policy_args.get("destination").is_none());
            }
        }
    }

    #[test]
    fn an_unknown_function_is_unvalued() {
        assert_unknown(&invocation_effects(vec![call("swap", vec![])]));
    }

    #[test]
    fn a_token_call_for_another_address_is_unvalued() {
        assert_unknown(&invocation_effects(vec![call(
            "transfer",
            token_args("transfer", OTHER, 5),
        )]));
    }

    #[test]
    fn a_negative_token_argument_is_unvalued() {
        for name in ["transfer", "transfer_from", "approve", "burn", "burn_from"] {
            for amount in [-1, i128::MIN] {
                assert_unknown(&invocation_effects(vec![token(name, amount)]));
            }
        }
    }

    #[test]
    fn address_credential_entries_carry_no_effect() {
        let mut checked = 0;
        for kind in SorobanCredentialsType::VARIANTS {
            let credentials = match kind {
                SorobanCredentialsType::SourceAccount => continue,
                SorobanCredentialsType::Address => {
                    SorobanCredentials::Address(SorobanAddressCredentials {
                        address: address(WALLET),
                        ..Default::default()
                    })
                }
                SorobanCredentialsType::AddressV2 => {
                    SorobanCredentials::AddressV2(SorobanAddressCredentials {
                        address: address(WALLET),
                        ..Default::default()
                    })
                }
                SorobanCredentialsType::AddressWithDelegates => {
                    SorobanCredentials::AddressWithDelegates(
                        SorobanAddressCredentialsWithDelegates {
                            address_credentials: SorobanAddressCredentials {
                                address: address(WALLET),
                                ..Default::default()
                            },
                            delegates: Default::default(),
                        },
                    )
                }
            };
            let body = OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                auth: vec![SorobanAuthorizationEntry {
                    credentials,
                    root_invocation: token("transfer", 5),
                }]
                .try_into()
                .unwrap(),
                ..Default::default()
            });
            empty(&decode(&transaction(vec![operation(body)])));
            checked += 1;
        }
        assert_eq!(checked, SorobanCredentialsType::VARIANTS.len() - 1);
    }

    #[test]
    fn a_call_on_an_address_that_is_not_a_contract_is_unvalued() {
        for invalid in [
            address(OTHER),
            ScAddress::MuxedAccount(MuxedEd25519Account {
                id: 1,
                ed25519: Uint256(OTHER),
            }),
            ScAddress::MuxedContract(MuxedContract {
                id: 1,
                contract_id: ContractId(Hash([9; 32])),
            }),
            ScAddress::ClaimableBalance(ClaimableBalanceId::default()),
            ScAddress::LiquidityPool(PoolId::default()),
        ] {
            let mut root = token("transfer", 5);
            let SorobanAuthorizedFunction::ContractFn(call) = &mut root.function else {
                unreachable!()
            };
            call.contract_address = invalid;
            assert_unknown(&invocation_effects(vec![root]));
        }
        for invalid in [
            ScAddress::ClaimableBalance(ClaimableBalanceId::default()),
            ScAddress::LiquidityPool(PoolId::default()),
        ] {
            assert_unknown(&invocation_effects(vec![call(
                "transfer",
                vec![
                    ScVal::Address(address(WALLET)),
                    ScVal::Address(invalid),
                    ScVal::from(5i128),
                ],
            )]));
        }
    }

    #[test]
    fn another_sources_invocation_is_decided_for_that_source() {
        for authorizer in [OTHER, WALLET] {
            let mut op = operation(invocation_body(vec![call(
                "transfer",
                vec![
                    ScVal::Address(address(authorizer)),
                    ScVal::Address(address(THIRD)),
                    ScVal::from(5i128),
                ],
            )]));
            op.source_account = Some(muxed(OTHER, Some(27)));
            let effects = decode(&transaction(vec![op]));
            if authorizer == OTHER {
                assert!(effects.unvalued.is_empty());
                assert_eq!(effects.valued.len(), 1);
                assert_token_leg(
                    &effects.valued[0],
                    0,
                    OTHER,
                    5,
                    &contract_strkey(),
                    Some(&strkey(THIRD)),
                );
            } else {
                assert_unknown(&effects);
            }
        }
    }

    #[test]
    fn an_invocation_without_source_account_authorization_carries_no_effect() {
        for kind in HostFunctionType::VARIANTS {
            let host_function = match kind {
                HostFunctionType::InvokeContract => {
                    HostFunction::InvokeContract(Default::default())
                }
                HostFunctionType::CreateContract => {
                    HostFunction::CreateContract(Default::default())
                }
                HostFunctionType::UploadContractWasm => {
                    HostFunction::UploadContractWasm(Default::default())
                }
                HostFunctionType::CreateContractV2 => {
                    HostFunction::CreateContractV2(Default::default())
                }
            };
            for roots in [vec![], vec![token("transfer", 5)]] {
                let OperationBody::InvokeHostFunction(mut op) = invocation_body(roots.clone())
                else {
                    unreachable!()
                };
                op.host_function = host_function.clone();
                let effects = decode(&transaction(vec![operation(
                    OperationBody::InvokeHostFunction(op),
                )]));
                if roots.is_empty() {
                    empty(&effects);
                } else {
                    assert!(effects.unvalued.is_empty());
                    assert_eq!(effects.valued.len(), 1);
                    assert_token_leg(
                        &effects.valued[0],
                        0,
                        WALLET,
                        5,
                        &contract_strkey(),
                        Some(&strkey(OTHER)),
                    );
                }
            }
        }
    }

    #[test]
    fn one_unvalued_entry_per_operation() {
        for roots in [
            vec![call("swap", vec![]), call("unknown", vec![])],
            vec![create_tree(vec![
                call("swap", vec![]),
                call("unknown", vec![]),
            ])],
        ] {
            assert_unknown(&invocation_effects(roots));
        }
    }

    #[test]
    fn a_mixed_invocation_is_classified_once_as_unvalued() {
        for roots in [
            vec![create_tree(vec![
                token("transfer", 5),
                call("swap", vec![]),
            ])],
            vec![token("transfer", 5), call("swap", vec![])],
            vec![call("swap", vec![]), token("transfer", 5)],
        ] {
            let effects = invocation_effects(roots);
            assert!(
                effects.valued.is_empty(),
                "mixed calls have no separate valued operations"
            );
            assert_eq!(effects.unvalued.len(), 1);
            let mixed = &effects.unvalued[0];
            assert_eq!(mixed.operation_index, 0);
            assert_eq!(mixed.effect, UnvaluedEffect::ContractInvocation);
            assert_eq!(mixed.valued_legs.len(), 1);
            assert_token_leg(
                &mixed.valued_legs[0],
                0,
                WALLET,
                5,
                &contract_strkey(),
                Some(&strkey(OTHER)),
            );
        }
    }

    #[test]
    fn a_mixed_invocation_retains_every_valued_leg() {
        let mut approval = token("approve", i128::MAX);
        let SorobanAuthorizedFunction::ContractFn(args) = &mut approval.function else {
            unreachable!()
        };
        args.contract_address = ScAddress::Contract(ContractId(Hash([8; 32])));
        let effects = invocation_effects(vec![create_tree(vec![
            token("transfer", 5),
            call("swap", vec![]),
            create_tree(vec![approval, token("burn", 7)]),
        ])]);
        assert!(effects.valued.is_empty());
        assert_eq!(effects.unvalued.len(), 1);
        let legs = &effects.unvalued[0].valued_legs;
        assert_eq!(legs.len(), 3);
        assert_token_leg(
            &legs[0],
            0,
            WALLET,
            5,
            &contract_strkey(),
            Some(&strkey(OTHER)),
        );
        assert_token_leg(
            &legs[1],
            0,
            WALLET,
            i128::MAX,
            stellar_strkey::Contract([8; 32]).to_string().as_str(),
            Some(&strkey(OTHER)),
        );
        assert_token_leg(&legs[2], 0, WALLET, 7, &contract_strkey(), None);
    }

    #[test]
    fn payment_legs_lists_valued_and_retained_legs_by_operation() {
        let effects = decode(&transaction(vec![
            operation(payment(muxed(OTHER, None))),
            operation(invocation_body(vec![create_tree(vec![
                token("transfer", 5),
                call("swap", vec![]),
                token("burn", 7),
            ])])),
            operation(invocation_body(vec![
                token("approve", 9),
                token("transfer", 11),
            ])),
            fixture_op(OperationType::ManageSellOffer),
        ]));
        let legs = effects.payment_legs();
        assert_eq!(
            legs.iter().map(|op| op.operation_index).collect::<Vec<_>>(),
            vec![0, 1, 1, 2, 2]
        );
        assert_eq!(legs[0], &effects.valued[0]);
        for (op, index, amount, destination) in [
            (legs[1], 1, 5, Some(strkey(OTHER))),
            (legs[2], 1, 7, None),
            (legs[3], 2, 9, Some(strkey(OTHER))),
            (legs[4], 2, 11, Some(strkey(OTHER))),
        ] {
            assert_token_leg(
                op,
                index,
                WALLET,
                amount,
                &contract_strkey(),
                destination.as_deref(),
            );
        }
        assert_eq!(effects.unvalued.len(), 2);
        assert!(effects.unvalued[1].valued_legs.is_empty());
    }

    #[test]
    fn a_text_memo_reaches_classic_and_token_legs_in_one_transaction() {
        let mut tx = transaction(vec![
            operation(payment(muxed(OTHER, None))),
            operation(invocation_body(vec![token("transfer", 5)])),
        ]);
        tx.memo = Memo::Text("inv-7".try_into().unwrap());
        let effects = decode(&tx);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 2);
        for leg in effects.payment_legs() {
            assert_eq!(leg.policy_args["memo"], "inv-7");
        }
        assert_eq!(
            effects.valued[1].value.as_ref().unwrap().memo(),
            Some(&ClassicMemo::Text("inv-7".to_owned()))
        );
        assert_eq!(effects.memo, Some(ClassicMemo::Text("inv-7".to_owned())));
    }

    #[test]
    fn signed_memos_reach_token_arguments_and_value() {
        for (memo, expected, fields) in [
            (
                Memo::Text("inv-7".try_into().unwrap()),
                ClassicMemo::Text("inv-7".to_owned()),
                serde_json::json!({"memo": "inv-7"}),
            ),
            (
                Memo::Text("".try_into().unwrap()),
                ClassicMemo::Text(String::new()),
                serde_json::json!({"memo": ""}),
            ),
            (
                Memo::Id(u64::MAX),
                ClassicMemo::Id(u64::MAX),
                serde_json::json!({"memo": null, "memo_id": "18446744073709551615"}),
            ),
            (
                Memo::Hash(Hash([4; 32])),
                ClassicMemo::Hash([4; 32]),
                serde_json::json!({"memo": null, "memo_hash": "04".repeat(32)}),
            ),
            (
                Memo::Return(Hash([5; 32])),
                ClassicMemo::Return([5; 32]),
                serde_json::json!({"memo": null, "memo_return": "05".repeat(32)}),
            ),
        ] {
            for roots in [
                vec![token("transfer", 5)],
                vec![call("swap", vec![]), token("transfer", 5)],
            ] {
                let mut tx = transaction(vec![operation(invocation_body(roots))]);
                tx.memo = memo.clone();
                let effects = decode(&tx);
                let legs = effects.payment_legs();
                assert_eq!(legs.len(), 1);
                let mut args = serde_json::json!({
                    "source": strkey(WALLET),
                    "total_fee_stroops": 1234,
                    "amount_stroops": "5",
                    "asset": contract_strkey(),
                    "destination": strkey(OTHER),
                });
                args.as_object_mut()
                    .unwrap()
                    .extend(fields.as_object().unwrap().clone());
                assert_eq!(legs[0].policy_args, args);
                assert_eq!(legs[0].value.as_ref().unwrap().memo(), Some(&expected));
                assert_eq!(effects.memo.as_ref(), Some(&expected));
            }
        }
    }

    #[test]
    fn a_token_transfer_without_a_memo_carries_no_memo() {
        let effects = invocation_effects(vec![token("transfer", 5)]);
        assert!(effects.unvalued.is_empty());
        assert_eq!(effects.valued.len(), 1);
        assert_token_leg(
            &effects.valued[0],
            0,
            WALLET,
            5,
            &contract_strkey(),
            Some(&strkey(OTHER)),
        );
        assert_eq!(
            effects.valued[0].value.as_ref().unwrap().memo(),
            Some(&ClassicMemo::None)
        );
        assert_eq!(effects.memo, Some(ClassicMemo::None));
    }

    #[test]
    fn an_unreadable_text_memo_is_refused_only_with_a_payment_leg() {
        for body in [
            payment(muxed(OTHER, None)),
            invocation_body(vec![token("transfer", 5)]),
            invocation_body(vec![token("transfer", 5), call("swap", vec![])]),
        ] {
            let mut tx = transaction(vec![operation(body)]);
            tx.memo = Memo::Text(vec![0xff].try_into().unwrap());
            assert_eq!(
                transaction_effects(&encode(&envelope(&tx)), Some(&WALLET), TESTNET),
                Err(TransactionEffectsError::UnreadableMemo)
            );
            let effects = transaction_effects(
                &encode(&fee_bump(&tx, muxed(WALLET, None), 2000)),
                Some(&WALLET),
                TESTNET,
            )
            .unwrap();
            empty(&effects);
            assert_eq!(effects.memo, None);
        }
        for kind in [OperationType::BumpSequence, OperationType::ManageSellOffer] {
            let mut tx = transaction(vec![fixture_op(kind)]);
            tx.memo = Memo::Text(vec![0xff].try_into().unwrap());
            let effects = decode(&tx);
            assert!(effects.payment_legs().is_empty());
            assert_eq!(effects.memo, None);
        }
    }

    #[test]
    fn zero_token_arguments_keep_their_node_outcomes() {
        for name in ["transfer", "transfer_from", "burn", "burn_from"] {
            let effects = invocation_effects(vec![token(name, 0)]);
            assert!(effects.unvalued.is_empty());
            assert_eq!(effects.valued.len(), 1);
            let destination = name.starts_with("transfer").then(|| strkey(OTHER));
            assert_token_leg(
                &effects.valued[0],
                0,
                WALLET,
                0,
                &contract_strkey(),
                destination.as_deref(),
            );
        }
        empty(&invocation_effects(vec![token("approve", 0)]));
    }

    #[test]
    fn approve_preserves_amount_and_spender_for_every_expiration() {
        for expiration in [ScVal::U32(0), ScVal::U32(u32::MAX), ScVal::I32(1)] {
            let args = vec![
                ScVal::Address(address(WALLET)),
                ScVal::Address(address(OTHER)),
                ScVal::from(i128::MAX),
                expiration.clone(),
            ];
            let effects = invocation_effects(vec![call("approve", args)]);
            if matches!(expiration, ScVal::U32(_)) {
                assert!(effects.unvalued.is_empty());
                assert_eq!(effects.valued.len(), 1);
                assert_token_leg(
                    &effects.valued[0],
                    0,
                    WALLET,
                    i128::MAX,
                    &contract_strkey(),
                    Some(&strkey(OTHER)),
                );
            } else {
                assert_unknown(&effects);
            }
        }
    }

    #[test]
    fn token_shapes_and_authorizing_roles_are_exact() {
        for name in ["transfer", "transfer_from", "approve", "burn", "burn_from"] {
            let args = token_args(name, WALLET, 5);
            let amount_index = args
                .iter()
                .position(|arg| matches!(arg, ScVal::I128(_)))
                .unwrap();
            let mut wrong_type = args.clone();
            wrong_type[amount_index] = ScVal::I64(5);
            let mut extra = args.clone();
            extra.push(ScVal::Void);
            let mut missing = args.clone();
            missing.pop();
            for malformed in [wrong_type, extra, missing] {
                assert_unknown(&invocation_effects(vec![call(name, malformed)]));
            }
            for index in 0..amount_index {
                let mut malformed = args.clone();
                malformed[index] = ScVal::Void;
                assert_unknown(&invocation_effects(vec![call(name, malformed)]));
            }
            assert_unknown(&invocation_effects(vec![call(
                name,
                token_args(name, OTHER, 5),
            )]));
            let effects = invocation_effects(vec![call(name, args.clone())]);
            assert!(
                effects.unvalued.is_empty(),
                "the authorizing role matches for {name}"
            );
            assert_eq!(effects.valued.len(), 1);
            if name.ends_with("_from") {
                let mut wrong_role = args;
                wrong_role[0] = ScVal::Address(address(OTHER));
                wrong_role[1] = ScVal::Address(address(WALLET));
                assert_unknown(&invocation_effects(vec![call(name, wrong_role)]));
            }
        }
    }

    #[test]
    fn a_destination_keeps_its_full_mux_id() {
        for is_contract in [false, true] {
            let mut destinations = Vec::new();
            for id in [1, u64::MAX] {
                let (to, expected) = if is_contract {
                    (
                        ScAddress::MuxedContract(MuxedContract {
                            id,
                            contract_id: ContractId(Hash([9; 32])),
                        }),
                        stellar_strkey::MuxedContract {
                            id,
                            contract_id: [9; 32],
                        }
                        .to_string()
                        .as_str()
                        .to_owned(),
                    )
                } else {
                    (
                        ScAddress::MuxedAccount(MuxedEd25519Account {
                            id,
                            ed25519: Uint256(OTHER),
                        }),
                        stellar_strkey::ed25519::MuxedAccount { id, ed25519: OTHER }
                            .to_string()
                            .as_str()
                            .to_owned(),
                    )
                };
                let effects = invocation_effects(vec![call(
                    "transfer",
                    vec![
                        ScVal::Address(address(WALLET)),
                        ScVal::Address(to),
                        ScVal::from(5i128),
                    ],
                )]);
                assert!(effects.unvalued.is_empty());
                assert_eq!(effects.valued.len(), 1);
                assert_token_leg(
                    &effects.valued[0],
                    0,
                    WALLET,
                    5,
                    &contract_strkey(),
                    Some(&expected),
                );
                destinations.push(
                    effects.valued[0].value.as_ref().unwrap().legs()[0]
                        .destination
                        .clone(),
                );
            }
            assert_ne!(destinations[0], destinations[1]);
        }
    }

    #[test]
    fn a_fee_bump_does_not_value_its_inner_authorization_tree() {
        let mut tx = transaction(vec![operation(invocation_body(vec![token("transfer", 5)]))]);
        tx.memo = Memo::Text("fee".try_into().unwrap());
        let effects = transaction_effects(
            &encode(&fee_bump(&tx, muxed(WALLET, None), 2000)),
            Some(&WALLET),
            TESTNET,
        )
        .unwrap();
        assert_eq!(
            effects.fee,
            Some(FeeEffect {
                total_stroops: 2000,
                operation_count: 2,
                resource_fee_stroops: None
            })
        );
        empty(&effects);
        assert_eq!(effects.memo, None);
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
                invocation_body(vec![call("swap", vec![])]),
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
                        valued_legs: Vec::new(),
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
                effect: UnvaluedEffect::Clawback,
                valued_legs: Vec::new(),
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
                    effect,
                    valued_legs: Vec::new(),
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
                    effect: UnvaluedEffect::ContractInvocation,
                    valued_legs: Vec::new(),
                },
                UnvaluedOperation {
                    operation_index: 1,
                    effect: UnvaluedEffect::ContractInvocation,
                    valued_legs: Vec::new(),
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
                    effect: UnvaluedEffect::Clawback,
                    valued_legs: Vec::new(),
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
                            effect,
                            valued_legs: Vec::new(),
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
                        effect: UnvaluedEffect::ContractInvocation,
                        valued_legs: Vec::new(),
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
