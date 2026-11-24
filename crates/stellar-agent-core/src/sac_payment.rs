//! Offline verification of classic-asset transfers to contract recipients.
//!
//! Verified facts grant no signing authority. Callers must separately validate
//! the transaction data, policy, signatures and submission boundary.

use serde::{Deserialize, Serialize};
use stellar_xdr::*;

use crate::approval::IntentAsset;
use crate::asset_id::CanonicalAsset;
use crate::error::{ValidationError, WalletError};
use crate::profile::caip2::Caip2;

/// Validated, owned network and classic-asset facts, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ContextFacts")]
pub struct SacPaymentContext {
    chain: Caip2,
    asset: IntentAsset,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFacts {
    chain: Caip2,
    asset: IntentAsset,
}

impl TryFrom<ContextFacts> for SacPaymentContext {
    type Error = WalletError;

    fn try_from(facts: ContextFacts) -> Result<Self, Self::Error> {
        Self::new(facts.chain, facts.asset)
    }
}

impl SacPaymentContext {
    /// Validates native or issued asset facts on the selected chain.
    ///
    /// # Errors
    /// Returns `validation.contract_payment_invalid` for an invalid asset code
    /// or noncanonical issuer account.
    pub fn new(chain: Caip2, asset: IntentAsset) -> Result<Self, WalletError> {
        if let IntentAsset::Issued { code, issuer } = &asset {
            CanonicalAsset::classic(code, issuer).map_err(|_| SacPaymentError::Invalid)?;
        }
        Ok(Self { chain, asset })
    }

    /// Network used in forward SAC derivation.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        self.chain
    }

    /// Validated classic asset.
    #[must_use]
    pub fn asset(&self) -> &IntentAsset {
        &self.asset
    }

    fn canonical_asset(&self) -> CanonicalAsset {
        match &self.asset {
            IntentAsset::Native => CanonicalAsset::Native,
            IntentAsset::Issued { code, issuer } => CanonicalAsset::Classic {
                code: code.clone(),
                issuer: issuer.clone(),
            },
        }
    }
}

impl std::fmt::Display for SacPaymentContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} on {}", self.canonical_asset(), self.chain)
    }
}

/// Closed, safe contract-payment refusal reasons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SacPaymentError {
    /// This payment surface cannot execute contract payments.
    #[error("Contract payments are not available on this payment surface.")]
    Unavailable,
    /// A SourceAccount witness is unavailable.
    #[error("A contract payment SourceAccount witness is not available.")]
    WitnessUnavailable,
    /// The instance failure does not establish either possible cause.
    #[error(
        "Asset contract for {context} is unavailable: it may never have been deployed or may not be restorable. This is not a diagnosis."
    )]
    AssetContractNotDeployed {
        /// Validated asset and network named by the failed request.
        context: SacPaymentContext,
    },
    /// An identified archived key could not be restored atomically.
    #[error("An archived contract payment entry cannot be restored in this transaction.")]
    ArchivedEntry {
        /// SHA-256 of the canonical ledger-key XDR.
        key_sha256: [u8; 32],
    },
    /// The network forbids a memo on this invocation.
    #[error(
        "The network rejects a memo on a contract invocation. Use a W address to carry an id on a network at protocol 30 or later. W payments are not available in this implementation."
    )]
    MemoUnsupported,
    /// The active policy must consent to a total fee cap.
    #[error("A signed total contract transfer fee cap is required.")]
    FeeConsentRequired,
    /// The full transaction fee exceeds the supplied cap.
    #[error("The contract transfer total fee exceeds the supplied cap.")]
    FeeExceeded,
    /// Footprint keys, permissions or restoration indices are invalid.
    #[error("The contract payment footprint or restoration indices are invalid.")]
    Footprint,
    /// The context, transfer, authorization or fee arithmetic is invalid.
    #[error("The contract payment facts or fee arithmetic are invalid.")]
    Invalid,
    /// The simulation cannot establish a usable transaction.
    #[error("The contract payment simulation response is invalid.")]
    SimulationInvalid,
}

impl SacPaymentError {
    /// Stable wire code, preserved through [`WalletError`].
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => "validation.contract_payment_unavailable",
            Self::WitnessUnavailable => "validation.contract_payment_witness_unavailable",
            Self::AssetContractNotDeployed { .. } => "validation.asset_contract_not_deployed",
            Self::ArchivedEntry { .. } => "validation.contract_payment_archived_entry",
            Self::MemoUnsupported => "validation.contract_payment_memo_unsupported",
            Self::FeeConsentRequired => "validation.contract_transfer_fee_cap_required",
            Self::FeeExceeded => "validation.contract_transfer_fee_exceeded",
            Self::Footprint => "validation.contract_payment_footprint",
            Self::Invalid => "validation.contract_payment_invalid",
            Self::SimulationInvalid => "validation.contract_payment_simulation_invalid",
        }
    }
}

impl From<SacPaymentError> for WalletError {
    fn from(reason: SacPaymentError) -> Self {
        ValidationError::SacPayment(reason).into()
    }
}

/// Caller-supplied total fee bound; `signed` is descriptive, not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractTransferFeeCap {
    /// Maximum full transaction fee in stroops.
    pub stroops: u32,
    /// Whether the caller obtained the cap from a signed policy.
    pub signed: bool,
}

/// Fee limits consumed by the pure data validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractTransferFeeLimits {
    /// The single bound covering inclusion, resources and restoration.
    pub total: ContractTransferFeeCap,
}

/// Checked decomposition of the envelope's full fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SacTransferFee {
    /// Full transaction fee.
    pub total_stroops: u32,
    /// Full fee minus resource fee.
    pub inclusion_bid_stroops: u32,
    /// Nonnegative resource fee, including any restoration charge.
    pub resource_stroops: u32,
}

/// Semantically verified transfer facts, privately constructed from bounded XDR.
///
/// Signatures may be present but are not authenticated by this type. Resource
/// data and fee consent require [`validate_sac_payment_data`].
///
/// # Examples
///
/// Checked facts cannot be modified through field access:
///
/// ```compile_fail
/// use stellar_agent_core::sac_payment::VerifiedSacPayment;
/// fn alter(payment: &mut VerifiedSacPayment) {
///     payment.transaction.fee = 0;
/// }
/// ```
///
/// Deserialization cannot create verified facts:
///
/// ```compile_fail
/// use stellar_agent_core::sac_payment::VerifiedSacPayment;
/// fn deserializable<T: serde::de::DeserializeOwned>() {}
/// deserializable::<VerifiedSacPayment>();
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedSacPayment {
    context: SacPaymentContext,
    transaction: Transaction,
    invoke: InvokeContractArgs,
    payer: AccountId,
    recipient: ContractId,
    amount: i64,
}

impl VerifiedSacPayment {
    /// Validated context used to prove the invoked SAC.
    #[must_use]
    pub fn context(&self) -> &SacPaymentContext {
        &self.context
    }

    /// Exact transaction inspected by the verifier.
    #[must_use]
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Exact transfer invocation inspected by the verifier.
    #[must_use]
    pub fn invoke(&self) -> &InvokeContractArgs {
        &self.invoke
    }

    /// Authoritative facts of the `stellar_pay_commit` policy schema.
    ///
    /// The destination is the full C recipient, `total_fee_stroops` is the
    /// whole transaction fee and `sequence_number` is numeric. The memo is
    /// always absent because verification refuses any other memo.
    #[must_use]
    pub fn policy_args(&self) -> serde_json::Value {
        let mut args = serde_json::json!({
            "source": self.source(),
            "total_fee_stroops": self.transaction.fee,
            "destination": self.destination(),
            "amount_stroops": self.amount.to_string(),
            "asset": self.asset_text(),
            "sequence_number": self.transaction.seq_num.0,
        });
        for (key, value) in crate::envelope_decode::ClassicMemo::None.policy_fields() {
            args[key] = value;
        }
        args
    }

    /// The approval summary of the verified transfer.
    ///
    /// The inclusion and resource fees are present when the Soroban
    /// resource fee fits in `u32` and does not exceed the transaction fee.
    #[must_use]
    pub fn summary(&self) -> crate::envelope_decode::ClassicSummary {
        use crate::envelope_decode::{ClassicMemo, ClassicOperation, ClassicSummary};
        let tx = &self.transaction;
        let split = match &tx.ext {
            TransactionExt::V1(data) => u32::try_from(data.resource_fee)
                .ok()
                .and_then(|resource| Some((tx.fee.checked_sub(resource)?, resource))),
            TransactionExt::V0 => None,
        };
        ClassicSummary {
            source: self.source(),
            fee_stroops: tx.fee,
            seq_num: tx.seq_num.0,
            memo: ClassicMemo::None,
            operation: ClassicOperation::SacTransfer {
                destination: self.destination(),
                asset: self.asset_text(),
                amount_stroops: self.amount,
                inclusion_fee_stroops: split.map(|(inclusion, _)| inclusion),
                resource_fee_stroops: split.map(|(_, resource)| resource),
            },
        }
    }

    /// The canonical intent payload of the verified transfer.
    ///
    /// `explicit_inclusion_bid_stroops` records whether the caller chose the
    /// inclusion bid; `None` and `Some(0)` encode differently.
    #[must_use]
    pub fn intent_payload(
        &self,
        explicit_inclusion_bid_stroops: Option<u32>,
    ) -> crate::approval::IntentPayload {
        crate::approval::IntentPayload::ContractPay {
            destination: self.destination(),
            asset: self.context.asset.clone(),
            amount_stroops: self.amount,
            explicit_inclusion_bid_stroops,
        }
    }

    /// The G payer, which is also the transaction source.
    fn source(&self) -> String {
        let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer))) = &self.payer;
        format!("{}", stellar_strkey::ed25519::PublicKey(*payer))
    }

    /// The full C recipient.
    pub(crate) fn destination(&self) -> String {
        format!("{}", stellar_strkey::Contract(self.recipient.0.0))
    }

    /// The transfer amount in stroops.
    pub(crate) fn amount_stroops(&self) -> i64 {
        self.amount
    }

    /// `"XLM"` or `"CODE:ISSUER"`, the classic payment asset text.
    pub(crate) fn asset_text(&self) -> String {
        match &self.context.asset {
            IntentAsset::Native => "XLM".to_owned(),
            IntentAsset::Issued { code, issuer } => format!("{code}:{issuer}"),
        }
    }
}

/// Whether `text` is a canonical C contract strkey.
pub(crate) fn is_canonical_contract(text: &str) -> bool {
    stellar_strkey::Contract::from_string(text).is_ok_and(|key| format!("{key}") == text)
}

/// Whether `text` is a canonical W muxed contract strkey.
pub(crate) fn is_canonical_muxed_contract(text: &str) -> bool {
    stellar_strkey::MuxedContract::from_string(text).is_ok_and(|key| format!("{key}") == text)
}

/// The transfer operation and its arguments when `tx` holds exactly one
/// `transfer(Account, Contract, I128)` contract invocation.
type TransferParts<'a> = (
    &'a Operation,
    &'a InvokeHostFunctionOp,
    &'a InvokeContractArgs,
    &'a AccountId,
    &'a ContractId,
    &'a Int128Parts,
);

fn transfer_parts(tx: &Transaction) -> Option<TransferParts<'_>> {
    let [op] = tx.operations.as_slice() else {
        return None;
    };
    let OperationBody::InvokeHostFunction(host) = &op.body else {
        return None;
    };
    let HostFunction::InvokeContract(invoke) = &host.host_function else {
        return None;
    };
    if invoke.function_name.0.as_slice() != b"transfer" {
        return None;
    }
    let [
        ScVal::Address(ScAddress::Account(payer)),
        ScVal::Address(ScAddress::Contract(recipient)),
        ScVal::I128(amount),
    ] = invoke.args.as_slice()
    else {
        return None;
    };
    Some((op, host, invoke, payer, recipient, amount))
}

/// Whether the envelope is a v1 transaction with exactly one
/// `transfer(Account, Contract, I128)` invocation of any contract.
///
/// A payment surface evaluates every such envelope as a payment.
pub(crate) fn is_transfer_shaped(envelope_xdr: &str) -> bool {
    matches!(
        crate::envelope_decode::read_envelope(envelope_xdr),
        Ok(TransactionEnvelope::Tx(envelope)) if transfer_parts(&envelope.tx).is_some()
    )
}

/// Refuses a payment request whose destination is a canonical C contract or W
/// muxed contract.
///
/// No payment surface executes a contract payment. Other destinations pass,
/// and their own checks still apply.
///
/// # Errors
/// `validation.contract_payment_memo_unsupported` when `memo` is set,
/// otherwise `validation.contract_payment_unavailable`.
pub fn refuse_contract_destination(destination: &str, memo: bool) -> Result<(), SacPaymentError> {
    if !is_canonical_contract(destination) && !is_canonical_muxed_contract(destination) {
        return Ok(());
    }
    Err(if memo {
        SacPaymentError::MemoUnsupported
    } else {
        SacPaymentError::Unavailable
    })
}

/// Refuses an envelope a payment surface evaluates as a contract transfer.
///
/// An envelope that is not one `transfer(Account, Contract, I128)`
/// invocation passes. Such a transfer never falls back to opaque signing: it
/// refuses with the verifier's reason, or once proven for `context`, with
/// `Unavailable`.
///
/// # Errors
/// The closed reason of [`verify_sac_payment`],
/// `validation.contract_payment_invalid` without a context, and
/// `validation.contract_payment_unavailable` for a verified transfer.
pub fn refuse_contract_transfer(
    envelope_xdr: &str,
    context: Option<&SacPaymentContext>,
) -> Result<(), SacPaymentError> {
    if !is_transfer_shaped(envelope_xdr) {
        return Ok(());
    }
    verify(envelope_xdr, context.ok_or(SacPaymentError::Invalid)?)?;
    Err(SacPaymentError::Unavailable)
}

/// Proves a single classic-asset transfer from a G payer to a C recipient.
///
/// This bounded offline inspection accepts signed or unsigned v1 envelopes.
/// It authenticates neither signatures nor ledger state.
///
/// # Errors
/// Returns a closed [`SacPaymentError`] through [`WalletError`] for malformed
/// XDR, transfer facts, source, SAC identity, authorization or memo.
pub fn verify_sac_payment(
    envelope_xdr: &str,
    context: &SacPaymentContext,
) -> Result<VerifiedSacPayment, WalletError> {
    Ok(verify(envelope_xdr, context)?)
}

fn verify(
    envelope_xdr: &str,
    context: &SacPaymentContext,
) -> Result<VerifiedSacPayment, SacPaymentError> {
    let TransactionEnvelope::Tx(envelope) = crate::envelope_decode::read_envelope(envelope_xdr)
        .map_err(|_| SacPaymentError::Invalid)?
    else {
        return Err(SacPaymentError::Invalid);
    };
    let tx = envelope.tx;
    if tx.memo != Memo::None {
        return Err(SacPaymentError::MemoUnsupported);
    }
    let (op, host, invoke, payer, recipient, amount) =
        transfer_parts(&tx).ok_or(SacPaymentError::Invalid)?;
    let AccountId(PublicKey::PublicKeyTypeEd25519(payer_key)) = payer;
    if tx.source_account != MuxedAccount::Ed25519(payer_key.clone()) {
        return Err(SacPaymentError::Invalid);
    }
    if op
        .source_account
        .as_ref()
        .is_some_and(|source| source != &tx.source_account)
    {
        return Err(SacPaymentError::Invalid);
    }
    let amount = i64::try_from(i128::from(amount)).map_err(|_| SacPaymentError::Invalid)?;
    if amount <= 0 {
        return Err(SacPaymentError::Invalid);
    }
    let sac = context
        .canonical_asset()
        .sac_contract_id(context.chain.network_passphrase())
        .ok_or(SacPaymentError::Invalid)?;
    let invoked = crate::sc_address::scaddress_to_strkey(&invoke.contract_address)
        .map_err(|_| SacPaymentError::Invalid)?;
    if invoked != sac {
        return Err(SacPaymentError::Invalid);
    }
    let [auth] = host.auth.as_slice() else {
        return Err(SacPaymentError::Invalid);
    };
    if auth.credentials != SorobanCredentials::SourceAccount
        || auth.root_invocation.function != SorobanAuthorizedFunction::ContractFn(invoke.clone())
        || !auth.root_invocation.sub_invocations.is_empty()
    {
        return Err(SacPaymentError::Invalid);
    }
    Ok(VerifiedSacPayment {
        context: context.clone(),
        invoke: invoke.clone(),
        payer: payer.clone(),
        recipient: recipient.clone(),
        amount,
        transaction: tx,
    })
}

struct AllowedKeys {
    instance: LedgerKey,
    balance: LedgerKey,
    payer: LedgerKey,
    issuer: Option<LedgerKey>,
    trustline: Option<LedgerKey>,
}

impl AllowedKeys {
    fn derive(payment: &VerifiedSacPayment) -> Result<Self, WalletError> {
        let contract_data = |key| {
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: payment.invoke.contract_address.clone(),
                key,
                durability: ContractDataDurability::Persistent,
            })
        };
        let balance = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol(
                    "Balance".try_into().map_err(|_| SacPaymentError::Invalid)?,
                )),
                ScVal::Address(ScAddress::Contract(payment.recipient.clone())),
            ]
            .try_into()
            .map_err(|_| SacPaymentError::Invalid)?,
        )));
        let mut keys = Self {
            instance: contract_data(ScVal::LedgerKeyContractInstance),
            balance: contract_data(balance),
            payer: LedgerKey::Account(LedgerKeyAccount {
                account_id: payment.payer.clone(),
            }),
            issuer: None,
            trustline: None,
        };
        if let IntentAsset::Issued { code, issuer } = payment.context.asset() {
            let key = stellar_strkey::ed25519::PublicKey::from_string(issuer)
                .map_err(|_| SacPaymentError::Invalid)?;
            let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key.0)));
            keys.issuer = Some(LedgerKey::Account(LedgerKeyAccount {
                account_id: issuer.clone(),
            }));
            if issuer != payment.payer {
                let asset = if code.len() <= 4 {
                    let mut bytes = [0; 4];
                    bytes[..code.len()].copy_from_slice(code.as_bytes());
                    TrustLineAsset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(bytes),
                        issuer,
                    })
                } else {
                    let mut bytes = [0; 12];
                    bytes[..code.len()].copy_from_slice(code.as_bytes());
                    TrustLineAsset::CreditAlphanum12(AlphaNum12 {
                        asset_code: AssetCode12(bytes),
                        issuer,
                    })
                };
                keys.trustline = Some(LedgerKey::Trustline(LedgerKeyTrustLine {
                    account_id: payment.payer.clone(),
                    asset,
                }));
            }
        }
        Ok(keys)
    }

    fn check_footprint(&self, footprint: &LedgerFootprint) -> Result<(), WalletError> {
        let mut seen = std::collections::BTreeSet::new();
        for key in footprint
            .read_only
            .iter()
            .chain(footprint.read_write.iter())
        {
            if !seen.insert(key) {
                return Err(SacPaymentError::Footprint.into());
            }
        }
        for key in &footprint.read_only {
            if key != &self.instance && Some(key) != self.issuer.as_ref() {
                return Err(SacPaymentError::Footprint.into());
            }
        }
        for key in &footprint.read_write {
            if key != &self.instance
                && key != &self.balance
                && key != &self.payer
                && Some(key) != self.trustline.as_ref()
            {
                return Err(SacPaymentError::Footprint.into());
            }
        }
        Ok(())
    }

    fn check_restoration(&self, data: &SorobanTransactionData) -> Result<(), WalletError> {
        let indices = match &data.ext {
            SorobanTransactionDataExt::V0 => &[][..],
            SorobanTransactionDataExt::V1(ext) => ext.archived_soroban_entries.as_slice(),
        };
        if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SacPaymentError::Footprint.into());
        }
        let rw = &data.resources.footprint.read_write;
        for index in indices {
            let key = rw.get(*index as usize).ok_or(SacPaymentError::Footprint)?;
            if key != &self.instance && key != &self.balance {
                return Err(SacPaymentError::Footprint.into());
            }
        }
        if let Some(index) = rw.iter().position(|key| key == &self.instance)
            && !indices.contains(&(index as u32))
        {
            return Err(SacPaymentError::Footprint.into());
        }
        Ok(())
    }
}

/// Checks forward footprint permissions, atomic restoration and the full fee.
///
/// Keys are optional allowances. Supplied footprint and restoration order are
/// preserved. The cap's `signed` flag grants no policy or signing authority.
///
/// # Errors
/// Returns `validation.contract_payment_footprint` for invalid keys or indices,
/// `validation.contract_payment_invalid` for absent Soroban data or invalid fee
/// arithmetic, and `validation.contract_transfer_fee_exceeded` above the cap.
pub fn validate_sac_payment_data(
    payment: &VerifiedSacPayment,
    explicit_inclusion_bid_stroops: Option<u32>,
    limits: ContractTransferFeeLimits,
) -> Result<SacTransferFee, WalletError> {
    let TransactionExt::V1(data) = &payment.transaction.ext else {
        return Err(SacPaymentError::Invalid.into());
    };
    let keys = AllowedKeys::derive(payment)?;
    keys.check_footprint(&data.resources.footprint)?;
    keys.check_restoration(data)?;
    let resource_stroops =
        u32::try_from(data.resource_fee).map_err(|_| SacPaymentError::Invalid)?;
    let total_stroops = payment.transaction.fee;
    let inclusion_bid_stroops = total_stroops
        .checked_sub(resource_stroops)
        .ok_or(SacPaymentError::Invalid)?;
    if explicit_inclusion_bid_stroops.is_some_and(|bid| bid != inclusion_bid_stroops) {
        return Err(SacPaymentError::Invalid.into());
    }
    if total_stroops > limits.total.stroops {
        return Err(SacPaymentError::FeeExceeded.into());
    }
    Ok(SacTransferFee {
        total_stroops,
        inclusion_bid_stroops,
        resource_stroops,
    })
}

#[cfg(test)]
mod tests;
