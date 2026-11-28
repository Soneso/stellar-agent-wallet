//! Construction of bounded, single SAC payments from a canonical contract intent.
//!
//! These helpers grant no signing or submission authority. Ordinary payment
//! surfaces retain their C and W refusals.

use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::{ClassicIntent, IntentAsset, IntentPayload, MemoFact};
use stellar_agent_core::asset_id::CanonicalAsset;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::sac_payment::{
    ContractTransferFeeLimits, SacPaymentContext, SacPaymentError as Refusal, SacTransferFee,
    VerifiedSacPayment, validate_sac_payment_data, verify_sac_payment,
};
use stellar_rpc_client::{GetLedgerEntriesResponse, SimulateTransactionResponse};
use stellar_xdr::*;

use crate::StellarRpcClient;
use crate::fees::{ClassicFeeChoice, FeeStatsView, contract_transfer_fee_cap};

const MAX_XDR: usize = 65_536;
const MAX_XDR_DEPTH: u32 = 64;

/// Terms retained by preparation, with the final transaction sequence.
pub struct SacPaymentBuildRequest<'a> {
    /// Canonical ContractPay intent, including the total bound and bid option.
    pub intent: &'a ClassicIntent,
    /// Independently validated network and classic asset.
    pub context: &'a SacPaymentContext,
    /// Final sequence, with no implicit increment.
    pub sequence: i64,
    /// Preconditions to retain exactly.
    pub conditions: Preconditions,
    /// Inclusion bid selection; explicit selection must agree with the intent.
    pub fee_choice: ClassicFeeChoice,
    /// Inclusion bid used for ProfileDefault.
    pub default_inclusion_bid: u32,
    /// Verified policy used for current total-fee consent.
    pub policy: Option<&'a VerifiedPolicy>,
}

/// Prepared unsigned envelope and the verified facts from those exact bytes.
#[derive(Debug)]
pub struct PreparedSacPayment {
    /// Canonical base64 envelope.
    pub envelope_xdr: String,
    /// Retained canonical intent.
    pub intent: ClassicIntent,
    /// Verified payment facts; data validation has also succeeded.
    pub payment: VerifiedSacPayment,
    /// Checked full fee and its parts.
    pub fee: SacTransferFee,
}

/// Bounded simulation allocation, containing no reusable authorization.
#[derive(Debug)]
pub struct SacSimulationData {
    data: SorobanTransactionData,
    resource_stroops: u32,
}

impl SacSimulationData {
    /// Decoded simulation allocation, preserving footprint and restoration index order.
    /// Only the validator checks the footprint and restoration indices.
    pub fn transaction_data(&self) -> &SorobanTransactionData {
        &self.data
    }

    /// Greater of the encoded allocation fee and the reported minimum.
    pub fn resource_stroops(&self) -> u32 {
        self.resource_stroops
    }
}

fn decode<T: ReadXdr>(encoded: &str) -> Result<T, WalletError> {
    if encoded.len() > MAX_XDR {
        return Err(Refusal::SimulationInvalid.into());
    }
    T::from_xdr_base64(
        encoded,
        Limits {
            depth: MAX_XDR_DEPTH,
            len: MAX_XDR,
        },
    )
    .map_err(|_| Refusal::SimulationInvalid.into())
}

fn encode<T: WriteXdr>(value: &T) -> Result<String, WalletError> {
    value
        .to_xdr_base64(Limits {
            depth: MAX_XDR_DEPTH,
            len: MAX_XDR,
        })
        .map_err(|_| Refusal::Invalid.into())
}

fn local_auth(invoke: &InvokeContractArgs) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
            sub_invocations: VecM::default(),
        },
    }
}

/// Checks one void result, allocation, and exact SourceAccount authorization.
///
/// Each encoded XDR value is bounded to 64 KiB and depth 64. Every restore
/// preamble refuses. Allocation uses the greater of the encoded resource fee
/// and the reported minimum; neither can reduce the other.
///
/// # Errors
/// Returns the closed simulation refusal for malformed responses or mismatched
/// authorization, and the invalid-payment refusal for unrepresentable fees.
pub fn check_sac_simulation(
    response: &SimulateTransactionResponse,
    invoke: &InvokeContractArgs,
) -> Result<SacSimulationData, WalletError> {
    if response.error.is_some() || response.restore_preamble.is_some() {
        return Err(Refusal::SimulationInvalid.into());
    }
    let [result] = response.results.as_slice() else {
        return Err(Refusal::SimulationInvalid.into());
    };
    if decode::<ScVal>(&result.xdr)? != ScVal::Void {
        return Err(Refusal::SimulationInvalid.into());
    }
    let [auth] = result.auth.as_slice() else {
        return Err(Refusal::SimulationInvalid.into());
    };
    if decode::<SorobanAuthorizationEntry>(auth)? != local_auth(invoke) {
        return Err(Refusal::SimulationInvalid.into());
    }
    let mut data: SorobanTransactionData = decode(&response.transaction_data)?;
    let encoded_fee = u32::try_from(data.resource_fee).map_err(|_| Refusal::Invalid)?;
    let minimum = u32::try_from(response.min_resource_fee).map_err(|_| Refusal::Invalid)?;
    let resource_stroops = encoded_fee.max(minimum);
    data.resource_fee = i64::from(resource_stroops);
    Ok(SacSimulationData {
        data,
        resource_stroops,
    })
}

fn invocation(request: &SacPaymentBuildRequest<'_>) -> Result<InvokeContractArgs, WalletError> {
    let base = request.intent.base();
    let IntentPayload::ContractPay {
        destination,
        asset,
        amount_stroops,
        explicit_inclusion_bid_stroops,
    } = request.intent.payload()
    else {
        return Err(Refusal::Invalid.into());
    };
    if base.memo() != &MemoFact::None {
        return Err(Refusal::MemoUnsupported.into());
    }
    let explicit = match request.fee_choice {
        ClassicFeeChoice::Explicit(bid) => Some(bid),
        _ => None,
    };
    if base.chain_id() != request.context.chain().caip2_str()
        || asset != request.context.asset()
        || &explicit != explicit_inclusion_bid_stroops
    {
        return Err(Refusal::Invalid.into());
    }
    let asset = match asset {
        IntentAsset::Native => CanonicalAsset::Native,
        IntentAsset::Issued { code, issuer } => CanonicalAsset::Classic {
            code: code.clone(),
            issuer: issuer.clone(),
        },
    };
    let sac = asset
        .sac_contract_id(request.context.chain().network_passphrase())
        .ok_or(Refusal::Invalid)?;
    let contract = stellar_strkey::Contract::from_string(&sac).map_err(|_| Refusal::Invalid)?;
    let payer = stellar_strkey::ed25519::PublicKey::from_string(base.source())
        .map_err(|_| Refusal::Invalid)?;
    let recipient =
        stellar_strkey::Contract::from_string(destination).map_err(|_| Refusal::Invalid)?;
    crate::sep41::build_sep41_transfer_invoke(
        ContractId(Hash(contract.0)),
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer.0)))),
        ScAddress::Contract(ContractId(Hash(recipient.0))),
        i128::from(*amount_stroops),
    )
    .map_err(|_| Refusal::Invalid.into())
}

fn envelope(
    request: &SacPaymentBuildRequest<'_>,
    invoke: &InvokeContractArgs,
    fee: u32,
    ext: TransactionExt,
) -> Result<TransactionEnvelope, WalletError> {
    let payer = stellar_strkey::ed25519::PublicKey::from_string(request.intent.base().source())
        .map_err(|_| Refusal::Invalid)?;
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(payer.0)),
            fee,
            seq_num: SequenceNumber(request.sequence),
            cond: request.conditions.clone(),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(invoke.clone()),
                    auth: match &ext {
                        TransactionExt::V0 => VecM::default(),
                        TransactionExt::V1(_) => vec![local_auth(invoke)]
                            .try_into()
                            .map_err(|_| Refusal::Invalid)?,
                    },
                }),
            }]
            .try_into()
            .map_err(|_| Refusal::Invalid)?,
            ext,
        },
        signatures: VecM::default(),
    }))
}

fn contract_key(invoke: &InvokeContractArgs, key: ScVal) -> LedgerKeyContractData {
    LedgerKeyContractData {
        contract: invoke.contract_address.clone(),
        key,
        durability: ContractDataDurability::Persistent,
    }
}

fn instance_live(
    response: GetLedgerEntriesResponse,
    expected: &LedgerKeyContractData,
) -> Result<bool, WalletError> {
    let entries = response.entries.unwrap_or_default();
    let entry = match entries.as_slice() {
        [] => return Ok(false),
        [entry] => entry,
        _ => return Err(Refusal::SimulationInvalid.into()),
    };
    if decode::<LedgerKey>(&entry.key)? != LedgerKey::ContractData(expected.clone()) {
        return Err(Refusal::SimulationInvalid.into());
    }
    let LedgerEntryData::ContractData(data) = decode(&entry.xdr)? else {
        return Err(Refusal::SimulationInvalid.into());
    };
    if data.contract != expected.contract
        || data.key != expected.key
        || data.durability != expected.durability
        || !matches!(
            data.val,
            ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                ..
            })
        )
    {
        return Err(Refusal::SimulationInvalid.into());
    }
    Ok(true)
}

fn validate_data(
    payment: &VerifiedSacPayment,
    data: &SorobanTransactionData,
    request: &SacPaymentBuildRequest<'_>,
) -> Result<SacTransferFee, WalletError> {
    let invoke = payment.invoke();
    let instance = LedgerKey::ContractData(contract_key(invoke, ScVal::LedgerKeyContractInstance));
    let balance = LedgerKey::ContractData(contract_key(
        invoke,
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol(
                    "Balance".try_into().map_err(|_| Refusal::Invalid)?,
                )),
                invoke.args[1].clone(),
            ]
            .try_into()
            .map_err(|_| Refusal::Invalid)?,
        ))),
    ));
    if let SorobanTransactionDataExt::V1(ext) = &data.ext {
        let indices = &ext.archived_soroban_entries;
        let rw = &data.resources.footprint.read_write;
        if indices.windows(2).any(|pair| pair[0] >= pair[1])
            || indices.iter().any(|index| *index as usize >= rw.len())
        {
            return Err(Refusal::Footprint.into());
        }
        for index in indices {
            let key = &rw[*index as usize];
            if key != &instance && key != &balance {
                let bytes = key
                    .to_xdr(Limits {
                        depth: MAX_XDR_DEPTH,
                        len: MAX_XDR,
                    })
                    .map_err(|_| Refusal::Invalid)?;
                return Err(Refusal::ArchivedEntry {
                    key_sha256: Sha256::digest(bytes).into(),
                }
                .into());
            }
        }
    }
    let mut cap = contract_transfer_fee_cap(request.context.chain(), request.policy)?;
    cap.stroops = cap.stroops.min(request.intent.base().fee_bound_stroops());
    let explicit = match request.fee_choice {
        ClassicFeeChoice::Explicit(bid) => Some(bid),
        _ => None,
    };
    validate_sac_payment_data(payment, explicit, ContractTransferFeeLimits { total: cap })
}

/// Assembles retained allocation and total fee, then runs the core validator.
///
/// This offline adapter preserves footprint and index order and constructs
/// authorization locally. It performs no simulation or ledger read.
///
/// # Errors
/// Returns a closed SAC refusal for intent/context disagreement, invalid
/// allocation, unsupported archived keys, or a total above either bound.
pub(crate) fn assemble_sac_payment(
    request: &SacPaymentBuildRequest<'_>,
    data: &SorobanTransactionData,
    total_fee: u32,
) -> Result<PreparedSacPayment, WalletError> {
    let invoke = invocation(request)?;
    let envelope_xdr = encode(&envelope(
        request,
        &invoke,
        total_fee,
        TransactionExt::V1(data.clone()),
    )?)?;
    let payment = verify_sac_payment(&envelope_xdr, request.context)?;
    let fee = validate_data(&payment, data, request)?;
    Ok(PreparedSacPayment {
        envelope_xdr,
        intent: request.intent.clone(),
        payment,
        fee,
    })
}

trait SacRpc {
    async fn entries(&self, keys: &[LedgerKey]) -> Result<GetLedgerEntriesResponse, NetworkError>;
    async fn stats(&self) -> Result<FeeStatsView, NetworkError>;
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, NetworkError>;
}

impl SacRpc for StellarRpcClient {
    async fn entries(&self, keys: &[LedgerKey]) -> Result<GetLedgerEntriesResponse, NetworkError> {
        self.get_ledger_entries(keys).await
    }
    async fn stats(&self) -> Result<FeeStatsView, NetworkError> {
        self.get_fee_stats().await
    }
    async fn simulate(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, NetworkError> {
        self.simulate_transaction_envelope(envelope).await
    }
}

/// Reads the derived instance and simulates one intent-derived transfer.
///
/// Explicit fees are inclusion bids. Automatic fees use Soroban statistics.
/// An absent instance requires an indexed restoration in this transaction.
/// No deployment, separate restoration, signing, or submission occurs.
///
/// # Errors
/// Preserves transport errors. Failed simulation with an absent instance gives
/// the combined deployment/restoration refusal, without echoing server prose.
/// Other failures retain their closed SAC reason.
pub async fn prepare_sac_payment(
    client: &StellarRpcClient,
    request: &SacPaymentBuildRequest<'_>,
) -> Result<PreparedSacPayment, WalletError> {
    prepare_with(client, request).await
}

async fn prepare_with(
    client: &impl SacRpc,
    request: &SacPaymentBuildRequest<'_>,
) -> Result<PreparedSacPayment, WalletError> {
    let invoke = invocation(request)?;
    contract_transfer_fee_cap(request.context.chain(), request.policy)?;
    let bid = match request.fee_choice {
        ClassicFeeChoice::ProfileDefault => request.default_inclusion_bid,
        ClassicFeeChoice::Explicit(bid) => bid,
        ClassicFeeChoice::Auto(percentile) => {
            u32::try_from(percentile.select(&client.stats().await?.soroban_inclusion_fee))
                .map_err(|_| Refusal::Invalid)?
        }
    };
    let instance = contract_key(&invoke, ScVal::LedgerKeyContractInstance);
    let instance_key = LedgerKey::ContractData(instance.clone());
    let live = instance_live(
        client.entries(std::slice::from_ref(&instance_key)).await?,
        &instance,
    )?;
    let response = client
        .simulate(&envelope(request, &invoke, bid, TransactionExt::V0)?)
        .await?;
    if !live && response.error.is_some() {
        return Err(Refusal::AssetContractNotDeployed {
            context: request.context.clone(),
        }
        .into());
    }
    let checked = check_sac_simulation(&response, &invoke)?;
    if !live {
        let restored = match &checked.data.ext {
            SorobanTransactionDataExt::V0 => false,
            SorobanTransactionDataExt::V1(ext) => {
                ext.archived_soroban_entries.iter().any(|index| {
                    checked
                        .data
                        .resources
                        .footprint
                        .read_write
                        .get(*index as usize)
                        == Some(&instance_key)
                })
            }
        };
        if !restored {
            return Err(Refusal::Footprint.into());
        }
    }
    let total = checked
        .resource_stroops()
        .checked_add(bid)
        .ok_or(Refusal::Invalid)?;
    assemble_sac_payment(request, &checked.data, total)
}

/// Builds the C-route nonce subject from a validated intent and envelope text.
///
/// The domain is `stellar-agent:sac-payment:nonce:v1\0`, followed by each
/// value's u64 big-endian byte length and bytes, intent first. Canonical intent
/// bytes preserve the distinction between absent and explicit zero bids.
/// Classic and durable nonce subjects do not use this function.
///
/// # Errors
/// Returns the invalid-payment refusal for missing or non-contract intent,
/// or an unrepresentable length.
pub fn sac_payment_nonce_subject(
    intent: Option<&ClassicIntent>,
    envelope_xdr: &str,
) -> Result<Vec<u8>, WalletError> {
    let intent = intent.ok_or(Refusal::Invalid)?;
    crate::operation_entry::contract_pay_identity(intent)?;
    let mut subject = b"stellar-agent:sac-payment:nonce:v1\0".to_vec();
    for value in [intent.canonical_bytes().as_slice(), envelope_xdr.as_bytes()] {
        subject.extend_from_slice(
            &u64::try_from(value.len())
                .map_err(|_| Refusal::Invalid)?
                .to_be_bytes(),
        );
        subject.extend_from_slice(value);
    }
    Ok(subject)
}

/// Independent caller terms checked against the nonce-bound contract intent.
pub struct SacPaymentCaller<'a> {
    /// Unmuxed payer account.
    pub source: &'a str,
    /// Full C recipient.
    pub destination: &'a str,
    /// Classic asset identity.
    pub asset: &'a IntentAsset,
    /// Positive amount in stroops.
    pub amount_stroops: i64,
    /// Explicit inclusion option, preserving None versus Some(0).
    pub explicit_inclusion_bid_stroops: Option<u32>,
    /// Caller memo; only None agrees with a contract payment.
    pub memo: &'a MemoFact,
}

/// Rebuilds the C envelope from its bound intent and its own retained data.
///
/// `request` carries the current expected final sequence and retained
/// preconditions. Caller terms are checked independently. Canonical envelope
/// equality includes authorization, source, sequence, preconditions, fees and
/// data. This offline function cannot obtain a new simulation estimate.
///
/// # Errors
/// Returns the invalid-payment refusal for caller or envelope disagreement,
/// or a closed SAC data/fee refusal from the retained-data adapter.
pub fn rebuild_sac_payment(
    request: &SacPaymentBuildRequest<'_>,
    presented_xdr: &str,
    caller: &SacPaymentCaller<'_>,
) -> Result<PreparedSacPayment, WalletError> {
    let IntentPayload::ContractPay {
        destination,
        asset,
        amount_stroops,
        explicit_inclusion_bid_stroops,
    } = request.intent.payload()
    else {
        return Err(Refusal::Invalid.into());
    };
    if caller.source != request.intent.base().source()
        || caller.destination != destination
        || caller.asset != asset
        || caller.amount_stroops != *amount_stroops
        || caller.explicit_inclusion_bid_stroops != *explicit_inclusion_bid_stroops
        || caller.memo != request.intent.base().memo()
    {
        return Err(Refusal::Invalid.into());
    }
    let presented: TransactionEnvelope = decode(presented_xdr).map_err(|_| Refusal::Invalid)?;
    let TransactionEnvelope::Tx(envelope) = &presented else {
        return Err(Refusal::Invalid.into());
    };
    let TransactionExt::V1(data) = &envelope.tx.ext else {
        return Err(Refusal::Invalid.into());
    };
    let rebuilt = assemble_sac_payment(request, data, envelope.tx.fee)?;
    if rebuilt.envelope_xdr != encode(&presented)? {
        return Err(Refusal::Invalid.into());
    }
    Ok(rebuilt)
}

#[cfg(test)]
mod tests;
